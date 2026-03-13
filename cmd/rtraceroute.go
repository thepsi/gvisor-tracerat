// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

// This sample creates a stack with TCP and IPv4 protocols on top of a TUN
// device, and listens on a port. Data received by the server in the accepted
// connections is echoed back to the clients.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/tun"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	sweeps  = 3
	maxHops = 63
)

type connHelper struct {
	ep tcpip.Endpoint
	wq *waiter.Queue
}

type tcpipError struct {
	inner tcpip.Error
}

func (e *tcpipError) Error() string {
	return e.inner.String()
}

func (ch *connHelper) GetRemoteAddress() (tcpip.FullAddress, error) {
	addr, err := ch.ep.GetRemoteAddress()
	if err != nil {
		return addr, &tcpipError{inner: err}
	}
	return addr, nil
}

func (ch *connHelper) Write(p []byte) (int, error) {
	var r bytes.Reader
	r.Reset(p)
	n, err := ch.ep.Write(&r, tcpip.WriteOptions{})
	if err != nil {
		return int(n), &tcpipError{
			inner: err,
		}
	}
	if n != int64(len(p)) {
		return int(n), io.ErrShortWrite
	}
	return int(n), nil
}

func (ch *connHelper) Read(p []byte) (int, error) {
	w := tcpip.SliceWriter(p)
	res, err := ch.ep.Read(&w, tcpip.ReadOptions{})
	if err == nil {
		return res.Count, nil
	}
	if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		return res.Count, &tcpipError{inner: err}
	}

	// Create a wait entry.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	ch.wq.EventRegister(&waitEntry)
	defer ch.wq.EventUnregister(&waitEntry)

	for {
		w := tcpip.SliceWriter(p)
		res, err := ch.ep.Read(&w, tcpip.ReadOptions{})
		if err == nil {
			return res.Count, nil
		}
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			return res.Count, &tcpipError{inner: err}
		}

		<-notifyCh
	}
}

func (ch *connHelper) startKeepalive(ttl int) error {
	ch.ep.SocketOptions().SetIPv4RecvError(true)
	ch.ep.SocketOptions().SetIPv6RecvError(true)
	ttlOpt := tcpip.KeepaliveTTLOption(ttl)
	if err := ch.ep.SetSockOpt(&ttlOpt); err != nil {
		return fmt.Errorf("failed to set KeepaliveTTLOption: %v", err)
	}
	// initial delay
	idle := tcpip.KeepaliveIdleOption(500 * time.Millisecond)
	if err := ch.ep.SetSockOpt(&idle); err != nil {
		return fmt.Errorf("failed to set KeepaliveIdleOption: %v", err)
	}
	// time between keepalives; this needs to be longer than our timeout below
	interval := tcpip.KeepaliveIntervalOption(5 * time.Second)
	if err := ch.ep.SetSockOpt(&interval); err != nil {
		return fmt.Errorf("failed to set KeepaliveIntervalOption: %v", err)
	}
	// Start the keepalive
	ch.ep.SocketOptions().SetKeepAlive(true)
	return nil
}

func (ch *connHelper) stopKeepalive() {
	ch.ep.SocketOptions().SetKeepAlive(false)
}

func (ch *connHelper) DoKeepalive(ttl int) (time.Duration, bool, *tcpip.Address, error) {
	notifyCh := make(chan waiter.EventMask, 1)
	waitEntry := waiter.NewFunctionEntry(
		waiter.ReadableEvents|waiter.EventKeepAliveResponse|waiter.EventKeepAliveSent|waiter.EventErr,
		func(mask waiter.EventMask) {
			select {
			case notifyCh <- mask:
			default:
			}
		})
	ch.wq.EventRegister(&waitEntry)
	defer ch.wq.EventUnregister(&waitEntry)

	if err := ch.startKeepalive(ttl); err != nil {
		return 0, false, nil, fmt.Errorf("startKeepalive: %v", err)
	}
	defer ch.stopKeepalive()

	var lastSent time.Time
	for {
		var buf bytes.Buffer
		select {
		case <-time.After(3 * time.Second):
			// timeout
			return 0, false, nil, nil
		case ev := <-notifyCh:
			switch {
			case ev&waiter.ReadableEvents != 0:
				// client sent us something or disconnected
				if _, err := ch.ep.Read(&buf, tcpip.ReadOptions{}); err != nil {
					return 0, false, nil, fmt.Errorf("failed to read: %v", err)
				}
				log.Printf("%p: ignoring %d bytes", ch.ep, buf.Len())
			case ev&waiter.EventKeepAliveSent != 0:
				lastSent = time.Now()
				log.Printf("%p: keepalive sent", ch.ep)
			case ev&waiter.EventKeepAliveResponse != 0:
				latency := time.Now().Sub(lastSent)
				return latency, true, nil, nil
			case ev&waiter.EventErr != 0:
				// errors
				for {
					err := ch.ep.SocketOptions().DequeueErr()
					if err == nil {
						break
					}
					latency := time.Now().Sub(lastSent)
					return latency, false, &err.ControlSrc.Addr, nil
				}
			}
		}
	}
}

func handleConnection(wq *waiter.Queue, ep tcpip.Endpoint) {
	defer ep.Close()

	ch := connHelper{
		ep: ep,
		wq: wq,
	}

	remote, err := ch.GetRemoteAddress()
	if err != nil {
		log.Printf("%p: failed to get remote address: %v", ep, err)
		return
	}
	log.Printf("%p: connect from: %v", ep, remote)

	br := bufio.NewReader(&ch)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("%p: ReadRequest: %v", ep, err)
		return
	}
	log.Printf("%p: got request: %s %s %s", ep, req.Method, req.URL, req.Proto)

	ch.Write([]byte("HTTP/1.1 200 200 OK\r\n"))
	ch.Write([]byte("content-type: text/plain; charset=utf-8\r\n"))
	ch.Write([]byte("connection: close\r\n\r\n"))
	ch.Write([]byte(fmt.Sprintf("%d sweeps, max %d hops:\n\n", sweeps, maxHops)))

sweeps:
	for sweep := 1; sweep <= sweeps; sweep++ {
		for ttl := 1; ttl <= maxHops; ttl++ {
			latency, done, addr, err := ch.DoKeepalive(ttl)
			switch {
			case err != nil:
				log.Printf("%p: error: %v", ep, err)
				return
			case latency == 0:
				log.Printf("%p: timeout", ep)
				ch.Write([]byte(fmt.Sprintf("%d: timeout\n", ttl)))
			case !done:
				log.Printf("%p: error from %v in %v", ep, addr, latency)
				ch.Write([]byte(fmt.Sprintf("%d: got error from %v after %v\n", ttl, addr, latency)))
			default:
				log.Printf("%p: keepalive response received", ep)
				ch.Write([]byte(fmt.Sprintf("%d: got response from %v after %v\n\n", ttl, remote.Addr, latency)))
				continue sweeps
			}
		}
	}

	ch.Write([]byte("bye!\r\n"))
}

func main() {
	flag.Parse()
	if len(flag.Args()) != 3 {
		log.Fatal("Usage: ", os.Args[0], " <tun-device> <local-address> <local-port>")
	}

	tunName := flag.Arg(0)
	addrName := flag.Arg(1)
	portName := flag.Arg(2)

	// Parse the IP address. Support both ipv4 and ipv6.
	parsedAddr := net.ParseIP(addrName)
	if parsedAddr == nil {
		log.Fatalf("Bad IP address: %v", addrName)
	}

	var addrWithPrefix tcpip.AddressWithPrefix
	var proto tcpip.NetworkProtocolNumber
	if parsedAddr.To4() != nil {
		addrWithPrefix = tcpip.AddrFromSlice(parsedAddr.To4()).WithPrefix()
		proto = ipv4.ProtocolNumber
	} else if parsedAddr.To16() != nil {
		addrWithPrefix = tcpip.AddrFromSlice(parsedAddr.To16()).WithPrefix()
		proto = ipv6.ProtocolNumber
	} else {
		log.Fatalf("Unknown IP type: %v", addrName)
	}

	localPort, err := strconv.Atoi(portName)
	if err != nil {
		log.Fatalf("Unable to convert port %v: %v", portName, err)
	}

	// Create the stack with ip and tcp protocols, then add a tun-based
	// NIC and address.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	mtu, err := rawfile.GetMTU(tunName)
	if err != nil {
		log.Fatal(err)
	}

	var fd int
	fd, err = tun.Open(tunName)
	if err != nil {
		log.Fatal(err)
	}

	linkEP, err := fdbased.New(&fdbased.Options{
		FDs: []int{fd},
		MTU: mtu,
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := s.CreateNIC(1, linkEP); err != nil {
		log.Fatal(err)
	}

	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          proto,
		AddressWithPrefix: addrWithPrefix,
	}
	if err := s.AddProtocolAddress(1, protocolAddr, stack.AddressProperties{}); err != nil {
		log.Fatalf("AddProtocolAddress(%d, %+v, {}): %s", 1, protocolAddr, err)
	}

	subnet, err := tcpip.NewSubnet(tcpip.AddrFromSlice([]byte(strings.Repeat("\x00", addrWithPrefix.Address.Len()))), tcpip.MaskFrom(strings.Repeat("\x00", addrWithPrefix.Address.Len())))
	if err != nil {
		log.Fatal(err)
	}

	// Add default route.
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         1,
		},
	})

	// Create TCP endpoint, bind it, then start listening.
	var wq waiter.Queue
	ep, e := s.NewEndpoint(tcp.ProtocolNumber, proto, &wq)
	if e != nil {
		log.Fatal(e)
	}

	defer ep.Close()

	if err := ep.Bind(tcpip.FullAddress{Port: uint16(localPort)}); err != nil {
		log.Fatal("Bind failed: ", err)
	}
	log.Printf("bound to %s:%d", addrWithPrefix, localPort)

	if err := ep.Listen(10); err != nil {
		log.Fatal("Listen failed: ", err)
	}

	// Wait for connections to appear.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	for {
		n, wq, err := ep.Accept(nil)
		if err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}

			log.Fatal("Accept() failed:", err)
		}

		go handleConnection(wq, n)
	}
}
