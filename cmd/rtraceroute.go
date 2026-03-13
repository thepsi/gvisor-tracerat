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

var tap = flag.Bool("tap", false, "use tap instead of tun")
var mac = flag.String("mac", "aa:00:01:01:01:01", "mac address to use in tap device")

const maxHops = 63

type endpointReadWriter struct {
	ep tcpip.Endpoint
	wq *waiter.Queue
}

type tcpipError struct {
	inner tcpip.Error
}

func (e *tcpipError) Error() string {
	return e.inner.String()
}

func (e *endpointReadWriter) GetRemoteAddress() (tcpip.FullAddress, error) {
	addr, err := e.ep.GetRemoteAddress()
	if err != nil {
		return addr, &tcpipError{inner: err}
	}
	return addr, nil
}

func (e *endpointReadWriter) Write(p []byte) (int, error) {
	var r bytes.Reader
	r.Reset(p)
	n, err := e.ep.Write(&r, tcpip.WriteOptions{})
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

func (e *endpointReadWriter) Read(p []byte) (int, error) {
	w := tcpip.SliceWriter(p)
	res, err := e.ep.Read(&w, tcpip.ReadOptions{})
	if err == nil {
		return res.Count, nil
	}
	if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
		return res.Count, &tcpipError{inner: err}
	}

	// Create a wait entry.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	e.wq.EventRegister(&waitEntry)
	defer e.wq.EventUnregister(&waitEntry)

	for {
		w := tcpip.SliceWriter(p)
		res, err := e.ep.Read(&w, tcpip.ReadOptions{})
		if err == nil {
			return res.Count, nil
		}
		if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
			return res.Count, &tcpipError{inner: err}
		}

		<-notifyCh
	}
}

func handleConnection(wq *waiter.Queue, ep tcpip.Endpoint) {
	defer ep.Close()

	rw := endpointReadWriter{
		ep: ep,
		wq: wq,
	}

	remote, err := rw.GetRemoteAddress()
	if err != nil {
		log.Printf("%p: failed to get remote address: %v", ep, err)
		return
	}
	log.Printf("%p: connect from: %v", ep, remote)

	br := bufio.NewReader(&rw)
	req, err := http.ReadRequest(br)
	if err != nil {
		log.Printf("%p: ReadRequest: %v", ep, err)
		return
	}
	log.Printf("%p: got request: %s %s %s", ep, req.Method, req.URL, req.Proto)

	rw.Write([]byte("HTTP/1.1 200 200 OK\r\n"))
	rw.Write([]byte("content-type: text/plain; charset=utf-8\r\n"))
	rw.Write([]byte("connection: close\r\n\r\n"))

	// Enable keepalives.
	ep.SocketOptions().SetKeepAlive(true)

	// Enable error reporting.
	ep.SocketOptions().SetIPv4RecvError(true)
	ep.SocketOptions().SetIPv6RecvError(true)

	// Set a custom TTL for keepalive packets.
	var currentTTL int
	updateTTL := func(newTTL int) {
		currentTTL = newTTL
		log.Printf("%p: updating TTL to: %d", ep, currentTTL)
		ttl := tcpip.KeepaliveTTLOption(currentTTL)
		if err := ep.SetSockOpt(&ttl); err != nil {
			log.Printf("%p: failed to set KeepaliveTTLOption: %v", ep, err)
		}
	}
	incrementTTL := func() {
		updateTTL(currentTTL + 1)
	}
	resetKeepalive := func() {
		ep.SocketOptions().SetKeepAlive(false)
		ep.SocketOptions().SetKeepAlive(true)
	}
	updateTTL(1)

	// idle time before first keepalive
	idle := tcpip.KeepaliveIdleOption(time.Second)
	if err := ep.SetSockOpt(&idle); err != nil {
		log.Printf("%p: failed to set KeepaliveIdleOption: %v", ep, err)
	}
	// time between keepalives; this needs to be longer than our timeout below
	interval := tcpip.KeepaliveIntervalOption(5 * time.Second)
	if err := ep.SetSockOpt(&interval); err != nil {
		log.Printf("%p: failed to set KeepaliveIntervalOption: %v", ep, err)
	}

	// Create wait queue entry that notifies a channel for readable, keepalive response, and error events.
	notifyCh := make(chan waiter.EventMask, 1)
	waitEntry := waiter.NewFunctionEntry(waiter.ReadableEvents|waiter.EventKeepAliveResponse|waiter.EventKeepAliveSent|waiter.EventErr, func(mask waiter.EventMask) {
		select {
		case notifyCh <- mask:
		default:
		}
	})
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	var lastSent time.Time
	sweepsRemaining := 3
	rw.Write([]byte(fmt.Sprintf("%d sweeps, max %d hops:\n\n", sweepsRemaining, maxHops)))

outerLoop:
	for {
		var buf bytes.Buffer
		select {
		case <-time.After(3 * time.Second):
			log.Printf("%p: timeout", ep)
			rw.Write([]byte(fmt.Sprintf("%d: timeout\n", currentTTL)))
			incrementTTL()
			if currentTTL > maxHops {
				log.Printf("%p: resetting TTL", ep)
				updateTTL(1)
				sweepsRemaining--
				if sweepsRemaining == 0 {
					break outerLoop
				}
			}
			resetKeepalive()
		case ev := <-notifyCh:
			if ev&waiter.ReadableEvents != 0 {
				if _, err := ep.Read(&buf, tcpip.ReadOptions{}); err != nil {
					log.Printf("%p: failed to read, exiting: %v", ep, err)
					return
				}
				log.Printf("%p: ignoring %d bytes", ep, buf.Len())
			}
			if ev&waiter.EventKeepAliveSent != 0 {
				lastSent = time.Now()
				log.Printf("%p: keepalive sent", ep)
			}
			if ev&waiter.EventKeepAliveResponse != 0 {
				delta := time.Now().Sub(lastSent)
				log.Printf("%p: keepalive response received", ep)
				rw.Write([]byte(fmt.Sprintf("%d: got response from %v after %v\n\n", currentTTL, remote.Addr, delta)))
				updateTTL(1)
				resetKeepalive()
				sweepsRemaining--
				if sweepsRemaining == 0 {
					break outerLoop
				}
			}
			if ev&waiter.EventErr != 0 {
				for {
					err := ep.SocketOptions().DequeueErr()
					if err == nil {
						break
					}
					delta := time.Now().Sub(lastSent)
					log.Printf("%p: error received: %v (orig dst: %v, offender: %v, control source: %v)", ep, err.Err, err.Dst, err.Offender, err.ControlSrc)
					rw.Write([]byte(fmt.Sprintf("%d: got error (%v) from %v after %v\n", currentTTL, err.Err, err.ControlSrc.Addr, delta)))
					incrementTTL()
					resetKeepalive()
				}
			}
		}
	}
	rw.Write([]byte("bye!\r\n"))
}

func main() {
	flag.Parse()
	if len(flag.Args()) != 3 {
		log.Fatal("Usage: ", os.Args[0], " <tun-device> <local-address> <local-port>")
	}

	tunName := flag.Arg(0)
	addrName := flag.Arg(1)
	portName := flag.Arg(2)

	// Parse the mac address.
	maddr, err := net.ParseMAC(*mac)
	if err != nil {
		log.Fatalf("Bad MAC address: %v", *mac)
	}

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
	if *tap {
		fd, err = tun.OpenTAP(tunName)
	} else {
		fd, err = tun.Open(tunName)
	}
	if err != nil {
		log.Fatal(err)
	}

	linkEP, err := fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            mtu,
		EthernetHeader: *tap,
		Address:        tcpip.LinkAddress(maddr),
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
