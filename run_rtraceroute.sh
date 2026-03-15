#!/bin/bash
set -e

RUNAS=nobody
DEVICE=tun-$RUNAS
PREFIX=10.128.0
V6PREFIX=2a0a:1100:1139:4

ip tuntap add user $RUNAS mode tun $DEVICE
ip link set $DEVICE up
ip addr add $PREFIX.1/24 dev $DEVICE
ip -6 addr add $V6PREFIX::1/64 dev $DEVICE

function on_exit {
  echo Cleaning up:
  ip -6 addr del $V6PREFIX::1/64 dev $DEVICE
  ip addr del $PREFIX.1/24 dev $DEVICE
  ip link set $DEVICE down
  ip tuntap del mode tun $DEVICE
}
trap on_exit EXIT

sudo -u $RUNAS ./rtraceroute --device=$DEVICE --address=$PREFIX.2 --port=3001 "$@"
#sudo -u $RUNAS ./rtraceroute "$@" $DEVICE $V6PREFIX::2 3001
