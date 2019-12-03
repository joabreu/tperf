# tperf - TSN Performance Tool

* Version: 0.1
* Author: Jose Abreu <joabreu@synopsys.com>
* Inspired-by: https://patchwork.ozlabs.org/patch/808507/

This tool can be used to monitor the performance of CBS by sending TSN tagged
packets to a fixed multicast address. A server mode is included which can be
used to monitor the performance on the RX path. The packets sent are assembled
using a standard AVTP packet header as defined by the IEEE 1722-2016 spec.

# Build

```
$ gcc -Wall tperf.c -o tperf
```

# Usage

First start the server. Run on remote end:
```
$ tperf -s -i <ethX> -p <priority>
```

Then run the client:
```
$ tperf -i <ethX> -p <priority>
```

Parameters:
* ethX: The interface for which to send or listen to packets
* priority: Priority to assign to the socket

The tperf application will send for 10 seconds the maximum number of packets
that the interface can handle and report the BW. Server will report how many
packets has received.

# Usage with CBS

For real CBS usage you will need to configure your NIC to the desired BW and
queue mapping.

For a NIC (eth0) with 4 queues and IP 192.168.0.2, run on remote end (server):
```
$ vconfig add eth0 100
$ vconfig add eth0 200
$ vconfig add eth0 300
$ vconfig add eth0 400
$ vconfig set_ingress_map eth0.100 0 0
$ vconfig set_ingress_map eth0.200 1 1
$ vconfig set_ingress_map eth0.300 2 2
$ vconfig set_ingress_map eth0.400 3 3
$ ifconfig eth0.100 192.168.10.2 netmask 255.255.255.0
$ ifconfig eth0.200 192.168.20.2 netmask 255.255.255.0
$ ifconfig eth0.300 192.168.30.2 netmask 255.255.255.0
$ ifconfig eth0.400 192.168.40.2 netmask 255.255.255.0
```

Then start tperf and iperf3, which will be used to prove CBS is working
correctly:
```
$ iperf3 -s &
$ tperf -s -i eth0.100 -p 0 &
$ tperf -s -i eth0.200 -p 1 &
$ tperf -s -i eth0.300 -p 2 &
$ tperf -s -i eth0.400 -p 3 &
```

To configure local VLAN parameters, run:
```
$ vconfig add eth0 100
$ vconfig add eth0 200
$ vconfig add eth0 300
$ vconfig add eth0 400
$ vconfig set_egress_map eth0.100 0 0
$ vconfig set_egress_map eth0.200 1 1
$ vconfig set_egress_map eth0.300 2 2
$ vconfig set_egress_map eth0.400 3 3
$ ifconfig eth0.100 192.168.10.1 netmask 255.255.255.0
$ ifconfig eth0.200 192.168.20.1 netmask 255.255.255.0
$ ifconfig eth0.300 192.168.30.1 netmask 255.255.255.0
$ ifconfig eth0.400 192.168.40.1 netmask 255.255.255.0
```

Then, configure CBS by running:
```
$ tc qdisc add dev eth0 clsact
$ tc filter add dev eth0 egress protocol all u32 ht 800: order 1 \
	match ip dst 192.168.0.2 action skbedit queue_mapping 0
$ tc qdisc add dev eth0 handle 100: parent root mqprio num_tc 4 \
	map 0 1 2 3 3 3 3 3 3 3 3 3 3 3 3 3 queues 1@0 1@1 1@2 1@3 hw 0
$ tc qdisc replace dev eth0 parent 100:2 cbs \
	idleslope 100000 \
	sendslope -900000 \
	hicredit 150 \
	locredit -1350 \
	offload 1
$ tc qdisc replace dev eth0 parent 100:3 cbs \
	idleslope 200000 \
	sendslope -800000 \
	hicredit 300 \
	locredit -1200 \
	offload 1
$ tc qdisc replace dev eth0 parent 100:4 cbs \
	idleslope 300000 \
	sendslope -700000 \
	hicredit 450 \
	locredit -1050 \
	offload 1
```

This will configure the NIC queues to the following settings:
* Queue 0: No BW Restriction, general traffic
* Queue 1: 10% BW, traffic priority 1
* Queue 2: 20% BW, traffic priority 2
* Queue 3: 30% BW, traffic priority 3

You can now run the tperf clients on local end:
```
$ tperf -i eth0.100 -p 0
$ iperf3 -t 35 -c 192.168.0.2 &
$ echo "Queue 1: Exp=10% of Maximum"
$ tperf -i eth0.200 -p 1
$ echo "Queue 2: Exp=20% of Maximum"
$ tperf -i eth0.300 -p 2
$ echo "Queue 3: Exp=30% of Maximum"
$ tperf -i eth0.400 -p 3

```

The tperf results shall match the specified BW and the iperf3 results will
go lower as we go upper in the CBS allocated BW, which proves that CBS traffic
is getting higher priority than General traffic.

