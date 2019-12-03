// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Synopsys, Inc. and/or its affiliates.
 * Synopsys TPerf Application
 *
 * Author: Jose Abreu <joabreu@synopsys.com>
 * Inspired-by: https://patchwork.ozlabs.org/patch/808507/
 */

#include <argp.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define MAX_FRAME_SIZE		1500
#define RCV_FRAME_SIZE		(sizeof(struct ethhdr) + MAX_FRAME_SIZE)

static uint8_t multicast_macaddr[] = { 0xBB, 0xAA, 0xBB, 0xAA, 0xBB, 0xAA };
static uint8_t terminate_magic[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
static ssize_t terminate_size = 8;
static char ifname[IFNAMSIZ];
static uint64_t data_count;
static int is_server;
static int arg_count;
static int prio;

struct avtp_chdr {
	uint64_t subtype:7;
	uint64_t cd_indicator:1;
	union {
		struct {
			uint64_t control_data:4;
		} control;
		struct {
			uint64_t timestamp_valid:1;
			uint64_t gateway_valid:1;
			uint64_t reserved0:1;
			uint64_t reset:1;
		} data;
	} tsd1;
	uint64_t version:3;
	uint64_t sid_valid:1;
	union {
		struct {
			uint64_t control_data_length:11;
			uint64_t status:5;
		} control;
		struct {
			uint64_t seq_number:8;
			uint64_t timestamp_uncertain:1;
			uint64_t reserved1:7;
		} data;
	} tsd2;
	uint64_t stream_id;
	union {
		struct {
			uint8_t payload[0];
		} control;
		struct {
			uint64_t timestamp:32;
			uint64_t gateway_info:32;
			uint64_t length:16;
			uint64_t psh:16;
			uint8_t payload[0];
		} data;
	} pbs;
} __attribute__((packed));

static struct argp_option options[] = {
	{ "ifname", 'i', "IFNAME", 0, "Network Interface" },
	{ "server", 's', 0, 0, "Run in server mode" },
	{ "priority", 'p', "NUM", 0, "SO_PRIORITY to be set in socket or to listen to packets" },
	{ 0 }
};

static error_t parser(int key, char *arg, struct argp_state *s)
{
	switch (key) {
	case 'i':
		strncpy(ifname, arg, sizeof(ifname) - 1);
		arg_count++;
		break;
	case 's':
		is_server = 1;
		break;
	case 'p':
		prio = atoi(arg);
		if (prio < 0)
			argp_failure(s, 1, 0, "Priority must be >= 0\n");
		arg_count++;
		break;
	case ARGP_KEY_END:
		if (arg_count < 2)
			argp_failure(s, 1, 0, "Options missing. Check --help");
		break;
	}

	return 0;
}

static struct argp argp = { options, parser };

static void hex_dump(uint8_t *data, ssize_t size)
{
	uint64_t *ptr = (uint64_t *)data;
	int i;

	if (size <= 0)
		return;

	for (i = 0; i < (size / sizeof(*ptr)); i += sizeof(*ptr))
		printf("%4lx: %16lx\n", i * sizeof(*ptr), *ptr++);
}

static void build_header(uint8_t *data, int end)
{
	struct avtp_chdr *avtphdr;
	uint8_t *header = data;

	avtphdr = (struct avtp_chdr *)header;
	memset(avtphdr, 0, sizeof(*avtphdr));

	avtphdr->subtype = 0x7f;
	avtphdr->version = 0;

	if (end) {
		uint8_t *buf = avtphdr->pbs.control.payload;

		avtphdr->cd_indicator = 1;
		memcpy(buf, terminate_magic, terminate_size);
	}
}

static int parse_header(uint8_t *data, int end)
{
	uint8_t *header = data + sizeof(struct ethhdr);
	struct avtp_chdr *avtphdr;

	avtphdr = (struct avtp_chdr *)header;
	if (avtphdr->cd_indicator) {
		uint8_t *buf = avtphdr->pbs.control.payload;

		return !memcmp(buf, terminate_magic, terminate_size);
	}

	return 0;
}

static int setup_server_socket(void)
{
	struct sockaddr_ll sk_addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_TSN),
	};
	struct packet_mreq mreq = { 0 };
	struct ifreq req;
	int fd;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_TSN));
	if (fd < 0) {
		perror("Failed to open socket");
		return -1;
	}

	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name) - 1);
	if (ioctl(fd, SIOCGIFINDEX, &req) < 0) {
		perror("Failed to get interface index");
		goto err;
	}

	sk_addr.sll_ifindex = req.ifr_ifindex;
	if (bind(fd, (struct sockaddr *)&sk_addr, sizeof(sk_addr))) {
		perror("Failed to bind socket");
		goto err;
	}

	mreq.mr_ifindex = sk_addr.sll_ifindex;
	mreq.mr_type = PACKET_MR_MULTICAST;
	mreq.mr_alen = ETH_ALEN;
	memcpy(&mreq.mr_address, multicast_macaddr, ETH_ALEN);

	if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
		       &mreq, sizeof(mreq)) < 0) {
		perror("Failed to add multicast membership");
		goto err;
	}
	
	return fd;
err:
	close(fd);
	return -1;
}

static int setup_timer(void)
{
	struct itimerspec tspec = { 0 };
	int fd;

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		perror("Failed to create timer");
		return -1;
	}

	tspec.it_value.tv_sec = 1;
	tspec.it_interval.tv_sec = 1;

	if (timerfd_settime(fd, 0, &tspec, NULL) < 0) {
		perror("Failed to set timer settings");
		close(fd);
		return -1;
	}

	return fd;
}

static int recv_packet(int fd)
{
	uint8_t *data = alloca(RCV_FRAME_SIZE);
	ssize_t n;

	n = recv(fd, data, RCV_FRAME_SIZE, 0);
	if (n < 0) {
		perror("Failed to recv() from socket");
		return 1;
	}

	if (n < RCV_FRAME_SIZE) {
		printf("Size mismatch: expected %ld, got %zd\n",
		       RCV_FRAME_SIZE, n);
	} else {
		if (parse_header(data, n)) {
			printf("Terminating\n");
			return 1;
		} else if (data_count == 0) {
			hex_dump(data, n);
		}
	}

	data_count += n;
	return 0;
}

static void report_bw(int fd, int curr_sec)
{
	uint64_t expirations;
	ssize_t n;

	n = read(fd, &expirations, sizeof(expirations));
	if (n < 0) {
		perror("Failed to read timer");
		return;
	}

	if (expirations != 1)
		printf("Invalid expirations count for timer\n");

	if (data_count)
		printf("[ %2d ] Data rate: %zu Mbps\n", curr_sec,
		       (data_count * 8) / 1000 / 1000);

	data_count = 0;
}

static int server_loop(void)
{
	int sk_fd, timer_fd, ret = 0, sec_count = 0;
	struct pollfd fds[2];

	sk_fd = setup_server_socket();
	if (sk_fd < 0)
		return -1;

	timer_fd = setup_timer();
	if (timer_fd < 0) {
		close(sk_fd);
		return 1;
	}

	fds[0].fd = sk_fd;
	fds[0].events = POLLIN;
	fds[1].fd = timer_fd;
	fds[1].events = POLLIN;

	printf("Waiting for packets ...\n");
	while (1) {
		ret = poll(fds, 2, -1);
		if (ret < 0) {
			perror("Failed to poll()");
			goto err;
		}

		ret = 0;

		if (fds[0].revents & POLLIN) {
			if (recv_packet(fds[0].fd))
				break;
		}
		if (fds[1].revents & POLLIN) {
			report_bw(fds[1].fd, sec_count++);
		}
	}

err:
	close(timer_fd);
	close(sk_fd);
	return ret;
}

static int client_loop(void)
{
	struct sockaddr_ll dst_ll_addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_TSN),
		.sll_halen = ETH_ALEN,
	};
	int sk_fd, timer_fd, ret = 0, sec_count = 0;
	struct pollfd fds;
	struct ifreq req;
	uint8_t *payload;

	sk_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_TSN));
	if (sk_fd < 0) {
		perror("Failed to open socket");
		return -1;
	}

	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name) - 1);
	if (ioctl(sk_fd, SIOCGIFINDEX, &req) < 0) {
		perror("Failed to get interface index");
		close(sk_fd);
		return -1;
	}

	if (setsockopt(sk_fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio)) < 0) {
		perror("Failed to set socket priority");
		close(sk_fd);
		return -1;
	}

	timer_fd = setup_timer();
	if (timer_fd < 0) {
		close(sk_fd);
		return -1;
	}

	dst_ll_addr.sll_ifindex = req.ifr_ifindex;
	memcpy(&dst_ll_addr.sll_addr, multicast_macaddr, ETH_ALEN);
	payload = alloca(MAX_FRAME_SIZE);
	memset(payload, 0xAB, MAX_FRAME_SIZE);

	build_header(payload, 0);

	fds.fd = timer_fd;
	fds.events = POLLIN;

	printf("Sending packets ...\n");
	while (sec_count < 10) {
		ssize_t n = sendto(sk_fd, payload, MAX_FRAME_SIZE, 0,
				   (struct sockaddr *)&dst_ll_addr,
				   sizeof(dst_ll_addr));
		if (n < 0)
			perror("Failed to send data");

		data_count += n;

		ret = poll(&fds, 1, 0);
		if (ret < 0) {
			perror("Failed to poll()");
			ret = 1;
			goto err;
		}

		ret = 0;

		if (fds.revents & POLLIN) {
			report_bw(timer_fd, sec_count++);
		}
	}

err:
	sleep(1);
	build_header(payload, 1);
	ret = sendto(sk_fd, payload, MAX_FRAME_SIZE, 0,
		     (struct sockaddr *)&dst_ll_addr, sizeof(dst_ll_addr));
	sleep(1);
	close(timer_fd);
	close(sk_fd);
	return ret < 0 ? ret : 0;
}

int main(int argc, char **argv)
{
	int ret;

	/* Run in client mode by default */
	is_server = 0;
	arg_count = 0;
	data_count = 0;
	prio = -1;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);

	if (is_server) {
		ret = server_loop();
	} else {
		ret = client_loop();
	}

	exit(ret);
}
