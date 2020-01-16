// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Synopsys, Inc. and/or its affiliates.
 * Synopsys TPerf Application
 *
 * Author: Jose Abreu <joabreu@synopsys.com>
 * Inspired-by: https://patchwork.ozlabs.org/patch/808507/
 */

#define _GNU_SOURCE
#include <argp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/errqueue.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/net_tstamp.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <sys/timex.h>
#include <time.h>
#include <unistd.h>

#define NSEC_PER_SEC		1000000000ULL
#define MIN_PERIOD		100000
#define MIN_DELAY		100000
#define DEFAULT_PRIORITY	0
#define DEFAULT_CPU		0
#define DEFAULT_TTR		10
#define MAX_FRAME_SIZE		1500
#define RCV_FRAME_SIZE		(sizeof(struct ethhdr) + MAX_FRAME_SIZE)

static uint8_t multicast_macaddr[] = { 0xBB, 0xAA, 0xBB, 0xAA, 0xBB, 0xAA };
static uint8_t terminate_magic[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
static ssize_t terminate_size = 8;
static int period_ns = MIN_PERIOD;
static int delay_ns = MIN_DELAY;
static uint64_t packet_drop_unknown = 0;
static uint64_t packet_drop_invalid = 0;
static uint64_t packet_drop_missed = 0;
static uint64_t packet_drop = 0;
static uint64_t packet_sent = 0;
static char ifname[IFNAMSIZ];
static uint64_t data_count;
static uint64_t last_rxtime = 0;
static uint64_t rxdelta_sum = 0;
static uint64_t rxdelta_cnt = 0;
static int priority = DEFAULT_PRIORITY;
static int cpu = DEFAULT_CPU;
static int sec_count = 0;
static int use_txtime;
static int is_server;
static int server_closed = 0;
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
	{ "txtime", 't', 0, 0, "Use SO_TXTIME flag" },
	{ "period", 'n', "NUM", 0, "Period in ns if txtime is set" },
	{ "delay", 'd', "NUM", 0, "Delay in ns if txtime is set" },
	{ "cpu", 'c', "NUM", 0, "CPU to run on" },
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
	case 't':
		use_txtime = 1;
		break;
	case 'n':
		period_ns = atoi(arg);
		if (period_ns < MIN_PERIOD)
			argp_failure(s, 1, 0, "Period must be >= %d\n",
					MIN_PERIOD);
		break;
	case 'd':
		delay_ns = atoi(arg);
		if (delay_ns < MIN_DELAY)
			argp_failure(s, 1, 0, "Delay must be >= %d\n",
					MIN_DELAY);
		break;
	case 'c':
		cpu = atoi(arg);
		break;
	case ARGP_KEY_END:
		if (arg_count < 2)
			argp_failure(s, 1, 0, "Options missing. Check --help");
		break;
	}

	return 0;
}

static struct argp argp = { options, parser };

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

static void normalize(struct timespec *ts)
{
	while (ts->tv_nsec >= NSEC_PER_SEC) {
		ts->tv_sec++;
		ts->tv_nsec -= NSEC_PER_SEC;
	}
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
	struct timespec ts;
	__u64 rxtime;
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
		clock_gettime(CLOCK_TAI, &ts);
		rxtime = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;

		if (last_rxtime) {
			rxdelta_sum += rxtime - last_rxtime;
			rxdelta_cnt++;
		}

		last_rxtime = rxtime;

		if (parse_header(data, n)) {
			printf("Terminating\n");
			return 1;
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
		printf("[ %2d ] Data rate: %zu Bytes, %ld packets (%zu Mbps)\n",
			curr_sec, data_count, data_count / MAX_FRAME_SIZE,
			(data_count * 8) / 1000 / 1000);
	if (is_server && rxdelta_cnt)
		printf("[ %2d ] Packet delta: %lu ns\n", curr_sec,
			rxdelta_sum / rxdelta_cnt);

	data_count = 0;
}

static void *reporter(void *arg)
{
	struct pollfd fds[1];
	int ret, fd;

	fd = setup_timer();
	if (fd < 0)
		return NULL;

	fds[0].fd = fd;
	fds[0].events = POLLIN;

	while (is_server || (sec_count < DEFAULT_TTR)) {
		ret = poll(fds, 1, 100);
		if (ret < 0) {
			perror("Failed to poll()");
			break;
		}

		if (fds[0].revents & POLLIN)
			report_bw(fd, sec_count++);
		if (server_closed)
			break;
	}

	close(fd);
	return NULL;
}

static int server_loop(void)
{
	int sk_fd, ret = 0;
	struct pollfd fds[1];

	sk_fd = setup_server_socket();
	if (sk_fd < 0)
		return -1;

	fds[0].fd = sk_fd;
	fds[0].events = POLLIN;

	printf("Waiting for packets ...\n");
	while (1) {
		ret = poll(fds, 1, -1);
		if (ret < 0) {
			perror("Failed to poll()");
			goto err;
		}

		ret = 0;

		if (fds[0].revents & POLLIN) {
			if (recv_packet(fds[0].fd))
				break;
		}
	}

err:
	server_closed = 1;
	close(sk_fd);
	return ret;
}

static int send_packet(int sk_fd, void *buf, int len, struct sockaddr_ll *addr,
		       __u64 txtime)
{
	char control[CMSG_SPACE(sizeof(txtime))] = { };
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;

	iov.iov_base = buf;
	iov.iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = addr;
	msg.msg_namelen = sizeof(*addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (use_txtime) {
		msg.msg_control = control;
		msg.msg_controllen = sizeof(control);

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_TXTIME;
		cmsg->cmsg_len = CMSG_LEN(sizeof(__u64));
		*((__u64 *) CMSG_DATA(cmsg)) = txtime;
	}

	return sendmsg(sk_fd, &msg, 0);
}

static int parse_err(struct sock_extended_err *err)
{
	__u64 tstamp = 0;

	if (err->ee_origin != SO_EE_ORIGIN_TXTIME) {
		packet_drop_unknown++;
		return 0;
	}

	tstamp = ((__u64) err->ee_data << 32) + err->ee_info;
	switch(err->ee_code) {
	case SO_EE_CODE_TXTIME_INVALID_PARAM:
		packet_drop_invalid++;
		break;
	case SO_EE_CODE_TXTIME_MISSED:
		packet_drop_missed++;
		break;
	default:
		fprintf(stderr,
			"packet with tstamp %llu dropped due to unknown error %d\n",
			tstamp, err->ee_code);
		packet_drop_unknown++;
		break;
	}

	return -1;
}

static void report_err(int sk_fd)
{
	uint8_t msg_control[CMSG_SPACE(sizeof(struct sock_extended_err))];
	unsigned char err_buffer[MAX_FRAME_SIZE];
	struct sock_extended_err *serr;
	struct iovec iov = {
		.iov_base = err_buffer,
		.iov_len = sizeof(err_buffer),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = msg_control,
		.msg_controllen = sizeof(msg_control),
	};
	struct cmsghdr *cmsg;

	if (recvmsg(sk_fd, &msg, MSG_ERRQUEUE) == -1) {
		perror("recvmsg failed");
		return;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	while (cmsg != NULL) {
		serr = (void *) CMSG_DATA(cmsg);

		if (parse_err(serr)) {
			packet_drop++;
			if (data_count >= MAX_FRAME_SIZE)
				data_count -= MAX_FRAME_SIZE;
		}

		cmsg = CMSG_NXTHDR(&msg, cmsg);
	}
}

static int client_loop(void)
{
	struct sockaddr_ll dst_ll_addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_TSN),
		.sll_halen = ETH_ALEN,
	};
	int sk_fd, ret = 0;
	struct sock_txtime sk_txtime;
	__u64 txtime, rtsum, rtcount;
	struct pollfd fds[1];
	struct timespec ts;
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

	if (use_txtime) {
		sk_txtime.clockid = CLOCK_TAI;
		sk_txtime.flags = SOF_TXTIME_REPORT_ERRORS;

		if (setsockopt(sk_fd, SOL_SOCKET, SO_TXTIME, &sk_txtime,
			       sizeof(sk_txtime)) < 0) {
			perror("Failed to set SO_TXTIME");
			close(sk_fd);
			return -1;
		}
	}

	dst_ll_addr.sll_ifindex = req.ifr_ifindex;
	memcpy(&dst_ll_addr.sll_addr, multicast_macaddr, ETH_ALEN);

	payload = alloca(MAX_FRAME_SIZE);
	memset(payload, 0xAB, MAX_FRAME_SIZE);

	build_header(payload, 0);

	fds[0].fd = sk_fd;
	fds[0].events = POLLERR | POLLOUT;

	rtsum = 0;
	rtcount = 0;

	clock_gettime(CLOCK_TAI, &ts);
	txtime = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
	txtime += delay_ns;

	printf("delay: %d, period: %d\n", delay_ns, period_ns);
	while (sec_count < DEFAULT_TTR) {
		struct timespec ts_rt1, ts_rt2;
		__u64 rt1, rt2;
		ssize_t n;

		clock_gettime(CLOCK_TAI, &ts_rt1);
		rt1 = ts_rt1.tv_sec * NSEC_PER_SEC + ts_rt1.tv_nsec;

		ret = poll(fds, 1, -1);
		if (ret == 0) {
			goto tx_time;
		} else if (ret < 0) {
			perror("Failed to poll()");
			ret = 1;
			goto err;
		}

		if (fds[0].revents & POLLOUT) {
			n = send_packet(sk_fd, payload, MAX_FRAME_SIZE,
					&dst_ll_addr, txtime);
			data_count += (n > 0) ? n : 0;
			packet_sent += (n > 0) ? 1 : 0;
		}
		if (fds[0].revents & POLLERR) {
			report_err(sk_fd);
		}

tx_time:
		ts.tv_nsec += period_ns;
		normalize(&ts);

		if (use_txtime) {
			ret = clock_nanosleep(CLOCK_TAI, TIMER_ABSTIME,
					      &ts, NULL);
			if (ret)
				break;

			txtime += period_ns;
		}

		clock_gettime(CLOCK_TAI, &ts_rt2);
		rt2 = ts_rt2.tv_sec * NSEC_PER_SEC + ts_rt2.tv_nsec;
		rtsum += rt2 - rt1;
		rtcount++;
	}

err:
	sleep(1);
	build_header(payload, 1);
	clock_gettime(CLOCK_TAI, &ts);
	txtime = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
	txtime += delay_ns;
	send_packet(sk_fd, payload, MAX_FRAME_SIZE, &dst_ll_addr, txtime);
	sleep(1);
	printf("packets: delivered: %lu (sent: %lu, dropped: %lu "
	       "[%lu invalid, %lu missed, %lu unknown])\n",
			packet_sent - packet_drop,
			packet_sent, packet_drop, packet_drop_invalid,
			packet_drop_missed, packet_drop_unknown);
	printf("packets: time per packet: %llu ns\n", rtsum / rtcount);
	close(sk_fd);
	return ret < 0 ? ret : 0;
}

static int set_realtime(pthread_t thread, int priority, int cpu)
{
	struct sched_param sp;
	cpu_set_t cpuset;
	int ret, policy;

	if (priority < 0)
		return 0;

	ret = pthread_getschedparam(thread, &policy, &sp);
	if (ret < 0) {
		perror("Failed to get schedparam");
		return ret;
	}

	printf("Default prio %d, setting to %d\n", sp.sched_priority, priority);
	sp.sched_priority = priority;

	ret = pthread_setschedparam(thread, SCHED_FIFO, &sp);
	if (ret < 0) {
		perror("Failed to set schedparam");
		return ret;
	}

	if (cpu < 0)
		return 0;

	CPU_ZERO(&cpuset);
	CPU_SET(cpu, &cpuset);

	ret = pthread_setaffinity_np(thread, sizeof(cpuset), &cpuset);
	if (ret < 0) {
		perror("Failed to set CPU affinity");
		return ret;
	}

	return 0;
}

int main(int argc, char **argv)
{
	pthread_t reporter_thread;
	int ret;

	/* Run in client mode by default */
	is_server = 0;
	arg_count = 0;
	data_count = 0;
	prio = -1;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);

	ret = set_realtime(pthread_self(), priority, cpu);
	if (ret)
		exit(ret);

	pthread_create(&reporter_thread, NULL, reporter, NULL);

	if (is_server) {
		ret = server_loop();
	} else {
		ret = client_loop();
	}

	pthread_join(reporter_thread, NULL);
	exit(ret);
}
