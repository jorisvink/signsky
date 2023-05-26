/*
 * Copyright (c) 2023 Joris Vink <joris@coders.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "signsky.h"

/* The number of packets in a single run we try to read. */
#define PACKETS_PER_EVENT		32

static void	clear_recv_packets(int);
static void	clear_send_packet(int, struct signsky_packet *);

/* Temporary packet for when the packet pool is empty. */
static struct signsky_packet	tpkt;

/*
 * The process responsible for receiving packets on the clear side
 * and submitting them to the encryption worker.
 */
void
signsky_clear_entry(struct signsky_proc *proc)
{
	struct pollfd			pfd;
	struct signsky_packet		*pkt;
	int				fd, sig, running;

	PRECOND(proc != NULL);

	signsky_signal_trap(SIGQUIT);
	signsky_signal_ignore(SIGINT);

	fd = signsky_platform_tundev_create();

	pfd.fd = fd;
	pfd.events = POLLIN;

	running = 1;

	while (running) {
		if ((sig = signsky_last_signal()) != -1) {
			printf("%s received signal %d\n", proc->name, sig);
			switch (sig) {
			case SIGQUIT:
				running = 0;
				continue;
			}
		}

		if (poll(&pfd, 1, 0) == -1) {
			if (errno == EINTR)
				continue;
			fatal("poll: %s", errno_s);
		}

		if (pfd.revents & POLLIN)
			clear_recv_packets(fd);

		while ((pkt = signsky_ring_dequeue(&signsky->clear_tx)))
			clear_send_packet(fd, pkt);

		usleep(10);
	}

	close(fd);

	printf("%s exiting\n", proc->name);

	exit(0);
}

/*
 * Send the given packet onto the clear interface.
 * This function will return the packet to the packet pool.
 */
static void
clear_send_packet(int fd, struct signsky_packet *pkt)
{
	ssize_t		ret;
	u_int8_t	*data;

	PRECOND(fd >= 0);
	PRECOND(pkt != NULL);

	for (;;) {
		/* XXX, take this from ESP next proto header later */
		data = signsky_packet_info(pkt);

		data[0] = 0x0;
		data[1] = 0x0;
		data[2] = SIGNSKY_PACKET_PROTO_IP4 >> 8;
		data[3] = SIGNSKY_PACKET_PROTO_IP4 & 0xff;

		if ((ret = write(fd, data, pkt->length + 4)) == -1) {
			if (errno == EINTR)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fatal("%s: write(): %s", __func__, errno_s);
		}

		break;
	}

	printf("clear-tx %p (%zd/%zu)\n", (void *)pkt, ret, pkt->length);

	signsky_packet_release(pkt);
}

/*
 * Read up to PACKETS_PER_EVENT number of packets, queueing them up
 * for encryption via the encryption queue.
 */
static void
clear_recv_packets(int fd)
{
	int			idx;
	ssize_t			ret;
	struct signsky_packet	*pkt;
	u_int8_t		*data;

	PRECOND(fd >= 0);

	for (idx = 0; idx < PACKETS_PER_EVENT; idx++) {
		if ((pkt = signsky_packet_get()) == NULL)
			pkt = &tpkt;

		/*
		 * When reading from a tunnel device we have 4 bytes of
		 * extra information at the start from the kernel which
		 * informs us about the protocol.
		 */
		data = signsky_packet_info(pkt);

		if ((ret = read(fd, data,
		    SIGNSKY_PACKET_INFO_LEN + SIGNSKY_PACKET_MAX_LEN)) == -1) {
			if (pkt != &tpkt)
				signsky_packet_release(pkt);
			if (errno == EINTR)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fatal("%s: read(): %s", __func__, errno_s);
		}

		if (ret == 0)
			fatal("eof on tunnel interface");

		if (ret <= SIGNSKY_PACKET_MIN_LEN) {
			if (pkt != &tpkt)
				signsky_packet_release(pkt);
			continue;
		}

		if (pkt == &tpkt)
			continue;

		/* Store the protocol for later. */
		memcpy(&pkt->protocol, data, sizeof(pkt->protocol));

		/* Remove the packet information (see above). */
		pkt->length = ret - SIGNSKY_PACKET_INFO_LEN;

		if (signsky_ring_queue(&signsky->encrypt_queue, pkt) == -1)
			signsky_packet_release(pkt);
	}
}
