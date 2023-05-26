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

#include <arpa/inet.h>
#include <netinet/in.h>

#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "signsky.h"

/* The number of packets in a single run we try to read. */
#define PACKETS_PER_EVENT		32

static void	crypto_recv_packets(int);
static int	crypto_bind_address(void);
static void	crypto_send_packet(int, struct signsky_packet *);

/* Temporary packet for when the packet pool is empty. */
static struct signsky_packet	tpkt;

/*
 * The process responsible for receiving packets on the crypto side
 * and submitting them to the decryption worker.
 */
void
signsky_crypto_entry(struct signsky_proc *proc)
{
	struct pollfd			pfd;
	struct signsky_packet		*pkt;
	int				fd, sig, running;

	PRECOND(proc != NULL);

	signsky_signal_trap(SIGQUIT);
	signsky_signal_ignore(SIGINT);

	fd = crypto_bind_address();

	pfd.fd = fd;
	pfd.revents = 0;
	pfd.events = POLLIN;

	running = 1;

	while (running) {
		if ((sig = signsky_last_signal()) != -1) {
			printf("ifc-crypto received signal %d\n", sig);
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
			crypto_recv_packets(fd);

		while ((pkt = signsky_ring_dequeue(&signsky->crypto_tx)))
			crypto_send_packet(fd, pkt);

		usleep(10);
	}

	printf("ifc-crypto exiting\n");

	exit(0);
}

/*
 * Setup the crypto interface by creating a new socket, binding
 * it locally to the specified port and connecting it to the remote peer.
 */
static int
crypto_bind_address(void)
{
	struct sockaddr_in	sin;
	int			fd, flags;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("%s: socket: %s", __func__, errno_s);

	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = signsky->peer.sin_port;

	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		fatal("%s: connect: %s", __func__, errno_s);

	if (fcntl(fd, F_GETFL, &flags) == -1)
		fatal("%s: fcntl: %s", __func__, errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("%s: fcntl: %s", __func__, errno_s);

	return (fd);
}

/*
 * Send the given packet onto the crypto interface.
 * This function will return the packet to the packet pool.
 */
static void
crypto_send_packet(int fd, struct signsky_packet *pkt)
{
	ssize_t			ret;
	u_int8_t		*data;

	PRECOND(fd >= 0);
	PRECOND(pkt != NULL);

	for (;;) {
		data = signsky_packet_data(pkt);

		if ((ret = sendto(fd, data, pkt->length, 0,
		    (struct sockaddr *)&signsky->peer,
		    sizeof(signsky->peer))) == -1) {
			if (errno == EINTR)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fatal("sendto: %s", errno_s);
		}

		break;
	}

	printf("crypto-tx %p (%zd/%zu)\n", (void *)pkt, ret, pkt->length);

	signsky_packet_release(pkt);
}

/*
 * Read up to PACKETS_PER_EVENT number of packets, queueing them up
 * for decryption via the decryption queue.
 */
static void
crypto_recv_packets(int fd)
{
	int			idx;
	ssize_t			ret;
	struct signsky_packet	*pkt;
	struct sockaddr_in	peer;
	u_int8_t		*data;
	socklen_t		socklen;

	PRECOND(fd >= 0);

	for (idx = 0; idx < PACKETS_PER_EVENT; idx++) {
		if ((pkt = signsky_packet_get()) == NULL)
			pkt = &tpkt;

		socklen = sizeof(peer);
		data = signsky_packet_data(pkt);

		if ((ret = recvfrom(fd, data, SIGNSKY_PACKET_DATA_LEN, 0,
		    (struct sockaddr *)&peer, &socklen)) == -1) {
			if (pkt != &tpkt)
				signsky_packet_release(pkt);
			if (errno == EINTR)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fatal("read error: %s", errno_s);
		}

		if (ret == 0)
			fatal("eof on crypto interface");

		if (pkt == &tpkt)
			continue;

		pkt->length = ret;
		printf("crypto-rx %p %zd\n", (void *)pkt, pkt->length);
		printf("  |-> from %s (%u)\n", inet_ntoa(peer.sin_addr),
		    htons(peer.sin_port));

		if (signsky_ring_queue(&signsky->decrypt_queue, pkt) == -1)
			signsky_packet_release(pkt);
	}
}
