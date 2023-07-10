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

static void	crypto_drop_access(void);
static void	crypto_recv_packets(int);
static int	crypto_bind_address(void);
static void	crypto_send_packet(int, struct signsky_packet *);

/* Temporary packet for when the packet pool is empty. */
static struct signsky_packet	tpkt;

/* The local queues. */
static struct signsky_proc_io	*io = NULL;

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
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	crypto_drop_access();

	signsky_signal_trap(SIGQUIT);
	signsky_signal_ignore(SIGINT);

	fd = crypto_bind_address();

	pfd.fd = fd;
	pfd.revents = 0;
	pfd.events = POLLIN;

	running = 1;
	signsky_proc_privsep(proc);

	while (running) {
		if ((sig = signsky_last_signal()) != -1) {
			syslog(LOG_NOTICE, "received signal %d", sig);
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

		while ((pkt = signsky_ring_dequeue(io->crypto)))
			crypto_send_packet(fd, pkt);

		usleep(10);
	}

	syslog(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to the queues and fds it does not need.
 */
static void
crypto_drop_access(void)
{
	signsky_shm_detach(io->tx);
	signsky_shm_detach(io->rx);
	signsky_shm_detach(io->clear);
	signsky_shm_detach(io->encrypt);

	io->tx = NULL;
	io->rx = NULL;
	io->clear = NULL;
	io->encrypt = NULL;
}

/*
 * Setup the crypto interface by creating a new socket, binding
 * it locally to the specified port and connecting it to the remote peer.
 */
static int
crypto_bind_address(void)
{
	int		fd, val;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		fatal("%s: socket: %s", __func__, errno_s);

	signsky->local.sin_family = AF_INET;

	if (bind(fd, (struct sockaddr *)&signsky->local,
	    sizeof(signsky->local)) == -1)
		fatal("%s: connect: %s", __func__, errno_s);

	if ((val = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("%s: fcntl: %s", __func__, errno_s);

	val |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, val) == -1)
		fatal("%s: fcntl: %s", __func__, errno_s);

#if defined(__linux__)
	val = IP_PMTUDISC_DO;
	if (setsockopt(fd, IPPROTO_IP,
	    IP_MTU_DISCOVER, &val, sizeof(val)) == -1)
		fatal("%s: setsockopt: %s", __func__, errno_s);
#else
	val = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(val)) == -1)
		fatal("%s: setsockopt: %s", __func__, errno_s);
#endif

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
	PRECOND(pkt->target == SIGNSKY_PROC_CRYPTO);

	for (;;) {
		data = signsky_packet_head(pkt);

		if ((ret = sendto(fd, data, pkt->length, 0,
		    (struct sockaddr *)&signsky->peer,
		    sizeof(signsky->peer))) == -1) {
			if (errno == EINTR)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			if (errno == ENETUNREACH || errno == EHOSTUNREACH) {
				syslog(LOG_INFO, "host %s unreachable (%s)",
				    inet_ntoa(signsky->peer.sin_addr),
				    errno_s);
				break;
			}
			fatal("sendto: %s", errno_s);
		}

		break;
	}

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
		data = signsky_packet_head(pkt);

		if ((ret = recvfrom(fd, data, SIGNSKY_PACKET_DATA_LEN, 0,
		    (struct sockaddr *)&peer, &socklen)) == -1) {
			if (pkt != &tpkt)
				signsky_packet_release(pkt);
			if (errno == EINTR || errno == EIO)
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
		pkt->target = SIGNSKY_PROC_DECRYPT;

		if (signsky_ring_queue(io->decrypt, pkt) == -1)
			signsky_packet_release(pkt);
	}
}
