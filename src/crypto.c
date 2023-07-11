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
static int	crypto_arwin_check(struct signsky_packet *);
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
	struct sockaddr_in	peer;
	u_int8_t		*data;

	PRECOND(fd >= 0);
	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SIGNSKY_PROC_CRYPTO);

	peer.sin_family = AF_INET;
	peer.sin_port = signsky_atomic_read(&signsky->peer_port);
	peer.sin_addr.s_addr = signsky_atomic_read(&signsky->peer_ip);

	if (peer.sin_addr.s_addr == 0) {
		signsky_packet_release(pkt);
		return;
	}

	for (;;) {
		data = signsky_packet_head(pkt);

		if ((ret = sendto(fd, data, pkt->length, 0,
		    (struct sockaddr *)&peer, sizeof(peer))) == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			if (errno == EMSGSIZE) {
				syslog(LOG_INFO,
				    "packet (size=%zu) too large for crypto, "
				    "lower tunnel MTU", pkt->length);
				break;
			}
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
	u_int8_t		*data;
	socklen_t		socklen;

	PRECOND(fd >= 0);

	for (idx = 0; idx < PACKETS_PER_EVENT; idx++) {
		if ((pkt = signsky_packet_get()) == NULL)
			pkt = &tpkt;

		socklen = sizeof(pkt->addr);
		data = signsky_packet_head(pkt);

		if ((ret = recvfrom(fd, data, SIGNSKY_PACKET_DATA_LEN, 0,
		    (struct sockaddr *)&pkt->addr, &socklen)) == -1) {
			if (pkt != &tpkt)
				signsky_packet_release(pkt);
			if (errno == EINTR)
				continue;
			if (errno == EIO)
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

		if (crypto_arwin_check(pkt) == -1) {
			signsky_packet_release(pkt);
			continue;
		}

		if (signsky_ring_queue(io->decrypt, pkt) == -1)
			signsky_packet_release(pkt);
	}
}

/*
 * Perform the initial anti-replay check before we move it forward
 * to our decryption process. We only check if the packet falls
 * inside of the anti-replay window here, the rest is up to
 * the decryption process.
 *
 * We need to account for the fact that the decryption worker could
 * have up to 1023 queued packets in worst case scenario.
 */
static int
crypto_arwin_check(struct signsky_packet *pkt)
{
	u_int32_t			seq;
	struct signsky_ipsec_hdr	*hdr;
	u_int64_t			pn, last;

	PRECOND(pkt != NULL);

	if (signsky_packet_crypto_checklen(pkt) == -1)
		return (-1);

	hdr = signsky_packet_head(pkt);
	seq = be32toh(hdr->esp.seq);
	pn = be64toh(hdr->pn);

	if ((pn & 0xffffffff) != seq)
		return (-1);

	last = signsky_atomic_read(&io->arwin->last);

	if (pn > last)
		return (0);

	if (pn > 0 && (SIGNSKY_ARWIN_SIZE + 1023) > last - pn)
		return (0);

	syslog(LOG_INFO, "dropped too old packet (seq=0x%08llx)", pn);

	return (-1);
}
