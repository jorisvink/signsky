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
#define PACKETS_PER_EVENT		64

static void	clear_drop_access(void);
static void	clear_recv_packets(int);
static void	clear_send_packet(int, struct signsky_packet *);

/* Temporary packet for when the packet pool is empty. */
static struct signsky_packet	tpkt;

/* The local queues. */
static struct signsky_proc_io	*io = NULL;

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
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	clear_drop_access();

	signsky_signal_trap(SIGQUIT);
	signsky_signal_ignore(SIGINT);

	fd = signsky_platform_tundev_create();
	pfd.fd = fd;
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
			clear_recv_packets(fd);

		while ((pkt = signsky_ring_dequeue(io->clear)))
			clear_send_packet(fd, pkt);

#if !defined(SIGNSKY_HIGH_PERFORMANCE)
		usleep(500);
#endif
	}

	close(fd);

	syslog(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to the queues and fds it does not need.
 */
static void
clear_drop_access(void)
{
	signsky_shm_detach(io->tx);
	signsky_shm_detach(io->rx);
	signsky_shm_detach(io->arwin);
	signsky_shm_detach(io->crypto);
	signsky_shm_detach(io->decrypt);

	io->tx = NULL;
	io->rx = NULL;
	io->arwin = NULL;
	io->crypto = NULL;
	io->decrypt = NULL;
}

/*
 * Send the given packet onto the clear interface.
 * This function will return the packet to the packet pool.
 */
static void
clear_send_packet(int fd, struct signsky_packet *pkt)
{
	ssize_t		ret;

	PRECOND(fd >= 0);
	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SIGNSKY_PROC_CLEAR);

	for (;;) {
		if ((ret = signsky_platform_tundev_write(fd, pkt)) == -1) {
			if (errno == EINTR)
				continue;
			if (errno == EIO)
				break;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			fatal("%s: write(): %s", __func__, errno_s);
		}

		signsky_atomic_add(&signsky->rx.pkt, 1);
		signsky_atomic_add(&signsky->rx.bytes, pkt->length);
		signsky_atomic_write(&signsky->rx.last, signsky->uptime);

		break;
	}

	signsky_packet_release(pkt);
}

/*
 * Read up to PACKETS_PER_EVENT number of packets, queueing them up
 * for encryption via the encryption queue.
 */
static void
clear_recv_packets(int fd)
{
	int				idx;
	ssize_t				ret;
	struct signsky_packet		*pkt;

	PRECOND(fd >= 0);

	for (idx = 0; idx < PACKETS_PER_EVENT; idx++) {
		if ((pkt = signsky_packet_get()) == NULL)
			pkt = &tpkt;

		if ((ret = signsky_platform_tundev_read(fd, pkt)) == -1) {
			if (pkt != &tpkt)
				signsky_packet_release(pkt);
			if (errno == EINTR)
				continue;
			if (errno == EIO)
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

		pkt->length = ret;
		pkt->target = SIGNSKY_PROC_ENCRYPT;

		if (signsky_ring_queue(io->encrypt, pkt) == -1)
			signsky_packet_release(pkt);
	}
}
