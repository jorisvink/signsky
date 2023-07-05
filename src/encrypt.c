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

static void	encrypt_drop_access(void);
static void	encrypt_packet_process(struct signsky_packet *);

/* The current TX sa. */
static struct signsky_sa	sa_tx;

/* The local queues. */
static struct signsky_proc_io	*io = NULL;

/*
 * The process responsible for encryption of packets coming
 * from the clear side of the tunnel.
 */
void
signsky_encrypt_entry(struct signsky_proc *proc)
{
	struct signsky_packet	*pkt;
	int			sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	encrypt_drop_access();

	signsky_signal_trap(SIGQUIT);
	signsky_signal_ignore(SIGINT);

	memset(&sa_tx, 0, sizeof(sa_tx));

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

		while ((pkt = signsky_ring_dequeue(io->encrypt)))
			encrypt_packet_process(pkt);

		usleep(10);
	}

	syslog(LOG_NOTICE, "exiting");

	exit(0);
}

static void
encrypt_drop_access(void)
{
	signsky_shm_detach(io->rx[0]);
	signsky_shm_detach(io->rx[1]);
	signsky_shm_detach(io->clear);
	signsky_shm_detach(io->decrypt);

	io->rx[0] = NULL;
	io->rx[1] = NULL;
	io->clear = NULL;
	io->decrypt = NULL;
}

static void
encrypt_packet_process(struct signsky_packet *pkt)
{
	struct signsky_ipsec_hdr	*hdr;

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SIGNSKY_PROC_ENCRYPT);

	if (signsky_atomic_read(&io->tx->valid) == 0) {
		signsky_packet_release(pkt);
		return;
	}

	hdr = signsky_packet_start(pkt);

	hdr->pn = signsky_atomic_read(&io->tx->seqnr);
	signsky_atomic_add(&io->tx->seqnr, 1);

	hdr->esp.spi = signsky_atomic_read(&io->tx->spi);
	hdr->esp.seq = hdr->pn & 0xffffffff;

//	pkt->length += sizeof(*esp);

	signsky_ring_queue(io->crypto, pkt);
}
