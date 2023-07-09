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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "signsky.h"

static void	encrypt_drop_access(void);
static void	encrypt_install_pending(void);
static void	encrypt_packet_process(struct signsky_packet *);

/* The shared queues. */
static struct signsky_proc_io	*io = NULL;

/* The local state for TX. */
static struct {
	u_int32_t		spi;
	u_int32_t		salt;
	u_int64_t		seqnr;
	void			*cipher;
} state;

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

	memset(&state, 0, sizeof(state));

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

		encrypt_install_pending();

		while ((pkt = signsky_ring_dequeue(io->encrypt)))
			encrypt_packet_process(pkt);

		usleep(10);
	}

	syslog(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to queues the encrypt process does not need.
 */
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

/*
 * Encrypt a single packet under the current TX key.
 */
static void
encrypt_packet_process(struct signsky_packet *pkt)
{
	struct signsky_ipsec_hdr	*hdr;
	struct signsky_ipsec_tail	*tail;
	size_t				overhead;
	u_int8_t			nonce[12], aad[12];

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SIGNSKY_PROC_ENCRYPT);

	/* Install any pending TX key first. */
	encrypt_install_pending();

	/* If we don't have a cipher state, we shall not submit. */
	if (state.cipher == NULL) {
		signsky_packet_release(pkt);
		return;
	}

	/* Belts and suspenders. */
	overhead = sizeof(*hdr) + sizeof(*tail) + signsky_cipher_overhead();

	if ((pkt->length + overhead < pkt->length) ||
	    (pkt->length + overhead > sizeof(pkt->buf))) {
		signsky_packet_release(pkt);
		return;
	}

	/* Fill in ESP header and t(r)ail. */
	hdr = signsky_packet_head(pkt);
	tail = signsky_packet_tail(pkt);

	hdr->pn = state.seqnr++;
	hdr->esp.spi = state.spi;
	hdr->esp.seq = hdr->pn & 0xffffffff;

	/* We don't pad, RFC says its a SHOULD not a MUST. */
	tail->pad = 0;
	tail->next = IPPROTO_IPV4;

	/* Tail is included in the plaintext. */
	pkt->length += sizeof(*tail);

	/* Prepare the nonce and aad. */
	memcpy(nonce, &state.salt, sizeof(state.salt));
	memcpy(&nonce[sizeof(state.salt)], &hdr->pn, sizeof(hdr->pn));

	memcpy(aad, &state.spi, sizeof(state.spi));
	memcpy(&aad[sizeof(state.spi)], &hdr->pn, sizeof(hdr->pn));

	/* Do the cipher dance. */
	signsky_cipher_encrypt(state.cipher, nonce, sizeof(nonce),
	    aad, sizeof(aad), pkt);

	/* Account for the header. */
	VERIFY(pkt->length + sizeof(*hdr) < sizeof(pkt->buf));
	pkt->length += sizeof(*hdr);

	/* Ship it. */
	signsky_ring_queue(io->crypto, pkt);
}

/*
 * Check if there is a pending TX key, and if there is cleanup the
 * previous cipher state, setup a new one and swap the key out.
 */
static void
encrypt_install_pending(void)
{
	PRECOND(io != NULL);
	PRECOND(io->tx != NULL);

	if (signsky_atomic_read(&io->tx->state) != SIGNSKY_KEY_PENDING)
		return;

	if (!signsky_atomic_cas_simple(&io->tx->state,
	    SIGNSKY_KEY_PENDING, SIGNSKY_KEY_INSTALLING))
		fatal("failed to swap key state to installing");

	if (state.cipher != NULL)
		signsky_cipher_cleanup(state.cipher);

	state.cipher = signsky_cipher_setup(io->tx);

	state.seqnr = 1;
	state.spi = signsky_atomic_read(&io->tx->spi);

	if (!signsky_atomic_cas_simple(&io->tx->state,
	    SIGNSKY_KEY_INSTALLING, SIGNSKY_KEY_EMPTY))
		fatal("failed to swap key state to empty");
}
