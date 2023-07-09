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

static void	decrypt_drop_access(void);
static void	decrypt_keys_install(void);
static void	decrypt_packet_process(struct signsky_packet *);
static int	decrypt_with_slot(struct signsky_sa *, struct signsky_packet *);

/* The local queues. */
static struct signsky_proc_io	*io = NULL;

/* The local state for RX. */
static struct {
	struct signsky_sa	slot_1;
	struct signsky_sa	slot_2;
} state;

/*
 * The worker process responsible for encryption of packets coming
 * from the clear side of the tunnel.
 */
void
signsky_decrypt_entry(struct signsky_proc *proc)
{
	struct signsky_packet		*pkt;
	int				sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	decrypt_drop_access();

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

		decrypt_keys_install();

		while ((pkt = signsky_ring_dequeue(io->decrypt)))
			decrypt_packet_process(pkt);

		usleep(10);
	}

	syslog(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Drop access to queues the decrypt process does not need.
 */
static void
decrypt_drop_access(void)
{
	signsky_shm_detach(io->tx);
	signsky_shm_detach(io->crypto);
	signsky_shm_detach(io->encrypt);

	io->tx = NULL;
	io->crypto = NULL;
	io->encrypt = NULL;
}

/*
 * Attempt to install any pending keys into the correct slot.
 *
 * Once we have a primary RX key in slot_1, all keys that are
 * pending will be installed under slot_2 first.
 */
static void
decrypt_keys_install(void)
{
	if (state.slot_1.cipher == NULL)
		signsky_key_install(io->rx, &state.slot_1);
	else
		signsky_key_install(io->rx, &state.slot_2);
}

/*
 * Decrypt and verify a single packet under the current RX key, or if
 * that fails and there is a pending key, under the pending RX key.
 *
 * If successfull the packet is sent onto the clear interface.
 * If the pending RX key was used, it becomes the active one.
 */
static void
decrypt_packet_process(struct signsky_packet *pkt)
{
	size_t		minlen;

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SIGNSKY_PROC_DECRYPT);

	decrypt_keys_install();

	/* Belts and suspenders. */
	minlen = sizeof(struct signsky_ipsec_hdr) +
	    sizeof(struct signsky_ipsec_tail) +
	    signsky_cipher_overhead();

	if (pkt->length < minlen) {
		signsky_packet_release(pkt);
		return;
	}

	/* Try decrypting with the SA in slot_1. */
	if (decrypt_with_slot(&state.slot_1, pkt) != -1)
		return;

	/* Didn't work, lets try the SA in slot_2. */
	if (decrypt_with_slot(&state.slot_2, pkt) == -1) {
		signsky_packet_release(pkt);
		return;
	}

	/* We managed with slot_2, so we make slot_2 the primary. */
	signsky_cipher_cleanup(state.slot_1.cipher);

	state.slot_1.spi = state.slot_2.spi;
	state.slot_1.salt = state.slot_2.salt;
	state.slot_1.seqnr = state.slot_2.seqnr;
	state.slot_1.cipher = state.slot_2.cipher;

	signsky_mem_zero(&state.slot_2, sizeof(state.slot_2));
}

/*
 * Attempt to verify and decrypt a packet using the given SA.
 */
static int
decrypt_with_slot(struct signsky_sa *sa, struct signsky_packet *pkt)
{
	struct signsky_ipsec_hdr	*hdr;
	struct signsky_ipsec_tail	*tail;
	u_int8_t			nonce[12], aad[12];

	PRECOND(sa != NULL);
	PRECOND(pkt != NULL);

	/* If the SA has no cipher context, don't bother. */
	if (sa->cipher == NULL)
		return (-1);

	/* Match SPI. */
	hdr = signsky_packet_head(pkt);
	if (hdr->esp.spi != sa->spi)
		return (-1);

	/* XXX anti-replay check. */

	/* Prepare the nonce and aad. */
	memcpy(nonce, &sa->salt, sizeof(sa->salt));
	memcpy(&nonce[sizeof(sa->salt)], &hdr->pn, sizeof(hdr->pn));

	memcpy(aad, &sa->spi, sizeof(sa->spi));
	memcpy(&aad[sizeof(sa->spi)], &hdr->pn, sizeof(hdr->pn));

	/* Do the cipher dance. */
	if (signsky_cipher_decrypt(sa->cipher, nonce, sizeof(nonce),
	    aad, sizeof(aad), pkt) == -1)
		return (-1);

	/* XXX anti-replay update. */

	/*
	 * Packet checks out, remove all overhead for IPSec and the cipher.
	 * The caller already verified that there was enough data in
	 * the packet to satisfy the fact that there is a tail and cipher tag.
	 */
	pkt->length -= sizeof(struct signsky_ipsec_hdr);
	pkt->length -= sizeof(struct signsky_ipsec_tail);
	pkt->length -= signsky_cipher_overhead();

	tail = signsky_packet_tail(pkt);
	if (tail->pad != 0 || tail->next != IPPROTO_IP)
		return (-1);

	/* Ship it. */
	if (signsky_ring_queue(io->clear, pkt) == -1)
		signsky_packet_release(pkt);

	return (0);
}
