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

#include <netinet/in.h>
#include <arpa/inet.h>

#include <poll.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "signsky.h"

static void	decrypt_drop_access(void);
static void	decrypt_keys_install(void);
static void	decrypt_packet_process(struct signsky_packet *);
static int	decrypt_with_slot(struct signsky_sa *, struct signsky_packet *);

static int	decrypt_arwin_check(struct signsky_packet *,
		    struct signsky_ipsec_hdr *);
static void	decrypt_arwin_update(struct signsky_packet *,
		    struct signsky_ipsec_hdr *);

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

#if !defined(SIGNSKY_HIGH_PERFORMANCE)
		usleep(500);
#endif
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
	if (state.slot_1.cipher == NULL) {
		if (signsky_key_install(io->rx, &state.slot_1) != -1) {
			signsky_atomic_write(&signsky->rx.spi,
			    state.slot_1.spi);
			syslog(LOG_NOTICE, "new RX SA (spi=0x%08x)",
			    state.slot_1.spi);
		}
	} else {
		if (signsky_key_install(io->rx, &state.slot_2) != -1) {
			syslog(LOG_NOTICE, "pending RX SA (spi=0x%08x)",
			    state.slot_2.spi);
		}
	}
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
	struct signsky_ipsec_hdr	*hdr;

	PRECOND(pkt != NULL);
	PRECOND(pkt->target == SIGNSKY_PROC_DECRYPT);

	decrypt_keys_install();

	if (signsky_packet_crypto_checklen(pkt) == -1) {
		signsky_packet_release(pkt);
		return;
	}

	hdr = signsky_packet_head(pkt);
	hdr->esp.spi = be32toh(hdr->esp.spi);
	hdr->esp.seq = be32toh(hdr->esp.seq);
	hdr->pn = be64toh(hdr->pn);

	if (decrypt_with_slot(&state.slot_1, pkt) != -1)
		return;

	if (decrypt_with_slot(&state.slot_2, pkt) == -1) {
		signsky_packet_release(pkt);
		return;
	}

	signsky_atomic_write(&signsky->rx.spi, state.slot_2.spi);
	syslog(LOG_NOTICE, "swapping RX SA (spi=0x%08x)", state.slot_2.spi);

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

	if (sa->cipher == NULL)
		return (-1);

	hdr = signsky_packet_head(pkt);
	if (hdr->esp.spi != sa->spi)
		return (-1);

	if (decrypt_arwin_check(pkt, hdr) == -1)
		return (-1);

	memcpy(nonce, &sa->salt, sizeof(sa->salt));
	memcpy(&nonce[sizeof(sa->salt)], &hdr->pn, sizeof(hdr->pn));

	memcpy(aad, &sa->spi, sizeof(sa->spi));
	memcpy(&aad[sizeof(sa->spi)], &hdr->pn, sizeof(hdr->pn));

	if (signsky_cipher_decrypt(sa->cipher, nonce, sizeof(nonce),
	    aad, sizeof(aad), pkt) == -1)
		return (-1);

	decrypt_arwin_update(pkt, hdr);

	if (pkt->addr.sin_addr.s_addr != signsky->peer_ip ||
	    pkt->addr.sin_port != signsky->peer_port) {
		syslog(LOG_NOTICE, "peer address change (new=%s:%u)",
		    inet_ntoa(pkt->addr.sin_addr), ntohs(pkt->addr.sin_port));

		signsky_atomic_write(&signsky->peer_ip,
		    pkt->addr.sin_addr.s_addr);
		signsky_atomic_write(&signsky->peer_port, pkt->addr.sin_port);
	}

	pkt->length -= sizeof(struct signsky_ipsec_hdr);
	pkt->length -= sizeof(struct signsky_ipsec_tail);
	pkt->length -= signsky_cipher_overhead();

	tail = signsky_packet_tail(pkt);
	if (tail->pad != 0 || tail->next != IPPROTO_IP)
		return (-1);

	pkt->target = SIGNSKY_PROC_CLEAR;

	if (signsky_ring_queue(io->clear, pkt) == -1)
		signsky_packet_release(pkt);

	return (0);
}

/*
 * Check if the given packet was too old, or already seen.
 */
static int
decrypt_arwin_check(struct signsky_packet *pkt, struct signsky_ipsec_hdr *hdr)
{
	u_int64_t	bit;

	PRECOND(pkt != NULL);
	PRECOND(hdr != NULL);

	if ((hdr->pn & 0xffffffff) != hdr->esp.seq)
		return (-1);

	if (hdr->pn > io->arwin->last)
		return (0);

	if (hdr->pn > 0 && SIGNSKY_ARWIN_SIZE > io->arwin->last - hdr->pn) {
		bit = (SIGNSKY_ARWIN_SIZE - 1) - (io->arwin->last - hdr->pn);
		if (io->arwin->bitmap & ((u_int64_t)1 << bit)) {
			syslog(LOG_INFO,
			    "packet seq=0x%" PRIx64 " already seen", hdr->pn);
			return (-1);
		}
		return (0);
	}

	return (-1);
}

/*
 * Update the anti-replay window.
 */
static void
decrypt_arwin_update(struct signsky_packet *pkt, struct signsky_ipsec_hdr *hdr)
{
	u_int64_t	bit;

	PRECOND(pkt != NULL);
	PRECOND(hdr != NULL);

	if (hdr->pn > io->arwin->last) {
		if (hdr->pn - io->arwin->last >= SIGNSKY_ARWIN_SIZE) {
			io->arwin->bitmap = ((u_int64_t)1 << 63);
		} else {
			io->arwin->bitmap >>= (hdr->pn - io->arwin->last);
			io->arwin->bitmap |= ((u_int64_t)1 << 63);
		}

		signsky_atomic_write(&io->arwin->last, hdr->pn);
		return;
	}

	if (io->arwin->last < hdr->pn)
		fatal("%s: window corrupt", __func__);

	bit = (SIGNSKY_ARWIN_SIZE - 1) - (io->arwin->last - hdr->pn);
	io->arwin->bitmap |= ((u_int64_t)1 << bit);
}
