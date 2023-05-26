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

#include <stdio.h>

#include "signsky.h"

/*
 * Shared pool of packets that are to be processed.
 *
 * The clear and crypto io processes will for each received packet grab
 * one from the pool and hand them over to either the encryption or decryption
 * processes who in turn hand them over to the crypto or clear io processes.
 */
struct signsky_pool	*pktpool;

/*
 * Setup the packet pool, the 1024 could maybe be tuneable.
 */
void
signsky_packet_init(void)
{
	pktpool = signsky_pool_init(1024, sizeof(struct signsky_packet));
}

/*
 * Obtain a new packet from the packet pool. If no packets are
 * available NULL is returned to the caller.
 */
struct signsky_packet *
signsky_packet_get(void)
{
	struct signsky_packet	*pkt;

	pkt = signsky_pool_get(pktpool);

	pkt->length = 0;
	pkt->target = 0;

	return (pkt);
}

/*
 * Place a packet back into the packet pool, making it available again
 * for clear or crypto.
 */
void
signsky_packet_release(struct signsky_packet *pkt)
{
	PRECOND(pkt != NULL);

	signsky_pool_put(pktpool, pkt);
}

/*
 * Returns a pointer to the packet start (the location of the ESP header).
 */
void *
signsky_packet_start(struct signsky_packet *pkt)
{
	PRECOND(pkt != NULL);

	return (&pkt->buf[0]);
}

/*
 * Returns a pointer to the packet data (immediately after the ESP header).
 */
void *
signsky_packet_data(struct signsky_packet *pkt)
{
	PRECOND(pkt != NULL);
	PRECOND(pkt->length <= SIGNSKY_PACKET_DATA_LEN);

	return (&pkt->buf[SIGNSKY_PACKET_HEAD_LEN]);
}
