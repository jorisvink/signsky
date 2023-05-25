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

	signsky_signal_trap(SIGQUIT);
	signsky_signal_ignore(SIGINT);

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

		while ((pkt = signsky_ring_dequeue(&signsky->decrypt_queue))) {
			printf("%s: decrypt %p\n", proc->name, (void *)pkt);
			signsky_ring_queue(&signsky->clear_tx, pkt);
		}

		usleep(10);
	}

	printf("%s exiting\n", proc->name);

	exit(0);
}
