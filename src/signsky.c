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
#include <sys/shm.h>

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#if defined(__linux__)
#include <bsd/stdlib.h>
#endif

#include "signsky.h"

static void	signal_hdlr(int);

volatile sig_atomic_t		sig_recv = -1;
struct signsky_state		*signsky = NULL;

int
main(int argc, char *argv[])
{
	const char	*errstr;
	int		running, sig;

	if (argc != 3)
		fatal("Usage: signsky [peer] [port]");

	/* Setup the global state that is shared between all processes. */
	signsky = signsky_alloc_shared(sizeof(*signsky), NULL);

	signsky->peer = argv[1];
	signsky->port = strtonum(argv[2], 1, USHRT_MAX, &errstr);
	if (errstr)
		fatal("port '%s' invalid: %s", argv[2], errstr);

	/* Setup the proc system and initialize the packet pools. */
	signsky_proc_init();
	signsky_packet_init();

	/*
	 * We allocate the shared ring queues before firing off the
	 * processes so they all share them automatically.
	 */
	signsky_ring_init(&signsky->clear_tx, 1024);
	signsky_ring_init(&signsky->crypto_tx, 1024);
	signsky_ring_init(&signsky->decrypt_queue, 1024);
	signsky_ring_init(&signsky->encrypt_queue, 1024);

	/*
	 * Prepare the 4 processes in signsky:
	 *	- 1 process handling io on the clear side.
	 *	- 1 process handling io on the crypto side.
	 *	- 1 process handling encryption only.
	 *	- 1 process handling decryption only.
	 */
	signsky_proc_create(SIGNSKY_PROC_CLEAR, signsky_clear_entry);
	signsky_proc_create(SIGNSKY_PROC_CRYPTO, signsky_crypto_entry);

	signsky_proc_create(SIGNSKY_PROC_ENCRYPT, signsky_encrypt_entry);
	signsky_proc_create(SIGNSKY_PROC_DECRYPT, signsky_decrypt_entry);

	signsky_proc_startall();

	/* Detach from the state, we no longer need it mapped in our parent. */
	if (shmdt(signsky) == -1)
		printf("warning: failed to detach from state\n");

	/* XXX SIGCHLD needs to be done before starting procs, fix. */
	signsky_signal_trap(SIGINT);
	signsky_signal_trap(SIGHUP);
	signsky_signal_trap(SIGCHLD);

	running = 1;

	while (running) {
		if ((sig = signsky_last_signal()) != -1) {
			printf("parent received signal %d\n", sig);
			switch (sig) {
			case SIGINT:
			case SIGHUP:
				running = 0;
				continue;
			case SIGCHLD:
				running = 0;
				signsky_proc_reap();
				continue;
			default:
				break;
			}
		}

		/* Parent ain't doing much for now. */
		sleep(1);
	}

	signsky_proc_shutdown();

	return (0);
}

/*
 * Setup the given signal to be caught by our signal handler.
 */
void
signsky_signal_trap(int sig)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_hdlr;

	if (sigfillset(&sa.sa_mask) == -1)
		fatal("sigfillset: %s", errno_s);

	if (sigaction(sig, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
}

/*
 * Explicitly ignore the given signal.
 */
void
signsky_signal_ignore(int sig)
{
	(void)signal(sig, SIG_IGN);
}

/*
 * Returns the last received signal to the caller and resets sig_recv.
 */
int
signsky_last_signal(void)
{
	int	sig;

	sig = sig_recv;
	sig_recv = -1;

	return (sig);
}

/*
 * Bad juju happened.
 */
void
fatal(const char *fmt, ...)
{
	va_list			args;
	struct signsky_proc	*proc;

	PRECOND(fmt != NULL);

	if ((proc = signsky_process()) != NULL)
		fprintf(stderr, "proc-%s: ", proc->name);

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	if (proc == NULL)
		signsky_proc_shutdown();

	fprintf(stderr, "\n");

	exit(1);
}

/*
 * Our signal handler, doesn't do much more than set sig_recv so it can
 * be obtained by signsky_last_signal().
 */
static void
signal_hdlr(int sig)
{
	sig_recv = sig;
}
