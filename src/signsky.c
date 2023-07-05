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

#include <arpa/inet.h>

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
static void	signsky_parse_host(char *, struct sockaddr_in *);

static void	usage(void) __attribute__((noreturn));

volatile sig_atomic_t		sig_recv = -1;
struct signsky_state		*signsky = NULL;

static void
usage(void)
{
	fprintf(stderr, "signsky [options]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr,
	    "  -k  specify the file containing the 256-bit symmetrical key\n");
	fprintf(stderr, "  -l  specify the local ip and port (ip:port)\n");
	fprintf(stderr, "  -p  specify the peer ip and port (ip:port)\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	const char	*key;
	char		*peer, *local;
	int		ch, running, sig;

	key = NULL;
	peer = NULL;
	local = NULL;

	while ((ch = getopt(argc, argv, "k:l:p:")) != -1) {
		switch (ch) {
		case 'k':
			key = optarg;
			break;
		case 'l':
			local = optarg;
			break;
		case 'p':
			peer = optarg;
			break;
		default:
			usage();
		}
	}

	if (peer == NULL || key == NULL)
		usage();

	signsky = signsky_alloc_shared(sizeof(*signsky), NULL);
	signsky_parse_host(peer, &signsky->peer);

	if (local != NULL)
		signsky_parse_host(local, &signsky->local);

	signsky_signal_trap(SIGINT);
	signsky_signal_trap(SIGHUP);
	signsky_signal_trap(SIGCHLD);

	signsky_proc_init();
	signsky_packet_init();
	signsky_proc_start();

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
 * Helper to parse the specified ip:port combo into the given sockaddr.
 */
static void
signsky_parse_host(char *host, struct sockaddr_in *sin)
{
	char		*port;
	const char	*errstr;

	PRECOND(host != NULL);
	PRECOND(sin != NULL);

	if ((port = strchr(host, ':')) == NULL)
		fatal("'%s': argument must be in format ip:port", host);
	*(port)++ = '\0';

	if (inet_pton(AF_INET, host, &sin->sin_addr.s_addr) == -1)
		fatal("ip '%s' invalid", host);

	sin->sin_port = strtonum(port, 1, USHRT_MAX, &errstr);
	if (errstr)
		fatal("port '%s' invalid: %s", port, errstr);

	sin->sin_port = htons(sin->sin_port);
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
