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
#include <sys/un.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "signsky.h"

#define STATUS_REQUEST_DUMP		1

static void	status_handle_request(int);

/*
 * How a status request looks like on the wire.
 */
struct request {
	u_int8_t	cmd;
} __attribute__((packed));

/*
 * The status process, handles incoming status requests.
 */
void
signsky_status_entry(struct signsky_proc *proc)
{
	struct pollfd	pfd;
	int		sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg == NULL);

	signsky_signal_trap(SIGQUIT);
	signsky_signal_ignore(SIGINT);

	pfd.fd = signsky_unix_socket(&signsky->keying);

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

		pfd.events = POLLIN;

		if (poll(&pfd, 1, -1) == -1) {
			if (errno == EINTR)
				continue;
			fatal("poll: %s", errno_s);
		}

		if (pfd.revents & POLLIN)
			status_handle_request(pfd.fd);

	}

	syslog(LOG_NOTICE, "exiting");

	exit(0);
}

/*
 * Handle a request on the UNIX socket.
 */
static void
status_handle_request(int fd)
{
	ssize_t			ret;
	struct request		req;
	struct sockaddr_un	peer;
	socklen_t		socklen;

	PRECOND(fd >= 0);

	socklen = sizeof(peer);

	for (;;) {
		if ((ret = recvfrom(fd, &req, sizeof(req), 0,
		    (struct sockaddr *)&peer, &socklen)) == -1) {
			if (errno == EINTR)
				continue;
			fatal("recvfrom: %s", errno_s);
		}

		if (ret == 0)
			fatal("eof on keying socket");

		if ((size_t)ret != sizeof(req))
			break;

		break;
	}
}
