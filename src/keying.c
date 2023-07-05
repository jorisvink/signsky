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

#include <arpa/inet.h>
#include <netinet/in.h>

#include <poll.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "signsky.h"

#define KEY_SOCK_PATH		"/tmp/signsky.key"

struct request {
	/* The shared secret from a key exchange. */
	u_int8_t	ss[SIGNSKY_KEY_LENGTH];
} __attribute__((packed));

static int	keying_bind_path(void);
static void	keying_drop_access(void);
static void	keying_handle_request(int);

/* The local queues. */
static struct signsky_proc_io	*io = NULL;

/*
 * The keying process.
 *
 * This process is will receive new key material via a unix socket and
 * derive new RX/TX keys from it, together with the base symmetrical key.
 *
 * The RX/TX session keys are then installed in the decrypt and encrypt
 * processes respectively.
 */
void
signsky_keying_entry(struct signsky_proc *proc)
{
	struct pollfd	pfd;
	int		sig, running;

	PRECOND(proc != NULL);
	PRECOND(proc->arg != NULL);

	io = proc->arg;
	keying_drop_access();

	signsky_signal_trap(SIGQUIT);
	signsky_signal_ignore(SIGINT);

	pfd.fd = keying_bind_path();

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
			keying_handle_request(pfd.fd);
	}

	syslog(LOG_NOTICE, "exiting");

	exit(0);
}

static void
keying_drop_access(void)
{
	signsky_shm_detach(io->clear);
	signsky_shm_detach(io->crypto);
	signsky_shm_detach(io->encrypt);
	signsky_shm_detach(io->decrypt);

	io->clear = NULL;
	io->crypto = NULL;
	io->encrypt = NULL;
	io->decrypt = NULL;
}

static int
keying_bind_path(void)
{
	struct sockaddr_un	sun;
	int			fd, flags, len;

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;

	len = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", KEY_SOCK_PATH);
	if (len == -1 || (size_t)len >= sizeof(sun.sun_path))
		fatal("the socket path didnt fit into sun.sun_path");

	if (unlink(sun.sun_path) == -1 && errno != ENOENT)
		fatal("unlink(%s): %s", sun.sun_path, errno_s);

	if (bind(fd, (const struct sockaddr *)&sun, sizeof(sun)) == -1)
		fatal("bind(%s): %s", sun.sun_path, errno_s);

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl: %s", errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("fcntl: %s", errno_s);

	return (fd);
}

static void
keying_handle_request(int fd)
{
	ssize_t			ret;
	struct request		req;
	struct sockaddr_un	peer;
	socklen_t		socklen;

	PRECOND(fd >= 0);

	socklen = sizeof(peer);

	for (;;) {
		if ((ret = recvfrom(fd, req.ss, sizeof(req.ss), 0,
		    (struct sockaddr *)&peer, &socklen)) == -1) {
			if (errno == EINTR)
				continue;
			fatal("recvfrom: %s", errno_s);
		}

		if (ret == 0)
			fatal("eof on keying socket");

		if ((size_t)ret != sizeof(req.ss))
			break;

		syslog(LOG_DEBUG, "keying read %zd bytes", ret);
		break;
	}
}
