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
#include <sys/stat.h>
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

/*
 * How a request over the UNIX socket must look like.
 */
struct request {
	u_int32_t	tx_spi;
	u_int32_t	rx_spi;
	u_int8_t	ss[SIGNSKY_KEY_LENGTH];
} __attribute__((packed));

static void	keying_drop_access(void);
static void	keying_handle_request(int);
static int	keying_create_socket(void);
static void	keying_install(struct signsky_key *, u_int32_t, void *, size_t);

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

	pfd.fd = keying_create_socket();

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

/*
 * Drop access to queues that keying does not need.
 */
static void
keying_drop_access(void)
{
	signsky_shm_detach(io->arwin);
	signsky_shm_detach(io->clear);
	signsky_shm_detach(io->crypto);
	signsky_shm_detach(io->encrypt);
	signsky_shm_detach(io->decrypt);

	io->clear = NULL;
	io->arwin = NULL;
	io->crypto = NULL;
	io->encrypt = NULL;
	io->decrypt = NULL;
}

/*
 * Create a local UNIX socket on the configured keying path and
 * change its user to the configured owner.
 */
static int
keying_create_socket(void)
{
	struct sockaddr_un	sun;
	int			fd, flags;

	PRECOND(signsky->keying_path != NULL);

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;

	if (strlcpy(sun.sun_path, signsky->keying_path,
	    sizeof(sun.sun_path)) >= sizeof(sun.sun_path)) {
		fatal("keying path '%s' didnt fit into sun.sun_path",
		    signsky->keying_path);
	}

	free(signsky->keying_path);
	signsky->keying_path = NULL;

	if (unlink(sun.sun_path) == -1 && errno != ENOENT)
		fatal("unlink(%s): %s", sun.sun_path, errno_s);

	if (bind(fd, (const struct sockaddr *)&sun, sizeof(sun)) == -1)
		fatal("bind(%s): %s", sun.sun_path, errno_s);

	if (chown(sun.sun_path, signsky->keying_uid, signsky->keying_gid) == -1)
		fatal("chown(%s): %s", sun.sun_path, errno_s);

	if (chmod(sun.sun_path, S_IRWXU) == -1)
		fatal("chmod(%s): %s", sun.sun_path, errno_s);

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl: %s", errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("fcntl: %s", errno_s);

	return (fd);
}

/*
 * Handle a request on the UNIX socket.
 */
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

		/* XXX - RX/TX derivation. */
		keying_install(io->tx, req.tx_spi, req.ss, sizeof(req.ss));
		keying_install(io->rx, req.rx_spi, req.ss, sizeof(req.ss));
		break;
	}
}

/*
 * Install the given key into shared memory so that RX/TX can pick these up.
 */
static void
keying_install(struct signsky_key *state, u_int32_t spi, void *key, size_t len)
{
	PRECOND(state != NULL);
	PRECOND(spi > 0);
	PRECOND(key != NULL);
	PRECOND(len == SIGNSKY_KEY_LENGTH);

	while (signsky_atomic_read(&state->state) != SIGNSKY_KEY_EMPTY)
		signsky_cpu_pause();

	if (!signsky_atomic_cas_simple(&state->state,
	    SIGNSKY_KEY_EMPTY, SIGNSKY_KEY_GENERATING))
		fatal("failed to swap key state to generating");

	memcpy(state->key, key, len);
	signsky_atomic_write(&state->spi, spi);

	if (!signsky_atomic_cas_simple(&state->state,
	    SIGNSKY_KEY_GENERATING, SIGNSKY_KEY_PENDING))
		fatal("failed to swap key state to pending");
}
