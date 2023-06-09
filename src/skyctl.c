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

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "signsky_ctl.h"

#define SKYCTL_CLIENT_SOCKET		"/tmp/skyctl.sock"

static void	usage(void) __attribute__((noreturn));

static int	skyctl_socket_local(const char *);
static void	skyctl_socket_fill(struct sockaddr_un *, const char *);

static void	skyctl_request_status(void);
static void	skyctl_response(int, void *, size_t);
static void	skyctl_request(int, const void *, size_t);
static void	skyctl_dump_ifstat(const char *, struct signsky_ifstat *);

static const struct {
	const char	*name;
	void		(*cb)(void);
} cmds[] = {
	{ "status",	skyctl_request_status },
	{ NULL,		NULL },
};

static void
usage(void)
{
	printf("usage: skyctl [cmd]\n");
	printf("possible cmd: status\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	int		idx;

	if (argc != 2)
		usage();

	for (idx = 0; cmds[idx].name != NULL; idx++) {
		if (!strcmp(cmds[idx].name, argv[1])) {
			cmds[idx].cb();
			break;
		}
	}

	if (cmds[idx].name == NULL)
		errx(1, "unknown command '%s'", argv[1]);

	return (0);
}

static void
skyctl_socket_fill(struct sockaddr_un *sun, const char *path)
{
	int		len;

	memset(sun, 0, sizeof(*sun));
	sun->sun_family = AF_UNIX;

	len = snprintf(sun->sun_path, sizeof(sun->sun_path), "%s", path);
	if (len == -1 || (size_t)len >= sizeof(sun->sun_path))
		errx(1, "failed to create path to '%s'", path);
}

static int
skyctl_socket_local(const char *path)
{
	int			fd;
	struct sockaddr_un	sun;

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
		err(1, "socket");

	if (unlink(SKYCTL_CLIENT_SOCKET) && errno != ENOENT)
		err(1, "unlink: %s", SKYCTL_CLIENT_SOCKET);

	skyctl_socket_fill(&sun, SKYCTL_CLIENT_SOCKET);

	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "bind");

	return (fd);
}

static void
skyctl_request_status(void)
{
	int					fd;
	struct signsky_ctl_status		req;
	struct signsky_ctl_status_response	resp;

	fd = skyctl_socket_local("/tmp/skyctl-status");

	memset(&req, 0, sizeof(req));

	req.cmd = SIGNSKY_CTL_STATUS;

	skyctl_request(fd, &req, sizeof(req));
	skyctl_response(fd, &resp, sizeof(resp));

	skyctl_dump_ifstat("tx", &resp.tx);
	skyctl_dump_ifstat("rx", &resp.rx);

	close(fd);
}

static void
skyctl_dump_ifstat(const char *name, struct signsky_ifstat *st)
{
	struct timespec				ts;

	printf("%s\n", name);

	if (st->spi == 0) {
		printf("  spi            none\n");
	} else {
		printf("  spi            0x%08x\n", st->spi);
	}

	printf("  pkt            %" PRIu64 " \n", st->pkt);
	printf("  bytes          %" PRIu64 " \n", st->bytes);

	(void)clock_gettime(CLOCK_MONOTONIC, &ts);

	if (st->last == 0) {
		printf("  last packet    never\n");
	} else {
		printf("  last packet    %" PRIu64 " seconds ago\n",
		    ts.tv_sec - st->last);
	}

	printf("\n");
}

static void
skyctl_request(int fd, const void *req, size_t len)
{
	ssize_t			ret;
	struct sockaddr_un	sun;

	skyctl_socket_fill(&sun, "/tmp/signsky-status");

	for (;;) {
		if ((ret = sendto(fd, req, len, 0,
		    (const struct sockaddr *)&sun, sizeof(sun))) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "send");
		}

		if ((size_t)ret != len)
			errx(1, "short send, %zd/%zu", ret, len);

		break;
	}
}

static void
skyctl_response(int fd, void *resp, size_t len)
{
	ssize_t		ret;

	for (;;) {
		if ((ret = recv(fd, resp, len, 0)) == -1) {
			if (errno == EINTR)
				continue;
			err(1, "send");
		}

		if ((size_t)ret != len)
			errx(1, "short recv, %zd/%zu", ret, len);

		break;
	}
}
