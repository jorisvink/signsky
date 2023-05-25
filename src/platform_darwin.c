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
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>

#include <net/if_utun.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "signsky.h"

#define APPLE_UTUN_CONTROL	"com.apple.net.utun_control"

/*
 * MacOS tunnel interface creation.
 * Creates utun99 on the host and returns a socket for it.
 */
int
signsky_platform_alloc_tundev(void)
{
	struct sockaddr_ctl	sctl;
	struct ctl_info		info;
	int			fd, flags;

	memset(&info, 0, sizeof(info));
	memset(&sctl, 0, sizeof(sctl));

	if ((fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)) == -1)
		fatal("socket: %s", errno_s);

	if (strlcpy(info.ctl_name, APPLE_UTUN_CONTROL,
	    sizeof(info.ctl_name)) >= sizeof(info.ctl_name))
		fatal("failed to copy %s", APPLE_UTUN_CONTROL);

	if (ioctl(fd, CTLIOCGINFO, &info) == -1)
		fatal("ioctl: %s", errno_s);

	sctl.sc_unit = 100;
	sctl.sc_id = info.ctl_id;
	sctl.sc_family = AF_SYSTEM;
	sctl.ss_sysaddr = AF_SYS_CONTROL;

	if (connect(fd, (struct sockaddr *)&sctl, sizeof(sctl)) == -1)
		fatal("connect: %s", errno_s);

	if ((flags = fcntl(fd, F_GETFL, 0)) == -1)
		fatal("fcntl: %s", errno_s);

	flags |= O_NONBLOCK;

	if (fcntl(fd, F_SETFL, flags) == -1)
		fatal("fcntl: %s", errno_s);

	return (fd);
}
