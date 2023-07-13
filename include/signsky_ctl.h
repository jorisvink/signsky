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

#ifndef __H_SIGNSKY_CTL_H
#define __H_SIGNSKY_CTL_H

/*
 * Some statistics that can be kept around.
 */
struct signsky_ifstat {
	volatile u_int32_t	spi;
	volatile u_int64_t	pkt;
	volatile u_int64_t	last;
	volatile u_int64_t	bytes;
};

/* ctl requests, some go to keying, some go to status. */
#define SIGNSKY_CTL_STATUS		1

/*
 * A request to the status process for signsky.
 */
struct signsky_ctl_status {
	u_int8_t	cmd;
};

/*
 * The response to a SIGNSKY_CTL_STATUS_GET.
 */
struct signsky_ctl_status_response {
	struct signsky_ifstat	tx;
	struct signsky_ifstat	rx;
};

#endif
