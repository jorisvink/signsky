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

#include "signsky.h"

/*
 * Allocate a shared memory segment with the given len as its size.
 * If key is not NULL, the shm key is written to it.
 *
 * The shared memory segment is attached automatically after allocation
 * and returned to the caller.
 *
 * Before returning the segment to the caller, it is marked for deletion
 * so that once the process exits the shared memory goes away.
 */
void *
signsky_alloc_shared(size_t len, int *key)
{
	int		tmp;
	void		*ptr;

	tmp = shmget(IPC_PRIVATE, len, IPC_CREAT | IPC_EXCL | 0700);
	if (tmp == -1)
		fatal("%s: shmget: %s", __func__, errno_s);

	if ((ptr = shmat(tmp, NULL, 0)) == (void *)-1)
		fatal("%s: shmat: %s", __func__, errno_s);

	if (shmctl(tmp, IPC_RMID, NULL) == -1)
		fatal("%s: shmctl: %s", __func__, errno_s);

	if (key != NULL)
		*key = tmp;

	return (ptr);
}

/*
 * Detach from a shared memory segment.
 */
void
signsky_shm_detach(void *ptr)
{
	PRECOND(ptr != NULL);

	if (shmdt(ptr) == -1)
		fatal("failed to detach from 0x%p (%s)", ptr, errno_s);
}
