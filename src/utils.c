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
#include <sys/stat.h>
#include <sys/un.h>

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "signsky.h"

/*
 * Install the key pending under the given `key` data structure into
 * the SA context `sa`.
 */
int
signsky_key_install(struct signsky_key *key, struct signsky_sa *sa)
{
	PRECOND(key != NULL);
	PRECOND(sa != NULL);

	if (signsky_atomic_read(&key->state) != SIGNSKY_KEY_PENDING)
		return (-1);

	if (!signsky_atomic_cas_simple(&key->state,
	    SIGNSKY_KEY_PENDING, SIGNSKY_KEY_INSTALLING))
		fatal("failed to swap key state to installing");

	if (sa->cipher != NULL)
		signsky_cipher_cleanup(sa->cipher);

	sa->cipher = signsky_cipher_setup(key);
	signsky_mem_zero(key->key, sizeof(key->key));

	sa->seqnr = 1;
	sa->spi = signsky_atomic_read(&key->spi);

	if (!signsky_atomic_cas_simple(&key->state,
	    SIGNSKY_KEY_INSTALLING, SIGNSKY_KEY_EMPTY))
		fatal("failed to swap key state to empty");

	return (0);
}

/*
 * Create a new UNIX socket at the given path, owned by the supplied
 * uid and gid and with 0700 permissions.
 */
int
signsky_unix_socket(struct signsky_sun *cfg)
{
	struct sockaddr_un	sun;
	int			fd, len, flags;

	PRECOND(cfg != NULL);

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;

	len = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", cfg->path);
	if (len == -1 || (size_t)len >= sizeof(sun.sun_path))
		fatal("path '%s' didnt fit into sun.sun_path", cfg->path);

	if (unlink(sun.sun_path) == -1 && errno != ENOENT)
		fatal("unlink(%s): %s", sun.sun_path, errno_s);

	if (bind(fd, (const struct sockaddr *)&sun, sizeof(sun)) == -1)
		fatal("bind(%s): %s", sun.sun_path, errno_s);

	if (chown(sun.sun_path, cfg->uid, cfg->gid) == -1)
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

/*
 * Poor mans memset() that isn't optimized away on the platforms I use it on.
 *
 * If you build this on something and don't test that it actually clears the
 * contents of the data, thats on you. You probably want to do some binary
 * verification.
 */
void
signsky_mem_zero(void *ptr, size_t len)
{
	volatile char	*p;

	PRECOND(ptr != NULL);
	PRECOND(len > 0);

	p = (volatile char *)ptr;

	while (len-- > 0)
		*(p)++ = 0x00;
}

