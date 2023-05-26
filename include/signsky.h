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

#ifndef __H_SIGNSKY_H
#define __H_SIGNSKY_H

#include <sys/types.h>
#include <sys/queue.h>

#include <netinet/in.h>

#if defined(__linux__)
#include <linux/if_ether.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <string.h>

/* A few handy macros. */
#define errno_s		strerror(errno)

#define signsky_atomic_read(x)		\
    __atomic_load_n(x, __ATOMIC_SEQ_CST)

#define signsky_atomic_write(x, v)	\
    __atomic_store_n(x, v, __ATOMIC_SEQ_CST)

#define signsky_atomic_cas(x, e, d)	\
    __atomic_compare_exchange(x, e, d, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)

#define signsky_atomic_cas_simple(x, e, d)	\
    __sync_bool_compare_and_swap(x, e, d)

#define signsky_atomic_add(x, e)	\
    __atomic_fetch_add(x, e, __ATOMIC_SEQ_CST)

#define PRECOND(x)							\
	do {								\
		if (!(x)) {						\
			fatal("precondition failed in %s:%s:%d\n",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

#define VERIFY(x)							\
	do {								\
		if (!(x)) {						\
			fatal("verification failed in %s:%s:%d\n",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

/* Process types */
#define SIGNSKY_PROC_CLEAR		1
#define SIGNSKY_PROC_CRYPTO		2
#define SIGNSKY_PROC_ENCRYPT		3
#define SIGNSKY_PROC_DECRYPT		4
#define SIGNSKY_PROC_MAX		5

/*
 * A process under the control of the parent process.
 */
struct signsky_proc {
	pid_t			pid;
	u_int16_t		type;
	const char		*name;
	void			(*entry)(struct signsky_proc *);

	LIST_ENTRY(signsky_proc)	list;
};

/*
 * A shared memory ring queue with space for up to 4096 elements.
 * The actual size is given via signsky_ring_init() and must be <= 4096.
 */
struct signsky_ring_span {
	volatile u_int32_t	head;
	volatile u_int32_t	tail;
};

struct signsky_ring {
	size_t				elm;
	u_int32_t			mask;
	struct signsky_ring_span	producer;
	struct signsky_ring_span	consumer;
	volatile uintptr_t		data[4096];
};

/*
 * A shared memory object pool.
 */
struct signsky_pool {
	size_t			len;
	u_int8_t		*base;
	struct signsky_ring	queue;
};

/* The ESP header. */
struct signsky_esphdr {
	u_int32_t		spi;
	u_int32_t		seq;
} __attribute__((packed));

/* The ESP trailer. */
struct signsky_esptrail {
	u_int8_t		pad;
	u_int8_t		next;
} __attribute__((packed));

/*
 * The available head room is the entire size of an ESP header.
 */
#define SIGNSKY_PACKET_HEAD_LEN		sizeof(struct signsky_esphdr)
#define SIGNSKY_PACKET_DATA_LEN		1500
#define SIGNSKY_PACKET_MAX_LEN		\
    (SIGNSKY_PACKET_HEAD_LEN + SIGNSKY_PACKET_DATA_LEN)

/* The minimum size we can read from an interface. */
#define SIGNSKY_PACKET_MIN_LEN		12

/*
 * A network packet that will be encrypted / decrypted.
 */
struct signsky_packet {
	size_t		length;
	u_int32_t	target;
	u_int8_t	buf[SIGNSKY_PACKET_MAX_LEN];
};

/*
 * The shared state between processes.
 */
struct signsky_state {
	struct signsky_ring	clear_tx;
	struct signsky_ring	crypto_tx;
	struct signsky_ring	decrypt_queue;
	struct signsky_ring	encrypt_queue;

	struct sockaddr_in	peer;
};

extern struct signsky_state	*signsky;

/* src/signsky.c */
void	signsky_signal_trap(int);
int	signsky_last_signal(void);
void	signsky_signal_ignore(int);
void	fatal(const char *, ...) __attribute__((format (printf, 1, 2)));

/* src/proc. */
void	signsky_proc_init(void);
void	signsky_proc_reap(void);
void	signsky_proc_killall(int);
void	signsky_proc_shutdown(void);
void	signsky_proc_startall(void);
void	signsky_proc_create(u_int16_t, void (*entry)(struct signsky_proc *));

struct signsky_proc	*signsky_process(void);

/* src/packet.c */
void	signsky_packet_init(void);
void	signsky_packet_release(struct signsky_packet *);

void	*signsky_packet_info(struct signsky_packet *);
void	*signsky_packet_data(struct signsky_packet *);
void	*signsky_packet_start(struct signsky_packet *);

struct signsky_packet	*signsky_packet_get(void);

/* src/pool.c */
void	*signsky_pool_get(struct signsky_pool *);
void	signsky_pool_put(struct signsky_pool *, void *);

struct signsky_pool	*signsky_pool_init(size_t, size_t);

/* src/ring.c */
size_t	signsky_ring_pending(struct signsky_ring *);
void	*signsky_ring_dequeue(struct signsky_ring *);
size_t	signsky_ring_available(struct signsky_ring *);
void	signsky_ring_init(struct signsky_ring *, size_t);
int	signsky_ring_queue(struct signsky_ring *, void *);

struct signsky_ring	*signsky_ring_alloc(size_t);

/* src/utils.c */
void	*signsky_alloc_shared(size_t, int *);

/* platform bits. */
int	signsky_platform_tundev_create(void);
ssize_t	signsky_platform_tundev_read(int, struct signsky_packet *);
ssize_t	signsky_platform_tundev_write(int, struct signsky_packet *);

/* Worker entry points. */
void	signsky_clear_entry(struct signsky_proc *) __attribute__((noreturn));
void	signsky_crypto_entry(struct signsky_proc *) __attribute__((noreturn));
void	signsky_decrypt_entry(struct signsky_proc *) __attribute__((noreturn));
void	signsky_encrypt_entry(struct signsky_proc *) __attribute__((noreturn));

#endif
