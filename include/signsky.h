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

#if defined(__APPLE__)
#define daemon portability_is_king
#endif

#include <sys/types.h>
#include <sys/queue.h>

#include <netinet/in.h>

#if defined(__linux__)
#include <linux/if_ether.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#if defined(__APPLE__)
#undef daemon
extern int daemon(int, int);
#endif

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

#define SIGNSKY_KEY_LENGTH		32

/* Process types */
#define SIGNSKY_PROC_CLEAR		1
#define SIGNSKY_PROC_CRYPTO		2
#define SIGNSKY_PROC_ENCRYPT		3
#define SIGNSKY_PROC_DECRYPT		4
#define SIGNSKY_PROC_KEYING		5
#define SIGNSKY_PROC_MAX		6

/* Key states. */
#define SIGNSKY_KEY_EMPTY		0
#define SIGNSKY_KEY_GENERATING		1
#define SIGNSKY_KEY_PENDING		2
#define SIGNSKY_KEY_INSTALLING		3

/*
 * Used to swap TX / RX keys between keying and encrypt and decrypt processes.
 */
struct signsky_key {
	volatile u_int32_t	spi;
	volatile int		state;
	u_int8_t		key[SIGNSKY_KEY_LENGTH];
};

/*
 * An SA context with an SPI, salt, sequence number and underlying cipher.
 */
struct signsky_sa {
	u_int32_t		spi;
	u_int32_t		salt;
	u_int64_t		seqnr;
	void			*cipher;
};

/*
 * A process under the control of the parent process.
 */
struct signsky_proc {
	pid_t			pid;
	uid_t			uid;
	gid_t			gid;
	u_int16_t		type;
	void			*arg;
	const char		*name;
	void			(*entry)(struct signsky_proc *);

	LIST_ENTRY(signsky_proc)	list;
};

/*
 * Used to pass all the queues to the clear and crypto sides.
 * Each process is responsible for removing the queues they
 * do not need themselves.
 */
struct signsky_proc_io {
	struct signsky_key	*tx;
	struct signsky_key	*rx;

	struct signsky_ring	*clear;
	struct signsky_ring	*crypto;
	struct signsky_ring	*encrypt;
	struct signsky_ring	*decrypt;
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

/*
 * An encrypted packet its head, includes the ESP header *and* the
 * 64-bit packet number used as part of the nonce later.
 */
struct signsky_ipsec_hdr {
	struct {
		u_int32_t		spi;
		u_int32_t		seq;
	} esp;
	u_int64_t		pn;
} __attribute__((packed));

/* ESP trailer, added to the plaintext before encrypted. */
struct signsky_ipsec_tail {
	u_int8_t		pad;
	u_int8_t		next;
} __attribute__((packed));

/* The available head room is the entire size of an signsky_ipsec_hdr. */
#define SIGNSKY_PACKET_HEAD_LEN		sizeof(struct signsky_ipsec_hdr)

/*
 * Maximum packet sizes we can receive from the interfaces.
 * Clearly we don't do jumbo frames.
 */
#define SIGNSKY_PACKET_DATA_LEN		1500

/*
 * The total space available in a packet buffer, we're lazy and just
 * made it large enough to hold the head room, packet data and
 * any tail that is going to be added to it.
 */
#define SIGNSKY_PACKET_MAX_LEN		2048

/* The minimum size we can read from an interface. */
#define SIGNSKY_PACKET_MIN_LEN		12

/*
 * A network packet.
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
	/* Local and remote addresses. */
	struct sockaddr_in	peer;
	struct sockaddr_in	local;

	/* The users the different processes runas. */
	const char		*runas[SIGNSKY_PROC_MAX];
};

extern struct signsky_state	*signsky;

/* src/config.c */
void	signsky_config_load(const char *);

/* src/signsky.c */
void	signsky_signal_trap(int);
int	signsky_last_signal(void);
void	signsky_signal_ignore(int);
void	fatal(const char *, ...) __attribute__((format (printf, 1, 2)))
	    __attribute__((noreturn));

/* src/proc. */
void	signsky_proc_init(void);
void	signsky_proc_reap(void);
void	signsky_proc_start(void);
void	signsky_proc_killall(int);
void	signsky_proc_shutdown(void);
void	signsky_proc_privsep(struct signsky_proc *);
void	signsky_proc_create(u_int16_t,
	    void (*entry)(struct signsky_proc *), void *);

struct signsky_proc	*signsky_process(void);

/* src/packet.c */
void	signsky_packet_init(void);
void	signsky_packet_release(struct signsky_packet *);

void	*signsky_packet_info(struct signsky_packet *);
void	*signsky_packet_data(struct signsky_packet *);
void	*signsky_packet_tail(struct signsky_packet *);
void	*signsky_packet_head(struct signsky_packet *);

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
void	signsky_shm_detach(void *);
void	signsky_mem_zero(void *, size_t);
void	*signsky_alloc_shared(size_t, int *);
void	signsky_key_install(struct signsky_key *, struct signsky_sa *);

/* platform bits. */
int	signsky_platform_tundev_create(void);
ssize_t	signsky_platform_tundev_read(int, struct signsky_packet *);
ssize_t	signsky_platform_tundev_write(int, struct signsky_packet *);

/* Worker entry points. */
void	signsky_clear_entry(struct signsky_proc *) __attribute__((noreturn));
void	signsky_keying_entry(struct signsky_proc *) __attribute__((noreturn));
void	signsky_crypto_entry(struct signsky_proc *) __attribute__((noreturn));
void	signsky_decrypt_entry(struct signsky_proc *) __attribute__((noreturn));
void	signsky_encrypt_entry(struct signsky_proc *) __attribute__((noreturn));

/* The cipher goo. */
size_t	signsky_cipher_overhead(void);
void	signsky_cipher_cleanup(void *);
void	*signsky_cipher_setup(struct signsky_key *);
void	signsky_cipher_encrypt(void *, const void *, size_t, const void *,
	    size_t, struct signsky_packet *);
int	signsky_cipher_decrypt(void *, const void *, size_t, const void *,
	    size_t, struct signsky_packet *);

#endif
