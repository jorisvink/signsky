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

#include <err.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "signsky.h"

/*
 * Test code for the ring buffer, you can ignore this.
 */

#define signsky_atomic_read(x)		\
    __atomic_load_n(x, __ATOMIC_SEQ_CST)

#define signsky_atomic_write(x, v)	\
    __atomic_store_n(x, v, __ATOMIC_SEQ_CST)

#define signsky_atomic_exchange(x, e)	\
    __atomic_exchange_n(x, e, __ATOMIC_SEQ_CST)

#define signsky_atomic_add(x, e)	\
    __atomic_fetch_add(x, e, __ATOMIC_SEQ_CST)

#define ring_cpu_pause()					\
	do {							\
		__asm__ volatile("yield" ::: "memory");		\
	} while (0)

static void	producer(void);
static void	consumer(void);

struct state {
	volatile u_int64_t	produced;
	volatile u_int64_t	consumed;
	volatile int		stoptheworld;
};

extern struct signsky_pool	*pktpool;

struct signsky_ring		*tx = NULL;
static struct signsky_packet	*pkt = NULL;
static u_int64_t		iters = 0;
struct state			*state = NULL;
const char			*procname = "parent";

void
fatal(const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	printf("%s(pid=%d,iters=%llu,pkt=%p): ", procname, getpid(), iters,
	    (void *)pkt);
	vprintf(fmt, args);
	printf("\n");
	va_end(args);

	exit(1);
}

int
main(int argc, char *argv[])
{
	u_int64_t	nr;
	int		idx, key;
	time_t		last, now;

	key = shmget(IPC_PRIVATE, sizeof(*state), IPC_CREAT | IPC_EXCL | 0700);
	if (key == -1)
		err(1, "shmget");

	printf("created %d\n", key);

	if ((state = shmat(key, NULL, 0)) == (void *)-1)
		err(1, "shmat");

	signsky_packet_init();
	tx = signsky_ring_alloc(1024);

	state->consumed = 0;
	state->produced = 0;
	state->stoptheworld = 0;

	(void)shmctl(key, IPC_RMID, NULL);

	printf("parent is %d\n", getpid());
	printf("=====================================\n");
	fflush(stdout);

	for (idx = 0; idx < 2; idx++)
		producer();

	for (idx = 0; idx < 2; idx++)
		consumer();

	time(&now);
	last = now;

	for (;;) {
		time(&now);
		if ((now - last) >= 1) {
			last = now;
			signsky_atomic_write(&state->stoptheworld, 1);

			nr = signsky_atomic_exchange(&state->produced, 0);
			printf("produced: %llu\n", nr);

			nr = signsky_atomic_exchange(&state->consumed, 0);
			printf("consumed: %llu\n", nr);

			printf("tx pending: %zu\n", signsky_ring_pending(tx));

			printf("pkt available in pool: %zu\n",
			    signsky_ring_pending(&pktpool->queue));

			signsky_atomic_write(&state->stoptheworld, 0);
			fflush(stdout);
		}

		sleep(1);
	}

	if (shmdt(state) == -1)
		warn("shmdt");

	return (0);
}

static void
producer(void)
{
	pid_t			pid;

	if ((pid = fork()) == -1)
		err(1, "fork");

	if (pid != 0)
		return;

	pid = getpid();
	printf("prod proc %d\n", pid);

	procname = "producer";

	for (;;) {
		while (signsky_atomic_read(&state->stoptheworld) == 1)
			ring_cpu_pause();

		if ((pkt = signsky_packet_get()) == NULL)
			continue;

		if (signsky_ring_queue(tx, pkt) == -1) {
			signsky_packet_release(pkt);
			continue;
		}

		signsky_atomic_add(&state->produced, 1);
	}
}

static void
consumer(void)
{
	pid_t		pid;

	if ((pid = fork()) == -1)
		err(1, "fork");

	if (pid != 0)
		return;

	pid = getpid();
	printf("consumer proc %d\n", pid);

	procname = "consumer";

	for (;;) {
		while (signsky_atomic_read(&state->stoptheworld) == 1)
			ring_cpu_pause();

		while ((pkt = signsky_ring_dequeue(tx)) != NULL) {
			signsky_packet_release(pkt);
			signsky_atomic_add(&state->consumed, 1);
			iters++;
		}
	}
}
