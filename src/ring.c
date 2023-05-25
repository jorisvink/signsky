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

#include "signsky.h"

/*
 * A multi-producer, multi-consumer ring queue.
 */

/*
 * Use architecture specific instructions to hint to the CPU that
 * we are in a spinloop hopefully avoiding a memory order violation
 * which would incur a performance hit.
 */
#if defined(__arm64__)
#define ring_cpu_pause()					\
	do {							\
		__asm__ volatile("yield" ::: "memory");		\
	} while (0)
#elif defined(__x86_64__)
#define ring_cpu_pause()					\
	do {							\
		__asm__ volatile("pause" ::: "memory");		\
	} while (0)
#else
#error "unsupported architecture"
#endif

/*
 * Allocate a new ring of the given number of elements. This must
 * be a power of 2 and must be maximum 4096. This is checked in
 * the signsky_ring_init() function.
 */
struct signsky_ring *
signsky_ring_alloc(size_t elm)
{
	struct signsky_ring	*ring;

	ring = signsky_alloc_shared(sizeof(*ring), NULL);
	signsky_ring_init(ring, elm);

	return (ring);
}

/*
 * Initialise the given ring queue with the number of elements.
 * The number of elements must be a power of 2 and must maximum
 * be 4096.
 */
void
signsky_ring_init(struct signsky_ring *ring, size_t elm)
{
	PRECOND(ring != NULL);
	PRECOND(elm > 0 && (elm & (elm - 1)) == 0);

	memset(ring, 0, sizeof(*ring));

	ring->elm = elm;
	ring->mask = elm - 1;
}

/*
 * Returns the number of entries that are ready to be dequeued from the queue.
 * This is intended for the consumers of the ring queue.
 */
size_t
signsky_ring_pending(struct signsky_ring *ring)
{
	u_int32_t	head, tail;

	PRECOND(ring != NULL);

	head = signsky_atomic_read(&ring->consumer.head);
	tail = signsky_atomic_read(&ring->producer.tail);

	return (tail - head);
}

/*
 * Returns the number of available entries in the queue.
 * This is intended for the producers of the ring queue.
 */
size_t
signsky_ring_available(struct signsky_ring *ring)
{
	u_int32_t	head, tail;

	PRECOND(ring != NULL);

	head = signsky_atomic_read(&ring->producer.head);
	tail = signsky_atomic_read(&ring->consumer.tail);

	return (ring->elm + (tail - head));
}

/*
 * Dequeue an item from the given ring queue. If no items were
 * available to be dequeued, NULL is returned to the caller.
 */
void *
signsky_ring_dequeue(struct signsky_ring *ring)
{
	uintptr_t	uptr;
	u_int32_t	slot, head, tail, next;

	PRECOND(ring != NULL);

dequeue_again:
	head = signsky_atomic_read(&ring->consumer.head);
	tail = signsky_atomic_read(&ring->producer.tail);

	if ((tail - head) == 0)
		return (NULL);

	next = head + 1;
	if (!signsky_atomic_cas(&ring->consumer.head, &head, &next))
		goto dequeue_again;

	slot = head & ring->mask;
	uptr = signsky_atomic_read(&ring->data[slot]);

	while (!signsky_atomic_cas_simple(&ring->consumer.tail, head, next))
		ring_cpu_pause();

	return ((void *)uptr);
}

/*
 * Queue the given item into the given ring queue. If no available
 * slots were available, this function will return -1.
 */
int
signsky_ring_queue(struct signsky_ring *ring, void *ptr)
{
	u_int32_t	slot, head, tail, next;

queue_again:
	head = signsky_atomic_read(&ring->producer.head);
	tail = signsky_atomic_read(&ring->consumer.tail);

	if ((ring->elm + (tail - head)) == 0)
		return (-1);

	next = head + 1;
	if (!signsky_atomic_cas(&ring->producer.head, &head, &next))
		goto queue_again;

	slot = head & ring->mask;
	signsky_atomic_write(&ring->data[slot], (uintptr_t)ptr);

	while (!signsky_atomic_cas_simple(&ring->producer.tail, head, next))
		ring_cpu_pause();

	return (0);
}
