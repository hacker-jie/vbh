#include <asm/cmpxchg.h>
#include <asm/processor.h>
#include "lock.h"

bool slock_trylock(slock_t *lock)
{
	return !arch_xchg(&(lock->counter), 1);
}

void slock_lock(slock_t *lock)
{
	while (!slock_trylock(lock))
		cpu_relax();
}

void slock_unlock(slock_t *lock)
{
	WRITE_ONCE(lock->counter, 0);
}

void sspinlock_init(sspinlock_t *lock)
{
	lock->head = 0;
	lock->tail = 0;
}

void sspinlock_obtain(sspinlock_t *lock)
{
	/* The lock function atomically increments and exchanges the head
	 * counter of the queue. If the old head of the queue is equal to the
	 * tail, we have locked the spinlock. Otherwise we have to wait.
	 */

	asm volatile ("   movl $0x1,%%eax\n"
		      "   lock xaddl %%eax,%[head]\n"
		      "   cmpl %%eax,%[tail]\n"
		      "   jz 1f\n"
		      "2: pause\n"
		      "   cmpl %%eax,%[tail]\n"
		      "   jnz 2b\n"
		      "1:\n"
		      :
		      :
		      [head] "m"(lock->head),
		      [tail] "m"(lock->tail)
		      : "cc", "memory", "eax");
}

void sspinlock_release(sspinlock_t *lock)
{
	/* Increment tail of queue */
	asm volatile ("   lock incl %[tail]\n"
				:
				: [tail] "m" (lock->tail)
				: "cc", "memory");
}
