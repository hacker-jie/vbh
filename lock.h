#ifndef __VBH_LOCK_H
#define __VBH_LOCK_H

// simple lock
typedef struct {
	u8 counter;
} slock_t;

// spin lock likely
typedef struct {
	u32 head;
	u32 tail;
} sspinlock_t;

bool slock_trylock(slock_t *lock);
void slock_lock(slock_t *lock);
void slock_unlock(slock_t *lock);

void sspinlock_init(sspinlock_t *lock);
void sspinlock_obtain(sspinlock_t *lock);
void sspinlock_release(sspinlock_t *lock);
#endif
