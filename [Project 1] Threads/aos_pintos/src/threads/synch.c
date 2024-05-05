/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
*/

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"


/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
     decrement it.

   - up or "V": increment the value (and wake up one waiting
     thread, if any). */
void sema_init (struct semaphore *sema, unsigned value)
{
  ASSERT (sema != NULL);          // Ensure that the semaphore pointer is not null

  sema->value = value;            // Set the initial value of the semaphore
  list_init (&sema->waiters);     // Init the list of threads waiting on this semaphore
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. */
void sema_down (struct semaphore *sema)
{
  enum intr_level old_level;    // Variable to store the previous interrupt state

  ASSERT (sema != NULL);        // Ensure the semaphore pointer is not null
  ASSERT (!intr_context ());    // Ensure this function is not called from an interrupt handler

  old_level = intr_disable ();  // Disable interrupts to enter a critical section.
  while (sema->value == 0)
    { // Loop until the semaphore value is positive
      list_push_back (&sema->waiters, &thread_current ()->elem); // Add the current thread to the semaphore's waiters list
      thread_block ();                                           // Block the current thread, causing it to stop executing
    }
  sema->value--;              // Decrement the semaphore value 
  intr_set_level (old_level); // Restore the previous interrupt state, re-enabling interrupts
}


/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down (struct semaphore *sema)
{
  enum intr_level old_level;
  bool success;

  ASSERT (sema != NULL);

  old_level = intr_disable ();    // Disable interrupts to enter critical section
  if (sema->value > 0)
    {
      sema->value--;              // Decrement the semaphore's value if possible
      success = true;
    }
  else
    success = false;
  intr_set_level (old_level);

  return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
// void sema_up (struct semaphore *sema)
// {
//   enum intr_level old_level;

//   ASSERT (sema != NULL);

//   old_level = intr_disable ();
//   if (!list_empty (&sema->waiters))
//     thread_unblock (
//         list_entry (list_pop_front (&sema->waiters), struct thread, elem));
//   sema->value++;
//   intr_set_level (old_level);
// }

// Modified
void sema_up(struct semaphore *sema) {
    enum intr_level old_level = intr_disable(); // Disables interrupts and stores the previous interrupt level in old_level
    if (!list_empty(&sema->waiters)) {
        // Ensure the waiters list is sorted by priority to unblock the highest priority thread first
        list_sort(&sema->waiters, thread_compare_priority, NULL);
        struct list_elem *highest_priority_elem = list_pop_front(&sema->waiters); // Remove the highest priority thread from the waiters list
        thread_unblock(list_entry(highest_priority_elem, struct thread, elem));   // Unblock the thread removed from the waiters list
    }
    sema->value++; // Increment the semaphore's value, signaling that a resource is available or a condition is met
    /*
    if (!intr_context()) {
        test_yield(); 
    }
    */
    thread_yield();             // Yield the current thread to allow a higher-priority thread to run
    intr_set_level(old_level);  // Restore the previous interrupt level
}



static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test (void)
{
  struct semaphore sema[2];
  int i;

  printf ("Testing semaphores...");
  sema_init (&sema[0], 0);
  sema_init (&sema[1], 0);
  thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
  for (i = 0; i < 10; i++)
    {
      sema_up (&sema[0]);
      sema_down (&sema[1]);
    }
  printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void sema_test_helper (void *sema_)
{
  struct semaphore *sema = sema_;
  int i;

  for (i = 0; i < 10; i++)
    {
      sema_down (&sema[0]);
      sema_up (&sema[1]);
    }
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void lock_init (struct lock *lock)
{
  ASSERT (lock != NULL);

  lock->holder = NULL;
  sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
// void lock_acquire (struct lock *lock)
// {
//   ASSERT (lock != NULL);
//   ASSERT (!intr_context ());
//   ASSERT (!lock_held_by_current_thread (lock));

//   sema_down (&lock->semaphore);
//   lock->holder = thread_current ();
// }

// Added
void donate_priority_recursive(struct thread *holder, struct lock *lock) {
    // Recursively donates priority from a thread to all threads holding locks that the current thread is waiting on
    while (lock != NULL && lock->holder != NULL && holder->priority > lock->holder->priority) {
        // Continue as long as there is a lock and its holder, and the donating thread's priority is higher than the lock holder's priority
        lock->holder->priority = holder->priority;  // Donate the priority: update the lock holder's priority to the donating thread's priority
        holder = lock->holder;                      // Move to the next thread that holds a lock which the current lock's holder is waiting on
        lock = holder->waiting_on_lock;             // Proceed to the next lock in the chain of priority donation
    }
}


// Added
void donate_priority(struct lock *lock) {
    struct thread *holder = lock->holder;       // Get the current holder of the lock
    struct thread *current = thread_current();  // Get the current thread attempting to acquire the lock

    // Donation should only occur if the current thread has a higher priority than the holder's
    if (holder->priority < current->priority) {
        holder->priority = current->priority; // Directly donate the current thread's priority to the holder

        // Add the current thread to the list of donors of the lock holder in a sorted order based on priority
        list_insert_ordered(&holder->donations, &current->donation_elem, thread_compare_priority, NULL);

        // If the lock holder is waiting on another lock (indicating a chain of locks),
        // recursively donate the priority to ensure that all threads in the chain are updated
        if (holder->waiting_on_lock != NULL && holder->waiting_on_lock->holder != NULL) {
            donate_priority_recursive(holder, holder->waiting_on_lock);
        }
    }
}


// Added
void remove_donation(struct lock *lock) {
    struct thread *current = thread_current(); // Get the current thread
    struct list_elem *e;
    int maxPriority = current->base_priority; // Reset the thread's priority to the original one.

    // Iterate through the list of priority donations
    for (e = list_begin(&current->donations); e != list_end(&current->donations);) {
        struct thread *t = list_entry(e, struct thread, donation_elem); // Retrieve the thread that made the donation.
        if (t->waiting_on_lock == lock) {   // If the donation was made due to the current lock,
            e = list_remove(e);             // Remove the donation from the list and move to the next element
        } else {
            e = list_next(e);               // Otherwise, just move to the next element without removing

            if (maxPriority < t->priority)
            {
                maxPriority = t->priority;
            } 
        }
    }

    current->priority = maxPriority; // Reset the thread's priority to the highest priority in the donation list.
}

// Modified
void lock_acquire(struct lock *lock) {
  ASSERT (lock != NULL);        // Ensuring that the lock is not null.
  ASSERT (!intr_context ());    // Ensuring this function is not called within an interrupt context.
  ASSERT (!lock_held_by_current_thread (lock)); // Check that the current thread does not already hold the lock.

  enum intr_level old_level = intr_disable ();  // Disables interrupts and stores the previous interrupt level in old_level

  
  if (!lock_try_acquire (lock)) {           // Attempt to acquire the lock without blocking
    struct thread *cur = thread_current (); // Get the current thread
    cur->waiting_on_lock = lock;            // Set the lock that the current thread is waiting on
    donate_priority (lock);                 // Donate the current thread's priority to the holder of the lock
    sema_down(&lock->semaphore);            // Block the current thread until the lock becomes available
  }

  lock->holder = thread_current (); // Set the current thread as the new holder of the lock
  intr_set_level (old_level);       // Restore the previous interrupt level
}



/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire (struct lock *lock)
{
  bool success;

  ASSERT (lock != NULL);
  ASSERT (!lock_held_by_current_thread (lock));

  success = sema_try_down (&lock->semaphore);
  if (success)
    lock->holder = thread_current ();
  return success;
}

/* Releases LOCK, which must be owned by the current thread.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
// void lock_release (struct lock *lock)
// {
//   ASSERT (lock != NULL);
//   ASSERT (lock_held_by_current_thread (lock));

//   lock->holder = NULL;
//   sema_up (&lock->semaphore);
// }


// Test purpose
void test_yield(void) {     // Defines the test_yield function, Its purpose is to potentially yield the CPU to another thread based on priority.
    if (!list_empty(&ready_list))
    {
        struct thread *t = list_entry(list_front(&ready_list), struct thread, elem);  // Retrieves the thread at the front of the ready list, which is the next thread scheduled to run. 
                                                                                      // This is done by accessing the 1st element of the ready list and using list_entry to get the struct thread containing that element. 
                                                                                      // The system assumes that the ready list is sorted by priority.
        if (t->priority > thread_current()->priority)   // Compares the priority of the thread at the front of the ready list (t) with the priority of the current thread. 
        {                                               // If t's priority is higher, it indicates that the current thread should yield the processor.
            thread_yield();                             // Causes the current thread to yield the CPU, allowing the scheduler to switch to the higher-priority thread (t). 
        }
    }
}

// Modified
void lock_release(struct lock *lock) {          // This function releases the specified lock
    ASSERT(lock != NULL);                       // Ensuring that a valid lock is being released
    ASSERT(lock_held_by_current_thread(lock));  // Asserts that the lock is currently held by the calling thread. This is crucial for maintaining lock discipline

    enum intr_level old_level = intr_disable(); // Disables interrupts and stores the previous interrupt level in old_level 
    struct thread *current = thread_current();  // Retrieves a pointer to the current thread, which is releasing the lock

    remove_donation(lock);      // Reverse any priority donation that might have occurred because of this lock. 
    lock->holder = NULL;        // Sets the lock's holder to NULL, indicating that the lock is no longer held by any thread
    sema_up(&lock->semaphore);  // sema_up on the lock's semaphore to increment its value, potentially waking up a thread waiting for this lock
    //test_yield();              
    intr_set_level(old_level);  // Restores the previous interrupt level
}


/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread (const struct lock *lock)
{
  ASSERT (lock != NULL);

  return lock->holder == thread_current ();
}

/* One semaphore in a list. */
struct semaphore_elem
{
  struct list_elem elem;      /* List element. */
  struct semaphore semaphore; /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init (struct condition *cond)
{
  ASSERT (cond != NULL);

  list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void cond_wait (struct condition *cond, struct lock *lock)
{
  struct semaphore_elem waiter;

  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  sema_init (&waiter.semaphore, 0);
  list_push_back (&cond->waiters, &waiter.elem);
  lock_release (lock);
  sema_down (&waiter.semaphore);
  lock_acquire (lock);
}

bool compare_sema(struct list_elem *l1, struct list_elem *l2,void *aux)
{
  struct semaphore_elem *t1 = list_entry(l1,struct semaphore_elem,elem);
  struct semaphore_elem *t2 = list_entry(l2,struct semaphore_elem,elem);
  struct semaphore *s1=&t1->semaphore;
  struct semaphore *s2=&t2->semaphore;
  if( list_entry (list_front(&s1->waiters), struct thread, elem)->priority > list_entry (list_front(&s2->waiters),struct thread, elem)->priority)
    return true;
  return false;
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_signal (struct condition *cond, struct lock *lock UNUSED)
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);
  ASSERT (!intr_context ());
  ASSERT (lock_held_by_current_thread (lock));

  list_sort(&cond->waiters, compare_sema, 0);

  if (!list_empty (&cond->waiters))
    sema_up (&list_entry (list_pop_front (&cond->waiters),
                          struct semaphore_elem, elem)
                  ->semaphore);
}


/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast (struct condition *cond, struct lock *lock)
{
  ASSERT (cond != NULL);
  ASSERT (lock != NULL);

  while (!list_empty (&cond->waiters))
    cond_signal (cond, lock);
}
