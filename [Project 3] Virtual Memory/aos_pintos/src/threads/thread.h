#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>

#include <stdint.h>
#include "threads/synch.h"

#include <hash.h>
#include <stdlib.h>

/* Fixed-point arithmetic definitions */
#define F (1 << 14)                  // Fixed-point 1
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))

// Fixed-point number 
int int2fp(int n);           // Convert integer to fixed-point
int fp2int_r(int x);         // Convert fixed-point to integer (round)
int fp2int(int x);           // Convert fixed-point to integer (truncate)
int addfp(int x, int y);     // Add two fixed-point numbers
int addfpi(int x, int n);    // Add fixed-point and integer
int subfp(int x, int y);     // Subtract two fixed-point numbers (x-y)
int subfpi(int x, int n);    // Subtract integer from fixed-point (x-n)
int multfp(int x, int y);    // Multiply two fixed-point numbers
int multfpi(int x, int n);   // Multiply fixed-point by integer
int divfp(int x, int y);     // Divide two fixed-point numbers (x/y)
int divfpi(int x, int n);    // Divide fixed-point by integer (x/n)



/* States in a thread's life cycle. */
enum thread_status
{
  THREAD_RUNNING, /* Running thread. */
  THREAD_READY,   /* Not running but ready to run. */
  THREAD_BLOCKED, /* Waiting for an event to trigger. */
  THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion.  (So don't add elements below
   THREAD_MAGIC.)
*/
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
{
  /* Owned by thread.c. */
  tid_t tid;                 /* Thread identifier. */
  enum thread_status status; /* Thread state. */
  char name[16];             /* Name (for debugging purposes). */
  uint8_t *stack;            /* Saved stack pointer. */
  int priority;              /* Priority. */
  struct list_elem allelem;  /* List element for all threads list. */

  /* Shared between thread.c and synch.c. */
  struct list_elem elem; /* List element. */

#ifdef USERPROG
  /* Owned by userprog/process.c. */
  uint32_t *pagedir; /* Page directory. */
#endif

	/* Pointer to the file currently being executed by this thread, used to prevent writing to executable files. */
	struct file* run_file;

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
    bool is_loaded; /* Indicates whether the thread's associated process is loaded into memory, used during process startup. */
    bool is_terminated; /* Indicates whether the thread has finished execution, used for cleanup and synchronization. */
	
    struct thread* parent; /* Descriptor of the parent process. It's essential for implementing process hierarchies and managing child processes. */
    struct list children; /* List of child processes. Allows a thread to manage its spawned children effectively. */
    struct list_elem childelem; /* List element for inserting this thread into its parent's children list. */

    struct semaphore load;  /* Semaphore for load synchronization, ensuring the parent thread waits for the child's loading. */
    struct semaphore exit;  /* Semaphore for exit synchronization, allowing a thread to wait for its child's termination. */
    int exit_status;  /* Exit status code, which is returned to the parent process upon this thread's termination. */

    int new_fd; /* The next available file descriptor number, ensuring unique identifiers for open files. */
    struct file* fd_table[140]; /* File descriptor table, mapping file descriptors to file structures for file operations. */

    int init_priority; /* Initial priority value stored to reset the thread's priority after priority donation. */
    struct lock *wait_on_lock; /* Pointer to the lock on which the thread is currently waiting, used for priority donation. */
    struct list donations; /* List of priority donations received by this thread, supporting multiple donations. */
    struct list_elem donation_elem; /* List element for organizing threads in the priority donation list. */

    int64_t wakeup_tick; /* Tick count at which the thread should be awakened from sleep. */

    struct hash vm; /* Hash table managing the thread's virtual address space, supporting efficient memory mapping and lookup. */


    int nice; /* Nice value affecting the thread's priority, used by the advanced scheduler to adjust priority based on thread behavior. */
    int recent_cpu; /* Represents the amount of CPU time the thread has recently consumed, used by the advanced scheduler for priority calculation. */

    struct list mmap_list;  /* List of memory-mapped files associated with the thread, used for managing memory-mapped I/O. */
    int next_mapid; /* The identifier for the next memory-mapped file, ensuring unique mapids for each mmap call. */
  };

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

#endif /* threads/thread.h */
/* Searches for a child process with a given pid among the current thread's children and returns its thread descriptor if found. */
struct thread *get_child_process(int pid);

/* Removes a child process from the current thread's list of children and deallocates its resources. */
void remove_child_process(struct thread *cp);

/* Puts the currently executing thread into sleep state until the specified number of timer ticks has elapsed. */
void thread_sleep(int64_t ticks);

/* Wakes up threads that are scheduled to wake up at or before the current tick count. */
void thread_awake(int64_t ticks);

/* Updates the earliest tick at which a sleeping thread is scheduled to be awakened, optimizing sleep list checks. */
void update_next_tick_to_awake(int64_t ticks);

/* Returns the next tick count at which a sleeping thread needs to be awakened, used for scheduling optimizations. */
int64_t get_next_tick_to_awake(void);

/* Compares the priority of the currently executing thread with the highest priority thread in the ready list and yields CPU if necessary. */
void test_max_priority(void);

/* Compares the priorities of two threads based on their list elements, used for inserting threads into priority-ordered lists. */
bool cmp_priority(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);

void donate_priority(void);
void remove_with_lock(struct lock *lock);
void refresh_priority(void);

void mlfqs_priority(struct thread *t);
void mlfqs_recent_cpu(struct thread *t);
void mlfqs_load_avg(void);
void mlfqs_increment(void);
void mlfqs_recalc(void);