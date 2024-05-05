#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include <hash.h>
#include "userprog/syscall.h"

/* States in a thread's life cycle. */
enum thread_status
{
   THREAD_RUNNING,     /* Running thread. */
   THREAD_READY,       /* Not running but ready to run. */
   THREAD_BLOCKED,     /* Waiting for an event to trigger. */
   THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

// added
#define START_FD 2                      /*First fd a process can use*/
#define MAX_PRIORITY_DONATION_NESTED_DEPTH 8    /* For recursive donations. */


/* fixed point start*/
#define F (1 << 16)

/* Helper functions for fixed-point arithmetic
 * Note: helpers were not defined for arithmetic operations
 * that can be done without fixed-point const F.
 */

#include <stdint.h>

typedef int32_t fp_t;
static inline fp_t fp (int n) { return n * F; }
static inline int fp_to_int (fp_t x) { return x / F; }
static inline int fp_to_nearest_int (fp_t x)
{
  return (x >= 0) ? (x + F/2) / F : (x - F/2) / F;
}
static inline fp_t fp_add_to_int (fp_t x, int n) { return x + fp(n); }
static inline fp_t fp_sub_int (fp_t x, int n) { return x - fp(n); }
static inline fp_t fp_mult (fp_t x, fp_t y) 
{
  return ((int64_t) x) * y / F; 
}
static inline fp_t fp_div (fp_t x, fp_t y) 
{
  return ((int64_t) x) * F / y; 
}
/* fixed point end*/

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
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* After donations priority. */
    
    // added

    int base_priority;         /* The original priority of the thread before any priority donations are applied. */
    int mlfqs_nice;            /* The 'niceness' level of the thread, influencing its priority within the MLFQS scheduler. */
    fp_t mlfqs_recent_cpu;     /* Accumulated 'recent_cpu' value indicating the amount of CPU time the thread has received recently in MLFQS. */
    
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

    // added
    struct list locks_held;             /* List of locks currently held by the thread, used for managing lock ownership. */
    struct list_elem lock_elem;         /* Element used for linking this thread to a lock's list of waiting threads. */
    struct lock *blocking_lock;         /* Pointer to the lock that is currently preventing the thread from progressing. */


#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    char *process_fn;                   /* Name of the executable file passed to process_execute. */
    int32_t process_exit_code;          /* Exit code set by process_exit to indicate process termination status. */

    /* Process hierarchy and management: */
    struct process_child *inparent;     /* Pointer to a record in the parent's process structure, or NULL if the thread is orphaned. */
    struct list process_children;       /* List containing records of child processes managed by this thread. */

    /* Virtual memory management: */
    struct hash page_table;             /* Supplemental page table used for managing virtual memory pages specific to this process. */
    struct lock *page_table_lock;       /* Lock used to synchronize access to the page table. */

    /* Memory-mapped files management: */
    struct list mmap_list;              /* List of memory-mapped files associated with the process. */
    mapid_t mmap_next_id;               /* Identifier for the next memory-mapped file to be created. */

    /* File system interactions: */
    void *exec_file;                    /* Pointer to the executable file from which this process was created. */
    void *cwd;                          /* Current working directory of the process, initialized at file system setup. */
    struct list process_fd_table;       /* List of file descriptors belonging to this process. */
    int process_fd_next;                /* Next file descriptor ID to be assigned. */

    /* File descriptor management: */
    bool fd_table_ready;                /* Flag indicating if the file descriptor table is ready for operations. */
    struct hash fd_table;               /* Table storing open file descriptors and their associated data. */
    int fd_next;                        /* Next file descriptor ID to be assigned. */
#endif

   int64_t wake_tick;                  /* Tick count indicating when the thread should wake from sleeping. */
   struct semaphore *sleep_sema;       /* Semaphore used to block and unblock the thread during sleep. */
   struct list_elem slept_elem;        /* Element used to include this thread in a list of sleeping threads. */

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
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
void thread_yield_for_priority (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

void thread_wake_eligible_slept (void);
void thread_add_to_slept (void);

int thread_get_priority (void);
void thread_set_priority (int);

bool thread_less_sleep_func(const struct list_elem *,
                             const struct list_elem *,
                             void * UNUSED);
bool thread_higher_priority (const struct list_elem *,
                             const struct list_elem *,
                             void * UNUSED);
void thread_recalculate_priority (struct thread *, size_t);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

#endif /* threads/thread.h */
