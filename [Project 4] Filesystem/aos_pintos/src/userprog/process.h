#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

// added
#include "userprog/syscall.h"

// /* Struct and functions for process fd table*/
// struct process_fd
//  {
//    int id;                     /* ID of file descriptor*/
//    struct list_elem list_elem; /* List element to place fd in table*/
//    struct file *file;          /* File associated with fd*/
//    char* file_name;            /* Name of file*/
//  };

/* Structure to represent a file descriptor within a process.
   This structure is used to manage and track open files in the process's file descriptor table.
   Each process_fd instance is linked in a list to facilitate efficient lookup and management. */

struct process_fd
{
  int id;                     /* Unique identifier for the file descriptor. */
  struct list_elem list_elem; /* List element for inclusion in a linked list, enabling organization within the file descriptor table. */
  struct file *file;          /* Pointer to the file structure associated with this file descriptor, representing the open file. */
  char* file_name;            /* Name of the file associated with this file descriptor, used for referencing and management purposes. */
};


int process_new_fd(struct thread *t, struct file *file, char* file_name);
void process_remove_fd(struct thread *t, int id);
struct process_fd *process_get_fd(struct thread *t, int id);



// /* Keeps track of the status of a child in the list of children
//    of a parent thread. */
// struct process_child
//   {
//     tid_t tid;
//     struct thread *thread;
//     struct list_elem elem;
//     int32_t exit_code;
//     struct semaphore exited;
//   };

/* Structure to manage and monitor the state of a child process within a parent process's list of children.
   This structure is crucial for inter-process communication and synchronization, particularly in managing
   the lifecycle and termination of child processes. It is linked in a list managed by the parent thread
   to keep track of all its child processes. */

struct process_child
{
    tid_t tid;                   /* Thread identifier for the child process. */
    struct thread *thread;       /* Pointer to the thread structure of the child, allowing direct access to its state. */
    struct list_elem elem;       /* List element for linking this structure into the parent's list of children. */
    int32_t exit_code;           /* Exit code of the child process, which is set when the child terminates. */
    struct semaphore exited;     /* Semaphore used to signal the parent that this child process has exited,
                                    enabling synchronization such as waiting on the child's termination. */
};


tid_t process_execute (const char *file_name);
void process_init (void);
void process_activate (void);
int process_wait (tid_t);
void process_exit (void);


#endif /* userprog/process.h */
