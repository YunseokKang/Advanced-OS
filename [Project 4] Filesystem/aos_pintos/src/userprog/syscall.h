#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

#define SYSCALL_ERROR -1

void syscall_init (void);

//added
bool syscall_process_init (void);
void syscall_close_helper (int fd);
void syscall_process_done (void);

/* Region identifier. */
typedef int mapid_t;
#define MAP_FAILED ((mapid_t) -1)

#endif /* userprog/syscall.h */
