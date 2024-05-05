#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/block.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "lib/user/syscall.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"


static void syscall_handler (struct intr_frame *);

// Added
struct lock syscall_lock;


// Modified
void syscall_init (void) 
{
	lock_init(&syscall_lock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


//Added 
void exit_if_invalid_ptr(const void *vaddr) {
	//Null pointer
	if (vaddr == NULL) exit(-1);
	//Pointer to kernel address space
	if (!is_user_vaddr(vaddr) || is_kernel_vaddr(vaddr)) exit(-1);
	//Unmapped virtual memory
	if (pagedir_get_page(thread_current()->pagedir, vaddr) == NULL) exit(-1);
}

//Added, null fd check
void is_null(int fd){
	if (thread_current()->fd[fd] == NULL) exit(-1);
}

//Added, syscall_handler
static void syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *args = (uint32_t *)f->esp;

  switch(args[0]) {
	case SYS_HALT:
		halt();
		break;

	case SYS_EXIT:
		exit_if_invalid_ptr(&args[1]);
		exit((int)args[1]);
		break;

	case SYS_EXEC:
		exit_if_invalid_ptr(&args[1]);
		f->eax = exec((const char *)args[1]);
		break;

	case SYS_WAIT:
                exit_if_invalid_ptr(&args[1]);
		f->eax = wait((pid_t)args[1]);
		break;

	case SYS_CREATE:
		exit_if_invalid_ptr(&args[1]);
		exit_if_invalid_ptr(&args[2]);
		f->eax = create((const char *)args[1], (unsigned)args[2]);
		break;

	case SYS_REMOVE:
		exit_if_invalid_ptr(&args[1]);
		f->eax = remove((const char *)args[1]);
		break;

	case SYS_OPEN:
        exit_if_invalid_ptr(&args[1]);
        f->eax = open((const char *)args[1]);
        break;

	case SYS_FILESIZE:
		exit_if_invalid_ptr(&args[1]);
		f->eax = filesize((int)args[1]);
		break;

	case SYS_READ:
		exit_if_invalid_ptr(&args[1]);
		exit_if_invalid_ptr(&args[2]);
		exit_if_invalid_ptr(&args[3]);
		f->eax = read((int)args[1], (void *)args[2], (unsigned)args[3]);
		break;

	case SYS_WRITE:
		exit_if_invalid_ptr(&args[1]);
		exit_if_invalid_ptr(&args[2]);
		exit_if_invalid_ptr(&args[3]);
		f->eax = write((int)args[1], (const void *)args[2], (unsigned)args[3]);
		break;

	case SYS_SEEK:
		exit_if_invalid_ptr(&args[1]);
		exit_if_invalid_ptr(&args[2]);
		seek((int)args[1], (unsigned)args[2]);
		break;

	case SYS_TELL:
		exit_if_invalid_ptr(&args[1]);
		f->eax = tell((int)args[1]);
		break;
	
	case SYS_CLOSE:
		exit_if_invalid_ptr(&args[1]);
		close((int)args[1]);
		break;

	case SYS_SYMLINK:
		exit_if_invalid_ptr(&args[1]);
		exit_if_invalid_ptr(&args[2]);
		f->eax = symlink ((const char *)args[1], (const char *)args[2]);
		break;
  }
}


// Added, System Call Implementation
// Added, System Call - Halt
void halt(void){
	shutdown_power_off();
}

// Added, System Call - Exit
void exit(int status){
	printf("%s: exit(%d)\n", thread_current()->name, status);
	thread_current()->exit_status = status;

	for (int i = 2; i < 128; i++) {
		if (thread_current()->fd[i] != NULL) close(i);
 	}
    thread_exit(); 
}

// Added, System Call - Exec
pid_t exec(const char *file) {
	return process_execute(file);
}

// Added, System Call - Wait
int wait(pid_t pid) {
	return process_wait(pid);
}

// Added, System Call - Create
bool create(const char *file, unsigned initial_size){
	if (!file) exit(-1);

	return filesys_create(file, initial_size);
}

// Added, System Call - Remove
bool remove(const char *file){
	if (!file) exit(-1);
	return filesys_remove(file);
}

// Added, System Call - Open
int open(const char *file){
	if (!file) exit(-1);

	lock_acquire(&syscall_lock);
	struct file *file_ptr = filesys_open(file);

    if (file_ptr != NULL) {
        for (int i = 2; i < 128; i++) {
            if (thread_current()->fd[i] == NULL) {
                if (strcmp(thread_current()->name, file) == 0) {
                    file_deny_write(file_ptr);
                }
                thread_current()->fd[i] = file_ptr;
                lock_release(&syscall_lock);
                return i;
            }
        }
    }


	lock_release(&syscall_lock);
	return -1;
}

// Added, System Call - Filesize
int filesize(int fd){
	is_null(fd);
	if (fd >= 2) {
		return file_length(thread_current()->fd[fd]);
	}
}

// Added, System Call - Read
int read(int fd, void *buffer, unsigned size){
	exit_if_invalid_ptr(buffer);
	lock_acquire(&syscall_lock);

	uint32_t result = -1;
	char byte;
	int i;

	if (fd == 0){
		for (i = 0; i < size; i++){
			byte = input_getc();

			if (byte == '\0') 
			break;
		}
		result = i;
	}
	else if (fd >= 2){
		if (NULL != thread_current()->fd[fd]){
			result = file_read(thread_current()->fd[fd], buffer, size);
		}
	}
	lock_release(&syscall_lock);
	if(-1 == result) exit(-1);

	return result;
}

// Added, System Call - Write
int write(int fd, const void *buffer, unsigned size){
	uint32_t result = -1;
	exit_if_invalid_ptr(buffer);
	lock_acquire(&syscall_lock);

	if (fd == 1){
		putbuf((char*)buffer, size);
		result =  size;
	}
	else if (fd >= 2){
		if (NULL != thread_current()->fd[fd]){
			if (thread_current()->fd[fd]->deny_write) {
				file_deny_write(thread_current()->fd[fd]);
			}	
			result = file_write(thread_current()->fd[fd], buffer, size);
		}
	}
	
	lock_release(&syscall_lock);
	if(-1 == result) exit(-1);
	
	return result;
}

// Added, System Call - Seek
void seek(int fd, unsigned position){
	is_null(fd);	
	file_seek(thread_current()->fd[fd], position);
}

// Added, System Call - Tell
unsigned tell(int fd){
	is_null(fd);
	if (fd >= 2) {
		return file_tell(thread_current()->fd[fd]);
	}
}

// Added, System Call - Close
void close(int fd){
	is_null(fd);
	if (fd >= 2) {
		file_close(thread_current()->fd[fd]);
		thread_current()->fd[fd] = NULL;
	}
}

// Added, System Call - Symlink
int symlink (char *target, char *linkpath){
	int result = -1;

 	struct file *target_file = filesys_open(target);

    if (target_file != NULL) {
		if(filesys_symlink(target, linkpath)){
			result = 0;
		}
		file_close(target_file);
    }
	return result;
}
