#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/page.h"

#define MAX_ARGS 3

static void syscall_handler (struct intr_frame *);
	
void syscall_init (void) 
{
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
	lock_init(&filesys_lock);
}

struct vm_entry *check_address(void *addr, void *esp)
{
    // Verify if the pointer is within user space address boundaries.
    // If it's an incorrect access, terminate the process.
    if (addr < (void *)0x8048000 || addr >= (void *)0xc0000000) {
        exit(-1);
    }

    // Use findVmEntry to check if the address is associated with a vm_entry.
    // If found, return the vm_entry; otherwise, attempt to handle a stack growth scenario.
    struct vm_entry *vme = findVmEntry(addr);
    if (vme == NULL) {
        if (!verify_stack(addr, esp)) {
            exit(-1);
        }
        expand_stack(addr);
        vme = findVmEntry(addr);
    }
    return vme;
}


void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write) {
    // Cast the void pointer to a char pointer for arithmetic operations.
    char *ptr = (char *)pg_round_down(buffer);
    // Calculate the end of the buffer to avoid pointer arithmetic in the loop condition.
    char *end = (char *)buffer + size;

    // Iterate over each page in the buffer.
    for (; ptr < end; ptr += PGSIZE) {
        // Cast back to void* when passing to check_address, as it expects a void*.
        struct vm_entry *vme = check_address((void *)ptr, esp);

        // Check if the vm_entry is valid and writable if needed.
        if (vme == NULL || !(vme->writable)) {
            exit(-1);
        }
        // Note: No further modifications needed inside the loop.
    }
}

void check_valid_string(void *str, void *esp) {
    // Cast the void pointer to char pointer for arithmetic and dereferencing.
    char *char_str = (char *)str;
    
    // Initially check if the starting address of the string is valid.
    struct vm_entry *vme = check_address(str, esp);
    if (vme == NULL) {
        exit(-1); // Exit if the starting address is invalid.
    }

    // Calculate the string length to find the end of the string.
    int size = 0;
    while (char_str[size] != '\0') {
        size++;
    }

    // Iterate over the pages spanned by the string, from start to end.
    // Start from the rounded-down address of the initial string pointer.
    for (char *ptr = (char *)pg_round_down(str); ptr < char_str + size; ptr += PGSIZE) {
        // As the address could span multiple pages, check each page for validity.
        vme = check_address(ptr, esp);
        if (vme == NULL) {
            exit(-1); // Exit if any part of the string is in an invalid address space.
        }
    }
}

void check_valid_string_length(void *str, unsigned size, void *esp) {
    char *char_ptr = (char *)str; // Cast to char* for valid pointer arithmetic.
    for (unsigned i = 0; i < size; i++) {
        if (!check_address((void *)(char_ptr + i), esp)) {
            exit(-1); // Terminate if any byte's address is invalid.
        }
    }
}

// Added, Prevents the buffer from being swapped out by pinning it.
void pin_buffer(void *start, int size) {
    char *ptr;
    char *start_char = (char *)start; // Cast to char * for pointer arithmetic
    for (ptr = start_char; ptr < start_char + size; ptr += PGSIZE) 
    {
        struct vm_entry *vme = findVmEntry((void *)ptr); // Finds the vm_entry for the current address.
        vme->pinned = true; // Marks the vm_entry as pinned to prevent swapping.
        if (!vme->is_loaded) // If the vm_entry is not yet loaded,
            handle_mm_fault(vme); // handle the page fault to load the page.
    }
}

// Added, Unpins the buffer to allow it to be swapped out again.
void unpin_buffer(void *start, int size) {
    char *ptr;
    char *start_char = (char *)start; // Cast to char * for pointer arithmetic
    for (ptr = start_char; ptr < start_char + size; ptr += PGSIZE) 
	{
        struct vm_entry *vme = findVmEntry((void *)ptr); // Finds the vm_entry for the current address.
        vme->pinned = false; // Marks the vm_entry as unpinned to allow swapping.
    }
}


// Added, Retrieves arguments stored on the user stack and verifies their addresses.
void get_argument(void *esp, int *arg, int count) {
    int i = 0;
    char *ptr = (char *)esp + 4; // Cast to char* to perform arithmetic operations

    // Iterates over the count of arguments to retrieve
    while (count--) {
        char *next_arg_ptr = ptr + (i * 4); // Move to the next argument's address
        check_address((void *)next_arg_ptr, esp); // Check if the argument's address is valid

        // Cast the pointer to int* before dereferencing to get the argument value
        arg[i] = *(int *)next_arg_ptr; 
        i++; // Increment after retrieving the argument to move to the next
    }
}







void halt(void)
{
	shutdown_power_off();
}


void exit(int status)
{
    struct thread *cur = thread_current(); 	// Gets the current thread.
    										// Saves the exit status in the process descriptor.
    cur->exit_status = status;
    printf("%s: exit(%d)\n", cur->name, status); // Prints the exit message.
    thread_exit(); // Exits the thread, cleaning up the process.
}



bool create(const char *file, unsigned initial_size)
{
	return filesys_create(file, initial_size);
	//return true if success, else false
}


bool remove(const char *file)
{
	return filesys_remove(file);
	//return true if success, else false
}

tid_t exec(const char* cmd_line)
{
    // Calls process_execute to create a child process
    tid_t tid = process_execute(cmd_line);
    // Searches for the process descriptor of the created child process
    struct thread *child = get_child_process(tid);
    // Waits until the child process has loaded its program
    sema_down(&(child->load));
    // Returns -1 if program loading failed
    if (!(child->is_loaded))
        return -1;
    // Returns the tid of the child process if program loading succeeded
    return tid;
}


int wait(tid_t tid)
{
    // Waits for a child process to exit
    return process_wait(tid);
}


int open(const char *file)
{
    lock_acquire(&filesys_lock); // Acquires a lock for file system operations to ensure atomic access
    struct thread* cur = thread_current();
    // Opens the file
    struct file* fp = filesys_open(file);
    // Returns -1 if the file does not exist
    if (fp == NULL) {
        lock_release(&filesys_lock);
        return -1;
    }
    // Assigns a file descriptor to the opened file object
    int fd = cur->new_fd++;
    cur->fd_table[fd] = fp;
    // Returns the file descriptor
    lock_release(&filesys_lock);
    return fd;
}

void close(int fd)
{
    struct thread* cur = thread_current();
    // Closes the file associated with the file descriptor
    file_close(cur->fd_table[fd]);
    // Resets the file descriptor entry in the table to NULL
    cur->fd_table[fd] = NULL;
}

int filesize(int fd)
{
    struct thread* cur = thread_current();
    // Searches for the file object using the file descriptor
    struct file* fp = cur->fd_table[fd];
    // Returns -1 if the file does not exist
    if (fp == NULL)
        return -1;
    // Returns the length of the file
    return file_length(fp);
}


int read(int fd, void *buffer, unsigned size)
{
    lock_acquire(&filesys_lock); // Ensures atomic access to file operations
    pin_buffer(buffer, size); // Prevents swapping of the buffer while reading
    struct thread *cur = thread_current();
    int read_length = 0;

    if (fd == 0) {
        // If fd is 0, reads from the keyboard input and stores it in the buffer
        for (int i = 0; i < size; i++) {
            ((char*)buffer)[i] = input_getc();
            read_length++;
            if (((char*)buffer)[i] == '\0')
                break;
        }
    } else {
        // If fd is not 0, reads data from the file and stores it in the buffer
        struct file *fp = cur->fd_table[fd];
        if (fp != NULL)
            read_length = file_read(fp, buffer, size);
    }
    unpin_buffer(buffer, size); // Allows swapping of the buffer after reading
    lock_release(&filesys_lock);
    return read_length;
}

int write(int fd, const void *buffer, unsigned size)
{
    struct thread *cur = thread_current();
    int write_length = 0;
    lock_acquire(&filesys_lock); // Ensures atomic access to file operations
    pin_buffer(buffer, size); // Prevents swapping of the buffer while writing
    if (fd == 1) {
        // If fd is 1, writes the data from the buffer to the console
        putbuf(buffer, size);
        write_length = size;
    } else {
        // If fd is not 1, writes the data from the buffer to the file
        struct file *fp = cur->fd_table[fd];
        if (fp != NULL)
            write_length = file_write(fp, buffer, size);
    }
    unpin_buffer(buffer, size); // Allows swapping of the buffer after writing
    lock_release(&filesys_lock);
    return write_length;
}


void seek(int fd, unsigned position)
{
    struct thread *cur = thread_current();
    // Searches for the file object using the file descriptor
    struct file *fp = cur->fd_table[fd];
    // Moves the file's position to the specified position
    file_seek(fp, position);
}

unsigned tell(int fd)
{
    struct thread *cur = thread_current();
    // Searches for the file object using the file descriptor
    struct file *fp = cur->fd_table[fd];
    // Returns the current position of the file
    return file_tell(fp);
}



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

	
static void syscall_handler (struct intr_frame *f UNUSED) 
{
	uint32_t syscall_number;
	void *esp;
	int arg[MAX_ARGS];
	esp=f->esp;
	check_address(esp, f->esp);
	syscall_number=*(uint32_t*)esp;

	switch(syscall_number)
	{

		case SYS_HALT:
			halt();
			break;
			
		case SYS_EXIT:
			get_argument(esp, arg, 1);
			exit((int)arg[0]);
			break;
			
		case SYS_CREATE:
			get_argument(esp, arg, 2);
			check_valid_string((void *)arg[0], f->esp);
			f->eax = create((const char*)arg[0], (unsigned)arg[1]);
			break;
			
		case SYS_REMOVE:
			get_argument(esp, arg, 1);
			check_valid_string((void *)arg[0], f->esp);
			f->eax=remove((const char *)arg[0]);
			break;
			
		case SYS_EXEC:
			get_argument(esp, arg, 1);
			check_valid_string((void *)arg[0], f->esp);
			f->eax=exec((const char *)arg[0]);
			break;
			
		case SYS_WAIT:
			get_argument(esp, arg, 1);
			f->eax=wait((int)arg[0]);
			break;
			
		case SYS_READ:
			get_argument(esp, arg, 3);
			check_valid_string_length((void *) arg[1], (unsigned) arg[2], f->esp);
			f->eax=read((int)arg[0], (void*)arg[1], (unsigned)arg[2]);
			break;
			
		case SYS_WRITE:
			get_argument(esp, arg, 3);
			check_valid_string_length((void *) arg[1], (unsigned) arg[2], f->esp);
			f->eax=write((int)arg[0], (void*)arg[1], (unsigned)arg[2]);
			break;
			
		case SYS_OPEN:
			get_argument(esp, arg, 1);
			check_valid_string((void *)arg[0], f->esp);
			f->eax=open((const char *)arg[0]);
			break;
			
		case SYS_FILESIZE:
			get_argument(esp, arg, 1);
			f->eax=filesize((int)arg[0]);
			break;
			
		case SYS_SEEK:
			get_argument(esp, arg, 2);
			seek((int)arg[0], (unsigned)arg[1]);
			break;
			
		case SYS_TELL:
			get_argument(esp, arg, 1);
			f->eax=tell((int)arg[0]);
			break;
			
		case SYS_CLOSE:
			get_argument(esp, arg, 1);
			close((int)arg[0]);
			break;
			
		case SYS_SYMLINK:
		    get_argument(esp, arg, 2); 					// Assuming arg[0] is target, arg[1] is linkpath
		    check_valid_string((void *)arg[0], f->esp); // Validate target path
		    check_valid_string((void *)arg[1], f->esp); // Validate linkpath
		    f->eax = symlink((char *)arg[0], (char *)arg[1]); // Call symlink and set return value
		    break;

	}
}
