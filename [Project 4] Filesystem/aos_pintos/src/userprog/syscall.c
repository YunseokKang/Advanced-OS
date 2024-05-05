#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "vm/page.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stddef.h>
#include <hash.h>
#include <string.h>
#include "devices/shutdown.h"
#include "devices/input.h"


/* Array of syscall handler functions to dispatch on interrupt. */
#define SYSCALL_CNT SYS_STAT + 1
typedef void syscall_handler_func (struct intr_frame *);
static syscall_handler_func *syscall_handlers[SYSCALL_CNT];

/* Syscall handlers prototypes. */
static void syscall_handler (struct intr_frame *);
static void syscall_open (struct intr_frame *);
static void syscall_filesize (struct intr_frame *);
static void syscall_read (struct intr_frame *);
static void syscall_write (struct intr_frame *);
static void syscall_seek (struct intr_frame *);
static void syscall_tell (struct intr_frame *);
static void syscall_close (struct intr_frame *);
static void syscall_halt (struct intr_frame *);
static void syscall_exit (struct intr_frame *);
static void syscall_exec (struct intr_frame *);
static void syscall_wait (struct intr_frame *);
static void syscall_chdir (struct intr_frame *f);
static void syscall_mkdir (struct intr_frame *f);
static void syscall_readdir (struct intr_frame *f);
static void syscall_isdir (struct intr_frame *f);
static void syscall_inumber (struct intr_frame *f);
static void syscall_create (struct intr_frame *);
static void syscall_remove (struct intr_frame *);


// added
static void syscall_symlink(struct intr_frame *f);
static void syscall_stat(struct intr_frame *f);
static uint32_t syscall_get_arg (struct intr_frame *f, size_t idx);
static void syscall_validate_user_memory (const void *uaddr, size_t, bool);
static void syscall_validate_user_string (const char *uaddr, size_t max_size);
static void syscall_terminate_process (void);


/* Structure to represent a file descriptor within the process's file descriptor table (fd_table).
   This structure is used to store information about open files or directories, facilitating file system operations.
   It includes mechanisms for efficient look-up and identification, distinguishing between file and directory types. */

struct fd_entry
{
    struct hash_elem hash_elem; /* Hash table element used for organizing and searching within the fd_table. */
    int fd;                     /* Numeric identifier for the file descriptor, used as a unique index for file operations. */
    void *filesys_ptr;          /* Generic pointer to either a file or directory structure, depending on the type of file descriptor. */
    bool isdir;                 /* Boolean flag indicating whether the filesys_ptr points to a directory structure (`struct dir *`). If false, it points to a file structure (`struct file *`). */
};


#define SYSCALL_FIRST_FD 3 /* File descriptors 0, 1, and 2 are reserved for std i/o/e. */
static int fd_allocate (void);
static struct fd_entry *fd_lookup (int);
static hash_less_func fd_entry_less;
static hash_hash_func fd_entry_hash;
static hash_action_func fd_entry_destroy;


static struct semaphore filesys_mutex; // Ensure mutual exclusion to filesys


/* Sets up and registers system call handler functions for various system call numbers. 
   It populates an array of function pointers, `syscall_handlers`, with specific functions 
   that handle different system calls. After setting up these handlers, it registers the 
   system call interrupt handler with the interrupt controller to handle system call interrupts. 
   This setup is crucial for the operating system to respond appropriately to system calls 
   made by user programs. */
void syscall_init(void)
{
  // Assign handler functions to each system call by its identifier.
  syscall_handlers[SYS_HALT] = syscall_halt;
  syscall_handlers[SYS_EXIT] = syscall_exit;
  syscall_handlers[SYS_EXEC] = syscall_exec;
  syscall_handlers[SYS_WAIT] = syscall_wait;
  syscall_handlers[SYS_CREATE] = syscall_create;
  syscall_handlers[SYS_REMOVE] = syscall_remove;
  syscall_handlers[SYS_OPEN] = syscall_open;
  syscall_handlers[SYS_FILESIZE] = syscall_filesize;
  syscall_handlers[SYS_READ] = syscall_read;
  syscall_handlers[SYS_WRITE] = syscall_write;
  syscall_handlers[SYS_SEEK] = syscall_seek;
  syscall_handlers[SYS_TELL] = syscall_tell;
  syscall_handlers[SYS_CLOSE] = syscall_close;
  syscall_handlers[SYS_CHDIR] = syscall_chdir;
  syscall_handlers[SYS_MKDIR] = syscall_mkdir;
  syscall_handlers[SYS_READDIR] = syscall_readdir;
  syscall_handlers[SYS_ISDIR] = syscall_isdir;
  syscall_handlers[SYS_INUMBER] = syscall_inumber;
  // Register additional system call handlers as needed.
  syscall_handlers[SYS_SYMLINK] = syscall_symlink;
  syscall_handlers[SYS_STAT] = syscall_stat;

  barrier();  /* Ensure that all handler assignments are completed before registering the interrupt handler. */
  
  // Register the system call interrupt handler with the interrupt controller.
  // Interrupt vector 0x30 is used, with privilege level 3, enabling it to be triggered from user mode.
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/* Initializes the file descriptor management system for the current thread.
   This involves setting the initial file descriptor number and creating a hash table to store file descriptor entries. */
bool syscall_process_init(void)
{
  struct thread *t = thread_current();  // Retrieve the current thread's information.

  t->fd_next = SYSCALL_FIRST_FD;  // Initialize the file descriptor counter with the first usable file descriptor number.

  // Initialize the file descriptor hash table for the current thread.
  // This table will store entries corresponding to open files and directories.
  t->fd_table_ready = hash_init(&t->fd_table, fd_entry_hash, 
                                fd_entry_less, NULL);

  return t->fd_table_ready;  // Return true if the hash table was successfully initialized, false otherwise.
}


/* Cleans up the file descriptor table of the current thread, effectively closing all open files
   and freeing any associated resources. This function is called when system call processing is complete. */
void syscall_process_done(void)
{
  struct thread *t = thread_current();  // Get the current thread.

  // Early exit if the file descriptor table was never initialized.
  if (!t->fd_table_ready)
    return;

  // Clean up the file descriptor table: close all files and free resources.
  hash_destroy(&t->fd_table, fd_entry_destroy);  // Destroy the hash table and free all fd_entry resources.
  t->fd_table_ready = false;  // Mark the fd table as not ready to prevent further use.
}


/* Handles system calls from user programs. It retrieves the system call number,
   verifies it, and dispatches the appropriate handler function. */
static void syscall_handler(struct intr_frame *f)
{
  int syscall_number;  // To store the system call number.
  syscall_handler_func *handler_func;  // Pointer to the handler function.

  ASSERT(f != NULL);  // Ensure the frame pointer is not null.

  // Retrieve the system call number from the user's stack.
  syscall_number = syscall_get_arg(f, 0);
  
  // Validate the system call number and check handler presence.
  if (syscall_number < 0 || syscall_number >= SYSCALL_CNT || syscall_handlers[syscall_number] == NULL)
    {
      // If the system call number is invalid or no handler is registered, terminate the process.
      syscall_terminate_process();
    }
  else
    {
      // If valid, fetch the corresponding handler from the syscall handlers array.
      handler_func = syscall_handlers[syscall_number];
      handler_func(f);  // Call the handler function with the interrupt frame.
    }
}


/* Terminates the operating system by turning off the power. This function does not return. */
static void syscall_halt(struct intr_frame *f UNUSED)
{
  shutdown_power_off();  // Power off the machine.
}


/* Terminates the current user program and returns the specified status to the kernel. 
   This function does not return. */
static void syscall_exit(struct intr_frame *f)
{
  int32_t status = syscall_get_arg(f, 1);  // Retrieve the exit status from the user's stack.
  thread_current()->process_exit_code = status;  // Set the exit code in the current thread's control block.
  thread_exit();  // Terminate the current thread.
}


/* Executes a new process specified by the command line argument. Returns the TID of the new process,
   or TID_ERROR if the process could not be started. */
static void syscall_exec(struct intr_frame *f)
{
  const char *cmd_line = (const char*) syscall_get_arg(f, 1);  // Retrieve the command line argument.
  syscall_validate_user_string(cmd_line, PGSIZE);  // Validate the command line string from user space.
  tid_t tid = process_execute(cmd_line);  // Execute the process and get the TID.
  f->eax = tid;  // Store the TID (or TID_ERROR) in the eax register for the caller.
}


/* Waits for a child process specified by TID and retrieves the child's exit status. */
static void syscall_wait(struct intr_frame *f)
{
  tid_t tid = syscall_get_arg(f, 1);  // Get the TID of the child process to wait for.
  int32_t exit_code = process_wait(tid);  // Wait for the child process and retrieve the exit status.
  f->eax = exit_code;  // Store the exit status in the eax register for the caller.
}


/* Changes the current working directory of the process to the directory specified by DIR_PATH. 
   Returns true if successful, false otherwise. This system call enables processes to change 
   their context to a new directory. */
static void syscall_chdir(struct intr_frame *f)
{
    const char *dir_path = (const char *)syscall_get_arg(f, 1); // Retrieve the directory path argument from the system call.
    syscall_validate_user_string(dir_path, PGSIZE); // Validate the directory path string provided by the user.

    bool isdir = false; // Flag to check if the file system object is a directory.
    struct dir *dir_filesys_ptr = filesys_open(dir_path, &isdir); // Try to open the directory.

    f->eax = false; // Default return value is false (failure).
    if (dir_filesys_ptr != NULL) {
        if (isdir) {
            // If it is a directory, update the current working directory.
            filesys_closedir(thread_current()->cwd); // Close the current working directory.
            thread_current()->cwd = dir_filesys_ptr; // Set the new directory as the current working directory.
            f->eax = true; // Set return value to true (success).
        } else {
            // If the opened object is not a directory, close it.
            filesys_close(dir_filesys_ptr);
        }
    }
}



/* Creates a new directory at the specified path DIR_PATH. Returns true if successful, 
   false if the directory already exists or if any part of the path does not exist. */
static void syscall_mkdir(struct intr_frame *f)
{
    const char *dir_path = (const char *)syscall_get_arg(f, 1); // Retrieve the directory path from the system call.
    syscall_validate_user_string(dir_path, PGSIZE); // Validate the directory path string provided by the user.

    f->eax = filesys_mkdir(dir_path); // Attempt to create the directory and store the result (true or false) in eax.
}


/* Reads the next directory entry from a directory file described by file descriptor FD. 
   Stores the name of the entry in NAME, and returns true if successful, false if no more entries exist. */
static void syscall_readdir(struct intr_frame *f)
{
    int32_t fd = syscall_get_arg(f, 1);  // Retrieve the file descriptor from the system call.
    char *name = (char *)syscall_get_arg(f, 2);  // Retrieve the pointer to the buffer for storing the directory name.
    syscall_validate_user_memory(name, FILESYS_NAME_MAX + 1, true);  // Validate the buffer memory where the name will be stored.

    struct fd_entry *fd_entry = fd_lookup(fd);  // Look up the file descriptor entry.
    if (fd_entry == NULL || !fd_entry->isdir) {
        f->eax = false;  // Return false if FD is invalid or not a directory.
    } else {
        // If the descriptor is valid and is a directory, attempt to read the next directory entry.
        f->eax = filesys_readdir(fd_entry->filesys_ptr, name);
    }
}


/* Determines if a file descriptor FD corresponds to a directory. Returns true if it is a directory, 
   false if it is an ordinary file or invalid. */
static void syscall_isdir(struct intr_frame *f)
{
    int32_t fd = syscall_get_arg(f, 1);  // Retrieve the file descriptor from the system call.
    struct fd_entry *fd_entry = fd_lookup(fd);  // Look up the file descriptor entry.

    f->eax = (fd_entry != NULL && fd_entry->isdir);  // Return true if FD is a directory, false otherwise.
}



/* Retrieves the inode number associated with the file or directory described by file descriptor FD. */
static void syscall_inumber(struct intr_frame *f)
{
    int32_t fd = syscall_get_arg(f, 1);  // Retrieve the file descriptor from the system call.
    struct fd_entry *fd_entry = fd_lookup(fd);  // Look up the file descriptor entry.

    if (fd_entry == NULL) {
        f->eax = SYSCALL_ERROR;  // Return an error code if the file descriptor is invalid.
    } else {
        // Retrieve the inode number for the file or directory and return it.
        f->eax = fd_entry->isdir ? filesys_dir_inumber(fd_entry->filesys_ptr) 
                                 : filesys_file_inumber(fd_entry->filesys_ptr);
    }
}


/* Attempts to create a new file at a specified path PATH with an initial size INITIAL_SIZE. 
   Returns true if the file was successfully created, false otherwise. */
static void syscall_create(struct intr_frame *f)
{
  const char *path = (const char *)syscall_get_arg(f, 1);  // Retrieve the file path from the system call.
  uint32_t initial_size = syscall_get_arg(f, 2);  // Retrieve the initial size for the file.
  syscall_validate_user_string(path, PGSIZE);  // Validate the path string provided by the user.

  f->eax = filesys_create(path, initial_size);  // Attempt to create the file and store the result (true or false) in eax.
}


/* Deletes the file or directory at the specified PATH. Returns true if successful, false otherwise.
   The removal does not close the file if it is open, allowing continued operations on open file descriptors. */
static void syscall_remove(struct intr_frame *f)
{
  const char *path = (const char *) syscall_get_arg(f, 1);  // Retrieve the file path from the system call.
  syscall_validate_user_string(path, PGSIZE);  // Validate the user-provided string for safety.

  f->eax = filesys_remove(path);  // Attempt to remove the file or directory and store the result (true or false) in eax.
}


/* Opens the file or directory at PATH and returns a file descriptor, or -1 if the file could not be opened.
   This descriptor can be used to manipulate the file or directory. */
static void syscall_open(struct intr_frame *f)
{
  const char *path = (const char *) syscall_get_arg(f, 1);  // Retrieve the path from the system call.
  struct fd_entry *fd_entry = NULL;  // Initialize fd_entry pointer to NULL.
  syscall_validate_user_string(path, PGSIZE);  // Validate the path string from the user.

  fd_entry = malloc(sizeof *fd_entry);  // Allocate memory for the file descriptor entry.
  if (fd_entry == NULL)
    goto fail;  // If memory allocation fails, jump to the fail label.

  // Try to open the file or directory.
  fd_entry->filesys_ptr = filesys_open(path, &fd_entry->isdir);
  if (fd_entry->filesys_ptr == NULL)
    goto fail;  // If opening fails, jump to the fail label.

  fd_entry->fd = fd_allocate();  // Allocate a file descriptor number.
  hash_insert(&thread_current()->fd_table, &fd_entry->hash_elem);  // Insert the new fd entry into the current thread's fd table.
  f->eax = fd_entry->fd;  // Return the file descriptor.
  return;  // Exit the function successfully.

fail:
  free(fd_entry);  // Free the allocated fd_entry on failure.
  f->eax = -1;  // Return -1 indicating failure to open the file.
  return;
}


/* Returns the size of the file associated with file descriptor FD, or SYSCALL_ERROR if FD is invalid
   or does not represent a file. */
static void syscall_filesize(struct intr_frame *f)
{
  int32_t fd = syscall_get_arg(f, 1);  // Retrieve the file descriptor from the system call.
  struct fd_entry *fd_entry;

  fd_entry = fd_lookup(fd);  // Lookup the file descriptor entry.
  if (fd_entry == NULL || fd_entry->isdir)
    {
      f->eax = SYSCALL_ERROR;  // Return error if FD is invalid or is a directory.
    }
  else
    {
      f->eax = filesys_filesize(fd_entry->filesys_ptr);  // Get the filesize and store it in eax.
    }
}


/* Reads SIZE bytes from the file described by FD into BUFFER. Returns the number of bytes read,
   or SYSCALL_ERROR if the read fails. Special case: FD 0 reads from the keyboard. */
static void syscall_read(struct intr_frame *f)
{
  int32_t fd = syscall_get_arg(f, 1);  // File descriptor from which to read.
  uint8_t *buffer = (uint8_t *) syscall_get_arg(f, 2);  // Buffer to store the read data.
  uint32_t size = syscall_get_arg(f, 3);  // Number of bytes to read.
  struct fd_entry *fd_entry;
  syscall_validate_user_memory(buffer, size, true);  // Ensure the buffer is valid and writable.

  if (fd == 0)
    {
      size_t bytes_read = 0;
      while (bytes_read < size)
        {
          buffer[bytes_read] = input_getc();  // Read from the keyboard.
          bytes_read++;
        }
      f->eax = bytes_read;  // Return the number of bytes read.
    }
  else
    {
      fd_entry = fd_lookup(fd);
      if (fd_entry == NULL || fd_entry->isdir)
        {
          f->eax = SYSCALL_ERROR;  // Return error if FD is invalid or is a directory.
          return;
        }
      f->eax = filesys_read(fd_entry->filesys_ptr, buffer, size);  // Perform the file read.
    }
}


/* Writes SIZE bytes from BUFFER to the file described by FD. Returns the number of bytes written,
   which may be less than SIZE if there is less space left. Special case: FD 1 writes to the console. */
static void syscall_write(struct intr_frame *f)
{
  int32_t fd = syscall_get_arg(f, 1);  // File descriptor to write to.
  const uint8_t *buffer = (const uint8_t *)syscall_get_arg(f, 2);  // Buffer containing data to write.
  size_t size = syscall_get_arg(f, 3);  // Number of bytes to write.
  struct fd_entry *fd_entry;
  syscall_validate_user_memory(buffer, size, false);  // Ensure the buffer is valid.

  if (fd == 1)
    {
      // Write to the console if fd is 1 (stdout).
      putbuf((const char *)buffer, size);  // Use putbuf to handle console output.
      f->eax = size;  // Assume all bytes are written to the console.
    }
  else
    {
      fd_entry = fd_lookup(fd);
      if (fd_entry == NULL || fd_entry->isdir)
        {
          f->eax = SYSCALL_ERROR;  // Return error if FD is invalid or is a directory.
          return;
        }
      f->eax = filesys_write(fd_entry->filesys_ptr, buffer, size);  // Perform the file write.
    }
}


/* Sets the file position for the file descriptor FD to POSITION, 
   which is measured in bytes from the start of the file. 
   This allows for adjusting the read/write position within the file. */
static void syscall_seek(struct intr_frame *f)
{
  int32_t fd = syscall_get_arg(f, 1);  // Retrieve the file descriptor from the system call.
  unsigned position = syscall_get_arg(f, 2);  // Retrieve the position to set the file pointer to.
  struct fd_entry *fd_entry;

  fd_entry = fd_lookup(fd);  // Look up the file descriptor entry.
  if (fd_entry == NULL || fd_entry->isdir)
    {
      // Check if the file descriptor is valid and not a directory.
      f->eax = SYSCALL_ERROR;  // Return an error code if invalid.
      return;
    }
  filesys_seek(fd_entry->filesys_ptr, position);  // Set the file position.
}


/* Returns the current position of the file pointer for the file descriptor FD,
   which indicates the next byte to be read or written. */
static void syscall_tell(struct intr_frame *f)
{
  int32_t fd = syscall_get_arg(f, 1);  // Retrieve the file descriptor from the system call.
  struct fd_entry *fd_entry;

  fd_entry = fd_lookup(fd);  // Look up the file descriptor entry.
  if (fd_entry == NULL || fd_entry->isdir)
    {
      // Check if the file descriptor is valid and not a directory.
      f->eax = SYSCALL_ERROR;  // Return an error code if invalid.
      return;
    }
  f->eax = filesys_tell(fd_entry->filesys_ptr);  // Get and return the current file position.
}


/* Closes the file associated with file descriptor FD and frees its associated resources.
   This operation is crucial for resource management and preventing leaks. */
static void syscall_close(struct intr_frame *f)
{
  int32_t fd = syscall_get_arg(f, 1);  // Retrieve the file descriptor from the system call.
  struct fd_entry query;
  struct hash_elem *e;

  query.fd = fd;  // Set the query object's fd for hash lookup.
  e = hash_delete(&thread_current()->fd_table, &query.hash_elem);  // Try to delete the fd entry from the hash table.
  if (e == NULL)
    return;  // If the fd does not exist, just return.

  // If found, close the file or directory and free the fd_entry.
  fd_entry_destroy(e, NULL);
}


/* Helper function to allocate the next available file descriptor for the current thread. */
static int fd_allocate(void)
{
  return thread_current()->fd_next++;  // Increment and return the next available file descriptor.
}

/* Frees resources associated with a file descriptor entry and closes the open file or directory. */
static void fd_entry_destroy(struct hash_elem *e, void *aux UNUSED)
{
  struct fd_entry *fd_entry = hash_entry(e, struct fd_entry, hash_elem);  // Retrieve the fd_entry from the hash element.
  if (fd_entry->isdir)
    filesys_closedir(fd_entry->filesys_ptr);  // Close the directory if it is one.
  else
    filesys_close(fd_entry->filesys_ptr);  // Close the file otherwise.
  free(fd_entry);  // Free the memory allocated to the fd_entry.
}

/* Looks up a file descriptor entry in the current thread's file descriptor table. */
static struct fd_entry *fd_lookup(int fd)
{
  struct thread *t = thread_current();  // Get the current thread.
  struct fd_entry query, *found;
  struct hash_elem *e;

  query.fd = fd;  // Set up the query object with the fd to search for.
  e = hash_find(&t->fd_table, &query.hash_elem);  // Find the fd_entry in the hash table.
  found = e != NULL ? hash_entry(e, struct fd_entry, hash_elem) : NULL;  // Extract the entry if found.
  return found;  // Return the found entry or NULL.
}

/* Hash function for hashing file descriptor entries. */
static unsigned fd_entry_hash(const struct hash_elem *e, void *aux UNUSED)
{
  const struct fd_entry *fd_entry = hash_entry(e, struct fd_entry, hash_elem);  // Retrieve the fd_entry.
  return hash_int(fd_entry->fd);  // Hash the file descriptor.
}

/* Comparison function for file descriptor entries in the hash table. */
static bool fd_entry_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct fd_entry *a = hash_entry(a_, struct fd_entry, hash_elem);  // Retrieve fd_entry 'a'.
  const struct fd_entry *b = hash_entry(b_, struct fd_entry, hash_elem);  // Retrieve fd_entry 'b'.
  return a->fd < b->fd;  // Compare the file descriptors.
}

/* Terminates the current process due to an error, setting the exit code to -1 and freeing resources. */
static void syscall_terminate_process(void)
{
  thread_current()->process_exit_code = -1;  // Set the exit code to indicate an error.
  thread_exit();  // Exit the thread, freeing its resources.
}


/* Verifies if a block of memory starting at address UADDR and extending for SIZE bytes 
   is valid within the current thread's address space. If the memory is not valid or 
   the required memory is not writable when requested, the function terminates the process. */
static void syscall_validate_user_memory(const void *uaddr, size_t size, bool writable)
{
  const void *current_page;
  struct page *p;

  ASSERT(thread_current()->pagedir != NULL);  // Assert the current thread has a valid page directory.

  if (uaddr == NULL)
    syscall_terminate_process();  // Terminate the process if the user address is NULL.

  // Check each page in the range for validity.
  for (current_page = pg_round_down(uaddr);
       (char *)current_page <= (char *)pg_round_down((const uint8_t *)uaddr + size);
       current_page = (char *)current_page + PGSIZE)
  {
    if (!is_user_vaddr(current_page)  // Check if the address is within user space.
        || (p = page_lookup((void *)current_page)) == NULL  // Look up the page.
        || (writable && !page_is_writable(p)))  // Ensure the page is writable if required.
      syscall_terminate_process();  // Terminate the process if any condition fails.
  }
}


/* Ensures that UADDR points to a valid null-terminated string within the user space.
   Terminates the process if the string exceeds MAX_SIZE or is otherwise invalid. */
static void syscall_validate_user_string(const char *uaddr, size_t max_size)
{
  const char *caddr = uaddr;

  ASSERT(thread_current()->pagedir != NULL);  // Assert the current thread has a valid page directory.

  // Validate each character until max_size or null-terminator is found.
  for (; (char *)caddr != (char *)uaddr + max_size + 1; ++caddr)
  {
    syscall_validate_user_memory(caddr, sizeof(char), false);  // Validate memory for each character.
    if (*caddr == '\0')
      break;  // Stop if null-terminator is found.
  }
}


/* Retrieves an argument from the system call, validated for memory safety.
   IDX is the index of the argument, with 0 being the syscall number. */
static uint32_t syscall_get_arg(struct intr_frame *f, size_t idx)
{
  uint32_t *arg = (uint32_t *)(f->esp) + idx;  // Calculate the address of the argument in the stack.
  syscall_validate_user_memory(arg, sizeof(uint32_t), false);  // Validate the memory where the argument is stored.
  return *arg;  // Return the argument.
}


// added
int symlink (char *target, char *linkpath)
{ 
  struct file *target_file = filesys_open (target, false);

  if (target_file == NULL)
    {
      return -1;
    }

  // sema_down (&filesys_mutex);
  bool success = filesys_symlink (target, linkpath);
  // sema_up (&filesys_mutex);

  return success ? 0 : -1;
}


/* Creates a symbolic link named LINKPATH that points to TARGET. Returns 0 if successful, -1 otherwise. */
static void syscall_symlink(struct intr_frame *f)
{
  char *target = *((char **)f->esp + 1);  // Retrieve the target for the symlink.
  char *linkpath = *((char **)f->esp + 2);  // Retrieve the path for the symlink.
  f->eax = symlink(target, linkpath);  // Create the symlink and store the result.
}


/* Retrieves file statistics for the file at PATHNAME, filling the stat structure in BUF.
   Returns 0 on success, -1 on failure. */
static void syscall_stat(struct intr_frame *f)
{
  struct file *file;
  struct inode *inode;
  struct stat st;

  const char *pathname = syscall_get_arg(f, 1);  // Retrieve the pathname.
  uint8_t* buf = (uint8_t *)syscall_get_arg(f, 2);  // Retrieve the buffer to store file stats.

  // Validate user memory for pathname and buffer.
  if (!is_user_vaddr(pathname) || !is_user_vaddr(buf)) {
    f->eax = -1;
    return;
  }

  file = filesys_open(pathname, false);  // Open the file.
  if (file == NULL) {
    f->eax = -1;
    return;
  }

  inode = file_get_inode(file);  // Retrieve the inode from the file.
  if (inode == NULL) {
    file_close(file);
    f->eax = -1;
    return;
  }

  // Populate the stat structure.
  st.logical_size = filesys_filesize(file);
  st.physical_size = inode_get_physicalsize(inode);
  st.inode_number = inode_get_inumber(inode);

  // Calculate the number of blocks based on physical size.
  if (st.physical_size == 0) {
    st.blocks = 0;
  } else if (st.physical_size < BLOCK_SECTOR_SIZE) {
    st.blocks = 1;
  } else {
    st.blocks = st.physical_size / BLOCK_SECTOR_SIZE;
  }

  memcpy(buf, &st, sizeof(st));  // Copy the stat structure to user buffer.

  file_close(file);  // Close the file.
  f->eax = 0;  // Set return value to success.
}
