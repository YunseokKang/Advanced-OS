#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

//added
#include "vm/page.h"
#include "vm/frame.h"
#include "syscall.h"
#include "threads/synch.h"


/* This lock is used by processes to synchronize modifications to their parent or child structures,
   thereby preventing race conditions during simultaneous exits of multiple processes. */
static struct lock process_child_lock;


/* Structure to pass necessary details such as the process name and arguments
   from process_execute() through start_process() to load(). It includes a semaphore
   to ensure the process remains idle until all arguments are fully loaded into the stack. */
struct process_info {
  char *cmd_line;           /* Command line arguments stored on the heap. */
  char *program_name;       /* Name of the program, derived from the first argument. */
  struct dir *cwd;          /* Inherited current working directory of the process. */
  struct semaphore loaded;  /* Semaphore that halts execution until the process info 
                               is completely initialized in the stack. */
  struct process_child *inparent;
                          /* Link to this process's record in its parent's context. */
  bool load_success;        /* Flag indicating whether loading was successful. */
};


static thread_func start_process NO_RETURN;
static bool pass_args_to_stack(struct process_info *p_info, void **esp);
static bool stack_push(void **esp, void *data, size_t size);
static bool load (struct process_info *p_info, void (**eip) (void), void **esp);


void process_init (void) { lock_init(&process_child_lock); }


/* Starts a new thread that runs a user program loaded from FILENAME. This thread can be scheduled
   and may exit before process_execute() returns. It returns the new process's thread ID, or TID_ERROR
   if the thread creation fails. */
tid_t process_execute (const char *file_name)
{
  tid_t tid;
  struct thread *curr_t = thread_current ();  // Get the current thread's pointer.

  struct process_info *p_info = calloc (1, sizeof(struct process_info));  // Allocate memory for process information.
  struct process_child *p_child = calloc (1, sizeof(struct process_child));  // Allocate memory for child process structure.
  if (p_info == NULL || p_child == NULL)  // Check for memory allocation failure.
    {
      tid = TID_ERROR;  // Set thread ID to error if memory allocation fails.
      goto done;
    }

  /* Initialize the semaphores in process_info and process_child structures. */
  sema_init (&p_info->loaded, 0);  // Initialize the semaphore to control the loading of process info.
  sema_init (&p_child->exited, 0);  // Initialize the semaphore to signal exit of child process.

  /* Link child's record with its parent. */
  p_child->thread = NULL;  // Initially, no thread is associated with the child.
  p_info->inparent = p_child;  // Associate child record with its parent.
  lock_acquire (&process_child_lock);  // Acquire lock to modify process structures safely.
  list_push_back (&curr_t->process_children, &p_child->elem);  // Add child to parent's list of children.
  lock_release (&process_child_lock);  // Release the lock after modification.

  /* Safely copy the file name to avoid race conditions with the loader. */
  p_info->cmd_line = palloc_get_page (0);  // Allocate a page for the command line.
  if (p_info->cmd_line == NULL)  // Check if the page allocation failed.
    {
      tid = TID_ERROR;  // Set thread ID to error if allocation fails.
      goto done;
    }
  strlcpy (p_info->cmd_line, file_name, PGSIZE);  // Copy the command line into the allocated page.

  /* Extract the program name from the command line without altering the original string. */
  size_t len_prog_name = strcspn(p_info->cmd_line, " ");  // Determine the length of the program name.
  p_info->program_name = calloc (sizeof(char), len_prog_name + 1);  // Allocate space for the program name.
  p_info->cwd = dir_reopen (curr_t->cwd);  // Reopen the current working directory for the new process.
  if (p_info->program_name == NULL)  // Check if allocation for the program name failed.
    {
      tid = TID_ERROR;  // Set thread ID to error if allocation fails.
      goto done;
    }
  memcpy(p_info->program_name, p_info->cmd_line, len_prog_name);  // Copy the program name from the command line.

  /* Create a new thread to execute the user program. */
  tid = thread_create (p_info->program_name, PRI_DEFAULT, start_process, p_info);  // Create the thread with the extracted program name.
  sema_down (&p_info->loaded);  // Wait on the semaphore until the process is fully loaded.

done: /* Cleanup and final steps occur here, handling both success and error cases. */
  if (p_info->load_success == false)  // Check if the process load was unsuccessful.
    tid = TID_ERROR;  // Set thread ID to error if loading failed.
  if (tid == TID_ERROR)  // If any error occurred,
    {
      if (p_child != NULL)  // Check if child structure exists.
        list_remove (&p_child->elem);  // Remove the child from the parent's list.
      free (p_child);  // Free the child process structure.
      if (p_info != NULL)  // Check if process info structure exists.
        dir_close (p_info->cwd);  // Close the directory handle.
    }
  else
    p_child->tid = tid;  // If successful, set the child's thread ID.
  if (p_info != NULL)  // Check if process info structure exists.
    palloc_free_page (p_info->cmd_line);  // Free the page allocated for the command line.
  free (p_info);  // Free the process info structure.
  return tid;  // Return the thread ID or error.
}


/* Compares the thread id (tid) of a process_child structure with a given tid. Used to find
   a specific child process in a list. */
static bool process_elem_tid_equal (struct list_elem *elem, void *aux)
{
  struct process_child *child = list_entry (elem, struct process_child, elem);  // Retrieve the process_child from the list element.
  return child->tid == *(tid_t *)aux;  // Return true if the tids match.
}

/* Compares the file descriptor id of a process_fd structure with a given id. Used to find
   a specific file descriptor in a list. */
static bool process_elem_fd_equal (struct list_elem *elem, void *aux)
{
  struct process_fd *fd = list_entry(elem, struct process_fd, list_elem);  // Retrieve the process_fd from the list element.
  return fd->id == *(int *)aux;  // Return true if the ids match.
}

/* Retrieves a file descriptor structure from a thread's file descriptor table by id. */
struct process_fd *process_get_fd(struct thread *t, int id)
{
  struct list_elem *e;
  if (!list_empty(&t->process_fd_table))  // Check if the fd table is not empty.
    {
      e = list_find(&t->process_fd_table, process_elem_fd_equal, &id);  // Find the fd in the list.
      return list_entry(e, struct process_fd, list_elem);  // Return the process_fd if found.
    }
  return NULL;  // Return NULL if not found or list is empty.
}

/* Allocates a new file descriptor for a thread, associating it with a file and a file name. */
int process_new_fd(struct thread *t, struct file *file, char* file_name)
{
  int id = t->process_fd_next++;  // Increment the next available fd id.
  struct process_fd *fd = malloc(sizeof(struct process_fd));  // Allocate memory for the new process_fd.
  if (fd == NULL) return -1;  // Return -1 if the allocation fails.

  fd->id = id;  // Set the fd id.
  list_push_back(&t->process_fd_table, &fd->list_elem);  // Add the new fd to the thread's fd table.
  fd->file = file;  // Associate the file with the fd.
  fd->file_name = file_name;  // Associate the file name with the fd.
  return id;  // Return the new id.
}

/* Removes a file descriptor from a thread's file descriptor table by id and frees its resources. */
void process_remove_fd(struct thread *t, int id)
{
  struct process_fd *fd = process_get_fd(t, id);  // Retrieve the fd from the thread's fd table.
  if (fd == NULL) return;  // Return immediately if the fd is not found.
  list_remove(&fd->list_elem);  // Remove the fd from the list.
  free(fd);  // Free the memory allocated to the fd.
}

/* Loads a user program and starts its execution. This function is run by a new thread. */
static void start_process (void *process_info)
{
  struct process_info *p_info = (struct process_info *) process_info;  // Cast the process_info from the passed void pointer.
  struct thread *cur = thread_current ();  // Get the current thread.
  struct intr_frame if_;
  bool success = false;

  /* Set up process-specific values from the process_info structure. */
  cur->process_fn = p_info->program_name;  // Set the current process' function name.
  cur->cwd = p_info->cwd;  // Set the current working directory.
  lock_acquire (&process_child_lock);  // Acquire the child process lock.
  cur->inparent = p_info->inparent;  // Link the process to its parent.
  if (cur->inparent != NULL)
      cur->inparent->thread = cur;  // Set the current thread as the parent thread.
  lock_release (&process_child_lock);  // Release the child process lock.

  /* Initialize the interrupt frame and prepare to load the executable. */
  memset (&if_, 0, sizeof if_);  // Clear the interrupt frame structure.
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;  // Set segment registers to user data segment.
  if_.cs = SEL_UCSEG;  // Set code segment to user code segment.
  if_.eflags = FLAG_IF | FLAG_MBS;  // Set flags for interrupt enable and mandatory flag bits.

  /* Open the executable file and deny writing to ensure it remains unchanged during execution. */
  struct file* file = filesys_open (p_info->program_name, NULL);  // Open the file specified by the program name.
  if (file != NULL) filesys_deny_write (file);  // Deny write access to the file if it is successfully opened.

  success = load (p_info, &if_.eip, &if_.esp);  // Attempt to load the program into memory.

  /* Initialize system call infrastructure. */
  cur->fd_table_ready = false;
  success = success && syscall_process_init ();  // Initialize system calls and check load success.

  sema_up (&p_info->loaded);  // Signal that the process has been loaded.

  /* Terminate the thread if loading failed. */
  if (!success)
    {
      if (file != NULL) file_allow_write (file);  // Re-enable writing if the file was previously opened.
      syscall_process_done ();  // Clean up resources associated with system calls.
      thread_current()->process_exit_code = -1;  // Set the exit code to indicate failure.
      thread_exit ();  // Exit the thread.
    }
  else
    thread_current()->exec_file = file;  // Associate the executable file with the current thread.

  /* Start the user process by jumping to the interrupt exit routine. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");  // Set the stack pointer to the interrupt frame and jump to it.
  NOT_REACHED ();  // This point should not be reached.
}


/* Waits for the specified thread (by TID) to terminate and returns its exit status.
   If the thread was terminated by the kernel or is invalid, or not a child of the calling
   process, or has been waited on before, returns -1 immediately without waiting. */
int process_wait (tid_t child_tid)
{
  struct list_elem *child_elem;
  struct process_child *child;
  int exit_code;

  lock_acquire (&process_child_lock);  // Acquire lock to access child processes safely.
  // Find the child process in the list of child processes.
  child_elem = list_find(&thread_current()->process_children, process_elem_tid_equal, &child_tid);
  lock_release (&process_child_lock);  // Release lock after accessing.

  if (child_elem != NULL)
    {
      child = list_entry(child_elem, struct process_child, elem);  // Get the process_child from the list element.
      sema_down(&child->exited);  // Wait for the child to signal it has exited.
      lock_acquire(&process_child_lock);  // Reacquire lock to safely modify the list.
      exit_code = child->exit_code;  // Retrieve the exit code from the child process.
      list_remove(&child->elem);  // Remove the child process from the list.
      free(child);  // Free the memory allocated to the child.
      lock_release(&process_child_lock);  // Release the lock after modification.
      return exit_code;  // Return the retrieved exit code.
    }
  else
    return -1;  // Return -1 if no such child exists.
}

/* Frees the resources of the current process and logs its exit status. */
void process_exit (void)
{
  struct thread *cur = thread_current();
  struct list_elem *curr_child_elem;
  struct process_child *curr_child;
  uint32_t *pd;

  if (!lock_held_by_current_thread(&process_child_lock))
    lock_acquire(&process_child_lock);  // Ensure the process child lock is held.

  // Notify parent that this process has exited.
  if (cur->inparent != NULL)
    {
      cur->inparent->exit_code = cur->process_exit_code;
      cur->inparent->thread = NULL;
      sema_up(&cur->inparent->exited);  // Signal the parent that this process has exited.
    }

  // Log and free the process function name.
  if (cur->process_fn != NULL)
    {
      printf("%s: exit(%d)\n", cur->process_fn, cur->process_exit_code);
      free(cur->process_fn);
    }

  // Orphan all child processes and free their resources.
  for (curr_child_elem = list_begin(&cur->process_children);
       curr_child_elem != list_end(&cur->process_children);
       curr_child_elem = list_remove(curr_child_elem))
    {
      curr_child = list_entry(curr_child_elem, struct process_child, elem);
      if (curr_child->thread != NULL)
        curr_child->thread->inparent = NULL;
      free(curr_child);
    }
  lock_release(&process_child_lock);

  // Free all memory mapped pages.
  struct list* mmap_list = &thread_current()->mmap_list;
  struct page_mmap *mmap_page;
  size_t n_mmap = list_size(mmap_list);
  struct list_elem *cur_mmap = list_begin(mmap_list);
  for (size_t i = 0; i < n_mmap; ++i)
    {
      mmap_page = list_entry(cur_mmap, struct page_mmap, list_elem);
      cur_mmap = list_remove(cur_mmap);
      page_delete_mmap(mmap_page);
    }

  // Destroy the supplemental page table.
  page_table_destroy();

  // Re-enable writing and close the executable file.
  if (cur->exec_file != NULL)
  {
    filesys_allow_write(cur->exec_file);
    filesys_close(cur->exec_file);
  }

  // Free up resources related to system calls and file descriptors.
  syscall_process_done();

  // Destroy the process's page directory.
  pd = cur->pagedir;
  if (pd != NULL)
  {
    cur->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }
}

/* Sets up the CPU for running user code in the current thread.
   This function is called on every context switch to ensure the correct
   runtime environment for the thread. */
void process_activate (void)
{
  struct thread *t = thread_current();

  // Activate the thread's own page tables.
  pagedir_activate(t->pagedir);

  // Update the task state segment to point to the thread's kernel stack.
  tss_update();
}

/* Definitions for ELF types and printf format specifiers derived from the ELF specification,
   providing clarity on their use and formatting in debugging and logging. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;
#define PE32Wx PRIx32  /* Printf format specifier for Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32  /* Printf format specifier for Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32  /* Printf format specifier for Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16  /* Printf format specifier for Elf32_Half in hexadecimal. */


/* The ELF header at the beginning of an ELF binary specifies the file's layout and properties.
   See [ELF1] Sections 1-4 to 1-8 for more detailed specifications. */
struct Elf32_Ehdr
{
    unsigned char e_ident[16];  // Magic number and other info
    Elf32_Half    e_type;       // Object file type
    Elf32_Half    e_machine;    // Architecture
    Elf32_Word    e_version;    // Object file version
    Elf32_Addr    e_entry;      // Entry point virtual address
    Elf32_Off     e_phoff;      // Program header table file offset
    Elf32_Off     e_shoff;      // Section header table file offset
    Elf32_Word    e_flags;      // Processor-specific flags
    Elf32_Half    e_ehsize;     // ELF header size
    Elf32_Half    e_phentsize;  // Program header entry size
    Elf32_Half    e_phnum;      // Program header entry count
    Elf32_Half    e_shentsize;  // Section header entry size
    Elf32_Half    e_shnum;      // Section header entry count
    Elf32_Half    e_shstrndx;   // Section header string table index
};

/* The program header describes a segment or other information the system needs to prepare the program for execution.
   An ELF file has an array of these headers, starting at the file offset e_phoff. See [ELF1] Sections 2-2 to 2-4. */
struct Elf32_Phdr
{
    Elf32_Word p_type;    // Type of segment
    Elf32_Off  p_offset;  // Segment file offset
    Elf32_Addr p_vaddr;   // Segment virtual address
    Elf32_Addr p_paddr;   // Segment physical address
    Elf32_Word p_filesz;  // Segment size in file
    Elf32_Word p_memsz;   // Segment size in memory
    Elf32_Word p_flags;   // Segment flags
    Elf32_Word p_align;   // Segment alignment
};

/* Defines for segment types and flags that specify the characteristics and functions of segments in executable files. */
#define PT_NULL    0            // Unused segment.
#define PT_LOAD    1            // Loadable segment.
#define PT_DYNAMIC 2            // Dynamic linking information.
#define PT_INTERP  3            // Interpreter pathname.
#define PT_NOTE    4            // Auxiliary information.
#define PT_SHLIB   5            // Reserved.
#define PT_PHDR    6            // Location of program header itself.
#define PT_STACK   0x6474e551   // Indicates a stack segment.

#define PF_X 1                  // Segment is executable.
#define PF_W 2                  // Segment is writable.
#define PF_R 4                  // Segment is readable.


static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct page_mmap* mmap, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(struct process_info *p_info, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current();  // Get the current thread.
  struct Elf32_Ehdr ehdr;               // ELF header for the executable.
  struct file *file = NULL;             // File pointer for the executable.
  off_t file_ofs;                       // Offset in the file for reading data.
  bool success = false;                 // Status of the loading process.
  int i;                                // Loop counter for program headers.

  /* Create a new page directory and initialize supplemental page tables for the current thread. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL || !page_table_init())  // Check if creation and initialization were successful.
    goto done;

  process_activate();  // Load the new page directory into the CPU's page directory register.

  /* Attempt to open the executable file. */
  file = filesys_open(p_info->program_name, NULL);
  if (file == NULL)  // If the file could not be opened, print error and exit.
    {
      printf("load: %s: open failed\n", p_info->program_name);
      goto done;
    }

  /* Read and check the ELF header to confirm it's a valid ELF file. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof(struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf("load: %s: error loading executable\n", p_info->program_name);
      goto done;
    }

  /* Create a memory map for the executable file. */
  size_t file_size = file_length(file);
  struct page_mmap *mmap = page_mmap_new(file, file_size);

  /* Iterate over all program headers to load necessary segments. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length(file))  // Validate file offset.
        goto done;
      file_seek(file, file_ofs);  // Set file position to the start of the program header.

      if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)  // Read a program header.
        goto done;
      file_ofs += sizeof phdr;  // Increment file offset for the next header.

      switch (phdr.p_type)  // Handle different types of segments.
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
          // These segments do not require loading.
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          // Unsupported segment types, fail the loading process.
          goto done;
        case PT_LOAD:
          // Load this segment if it's a loadable segment.
          if (validate_segment(&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;  // Determine if the segment is writable.
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  // Calculate the number of bytes to read from the file and to zero-fill.
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
                }
              else
                {
                  // If the segment has no bytes to read, it's entirely zero.
                  read_bytes = 0;
                  zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                }
              // Load the segment into memory.
              if (!load_segment(mmap, file_page, (void *)mem_page, read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  mmap->id = thread_current()->mmap_next_id++;  // Assign an ID to the memory map.
  list_push_back(&thread_current()->mmap_list, &mmap->list_elem);  // Add the memory map to the thread's list of maps.

  /* Setup the user stack. */
  if (!setup_stack(esp))
    goto done;
  /* Pass command-line arguments to the stack. */
  if (!pass_args_to_stack(p_info, esp))
    goto done;

  /* Set the entry point from the ELF header. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;  // Mark the load as successful.

done:  // Label for cleanup and exit.
  /* Set the loading success status in the process info and close the file if it was opened. */
  p_info->load_success = success;
  if (file != NULL)
    file_close(file);
  return success;
}


/* load() helpers. */

// /* Checks whether PHDR describes a valid, loadable segment in
//    FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
    /* Ensure the offset within the file and virtual address have the same offset within their respective pages. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* The file offset must point to a location within the file. */
    if (phdr->p_offset > (Elf32_Off)file_length(file))
        return false;

    /* The memory size of the segment must at least be as large as the file size. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* Ensure the segment is not empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual address range must be entirely within the user address space. */
    if (!is_user_vaddr((void *)phdr->p_vaddr) || !is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* Check for address wrapping which is undefined behavior. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0 to prevent potential null pointer dereferences in user programs. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    return true; // The segment is valid and can be loaded.
}


/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct page_mmap *mmap, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0); // Ensure the total size is page-aligned.
    ASSERT(pg_ofs(upage) == 0); // Ensure the user page is page-aligned.
    ASSERT(ofs % PGSIZE == 0); // Ensure file offset is page-aligned.

    while (read_bytes > 0 || zero_bytes > 0)
    {
        /* Calculate how many bytes to read from the file and how many to zero-fill. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Add page to the memory map with the specified settings. */
        if (!page_add_to_mmap(mmap, upage, ofs, page_zero_bytes))
            return false; // Fail if the page cannot be added.

        struct page *page = page_lookup(upage);
        if (writable)
            page->evict_to = SWAP; // Set page eviction policy based on writability.
        page_set_writable(upage, writable); // Set the page's writability.

        /* Update variables for the next iteration to process the next page. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
        ofs += PGSIZE;
    }
    return true;
}


/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void **esp)
{
    uint8_t *page;

    page = page_alloc(((uint8_t *) PHYS_BASE) - PGSIZE);
    if (page != NULL)
    {
        memset(page, 0, PGSIZE); // Zero out the new page.
        *esp = PHYS_BASE; // Set the initial stack pointer to the top of the physical base.
        return true;
    }
    return false; // Return false if the page allocation fails.
}


/* Push data onto the stack if in bounds */
static bool stack_push(void **esp, void *data, size_t size)
{
    // Check that the stack has enough space to push 'size' bytes.
    if ((intptr_t)*esp - size < 0)
    {
        return false;  // Return false if pushing 'size' bytes would underflow the stack pointer.
    }

    *esp = (void *)((char *)(*esp) - size);  // Move the stack pointer down by 'size' bytes.
    memcpy(*esp, data, size);  // Copy 'size' bytes of 'data' into the stack at the new location.
    return true;  // Return true if the operation is successful.
}


/* Parses the command-line arguments from the process info, organizes them appropriately,
   and pushes them onto the stack of the newly created process. This setup is crucial for
   the process to receive arguments correctly when it starts executing. */
static bool pass_args_to_stack(struct process_info *p_info, void **esp)
{
  bool success = true;  // Flag to indicate success of operations.

  // Parse the command line to count the number of arguments.
  int argc = 0;
  char *token, *save_ptr;
  for (token = strtok_r(p_info->cmd_line, " ", &save_ptr); token != NULL;
       token = strtok_r(NULL, " ", &save_ptr))
    argc++;

  // Allocate an array to hold pointers to the arguments on the stack.
  char *argv[argc];

  // Reinitialize the tokenizer to push each argument onto the stack.
  token = p_info->cmd_line;
  for (int i = 0; i < argc; i++)
    {
      int size_arg = strlen(token) + 1;  // Determine the length of the argument including the null terminator.
      success = stack_push(esp, token, size_arg);  // Push the argument onto the stack.

      // Advance token to the next argument in the command line string.
      token = strchr(token, '\0') + 1;
      while (*token == ' ') token++;  // Skip any extra spaces between arguments.

      // Save the location of the argument on the stack in the argv array.
      argv[i] = *esp;
    }

  // Align the stack pointer to a multiple of 4 for word alignment.
  *esp = (void*) (((intptr_t) *esp) & 0xfffffffc);

  // Push a null pointer to the stack as required by the C standard (end of argv).
  int null_ptr = 0;
  success &= stack_push(esp, &null_ptr, sizeof(void *));

  // Push the address of each argument stored in argv in reverse order onto the stack.
  for (int i = argc - 1; i >= 0; i--)
    success &= stack_push(esp, &argv[i], sizeof(char *));

  // Push the address of argv (i.e., address of argv[0]) onto the stack.
  void *argv_0 = *esp;
  success &= stack_push(esp, &argv_0, sizeof(void *));

  // Push argc (the number of arguments) onto the stack.
  success &= stack_push(esp, &argc, sizeof(argc));

  // Push a fake return address onto the stack; standard for new stack frames.
  success &= stack_push(esp, &null_ptr, sizeof(void *));

  return success;  // Return the success flag.
}

