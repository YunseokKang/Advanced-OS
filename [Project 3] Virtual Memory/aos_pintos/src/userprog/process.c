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
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "lib/string.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

#define PARSE_BUFFER_SIZE 256
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

tid_t process_execute (const char *file_name)
{
  char *fn_copy;
  tid_t tid;
  char *command=(char*)malloc(sizeof(char)*PGSIZE);
  char *real_file_name;
  char *next;
  struct file *file=NULL;
  strlcpy(command, file_name, PGSIZE);
  real_file_name=strtok_r(command, " ", &next);

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);


  /* Create a new thread to execute FILE_NAME. */
	tid = thread_create (real_file_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);
	free(command);
  return tid;
}

void argument_stack(char **argv, int argc, void **esp) {
    int i;
    uintptr_t *stack_address[PARSE_BUFFER_SIZE]; // Store the stack addresses of the arguments

    // Push arguments onto the stack in reverse order
    for (i = argc - 1; i >= 0; i--) {
        int arg_length = strlen(argv[i]) + 1; // Include null terminator
        *esp = (char *)(*esp) - arg_length; // Cast *esp to char* for byte-wise arithmetic
        memcpy(*esp, argv[i], arg_length); // Copy argument to stack
        stack_address[i] = (uintptr_t)*esp; // Save argument's address on the stack
    }
    // Word-align the stack pointer
    *esp = (void *)(((uintptr_t)(*esp) & ~0x3)); // Directly cast and then align
    // Push null sentinel
    *esp = (uintptr_t *)(*esp) - 1; // Move esp back by the size of uintptr_t*
    **(uintptr_t **)(esp) = 0; // Set the value to 0 directly
    // Push addresses of arguments in reverse order
    for (i = argc - 1; i >= 0; i--) {
        *esp = (uintptr_t *)(*esp) - 1; // Adjust esp for each address
        **(uintptr_t **)(esp) = stack_address[i]; // Assign address directly
    }
    // Push argv (address of the first argument's address)
    void *argv_start = *esp;
    *esp = (uintptr_t **)(*esp) - 1; // Adjust esp for argv
    **(uintptr_t **)(esp) = (uintptr_t)argv_start; // Assign the start of argv
    // Push argc
    *esp = (int *)(*esp) - 1; // Adjust esp for argc
    **(int **)(esp) = argc; // Assign argc value
    // Push a fake return address
    *esp = (uintptr_t **)(*esp) - 1; // Adjust esp for the fake return address
    **(uintptr_t **)(esp) = 0; // Set the fake return address to 0
}




/* A thread function that loads a user process and starts it
   running. */

static void start_process(void *filename) 
{   
  char *file_name = filename;
  struct intr_frame if_;
  bool success;
  char *argv[PARSE_BUFFER_SIZE]; // Use a fixed-size array for simplicity
  int argc = 0;
  struct thread *current_thread = thread_current();

  // Instead of copying the entire command into a new buffer, operate directly on file_name.
  char *token, *save_ptr;
  for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
      argv[argc++] = token;
      if (argc >= PARSE_BUFFER_SIZE) { // Prevent overflow of argv array
          break;
      }
  }

    // Verify at least one argument (the program name) is present.
  if (argc == 0) {
  	thread_exit(); // Exit if the command is empty.
  }

    // Initialize the VM before attempting to load the executable.
  initVm(&(current_thread->vm));

    /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof(if_));
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load(argv[0], &if_.eip, &if_.esp);
  // No need to free file_name here since it's provided by caller and might be used after this function returns.

  if (!success) {
  	current_thread->is_loaded = false;
    sema_up(&(current_thread->load));
      thread_exit(); // Properly exit thread if load failed.
    }

  current_thread->is_loaded = true;
  sema_up(&(current_thread->load)); // Signal loading completed successfully.

  // Prepare the user stack with the program arguments.
  argument_stack(argv, argc, &if_.esp);

  // No need to free 'command' as we didn't allocate new memory for it.

  /* Start the user process by simulating a return from an interrupt. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */

int process_wait (tid_t child_tid UNUSED)
{
	struct thread* child=get_child_process(child_tid);
	int exit_status;

	if(child==NULL)
      return -1;

	sema_down(&(child->exit));

	exit_status=child->exit_status;
	remove_child_process(child);

	return exit_status;
}

/* Free the current process's resources. */

void process_exit(void) {
    struct thread *cur = thread_current();
    uint32_t *pd;

    // Close the running file, if any.
    if (cur->run_file != NULL) {
        file_close(cur->run_file);
        cur->run_file = NULL; // Ensure the file is marked as closed.
    }

    // Unmap all memory-mapped files.
    while (!list_empty(&cur->mmap_list)) {
        struct list_elem *e = list_pop_front(&cur->mmap_list);
        struct mmap_file *m_file = list_entry(e, struct mmap_file, elem);
        do_munmap(m_file); // `do_munmap` should also free `m_file` or it should be freed here if not.
    }

    // Close all open files, starting from the highest file descriptor.
    for (int fd = cur->new_fd - 1; fd >= 2; fd--) {
        if (cur->fd_table[fd] != NULL) {
            process_close_file(fd); // Ensure `process_close_file` sets the entry to NULL after closing.
        }
    }
    cur->new_fd = 2; // Reset the file descriptor counter.

    // Destroy the virtual memory entries.
    destroyVm(&cur->vm); // Ensure `destroyVm` handles all necessary cleanup.

    // Destroy the current process's page directory.
  pd = cur->pagedir;
  if (pd != NULL)
    {
      cur->pagedir = NULL; 		// Preemptively unset the page directory.
      pagedir_activate (NULL); 	// Switch to the kernel's page directory.
      pagedir_destroy (pd); 	// Finally, destroy the process's page directory.
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

	lock_acquire(&filesys_lock);
  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
	  lock_release(&filesys_lock);
	  printf ("load: %s: open failed\n", file_name);
      goto done;
    }

	t->run_file=filesys_open(file_name);
	file_deny_write(t->run_file);
	lock_release(&filesys_lock);
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 3 || ehdr.e_version != 1 ||
      ehdr.e_phentsize != sizeof (struct Elf32_Phdr) || ehdr.e_phnum > 1024)
    {
	  printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;

      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
          case PT_NULL:
          case PT_NOTE:
          case PT_PHDR:
          case PT_STACK:
          default:
            /* Ignore this segment. */
            break;
          case PT_DYNAMIC:
          case PT_INTERP:
          case PT_SHLIB:
            goto done;
          case PT_LOAD:
            if (validate_segment (&phdr, file))
              {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint32_t file_page = phdr.p_offset & ~PGMASK;
                uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint32_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0)
                  {
                    /* Normal segment.
                       Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes =
                        (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE) -
                         read_bytes);
                  }
                else
                  {
                    /* Entirely zero.
                       Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                  }
                if (!load_segment (file, file_page, (void *) mem_page,
                                   read_bytes, zero_bytes, writable))
                  goto done;
              }
            else
              goto done;
            break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
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
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      // Create a vm_entry for this page
      struct vm_entry *vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
      if (vme == NULL) {
          return false; // Failed to allocate vm_entry
        }

        // Initialize the vm_entry
        vme->type = VM_EXEC;
        vme->vaddr = upage;
        vme->writable = writable;
        vme->is_loaded = false;
        vme->file = file;
        vme->offset = ofs;
        vme->read_bytes = page_read_bytes;
        vme->zero_bytes = page_zero_bytes;

        // Add the vm_entry to the current process's virtual memory table
        if (!insertVmEntry(&thread_current()->vm, vme)) {
            free(vme); // Cleanup on failure to insert vm_entry
          return false;
        }

      // Update for the next iteration
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}


/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void **esp) {
    struct page *kpage;
    void *upage = ((uint8_t *)PHYS_BASE) - PGSIZE;
    bool success = false;

    // Allocate a zeroed page for the stack
    kpage = allocPage(PAL_USER | PAL_ZERO);
    if (kpage == NULL) {
        return false; // Failed to allocate page
    }

    // Try to map the user page to the allocated kernel page
    if (install_page(upage, kpage->kaddr, true)) {
        *esp = PHYS_BASE; // Set the initial stack pointer to the top of the user virtual memory space

        // Create a vm_entry for the stack page
        struct vm_entry *vme = malloc(sizeof(struct vm_entry));
        if (vme == NULL) {
            freePageByAddr(kpage->kaddr); // Clean up on failure
            return false;
        }

        // Initialize the vm_entry
        vme->type = VM_SWAP; 
        vme->vaddr = upage; 	// Virtual address mapped to
        vme->writable = true; 	// Stack pages must be writable
        vme->is_loaded = true; 	// This page is now loaded into memory

        kpage->vme = vme; // Link the vm_entry back to the physical page

        // Add the vm_entry to the current thread's vm map
        if (!insertVmEntry(&thread_current()->vm, vme)) {
            freePageByAddr(kpage->kaddr); // Clean up allocated resources on failure
            free(vme); // Free the vm_entry if insertion fails
            return false;
        }

        success = true;
    } else {
        // Cleanup on failure to map page
        freePageByAddr(kpage->kaddr);
    }

    return success;
}


/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */

static bool install_page (void *upage, void *kpage, bool writable)
{
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	   address, then map our page there. */
	return (pagedir_get_page (t->pagedir, upage) == NULL &&
			 pagedir_set_page (t->pagedir, upage, kpage, writable));
}


int process_add_file(struct file *f) {
    struct thread *t = thread_current();
    if (!f) return -1; // Check for null file.

    int fd = t->new_fd++; // Save the current value to return it.
    t->fd_table[fd] = f;
    return fd;
}


struct file *process_get_file(int fd) {
    struct thread *t = thread_current();
    if (fd < 2 || fd >= t->new_fd) return NULL; // Check for valid fd range.
    return t->fd_table[fd];
}


void process_close_file(int fd) {
    struct thread* t = thread_current();
    if (fd < 2 || fd >= t->new_fd || t->fd_table[fd] == NULL) return; // Validate fd.

    file_close(t->fd_table[fd]);
    t->fd_table[fd] = NULL;
}


bool expand_stack(void *addr) {
    struct thread *cur = thread_current();
    void *rounded_addr = pg_round_down(addr);

    if (findVmEntry(rounded_addr)) return false; // Check if vme already exists for this address.

    struct page *kpage = allocPage(PAL_USER | PAL_ZERO);
    if (!kpage) return false; // Check kpage allocation.

    struct vm_entry *vme = malloc(sizeof(struct vm_entry));
    if (!vme) {
        freePageByAddr(kpage->kaddr); // Free allocated page on failure.
        return false;
    }

    *vme = (struct vm_entry){.type = VM_SWAP, .vaddr = rounded_addr, .writable = true, .is_loaded = true};
    kpage->vme = vme;
    if (!install_page(rounded_addr, kpage->kaddr, true)) {
        freePageByAddr(kpage->kaddr);
        free(vme);
        return false;
    }

    insertVmEntry(&cur->vm, vme);
    return true;
}



bool verify_stack(void *fault_addr, void *esp) {
    // Cast void* to uintptr_t for arithmetic operations
    uintptr_t max_limit = (uintptr_t)PHYS_BASE - 8 * 1024 * 1024; // 8MB below PHYS_BASE
    
    // Check if the fault address is a valid user address, above esp (considering a heuristic 32-byte margin for function calls),
    // and not below the stack size limit (8MB below PHYS_BASE).
    return is_user_vaddr(fault_addr) &&
           (uintptr_t)fault_addr >= (uintptr_t)esp - 32 &&
           (uintptr_t)fault_addr >= max_limit;
}


bool handle_mm_fault(struct vm_entry *vme) {
    if (!vme) return false; // Check for null pointer

    // Allocate physical memory
    struct page *kpage = allocPage(PAL_USER);
    if (!kpage) return false; // Check allocation success

    kpage->vme = vme;
    bool success = false;

    // Use a unified approach for VM_EXEC and VM_MAP since their handling is identical
    if (vme->type == VM_EXEC || vme->type == VM_MAP) {
        success = loadFileIntoVm(kpage->kaddr, vme);
    } else if (vme->type == VM_SWAP) {
        // For VM_SWAP, swap the page in
        swap_in(vme->swap_slot, kpage->kaddr);
        success = true; // Assume swap_in always succeeds for simplicity, adjust based on your implementation
    }

    // If loading was successful, map the physical page to the virtual page
    if (success && install_page(vme->vaddr, kpage->kaddr, vme->writable)) {
        vme->is_loaded = true;
        return true;
    } else {
        freePageByAddr(kpage->kaddr); // Clean up on failure
        return false;
    }
}



void do_munmap(struct mmap_file* mmap_file) {
    // Check for null pointer to avoid dereferencing it.
    if (!mmap_file) return;

    // Iterate through all vm_entries linked to the mmap_file.
    struct list_elem *e = list_begin(&mmap_file->vme_list);
    while (e != list_end(&mmap_file->vme_list)) {
        struct vm_entry *vme = list_entry(e, struct vm_entry, mmap_elem);
        // Move to the next element early so we don't lose our place after removing the current element.
        e = list_next(e);

        // Write back the memory content to the file if the page is dirty.
        if (vme->is_loaded && pagedir_is_dirty(thread_current()->pagedir, vme->vaddr)) {
            lock_acquire(&filesys_lock); // Ensure file system operations are atomic.
            file_write_at(vme->file, vme->vaddr, vme->read_bytes, vme->offset);
            lock_release(&filesys_lock);
        }

        // Unload the page, if loaded, and remove the vm_entry.
        if (vme->is_loaded) {
            // Clearing the page here might be necessary depending on the implementation of `deleteVmEntry`.
            pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
            vme->is_loaded = false;
        }

        // Remove the vm_entry from the process's vm list and free it.
        list_remove(&vme->mmap_elem);
        deleteVmEntry(&thread_current()->vm, vme);
    }

    // After cleaning up all vm_entries, remove the mmap_file from the list and free it.
    list_remove(&mmap_file->elem);
    free(mmap_file);
}
