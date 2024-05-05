#ifndef VM_PAGE_H
#define VM_PAGE_H
#include "threads/thread.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include <stdbool.h>
#include <hash.h>
#include <stddef.h>


/**
* Enumerates the possible sources and statuses of a virtual memory page.
*/
enum page_location
{
  NEW,        /* Uninitialized page, typically filled with zeros upon actual allocation. */
  FRAME,      /* Indicates that the page is currently loaded in a physical frame. */
  SWAP,       /* Indicates that the page is currently stored in swap space. */
  FILE,       /* Indicates that the page is backed by a file, used primarily for memory-mapped files. */
  CORRUPTED,  /* Indicates that the page data has been lost or is otherwise corrupt. */
};


/**
* Represents a page within a thread's virtual memory space.
*/
struct page
{
  struct hash_elem hash_elem;   /* Hash table element for inclusion in the thread's page_table. */
  struct lock lock;             /* Lock to synchronize access to this page structure. */
  struct thread *thread;        /* Pointer to the thread that owns this page. */
  void *uaddr;                  /* User virtual address corresponding to this page, serves as a key in the page table. */
  enum page_location location;  /* Current location or status of the page (e.g., in frame, in swap). */
  bool writable;                /* True if the page can be written to, false if read-only. */
  struct frame *frame;          /* Pointer to the frame that currently holds this page, if any. */
  bool pinned;                  /* Indicates whether the page is exempt from eviction. */
  size_t swap_slot;             /* Index of the swap slot holding this page if it's swapped out. */
  enum page_location evict_to;  /* Preferred location to evict this page to when necessary (e.g., back to a file). */
  struct page_mmap *mmap;       /* Pointer to the memory-mapped file structure if this page is part of an mmap. */
  size_t file_zero_bytes;       /* Number of bytes at the end of the page that should be zeroed out (for partial pages in files). */
  unsigned start_byte;          /* Starting byte offset in the file for this page. */
};


/* Wrapper struct for a mmaped file */
struct page_mmap
  {
    mapid_t id;                 /* ID of mmap*/
    struct list_elem list_elem; /* List element to place mmap in list */
    struct file *file;          /* File backing mmap */
    size_t file_size;           /* Size of above */
    struct list mmap_pages;     /* List of pages mapped to this mmap */
  };

/**
* Wrapper structure for a single page within a memory-mapped file.
*/
struct page_mmap_elem
{
  struct list_elem list_elem; /* List element for inclusion in the mmap's list of pages. */
  void* page_addr;            /* Virtual address of the page within the user space. */
};


void *page_alloc (void *uaddr);
struct page *page_lookup (void *uaddr);
bool page_table_init (void);
void page_table_destroy (void);
void page_pin (void *uaddr);
void page_unpin (void *uaddr);
void page_free (void *uaddr);
bool page_evict (struct page *page);
bool page_resolve_fault (void *fault_addr);
void page_set_writable (void *uaddr, bool writable);
bool page_is_writable (struct page *page);
struct page_mmap *page_get_mmap (struct thread *t, mapid_t id);
struct page_mmap *page_mmap_new (struct file* file, size_t file_size);
bool page_add_to_mmap (struct page_mmap *mmap, void* uaddr,
                       unsigned offset, size_t zero_bytes);
void page_delete_mmap (struct page_mmap *mmap);

#endif /* vm/page.h */
