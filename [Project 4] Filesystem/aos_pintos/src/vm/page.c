#include "vm/page.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <string.h>

extern struct lock syscall_file_lock;
static void page_page_pin (struct page *page);
static void page_page_unpin (struct page *page);
static void page_page_free (struct page *p);
static bool page_in (struct page *page);
static bool page_file_in (struct page *page);
static hash_hash_func page_hash;
static hash_less_func page_less;
static hash_action_func hash_page_free;


/**
 * Initializes the page table for the current thread, setting up structures for managing virtual memory.
 * Returns true if initialization is successful, false if memory allocation fails.
 */
bool page_table_init(void)
{
  struct thread *t = thread_current(); // Get the current thread.
  bool success;

  t->page_table_lock = malloc(sizeof(struct lock)); // Allocate memory for the page table lock.
  if (t->page_table_lock == NULL)  // Check if lock allocation failed.
    return false;  // Return false if memory was not allocated.
  lock_init(t->page_table_lock); // Initialize the newly allocated lock.
  lock_acquire(t->page_table_lock); // Acquire the lock before modifying the page table.
  success = hash_init(&t->page_table, page_hash, page_less, NULL); // Initialize the page table hash.
  lock_release(t->page_table_lock); // Release the lock after initialization.
  return success; // Return the status of page table initialization.
}


/**
 * Destroys the current thread's page table and frees all associated pages,
 * called during process exit to reclaim memory.
 */
void page_table_destroy(void)
{
  struct thread *t = thread_current(); // Get the current thread.

  lock_acquire(t->page_table_lock); // Acquire the lock to safely modify the page table.
  hash_destroy(&t->page_table, hash_page_free); // Destroy the page table, freeing all associated pages.
  lock_release(t->page_table_lock); // Release the lock.
  free(t->page_table_lock); // Free the memory allocated for the page table lock.
}


/**
 * Allocates a page with the specified user address in the current thread's page table.
 * Marks the page table entry as invalid to trigger lazy loading on access.
 * Returns the user address on success, or NULL if the page is already mapped or allocation fails.
 */
void *page_alloc(void *uaddr)
{
  struct thread *t = thread_current(); // Get the current thread.
  void *paddr = pg_round_down(uaddr); // Align the address to page boundaries.
  struct page *p;

  ASSERT(is_user_vaddr(uaddr)); // Ensure the address is within user space.

  lock_acquire(t->page_table_lock); // Acquire the lock to ensure thread safety.
  p = page_lookup(paddr); // Check if a page is already mapped at this address.
  if (p != NULL)  // If a page exists, return NULL.
  {
    uaddr = NULL;
    goto done;
  }
  p = malloc(sizeof(struct page)); // Allocate memory for a new page structure.
  if (p == NULL)  // Check if the memory allocation failed.
  {
    uaddr = NULL;
    goto done;
  }
  lock_init(&p->lock); // Initialize the lock for the new page.
  p->uaddr = paddr;
  p->thread = t;
  p->location = NEW;
  p->evict_to = SWAP;
  p->frame = NULL;
  p->writable = true;
  p->pinned = false;
  p->mmap = NULL;
  pagedir_clear_page(t->pagedir, paddr); // Invalidate the page table entry.
  hash_insert(&t->page_table, &p->hash_elem); // Insert the new page into the page table.
done:
  lock_release(t->page_table_lock); // Release the lock.
  return uaddr; // Return the user address or NULL.
}


/**
 * Sets the writable attribute for a page at a specific user address in the current thread's page table.
 * Updates the page table entry to reflect this change.
 */
void page_set_writable(void *uaddr, bool writable)
{
  struct thread *t = thread_current(); // Get the current thread.
  void *upage = pg_round_down(uaddr); // Align the address to page boundaries.
  struct page *p;

  ASSERT(is_user_vaddr(uaddr)); // Ensure the address is within user space.

  lock_acquire(t->page_table_lock); // Acquire the lock to ensure thread safety.
  p = page_lookup(uaddr); // Look up the page in the page table.
  if (p != NULL)
  {
    lock_acquire(&p->lock); // Acquire the lock for the page.
    p->writable = writable; // Set the writable attribute.
    if (p->location == FRAME) // Check if the page is loaded into a frame.
      pagedir_set_writable(t->pagedir, upage, writable); // Update the page table entry.
    lock_release(&p->lock); // Release the page lock.
  }
  lock_release(t->page_table_lock); // Release the page table lock.
}


/**
 * Checks if a page is writable.
 * @param page The page to check.
 * @return True if the page is writable, false otherwise.
 * This operation is thread-safe.
 */
bool page_is_writable(struct page *page)
{
  bool writable;

  lock_acquire(&page->lock);  // Acquire the lock to ensure thread-safe access to the page's attributes.
  writable = page->writable;  // Read the writable attribute of the page.
  lock_release(&page->lock);  // Release the lock after reading.
  return writable;  // Return the writable status.
}


/**
 * Frees a given page, removing it from the page table and evicting its data if necessary.
 * @param p The page to free.
 */
static void page_page_free(struct page *p)
{
  struct thread *t = thread_current(); // Get the current thread.

  lock_acquire(&p->lock);  // Acquire the page's lock to ensure exclusive access.
  if (p != NULL)
  {
    // Free up resources based on the location of the page.
    switch (p->location)
    {
      case SWAP:
        swap_free(p->swap_slot);  // Free the swap slot if the page is in swap.
        break;
      case FRAME:
        if (p->evict_to != SWAP)
          page_evict(p);  // Evict the page to disk if necessary.
        frame_free(p->frame);  // Free the frame associated with this page.
        break;
      default:
        break;
    }
  }
  hash_delete(&t->page_table, &p->hash_elem);  // Remove the page from the page table.
  pagedir_clear_page(t->pagedir, p->uaddr);  // Clear the page directory entry.
  lock_release(&p->lock);  // Release the lock.
  free(p);  // Free the page structure.
}


/**
 * Removes a page at a specified user address from the current thread's page table and frees it.
 * @param uaddr The user address of the page to free.
 */
void page_free(void *uaddr)
{
  struct thread *t = thread_current();  // Get the current thread.
  struct page *p;

  lock_acquire(t->page_table_lock);  // Acquire the page table lock.
  p = page_lookup(uaddr);  // Lookup the page in the page table.
  if (p == NULL)
    PANIC("Freeing page at invalid memory!");  // Panic if no page is found at the address.
  page_page_free(p);  // Free the found page.
  lock_release(t->page_table_lock);  // Release the page table lock.
}


/**
 * Ensures that a page at a specific user address will not be evicted.
 * @param uaddr The user address of the page to pin.
 */
void page_pin(void *uaddr)
{
  struct page *page = page_lookup(uaddr);  // Lookup the page in the page table.

  if (page == NULL)
    PANIC("Pinning invalid page!");  // Panic if no page is found.

  lock_acquire(&page->lock);  // Acquire the lock for the page.
  page_page_pin(page);  // Pin the page to prevent eviction.
  lock_release(&page->lock);  // Release the lock after pinning.
}


/**
 * Allows a page at a specific user address to be evicted after being pinned.
 * @param uaddr The user address of the page to unpin.
 */
void page_unpin(void *uaddr)
{
  struct page *page = page_lookup(uaddr);  // Lookup the page in the page table.

  if (page == NULL)
    PANIC("Unpinning invalid page!");  // Panic if no page is found.

  lock_acquire(&page->lock);  // Acquire the lock for the page.
  page_page_unpin(page);  // Unpin the page to allow eviction.
  lock_release(&page->lock);  // Release the lock after unpinning.
}


/**
 * Pins a page and ensures it is loaded into a frame, preventing page faults.
 * Assumes the page's lock is already acquired.
 * @param page The page to pin.
 */
static void page_page_pin(struct page *page)
{
  ASSERT(lock_held_by_current_thread(&page->lock));  // Ensure the lock is held by the current thread.

  page->pinned = true;  // Mark the page as pinned.
  // Ensure the page is loaded into a frame.
  if (page->location != FRAME && !page_in(page))
    PANIC("Failed to Page-in page before pinning it!");
  // Pin the associated frame to prevent its eviction.
  frame_pin(page->frame);
}


/**
 * Unpins a page, allowing it to become a candidate for eviction.
 * Assumes that the lock for the page is already acquired.
 * @param page The page to unpin.
 */
static void page_page_unpin(struct page *page)
{
  ASSERT(lock_held_by_current_thread(&page->lock)); // Ensure the lock is held by the current thread.

  page->pinned = false; // Set the page as unpinned, allowing eviction.
  if (page->location == FRAME) // Check if the page is currently loaded in a frame.
    frame_unpin(page->frame); // Unpin the frame associated with the page.
}


/**
 * Loads a page into physical memory, pinning it by default to prevent immediate eviction.
 * Assumes that the page's lock is acquired by the current thread.
 * @param page The page to load into memory.
 * @return True if the page is successfully loaded; false otherwise.
 */
static bool page_in(struct page *page)
{
  struct thread *t = thread_current(); // Get the current thread.
  struct frame *frame;

  ASSERT(lock_held_by_current_thread(&page->lock)); // Ensure the lock is held by the current thread.

  if (page->location == FRAME) // If the page is already in a frame, return true.
    return true;

  frame = frame_alloc(); // Allocate a new frame and pin it.
  page->pinned = true; // Pin the page.
  frame->page = page;
  page->frame = frame;
  
  if (!pagedir_set_page(t->pagedir, page->uaddr, frame->kaddr, true)) // Set the page table entry.
  {
    frame_free(frame); // Free the frame if setting the page fails.
    page->pinned = false;
    return false;
  }

  switch (page->location) // Populate the frame based on the page's location.
  {
    case NEW:
      memset(frame->kaddr, 0xcc, PGSIZE); // Populate new pages with 0xcc for debugging.
      break;
    case SWAP:
      if (!swap_in(frame, page->swap_slot)) // Load the page from swap.
        goto fail;
      break;
    case FILE:
      if (!page_file_in(page)) // Load the page from a file.
        goto fail;
      break;
    default:
      PANIC("Failed to page-in at address %p!", page->uaddr);
  }

  page->location = FRAME; // Update the page's location.
  pagedir_set_writable(t->pagedir, page->uaddr, page->writable); // Set the writable attribute.
  return true;

fail:
  page->location = CORRUPTED; // Mark the page as corrupted if loading fails.
  frame_free(frame);
  page->pinned = false;
  return false;
}


/**
 * Reads data from a memory-mapped file into a page.
 * @param page The page to populate with data from its backing file.
 * @return True if the data was successfully read, false otherwise.
 */
static bool page_file_in(struct page *page)
{
  struct page_mmap *mmap = page->mmap; // Access the mmap structure associated with the page.
  if (!mmap) // Check if there's no mmap structure linked.
    return false;

  off_t old_cur = filesys_tell(mmap->file); // Save the current file position.
  filesys_seek(mmap->file, page->start_byte); // Seek to the start of the data in the file.

  off_t bytes_to_read = PGSIZE - page->file_zero_bytes; // Calculate the number of bytes to read.
  off_t bytes_read = filesys_read(mmap->file, page->frame->kaddr, bytes_to_read); // Read the data into the frame.

  filesys_seek(mmap->file, old_cur); // Restore the original file position.

  if (bytes_read != bytes_to_read) // Check if the read was incomplete.
    return false;

  // Zero out the remaining part of the page if necessary.
  memset((char *)page->frame->kaddr + bytes_read, 0, page->file_zero_bytes);
  page->location = FRAME; // Update the page location to indicate it's in a frame.
  return true;
}


/**
 * Resolves a page fault by loading the page containing the fault address into a frame.
 * @param fault_addr The address at which the fault occurred.
 * @return True if the fault was successfully resolved, false if the address is invalid.
 */
bool page_resolve_fault(void *fault_addr)
{
  if (!is_user_vaddr(fault_addr)) // Check if the fault address is within user space.
  {
    thread_current()->process_exit_code = -1; // Set exit code to indicate error.
    thread_exit(); // Terminate the current thread.
  }

  struct page *page = page_lookup(fault_addr); // Lookup the page associated with the fault address.
  if (!page) // Check if there's no page mapped at the fault address.
    return false;

  if (page->location == FRAME || page->location == CORRUPTED) // If the page is already in a frame or corrupted.
    return false;

  lock_acquire(&page->lock); // Acquire the page's lock to load it safely.
  bool success = page_in(page); // Load the page into a frame.
  page_page_unpin(page); // Unpin the page by default after handling the fault.
  lock_release(&page->lock); // Release the lock.
  return success; // Return the success status of the fault handling.
}


/**
 * Evicts a page by writing it to disk or swapping it out based on its configuration.
 * This function is thread-safe and requires that the page's lock has already been acquired.
 * @param page The page to evict.
 * @return True if the page was successfully evicted or already evicted, false on failure.
 */
bool page_evict(struct page *page)
{
  bool success = false;

  ASSERT(lock_held_by_current_thread(&page->lock));  // Verify that the page lock is held by the calling thread.

  if (page->location != FRAME)  // Check if the page is not in a frame, which means it's already evicted.
  {
    success = true;
    goto done;
  }

  if (page->pinned)  // Can't evict pinned pages as they are protected from eviction.
  {
    success = false;
    goto done;
  }

  // Handle eviction based on the type of storage associated with the page.
  if (page->location == FRAME)
  {
    if (page->evict_to == FILE)  // Check if the page needs to be written back to a file.
    {
      if (page->writable && pagedir_is_dirty(page->thread->pagedir, page->uaddr))  // Check if the page is dirty.
      {
        struct page_mmap *mmap = page->mmap;
        filesys_seek(mmap->file, page->start_byte);  // Position file pointer to start writing.
        off_t bytes_to_write = PGSIZE - page->file_zero_bytes;  // Calculate the number of bytes to write.
        success = (bytes_to_write == filesys_write(mmap->file, page->frame->kaddr, bytes_to_write));  // Write to file.
      }
      else  // If the page is not writable or not dirty, simply discard changes.
      {
        page->location = FILE;
        success = true;
      }
      pagedir_clear_page(page->thread->pagedir, page->uaddr);  // Clear the page directory entry.
    }
    else  // The default eviction to swap space.
    {
      page->swap_slot = swap_out(page->frame);  // Try to swap out the page.
      if (page->swap_slot != SWAP_ERROR)
      {
        pagedir_clear_page(page->thread->pagedir, page->uaddr);
        page->location = SWAP;  // Update the page's location to swap.
        success = true;
      }
      else
      {
        success = false;
      }
    }
  }
done:
  return success;
}


/**
 * Creates a new memory-mapped file structure for the given file.
 * Assumes that the file lock has already been acquired.
 * @param file Pointer to the file to be memory-mapped.
 * @param file_size The size of the file to be mapped.
 * @return A pointer to the newly created memory map structure, or NULL on failure.
 */
struct page_mmap* page_mmap_new(struct file* file, size_t file_size)
{
  struct page_mmap *mmap = malloc(sizeof(struct page_mmap));  // Allocate memory for the new memory map.
  if (mmap == NULL)
    return NULL;  // Return NULL if allocation fails.

  list_init(&mmap->mmap_pages);  // Initialize the list of pages associated with this map.
  mmap->file = file_reopen(file);  // Reopen the file for this memory map to maintain a separate file pointer.
  if (mmap->file == NULL)  // Check if file reopening failed.
  {
    free(mmap);  // Free the allocated memory map.
    return NULL;
  }
  mmap->file_size = file_size;  // Set the size of the file.
  mmap->id = MAP_FAILED;  // Initialize the map ID to indicate failure (updated upon successful mapping).

  return mmap;  // Return the pointer to the new memory map structure.
}


/**
 * Allocates a new page and associates it with a file-backed memory map.
 * @param mmap The memory map to associate with the new page.
 * @param uaddr The user address where the page will be mapped.
 * @param offset The offset in the file where the page's data starts.
 * @param zero_bytes The number of bytes to be zeroed at the end of the page.
 * @return True if the page was successfully added to the memory map, false otherwise.
 */
bool page_add_to_mmap(struct page_mmap *mmap, void* uaddr, unsigned offset, size_t zero_bytes)
{
  struct thread *t = thread_current();  // Get the current thread.

  // Check that the address isn't already mapped to a page.
  if (page_lookup(uaddr) != NULL || pagedir_get_page(t->pagedir, uaddr))
    return false;

  struct page_mmap_elem *page_wrapper = malloc(sizeof(struct page_mmap_elem));  // Allocate a wrapper for the new page.
  if (page_wrapper == NULL)
    return false;  // Return false if allocation fails.
  page_wrapper->page_addr = uaddr;  // Set the page address in the wrapper.

  // Allocate a page at the specified user address.
  if (!page_alloc(uaddr))
  {
    free(page_wrapper);  // Free the wrapper if page allocation fails.
    return false;
  }
  struct page *pRet = page_lookup(uaddr);  // Lookup the newly allocated page.
  if (pRet == NULL)
  {
    free(page_wrapper);  // Free the wrapper if the page lookup fails.
    return false;
  }

  // Set the page's properties for file mapping.
  pRet->location = FILE;
  pRet->evict_to = FILE;
  pRet->file_zero_bytes = zero_bytes;
  pRet->start_byte = offset;
  pRet->mmap = mmap;  // Associate the page with the mmap.

  // Add the page to the mmap's list of pages.
  list_push_back(&mmap->mmap_pages, &page_wrapper->list_elem);
  return true;  // Return true indicating successful addition to the mmap.
}


/**
 * Deletes a memory-mapped file mapping and frees all associated resources.
 * This includes freeing all pages mapped by the memory map.
 * @param mmap The memory map to delete.
 */
void page_delete_mmap(struct page_mmap *mmap)
{
  struct list_elem *curr_elem = NULL;
  struct list_elem *next_elem = NULL;

  // Iterate through all pages in the memory map's list of pages.
  for (curr_elem = list_begin(&mmap->mmap_pages); curr_elem != list_end(&mmap->mmap_pages); curr_elem = next_elem)
  {
    next_elem = list_next(curr_elem); // Prepare the next element before potentially modifying the list.
    
    struct page_mmap_elem *page = list_entry(curr_elem, struct page_mmap_elem, list_elem);
    struct page *pRet = page_lookup(page->page_addr); // Look up the page in the current thread's page table.
    if (pRet == NULL)
      PANIC("Error in mmap, missing page entry"); // Panic if a page entry is missing.
    page_free(page->page_addr); // Free the page.
    free(page); // Free the memory-mapped page structure.
  }
  filesys_close(mmap->file); // Close the file associated with the mmap.
  free(mmap); // Free the memory map structure itself.
}


/**
 * Helper function for comparing memory-mapped file IDs during list operations.
 * @param elem List element associated with a memory-mapped file.
 * @param aux Auxiliary data (expected to be a pointer to a mapid_t containing the ID to compare).
 * @return True if the IDs match, false otherwise.
 */
static bool page_mmap_equal(struct list_elem *elem, void *aux)
{
  struct page_mmap *mmap = list_entry(elem, struct page_mmap, list_elem);
  return mmap->id == *(mapid_t *)aux; // Compare the mmap ID to the provided ID.
}


/**
 * Retrieves a memory-mapped file structure by its ID from the current thread's list of memory maps.
 * @param t The thread whose memory maps to search.
 * @param id The ID of the memory-mapped file to retrieve.
 * @return Pointer to the memory-mapped file structure if found, NULL otherwise.
 */
struct page_mmap *page_get_mmap(struct thread *t, mapid_t id)
{
  if (!list_empty(&t->mmap_list)) // Ensure there are memory maps to search.
  {
    struct list_elem *e = list_find(&t->mmap_list, page_mmap_equal, &id); // Find the mmap with the given ID.
    if (e != NULL)
      return list_entry(e, struct page_mmap, list_elem); // Return the found memory map.
  }
  return NULL; // Return NULL if the map is not found.
}


/**
 * Finds a page with a given user address in the current thread's page table.
 * @param uaddr User address to find the corresponding page.
 * @return Address of the struct page if found, or NULL if not found.
 */
struct page *page_lookup(void *uaddr)
{
  struct thread *t = thread_current(); // Get the current thread.
  struct page p;
  struct hash_elem *e;

  p.uaddr = pg_round_down(uaddr); // Round down the address to the nearest page boundary.
  e = hash_find(&t->page_table, &p.hash_elem); // Find the page in the hash table.
  return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL; // Return the page or NULL.
}


/**
 * Hash function that computes the hash of a page's user address for insertion into a hash table.
 * @param e Hash element to compute the hash for.
 * @param aux Unused parameter.
 * @return Computed hash value based on the page's user address.
 */
static unsigned page_hash(const struct hash_elem *e, void *aux UNUSED)
{
  const struct page *p = hash_entry(e, struct page, hash_elem);
  return hash_bytes(&p->uaddr, sizeof(p->uaddr)); // Hash the page address.
}


/**
 * Hash comparison function to order pages by their user address.
 * @param a_ First hash element to compare.
 * @param b_ Second hash element to compare.
 * @param aux Unused parameter.
 * @return True if the address of 'a' is less than the address of 'b'.
 */
static bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct page *a = hash_entry(a_, struct page, hash_elem);
  const struct page *b = hash_entry(b_, struct page, hash_elem);
  return a->uaddr < b->uaddr; // Compare the user addresses of the pages.
}


/**
 * Helper function that is called to free a page during the destruction of a hash table.
 * This function ensures each page's resources are properly released.
 * @param e Hash element corresponding to the page to free.
 * @param aux Unused parameter.
 */
static void hash_page_free(struct hash_elem *e, void *aux UNUSED)
{
  struct page *page = hash_entry(e, struct page, hash_elem);
  page_page_free(page); // Call the function to free the resources of the page.
}

