#include "vm/frame.h"
#include <stdio.h>
#include <debug.h>
#include "userprog/pagedir.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"

static struct frame_table ft;  /* Table that maintains records of all memory frames used by the system. */
static struct lock frame_table_lock;  /* Lock used to synchronize access to the frame table, ensuring atomic operations. */
static struct list_elem *clock_hand;  /* Pointer used by the clock replacement algorithm to track the current position in the frame list. */

static struct frame *frame_pick_and_evict (void);

/**
 * Frees up the specified FRAME, making it available for future use.
 * The data within the FRAME is not cleared or modified.
 * @param frame Pointer to the frame to be freed.
 */
void frame_free(struct frame *frame)
{
  lock_acquire(&frame_table_lock);  // Acquire the lock to ensure atomic access to the frame table.
  
  frame->page = NULL;               // Detach any associated page from the frame.
  frame->pinned = false;            // Mark the frame as not pinned, allowing it to be evicted or reused.
  
  list_remove(&frame->elem);        // Remove the frame from its current list (likely the list of occupied frames).
  list_push_back(&ft.free_frames, &frame->elem); // Add the frame to the list of free frames, making it available for reuse.
  
  lock_release(&frame_table_lock);  // Release the lock after modifying the frame table.
}

/**
 * Initializes the frame table by allocating and marking all user pages as free.
 */
void frame_init(void)
{
  void *upage;
  struct frame *frame;

  lock_init(&frame_table_lock); // Initialize the lock for frame table operations.
  lock_acquire(&frame_table_lock); // Acquire the lock to ensure exclusive access to the frame table.
  list_init(&ft.free_frames); // Initialize the list of free frames.
  list_init(&ft.allocated_frames); // Initialize the list of allocated frames.
  clock_hand = list_head(&ft.allocated_frames); // Set the clock hand to the head of the allocated frames list.

  // Continuously allocate pages from the user pool until none are left.
  while ((upage = palloc_get_page(PAL_USER)))
    {
      frame = malloc(sizeof(struct frame)); // Allocate memory for a new frame struct.
      ASSERT(frame != NULL); // Ensure the frame was successfully allocated.
      frame->kaddr = upage; // Store the kernel address of the allocated user page.
      frame->page = NULL; // Initially, no virtual page is associated with this frame.
      frame->pinned = false; // Mark the frame as unpinned, indicating it's available for eviction.
      list_push_back(&ft.free_frames, &frame->elem); // Add the new frame to the list of free frames.
    }
  lock_release(&frame_table_lock); // Release the lock after initializing the frame table.
}

/**
 * Advances the clock hand used in the clock algorithm for frame eviction.
 * Returns the next element in the allocated frames list, wrapping around if necessary.
 * @return The next list element where the clock hand points.
 */
static struct list_elem *clock_next(void)
{
  clock_hand = list_next(clock_hand); // Move the clock hand to the next frame.
  // If the end of the list is reached, wrap the clock hand to the beginning.
  if (clock_hand == list_end(&ft.allocated_frames))
    clock_hand = list_begin(&ft.allocated_frames);

  return clock_hand; // Return the new position of the clock hand.
}

/**
 * Picks and evicts a frame using the clock replacement algorithm.
 * This function assumes that the frame table lock is already acquired.
 * @return Pointer to the evicted frame.
 */
static struct frame *frame_pick_and_evict(void)
{
    // Ensure that the frame table lock is currently held by the executing thread.
    ASSERT(lock_held_by_current_thread(&frame_table_lock));
    // Ensure there is at least one frame that could potentially be evicted.
    ASSERT(!list_empty(&ft.allocated_frames));

    // Start the eviction process from the current position of the clock hand.
    struct frame *frame = list_entry(clock_next(), struct frame, elem);
    struct frame *clock_start = frame;  // Remember the start point of the clock hand.

    do {
        // Check if the frame can be considered for eviction.
        if (!frame->pinned) {
            // Check if the frame's page has been accessed.
            if (pagedir_is_accessed(frame->page->thread->pagedir, frame->page->uaddr)) {
                // If accessed, clear the accessed bit and continue to the next frame.
                pagedir_set_accessed(frame->page->thread->pagedir, frame->page->uaddr, false);
            } else {
                // If not accessed, this frame is a candidate for eviction.
                break;
            }
        }
        // Move the clock hand to the next frame.
        frame = list_entry(clock_next(), struct frame, elem);
    } while (frame != clock_start); // Continue until we've circled back to the start.

    // Attempt to evict the selected frame. Panic if eviction is not possible due to all frames being pinned.
    if (!frame_evict(frame)) {
        PANIC("No unpinned frames available for eviction!");
    }

    // Return the now-available (evicted) frame.
    return frame;
}
/**
 * Allocates a frame from the free list or evicts one if necessary, and pins it.
 * This function is primarily used during page fault resolution.
 * @return Pointer to the allocated frame.
 */
struct frame *frame_alloc(void) 
{
    // Acquire the lock on the frame table to ensure exclusive access during frame allocation.
    lock_acquire(&frame_table_lock);

    struct frame *frame;

    // Check if there are any free frames available.
    if (!list_empty(&ft.free_frames)) {
        // If free frames are available, pop the first free frame from the list.
        frame = list_entry(list_pop_front(&ft.free_frames), struct frame, elem);
    } else {
        // If no free frames are available, attempt to pick and evict a frame.
        frame = frame_pick_and_evict();
    }

    if (frame) {
        // If a frame was successfully allocated or evicted:
        frame->pinned = true;  // Pin the frame to prevent it from being evicted.
        // Add the frame to the list of allocated frames.
        list_push_back(&ft.allocated_frames, &frame->elem);
    }

    // Release the frame table lock after the frame has been allocated.
    lock_release(&frame_table_lock);
    
    // Return the pointer to the newly allocated frame, or NULL if allocation failed.
    return frame;
}


/**
 * Pins a frame, preventing it from being evicted.
 * @param frame The frame to pin.
 */
void frame_pin(struct frame *frame)
{
  lock_acquire(&frame_table_lock); // Acquire lock to modify the frame's properties safely.
  frame->pinned = true; // Set the frame's pinned status to true.
  lock_release(&frame_table_lock); // Release the lock.
}


/**
 * Unpins a frame, making it eligible for eviction.
 * @param frame The frame to unpin.
 */
void frame_unpin(struct frame *frame)
{
  lock_acquire(&frame_table_lock); // Acquire lock to modify the frame's properties safely.
  frame->pinned = false; // Set the frame's pinned status to false, allowing it to be evicted.
  lock_release(&frame_table_lock); // Release the lock.
}


/**
 * Attempts to evict a frame, handling the associated page if necessary.
 * This function assumes the frame_table_lock is already acquired.
 * @param frame The frame to evict.
 * @return True if the frame was successfully evicted, false otherwise.
 */
bool frame_evict(struct frame *frame)
{
    ASSERT(lock_held_by_current_thread(&frame_table_lock)); // Ensure that the current thread holds the frame table lock.

    if (frame->pinned) // Check if the frame is pinned. Pinned frames cannot be evicted.
        return false;

    // Lock the page associated with the frame to ensure exclusive access during eviction.
    lock_acquire(&frame->page->lock);

    // Attempt to evict the page. `page_evict` returns true if eviction was successful.
    bool eviction_successful = page_evict(frame->page);

    // Release the page lock after attempting eviction.
    lock_release(&frame->page->lock);

    // If the eviction was unsuccessful, leave the frame unchanged and return false.
    if (frame->page != NULL && !eviction_successful)
        return false;

    // Nullify the page pointer to dissociate the frame from its page.
    frame->page = NULL;

    // Manage the frame list: specifically handle if the frame is the current position of the clock hand.
    if (&frame->elem == clock_hand) {
        // Move the clock hand to the next frame in the list.
        clock_hand = list_next(clock_hand);

        // Remove the current frame from the list.
        list_remove(&frame->elem);

        // If the clock hand reaches the end of the list, wrap it to the beginning.
        if (clock_hand == list_end(&ft.allocated_frames))
            clock_hand = list_begin(&ft.allocated_frames);
    } else {
        // If the frame is not the clock hand, simply remove it from the list.
        list_remove(&frame->elem);
    }

    // Return true to indicate that the frame was successfully evicted.
    return true;
}
