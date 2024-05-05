#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "vm/page.h"
#include <stdbool.h>
#include <list.h>

/**
 * Manages the organization of physical memory frames within the system,
 * distinguishing between frames that are available for allocation and those currently in use.
 */
struct frame_table
{
    struct list free_frames;      /* List of frames that are currently unallocated and available for new allocations. */
    struct list allocated_frames; /* List of frames that are in use and may be candidates for eviction if needed. */
};


/**
 * Represents a physical memory frame, detailing its status and association with a virtual page.
 */
struct frame
{
    struct list_elem elem;        /* Link element for inclusion in the lists maintained by frame_table. */
    void *kaddr;                  /* Physical address of the frame, also used as the kernel address for the frame. */
    struct page *page;            /* Virtual page that is currently mapped to this frame, if any. */
    bool pinned;                  /* Flag indicating whether the frame is immune to eviction. When set, the frame cannot be evicted. */
};


void frame_init (void);
struct frame *frame_alloc (void);
bool frame_evict (struct frame *frame);
void frame_free (struct frame *frame);
void frame_pin (struct frame *frame);
void frame_unpin (struct frame *frame);



#endif /* vm/frame.h */
