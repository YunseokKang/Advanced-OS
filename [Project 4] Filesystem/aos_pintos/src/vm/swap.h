#ifndef VM_SWAP_H
#define VM_SWAP_H
#include "vm/frame.h"
#include "devices/block.h"
#include <stdbool.h>
#include <bitmap.h>
#include <stddef.h>


/**
 * Manages the swap slots on a block device, maintaining information about which slots are currently in use.
 */
struct swap_table
{
  struct block *block_device;     /* The block device that houses the swap slots. */
  struct bitmap *allocated_slots; /* Bitmap tracking the status of each swap slot as either allocated or free. */
};

#define SWAP_ERROR SIZE_MAX /* Represents a single swap slot designated for paging operations. */

/* Functions for swap Table paging. */
void swap_init (void);
bool swap_in (void *frame, size_t slot_idx);
size_t swap_out (void *frame);
void swap_free (size_t swap_slot);

#endif /* vm/swap.h */
