#include "vm/swap.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include <stdio.h>

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)


static struct swap_table st; /* Manages swap space, tracking which swap slots are free or occupied on the associated block device. */
static struct lock swap_table_lock; /* Lock used to synchronize changes to the swap table, ensuring safe allocation and release of swap slots. */


/**
 * Initializes the swap table by setting up the block device and creating a bitmap
 * to manage swap slots.
 */
void swap_init(void)
{
  size_t slot_count;  // Variable to hold the number of slots in the swap area.

  lock_init(&swap_table_lock);  // Initialize the lock for swap table operations.
  st.block_device = block_get_role(BLOCK_SWAP);  // Retrieve the block device dedicated to swap.
  if (st.block_device == NULL)
    PANIC("Swap block device does not exist!");  // Panic if no swap block device is found.

  slot_count = block_size(st.block_device) / SECTORS_PER_PAGE;  // Calculate the number of slots available.
  lock_acquire(&swap_table_lock);  // Acquire the lock before modifying the swap table.
  st.allocated_slots = bitmap_create(slot_count);  // Create a bitmap to manage allocation of swap slots.
  if (st.allocated_slots == NULL)
    PANIC("OOM when allocating swap table structures!");  // Panic if memory for the bitmap cannot be allocated.
  lock_release(&swap_table_lock);  // Release the lock after initializing the swap table.
}


/**
 * Writes the page from the given frame to an available swap slot.
 * @param frame_ Pointer to the frame containing the page to be swapped out.
 * @return The index of the swap slot used, or SWAP_ERROR if no slots are available.
 */
size_t swap_out(void *frame_)
{
  struct frame *frame = frame_;  // Cast the input to a frame pointer.
  size_t swap_slot;  // Variable to store the swap slot index.
  block_sector_t sector_begin, sector_offs;  // Variables for calculating block device sectors.

  lock_acquire(&swap_table_lock);  // Acquire the swap table lock.
  swap_slot = bitmap_scan_and_flip(st.allocated_slots, 0, 1, false);  // Find the first free swap slot and mark it as used.
  lock_release(&swap_table_lock);  // Release the lock.
  if (swap_slot == BITMAP_ERROR)
    return SWAP_ERROR;  // Return an error if no free slot is found.

  sector_begin = swap_slot * SECTORS_PER_PAGE;  // Calculate the starting sector for the swap slot.
  // Write the frame data to the swap slot sector by sector.
  for (sector_offs = 0; sector_offs < SECTORS_PER_PAGE; sector_offs++)
    block_write(st.block_device, sector_begin + sector_offs,
                ((uint8_t *) frame->kaddr) + sector_offs * BLOCK_SECTOR_SIZE);
  return swap_slot;  // Return the swap slot index.
}


/**
 * Loads a page from a swap slot into the specified frame.
 * @param frame_ Pointer to the frame where the page will be loaded.
 * @param swap_slot The index of the swap slot to load from.
 * @return True if successful, false if the swap slot is invalid or not in use.
 */
bool swap_in(void *frame_, size_t swap_slot)
{
  struct frame *frame = frame_;  // Cast the input to a frame pointer.
  block_sector_t sector_begin, sector_offs;  // Variables for calculating block device sectors.

  if (!bitmap_test(st.allocated_slots, swap_slot))
    return false;  // Return false if the swap slot is not marked as used.

  sector_begin = swap_slot * SECTORS_PER_PAGE;  // Calculate the starting sector for the swap slot.
  // Read the data from the swap slot into the frame, sector by sector.
  for (sector_offs = 0; sector_offs < SECTORS_PER_PAGE; sector_offs++)
    block_read(st.block_device, sector_begin + sector_offs,
               ((uint8_t *) frame->kaddr) + sector_offs * BLOCK_SECTOR_SIZE);

  bitmap_reset(st.allocated_slots, swap_slot);  // Mark the swap slot as free.
  return true;  // Return true indicating successful swap-in.
}


/**
 * Frees a swap slot, making it available for future use.
 * @param swap_slot The index of the swap slot to free.
 */
void swap_free(size_t swap_slot)
{
  bitmap_reset(st.allocated_slots, swap_slot);  // Mark the specified swap slot as free.
}

