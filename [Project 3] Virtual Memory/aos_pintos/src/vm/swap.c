#include "vm/swap.h"
#include "devices/block.h"
#include "vm/frame.h"
#include "vm/page.h"

const size_t BLOCK_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE; // Number of blocks per page.

// Initializes the swap system.
void swap_init() {
    swap_bitmap = bitmap_create(8 * 1024); // Create a bitmap for swap space management.
}



// Added
void swap_in(size_t used_index, void *kaddr) {
    struct block *swap_disk = block_get_role(BLOCK_SWAP);
    if (bitmap_test(swap_bitmap, used_index)) {
        for (int i = 0; i < BLOCK_PER_PAGE; i++) {
            block_read(swap_disk, used_index * BLOCK_PER_PAGE + i, (char *)kaddr + (i * BLOCK_SECTOR_SIZE));
        }
        bitmap_reset(swap_bitmap, used_index);
    }
}




// Added
size_t swap_out(void *kaddr) {
    struct block *swap_disk = block_get_role(BLOCK_SWAP);
    size_t swap_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
    if (swap_index != BITMAP_ERROR) {
        for (int i = 0; i < BLOCK_PER_PAGE; i++) {
            block_write(swap_disk, swap_index * BLOCK_PER_PAGE + i, (char *)kaddr + (i * BLOCK_SECTOR_SIZE));
        }
    }
    return swap_index;
}

