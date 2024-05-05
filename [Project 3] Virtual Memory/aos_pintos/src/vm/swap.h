#ifndef VM_SWAP_H
#define VM_SWAP_H
#include <bitmap.h>
#include <hash.h>
#include <list.h>

struct bitmap *swap_bitmap; 					// Bitmap to track usage of swap space indexes

void swap_init();								// Initializes swap system resources

void swap_in(size_t used_index, void *kaddr);	// Loads data from swap slot into physical memory address

size_t swap_out(void *kaddr);					// Writes page at physical address to swap partition and returns its index

#endif