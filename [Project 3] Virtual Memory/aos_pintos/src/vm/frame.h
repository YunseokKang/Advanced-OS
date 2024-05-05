#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include <list.h>
#include "threads/synch.h"
#include "vm/page.h"
#include "threads/palloc.h"

struct list lruList;                               // LRU list for page management
struct lock lruLock;                               // and its synchronization lock

void initLru(void);                                // Init the LRU management system
struct list_elem *lruIter;                         // Pointer for iterating the LRU list with the clock algorithm

struct page *allocPage(enum palloc_flags flags);   // Allocates a page, possibly freeing others to make space

void addPageToLru(struct page* page);              // Adds a page to the LRU list
void removePageFromLru(struct page *page);         // Removes a page from the LRU list

void tryFreePages(enum palloc_flags flags);        // Frees pages using LRU and clock algorithm when necessary
void freePageByAddr(void *kaddr);                  // Frees a page by kernel address
void freePageHelper(struct page *page);            // Helper to free page resources and remove from LRU list

#endif /* VM_FRAME_H */
