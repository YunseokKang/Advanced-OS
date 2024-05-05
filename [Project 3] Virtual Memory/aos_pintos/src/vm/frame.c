#include "frame.h"


// Added
struct page *allocPage(enum palloc_flags flags) {
    lock_acquire(&lruLock); // Lock to ensure exclusive access to the LRU list and related operations.

    // Attempt to allocate a page. If unsuccessful, free some pages and try again.
    uint8_t *kpage = NULL;
    while ((kpage = palloc_get_page(flags)) == NULL) {
        tryFreePages(flags); // Try to free some pages if allocation fails.
    }

    // Allocate and initialize a new page structure.
    struct page *page = malloc(sizeof(struct page));
    if (page == NULL) {
        palloc_free_page(kpage); // Ensure to free the allocated kernel page if page structure allocation fails.
        lock_release(&lruLock);
        return NULL; // Return NULL if unable to allocate the page structure.
    }
    page->kaddr = kpage;
    page->thread = thread_current();

    addPageToLru(page); // Add the new page to the LRU list.
    lock_release(&lruLock); // Unlock after the page has been added to the list.

    return page; // Return the pointer to the newly allocated page structure.
}


//Added, To move the LRU list of the clock algorithm
static struct list_elem* get_next_lru_clock() 
{   // Immediately return NULL if the lruList is empty.
    if (list_empty(&lruList))
        return NULL;

    // If lruIter is either NULL or at the list's end, reset it to the beginning.
    if (lruIter == NULL || lruIter == list_end(&lruList))
        lruIter = list_begin(&lruList);
    else
        // Move lruIter to the next element, or wrap around to the beginning if at the end.
        lruIter = list_next(lruIter) == list_end(&lruList) ? list_begin(&lruList) : list_next(lruIter);

    return lruIter;
}


// Added, Init data structure related to LRU
void initLru(void) {
    // Initialize the list that will be used for LRU page tracking.
    list_init(&lruList);
    // Initialize the lock for thread-safe access to the LRU list.
    lock_init(&lruLock);
    // Initially, there are no pages in the LRU list, so set the clock to NULL.
    lruIter = NULL;
}

//Added, add user pages at the end of the LRU list
void addPageToLru(struct page* page)
{
    list_push_back(&lruList, &(page->lru));
}



void removePageFromLru(struct page *page)
{
    if(&page->lru==lruIter) {
        lruIter=list_next(lruIter);
    }
    list_remove(&page->lru);
}

//Added, To secure free memory when there is a lack of physical pages using the clock algorithm 
void tryFreePages(enum palloc_flags flags)
{
    struct page *victim = NULL;

    // Iterate through the LRU list to find a suitable victim page.
    for (struct list_elem *e = get_next_lru_clock(); e != list_end(&lruList); e = get_next_lru_clock()) {
        struct page *page = list_entry(e, struct page, lru);

        // Skip pages that are pinned or have been recently accessed.
        if (!page->vme->pinned && !pagedir_is_accessed(page->thread->pagedir, page->vme->vaddr)) {
            victim = page;
            break;
        }

        // Reset the accessed flag for the next iteration.
        pagedir_set_accessed(page->thread->pagedir, page->vme->vaddr, false);
    }

    // If no suitable victim is found, exit early.
    if (!victim) return;

    // Handle the victim page based on its type.
    bool is_dirty = pagedir_is_dirty(victim->thread->pagedir, victim->vme->vaddr);
    switch (victim->vme->type) {
        case VM_EXEC:
            if (is_dirty) {
                victim->vme->swap_slot = swap_out(victim->kaddr);
                victim->vme->type = VM_SWAP;
            }
            break;
        case VM_MAP:
            if (is_dirty) {
                file_write_at(victim->vme->file, victim->vme->vaddr, victim->vme->read_bytes, victim->vme->offset);
            }
            break;
        case VM_SWAP:
            victim->vme->swap_slot = swap_out(victim->kaddr);
            break;
    }

    // Update the page's loaded status and release it.
    victim->vme->is_loaded = false;
    freePageHelper(victim);
}



// Added
void freePageHelper(struct page *page) {
    // Ensure the page is valid before attempting to free it.
    if (page == NULL) return;

    // Remove the page from the LRU list to maintain the correct state of the LRU mechanism.
    removePageFromLru(page);

    // Clear the page's entry in the page directory to maintain the consistency of the memory mapping.
    // This prevents stale mappings from persisting after the page is freed.
    if (page->thread && page->vme && page->vme->vaddr) {
        pagedir_clear_page(page->thread->pagedir, pg_round_down(page->vme->vaddr));
    }

    // Free the physical memory associated with the page.
    if (page->kaddr) {
        palloc_free_page(page->kaddr);
    }

    // Finally, free the memory allocated for the page structure itself.
    free(page);
}


// Added
void freePageByAddr(void *kaddr) {
    lock_acquire(&lruLock); // Ensure exclusive access to the LRU list.

    // Iterate over the LRU list to find the page with the given kernel address.
    for (struct list_elem *e = list_begin(&lruList); e != list_end(&lruList); e = list_next(e)) {
        struct page *candidate_page = list_entry(e, struct page, lru);
        if (candidate_page->kaddr == kaddr) {
            // Found the page to be freed, exit the loop.
            freePageHelper(candidate_page);
            break; // Exit after freeing the page to avoid further traversal.
        }
    }

    lock_release(&lruLock); // Release the lock after operation completion.
}



