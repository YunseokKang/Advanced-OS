#include "vm/page.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include <string.h>
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"

// Added
static unsigned vm_hash_func(const struct hash_elem *e, void *aux) {
    struct vm_entry *vme = hash_entry(e, struct vm_entry, elem); // Retrieve the vm_entry from the hash element.
    return hash_int((int)vme->vaddr); // Calculate and return the hash value using the virtual address.
}

// Added
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux) {
    struct vm_entry *vme_a = hash_entry(a, struct vm_entry, elem); // Retrieve the first vm_entry.
    struct vm_entry *vme_b = hash_entry(b, struct vm_entry, elem); // Retrieve the second vm_entry.
    return vme_a->vaddr < vme_b->vaddr; // Compare their virtual addresses and return the result.
}

// Added
static void destroyVm_func(struct hash_elem *e, void *aux)
{
	struct vm_entry *vme=hash_entry(e, struct vm_entry, elem);
	freePageByAddr(pagedir_get_page (thread_current ()->pagedir, vme->vaddr));
	free(vme);
}

// Added
void initVm(struct hash *vm) {
    // Init the hash table with the provided hash function, comparison function,
    // and NULL for auxiliary data. This configuration allows the hash table to efficiently
    // organize and access vm_entry structures based on their virtual addresses.
    hash_init(vm, vm_hash_func, vm_less_func, NULL);
}











// Added
bool insertVmEntry(struct hash *vm, struct vm_entry *vme) {
    // Before insertion, ensure the vm_entry is not marked as pinned.
    // "Pinned" entries are prevented from being swapped out, but new entries
    // should initially allow swapping.
    vme->pinned = false;

    // Attempt to insert the vm_entry into the hash table. If an entry with the
    // same key (virtual address) already exists, hash_insert returns a pointer
    // to the existing element, otherwise it returns NULL.
    struct hash_elem *elem = hash_insert(vm, &(vme->elem));

    // Return true if the insertion was successful (no existing entry with the same key),
    // or false if an entry with the same key already exists.
    return elem == NULL;
}

bool deleteVmEntry(struct hash *vm, struct vm_entry *vme) {
    // Attempt to delete the vm_entry from the hash table.
    struct hash_elem *elem = hash_delete(vm, &(vme->elem));

    // If the element was not found in the hash table, return false.
    if (elem == NULL) {
        return false; // Deletion failed because the element wasn't found.
    }
    
    // If the vm_entry was successfully deleted, proceed with cleaning up.
    // First, retrieve the physical page associated with the vm_entry's virtual address
    // and free it. Note: free_page also clears the page from the page directory.
    void *kaddr = pagedir_get_page(thread_current()->pagedir, vme->vaddr);
    if (kaddr != NULL) {
        freePageByAddr(kaddr);
    }

    // Free the vm_entry structure itself.
    free(vme);

    return true; // Deletion succeeded.
}


struct vm_entry *findVmEntry(void *vaddr) {
    // Obtain the current thread's structure for access to its virtual memory hash table.
    struct thread *cur = thread_current();

    // Round down the virtual address to the start of the page.
    // This ensures we're working with page-aligned addresses, as the VM system operates on pages.
    void *page_vaddr = pg_round_down(vaddr);

    // Prepare a temporary vm_entry structure to use for the search.
    // This is necessary because hash_find expects a hash_elem, and in our hash table,
    // hash_elems are embedded within vm_entry structures.
    struct vm_entry search_entry;
    search_entry.vaddr = page_vaddr;

    // Attempt to find the vm_entry.
    // hash_find returns a pointer to the hash_elem if found, or NULL if not.
    struct hash_elem *e = hash_find(&cur->vm, &search_entry.elem);

    // Convert the found hash_elem back to a vm_entry structure and return it.
    // If no entry is found, return NULL to indicate failure to find a matching vm_entry.
    return e ? hash_entry(e, struct vm_entry, elem) : NULL;
}

// Added
bool loadFileIntoVm(void *kaddr, struct vm_entry *vme) {
    // Seek to the specified offset in the file.
    file_seek(vme->file, vme->offset);

    // Read the file content into memory. Check if read bytes match expected.
    if (file_read(vme->file, kaddr, vme->read_bytes) != (int)vme->read_bytes) {
        return false; // Return false if the read operation didn't complete as expected.
    }

    // Zero the rest of the page if there are any zero bytes specified.
    // Cast kaddr to char* for arithmetic operation
    memset((char *)kaddr + vme->read_bytes, 0, vme->zero_bytes);

    return true; // Indicate success.
}

// Added
void destroyVm(struct hash *vm)
{
	hash_destroy (vm, destroyVm_func);
}

