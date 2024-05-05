#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <list.h>
#include "threads/thread.h"
#include "threads/vaddr.h"

#define VM_EXEC 0    /* Load data from a executable file. */
#define VM_MAP 1   		/* Load data from a mapped file. */
#define VM_SWAP 2   	/* Load data from swap space. */


struct vm_entry{
    uint8_t type; 		/* Type of the vm_entry: VM_BIN, VM_FILE, or VM_ANON. */
    void *vaddr;  		/* Virtual page number managed by this vm_entry. */
    bool writable;    	/* True if the address is writable. */
    bool pinned;      	/* Prevents eviction if true. */
    bool is_loaded;   	/* Flag indicating if the page is loaded into physical memory. */
    struct file* file;  /* File mapped to the virtual address. */

    struct list_elem mmap_elem;   /* List element for mmap list. */

    size_t offset;    		/* File offset to read from. */
    size_t read_bytes;    	/* Data size written in the virtual page. */
    size_t zero_bytes;    	/* Remaining bytes of the page to be filled with zeros. */

    size_t swap_slot;     	/* Swap slot index. */
    struct hash_elem elem;  /* Hash table element. */
};

void initVm(struct hash *vm);                          		// Init the virtual memory hash table
bool insertVmEntry(struct hash *vm, struct vm_entry *vme); 	// Inserts a vm_entry into the hash table
bool deleteVmEntry(struct hash *vm, struct vm_entry *vme); 	// Deletes a vm_entry from the hash table
struct vm_entry *findVmEntry(void *vaddr);              	// Finds a vm_entry by virtual address
void destroyVm(struct hash *vm);                        	// Destroys the virtual memory hash table, freeing resources
bool loadFileIntoVm(void *kaddr, struct vm_entry *vme); 	// Loads a file segment into memory based on vm_entry spec

struct page{
    void *kaddr;    		/* Physical address of the page. */
    struct vm_entry *vme;   /* Pointer to the vm_entry mapped to this physical page. */
    struct thread *thread;  /* Pointer to the thread using this physical page. */
    struct list_elem lru;   /* List element for LRU list linkage. */
};

struct mmap_file{
    int mapid;  			/* Mapping ID returned by mmap(). 0 signifies CLOSE_ALL. */
    struct file * file; 	/* File object being mapped. */
    struct list_elem elem;  /* List element for linking mmap_file structures. */
    struct list vme_list;   /* List of all vm_entry structures corresponding to this mmap_file. */
};



#endif
