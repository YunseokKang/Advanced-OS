#include "filesys/inode.h"
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

// added
#define INODE_NUM_DIRECT 122
#define INODE_NUM_BLOCKS 124
#define INODE_IND_IDX INODE_NUM_DIRECT
#define INODE_DUB_IND_IDX INODE_NUM_BLOCKS - 1
#define INODE_NUM_IN_IND_BLOCK 128

static char ZEROARRAY[BLOCK_SECTOR_SIZE];  // An array of zeros, typically used to initialize or clear sectors.


static struct lock open_inodes_lock;  // Mutex lock for synchronizing access to the list of open inodes.
static struct list open_inodes;  // A list that tracks all open inodes to ensure unique instances.


/* Defines the structure of an on-disk indirect inode sector, which contains an array of block sector indices.
   This structure enables the expansion of the inode to support large files by pointing to additional blocks of data. */
struct inode_indirect_sector
{
  block_sector_t block_idxs[INODE_NUM_IN_IND_BLOCK];  // Array of block indices stored in this indirect sector.
};


/* Represents the on-disk format of an inode. This structure must match exactly the size of a disk sector
   to ensure proper alignment and storage on disk. */
struct inode_disk
{
  block_sector_t block_idxs[INODE_NUM_BLOCKS];  // Array of direct block indices where actual file data is stored.
  bool is_dir;  // Flag to indicate if this inode represents a directory.
  off_t length;  // The total size of the file or directory in bytes.
  unsigned magic;  // Magic number for identifying valid inode structures.
  bool is_symlink;  // Flag to indicate if this inode represents a symbolic link.
};

static bool inode_clear (struct inode*);
static void inode_clear_recursive (block_sector_t, off_t, int);
static bool inode_expand (struct inode_disk*, off_t);
static bool inode_expand_recursive (block_sector_t*, off_t, int);
static block_sector_t get_index (const struct inode_disk*, off_t);
static struct inode_disk *get_data_at (block_sector_t);


/* Calculates and returns the number of disk sectors required to store 'size' bytes.
   This function uses rounding to ensure that any partial sector of data still
   requires a full sector's allocation on disk. */
static inline size_t
bytes_to_sectors(off_t size)
{
  return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE);  // Rounds up division of 'size' by BLOCK_SECTOR_SIZE.
}


/* Represents an in-memory structure for an inode, which includes metadata about a file
   or directory such as its size, type, and status, along with synchronization mechanisms
   for concurrent access and modification. */
struct inode
{
  struct lock lock;                   // Mutex for protecting the inode structure from concurrent modifications.
  struct lock eof_lock;               // Mutex for synchronizing read operations that extend beyond the current end of the file.
  struct condition data_loaded_cond;  // Condition variable used to wait for inode data to be fully loaded on open.
  bool data_loaded;                   // Flag indicating whether the inode data has been successfully loaded and is ready to use.
  struct lock dir_lock;               // Mutex for directory operations, providing synchronization during modifications.
  struct list_elem elem;              // List element for including this inode in global lists.
  block_sector_t sector;              // Disk sector number where this inode's data is stored.
  bool is_dir;                        // Boolean indicating if this inode represents a directory (true) or a file (false).
  off_t length;                       // Size of the file or directory in bytes.
  int open_cnt;                       // Counter tracking how many processes have this inode open.
  bool removed;                       // Boolean indicating if the inode has been marked for deletion.
  int deny_write_cnt;                 // Counter to manage write denial states. When greater than 0, writing is denied.

  // Additional fields added for extended functionality.
  int physicalsize;                   // Physical size of the inode content (may differ from logical size due to things like sparse allocation).
  bool is_symlink;                    // Boolean indicating if this inode is a symbolic link.
};


/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector (const struct inode_disk *disk_inode, off_t pos, off_t length) 
{
  ASSERT (disk_inode != NULL);
  if (pos >= 0 && pos < length)
    {
      off_t abs_idx =  pos / BLOCK_SECTOR_SIZE;
      return get_index (disk_inode, abs_idx);
    }
  else
    return INODE_INVALID_SECTOR;
}

/* Initializes the inode module. */
void inode_init (void) 
{
  lock_init (&open_inodes_lock);
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create (block_sector_t sector, off_t length, bool isdir)
{
  struct inode_disk *t_disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *t_disk_inode == BLOCK_SECTOR_SIZE);

  t_disk_inode = calloc (1, sizeof(struct inode_disk));
  if (t_disk_inode != NULL)
    {
      t_disk_inode->length = length;
      t_disk_inode->magic = INODE_MAGIC;
      t_disk_inode->is_dir = isdir;
      
      memset (&t_disk_inode->block_idxs, INODE_INVALID_SECTOR,
              INODE_NUM_BLOCKS * sizeof(block_sector_t));
      if (!inode_expand (t_disk_inode, length))
        success = false;
      else
        {
          cache_io (sector, t_disk_inode, true, 0, BLOCK_SECTOR_SIZE, true);
          success = true; 
        } 
    }
  free (t_disk_inode);
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *inode_open(block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Acquire the lock to access the global list of open inodes safely. */
  lock_acquire(&open_inodes_lock);
  /* Iterate through the list of open inodes to check if the inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes);
       e = list_next(e))
    {
      inode = list_entry(e, struct inode, elem);
      if (inode->sector == sector)  // Check if the sector matches.
        {
          /* If found, release the global lock and return the reopened inode. */
          lock_release(&open_inodes_lock);
          return inode_reopen(inode);
        }
    }

  /* If the inode is not open, allocate memory for a new inode. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    {
      /* Release lock and return NULL if memory allocation fails. */
      lock_release(&open_inodes_lock);
      return NULL;
    }

  /* Initialize the newly created inode structure. */
  lock_init(&inode->lock);
  lock_init(&inode->eof_lock);
  cond_init(&inode->data_loaded_cond);
  lock_init(&inode->dir_lock);
  lock_acquire(&inode->lock);
  list_push_front(&open_inodes, &inode->elem);  // Add the inode to the list of open inodes.
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  inode->data_loaded = false;
  
  lock_release(&inode->lock);
  lock_release(&open_inodes_lock);

  /* Load the inode data from disk. */
  lock_acquire(&inode->lock);
  struct inode_disk *disk_inode = get_data_at(inode->sector);
  cache_io(inode->sector, disk_inode, true, 0, sizeof(struct inode_disk), false);
  inode->is_dir = disk_inode->is_dir;
  inode->length = disk_inode->length;

  inode->data_loaded = true;  // Mark the data as loaded.
  inode->physicalsize = 0;  // Initialize physical size.
  inode->is_symlink = disk_inode->is_symlink;  // Set symlink status based on disk data.

  cond_broadcast(&inode->data_loaded_cond, &inode->lock);  // Signal all waiting threads that the data is now loaded.
  lock_release(&inode->lock);
  free(disk_inode);  // Free the disk inode structure.
  return inode;  // Return the initialized inode.
}


/* Reopens an inode, increasing its open count. Ensures that the inode data is loaded before returning. */
struct inode *inode_reopen(struct inode *inode)
{
  if (inode == NULL)  // Check if the inode is null.
    return NULL;

  lock_acquire(&inode->lock);  // Acquire lock to modify inode properties safely.
  if (inode->removed)  // Check if the inode has been marked as removed.
    {
      lock_release(&inode->lock);  // Release lock if inode is removed.
      return NULL;
    }
  inode->open_cnt++;  // Increment the open count to keep track of how many times the inode is opened.
  while (!inode->data_loaded)  // Wait until the inode data is fully loaded.
    cond_wait(&inode->data_loaded_cond, &inode->lock);
  lock_release(&inode->lock);  // Release the lock.
  return inode;  // Return the inode.
}


/* Returns the count of how many times an inode is currently open. */
int inode_open_count(struct inode *inode)
{
  int count;
  lock_acquire(&inode->lock);  // Acquire lock to access inode properties safely.
  count = inode->open_cnt;  // Retrieve the open count.
  lock_release(&inode->lock);  // Release the lock.
  return count;  // Return the open count.
}


/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}


/* Returns a pointer to the directory lock. */
struct lock *
inode_dir_lock (struct inode *inode)
{
  return &inode->dir_lock;
}


/* Clears the data associated with an inode, releasing all of its allocated sectors. */
static bool inode_clear(struct inode* inode)
{
  struct inode_disk *disk_inode = get_data_at(inode->sector);  // Retrieve the on-disk inode data.
  if (inode->length < 0) return false;  // Validate that the inode length is non-negative.

  int num_sectors_left = bytes_to_sectors(inode->length);  // Compute the total number of sectors the inode uses.

  // Clear direct block pointers.
  int num_direct = (num_sectors_left < INODE_NUM_DIRECT) ? num_sectors_left : INODE_NUM_DIRECT;
  for (int i = 0; i < num_direct; ++i)
    {
      free_map_release(disk_inode->block_idxs[i], 1);  // Release each sector allocated to direct blocks.
    }
  num_sectors_left -= num_direct;  // Decrement the count of sectors left to clear.

  // Free sectors from indirect block if necessary.
  int num_indirect = (num_sectors_left < INODE_NUM_IN_IND_BLOCK) ? num_sectors_left : INODE_NUM_IN_IND_BLOCK;
  if (num_indirect > 0)
  {
    inode_clear_recursive(disk_inode->block_idxs[INODE_IND_IDX], num_indirect, 1);
    num_sectors_left -= num_indirect;  // Adjust remaining sectors count after clearing indirect blocks.
  }

  // Free sectors from doubly indirect block if necessary.
  off_t oRet = INODE_NUM_IN_IND_BLOCK * INODE_NUM_IN_IND_BLOCK;
  num_indirect = (num_sectors_left < oRet) ? num_sectors_left : oRet;
  if (num_indirect > 0)
    {
      inode_clear_recursive(disk_inode->block_idxs[INODE_DUB_IND_IDX], num_indirect, 2);
      num_sectors_left -= num_indirect;
    }

  ASSERT(num_sectors_left == 0);  // Ensure all sectors were accounted for and released.
  free(disk_inode);  // Free the disk_inode structure.
  return true;
}


/* Helper function to recursively clear indirect and doubly indirect block references. */
static void inode_clear_recursive(block_sector_t idx, off_t num_sectors, int level)
{
  if (level != 0)
    {
      struct inode_indirect_sector indirect_block;  // Structure to hold indirect block data.
      cache_io(idx, &indirect_block, true, 0, BLOCK_SECTOR_SIZE, false);  // Read the block from disk.

      off_t base = (level == 1 ? 1 : INODE_NUM_IN_IND_BLOCK);
      off_t n = DIV_ROUND_UP(num_sectors, base);
      for (off_t i = 0; i < n; ++i)
        {
          off_t num_in_level = num_sectors < base ? num_sectors : base;
          inode_clear_recursive(indirect_block.block_idxs[i], num_in_level, level - 1);
          num_sectors -= num_in_level;
        }
    }
  free_map_release(idx, 1);  // Release the block at the current index.
}


/* Closes an inode, decrementing its open count. If it is the last reference, the inode is freed and,
   if marked as removed, its blocks are also freed. */
void inode_close(struct inode *inode)
{
  bool last_instance;

  if (inode == NULL)  // Check if the inode pointer is NULL.
    return;

  lock_acquire(&open_inodes_lock);  // Acquire the global open inodes lock.
  lock_acquire(&inode->lock);  // Acquire the inode-specific lock.
  last_instance = --inode->open_cnt == 0;  // Decrement open count and check if this is the last reference.
  if (last_instance)
    {
      list_remove(&inode->elem);  // Remove the inode from the list of open inodes.
      if (inode->removed)  // Check if the inode is marked for deletion.
        {
          free_map_release(inode->sector, 1);  // Release the inode's sector.
          inode_clear(inode);  // Clear the inode's data.
        }
    }
  lock_release(&inode->lock);  // Release the inode-specific lock.
  lock_release(&open_inodes_lock);  // Release the global lock.

  if (last_instance)
    free(inode);  // Free the inode structure if it's the last instance.
}


/* Returns true if the inode represents a directory, false otherwise. */
bool inode_isdir(const struct inode *inode)
{
  return inode->is_dir;  // Return the is_dir flag of the inode.
}

/* Returns the physical size of the inode. */
off_t inode_get_physicalsize(struct inode *inode)
{
  return inode->physicalsize;  // Return the physical size stored in the inode.
}


/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  lock_acquire (&inode->lock);
  inode->removed = true;
  lock_release (&inode->lock);
}


/* Reads SIZE bytes from INODE into BUFFER, starting at OFFSET. Returns the number of bytes actually read,
   which may be less than SIZE due to end of file or an error. */
off_t
inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset)
{
    uint8_t *buffer = buffer_;  // Cast the void buffer to a type-specific pointer for byte manipulation.
    off_t bytes_read = 0;  // Initialize counter for bytes read.
    off_t inode_len = inode_length(inode);  // Get the current length of the inode (file size).

    struct inode_disk *disk_inode = get_data_at(inode->sector);  // Retrieve inode data from disk.
    while (size > 0)  // Continue reading while there are bytes left to read.
    {
        block_sector_t sector_idx = byte_to_sector(disk_inode, offset, inode_len);  // Get sector index from offset.
        if (sector_idx == INODE_INVALID_SECTOR) break;  // Stop if no valid sector is found.
        int sector_ofs = offset % BLOCK_SECTOR_SIZE;  // Calculate offset within the sector.

        off_t inode_left = inode_len - offset;  // Calculate remaining bytes in the inode.
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;  // Calculate remaining bytes in the sector.
        int min_left = inode_left < sector_left ? inode_left : sector_left;  // Find the minimum of the two.

        off_t chunk_size = size < min_left ? size : min_left;  // Determine the actual number of bytes to read next.
        if (chunk_size <= 0)
            break;

        block_sector_t sector_next = byte_to_sector(disk_inode, offset + chunk_size, inode_len);  // Get the next sector.
        if (sector_next == sector_idx) sector_next = INODE_INVALID_SECTOR;  // Avoid looping on the same sector.

        uint8_t tmp_buf[chunk_size];  // Temporary buffer to store read data.
        cache_io_next(sector_idx, tmp_buf, false, sector_ofs, chunk_size, false, sector_next);  // Perform cached read.
        memcpy(buffer + bytes_read, tmp_buf, chunk_size);  // Copy from temp buffer to the output buffer.

        size -= chunk_size;  // Decrease remaining size.
        offset += chunk_size;  // Increment offset.
        bytes_read += chunk_size;  // Increment count of bytes read.
    }

    free(disk_inode);  // Free the allocated disk inode structure.
    return bytes_read;  // Return the number of bytes read.
}


/* Writes SIZE bytes from BUFFER into INODE starting at OFFSET. Returns the number of bytes actually written,
   which may be less than SIZE if end of file is reached or an error occurs. */
off_t
inode_write_at(struct inode *inode, const void *buffer_, off_t size, off_t offset)
{
    const uint8_t *buffer = buffer_;  // Cast the void buffer to a type-specific pointer for byte manipulation.
    off_t bytes_written = 0;  // Initialize counter for bytes written.
    off_t length_after_write;  // Variable to hold potential new file length after write.
    bool expand_write = false;  // Flag to indicate if the file needs to be expanded.

    if (inode->deny_write_cnt)  // Check if writes are currently denied on this inode.
        return 0;

    struct inode_disk *disk_inode = get_data_at(inode->sector);  // Retrieve inode data from disk.
    length_after_write = inode_length(inode);  // Get the current length of the inode.

    expand_write = (offset + size) > length_after_write;  // Determine if the write requires file expansion.
    if (expand_write)
        lock_acquire(&inode->eof_lock);  // Acquire lock if writing past end of file.

    if (byte_to_sector(disk_inode, offset + size - 1, length_after_write) == INODE_INVALID_SECTOR)
    {
        if (!inode_expand(disk_inode, offset + size))
        {
            lock_release(&inode->eof_lock);  // Release lock if expansion fails.
            free(disk_inode);  // Free the disk inode.
            return 0;  // Return 0 as the write failed.
        }
    }
    else if (expand_write)
    {
        expand_write = false;  // Expansion not needed if already expanded by another process.
        lock_release(&inode->eof_lock);
    }

    if (expand_write)
        length_after_write = offset + size;  // Adjust the length after write if expansion occurred.

    while (size > 0)  // Continue writing while there is data left.
    {
        block_sector_t sector_idx = byte_to_sector(disk_inode, offset, length_after_write);  // Get the sector for writing.
        int sector_ofs = offset % BLOCK_SECTOR_SIZE;  // Calculate offset within the sector.

        off_t inode_left = length_after_write - offset;  // Calculate remaining bytes in the inode.
        int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;  // Calculate remaining bytes in the sector.
        int min_left = inode_left < sector_left ? inode_left : sector_left;  // Determine the minimum of the two.

        off_t chunk_size = size < min_left ? size : min_left;  // Determine the chunk size to write next.
        if (chunk_size <= 0)
            break;

        block_sector_t sector_next = byte_to_sector(disk_inode, offset + chunk_size, length_after_write);  // Get next sector.
        if (sector_next == sector_idx) sector_next = INODE_INVALID_SECTOR;  // Avoid looping on the same sector.

        uint8_t tmp_buf[chunk_size];  // Temporary buffer for writing.
        memcpy(tmp_buf, buffer + bytes_written, chunk_size);  // Copy data to the temporary buffer.
        cache_io_next(sector_idx, tmp_buf, true, sector_ofs, chunk_size, true, sector_next);  // Write data to cache.

        size -= chunk_size;  // Decrease the remaining size.
        offset += chunk_size;  // Increase the offset.
        bytes_written += chunk_size;  // Increase the count of bytes written.
    }

    if (expand_write)
    {
        inode->length = length_after_write;  // Update the inode's length.
        disk_inode->length = length_after_write;  // Update the disk inode's length.
        lock_release(&inode->eof_lock);  // Release the EOF lock.
        cache_io(inode->sector, disk_inode, true, 0, BLOCK_SECTOR_SIZE, true);  // Flush changes to cache.
    }
    free(disk_inode);  // Free the disk inode.
    inode->physicalsize = bytes_written;  // Update the inode's physical size.
    return bytes_written;  // Return the number of bytes written.
}


/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write (struct inode *inode) 
{
  lock_acquire (&inode->lock);
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  lock_release (&inode->lock);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write (struct inode *inode) 
{
  lock_acquire (&inode->lock);
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
  lock_release (&inode->lock);
}


/* Returns the current length of an inode in bytes by acquiring a lock to ensure thread-safe access to the inode's length attribute. */
off_t inode_length(struct inode *inode)
{
    off_t length;
    lock_acquire(&inode->lock);  // Acquire lock to safely access the inode's properties.
    length = inode->length;      // Copy the length to a local variable.
    lock_release(&inode->lock);  // Release the lock.
    return length;               // Return the length of the inode.
}


/* Retrieves the block index for a given absolute index from an inode's disk structure. This function handles direct, indirect, and doubly indirect block indexing. */
static block_sector_t get_index(const struct inode_disk *disk_inode, off_t abs_idx)
{
    struct inode_indirect_sector *sect;
    block_sector_t idx = INODE_INVALID_SECTOR;  // Default to invalid sector.
    
    if (abs_idx < INODE_NUM_DIRECT)
    {
        idx = disk_inode->block_idxs[abs_idx];  // Direct indexing.
    }
    else if (abs_idx < (INODE_NUM_DIRECT + INODE_NUM_IN_IND_BLOCK))
    {
        sect = calloc(1, sizeof(struct inode_indirect_sector));  // Allocate space for an indirect block structure.
        if (sect != NULL)
        {
            cache_io(disk_inode->block_idxs[INODE_IND_IDX], sect, true, 0, BLOCK_SECTOR_SIZE, false);  // Read the indirect block from disk.
            idx = sect->block_idxs[abs_idx - INODE_NUM_DIRECT];  // Calculate the index within the indirect block.
            free(sect);  // Free the allocated memory.
        }
    }
    else if (abs_idx < (INODE_NUM_DIRECT + INODE_NUM_IN_IND_BLOCK) + INODE_NUM_IN_IND_BLOCK * INODE_NUM_IN_IND_BLOCK)
    {
        off_t start = abs_idx - (INODE_NUM_DIRECT + INODE_NUM_IN_IND_BLOCK);
        off_t outer_idx = start / INODE_NUM_IN_IND_BLOCK;  // Calculate index for outer block.
        off_t inner_idx = start % INODE_NUM_IN_IND_BLOCK;  // Calculate index for inner block.

        sect = calloc(1, sizeof(struct inode_indirect_sector));  // Allocate space for an indirect block structure.
        if (sect != NULL)
        {
            cache_io(disk_inode->block_idxs[INODE_DUB_IND_IDX], sect, true, 0, BLOCK_SECTOR_SIZE, false);  // Read the doubly indirect block from disk.
            cache_io(sect->block_idxs[outer_idx], sect, true, 0, BLOCK_SECTOR_SIZE, false);  // Read the specific indirect block from the doubly indirect block.
            idx = sect->block_idxs[inner_idx];  // Calculate the final block index.
            free(sect);  // Free the allocated memory.
        }
    }

    return idx;  // Return the calculated block index or INODE_INVALID_SECTOR if not found.
}


/* Reads and returns the inode_disk structure from the given sector index. The caller is responsible for freeing the returned buffer. */
static struct inode_disk *get_data_at(block_sector_t sector_idx)
{
    struct inode_disk *ret_disk_inode = calloc(1, sizeof(struct inode_disk));  // Allocate memory for the inode_disk structure.
    cache_io(sector_idx, ret_disk_inode, true, 0, BLOCK_SECTOR_SIZE, false);  // Read the inode data from the disk into the allocated buffer.
    return ret_disk_inode;  // Return the pointer to the newly filled inode_disk structure.
}


/* Expands an inode to at least a specified size (NEW_SIZE), allocating necessary sectors. Returns true on successful expansion, or false on failure. */
static bool inode_expand(struct inode_disk *disk_inode, off_t new_size)
{
    if (new_size < 0) return false;  // Return false if the new size is invalid.

    int num_sectors_left = bytes_to_sectors(new_size);  // Calculate the total number of sectors required.

    // Handle direct blocks allocation.
    int num_direct = (num_sectors_left < INODE_NUM_DIRECT) ? num_sectors_left : INODE_NUM_DIRECT;
    for (int i = 0; i < num_direct; ++i)
    {
        block_sector_t *sector_cand = &disk_inode->block_idxs[i];
        if (*sector_cand == INODE_INVALID_SECTOR)
        {
            if (!free_map_allocate(1, sector_cand))
            {
                return false;  // Return false if sector allocation fails.
            }
            cache_io(*sector_cand, ZEROARRAY, false, 0, BLOCK_SECTOR_SIZE, true);  // Initialize the new sector to zeros.
        }
    }
    num_sectors_left -= num_direct;
    if (num_sectors_left == 0) return true;  // Return true if all needed sectors have been allocated.

    // Handle indirect blocks allocation.
    int num_indirect = (num_sectors_left < INODE_NUM_IN_IND_BLOCK) ? num_sectors_left : INODE_NUM_IN_IND_BLOCK;
    bool bRet = inode_expand_recursive(&disk_inode->block_idxs[INODE_IND_IDX], num_indirect, 1);
    if (!bRet) return false;  // Return false if expanding indirect blocks fails.
    num_sectors_left -= num_indirect;
    if (num_sectors_left == 0) return true;  // Return true if all needed sectors have been allocated.

    // Handle doubly indirect blocks allocation.
    off_t oRet = INODE_NUM_IN_IND_BLOCK * INODE_NUM_IN_IND_BLOCK;
    num_indirect = (num_sectors_left < oRet) ? num_sectors_left : oRet;
    bRet = inode_expand_recursive(&disk_inode->block_idxs[INODE_DUB_IND_IDX], num_indirect, 2);
    if (!bRet) return false;  // Return false if expanding doubly indirect blocks fails.
    num_sectors_left -= num_indirect;
    return num_sectors_left == 0;  // Return true if all needed sectors have been allocated, false otherwise.
}


/* Recursive helper function to expand an inode by allocating necessary indirect blocks. Handles both levels of indirect blocks (level 1 and level 2). Returns true on success, false on failure. */
static bool inode_expand_recursive(block_sector_t *idx, off_t num_sectors_left, int level)
{
    if (level == 0)  // Base case: allocate a sector directly.
    {
        if (*idx == 0)  // Check if the sector needs allocation.
        {
            if (!free_map_allocate(1, idx))
            {
                return false;  // Return false if allocation fails.
            }
            cache_io(*idx, ZEROARRAY, false, 0, BLOCK_SECTOR_SIZE, true);  // Initialize the sector.
        }
        return true;
    }

    struct inode_indirect_sector indirect_block;  // Structure to hold indirect sector data.
    if (*idx == INODE_INVALID_SECTOR || *idx == 0)  // Check if the indirect block needs allocation.
    {
        if (!free_map_allocate(1, idx))
        {
            return false;  // Return false if allocation fails.
        }
        cache_io(*idx, ZEROARRAY, true, 0, BLOCK_SECTOR_SIZE, true);  // Initialize the new indirect block.
    }
    cache_io(*idx, &indirect_block, true, 0, BLOCK_SECTOR_SIZE, false);  // Read existing indirect block data.

    off_t base = (level == 1 ? 1 : INODE_NUM_IN_IND_BLOCK);  // Determine the base for this level.
    off_t n = DIV_ROUND_UP(num_sectors_left, base);  // Calculate how many entries to handle at this level.
    for (off_t i = 0; i < n; ++i)
    {
        off_t num_in_level = (num_sectors_left < base) ? num_sectors_left : base;  // Determine number of sectors in this block.
        bool bRet = inode_expand_recursive(&indirect_block.block_idxs[i], num_in_level, level - 1);
        if (!bRet) return false;  // Return false if recursive expansion fails.
        num_sectors_left -= num_in_level;  // Decrease remaining sectors.
    }

    cache_io(*idx, &indirect_block, true, 0, BLOCK_SECTOR_SIZE, true);  // Write back the modified indirect block.
    return true;  // Return true on successful expansion.
}


bool inode_get_symlink (struct inode *inode) { 
  ASSERT (inode != NULL);
  return inode->is_symlink; 
}

void inode_set_symlink (struct inode *inode, bool is_symlink)
{
  struct inode_disk* inode_disk = get_data_at(inode->sector);
  inode->is_symlink = inode_disk->is_symlink = is_symlink;
  cache_io(inode->sector, inode_disk, false, 0, BLOCK_SECTOR_SIZE, true);
}
