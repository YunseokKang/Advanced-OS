#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "threads/thread.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "devices/timer.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "debug.h"

/* Partition that contains the file system. */
struct block *fs_device;


static void do_format (void);

static struct semaphore filesys_mutex; // Ensure mutual exclusion to filesys


/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init (bool format) 
{
  sema_init(&filesys_mutex, 1);  // Initialize semaphore

  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (!cache_init ())
    PANIC ("Could not initialize cache");

  if (format) 
    do_format ();

  free_map_open ();
  thread_current ()->cwd = dir_open_root ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done (void) 
{
  free_map_close ();
  cache_flush_all ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create (const char *path, off_t initial_size) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir = dir_open_dirs (path);
  const char *name = dir_parse_filename (path);
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, false)
                  && dir_add (dir, name, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}


// Added
bool filesys_symlink (char *target, char *linkpath)
{ 
  ASSERT (target != NULL && linkpath != NULL);
  bool success = filesys_create (linkpath,  NAME_MAX + 1);
  struct file *symlink = filesys_open (linkpath, false);
  inode_set_symlink (file_get_inode (symlink), true);
  inode_write_at (file_get_inode (symlink), target,  NAME_MAX + 1, 0);
  file_close (symlink);
  return success;
}


/* Attempts to create a new directory at the specified path. The creation is successful only if
   the immediate parent directory exists and the specified directory name does not exist in that parent.
   Returns true if the directory is successfully created, false otherwise. */
bool filesys_mkdir(const char *path) {
    struct dir *parent_dir = NULL;
    struct inode *inode = NULL;
    struct dir *dir = NULL;
    const char *dir_name;
    block_sector_t inode_sector = 0;

    ASSERT(path != NULL);

    parent_dir = dir_open_dirs(path);
    dir_name = dir_parse_filename(path);
    if (dir_name[0] == '\0')
        goto fail;

    if (parent_dir == NULL || !free_map_allocate(1, &inode_sector) || !dir_create(inode_sector))
        goto fail;

    inode = inode_open(inode_sector);
    if (inode == NULL)
        goto fail;

    dir = dir_open(inode);
    if (dir == NULL ||
        !dir_add(dir, "..", inode_get_inumber(dir_get_inode(parent_dir))) ||
        !dir_add(dir, ".", inode_sector) ||
        !dir_add(parent_dir, dir_name, inode_sector))
        goto fail;

    dir_close(dir);
    dir_close(parent_dir);
    return true;

fail:
    if (inode != NULL)
        inode_remove(inode);
    if (dir != NULL)
        dir_close(dir);
    if (inode == NULL && inode_sector != 0)
        free_map_release(inode_sector, 1);
    if (parent_dir != NULL)
        dir_close(parent_dir);
    return false;
}


/* Reads the next entry in the directory 'dir' and stores the null-terminated filename in 'name',
   which must have space for READDIR_MAX_LEN + 1 characters. Returns true if an entry is read,
   false if there are no more entries. */

bool filesys_readdir(struct dir *dir, char *name)
{
  ASSERT(name != NULL && dir != NULL);  // Assert that the name buffer and directory pointer are not NULL.
  return dir_readdir(dir, name);  // Call the lower-level dir_readdir function and return its result.
}


/* Opens a file or directory given a path. Returns a pointer to a file or directory structure,
   or NULL if the file or directory could not be found or opened. Additionally, sets 'isdir' to indicate
   if the path is a directory. */
void *filesys_open(const char *path, bool *isdir) {
    ASSERT(path != NULL);

    struct dir *dir;
    struct inode *inode = NULL;
    const char *name;
    bool found = false;

    dir = dir_open_dirs(path);
    if (!strcmp(path, "/"))
        name = ".";
    else
        name = dir_parse_filename(path);

    if (dir != NULL)
        found = dir_lookup(dir, name, &inode);
    dir_close(dir);

    if (!found)
        return NULL;

    if (isdir != NULL)
        *isdir = inode_isdir(inode);

    if (inode_get_symlink(inode)) {
        char target[15];
        inode_read_at(inode, target, NAME_MAX + 1, 0);
        struct dir *root = dir_open_root();
        if (!dir_lookup(root, target, &inode)) {
            dir_close(root);
            return NULL;
        }
        dir_close(root);
    }

    return inode_isdir(inode) ? (void *)dir_open(inode) : (void *)file_open(inode);
}


/* Evaluate the inumber of directory DIR. */
int filesys_dir_inumber (struct dir *dir)
{
  return inode_get_inumber (dir_get_inode (dir));
}

/* Evaluate the inumber of file FILE. */
int  filesys_file_inumber (struct file *file)
{
  return inode_get_inumber (file_get_inode (file));
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove (const char *path) 
{
  struct dir *dir = dir_open_dirs (path);
  const char *name = dir_parse_filename (path);
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir); 
  return success;
}


/* Initializes the file system by formatting it, creating the root directory, and setting up initial directory entries. */
static void do_format(void)
{
  struct inode *root_inode;  // Pointer to the inode of the root directory.
  struct dir *root_dir;      // Pointer to the directory structure of the root.

  printf("Formatting file system...");  // Print a message indicating the start of the file system formatting process.
  free_map_create();  // Create and initialize the free map to manage free sectors on the disk.

  if (!dir_create(ROOT_DIR_SECTOR))  // Attempt to create the root directory at the predefined sector.
    PANIC("root directory creation failed");  // If creation fails, halt the system with a panic message.

  /* Open the newly created root directory's inode. */
  root_inode = inode_open(ROOT_DIR_SECTOR);
  if (root_inode == NULL)  // Check if opening the root inode failed.
    PANIC("root directory creation failed");  // Panic if the root inode cannot be opened, indicating a critical error.

  root_dir = dir_open(root_inode);  // Open the root directory from the inode to start populating it.
  
  /* Initialize the root directory by adding directory entries for "." and ".." */
  if (root_dir == NULL
      || !dir_add(root_dir, "..", ROOT_DIR_SECTOR)  // Attempt to add the parent directory entry.
      || !dir_add(root_dir, ".", ROOT_DIR_SECTOR))  // Attempt to add the current directory entry.
    PANIC("root directory creation failed");  // Panic if any of the operations fail, as the root directory is essential.

  dir_close(root_dir);  // Close the root directory structure after setup is complete.
  free_map_close();  // Close and write back the free map to the disk.
  printf("done.\n");  // Print a completion message indicating the formatting is done.
}


/* Calls file_read to read 'size' bytes from 'file' into 'buffer'. 
   Returns the number of bytes actually read. */
off_t filesys_read(struct file *file, void *buffer, off_t size)
{
  return file_read(file, buffer, size);
}


/* Calls file_write to write 'size' bytes from 'buffer' to 'file'. 
   Returns the number of bytes actually written. */
off_t filesys_write(struct file *file, const void *buffer, off_t size)
{
  return file_write(file, buffer, size);
}


/* Calls file_seek to set the current position of the file pointer in 'file' to 'position'. */
void filesys_seek(struct file *file, off_t position)
{
  file_seek(file, position);
}


/* Calls file_tell to retrieve the current position of the file pointer in 'file'. */
off_t filesys_tell(struct file *file)
{
  return file_tell(file);
}


/* Calls file_deny_write to prevent further writes to 'file'. */
void filesys_deny_write(struct file *file)
{
  file_deny_write(file);
}


/* Calls file_allow_write to allow writes to 'file' that were previously denied. */
void filesys_allow_write(struct file *file)
{
  file_allow_write(file);
}


/* Calls dir_close to close the directory 'dir' and free associated resources. */
void filesys_closedir(struct dir *dir)
{
  dir_close(dir);
}


/* Calls file_close to close 'file' and release associated resources. */
void filesys_close(struct file *file)
{
  file_close(file);
}


/* Calls file_length to get the size of 'file' in bytes. */
int filesys_filesize(struct file *file)
{
  return file_length(file);
}


/* Calls file_read_at to read 'size' bytes from 'file' starting at 'start' offset into 'buffer'. 
   Returns the number of bytes actually read. */
off_t filesys_read_at(struct file *file, void *buffer, off_t size, off_t start)
{
  return file_read_at(file, buffer, size, start);
}


/* Calls file_write_at to write 'size' bytes from 'buffer' to 'file' starting at 'start' offset.
   Returns the number of bytes actually written. */
off_t filesys_write_at(struct file *file, const void *buffer, off_t size, off_t start)
{
  return file_write_at(file, buffer, size, start);
}



#define TIME_BETWEEN_FLUSH 30000
/*
 * Wrapper struct to add next sectors to list of sectors to read in background. 
 */
struct cache_wrapper 
{
  struct list_elem elem;
  block_sector_t sector_idx;
};

/* helper for Cache table */
static struct cache_sector cache[CACHE_NUM_SECTORS];
static struct lock evict_lock; /* Lock to ensure only one instance of the clock
                                  algorithm runs*/
                                  static struct condition list_ready;
static struct list read_queue; /* List of sectors to be cached in back*/
static int evict_ptr;
static struct lock async_read_lock;

/* Private helper functions.*/
struct cache_sector *cache_acquire (block_sector_t sector_idx, bool is_metadata);
struct cache_sector *cache_lookup (block_sector_t sector_idx);
struct cache_sector* cache_load (block_sector_t sector_idx, bool is_metadata);
struct cache_sector* cache_evict (void);
void cache_disk_wr (struct cache_sector *sect, bool wait);
void cache_disk_rd (block_sector_t sector_idx, struct cache_sector *sector, 
                     bool is_metadata);
static void cache_preload (block_sector_t sector_idx);
static thread_func cache_read;
static thread_func cache_flush;


/* Asynchronously reads from disk sectors added to the read_queue and updates the cache sectors. */
static void cache_read(void *aux UNUSED)
{
  struct list temp_list;  // Temporary list to store sectors during processing.
  struct cache_wrapper *a;  // Wrapper for sectors.
  list_init(&temp_list);  // Initialize the temporary list.

  for (;;)
    {
      lock_acquire(&async_read_lock);  // Acquire lock to synchronize access to the read_queue.
      /* Wait until there are sectors to process. */
      while (list_empty(&read_queue))
        cond_wait(&list_ready, &async_read_lock);

      /* Move sectors from the shared list to a private list to minimize locked duration. */
      while (!list_empty(&read_queue))
        list_push_front(&temp_list, list_pop_back(&read_queue));

      lock_release(&async_read_lock);  // Release lock after moving sectors to private list.

      /* Process each sector in the private list. */
      while (!list_empty(&temp_list))
        {
          struct list_elem *e = list_pop_front(&temp_list);
          a = list_entry(e, struct cache_wrapper, elem);
          struct cache_sector *s = cache_acquire(a->sector_idx, false);  // Get the cache sector.

          lock_acquire(&s->lock);  // Lock the cache sector for processing.
          s->access_count--;  // Decrement the accessor count.
          if (s->access_count == 0)
            cond_broadcast(&s->access_wait, &s->lock);  // Notify waiting threads if no more accessors.
          lock_release(&s->lock);  // Release lock on the cache sector.
          free(a);  // Free the sector wrapper.
        }
    }
}


/* Periodically writes dirty cache sectors to disk at fixed intervals defined by TIME_BETWEEN_FLUSH. */
static void cache_flush(void *aux UNUSED)
{
  for (;;)
    {
      timer_msleep(TIME_BETWEEN_FLUSH);  // Sleep for a predefined period between flushes.

      /* Iterate over all cache sectors and write dirty ones to disk. */
      for (int i = 0; i < CACHE_NUM_SECTORS; ++i)
        {
          lock_acquire(&cache[i].lock);  // Acquire lock for each cache sector.
          cache_disk_wr(&cache[i], false);  // Write the sector to disk if it is dirty.
          lock_release(&cache[i].lock);  // Release the lock after processing.
        }
    }
}


/* Identifies and returns a cache sector to evict, ensuring exclusive access by locking the sector first. */
struct cache_sector *cache_evict()
{
  lock_acquire(&evict_lock);  // Acquire clock lock to manage eviction safely.
  int clock_start = (++evict_ptr) % CACHE_NUM_SECTORS;  // Determine starting point using clock algorithm.
  struct cache_sector *sector_cand = &cache[clock_start];  // Initial candidate for eviction.

  while (sector_cand->state != CACHE_SECTOR_RDY)  // Ensure the candidate is ready for eviction.
    {
      clock_start = (++evict_ptr) % CACHE_NUM_SECTORS;
      if (evict_ptr == clock_start)
        PANIC("No READY cache sector found to evict");  // Panic if no suitable sector found after a full cycle.
      sector_cand = &cache[clock_start];
    }

  /* Iterate until a suitable sector is found. */
  do
    {
      if (sector_cand->state == CACHE_SECTOR_RDY)
        {
          if (sector_cand->dirty_bit & ACCESSED)
            sector_cand->dirty_bit &= ~ACCESSED;
          else if (sector_cand->dirty_bit & META)
            sector_cand->dirty_bit &= ~META;
          else
            break;
        }
      sector_cand = &cache[++evict_ptr % CACHE_NUM_SECTORS];
    }
  while (evict_ptr != clock_start);

  ASSERT(sector_cand->state == CACHE_SECTOR_RDY);  // Verify the final candidate is ready.
  lock_acquire(&sector_cand->lock);  // Lock the candidate.
  sector_cand->state = CACHE_SECTOR_EVICTED;  // Mark the sector as evicted.
  while (sector_cand->access_count > 0)
    cond_wait(&sector_cand->access_wait, &sector_cand->lock);  // Wait until all accessors have finished.
  lock_release(&evict_lock);  // Release the clock lock.
  return sector_cand;  // Return the evicted sector.
}


/* Writes the contents of a cache sector to disk, ensuring exclusive access during the write operation. */
void cache_disk_wr(struct cache_sector *sect, bool wait)
{
  ASSERT(lock_held_by_current_thread(&sect->lock));  // Ensure the function is called with the sector lock held.
  if (!(sect->dirty_bit & DIRTY))
    return;  // Return immediately if the sector is not dirty.

  if (sect->state == CACHE_SECTOR_RDY || sect->state == CACHE_SECTOR_EVICTED)
    {
      enum cache_state original_state = sect->state;  // Save the original state.
      sect->state = CACHE_PENDING_WRITE;  // Mark the state as pending write.
      while (sect->access_count > 0)
        cond_wait(&sect->access_wait, &sect->lock);  // Wait for ongoing accessors to finish.

      sect->state = CACHE_WRITING_SECTOR;  // Set the state to being written.
      ASSERT(sect->sector_idx != INODE_INVALID_SECTOR);
      block_write(fs_device, sect->sector_idx, sect->buffer);  // Write the buffer to the disk.

      sect->dirty_bit &= ~DIRTY;  // Clear the dirty bit after writing.
      sect->state = original_state;  // Restore the original state.
      cond_broadcast(&sect->write_wait, &sect->lock);  // Notify any waiting threads.
    }
  else if (wait)
    {
      /* If another operation is writing the sector, wait until it finishes. */
      while (sect->state == CACHE_WRITING_SECTOR || sect->state == CACHE_PENDING_WRITE)
        cond_wait(&sect->write_wait, &sect->lock);
    }
}


/* Reads the contents of the specified sector_idx into the buffer of the provided cache sector (sect),
   updating its state and ensuring no other operations are reading it concurrently. */
void cache_disk_rd(block_sector_t sector_idx, struct cache_sector *sect, bool is_metadata)
{
  ASSERT(sect->state != CACHE_SECTOR_RDY);  // Ensure the sector is not already in a ready state.
  /* Wait until no other accessor is using this sector. */
  while (sect->access_count > 0)
    cond_wait(&sect->access_wait, &sect->lock);

  ASSERT(sect->access_count == 0);  // Verify that there are no active accessors.

  sect->state = CACHE_READING_SECTOR;  // Update the state to indicate the sector is being read.
  sect->sector_idx = sector_idx;  // Set the sector index.
  sect->dirty_bit = CLEAN;  // Mark the sector as clean (not dirty).
  sect->is_metadata = is_metadata;  // Set whether the sector contains metadata.

  ASSERT(sect->sector_idx != INODE_INVALID_SECTOR);  // Ensure a valid sector is being read.
  block_read(fs_device, sector_idx, sect->buffer);  // Perform the read operation.

  sect->state = CACHE_SECTOR_RDY;  // Mark the sector as ready for use.
  cond_broadcast(&sect->read_wait, &sect->lock);  // Notify other threads that the read is complete.
}


/* Retrieves and possibly evicts a cache sector to cache a new sector from the disk. */
struct cache_sector* cache_load(block_sector_t sector_idx, bool is_metadata)
{
  struct cache_sector *sect = cache_evict();  // Pick a sector to evict if necessary.
  cache_disk_wr(sect, true);  // Flush any changes if the sector is dirty.

  // Perform the read operation.
  cache_disk_rd(sector_idx, sect, is_metadata);
  sect->access_count++;  // Increment accessors count as this sector is now in use.
  lock_release(&sect->lock);  // Release the lock held by cache_evict.

  return sect;  // Return the cache sector that now contains the new data.
}


/* Looks up a cache sector by sector index and returns it if found and ready, otherwise returns NULL. */
struct cache_sector* cache_lookup(block_sector_t sector_idx)
{
  for (int i = 0; i < CACHE_NUM_SECTORS; ++i)
    {
      struct cache_sector *sector_cand = &cache[i];
      if (sector_cand->sector_idx == sector_idx)  // Check if the sector index matches.
        {
          // Ensure the sector is ready or being read.
          if (sector_cand->state != CACHE_SECTOR_RDY && sector_cand->state != CACHE_READING_SECTOR)
            continue;

          // Acquire the sector's lock to ensure its state remains stable.
          lock_acquire(&sector_cand->lock);
          // Check again to ensure the sector index hasn't changed.
          if (sector_cand->sector_idx == sector_idx)
            {
              ASSERT(sector_cand->state == CACHE_SECTOR_RDY);  // Verify the sector is ready.
              sector_cand->access_count++;  // Increment the number of accessors.
              lock_release(&sector_cand->lock);  // Release the lock.
              return sector_cand;  // Return the found sector.
            }
          else
            {
              // If the sector was replaced after finding it, release the lock and return NULL.
              lock_release(&sector_cand->lock);
              return NULL;
            }
        }
    }
  return NULL;  // Return NULL if no matching sector is found.
}


/* Retrieves a cache sector for the given sector index. If not in cache, the sector is read into cache. */
struct cache_sector* cache_acquire(block_sector_t sector_idx, bool is_metadata)
{
  struct cache_sector *sect = cache_lookup(sector_idx);  // Attempt to find the sector in the cache.
  if (sect == NULL)
    sect = cache_load(sector_idx, is_metadata);  // Cache the sector if not found.

  lock_acquire(&sect->lock);  // Acquire the lock to update access information.
  sect->dirty_bit |= ACCESSED;  // Mark the sector as accessed.
  if (is_metadata)
    sect->dirty_bit |= META;  // Mark as metadata if applicable.
  lock_release(&sect->lock);  // Release the lock.
  return sect;  // Return the cache sector.
}


/* Enqueues a sector for asynchronous reading to improve read performance by preloading likely needed sectors. */
static void cache_preload(block_sector_t sector_idx)
{
  if (sector_idx == INODE_INVALID_SECTOR) return;  // Do not enqueue if the sector index is invalid.

  lock_acquire(&async_read_lock);  // Acquire the lock to safely modify the read list.
  struct cache_wrapper *a = malloc(sizeof(struct cache_wrapper));  // Allocate a wrapper for the sector.
  if (a != NULL)
    {
      a->sector_idx = sector_idx;  // Set the sector index.
      list_push_back(&read_queue, &a->elem);  // Add to the list of sectors to be read ahead.
      cond_broadcast(&list_ready, &async_read_lock);  // Signal the condition variable that there's new data.
    }
  lock_release(&async_read_lock);  // Release the lock after enqueuing the sector.
}


/* Performs direct I/O operations between the disk and a buffer, handling both read and write operations. */
static void cache_direct_io(block_sector_t sector_idx, void *buffer,
                          off_t offset, off_t size, bool is_write)
{
  uint8_t *temp_buffer = malloc(BLOCK_SECTOR_SIZE);  // Allocate a temporary buffer for a full sector.
  if (temp_buffer == NULL) return;  // Exit if memory allocation fails.

  if (is_write)
  {
    if (offset == 0 && size == BLOCK_SECTOR_SIZE)
    {
      /* Directly write the entire sector from the buffer to disk if no partial write is needed. */
      block_write(fs_device, sector_idx, buffer);
    }
    else 
    {
      /* For partial writes, read the existing data into the temp_buffer buffer, modify it, and write back. */
      block_read(fs_device, sector_idx, temp_buffer);
      memcpy(temp_buffer + offset, buffer, size);
      block_write(fs_device, sector_idx, temp_buffer);
    }
  }
  else
  {
    if (offset == 0 && size == BLOCK_SECTOR_SIZE)
    {
      /* Directly read the entire sector into the buffer if no partial read is needed. */
      block_read(fs_device, sector_idx, buffer);
    }
    else 
    {
      /* For partial reads, read the full sector into the temp_buffer buffer, then copy the relevant part. */
      block_read(fs_device, sector_idx, temp_buffer);
      memcpy(buffer, temp_buffer + offset, size);
    }
  }
  free(temp_buffer);  // Free the temporary buffer.
}


/* Performs I/O operations between a cache sector and a buffer, handling both read and write operations. */
void cache_io(block_sector_t sector_idx, void *buffer, bool is_metadata,
                 off_t offset, off_t size, bool is_write)
{
  struct cache_sector *sect = cache_acquire(sector_idx, is_metadata);  // Get or create a cache sector.

  ASSERT(offset + size <= BLOCK_SECTOR_SIZE);  // Ensure the operation does not exceed sector boundaries.
  ASSERT(sect->state == CACHE_SECTOR_RDY);  // Ensure the cache sector is in a ready state.
  ASSERT(sect->sector_idx == sector_idx);  // Ensure the sector index matches.
  ASSERT(sect->access_count > 0);  // Ensure there are active accessors.

  if (!is_write)
    memcpy(buffer, sect->buffer + offset, size);  // Copy data from the cache sector to the buffer.
  else
  {
    sect->dirty_bit |= DIRTY;  // Mark the sector as dirty.
    memcpy(sect->buffer + offset, buffer, size);  // Copy data from the buffer to the cache sector.
  }

  lock_acquire(&sect->lock);  // Acquire the lock to update access counts.
  sect->access_count--;  // Decrement the number of accessors.
  if (sect->access_count == 0)
    cond_broadcast(&sect->access_wait, &sect->lock);  // Signal any waiting threads if no more accessors.
  lock_release(&sect->lock);  // Release the lock.
  return;
}


/* Wrapper function for cache_io to maintain compatibility and prepare for possible read-ahead. */
void cache_io_next(block_sector_t sector_idx, void *buffer, bool is_metadata,
                  off_t offset, off_t size, bool is_write, block_sector_t sector_next)
{
  cache_io(sector_idx, buffer, is_metadata, offset, size, is_write);  // Delegate to cache_io.
  // Potential place for calling cache_preload(sector_next) if future read-ahead logic is implemented.
}


/* Writes all dirty cache sectors to disk. */
void cache_flush_all(void)
{
  for (int i = 0; i < CACHE_NUM_SECTORS; ++i)
  {
    lock_acquire(&cache[i].lock);  // Acquire lock on each cache sector.
    cache_disk_wr(&cache[i], true);  // Write the sector to disk if it's dirty.
    lock_release(&cache[i].lock);  // Release the lock.
  }
}


/* Initializes the cache system, creating necessary structures and launching background threads. */
bool cache_init(void)
{
  evict_ptr = CACHE_NUM_SECTORS - 1;  // Initialize the clock hand for eviction policy.
  lock_init(&evict_lock);  // Initialize locks and condition variables for synchronization.
  lock_init(&async_read_lock);
  cond_init(&list_ready);
  list_init(&read_queue);  // Initialize the list for asynchronous read operations.

  for (int i = 0; i < CACHE_NUM_SECTORS; ++i)  // Initialize each cache sector.
  {
    cache[i].access_count = 0;
    cache[i].sector_idx = INODE_INVALID_SECTOR;
    cache[i].is_metadata = false;
    cache[i].dirty_bit = CLEAN;
    cache[i].state = CACHE_SECTOR_RDY;
    lock_init(&cache[i].lock);
    cond_init(&cache[i].access_wait);
    cond_init(&cache[i].read_wait);
    cond_init(&cache[i].write_wait);
  }

  // Create background threads for asynchronous read and write operations.
  if (thread_create("cache_async_read", PRI_DEFAULT, cache_read, NULL) == TID_ERROR)
    return false;
  if (thread_create("cache_async_write", PRI_DEFAULT, cache_flush, NULL) == TID_ERROR)
    return false;

  return true;  // Return true if initialization is successful.
}
