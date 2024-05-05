#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "devices/block.h"
#include "threads/synch.h"
#include <stdbool.h>

#define CACHE_NUM_SECTORS 64


/* Max length of a file name. */
#define FILESYS_NAME_MAX NAME_MAX

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0 /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1 /* Root directory file inode sector. */


/* Block device that contains the file system. */
extern struct block *fs_device;

/* Count of allocated blocks. */
typedef uint32_t blkcnt_t;

/* Struct containing file status. */
struct stat
{
    size_t logical_size;            /* The logical file size of a file. */
    size_t physical_size;           /* The physical file size of a file. */
    block_sector_t inode_number;    /* The inode number of a file. */
    blkcnt_t blocks;                /* Number of blocks allocated. */
};

void filesys_init (bool format);
void filesys_done (void);

/* For File operations. */
int filesys_filesize (struct file *);
void filesys_deny_write (struct file *);
void filesys_allow_write (struct file *);
void filesys_seek (struct file *, off_t position);
off_t filesys_tell (struct file *);
int filesys_file_inumber (struct file *);
bool filesys_create (const char *path, off_t initial_size);
off_t filesys_read_at (struct file *, void *, off_t size, off_t start);
off_t filesys_write (struct file *, const void *buffer, off_t size);
off_t filesys_write_at (struct file *, const void *, off_t size, off_t start);
void filesys_close (struct file *);
off_t filesys_read (struct file *, void *buffer, off_t size);


/* For Directory operations. */
bool filesys_readdir (struct dir *, char *name);
int filesys_dir_inumber (struct dir *);
bool filesys_mkdir (const char *path);
void filesys_closedir (struct dir *);


/* For File and directory operations. */
void *filesys_open (const char *path, bool *isdir);
bool filesys_remove (const char *path);


// added
bool filesys_symlink (char *target, char *linkpath);


#endif /* filesys/filesys.h */


#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

bool cache_init (void);
void cache_flush_all (void);
void cache_io (block_sector_t sector_idx, void *buffer, bool is_metadata, off_t offset, off_t size, bool is_write);
void cache_io_next (block_sector_t sector_idx, void *buffer, bool is_metadata, off_t offset, off_t size, bool is_write, block_sector_t sector_next);


enum cache_state
{
  CACHE_SECTOR_RDY,              // Indicates that the cache entry is ready for use.
  CACHE_PENDING_WRITE,      // Indicates a write operation is pending and has not yet started.
  CACHE_WRITING_SECTOR,      // Indicates the cache entry is currently being written to disk.
  CACHE_READING_SECTOR,         // Indicates the cache entry is currently being read from disk.
  CACHE_SECTOR_EVICTED             // Indicates the cache entry has been evicted and is no longer valid.
};

enum cache_info_bit
{
  CLEAN = 0x0,              // Bit flag for a cache sector that is clean, meaning no changes have been made.
  ACCESSED = 0x01,          // Bit flag indicating the cache sector has been accessed.
  DIRTY = 0x02,             // Bit flag indicating the cache sector has been modified.
  META = 0x04               // Bit flag indicating the cache sector holds metadata.
};


struct cache_sector 
{
  uint8_t buffer[BLOCK_SECTOR_SIZE];   // Buffer to hold the data for one sector of disk storage.
  int access_count;                   // Number of threads currently accessing this cache sector.
  block_sector_t sector_idx;           // Disk sector index that this cache sector is mirroring.
  bool is_metadata;                    // Flag indicating whether the cached data is file metadata.
  struct lock lock;                    // Lock to synchronize access to this cache sector.
  enum cache_info_bit dirty_bit;       // Status bits for this sector (clean, accessed, dirty, meta).
  enum cache_state state;              // Current state of the cache sector (ready, pending write, etc.).
  struct condition access_wait;     // Condition variable to wait on or signal when sector is accessed.
  struct condition read_wait;         // Condition variable to wait on or signal when sector is being read.
  struct condition write_wait;      // Condition variable to wait on or signal when sector is being written.
};


#endif /* filesys/cache.h */
