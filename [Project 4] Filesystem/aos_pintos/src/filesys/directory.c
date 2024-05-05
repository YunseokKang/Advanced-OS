#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/malloc.h"

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
    struct lock *lock;                  /* Shared lock across directories for inode. */
  };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

/* Creates a directory with space for no entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create (block_sector_t sector)
{
  return inode_create (sector, 0, true);
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *dir_open(struct inode *inode) 
{
    // Allocate memory for directory structure
    struct dir *dir = calloc(1, sizeof(struct dir));
    bool isValidInode = inode != NULL && inode_isdir(inode);

    // Check if inode is valid and memory allocation was successful
    if (isValidInode && dir != NULL) {
        // Set up directory structure
        dir->inode = inode;
        dir->lock = inode_dir_lock(dir->inode);
        dir->pos = 2 * sizeof(struct dir_entry); // Position to skip '.' and '..' entries
        return dir;
    } else {
        // Clean up in case of failure
        if (inode != NULL) {
            inode_close(inode);
        }
        if (dir != NULL) {
            free(dir);
        }
        return NULL;
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens a directory from a given FILEPATH, 
which can be either an absolute path or relative to the current working directory, 
and returns the directory pointer or NULL if an error occurs. */
struct dir *dir_open_dirs(const char *filepath) {
    ASSERT(filepath != NULL); // Ensure the filepath is not NULL.

    struct dir *parent_dir;
    struct inode *curr_inode;
    const char *next_slash;
    char curr_name[NAME_MAX + 1];
    size_t curr_name_len;

    // Determine if the path is absolute and initialize parent directory accordingly.
    if (filepath[0] == '/') {
        parent_dir = dir_open_root(); // Open the root directory.
        filepath++; // Move past the initial forward slash.
    } else {
        parent_dir = dir_reopen(thread_current()->cwd); // Reopen current working directory.
    }

    if (parent_dir == NULL) {
        goto cleanup; // Handle NULL parent directory early.
    }

    // Iterate through each segment of the filepath.
    while ((next_slash = strchr(filepath, '/')) != NULL) {
        if (*(next_slash + 1) == '\0') {
            goto cleanup; // Handle case with trailing slash.
        }

        // Manage segments of consecutive slashes.
        if (next_slash == filepath) {
            filepath++; // Skip over the consecutive slashes.
            continue;
        }

        curr_name_len = next_slash - filepath; // Calculate the length of the current segment.
        if (curr_name_len > NAME_MAX) {
            goto cleanup; // Exit if segment length exceeds maximum allowed.
        }

        // Extract the current segment name.
        strlcpy(curr_name, filepath, curr_name_len + 1);
        // Attempt to locate the inode associated with the current directory name.
        lock_acquire(parent_dir->lock);
        if (!dir_lookup(parent_dir, curr_name, &curr_inode)) {
            lock_release(parent_dir->lock);
            goto cleanup; // Fail if the directory entry is not found.
        }
        lock_release(parent_dir->lock);
        dir_close(parent_dir); // Close the current directory.

        parent_dir = dir_open(curr_inode); // Open the directory for the next segment.
        if (parent_dir == NULL) {
            goto cleanup; // Handle failure to open the next directory.
        }
        filepath = next_slash + 1; // Proceed to the next segment.
    }
    return parent_dir; // Return the directory pointer of the final segment.

cleanup:
    if (parent_dir != NULL && lock_held_by_current_thread(parent_dir->lock)) {
        lock_release(parent_dir->lock); // Release lock if still held.
    }
    dir_close(parent_dir); // Clean up and close the directory.
    return NULL; // Return NULL due to failure to process the filepath.
}



/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close (struct dir *dir) 
{
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
}

/* Returns the inode encapsulated by DIR. */
struct inode * dir_get_inode (struct dir *dir) { return dir->inode; }

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        return true;
      }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup (const struct dir *dir, const char *name, struct inode **inode) 
{
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;

  return *inode != NULL;
}

/* Returns a pointer to the filename component in FILEPATH, starting after the last slash. */
const char * dir_parse_filename (const char *filepath)
{
  ASSERT (filepath != NULL);  // Ensure the filepath is not NULL.

  const char *file_name;
  
  file_name = strrchr (filepath, '/');
  if (file_name == NULL)
    return filepath;  /* return FILEPATH. */
  return file_name + 1;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  lock_acquire (dir->lock);
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  if (lock_held_by_current_thread (dir->lock))
    lock_release (dir->lock);
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove (struct dir *dir, const char *name) 
{
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  //added
  struct dir *dir_removed = NULL;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  lock_acquire (dir->lock);
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode and fail on error. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL)
    goto done;

  /* Verify if the inode corresponds to a directory before proceeding. */
  if (inode_isdir (inode))
    {
      /* Open the directory; exit the function if this operation fails. */
      dir_removed = dir_open (inode);
      if (dir_removed == NULL)
        goto done;
      /* Ensure the directory is not in use by others and is actually empty. */
      if ((inode_open_count (inode) > 1)
          || !dir_empty (dir_removed))
        goto done;
    }

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  if (lock_held_by_current_thread (dir->lock))
    lock_release (dir->lock);
  if (dir_removed != NULL)
    dir_close (dir_removed);
  else if (inode != NULL)
    inode_close (inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  struct dir_entry e;

  lock_acquire (dir->lock);
  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, NAME_MAX + 1);
          lock_release (dir->lock);
          return true;
        } 
    }
  lock_release (dir->lock);
  return false;
}

/* Returns true if the DIR contains no entries other than the special directories '.' and '..', 
and false if it contains additional entries. */
bool dir_empty(struct dir *dir) {
    ASSERT(dir != NULL); // Ensure directory pointer is not NULL.

    struct dir_entry entry; // Renamed from 'e' to 'entry' for clarity.
    size_t offset = 0; // Renamed from 'ofs' to 'offset' for better readability.

    lock_acquire(dir->lock); // Acquire lock on directory.
    while (inode_read_at(dir->inode, &entry, sizeof(entry), offset) == sizeof(entry)) {
        // Verify if the entry is in use and is not a special directory ('.' or '..')
        if (entry.in_use && strcmp(entry.name, ".") != 0 && strcmp(entry.name, "..") != 0) {
            lock_release(dir->lock); // Release lock before returning.
            return false; // Found a valid entry, directory is not empty.
        }
        offset += sizeof(entry); // Move to the next directory entry.
    }
    lock_release(dir->lock); // Release lock after loop completion.
    return true; // No valid entries found, directory is empty.
}
