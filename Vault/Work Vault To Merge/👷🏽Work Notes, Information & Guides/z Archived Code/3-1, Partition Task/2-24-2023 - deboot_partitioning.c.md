```
Path: /home/kt/work/devices/s21plus/SM-G996B_RR_Opensource/deboot/deboot_partitioning.c

This is the deboot_partitioning.c file before introducing AI changes to the code. Specifically, AI is being used to rewrite code due to standard library functions not being available. This code doesn't work, but I wanted a backup nonetheless.

//
// Created by donalda on 1/25/2023.
//

#include "deboot_partitioning.h"

#include <linux/fs.h>
#include <linux/kern_levels.h>

#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#define BUFFER_SIZE 512 // We read/write from drive in 512 byte chunks for efficiency.

int wipe_and_verify_s21plus(void *data);

/**
 *  Experimental new code to read/write file data begins here.
 */

// Open File
struct file *file_open(const char *path, int flags, int rights) 
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());
    filp = filp_open(path, flags, rights);
    set_fs(oldfs);

    if (IS_ERR(filp)) {
        err = PTR_ERR(filp);
        return NULL;
    }

    return filp;
}

// Close a file (similar to close):
void file_close(struct file *file) 
{
    filp_close(file, NULL);
}

// Reading data from a file (similar to pread):
int file_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) 
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}   

// Writing data to a file (similar to pwrite):
int file_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size) 
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

// Syncing changes a file (similar to fsync):
int file_sync(struct file *file) 
{
    vfs_fsync(file, 0);
    return 0;
}




// Function that wipes all space on the phone beginning at 'start_offset'.
// start_offset is a byte offset to begin at.
int wipe_space(unsigned long start_offset) {
    FILE *fp = fopen("/dev/block/sda", "r+"); // open the file for reading and writing

    if (fp == NULL) {
        LOG(KERN_DEBUG, "Error opening file");
        return 1;
    }

    LOG(KERN_DEBUG, "Starting write.");

    fseek(fp, start_offset, SEEK_SET);
    char buf[BUFFER_SIZE]; // write buffer
    memset(buf, 0, BUFFER_SIZE); // fill the buffer with 0s

    while (!feof(fp)) { // while not at the end of the file
        int result = fwrite(buf, 1, BUFFER_SIZE, fp);

        if (result < BUFFER_SIZE) {
            LOG(KERN_DEBUG, "Error writing to file");
            fclose(fp);
            return 1;
        }
    }

    LOG(KERN_DEBUG, "Done successfully.");
    fclose(fp);
    return 0;
}

// Function that verifies all space is empty after 'start_offset'.
// start_offset is a byte offset to begin the search at.
int verify_free_space_is_empty(unsigned long start_offset) {
    FILE *fp = fopen("/dev/block/sda", "r+"); // open the file for reading and writing
    void *buffer;
    int counter;
    int i;

    if (fp == NULL) {
        LOG(KERN_DEBUG, "Error opening file");
        return 1;
    }

    LOG(KERN_DEBUG, "Starting read.");

    // Initialize buffer.
    buffer = malloc(BUFFER_SIZE);

    // Skip to starting point.
    fseek(fp, start_offset, SEEK_SET);

    // Keep reading file until nothing is left to be read.
    while (fread(buffer, 1, BUFFER_SIZE, fp) != 0) {
        for (i = 0; i < BUFFER_SIZE; i++) {
            if (((unsigned char*)buffer)[i] == 0) {
                ((unsigned char*)buffer)[i] = '.';
            } else {
                LOG(KERN_DEBUG, "Found non-empty line. Aborting.");
                LOG(KERN_DEBUG, "Counter: %d - Buffer: %s", counter, buffer);
                fclose(fp);
                return 1;
            }
        }

        counter++;
    }

    LOG(KERN_DEBUG, "Read complete.");
    fclose(fp);
    return 0;
}

// Function that wipes all space on on s21 plus from 132 billionth byte, then verifies that that space is empty.
int wipe_and_verify_s21plus(void *data) {
	LOG(KERN_DEBUG, "!!! PERFORMING WIPE AND VERIFY FOR S21+ CODE. !!!");

    wipe_space(132000000000);
    verify_free_space_is_empty(132000000000);

	LOG(KERN_DEBUG, "!!! DONE PERFORMING WIPE AND VERIFY FOR S21+ CODE. !!!");

    return 0;
}

/**
 * Sample start_offset values:
 * - Pixel 4 Flame:          40000000000  (40b = 32b + 8b)
 * - s21+:                   132000000000 (132b = 128b + 4b)
 * - s21+ developer testing: 255000000000 (255b)
*/

```