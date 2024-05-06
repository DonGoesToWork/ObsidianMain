```


//
// Created by donalda on 1/25/2023.
//

#include "deboot_partitioning.h"

#include <linux/fs.h>
#include <linux/kern_levels.h>
#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/buffer_head.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/stat.h> // S_IRWXUGO
#include <linux/syscalls.h> // sys_chmod, ksys_open

#define BUFFER_SIZE 512 // We read/write from drive in 512 byte chunks for efficiency.

int wipe_and_verify_s21plus(void *data);

// Function that wipes all space on the phone beginning at 'start_offset'.
// start_offset is a byte offset to begin at.
int wipe_space(unsigned long start_offset) {
    int fd;
    int err = 0;
    unsigned long pos = start_offset;
    size_t remaining = 0;
    char *buf = kzalloc(BUFFER_SIZE, GFP_KERNEL); // write buffer
    unsigned long end_offset = 256000000000;

    fd = ksys_open("/dev/block/sda", O_RDWR, 0);

    if (fd < 0) {
        printk(KERN_DEBUG "Error opening file");
        return -1;
    }

    printk(KERN_DEBUG "Starting write.");

    if (!buf) {
        err = -ENOMEM;
        goto out;
    }

    // Advance to start_offset.

    while (start_offset < end_offset) {
        // First iteration moves to start_offset, future ierations advance by BUFFER_SIZE (512).
        if (pos == start_offset) {
            ksys_lseek(fd, start_offset, 0);
            pos += start_offset;
        } else {
            ksys_lseek(fd, BUFFER_SIZE, 0);
            pos += BUFFER_SIZE;
        }

        // Write at position.
        remaining = ksys_write(fd, buf, BUFFER_SIZE);

        // Handle partial writes case at end.
        if (remaining < BUFFER_SIZE) {
            ksys_lseek(fd, remaining, 0);
            ksys_write(fd, buf, remaining);
            printk(KERN_DEBUG "PARTIAL WRITE %lu", remaining);
            goto out_free_buf;
        }
    }

    printk(KERN_DEBUG "Wipe completed successfully.");

out_free_buf:
    kfree(buf);
out:
    ksys_close(fd);
    return -1;
}

/**
// Function that verifies all space is empty after 'start_offset'.
// start_offset is a byte offset to begin the search at.
int verify_free_space_is_empty(unsigned long start_offset) {
    struct file *filp = NULL;
    int err = 0;
    void *buffer = NULL;
    int counter = 0;
    int i = 0;
    loff_t pos = start_offset;

    filp = ksys_open("/dev/block/sda", O_RDWR, 0);

    if (!filp || IS_ERR(filp)) {
        printk(KERN_DEBUG "Error opening file");
        return PTR_ERR(filp);
    }

    printk(KERN_DEBUG "Starting read.");

    // Initialize buffer.
    buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);

    if (!buffer) {
        err = -ENOMEM;
        goto out;
    }

    // Skip to starting point.
    vfs_llseek(filp, pos, SEEK_SET);

    // Keep reading file until nothing is left to be read.
    while (kernel_read(filp, buffer, BUFFER_SIZE, &pos) != 0) {
        for (i = 0; i < BUFFER_SIZE; i++) {
            if (((unsigned char*)buffer)[i] == 0) {
                ((unsigned char*)buffer)[i] = '.';
            } else {
                printk(KERN_DEBUG "Found non-empty line. Aborting.");
                printk(KERN_DEBUG "Counter: %d - Buffer: %s", counter, (char*)buffer);
                err = 1;
                goto out_free_buf;
            }
        }
        counter++;
    }

    printk(KERN_DEBUG "Read complete.");

out_free_buf:
    kfree(buffer);
out:
    filp_close(filp, NULL);
    return err;
}

int write_to_file(unsigned long start_offset, const char *data, size_t size) {
    struct file *filp;
    loff_t pos;
    ssize_t ret;

    filp = ksys_open("/dev/block/sda", O_WRONLY|O_LARGEFILE, 0644);

    if (IS_ERR(filp)) {
        printk(KERN_DEBUG, "Error opening file");
        return PTR_ERR(filp);
    }

    pos = start_offset;
    ret = vfs_llseek(filp, pos, SEEK_SET);

    if (ret < 0) {
        printk(KERN_DEBUG, "Error seeking to offset");
        filp_close(filp, NULL);
        return ret;
    }

    ret = vfs_write(filp, data, size, &pos);

    if (ret < 0) {
        printk(KERN_DEBUG, "Error writing to file");
        filp_close(filp, NULL);
        return ret;
    }

    filp_close(filp, NULL);
    return ret;
}
*/

// Function that wipes all space on on s21 plus from 132 billionth byte, then verifies that that space is empty.
int wipe_and_verify_s21plus(void *data) {
    unsigned long so = 132000000000;
    // int status;

    // Log that we're starting operations.
	printk(KERN_DEBUG "!!!!!!~~ PERFORMING WIPE AND VERIFY FOR S21+ CODE. ~~!!!!!!");

    /**
    status = ksys_chmod("/dev/block/sda", S_IRWXUGO);

    printk(KERN_DEBUG "~~Permission change status %d", status);

    // Attempt to set drive as rwx for all users.
    if (status != 0) {
        // On fail, log failure and always return 0.
	    printk(KERN_DEBUG "!!!!!! FAILED TO SET PERMISSIONS %d", status);
        return 0;
    } else {
        printk(KERN_DEBUG "~~Set status change %d", status);
    }
    */

    // Wipe space on drive.
    wipe_space(so);

    // Verify space is empty.
    // verify_free_space_is_empty(so);

    // Write to the free space 8 bytes of data.
    // write_to_file(so, "hi there", 8);

    // Verify space is empty again. (It won't be, should see an error).
    // verify_free_space_is_empty(so);

    // Log that we're done.
	printk(KERN_DEBUG "!!!!!! DONE PERFORMING WIPE AND VERIFY FOR S21+ CODE. !!!!!!");

    // Always return 0.
    return 0;
}

/**
 * Sample start_offset values:
 * - Pixel 4 Flame:          40000000000  (40b = 32b + 8b)
 * - s21+:                   132000000000 (132b = 128b + 4b)
 * - s21+ developer testing: 255000000000 (255b)
*/

```