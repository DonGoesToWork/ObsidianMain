```
//
// Created by donalda on 1/25/2023.
//

#include "deboot_partitioning.h"
#include "deboot_lib.h"

#include <linux/fs.h>
#include <linux/kern_levels.h>
#include <linux/types.h>
#include <linux/gfp.h>
#include <linux/buffer_head.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/stat.h> // S_IRWXUGO
#include <linux/syscalls.h> // sys_chmod

#define BUFFER_SIZE 512 // We read/write from drive in 512 byte chunks for efficiency.

int deboot_partitioning_stages(void *data);
int wipe_s21(void *data);
int verify_s21(void *data);
int write_s21(void *data);

// Function that wipes all space on the phone beginning at 'start_offset'.
// start_offset is a byte offset to begin at.
int wipe_space(unsigned long start_offset) {
    struct file *filp = NULL;
    int err = 0;
    loff_t pos = start_offset;
    size_t remaining = 0;
    char *buf = kzalloc(BUFFER_SIZE, GFP_KERNEL); // write buffer

	GET_FS(old_fs)

    printk(KERN_DEBUG "!!!!!!~ Start Operation ~!!!!!!");

    filp = filp_open("/dev/block/sda", O_RDWR, 0);

    if (!filp || IS_ERR(filp)) {
        printk(KERN_DEBUG "Error opening file - Error: %d", PTR_ERR(filp));
        SET_FS(old_fs)
        return 0;
    }

    printk(KERN_DEBUG "Starting write.");

    if (!buf) {
        err = -ENOMEM;
        goto out;
    }

    do {
        remaining = kernel_write(filp, buf, BUFFER_SIZE, &pos);

        if (remaining < BUFFER_SIZE && remaining > 0) {
            memset(buf, 0, BUFFER_SIZE);
            remaining = kernel_write(filp, buf, BUFFER_SIZE - remaining, &pos);
        }

        if (remaining < 0) {
            printk(KERN_DEBUG "Error writing to file");
            err = remaining;
            goto out_free_buf;
        }
    } while (remaining > 0);

    printk(KERN_DEBUG "Done successfully.");

out_free_buf:
    kfree(buf);
out:
    filp_close(filp, NULL);
    SET_FS(old_fs)
    return 0;
}

// Function that verifies all space is empty after 'start_offset'.
// start_offset is a byte offset to begin the search at.
int verify_free_space_is_empty(unsigned long start_offset) {
    struct file *filp = NULL;
    int err = 0;
    void *buffer = NULL;
    int counter = 0;
    int i = 0;
    loff_t pos = start_offset;

	GET_FS(old_fs)

    printk(KERN_DEBUG "!!!!!!~ Start Operation ~!!!!!!");
    
    filp = filp_open("/dev/block/sda", O_RDWR, 0);

    if (!filp || IS_ERR(filp)) {
        // PTR_ERR(filp)
        printk(KERN_DEBUG "Error opening file");
        SET_FS(old_fs)
        return 0;
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
    SET_FS(old_fs)
    return 0;
}

int write_to_file(unsigned long start_offset, const char *data, size_t size) {
    struct file *filp;
    loff_t pos;
    ssize_t ret;

	GET_FS(old_fs)

    printk(KERN_DEBUG "!!!!!!~ Start Operation ~!!!!!!");

    filp = filp_open("/dev/block/sda", O_WRONLY|O_LARGEFILE, 0644);

    if (IS_ERR(filp)) {
        printk(KERN_DEBUG, "Error opening file");
        SET_FS(old_fs)
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

    SET_FS(old_fs)
    filp_close(filp, NULL);
    return 0;
}

int wipe_s21(void *data) {
    wipe_space(132000000000);
    return 0;
}

int verify_s21(void *data) {
    verify_free_space_is_empty(132000000000);
    return 0;
}

int write_s21(void *data) {
    write_to_file(132000000000, "hi there", 8);
    return 0;
}

int deboot_partitioning_stages(void *data) {
	ADD_STAGE_FUNC(wipe_s21);
	ADD_STAGE_FUNC(verify_s21);
	ADD_STAGE_FUNC(write_s21);

	return 0;
}

/**
// Function that wipes all space on on s21 plus from 132 billionth byte, then verifies that that space is empty.
int wipe_and_verify_s21plus(void *data) {
    unsigned long so = 132000000000;
    //int status;

    // Log that we're starting operations.
	printk(KERN_DEBUG "!!!!!!~~ PERFORMING WIPE AND VERIFY FOR S21+ CODE. ~~!!!!!!");

    // Wipe space on drive.

    // Verify space is empty.

    // Write to the free space 8 bytes of data.
    // 

    // Verify space is empty again. (It won't be, should see an error).
    // verify_free_space_is_empty(so);

    // Log that we're done.
	printk(KERN_DEBUG "!!!!!! DONE PERFORMING WIPE AND VERIFY FOR S21+ CODE. !!!!!!");

    // Always return 0.
    return 0;
}
*/

/**
 * Sample start_offset values:
 * - Pixel 4 Flame:          40000000000  (40b = 32b + 8b)
 * - s21+:                   132000000000 (132b = 128b + 4b)
 * - s21+ developer testing: 255000000000 (255b)
*/


/**

Old permission change code.

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

```

