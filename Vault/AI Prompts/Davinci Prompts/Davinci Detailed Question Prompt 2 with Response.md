Create a C program that performs a specific task. The task is for the C program to identify the space on a phone that is not partitioned (referred to as 'free space' when using a tool like parted) of my phone's partitioned '/dev/block/sda' drive in order to be capable of reading and writing to that free space. The solution needs to be able to support writing potentially several megabytes of data to the phone, so it needs to find the maximum amount of free space available on the phone and support accessing non-contiguous free space. The code should be concise and optimized with no excessive comments or unnneccessary additions.

I already have Android Studio installed with Android NDK and cmake. I already have a project created that is capable of creating a Native C App to run on the phone. I already understand how to run C programs on my phone. I only need help with actually writing the C code for identifying non-partitioned space and reading and writing bytes there.

The solution is:

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define BLOCK_SIZE 512
#define PARTITION_TABLE_OFFSET 0x1BE
#define PARTITION_TABLE_SIZE   0x40
#define PARTITION_ENTRY_SIZE   0x10
#define PARTITION_ENTRY_OFFSET 0x8
#define PARTITION_TYPE_OFFSET  0x4
#define PARTITION_TYPE_NONE    0x00

int get_free_space(char *dev_name);

int main(int argc, char *argv[])
{
    int free_space = get_free_space("/dev/block/sda");
    printf("Free space on %s: %d bytes\n", dev_name, free_space);
    return 0;
}

 int get_free_space(char *dev_name)
{
	int dev_fd = open(dev_name, O_RDONLY);
	
    if (dev_fd == -1)
    {
        printf("Error: Failed to open device: %s\n", dev_name);
        return -1;
    }
    
	char partition_table[PARTITION_TABLE_SIZE];
    
	off_t offset = lseek(dev_fd, PARTITION_TABLE_OFFSET, SEEK_SET);
	
    if (offset == -1)
    {
        printf("Error: Failed to seek to partition table offset: %lu\n", PARTITION_TABLE_OFFSET);
        return -1;
    }
    
	ssize_t num_read = read(dev_fd, partition_table, PARTITION_TABLE_SIZE);
	
    if (num_read != PARTITION_TABLE_SIZE)
    {
        printf("Error: Failed to read partition table: %lu\n", PARTITION_TABLE_SIZE);
        return -1;
    }
    
	int num_partitions = PARTITION_TABLE_SIZE / PARTITION_ENTRY_SIZE;
    
	int last_partition = -1;
	
    for (int i = 0; i < num_partitions; i++)
    {
	        unsigned char *partition_type = (unsigned char*)(partition_table + (i * PARTITION_ENTRY_SIZE) + PARTITION_TYPE_OFFSET);
        if (*partition_type != PARTITION_TYPE_NONE)
        {
	   last_partition = i;
        }
    }
    
	int free_space = 0;
	
    if (last_partition != -1)
    {
	        unsigned char *last_partition_entry = (unsigned char*)(partition_table + (last_partition * PARTITION_ENTRY_SIZE));
        
	        int *last_partition_size = (int*)(last_partition_entry + PARTITION_ENTRY_OFFSET);
			int last_partition_end_block = *last_partition_size + *last_partition_size;
        
	        int total_blocks = lseek(dev_fd, 0, SEEK_END) / BLOCK_SIZE;
			int free_blocks = total_blocks - last_partition_end_block;
			free_space = free_blocks * BLOCK_SIZE;
    }
    
	close(dev_fd);
    
	return free_space;
}