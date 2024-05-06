```
/**
 * Working, albeit old code to check space.
 * Main problem is that I have to manually set 'j' to some amount of space to check.
 * 'read_space()' instead dynamically reads to the end of the file.
 * Could go into deboot_partitioning.c
 */
void check_space() {
    int fd;
    void *buffer;
    int i;
    int j;
    int counter = 0;
    bool foundSomething = false;
    int foundCounter = 0;

    LOGD("Variables initialized.");

    fd = open("/dev/block/sda", O_RDONLY);

    if (fd < 0) {
        perror("Failed to open device");
        exit(1);
    }

    buffer = malloc(BLOCK_SIZE);

    LOGD("Let's go.");

    lseek(fd, STARTING_POINT, SEEK_CUR);

    for (j = 0; j < 10000000; j++) {
        read(fd, buffer, BLOCK_SIZE);
        char str[BLOCK_SIZE];
        foundSomething = false;

        for (i = 0; i < BLOCK_SIZE; i++) {
            if (((unsigned char*)buffer)[i] == 0) {
                ((unsigned char*)buffer)[i] = '.';
            } else if (!foundSomething) {
                foundSomething = true;
                foundCounter++;
            }
        }

        if (foundSomething)
            LOGD("Output for %d - %s.", counter, buffer);

        counter++;
    }

    LOGD("Done.");

    free(buffer);
    close(fd);
}

```