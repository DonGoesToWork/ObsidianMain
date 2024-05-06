

```

int generate_random_number(int a, int b) {
    int range = b - a + 1;
    int result;

    get_random_bytes(&result, sizeof(result));

    result = result % range;

    if (result < 0) {
        result += range;
    }

    return a + result;
}

static int do_file_copy_literal(int i, int amount_to_read, void *buffer, struct ufc_stage_data *op, struct ufc_copy_data *copy_data) {
    int new_read_size = 0; // todo remove
    int new_write_size = 0; // todo remove
    loff_t start_read_pos = op->read_file_data_offset;
    loff_t start_write_pos = op->write_file_offset;

	// Sample Chaos
	
    // todo remove / 1% of the time, reduce read_size by a random amount between 1 and read_size - 1. (If 1, we don't reduce.)
    if (generate_random_number(1, 2000) == 1 && read_size > 2) {
        new_read_size = generate_random_number(1, (read_size - 1));
        printk("---> Reducing read size. %i / %d to %d", i, read_size, new_read_size);
        read_size = new_read_size;
        op->read_file_data_offset = start_read_pos + read_size;
    }

    // 1% of the time, reduce write_size by a random amount between 1 and write_size - 1. (If 1, we don't reduce.)
    if (generate_random_number(1, 2000) == 1 && write_size > 2) {
        new_write_size = generate_random_number(1, (write_size - 1));
        printk("---> Reducing write size. %i / %d to %d", i, write_size, new_write_size);
        write_size = new_write_size;
        op->write_file_offset = start_write_pos + write_size;
    }

	// Extreme Chaos
	
	if (read_size > 2) {
        new_read_size = generate_random_number(1, (read_size - 1));
        // printk("---> Reducing read size. %i / %d to %d", i, read_size, new_read_size);
        read_size = new_read_size;
        op->read_file_data_offset = start_read_pos + read_size;
    }

	if (write_size > 2) {
        new_write_size = generate_random_number(1, (write_size - 1));
        // printk("---> Reducing write size. %i / %d to %d", i, write_size, new_write_size);
        write_size = new_write_size;
        op->write_file_offset = start_write_pos + write_size;
    }
    
}

```