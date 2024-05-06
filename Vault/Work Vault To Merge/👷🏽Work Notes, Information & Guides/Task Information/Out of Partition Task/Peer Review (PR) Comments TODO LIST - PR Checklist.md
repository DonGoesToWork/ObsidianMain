# Tim's Comments:

- Replace instances of SAFE_LOG with LOG. +
- Make utility functions static. +
- Sentinal Values.
- Don't write strings directly.
- Change BUFFER_SIZE  to 4096
- do_file_copy_literal() -> Can fail to read/write all data -> Add TODO for now
- Add labels:
	- This is missing a __label for deboot_universal_file_copy_stages.  It is also missing a prototype so the non-jstage version of the stage can be called from deboot_parameters and a __label for that.

There are a few things that really must be fixed here before we can merge this. The most important things are to make all of these functions that are not the actual stage static and to get the __label's added for the functions in the header.

# Satish's Comments

* Function/Logic changes
	* Under discussion.
- Null check on char fields.
	- First
	- Second
- Get rid of O_CREAT on read file open.
- Free up copy_data
- get_file_size () error needs handling
- I would recommend an enum type with descriptive names for buffer_set_method instead of 0,1,2 for readability
- I would recommend checking return status and do error handling on all kmalloc/kzalloc calls
	- Retry kfree on various fields like all the kmalloc'd fields and copy_data.