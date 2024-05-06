> Start

## copy_file_with_offset_jstage

Copy's some data from point A to some File B. This stage's algorithm is fundamentally: Acquire Data then Write Data using Some Technique:

1.) Populate a 'file_size' buffer with the length of some file.
2.) Choose how 'file_size' will be used.
3.) Choose where to write data.
4.) If we are writing a file size, choose the format to write the file size in.
5.) Write obtained data from 'Step 1' to 'Step 3' using 'Step 2'.

For the purposes of this feature, to keep it short and simple, references to 'file_size' are replaced with the term 'buffer'. You may assume that the two terms may be used interchangeably in most cases.

- hook_fn : (stage reference) *copy_file_with_offset_jstage,
- hook_data : 
```yaml
    { (object)
		buffer_set_method: (long) See below for details,
		buffer_write_location_method: (long) See below for details,
		buffer_write_method: (long) See below for details,
		buffer_write_format: (long) See below for details,
        read_file_path : (string) path to read file, commonly referred to as File A
        read_file_size_offset : (long) offset to file size data contained in read file.
        read_file_data_offset : (long) offset to file data contained in read file.
        write_file_path : (string) path to write file, commonly referred to as File B
        write_file_offset : (long) offset to file data contained in write file.
        variable_name : (string) name of stack variable
        static_data : (string) manual File Size entry
    }
```

### Additional Field Information

The 'buffer_[...]' methods are used to determine what should be copied, to where and how. The following parameters that must be set depend on these parameter values and are described below.

buffer_set_method:

0 or \*BUFFER_SET_METHOD_COMPUTE: Set Code Buffer to Actual File Size Computed From Disk.
     - read_file_path
1 or \*BUFFER_SET_METHOD_FILE: Set Code Buffer to Actual File Size read from File from [read_file_size_offset] to [read_file_size_offset + 20].
     - read_file_path
     - read_file_size_offset
2 or \*BUFFER_SET_METHOD_KERNEL. Kernel: Set Code Buffer to Actual File Size read from Kernel Stack.
     - variable_name
3 or \*BUFFER_SET_METHOD_STATIC. Static: Set Code Buffer to Actual File Size from a User Defined Value.
     - static_data

buffer_write_location_method:

0 or \*BUFFER_WRITE_LOCATION_FILE: Write to file at an offset.
     - write_file_path
     - write_file_offset
1 or \*BUFFER_WRITE_LOCATION_MEMORY: Write to the Kernel Stack.
     - variable_name

buffer_write_method: Do we write the buffer literally? Or, do we interpret it as a write operation modifier?

0 or \*BUFFER_WRITE_METHOD_EXACT: Write Buffer 'FILE SIZE' into 'BUFFER WRITE LOCATION'
     - N/A (Has no parameter dependencies)
1 or \*BUFFER_WRITE_METHOD_DATA_AMOUNT: Write 'FILE SIZE BYTES OF DATA' into 'BUFFER WRITE LOCATION'
     - read_file_path
     - read_file_data_offset

buffer_write_format: Used when writing file size to a file to control format.

0 or \*BUFFER_WRITE_FORMAT_NORMAL: Write Buffer 'FILE SIZE' as binary.
     - N/A (Has no parameter dependencies)
1 or \*BUFFER_WRITE_FORMAT_BINARY: Write 'FILE SIZE BYTES OF DATA' as regular text.
     - N/A (Has no parameter dependencies)

### Important Tips:

- We don't support writing 'x' bytes of data to the stack.
	- This is parameter combination, buffer_write_method: \*BUFFER_WRITE_METHOD_DATA_AMOUNT and buffer_write_location_method: \*BUFFER_WRITE_LOCATION_MEMORY
- The buffer_write_format setting is only checked when writing a file size to a file.
	- This is the parameter combination: buffer_write_method: \*BUFFER_WRITE_METHOD_EXACT and buffer_write_location_method: BUFFER_WRITE_LOCATION_FILE
- The parameter 'buffer_set_method' with value \*BUFFER_WRITE_METHOD_EXACT always assumes that that the file size to be read is stored in binary and will convert it to a regular string. There is no read_file_format setting to control this behavior at this time.
	- It is recommended toset buffer_write_format to BUFFER_WRITE_FORMAT_BINARY when using buffer_set_method: \*BUFFER_WRITE_METHOD_EXACT
- It may be easier to determine desired parameter combinations in real situations by reviewing the code, figuring out which path you desire and then copying the parameters that are set to achieve that path.

[back to top](#stages-module)

> End

#  My Custom Notes:

> Sample read_file_data_offset for various devices:

- Pixel 4 Flame:          40000000000  (40b = 32b + 8b)
- s21+:                   132000000000 (132b = 128b + 4b)
- s21+ developer testing: 255000000000 (255b)

- ! You should always verify device sizes before choosing an offset.

### Examples:

## Newest Implementation




## My most recent tested example for Prior Implementation:

```yaml
	# DAR START
	{ # Ex 1: w1 - w3
		name : "Compute ROM Size and Write to SDA",
		args : [
			"/system/bin/sh",
			"w1"
		],
		hook_data : {
			buffer_set_method: *BUFFER_SET_METHOD_COMPUTE,
			buffer_write_location_method: *BUFFER_WRITE_LOCATION_FILE,
			buffer_write_method: *BUFFER_WRITE_METHOD_EXACT,
			buffer_write_format: *BUFFER_WRITE_FORMAT_BINARY,
			read_file_path : "/sdcard/rom.enc",
			read_file_size_offset: 0,
			read_file_data_offset: 0,
			write_file_path : "/dev/block/sda",
			write_file_offset: 131999999488,
			variable_name: "",
			static_data: "",
		},
		hook_fn : *universal_file_copy_jstage,
		clear_param1 : true,
	},
	{
		name : "Store contents of ROM into SDA",
		args : [
			"/system/bin/sh",
			"w2"
		],
		hook_data : {
			buffer_set_method: *BUFFER_SET_METHOD_COMPUTE,
			buffer_write_location_method: *BUFFER_WRITE_LOCATION_FILE,
			buffer_write_method: *BUFFER_WRITE_METHOD_DATA_AMOUNT,
			buffer_write_format: *BUFFER_WRITE_FORMAT_NORMAL,
			read_file_path : "/sdcard/rom.enc",
			read_file_size_offset: 0,
			read_file_data_offset: 0,
			write_file_path : "/dev/block/sda",
			write_file_offset: 132000000000,
			variable_name: "",
			static_data: "",
		},
		hook_fn : *universal_file_copy_jstage,
		clear_param1 : true,
	},
	{
		name : "Get File A Size from File and Write Size Amount of Data to File B",
		args : [
			"/system/bin/sh",
			"w3"
		],
		hook_data : {
			buffer_set_method: *BUFFER_SET_METHOD_FILE,
			buffer_write_location_method: *BUFFER_WRITE_LOCATION_FILE,
			buffer_write_method: *BUFFER_WRITE_METHOD_DATA_AMOUNT,
			buffer_write_format: *BUFFER_WRITE_FORMAT_NORMAL,
			read_file_path : "/dev/block/sda",
			read_file_size_offset: 131999999488,
			read_file_data_offset: 132000000000,
			write_file_path : "/sdcard/rom.enc.copy",
			write_file_offset: 0,
			variable_name: "",
			static_data: "",
		},
		hook_fn : *universal_file_copy_jstage,
		clear_param1 : true,
	},
	{ # Ex 2: w4 - w6
		name : "Compute ROM Size and Write to STACK",
		args : [
			"/system/bin/sh",
			"w4"
		],
		hook_data : {
			buffer_set_method: *BUFFER_SET_METHOD_COMPUTE,
			buffer_write_location_method: *BUFFER_WRITE_LOCATION_MEMORY,
			buffer_write_method: *BUFFER_WRITE_METHOD_EXACT,
			buffer_write_format: *BUFFER_WRITE_FORMAT_NORMAL,
			read_file_path : "/sdcard/rom.enc",
			read_file_size_offset: 0,
			read_file_data_offset: 0,
			write_file_path : "",
			write_file_offset: 0,
			variable_name: "VAR_UWRITE",
			static_data: "",
		},
		hook_fn : *universal_file_copy_jstage,
		clear_param1 : true,
	},
	{
		name : "Get Rom Size From Stack and Write Stack Amount of Data to SDA",
		args : [
			"/system/bin/sh",
			"w5"
		],
		hook_data : {
			buffer_set_method: *BUFFER_SET_METHOD_KERNEL,
			buffer_write_location_method: *BUFFER_WRITE_LOCATION_FILE,
			buffer_write_method: *BUFFER_WRITE_METHOD_DATA_AMOUNT,
			buffer_write_format: *BUFFER_WRITE_FORMAT_NORMAL,
			read_file_path : "/sdcard/rom.enc",
			read_file_size_offset: 0,
			read_file_data_offset: 0,
			write_file_path : "/dev/block/sda",
			write_file_offset: 132000000000,
			variable_name: "VAR_UWRITE",
			static_data: "",
		},
		hook_fn : *universal_file_copy_jstage,
		clear_param1 : true,
	},
	{
		name : "Get File A Size from File and Write Size Amount of Data to File B",
		args : [
			"/system/bin/sh",
			"w6"
		],
		hook_data : {
			buffer_set_method: *BUFFER_SET_METHOD_KERNEL,
			buffer_write_location_method: *BUFFER_WRITE_LOCATION_FILE,
			buffer_write_method: *BUFFER_WRITE_METHOD_DATA_AMOUNT,
			buffer_write_format: *BUFFER_WRITE_FORMAT_NORMAL,
			read_file_path : "/dev/block/sda",
			read_file_size_offset: 0,
			read_file_data_offset: 132000000000,
			write_file_path : "/sdcard/rom.enc.copy",
			write_file_offset: 0,
			variable_name: "VAR_UWRITE",
			static_data: "",
		},
		hook_fn : *universal_file_copy_jstage,
		clear_param1 : true,
	},
	# DAR END
```

## What I used for DMSETUP Ticket Testing. (Bit out of Date Now)

```yaml
        # Put File 1 Size into Stack and Contents into File 2
        {
            name : "Compute and Write File A Size into STACK.",
            args : [
                "/system/bin/sh",
                "w1"
            ],
            hook_data : {
                buffer_set_method: 0, # auto-compute file size
                buffer_write_location_method: 1, # write to stack
                buffer_write_method: 0, # write file size literally
                read_file_path : "/sdcard/rom.enc",
                read_file_size_offset: 0,
                read_file_data_offset: 0,
                write_file_path : "/dev/block/sda",
                write_file_offset: 0,
                variable_name: "VAR_UWRITE",
                static_data: "",
            },
            hook_fn : *universal_file_copy_jstage,
            clear_param1 : true,
        },
        { # Alternative, Write Contents Literally Using Header
            name : "Get File A Size from Stack and Write to File B Literally",
            args : [
                "/system/bin/sh",
                "s2b"
            ],
            hook_data : {
                buffer_set_method: 2, # read file size from stack
                buffer_write_location_method: 0, # write to file
                buffer_write_method: 0, # write buffer literally
                read_file_path : "",
                read_file_size_offset: 0,
                read_file_data_offset: 0,
                write_file_path : "/sdcard/bf.s2b.txt",
                write_file_offset: 0,
                variable_name: "VAR_UWRITE",
                static_data: "",
            },
            hook_fn : *universal_file_copy_jstage,
            clear_param1 : true,
        },
        # Device Mapper Stage (DAR)
        {
            name : "dar_ioctl",
            args : [
                "/system/bin/sh",
                "w2"
            ],
            hook_fn : *for_each_jstage,
            hook_data : {
                fn : *dm_ioctl_jstage,
                data : [
                    {
                        path : "/dev/device-mapper", 
                        cmd : *DEBOOT_DM_CREATE,
                        name : "rom",
                    },
                    {
                        path : "/dev/device-mapper",
                        cmd : *DEBOOT_DM_TABLE_LOAD,
                        name : "rom",
                        targets : [
                            {
                                sector_start : 0,
                                length : *VAR_UWRITE, # *VAR_UWRITE,
                                target_type : "crypt",
                                data : "aes-xts-plain64 1415d35ee751040e95b82f05cbeeb6bd6818678d8c4f7246e82408bab67875f4 5000 8:0 257812500"
                            }
                        ],
                    },
                    {
                        path : "/dev/device-mapper",
                        cmd : *DEBOOT_DM_SUSPEND,
                        name : "rom",
                    }
                ]
            }
        },
        # END DM Stage.

```

# Generic YAML for records:

```yaml
{
	name : "sh su",
	args : [
	   "/system/bin/sh",
		"su"
	],
	hook_fn : $deboot_elevate_privileges,
	clear_param1 : true
},
{
	name : "sh zip finder stage",
	args : [
	   "/system/bin/sh",
		"w1"
	],
	hook_fn : $zip_last_file_offset_jstage,
	hook_data : {
		path : "/sdcard/test.bin",
		var : "zip_offset"
	},
	clear_param1 : true
},
```