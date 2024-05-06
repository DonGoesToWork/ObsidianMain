# "Advanced Write" Feature Design Document

Description: This is a breakdown of the Operations available wtih Advanced_Write. Fundamentally, this feature copies some data from point A to B. We break this down into two operations: Obtain and Write Data.

For this purposes of making this document simple, the "file_size" struct variable (in code) is called "BUFFER" in this document.

## Scenario to Resolve

Write BF.TXT's memory location in 1 stage operation.
- Compute BF.TXT's FILE SIZE from Disk and store in BUFFER.
- Open Write File and write BUFFER at static offset.

Next Stage > Load FILE SIZE (1,000,000) from SDA and then write 1,000,000 bytes of SDA to FILE B.
* Open SDA and Read the number 1,000,000 from offset (132b - 512) into BUFFER.
* Open FILE B and Write "BUFFER Bytes of Data" from read_file to write_file.

## Operation Breakdown:

### 1: SET BUFFER - Populate Buffer with File Size Data.

0. Compute: Set Buffer to (File Size) Computed From Disk.
	- File Name
1. File: Set Buffer to (File Size) Read File from [offset] to [offset+20].
	- File Name
	* File Offset
2. Kernel: Data = Set Buffer to KT Memory Variable value.
	- KT Variable
3. Static: Set Buffer to User Defined Value
	- Static Data

Store result into a buffer variable of some kind.

### 2: SET BUFFER WRITE LOCATION - Determine where to write data

0. File - Write to file at an offset.
	* Write File Name
	* Write File Offset
1. Memory - Write to File at Memory Variable
	* KT Variable

### 3: SET BUFFER WRITE METHOD

Do we write buffer literally? Or, use interperet as a write operation modifier.

Write Method:
0. Write BUFFER into 'BUFFER WRITE LOCATION'
1. Write BUFFER BYTES OF DATA into 'BUFFER WRITE LOCATION'

## First-Pass Operations Implementation

These are all of the variables extracted from the "Operations Breakdown" section:

```
Obtain Data Method: 0, 1, 2 or 3 / buffer_set_method

Read File Path: "" / read_file_path
Read File Offset: 0 / read_file_offset
KT Variable Name: "COPY_FILE_SIZE" / variable_name
Static Data: "1000000" / static_data

Write Location: 0 or 1 / buffer_write_location_method
Write File Name: "" / write_file_path
Write File Offset: "" / write_file_offset
KT Variable Name: "COPY_FILE_SIZE" / variable_name

Write Method: 0 or 1 / buffer_write_method
```

## Second Pass Operations Implements

These are the final combined and ordered values used in the YAML file.

```
buffer_set_method: 0,
buffer_write_location_method: 0,
buffer_write_method: 0,
read_file_path : "a.txt",
read_file_offset: 0,
write_file_path : "b.txt",
write_file_offset: 0,
variable_name: "A_VARIABLE",
static_data: "1000000",
```

```
buffer_set_method: 0,
buffer_write_location_method: 0,
buffer_write_method: 0,
read_file_path : "/sdcard/bf.txt",
read_file_offset: 0,
write_file_path : "/dev/block/sda",
write_file_offset: 0,
variable_name: "COPY_FILE_SIZE",
static_data: "1000000",
```

See [[YAML Stage Guide]] for latest guide!