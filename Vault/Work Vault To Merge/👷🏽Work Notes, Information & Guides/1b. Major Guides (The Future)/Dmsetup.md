#### DMSetup Example Usage

Push rom.enc: `adb push ~/work/devices/s21plus/workdir/s21plus/gsi-11/rom/rom.enc /sdcard`

#### Link(s)

DM Guide Website: https://wiki.gentoo.org/wiki/Device-mapper

#### My DMSETUP

Ideal Command:
dmsetup create ucopy --table '0 846916608 crypt aes-xts-plain64 abcd 257812500 /dev/block/sda 0 1'

846916608 (rom.enc size) = 1654134 * 512
132000000000 (read offset) = 32226562.5 * 4096 = 257812500 * 512
136000000000 (read offset) = 33203125 * 4096

For YAML:

default: aes-xts-plain64 %key 5000      %romdisk 0
mine:    aes-xts-plain64 %key 257812500 /dev/block/sda 0 1

Upon Run:

> Log from deboot:

Expanding aes-xts-plain64 abc 132000000000 /dev/block/sda 0 1 to aes-xts-plain64 abc 132000000000 /dev/block/sda 0 1

gap in table


GPT Test:

sudo dmsetup create encrypted_drive --table "0 1953125 crypt aes-xts-plain64 <encryption_key> 1000000 /dev/loop0 0"


#### Dmsetup explanation

```
Can you explain the arguments for this command?

dmsetup create test-crypt --table '0 1953125 crypt aes-xts-plain64 babebabebabebabebabebabebabebabebabebabebabebabebabebabebabebabe 0 /dev/loop0 0 1 allow_discards'

Certainly! This command is used to create a dm-crypt device mapper target named "test-crypt". Here's a breakdown of the arguments:

    "dmsetup" is the command-line tool used to manage device mapper devices.
    "create" is the sub-command used to create a new device mapper target.
    "test-crypt" is the name of the new device mapper target being created.
    "--table" is an option used to specify the table of the device mapper target being created.
    
    "'0 1953125 crypt aes-xts-plain64 babebabebabebabebabebabebabebabebabebabebabebabebabebabebabebabe 0 /dev/loop0 0 1 allow_discards'" is the table for the device mapper target being created. The table is made up of several fields separated by spaces. Here's what each field means:
    
        "0": the starting block of the device mapper target.
        "1953125": the length of the device mapper target in blocks.
        "crypt": the type of target being created (in this case, a dm-crypt target).
        "aes-xts-plain64": the encryption algorithm being used.
        "babebabebabebabebabebabebabebabebabebabebabebabebabebabebabebabe": the encryption key being used (in this example, it's a 256-bit key represented in hexadecimal format).
        "0": the offset of the source device.
        "/dev/loop0": the source device being encrypted.
        "0": the starting block of the source device.
        "1": the number of active targets (in this case, just one).
        "allow_discards": allows the target device to issue TRIM or UNMAP commands to the underlying storage device, which can improve performance in certain situations.

Overall, this command is creating a dm-crypt device mapper target using the AES-XTS encryption algorithm with a 256-bit key, and encrypting the data on /dev/loop0. The resulting device mapper target will be named "test-crypt" and can be used like any other block device (e.g., /dev/mapper/test-crypt).
```

#### Something Unknown

sudo dmsetup create mycrypt --table "0 $(blockdev --getsize /dev/sdb1) crypt aes-xts-plain64 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0 /dev/sdb1 0"

- Store our file size in a variable
- Store contents into drive at location /dev/block/sda
- Encrypt portion of /dev/block/sda using dmsetup create mycrypt
