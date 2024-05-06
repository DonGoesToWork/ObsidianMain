# Get Magisk Installed and Phone Rooted.

1. Get phone model out of phone. See below for notes.
2. Get boot.img and vbmeta.img and put somewhere

Download relevant factory image here: https://developers.google.com/android/images
Unzip the boot.img and vbmeta.img to a folder. Then, push them:

`adb push “C:\Users\donalda\Desktop\Pixel 4 Files\flame-rp1a.201105.002\boot.img”  /sdcard
``adb push “C:\Users\donalda\Desktop\Pixel 4 Files\flame-rp1a.201105.002\vbmeta.img”  /sdcard

New! Custom Linux Kernel Boot Image: ``~/pixelSources/workdir/flame/aosp-11

`adb push ~/pixelSources/workdir/flame/aosp-11/boot.img /sdcard

3. Install Magisk

`adb.exe install C:\Users\donalda\Downloads\Magisk-v25.2.apk`

- Run Magisk Installation by opening app in phone and installing boot image.

4. Pull Magisk Image

adb pull /sdcard/Download/magisk_patched-[WHATEVER].img C:\temp
ex: adb pull /sdcard/Download/.img C:\temp

5. Flash new image

adb reboot bootloader
fastboot flash boot C:\temp\magisk_patched.img

`fastboot flash vbmeta --slot=all --disable-verity --disable-verification C:\temp\vbmeta.img

vbmeta original loc: ``/home/kt/pixelSources/workdir/flame/aosp-11/vbmeta_disabled.img

`fastboot flash vbmeta --slot=all --disable-verity --disable-verification C:\temp\vbmeta_disabled.img

6. Test Root:

`mount -o rw,remount /

If that fails, you have issues! RIP ME.


## 1. Full Notes For #1

About Phone > Regulatory Labels > Search google for model #
Determined Using Pixel 4 Flame (XL = Coral)

- I correlated that information with information in share’s to determine factory image to download:

\\10.40.49.51\Builds\00_Dependencies\Android_ROMs_Stock

- Concluded I’m using flame-rp1a.201105.002-factory-351561c6.zip

## Side Notes:

cd C:\ProgramData\platform-tools

# Manually Modifying Binary

Guide:
https://harrisonsand.com/posts/patching-adb-root/

ADB Shell:

su
cd /data/adb/magisk
./magiskboot unpack /sdcard/Download/magisk_patched-25200_65J2O.img
./magiskboot cpio ramdisk.cpio extract

TODO: Figure out how to get adbd version from sbin ?
cp /data/adb/magisk/system/bin/adbd /sdcard

adb pull /sdcard/adbd C:\Temp

* Edit File with Ghidra
* Can look for: minijail_change_gid

adb push C:\Temp\adbd /sdcard/

cp /sdcard/adbd /data/adb/magisk/system/bin/

./magiskboot cpio ramdisk.cpio "add 750 sbin/adbd /data/adb/magisk/system/bin/adbd"
./magiskboot repack /sdcard/Download/magisk_patched-25200_65J2O.img

Powershell:
adb reboot bootloader
adb push “C:\Users\donalda\Desktop\Pixel 4 Files\flame-rp1a.201105.002\boot.img” /sdcard
Building AOSP

Directory I’m using with android AOSP:
~/pixelSources/android-11.0.0_r27

fastboot flash vendor "C:\Users\donalda\Desktop\Pixel 4 Flame Files\vendor.img"

Root:
/home/kt/pixelSources/android-11.0.0_r27

fastboot flash boot out/target/product/flame/boot.img
fastboot flash vbmeta out/target/product/flame/vbmeta.img
fastboot flash dtbo out/target/product/flame/dtbo.img
fastboot flash recovery out/target/product/flame/recovery.img
fastboot flash system out/target/product/flame/system.img
fastboot flash vendor out/target/product/flame/vendor.img
fastboot flash userdata out/target/product/flame/userdata.img
fastboot flash product out/target/product/flame/product.img
fastboot flash vbmeta_system out/target/product/flame/vbmeta_system.img
fastboot flash system_ext out/target/product/flame/system_ext.img

Get parted running
Use the Magisk Module to add parted to the phone!

https://forum.xda-developers.com/t/module-debugging-modules-adb-root-selinux-permissive-enable-eng.4050041/

Then:

adb shell
cd /sbin/.magisk/modules/disk/system/bin
./parted /dev/block/sda
resizepart 15
31.9GB
yes

Command to view free space:
print free


# Unzipping Image Files

simg2img "/mnt/c/Users/donalda/Desktop/Pixel 4 Files/flame-rp1a.201105.002/image-flame-rp1a.201105.002/system.img" "/mnt/c/Users/donalda/Desktop/Pixel 4 Files/flame-rp1a.201105.002/image-flame-rp1a.201105.002/unzipped/system.raw.img"

img2simg "/mnt/c/Users/donalda/Desktop/Pixel 4 Files/flame-rp1a.201105.002/image-flame-rp1a.201105.002/unzipped/system.raw.img" "/mnt/c/Users/donalda/Desktop/Pixel 4 Files/flame-rp1a.201105.002/image-flame-rp1a.201105.002/system2.img"

/mnt/c/Users/donalda/Desktop/Pixel 4 Files/flame-rp1a.201105.002/image-flame-rp1a.201105.002/unzipped/

resize2fs -p "${raw_image}" ${size}s
resize2fs -p "/mnt/c/Users/donalda/Desktop/Pixel 4 Files/flame-rp1a.201105.002/image-flame-rp1a.201105.002/unzipped/system.raw.img" 31G

# Running Parted in WSL:

cd "/mnt/c/Users/donalda/Desktop/Desktop Files/Software/"

parted "/mnt/c/Users/donalda/Desktop/Pixel 4 Files/flame-rp1a.201105.002/image-flame-rp1a.201105.002/unzipped/system.raw.img"

Mount Image:

mount -t ext4 -o ro,loop "/mnt/c/Users/donalda/Desktop/Pixel 4 Files/flame-rp1a.201105.002/image-flame-rp1a.201105.002/unzipped/system.raw.img" "/mnt/c/Users/donalda/Desktop/Pixel 4 Files/flame-rp1a.201105.002/image-flame-rp1a.201105.002/unzipped/temp/"

Unmount Image (Note the lack of N):
 
umount "/mnt/c/Users/donalda/Desktop/Pixel 4 Files/flame-rp1a.201105.002/image-flame-rp1a.201105.002/unzipped/system.raw.img"

# Useful Random Links:

For the android logging:
https://stackoverflow.com/questions/10274920/how-to-get-printf-messages-written-in-ndk-application


# Building Parted Notes:

https://ftp.gnu.org/gnu/parted/

sudo apt-get install uuid-dev
sudo apt-get install libdevmapper-dev
sudo apt-get install libreadline-dev

Helper apt-get search command:

apt-cache search device-mapper

GNU Parted Source: https://github.com/Ahren-Li/android-external-parted-3.2

# Random Information

Selinux bypass instructions:

ECHO set_contextSYSTEM,[FILENAME] > /DEV/DEBOOT
just cat /dev/deboot
can use ‘get_state’ to see status of everything

echo get_state > /dev/deboot

cat /dev/deboot

echo > /dev/deboot get_state

cat /dev/deboot
echo > /dev/deboot get_state
dd if=/dev/deboot

Getting output: echo "get_state" > /dev/deboot

#### View devices:
cat /proc/devices

# Random Notes

apk is in:

`/data/app/~~FfSYlTwMXhJdgnexQfA8QQ==/com.example.mycapp2-Dmsj55nQSXobOsDx9J3TZw==`

set context of these files to get past permission issue:

echo set_context /data/data/com.example.mycapp2,u:object_r:system_file:s0 > /dev/deboot
echo set_context /data/data/com.example.mycapp2/cache,u:object_r:system_file:s0 > /dev/deboot
echo set_context /data/data/com.example.mycapp2/code_cache,u:object_r:system_file:s0 > /dev/deboot
chmod 777 dev/block/sda

# Building parted from scratch:

sudo apt-get install libtool
sudo apt-get install autopoint gperf

sudo apt-get install texinfo
sudo apt-get install libuuid1

/.boostrap
./configure
OLD NOTES (OUTDATED):

adb push "C:\temp\parted" /sdcard

Then should be able to chmod 0777 it and run. But, getting error with root perms first. See below

* Root Issues

Try vbmeta_disabled.img

vbmeta_disabled_R.tar from \\10.40.49.51\Software\KT Developer Baseline Software\Flashing Utilities
Result: Phone simply doesn’t boot

Try avbtool:

cd /home/kt/pixelSources/unpatched-android-folder/android-11.0.0_r27/external/avb/
./avbtool make_vbmeta_image --flags 2 --padding_size 4096
^ command extracted from C:\devel\kt-dev\dev\scripts\make_vbmeta_disabled.sh
Doesn’t work though.

Zipping and Unzipping Parted:

tar -zcvf parted.tar.gz /home/kt/temp/parted
tar -xvf parted.tar.gz

Fastboot:

.\fastboot flash recovery C:\Users\donalda\Desktop\twrp\flame.img

# New DMSETUP Device should appear in:

ls -l by-name
or 
ls -l /dev/block
