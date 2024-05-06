# Table of Contents
- [[#Introduction to Rooting:|Introduction to Rooting:]]
- [[#Using Parted to Resize Partition (The ‘Good’ Stuff):|Using Parted to Resize Partition (The ‘Good’ Stuff):]]
  
***
Partitioning Android Notes
Written For Samsung Galaxy S10
By: Donald Abdullah-Robinson
***

# Introduction to Rooting:

tl;dr: Follow the Magisk Guide. This guide exists to supplament it with additional tips.

## Links:

Magisk Install Guide : https://topjohnwu.github.io/Magisk/install.html
Parted Download Link: https://forum.xda-developers.com/t/how-to-boot-from-sd-card-successfully-on-qmobile-z8-with-bricked-dead-emmc.3712171/
ADB can be found inside of the Dev Repo > File Explorer > Navigation Bar > 10.40.49.51 on Rocky (I think) connected network.

## Paths:

ADB Folder Directory: ```cd C:\ProgramData\platform-tools```
Location of Internal Storage for Samsung Galaxy S10: ```/storage/self/primary```

* Tips:

Don’t use .\adb.exe root. Use .\adb.exe shell, then ‘su’ command.

Unlock bootloader:

- ??? - Was done for me already. Will need to be figured out for oneself.

Magisk Tips:

- After flashing magisk stuff, your phone should restart with no app installed, etc., due to being wiped. Simply reinstall magisk to the phone (command on next line), accept prompt to do additional installation steps, which will restart phone again, and boom. Should be done!

Install Magisk:

.\adb.exe install C:\Users\donalda\Downloads\Magisk-v25.2.apk

Remount file system as r/w to transfer files:

$ adb shell
$ su
\# mount -o rw,remount /

Transfering to phone:

Use Windows File explorer to transfer files to phone. Then, while within the adb shell, use cp command to move files around as needed.

Run Parted on Linux

(How to get past read-write mounting error too)

- Copy it over through Windows File explorer to Internal Storage.
- Enter adb shell’s admin mode with command ‘su’.
- Mount system as r/w with ‘mount -o rw,remount /’
- Copy parted to root with ‘cp parted /’
- Start parted with ‘./parted’

S10 Hotkeys:

Download Mode (WORKS):
Hold Volume Down + Bixby, then plug in USB cable. Phone will turn on.

Recovery Mode: (WORKS)
Hold down Volume Up + Bixby + Power Buttons. Once little android icon man appears, let go.
Video: https://www.youtube.com/watch?v=ER5W8J159os

General Rooting S10 Advice:

Most steps from guides work. But, pitfalls happen around making sure OEM mode is enabled. Connect to WIFI at least once to make sure that OEM mode is properly enabled, even if you see it as enabled and greyed in developer settings. If ODIN freezes on USERDATA step, it is likely because of this issue.

# Using Parted to Resize Partition (The ‘Good’ Stuff):

Once you have parted moved to ‘/’ in your adb shell, you can run the parted command on a given drive of your system to see information about it.

Extremely Useful Links:
(Probably worth it to read them like 100 times until you perfectly understand their contents before even THINKING of running any parted commands.)

https://www.hovatek.com/forum/thread-32750.html
https://forum.xda-developers.com/t/tutorial-how-to-resize-system-partition-on-galaxy-s3-for-larger-gapps.4218903/
https://forum.xda-developers.com/t/how-to-resizing-partitions-universal-mode.2662382/

Run parted on the drive you want to resize. Then, run the resize part command. The 4 commands I use to resize are:

./parted /dev/block/sda
resizepart 31
64GB
y

WORKS!

Note: The command ‘p’ can be used inside of parted to view the drives that you wish to resize. USE IT!
Note: The command ‘help’ shows help. ‘help [command]’ shows command specific help