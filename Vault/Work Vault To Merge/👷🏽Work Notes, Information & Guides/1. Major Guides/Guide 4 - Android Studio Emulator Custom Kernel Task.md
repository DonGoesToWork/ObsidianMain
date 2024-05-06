Starting Information

Recommended Device to Emulate According to Tim:
Pixel 6 Pro, Sv2, Android 12L, x86_64, API 32.

Device’s Kernel:

![[Pasted image 20230222163414.png]]

As Text:
5.10.66

Source: https://cdn.kernel.org/pub/linux/kernel/v5.x/

WSL Temp Folder: \\wsl$\Ubuntu-22.04\home\kt\temp

Variety of Data Points and Commands:

Template for running emulator:
./emulator -verbose @AVD_NAME -kernel /path/to/repo/goldfish/arch/x86/boot/bzImage -show-kernel -qemu — enable-kvm

How I run emulator:
cd /mnt/c/Users/donalda/AppData/Local/Android/Sdk/emulator
./emulator -verbose P6 -kernel ~/goldfish/arch/x86/boot/bzImage -show-kernel -qemu — enable-kvm

^ That command actually didn’t work though, so I used this which crashes still but works better:
.\emulator -avd P6 -kernel C:\temp\bzImage -show-kernel

Note: I created bzImage by downloading the linux source kernel and then grabbing it from the /arch/x86/boot/bzImage

This task is incomplete. 3 other people are working on it, so I ABORTED.