

THIS GUIDE IS TEMPORARILY UNFINISHED DUE TO MULTI-QUEUE ISSUE TAKING PRECEDENCE! REVISIT LATER.

0. Git Setup

In a powershell window, use ‘ssh-keygen -t rsa’
Cat the stated file from command output to get your key. Sample: ‘cat /home/kt/.ssh/id_rsa.pub’
Add the output to Gitlab page.

1. Create directories

mkdir ~/samsungS10
mkdir ~/samsungS10/logs
mkdir ~/samsungS10/workdir
mkdir ~/samsungS10/lineage-17.1

2. Download/Clone the Lineage 17.1 source repo and setup manifests:

repo init -u git://github.com/LineageOS/android.git -b lineage-17.1
mkdir .repo/local_manifests
vim .repo/local_manifests/roomservice.xml 

Contents:
  <?xml version="1.0" encoding="UTF-8"?>
  <manifest>
      <project name="whatawurst/android_device_samsung_beyond1lte" path="device/samsung/beyond1lte" />
      <project name="whatawurst/android_device_samsung_exynos9820-common" path="device/samsung/exynos9820-common" remote="github" />
      <project name="whatawurst/android_kernel_samsung_exynos9820" path="kernel/samsung/exynos9820" remote="github" />
      <project name="whatawurst/android_vendor_samsung_beyond1lte" path="vendor/samsung/beyond1lte" remote="github" />
      <project name="LineageOS/android_device_samsung_slsi_sepolicy" path="device/samsung_slsi/sepolicy" remote="github" />
  <project name="LineageOS/android_hardware_samsung" path="hardware/samsung" remote="github" />
  </manifest>

repo sync (note: this command can take like 4 hours to complete)
cd device/samsung/beyond1lte
./extract-files.sh
3. Get Kernel

Reference Link: https://opensource.samsung.com/uploadSearch?searchValue=G973FXXU7CTF1

- Copy SM-G973F_QQ_Opensource.zip from share to your computer somewhere.
- Unzip to ~/samsungS10

git status
git add *
git commit -m “initial commit” -a

4. Apply patches from kt repo

In directory: C:\devel\kt-dev\dev\scripts

.\apply_kernel_patch.py rom=lineage-17.1 ~/samsung10/SM-G973F_QQ_Opensource ~/work/kt/patch/kernel

5. Get stock firmware

Reference Link: https://www.sammobile.com/samsung/galaxy-s10/./
  	firmware/SM-G973F/H3G/download/G973FXXU8CTG4/360079/

- Copy from share: G973FXXU8CTG4_G973FCKH8CTG4_H3G.zip
- Unzip to ~/samsungS10

6. Run the setup_env.sh script to set up the build environment for S10

Within wsl, go to: /mnt/c/devel/kt-dev/dev/scripts$

source "/mnt/c/devel/kt-dev/dev/scripts/setup_env.sh" --device s10 --rom lineage-17 --ktsrc ~/work/kt --rootdev ~/samsungS10 --buildtype eng

source "/home/kt/work/kt/dev/scripts/setup_env.sh" --device s10 --rom lineage-17 --ktsrc ~/work/kt --rootdev ~/samsungS10 --buildtype eng




7. Build custom kernel

Within wsl, go to: /mnt/c/devel/kt-dev/dev/script
Then run:

build_kernel.sh

Note: No arguments are required, command recognizes the environment variables set up in the step above). On successful completion, look for the kernel image file under arch/arm64/boot/Image

Personally, I had to do a few other steps to address errors. But, please note that you MIGHT NOT SEE some of these IF you properly setup your GIT repo. (This is what I was advised by the ALMIGHTTY Chris.) 

Make not found

apt install make

“+ pushd /root/samsungS10/SM-G973F_QQ_Opensource
/mnt/c/devel/kt-dev/dev/scripts/build_kernel.sh: line 38: pushd: /root/samsungS10/SM-G973F_QQ_Opensource: No such file or directory”

cp -r /home/kt/samsungS10/SM-G973F_QQ_Opensource /root/samsungS10

“+ ln -s /usr/bin/python2 /root/samsungS10/workdir/s10/lineage-17/python
ln: failed to create symbolic link '/root/samsungS10/workdir/s10/lineage-17/python': No such file or directory”

mkdir -p ~/samsungS10/workdir/s10/lineage-17

/bin/sh: 1: gcc: not found

apt install gcc

***
*** Configuration file ".config" not found!
***
*** Please run some configurator (e.g. "make oldconfig" or
*** "make menuconfig" or "make xconfig").
***
make[2]: *** [scripts/kconfig/Makefile:40: silentoldconfig] Error 1
make[1]: *** [Makefile:554: silentoldconfig] Error 2
make: *** No rule to make target 'include/config/auto.conf', needed by 'include/config/kernel.release'.  Stop.

Fatal error to resolve.

(DID NOT GET ANY OF THESE NEXT STEPS TO WORK)

8. Next Steps 

- Make the vbmeta_disabled.img
- run make_vbmeta_disabled.sh

- Make boot image with the custom kernel, that can be flashed to device

  - run make_bootimg.sh (no arguments required, 
  	it uses environment variables already set up 
	in setup_env.sh step above)

- Flash the boot image to the device ( run flash_boot.sh script)

- Run make_rom.sh to create the 2nd ROM tgz file 

- Run create_encrypted_files.sh script to create encrypted archives.
  
  If using the streaming decryption (most newer devices should be, then use):
  make_rom_context.sh
  create_encrypted_files.sh -E mkenc_rom.sh 10000 7373727273

  For the older setups, use:
  Example: create_encrypted_files.sh 10000 7272737372

- Run pushFiles.sh script to push encrypted archives in the right spot on target device