General Workflow to Make Kernel Changes:

1. Start up VS Code within Kernel Source Area. Commands:

cd ~/pixelSources/android-msm-coral-4.14-android11/private/msm-google
code .

Variant: ~/pixelSources/unpatched-android-folder/android-msm-coral-4.14-android11-no-patch/private/msm-google

2. Open up WSL terminal in VS Code
3. Run setup.env. Command:

source ~/work/kt/dev/scripts/setup_env.sh --device flame --rom aosp-11 --ktsrc ~/work/kt --rootdev ~/pixelSources --buildtype eng

Variant for vanilla kernel:

source ~/work/kt/dev/scripts/setup_env.sh --device flame --rom aosp-11 --ktsrc ~/work/kt --rootdev ~/pixelSources/unpatched-android-folder --buildtype eng

4. Run the following sequence of commands while making sure to check for errors.
apply_kernel_patch.py <- This copies our files from our KT source repo to the KT Dev repo.

clear ; build_kernel.sh
make_bootimg.sh
flash_boot.sh

7. Validate changes by going into adb, dev folder and then checking for mybuffer.
 
cd C:\ProgramData\platform-tools
.\adb.exe shell
cd /dev/block
	May need to do a ‘sh [command]’ in here. (Like ‘sh expose’)
ls | grep mybuffer

8: Finish

make_kernel_patch.py


Code Tips:

Kernel Patching Other Details:

apply_kernel_patch.py 
build_kernel.sh
build_kernel.sh -dev (-dev makes it not make/clean)

Relevant code line:
blk_mq_init_sq_queue

In terminal, use commands:
- ???

Can apply patch with:
apply_kernel_patch.py

Misc:

- When building kernel, add a -dev 

Building KT for ANDROID 10!!! (OLD):

source ~/work/kt/dev/scripts/setup_env.sh --device coral --rom aosp-10 --ktsrc ~/work/kt --rootdev ~/pixelSources --buildtype eng
apply_kernel_patch.py
build_kernel.sh


What Comes After:

Image Folder:

\\wsl$\Ubuntu-22.04\home\kt\pixelSources\android-msm-coral-4.14-android10-qpr1\out\android-msm-floral-4.14\dist

Resume work paths:

\\wsl$\Ubuntu-22.04\home\kt\linux_source\linux-5.4.219\arch\alpha\boot\main.c
\\wsl$\Ubuntu-22.04\home\kt\work\kt\dev\scripts\README.md
kt@TRILAPTOP04:~/work/kt/dev/scripts$
\\10.40.49.51\Builds\00_Dependencies\Android_ROMs_Stock
\\wsl$\Ubuntu-22.04\home\kt\pixel
C:\Users\donalda\Desktop\Work Notes
~/work/kt/dev/scripts
C:\Users\All Users\platform-tools> .\fastboot.exe devices

Android 11 Kernel Build (and KT in optional steps after):

cd ~/work/kt

source ~/work/kt/dev/scripts/setup_env.sh --device flame --rom aosp-11 --ktsrc ~/work/kt --rootdev ~/pixelSources --buildtype eng

apply_kernel_patch.py
build_kernel.sh

(
merged:
apply_kernel_patch.py ; build_kernel.sh
)

Following steps are optional if I want to build android source for kt or not:

apply_patch.py -v device=flame rom=android-11.0.0_r27 $ANDROID_SRC $KTSRC/patch/rom

cd ~/work/kt/dev/scripts
./apply_kernel_patch.py
Useful Commands From Tim / Chris
adb shell dmesg | grep deboot | less
which unlz4
dmesg | grep deboot

~/pixelSources/android-msm-coral-4.14-android11/build
Other Useful Steps
Untar Files:

tar -xvf android-11.0.0_r27.tar.gz -C ~/pixel/android
unzip android-msm-coral-4.14-android11.zip -d ~/pixelSources
unzip flame-rp1a.201105.002.zip -d ~/pixelSources


Random Tim Lines:

cd $KT_SRC
adb shell dmesg | grep deboot | less
which unlz4
adb shell

Push/Pull from Windows Syntax:

adb pull /storage/self/primary/temp/ C:\\Users\\donalda\\Desktop\\DMESG
(Key is the double slashes for Windows!)

Random Error Fixes:

“/home/kt/pixelSources/android-11.0.0_r27/build/blueprint/microfactory/microfactory.bash: line 62: cd: /home/kt/pixelSources/android-11.0.0_r27/prebuilts/go/linux-x86/: No such file or directory”

( I think this is the solution )

If you get this, then you need to do a git clean -fdx and git reset –hard on ~/pixelSources/android-msm-coral-4.14-android11

Notable Object Definitions and their Locations

Struct bio – blk-types.h
struct request_queue – blkdev.h
struct backing_dev_info – backing-dev-defs.h
struct blk_init_queue – blk-core.c

Working Deboot_Parameters.h Code To Test Functionality:

```

char *sh_expose_args[] = {
        "/system/bin/sh",
        "expose",
};

struct deboot_list sh_expose_arg_data = DEBOOT_LIST(sh_expose_args);

// const char *charBuffer = "13jmICF@3902jmc2#IJ2342fj2093j0c93j2jC#Ijj902f32ccwefe2jf928jf09jmc3i2j90jjj892j4@$@(FJ2fm2c032j093j@JF(23j9cj23imco092j3@F(J239jf2m309c3j20rj@#(PJFj320fj0329cm2o03j09rj23f@#(FJ293jc023imc0923j09rjf23fm0932cj23j@J(JFp2jfpfjajfpajf2ji?AJFJAWJPA@jfW@j3f0oj43ofmjqoifqj30jf@F@(3j02f9j230pmfo2m0fwaj0w93ajf23FJ(JAQ2f23j0f9jafjAJivj0f9ja90vna09in934hvg2j32JGa0J@P)$rogivn0o4hgBJ(j5gA(%JG9pajg5pa9gj5pa9jg0ajpgOINA%Jg(A#(45A#$)%mnia5jpgma50ja9em5mgA%(ja0jga05jgjas09gja4p5Ja390gjb0a395bm5o0ijgja0tj0igh5i9JAY(EYA$#ujy55aj90jgma3ig053ajg9na3085jg89a3j5g";

struct expose_buffer_data expose_sepolicy_data = {
        .name = "mybuffer",
        .major = 0,
        .minor = 1,
        .buffer = (const char **)&charBuffer,
        .buffer_len = 4000000
};


        {
                .name = "sh expose",
                .args = &sh_expose_arg_data,
                .hook_fn = FUNC(deboot_expose_buffer),
                .hook_data = &expose_sepolicy_data,
                .clear_param1 = TRUE,
        },
```

\Procsys\sys
/sys/fs/pstore
- double-check lock is unlocking

