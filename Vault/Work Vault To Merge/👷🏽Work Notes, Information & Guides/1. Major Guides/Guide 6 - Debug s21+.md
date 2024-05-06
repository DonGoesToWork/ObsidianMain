
Todo:

- Put my changes for the multi-queue branch up for review.
	- If there are duplicated comments, add a note and ignore.
	
- Wrap up my out of partition ticket
	- Make sure that we still have 0's after 40 billionth byte.

- Do s21 debug work
	- Make sure to put ticket into dev ops.

---

Tim's comments to fix Single Queue Block Device Implementation Ticket.

+ remove logical_block_size
+ no module paramaters
+ avoid using 'major_num', use op->major instead
+ remove deboot_paramters stuff
- make sure to filter all /patch folder things (from patch submodule being changed) / make sure there are no submodule additions like 'patch/kernel/auth_input.patch'

---

Tips for Building Android Stock ROM:

- When you do the repo sync, add ‘v’ to the command to be verbose.
- Put relevant files into: ```\\wsl.localhost\Ubuntu-22.04\home\kt\work\devices\s21plus```
- Then, unzip “SM-G996B_RR_Opensource.zip” into a folder by the same name and untar the contents of the kernel.tar.gz

---

Kernel Build Steps:

- apply_kernel_patch.py
- source ~/work/kt/dev/scripts/setup_env.sh --device s21plus --rom gsi-11 --ktsrc ~/work/kt --rootdev ~/work/devices/s21plus --buildtype eng```
- clear ; build_kernel.sh

***

Command for ROM: ```apply_patch.py -v device=G996B rom=gsi-11 $ANDROID_SRC  $KTSRC/patch/rom```

***

Gotcha’s to Watch Out For And Avoid:

The "cd $ROOT_DEV && repo init -u https://android.googlesource.com/platform/manifest -b android11-gsi" command puts everything into "~/work/devices/s21plus". I moved the repo contents into a sub-folder and this fixed my issue. In general, try to use share files to as they are in the correct format. Even the Android Stock Rom should be from there.

***

Main Work Folder:  ```~/work/devices/s21plus/android11-gsi```
Output Folder:  ```~/work/devices/s21plus/android11-gsi/out/target/product/generic_arm64```
OR:  ```\\wsl.localhost\Ubuntu-22.04\home\kt\work\devices\s21plus\android11-gsi\out\target\product\generic_arm64```

Boot Image Location: ```\\wsl.localhost\Ubuntu-22.04\home\kt\work\devices\s21plus\workdir\s21plus\gsi-11```

***


