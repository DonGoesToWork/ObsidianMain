# Commands

In WSL > setupenv.sh shortcut: `~/setup.sh`
Go to our patched kernel repo that we're working in: `cd $KERNEL_SRC`
Build Kernel Universally with No Conflicts:

```
cd ~/ ; . setup.sh ; cd $KERNEL_SRC
clear ; ~/kt/dev/scripts/build_kernel.sh -dev
```

~/kt/dev/scripts/build_kernel.sh

`make_bootimg.sh`
`adb reboot download`

~/kt/dev/scripts/setup_env.py --device s21plus --rom gsi-11 --ktsrc ~/kt --rootdev ~/s21plus --buildtype eng

#### PREP KT Repo

Make sure to delete build_kernel.sh and also [SOME OTHER FILE!!! FIGURE OUT]

#### Adb Shell Commands

**Get into phone shell and create log:**
```
adb shell
dmesg -w
```

```
dmesg > /sdcard/dmesg.txt
cd /mnt/c/temp ; adb pull /sdcard/dmesg.txt 


dmesg -w | tee -a /sdcard/dmesg.txt
```

While NOT in ADB SHELL:
cd /mnt/c/temp ; adb pull /sdcard/dmesg.txt 
adb pull /sdcard/dmesg.txt C:\temp\dmesg.txt

For current ticket, fast test yaml changes:

```
chmod 777 /dev/block/sda
```

####  Logwatch Details

**Script Paths:**
/home/kt/work/kt/dev/scripts/klogless.sh
/home/kt/work/kt/dev/scripts/klogwatch.sh

**Log Output Dir:**
LogDir Path in WSL: `/home/kt/work/devices/s21plus/logs/s21plus/gsi-11/`
Windows Version: `\\wsl.localhost\Ubuntu-22.04\home\kt\work\devices\s21plus\logs\s21plus\gsi-11`

#### Can Verify my 'Key' that I built KT with Using:

build_key.sh 73737272 10000

#### Dmesg to Keyword

matched argv1:'w1' == 'w1'
matched argv1:'w2' == 'w2'

#### Getting a Variable and outputing.

`echo "get_str_variable SOME_VAR" > /dev/deboot ; cat /dev/deboot ; echo`

ex: echo "get_str_variable calc_size" > /dev/deboot ; cat /dev/deboot ; echo

#### Get Linux Version

`uname -r`

# Git Reference

## Create KT Patch Steps

### Create Patch

`apply_kernel_patch.py` <- Copies files from KT Source Repo to KT Dev Repo. (From ~/work/kt to ~/blah blah blah/SM-Whatever/Blah)

### Migrate changes back from Source to KT Repo

- Make a backup of your changes, just to be safe.
- If you created any new files in the kernel repo, do a `git add <file>`  / `git add .`
- Run `make_kernel_patch.py` in your dev environment shell
- Inspect the patches ( git diff) in your KT source dir to make sure patches look right. `cd ~/work/kt ; git status` / `git diff origin/dar_sq_expose_buffer..dev`
- Update dev into your branch:

```
 2010  git stash
 2014  git pull
 2016  git merge origin --no-ff dev
 2020  cd dev/patchtool/
 2025  git checkout dev
 2026  git pull
 2027  git checkout master
 2028  git pull
 2030  cd ../..
```

### Uncommit already commited changes:
git reset HEAD~1

## Get Rid of Stuff after git add .

```
git restore --staged .vscode ; git restore --staged scripts/crypto/__pycache__/
```

### Clear out submodule stuff

```
git submodule deinit -f .
git submodule update --init
```

# Lots of Smaller Misc Items

## Ramoops

find / -name *ramoops* 2>/dev/null

/sys/devices/platform/8f000000.ramoops
/sys/fs/pstore/pmsg-ramoops-0

-> /sys/fs/pstore/dmesg-ramoops-0

/sys/bus/platform/devices/8f000000.ramoops
/sys/bus/platform/drivers/ramoops
/sys/bus/platform/drivers/ramoops/8f000000.ramoops
/sys/firmware/devicetree/base/reserved-memory/ramoops@8f000000
/sys/module/ramoops

## Quick File Paths

Network Drive Location: `\\10.40.49.51`
Odin Location: `C:\Users\donalda\Desktop\Desktop Files\Software\Odin3_v3.14.4`

## Hard Regex (Time to git gud on some harder one's)

Negative search for a character (in this case ')' is the character of choice). `get_fs\((?!\))`

numeros:
257 148
76 25 43
4578*

### Sammobile login

Destro169
[usual]1