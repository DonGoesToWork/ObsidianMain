---
title: Status, 2-23-2023
allDay: false
type: recurring
daysOfWeek: [F,R,W,T,M]
startRecur: 2023-02-23
endRecur: 2023-03-18
startTime: 09:00
endTime: 09:00
---

# KT - Deboot Partitioning Work

Error when transferring my Space Manipulation Code from Android Studio to the KERNEL_SRC repo that I'm working in. (SM-G996B...)

![[Pasted image 20230222173250.png]]

```
  MODINFO modules.builtin.modinfo
  LD      .tmp_vmlinux.kallsyms1
ld.lld: error: undefined symbol: wipe_and_verify_s21plus
>>> referenced by deboot_yaml.c:1163 (../deboot/deboot_yaml.c:1163)
>>>               vmlinux.o:(deboot_setup_yaml)
make[1]: *** [/home/kt/work/devices/s21plus/SM-G996B_RR_Opensource/Makefile:1181: vmlinux] Error 1
make[1]: Leaving directory '/home/kt/work/devices/s21plus/SM-G996B_RR_Opensource/out'
make: *** [Makefile:179: sub-make] Error 2
+ popd
```

Investigating proper coding solution. The standard C coding convention of including a header file with a function protype doesn't seem to be working.

Most of this is tied to [[Guide 6 - Debug s21+]]

> 2/24 (Start):

Fixed issue by adding my deboot_partitioned.o file into the deboot folder's Makefile

> 2/24 (End):

- Swap around tickets 40349 and 40348?
- YAML Stages setup instructions?



> 2/27 Start

Guide for doing file stuff...

"Driving Me Nuts": `https://www.linuxjournal.com/article/8110`
"Narkive": `https://linux-kernel.vger.kernel.narkive.com/PwsO1oRK/how-can-i-create-or-read-write-a-file-in-linux-device-driver`


Picture of permission change attempt? Are permission changes even necessary? zzz....

![[Pasted image 20230227152320.png]]

Filp_Open:

![[Pasted image 20230227155053.png]]

ksys_open (I cri):

![[Pasted image 20230228103044.png]]


vfs_open (@Linux_Kernel, why do you hurt me?):

[todo]

Perhaps investigate timing/permissions again

