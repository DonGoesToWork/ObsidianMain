
Used Parted with S21+ to resize userdata down to 128GB:

```
cd /mnt/c/users/donaldro/Desktop ; adb push parted /data
adb shell
cd /data ; chmod 0777 parted ; ./parted /dev/block/sda
resizepart 34
128GB
yes
```

