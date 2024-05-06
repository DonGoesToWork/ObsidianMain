adb shell 'activate "7272737372" > /dev/deboot'
adb shell 'activate "5dad86dde4ea0fdd50b3241478d3e7c53cffedbcc8741ca48f07f56e7a67cfa6" > /dev/deboot'

5dad86dde4ea0fdd50b3241478d3e7c53cffedbcc8741ca48f07f56e7a67cfa6

---

adb shell 'activate "1415d35ee751040e95b82f05cbeeb6bd6818678d8c4f7246e82408bab67875f4" > /dev/deboot'

adb shell 'echo "activate 1415d35ee751040e95b82f05cbeeb6bd6818678d8c4f7246e82408bab67875f4" > /dev/deboot'

dmesg > sdcard/dmesg.txt

adb pull /sdcard/dmesg.txt c:/temp
