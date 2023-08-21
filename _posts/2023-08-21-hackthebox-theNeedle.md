---
title: HTB - The Needle
date: 2023-08-21 01:22:15 +0200
categories: [Hardware & IoT]
tags: [firmware,squashfs,binwalk]
author: 1
---

Hello friends , in this post i will solve `The Needle` challenge from hackthebox , its a very easy challenge, so lets do it.

## Hints
first things first , if you are someone who like to solve things on your own like me , but you are stuck then here some hints that can help. ^_^

1. binwalk
2. squashfs
3. go throw the file system to find a bash file that can help you

## Solution
First of all lets see what kind of files we are working with, i used the `file` command to identify it.

```terminal
***root@caretaker:$*** file firmware.bin 

firmware.bin: Linux kernel ARM boot executable zImage (big-endian)
```

and it's looks like a linux kernel , hmm let's use binwalk to see what is this file parts are?


```terminal
***root@caretaker:$*** binwalk firmware.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Linux kernel ARM boot executable zImage (big-endian)
14419         0x3853          xz compressed data
14640         0x3930          xz compressed data
538952        0x83948         Squashfs filesystem, little endian, version 4.0, compression:xz, size: 2068458 bytes, 995 inodes, blocksize: 262144 bytes, created: 2021-03-11 03:18:10
```

like you can see there is a file system in the end of the file, a `squashfs` file system , ![squash](https://en.wikipedia.org/wiki/SquashFS) file system is widly used in firmwares of iot devices. 

## Extracting the file system

Extracting the file system can be very help full where you can find some hardcoded passwords, vulnerable code , etc\.\..
so now lets use the `dd` command to extract the file system

```terminal
***root@caretaker:$*** dd if=firmware.bin of=rootfs bs=1 skip=538952
```

lets explain the command parts and options, 
- `if`: 
      option is used to identify the `input file`.
- `of`: 
      to identify the `output file`.
- `bs`: 
      the dd command reads one block of input and process it and writes it into an output file, so with the `bs` you can identify the block size , i set it to `1` so dd will read one byte then process it and write that byte into the output file.
- `skip`: 
      if you go back up to the output of the binwalk you will see there is a numbers in the left of every part of the file , this numbers are the offset of the beginneing of the part in the file , so we need to skip `538952` to make `dd` start processing from the beginneing of the squash file system.

so after running `dd` we got this file `rootfs` if we run `file` command on the file we will get this.

```terminal
***root@caretaker:$*** file rootfs
rootfs: Squashfs filesystem, little endian, version 4.0, xz compressed, 2068458 bytes, 995 inodes, blocksize: 262144 bytes, created: Thu Mar 11 03:18:10 2021
```
now we can use the `unsquashfs` tool to extract the file system.

```terminal
***root@caretaker:$*** unsquashfs rootfs
```
you will got a directory called `squashfs-root`

## Analyzing the file system

After entering the squashfs-root you will notice its a linux file system

```terminal
***root@caretaker:$*** ls squashfs-root
bin  dev  etc  lib  mnt  overlay  proc  rom  root  sbin  sys  tmp  usr  var  www
```

lets first go to `etc` because its the first place i go to for finding low hanging fruits like shadow file contains hardcoded password etc\.\..

so etc contains alot of things inside it , i started by reading the shadow file but got nothing , after a time i noticed this directory `/etc/scripts` it's contains a file called `telnetd.sh` , its a bash file and looks like its a deamon for telnet service , interesting let's see what's inside.

```bash
sign=`cat /etc/config/sign`
TELNETD=`rgdb
TELNETD=`rgdb -g /sys/telnetd`
if [ "$TELNETD" = "true" ]; then
	echo "Start telnetd ..." > /dev/console
	if [ -f "/usr/sbin/login" ]; then
		lf=`rgbd -i -g /runtime/layout/lanif`
		telnetd -l "/usr/sbin/login" -u Device_Admin:$sign	-i $lf &
	else
		telnetd &
	fi
fi
```

you can recoginze that the file using the `login` command to login with the user `Device_Admin` so we got the user , its using the variable `$sign` as a password lets see what it's value
`sign=\`cat /etc/config/sign\``
so we just need to `cat /etc/config/sign` to find the password, and we did. `qS6-X/n]u>fVfAt!` we found the password , so lets connect to the machine and see if this will work.

## Conclusion
```terminal
***root@caretaker:$*** nc IP PORT
hwtheneedle-1226574-949687cbc-hlmmm login: Device_Admin
Password: qS6-X/n]u>fVfAt!

hwtheneedle-1226574-949687cbc-hlmmm:~$ 
```

so after we using the credentials we found we were able to login to the device.
thank you for reading and hope you learned something new , feel free to contact me for any ideas or feedbacks on ![twitter](https://twitter.com/0xSn4k3000) or by commenting down below.
