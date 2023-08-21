---
title: HackTheBox - The Needle
date: 2023-08-21 01:22:15 +0800
categories: [TOP_CATEGORIE, SUB_CATEGORIE]
tags: [first-post]     # TAG names should always be lowercase
---

Hello friends ! , to day i'm going to solve `The Needle` hardware challenge from hackthebox , first if you are a guy who like to solve every things your self like me then check the Hints first ^_^ i hope it will help you , don't forget to back to read my blog after solving the challenge so maybe you learn something new. without a more words lets start.

# Hints
1. binwalk.
2. squashfs.
3. go throw the file system to find a bash file that can help you.

# Solution

First of all lets see what kind of files we are working with, i used the `file` command to identify it.
  ```bash
  $ file firmware.bin 
firmware.bin: Linux kernel ARM boot executable zImage (big-endian)
  ```

and it's look like a linux kernel , hmm let's use binwalk to see what is this file parts are?

  ```bash
  $ binwalk firmware.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Linux kernel ARM boot executable zImage (big-endian)
14419         0x3853          xz compressed data
14640         0x3930          xz compressed data
538952        0x83948         Squashfs filesystem, little endian, version 4.0, compression:xz, size: 2068458 bytes, 995 inodes, blocksize: 262144 bytes, created: 2021-03-11 03:18:10

  ```

And like what we expect there is a `squashfs` file system , squash file system is widly used in firmwares of iot devices , you can read more about it from ![here](https://en.wikipedia.org/wiki/SquashFS) 
  
# Extracting the file system

now lets use the `dd` command to extract the file system

```bash
$ dd if=firmware.bin of=rootfs bs=1 skip=538952
```

so here is the command , first the `if` option is used to identify the `input file` , `of` to identify the `output file` , `bs` the dd command reads one block of input and process it and writes it into an output file, so with the `bs` you can identify the block size , i set it to `1` so dd will read one byte process it and write that byte into the output file, and finaly the `skip` option , if you back up the output of the binwalk you will see there is a numbers in the left of every part of the file , this numbers are the offset of the beginneing of the part in the file , so we need to skip `538952` to make `dd` start processing from the beginneing of the squash file system.

so after running dd we got this file `roofs` if we run file on the file we will get this.

```bash
$ file rootfs
rootfs: Squashfs filesystem, little endian, version 4.0, xz compressed, 2068458 bytes, 995 inodes, blocksize: 262144 bytes, created: Thu Mar 11 03:18:10 2021
```

everythings good , now we can use the unsquashfs utility to extract the file system

```bash
$ unsquashfs rootfs
```

if you current directory looks like this then you are ready to go to the next step

```bash
$ ls
firmware.bin  rootfs  squashfs-root
```

# Analyzing the file system

  After entering the squashfs-root you will notice its a linux  file system like your own. `Note :(if you use linux heheh ^_^!!)`
```bash
squashfs-root$ ls
bin  dev  etc  lib  mnt  overlay  proc  rom  root  sbin  sys  tmp  usr  var  www
```

lets first go to `etc` becouse its first place i go to for finding files like shadow to find hardcoded password etc.
so etc contains alot of things inside it , i start by reading the shadow file but got nothing , after a time i noticed this dir `/etc/scripts` the dir contain a file called `telnetd.sh` , its a bash file , interesting let's see what inside

```bash
$ cat telnetd.sh 
#!/bin/sh
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

```bash
$ nc IP PORT
```

its will ask for a usename and we will use `Device_Admin` , next it will ask for password , after entering the password we found it's worked just fine , now we can got our flag.

thanks !!