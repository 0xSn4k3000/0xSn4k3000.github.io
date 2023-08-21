---
title: HTB - The Needle
date: 2023-08-21 01:22:15 +0200
categories: [Hardware & IoT]
tags: [firmware,squashfs,binwalk]     # TAG names should always be lowercase
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