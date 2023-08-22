---
title: HTB - Reg writeup
date: 2023-08-22 02:08:00 +0200
categories: [Binary Exploitation]
tags: [bufferoverflow,bof,htb,writeup]
author: 1
img_path: /assets/posts_imgs/2023-08-22-htb-reg/
---

Hello friends , in this post i will solve `Reg` challenge from hackthebox , its an easy pwn challenge, so lets do it.

## Hints
first things first , if you are someone who like to solve things on your own like me , but you are stuck then here some hints that can help. ^_^


## Static analysis
Starting from knowing what type of file we're working with, I ran the `file` command on the file to get it.

```terminal
root@caretaker:$ file reg
reg: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=134349a67c90466b7ce51c67c21834272e92bdbf, for GNU/Linux 3.2.0, not stripped
```
so it's a linux executable file , from this output we can find out that the binary is `dynamically linked` so the shared libs will be loaded in the runtime , next is the `not stripped` , this mean we can read the functions names etc\.\..

Next let's check the kind of security enabled on this binary, using the checksec util from pwntools
i will get what i want.

```terminal
root@caretaker:$ checksec --file=reg
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   80 Symbols	  No	0		3		reg
```

so from here we can see that there is no `stack canary` or `pie` enabled.

## Go further and read the code

Now let's open `ida` and disassemble the program , for those who don't know [ida](https://hex-rays.com/ida-pro/) , it's a powerful disassembler and a versatile debugger.

so after opening ida and navigate to the main function we will get this code.

![main_function](main_function.png)
_Main Function_