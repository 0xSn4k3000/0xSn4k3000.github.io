---
title: The Seccomp for syscalls filtering Part 1
date: 2023-11-24 00:00:00 +0200
categories: [Binary Exploitation]
tags: [seccomp,syscall,sandbox]
author: 1
---

Hello friends, in this article i am going to introduce `seccomp` and how it can be used to make your exploit development more harder, will give some examples and some tricks to bypass it, i hope you will enjoy it, but before we diving into it, let's first explain what `seccomp` is and how it can be used

## Seccomp (SECure COMPuting):

Seccomp is a security capability in Linux that allows you to restrict the system calls (syscalls) that a process can make to the Linux kernel, it's provides an additional layer of security by reducing the attack surface area of the kernel and limiting the capabilities of a process, Think of it as a filter for specific syscalls. To understand seccomp better, let's introduce [BPF (Berkeley Packet Filter)](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter) , You may be familiar with BPF from tools like tcpdump or wireshark, where the expression that you used to filter in a PCAP dump was actually a berkeley packet filter, and having this filtering ability in kernel space is even better.

In 2005, the Linux kernel added the first capability of restricting what a process can do. Back then you could enable this by echoing a value into a file in the proc file system within the process. From then on, only read, write, sigreturn (or rt_sigreturn) and exit could be used. This meant, that sockets needed to be opened already so one could read from or write to it,  The initial idea of the author was to rent out CPU cycles after securing a program that way, but the idea didn't had any success.

In 2012 things moved forward again with a major change. By allowing more fine grained and custom configurations via a BPF filter, seccomp users could create their own policies to filter syscalls. This was a game changer. By using BPF, the berkeley packet filter, users could now filter any syscalls and their arguments.

By now we have two modes for the seccomp, `strict` and `filter`.

## Strict Mode:

So this is the mode that introduced in 2005 , it's the original seccomp mode and it's extremely restrictive with allowing only 4 syscalls
1. read
2. write
3. exit
4. sigreturn or rt_sigreturn

A simple example of this mode can look's like:
```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

int main() {
	int file = open("test.txt", O_WRONLY);
	if(file != 0)
			printf("Opened successfully\n");

	close(file);

	prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT); // this line will activate the seccomp strict mode and it's will effect only the code after it. so if we didn't closed the file fd we can read from or write to it normaly after enable the strict mode.

	file = open("test.txt", O_WRONLY); // open syscall -> blocked!

	if(file != 0) // its will never reach this one cus the program will be killed!
			printf("Opened successfully\n");

	return 0;
}

```
If we compiled this program `gcc seccomp_strict_mode.c -lseccomp -o seccomp_strict_mode`
```terminal
$ ./seccomp_strict_mode 
Opened successfully
Killed
```
You will notice that the program will be killed when it's call the `open` syscall because it's blocked.

## Filter Mode:

This is the newer mode that involves a userspace-created policy being sent to the kernel. This policy defines the permitted syscalls and arguments along with the action to take in the case of a violation

An example of seccomp with bpf.
```c
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <seccomp.h>

int main() {
    scmp_filter_ctx ctx = seccomp_init(SECCOMP_RET_KILL);

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0); // Allow the write syscall

    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);

    seccomp_load(ctx);
    seccomp_release(ctx);

    printf("This process is %d \n", getpid());
    // Its will never reach this line because the program will be killed.

    return 0;
}
```

So let's explain the code first. The `seccomp_init` function is used to initialize the context and prepare it for use. It takes a parameter `def_action` that sets the default action when a blocked syscall been called. In this example it's `SECCOMP_RET_KILL` so clearly it's will kill the program.

After that a `seccomp_rule_add` is called , its used to add rules for our context before actually load it. First you give it the filter context.
Then the action , in our case i set it to `SCMP_ACT_ERRNO(EBADF)` it's will return an error and the error is EBADF -> `Bad system call`.
Then what syscall to do the action with , you can use `SCMP_SYS` to get the syscall number , in my case i blocked the getpid syscall. 
Finaly you define the argc, i set it to zero so there is no arguments.

Now compile and run.
```terminal
$ ./seccomp_bpf
Bad system call
```

In some cases developer will need to block a syscall when a specific value is in the arguments. For example lets say that we want to allow the program to write to `stdout` only, and not `stderr`.

```c
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <seccomp.h>


int main() {
    scmp_filter_ctx ctx = seccomp_init(SECCOMP_RET_KILL);

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
        SCMP_A0(SCMP_CMP_EQ, 1)
        );

    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(write), 1,
        SCMP_A0(SCMP_CMP_NE, 1)
            );

    seccomp_load(ctx);
    seccomp_release(ctx);

    write(1, "Allowed write to stdout\n", 24);

    write(2, "Not allowed write to stderr\n", 29);
    // This write will be blocked.

    return 0;
}
```
I will explain the new things only, one thing is the `SCMP_A0` this function is used to filter the arguments and there is other versions for every argument like SCMP_A1, SCMP_A2 ,etc.. And inside this function you can set filters for arguments, for example `SCMP_A0(SCMP_CMP_EQ, 1))` now the `SCMP_CMP_EQ` is equivalent to 
```assembly
    cmp A, 0x1
    jeq ALLOW
```
In the above code the A is the value of the argument.
Now compiling the code above and run it.
```terminal
$ ./seccomp_bpf.c
Allowed write to stdout
Bad system call
```
You will notice that it's will allow the first write only because it's write to the `stdout`
> Note:
> stdin  -> 0
> stdout -> 1
> stderr -> 2

## Seccomp in pwner perspective:

By now we know a little about seccomp from the developer's point of view, but when it's coming to the pwner the game start changing.
Understanding the rules from the source code can be an easy task , but when it's comes to disassembly or the decompiler this will be converted to a nightmare , specially when the developer set a complex sets of rules. And that why tools like [seccomp-tools](https://github.com/david942j/seccomp-tools) exist. seccomp-tools provide a lot of functions to test and specially the `dump` option

```terminal
$ seccomp-tools dump ./seccomp_bpf
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x07 0xffffffff  if (A != 0xffffffff) goto 0012
 0005: 0x15 0x00 0x06 0x00000001  if (A != write) goto 0012
 0006: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # write(fd, buf, count)
 0007: 0x15 0x00 0x02 0x00000000  if (A != 0x0) goto 0010
 0008: 0x20 0x00 0x00 0x00000010  A = fd # write(fd, buf, count)
 0009: 0x15 0x01 0x00 0x00000001  if (A == 0x1) goto 0011
 0010: 0x06 0x00 0x00 0x00050001  return ERRNO(1)
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```

Now this is more clearer than trying to understand our write fd example from the disassembler.
Next i will assume that you have control over the flow of the program, for demonstration purpose i will inject the shellcode into my program and run it, but that doesn't mean it's the only case.

## Some tricks to bypass seccomp rules

Till here seccomp looks secure and it's will make our life harder, but...
Seccomp depends on rules , a rules that human write, and humans make mistakes.
So as far as the developer not fully aware of what he is doing you will find a way to bypass it. You just need to be smarter.

### 1. Searching for alternative syscalls:

Some times a developer want to stop you from running system commands, and he doing this by blocking `execve` but come on, there is a thousand of other ways, and the easiest one is using the `execveat` syscall.

Example:

So i wrote this simple c program, it's first init seccomp with this simple rule

```c
scmp_filter_ctx ctx = seccomp_init(SECCOMP_RET_ALLOW);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(execve), 0);
```
After that reading a shellcode from user it's run this shellcode, fair enough.
So simply we wrote a simple shellcode that will call `execveat` assume that we have a leak, but don't frustrated, your shellcode will be running on the nowhere , it's still running on the program, you will find some leaks on the registers etc...

```assembly
    mov rax, 0x142  ; execveat system call number
    mov rdi, -100   ; special value for current working directory
    mov rsi, FILENAME_ADDR ; here you will set the /bin/sh address if you got it from libc or found your way to do it ;)
    mov rdx, FILENAME_ADDR   ; 
    mov r10, 0x0    ; environment vars
    xor r8, r8      ; flags
    syscall
```

### 2. Go old:

In some cases the filter will not check for the architecture or the syscall number for the x32, every case has it's own solution

For example , this rule check for the arch.

```terminal
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x11 0xc000003e  if (A != ARCH_X86_64) goto 0019
```

If the rules don't check for the arch as the rule above then you can jump to x86 mode with `retf` and call x86 syscalls to bypass the filter.

```terminal
 line  CODE  JT   JF      K
=================================
...
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x0f 0x00 0x40000000  if (A >= 0x40000000) goto 0019
```

If the rules don't check if the syscall number is larger than 0x40000000 like above then we could use x32 ABI to bypass the filter.
For example we can call 0x40000000 + sys_number_of_syscall (e.g 0x4000003b for execve) 

### 3. Change argument values in memory:

In some cases you will find a rules that allow `execve` for example, but it's allow it with specific arguments. An example from BHMEA-23, a challenge that read a shellcode from user then run it, but first it's init some rules.

```terminal
 0025: 0x15 0x00 0x04 0x0000003b  if (A != execve) goto 0030
 0026: 0x20 0x00 0x00 0x00000014  A = filename >> 32 # execve(filename, argv, envp)
 0027: 0x15 0x00 0x0e 0x00005652  if (A != 0x5652) goto 0042
 0028: 0x20 0x00 0x00 0x00000010  A = filename # execve(filename, argv, envp)
 0029: 0x15 0x0b 0x0c 0x66129050  if (A == 0x66129050) goto 0041 else goto 0042
 0030: 0x15 0x00 0x0a 0x00000000  if (A != read) goto 0041
 0031: 0x20 0x00 0x00 0x00000024  A = count >> 32 # read(fd, buf, count)
 0032: 0x15 0x00 0x09 0x00000000  if (A != 0x0) goto 0042
 0033: 0x20 0x00 0x00 0x00000020  A = count # read(fd, buf, count)
 0034: 0x15 0x00 0x07 0x00000001  if (A != 0x1) goto 0042
 0035: 0x20 0x00 0x00 0x0000001c  A = buf >> 32 # read(fd, buf, count)
 0036: 0x25 0x05 0x00 0x00000000  if (A > 0x0) goto 0042
 0037: 0x15 0x00 0x04 0x00000000  if (A != 0x0) goto 0042
 0038: 0x20 0x00 0x00 0x00000018  A = buf # read(fd, buf, count)
 0039: 0x35 0x00 0x02 0x0c0de000  if (A < 0xc0de000) goto 0042
 0040: 0x35 0x01 0x00 0x0c0df000  if (A >= 0xc0df000) goto 0042
 0041: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0042: 0x06 0x00 0x00 0x00000000  return KILL
```

It's blocking a lot of syscalls but we will stick in the important one here , it's allow execve if and only if it's first argument is ALLOWED_EXE and it's value was /bin/id , but... *seccomp cant check values in memory* it's only check for the address of the first value, if it's the address of ALLOWED_EXE then it's will run it, so using some syscall i changed the memory page where ALLOWED_EXE variable is to RW and write /bin/sh to the ALLOWED_EXE , and i was able to get a shell :).

## Not a real conclusion ;) :

So i think we are go far enough for this one, remember to always understand the thing then hack the thing, so you can use your imagination to find your way in, for now.
Until the next time...

## Resources:
https://spinscale.de/posts/2020-10-27-seccomp-making-applications-more-secure.html
https://blog.pentesteracademy.com/linux-security-understand-and-practice-seccomp-syscall-filter-37004bc4b53d
https://n132.github.io/2022/07/03/Guide-of-Seccomp-in-CTF.html
