---
title: "CTF-user pwn 栈漏洞学习总结 0x10 版"
description: "在学习日志 0x00 版进行了优化与删减，如有错误请指出。"
date: 2026-3-11T00:00:00+08:00
image: ctf_pwn_stack.png
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

使用环境 ：wsl kali linux

```
PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
VERSION_ID="2025.3"
VERSION="2025.3"
VERSION_CODENAME=kali-rolling
ID=kali
ID_LIKE=debian
HOME_URL="https://www.kali.org/"
SUPPORT_URL="https://forums.kali.org/"
BUG_REPORT_URL="https://bugs.kali.org/"
ANSI_COLOR="1;31
```

栈漏洞是 pwn 手的入门阶段，所以本文将从汇编讲起。

如果没有底层的重大谬误，这一版应该是栈漏洞的最终版，之后可能只会看心情打补丁。

写这篇总结的原因是发现，最初边学边写的学习日志有相当一部分的重复题型与不明概念，大量无意义图片，今天重写，也是为了更好的巩固栈漏洞，预计在今年 4 月正式开始学堆漏洞。

这篇博客依然有高风险出现以下情况：

* 多变的代码风格
* 无力的叙述语言
* 半对半错的理解
* 效率低下的调试

请见谅，如有错误请指出。

![98e80b34343ce49fa1e5d7b94f7a0a8e](https://github.com/user-attachments/assets/f62be8b4-e0a8-48a9-b219-176d188e59fd)


更新日志：

* upd on 2026.3.11：初发布。


## Reference

在学习过程中参考了以下文章或博客：

[CTF-wiki](https://ctf-wiki.org/)

[hello ctf](https://hello-ctf.com/home/)

[shellcode 的艺术](https://xz.aliyun.com/news/6249)

[生成可打印的shellcode](https://xz.aliyun.com/news/5275)

[buuctf之pwn题(持续更新)](https://www.z1r0.top/2022/02/22/buuctf%E4%B9%8Bpwn%E9%A2%98-%E6%8C%81%E7%BB%AD%E6%9B%B4%E6%96%B0/)

[SROP 攻击原理与例题解析](https://www.anquanke.com/post/id/217081)

## 安全保护检查

设某道题附加可执行文件 pwn。

`file pwn` 主要查看三个信息：

* `ELF 64-bit` 或 `ELF 32-bit`：**64 位参数走寄存器，32 位参数走栈上。**
* `LSB` 或 `MSB`：
  * **LSB 是小端序，低位字节放在低地址，地址在内存倒着写**（比如地址 0x11223344，在内存中：44 33 22 11），在本阶段我们绝大多数题目都是小端序。
  * MSB 是大端序，高位字节放在低地址。
* `dynamically linked` 或 `statically linked`：
  * dynamically linked 是动态链接，程序文件小，**自己不带系统函数，运行时要去借用操作系统的 `libc.so`。**
  * statically linked是静态链接，程序文件大，在编译时，把 `printf, read` 这些库函数的底层代码全部硬塞进了程序里，**这使得 ROPgadget 非常全，可以靠大量 gadgets 堆叠拿shell。**

`pwn checksec pwn` 查看常见的安全保护：

* Arch: 
  * `i386-32-little`：32 位，小端，参数多在栈上传。
  * `amd64-64-little`：64 位，小端，参数通常走寄存器。
* RELRO：
  * `No RELRO`：GOT 表可写、可在运行时继续解析，更容易做 GOT 覆写。
  * `Partial RELRO`：启用了部分保护：`.got` `.plt` 仍可能可写。
  * `Full RELRO`: GOT 在解析完成后会被设成只读，基本堵死 GOT 覆写路线（但不影响 ret2libc/ROP 泄露）
* Stack:
  * `Canary found`：有栈保护，溢出覆盖返回地址前会先覆盖 canary，函数返回时会检查。
  * `No canary found`：没 canary，栈溢出更直接。
* NX：
  * `NX enabled`：栈/堆大多不可执行。
  * `NX disabled`：可执行栈。
* PIE：
  * `PIE enabled`：程序本体代码段地址也会随机化（每次运行基址变）。
  * `No PIE (0x400000)`：程序本体地址固定（常见起点 0x400000），libc 仍可能因 ASLR 随机。
 
## user pwn 的目标

pwn 大抵分 Kernel PWN（内核态利用）和 User-space PWN（用户态利用），我们本博客属于 User-space PWN 的初级形态。

**user pwn 的目标只有一个，那就是 get shell。**

**在 CTF 比赛中，就是执行 `system("/bin/sh")` 或 `execve("/bin/sh", 0, 0)`。**

## 初识汇编语言

虽然现在 IDA 可以得到 C 的伪代码，但是还是要至少理解程序执行的原理与逻辑。

以 `C++` 为代表的高级语言，与汇编语言有很大的区别，其中有个区别在于 **如何传递参数** ，而且**对于 64位 和 32位 的程序来讲，参数的传递方式也有所不同**。

```cpp
#include<stdio.h>

int main(){
    printf("hello world");
    return 0;
}
```

以上述代码（设为 `main.c`）为例，这里的“参数”指的就是字符串 "hello world" 的内存地址。

在 `C` 这类高级语言中，你不需要操心这个字符串放在哪，也不需要操心 printf 怎么拿到它，编译器会帮你搞定一切。

但是从汇编语言的角度来讲，CPU 在执行 `printf` 函数时（即汇编语言中 `call printf` 指令），必须先把参数准备好，**64 位放到寄存器上，32 位放到栈上**，`printf` 来了直接拿。

### 寄存器与参数调用约定

大多 64 位寄存器以 r 开头（Register），32 位寄存器以 e 开头（Extended）。

拿 64 位程序的 `write(fd,buf,len)` 来说，write 需要三个参数，那么程序正常运行的话，就会**在 call write 之前就会把这三个参数按 rdi，rsi，rdx 的顺序填进去**，执行 write 时，cpu 就会把这三个参数从对应的寄存器取出来。

至于 32 位的程序，**在 call 之前直接布置到栈上**，执行 write 时，cpu 就会把这几个参数从栈上取出来。

（怎么取的下文会说）

寄存器通常很小，64 位程序的寄存器有 64位（8个字节），32 位程序的寄存器只有 32位（4 个字节），**所以在寄存器里往往装的是参数的地址**，而不是 “hello world” 一类很长的字符串。

由于 32 位的传参根本不用寄存器，所以这里只说 64 位。

1. `rdi`，Destination Index（目的）。
2. `rsi`，Source Index （源）。
3. `rdx`，Data（数据）。
4. `rcx`，Counter（计数）。
5. `r8`，第 8 号。
6. `r9`，第 9 号。

在 64 位程序中，我们也经常发现 32 位的寄存器，比如 eax，其实在 64 位程序中，eax 就是 rax 的低 32 位（右半边），ax 就是 eax 的低 16 位（右半边），al 就是 ax 的低 8 位（low，右半边），ah 就是 ax 的高 8 位（high，左半边）。

### 寄存器与系统调用约定

32 位，当你执行 `int 0x80` （Interrupt 0x80）时，CPU 会立刻暂停手头的用户态工作，切换到最高特权级，去内核的“中断向量表”里找 0x80 号对应的处理程序。

比如 execve 需要传 3 个参，32 位对应的系统调用号是 11，那么**在触发 `int 0x80` 时，cpu 就会从 eax 取系统调用号，从 ebx，ecx，edx 依次取出参数。**

**32 位系统调用传参顺序：ebx，ecx，edx，esi，edi，ebp。**

64 位，当你执行 syscall 时，CPU 状态直接切换到内核态。

比如 execve 需要传 3 个参，64 位对应的系统调用号是 59，那么**在触发 syscall 时，cpu 就会从 rax 取系统调用号，从 rdi，rsi，rdx 依次取出参数。**

**64 位系统调用传参顺序：rdi, rsi, rdx, r10, r8, r9。**

通过 `pwn constgrep -c amd64 execve` 可以查 64 位的 execve 等函数的系统调用号，`pwn constgrep -c i386 execve` 则是 32 位的。

### 栈相关

对于每一个程序，其启动的时候，内核会为其分配一段 **内存，称为栈**，遵循先进后出。

这里要先介绍三个十分重要的寄存器：栈顶 esp/rsp，栈底 ebp/rbp，**下一条即将执行的**命令 rip/eip。

同所有其他的寄存器一样，rsp/rbp 也**不会**无缘无故的像个“光标”一样任意移动，只有特定操作才会使其移动。**而 rip/eip 不可直接修改。**

rip/eip 与大多寄存器不同，大多寄存器，不特意操作是不会移动的，但是 rip/eip 只要在 cpu 从内存取出了一条指令（如 `mov rax,1`），rip 就会自然加 7，指向下一个指令的开头，

我们对栈的一切操作，最终的目的都是为了把目标地址，塞进 rip/eip 里。

* push 即入栈，**栈的生长方向是从高地址往低地址生长**，`push eax` 会把栈顶 esp 的值减去 4，然后再把 eax 的值压入 esp 新指向的内存地址中。

* pop 即出栈，`pop eax` 会 **先从当前的 esp 指向的内存地址复制值** 放入eax，然后再把 esp 的值加 4。

值得一提的是，pop 出栈时，esp 虽然往高地址走了，看似“取出”了那个值，**但是其实那个数据并没有清除或消失**，所以这里严谨说是“拷贝”，下文直接说“取出”。

（有点像 steam 的删除游戏，只是逻辑上释放了空间，但是并没有删除，只是再下载数据的时候直接覆写）

* mov 即赋值，它是**纯粹的赋值指令**，如 `mov rsi, r14` 把 r14 的值赋值给 rsi，只要不给 esp 赋值，esp 不会动。

* sub 即减，如 `sub esp,0x20`，这使得 esp 上移了 0x20 个字节，**相当于拉开了一个新的空白区域**。

比如某个函数里定义了局部变量（如 `int a; char buf[0x20];`），那么执行 `sub esp,0x20` 就会让 esp 上移一个 buf 的距离。

注意这里相当于**只是移动了 esp 这个指针，而不更改这之间的内容。**

* add 即加，如 `add esp,0x20`，这使得 esp 下移了 0x20 个字节，**释放了一个区域的空间**。

同样，add **只动指针，不动数据**。

### 调用函数与系统库

假设 CPU 正在执行 位于 0x00 的 call 指令，而紧挨着它的下一条指令在 0x04，我们 call 的函数真实地址在 0xe4。

在准备好参数之后，call 指令可以拆成以下两步：

* `push rip`：把下一条指令压入栈中（备份 rip）。

* `jmp target`：把目标地址赋给 rip。



，
* `push rip`：
