---
title: "CTF-user-pwn 堆漏洞学习日志 0x00 版"
description: "在学习日志 0x00 版，存在部分谬误待修正，如有错误请指出。"
date: 2026-03-16T00:00:00+08:00
image: ctf_pwn_heap0.png
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

请确保在已经学习并掌握了常见栈漏洞的前提下阅读本文。

使用环境 ：wsl kali linux。

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

由于本篇学习日志大多边学边写，所以难免出现以下情况：

* 多变的代码风格
* 无力的叙述语言
* 半对半错的理解
* 效率低下的调试

请见谅，如有错误请指出。

---

## 堆的基本认识

我们以 `heap_text.c` 展示堆的相关调试信息：

```
#include<stdio.h>
#include<stdlib.h>

int main(){
    int *p = NULL;
    p = (int*)malloc(0x114);
    p = (int*)malloc(0x514);
    p = (int*)malloc(0x1919);
    p = (int*)malloc(0x810);
    return 0;
}
```

### 堆的基本概念

当我们运行一个程序时，操作系统会为我们分配一个空间，这个空间分为多个部分，其中就包含堆段和栈段。

与栈对比，**栈（stack）是由编译器自动管理（存放局部变量），而堆（Heap）则是供程序员动态分配的内存空间。**

当 heap_test 执行第一行 malloc(0x114) 结束后，我们可以清晰的看到其空间被严格划分为：

![heap_test](./1.png)

* **蓝色的堆段**：
  * 起始地址 `0x555555559000`，结束地址 `0x55555557a000`。
  * **大小为0x21000**。
  * 权限：`rw-p`（可读 read，可写 write，私有 private，**没有执行权限 x**）

* **红色的代码段**：
  * 权限：`r--xp`（不可写）

* **粉紫色的数据段**：
  * 程序自己的数据段结束地址是 ` 0x555555559000`，与 heap 段的起始位置相同，紧挨着 heap 段。
  * 权限：`rw-p`。
 
* **黄色的栈段**：
  * 权限：`rw-p`。

观察发现，栈的地址往往较大（`0x7ffff`开头），这是因为**栈的生长方向是 高地址 → 低地址**，而**堆的生长方向是 低地址 → 高地址**，其间留有巨大的空间给各种动态链接库。

**并且 heap 的大小（0x21000）远大于我们实际申请的大小（0x114）。**

### 堆的实现

堆之所以远大于我们申请的大小的原因是堆的管理机制，当下 linux 系统最主流的堆的管理机制是 Glibc 的 ptmalloc，为了高效管理，其引入了几个核心概念：

* Chunk（内存块）：当我们申请一块 0x20 大小的内存时，不会只给 0x20 个字节，**而是给一个包装过的结构，称为 chunk**，包含以下数据：
  * prev_size：前一个邻接 chunk 的大小。
  * size：当前 chunk 的大小。
  * user_data：真正给程序使用的数据区。

其中，**prev_size 的作用是**，当当前 chunk 需要被释放时，系统将检查前一个邻接的 chunk 是否已经被释放，如果被释放了，**那么系统将把这两个 chunk 合并（修改前一个 chunk 的头部信息）**，等待重新分配。

而**判断 chunk 是否被释放的主要依据是 P 位**。

在 64 位系统中，**chunk 的大小必须是 16 字节对齐的**。

这意味着**对于合法的 chunk，其 size 的二进制表示最后四位一定是 0000**。

既然这几位一定是 0，那么 glibc 就决定利用这些位置，**把最低的三位拿来当作状态标志位（Flags）**。

* A (NON_MAIN_ARENA)：是否属于主分配区
* M (IS_MMAPPED)：是否是通过 mmap 分配的超大块。
* P (PREV_INUSE)：最低的一位，记录**上一个邻接 chunk 的空闲状态**。

也就是说，如果 低地址 → 高地址 存在邻接的 chunk_1，chunk_2，chunk_3，**如果 chunk_1 正在被占用，那么 chunk_2 的 size 字段最低位就是 1**。

同理，如果 chunk_1 被 free 了，那么系统就会立刻把 chunk_2 的 P 位改成 0。

这样的好处就是**当你释放当前 chunk 时，只要取当前 chunk 的 size&1 就可以得到是否要合并前一个 chunk 的信息**。

我们对 heap_test 这个程序举例，查看它的信息：

![chunk](./3.png)

* 第一个 Allocated chunk 是现代 glibc 用来存放自己的 Tcache (Thread Local Cache) 管理块，当程序第一次调用 malloc() 的时候就会将其存放，用来加速内存分配，大小通常是 0x290。
* 第二个 Allocated chunk，即用户申请的内存：
  * 地址：0x555555559290
  * 大小 0x120（我们申请了 0x114 + 0x8 = 0x11C 的内存，）

