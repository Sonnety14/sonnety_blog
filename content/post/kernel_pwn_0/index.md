---
title: "kernel_pwn 0x00版学习总结"
description: "如有错误，请直接指出，谢谢。"
date: 2026-07-11T00:00:00+08:00
image: hate_only.png
math: true
license: 
hidden: false
comments: true
draft: false
categories:
    - CTF
tags:
    - CTF
---

## 前言提要

可能需要复习的一些小知识。


### CPU 分级

<img width="475" height="290" alt="image" src="https://github.com/user-attachments/assets/e4cb3e3b-3e5b-421d-85d6-886b0f3a3b2d" />

CPU 分级数值上越小，权限越大，如果低权限访问高权限的东西，会导致失败。

不过虽然有四个权限等级，但包括 Linux 和 Windows 在内的大多数现代操作系统，**在实际运行中主要只使用 Ring0 和 Ring3**。

* Ring0（内核态）：拥有最高权限，可以直接访问底层硬件和所有内存空间。Linux 内核及其核心驱动模块运行在此级别。
* Ring3（用户态）：拥有最低权限，代码受到严格限制。普通的应用程序（如浏览器、办公软件等）均运行在此级别。

### GDT 与 LDT

GPT（Global Descriptor Table，全局描述符表）与 LDT（Local Descriptor Table，局部描述符表）可以理解为一个数组，其内放的元素是**描述符**。

描述符是一个**八字节大小的，描述了某个代码段的信息**的数。

其信息主要包括该代码段的位置、大小、类型和权限。

举个例子：

假如内存中有一段内核代码：

```
0x00100000  push rbp
0x00100001  mov rbp, rsp
0x00100004  ...
```

那么 GDT 中就会有一段描述符，记录了类似：

```
Base    = 0x00100000    // 段基地址
Limit   = 0x000fffff    //段界限，即段内允许的最大偏移，可以理解为代码段允许使用的最大范围
Type    = 代码段        //代码段 or 数据段
DPL     = 0            //描述符特权级，Ring3 or Ring0
Present = 1            //描述符是否存在且有效
```



* GDT 一个系统只有一个

### linux 系统中常见选择子：CS、SS、CPL

CS、SS 的可见部分都是一个 16 位的**段选择子**，段选择子的作用是

段选择子的结构如下：

```
15                             3  2   1 0
┌──────────────────────────────┬───┬─────┐
│           Index              │ TI│ RPL │
└──────────────────────────────┴───┴─────┘
```

其中含义是:

* Index：到描述符表中找第几项。
* TI：使用 GDT 还是 LDT。
* RPL：请求特权级。

所以：

* index = selector >> 3;
* TI    = (selector >> 2) & 1;
* RPL   = selector & 3;
