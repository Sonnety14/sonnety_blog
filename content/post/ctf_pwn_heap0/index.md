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

### 什么是堆

当我们运行一个程序时，操作系统会为我们分配一个空间，当 heap_text 执行第一行 malloc(0x114) 结束后，我们可以清晰的看到其空间被严格划分为：

