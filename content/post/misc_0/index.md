---
title: "CTF-misc 做题日志 0x00 版"
description: "在做题日志 0x00 版，存在部分谬误待修正，如有错误请指出。"
date: 2026-08-16T00:00:00+08:00
image: misc_0.png
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

## 图片隐写

一张图片 png，本质就是一个文件，也就是一串字节，比如我们用记事本来打开一张图片：

<img width="1504" height="642" alt="image" src="https://github.com/user-attachments/assets/da5422d9-3543-4774-94fd-640583708bbb" />

可以看到，记事本翻译出了一串乱码，这是为什么呢，因为记录图片信息的字符在 0~255 （0xff）之间，而记事本的翻译方式就是 ASCII 码，自然会有一些乱码和不可见字符被翻译出来。

那么我们可以使用 010 Editor 这个工具，它会忠诚地把这些都表示成 hex 码。

那么正常的 PNG 图片格式大概如下：

```
┌───────────────┐
│   PNG Header  │
├───────────────┤
│     IHDR      │
├───────────────┤
│     IDAT      │
├───────────────┤
│     IEND      │
└───────────────┘
```

PNG Header ：`89 50 4E 47 0D 0A 1A 0A`（0x50 → P，0x4E → N，0x47 → G）

INED：`49 45 4E 44`（0x49 → I，其他同理）

但是我们可以这样隐藏信息：

```
┌───────────────┐
│   PNG Header  │
├───────────────┤
│     IHDR      │
├───────────────┤
│     IDAT      │
├───────────────┤
│     IEND      │
├───────────────┤
│               │
│    ZIP文件    │
│               │
└───────────────┘
```

图片查看器在 IEND 这里就截止，这样我们就可以隐藏信息了。


### [BUUCTF-MISC] 二维码

[题目链接](https://ctf2.dasctf.com/dashboard/practice/b9bbb32f-f186-458f-b90b-12440c0f6aea?tab=challenges&challenge=7a44e5a1-beea-4663-9b23-ebe1baf38765)

把图片放进这个 010 Editor 里面，容易发现这个 IEND 后面隐藏的信息：

<img width="687" height="855" alt="image" src="https://github.com/user-attachments/assets/bfd8f920-2848-479d-afcb-afe49c05e5a5" />

我选中的蓝色部分就是 PNG 部分。

可以看到有效信息，标灰色的地方 `50 4B 03 04 14 00 09 00` 翻译出 `PK ...`，**其实就是 ZIP 文件头（`50 4B 03 04`）**。

还有 `4number.txt`，也就是说这个 PNG 后面藏了 ZIP，ZIP 里面有一个 4number.txt。

我们也可以用 kali 里的 binwalk 工具，自动查找有没有已知的文件格式：

<img width="1460" height="213" alt="image" src="https://github.com/user-attachments/assets/2a7c1335-a0ba-4341-ad24-579a8b79307f" />

