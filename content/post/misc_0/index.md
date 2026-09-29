---
title: "CTF-misc 做题日志 0x00 版"
description: "在做题日志 0x00 版，存在部分谬误待修正，如有错误请指出。"
date: 2026-08-16T00:00:00+08:00
image: misc_0.jpg
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


#### [BUUCTF-MISC] 二维码

[题目链接](https://ctf2.dasctf.com/dashboard/practice/b9bbb32f-f186-458f-b90b-12440c0f6aea?tab=challenges&challenge=7a44e5a1-beea-4663-9b23-ebe1baf38765)

把图片放进这个 010 Editor 里面，容易发现这个 IEND 后面隐藏的信息：

<img width="687" height="855" alt="image" src="https://github.com/user-attachments/assets/bfd8f920-2848-479d-afcb-afe49c05e5a5" />

我选中的蓝色部分就是 PNG 部分。

可以看到有效信息，标灰色的地方 `50 4B 03 04 14 00 09 00` 翻译出 `PK ...`，**其实就是 ZIP 文件头（`50 4B 03 04`）**。

还有 `4number.txt`，也就是说这个 PNG 后面藏了 ZIP，ZIP 里面有一个 4number.txt。

我们也可以用 kali 里的 binwalk 工具，自动查找有没有已知的文件格式：

<img width="1460" height="213" alt="image" src="https://github.com/user-attachments/assets/2a7c1335-a0ba-4341-ad24-579a8b79307f" />

使用 `binwalk -e` 可以自动解析剥离内部文件，也可以再 010 Editor 中选中相关部分，右键选择 `Save Selection` 将其保存为相关文件。

随后我们发现这个压缩文件有密码，根据内部文件 4number.txt 合理猜测，该文件密码为四位数字，进行穷举，使用工具 fcrackzip。

#### fcrackzip 工具

fcrackzip是一款用于破解zip类型压缩文件密码的工具，主要有**暴力破解**和**字典破解**两大功能。

暴力破解 `-b`（brute force），可选字符集 `-c`：

* `-c 1`：字符集为 0~9。
* `-c a`：字符集为 a~z。
* `-c A`：字符集为 A~Z。
* `-c !`：常见特殊字符。

可选长度 `-l`，如 `-l 4~6` 指长度在 4~6 位的密码。


字典攻击 `-D`，可以在有限的可能的密码中进行爆破，如存在某密码文本薄 `passwd.txt`，可以用 `fcrackzip -D -p passwd.txt -u secret.zip` 来爆破文件。

总之，如 `fcrackzip -b -c a1 -l 1-6 -u flag.zip`，fcrackzip 是一个好用的爆破工具。

### 常见的 Header

```
PNG
89 50 4E 47 0D 0A 1A 0A

JPG
FF D8 FF

GIF
47 49 46 38

ZIP
50 4B 03 04

RAR
52 61 72 21

7z
37 7A BC AF 27 1C

PDF
25 50 44 46

ELF
7F 45 4C 46

Windows EXE
4D 5A

GZIP
1F 8B
```

### PNG 文件结构与宽高修改

现在拿下图，深入学习 PNG 的图片结构：

<img width="1744" height="935" alt="image" src="https://github.com/user-attachments/assets/67ed5b2d-e220-4a36-89ad-24a6bdcf3e4c" />

图片的前八个字节是签名（`89 50 4E 47 0D 0A 1A 0A`），表示这是个 PNG 文件。

**其余部分都是由 chunk 组成的**，而 chunk 的结构一般如下：

```
[ Length: 4 字节 ] [ Type: 4 字节 ] [ Data: Length 字节 ] [ CRC: 4 字节 ]
```

比如说，紧挨着签名后面的 chunk 的 type 是 IHDR （`49 48 44 52`），IHDR 前四个字节 （`00 00 00 0D`）就是这个 chunk 的长度，比如 IHDR 的起始位是 0x08，data 的长度是 13，那么 0x08 + 13 + 4 * 3 = 0x21，**就是下一个 chunk 的起始位**。

IHDR 的 data 部分，13 个字节也各有含义：

* 0x10 位（`00 00 09 FF`）：宽度 width。
* 0x14 位（`00 00 06 3F`）：高度 height。
* 0x18 位（`08`）：位深，每通道8位。
* 0x19 位（`02`）：颜色类型，2 = 真彩色 RGB（3 通道）。
* 0x1A 位（`00`）：压缩方式，deflate。
* 0x1B 位（`00`）：滤波方式，自适应。
* 0x1C 位（`00`）：是否隔行，否。

CRC 则是对 Type + Data 算出的检验值，全名叫 Cyclic Redundancy Check（循环冗余校验），本质是多项式除法取余数，**用来发现数据在传输/存储中是否被改坏**。

```
# deepseek v4.1Flash 生成，仅作参考
crc = 0xFFFFFFFF                      # ① 初始值
for byte in data:
    crc ^= byte                       # ② 把当前字节异或进最低 8 位
    for _ in range(8):                # ③ 逐位处理（共 8 次）
        if crc & 1:                   #    最低位是 1
            crc = (crc >> 1) ^ 0xEDB88320   # 右移一位，再异或多项式
        else:                         #    最低位是 0
            crc >>= 1                       # 只右移
return crc ^ 0xFFFFFFFF               # ④ 最后整体取反
```

**仅在 PNG 类型文件一般情况下**，可以简单认为 CRC = Type || data （“||”表示拼接）。

因此就可以快速判断该图片是否存在宽高隐写，我们也可以利用 kali 中的 pngcheck 工具快速查看结构错误：

<img width="1153" height="181" alt="image" src="https://github.com/user-attachments/assets/895e72a3-c616-4f17-86db-49af9bd735e3" />

（但是 CRC 没有防篡改机制，因此只要出题人把 CRC 将错就错地修改，pngcheck 就做不出来了）

那么对于存在宽高隐写的题目，我们可以直接在 010 Editor，用 pngcheck 查出的 expected CRC （本题是 b757db33），直接去掉 type 得到正确的 data，然后在 010 Editor 里手动修改，得到原图。

（也可以直接使用我在该博客目录下存放的，自写的 pngfix.py，直接 `python pngfix.py target.png fixed.png` 来输出原图）
