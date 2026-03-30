---
title: "CTF-web 做题日志 0x00 版"
description: "做题日志的第 0 版本，如有错误请指出。"
date: 2026-03-30T00:00:00+08:00
image: ctf_web_q0.png
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


### [HCTF 2018]WarmUp

[题目链接](https://buuoj.cn/challenges#[HCTF%202018]WarmUp)

首先查看原代码，有提示看一下 source.php 的东西。

看了一下把整个伪代码给你了。

<img width="1193" height="1256" alt="image" src="https://github.com/user-attachments/assets/08cd4e83-38bc-41d5-9993-ace6ba1749bb" />

`$_REQUEST['file']` 让我们把参数传进去，然后重点在 `::checkFile($_REQUEST['file'])`上吗，也就是把 file 的内容传给了形参 page 进入了这个检查函数，这个检查函数的重点在：

```
$_page = mb_substr(
                $page,
                0,
                mb_strpos($page . '?', '?')
            );
```

`mb_substr()` 函数从 $page 中第 0 个字符开始，截取 `mb_strpos($page . '?', '?')` 长度的字符。

`mb_strpos($page . '?', '?')` 其中 `$page . '?'` 的含义是在 $page 的后面接一个 '?' 字符，防止你输入没有这个。

然后再返回 $page 直到 '?' 的长度。

整个函数的大意就是把 $page 截取到第一个问号之前。

之后

```
if (in_array($_page, $whitelist)) {
                return true;
            }
```

表示当 $_page 是 $whitelist 中的元素之一时，放行。

所以我们可以写成 `?page=hint.php`，可以得到 flag 在 `ffffllllaaaagggg` 的信息。

然后为了绕过这个检查机制，我们在后面再写一个问号，即 `?file=hint.php?`

由于 .php 的 include 机制，即**即使当前目录下不存在 `hint.php` 文件**，当 `include(hint.php/..)` 时，由于其认为你进入了某个文件又返回上一级，相当于没做，所以不做操作。

因此可以绕过检查机制，构造 `?file=hint.php?../../../../../../../../ffffllllaaaagggg` 一路返回上一级找到 flag。
