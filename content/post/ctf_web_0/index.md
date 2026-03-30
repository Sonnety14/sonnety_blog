---
title: "CTF-web 学习总结 0x00 版"
description: "边学边写的第 0 版本，如有错误请指出。"
date: 2026-03-28T00:00:00+08:00
image: ctf_web_0.jpeg
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

如题，本人 0 基础 web，学习的东西大概率也比较基础，如有错误请指出。

这篇博客有高风险出现以下情况：

* 多变的代码风格
* 无力的叙述语言
* 半对半错的理解
* 效率低下的调试

## HTTP 协议基础

HTTP即超文本传输协议（HyperText Transfer Protocol），**本质上是一个基于文本的、无状态的请求-响应协议**。

### HTTP 基本运作模式

HTTP **永远是客户端先发起请求，服务器再给出响应**。

好比一个 C 语言程序的函数，通过网络把参数塞过去（Request），远端执行完后把 return 的结果扔回来（Response）。而且它是**无状态**的，下一次再发送请求，和第一次没有任何区别。

### HTTP 请求包 (Request) 基本结构

当我们在浏览器输入网址并回车，或者在 Burp Suite 里点击 Send 时，你发出的文本结构严格分为四部分：

```
GET /index.php?id=1 HTTP/1.1
Host: node5.buuoj.cn:1145
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Cookie: PHPSESSID=abc123def456
Connection: close

```

（最后有**两个**连续的换行符 `\r\n\r\n` 表示请求结束）

1. 请求行 (Request Line)

如：`GET /index.php?id=1 HTTP/1.1`

包含三个元素，用空格隔开：`方法` `路径` `协议版本`

方法:

* `GET`：向服务器索要数据（参数通常放在 URL 的 `?` 后面）。
* `POST`：向服务器提交大量数据（参数放在后面的请求体里）。
* 其他等。

路径：要访问的靶标（比如 `/check.php`）。

版本： 通常是 `HTTP/1.1`，现在也有 `HTTP/2`。

2. 请求头 (Headers)：

包含了向服务器传递的数据，格式为 `Key: Value。`

* `Host：` 指定目标域名。多站点部署在同一台服务器时，靠这个区分。
* `User-Agent：` 你的浏览器身份。
* `Cookie：` 因为 HTTP 是无状态的，登录成功后服务器会给你发一段字符串，你以后的每次请求都在头里带上这个 Cookie，服务器就知道你是谁了。
* `Content-Type：` 告诉服务器你下面（请求体）发的数据是什么格式（是 JSON，还是普通的表单 `application/x-www-form-urlencoded`，还是带文件的混合表单 `multipart/form-data`）。

3.空行：

一个单独的 `\r\n`，告诉后端解析器，头信息到此结束，下面是正文。

4.请求体 (Body)：

如果是 `GET` 请求，这里通常是空的。如果是 `POST` 请求，你要传的数据（比如密码、上传的木马文件）全放在这里。

#### URL 与 HTTP 请求包的关系

URL（统一资源定位符）不仅是一个网址，它更像是一条能在目标服务器底层执行的指令。

URL 具体结构如下：

* 斜杠 `/`：代表着服务器上的目录层级（Path）。

当你在浏览器请求 `http://node5.buuoj.cn:1145/` 时，其实是在请求目标服务器 Web 根目录（比如 `/var/www/html/`）下的默认首页（通常是 `index.php` 或 `index.html`）。

* 问号 `?`：后面的内容全部是传给脚本的参数。

在终端里：`./check.php username=admin password=123`

在 Web 中：`/check.php?username=admin&password=123`

我们在浏览器输入一个 URL 并回车时，浏览器在底层会为我们打包一个 HTTP GET 请求。

不过 URL 只提供一个靶标，而 GET 请求还包含 cookie 一类的数据。

比如当我们键入一个 URL：`http://node5.buuoj.cn:81/check.php?id=1`。

实际打包的 HTTP GET 请求却是如下的：

```
GET /check.php?id=1 HTTP/1.1    <-- URL 的后半部分（路径和参数）
Host: node5.buuoj.cn:81         <-- URL 的前半部分（域名和端口）
User-Agent: Mozilla/5.0 ...     <-- 这些是 HTTP 请求独有的，URL 里没有
Accept: text/html ...
Cookie: session=xyz ...         <-- 你的身份凭证，URL 里没有

```

### HTTP 响应包 (Response) 基本结构：

```
HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Type: text/html; charset=UTF-8
Set-Cookie: PHPSESSID=xyz789; path=/

<html>
<body>Welcome to the admin panel...</body>
</html>
```

1. 状态行 (Status Line)：

`HTTP/1.1 200 OK`

包含：`协议版本` `状态码` `状态描述`。

状态码类似于程序的 Exit Status：

* 2xx (成功)： 最常见的是 `200 OK`，表示你要的东西我给你了，或者你的指令执行成功了。
* 3xx (重定向)： 比如 `302 Found`。服务器告诉你：“东西不在我这，你去另一个 URL 找”。
* 4xx (客户端错误)：
  * `403 Forbidden`：权限不够，禁止访问（找到后台但进不去）。
  * `404 Not Found`：你请求的路径不存在。
* 5xx (服务端错误)： 比如 `500 Internal Server Error`。

2. 响应头 (Response Headers)

* Server： 暴露了服务器用的什么软件（如 Apache, Nginx）及其版本。红队拿到这个版本号，就可以直接去搜索对应的已知 CVE 漏洞。
* Set-Cookie： 服务器给你下发 cookie 的地方，要求你的浏览器保存下来。

3. 响应体 (Body)

在浏览器里看到的网页源代码（HTML/JS/CSS），或者是下载的文件内容。

## PHP 基础

PHP 全称是 PHP: Hypertext Preprocessor（超文本预处理器），是一种广泛使用的开源服务器端脚本语言。

一个网页：

* HTML / CSS（前端）

* JavaScript（前端交互）

* PHP 等（后端逻辑）

PHP 等后端代码只在服务器端运行，客户端不可见。

### 基本语法

所有 PHP 代码都必须包裹在 `<?php` 和 `?>` 之间执行，Web 服务器只会把这其中的内容当代码执行。

* 变量声明：所有的变量前面必须加 `$`。
* 结束符：`;`。

在 PHP 中，**用户的输入被打包在几个系统自带的超全局变量里：**

* `$_GET`： 接收 URL 问号 ? 后面的参数。比如你请求 `/?cmd=ls`，PHP 里 `$_GET['cmd']` 的值就是 `"ls"`。
* `$_POST`： 接收 HTTP 请求体（Body）里的数据。常用于登录框提交的账号密码。
* `$_COOKIE`： 接收浏览器本地存储的凭据。

## SQL 注入

SQL 全称是 Structured Query Language（结构化查询语言）。它是一门专门用来与关系型数据库（比如 MySQL、Oracle、SQL Server）进行沟通和操作的编程语言。

可以将 SQL 简单化理解为数据库的“shell 命令”，只要向数据库发送符合 SQL 语法的指令，就可以对里面的数据进行任意的增删改查。

SQL 有四大核心动作：

* SELECT：查，从庞大的数据库中提取你需要的信息。

* INSERT：加，向数据表里插入一行全新的数据。

* UPDATE：改，修改表里已经存在的数据。这非常像 pwn 中的利用 Use-After-Free 或堆溢出漏洞，去精准覆写某个已被分配的堆块里的关键数据（例如，将自己账号在数据库里的权限字段从普通用户强制改为 admin）。

* DELETE：删，删除表里的一行数据。

现代的 web 应用程序作用就是**接收用户在浏览器发送的 HTTP 数据包，把里面的参数翻译成 SQL 语句，然后发送给后台数据库执行，最后把数据库返回的数据打包成网页形式包装给用户。**

**Web 中的 SQL 注入，即：越权将用户提交的数据当成了指令去执行，从而劫持了数据库的查询逻辑。**

### 攻击原理

比如我们如果有一个登录网页，其后台程序的代码逻辑如下：

`SELECT * FROM users WHERE username = ' $user_input ' AND password = ' $password_input '`

大概意思就是从 `users` 这个数据表中查询 username 等于你输入的 user，password 等于你输入的 password 的账户。

如果我们在输入框里输入 `admin' #`，代入到后台拼接后，SQL 语句就变成了：

`SELECT * FROM users WHERE username = 'admin' #' AND password = ...`

后面的都注释掉了，也就成了从 `users` 这个数据表中查询 username 等于 admin 的账户。

**注意不同的数据库，支持的注释符号不同，比如 `#` 是 MySQL 专属，`-- `（双短线 + 空格）支持几乎所有主流数据库（MySQL, PostgreSQL, MSSQL, Oracle 等）**

#### 例题 1：[极客大挑战 2019]EasySQL

[BUU CTF 题目链接](https://buuoj.cn/challenges#[%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98%202019]EasySQL)

首先点进去是一个登录页面，拿 Burp Suite 拦截一下，然后得到一个 HTTP POST 请求。

比如 `check.php?username=test&password=123`。·

对这个右键扫描一下，发现 SQL 漏洞。

尝试在 username 写个一个 `admin'#`，没过，证明 user 这个数据表里没有 admin，构造一个永真式 1=1，发送 `admin' or '1=1'#`。

## PHP 伪协议

当 Web 开发者想要在代码里读取文件时，通常会用到 `include()` 或 `file_get_contents()` 这类文件包含函数。

比如：

```
$file = $_GET['page'];
include($file);
```

那么我们在 url 后面加上 `?page=index.php`（如果根目录下存在 `index.php` 该文件），那么就会返回 index.php 执行后的结果。

1. `file://` 读本地文件。

读取服务器本地的绝对路径文件。

如 `?page=file:///etc/passwd` 就是读取服务器端 /etc/passwd 的文件。

2. `php://filter`

相当于 `cat index.php | base64`。

如 `?page=php://filter/read=convert.base64-encode/resource=index.php` 会把 index.php 的代码转换成 base64，然后再打印出来。


3.`php://input`

这个伪协议的作用是读取 HTTP 请求体（Body）里的原始 POST 数据。


### 例题 1：[ACTF2020 新生赛]Include

[BUU CTF 题目链接](https://buuoj.cn/challenges#[ACTF2020%20%E6%96%B0%E7%94%9F%E8%B5%9B]Include)

用 php://filter 把 index.php 的代码转换成 base64。

### 例题 2：[BJDCTF2020]ZJCTF，不过如此

[BUU CTF 题目链接](https://buuoj.cn/challenges#[BJDCTF2020]ZJCTF%EF%BC%8C%E4%B8%8D%E8%BF%87%E5%A6%82%E6%AD%A4)

