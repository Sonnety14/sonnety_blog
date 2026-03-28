---
title: "CTF-web 学习总结 0x00 版"
description: "边学边写的第 0 版本，如有错误请指出。"
date: 2026-03-28T00:00:00+08:00
image: ctf_web_0.png
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

比如 `check.php?username=test&password=123`。

对这个右键扫描一下，发现 SQL 漏洞。

尝试在 username 写个一个 `admin'#`，没过，证明 user 这个数据表里没有 admin，构造一个永真式 1=1，发送 `admin' or '1=1'#`。

### 例题 2
