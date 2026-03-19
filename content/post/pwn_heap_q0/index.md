
### babyheap_0ctf_2017

[题目链接](https://buuoj.cn/challenges#babyheap_0ctf_2017)

发现这个题有个菜单，显然的堆漏洞题目，但是它的 fill 没有检查 chunk 大小，所以显然可以堆溢出。

首先泄露 libc 基址，因为可以堆溢出，所以我们可以通过 溢出 chunk_0 修改 chunk_1 的 size 值，使 chunk_1 和 chunk_2 **表面上合并**，这会使它们被 free 时一起进 unsorted bins（双向链表，fd 指向 main_arena + 88）。

然而 free 函数是直接对着 chunk 的标号释放内存的，所以我们把 chunk_1 free 掉，这使 chunk_1 不可被打印，**但是 chunk_2 是可以打印**的**在 unsorted bins 的**数据。

这时我们通过 allocate 复活 chunk_1，让 fd 指针挪到 chunk_2 的 user_data 部分，这就可以打印出 chunk_2 的 fd 指针。

（要设 chunk_3 防止掉到 TOP chunk）
