## 前言

使用环境 ：`wsl kali linux`。

本文集中介绍 `seccomp` 沙箱与 orw 相关题型知识。

## seccomp 沙箱

全称名为 `secure computing mode`，其是 linux 内核提供的一种安全机制，它的作用是：

**设定并检查一种 syscall 是否合法**

比如在 pwn 中，就可以通过 seccomp 沙箱，禁止调用  `execve('/bin/sh',,)`。

### seccomp 沙箱模式

1.strict mode

严格模式（白名单），只允许少数的 syscall 执行。

设置方式类似：

`prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);`

2.filter mode

过滤模式，相比严格模式更加灵活。黑名单。

设置方式类似：

`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);`

或者用 `libseccomp`：

```
v1 = seccomp_init(0);
seccomp_rule_add(v1, 2147418112, 0, 0);
seccomp_rule_add(v1, 2147418112, 1, 0);
seccomp_rule_add(v1, 2147418112, 2, 0);
seccomp_rule_add(v1, 2147418112, 60, 0);
return seccomp_load(v1);
```

### 如何使用 libseccomp 设置一个 seccomp 沙箱

1.安装开发库

`sudo apt install -y libseccomp-dev gcc`

2.一个简单的 seccomp 程序

这个程序只允许：

```
read
write
open
exit
exit_group
```

写 `sandbox.c`：

```
#include <seccomp.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>

void sandbox() {
    scmp_filter_ctx ctx;

    // 默认动作：不符合规则的 syscall 全部杀掉
    ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        perror("seccomp_init");
        _exit(1);
    }

    // 允许 read
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);

    // 允许 write
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);

    // 允许 open
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);

    // 允许 exit
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);

    // 允许 exit_group
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    // 加载规则
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        _exit(1);
    }

    seccomp_release(ctx);
}

int main() {
    sandbox();

    // 以下具体功能实现
}
```

编译： `gcc sandbox.c -o sandbox -lseccomp`。

（`-lseccomp` 指链接 seccomp 库）

### seccomp 其他规则

上面程序的规则是 `SCMP_ACT_KILL`，也就是所有不符合条件的 syscall 直接杀程序。

我们也可以改为 `SCMP_ACT_ERRNO(1)`，也就是不符合条件的 syscall 不会直接杀程序，而是返回 `EPERM`，调试更加友好。

### seccomp 限制 syscall 参数

seccomp 不仅可以限制 syscall 的 rax，或者 32 位中的 “syscall 类型”，还可以进一步实现参数的控制与限制。

比如，允许 `write(1, buf, size);`，但是不允许 `write(2, buf, size);`，可以这样写：

```
seccomp_rule_add(
    ctx,
    SCMP_ACT_ALLOW,
    SCMP_SYS(write),
    1,    // 有一个限制条件
    SCMP_A0(SCMP_CMP_EQ, 1)  // 限制 fd 必须为 1
);
```

但是 seccomp 不能检查其指针指向的内存内容。

比如说 `write(1, buf, size);`，我们可以限制其只能输出 buf1，假设 buf1 的地址是 `0x404080`，我们可以这样写：

 `SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)buf1)    // buf == buf1`
