---
title: "cve-2025-55182 初解"
description: "初衷疑似是为了完成导论作业，顺便学一下，如有错误请指出"
date: 2026-01-01T00:00:00+08:00
image: 55182.jpg
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

特别鸣谢：

* Chill With You，感谢聪音与我共同度过学习时间。

<img width="1277" height="759" alt="image" src="https://github.com/user-attachments/assets/3edfbc09-e974-4ced-a1ca-f65d753a5743" />

* Weedy

<img width="999" height="395" alt="image" src="https://github.com/user-attachments/assets/dfd3b6fd-3bfe-4025-98ce-4ce530e6f5d4" />

初衷是为了完成导论作业，由于本人暂时没有什么想法去学 Next.js 或者搭建什么服务器，所以仅为“初解”参考。

---

## 选题背景与现实需求

导论作业板块硬性要求内容，略。

## 技术起源与演进逻辑

### 背景：Vercel 的商业阳谋

在 2024 年底，万众期待的 React 19 <span id="jump5"><sup>[<a href="#ref5">5</a>]</sup></span>发布，其中重磅更新了 **React Server Components(RSC)**，一个全新的后端渲染机制<span id="jump6"><sup>[<a href="#ref6">6</a>]</sup></span>。

在 RSC 更新之前，React 组件主要在浏览器里运行。服务器把代码发给浏览器，浏览器自己渲染页面。

RSC 更新后，**React 组件可以直接在服务器上运行**，生成好 HTML 再发给浏览器。

其意味着以下两点：

* 从此，前端不再只是渲染界面的，前端代码现在**需要一个强大的服务器环境(Node.js)来支撑**才能运行。
* 前端和后端的边界被打破，让数据流自由穿梭。

对于当今世界最受欢迎的前端框架，这是一个重要的里程碑，这意味在 Vercel 公司的推动下，React 彻底押注 **Server Side Rendering(SSR)** 的技术路线。

同时，Vercel 推出的开源的 Next.js 框架<span id="jump7"><sup>[<a href="#ref7">7</a>]</sup></span>是目前对 RSC 支持最完美、最好用的框架，意味着 **如果你想用 React 的新特性，最简单的办法就是用 Next.js** 。

然而 Next.js 很复杂，自己买服务器部署很麻烦，容易报错且维护成本高，所以 **Vercel 云服务器托管服务应运而生**。

结果最终就形成了 Vercel 公司推销云服务的战略：

**开发者为了用 React 新特性 -> 不得不学 Next.js -> 为了省事不得不买 Vercel 的云服务。**

Vercel 公司通过 React 大搞 SSR 给后端引流，然后用 Next.js 框架做壳，给自家云服务器引流，整个战略一气呵成。

通过让前端开发变得更依赖服务端，他们成功地将原本廉价的静态网页托管需求，转化为了昂贵的云计算服务需求，从而确立了 Vercel 在前端基础设施领域的霸主地位。

### cve-2025-55182：不要相信前端的话

以上提到：

> （ RSC 更新意味着）前端和后端的边界被打破，让数据流自由穿梭。

为了让前后端协同工作，Next.js/React 需要把复杂的数据对象（如 React 组件），在服务器（Node.js）和浏览器（你的电脑）之前来回传输。

而 **“序列化”和“反序列化”是实现“前后端数据传输”的唯一技术手段**。

* 序列化（从服务器发送至浏览器）：把复杂的内存对象变成一串文本字符串。
  * 即把内存里的“JavaScript 对象”变成“JSON 字符串”或“React Flight 协议字符串”的过程。
* 反序列化（浏览器端接收）：把收到的文本字符串变回内存里可用的对象。
  * 即把收到的“字符串”重新变回内存里的“JavaScript 对象”的过程。

那么攻击者就可以通过构造恶意的序列化 Payload，在服务端**反序列化过程中**通过三个关键步骤实现代码执行：

1. 原型链遍历与构造函数获取

* 机制：React Flight 协议允许客户端通过类似 `$id:key1:key2` 的引用语法，在反序列化时动态访问对象的嵌套属性。
  * React Flight 协议的**初衷是让服务器能灵活地指向模块中的特定组件或者复用已传输数据的子属性。**
* 缺陷：在漏洞修复前，解析逻辑（`getOutlinedModel` 函数）直接根据提供的路径键名读取属性，未检查该属性是否属于对象自身。
  * 即 **React 仅仅实现了‘根据路径查属性’的功能，却忘记了限制查找的范围。**
* 利用：攻击者构造如 `$1:then:constructor` 的路径。在 JavaScript 中，几乎所有对象的原型链最终都能指向 `Function` 构造函数（例如通过 `Array.prototype.constructor`）。利用这一缺陷，攻击者获取了 JavaScript 的 `Function` 构造器引用，这等同于获取了动态执行任意代码的能力。

2. 上下文劫持与伪造 Chunk (Context Hijacking)

* 机制：在 React 的内部实现中，每个数据块（Chunk）对象上都挂载了一个 `_response` 属性，该属性包含了全局的响应上下文（如 `_formData`，用于处理文件上传等数据）。
  * 通常，Chunk（数据块）只负责传递数据（如 `{name: "张三"}`）。虽然 Chunk 对象内部有一个管理员工具箱 `_response`（用来加载文件等），但普通数据看不见也摸不着这个工具箱。
* 缺陷：协议支持 `$@` 语法，允许直接引用 Chunk 实例本身（而不仅仅是其包含的值）。
* 利用：攻击者构造了一个 **“自引用”** 的 Payload。通过 `$@` 语法，攻击者在序列化数据中直接操作了 Chunk 实例，并覆盖了其内部的 `_response` 属性。攻击者注入了一个伪造的 `_response` 对象，其中包含恶意的 `_formData` 和 `_prefix`。
  * 例如：攻击者创建了 Chunk 1，内容是 `$@0`（引用 Chunk 0 的对象实例）。
  * Chunk 0 引用 Chunk 1。
  * 形成 `Chunk0 -> Chunk1 -> Chunk0 (实例)` 的闭环，得到 Chunk 0 的对象实例。

3. 恶意函数构造与自动触发 (Execution Trigger)

* 机制：
  * React 的反序列化逻辑（`reviveModel`）在处理 `$B`（Blob/文件引用）类型时，会调用 `chunk._response._formData.get(key)` 来获取数据。
  * JavaScript 的 `await` 操作符会自动执行 Thenable 对象（即拥有 `.then` 方法的对象）。
* 利用：
  * 攻击者将上一步伪造的 `_formData.get` 方法指向第一步获取的 `Function` 构造器。
  * 当解析器处理 `$B` 引用时，实际上执行了 `Function("恶意代码字符串")`，从而在内存中生成了一个包含恶意逻辑的匿名函数。
  * 攻击者将这个恶意函数赋值给某个对象的 `then` 属性，将其伪装成一个 Promise。
  * 当 React 框架尝试 `await` 这个对象时，恶意函数被自动执行，完成 RCE。

 总结：这个漏洞之所以成立，根本原因就在于：
 
 **服务端（React Server）放弃了自己的判断力，把“怎么执行”、“用什么环境执行”的控制权，全盘交给了客户端（前端/攻击者）传来的数据。**

### 漏洞的修复：艰难却无意义的混淆

这个漏洞不仅严重，而且很容易被复现。（这也是它能被评为满分漏洞的原因）

幸运的是，这个漏洞由  lachlan2k 发现，并且负责任地上报给了 React 团队。

不幸的是，上文曾提到 React 是开源的，也就是说，React 团队对的任何补丁的源代码都是可见的，留给 React 团队的是个两难选择：

* 偷偷发布补丁：难以保证补丁的安装率。
* 全世界通告补丁：黑客通过解析补丁，比用户更先发现并利用漏洞。

所以 React 团队为了延缓黑客的速度，给用户时间打好补丁，他们在 2025 年 12 月 3 日，仅发布了通告和补丁<span id="jump8"><sup>[<a href="#ref8">8</a>]</sup></span>，**没有解释任何技术细节**。

React 团队还在补丁内**混入了将近 1000 行的无意义其他代码**，就是为了让人更难发现漏洞的源头。

实际有效修补手段如下：

1. 阻断原型链访问
 
即在访问对象属性之前，强制增加 `hasOwnProperty.call(value, key)` 检查。

2. 隔离上下文环境

重构代码，从 Chunk 对象（现更名为 `ReactPromise`）中彻底移除了 `_response` 属性。

### 漏洞后续影响：Cloudflare 还有高手

互联网笑传之 Cloudflare continue boom。

本来作为一个基建服务商，React 一个前端框架出漏洞和 Cloudflare 没什么关系。

而且，Cloudflare 还很骄傲地在 React 补丁发布同日，发布了自家的防火墙服务 WAF 对该漏洞的防护<span id="jump9"><sup>[<a href="#ref9">9</a>]</sup></span>，蹭上了热度。

而 WAF 的最大 proxy 缓存是 `128KB`，鉴于用上 RSC 的人基本都是 Next.js 用户，而 Next.js 的上限是 `1MB`，所以 Cloudflare 也决定将其升至 `1MB`，以保证 Next.js 的流量都可以被 WAF 保护。

但是，给 WAF 做测试的工具**不支持 1MB 的数据体积**，于是团队**跳过了这个测试**。导致**触发了 FL1 引擎的代码 bug**。

**最终戏剧性地造成了半个互联网的瘫痪**。

（值得一提的是，FL1 引擎的代码 bug 十分低级且从未执行，如果没有这次的漏洞，直到 FL1 引擎彻底被 FL2 接管，这个bug 可能永远不被发现）

---

## 核心挑战与局限性分析

本次事件，无论是能力对不上野心的 React 和 Next.js 团队，还是草台班子 Cloudflare，都难逃其咎。

React 团队及其背后的 Vercel 公司一直在模糊前端和后端的界限，剑走偏锋，走极端 SSR 路线。

但是本质上，这种跨网络的通讯就是**一种远程过程调用(Remote Procedure Call,PRC)**。

RPC 本身不是十分新鲜的事物，**其安全流程早已有了很成熟的设计准则**<sup>[<a href="#ref10">10</a>]</sup>，比如说 schema 的设计、explicit 的定义、防止边界混淆的措施等等，

然而 Vercel 的开发团队却沿袭了前端的设计思路，把**前端“所见即所得”的作风带到了后端**。

---

## （以下内容为 gemini 生成续写，不代表本人观点）

## 潜在应用与未来机会

尽管 RSC 目前面临着安全架构与商业捆绑的争议，但作为一种打破前后端物理边界的渲染机制，结合当前数字化转型的趋势，其在未来 3-5 年内仍具有广泛的潜在应用场景。

* 极致轻量化的物联网（IoT）

在网络环境不稳定的发展中地区，或算力受限的嵌入式设备上，RSC 可以将复杂的计算逻辑与组件渲染完全滞留在服务端或边缘节点，终端仅接收并展示生成的 HTML 流。这将极大降低移动应用的电量消耗与启动延迟，实现“瘦客户端”的现代复兴。

* AI 生成式用户界面（Generative UI）的实时流式传输 

由于 RSC 运行在服务端，AI 模型可以直接生成 React 组件结构并流式传输至前端，无需前端预埋大量组件代码。这将推动“对话即界面”（Conversation as Interface）的交互范式变革，实现真正意义上的动态个性化应用。

等等。

---

## 个人见解与批判性思考

基于上述对技术原理、商业逻辑及安全漏洞的深度分析，针对 RSC 技术的前景与推广策略，提出以下批判性见解。

### RSC 根本上说依旧是是“颠覆性技术”

RSC 试图在保留现代组件化开发体验（DX）的同时，解决客户端渲染（CSR）带来的性能瓶颈与 SEO 难题。

它从架构层面统一了数据获取与视图渲染，这种 **“全栈组件化”** 的理念具有极高的工程价值，很大可能将成为未来 Web 开发的主流范式。

### RSC 的隐忧

正如 CVE-2025-55182 漏洞所揭示的，React 团队正在试图**用处理前端的思维去处理后端 RPC 通讯**。

Vercel 和 React 团队在推动 RSC 时，过分强调了“让数据流自由穿梭”的便利性，却忽视了**序列化协议本质上就是一种攻击面** 。

### 推广策略

当务之急是**建立强制性的“显式安全契约”**。

目前的 React Flight 协议过于“魔法”，允许客户端任意引用服务端对象。必须引入类似 gRPC 或 GraphQL 的 Schema 定义机制。

在编译阶段，强制开发者显式声明哪些组件是可序列化的，哪些属性是可远程访问的。**默认拒绝一切隐式调用**，将安全边界的定义权从运行时的动态解析回收至编译时的静态分析。

其次，必须剥离 Vercel 的商业捆绑，**制定开放的 RSC 运行时标准**，使其能够平等地运行在 Go、Rust 或标准的 Node.js 容器中，而不是依赖特定云厂商的黑盒基础设施。

综上，RSC 是这一代 Web 技术的变革者，但目前的实现方式充满了“大跃进”式的激进与草率。只有补齐了后端安全视角的短板，它才能真正承担起下一代互联网基建的重任。

---

## Reference

<div id="ref1">
[1] [React2Shell: CVE-2025-55182 Walkthrough](https://github.com/kavienanj/CVE-2025-55182)
</div>
<div id="ref2">
[2] [SWJTU-CTF-25 新秀杯 writeup](https://blog.rikka.top/p/swjtu-ctf-25-%E6%96%B0%E7%A7%80%E6%9D%AF-wp/#hello)
</div>
<div id="ref3">
[3] [NIST National Vulnerability Database. (2025). CVE-2025-55182: React Server Components Remote Code Execution Vulnerability.](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
</div>
<div id="ref4">
[4] [【深度解读React满分漏洞，一个前端框架怎么炸掉半个互联网【让编程再次伟大#50】】](https://www.bilibili.com/video/BV1uG2DBgEQ8/?share_source=copy_web&vd_source=3e52d00d108d8a38959267ded931cf69)
</div>
<div id="ref5">
[5] [React Team. (2024). React 19 Release Notes & Server Components Documentation. React Official Blog](https://react.dev/blog/2024/12/05/react-19)
</div>
<div id="ref6">
[6] [Abramov, D. (2023). RSC: From Theory to Practice. React Conf 2023 Proceedings.](https://www.reddit.com/r/reactjs/comments/13px834/dan_abramov_react_core_team_discuss_rsc_react/)
</div>
<div id="ref7">
[7] [Vercel. (2024). Next.js Documentation: Data Fetching and Streaming. Vercel Inc.]([https://react.dev/blog/2024/12/05/react-19](https://vercel.com/docs/frameworks/full-stack/nextjs)
</div>
<div id="ref8">
[8] [Lachlan2k. (2025). Analyzing the React Server Components Vulnerability. Tech Security Blog.](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
</div>
<div id="ref9">
[9] [Cloudflare. (2025). Post-Mortem: Global Service Interruption and WAF Interaction with Next.js Payloads. Cloudflare Blog.](https://blog.cloudflare.com/waf-rules-react-vulnerability/)
</div>
<div id="ref10">
[10] [Fielding, R. T. (2000). Architectural Styles and the Design of Network-based Software Architectures (Dissertation on REST, referenced for comparison with RPC).](https://roy.gbiv.com/pubs/dissertation/fielding_dissertation.pdf)
</div>
