---
title: "CTF AI 本地化部署【白痴版】"
description: "白痴自用的 AI 本地化部署攻略，如有更好方案请私信教我谢谢喵。"
date: 2026-04-07T00:00:00+08:00
image: ctf_agent.jpeg
math: true
license: 
hidden: false
comments: true
draft: false
categories:
    - ctf
tags:
    - ctf
    - misc
---

## 前言

本人是 pwn 手，AI 本地化部署的主要需求是看懂伪代码（呜呜别说我菜）

然后本人配置是 `5070Ti Laptop 12GB 显存 + 32GB 内存 + Ryzen 9 9955HX3D`，所以选择了 `Qwen2.5-Coder-14B-Instruct`，模型文件约 9GB，加载进显存后大约占用 10GB 左右。

如果配置更高一点，或者说能接受高出显存的部分交给 cpu 计算，可以考虑 `Qwen2.5-Coder-32B-Instruct`，模型文件约 20GB，相比 14B 的轻量化版本，32B 模型的逻辑推演能力肯定高一点。

（不是 QWEN 软广）

## Windows 宿主机安装 Ollama 并下载模型

1.去官网下载 Windows 版 Ollama 并安装。

2.下载模型：

打开 PowerShell，运行：

```
ollama run qwen2.5-coder:14b
```

其会自动下载模型并运行。

## IDA 伪代码审计插件 Gepetto

Gepetto 本质上是一个 Python 脚本，它默认需要 openai 这个库来发送网络请求（Ollama 提供了与 OpenAI 完全兼容的本地 API）。

### 下载 openai 依赖

打开一个新的命令行（CMD 或 PowerShell），运行以下命令安装依赖：

```
pip install openai
```

（注：如果你的 IDA 使用的是独立的 Python 环境，请确保在这个特定环境下执行 pip install）

（注意 IDA 9.2 内部编译的 C++ 接口可能最高只兼容到 Python 3.11 或 3.12，无法兼容 3.14 的底层 API。）

（所以如果没有下载 [python 3.12](https://www.google.com/search?q=https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe) 以下版本，下载完毕后，要在 IDA 9.2 安装路径下找到 `idapyswitch.exe` 并运行，其会搜索当前你可绑定的 python 版本，选择 3.12 及以下版本）

### 下载 Gepetto

前往 Gepetto 的 GitHub 官方仓库：[JusticeRage/Gepetto](https://github.com/JusticeRage/Gepetto)

1.点击绿色的 Code 按钮，选择 Download ZIP。
2.解压下载的压缩包。里面有一个 `gepetto.py` 文件和一个 `gepetto` 文件夹。
3.将 `gepetto.py` 文件和整个 `gepetto` 文件夹，一起复制到你的 IDA 安装路径下的 `plugins` 文件夹。
（其余文件可以删掉）

### 配置 Gepetto 连接本地 Ollama

Gepetto 默认是连接 OpenAI 官方服务器的，我们需要修改它的配置文件，把请求“劫持”到你本地的 `127.0.0.1:11434`。

注意：喜欢“科学上网”的同学，记得设置 NO_PROXY 环境变量：

* 变量名: `NO_PROXY`

* 变量值: `localhost,127.0.0.1,::1`

即本地地址，不走代理。

随便用 IDA 开一个可执行文件，然后在 **`%APPDATA%\Hex-Rays\IDA Pro` 或 `IDA Professional 9.2\plugins\gepetto` 里找到 `gepetto.ini` 配置文件**

（都有就都改，都没有就自己创建一个）

改成如下内容：

```
[Gepetto]
model = qwen2.5-coder:14b
language = zh_CN

[OpenAI]
api_key = 123
base_url = http://127.0.0.1:11434/v1
```

（model 自己改）

然后在 models 目录下的 `openai.py`，在那些 `GPT_52_MODEL_NAME = "gpt-5.2"` 的附近，随便加上一行咱们的 AI 定义：

```
QWEN_MODEL_NAME = "qwen2.5-coder:14b"
```

（自己模型自己填）

再塞进默认列表 `_DEFAULT_OPENAI_MODELS = [`

```
_DEFAULT_OPENAI_MODELS = [
    QWEN_MODEL_NAME,   # <--- 加上这一行
    GPT_52_MODEL_NAME,
    ...
]
```

保存，重启 IDA。

### 设置中文 prompt

到现在，你应该可以右键一个函数的伪代码，然后让模型解释函数，但是生成的是英文的注释。

在 ida 目录下的 `handlers.py`，里面有一大串的提示词：

```
f"""
                You are a reverse-engineering assistant. Output plain text only (no Markdown, no code fences).
                - Locale: {locale}
                - Task: Summarize what the C function does and propose a clearer function name if one stands out.
                - Observations: Use any existing Gepetto-generated comments as hints but do not repeat them verbatim.
                - Response structure:
                    1. Brief explanation (2-4 sentences) covering purpose, key behaviours, and notable side effects.
                    2. Final line: "Proposed name: <name>" (use "(no change)" if you cannot recommend an improvement).

                ```C
                {decompiler_output}
                ```
```

可以在 `2.FINAL LINE` 下面另起一行，写上“请务必全程使用简体中文进行详细解释，包括所有的代码注释和逻辑分析”，模型即会用中文回答。

也可以加上：“如有可能存在的 CTF 漏洞，请以 "hint:……" 的形式给出。”

但是其实因为模型算力不太行，这个挺没啥必要的。
