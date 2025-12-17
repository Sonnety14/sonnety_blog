---
title: "Hugo+Github Pages博客搭建记录"
description: "可能持续更新（？）"
date: 2025-12-17T00:00:00+08:00
image: mkblog.png
math: true
license: 
hidden: false
comments: true
draft: false
categories:
    - misc
tags:
    - 闲话
---
# 备份 blog

在电脑上特定文件夹右键，`Open Git Bash here`。

输入 `https://github.com/Sonnety14/sonnety_blog`，`--recursive` 会自动把博客源码 + 主题源码 全部拉下来。

以后再更新博客，直接在该文件夹运行 `git pull`。

# upd on 25/12/17 搭建博客

[推歌:【重音テト/中字】平成【しぜんすい】](https://www.bilibili.com/video/BV1oPSEBKExA/?spm_id_from=333.1007.top_right_bar_window_custom_collection.content.click&vd_source=69aa8bfd2f389eec2562a6757236f432)

由于搭完完全不想写博客，所以直接让 gemini 生成了。

## 修改 hugo.yaml
 * 基本信息：修改了 title、copyright、languageCode (设为 zh-cn)。
 * 评论系统 (Disqus)：
   * 在 hugo.yaml 中配置了 Disqus Shortname。
   * 手动修改了 layouts/partials/disqus.html 以适配 Universal Code。
 * 数学公式 (LaTeX)：
   * 全局开启 math: true。
   * 修改 markup 配置，添加了对行内公式 $ ... $ 的支持。
 * 侧边栏链接：修改 menu.social，将 GitHub 图标指向了自己的主页，移除了无关链接。
 * Favicon (网页图标)：
   * 图片位置：static/img/favicon.png
   * 配置写法：favicon: /img/favicon.png (注意冒号后必须有空格)。
## 内容管理 (content/)
 * 普通文章：
   * 路径：content/post/文件夹名/index.md (必须叫 index.md)。
   * 图片：直接放在同级目录下，引用时直接写文件名（如 image: cover.png）。
 * 分类管理 (Categories)：
   * 关键点：文章 Front Matter 中的分类名（Key）必须与文件夹名一致。
   * 精美分类页：
     * 路径：content/categories/math/_index.md (注意是一个下划线)。
     * 配置：在 _index.md 中定义 title (显示名)、image (封面图) 和 description。
     * 避坑：不要随意设置 slug，容易导致路径冲突。
## 静态资源与路径逻辑
| 文件夹 | 用途 | 特点 | 引用路径示例 |
|---|---|---|---|
| assets/ | 存放源码/素材 | 给 Hugo 处理用的，不直接对外发布 | SCSS 文件放这里 |
| static/ | 存放成品资源 | 直接复制到网站根目录，路径绝对可靠 | /sonnety_blog/img/bg.jpg |
 * 背景图/全局图片：必须放在 static/img/ 下。
 * GitHub Pages 子目录陷阱：因为我的博客部署在 sonnety14.github.io/sonnety_blog/，所以在 CSS 中引用 static 图片时，必须加上仓库名：/sonnety_blog/img/bg.jpg。
## 界面美化 (custom.scss)
🤮杀软二次元🤮
 * 全屏背景图：
   * 使用了 background-image 配合 linear-gradient (线性渐变) 制作了半透明遮罩，防止背景太花看不清字。
   * 设置了 fixed 让背景固定不随滚动条移动。
 * 毛玻璃与卡片化：
   * 对 .article-wrapper 和 .widget (侧边栏) 应用了半透明背景 (rgba)。
   * 添加了圆角 (border-radius) 和轻微阴影，使界面看起来更加柔和、现代。
## 常见报错
 * YAML 格式严格：key: value 中间必须有空格！(曾导致 Actions 爆红)。
 * 文件名敏感：math.png 和 Math.png 是两张图；_index.md 和 index.md 用途完全不同。
 * 缓存顽固：修改 CSS 或图片后，如果网页没变化，记得 Ctrl + F5 强制刷新。
 * 关联逻辑：文章分类 (categories: [math]) -> 文件夹 (content/categories/math/) -> 配置文件 (_index.md)，三者必须对应。
