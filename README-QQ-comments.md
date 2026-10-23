# Hugo / giscus 评论 → QQ

接入仓库：`Sonnety14/sonnety_blog`。QQ 接收人来自 sonnety.top 当前账号的已验证绑定。

1. 在仓库 Settings → General 开启 Discussions，安装 https://github.com/apps/giscus ，只授权评论仓库。
2. 打开 https://giscus.app/zh-CN ，选择此仓库与讨论分类（建议 Announcements），复制 repository ID、category ID 到网站接入表单。
3. 把 `.github/workflows/qq-comments.yml` 放入**存放评论的仓库默认分支**。如果评论仓库与 Hugo 仓库不同，工作流放评论仓库，Hugo 配置放博客仓库。
4. 在仓库 Settings → Secrets and variables → Actions → New repository secret 创建 `SONNETY_COMMENT_SECRET`，值为 sonnety.top 创建接入时显示的密钥。密钥只显示一次；遗失后在网站重置并更新 Secret。不要把它写入 HTML、Hugo 配置或提交到 Git。
5. 把 `sonnety-comments.yaml` 中 `params.comments` 合并到 Hugo Stack 的 `hugo.yaml`（替换原评论块，别重复 params）。或构建时使用 `hugo --config hugo.yaml,sonnety-comments.yaml`。生成的文件是合法 YAML 的 JSON 形式。其他 Hugo 主题应把 giscus 官方脚本放到该主题的评论 partial 中，工作流不用改。
6. 推送并等待 GitHub Pages 构建完成。发表一条评论，在 Actions 查看 QQ comment notification；再到 sonnety.top → 账号设置 → 评论推送 查看接收/发送时间。

支持新 Discussion、Discussion 评论/回复（giscus）和 Issue 评论（utterances）；编辑、删除、表情反应不会通知，PR 评论会忽略。通知中的标题来自讨论标题，可能是文章路径。giscus 自动创建的 Bot 讨论框架会忽略，实际评论照常通知。评论仍保存在 GitHub；服务器仅临时排队通知，不复制公开评论数据库。

每账号每天最多 300 条通知、最多 100 条待发送。关闭某仓库通知会丢弃其待发送通知，重新开启不会补发关闭期间事件。失败消息会重试，成功后清除正文；待发送正文最多保留 7 天，去重记录 90 天。网络在“QQ 已发出、回执未送达”之间中断时可能重复一次（至少一次交付），不是严格恰好一次。

其他框架适配：可信服务端向配置内的 `/comments/hooks/{id}` POST JSON，Header 为 `Authorization: Bearer <密钥>`。结构为 `event_id, repository, author, title, body, url`。event_id 同一事件重试必须保持不变；目前链接只接受所配置 GitHub 仓库的 discussions/issues，非 GitHub 平台尚未提供适配器。不能把密钥嵌在浏览器代码里。

参考：https://giscus.app/zh-CN ，https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows
