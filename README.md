# Fine-Clash


Clash subscription:
https://raw.githubusercontent.com/fine-df/Fine-clash/refs/heads/main/live_clash.yaml

V2Ray subscription (Base64):
https://raw.githubusercontent.com/fine-df/Fine-clash/refs/heads/main/live_v2ray.txt

Mirror (jsDelivr):
https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@main/live_clash.yaml
https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@main/live_v2ray.txt


## 自动更新链路（无需人工干预）

```
GitHub Actions (cron 0 2,8,14,20 * * * UTC，即北京每天 10/16/22/04 点)
  └─ fine_clash.py  发现高星源 → 探测 → 评分 → live_clash.yaml
  └─ build_final.py 转路由器配置 → fine_final.yaml（PROXY=url-test 探测 gemini.google.com）
  └─ commit 到 main  ──►  jsDelivr CDN（缓存通常 1~20 分钟）
                                      │
小米路由器 ShellClash  ──►  /data/clash/fine_sync.sh（crontab 每 15 分钟）
                              └─ 拉 CDN 文件 → 护栏校验（url-test / ^proxies: / CrashCore -t）
                                 → 覆盖 /data/clash/yamls/config.yaml → 重启 CrashCore
```

- 节点池变化后，路由器最多 **~35 分钟**（CDN 缓存 ≤20 分钟 + 同步间隔 ≤15 分钟）自动生效。
- PROXY 组为 `url-test`，只在**能连上 gemini.google.com 的节点里**自动选延迟最小的，掉线即剔除。
- 装置保：CI 每次结束若距上次成功 >20 小时，会自己再触发一次 `workflow_dispatch`（防止 GitHub 冻结 schedule）。
- 直连源只有 `cdn.jsdelivr.net` 在路由器可用（raw.githubusercontent / gitclone.com / ghproxy 均不可达）。
