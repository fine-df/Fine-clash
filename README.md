# Fine-Clash

Automatic discovery, verification, scoring and publishing of public Clash/V2Ray nodes.

The workflow runs once per day. It searches recently updated, high-star GitHub repositories for public subscription sources, parses supported nodes, verifies them through Mihomo, tests Gemini and Google Play reachability, tracks node history, scores candidates and publishes two generated subscription files.

Clash subscription:
https://raw.githubusercontent.com/fine-df/Fine-clash/refs/heads/main/live_clash.yaml

V2Ray subscription (Base64):
https://raw.githubusercontent.com/fine-df/Fine-clash/refs/heads/main/live_v2ray.txt

Mirror (jsDelivr):
https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@main/live_clash.yaml
https://cdn.jsdelivr.net/gh/fine-df/Fine-clash@main/live_v2ray.txt

> Note for mainland China: both `raw.githubusercontent.com` and `cdn.jsdelivr.net` are DNS-poisoned (resolving to fake IPs such as `28.0.0.x`). If your client reports "invalid subscription" (无效的订阅内容), the subscription domain is being resolved to a fake IP.

Client-specific remedies:

- **Clash / mihomo**: add `DOMAIN-SUFFIX,jsdelivr.net,PROXY` (and the raw GitHub domain) to your rules, or enable "update subscription via proxy".
- **v2rayN**: updating a subscription goes DIRECT by default and cannot reuse a local proxy port. Import the subscription as a local file instead — copy the mirrored URL to a local file, then add the subscription with address `file:///C:/path/to/live_v2ray.txt` and click *update current subscription (not via proxy)*. Alternatively, open the mirrored URL in a browser while the proxy is on and copy the text into *Servers -> import batch URLs from clipboard*.

The generated Clash rules default to China direct and proxy for remaining traffic. WeChat/Tencent routes are explicitly direct, and the generated Clash config also enables redir-host DNS with China DNS policies for Tencent/WeChat domains.

A node is published only when both Gemini and Google Play checks pass, the total score reaches the configured threshold, and the Shenzhen TCP latency gate passes. Node longevity is measured from repeated observations, not from repository age. Candidate verification and Shenzhen probes run concurrently to keep daily runs within the workflow timeout.

The cleanliness score is a network-level heuristic based on exit-IP metadata and Google challenge signals. It is not a guarantee of account-level or device-level access. WeChat compatibility is improved at the routing/DNS configuration layer, but actual device/client compatibility still depends on the local router or client DNS/TUN behavior and cannot be fully certified by a GitHub Actions runner.

If a run finds fewer than the required number of qualifying nodes, the previous published subscriptions are preserved while history and the run report are updated. The Clash subscription keeps the legacy root-level path live_clash.yaml for client compatibility.


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
