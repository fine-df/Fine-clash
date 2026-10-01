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

