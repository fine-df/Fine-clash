# Fine-Clash

Automatic discovery, verification, scoring and publishing of public Clash/V2Ray nodes.

The workflow runs once per day. It searches recently updated, high-star GitHub repositories for public subscription sources, parses supported nodes, verifies them through Mihomo, tests Gemini and Google Play reachability, tracks node history, scores candidates and publishes two generated subscription files.

Clash subscription:
https://raw.githubusercontent.com/fine-df/Fine-clash/refs/heads/main/live_clash.yaml

V2Ray subscription (Base64):
https://raw.githubusercontent.com/fine-df/Fine-clash/refs/heads/main/live_v2ray.txt

The generated Clash rules default to China direct and proxy for remaining traffic.

A node is published only when both Gemini and Google Play checks pass and the total score reaches the configured threshold. Node longevity is measured from repeated observations, not from repository age.

The cleanliness score is a network-level heuristic based on exit-IP metadata and Google challenge signals. It is not a guarantee of account-level or device-level access.

If a run finds fewer than the required number of qualifying nodes, the previous published subscriptions are preserved while history and the run report are updated. The Clash subscription keeps the legacy root-level path live_clash.yaml for client compatibility.

