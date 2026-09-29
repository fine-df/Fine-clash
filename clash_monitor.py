name: Clash Gemini Monitor Agent

on:
  schedule:
    - cron: '0 */6 * * *' # 每 6 小时自动运行
  workflow_dispatch: # 支持手动点击触发

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Install Dependencies
        run: |
          pip install requests pyyaml

      - name: Install Mihomo (Clash Meta) Core
        run: |
          # 使用更稳定、仍在活跃维护的 Mihomo (Clash Meta) 核心
          curl -sSL -o mihomo.gz "https://github.com/MetaCubeX/mihomo/releases/download/v1.18.0/mihomo-linux-amd64-v1.18.0.gz" || wget -O mihomo.gz "https://github.com/MetaCubeX/mihomo/releases/download/v1.18.0/mihomo-linux-amd64-v1.18.0.gz"
          gunzip mihomo.gz
          sudo mv mihomo /usr/local/bin/clash
          sudo chmod +x /usr/local/bin/clash
          clash -v

      - name: Run Gemini Proxy Monitor Script
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: python clash_monitor.py

      - name: Commit & Push Verified Subscription
        run: |
          git config --local user.email "github-actions[bot]@users.noreply.github.com"
          git config --local user.name "github-actions[bot]"
          git add live_clash.yaml
          git commit -m "Auto update: Verified Gemini-accessible Clash nodes" || exit 0
          git push
