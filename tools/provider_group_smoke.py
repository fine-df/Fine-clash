#!/usr/bin/env python3
"""Offline Mihomo provider->policy-group compatibility smoke test.

This intentionally uses a local HTTP provider fixture, so no real subscription
URL or node credentials are involved. It checks the exact Bitz/Fine-era pattern:
- select group with use: [provider]
- url-test group with include-all-providers: true
- GLOBAL select group with include-all: true
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen


NODE_NAME = "AUDIT-PROVIDER-NODE"


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


def http_json(url: str):
    with urlopen(Request(url, headers={"User-Agent": "Fine-Clash-Audit/1.0"}), timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


def run(binary: str, timeout_seconds: float = 15.0) -> dict:
    with tempfile.TemporaryDirectory(prefix="fine-mihomo-provider-audit-") as tmp:
        root = Path(tmp)
        provider = root / "provider.yaml"
        provider.write_text(
            f"""proxies:
  - name: {NODE_NAME}
    type: socks5
    server: 203.0.113.10
    port: 65500
    udp: true
""",
            encoding="utf-8",
        )

        server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        # SimpleHTTPRequestHandler serves the current process cwd, so use a tiny
        # one-shot directory change only inside this isolated test process.
        import os

        old_cwd = os.getcwd()
        os.chdir(root)
        try:
            provider_url = f"http://127.0.0.1:{server.server_port}/provider.yaml"
            config = root / "config.yaml"
            config.write_text(
                f"""mixed-port: 17890
allow-lan: false
mode: rule
log-level: error
external-controller: 127.0.0.1:19090
proxy-providers:
  BitzPool:
    type: http
    url: {provider_url}
    interval: 3600
proxy-groups:
  - name: GLOBAL
    type: select
    proxies:
      - DIRECT
    include-all: true
  - name: Bitz
    type: select
    proxies:
      - Bitz-Auto
    use:
      - BitzPool
  - name: Bitz-Auto
    type: url-test
    include-all-providers: true
    url: https://www.gstatic.com/generate_204
    interval: 300
    timeout: 5000
    lazy: false
rules:
  - MATCH,Bitz
""",
                encoding="utf-8",
            )

            proc = subprocess.Popen(
                [binary, "-d", str(root), "-f", str(config)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            started = time.monotonic()
            last_error = None
            try:
                while time.monotonic() - started < timeout_seconds:
                    if proc.poll() is not None:
                        output = (proc.stdout.read() if proc.stdout else "")[-4000:]
                        raise RuntimeError(f"Mihomo exited rc={proc.returncode}: {output}")
                    try:
                        version = http_json("http://127.0.0.1:19090/version")
                        break
                    except Exception as exc:
                        last_error = exc
                        time.sleep(0.2)
                else:
                    raise RuntimeError(f"controller not ready: {last_error}")

                checks = {}
                for group in ("Bitz", "Bitz-Auto", "GLOBAL"):
                    data = http_json(f"http://127.0.0.1:19090/proxies/{group}")
                    members = list(data.get("all") or [])
                    checks[group] = {
                        "members": members,
                        "contains_provider_node": NODE_NAME in members,
                    }

                return {
                    "version": version.get("version"),
                    "checks": checks,
                    "all_provider_group_checks_pass": all(
                        row["contains_provider_node"] for row in checks.values()
                    ),
                }
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                os.chdir(old_cwd)
                server.shutdown()
                server.server_close()
        finally:
            os.chdir(old_cwd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    result = run(args.binary)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
