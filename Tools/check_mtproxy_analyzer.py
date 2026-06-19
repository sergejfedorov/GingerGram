#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import tempfile

from analyze_mtproxy_markers import Attempt


ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "Tools/analyze_mtproxy_markers.py"


def require(condition, message):
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        sys.exit(1)


def main():
    attempt = Attempt(key="synthetic")
    attempt.add(1, "connection(0x1) mtproxy_startup socket_connect_start ipv6=0 state=0")
    attempt.add(2, "connection(0x1) mtproxy_startup on_connected tls=0")
    require(
        attempt.verdict() == "connected_without_socket_connected_marker",
        "an attempt that reached on_connected must not be reported as tcp_not_connected_or_not_reached",
    )

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        marker_path = Path(handle.name)
        handle.write("logcat.txt:1: connection(0x1) mtproxy_startup socket_connect_start ipv6=0 state=0\n")
        handle.write("logcat.txt:2: connection(0x1) mtproxy_startup on_connected tls=0\n")
    try:
        result = subprocess.run(
            [sys.executable, str(ANALYZER), str(marker_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    finally:
        marker_path.unlink(missing_ok=True)

    require(result.returncode == 0, result.stderr.strip() or "analyzer exited with failure")
    require(
        "connected_without_socket_connected_marker: 1" in result.stdout,
        "analyzer summary must expose connected attempts that are missing the socket_connected marker",
    )
    require(
        "tcp_not_connected_or_not_reached: 1" not in result.stdout,
        "analyzer must not classify on_connected attempts as TCP failures",
    )

    print("MTProxy analyzer guard passed.")


if __name__ == "__main__":
    main()
