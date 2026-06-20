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
        "an attempt that reached on_connected must not be reported as tcp_not_connected",
    )

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        marker_path = Path(handle.name)
        handle.write("logcat.txt:1: connection(0x1) mtproxy_startup socket_connect_start ipv6=0 state=0\n")
        handle.write("logcat.txt:2: connection(0x1) mtproxy_startup on_connected tls=0\n")
        handle.write(
            "logcat.txt:3: connection(0x2) mtproxy_startup connect_start proxy_state=10 secret_kind=ee "
            "is_faketls=1 domain_len=17 profile=android_chrome address=203.0.113.10 port=443\n"
        )
        handle.write("logcat.txt:4: connection(0x2) mtproxy_startup socket_connect_start ipv6=0 state=10\n")
        handle.write("logcat.txt:5: connection(0x2) mtproxy_startup socket_connected elapsed=90\n")
        handle.write("logcat.txt:6: connection(0x2) mtproxy_startup client_hello_sent bytes=1897\n")
        handle.write(
            "logcat.txt:7: connection(0x2) mtproxy_startup admission_freeze_detected "
            "key=blocked.example:443:cdn.example elapsed=4500\n"
        )
        handle.write("logcat.txt:8: connection(0x2) mtproxy_startup server_hello_timeout_close elapsed=4500\n")
        handle.write(
            "logcat.txt:9: connection(0x2) mtproxy_startup connect_start proxy_state=10 secret_kind=ee "
            "is_faketls=1 domain_len=17 profile=android_chrome address=203.0.113.10 port=443\n"
        )
        handle.write("logcat.txt:10: connection(0x2) mtproxy_startup socket_connect_start ipv6=0 state=10\n")
        handle.write("logcat.txt:11: connection(0x2) mtproxy_startup socket_connected elapsed=80\n")
        handle.write("logcat.txt:12: connection(0x2) mtproxy_startup client_hello_sent bytes=1897\n")
        handle.write("logcat.txt:13: connection(0x2) mtproxy_startup server_hello_hmac_ok bytes=2219 len1=1210 len2=993 flight=993 extra=0\n")
        handle.write("logcat.txt:14: connection(0x2) mtproxy_startup on_connected tls=1\n")
        handle.write("logcat.txt:15: connection(0x2) mtproxy_startup first_tls_app_recv payload=105\n")
        handle.write(
            "logcat.txt:16: proxy_check_start state=ping_sent ping_id=1 request_token=1 "
            "address=dead.example:443 connection_num=0\n"
        )
        handle.write("logcat.txt:17: proxy_check_connection_closed close_reason=2 ping_id=1 request_token=1 connection_num=0 state=1\n")
        handle.write(
            "logcat.txt:18: proxy_check_finish result=fail reason=connection_closed request_found=1 "
            "ping_id=1 address=dead.example:443 connection_num=0 state=finished\n"
        )
        handle.write(
            "logcat.txt:19: proxy_check_start state=ping_sent ping_id=2 request_token=2 "
            "address=frozen.example:443 connection_num=0\n"
        )
        handle.write("logcat.txt:20: proxy_check_socket_connected ping_id=2 request_token=2 connection_num=0 connection_token=2\n")
        handle.write("logcat.txt:21: proxy_check_connection_closed close_reason=2 ping_id=2 request_token=2 connection_num=0 state=1\n")
        handle.write(
            "logcat.txt:22: proxy_check_finish result=fail reason=connection_closed request_found=1 "
            "ping_id=2 address=frozen.example:443 connection_num=0 state=finished\n"
        )
        handle.write(
            "logcat.txt:23: proxy_check_start state=ping_sent ping_id=3 request_token=3 "
            "address=ok.example:443 connection_num=0\n"
        )
        handle.write("logcat.txt:24: proxy_check_socket_connected ping_id=3 request_token=3 connection_num=0 connection_token=3\n")
        handle.write(
            "logcat.txt:25: proxy_check_finish result=ok reason=pong request_found=1 "
            "ping_id=3 address=ok.example:443 connection_num=0 state=finished\n"
        )
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
        "tcp_not_connected: 1" not in result.stdout,
        "analyzer must not classify on_connected attempts as TCP failures",
    )
    require(
        "client_hello_sent_no_server_hello: 1" in result.stdout,
        "analyzer must classify a connected ClientHello timeout as a pre-ServerHello failure",
    )
    require(
        "blocked.example:443 client_hello_sent_no_server_hello: 1" in result.stdout,
        "analyzer must summarize FakeTLS phase verdicts by endpoint",
    )
    require(
        "dead.example:443 fail:tcp_not_connected close_reason=2: 1" in result.stdout,
        "proxy-check without socket_connected must be visible as a network/TCP-layer failure",
    )
    require(
        "frozen.example:443 fail:tcp_connected_no_pong close_reason=2: 1" in result.stdout,
        "proxy-check with TCP but without pong must be visible as a post-TCP no-response failure",
    )
    require(
        "ok.example:443 ok:pong: 1" in result.stdout,
        "proxy-check pong success must be visible per endpoint",
    )

    print("MTProxy analyzer guard passed.")


if __name__ == "__main__":
    main()
