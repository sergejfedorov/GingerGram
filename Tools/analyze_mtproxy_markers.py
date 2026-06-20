#!/usr/bin/env python3
"""Summarize MTProxy FakeTLS lifecycle markers from collect_mtproxy_logs.ps1.

The analyzer is intentionally conservative: it does not try to prove DPI by
itself. It groups log markers by ConnectionSocket pointer and shows the exact
phase where each attempt stopped, so VPN/non-VPN captures can be compared.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


CONNECTION_RE = re.compile(r"connection\(([^)]+)\)")
PROFILE_RE = re.compile(r"profile selected=([a-z_]+)")
CONNECT_RE = re.compile(r"connect_start .*profile=([a-z_]+).*address=([^ ]+) port=([0-9]+)")
ADMISSION_KEY_RE = re.compile(r"admission_[a-z_]+ .*key=([^ ]+)")
DISCONNECT_RE = re.compile(
    r"mtproxy_disconnect reason=([-0-9]+) error=([-0-9]+) "
    r"proxy_state=([-0-9]+) tls_state=([-0-9]+) bytes_read=([0-9]+)"
)
PROXY_CHECK_RE = re.compile(r"proxy_check_([a-z_]+)")
PROXY_CHECK_SCHEDULER_RE = re.compile(r"proxy_check_scheduler ([a-z_]+)")
PROXY_CHECK_START_RE = re.compile(r"proxy_check_start .*ping_id=([0-9]+).*address=([^ ]+)")
PROXY_CHECK_SOCKET_RE = re.compile(r"proxy_check_socket_connected ping_id=([0-9]+)")
PROXY_CHECK_RESULT_RE = re.compile(r"proxy_check_finish result=([a-z]+) reason=([^ ]+)")
PROXY_CHECK_FINISH_RE = re.compile(r"proxy_check_finish result=([a-z]+) reason=([^ ]+).*ping_id=([0-9]+) address=([^ ]+)")
PROXY_CHECK_DIAGNOSTIC_RE = re.compile(r"proxy_check_finish .*diagnostic=([^ ]+)")
PROXY_CHECK_START_FAILED_RE = re.compile(r"proxy_check_start_failed reason=([^ ]+)")
PROXY_CHECK_CLOSE_RE = re.compile(r"proxy_check_connection_closed close_reason=([-0-9]+)")
PROXY_CHECK_CLOSE_WITH_PING_RE = re.compile(r"proxy_check_connection_closed close_reason=([-0-9]+) ping_id=([0-9]+)")
PROXY_CHECK_IGNORED_CLOSE_RE = re.compile(r"proxy_check_connection_closed_ignored close_reason=([-0-9]+)")
PROXY_ROTATION_RE = re.compile(r"proxy_rotation ([a-z_]+)")
ENDPOINT_RE = re.compile(r"endpoint=([^ ]+)")
SCHEDULER_LISTENERS_RE = re.compile(r"listeners=([0-9]+)")
SCHEDULER_FORCE_RE = re.compile(r"force=(true|false)")
SCHEDULER_RESULT_RE = re.compile(r"proxy_check_scheduler finish result=([a-z]+)")
SCHEDULER_APPLIED_RE = re.compile(r"time=([-0-9]+) applied_time=([-0-9]+) raw_time=([-0-9]+)")


@dataclass
class Attempt:
    key: str
    first_line: int = 0
    last_line: int = 0
    lines: list[str] = field(default_factory=list)
    events: Counter[str] = field(default_factory=Counter)
    profile: str = ""
    address: str = ""
    port: str = ""
    endpoint: str = ""
    proxy_key: str = ""
    disconnect: str = ""

    def add(self, line_no: int, text: str) -> None:
        if not self.first_line:
            self.first_line = line_no
        self.last_line = line_no
        self.lines.append(text)

        connect = CONNECT_RE.search(text)
        if connect:
            self.profile = connect.group(1)
            self.address = connect.group(2)
            self.port = connect.group(3)

        admission_key = ADMISSION_KEY_RE.search(text)
        if admission_key:
            self.proxy_key = admission_key.group(1)
            self.endpoint = endpoint_from_admission_key(self.proxy_key)

        profile = PROFILE_RE.search(text)
        if profile:
            self.profile = profile.group(1)

        disconnect = DISCONNECT_RE.search(text)
        if disconnect:
            self.disconnect = (
                f"reason={disconnect.group(1)} error={disconnect.group(2)} "
                f"proxy_state={disconnect.group(3)} tls_state={disconnect.group(4)} "
                f"bytes_read={disconnect.group(5)}"
            )

        event_map = {
            "connect_start": "connect_start",
            "socket_connect_start": "socket_connect_start",
            "socket_connected": "socket_connected",
            "client_hello_send_progress": "client_hello_send_progress",
            "client_hello_sent": "client_hello_sent",
            "server_hello_hmac_ok": "server_hello_hmac_ok",
            "server_hello_hmac_timeout": "server_hello_hmac_timeout",
            "server_hello_timeout_close": "server_hello_timeout_close",
            "TLS server hello hmac wait": "server_hello_hmac_wait",
            "admission_freeze_detected": "admission_freeze_detected",
            "on_connected": "on_connected",
            "first_tls_app_sent": "first_tls_app_sent",
            "first_tls_app_recv": "first_tls_app_recv",
            "tls_alert": "tls_alert",
            "recv_eof": "recv_eof",
            "EPOLLHUP": "epoll_hup",
            "EPOLLRDHUP": "epoll_rdhup",
            "socket error": "socket_error",
            "TLS response version mismatch": "tls_response_version_mismatch",
            "TLS response record type mismatch": "tls_response_record_type_mismatch",
        }
        for needle, event in event_map.items():
            if needle in text:
                self.events[event] += 1

    def verdict(self) -> str:
        has = self.events.__contains__
        if has("on_connected") and not has("socket_connected"):
            return "connected_without_socket_connected_marker"
        if not has("socket_connected"):
            return "tcp_not_connected"
        if not has("client_hello_sent"):
            return "connected_but_client_hello_not_fully_sent"
        if not has("server_hello_hmac_ok"):
            if has("server_hello_hmac_timeout") or has("server_hello_hmac_wait"):
                return "server_hello_hmac_mismatch"
            if has("server_hello_timeout_close") or has("admission_freeze_detected"):
                return "client_hello_sent_no_server_hello"
            if has("recv_eof"):
                return "peer_closed_after_client_hello"
            return "client_hello_sent_no_server_hello"
        if not has("on_connected"):
            return "hmac_ok_but_on_connected_not_reached"
        if has("first_tls_app_sent") and not has("first_tls_app_recv"):
            return "post_handshake_no_appdata"
        if has("first_tls_app_recv") and self.disconnect:
            return "dropped_after_appdata"
        if has("first_tls_app_recv"):
            return "ok"
        return "post_handshake_no_appdata"


def marker_text(line: str) -> tuple[int, str]:
    # collect_mtproxy_logs.ps1 writes: path:line_number: original log line
    match = re.match(r"^.*?:([0-9]+):\s*(.*)$", line.rstrip("\n"))
    if match:
        prefix = line[: match.start(1) - 1]
        if "/" not in prefix and "\\" not in prefix and not prefix.endswith((".txt", ".log")):
            return 0, line.rstrip("\n")
        return int(match.group(1)), match.group(2)
    return 0, line.rstrip("\n")


def endpoint_from_admission_key(proxy_key: str) -> str:
    match = re.match(r"^(.+):([0-9]+):.+$", proxy_key)
    if match:
        return f"{match.group(1)}:{match.group(2)}"
    return proxy_key


def is_connect_start(text: str) -> bool:
    return "mtproxy_startup connect_start " in text


def is_socket_connect_start(text: str) -> bool:
    return "mtproxy_startup socket_connect_start" in text


def load_attempts(path: Path) -> tuple[list[Attempt], list[str]]:
    attempts: dict[str, Attempt] = {}
    global_lines: list[str] = []
    sequence_by_key: defaultdict[str, int] = defaultdict(int)
    active_key_by_pointer: dict[str, str] = {}

    def new_attempt(pointer: str) -> Attempt:
        if pointer not in attempts and sequence_by_key[pointer] == 0:
            key = pointer
        else:
            sequence_by_key[pointer] += 1
            key = f"{pointer}#{sequence_by_key[pointer]}"
        attempt = Attempt(key=key)
        attempts[key] = attempt
        active_key_by_pointer[pointer] = key
        return attempt

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw.strip() == "No MTProxy markers found.":
            continue
        line_no, text = marker_text(raw)
        connection = CONNECTION_RE.search(text)
        if not connection:
            global_lines.append(text)
            continue

        pointer = connection.group(1)
        current_key = active_key_by_pointer.get(pointer)
        if is_connect_start(text):
            attempt = new_attempt(pointer)
        elif is_socket_connect_start(text):
            if current_key is None:
                attempt = new_attempt(pointer)
            else:
                current_attempt = attempts[current_key]
                if current_attempt.events["socket_connect_start"]:
                    attempt = new_attempt(pointer)
                else:
                    attempt = current_attempt
        elif current_key is None:
            attempt = new_attempt(pointer)
        else:
            attempt = attempts[current_key]
        attempt.add(line_no, text)

    return sorted(attempts.values(), key=lambda item: (item.first_line, item.key)), global_lines


def print_proxy_check_summary(lines: list[str]) -> None:
    native_events: Counter[str] = Counter()
    native_results: Counter[str] = Counter()
    native_endpoint_outcomes: Counter[str] = Counter()
    native_start_failures: Counter[str] = Counter()
    native_close_reasons: Counter[str] = Counter()
    native_ignored_close_reasons: Counter[str] = Counter()
    scheduler_events: Counter[str] = Counter()
    scheduler_endpoints: Counter[str] = Counter()
    scheduler_coalescing: Counter[str] = Counter()
    scheduler_listener_peaks: dict[str, int] = {}
    scheduler_force: Counter[str] = Counter()
    scheduler_results: Counter[str] = Counter()
    scheduler_preserved_connected: Counter[str] = Counter()
    scheduler_applied_split: Counter[str] = Counter()
    rotation_events: Counter[str] = Counter()
    proxy_checks: dict[str, dict[str, str | bool]] = {}

    for text in lines:
        rotation = PROXY_ROTATION_RE.search(text)
        if rotation:
            rotation_events[rotation.group(1)] += 1

        if "proxy_check_scheduler " in text:
            scheduler = PROXY_CHECK_SCHEDULER_RE.search(text)
            event = ""
            if scheduler:
                event = scheduler.group(1)
                scheduler_events[event] += 1
            endpoint = ENDPOINT_RE.search(text)
            if endpoint:
                endpoint_text = endpoint.group(1)
                scheduler_endpoints[endpoint_text] += 1
                listeners = SCHEDULER_LISTENERS_RE.search(text)
                if listeners:
                    scheduler_listener_peaks[endpoint_text] = max(
                        scheduler_listener_peaks.get(endpoint_text, 0),
                        int(listeners.group(1)),
                    )
                if event in {"attach_pending", "enqueue_now", "cancel_owner"}:
                    scheduler_coalescing[f"{event} endpoint={endpoint_text}"] += 1
            force = SCHEDULER_FORCE_RE.search(text)
            if force:
                scheduler_force[force.group(1)] += 1
            result = SCHEDULER_RESULT_RE.search(text)
            if result:
                scheduler_results[result.group(1)] += 1
                applied = SCHEDULER_APPLIED_RE.search(text)
                if applied and (applied.group(1) != applied.group(2) or applied.group(1) != applied.group(3)):
                    scheduler_applied_split[f"callback={applied.group(1)} applied={applied.group(2)} raw={applied.group(3)}"] += 1
            if event == "finish_keep_connected":
                endpoint = ENDPOINT_RE.search(text)
                scheduler_preserved_connected[endpoint.group(1) if endpoint else "unknown"] += 1
            continue

        native = PROXY_CHECK_RE.search(text)
        if native:
            native_events[native.group(1)] += 1
            start = PROXY_CHECK_START_RE.search(text)
            if start:
                proxy_checks[start.group(1)] = {
                    "endpoint": start.group(2),
                    "socket_connected": False,
                    "close_reason": "",
                }
            socket = PROXY_CHECK_SOCKET_RE.search(text)
            if socket:
                proxy_checks.setdefault(socket.group(1), {"endpoint": "unknown", "socket_connected": False, "close_reason": ""})[
                    "socket_connected"
                ] = True
            close_with_ping = PROXY_CHECK_CLOSE_WITH_PING_RE.search(text)
            if close_with_ping:
                proxy_checks.setdefault(close_with_ping.group(2), {"endpoint": "unknown", "socket_connected": False, "close_reason": ""})[
                    "close_reason"
                ] = close_with_ping.group(1)
            start_failed = PROXY_CHECK_START_FAILED_RE.search(text)
            if start_failed:
                native_start_failures[start_failed.group(1)] += 1
            result = PROXY_CHECK_RESULT_RE.search(text)
            if result:
                native_results[f"{result.group(1)}:{result.group(2)}"] += 1
            finish = PROXY_CHECK_FINISH_RE.search(text)
            if finish:
                result_text = finish.group(1)
                reason_text = finish.group(2)
                ping_id = finish.group(3)
                endpoint_text = finish.group(4)
                state = proxy_checks.setdefault(
                    ping_id,
                    {"endpoint": endpoint_text, "socket_connected": False, "close_reason": ""},
                )
                state["endpoint"] = endpoint_text
                close_reason = state.get("close_reason") or "none"
                if result_text == "ok":
                    outcome = f"{endpoint_text} ok:{reason_text}"
                elif (diagnostic := PROXY_CHECK_DIAGNOSTIC_RE.search(text)):
                    outcome = f"{endpoint_text} fail:{diagnostic.group(1)} close_reason={close_reason}"
                elif state.get("socket_connected"):
                    outcome = f"{endpoint_text} fail:tcp_connected_no_pong close_reason={close_reason}"
                else:
                    outcome = f"{endpoint_text} fail:tcp_not_connected close_reason={close_reason}"
                native_endpoint_outcomes[outcome] += 1
            close = PROXY_CHECK_CLOSE_RE.search(text)
            if close:
                native_close_reasons[close.group(1)] += 1
            ignored_close = PROXY_CHECK_IGNORED_CLOSE_RE.search(text)
            if ignored_close:
                native_ignored_close_reasons[ignored_close.group(1)] += 1

    if not native_events and not scheduler_events and not rotation_events:
        return

    print()
    print("Proxy-check lifecycle:")
    if rotation_events:
        print("  Rotation events:")
        for event, count in rotation_events.most_common():
            print(f"    {event}: {count}")
    if scheduler_events:
        print("  Java scheduler events:")
        for event, count in scheduler_events.most_common():
            print(f"    {event}: {count}")
    if scheduler_coalescing:
        print("  Scheduler coalescing:")
        for item, count in scheduler_coalescing.most_common(10):
            print(f"    {item}: {count}")
    if scheduler_listener_peaks:
        print("  Scheduler listener peaks:")
        for endpoint, count in sorted(scheduler_listener_peaks.items(), key=lambda item: (-item[1], item[0]))[:10]:
            print(f"    {endpoint}: {count}")
    if scheduler_force:
        print("  Scheduler force flags:")
        for value, count in scheduler_force.most_common():
            print(f"    {value}: {count}")
    if scheduler_results:
        print("  Scheduler finish results:")
        for result, count in scheduler_results.most_common():
            print(f"    {result}: {count}")
    if scheduler_preserved_connected:
        print("  Scheduler preserved connected state:")
        for endpoint, count in scheduler_preserved_connected.most_common(10):
            print(f"    {endpoint}: {count}")
    if scheduler_applied_split:
        print("  Scheduler applied/callback split:")
        for item, count in scheduler_applied_split.most_common(10):
            print(f"    {item}: {count}")
    if native_events:
        print("  Native events:")
        for event, count in native_events.most_common():
            print(f"    {event}: {count}")
    if native_results:
        print("  Native finish results:")
        for result, count in native_results.most_common():
            print(f"    {result}: {count}")
    if native_endpoint_outcomes:
        print("  Native endpoint outcomes:")
        for result, count in native_endpoint_outcomes.most_common():
            print(f"    {result}: {count}")
    if native_start_failures:
        print("  Native start failures:")
        for reason, count in native_start_failures.most_common():
            print(f"    {reason}: {count}")
    if native_close_reasons:
        print("  Native close reasons:")
        for reason, count in native_close_reasons.most_common():
            print(f"    {reason}: {count}")
    if native_ignored_close_reasons:
        print("  Native ignored close reasons:")
        for reason, count in native_ignored_close_reasons.most_common():
            print(f"    {reason}: {count}")
    if scheduler_endpoints:
        print("  Scheduler endpoints:")
        for endpoint, count in scheduler_endpoints.most_common(10):
            print(f"    {endpoint}: {count}")


def print_faketls_endpoint_summary(attempts: list[Attempt]) -> None:
    endpoint_verdicts: Counter[str] = Counter()
    for attempt in attempts:
        if attempt.endpoint:
            endpoint = attempt.endpoint
        elif attempt.address:
            endpoint = f"{attempt.address}:{attempt.port}"
        else:
            endpoint = "unknown"
        endpoint_verdicts[f"{endpoint} {attempt.verdict()}"] += 1

    if not endpoint_verdicts:
        return

    print()
    print("FakeTLS endpoint phases:")
    for item, count in endpoint_verdicts.most_common(30):
        print(f"  {item}: {count}")


def print_report(attempts: list[Attempt], global_lines: list[str]) -> None:
    print("MTProxy FakeTLS diagnostic summary")
    print("===================================")
    if not attempts and not global_lines:
        print("No MTProxy markers found.")
        print("Most likely causes: APK was built without LOGS_ENABLED, wrong package was captured, or the MTProxy path was not exercised.")
        return

    verdicts = Counter(attempt.verdict() for attempt in attempts)
    profiles = Counter(attempt.profile or "unknown" for attempt in attempts)
    print(f"Attempts: {len(attempts)}")
    print("Verdicts:")
    for verdict, count in verdicts.most_common():
        print(f"  {verdict}: {count}")
    print("Profiles:")
    for profile, count in profiles.most_common():
        print(f"  {profile}: {count}")

    if global_lines:
        print(f"Global/non-connection markers: {len(global_lines)}")

    print_faketls_endpoint_summary(attempts)

    all_lines = list(global_lines)
    for attempt in attempts:
        all_lines.extend(attempt.lines)
    print_proxy_check_summary(all_lines)

    print()
    print("Per-attempt details:")
    for attempt in attempts:
        endpoint = ""
        if attempt.endpoint:
            endpoint = f" {attempt.endpoint}"
        elif attempt.address:
            endpoint = f" {attempt.address}:{attempt.port}"
        flags = ",".join(sorted(attempt.events)) or "no_known_phase"
        print(f"- {attempt.key}{endpoint} profile={attempt.profile or 'unknown'} verdict={attempt.verdict()}")
        print(f"  lines={attempt.first_line}-{attempt.last_line} events={flags}")
        if attempt.disconnect:
            print(f"  disconnect={attempt.disconnect}")

    print()
    print("How to read the verdicts:")
    print("- tcp_not_connected: TCP/connect/IP/proxy availability layer.")
    print("- connected_without_socket_connected_marker: Telegram reached on_connected, but this log slice has no socket_connected marker; do not treat it as a TCP failure.")
    print("- client_hello_sent_no_server_hello: compare VPN vs non-VPN; with VPN failure points to server/client compatibility, without VPN it can be DPI blackhole.")
    print("- server_hello_hmac_mismatch: likely ClientHello/profile/server response mismatch, not plain packet loss.")
    print("- post_handshake_no_appdata: HMAC passed; inspect TLS app-data write/read path and first MTProto packets.")
    print("- dropped_after_appdata: startup worked; look at later MTProto keepalive, server close, or external throttling.")
    print("- proxy_check fail:tcp_not_connected: TCP/connect/DNS/server availability layer; compare with VPN and external probe.")
    print("- proxy_check fail:tcp_connected_no_pong: TCP opened, but MTProxy ping did not complete; can be dead proxy, server overload, or path filtering.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("markers", type=Path, help="Path to mtproxy_markers.txt")
    args = parser.parse_args()

    if not args.markers.exists():
        raise SystemExit(f"markers file not found: {args.markers}")

    attempts, global_lines = load_attempts(args.markers)
    print_report(attempts, global_lines)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
