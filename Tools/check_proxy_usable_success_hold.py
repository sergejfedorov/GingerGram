#!/usr/bin/env python3
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MESSENGER = ROOT / "TMessagesProj/src/main/java/org/telegram/messenger"
NATIVE = ROOT / "TMessagesProj/jni/tgnet"
ANALYZER = ROOT / "Tools/analyze_mtproxy_markers.py"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def method_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start == -1:
        return ""
    brace = text.find("{", start)
    if brace == -1:
        return ""
    depth = 0
    for index in range(brace, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    return text[start:]


def run_analyzer_shadow_check(failures: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        session = Path(tmp)
        markers = session / "mtproxy_markers.txt"
        markers.write_text(
            "\n".join(
                [
                    "logcat.txt:1: 06-25 20:31:30.000 connection(0x1) connecting via proxy sberbank.dns.army:45631 secret[34] secret_kind=ee",
                    "logcat.txt:2: 06-25 20:31:30.010 connection(0x1) mtproxy_startup connect_start profile=firefox_android address=sberbank.dns.army port=45631",
                    "logcat.txt:3: 06-25 20:31:30.020 connection(0x1) mtproxy_startup socket_connect_start",
                    "logcat.txt:4: 06-25 20:31:30.030 connection(0x1) mtproxy_startup socket_connected",
                    "logcat.txt:5: 06-25 20:31:30.040 connection(0x1) mtproxy_startup client_hello_sent bytes=2206",
                    "logcat.txt:6: 06-25 20:31:30.060 connection(0x1) mtproxy_startup server_hello_hmac_ok bytes=196 len1=122 len2=58 flight=58 extra=0",
                    "logcat.txt:7: 06-25 20:31:30.070 connection(0x1) mtproxy_startup on_connected tls=1",
                    "logcat.txt:8: 06-25 20:31:30.080 connection(0x1) mtproxy_startup first_tls_app_sent payload=244 frame=249",
                    "logcat.txt:9: 06-25 20:31:30.090 connection(0x1) mtproxy_startup first_tls_app_recv payload=1015",
                    "logcat.txt:10: 06-25 20:31:30.100 proxy_control decision=visible_usable_success source=native_stage account=0 phase=first_tls_app_recv endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army",
                    "logcat.txt:11: 06-25 20:31:30.200 connection(0x2) connecting via proxy sberbank.dns.army:45631 secret[34] secret_kind=ee",
                    "logcat.txt:12: 06-25 20:31:30.210 connection(0x2) mtproxy_startup endpoint_failure_shadowed_by_success key=sberbank.dns.army:45631 phase=tcp_not_connected reason=closeSocket hold_ms=44900",
                    "logcat.txt:13: 06-25 20:31:30.220 proxy_control decision=held_by_usable_success source=native_stage account=0 phase=tcp_not_connected endpoint=sberbank.dns.army:45631:ee:sberbank.dns.army held_by=first_tls_app_recv",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [sys.executable, str(ANALYZER), str(markers), "--out-dir", str(session)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(result.returncode == 0, result.stderr.strip() or result.stdout, failures)
        require("ok: 1" in result.stdout, "analyzer must keep the proven usable attempt as ok", failures)
        require("tcp_not_connected: 1" not in result.stdout, "shadowed sibling failure must not count as tcp_not_connected", failures)
        require("endpoint_failure_shadowed_by_success" in result.stdout, "analyzer must preserve the shadow marker", failures)
        require("held_by_usable_success" in result.stdout, "analyzer must preserve Java usable-success hold decisions", failures)


def main() -> int:
    failures: list[str] = []
    store = read(MESSENGER / "ProxyRuntimeStateStore.java")
    health = read(MESSENGER / "ProxyHealthStore.java")
    rotation = read(MESSENGER / "ProxyRotationController.java")
    engine = read(MESSENGER / "ProxyRotationEngine.java")
    policy_h = read(NATIVE / "MtProxyEndpointPolicy.h")
    policy_cpp = read(NATIVE / "MtProxyEndpointPolicy.cpp")
    socket = read(NATIVE / "ConnectionSocket.cpp")
    analyzer = read(ANALYZER)
    all_checks = read(ROOT / "Tools/check_mtproxy_all.py")

    require("public static boolean hasFreshUsableSuccess" in store, "runtime store must expose fresh usable-success state", failures)
    require("public static long usableSuccessRemainingMs" in store, "runtime store must expose remaining usable-success hold", failures)
    require("static long usableSuccessRemainingMs" in health, "health store must expose usable-success remaining time", failures)

    rotation_stage = rotation[rotation.find("NotificationCenter.proxyConnectionStageChanged"):]
    require(
        "ProxyRuntimeStateStore.hasFreshUsableSuccess(SharedConfig.currentProxy)" in rotation_stage
        and "cancelScheduledSwitch(\"usable_success\")" in rotation_stage
        and "cancel usable_success" in rotation_stage,
        "rotation controller must cancel pending switches on current-proxy usable success",
        failures,
    )

    complete_attempt = method_body(engine, "SwitchDecision completeScheduledAttempt")
    require(
        "ProxyRuntimeStateStore.hasFreshUsableSuccess(currentProxy)" in complete_attempt
        and "SwitchDecision.held" in complete_attempt
        and complete_attempt.find("hasFreshUsableSuccess") < complete_attempt.find("markEndpointFailure"),
        "rotation engine must hold scheduled attempts before marking connecting timeout failure",
        failures,
    )

    require("MT_PROXY_ENDPOINT_USABLE_SUCCESS_HOLD_MS" in policy_cpp, "native endpoint policy must define a usable-success hold window", failures)
    require("shadowedByUsableSuccess" in policy_h, "FailureResult must report shadowed usable-success failures", failures)
    require("failureCanBeShadowedBySuccess" in policy_cpp, "native policy must restrict which failures can be shadowed", failures)
    require('"dropped_early_after_appdata"' in policy_cpp and '"dropped_after_appdata"' in policy_cpp, "native policy must explicitly leave post-data drops unshadowed", failures)
    record_failure = method_body(policy_cpp, "MtProxyEndpointPolicy::FailureResult MtProxyEndpointPolicy::recordFailure")
    require(
        "usableSuccessRemainingMsLocked" in record_failure
        and "result.shadowedByUsableSuccess = true" in record_failure
        and "return result" in record_failure,
        "recordFailure must return a shadowed result without increasing cooldown counters",
        failures,
    )
    failure_body = method_body(socket, "void ConnectionSocket::recordMtProxyEndpointFailure")
    require(
        "endpoint_failure_shadowed_by_success" in failure_body
        and "shadowedByUsableSuccess" in failure_body
        and "hold_ms" in failure_body,
        "ConnectionSocket must log shadowed native failures with a dedicated marker",
        failures,
    )

    require("endpoint_failure_shadowed_by_success" in analyzer, "analyzer must know the native shadow marker", failures)
    require("held_by_usable_success" in analyzer, "analyzer must preserve Java usable-success hold decisions", failures)
    require('"check_proxy_usable_success_hold.py"' in all_checks, "full guard suite must include usable-success hold guard", failures)

    run_analyzer_shadow_check(failures)

    if failures:
        print("Proxy usable-success hold guard failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("Proxy usable-success hold guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
