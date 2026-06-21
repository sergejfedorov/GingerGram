#!/usr/bin/env python3
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SOCKET = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str) -> None:
    if not condition:
        print(f"FAIL: {message}", file=sys.stderr)
        raise SystemExit(1)


def slice_between(source: str, start: str, end: str) -> str:
    start_idx = source.find(start)
    require(start_idx >= 0, f"missing start marker: {start}")
    end_idx = source.find(end, start_idx)
    require(end_idx >= 0, f"missing end marker after {start}: {end}")
    return source[start_idx:end_idx]


def main() -> None:
    socket = read(SOCKET)
    scheduler_helpers = slice_between(
        socket,
        "struct MtProxyHandshakeQueuedRequest",
        "static void mtProxyClampCooldown",
    )
    admission = slice_between(
        socket,
        "bool ConnectionSocket::scheduleProxyHandshakeAdmissionIfNeeded",
        "void ConnectionSocket::scheduleProxyHandshakeAdmissionTimer",
    )
    release = slice_between(
        socket,
        "void ConnectionSocket::releaseProxyHandshakeAdmission",
        "bool ConnectionSocket::scheduleMtProxyEndpointCircuitBreakerIfNeeded",
    )

    require(
        "MT_PROXY_HANDSHAKE_GLOBAL_BROWSER_ACTIVE_LIMIT = 2" in socket
        and "MT_PROXY_HANDSHAKE_GLOBAL_QUIET_ACTIVE_LIMIT = 1" in socket
        and "MT_PROXY_HANDSHAKE_GLOBAL_STRICT_ACTIVE_LIMIT = 1" in socket,
        "global MTProxy handshake budget must define mode-specific app-wide active limits",
    )
    require(
        "struct MtProxyHandshakeGlobalState" in scheduler_helpers
        and "activeHandshakes" in scheduler_helpers
        and "lastGrantTime" in scheduler_helpers
        and "static MtProxyHandshakeGlobalState proxyHandshakeGlobal" in scheduler_helpers,
        "scheduler must keep app-wide handshake state shared across account instances",
    )
    require(
        "mtProxyHandshakeGlobalActiveLimit" in scheduler_helpers
        and "MT_PROXY_HANDSHAKE_GLOBAL_BROWSER_ACTIVE_LIMIT" in scheduler_helpers
        and "MT_PROXY_HANDSHAKE_GLOBAL_QUIET_ACTIVE_LIMIT" in scheduler_helpers
        and "MT_PROXY_HANDSHAKE_GLOBAL_STRICT_ACTIVE_LIMIT" in scheduler_helpers,
        "global active limit helper must be mode-aware",
    )
    require(
        "mtProxyHandshakeGlobalSpacingDelay" in scheduler_helpers
        and "proxyHandshakeGlobal.lastGrantTime" in scheduler_helpers
        and "mtProxyRecordGlobalHandshakeGrant" in scheduler_helpers,
        "global budget must space grants across endpoints and accounts",
    )
    require(
        "mtProxyHandshakeHasHigherPriorityQueuedGlobal" in scheduler_helpers
        and "for (const auto &entry : proxyHandshakeEndpoints)" in scheduler_helpers
        and "request.priority < priority" in scheduler_helpers,
        "priority checks must see queued handshakes from every endpoint/account",
    )
    require(
        "mtProxyTakeNextQueuedRequestGlobalLocked" in scheduler_helpers
        and "proxyHandshakeGlobal.activeHandshakes >= globalLimit" in scheduler_helpers
        and "entry.second.activeHandshakes >= endpointLimit" in scheduler_helpers
        and "proxyHandshakeGlobal.activeHandshakes++" in scheduler_helpers,
        "release must dequeue the next best request globally, not only from the same endpoint",
    )
    require(
        "globalActiveLimit = mtProxyHandshakeGlobalActiveLimit" in admission
        and "globalLimitReached = proxyHandshakeGlobal.activeHandshakes >= globalActiveLimit" in admission
        and "globalLimitReached || cooldownBlocks || state.activeHandshakes >= endpointActiveLimit" in admission,
        "admission must queue when the app-wide handshake budget is full",
    )
    require(
        "mtProxyHandshakeHasHigherPriorityQueuedGlobal(proxyHandshakeAdmissionPriority)" in admission
        and "proxyHandshakeGlobal.activeHandshakes++" in admission
        and "mtProxyRecordGlobalHandshakeGrant(now, delay)" in admission,
        "immediate grants must reserve and record an app-wide slot",
    )
    require(
        "global_active=%d" in admission
        and "global_limit=%d" in admission
        and "global_active=%d" in release
        and "global_limit=%d" in release,
        "startup diagnostics must expose global active/limit budget decisions",
    )
    require(
        "if (wasActive && proxyHandshakeGlobal.activeHandshakes > 0)" in release
        and "proxyHandshakeGlobal.activeHandshakes--" in release,
        "release must return an app-wide slot exactly once",
    )
    require(
        "mtProxyTakeNextQueuedRequestGlobalLocked(now, connectionPatternMode, nextRequest, nextRequestKey)" in release
        and "MtProxyHandshakeEndpointState &nextState = proxyHandshakeEndpoints[nextRequestKey]" in release
        and "mtProxyRecordGlobalHandshakeGrant(now, nextGrantDelay)" in release,
        "release must grant the next queued handshake across all accounts/endpoints",
    )

    print("MTProxy global handshake budget guard passed.")


if __name__ == "__main__":
    main()
