#!/usr/bin/env python3
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SOCKET = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.cpp"
HEADER = ROOT / "TMessagesProj/jni/tgnet/ConnectionSocket.h"
ANALYZER = ROOT / "Tools/analyze_mtproxy_markers.py"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def method_body(text: str, signature: str, next_signature: str) -> str:
    start = text.find(signature)
    if start == -1:
        return ""
    end = text.find(next_signature, start + len(signature))
    return text[start:] if end == -1 else text[start:end]


def main() -> int:
    failures: list[str] = []
    socket = read(SOCKET)
    header = read(HEADER)
    analyzer = read(ANALYZER)

    for state in (
        "idle",
        "prepared",
        "waiting_gate",
        "tcp_connecting",
        "epoll_registered",
        "faketls_handshake",
        "mtproto_ready",
        "closing",
    ):
        require(state in socket or state in header, f"transport state '{state}' must be named in native code", failures)

    require("enum class TransportState" in header, "ConnectionSocket must expose a private TransportState enum", failures)
    require("TransportState currentTransportState" in header, "ConnectionSocket must keep one explicit transport state", failures)
    require("bool epollRegistered" in header, "ConnectionSocket must track successful epoll registration explicitly", failures)
    for helper in (
        "transportStateName",
        "setTransportState",
        "logTransportSnapshot",
        "logTransportInvariant",
    ):
        require(helper in header and helper in socket, f"ConnectionSocket must implement {helper}", failures)

    for field in (
        "transport_state=%s",
        "epoll_registered=%d",
        "admission_active=%d",
        "admission_queued=%d",
        "tcp_gate_active=%d",
        "waiting_resolve=%d",
        "proxy_state=%d",
        "tls_state=%d",
    ):
        require(field in socket, f"native transport logs must include stable field {field}", failures)

    require(
        "void ConnectionSocket::recordMtProxyEndpointHandshakeOk" in socket
        and "void ConnectionSocket::recordMtProxyEndpointDataPathSuccess" in socket
        and "recordMtProxyEndpointSuccess" not in header,
        "endpoint success must be split into handshake-ok and data-path-success helpers",
        failures,
    )

    server_hello_body = socket[
        socket.find('publishProxyConnectionStage("server_hello_hmac_ok")'):
        socket.find('proxyCheckDiagnostic = "post_handshake_no_appdata"', socket.find('publishProxyConnectionStage("server_hello_hmac_ok")'))
    ]
    require(
        'recordMtProxyEndpointHandshakeOk("server_hello_hmac_ok")' in server_hello_body
        and "recordMtProxyEndpointDataPathSuccess" not in server_hello_body,
        "server_hello_hmac_ok must record handshake-ok only, not data-path success",
        failures,
    )

    tls_app_body = socket[
        socket.find('publishProxyConnectionStage("first_tls_app_recv")'):
        socket.find('onReceivedData(tlsBuffer)', socket.find('publishProxyConnectionStage("first_tls_app_recv")'))
    ]
    require(
        'recordMtProxyEndpointDataPathSuccess("first_tls_app_recv")' in tls_app_body,
        "first_tls_app_recv must record data-path success",
        failures,
    )

    plain_recv_body = socket[
        socket.find('publishProxyConnectionStage("first_mtproxy_packet_recv")'):
        socket.find('if (LOGS_ENABLED) DEBUG_D("connection(%p) mtproxy_startup first_mtproxy_packet_recv', socket.find('publishProxyConnectionStage("first_mtproxy_packet_recv")'))
    ]
    require(
        'recordMtProxyEndpointDataPathSuccess("first_mtproxy_packet_recv")' in plain_recv_body,
        "first_mtproxy_packet_recv must record data-path success",
        failures,
    )

    adjust_body = method_body(socket, "void ConnectionSocket::adjustWriteOp()", "void ConnectionSocket::setTimeout")
    require(
        "socketFd < 0 || !epollRegistered" in adjust_body
        and 'logTransportInvariant("adjustWriteOp"' in adjust_body
        and "EPOLL_CTL_MOD" in adjust_body,
        "adjustWriteOp must log and return before epoll_ctl MOD when fd/epoll registration is not live",
        failures,
    )

    client_hello_body = method_body(socket, "bool ConnectionSocket::sendPendingClientHello()", "void ConnectionSocket::clearPendingTlsFrame")
    require(
        "currentTransportState != TransportState::FaketlsHandshake" in client_hello_body
        and 'logTransportInvariant("sendPendingClientHello"' in client_hello_body,
        "sendPendingClientHello must be guarded by the FakeTLS handshake transport state",
        failures,
    )

    tls_frame_body = method_body(socket, "bool ConnectionSocket::sendPendingTlsFrame()", "uint32_t ConnectionSocket::nextMtProxyTlsRecordPayloadSize")
    require(
        "currentTransportState != TransportState::MtprotoReady" in tls_frame_body
        and 'logTransportInvariant("sendPendingTlsFrame"' in tls_frame_body,
        "sendPendingTlsFrame must be guarded by the mtproto_ready transport state",
        failures,
    )

    close_body = method_body(socket, "void ConnectionSocket::closeSocket", "void ConnectionSocket::onEvent")
    require(
        'setTransportState(TransportState::Closing, "closeSocket")' in close_body
        and 'setTransportState(TransportState::Idle, "closeSocket_cleanup")' in close_body
        and "transport_state=%s" in close_body
        and "epoll_registered=%d" in close_body,
        "closeSocket must be idempotent and log state before cleanup",
        failures,
    )

    require(
        '"transport_invariant": "transport_invariant"' in analyzer
        and '"endpoint_handshake_ok": "endpoint_handshake_ok"' in analyzer
        and '"endpoint_data_path_success": "endpoint_data_path_success"' in analyzer
        and "transport_state" in analyzer,
        "MTProxy analyzer must recognize transport-state and split endpoint-success markers",
        failures,
    )

    if failures:
        print("MTProxy transport-state guard failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1
    print("MTProxy transport-state guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
