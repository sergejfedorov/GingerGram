package org.telegram.messenger;

import android.os.SystemClock;

public final class ProxyConnectionEvent {

    public static final String SOURCE_NATIVE_STAGE = "native_stage";
    public static final String SOURCE_PROXY_CHECK = "proxy_check";
    public static final String SOURCE_CONNECTED = "connected";
    public static final String SOURCE_CONNECT_START = "connect_start";

    public enum Origin {
        ACTIVE_PROXY("active_proxy"),
        PROXY_CHECK("proxy_check"),
        PROXY_LIST_ROW("proxy_list_row"),
        BACKGROUND_PRECHECK("background_precheck"),
        SETTINGS_CHANGE("settings_change");

        public final String wireName;

        Origin(String wireName) {
            this.wireName = wireName;
        }

        public static Origin fromNative(String origin) {
            if (origin == null) {
                return ACTIVE_PROXY;
            }
            switch (origin) {
                case "proxy_check":
                    return PROXY_CHECK;
                case "proxy_list_row":
                    return PROXY_LIST_ROW;
                case "background_precheck":
                    return BACKGROUND_PRECHECK;
                case "settings_change":
                    return SETTINGS_CHANGE;
                case "active_proxy":
                default:
                    return ACTIVE_PROXY;
            }
        }
    }

    public final String source;
    public final Origin origin;
    public final int account;
    public final String phase;
    public final String endpointKey;
    public final String probeKey;
    public final long timestamp;

    private ProxyConnectionEvent(String source, Origin origin, int account, String phase, String endpointKey, String probeKey, long timestamp) {
        this.source = source;
        this.origin = origin == null ? Origin.ACTIVE_PROXY : origin;
        this.account = account;
        this.phase = ProxyCheckDiagnostics.normalize(phase);
        this.endpointKey = endpointKey == null ? "" : endpointKey;
        this.probeKey = probeKey == null ? "" : probeKey;
        this.timestamp = timestamp == 0 ? SystemClock.elapsedRealtime() : timestamp;
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey) {
        return nativeStage(account, phase, endpointKey, SystemClock.elapsedRealtime());
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey, long timestamp) {
        return new ProxyConnectionEvent(SOURCE_NATIVE_STAGE, Origin.ACTIVE_PROXY, account, phase, endpointKey, "", timestamp);
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey, String origin) {
        return nativeStage(account, phase, endpointKey, "", origin, SystemClock.elapsedRealtime());
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey, String origin, long timestamp) {
        return nativeStage(account, phase, endpointKey, "", origin, timestamp);
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey, String probeKey, String origin) {
        return nativeStage(account, phase, endpointKey, probeKey, origin, SystemClock.elapsedRealtime());
    }

    public static ProxyConnectionEvent nativeStage(int account, String phase, String endpointKey, String probeKey, String origin, long timestamp) {
        return new ProxyConnectionEvent(SOURCE_NATIVE_STAGE, Origin.fromNative(origin), account, phase, endpointKey, probeKey, timestamp);
    }

    public static ProxyConnectionEvent proxyCheck(int account, SharedConfig.ProxyInfo proxyInfo, String phase) {
        return new ProxyConnectionEvent(SOURCE_PROXY_CHECK, Origin.PROXY_CHECK, account, phase, ProxyEndpointKey.liveStage(proxyInfo), "", SystemClock.elapsedRealtime());
    }

    public static ProxyConnectionEvent connected(int account, SharedConfig.ProxyInfo proxyInfo) {
        return new ProxyConnectionEvent(SOURCE_CONNECTED, Origin.ACTIVE_PROXY, account, ProxyCheckDiagnostics.OK, ProxyEndpointKey.liveStage(proxyInfo), "", SystemClock.elapsedRealtime());
    }

    public static ProxyConnectionEvent connectStart(int account, SharedConfig.ProxyInfo proxyInfo) {
        return new ProxyConnectionEvent(SOURCE_CONNECT_START, Origin.ACTIVE_PROXY, account, ProxyCheckDiagnostics.CONNECT_START, ProxyEndpointKey.liveStage(proxyInfo), "", SystemClock.elapsedRealtime());
    }
}
