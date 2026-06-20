package org.telegram.messenger;

import android.content.SharedPreferences;
import org.telegram.tgnet.ConnectionsManager;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class ProxyRotationController implements NotificationCenter.NotificationCenterDelegate {
    private final static ProxyRotationController INSTANCE = new ProxyRotationController();

    public final static int DEFAULT_TIMEOUT_INDEX = 1;
    public final static List<Integer> ROTATION_TIMEOUTS = Arrays.asList(
            5, 10, 15, 30, 60
    );

    private boolean isCheckScheduled;
    private boolean isCurrentlyChecking;
    private final ProxyCheckScheduler.Callback rotationCheckCallback = new ProxyCheckScheduler.Callback() {
        @Override
        public void onProxyChecked(SharedConfig.ProxyInfo proxyInfo, long time, String diagnostic) {
            if (!SharedConfig.isProxyEnabled() || !SharedConfig.proxyRotationEnabled || !isCurrentlyChecking) {
                return;
            }
            if (time != -1 && proxyInfo.available) {
                log("check_ok endpoint=" + endpoint(proxyInfo) + " ping=" + time);
                switchToAvailable();
            } else {
                log("check_fail endpoint=" + endpoint(proxyInfo) + " phase=" + ProxyCheckDiagnostics.normalize(diagnostic));
            }
        }

        @Override
        public void onProxyCheckQueueFinished() {
            if (!isCurrentlyChecking) {
                return;
            }
            log("check_queue_finished");
            switchToAvailable();
        }
    };

    private Runnable checkProxyAndSwitchRunnable = () -> {
        isCheckScheduled = false;
        isCurrentlyChecking = true;

        int currentAccount = UserConfig.selectedAccount;
        int startedCheck = ProxyCheckScheduler.enqueueStale(currentAccount, SharedConfig.proxyList, this, rotationCheckCallback);
        log("scheduled_check started=" + startedCheck);

        if (startedCheck == 0) {
            isCurrentlyChecking = false;
            switchToAvailable();
        }
    };

    public static void init() {
        INSTANCE.initInternal();
    }

    @SuppressWarnings("ComparatorCombinators")
    private void switchToAvailable() {
        isCurrentlyChecking = false;

        if (!SharedConfig.proxyRotationEnabled) {
            log("skip_switch rotation_disabled");
            return;
        }

        List<SharedConfig.ProxyInfo> sortedList = new ArrayList<>(SharedConfig.proxyList);
        Collections.sort(sortedList, (o1, o2) -> Long.compare(o1.ping, o2.ping));
        for (SharedConfig.ProxyInfo info : sortedList) {
            if (info == SharedConfig.currentProxy || info.checking || !info.available || !ProxyCheckScheduler.isFresh(info)) {
                continue;
            }

            SharedPreferences.Editor editor = MessagesController.getGlobalMainSettings().edit();
            editor.putString("proxy_ip", info.address);
            editor.putString("proxy_pass", info.password);
            editor.putString("proxy_user", info.username);
            editor.putInt("proxy_port", info.port);
            editor.putString("proxy_secret", info.secret);
            editor.putBoolean("proxy_enabled", true);

            if (!info.secret.isEmpty()) {
                editor.putBoolean("proxy_enabled_calls", false);
            }
            editor.apply();

            SharedConfig.currentProxy = info;
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxySettingsChanged);
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.proxyChangedByRotation);
            ConnectionsManager.setProxySettings(true, SharedConfig.currentProxy.address, SharedConfig.currentProxy.port, SharedConfig.currentProxy.username, SharedConfig.currentProxy.password, SharedConfig.currentProxy.secret);
            log("switch endpoint=" + endpoint(info) + " ping=" + info.ping);
            return;
        }
        log("no_candidate");
    }

    private void initInternal() {
        for (int i = 0; i < UserConfig.MAX_ACCOUNT_COUNT; i++) {
            NotificationCenter.getInstance(i).addObserver(this, NotificationCenter.didUpdateConnectionState);
        }
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.proxyCheckDone);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.proxySettingsChanged);
    }

    @Override
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.proxyCheckDone) {
            if (!SharedConfig.isProxyEnabled() || !SharedConfig.proxyRotationEnabled || SharedConfig.proxyList.size() <= 1 || !isCurrentlyChecking) {
                return;
            }

            SharedConfig.ProxyInfo proxyInfo = args.length > 0 && args[0] instanceof SharedConfig.ProxyInfo ? (SharedConfig.ProxyInfo) args[0] : null;
            if (proxyInfo != null && proxyInfo.available) {
                switchToAvailable();
            }
        } else if (id == NotificationCenter.proxySettingsChanged) {
            AndroidUtilities.cancelRunOnUIThread(checkProxyAndSwitchRunnable);
            isCheckScheduled = false;
            isCurrentlyChecking = false;
            ProxyCheckScheduler.cancelOwner(this);
            log("cancel settings_changed");
        } else if (id == NotificationCenter.didUpdateConnectionState && account == UserConfig.selectedAccount) {
            if (!SharedConfig.isProxyEnabled() || !SharedConfig.proxyRotationEnabled || SharedConfig.proxyList.size() <= 1) {
                return;
            }

            int state = ConnectionsManager.getInstance(account).getConnectionState();

            if (state == ConnectionsManager.ConnectionStateConnectingToProxy) {
                if (!isCurrentlyChecking && !isCheckScheduled) {
                    isCheckScheduled = true;
                    log("schedule_after_connecting timeout_s=" + ROTATION_TIMEOUTS.get(SharedConfig.proxyRotationTimeout));
                    AndroidUtilities.runOnUIThread(checkProxyAndSwitchRunnable, ROTATION_TIMEOUTS.get(SharedConfig.proxyRotationTimeout) * 1000L);
                }
            } else {
                if ((state == ConnectionsManager.ConnectionStateConnected || state == ConnectionsManager.ConnectionStateUpdating) && SharedConfig.currentProxy != null) {
                    ProxyCheckScheduler.markConnected(SharedConfig.currentProxy);
                }
                AndroidUtilities.cancelRunOnUIThread(checkProxyAndSwitchRunnable);
                isCheckScheduled = false;
                isCurrentlyChecking = false;
                ProxyCheckScheduler.cancelOwner(this);
                log("cancel state=" + state);
            }
        }
    }

    private void log(String message) {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("proxy_rotation " + message);
        }
    }

    private String endpoint(SharedConfig.ProxyInfo proxyInfo) {
        if (proxyInfo == null) {
            return "null";
        }
        return proxyInfo.address + ":" + proxyInfo.port;
    }
}
