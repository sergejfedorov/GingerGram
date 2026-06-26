#!/usr/bin/env python3
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
CONNECTIONS_JAVA = ROOT / "TMessagesProj/src/main/java/org/telegram/tgnet/ConnectionsManager.java"
NOTIFICATIONS_UI = ROOT / "TMessagesProj/src/main/java/org/telegram/ui/NotificationsSettingsActivity.java"
STRINGS = ROOT / "TMessagesProj/src/main/res/values/strings.xml"
STRINGS_RU = ROOT / "TMessagesProj/src/main/res/values-ru/strings.xml"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def require(condition: bool, message: str, failures: list[str]) -> None:
    if not condition:
        failures.append(message)


def main() -> int:
    failures: list[str] = []
    connections = read(CONNECTIONS_JAVA)
    notifications = read(NOTIFICATIONS_UI)

    require(
        'BACKGROUND_NETWORK_ALWAYS_ON = "backgroundNetworkAlwaysOn"' in connections,
        "ConnectionsManager must define a stable background network policy key",
        failures,
    )
    require(
        "isBackgroundNetworkAlwaysOn()" in connections
        and "MessagesController.getGlobalNotificationsSettings()" in connections,
        "ConnectionsManager must read the keep-awake policy from global notification settings",
        failures,
    )
    require(
        "public void applyBackgroundNetworkPolicy()" in connections
        and "public static void applyBackgroundNetworkPolicyForAllAccounts()" in connections
        and "UserConfig.getInstance(a).isClientActivated()" in connections
        and re.search(
            r"if\s*\(isBackgroundNetworkAlwaysOn\(\)\)\s*\{[^{}]*lastPauseTime\s*=\s*0;[^{}]*native_resumeNetwork\(currentAccount,\s*false\);[^{}]*return;",
            connections,
            re.DOTALL,
        )
        is not None
        and "applyBackgroundNetworkPolicy();" in connections,
        "setAppPaused() must route background sleep through a policy method that skips native_pauseNetwork() when keep-awake is enabled",
        failures,
    )
    require(
        "backgroundNetworkAlwaysOnRow" in notifications,
        "Notifications settings must include a row for the keep-awake policy",
        failures,
    )
    require(
        "ConnectionsManager.BACKGROUND_NETWORK_ALWAYS_ON" in notifications,
        "Notifications settings must persist the keep-awake policy with the shared ConnectionsManager key",
        failures,
    )
    require(
        "ConnectionsManager.applyBackgroundNetworkPolicyForAllAccounts()" in notifications,
        "Toggling the policy must re-apply the current native pause/resume state for all active accounts",
        failures,
    )
    require(
        "NotificationsBackgroundNetworkAlwaysOn" in notifications
        and "NotificationsBackgroundNetworkAlwaysOnInfo" in notifications,
        "Notifications settings UI must render the keep-awake title and description",
        failures,
    )

    for path in (STRINGS, STRINGS_RU):
        text = read(path)
        require(
            'name="NotificationsBackgroundNetworkAlwaysOn"' in text,
            f"{path.relative_to(ROOT)} must define NotificationsBackgroundNetworkAlwaysOn",
            failures,
        )
        require(
            'name="NotificationsBackgroundNetworkAlwaysOnInfo"' in text,
            f"{path.relative_to(ROOT)} must define NotificationsBackgroundNetworkAlwaysOnInfo",
            failures,
        )

    if failures:
        print("Background network policy guard failed:", file=sys.stderr)
        for failure in failures:
            print(f" - {failure}", file=sys.stderr)
        return 1

    print("Background network policy guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
