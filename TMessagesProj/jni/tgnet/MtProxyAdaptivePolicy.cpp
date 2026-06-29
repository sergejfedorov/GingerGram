/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 */

#include "MtProxyAdaptivePolicy.h"

#include <map>
#include <openssl/rand.h>
#include <pthread.h>

struct MtProxyTlsAutoProfileState {
    int32_t profileIndex = -1;
    uint32_t failures = 0;
};

static pthread_mutex_t mtProxyTlsAutoProfilesMutex = PTHREAD_MUTEX_INITIALIZER;
static std::map<std::string, MtProxyTlsAutoProfileState> tlsAutoRotateProfiles;

static constexpr int32_t MT_PROXY_ALTERNATE_PROFILE_COUNT = 4;

static uint64_t tlsAutoRotateSalt() {
    static uint64_t salt = 0;
    if (salt == 0) {
        RAND_bytes((uint8_t *) &salt, sizeof(salt));
        if (salt == 0) {
            salt = 0x9e3779b97f4a7c15ULL;
        }
    }
    return salt;
}

static uint64_t profileHash(uint64_t hash, const std::string &value) {
    for (char c : value) {
        hash ^= (uint8_t) c;
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

static int32_t autoRotatePoolProfile(int32_t index) {
    static const int32_t profiles[] = {
            MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID,
            MT_PROXY_TLS_PROFILE_ANDROID_CHROME,
            MT_PROXY_TLS_PROFILE_YANDEX,
            MT_PROXY_TLS_PROFILE_FIREFOX,
    };
    int32_t normalizedIndex = index % MT_PROXY_ALTERNATE_PROFILE_COUNT;
    if (normalizedIndex < 0) {
        normalizedIndex += MT_PROXY_ALTERNATE_PROFILE_COUNT;
    }
    return profiles[normalizedIndex];
}

static int32_t autoRotateInitialIndex(const std::string &key) {
    uint64_t hash = 0xcbf29ce484222325ULL ^ tlsAutoRotateSalt();
    hash = profileHash(hash, key);
    return (int32_t) (hash % MT_PROXY_ALTERNATE_PROFILE_COUNT);
}

static const char *adaptiveTlsProfileName(int32_t profile) {
    switch (normalizeMtProxyTlsProfileOption(profile)) {
        case MT_PROXY_TLS_PROFILE_AUTO:
            return "auto";
        case MT_PROXY_TLS_PROFILE_FIREFOX:
            return "firefox";
        case MT_PROXY_TLS_PROFILE_ANDROID_CHROME:
            return "android_chrome";
        case MT_PROXY_TLS_PROFILE_YANDEX:
            return "yandex";
        case MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID:
            return "firefox_android";
        case MT_PROXY_TLS_PROFILE_ANDROID_OKHTTP:
            return "android_okhttp";
        case MT_PROXY_TLS_PROFILE_AUTO_ROTATE:
            return "auto_rotate";
        case MT_PROXY_TLS_PROFILE_CHROME_MODERN:
            return "chrome_modern";
        case MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE:
            return "legacy_no_grease_no_4469_no_modern_extensions";
        default:
            return "android_chrome";
    }
}

bool MtProxyAdaptivePolicy::profileUsesGrease(int32_t profile) {
    switch (normalizeMtProxyTlsProfileOption(profile)) {
        case MT_PROXY_TLS_PROFILE_CHROME_MODERN:
        case MT_PROXY_TLS_PROFILE_FIREFOX:
        case MT_PROXY_TLS_PROFILE_ANDROID_CHROME:
        case MT_PROXY_TLS_PROFILE_YANDEX:
        case MT_PROXY_TLS_PROFILE_ANDROID_OKHTTP:
            return true;
        default:
            return false;
    }
}

static bool profileUsesModernExtensions(int32_t profile) {
    switch (normalizeMtProxyTlsProfileOption(profile)) {
        case MT_PROXY_TLS_PROFILE_CHROME_MODERN:
        case MT_PROXY_TLS_PROFILE_FIREFOX:
        case MT_PROXY_TLS_PROFILE_ANDROID_CHROME:
        case MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID:
        case MT_PROXY_TLS_PROFILE_YANDEX:
            return true;
        default:
            return false;
    }
}

static const char *serverHelloParserName(int32_t parserMode) {
    switch (normalizeMtProxyServerHelloParserOption(parserMode)) {
        case MT_PROXY_SERVER_HELLO_PARSER_RESERVED:
            return "reserved_hmac_parser";
        case MT_PROXY_SERVER_HELLO_PARSER_STANDARD:
        default:
            return "standard_hmac_parser";
    }
}

static int32_t alternateCompatibilityTlsProfile(int32_t alternateProfileIndex) {
    static const int32_t profiles[] = {
            MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID,
            MT_PROXY_TLS_PROFILE_ANDROID_CHROME,
            MT_PROXY_TLS_PROFILE_YANDEX,
            MT_PROXY_TLS_PROFILE_FIREFOX,
    };
    int32_t normalizedIndex = alternateProfileIndex % MT_PROXY_ALTERNATE_PROFILE_COUNT;
    if (normalizedIndex < 0) {
        normalizedIndex += MT_PROXY_ALTERNATE_PROFILE_COUNT;
    }
    return profiles[normalizedIndex];
}

static bool serverHelloParserVariantAllowed(const std::string &diagnostic) {
    return diagnostic == "server_hello_hmac_mismatch"
           || diagnostic == "unrecognized_tls_response_after_client_hello";
}

static int32_t greaseProbeTlsProfile(int32_t configuredProfile, int32_t effectiveProfile) {
    configuredProfile = normalizeMtProxyTlsProfileOption(configuredProfile);
    effectiveProfile = normalizeMtProxyTlsProfileOption(effectiveProfile);
    if (MtProxyAdaptivePolicy::profileUsesGrease(configuredProfile)) {
        return configuredProfile;
    }
    if (MtProxyAdaptivePolicy::profileUsesGrease(effectiveProfile)) {
        return effectiveProfile;
    }
    return MT_PROXY_TLS_PROFILE_ANDROID_CHROME;
}

MtProxyAdaptivePolicy::RecipeResult MtProxyAdaptivePolicy::applyRecipe(const RecipeInput &input) {
    RecipeResult result;
    result.recipeLevel = input.recipeLevel;
    result.clientHelloFragmentation = normalizeMtProxyClientHelloFragmentationOption(input.clientHelloFragmentation);
    result.effectiveTlsProfile = normalizeMtProxyTlsProfileOption(input.effectiveTlsProfile);
    result.serverHelloParserMode = normalizeMtProxyServerHelloParserOption(input.serverHelloParserMode);
    result.connectionPatternMode = normalizeMtProxyConnectionPatternOption(input.connectionPatternMode);
    result.recordSizingMode = normalizeMtProxyRecordSizingOption(input.recordSizingMode);
    result.timingMode = normalizeMtProxyTimingOption(input.timingMode);
    result.startupCoverMode = normalizeMtProxyStartupCoverOption(input.startupCoverMode);
    bool useGreaseProfile = input.probeGrease || (input.greaseSupported && input.recipeLevel <= 1);
    if (useGreaseProfile) {
        int32_t previousProfile = result.effectiveTlsProfile;
        result.effectiveTlsProfile = greaseProbeTlsProfile(input.configuredTlsProfile, result.effectiveTlsProfile);
        if (result.effectiveTlsProfile != previousProfile) {
            result.changed = true;
        }
    } else if (input.fakeTls && input.recipeLevel == 2) {
        int32_t previousProfile = result.effectiveTlsProfile;
        result.effectiveTlsProfile = MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE;
        if (result.effectiveTlsProfile != previousProfile) {
            result.changed = true;
        }
    } else if (input.fakeTls && input.recipeLevel >= 3) {
        int32_t previousProfile = result.effectiveTlsProfile;
        result.effectiveTlsProfile = alternateCompatibilityTlsProfile(input.alternateProfileIndex);
        if (result.effectiveTlsProfile != previousProfile) {
            result.changed = true;
        }
    }
    if (!input.fakeTls || input.endpointKey.empty() || input.recipeLevel <= 0) {
        return result;
    }
    if (input.lastDiagnostic == "post_handshake_no_appdata") {
        if (result.recordSizingMode == MT_PROXY_RECORD_SIZING_OFF) {
            result.recordSizingMode = MT_PROXY_RECORD_SIZING_CONSERVATIVE;
            result.changed = true;
        }
        if (result.timingMode == MT_PROXY_TIMING_OFF) {
            result.timingMode = MT_PROXY_TIMING_GENTLE;
            result.changed = true;
        }
        if (result.startupCoverMode == MT_PROXY_STARTUP_COVER_OFF) {
            result.startupCoverMode = MT_PROXY_STARTUP_COVER_SOFT;
            result.changed = true;
        }
        if (input.recipeLevel >= 2 && result.connectionPatternMode != MT_PROXY_CONNECTION_PATTERN_STRICT) {
            if (result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_OFF
                    || result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_SOFT
                    || result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_BROWSER) {
                result.connectionPatternMode = MT_PROXY_CONNECTION_PATTERN_QUIET;
                result.changed = true;
            }
        }
        return result;
    }
    if (input.recipeLevel >= 1 && result.clientHelloFragmentation != MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF) {
        result.clientHelloFragmentation = MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
        result.changed = true;
    }
    if (serverHelloParserVariantAllowed(input.lastDiagnostic)
            && input.recipeLevel >= 4
            && result.serverHelloParserMode != MT_PROXY_SERVER_HELLO_PARSER_RESERVED) {
        result.serverHelloParserMode = MT_PROXY_SERVER_HELLO_PARSER_RESERVED;
        result.changed = true;
    }
    if (input.recipeLevel >= 4 && result.connectionPatternMode != MT_PROXY_CONNECTION_PATTERN_STRICT) {
        if (result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_OFF
                || result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_SOFT
                || result.connectionPatternMode == MT_PROXY_CONNECTION_PATTERN_BROWSER) {
            result.connectionPatternMode = MT_PROXY_CONNECTION_PATTERN_QUIET;
            result.changed = true;
        }
    }
    return result;
}

MtProxyAdaptivePolicy::MtProxyRecipe MtProxyAdaptivePolicy::recipeForResult(const RecipeInput &input, const RecipeResult &result) {
    MtProxyRecipe recipe;
    recipe.transportMode = input.fakeTls ? "faketls_ee" : "classic_obfuscated";
    recipe.tlsProfile = adaptiveTlsProfileName(result.effectiveTlsProfile);
    recipe.fragmentClientHello = result.clientHelloFragmentation != MT_PROXY_CLIENT_HELLO_FRAGMENTATION_OFF;
    recipe.useGrease = MtProxyAdaptivePolicy::profileUsesGrease(result.effectiveTlsProfile);
    recipe.useModernExtensions = profileUsesModernExtensions(result.effectiveTlsProfile);
    recipe.serverHelloParser = serverHelloParserName(result.serverHelloParserMode);
    recipe.sni = input.sni;
    return recipe;
}

std::string MtProxyAdaptivePolicy::recipeId(const MtProxyRecipe &recipe) {
    return recipe.transportMode
            + "+" + recipe.tlsProfile
            + "+" + (recipe.fragmentClientHello ? "soft_fragment" : "no_fragment")
            + "+" + (recipe.useGrease ? "grease" : "no_grease")
            + "+" + (recipe.useModernExtensions ? "modern_extensions" : "no_modern_extensions")
            + "+" + recipe.serverHelloParser
            + "+sni=" + (recipe.sni.empty() ? "none" : recipe.sni);
}

int32_t MtProxyAdaptivePolicy::resolveEffectiveTlsProfile(int32_t profile, const std::string &key) {
    profile = normalizeMtProxyTlsProfileOption(profile);
    if (profile != MT_PROXY_TLS_PROFILE_AUTO_ROTATE) {
        if (profile == MT_PROXY_TLS_PROFILE_AUTO) {
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        }
        return profile;
    }

    pthread_mutex_lock(&mtProxyTlsAutoProfilesMutex);
    MtProxyTlsAutoProfileState &state = tlsAutoRotateProfiles[key];
    if (state.profileIndex < 0) {
        state.profileIndex = autoRotateInitialIndex(key);
    }
    int32_t result = autoRotatePoolProfile(state.profileIndex);
    pthread_mutex_unlock(&mtProxyTlsAutoProfilesMutex);
    return result;
}

MtProxyAdaptivePolicy::RotateResult MtProxyAdaptivePolicy::rotateTlsProfileOnFailureIfNeeded(const std::string &key, const std::string &diagnostic, int32_t previousProfile) {
    RotateResult result;
    result.previousProfile = normalizeMtProxyTlsProfileOption(previousProfile);
    if (key.empty() || !failureNeedsRecipe(diagnostic)) {
        return result;
    }
    pthread_mutex_lock(&mtProxyTlsAutoProfilesMutex);
    MtProxyTlsAutoProfileState &state = tlsAutoRotateProfiles[key];
    if (state.profileIndex < 0) {
        state.profileIndex = autoRotateInitialIndex(key);
    }
    state.profileIndex = (state.profileIndex + 1) % MT_PROXY_ALTERNATE_PROFILE_COUNT;
    state.failures++;
    result.failures = state.failures;
    result.nextProfile = autoRotatePoolProfile(state.profileIndex);
    pthread_mutex_unlock(&mtProxyTlsAutoProfilesMutex);
    result.rotated = true;
    return result;
}

bool MtProxyAdaptivePolicy::failureNeedsRecipe(const std::string &diagnostic) {
    if (diagnostic == "tcp_not_connected") {
        return false; // ClientHello was not sent, so JA4 did not cause this failure.
    }
    return diagnostic == "true_client_hello_timeout"
           || diagnostic == "client_hello_sent_no_server_hello"
           || diagnostic == "tls_alert_after_client_hello"
           || diagnostic == "short_tls_response_after_client_hello"
           || diagnostic == "unrecognized_tls_response_after_client_hello"
           || diagnostic == "server_hello_hmac_mismatch"
           || diagnostic == "post_handshake_no_appdata";
}

int32_t MtProxyAdaptivePolicy::compatibilityTlsProfile(int32_t configuredProfile, int32_t effectiveProfile, int32_t recipeLevel) {
    (void) configuredProfile;
    effectiveProfile = normalizeMtProxyTlsProfileOption(effectiveProfile);
    if (recipeLevel <= 1) {
        return effectiveProfile;
    }
    if (recipeLevel == 2) {
        if (effectiveProfile == MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE) {
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        }
        return MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE;
    }
    if (recipeLevel == 3) {
        return alternateCompatibilityTlsProfile(0);
    }
    return alternateCompatibilityTlsProfile(MT_PROXY_ALTERNATE_PROFILE_COUNT - 1);
}

int32_t MtProxyAdaptivePolicy::adaptiveTlsProfile(int32_t configuredProfile, int32_t effectiveProfile) {
    configuredProfile = normalizeMtProxyTlsProfileOption(configuredProfile);
    if (configuredProfile != MT_PROXY_TLS_PROFILE_AUTO && configuredProfile != MT_PROXY_TLS_PROFILE_AUTO_ROTATE) {
        return effectiveProfile;
    }
    switch (normalizeMtProxyTlsProfileOption(effectiveProfile)) {
        case MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID:
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        case MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE:
            return MT_PROXY_TLS_PROFILE_LEGACY_NO_GREASE;
        case MT_PROXY_TLS_PROFILE_CHROME_MODERN:
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        case MT_PROXY_TLS_PROFILE_ANDROID_CHROME:
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
        default:
            return MT_PROXY_TLS_PROFILE_FIREFOX_ANDROID;
    }
}
