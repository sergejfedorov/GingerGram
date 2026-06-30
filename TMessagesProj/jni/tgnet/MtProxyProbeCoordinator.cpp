/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 */

#include "MtProxyProbeCoordinator.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <pthread.h>

// ProbeKey.key is the existing exact recipe key: host:port:secret_hash:SNI.
static constexpr int64_t MT_PROXY_PROBE_UNSUPPORTED_HOLD_MS = 15 * 60 * 1000;
static constexpr uint32_t MT_PROXY_PROBE_JOIN_WAIT_MS = 250;
static constexpr int32_t MT_PROXY_PROBE_ALTERNATE_PROFILE_LEVEL = 3;
static constexpr int32_t MT_PROXY_PROBE_ALTERNATE_PROFILE_COUNT = 4;
static constexpr int32_t MT_PROXY_PROBE_RECIPE_MAX_LEVEL = 4;

enum class ProbeStatus : uint8_t {
    IDLE,
    PROBING,
    WORKING_RECIPE_FOUND,
    UNSUPPORTED,
    NETWORK_FAILED,
    QUARANTINED,
};

struct MtProxyProbeState {
    ProbeStatus status = ProbeStatus::IDLE;
    const void *owner = nullptr;
    uint32_t generation = 0;
    int64_t unsupportedUntil = 0;
    int32_t recipeLevel = 0;
    int32_t workingRecipeLevel = 0;
    int32_t alternateProfileIndex = 0;
    int32_t workingAlternateProfileIndex = 0;
    bool greaseProbePending = false;
    bool greaseSupported = false;
    bool greaseRejected = false;
    std::string endpointKey;
    std::string networkEndpointKey;
    std::string lastRecipeDiagnostic;
};

static pthread_mutex_t mtProxyProbeCoordinatorMutex = PTHREAD_MUTEX_INITIALIZER;
static std::map<std::string, MtProxyProbeState> mtProxyProbeStates;

static bool serverHelloParserVariantAllowed(const std::string &diagnostic) {
    return diagnostic == "server_hello_hmac_mismatch"
           || diagnostic == "unrecognized_tls_response_after_client_hello";
}

static MtProxyProbeCoordinator::Decision decisionFromState(MtProxyProbeCoordinator::DecisionKind kind, const MtProxyProbeState &state) {
    MtProxyProbeCoordinator::Decision decision;
    decision.kind = kind;
    decision.generation = state.generation;
    decision.waitMs = MT_PROXY_PROBE_JOIN_WAIT_MS;
    decision.recipeLevel = state.recipeLevel > 0 ? state.recipeLevel : state.workingRecipeLevel;
    decision.alternateProfileIndex = state.recipeLevel > 0 ? state.alternateProfileIndex : state.workingAlternateProfileIndex;
    decision.workingRecipeLevel = state.workingRecipeLevel;
    decision.workingAlternateProfileIndex = state.workingAlternateProfileIndex;
    decision.lastRecipeDiagnostic = state.lastRecipeDiagnostic;
    decision.greaseProbe.probe = state.greaseProbePending && !state.greaseRejected;
    decision.greaseProbe.supported = state.greaseSupported;
    decision.greaseProbe.rejected = state.greaseRejected;
    decision.greaseProbe.useGrease = decision.greaseProbe.supported || decision.greaseProbe.probe;
    return decision;
}

MtProxyProbeCoordinator::Decision MtProxyProbeCoordinator::beginOrJoin(const ProbeKey &probeKey, const void *owner, int64_t now) {
    if (probeKey.key.empty()) {
        return Decision();
    }

    pthread_mutex_lock(&mtProxyProbeCoordinatorMutex);
    MtProxyProbeState &state = mtProxyProbeStates[probeKey.key];
    state.endpointKey = probeKey.endpointKey;
    state.networkEndpointKey = probeKey.networkEndpointKey;
    if (state.status == ProbeStatus::UNSUPPORTED && state.unsupportedUntil > now) {
        Decision decision = decisionFromState(DecisionKind::TerminalUnsupported, state);
        pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
        return decision;
    }
    if (state.status == ProbeStatus::UNSUPPORTED && state.unsupportedUntil <= now) {
        state.status = ProbeStatus::IDLE;
        state.owner = nullptr;
        state.unsupportedUntil = 0;
    }
    if (state.status == ProbeStatus::WORKING_RECIPE_FOUND) {
        Decision decision = decisionFromState(DecisionKind::UseWorkingRecipe, state);
        pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
        return decision;
    }
    if (state.status == ProbeStatus::PROBING && state.owner != nullptr && state.owner != owner) {
        Decision decision = decisionFromState(DecisionKind::JoinExisting, state);
        pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
        return decision;
    }
    state.status = ProbeStatus::PROBING;
    state.owner = owner;
    state.generation++;
    Decision decision = decisionFromState(DecisionKind::StartOwner, state);
    pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
    return decision;
}

MtProxyProbeCoordinator::FailureResult MtProxyProbeCoordinator::completeFailure(const ProbeKey &probeKey,
                                                                                const void *owner,
                                                                                const std::string &diagnostic,
                                                                                bool recipeUsesGrease,
                                                                                bool recipeIsGreaseProbe,
                                                                                bool classicFallbackAllowed,
                                                                                int64_t now) {
    (void) now;
    FailureResult result;
    if (probeKey.key.empty() || !failureNeedsRecipe(diagnostic)) {
        return result;
    }

    pthread_mutex_lock(&mtProxyProbeCoordinatorMutex);
    MtProxyProbeState &state = mtProxyProbeStates[probeKey.key];
    if (state.owner != nullptr && state.owner != owner) {
        result.generation = state.generation;
        pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
        return result;
    }
    state.status = ProbeStatus::PROBING;
    state.owner = owner;
    state.endpointKey = probeKey.endpointKey;
    state.networkEndpointKey = probeKey.networkEndpointKey;

    if (recipeUsesGrease && recipeIsGreaseProbe) {
        state.greaseProbePending = false;
        state.greaseSupported = false;
        state.greaseRejected = true;
    }

    int32_t previousRecipeLevel = state.recipeLevel > 0 ? state.recipeLevel : state.workingRecipeLevel;
    int32_t previousAlternateProfileIndex = state.recipeLevel > 0 ? state.alternateProfileIndex : state.workingAlternateProfileIndex;
    if (previousRecipeLevel < MT_PROXY_PROBE_ALTERNATE_PROFILE_LEVEL) {
        state.recipeLevel = previousRecipeLevel + 1;
        if (state.recipeLevel == MT_PROXY_PROBE_ALTERNATE_PROFILE_LEVEL) {
            state.alternateProfileIndex = 0;
        }
    } else if (previousRecipeLevel == MT_PROXY_PROBE_ALTERNATE_PROFILE_LEVEL) {
        if (previousAlternateProfileIndex < MT_PROXY_PROBE_ALTERNATE_PROFILE_COUNT - 1) {
            state.recipeLevel = MT_PROXY_PROBE_ALTERNATE_PROFILE_LEVEL;
            state.alternateProfileIndex = previousAlternateProfileIndex + 1;
        } else if (serverHelloParserVariantAllowed(diagnostic)) {
            state.recipeLevel = MT_PROXY_PROBE_RECIPE_MAX_LEVEL;
            state.alternateProfileIndex = previousAlternateProfileIndex;
        } else {
            state.recipeLevel = MT_PROXY_PROBE_RECIPE_MAX_LEVEL;
            state.alternateProfileIndex = previousAlternateProfileIndex;
            result.recipeExhausted = !classicFallbackAllowed;
        }
    } else {
        state.recipeLevel = MT_PROXY_PROBE_RECIPE_MAX_LEVEL;
        result.recipeExhausted = !classicFallbackAllowed;
    }

    state.lastRecipeDiagnostic = diagnostic;
    if (result.recipeExhausted) {
        state.status = ProbeStatus::UNSUPPORTED;
        state.unsupportedUntil = now + MT_PROXY_PROBE_UNSUPPORTED_HOLD_MS;
        state.owner = nullptr;
        state.generation++;
    }
    result.recorded = true;
    result.generation = state.generation;
    result.recipeLevel = state.recipeLevel;
    result.alternateProfileIndex = state.alternateProfileIndex;
    result.cachedRecipeLevel = state.workingRecipeLevel;
    result.cachedAlternateProfileIndex = state.workingAlternateProfileIndex;
    result.lastRecipeDiagnostic = state.lastRecipeDiagnostic;
    pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
    return result;
}

void MtProxyProbeCoordinator::completeSuccess(const ProbeKey &probeKey,
                                              const void *owner,
                                              const char *reason,
                                              bool recipeUsesGrease,
                                              int64_t now) {
    (void) now;
    if (probeKey.key.empty() || reason == nullptr) {
        return;
    }
    if (strcmp(reason, "server_hello_hmac_ok") != 0
            && strcmp(reason, "first_tls_app_recv") != 0
            && strcmp(reason, "first_mtproxy_packet_recv") != 0) {
        return;
    }

    pthread_mutex_lock(&mtProxyProbeCoordinatorMutex);
    MtProxyProbeState &state = mtProxyProbeStates[probeKey.key];
    if (state.owner != nullptr && state.owner != owner && state.status == ProbeStatus::PROBING) {
        pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
        return;
    }
    state.endpointKey = probeKey.endpointKey;
    state.networkEndpointKey = probeKey.networkEndpointKey;
    state.workingRecipeLevel = state.recipeLevel;
    state.workingAlternateProfileIndex = state.alternateProfileIndex;
    state.status = ProbeStatus::WORKING_RECIPE_FOUND;
    state.owner = nullptr;
    state.lastRecipeDiagnostic.clear();
    if (recipeUsesGrease) {
        state.greaseProbePending = false;
        state.greaseSupported = true;
        state.greaseRejected = false;
    } else if (strcmp(reason, "first_tls_app_recv") == 0 && !state.greaseSupported && !state.greaseRejected) {
        state.greaseProbePending = true;
    }
    pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
}

void MtProxyProbeCoordinator::completeUnsupported(const ProbeKey &probeKey, const void *owner, int64_t now) {
    if (probeKey.key.empty()) {
        return;
    }
    pthread_mutex_lock(&mtProxyProbeCoordinatorMutex);
    MtProxyProbeState &state = mtProxyProbeStates[probeKey.key];
    if (state.owner != nullptr && state.owner != owner) {
        pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
        return;
    }
    state.status = ProbeStatus::UNSUPPORTED;
    state.owner = nullptr;
    state.unsupportedUntil = now + MT_PROXY_PROBE_UNSUPPORTED_HOLD_MS;
    state.generation++;
    pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
}

void MtProxyProbeCoordinator::cancelOwner(const ProbeKey &probeKey, const void *owner) {
    if (probeKey.key.empty()) {
        return;
    }
    pthread_mutex_lock(&mtProxyProbeCoordinatorMutex);
    auto it = mtProxyProbeStates.find(probeKey.key);
    if (it != mtProxyProbeStates.end() && it->second.owner == owner) {
        it->second.owner = nullptr;
        if (it->second.status == ProbeStatus::PROBING) {
            it->second.status = it->second.workingRecipeLevel > 0 ? ProbeStatus::WORKING_RECIPE_FOUND : ProbeStatus::IDLE;
        }
    }
    pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
}

bool MtProxyProbeCoordinator::failureNeedsRecipe(const std::string &diagnostic) {
    if (diagnostic == "tcp_not_connected") {
        return false;
    }
    return diagnostic == "true_client_hello_timeout"
           || diagnostic == "faketls_server_hello_wait_timeout"
           || diagnostic == "server_closed_after_client_hello"
           || diagnostic == "client_hello_sent_no_server_hello"
           || diagnostic == "tls_alert_after_client_hello"
           || diagnostic == "short_tls_response_after_client_hello"
           || diagnostic == "unrecognized_tls_response_after_client_hello"
           || diagnostic == "server_hello_hmac_mismatch"
           || diagnostic == "post_handshake_no_appdata";
}

int32_t MtProxyProbeCoordinator::recipeLevelForProbe(const std::string &probeKey) {
    int32_t recipeLevel = 0;
    pthread_mutex_lock(&mtProxyProbeCoordinatorMutex);
    auto it = mtProxyProbeStates.find(probeKey);
    if (it != mtProxyProbeStates.end()) {
        recipeLevel = it->second.recipeLevel > 0 ? it->second.recipeLevel : it->second.workingRecipeLevel;
    }
    pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
    return recipeLevel;
}

int32_t MtProxyProbeCoordinator::recipeAlternateProfileIndexForProbe(const std::string &probeKey) {
    int32_t alternateProfileIndex = 0;
    pthread_mutex_lock(&mtProxyProbeCoordinatorMutex);
    auto it = mtProxyProbeStates.find(probeKey);
    if (it != mtProxyProbeStates.end()) {
        alternateProfileIndex = it->second.recipeLevel > 0 ? it->second.alternateProfileIndex : it->second.workingAlternateProfileIndex;
    }
    pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
    return alternateProfileIndex;
}

std::string MtProxyProbeCoordinator::lastRecipeDiagnosticForProbe(const std::string &probeKey) {
    std::string diagnostic;
    pthread_mutex_lock(&mtProxyProbeCoordinatorMutex);
    auto it = mtProxyProbeStates.find(probeKey);
    if (it != mtProxyProbeStates.end()) {
        diagnostic = it->second.lastRecipeDiagnostic;
    }
    pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
    return diagnostic;
}

MtProxyProbeCoordinator::GreaseProbeResult MtProxyProbeCoordinator::readGreaseProbeState(const std::string &probeKey) {
    GreaseProbeResult result;
    pthread_mutex_lock(&mtProxyProbeCoordinatorMutex);
    auto it = mtProxyProbeStates.find(probeKey);
    if (it != mtProxyProbeStates.end()) {
        result.probe = it->second.greaseProbePending && !it->second.greaseRejected;
        result.supported = it->second.greaseSupported;
        result.rejected = it->second.greaseRejected;
        result.useGrease = result.supported || result.probe;
    }
    pthread_mutex_unlock(&mtProxyProbeCoordinatorMutex);
    return result;
}
