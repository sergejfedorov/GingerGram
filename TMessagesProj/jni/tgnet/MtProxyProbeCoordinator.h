/*
 * This is the source code of tgnet library v. 1.1
 * It is licensed under GNU GPL v. 2 or later.
 */

#ifndef MTPROXYPROBECOORDINATOR_H
#define MTPROXYPROBECOORDINATOR_H

#include <stdint.h>
#include <string>

class MtProxyProbeCoordinator {
public:
    enum class DecisionKind : uint8_t {
        StartOwner,
        JoinExisting,
        UseWorkingRecipe,
        TerminalUnsupported,
    };

    struct ProbeKey {
        std::string key;
        std::string endpointKey;
        std::string networkEndpointKey;
    };

    struct GreaseProbeResult {
        bool useGrease = false;
        bool probe = false;
        bool supported = false;
        bool rejected = false;
    };

    struct Decision {
        DecisionKind kind = DecisionKind::StartOwner;
        uint32_t generation = 0;
        uint32_t waitMs = 0;
        int32_t recipeLevel = 0;
        int32_t alternateProfileIndex = 0;
        int32_t workingRecipeLevel = 0;
        int32_t workingAlternateProfileIndex = 0;
        std::string lastRecipeDiagnostic;
        GreaseProbeResult greaseProbe;
    };

    struct FailureResult {
        bool recorded = false;
        bool recipeExhausted = false;
        uint32_t generation = 0;
        int32_t recipeLevel = 0;
        int32_t alternateProfileIndex = 0;
        int32_t cachedRecipeLevel = 0;
        int32_t cachedAlternateProfileIndex = 0;
        std::string lastRecipeDiagnostic;
    };

    static Decision beginOrJoin(const ProbeKey &probeKey, const void *owner, int64_t now);
    static FailureResult completeFailure(const ProbeKey &probeKey,
                                         const void *owner,
                                         const std::string &diagnostic,
                                         bool recipeUsesGrease,
                                         bool recipeIsGreaseProbe,
                                         bool classicFallbackAllowed,
                                         int64_t now);
    static void completeSuccess(const ProbeKey &probeKey,
                                const void *owner,
                                const char *reason,
                                bool recipeUsesGrease,
                                int64_t now);
    static void completeUnsupported(const ProbeKey &probeKey, const void *owner, int64_t now);
    static void cancelOwner(const ProbeKey &probeKey, const void *owner);

    static bool failureNeedsRecipe(const std::string &diagnostic);
    static int32_t recipeLevelForProbe(const std::string &probeKey);
    static int32_t recipeAlternateProfileIndexForProbe(const std::string &probeKey);
    static std::string lastRecipeDiagnosticForProbe(const std::string &probeKey);
    static GreaseProbeResult readGreaseProbeState(const std::string &probeKey);
};

#endif
