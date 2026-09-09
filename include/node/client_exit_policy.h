#pragma once
#include <cstdint>

namespace veld::node_client {

enum class ExitAction { Stop, Restart, Inspect };
inline constexpr unsigned MAX_RECOVERY_RESTARTS = 3;

// Only a process owned by this client reaches this policy. Exit 75 requests
// a checked restart; exit 76 requires inspection. Operator stops always win.
inline constexpr ExitAction ClassifyExit(uint32_t code, bool operator_stop,
                                         unsigned recent_restarts) noexcept {
    if (operator_stop) return ExitAction::Stop;
    if (code == 76) return ExitAction::Inspect;
    if (code == 75)
        return recent_restarts < MAX_RECOVERY_RESTARTS
            ? ExitAction::Restart : ExitAction::Inspect;
    return ExitAction::Stop;
}

} // namespace veld::node_client
