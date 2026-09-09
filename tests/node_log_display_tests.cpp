#include "../include/gui/node_log_display.h"
#include <cassert>
#include <iostream>
int main() {
    using veld::node_gui::DisplayLogLine;
    assert(DisplayLogLine("[FATAL] db read failed") == "[FATAL] db read failed");
    assert(DisplayLogLine("[IBD complete] height=3722") == "[IBD complete] height=3722");
    assert(DisplayLogLine("{broken") == "{broken");
    for (const auto* reason : {"connected", "unspecified", "remote_eof", "node_stop"}) {
        const std::string raw = std::string("{\"event\":\"connection\",\"reason\":\"") + reason + "\"}";
        const auto display = DisplayLogLine(raw);
        assert(display.find("[network]") == 0);
        assert(display.find("WARN") == std::string::npos);
    }
    for (const auto* reason : {"receive_error", "send_error", "send_timeout", "invalid_frame", "receive_limit", "handshake_timeout", "idle_or_frame_timeout", "policy_rejection", "poll_error"}) {
        assert(DisplayLogLine(std::string("{\"event\":\"connection\",\"reason\":\"") + reason + "\"}").find("[network WARN]") == 0);
    }
    for (const auto* raw : {"{\"event\":\"connection_diagnostics_lost\",\"failed\":2}", "{\"event\":\"connection\",\"reason\":\"future_error\"}", "{\"event\":\"connection\",\"reason\":42}"}) assert(DisplayLogLine(raw) == raw);
    std::cout << "PASS: routine events readable; all failure and unknown events retained\n";
}
