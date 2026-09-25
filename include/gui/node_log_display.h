#pragma once
#include "../network/strict_json.h"
#include <string>

namespace veld::node_gui {
// Presentation only: the raw diagnostic file remains unchanged. Unknown or
// malformed events stay visible so the UI cannot silently hide a new failure.
inline std::string DisplayLogLine(const std::string& line) {
    if (line.empty() || line.front() != '{') return line;
    btc_buy::JsonValue root;
    std::string error;
    btc_buy::StrictJsonParser parser(line, 16U * 1024U, true);
    if (!parser.Parse(root, error) ||
        root.kind != btc_buy::JsonValue::Kind::Object) return line;
    const auto* event = root.Get("event");
    const auto* reason = root.Get("reason");
    if (!event || event->kind != btc_buy::JsonValue::Kind::String ||
        event->text != "connection" || !reason ||
        reason->kind != btc_buy::JsonValue::Kind::String) return line;
    if (reason->text == "connected") return "[network] Peer connected.";
    if (reason->text == "unspecified") return "[network] Peer connection closed.";
    if (reason->text == "remote_eof") return "[network] Peer closed its connection.";
    if (reason->text == "node_stop") return "[network] Peer disconnected for node shutdown.";
    for (const auto* known : {"receive_error", "send_error", "send_timeout",
            "invalid_frame", "receive_limit", "handshake_timeout",
            "idle_or_frame_timeout", "policy_rejection", "poll_error"}) {
        if (reason->text != known) continue;
        std::string readable = reason->text;
        for (char& c : readable) if (c == '_') c = ' ';
        return "[network WARN] Peer disconnected: " + readable + ".";
    }
    return line;
}
} // namespace veld::node_gui
