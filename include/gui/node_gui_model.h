#pragma once

#include "../network/strict_json.h"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>
#include <unordered_set>
#include <vector>

namespace veld::node_gui {

struct ChainStats {
    uint64_t height{0};
    uint64_t peers{0};
    uint64_t tip_timestamp{0};
    uint64_t mempool_size{0};
    double supply_veld{0.0};
    std::string best_block_hash;
};

struct MiningStats {
    bool mining_configured{false};
    bool mining_ready{false};
    bool mining_active{false};
    uint64_t total_hashes{0};
    uint64_t threads{0};
    uint64_t blocks_mined_session{0};
    uint64_t progress_counter{0};
    uint64_t updated_at{0};
    double hashrate{0.0};
    std::string miner_address;
    std::string work_state;
};

struct BlockSummary {
    uint64_t height{0};
    uint64_t timestamp{0};
    uint64_t transaction_count{0};
    double reward_veld{0.0};
    std::string hash;
    std::string winner;
};

struct PeerSummary {
    uint64_t anonymous_id{0};
    uint32_t role_index{0};
    bool identified{false};
    bool inbound{false};
    bool exact_tip{false};
    uint64_t services{0};
    uint64_t bytes_sent{0};
    uint64_t bytes_recv{0};
    uint64_t peer_height{0};
    int64_t peer_tip_age_s{-1};
    int64_t lag_blocks{0};
    std::string role{"node"};
};

struct TopologyNode {
    uint64_t anonymous_id{0};
    uint64_t updated_at{0};
    uint32_t role_index{0};
    std::string role{"node"};
    std::string tip_state{"unavailable"};
};

struct TopologyEdge {
    uint64_t first{0};
    uint64_t second{0};
    bool confirmed{false};
};

struct TopologySnapshot {
    uint64_t generated_at{0};
    uint64_t reporting_nodes{0};
    uint64_t eligible_nodes{0};
    std::vector<TopologyNode> nodes;
    std::vector<TopologyEdge> edges;
};

inline bool IsTopologyRole(const std::string& role) {
    return role == "fleet" || role == "node" || role == "miner" ||
           role == "validator";
}

inline bool IsTopologyTipState(const std::string& state) {
    return state == "exact" || state == "differs" ||
           state == "stale" || state == "unavailable";
}

inline bool ParseUint(const btc_buy::JsonValue* value, uint64_t& out) {
    if (!value || value->kind != btc_buy::JsonValue::Kind::Number ||
        value->text.empty()) return false;
    uint64_t parsed = 0;
    const char* begin = value->text.data();
    const char* end = begin + value->text.size();
    const auto result = std::from_chars(begin, end, parsed, 10);
    if (result.ec != std::errc{} || result.ptr != end) return false;
    out = parsed;
    return true;
}

inline bool ParseDouble(const btc_buy::JsonValue* value, double& out) {
    if (!value || value->kind != btc_buy::JsonValue::Kind::Number ||
        value->text.empty()) return false;
    char* end = nullptr;
    const double parsed = std::strtod(value->text.c_str(), &end);
    if (!end || end != value->text.c_str() + value->text.size() ||
        !std::isfinite(parsed)) return false;
    out = parsed;
    return true;
}

inline bool ParseBool(const btc_buy::JsonValue* value, bool& out) {
    if (!value || value->kind != btc_buy::JsonValue::Kind::Bool)
        return false;
    out = value->boolean;
    return true;
}

inline bool ParseInt(const btc_buy::JsonValue* value, int64_t& out) {
    if (!value || value->kind != btc_buy::JsonValue::Kind::Number ||
        value->text.empty()) return false;
    int64_t parsed = 0;
    const char* begin = value->text.data();
    const char* end = begin + value->text.size();
    const auto result = std::from_chars(begin, end, parsed, 10);
    if (result.ec != std::errc{} || result.ptr != end) return false;
    out = parsed;
    return true;
}

inline bool ParseGuiPeerStatus(const std::string& body,
                               std::vector<PeerSummary>& out,
                               std::string& error,
                               uint64_t* known_peer_count = nullptr,
                               bool* port_mapped = nullptr,
                               uint64_t* local_topology_id = nullptr) {
    btc_buy::JsonValue root;
    btc_buy::StrictJsonParser parser(body, 256U * 1024U,
                                     /*reject_escaped_object_keys=*/true);
    if (!parser.Parse(root, error) ||
        root.kind != btc_buy::JsonValue::Kind::Object) {
        if (error.empty()) error = "GUI status is not an object";
        return false;
    }
    const auto* result = root.Get("peer_details");
    if (!result || result->kind != btc_buy::JsonValue::Kind::Array ||
         result->array.size() > 256) {
        error = "GUI peer status is not a bounded array";
        return false;
    }
    uint64_t parsed_known_peer_count = result->array.size();
    if (const auto* known = root.Get("known_peer_count")) {
        if (!ParseUint(known, parsed_known_peer_count) ||
            parsed_known_peer_count > 4096) {
            error = "known peer count is invalid";
            return false;
        }
    }
    bool parsed_port_mapped = false;
    if (const auto* mapped = root.Get("port_mapped")) {
        if (!ParseBool(mapped, parsed_port_mapped)) {
            error = "port mapping status is invalid";
            return false;
        }
    }
    uint64_t parsed_local_topology_id = 0;
    if (const auto* topology_id = root.Get("topology_id")) {
        if (!ParseUint(topology_id, parsed_local_topology_id)) {
            error = "local topology identity is invalid";
            return false;
        }
    }

    std::vector<PeerSummary> parsed;
    parsed.reserve(result->array.size());
    for (const auto& item : result->array) {
        if (item.kind != btc_buy::JsonValue::Kind::Object) {
            error = "peer entry is not an object";
            return false;
        }
        PeerSummary peer;
        uint64_t anonymous_id = 0;
        if (!ParseUint(item.Get("id"), anonymous_id) ||
            anonymous_id == 0 ||
            !ParseBool(item.Get("inbound"), peer.inbound) ||
            !ParseBool(item.Get("exact_tip"), peer.exact_tip) ||
            !ParseUint(item.Get("bytes_sent"), peer.bytes_sent) ||
            !ParseUint(item.Get("bytes_recv"), peer.bytes_recv) ||
            !ParseUint(item.Get("peer_height"), peer.peer_height) ||
            !ParseInt(item.Get("peer_tip_age_s"), peer.peer_tip_age_s) ||
            !ParseInt(item.Get("lag_blocks"), peer.lag_blocks)) {
            error = "peer entry has an invalid field";
            return false;
        }
        if (const auto* identified = item.Get("identified")) {
            if (!ParseBool(identified, peer.identified)) {
                error = "peer entry has invalid identity state";
                return false;
            }
        }
        if (const auto* services = item.Get("services")) {
            if (!ParseUint(services, peer.services)) {
                error = "peer entry has invalid services";
                return false;
            }
        }
        if (const auto* role_index = item.Get("role_index")) {
            uint64_t parsed_role_index = 0;
            if (!ParseUint(role_index, parsed_role_index) ||
                parsed_role_index > 999) {
                error = "peer entry has invalid role index";
                return false;
            }
            peer.role_index = static_cast<uint32_t>(parsed_role_index);
        }
        if (const auto* role = item.Get("role")) {
            if (role->kind != btc_buy::JsonValue::Kind::String ||
                (role->text != "mesh" && !IsTopologyRole(role->text))) {
                error = "peer entry has invalid role";
                return false;
            }
            peer.role = role->text;
        }
        peer.anonymous_id = anonymous_id;
        parsed.push_back(std::move(peer));
    }
    std::sort(parsed.begin(), parsed.end(),
              [](const PeerSummary& a, const PeerSummary& b) {
                  return a.anonymous_id < b.anonymous_id;
              });
    out = std::move(parsed);
    if (known_peer_count) *known_peer_count = parsed_known_peer_count;
    if (port_mapped) *port_mapped = parsed_port_mapped;
    if (local_topology_id) *local_topology_id = parsed_local_topology_id;
    return true;
}

inline bool ParseTopologySnapshot(const std::string& body,
                                  TopologySnapshot& out,
                                  std::string& error) {
    btc_buy::JsonValue root;
    btc_buy::StrictJsonParser parser(body, 256U * 1024U,
                                     /*reject_escaped_object_keys=*/true);
    if (!parser.Parse(root, error) ||
        root.kind != btc_buy::JsonValue::Kind::Object) {
        if (error.empty()) error = "topology response is not an object";
        return false;
    }

    uint64_t schema = 0;
    TopologySnapshot parsed;
    if (!ParseUint(root.Get("schema"), schema) || schema != 1 ||
        !ParseUint(root.Get("generated_at"), parsed.generated_at) ||
        !ParseUint(root.Get("reporting_nodes"), parsed.reporting_nodes) ||
        !ParseUint(root.Get("eligible_nodes"), parsed.eligible_nodes) ||
        parsed.reporting_nodes > 256 || parsed.eligible_nodes > 4096 ||
        parsed.reporting_nodes > parsed.eligible_nodes) {
        error = "topology metadata is invalid";
        return false;
    }

    const auto* nodes = root.Get("nodes");
    const auto* edges = root.Get("edges");
    if (!nodes || nodes->kind != btc_buy::JsonValue::Kind::Array ||
        nodes->array.size() > 256 ||
        !edges || edges->kind != btc_buy::JsonValue::Kind::Array ||
        edges->array.size() > 1024) {
        error = "topology graph exceeds its bounds";
        return false;
    }

    std::unordered_set<uint64_t> node_ids;
    parsed.nodes.reserve(nodes->array.size());
    for (const auto& item : nodes->array) {
        if (item.kind != btc_buy::JsonValue::Kind::Object) {
            error = "topology node is not an object";
            return false;
        }
        TopologyNode node;
        if (!ParseUint(item.Get("id"), node.anonymous_id) ||
            node.anonymous_id == 0 ||
            !ParseUint(item.Get("updated_at"), node.updated_at)) {
            error = "topology node has an invalid field";
            return false;
        }
        const auto* role = item.Get("role");
        if (!role || role->kind != btc_buy::JsonValue::Kind::String ||
            !IsTopologyRole(role->text)) {
            error = "topology node has an invalid role";
            return false;
        }
        node.role = role->text;
        if (const auto* tip_state = item.Get("tip_state")) {
            if (tip_state->kind != btc_buy::JsonValue::Kind::String ||
                !IsTopologyTipState(tip_state->text)) {
                error = "topology node has an invalid tip state";
                return false;
            }
            node.tip_state = tip_state->text;
        }
        if (const auto* role_index = item.Get("role_index")) {
            uint64_t parsed_role_index = 0;
            if (!ParseUint(role_index, parsed_role_index) ||
                parsed_role_index > 999) {
                error = "topology node has an invalid role index";
                return false;
            }
            node.role_index = static_cast<uint32_t>(parsed_role_index);
        }
        if (!node_ids.insert(node.anonymous_id).second) {
            error = "topology contains a duplicate node";
            return false;
        }
        parsed.nodes.push_back(std::move(node));
    }

    std::unordered_set<std::string> edge_ids;
    parsed.edges.reserve(edges->array.size());
    for (const auto& item : edges->array) {
        if (item.kind != btc_buy::JsonValue::Kind::Object) {
            error = "topology edge is not an object";
            return false;
        }
        TopologyEdge edge;
        if (!ParseUint(item.Get("a"), edge.first) ||
            !ParseUint(item.Get("b"), edge.second) ||
            !ParseBool(item.Get("confirmed"), edge.confirmed) ||
            edge.first == 0 || edge.second == 0 ||
            edge.first == edge.second ||
            node_ids.count(edge.first) == 0 ||
            node_ids.count(edge.second) == 0) {
            error = "topology edge has an invalid field";
            return false;
        }
        if (edge.second < edge.first) std::swap(edge.first, edge.second);
        const std::string edge_id = std::to_string(edge.first) + ":" +
                                    std::to_string(edge.second);
        if (!edge_ids.insert(edge_id).second) {
            error = "topology contains a duplicate edge";
            return false;
        }
        parsed.edges.push_back(edge);
    }

    out = std::move(parsed);
    return true;
}

inline bool ParseStats(const std::string& body, ChainStats& out,
                       std::string& error) {
    btc_buy::JsonValue root;
    btc_buy::StrictJsonParser parser(body, 256U * 1024U,
                                     /*reject_escaped_object_keys=*/true);
    if (!parser.Parse(root, error) ||
        root.kind != btc_buy::JsonValue::Kind::Object) {
        if (error.empty()) error = "stats response is not an object";
        return false;
    }

    ChainStats parsed;
    if (!ParseUint(root.Get("height"), parsed.height) ||
        !ParseUint(root.Get("peers_local"), parsed.peers) ||
        !ParseUint(root.Get("tip_timestamp"), parsed.tip_timestamp) ||
        !ParseUint(root.Get("mempool_size_local"), parsed.mempool_size) ||
        !ParseDouble(root.Get("supply_veld"), parsed.supply_veld)) {
        error = "stats response is missing a required numeric field";
        return false;
    }
    const auto* hash = root.Get("best_block_hash");
    if (!hash || hash->kind != btc_buy::JsonValue::Kind::String ||
        hash->text.size() != 64) {
        error = "stats response has an invalid best block hash";
        return false;
    }
    parsed.best_block_hash = hash->text;
    out = std::move(parsed);
    return true;
}

inline bool ParseMiningStats(const std::string& body, MiningStats& out,
                             std::string& error) {
    btc_buy::JsonValue root;
    btc_buy::StrictJsonParser parser(body, 64U * 1024U,
                                     /*reject_escaped_object_keys=*/true);
    if (!parser.Parse(root, error) ||
        root.kind != btc_buy::JsonValue::Kind::Object) {
        if (error.empty()) error = "mining status is not an object";
        return false;
    }

    MiningStats parsed;
    if (!ParseBool(root.Get("mining_configured"), parsed.mining_configured) ||
        !ParseBool(root.Get("mining_ready"), parsed.mining_ready) ||
        !ParseBool(root.Get("mining_active"), parsed.mining_active) ||
        !ParseUint(root.Get("total_hashes"), parsed.total_hashes) ||
        !ParseUint(root.Get("threads"), parsed.threads) ||
        !ParseUint(root.Get("blocks_mined_session"),
                   parsed.blocks_mined_session) ||
        !ParseUint(root.Get("progress_counter"), parsed.progress_counter) ||
        !ParseUint(root.Get("updated_at"), parsed.updated_at) ||
        !ParseDouble(root.Get("hashrate"), parsed.hashrate)) {
        error = "mining status is missing a required field";
        return false;
    }
    const auto* work_state = root.Get("work_state");
    if (!work_state || work_state->kind != btc_buy::JsonValue::Kind::String ||
        work_state->text.empty() || work_state->text.size() > 48) {
        error = "mining status has an invalid work state";
        return false;
    }
    const auto* address = root.Get("miner_address");
    if (!address || address->kind != btc_buy::JsonValue::Kind::String ||
        address->text.size() < 20 || address->text.size() > 128) {
        error = "mining status has an invalid address";
        return false;
    }
    parsed.work_state = work_state->text;
    parsed.miner_address = address->text;
    out = std::move(parsed);
    return true;
}

inline bool ParseBlockSummary(const std::string& body, BlockSummary& out,
                              std::string& error) {
    btc_buy::JsonValue root;
    btc_buy::StrictJsonParser parser(body, 256U * 1024U,
                                     /*reject_escaped_object_keys=*/true);
    if (!parser.Parse(root, error) ||
        root.kind != btc_buy::JsonValue::Kind::Object) {
        if (error.empty()) error = "block response is not an object";
        return false;
    }

    BlockSummary parsed;
    if (!ParseUint(root.Get("height"), parsed.height) ||
        !ParseUint(root.Get("time"), parsed.timestamp) ||
        !ParseUint(root.Get("tx_count"), parsed.transaction_count) ||
        !ParseDouble(root.Get("reward_veld"), parsed.reward_veld)) {
        error = "block response is missing a required numeric field";
        return false;
    }
    const auto* hash = root.Get("hash");
    const auto* winner = root.Get("winner");
    if (!hash || hash->kind != btc_buy::JsonValue::Kind::String ||
        hash->text.size() != 64 || !winner ||
        winner->kind != btc_buy::JsonValue::Kind::String ||
        winner->text.size() > 128) {
        error = "block response has an invalid hash or winner";
        return false;
    }
    parsed.hash = hash->text;
    parsed.winner = winner->text;
    out = std::move(parsed);
    return true;
}

struct SyncProgress {
    uint64_t local_height{0};
    uint64_t target_height{0};
    uint64_t remaining{0};
    double percent{0.0};
    bool target_known{false};
    bool complete{false};
};

inline SyncProgress ComputeSyncProgress(uint64_t local_height,
                                        uint64_t reference_height) {
    SyncProgress out;
    out.local_height = local_height;
    out.target_height = std::max(local_height, reference_height);
    out.target_known = reference_height > 0;
    if (!out.target_known) return out;
    out.remaining = out.target_height > local_height
        ? out.target_height - local_height : 0;
    out.percent = out.target_height == 0 ? 0.0
        : std::min(100.0, 100.0 * static_cast<double>(local_height) /
                              static_cast<double>(out.target_height));
    out.complete = out.remaining == 0;
    return out;
}

} // namespace veld::node_gui
