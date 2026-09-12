#define VELD_GUI_TEST_INSTANCE 1
#define wWinMain veld_gui_unused_entry
#include "../src/veld-node-gui.cpp"
#undef wWinMain
#include <cassert>
#include <iostream>

namespace {
struct GuiStateQualification {
    static void CheckRevocation(const std::filesystem::path& dir, const MonitoringReply::Command& command,
                                PortalTrustState trusted) {
        NodeGuiApp app(dir);
        trusted.last_sequence = 0;
        trusted.unattended = true;
        app.remote_trust_ = trusted;
        std::string rejection;
        app.remote_monitoring_enabled_.store(false);
        assert(!app.AuthorizeRemoteCommand(command, rejection));
        assert(rejection.find("disabled") != std::string::npos);
        app.remote_monitoring_enabled_.store(true);
        app.portal_pair_reset_requested_.store(true);
        assert(!app.AuthorizeRemoteCommand(command, rejection));
        app.portal_pair_reset_requested_.store(false);
        assert(app.AuthorizeRemoteCommand(command, rejection));
        assert(app.remote_trust_.unattended);
        assert(!app.AuthorizeRemoteCommand(command, rejection));
        assert(rejection.find("Replay") != std::string::npos);
    }
};

void SaveLegacyTrust(const std::filesystem::path& path, const PortalTrustState& state) {
    std::string text = "VELD_PORTAL_TRUST_V1\n" + std::to_string(state.device_id) + "\n" +
        std::to_string(state.last_sequence) + "\n" + state.key_id + "\n" + state.key_x + "\n" + state.key_y + "\n";
    DATA_BLOB plain{static_cast<DWORD>(text.size()), reinterpret_cast<BYTE*>(text.data())}, encrypted{}, entropy = PortalTrustEntropy();
    assert(CryptProtectData(&plain, L"Veld portal command trust", &entropy, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &encrypted));
    assert(veld::node_gui::WriteStateFile(path, encrypted.pbData, encrypted.cbData));
    SecureZeroMemory(encrypted.pbData, encrypted.cbData);
    LocalFree(encrypted.pbData);
}
}

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::filesystem::path root(argv[1]);
    const auto json = ReadTextBounded(root / "signed-command.json", 16384);
    MonitoringReply reply;
    assert(ParseMonitoringReply(json, reply));
    assert(reply.command.action == "node.signin" && reply.device_id == 17 && reply.protocol == 4);
    PortalTrustState current, next;
    std::string rejection;
    const auto now = static_cast<uint64_t>(std::time(nullptr));
    assert(EvaluatePortalCommandTrust(reply.command, current, now, next, rejection) == PortalCommandTrustVerdict::NewPairing);
    assert(!next.unattended);
    current = next;
    current.unattended = true;
    const auto path = root / "command-trust.dat";
    assert(SavePortalTrust(path, current));
    PortalTrustState reloaded;
    assert(LoadPortalTrust(path, reloaded) && reloaded.unattended);
    const auto legacy_path = root / "legacy-trust.dat";
    SaveLegacyTrust(legacy_path, current);
    PortalTrustState legacy;
    assert(LoadPortalTrust(legacy_path, legacy));
    assert(legacy.Valid() && !legacy.unattended && legacy.last_sequence == current.last_sequence);
    assert(legacy.key_id == current.key_id && legacy.device_id == current.device_id);
    GuiStateQualification::CheckRevocation(root, reply.command, current);
    assert(EvaluatePortalCommandTrust(reply.command, reloaded, now, next, rejection) == PortalCommandTrustVerdict::Reject);
    assert(rejection.find("Replay") != std::string::npos);
    current = {};
    auto changed = reply.command;
    changed.unlock.ciphertext[3] = changed.unlock.ciphertext[3] == 'A' ? 'B' : 'A';
    assert(EvaluatePortalCommandTrust(changed, current, now, next, rejection) == PortalCommandTrustVerdict::Reject);
    assert(EvaluatePortalCommandTrust(reply.command, current, reply.command.expires_at + 1, next, rejection) == PortalCommandTrustVerdict::Reject);
    changed = reply.command;
    changed.device_id = 18;
    assert(EvaluatePortalCommandTrust(changed, current, now, next, rejection) == PortalCommandTrustVerdict::Reject);
    const auto before = ReadTextBounded(path);
    assert(before.find("VELD_PORTAL_TRUST") == std::string::npos);
    std::cout << "PASS: shipping encrypted command parser, browser signature, durable control grant, legacy migration, revocation, replay, expiry, tamper, device binding\n";
}
