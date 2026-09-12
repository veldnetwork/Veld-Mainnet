#define VELD_GUI_TEST_INSTANCE 1
#define wWinMain veld_gui_unused_entry
#include "../src/veld-node-gui.cpp"
#undef wWinMain
#include <cassert>
#include <iostream>

namespace {
void SaveLegacyTrust(const std::filesystem::path& path, const PortalTrustState& state);

struct GuiStateQualification {
    static void CheckPairing(const std::filesystem::path& root, const MonitoringReply& reply) {
        const auto dir = root / "first-pairing";
        std::filesystem::create_directory(dir);
        NodeGuiApp app(dir);
        std::string rejection;
        assert(!app.EnrollPortalControl(reply, rejection));
        app.remote_monitoring_enabled_.store(true);
        assert(!app.AuthorizeRemoteCommand(reply.command, rejection));
        auto incomplete = reply;
        incomplete.paired = false;
        assert(!app.EnrollPortalControl(incomplete, rejection));
        incomplete = reply;
        incomplete.command_key_present = false;
        assert(!app.EnrollPortalControl(incomplete, rejection));
        assert(app.EnrollPortalControl(reply, rejection));
        assert(app.remote_trust_.unattended && app.portal_control_ready_.load());
        const auto path = dir / "remote-trust.dat";
        const auto saved = ReadTextBounded(path);
        assert(!saved.empty());
        assert(app.EnrollPortalControl(reply, rejection));
        assert(saved == ReadTextBounded(path));
        assert(app.AuthorizeRemoteCommand(reply.command, rejection));
        assert(app.EnrollPortalControl(reply, rejection));
        assert(app.remote_trust_.last_sequence == reply.command.sequence);
        assert(!app.AuthorizeRemoteCommand(reply.command, rejection));
        assert(rejection.find("Replay") != std::string::npos);

        NodeGuiApp restarted(dir);
        restarted.remote_monitoring_enabled_.store(true);
        assert(!restarted.AuthorizeRemoteCommand(reply.command, rejection));
        assert(restarted.EnrollPortalControl(reply, rejection));
        assert(restarted.remote_trust_.last_sequence == reply.command.sequence);
        assert(!restarted.AuthorizeRemoteCommand(reply.command, rejection));
        assert(rejection.find("Replay") != std::string::npos);
        const auto trusted_record = ReadTextBounded(path);
        auto changed = reply;
        changed.device_id++;
        assert(!restarted.EnrollPortalControl(changed, rejection));
        assert(!restarted.portal_control_ready_.load());
        assert(!restarted.AuthorizeRemoteCommand(reply.command, rejection));
        assert(ReadTextBounded(path) == trusted_record);

        MonitoringReply other;
        assert(ParseMonitoringReply(ReadTextBounded(root / "other-pairing.json", 16384), other));
        assert(!restarted.EnrollPortalControl(other, rejection));
        assert(rejection.find("key changed") != std::string::npos);
    }

    static void CheckMigration(const std::filesystem::path& root, const MonitoringReply& reply,
                               PortalTrustState trusted) {
        for (const bool legacy : {false, true}) {
            const auto dir = root / (legacy ? "v1-migration" : "v2-migration");
            std::filesystem::create_directory(dir);
            trusted.unattended = false;
            trusted.last_sequence = 44;
            const auto path = dir / "remote-trust.dat";
            if (legacy) SaveLegacyTrust(path, trusted);
            else assert(SavePortalTrust(path, trusted));
            NodeGuiApp app(dir);
            app.remote_monitoring_enabled_.store(true);
            std::string rejection;
            assert(app.EnrollPortalControl(reply, rejection));
            PortalTrustState saved;
            assert(LoadPortalTrust(path, saved));
            assert(saved.unattended && saved.last_sequence == 44);
            assert(saved.key_id == trusted.key_id && saved.device_id == trusted.device_id);
            assert(!app.AuthorizeRemoteCommand(reply.command, rejection));
            assert(rejection.find("Replay") != std::string::npos);
        }
    }

    static void CheckStorageFailure(const std::filesystem::path& root, const MonitoringReply& reply) {
        const auto corrupt = root / "corrupt-trust";
        std::filesystem::create_directory(corrupt);
        const std::string invalid = "not a protected pairing record";
        assert(veld::node_gui::WriteStateFile(corrupt / "remote-trust.dat",
            reinterpret_cast<const BYTE*>(invalid.data()), invalid.size()));
        NodeGuiApp app(corrupt);
        app.remote_monitoring_enabled_.store(true);
        std::string rejection;
        assert(app.portal_trust_load_failed_);
        assert(!app.EnrollPortalControl(reply, rejection));
        assert(!app.AuthorizeRemoteCommand(reply.command, rejection));
        assert(ReadTextBounded(corrupt / "remote-trust.dat") == invalid);

        const auto unavailable = root / "unavailable-storage";
        std::filesystem::create_directory(unavailable);
        NodeGuiApp blocked(unavailable);
        blocked.remote_monitoring_enabled_.store(true);
        std::filesystem::create_directory(unavailable / "remote-trust.dat");
        assert(!blocked.EnrollPortalControl(reply, rejection));
        assert(!blocked.AuthorizeRemoteCommand(reply.command, rejection));
        assert(!blocked.remote_trust_.Valid());
        std::filesystem::remove(unavailable / "remote-trust.dat");
        assert(blocked.EnrollPortalControl(reply, rejection));
        assert(blocked.AuthorizeRemoteCommand(reply.command, rejection));
    }

    static void CheckRevocation(const std::filesystem::path& root, const MonitoringReply& reply) {
        const auto dir = root / "revocation";
        std::filesystem::create_directory(dir);
        NodeGuiApp app(dir);
        const auto& command = reply.command;
        std::string rejection;
        app.remote_monitoring_enabled_.store(false);
        assert(!app.AuthorizeRemoteCommand(command, rejection));
        assert(rejection.find("disabled") != std::string::npos);
        app.remote_monitoring_enabled_.store(true);
        app.portal_pair_reset_requested_.store(true);
        assert(!app.EnrollPortalControl(reply, rejection));
        assert(!app.AuthorizeRemoteCommand(command, rejection));
        app.portal_pair_reset_requested_.store(false);
        assert(app.EnrollPortalControl(reply, rejection));
        auto removed = reply;
        removed.paired = false;
        assert(!app.EnrollPortalControl(removed, rejection));
        assert(!app.AuthorizeRemoteCommand(command, rejection));
        assert(app.EnrollPortalControl(reply, rejection));
        assert(app.AuthorizeRemoteCommand(command, rejection));
        assert(app.remote_trust_.unattended);
        assert(!app.AuthorizeRemoteCommand(command, rejection));
        assert(rejection.find("Replay") != std::string::npos);
    }

    static void CheckControlActions(const std::filesystem::path& root) {
        for (const auto* action : {"node.start", "node.stop", "node.signin", "updates.check", "updates.install"}) {
            MonitoringReply reply;
            assert(ParseMonitoringReply(ReadTextBounded(root / (std::string(action) + ".json"), 16384), reply));
            const auto dir = root / (std::string(action) + "-state");
            std::filesystem::create_directory(dir);
            NodeGuiApp app(dir);
            app.remote_monitoring_enabled_.store(true);
            std::string rejection;
            assert(app.EnrollPortalControl(reply, rejection));
            assert(app.AuthorizeRemoteCommand(reply.command, rejection));
            assert(!app.AuthorizeRemoteCommand(reply.command, rejection));
        }
    }

    static void CheckResetPersistence(const std::filesystem::path& root, const MonitoringReply& reply) {
        const auto dir = root / "pending-reset";
        std::filesystem::create_directory(dir);
        NodeGuiApp app(dir);
        app.remote_monitoring_enabled_.store(true);
        std::string rejection;
        assert(app.EnrollPortalControl(reply, rejection));
        assert(app.BeginRemotePairReset());
        assert(!app.EnrollPortalControl(reply, rejection));
        assert(!app.AuthorizeRemoteCommand(reply.command, rejection));
        NodeGuiApp restarted(dir);
        restarted.remote_monitoring_enabled_.store(true);
        assert(restarted.portal_pair_reset_requested_.load());
        assert(!restarted.EnrollPortalControl(reply, rejection));
        assert(!restarted.AuthorizeRemoteCommand(reply.command, rejection));
        const auto path = dir / "remote-trust.dat";
        HANDLE locked = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        assert(locked != INVALID_HANDLE_VALUE);
        assert(!restarted.CompleteRemotePairReset());
        assert(restarted.portal_pair_reset_requested_.load());
        assert(std::filesystem::exists(dir / "remote-pair-reset.dat"));
        CloseHandle(locked);
        assert(restarted.CompleteRemotePairReset());
        assert(!restarted.portal_pair_reset_requested_.load());
        assert(!restarted.remote_trust_.Valid());
        assert(!std::filesystem::exists(path));
        assert(!std::filesystem::exists(dir / "remote-pair-reset.dat"));
        assert(!restarted.AuthorizeRemoteCommand(reply.command, rejection));
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
    GuiStateQualification::CheckPairing(root, reply);
    GuiStateQualification::CheckMigration(root, reply, current);
    GuiStateQualification::CheckStorageFailure(root, reply);
    GuiStateQualification::CheckRevocation(root, reply);
    GuiStateQualification::CheckControlActions(root);
    GuiStateQualification::CheckResetPersistence(root, reply);
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
    std::cout << "PASS: pairing grants remote control without prompts; five signed actions, restart, legacy migration, corrupt trust, storage failure, revocation, replay, expiry, tamper, and device binding\n";
}
