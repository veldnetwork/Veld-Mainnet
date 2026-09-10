#define VELD_GUI_TEST_INSTANCE 1
#define wWinMain veld_gui_unused_entry
#include "../src/veld-node-gui.cpp"
#undef wWinMain
#include <cassert>
#include <iostream>

namespace {
struct GuiStateQualification {
    static std::string Report(const std::filesystem::path& dir) {
        NodeGuiApp app(dir);
        app.LoadSettings();
        LiveState live;
        uint64_t included_ack = 0;
        return app.BuildMonitoringReport(live, included_ack);
    }
    static bool LoadSave(const std::filesystem::path& dir, bool expected_ok) {
        NodeGuiApp app(dir);
        app.LoadSettings();
        if (expected_ok) {
            assert(app.mining_thread_count_ == 15);
            assert(app.mining_preset_ == 3);
            assert(app.full_ibd_choice_ && app.sync_choice_explicit_);
            assert(app.remote_monitoring_enabled_);
            assert(!app.tor_choice_ && app.reachable_choice_);
        }
        return app.SaveSettings();
    }
};

void WriteFixture(const std::filesystem::path& path, const std::string& bytes) {
    std::ofstream out(path, std::ios::binary);
    out.write(bytes.data(), bytes.size());
    out.close(); assert(out.good());
}
struct FileLock {
    HANDLE handle = INVALID_HANDLE_VALUE;
    FileLock(const std::filesystem::path& path, DWORD sharing) {
        handle = CreateFileW(path.c_str(), GENERIC_READ, sharing, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        assert(handle != INVALID_HANDLE_VALUE);
    }
    ~FileLock() { CloseHandle(handle); }
};
}

int main(int argc, char** argv) {
    assert(argc == 2);
    const auto root = std::filesystem::path(argv[1]);
    assert(!std::filesystem::exists(root));
    const auto dir = root / L"User \u00e9 \u65e5\u672c\u8a9e";
    std::filesystem::create_directories(dir);
    const auto conf = dir / L"node-gui.conf";
    const std::string settings =
        "\xef\xbb\xbfmining=1\r\nmining_preset=custom\r\nmining_threads=15\r\n"
        "sync=full\r\nremote_monitoring=1\r\nreachable=1\r\ntor=0\r\n";
    WriteFixture(conf, settings);
    assert(GuiStateQualification::LoadSave(dir, true));
    const auto saved = ReadTextBounded(conf);
    assert(saved.find("mining_threads=15\n") != std::string::npos);
    assert(saved.find("sync=full\n") != std::string::npos);
    assert(GuiStateQualification::LoadSave(dir, true));
    assert(ReadTextBounded(conf) == saved);
    {
        FileLock deny_replace(conf, FILE_SHARE_READ);
        assert(!GuiStateQualification::LoadSave(dir, true));
        assert(ReadTextBounded(conf) == saved);
    }
    {
        FileLock unreadable(conf, 0);
        assert(!GuiStateQualification::LoadSave(dir, false));
    }
    assert(ReadTextBounded(conf) == saved);
    assert(GuiStateQualification::LoadSave(dir, true));
    std::cout << "PASS: BOM/CRLF legacy settings, Unicode path, 15 workers, full sync, monitoring, restart, sharing failures\n";
    WriteFixture(root / "monitoring-report.json", GuiStateQualification::Report(dir));

    const auto token_file = dir / L"remote-monitor.dat";
    const auto token = NewDeviceToken();
    assert(IsDeviceToken(token));
    assert(SaveDeviceToken(token_file, token));
    assert(LoadDeviceToken(token_file) == token);
    const auto token_bytes = ReadTextBounded(token_file);
    assert(!token_bytes.empty() && token_bytes.find(token) == std::string::npos);
    assert(!SaveDeviceToken(token_file, NewDeviceToken()));
    assert(ReadTextBounded(token_file) == token_bytes);
    {
        FileLock unreadable(token_file, 0);
        assert(LoadDeviceToken(token_file).empty());
        assert(!SaveDeviceToken(token_file, NewDeviceToken()));
    }
    assert(LoadDeviceToken(token_file) == token);
    std::cout << "PASS: protected pairing identity, duplicate save refused, unreadable identity preserved\n";

    PortalTrustState trust;
    trust.device_id = 17;
    trust.last_sequence = 42;
    trust.key_x = std::string(43, 'A');
    trust.key_y = std::string(43, 'A');
    trust.key_id = PortalCommandKeyId(trust.key_x, trust.key_y);
    assert(trust.Valid());
    const auto trust_file = dir / L"remote-trust.dat";
    assert(SavePortalTrust(trust_file, trust));
    PortalTrustState read_trust;
    assert(LoadPortalTrust(trust_file, read_trust));
    assert(read_trust.last_sequence == 42 && read_trust.device_id == trust.device_id);
    const auto trust_bytes = ReadTextBounded(trust_file);
    {
        FileLock deny_replace(trust_file, FILE_SHARE_READ);
        trust.last_sequence = 43;
        assert(!SavePortalTrust(trust_file, trust));
    }
    assert(ReadTextBounded(trust_file) == trust_bytes);
    assert(SavePortalTrust(trust_file, trust));
    assert(LoadPortalTrust(trust_file, read_trust) && read_trust.last_sequence == 43);
    std::cout << "PASS: protected portal replay state, failed save preserves prior sequence, successful retry advances\n";

    const auto result_file = dir / L"update-last-result.json";
    WriteFixture(result_file, R"({"schema":1,"status":"failed","phase":"Commit","message":"File is busy. Close other Veld windows and retry."})");
    assert(ReadLastUpdateFailure(dir) == "File is busy. Close other Veld windows and retry.");
    WriteFixture(result_file, R"({"schema":1,"status":"recovery-required","message":"Recovery needs attention"})");
    assert(ReadLastUpdateFailure(dir) == "Recovery needs attention");
    WriteFixture(result_file, R"({"schema":1,"status":"installed","message":"Completed"})");
    assert(ReadLastUpdateFailure(dir).empty());
    WriteFixture(result_file, "partial");
    assert(ReadLastUpdateFailure(dir).empty());
    std::cout << "PASS: hidden update failure visible after relaunch, success and malformed result handled\n";
}
