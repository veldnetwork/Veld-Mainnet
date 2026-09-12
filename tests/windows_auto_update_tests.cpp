#define VELD_GUI_TEST_INSTANCE 1
#define wWinMain veld_gui_unused_entry
#include "../src/veld-node-gui.cpp"
#undef wWinMain
#include <cassert>
#include <iostream>

namespace {
struct GuiStateQualification {
    static void Configure(NodeGuiApp& app, const std::filesystem::path& root) {
        app.node_path_ = root / L"bin" / L"veld-node.exe";
        app.data_dir_ = root / L"custom data";
    }
    static void Settings(const std::filesystem::path& profile, const std::filesystem::path& root) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.LoadSettings();
        assert(!app.auto_update_enabled_);
        app.auto_update_enabled_ = true;
        app.mining_thread_count_ = 15;
        app.mining_preset_ = 3;
        assert(app.SaveSettings());
        NodeGuiApp restarted(profile);
        Configure(restarted, root);
        restarted.LoadSettings();
        assert(restarted.auto_update_enabled_ && restarted.mining_thread_count_ == 15);
        restarted.auto_update_enabled_ = false;
        assert(restarted.SaveSettings());
        restarted.LoadSettings();
        assert(!restarted.auto_update_enabled_);
    }
    static std::filesystem::path Prepare(const std::filesystem::path& profile, const std::filesystem::path& root) {
        NodeGuiApp app(profile);
        Configure(app, root);
        assert(!app.PrepareUpdateResume());
        assert(app.StoreSessionPassphrase(L"Disposable fixture only \u65e5\u672c\u8a9e"));
        assert(!app.PrepareUpdateResume());
        app.session_unlock_confirmed_.store(true);
        assert(app.PrepareUpdateResume());
        assert(!app.PrepareUpdateResume());
        return app.UpdateResumePath();
    }
    static bool Resume(const std::filesystem::path& profile, const std::filesystem::path& root) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.LoadSettings();
        app.LoadUpdateResume();
        if (app.update_resume_pending_) {
            assert(app.HasSessionUnlock());
            std::wstring pass;
            assert(app.LoadSessionPassphrase(pass));
            assert(pass == L"Disposable fixture only \u65e5\u672c\u8a9e");
            SecureZeroMemory(pass.data(), pass.size() * sizeof(wchar_t));
            assert(app.data_dir_ == std::filesystem::weakly_canonical(root / L"custom data"));
        }
        return app.update_resume_pending_;
    }
    static void DownloadFailure(const std::filesystem::path& profile, const std::filesystem::path& root) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.state_.process_running = true;
        app.state_.pid = GetCurrentProcessId();
        app.automatic_update_operation_ = true;
        assert(app.StoreSessionPassphrase(L"Fixture session stays unlocked"));
        assert(app.BeginUpdateInstall());
        assert(WaitForSingleObject(app.update_process_, 15000) == WAIT_OBJECT_0);
        DWORD exit_code = 0;
        assert(GetExitCodeProcess(app.update_process_, &exit_code) && exit_code == 1);
        app.OnUpdateProcessComplete(exit_code);
        assert(app.HasSessionUnlock());
        assert(!app.automatic_install_pending_);
        assert(app.next_auto_update_ > std::chrono::steady_clock::now() + std::chrono::minutes(29));
    }
};

void Write(const std::filesystem::path& path, const std::string& text) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary); out << text; out.close(); assert(out.good());
}
}

int main(int argc, char** argv) {
    if (argc == 3 && std::string(argv[1]) == "--consume") {
        const auto root = std::filesystem::absolute(argv[2]);
        return GuiStateQualification::Resume(root / L"private profile",
            root / L"Install \u00e9 \u65e5\u672c\u8a9e") ? 0 : 1;
    }
    assert(argc == 2);
    const auto root = std::filesystem::absolute(argv[1]);
    assert(!std::filesystem::exists(root));
    const auto install = root / L"Install \u00e9 \u65e5\u672c\u8a9e";
    const auto profile = root / L"private profile";
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(install / L"custom data");
    std::filesystem::create_directories(install / L"bin");
    GuiStateQualification::Settings(profile, install);
    std::cout << "PASS settings opt-in, disable, reload and 15 workers\n";
    const auto stage = install / L".veld-update-transaction" / L"stage";
    auto prepare = [&]() {
        Write(install / L"custom data" / L"miner.key", "encrypted fixture identity");
        Write(install / L"SHA256SUMS.txt", "previous signed fixture manifest");
        Write(stage / L"SHA256SUMS.txt", "next signed fixture manifest");
        const auto ticket = GuiStateQualification::Prepare(profile, install);
        assert(ReadTextBounded(ticket).find("Disposable fixture") == std::string::npos);
        return ticket;
    };
    auto commit = [&]() {
        Write(install / L"SHA256SUMS.txt", "next signed fixture manifest");
        std::filesystem::remove_all(stage.parent_path());
        Write(install / L"update-last-result.json", "{\"status\":\"installed\"}");
    };
    auto ticket = prepare(); commit();
    assert(GuiStateQualification::Resume(profile, install));
    assert(!std::filesystem::exists(ticket));
    assert(!GuiStateQualification::Resume(profile, install));
    std::cout << "PASS update restart and single-use consumption\n";
    ticket = prepare(); commit();
    std::wstring command = L"\"" + ModulePath().wstring() + L"\" --consume \"" + root.wstring() + L"\"";
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(0);
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    assert(CreateProcessW(ModulePath().c_str(), mutable_command.data(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process));
    assert(WaitForSingleObject(process.hProcess, 15000) == WAIT_OBJECT_0);
    DWORD result = 1;
    assert(GetExitCodeProcess(process.hProcess, &result) && result == 0);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    assert(!std::filesystem::exists(ticket));
    std::cout << "PASS protected unlock transfers to a fresh Windows process\n";
    ticket = prepare();
    std::filesystem::remove_all(stage.parent_path());
    Write(install / L"update-last-result.json", "{\"status\":\"failed\"}");
    assert(GuiStateQualification::Resume(profile, install));
    std::cout << "PASS verified rollback restart\n";
    ticket = prepare(); commit();
    Write(install / L"custom data" / L"miner.key", "different identity");
    assert(!GuiStateQualification::Resume(profile, install));
    ticket = prepare(); commit();
    Write(install / L"SHA256SUMS.txt", "unrelated signed release");
    assert(!GuiStateQualification::Resume(profile, install));
    ticket = prepare(); commit();
    Write(install / L"update-last-result.json", "{\"status\":\"recovery-required\"}");
    assert(!GuiStateQualification::Resume(profile, install));
    std::cout << "PASS changed identity, unrelated package and incomplete rollback rejected\n";
    ticket = prepare(); commit();
    auto bytes = ReadTextBounded(ticket); bytes[bytes.size()/2] ^= 1;
    assert(veld::node_gui::WriteStateText(ticket, bytes));
    assert(!GuiStateQualification::Resume(profile, install));
    ticket = prepare(); commit();
    veld::node_gui::UpdateResume expired;
    assert(!veld::node_gui::ConsumeUpdateResume(ticket, veld::node_gui::UpdateInstallContext(install),
        expired, static_cast<uint64_t>(std::time(nullptr)) + 3601));
    assert(expired.passphrase.empty());
    ticket = prepare(); commit();
    veld::node_gui::UpdateResume wrong_install;
    assert(!veld::node_gui::ConsumeUpdateResume(ticket, L"other install", wrong_install,
        static_cast<uint64_t>(std::time(nullptr))));
    std::cout << "PASS tamper, expiry and cross-install rejection\n";
    ticket = prepare(); commit();
    HANDLE locked = CreateFileW(ticket.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    assert(locked != INVALID_HANDLE_VALUE);
    assert(!GuiStateQualification::Resume(profile, install));
    assert(std::filesystem::exists(ticket));
    CloseHandle(locked);
    assert(GuiStateQualification::Resume(profile, install));
    std::cout << "PASS locked ticket fails closed and recovers\n";
    Write(install / L"veld-update.ps1", "param($Mode,$InstallDir,$Distribution)\nWrite-Output '[update] FAILED: fixture download interrupted'\nexit 1\n");
    GuiStateQualification::DownloadFailure(profile, install);
    std::cout << "PASS real updater child download failure leaves process and session running; retry delayed\n";
}
