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
    static std::filesystem::path Prepare(const std::filesystem::path& profile,
                                         const std::filesystem::path& root) {
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
    static std::filesystem::path PrepareAddressOnly(const std::filesystem::path& profile,
                                                    const std::filesystem::path& root,
                                                    const std::string& address) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.address_only_ = true;
        app.mining_enabled_ = true;
        app.SetAddressPayout(address);
        assert(app.SaveSettings(false));
        assert(!app.HasSessionUnlock());
        assert(app.PrepareUpdateResume());
        return app.UpdateResumePath();
    }
    static void ExpiredDuringCommit(const std::filesystem::path& profile,
                                    const std::filesystem::path& root, const std::string& address) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.address_only_ = true;
        app.SetAddressPayout(address);
        assert(app.SaveSettings(false));
        veld::node_gui::UpdateResume expired;
        expired.created = static_cast<uint64_t>(std::time(nullptr)) - 3601;
        expired.data_directory = std::filesystem::weakly_canonical(app.data_dir_).wstring();
        expired.identity = Utf8ToWide(app.RemoteIdentityFingerprint());
        expired.previous_manifest = Utf8ToWide(
            veld::node_gui::PortalDigest(ReadTextBounded(root / L"SHA256SUMS.txt", 8192)));
        expired.target_manifest = Utf8ToWide(veld::node_gui::PortalDigest(ReadTextBounded(
            root / L".veld-update-transaction" / L"stage" / L"SHA256SUMS.txt", 8192)));
        const auto ticket = app.UpdateResumePath();
        assert(veld::node_gui::SaveUpdateResume(ticket, veld::node_gui::UpdateInstallContext(root),
                                                expired, expired.created, true));
        app.LoadUpdateResume();
        assert(!app.update_resume_pending_ && !std::filesystem::exists(ticket));
    }
    static bool ResumeAddressOnly(const std::filesystem::path& profile,
                                  const std::filesystem::path& root, const std::string& address) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.LoadSettings();
        assert(app.address_only_ && app.AddressPayout() == address);
        assert(app.mining_enabled_ && !app.HasSessionUnlock());
        app.LoadUpdateResume();
        if (app.update_resume_pending_) {
            assert(!app.HasSessionUnlock());
            const auto command = app.NodeStartCommand();
            assert(command.find(L" --mine --address-only --miner ") != std::wstring::npos);
        }
        return app.update_resume_pending_;
    }
    static void ChangeAddress(const std::filesystem::path& profile,
                              const std::filesystem::path& root, const std::string& address) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.LoadSettings();
        app.SetAddressPayout(address);
        assert(app.SaveSettings(false));
    }
    static void SaveWalletSettings(const std::filesystem::path& profile,
                                   const std::filesystem::path& root) {
        NodeGuiApp app(profile);
        Configure(app, root);
        assert(app.SaveSettings(false));
    }
    static bool ResumeWithChangedAddress(const std::filesystem::path& profile,
                                         const std::filesystem::path& root) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.LoadSettings();
        app.LoadUpdateResume();
        return app.update_resume_pending_;
    }
    static void DownloadFailure(const std::filesystem::path& profile,
                                const std::filesystem::path& root) {
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
        assert(app.next_auto_update_ > std::chrono::steady_clock::now() + std::chrono::minutes(59));
        assert(app.next_auto_update_ <= std::chrono::steady_clock::now() + std::chrono::hours(1));
    }
    static void AutomaticCycle(const std::filesystem::path& profile,
                               const std::filesystem::path& root) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.next_auto_update_ = std::chrono::steady_clock::now();
        app.TickAutomaticUpdates();
        assert(app.update_operation_.load() == UpdateOperation::None);
        app.auto_update_enabled_.store(true);
        app.TickAutomaticUpdates();
        assert(app.update_operation_.load() == UpdateOperation::Check);
        const HANDLE check = app.update_process_;
        app.TickAutomaticUpdates();
        assert(app.update_process_ == check);
        assert(WaitForSingleObject(check, 15000) == WAIT_OBJECT_0);
        DWORD exit_code = 0;
        assert(GetExitCodeProcess(check, &exit_code) && exit_code == 2);
        app.OnUpdateProcessComplete(exit_code);
        assert(app.automatic_install_pending_);
        app.TickAutomaticUpdates();
        assert(app.update_operation_.load() == UpdateOperation::Install);
        assert(WaitForSingleObject(app.update_process_, 15000) == WAIT_OBJECT_0);
        assert(GetExitCodeProcess(app.update_process_, &exit_code) && exit_code == 1);
        app.OnUpdateProcessComplete(exit_code);
        app.TickAutomaticUpdates();
        assert(app.update_operation_.load() == UpdateOperation::None);
        assert(!app.automatic_install_pending_);
        assert(!app.update_resume_pending_ && !app.HasSessionUnlock());
    }
    static void HourlyChecks(const std::filesystem::path& profile,
                             const std::filesystem::path& root) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.auto_update_enabled_.store(true);
        app.next_auto_update_ = std::chrono::steady_clock::now();
        for (int cycle = 0; cycle < 3; ++cycle) {
            const auto due = app.next_auto_update_;
            app.TickAutomaticUpdates(due - std::chrono::minutes(30));
            assert(app.update_operation_.load() == UpdateOperation::None);
            app.TickAutomaticUpdates(due - std::chrono::milliseconds(1));
            assert(app.update_operation_.load() == UpdateOperation::None);
            app.TickAutomaticUpdates(due);
            assert(app.update_operation_.load() == UpdateOperation::Check);
            assert(app.next_auto_update_ == due + std::chrono::hours(1));
            const HANDLE check = app.update_process_;
            app.TickAutomaticUpdates(due + std::chrono::hours(2));
            assert(app.update_process_ == check);
            assert(WaitForSingleObject(check, 15000) == WAIT_OBJECT_0);
            DWORD exit_code = 1;
            assert(GetExitCodeProcess(check, &exit_code) && exit_code == 0);
            app.OnUpdateProcessComplete(exit_code);
            assert(!app.automatic_install_pending_);
            assert(app.next_auto_update_ >
                   std::chrono::steady_clock::now() + std::chrono::minutes(59));
            assert(app.next_auto_update_ <=
                   std::chrono::steady_clock::now() + std::chrono::hours(1));
        }
        app.auto_update_enabled_.store(false);
        app.TickAutomaticUpdates(app.next_auto_update_ + std::chrono::hours(24));
        assert(app.update_operation_.load() == UpdateOperation::None);
    }
    static void NodeExitsDuringInstall(const std::filesystem::path& profile,
                                       const std::filesystem::path& root, bool address_only,
                                       const std::string& address = {}) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.address_only_ = address_only;
        app.mining_enabled_ = true;
        if (address_only)
            app.SetAddressPayout(address);
        assert(app.SaveSettings(false));
        const auto node = root / L"bin" / L"veld-node.exe";
        std::filesystem::create_directories(node.parent_path());
        assert(CopyFileW(ModulePath().c_str(), node.c_str(), TRUE));
        const std::string event_name = "Local\\VeldUpdateFixture-" +
                                       std::to_string(GetCurrentProcessId()) + "-" +
                                       std::to_string(GetTickCount64());
        HANDLE release = CreateEventA(nullptr, TRUE, FALSE, event_name.c_str());
        assert(release);
        std::wstring command = L"\"" + node.wstring() + L"\" --hold-node " + Utf8ToWide(event_name);
        std::vector<wchar_t> mutable_command(command.begin(), command.end());
        mutable_command.push_back(0);
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION child{};
        assert(CreateProcessW(node.c_str(), mutable_command.data(), nullptr, nullptr, FALSE,
                              CREATE_NO_WINDOW, nullptr, root.c_str(), &startup, &child));
        DWORD found = 0;
        for (int attempt = 0; attempt < 200 && !found; ++attempt) {
            found = FindNodeProcess(node);
            if (!found)
                Sleep(25);
        }
        assert(found == child.dwProcessId);
        assert(app.BeginUpdateInstall());
        assert(app.update_node_running_at_install_start_);
        assert(WaitForSingleObject(app.update_process_, 15000) == WAIT_OBJECT_0);
        DWORD exit_code = 1;
        assert(GetExitCodeProcess(app.update_process_, &exit_code) && exit_code == 0);
        assert(SetEvent(release));
        assert(WaitForSingleObject(child.hProcess, 15000) == WAIT_OBJECT_0);
        CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
        CloseHandle(release);
        assert(FindNodeProcess(node) == 0);
        app.OnUpdateProcessComplete(exit_code);
        assert(!app.update_node_running_at_install_start_);
        if (address_only) {
            assert(std::filesystem::exists(app.UpdateResumePath()));
            assert(app.update_status_.find(L"restarting") != std::wstring::npos);
        } else {
            assert(!std::filesystem::exists(app.UpdateResumePath()));
            assert(app.update_status_.find(L"postponed") != std::wstring::npos);
        }
    }
    static void LaunchAfterUpdate(const std::filesystem::path& profile,
                                  const std::filesystem::path& root, bool address_only) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.LoadSettings();
        assert(app.address_only_ == address_only);
        app.LoadUpdateResume();
        assert(app.update_resume_pending_);
        app.TickAutomaticUpdates();
        assert(!app.update_resume_pending_);
        assert(app.owned_pid_.load() != 0);
        const auto marker = root / L"custom data" / L"update-resume-node-started.txt";
        std::string started;
        const std::string expected = address_only ? "address-only mine\n" : "wallet mine\n";
        for (int attempt = 0; attempt < 200; ++attempt) {
            started = ReadTextBounded(marker, 256);
            if (started == expected)
                break;
            Sleep(25);
        }
        assert(started == (address_only ? "address-only mine\n" : "wallet mine\n"));
        assert(WaitForSingleObject(app.owned_process_, 10000) == WAIT_OBJECT_0);
        DWORD exit_code = 1;
        assert(GetExitCodeProcess(app.owned_process_, &exit_code) && exit_code == 0);
    }
    static void RetryEarlyOpenedAddressOnly(const std::filesystem::path& profile,
                                            const std::filesystem::path& root,
                                            const std::filesystem::path& test_node) {
        NodeGuiApp app(profile);
        Configure(app, root);
        app.LoadSettings();
        // Opening while bin/ is being replaced can leave a stale fallback path.
        app.node_path_ = root / L"veld-node.exe";
        app.LoadUpdateResume();
        assert(!app.update_resume_pending_ && std::filesystem::exists(app.UpdateResumePath()));
        std::filesystem::remove_all(root / L".veld-update-transaction");
        app.TickAutomaticUpdates();
        assert(!app.update_resume_pending_ && std::filesystem::exists(app.UpdateResumePath()));
        {
            std::ofstream manifest(root / L"SHA256SUMS.txt", std::ios::binary);
            manifest << "early-open committed fixture";
        }
        {
            Sleep(50);
            std::ofstream receipt(root / L"update-last-result.json", std::ios::binary);
            receipt << "{\"status\":\"installed\"}";
        }
        std::filesystem::create_directories(root / L"bin");
        assert(CopyFileW(test_node.c_str(), (root / L"bin" / L"veld-node.exe").c_str(), TRUE));
        app.TickAutomaticUpdates();
        assert(!std::filesystem::exists(app.UpdateResumePath()));
        assert(app.node_path_ == root / L"bin" / L"veld-node.exe");
        assert(app.owned_pid_.load() != 0 && !app.update_resume_pending_);
        const auto marker = root / L"custom data" / L"update-resume-node-started.txt";
        std::string started;
        for (int attempt = 0; attempt < 200; ++attempt) {
            started = ReadTextBounded(marker, 256);
            if (started == "address-only mine\n")
                break;
            Sleep(25);
        }
        assert(started == "address-only mine\n");
        assert(WaitForSingleObject(app.owned_process_, 10000) == WAIT_OBJECT_0);
    }
};

void Write(const std::filesystem::path& path, const std::string& text) {
    std::filesystem::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary);
    out << text;
    out.close();
    assert(out.good());
}
}

int main(int argc, char** argv) {
    std::cout.setf(std::ios::unitbuf);
    if (argc == 3 && std::string(argv[1]) == "--hold-node") {
        HANDLE release = OpenEventA(SYNCHRONIZE, FALSE, argv[2]);
        if (!release)
            return 3;
        const DWORD waited = WaitForSingleObject(release, 15000);
        CloseHandle(release);
        return waited == WAIT_OBJECT_0 ? 0 : 4;
    }
    if (argc == 3 && std::string(argv[1]) == "--consume") {
        const auto root = std::filesystem::absolute(argv[2]);
        return GuiStateQualification::Resume(root / L"private profile",
                                             root / L"Install \u00e9 \u65e5\u672c\u8a9e")
                   ? 0
                   : 1;
    }
    assert(argc == 3);
    const auto root = std::filesystem::absolute(argv[1]);
    const auto signed_test_node = std::filesystem::absolute(argv[2]);
    assert(std::filesystem::is_regular_file(signed_test_node));
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
        Sleep(50);
        Write(install / L"update-last-result.json", "{\"status\":\"installed\"}");
    };
    auto ticket = prepare();
    commit();
    assert(GuiStateQualification::Resume(profile, install));
    assert(!std::filesystem::exists(ticket));
    assert(!GuiStateQualification::Resume(profile, install));
    std::cout << "PASS update restart and single-use consumption\n";
    ticket = prepare();
    commit();
    std::wstring command =
        L"\"" + ModulePath().wstring() + L"\" --consume \"" + root.wstring() + L"\"";
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(0);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    assert(CreateProcessW(ModulePath().c_str(), mutable_command.data(), nullptr, nullptr, FALSE,
                          CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process));
    assert(WaitForSingleObject(process.hProcess, 15000) == WAIT_OBJECT_0);
    DWORD result = 1;
    assert(GetExitCodeProcess(process.hProcess, &result) && result == 0);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    assert(!std::filesystem::exists(ticket));
    std::cout << "PASS protected unlock transfers to a fresh Windows process\n";
    ticket = prepare();
    std::filesystem::remove_all(stage.parent_path());
    Sleep(50);
    Write(install / L"update-last-result.json", "{\"status\":\"failed\"}");
    assert(GuiStateQualification::Resume(profile, install));
    std::cout << "PASS verified rollback restart\n";
    ticket = prepare();
    commit();
    Write(install / L"custom data" / L"miner.key", "different identity");
    assert(!GuiStateQualification::Resume(profile, install));
    ticket = prepare();
    commit();
    Write(install / L"SHA256SUMS.txt", "unrelated signed release");
    assert(!GuiStateQualification::Resume(profile, install));
    ticket = prepare();
    commit();
    Write(install / L"update-last-result.json", "{\"status\":\"recovery-required\"}");
    assert(!GuiStateQualification::Resume(profile, install));
    std::cout << "PASS changed identity, unrelated package and incomplete rollback rejected\n";
    ticket = prepare();
    commit();
    auto bytes = ReadTextBounded(ticket);
    bytes[bytes.size() / 2] ^= 1;
    assert(veld::node_gui::WriteStateText(ticket, bytes));
    assert(!GuiStateQualification::Resume(profile, install));
    ticket = prepare();
    commit();
    veld::node_gui::UpdateResume expired;
    assert(!veld::node_gui::ConsumeUpdateResume(
        ticket, veld::node_gui::UpdateInstallContext(install), expired,
        static_cast<uint64_t>(std::time(nullptr)) + 3601));
    assert(expired.passphrase.empty());
    ticket = prepare();
    commit();
    veld::node_gui::UpdateResume wrong_install;
    assert(!veld::node_gui::ConsumeUpdateResume(ticket, L"other install", wrong_install,
                                                static_cast<uint64_t>(std::time(nullptr))));
    std::cout << "PASS tamper, expiry and cross-install rejection\n";
    ticket = prepare();
    commit();
    HANDLE locked = CreateFileW(ticket.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    assert(locked != INVALID_HANDLE_VALUE);
    assert(!GuiStateQualification::Resume(profile, install));
    assert(std::filesystem::exists(ticket));
    CloseHandle(locked);
    assert(GuiStateQualification::Resume(profile, install));
    std::cout << "PASS locked ticket fails closed and recovers\n";
    Write(
        install / L"veld-update.ps1",
        "param($Mode,$InstallDir,$Distribution)\nWrite-Output '[update] FAILED: fixture download interrupted'\nexit 1\n");
    GuiStateQualification::DownloadFailure(profile, install);
    std::cout
        << "PASS real updater child download failure leaves process and session running; retry delayed\n";
    Write(
        install / L"veld-update.ps1",
        "param($Mode,$InstallDir,$Distribution)\nif($Mode -eq 'Check'){Write-Output 'Remote version: 3.1.11';exit 2}\nWrite-Output '[update] FAILED: interrupted fixture download'\nexit 1\n");
    GuiStateQualification::AutomaticCycle(profile, install);
    std::cout
        << "PASS automatic check-to-install dispatch, opt-out, single in-flight operation and failure backoff; stopped node stays stopped\n";
    Write(install / L"veld-update.ps1", "param($Mode,$InstallDir,$Distribution)\nexit 0\n");
    GuiStateQualification::HourlyChecks(profile, install);
    std::cout
        << "PASS hourly check boundaries, repeated current-version checks, no concurrent check and opt-out\n";

    const auto address_root = root / L"address-only update";
    const auto address_install = address_root / L"installation";
    const auto address_profile = address_root / L"profile";
    std::filesystem::create_directories(address_install / L"custom data");
    std::filesystem::create_directories(address_profile);
    const auto address = veld::GenerateKeyPair(false).address;
    Write(address_install / L"SHA256SUMS.txt", "address-only previous signed fixture");
    Write(address_install / L".veld-update-transaction" / L"stage" / L"SHA256SUMS.txt",
          "address-only next signed fixture");
    const auto address_ticket =
        GuiStateQualification::PrepareAddressOnly(address_profile, address_install, address);
    assert(std::filesystem::exists(address_ticket));
    Write(address_install / L"SHA256SUMS.txt", "address-only next signed fixture");
    std::filesystem::remove_all(address_install / L".veld-update-transaction");
    Sleep(50);
    Write(address_install / L"update-last-result.json", "{\"status\":\"installed\"}");
    assert(GuiStateQualification::ResumeAddressOnly(address_profile, address_install, address));
    assert(!std::filesystem::exists(address_ticket));
    std::cout
        << "PASS address-only update restores solo mining intent without a wallet passphrase\n";

    const auto restart_root = root / L"post-commit relaunch failure";
    const auto restart_install = restart_root / L"installation";
    const auto restart_profile = restart_root / L"profile";
    std::filesystem::create_directories(restart_install / L"custom data");
    std::filesystem::create_directories(restart_profile);
    Write(restart_install / L"SHA256SUMS.txt", "restart previous signed fixture");
    Write(restart_install / L".veld-update-transaction" / L"stage" / L"SHA256SUMS.txt",
          "restart target signed fixture");
    const auto restart_ticket =
        GuiStateQualification::PrepareAddressOnly(restart_profile, restart_install, address);
    Write(restart_install / L"SHA256SUMS.txt", "restart target signed fixture");
    std::filesystem::remove_all(restart_install / L".veld-update-transaction");
    Sleep(50);
    Write(restart_install / L"update-last-result.json", "{\"status\":\"failed\"}");
    assert(GuiStateQualification::ResumeAddressOnly(restart_profile, restart_install, address));
    assert(!std::filesystem::exists(restart_ticket));
    std::cout << "PASS manually reopened GUI resumes after post-commit relaunch failure\n";

    const auto restart_wallet_root = root / L"post-commit wallet relaunch failure";
    const auto restart_wallet_install = restart_wallet_root / L"installation";
    const auto restart_wallet_profile = restart_wallet_root / L"profile";
    std::filesystem::create_directories(restart_wallet_install / L"custom data");
    std::filesystem::create_directories(restart_wallet_profile);
    Write(restart_wallet_install / L"custom data" / L"miner.key", "wallet restart identity");
    Write(restart_wallet_install / L"SHA256SUMS.txt", "wallet restart previous fixture");
    Write(restart_wallet_install / L".veld-update-transaction" / L"stage" / L"SHA256SUMS.txt",
          "wallet restart target fixture");
    GuiStateQualification::SaveWalletSettings(restart_wallet_profile, restart_wallet_install);
    const auto restart_wallet_ticket =
        GuiStateQualification::Prepare(restart_wallet_profile, restart_wallet_install);
    Write(restart_wallet_install / L"SHA256SUMS.txt", "wallet restart target fixture");
    std::filesystem::remove_all(restart_wallet_install / L".veld-update-transaction");
    Sleep(50);
    Write(restart_wallet_install / L"update-last-result.json", "{\"status\":\"failed\"}");
    assert(GuiStateQualification::Resume(restart_wallet_profile, restart_wallet_install));
    assert(!std::filesystem::exists(restart_wallet_ticket));
    std::cout << "PASS wallet-mode manual reopen retains protected resume after relaunch failure\n";

    Write(address_install / L".veld-update-transaction" / L"stage" / L"SHA256SUMS.txt",
          "address-only next signed fixture 2");
    const auto changed_ticket =
        GuiStateQualification::PrepareAddressOnly(address_profile, address_install, address);
    GuiStateQualification::ChangeAddress(address_profile, address_install,
                                         veld::GenerateKeyPair(false).address);
    Write(address_install / L"SHA256SUMS.txt", "address-only next signed fixture 2");
    std::filesystem::remove_all(address_install / L".veld-update-transaction");
    Sleep(50);
    Write(address_install / L"update-last-result.json", "{\"status\":\"installed\"}");
    assert(!GuiStateQualification::ResumeWithChangedAddress(address_profile, address_install));
    assert(!std::filesystem::exists(changed_ticket));
    std::cout << "PASS changed payout refuses address-only update resume\n";

    GuiStateQualification::ChangeAddress(address_profile, address_install, address);
    Write(address_install / L".veld-update-transaction" / L"stage" / L"SHA256SUMS.txt",
          "address-only next signed fixture 3");
    const auto wallet_ticket =
        GuiStateQualification::PrepareAddressOnly(address_profile, address_install, address);
    veld::node_gui::UpdateResume wrong_mode;
    assert(!veld::node_gui::ConsumeUpdateResume(
        wallet_ticket, veld::node_gui::UpdateInstallContext(address_install), wrong_mode,
        static_cast<uint64_t>(std::time(nullptr))));
    assert(!std::filesystem::exists(wallet_ticket));
    std::cout << "PASS wallet mode rejects a passphrase-free resume ticket\n";

    const auto early_root = root / L"early GUI during commit";
    const auto early_install = early_root / L"installation";
    const auto early_profile = early_root / L"profile";
    std::filesystem::create_directories(early_install / L"custom data");
    std::filesystem::create_directories(early_profile);
    Write(early_install / L"SHA256SUMS.txt", "early GUI previous fixture");
    Write(early_install / L"update-last-result.json", "{\"status\":\"installed\"}");
    Write(early_install / L".veld-update-transaction" / L"stage" / L"SHA256SUMS.txt",
          "early GUI target fixture");
    const auto early_ticket =
        GuiStateQualification::PrepareAddressOnly(early_profile, early_install, address);
    assert(!GuiStateQualification::ResumeAddressOnly(early_profile, early_install, address));
    assert(std::filesystem::exists(early_ticket));
    std::filesystem::remove_all(early_install / L".veld-update-transaction");
    assert(!GuiStateQualification::ResumeAddressOnly(early_profile, early_install, address));
    assert(std::filesystem::exists(early_ticket));
    Write(early_install / L"SHA256SUMS.txt", "early GUI target fixture");
    Sleep(50);
    Write(early_install / L"update-last-result.json", "{\"status\":\"installed\"}");
    assert(GuiStateQualification::ResumeAddressOnly(early_profile, early_install, address));
    assert(!std::filesystem::exists(early_ticket));
    std::cout << "PASS early GUI launches preserve the one-use ticket until verified commit\n";

    const auto retry_root = root / L"early-open GUI stays running";
    const auto retry_profile = retry_root / L"profile";
    std::filesystem::create_directories(retry_root / L"custom data");
    std::filesystem::create_directories(retry_profile);
    Write(retry_root / L"SHA256SUMS.txt", "early-open previous fixture");
    Write(retry_root / L"update-last-result.json", "{\"status\":\"installed\"}");
    Write(retry_root / L".veld-update-transaction" / L"stage" / L"SHA256SUMS.txt",
          "early-open committed fixture");
    GuiStateQualification::PrepareAddressOnly(retry_profile, retry_root, address);
    GuiStateQualification::RetryEarlyOpenedAddressOnly(retry_profile, retry_root, signed_test_node);
    std::cout
        << "PASS already-open GUI retries verified commit and starts its disposable address-only node\n";

    const auto expired_root = root / L"expired ticket during interrupted commit";
    const auto expired_profile = expired_root / L"profile";
    std::filesystem::create_directories(expired_root / L"custom data");
    std::filesystem::create_directories(expired_profile);
    Write(expired_root / L"SHA256SUMS.txt", "expired previous fixture");
    Write(expired_root / L".veld-update-transaction" / L"stage" / L"SHA256SUMS.txt",
          "expired target fixture");
    GuiStateQualification::ExpiredDuringCommit(expired_profile, expired_root, address);
    std::cout << "PASS expired ticket is purged while an interrupted commit remains\n";

    const auto exited_wallet_root = root / L"wallet exit during install";
    Write(exited_wallet_root / L"veld-update.ps1",
          "param($Mode,$InstallDir,$Distribution)\nexit 0\n");
    GuiStateQualification::NodeExitsDuringInstall(exited_wallet_root / L"profile",
                                                  exited_wallet_root, false);
    std::cout << "PASS node exit during install preserves wallet-mode sign-in requirement\n";

    const auto exited_address_root = root / L"address-only exit during install";
    Write(exited_address_root / L"veld-update.ps1",
          "param($Mode,$InstallDir,$Distribution)\nexit 0\n");
    Write(exited_address_root / L"SHA256SUMS.txt", "exit-before-stage old fixture");
    Write(exited_address_root / L".veld-update-transaction" / L"stage" / L"SHA256SUMS.txt",
          "exit-before-stage new fixture");
    GuiStateQualification::NodeExitsDuringInstall(exited_address_root / L"profile",
                                                  exited_address_root, true, address);
    Write(exited_address_root / L"SHA256SUMS.txt", "exit-before-stage new fixture");
    std::filesystem::remove_all(exited_address_root / L".veld-update-transaction");
    Sleep(50);
    Write(exited_address_root / L"update-last-result.json", "{\"status\":\"installed\"}");
    assert(GuiStateQualification::ResumeAddressOnly(exited_address_root / L"profile",
                                                    exited_address_root, address));
    std::cout
        << "PASS running address-only node exits during install and resumes after signed handoff\n";

    const auto launched_address_root = root / L"address-only process launch";
    const auto launched_address_profile = launched_address_root / L"profile";
    std::filesystem::create_directories(launched_address_root / L"custom data");
    std::filesystem::create_directories(launched_address_profile);
    Write(launched_address_root / L"SHA256SUMS.txt", "launch old fixture");
    Write(launched_address_root / L".veld-update-transaction" / L"stage" / L"SHA256SUMS.txt",
          "launch new fixture");
    GuiStateQualification::PrepareAddressOnly(launched_address_profile, launched_address_root,
                                              address);
    Write(launched_address_root / L"SHA256SUMS.txt", "launch new fixture");
    std::filesystem::remove_all(launched_address_root / L".veld-update-transaction");
    Sleep(50);
    Write(launched_address_root / L"update-last-result.json", "{\"status\":\"installed\"}");
    std::filesystem::create_directories(launched_address_root / L"bin");
    assert(CopyFileW(signed_test_node.c_str(),
                     (launched_address_root / L"bin" / L"veld-node.exe").c_str(), TRUE));
    GuiStateQualification::LaunchAfterUpdate(launched_address_profile, launched_address_root, true);
    std::cout << "PASS address-only signed update resumes an actual disposable node process\n";

    const auto launched_wallet_root = root / L"wallet process launch";
    const auto launched_wallet_profile = launched_wallet_root / L"profile";
    std::filesystem::create_directories(launched_wallet_root / L"custom data");
    std::filesystem::create_directories(launched_wallet_profile);
    Write(launched_wallet_root / L"custom data" / L"miner.key", "wallet launch identity");
    Write(launched_wallet_root / L"SHA256SUMS.txt", "wallet launch old fixture");
    Write(launched_wallet_root / L".veld-update-transaction" / L"stage" / L"SHA256SUMS.txt",
          "wallet launch new fixture");
    GuiStateQualification::SaveWalletSettings(launched_wallet_profile, launched_wallet_root);
    GuiStateQualification::Prepare(launched_wallet_profile, launched_wallet_root);
    Write(launched_wallet_root / L"SHA256SUMS.txt", "wallet launch new fixture");
    std::filesystem::remove_all(launched_wallet_root / L".veld-update-transaction");
    Sleep(50);
    Write(launched_wallet_root / L"update-last-result.json", "{\"status\":\"installed\"}");
    std::filesystem::create_directories(launched_wallet_root / L"bin");
    assert(CopyFileW(signed_test_node.c_str(),
                     (launched_wallet_root / L"bin" / L"veld-node.exe").c_str(), TRUE));
    GuiStateQualification::LaunchAfterUpdate(launched_wallet_profile, launched_wallet_root, false);
    std::cout << "PASS wallet-mode signed update resumes an actual disposable node process\n";
}
