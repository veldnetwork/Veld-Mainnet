// Real native command parsing, P-256 authorization, DPAPI trust and owned
// process lifecycle. The disposable child below does not connect or mine.
#define VELD_GUI_TEST_INSTANCE 1
#define wWinMain veld_gui_unused_entry
#include "../src/veld-node-gui.cpp"
#undef wWinMain
#include <cassert>
#include <iostream>

namespace {
void Check(bool value, const char* label) {
    if (!value)
        throw std::runtime_error(label);
    std::cout << "PASS " << label << '\n';
}
MonitoringReply Reply(const std::filesystem::path& root, const char* name) {
    MonitoringReply reply;
    Check(ParseMonitoringReply(ReadTextBounded(root / name, 16384), reply), name);
    return reply;
}
struct GuiStateQualification {
    static void Run(const std::filesystem::path& root) {
        const auto dir = root / "node-state";
        std::filesystem::create_directory(dir);
        NodeGuiApp app(dir);
        app.remote_monitoring_enabled_.store(true);
        app.hwnd_ = CreateWindowExW(0, L"STATIC", L"Disposable remote pool controls",
                                    WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, 0, 0, 1000, 700, nullptr,
                                    nullptr, GetModuleHandleW(nullptr), nullptr);
        Check(app.hwnd_ != nullptr, "native window");
        const auto pooldir = dir / "pool-client";
        std::string error;
        Check(veld::channel::secure_file::EnsurePrivateDirectory(pooldir.string(), &error),
              "private disposable pool profile");
        bool allowed = true;
        auto panel = [&] {
            return std::make_unique<veld::node_gui::PoolPanel>(
                app.hwnd_, pooldir, ModulePath(), 2, [&] {
                    if (!allowed)
                        throw std::runtime_error("Signed package or solo preflight refused start.");
                    return true;
                });
        };
        app.pool_panel_ = panel();
        auto send = [&](const MonitoringReply& reply) {
            app.pending_remote_command_ = reply.command;
            app.remote_command_pending_ = true;
            app.ExecuteRemoteCommand();
        };
        auto start = Reply(root, "pool.start.json");
        Check(app.EnrollPortalControl(start, error),
              "existing pairing grants unattended signed pool controls");
        auto changed = start;
        changed.command.action = "pool.stop";
        send(changed);
        Check(app.remote_ack_status_ == "failed" && !app.pool_panel_->Running(),
              "tampered action cannot stop or start");
        send(start);
        Check(app.remote_ack_status_ == "failed" && !app.pool_panel_->Running(),
              "missing saved pool settings fails without a modal prompt");
        // An execution failure consumes the signed sequence durably.
        Check(!app.AuthorizeRemoteCommand(start.command, error),
              "failed start cannot replay after settings change");
        app.pool_panel_.reset();
        const auto cfg = ReadTextBounded(root / "client.json", 16384);
        Check(veld::channel::secure_file::AtomicWriteText((pooldir / "client.json").string(), cfg,
                                                          &error, true),
              "save disposable endpoint and payout identity");
        app.pool_panel_ = panel();
        auto valid = Reply(root, "pool.start-ready.json");
        auto unauthorized = valid;
        unauthorized.command.device_id++;
        Check(!app.AuthorizeRemoteCommand(unauthorized.command, error), "wrong device rejected");
        app.remote_monitoring_enabled_.store(false);
        send(valid);
        Check(app.remote_ack_status_ == "failed" && !app.pool_panel_->Running(),
              "revoked remote access rejects start");
        app.remote_monitoring_enabled_.store(true);
        allowed = false;
        send(valid);
        Check(app.remote_ack_status_ == "failed" && !app.pool_panel_->Running(),
              "package or solo preflight refuses start without approval dialog");
        allowed = true;
        auto actual = Reply(root, "pool.start-actual.json");
        send(actual);
        Check(app.remote_ack_status_ == "completed" && app.pool_panel_->Running(),
              "authorized command launches GUI-owned child");
        auto saved = veld::pool::Parse(ReadTextBounded(pooldir / "client.json", 16384));
        const auto profile =
            std::filesystem::path(veld::pool::Text(veld::pool::Field(saved, "state_directory")));
        Check(profile.parent_path() == pooldir,
              "worker account profile stays in owned test directory");
        for (int i = 0; i < 200 && !std::filesystem::exists(profile / "fixture-ready"); ++i)
            Sleep(25);
        Check(std::filesystem::exists(profile / "fixture-ready"),
              "actual child reads saved configuration");
        Check(ReadTextBounded(pooldir / "resume.request", 16) == "resume\n",
              "start persists resume preference");
        uint64_t ack = 0;
        auto report = app.BuildMonitoringReport(app.SnapshotState(), ack);
        Check(report.find("\"pool_remote_control\":true") != std::string::npos,
              "client reports capability");
        auto stop = Reply(root, "pool.stop.json");
        send(stop);
        Check(app.remote_ack_status_ == "completed", "signed stop acknowledged");
        Check(ReadTextBounded(pooldir / "resume.request", 16) == "stopped\n",
              "stop durably clears auto resume");
        for (int i = 0; i < 200 && app.pool_panel_->Running(); ++i)
            Sleep(25);
        Check(!app.pool_panel_->Running(), "owned child exits after canonical stop request");
        Check(!app.AuthorizeRemoteCommand(stop.command, error), "stop replay rejected");
        app.pool_panel_.reset();
        app.pool_panel_ = panel();
        app.pool_panel_->Tick();
        Check(!app.pool_panel_->Running(),
              "recreated native panel does not resume after remote stop");
        auto restart = Reply(root, "pool.restart.json");
        send(restart);
        Check(app.remote_ack_status_ == "completed" && app.pool_panel_->Running(),
              "later fresh signed start resumes saved pool profile");
        Check(veld::pool::Text(veld::pool::Field(
                  veld::pool::Parse(ReadTextBounded(pooldir / "client.json", 16384)),
                  "payout_address")) ==
                  veld::pool::Text(veld::pool::Field(veld::pool::Parse(cfg), "payout_address")),
              "remote controls preserve payout identity");
        auto finalstop = Reply(root, "pool.final-stop.json");
        HANDLE lock = CreateFileW((pooldir / "resume.request").c_str(), GENERIC_READ,
                                  FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        Check(lock != INVALID_HANDLE_VALUE, "hold resume file to inject persistence failure");
        send(finalstop);
        Check(app.remote_ack_status_ == "failed",
              "persistence failure is not falsely acknowledged completed");
        CloseHandle(lock);
        Check(app.pool_panel_->Stop(true, &error), "clear resume safely after injected failure");
        app.pool_panel_.reset();
        DestroyWindow(app.hwnd_);
        app.hwnd_ = nullptr;
    }
};
}
int main(int argc, char** argv) try {
    if (argc == 3 && std::string(argv[1]) == "--config") {
        const auto cfg = veld::pool::Parse(ReadTextBounded(argv[2], 16384));
        const auto dir =
            std::filesystem::path(veld::pool::Text(veld::pool::Field(cfg, "state_directory")));
        std::ofstream(dir / "fixture-ready") << "non-mining process fixture\n";
        for (int i = 0; i < 1200 && !std::filesystem::exists(dir / "stop.request"); ++i)
            Sleep(25);
        return 0;
    }
    Check(argc == 2, "one disposable fixture root");
    GuiStateQualification::Run(argv[1]);
    std::cout << "PASS_NATIVE_SIGNED_POOL_CONTROL_LIFECYCLE\n";
} catch (const std::exception& error) {
    std::cerr << "FAIL " << error.what() << '\n';
    return 1;
}
