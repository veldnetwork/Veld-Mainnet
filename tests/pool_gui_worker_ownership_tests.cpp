// Native Windows process-lifetime regression using the actual packaged worker.
// Endpoint is closed loopback; this test never connects to a public pool.
#include "gui/pool_panel.h"
#include <tlhelp32.h>
#include <fstream>
#include <iostream>

namespace {
void Check(bool value, const char* reason) {
    if (!value)
        throw std::runtime_error(reason);
}
BOOL CALLBACK Edits(HWND window, LPARAM arg) {
    wchar_t type[32]{};
    GetClassNameW(window, type, 32);
    if (std::wstring(type) == L"Edit")
        reinterpret_cast<std::vector<HWND>*>(arg)->push_back(window);
    return TRUE;
}
int Parent(const std::filesystem::path& root, const std::filesystem::path& worker) {
    HWND window = CreateWindowExW(0, L"STATIC", L"Owned worker fixture", WS_OVERLAPPEDWINDOW, 0, 0,
                                  1000, 900, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    Check(window != nullptr, "parent fixture window");
    {
        veld::node_gui::PoolPanel panel(window, root, worker, 1, [] { return true; });
        std::vector<HWND> edits;
        EnumChildWindows(window, Edits, reinterpret_cast<LPARAM>(&edits));
        Check(edits.size() == 4, "real pool controls");
        SetWindowTextW(edits[0], L"https://127.0.0.1:1");
        SetWindowTextW(edits[1], L"VSVPeRwNp9MkdPgeq5YCNV3im7HUEks63z");
        SetWindowTextW(edits[3], L"1");
        panel.Command(MAKEWPARAM(veld::node_gui::PoolPanel::kStart, BN_CLICKED));
        Check(panel.Running(), "actual native worker launched");
        {
            std::ofstream ready(root / "ready");
            ready << "ready\n";
        }
        for (int i = 0; i < 300 && !std::filesystem::exists(root / "finish"); ++i)
            Sleep(100);
    }
    DestroyWindow(window);
    return 0;
}
HANDLE Child(DWORD parent, const std::filesystem::path& expected) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    Check(snapshot != INVALID_HANDLE_VALUE, "process snapshot");
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    HANDLE child = nullptr;
    if (Process32FirstW(snapshot, &entry))
        do {
            if (entry.th32ParentProcessID != parent)
                continue;
            HANDLE candidate =
                OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                            FALSE, entry.th32ProcessID);
            if (!candidate)
                continue;
            wchar_t path[32768]{};
            DWORD count = 32768;
            if (QueryFullProcessImageNameW(candidate, 0, path, &count) &&
                std::filesystem::equivalent(expected, path)) {
                Check(child == nullptr, "exactly one owned worker");
                child = candidate;
            } else
                CloseHandle(candidate);
        } while (Process32NextW(snapshot, &entry));
    CloseHandle(snapshot);
    return child;
}
std::wstring Read(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::string value((std::istreambuf_iterator<char>(input)), {});
    return std::wstring(value.begin(), value.end());
}
}
int wmain(int argc, wchar_t** argv) try {
    if (argc == 4 && std::wstring(argv[1]) == L"--parent")
        return Parent(argv[2], argv[3]);
    Check(argc == 2, "actual worker path required");
    const std::filesystem::path worker = std::filesystem::absolute(argv[1]);
    Check(std::filesystem::is_regular_file(worker), "actual worker exists");
    wchar_t self[32768]{};
    Check(GetModuleFileNameW(nullptr, self, 32768) > 0, "test executable identity");
    const auto root = std::filesystem::temp_directory_path() /
                      (L"veld-job-owner-" + std::to_wstring(GetCurrentProcessId()));
    Check(!std::filesystem::exists(root), "fresh disposable test root");
    bool all = true;
    for (bool crash : {true, false}) {
        const auto profile = root / (crash ? L"crash" : L"normal");
        std::string error;
        Check(veld::channel::secure_file::EnsurePrivateDirectory(profile.string(), &error),
              "private fixture profile");
        std::wstring command = L"\"" + std::wstring(self) + L"\" --parent \"" + profile.wstring() +
                               L"\" \"" + worker.wstring() + L"\"";
        std::vector<wchar_t> buffer(command.begin(), command.end());
        buffer.push_back(0);
        STARTUPINFOW start{};
        start.cb = sizeof(start);
        PROCESS_INFORMATION proc{};
        Check(CreateProcessW(self, buffer.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                             nullptr, nullptr, &start, &proc),
              "spawn actual pool parent");
        CloseHandle(proc.hThread);
        for (int i = 0; i < 100 && !std::filesystem::exists(profile / "ready") &&
                        WaitForSingleObject(proc.hProcess, 0) == WAIT_TIMEOUT;
             ++i)
            Sleep(100);
        HANDLE child = Child(proc.dwProcessId, worker);
        if (!std::filesystem::exists(profile / "ready") || !child) {
            TerminateProcess(proc.hProcess, 9);
            CloseHandle(proc.hProcess);
            throw std::runtime_error("worker readiness");
        }
        const auto config = Read(profile / "client.json");
        Check(config.find(L"\"nonce_count\":\"1024\"") != std::wstring::npos,
              "GUI requests a bounded 1024-nonce lease, reducing repeated TLS waits");
        if (crash)
            Check(TerminateProcess(proc.hProcess, 9), "inject parent crash");
        else {
            std::ofstream finish(profile / "finish");
            finish << "finish\n";
        }
        const bool parent_stopped = WaitForSingleObject(proc.hProcess, 30000) == WAIT_OBJECT_0;
        const bool child_stopped = WaitForSingleObject(child, 5000) == WAIT_OBJECT_0;
        // Always remove an exposed defect's owned orphan. Never kill by name.
        if (!child_stopped) {
            TerminateProcess(child, 9);
            WaitForSingleObject(child, 5000);
        }
        if (!parent_stopped)
            TerminateProcess(proc.hProcess, 9);
        CloseHandle(child);
        CloseHandle(proc.hProcess);
        const bool preserved = Read(profile / "client.json") == config &&
                               Read(profile / "resume.request") == L"resume\n";
        std::cout << (parent_stopped && child_stopped && preserved ? "PASS " : "FAIL ")
                  << (crash ? "parent crash" : "normal parent exit")
                  << ": worker stopped=" << child_stopped
                  << ", configuration/resume preserved=" << preserved << '\n';
        all = all && parent_stopped && child_stopped && preserved;
    }
    std::filesystem::remove_all(root); // Exact fresh test directory established above.
    return all ? 0 : 1;
} catch (const std::exception& error) {
    std::cerr << "FAIL " << error.what() << '\n';
    return 1;
}
