#include <windows.h>
#include <filesystem>
#include <string>

int wmain(int argc, wchar_t** argv) {
    std::filesystem::path data_directory;
    std::wstring payout;
    bool mine = false;
    bool address_only = false;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--datadir" && i + 1 < argc) data_directory = argv[++i];
        else if (arg == L"--miner" && i + 1 < argc) payout = argv[++i];
        else if (arg == L"--mine") mine = true;
        else if (arg == L"--address-only") address_only = true;
    }
    wchar_t secret[2]{};
    const DWORD secret_size = GetEnvironmentVariableW(
        L"VELD_VAULT_PASSPHRASE", secret, 2);
    SecureZeroMemory(secret, sizeof(secret));
    if (data_directory.empty() || secret_size == 0) return 2;
    if (address_only && (!mine || payout.empty())) return 3;
    const auto marker = data_directory / L"update-resume-node-started.txt";
    HANDLE file = CreateFileW(marker.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return 4;
    const std::string record = std::string(address_only ? "address-only" : "wallet") +
        (mine ? " mine" : " endorse") + "\n";
    DWORD written = 0;
    const bool saved = WriteFile(file, record.data(),
        static_cast<DWORD>(record.size()), &written, nullptr) != FALSE &&
        written == record.size() && FlushFileBuffers(file) != FALSE;
    CloseHandle(file);
    if (!saved) return 5;
    Sleep(1500);
    return 0;
}
