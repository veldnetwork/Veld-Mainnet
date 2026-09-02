#ifdef _WIN32

#include <windows.h>

#include <cstring>
#include <cwchar>
#include <filesystem>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

int g_checks = 0;
#define CHECK(condition) do {                                                   \
    ++g_checks;                                                                 \
    if (!(condition)) throw std::runtime_error(                                 \
        std::string("check failed at line ") + std::to_string(__LINE__) +      \
        ": " #condition);                                                      \
} while (false)

struct Handle {
    HANDLE value{INVALID_HANDLE_VALUE};
    Handle() = default;
    explicit Handle(HANDLE input) : value(input) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(other.value) {
        other.value = INVALID_HANDLE_VALUE;
    }
    Handle& operator=(Handle&& other) noexcept {
        if (this == &other) return *this;
        if (value != INVALID_HANDLE_VALUE && value != nullptr)
            ::CloseHandle(value);
        value = other.value;
        other.value = INVALID_HANDLE_VALUE;
        return *this;
    }
    ~Handle() {
        if (value != INVALID_HANDLE_VALUE && value != nullptr)
            ::CloseHandle(value);
    }
};

std::wstring QuoteArg(const std::wstring& value) {
    std::wstring output = L"\"";
    size_t slashes = 0;
    for (const wchar_t character : value) {
        if (character == L'\\') { ++slashes; continue; }
        if (character == L'\"') {
            output.append(slashes * 2U + 1U, L'\\');
            output.push_back(L'\"');
            slashes = 0;
            continue;
        }
        output.append(slashes, L'\\');
        slashes = 0;
        output.push_back(character);
    }
    output.append(slashes * 2U, L'\\');
    output.push_back(L'\"');
    return output;
}

std::wstring MakeCommand(const std::wstring& executable,
                         const std::vector<std::wstring>& arguments) {
    std::wstring command = QuoteArg(executable);
    for (const auto& argument : arguments) {
        command.push_back(L' ');
        command += QuoteArg(argument);
    }
    return command;
}

struct Child {
    Handle process;
    Handle thread;
    Handle output;
    DWORD pid{0};
    Child() = default;
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;
    Child(Child&&) noexcept = default;
    Child& operator=(Child&&) noexcept = default;
    ~Child() {
        if (process.value != INVALID_HANDLE_VALUE &&
            ::WaitForSingleObject(process.value, 0) == WAIT_TIMEOUT) {
            (void)::TerminateProcess(process.value, 126);
            (void)::WaitForSingleObject(process.value, 5000);
        }
    }
};

Child Spawn(const std::wstring& executable,
            const std::vector<std::wstring>& arguments,
            HANDLE input) {
    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    HANDLE output_read_raw = INVALID_HANDLE_VALUE;
    HANDLE output_write_raw = INVALID_HANDLE_VALUE;
    if (!::CreatePipe(&output_read_raw, &output_write_raw, &security, 0))
        throw std::runtime_error("output CreatePipe failed");
    Handle output_read(output_read_raw);
    Handle output_write(output_write_raw);
    if (!::SetHandleInformation(output_read.value, HANDLE_FLAG_INHERIT, 0))
        throw std::runtime_error("output pipe protection failed");

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    startup.hStdInput = input;
    startup.hStdOutput = output_write.value;
    startup.hStdError = output_write.value;
    PROCESS_INFORMATION information{};
    std::wstring command = MakeCommand(executable, arguments);
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');
    if (!::CreateProcessW(executable.c_str(), mutable_command.data(), nullptr,
                          nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr,
                          &startup, &information)) {
        throw std::runtime_error("CreateProcess failed: " +
                                 std::to_string(::GetLastError()));
    }
    output_write = Handle{};
    Child child;
    child.process = Handle(information.hProcess);
    child.thread = Handle(information.hThread);
    child.output = std::move(output_read);
    child.pid = information.dwProcessId;
    return child;
}

void Drain(Child& child, std::string& output) {
    for (;;) {
        DWORD available = 0;
        if (!::PeekNamedPipe(child.output.value, nullptr, 0, nullptr,
                             &available, nullptr) || available == 0)
            return;
        std::vector<char> bytes(available);
        DWORD count = 0;
        if (!::ReadFile(child.output.value, bytes.data(), available, &count,
                        nullptr))
            return;
        output.append(bytes.data(), count);
    }
}

DWORD WaitForExit(Child& child, std::string& output,
                  DWORD timeout_ms = 30000) {
    if (::WaitForSingleObject(child.process.value, timeout_ms) != WAIT_OBJECT_0) {
        Drain(child, output);
        throw std::runtime_error("child timeout; output=" + output);
    }
    Drain(child, output);
    DWORD exit_code = 0;
    if (!::GetExitCodeProcess(child.process.value, &exit_code))
        throw std::runtime_error("GetExitCodeProcess failed");
    return exit_code;
}

std::string CaptureProcessCommandLine(DWORD pid) {
    std::vector<wchar_t> system_directory(MAX_PATH + 1U, L'\0');
    const UINT length = ::GetSystemDirectoryW(
        system_directory.data(), static_cast<UINT>(system_directory.size()));
    if (length == 0 || length >= system_directory.size())
        throw std::runtime_error("cannot resolve Windows system directory");
    const std::wstring powershell =
        std::wstring(system_directory.data(), length) +
        L"\\WindowsPowerShell\\v1.0\\powershell.exe";
    const std::wstring expression =
        L"$p=Get-CimInstance Win32_Process -Filter 'ProcessId = " +
        std::to_wstring(pid) +
        L"'; if($null -eq $p){exit 4}; [Console]::Out.Write($p.CommandLine)";
    Handle null_input(::CreateFileW(L"NUL", GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_EXISTING, 0, nullptr));
    if (null_input.value == INVALID_HANDLE_VALUE)
        throw std::runtime_error("cannot open NUL");
    Child inspector = Spawn(
        powershell,
        {L"-NoProfile", L"-NonInteractive", L"-Command", expression},
        null_input.value);
    std::string output;
    if (WaitForExit(inspector, output, 20000) != 0 || output.empty())
        throw std::runtime_error("process-command inspection failed");
    return output;
}

struct RunResult {
    DWORD exit_code{0};
    std::string output;
    std::string inspected_command;
};

RunResult RunProtectedPipe(const std::wstring& executable,
                           const fs::path& output_path,
                           const std::optional<std::string>& input,
                           bool inspect_command = false) {
    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    HANDLE seed_read_raw = INVALID_HANDLE_VALUE;
    HANDLE seed_write_raw = INVALID_HANDLE_VALUE;
    if (!::CreatePipe(&seed_read_raw, &seed_write_raw, &security, 0))
        throw std::runtime_error("seed CreatePipe failed");
    Handle seed_read(seed_read_raw);
    Handle seed_write(seed_write_raw);
    if (!::SetHandleInformation(seed_write.value, HANDLE_FLAG_INHERIT, 0))
        throw std::runtime_error("seed writer protection failed");
    const uint64_t numeric_handle = static_cast<uint64_t>(
        reinterpret_cast<uintptr_t>(seed_read.value));
    Child child = Spawn(
        executable,
        {L"from-seed", L"--out", output_path.wstring(),
         L"--seed-input-handle", std::to_wstring(numeric_handle)},
        seed_read.value);
    seed_read = Handle{};

    RunResult result;
    if (inspect_command)
        result.inspected_command = CaptureProcessCommandLine(child.pid);
    if (input.has_value() && !input->empty()) {
        DWORD written = 0;
        if (!::WriteFile(seed_write.value, input->data(),
                         static_cast<DWORD>(input->size()), &written, nullptr) ||
            written != input->size()) {
            throw std::runtime_error("seed pipe write failed");
        }
    }
    seed_write = Handle{};
    result.exit_code = WaitForExit(child, result.output);
    return result;
}

RunResult RunProtectedHandleArgument(const std::wstring& executable,
                                     const fs::path& output_path,
                                     HANDLE candidate) {
    Handle null_input(::CreateFileW(L"NUL", GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr, OPEN_EXISTING, 0, nullptr));
    if (null_input.value == INVALID_HANDLE_VALUE)
        throw std::runtime_error("cannot open NUL");
    const uint64_t numeric_handle = static_cast<uint64_t>(
        reinterpret_cast<uintptr_t>(candidate));
    Child child = Spawn(
        executable,
        {L"from-seed", L"--out", output_path.wstring(),
         L"--seed-input-handle", std::to_wstring(numeric_handle)},
        null_input.value);
    RunResult result;
    result.exit_code = WaitForExit(child, result.output);
    return result;
}

RunResult RunClosedStdin(const std::wstring& executable,
                         const std::vector<std::wstring>& arguments) {
    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;
    HANDLE input_read_raw = INVALID_HANDLE_VALUE;
    HANDLE input_write_raw = INVALID_HANDLE_VALUE;
    if (!::CreatePipe(&input_read_raw, &input_write_raw, &security, 0))
        throw std::runtime_error("stdin CreatePipe failed");
    Handle input_read(input_read_raw);
    Handle input_write(input_write_raw);
    input_write = Handle{};
    Child child = Spawn(executable, arguments, input_read.value);
    RunResult result;
    result.exit_code = WaitForExit(child, result.output);
    return result;
}

bool EnvironmentContains(const std::string& needle) {
    LPWCH block = ::GetEnvironmentStringsW();
    if (!block) throw std::runtime_error("GetEnvironmentStrings failed");
    const std::wstring wide_needle(needle.begin(), needle.end());
    bool found = false;
    for (const wchar_t* entry = block; *entry != L'\0';
         entry += std::wcslen(entry) + 1U) {
        if (std::wstring(entry).find(wide_needle) != std::wstring::npos) {
            found = true;
            break;
        }
    }
    ::FreeEnvironmentStringsW(block);
    return found;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 3)
            throw std::runtime_error("usage: test.exe KEYGEN PRIVATE_OUTPUT_DIR");
        const std::wstring executable = fs::absolute(argv[1]).wstring();
        const fs::path output_dir = fs::absolute(argv[2]);
        CHECK(fs::is_regular_file(executable));
        CHECK(fs::is_directory(output_dir));
        CHECK(std::getenv("VELD_VAULT_PASSPHRASE") != nullptr);

        const std::string canary =
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f";
        CHECK(!EnvironmentContains(canary));

        const fs::path success_path = output_dir / L"seed-success.key";
        const RunResult success = RunProtectedPipe(
            executable, success_path, canary, true);
        if (success.exit_code != 0)
            std::cerr << "seed success child output: " << success.output << "\n";
        CHECK(success.exit_code == 0);
        CHECK(fs::is_regular_file(success_path));
        CHECK(success.output.find(canary) == std::string::npos);
        CHECK(success.inspected_command.find(canary) == std::string::npos);
        CHECK(success.inspected_command.find("--seed-input-handle") !=
              std::string::npos);

        const fs::path malformed_path = output_dir / L"seed-malformed.key";
        const RunResult malformed = RunProtectedPipe(
            executable, malformed_path, std::string(64, 'g'));
        CHECK(malformed.exit_code == 2);
        CHECK(!fs::exists(malformed_path));
        CHECK(malformed.output.find(std::string(64, 'g')) == std::string::npos);
        CHECK(malformed.output.find("seed must be 64 hex chars") !=
              std::string::npos);

        const fs::path cancelled_path = output_dir / L"seed-cancelled.key";
        const RunResult cancelled = RunProtectedPipe(
            executable, cancelled_path, std::string(1, '\x03'));
        CHECK(cancelled.exit_code == 2);
        CHECK(!fs::exists(cancelled_path));
        CHECK(cancelled.output.find("seed import cancelled") !=
              std::string::npos);

        const fs::path eof_path = output_dir / L"seed-eof.key";
        const RunResult eof = RunProtectedPipe(executable, eof_path,
                                                std::string{});
        CHECK(eof.exit_code == 2);
        CHECK(!fs::exists(eof_path));
        CHECK(eof.output.find("seed input ended before any data") !=
              std::string::npos);

        const fs::path oversized_path = output_dir / L"seed-oversized.key";
        const RunResult oversized = RunProtectedPipe(
            executable, oversized_path, std::string(65, 'a'));
        CHECK(oversized.exit_code == 2);
        CHECK(!fs::exists(oversized_path));
        CHECK(oversized.output.find(std::string(65, 'a')) == std::string::npos);
        CHECK(oversized.output.find("exceeds 64 characters") !=
              std::string::npos);

        SECURITY_ATTRIBUTES inheritable{};
        inheritable.nLength = sizeof(inheritable);
        inheritable.bInheritHandle = TRUE;
        const fs::path regular_input = output_dir / L"not-a-pipe.input";
        Handle regular(::CreateFileW(
            regular_input.wstring().c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ, &inheritable, CREATE_ALWAYS,
            FILE_ATTRIBUTE_TEMPORARY, nullptr));
        if (regular.value == INVALID_HANDLE_VALUE)
            throw std::runtime_error("cannot create regular-handle fixture");
        const fs::path regular_output = output_dir / L"regular-handle.key";
        const RunResult regular_result = RunProtectedHandleArgument(
            executable, regular_output, regular.value);
        CHECK(regular_result.exit_code == 2);
        CHECK(!fs::exists(regular_output));
        CHECK(regular_result.output.find("inherited anonymous pipe") !=
              std::string::npos);
        regular = Handle{};
        (void)fs::remove(regular_input);

        HANDLE noninherit_read_raw = INVALID_HANDLE_VALUE;
        HANDLE noninherit_write_raw = INVALID_HANDLE_VALUE;
        if (!::CreatePipe(&noninherit_read_raw, &noninherit_write_raw,
                          &inheritable, 0))
            throw std::runtime_error("non-inheritable CreatePipe failed");
        Handle noninherit_read(noninherit_read_raw);
        Handle noninherit_write(noninherit_write_raw);
        if (!::SetHandleInformation(noninherit_read.value,
                                    HANDLE_FLAG_INHERIT, 0))
            throw std::runtime_error("cannot protect negative pipe fixture");
        noninherit_write = Handle{};
        const fs::path noninherit_output =
            output_dir / L"noninherit-handle.key";
        const RunResult noninherit_result = RunProtectedHandleArgument(
            executable, noninherit_output, noninherit_read.value);
        CHECK(noninherit_result.exit_code == 2);
        CHECK(!fs::exists(noninherit_output));
        CHECK(noninherit_result.output.find("inherited anonymous pipe") !=
              std::string::npos);

        const fs::path duplicate_output = output_dir / L"duplicate-handle.key";
        const RunResult duplicate_handle = RunClosedStdin(
            executable,
            {L"from-seed", L"--out", duplicate_output.wstring(),
             L"--seed-input-handle", L"1",
             L"--seed-input-handle", L"1"});
        CHECK(duplicate_handle.exit_code == 2);
        CHECK(!fs::exists(duplicate_output));
        CHECK(duplicate_handle.output.find("argument value suppressed") !=
              std::string::npos);

        const fs::path noncanonical_output =
            output_dir / L"noncanonical-handle.key";
        const RunResult noncanonical_handle = RunClosedStdin(
            executable,
            {L"from-seed", L"--out", noncanonical_output.wstring(),
             L"--seed-input-handle", L"00"});
        CHECK(noncanonical_handle.exit_code == 2);
        CHECK(!fs::exists(noncanonical_output));
        CHECK(noncanonical_handle.output.find("argument value suppressed") !=
              std::string::npos);

        const RunResult redirected_eof = RunClosedStdin(
            executable, {L"from-seed", L"--out",
                         (output_dir / L"redirected.key").wstring()});
        CHECK(redirected_eof.exit_code == 2);
        CHECK(redirected_eof.output.find("hidden interactive terminal") !=
              std::string::npos);

        const std::string legacy_canary = "LEGACY_TEST_CANARY_NOT_A_SEED";
        const RunResult positional = RunClosedStdin(
            executable,
            {L"from-seed",
             std::wstring(legacy_canary.begin(), legacy_canary.end()),
             L"--out", (output_dir / L"legacy-positional.key").wstring()});
        CHECK(positional.exit_code == 2);
        CHECK(positional.output.find(legacy_canary) == std::string::npos);
        CHECK(positional.output.find("legacy positional seed import is rejected") !=
              std::string::npos);

        const RunResult named = RunClosedStdin(
            executable,
            {L"from-seed", L"--seed=LEGACY_TEST_CANARY_NOT_A_SEED",
             L"--out", (output_dir / L"legacy-named.key").wstring()});
        CHECK(named.exit_code == 2);
        CHECK(named.output.find(legacy_canary) == std::string::npos);
        CHECK(named.output.find("argument value suppressed") !=
              std::string::npos);

        const RunResult help = RunClosedStdin(executable, {});
        CHECK(help.exit_code == 2);
        CHECK(help.output.find("from-seed --out FILE") != std::string::npos);
        CHECK(help.output.find("--seed=") == std::string::npos);
        CHECK(help.output.find("inherited") != std::string::npos);

        std::cout << "PASS daybreak_seed_import_windows_process_tests checks="
                  << g_checks << "\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL daybreak_seed_import_windows_process_tests: "
                  << error.what() << "\n";
        return 1;
    }
}

#else
int main() { return 77; }
#endif
