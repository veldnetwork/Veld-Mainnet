#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#ifdef VELD_FLEET_NO_MINE
#error "VELD_FLEET_NO_MINE cannot be combined with the Windows mining GUI"
#endif
#if defined(VELD_PUBLIC_RELEASE) && defined(VELD_GUI_TEST_INSTANCE)
#error "VELD_GUI_TEST_INSTANCE cannot bypass package verification in a public release"
#endif

#include <windows.h>
#include <windowsx.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <shellapi.h>
#include <commdlg.h>
#include <tlhelp32.h>
#include <dwmapi.h>

#include "../include/core/version.h"
#include "../include/core/hash.h"
#include "../include/compat/platform.h"
#include "../include/crypto/release_verify.h"
#include "../include/gui/node_gui_model.h"
#include "../include/network/chainparams.h"
#include "../include/wallet/passphrase_policy.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <charconv>
#include <condition_variable>
#include <cmath>
#include <cctype>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifndef VELD_TRUSTED_WALLET_SHA256
#define VELD_TRUSTED_WALLET_SHA256 ""
#endif
#ifndef VELD_TRUSTED_NODE_SHA256
#define VELD_TRUSTED_NODE_SHA256 ""
#endif

namespace {

constexpr UINT WM_NODE_REFRESH = WM_APP + 11;
constexpr UINT WM_TOR_SETUP_COMPLETE = WM_APP + 12;
constexpr UINT WM_TRAY_ICON = WM_APP + 13;
constexpr UINT WM_UPDATE_CHECK_COMPLETE = WM_APP + 14;
constexpr UINT WM_REMOTE_COMMAND = WM_APP + 15;
constexpr UINT TIMER_REPAINT = 21;
constexpr UINT ID_TRAY_RESTORE = 4101;
constexpr UINT ID_TRAY_TOGGLE_NODE = 4102;
constexpr UINT ID_TRAY_EXIT = 4103;
constexpr int IDI_VELD_NODE = 101;
constexpr int IDD_VELD_PASSPHRASE = 201;
constexpr int IDC_VELD_PASSPHRASE = 1001;
constexpr int IDC_VELD_PASSPHRASE_PROMPT = 1002;
constexpr int IDC_VELD_PASSPHRASE_TITLE = 1003;
constexpr int IDC_VELD_PASSPHRASE_LABEL = 1004;
constexpr int IDC_VELD_PASSPHRASE_REVEAL = 1005;
constexpr int IDC_VELD_PASSPHRASE_BRAND = 1006;
constexpr COLORREF C_BG = RGB(8, 10, 9);
constexpr COLORREF C_SIDEBAR = RGB(13, 16, 14);
constexpr COLORREF C_PANEL = RGB(16, 19, 17);
constexpr COLORREF C_PANEL_ALT = RGB(20, 23, 21);
constexpr COLORREF C_BORDER = RGB(55, 62, 58);
constexpr COLORREF C_BORDER_SOFT = RGB(36, 42, 38);
constexpr COLORREF C_TEXT = RGB(241, 244, 241);
constexpr COLORREF C_SUBTEXT = RGB(173, 180, 175);
constexpr COLORREF C_MUTED = RGB(116, 124, 119);
constexpr COLORREF C_GREEN = RGB(126, 217, 73);
constexpr COLORREF C_WARN = RGB(216, 166, 74);
constexpr COLORREF C_BUTTON = RGB(45, 50, 47);
constexpr COLORREF C_BUTTON_HOVER = RGB(54, 60, 56);
constexpr COLORREF C_BUTTON_BORDER = RGB(84, 93, 87);

struct HttpResult {
    bool ok{false};
    std::string body;
    std::wstring error;
};

std::wstring Utf8ToWide(const std::string& text);

std::filesystem::path SystemPowerShellPath() {
    wchar_t system_directory[MAX_PATH]{};
    const UINT length = GetSystemDirectoryW(
        system_directory,
        static_cast<UINT>(sizeof(system_directory) / sizeof(system_directory[0])));
    if (length == 0 || length >= sizeof(system_directory) / sizeof(system_directory[0]))
        return {};
    const std::filesystem::path powershell =
        std::filesystem::path(system_directory) /
        L"WindowsPowerShell" / L"v1.0" / L"powershell.exe";
    std::error_code ec;
    return std::filesystem::is_regular_file(powershell, ec)
        ? powershell : std::filesystem::path{};
}

HttpResult HttpGetJson(const wchar_t* host, INTERNET_PORT port,
                       const wchar_t* path, bool secure,
                       DWORD timeout_ms) {
    HttpResult out;
    HINTERNET session = WinHttpOpen(
        L"VeldNodeGUI/1.0", secure ? WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
                                   : WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        out.error = L"HTTP session unavailable";
        return out;
    }
    WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
    HINTERNET connect = WinHttpConnect(session, host, port, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        out.error = L"HTTP connection unavailable";
        return out;
    }
    HINTERNET request = WinHttpOpenRequest(
        connect, L"GET", path, nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, secure ? WINHTTP_FLAG_SECURE : 0);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        out.error = L"HTTP request unavailable";
        return out;
    }
    const wchar_t* accept = L"Accept: application/json\r\n";
    const BOOL sent = WinHttpSendRequest(
        request, accept, static_cast<DWORD>(-1L), WINHTTP_NO_REQUEST_DATA,
        0, 0, 0);
    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        out.error = L"Endpoint did not respond";
    } else {
        DWORD status = 0;
        DWORD status_size = sizeof(status);
        if (!WinHttpQueryHeaders(request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                WINHTTP_NO_HEADER_INDEX) || status != 200) {
            out.error = L"Endpoint returned a non-200 response";
        } else {
            constexpr size_t MAX_BODY = 256U * 1024U;
            for (;;) {
                DWORD available = 0;
                if (!WinHttpQueryDataAvailable(request, &available)) break;
                if (available == 0) {
                    out.ok = !out.body.empty();
                    break;
                }
                if (out.body.size() + available > MAX_BODY) {
                    out.error = L"Endpoint response exceeded policy";
                    out.body.clear();
                    break;
                }
                const size_t offset = out.body.size();
                out.body.resize(offset + available);
                DWORD read = 0;
                if (!WinHttpReadData(request, out.body.data() + offset,
                                     available, &read)) {
                    out.body.clear();
                    break;
                }
                out.body.resize(offset + read);
            }
        }
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return out;
}

HttpResult HttpPostJson(const wchar_t* host, INTERNET_PORT port,
                        const wchar_t* path, const std::string& body,
                        const std::string& bearer, DWORD timeout_ms) {
    HttpResult out;
    if (body.empty() || body.size() > 32U * 1024U || bearer.empty() ||
        bearer.size() > 128) {
        out.error = L"Invalid monitoring request";
        return out;
    }
    HINTERNET session = WinHttpOpen(
        L"VeldNodeGUI/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        out.error = L"Monitoring session unavailable";
        return out;
    }
    WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
    HINTERNET connect = WinHttpConnect(session, host, port, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        out.error = L"Monitoring connection unavailable";
        return out;
    }
    HINTERNET request = WinHttpOpenRequest(
        connect, L"POST", path, nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        out.error = L"Monitoring request unavailable";
        return out;
    }
    DWORD redirect_policy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(request, WINHTTP_OPTION_REDIRECT_POLICY,
                          &redirect_policy, sizeof(redirect_policy))) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        out.error = L"Monitoring redirect policy unavailable";
        return out;
    }
    const std::wstring headers =
        L"Accept: application/json\r\nContent-Type: application/json\r\n"
        L"Authorization: Bearer " + Utf8ToWide(bearer) + L"\r\n";
    const BOOL sent = WinHttpSendRequest(
        request, headers.c_str(), static_cast<DWORD>(headers.size()),
        const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
        static_cast<DWORD>(body.size()), 0);
    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        out.error = L"Monitoring endpoint did not respond";
    } else {
        DWORD status = 0;
        DWORD status_size = sizeof(status);
        if (!WinHttpQueryHeaders(request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                WINHTTP_NO_HEADER_INDEX) || status != 200) {
            out.error = L"Monitoring endpoint rejected the report";
        } else {
            constexpr size_t MAX_RESPONSE = 16U * 1024U;
            for (;;) {
                DWORD available = 0;
                if (!WinHttpQueryDataAvailable(request, &available)) break;
                if (available == 0) {
                    out.ok = !out.body.empty();
                    break;
                }
                if (out.body.size() + available > MAX_RESPONSE) {
                    out.error = L"Monitoring response exceeded policy";
                    out.body.clear();
                    break;
                }
                const size_t offset = out.body.size();
                out.body.resize(offset + available);
                DWORD read = 0;
                if (!WinHttpReadData(request, out.body.data() + offset,
                                     available, &read)) {
                    out.body.clear();
                    break;
                }
                out.body.resize(offset + read);
            }
        }
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return out;
}

std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     text.data(), static_cast<int>(text.size()),
                                     nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
                        static_cast<int>(text.size()), out.data(), needed);
    return out;
}

std::string WideToUtf8(const std::wstring& text) {
    if (text.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                     text.data(), static_cast<int>(text.size()),
                                     nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
                        static_cast<int>(text.size()), out.data(), needed,
                        nullptr, nullptr);
    return out;
}

std::string JsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    constexpr char HEX[] = "0123456789abcdef";
    for (const unsigned char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out.push_back(HEX[c >> 4]);
                    out.push_back(HEX[c & 0x0f]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

std::wstring MonitoringMachineName() {
    std::wstring name(256, L'\0');
    DWORD size = static_cast<DWORD>(name.size());
    if (!GetComputerNameW(name.data(), &size) || size == 0) return L"Veld Node";
    name.resize(std::min<DWORD>(size, 48));
    for (wchar_t& c : name) {
        if (c < 0x20 || c == L'<' || c == L'>' || c == L'&') c = L' ';
    }
    while (!name.empty() && name.back() == L' ') name.pop_back();
    return name.empty() ? L"Veld Node" : name;
}

bool IsDeviceToken(const std::string& token) {
    if (token.size() != 43) return false;
    return std::all_of(token.begin(), token.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '-' || c == '_';
    });
}

std::string NewDeviceToken() {
    uint8_t random[32]{};
    if (!veld::compat::SecureRandom(random, sizeof(random))) return {};
    DWORD encoded_size = 0;
    CryptBinaryToStringA(random, sizeof(random),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
                         nullptr, &encoded_size);
    std::string encoded(encoded_size, '\0');
    if (encoded_size == 0 || !CryptBinaryToStringA(
            random, sizeof(random), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            encoded.data(), &encoded_size)) {
        SecureZeroMemory(random, sizeof(random));
        return {};
    }
    SecureZeroMemory(random, sizeof(random));
    if (!encoded.empty() && encoded.back() == '\0') encoded.pop_back();
    while (!encoded.empty() && encoded.back() == '=') encoded.pop_back();
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    return IsDeviceToken(encoded) ? encoded : std::string{};
}

DATA_BLOB MonitoringEntropy() {
    static BYTE entropy[] = {
        0x56, 0x65, 0x6c, 0x64, 0x4e, 0x6f, 0x64, 0x65,
        0x52, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x56, 0x31
    };
    return DATA_BLOB{static_cast<DWORD>(sizeof(entropy)), entropy};
}

bool SaveDeviceToken(const std::filesystem::path& path,
                     const std::string& token) {
    if (!IsDeviceToken(token)) return false;
    DATA_BLOB plain{static_cast<DWORD>(token.size()),
                    reinterpret_cast<BYTE*>(const_cast<char*>(token.data()))};
    DATA_BLOB protected_blob{};
    DATA_BLOB entropy = MonitoringEntropy();
    if (!CryptProtectData(&plain, L"Veld remote monitor credential", &entropy,
                          nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN,
                          &protected_blob)) return false;
    const std::filesystem::path pending = path.wstring() + L".new";
    bool written = false;
    {
        std::ofstream output(pending, std::ios::binary | std::ios::trunc);
        if (output) {
            output.write(reinterpret_cast<const char*>(protected_blob.pbData),
                         protected_blob.cbData);
            output.flush();
            written = static_cast<bool>(output);
        }
    }
    if (protected_blob.pbData) {
        SecureZeroMemory(protected_blob.pbData, protected_blob.cbData);
        LocalFree(protected_blob.pbData);
    }
    if (!written || !MoveFileExW(pending.c_str(), path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(pending.c_str());
        return false;
    }
    return true;
}

std::string LoadDeviceToken(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    input.seekg(0, std::ios::end);
    const std::streamoff size = input.tellg();
    if (size <= 0 || size > 4096) return {};
    input.seekg(0, std::ios::beg);
    std::vector<BYTE> protected_bytes(static_cast<size_t>(size));
    input.read(reinterpret_cast<char*>(protected_bytes.data()), size);
    if (input.gcount() != size) return {};
    DATA_BLOB protected_blob{static_cast<DWORD>(protected_bytes.size()),
                             protected_bytes.data()};
    DATA_BLOB plain{};
    DATA_BLOB entropy = MonitoringEntropy();
    if (!CryptUnprotectData(&protected_blob, nullptr, &entropy, nullptr,
                            nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain)) {
        SecureZeroMemory(protected_bytes.data(), protected_bytes.size());
        return {};
    }
    std::string token(reinterpret_cast<const char*>(plain.pbData), plain.cbData);
    if (plain.pbData) {
        SecureZeroMemory(plain.pbData, plain.cbData);
        LocalFree(plain.pbData);
    }
    SecureZeroMemory(protected_bytes.data(), protected_bytes.size());
    return IsDeviceToken(token) ? token : std::string{};
}

std::string Base64UrlEncode(const uint8_t* data, size_t size) {
    if ((!data && size != 0) || size > std::numeric_limits<DWORD>::max())
        return {};
    DWORD encoded_size = 0;
    if (!CryptBinaryToStringA(data, static_cast<DWORD>(size),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            nullptr, &encoded_size) || encoded_size == 0) return {};
    std::string encoded(encoded_size, '\0');
    if (!CryptBinaryToStringA(data, static_cast<DWORD>(size),
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            encoded.data(), &encoded_size)) return {};
    encoded.resize(encoded_size);
    if (!encoded.empty() && encoded.back() == '\0') encoded.pop_back();
    while (!encoded.empty() && encoded.back() == '=') encoded.pop_back();
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    return encoded;
}

bool Base64UrlDecodeExact(const std::string& encoded, size_t expected_size,
                          std::vector<uint8_t>& decoded) {
    decoded.clear();
    if (encoded.empty() || encoded.find_first_not_of(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
            != std::string::npos) return false;
    std::string padded = encoded;
    std::replace(padded.begin(), padded.end(), '-', '+');
    std::replace(padded.begin(), padded.end(), '_', '/');
    padded.append((4 - padded.size() % 4) % 4, '=');
    DWORD size = 0;
    if (!CryptStringToBinaryA(padded.c_str(), static_cast<DWORD>(padded.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, nullptr, &size,
            nullptr, nullptr) || size != expected_size) return false;
    decoded.resize(size);
    if (!CryptStringToBinaryA(padded.c_str(), static_cast<DWORD>(padded.size()),
            CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT, decoded.data(), &size,
            nullptr, nullptr) || size != expected_size ||
        Base64UrlEncode(decoded.data(), decoded.size()) != encoded) {
        decoded.clear();
        return false;
    }
    return true;
}

std::string LowerHex(const uint8_t* data, size_t size) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(size * 2, '0');
    for (size_t i = 0; i < size; ++i) {
        out[i * 2] = kHex[data[i] >> 4];
        out[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return out;
}

HANDLE OpenVerifiedTrustedFile(const std::filesystem::path& path,
                               const std::string& expected) {
    if (expected.size() != 64 ||
        expected.find_first_not_of("0123456789abcdef") != std::string::npos)
        return INVALID_HANDLE_VALUE;
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
            FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    FILE_ATTRIBUTE_TAG_INFO tag{};
    LARGE_INTEGER size{};
    if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag,
            sizeof(tag)) ||
        (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                               FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > 512LL * 1024LL * 1024LL) {
        CloseHandle(file);
        return INVALID_HANDLE_VALUE;
    }
    veld::SHA256 hasher;
    std::array<uint8_t, 64 * 1024> buffer{};
    uint64_t read_total = 0;
    for (;;) {
        DWORD count = 0;
        if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()),
                      &count, nullptr)) {
            SecureZeroMemory(buffer.data(), buffer.size());
            CloseHandle(file);
            return INVALID_HANDLE_VALUE;
        }
        if (count == 0) break;
        hasher.update(buffer.data(), count);
        read_total += count;
        if (read_total > static_cast<uint64_t>(size.QuadPart)) {
            SecureZeroMemory(buffer.data(), buffer.size());
            CloseHandle(file);
            return INVALID_HANDLE_VALUE;
        }
    }
    SecureZeroMemory(buffer.data(), buffer.size());
    const auto digest = hasher.digest();
    if (read_total != static_cast<uint64_t>(size.QuadPart) ||
        !veld::compat::ConstantTimeEqual(
            LowerHex(digest.data(), digest.size()), expected)) {
        CloseHandle(file);
        return INVALID_HANDLE_VALUE;
    }
    LARGE_INTEGER beginning{};
    if (!SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN)) {
        CloseHandle(file);
        return INVALID_HANDLE_VALUE;
    }
    // FILE_SHARE_READ deliberately withholds write/delete sharing. The caller
    // keeps this handle open through CreateProcess and signer readiness, so the
    // exact file whose hash was compiled into this signed GUI cannot be swapped
    // between verification and execution.
    return file;
}

std::string PortalCommandKeyId(const std::string& x,
                               const std::string& y) {
    veld::SHA256 hasher;
    hasher.update(std::string("VELD_PORTAL_KEY_V1\n") + x + "\n" + y);
    const auto digest = hasher.digest();
    return LowerHex(digest.data(), digest.size());
}

bool IsPortalKeyId(const std::string& value) {
    return value.size() == 64 && value.find_first_not_of("0123456789abcdef") ==
        std::string::npos;
}

bool IsPortalCommandKey(const std::string& x, const std::string& y,
                        const std::string& id) {
    std::vector<uint8_t> coordinate;
    return IsPortalKeyId(id) && Base64UrlDecodeExact(x, 32, coordinate) &&
        Base64UrlDecodeExact(y, 32, coordinate) &&
        PortalCommandKeyId(x, y) == id;
}

struct PortalTrustState {
    uint64_t device_id{0};
    uint64_t last_sequence{0};
    std::string key_id;
    std::string key_x;
    std::string key_y;

    bool Valid() const {
        return device_id != 0 &&
            IsPortalCommandKey(key_x, key_y, key_id);
    }
};

DATA_BLOB PortalTrustEntropy() {
    static BYTE entropy[] = {
        0x56, 0x65, 0x6c, 0x64, 0x50, 0x6f, 0x72, 0x74,
        0x61, 0x6c, 0x54, 0x72, 0x75, 0x73, 0x74, 0x56,
        0x33
    };
    return DATA_BLOB{static_cast<DWORD>(sizeof(entropy)), entropy};
}

bool SavePortalTrust(const std::filesystem::path& path,
                     const PortalTrustState& state) {
    if (!state.Valid()) return false;
    std::ostringstream serialized;
    serialized << "VELD_PORTAL_TRUST_V1\n" << state.device_id << '\n'
               << state.last_sequence << '\n' << state.key_id << '\n'
               << state.key_x << '\n' << state.key_y << '\n';
    std::string text = serialized.str();
    DATA_BLOB plain{static_cast<DWORD>(text.size()),
                    reinterpret_cast<BYTE*>(text.data())};
    DATA_BLOB protected_blob{};
    DATA_BLOB entropy = PortalTrustEntropy();
    if (!CryptProtectData(&plain, L"Veld portal command trust", &entropy,
            nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &protected_blob)) {
        SecureZeroMemory(text.data(), text.size());
        return false;
    }
    const std::filesystem::path pending = path.wstring() + L".new";
    bool written = false;
    {
        std::ofstream output(pending, std::ios::binary | std::ios::trunc);
        if (output) {
            output.write(reinterpret_cast<const char*>(protected_blob.pbData),
                         protected_blob.cbData);
            output.flush();
            written = static_cast<bool>(output);
        }
    }
    SecureZeroMemory(text.data(), text.size());
    if (protected_blob.pbData) {
        SecureZeroMemory(protected_blob.pbData, protected_blob.cbData);
        LocalFree(protected_blob.pbData);
    }
    if (!written || !MoveFileExW(pending.c_str(), path.c_str(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(pending.c_str());
        return false;
    }
    return true;
}

bool LoadPortalTrust(const std::filesystem::path& path,
                     PortalTrustState& state) {
    state = {};
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    input.seekg(0, std::ios::end);
    const std::streamoff size = input.tellg();
    if (size <= 0 || size > 4096) return false;
    input.seekg(0, std::ios::beg);
    std::vector<BYTE> protected_bytes(static_cast<size_t>(size));
    input.read(reinterpret_cast<char*>(protected_bytes.data()), size);
    if (input.gcount() != size) return false;
    DATA_BLOB protected_blob{static_cast<DWORD>(protected_bytes.size()),
                             protected_bytes.data()};
    DATA_BLOB plain{};
    DATA_BLOB entropy = PortalTrustEntropy();
    if (!CryptUnprotectData(&protected_blob, nullptr, &entropy, nullptr,
            nullptr, CRYPTPROTECT_UI_FORBIDDEN, &plain)) {
        SecureZeroMemory(protected_bytes.data(), protected_bytes.size());
        return false;
    }
    std::string text(reinterpret_cast<const char*>(plain.pbData), plain.cbData);
    if (plain.pbData) {
        SecureZeroMemory(plain.pbData, plain.cbData);
        LocalFree(plain.pbData);
    }
    SecureZeroMemory(protected_bytes.data(), protected_bytes.size());
    std::istringstream stream(text);
    std::vector<std::string> lines;
    for (std::string line; std::getline(stream, line);) {
        if (!line.empty() && line.back() == '\r') {
            SecureZeroMemory(text.data(), text.size());
            return false;
        }
        lines.push_back(std::move(line));
    }
    PortalTrustState parsed;
    const auto parse_number = [](const std::string& value, uint64_t& out) {
        if (value.empty()) return false;
        const auto result = std::from_chars(value.data(),
            value.data() + value.size(), out, 10);
        return result.ec == std::errc{} &&
            result.ptr == value.data() + value.size();
    };
    const bool ok = lines.size() == 6 && lines[0] == "VELD_PORTAL_TRUST_V1" &&
        parse_number(lines[1], parsed.device_id) && parsed.device_id != 0 &&
        parse_number(lines[2], parsed.last_sequence);
    if (ok) {
        parsed.key_id = lines[3];
        parsed.key_x = lines[4];
        parsed.key_y = lines[5];
    }
    SecureZeroMemory(text.data(), text.size());
    if (!ok || !parsed.Valid()) return false;
    state = std::move(parsed);
    return true;
}

bool VerifyPortalCommandSignature(const std::string& key_x,
                                  const std::string& key_y,
                                  const std::string& envelope,
                                  const std::string& signature_text) {
    std::vector<uint8_t> x, y, signature;
    if (!Base64UrlDecodeExact(key_x, 32, x) ||
        !Base64UrlDecodeExact(key_y, 32, y) ||
        !Base64UrlDecodeExact(signature_text, 64, signature)) return false;
    BCRYPT_ECCKEY_BLOB header{};
    header.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    header.cbKey = 32;
    std::vector<uint8_t> blob(sizeof(header) + x.size() + y.size());
    std::memcpy(blob.data(), &header, sizeof(header));
    std::memcpy(blob.data() + sizeof(header), x.data(), x.size());
    std::memcpy(blob.data() + sizeof(header) + x.size(), y.data(), y.size());
    veld::SHA256 hasher;
    hasher.update(envelope);
    const auto digest = hasher.digest();
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    bool verified = false;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM,
            nullptr, 0) == 0) {
        if (BCryptImportKeyPair(algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key,
                blob.data(), static_cast<ULONG>(blob.size()), 0) == 0) {
            verified = BCryptVerifySignature(key, nullptr,
                const_cast<PUCHAR>(digest.data()),
                static_cast<ULONG>(digest.size()), signature.data(),
                static_cast<ULONG>(signature.size()), 0) == 0;
        }
    }
    if (key) BCryptDestroyKey(key);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    SecureZeroMemory(signature.data(), signature.size());
    return verified;
}

struct MonitoringReply {
    struct Command {
        bool present{false};
        uint64_t id{0};
        uint64_t device_id{0};
        uint64_t sequence{0};
        uint64_t issued_at{0};
        uint64_t expires_at{0};
        std::string action;
        std::string nonce;
        std::string key_id;
        std::string key_x;
        std::string key_y;
        std::string signature;
        bool enabled{false};
        uint64_t workers{0};
        std::string mode;
    } command;
    uint64_t protocol{0};
    uint64_t device_id{0};
    bool paired{false};
    bool command_key_present{false};
    std::string command_key_id;
    std::string command_key_x;
    std::string command_key_y;
    std::string pair_code;
    uint64_t pair_expires{0};
    uint64_t report_interval{5};
};

bool ParseMonitoringReply(const std::string& body, MonitoringReply& out) {
    veld::btc_buy::JsonValue root;
    std::string error;
    veld::btc_buy::StrictJsonParser parser(
        body, 16U * 1024U, /*reject_escaped_object_keys=*/true);
    if (!parser.Parse(root, error) ||
        root.kind != veld::btc_buy::JsonValue::Kind::Object) return false;
    MonitoringReply parsed;
    if (root.object.size() != 8 ||
        !veld::node_gui::ParseUint(root.Get("portal_protocol"),
                                  parsed.protocol) ||
        parsed.protocol != 3 ||
        !veld::node_gui::ParseUint(root.Get("device_id"), parsed.device_id) ||
        parsed.device_id == 0 ||
        !veld::node_gui::ParseBool(root.Get("paired"), parsed.paired) ||
        !veld::node_gui::ParseUint(root.Get("pair_expires"),
                                  parsed.pair_expires) ||
        !veld::node_gui::ParseUint(root.Get("report_interval"),
                                  parsed.report_interval) ||
        parsed.report_interval < 5 || parsed.report_interval > 300)
        return false;
    const auto* pair_code = root.Get("pair_code");
    if (!parsed.paired) {
        if (!pair_code ||
            pair_code->kind != veld::btc_buy::JsonValue::Kind::String ||
            pair_code->text.size() != 9 || pair_code->text[4] != '-')
            return false;
        for (size_t i = 0; i < pair_code->text.size(); ++i) {
            if (i == 4) continue;
            if (std::string("23456789ABCDEFGHJKLMNPQRSTUVWXYZ").find(
                    pair_code->text[i]) == std::string::npos) return false;
        }
        parsed.pair_code = pair_code->text;
    } else if (!pair_code ||
               pair_code->kind != veld::btc_buy::JsonValue::Kind::Null) {
        return false;
    }
    const auto* command_key = root.Get("command_key");
    if (command_key &&
        command_key->kind == veld::btc_buy::JsonValue::Kind::Object) {
        if (command_key->object.size() != 3) return false;
        const auto* id = command_key->Get("id");
        const auto* x = command_key->Get("x");
        const auto* y = command_key->Get("y");
        if (!id || !x || !y ||
            id->kind != veld::btc_buy::JsonValue::Kind::String ||
            x->kind != veld::btc_buy::JsonValue::Kind::String ||
            y->kind != veld::btc_buy::JsonValue::Kind::String ||
            !IsPortalCommandKey(x->text, y->text, id->text)) return false;
        parsed.command_key_present = true;
        parsed.command_key_id = id->text;
        parsed.command_key_x = x->text;
        parsed.command_key_y = y->text;
    } else if (!command_key ||
               command_key->kind != veld::btc_buy::JsonValue::Kind::Null) {
        return false;
    }
    const auto* command = root.Get("command");
    if (command && command->kind == veld::btc_buy::JsonValue::Kind::Object) {
        if (!parsed.paired || !parsed.command_key_present ||
            command->object.size() != 9) return false;
        const auto* action = command->Get("action");
        const auto* payload = command->Get("payload");
        const auto* nonce = command->Get("nonce");
        const auto* key_id = command->Get("key_id");
        const auto* signature = command->Get("signature");
        if (!veld::node_gui::ParseUint(command->Get("id"),
                                       parsed.command.id) ||
            parsed.command.id == 0 ||
            !veld::node_gui::ParseUint(command->Get("sequence"),
                                       parsed.command.sequence) ||
            parsed.command.sequence == 0 ||
            !veld::node_gui::ParseUint(command->Get("issued_at"),
                                       parsed.command.issued_at) ||
            !veld::node_gui::ParseUint(command->Get("expires_at"),
                                       parsed.command.expires_at) ||
            !action || action->kind !=
                veld::btc_buy::JsonValue::Kind::String ||
            !payload || payload->kind !=
                veld::btc_buy::JsonValue::Kind::Object ||
            !nonce || nonce->kind != veld::btc_buy::JsonValue::Kind::String ||
            !key_id || key_id->kind !=
                veld::btc_buy::JsonValue::Kind::String ||
            !signature || signature->kind !=
                veld::btc_buy::JsonValue::Kind::String)
            return false;
        std::vector<uint8_t> decoded;
        if (nonce->text.size() != 22 ||
            !Base64UrlDecodeExact(nonce->text, 16, decoded) ||
            signature->text.size() != 86 ||
            !Base64UrlDecodeExact(signature->text, 64, decoded) ||
            key_id->text != parsed.command_key_id) return false;
        parsed.command.present = true;
        parsed.command.device_id = parsed.device_id;
        parsed.command.action = action->text;
        parsed.command.nonce = nonce->text;
        parsed.command.key_id = key_id->text;
        parsed.command.key_x = parsed.command_key_x;
        parsed.command.key_y = parsed.command_key_y;
        parsed.command.signature = signature->text;
        if (parsed.command.action == "mining.enabled" ||
            parsed.command.action == "privacy.tor" ||
            parsed.command.action == "network.reachable" ||
            parsed.command.action == "display.reference") {
            if (payload->object.size() != 1) return false;
            if (!veld::node_gui::ParseBool(payload->Get("enabled"),
                                           parsed.command.enabled))
                return false;
        } else if (parsed.command.action == "mining.workers") {
            if (payload->object.size() != 1) return false;
            if (!veld::node_gui::ParseUint(payload->Get("workers"),
                                           parsed.command.workers) ||
                parsed.command.workers < 1 || parsed.command.workers > 256)
                return false;
        } else if (parsed.command.action == "sync.mode") {
            const auto* mode = payload->Get("mode");
            if (payload->object.size() != 1) return false;
            if (!mode || mode->kind !=
                    veld::btc_buy::JsonValue::Kind::String ||
                (mode->text != "full" && mode->text != "snapshot"))
                return false;
            parsed.command.mode = mode->text;
        } else if (parsed.command.action != "node.start" &&
                   parsed.command.action != "node.stop" &&
                   parsed.command.action != "updates.check" &&
                   parsed.command.action != "updates.install") {
            return false;
        } else if (!payload->object.empty()) {
            return false;
        }
    } else if (command &&
               command->kind != veld::btc_buy::JsonValue::Kind::Null) {
        return false;
    }
    out = std::move(parsed);
    return true;
}

std::string CanonicalPortalCommandPayload(
        const MonitoringReply::Command& command) {
    if (command.action == "node.start" || command.action == "node.stop" ||
        command.action == "updates.check" ||
        command.action == "updates.install") return "{}";
    if (command.action == "mining.enabled" ||
        command.action == "privacy.tor" ||
        command.action == "network.reachable" ||
        command.action == "display.reference")
        return std::string("{\"enabled\":") +
            (command.enabled ? "true}" : "false}");
    if (command.action == "mining.workers" && command.workers >= 1 &&
        command.workers <= 256)
        return "{\"workers\":" + std::to_string(command.workers) + "}";
    if (command.action == "sync.mode" &&
        (command.mode == "full" || command.mode == "snapshot"))
        return "{\"mode\":\"" + command.mode + "\"}";
    return {};
}

std::string PortalCommandEnvelope(const MonitoringReply::Command& command) {
    const std::string payload = CanonicalPortalCommandPayload(command);
    if (payload.empty()) return {};
    std::ostringstream envelope;
    envelope << "VELD_PORTAL_COMMAND_V3\n" << command.device_id << '\n'
             << command.sequence << '\n' << command.issued_at << '\n'
             << command.expires_at << '\n' << command.nonce << '\n'
             << command.action << '\n' << payload;
    return envelope.str();
}

enum class PortalCommandTrustVerdict {
    Reject,
    NewPairing,
    ExistingPairing,
};

PortalCommandTrustVerdict EvaluatePortalCommandTrust(
        const MonitoringReply::Command& command,
        const PortalTrustState& current, uint64_t now,
        PortalTrustState& next, std::string& rejection) {
    next = {};
    rejection = "Remote command verification failed";
    std::vector<uint8_t> nonce;
    if (!command.present || command.id == 0 || command.device_id == 0 ||
        command.sequence == 0 || command.issued_at == 0 ||
        !Base64UrlDecodeExact(command.nonce, 16, nonce) ||
        !IsPortalCommandKey(command.key_x, command.key_y, command.key_id))
        return PortalCommandTrustVerdict::Reject;
    const std::string envelope = PortalCommandEnvelope(command);
    if (envelope.empty()) return PortalCommandTrustVerdict::Reject;
    if ((command.issued_at > now && command.issued_at - now > 120) ||
        command.expires_at <= now ||
        command.expires_at <= command.issued_at ||
        command.expires_at - command.issued_at < 30 ||
        command.expires_at - command.issued_at > 180)
        return PortalCommandTrustVerdict::Reject;
    if (!VerifyPortalCommandSignature(command.key_x, command.key_y,
            envelope, command.signature)) return PortalCommandTrustVerdict::Reject;

    const bool same_pairing = current.Valid() &&
        current.device_id == command.device_id;
    if (same_pairing && (current.key_id != command.key_id ||
            current.key_x != command.key_x ||
            current.key_y != command.key_y)) {
        rejection = "Command key changed; local re-pairing is required";
        return PortalCommandTrustVerdict::Reject;
    }
    if (same_pairing && command.sequence <= current.last_sequence) {
        rejection = "Replay or out-of-order command rejected";
        return PortalCommandTrustVerdict::Reject;
    }

    next.device_id = command.device_id;
    next.last_sequence = command.sequence;
    next.key_id = command.key_id;
    next.key_x = command.key_x;
    next.key_y = command.key_y;
    rejection.clear();
    return same_pairing ? PortalCommandTrustVerdict::ExistingPairing
                        : PortalCommandTrustVerdict::NewPairing;
}

std::vector<std::wstring> ReadLogTail(const std::filesystem::path& path,
                                      size_t max_lines = 28) {
    constexpr std::streamoff MAX_BYTES = 64 * 1024;
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    input.seekg(0, std::ios::end);
    const std::streamoff size = input.tellg();
    if (size <= 0) return {};
    const std::streamoff start = std::max<std::streamoff>(0, size - MAX_BYTES);
    input.seekg(start, std::ios::beg);
    std::string body(static_cast<size_t>(size - start), '\0');
    input.read(body.data(), static_cast<std::streamsize>(body.size()));
    body.resize(static_cast<size_t>(input.gcount()));
    if (start > 0) {
        const size_t first_line = body.find('\n');
        if (first_line != std::string::npos) body.erase(0, first_line + 1);
    }

    std::deque<std::wstring> lines;
    size_t cursor = 0;
    while (cursor <= body.size()) {
        const size_t end = body.find('\n', cursor);
        std::string line = body.substr(cursor,
            end == std::string::npos ? std::string::npos : end - cursor);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::string clean;
        clean.reserve(line.size());
        for (size_t i = 0; i < line.size(); ++i) {
            if (static_cast<unsigned char>(line[i]) == 0x1b &&
                i + 1 < line.size() && line[i + 1] == '[') {
                i += 2;
                while (i < line.size()) {
                    const unsigned char value =
                        static_cast<unsigned char>(line[i]);
                    if (value >= 0x40 && value <= 0x7e) break;
                    ++i;
                }
                continue;
            }
            clean.push_back(line[i]);
        }
        line = std::move(clean);
        for (char& c : line) {
            const unsigned char value = static_cast<unsigned char>(c);
            if (value < 0x20 && c != '\t') c = ' ';
        }
        if (line.size() > 360) line.resize(360);
        std::wstring wide = Utf8ToWide(line);
        if (!line.empty() && wide.empty()) wide = L"[unreadable log line]";
        if (!wide.empty()) {
            lines.push_back(std::move(wide));
            if (lines.size() > max_lines) lines.pop_front();
        }
        if (end == std::string::npos) break;
        cursor = end + 1;
    }
    return {lines.begin(), lines.end()};
}

std::string ReadTextBounded(const std::filesystem::path& path,
                            size_t max_bytes = 64U * 1024U) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    input.seekg(0, std::ios::end);
    const std::streamoff size = input.tellg();
    if (size <= 0 || static_cast<uint64_t>(size) > max_bytes) return {};
    input.seekg(0, std::ios::beg);
    std::string body(static_cast<size_t>(size), '\0');
    input.read(body.data(), static_cast<std::streamsize>(body.size()));
    if (input.gcount() != static_cast<std::streamsize>(body.size())) return {};
    return body;
}

std::wstring FormatUnsigned(uint64_t value) {
    std::wstring raw = std::to_wstring(value);
    for (ptrdiff_t i = static_cast<ptrdiff_t>(raw.size()) - 3; i > 0; i -= 3)
        raw.insert(static_cast<size_t>(i), 1, L',');
    return raw;
}

std::wstring FormatUptime(uint64_t seconds) {
    const uint64_t days = seconds / 86400;
    const uint64_t hours = (seconds % 86400) / 3600;
    const uint64_t minutes = (seconds % 3600) / 60;
    std::wostringstream out;
    if (days) out << days << L"d " << hours << L"h";
    else if (hours) out << hours << L"h " << minutes << L"m";
    else out << minutes << L"m";
    return out.str();
}

std::wstring FormatEta(uint64_t seconds) {
    if (seconds < 60) return L"under 1m";
    return FormatUptime(seconds);
}

std::wstring FormatAge(uint64_t unix_timestamp) {
    if (unix_timestamp == 0) return L"Unknown";
    const uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    if (unix_timestamp > now + 5) return L"Clock ahead";
    return FormatUptime(now > unix_timestamp ? now - unix_timestamp : 0) +
        L" ago";
}

std::wstring FormatPercent(double value) {
    std::wostringstream out;
    out << std::fixed << std::setprecision(1) << value << L"%";
    return out.str();
}

std::wstring FormatHashrate(double hashes_per_second) {
    std::wostringstream out;
    out << std::fixed << std::setprecision(
        hashes_per_second >= 1000.0 ? 1 : 2);
    if (hashes_per_second >= 1.0e9)
        out << hashes_per_second / 1.0e9 << L" GH/s";
    else if (hashes_per_second >= 1.0e6)
        out << hashes_per_second / 1.0e6 << L" MH/s";
    else if (hashes_per_second >= 1.0e3)
        out << hashes_per_second / 1.0e3 << L" KH/s";
    else
        out << hashes_per_second << L" H/s";
    return out.str();
}

std::wstring FormatBytes(uint64_t bytes) {
    static constexpr const wchar_t* UNITS[] = {
        L"B", L"KB", L"MB", L"GB", L"TB"
    };
    double value = static_cast<double>(bytes);
    size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < std::size(UNITS)) {
        value /= 1024.0;
        ++unit;
    }
    std::wostringstream out;
    out << std::fixed << std::setprecision(unit == 0 ? 0 : 1)
        << value << L" " << UNITS[unit];
    return out.str();
}

std::wstring FormatByteRate(double bytes_per_second) {
    if (!std::isfinite(bytes_per_second) || bytes_per_second < 0.0)
        return L"—";
    return FormatBytes(static_cast<uint64_t>(bytes_per_second + 0.5)) + L"/s";
}

unsigned EstimatedPhysicalThreads() {
    const unsigned logical = std::max(1u, std::thread::hardware_concurrency());
    return (logical >= 4 && logical % 2 == 0) ? logical / 2 : logical;
}

unsigned PresetThreadCount(int preset) {
    const unsigned physical = EstimatedPhysicalThreads();
    // Presets are semantic capacity profiles.  They are evaluated on the
    // machine running the app, so the same choice behaves consistently on a
    // laptop, workstation, or server without embedding one developer PC's
    // worker counts in the interface.
    if (preset == 0) return std::max(1u, (physical + 3u) / 4u);
    if (preset == 2) return physical;
    return std::max(1u, (physical * 3u + 3u) / 4u);
}

const wchar_t* PresetCapacityLabel(int preset) {
    if (preset == 0) return L"Eco · 25%";
    if (preset == 2) return L"Maximum · 100%";
    return L"Balanced · 75%";
}

uint64_t DirectorySizeBounded(const std::filesystem::path& root) {
    std::error_code ec;
    if (!std::filesystem::exists(root, ec)) return 0;
    uint64_t total = 0;
    size_t visited = 0;
    std::filesystem::recursive_directory_iterator it(
        root, std::filesystem::directory_options::skip_permission_denied, ec);
    const std::filesystem::recursive_directory_iterator end;
    for (; !ec && it != end && visited < 250000; it.increment(ec), ++visited) {
        if (!it->is_regular_file(ec)) {
            ec.clear();
            continue;
        }
        const uint64_t size = it->file_size(ec);
        if (!ec && total <= std::numeric_limits<uint64_t>::max() - size)
            total += size;
        ec.clear();
    }
    return total;
}

std::wstring MiningStateLabel(const std::string& state) {
    if (state == "hashing") return L"Hashing";
    if (state == "synchronizing") return L"Synchronizing";
    if (state == "waiting-for-anchor") return L"Waiting for anchor";
    if (state == "work-admission") return L"Checking peer work";
    if (state == "clock-drift") return L"Clock correction needed";
    if (state == "genesis-mismatch") return L"Genesis mismatch";
    if (state == "waiting-for-peer-tip") return L"Waiting for fresh peer tips";
    if (state == "below-peer-floor") return L"Waiting for peers";
    if (state == "propagation") return L"Waiting for block relay";
    if (state == "reorg-rebuild") return L"Rebuilding chain state";
    if (state == "error") return L"Mining error";
    return L"Stopped";
}

std::wstring MiningStateDetail(const std::string& state) {
    if (state == "hashing") return L"VeldHash workers are advancing live work.";
    if (state == "synchronizing") return L"Mining starts after the local chain is fully validated.";
    if (state == "waiting-for-anchor") return L"No configured network anchor is currently connected.";
    if (state == "clock-drift") return L"Local time differs too far from the anchor median.";
    if (state == "genesis-mismatch") return L"Connected peers do not match this build's genesis.";
    if (state == "waiting-for-peer-tip") return L"Fresh canonical peer-tip confirmation is required.";
    if (state == "below-peer-floor") return L"The configured peer floor is not currently satisfied.";
    if (state == "propagation") return L"Mining is paused until the current tip is acknowledged.";
    if (state == "reorg-rebuild") return L"Derived chain state is being rebuilt safely.";
    if (state == "error") return L"Review Logs for the node-reported mining error.";
    if (state == "work-admission") return L"The node is waiting for safe canonical work admission.";
    return L"CPU mining is disabled for this node role.";
}

std::wstring FormatVeld(double value) {
    std::wostringstream out;
    out << std::fixed << std::setprecision(2) << value << L" VELD";
    return out.str();
}

std::wstring FormatVeldNumber(double value) {
    std::wostringstream out;
    out << std::fixed << std::setprecision(2) << value;
    return out.str();
}

bool CopyWideText(HWND owner, const std::wstring& value) {
    if (value.empty() || !OpenClipboard(owner)) return false;
    EmptyClipboard();
    const SIZE_T bytes = (value.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!memory) {
        CloseClipboard();
        return false;
    }
    void* target = GlobalLock(memory);
    if (!target) {
        GlobalFree(memory);
        CloseClipboard();
        return false;
    }
    memcpy(target, value.c_str(), bytes);
    GlobalUnlock(memory);
    if (!SetClipboardData(CF_UNICODETEXT, memory)) {
        GlobalFree(memory);
        CloseClipboard();
        return false;
    }
    CloseClipboard();
    return true;
}

std::filesystem::path ModulePath() {
    std::wstring buffer(32768, L'\0');
    DWORD size = GetModuleFileNameW(nullptr, buffer.data(),
                                    static_cast<DWORD>(buffer.size()));
    if (size == 0 || size >= buffer.size()) return {};
    buffer.resize(size);
    return std::filesystem::path(buffer);
}

bool ReadBoundedRegularFile(const std::filesystem::path& path,
                            uint64_t max_size,
                            std::vector<uint8_t>& bytes) {
    bytes.clear();
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN |
            FILE_FLAG_OPEN_REPARSE_POINT,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    FILE_ATTRIBUTE_TAG_INFO tag{};
    LARGE_INTEGER size{};
    if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag,
            sizeof(tag)) ||
        (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY |
                               FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        static_cast<uint64_t>(size.QuadPart) > max_size ||
        static_cast<uint64_t>(size.QuadPart) >
            static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        CloseHandle(file);
        return false;
    }
    bytes.resize(static_cast<size_t>(size.QuadPart));
    size_t offset = 0;
    while (offset < bytes.size()) {
        const size_t remaining = bytes.size() - offset;
        const DWORD request = static_cast<DWORD>(std::min<size_t>(
            remaining, std::numeric_limits<DWORD>::max()));
        DWORD count = 0;
        if (!ReadFile(file, bytes.data() + offset, request, &count, nullptr) ||
            count == 0) {
            CloseHandle(file);
            bytes.clear();
            return false;
        }
        offset += count;
    }
    BYTE extra = 0;
    DWORD extra_count = 0;
    const bool exact = ReadFile(file, &extra, 1, &extra_count, nullptr) &&
        extra_count == 0;
    CloseHandle(file);
    if (!exact) bytes.clear();
    return exact;
}

bool IsSafePackageRelativePath(const std::string& path) {
    if (path.empty() || path.size() > 240 || path.front() == '/' ||
        path.back() == '/' || path.find("//") != std::string::npos)
        return false;
    size_t segment_start = 0;
    for (size_t i = 0; i <= path.size(); ++i) {
        if (i != path.size() && path[i] != '/') {
            const unsigned char value = static_cast<unsigned char>(path[i]);
            if (value < 0x20 || value > 0x7e || path[i] == '\\' ||
                path[i] == ':' || path[i] == '*' || path[i] == '?' ||
                path[i] == '"' || path[i] == '<' || path[i] == '>' ||
                path[i] == '|')
                return false;
            continue;
        }
        const std::string segment = path.substr(segment_start,
            i - segment_start);
        if (segment.empty() || segment == "." || segment == ".." ||
            segment.back() == '.' || segment.back() == ' ')
            return false;
        segment_start = i + 1;
    }
    return true;
}

std::string LowerAscii(std::string value) {
    for (char& c : value) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return value;
}

bool VerifySignedPackage(const std::filesystem::path& module,
                         std::wstring& error) {
    error = L"The signed Veld package could not be verified.";
    if (module.empty()) return false;
    const bool launched_from_bin =
        LowerAscii(module.parent_path().filename().string()) == "bin";
    const std::filesystem::path root = launched_from_bin
        ? module.parent_path().parent_path() : module.parent_path();
    const std::filesystem::path manifest_path = root / L"SHA256SUMS.txt";
    const std::filesystem::path signature_path =
        root / L"SHA256SUMS.txt.sig";
    std::vector<uint8_t> manifest, signature;
    if (!ReadBoundedRegularFile(manifest_path, 1024 * 1024, manifest) ||
        !ReadBoundedRegularFile(signature_path, 16 * 1024, signature) ||
        !veld::VerifyReleaseSignaturePinned(manifest, signature)) {
        error = L"The pinned release signature is missing or invalid.";
        return false;
    }
    const std::string text(manifest.begin(), manifest.end());
    if (text.empty() || text.back() != '\n' ||
        text.find('\r') != std::string::npos ||
        text.find('\0') != std::string::npos) {
        error = L"The signed package manifest is malformed.";
        return false;
    }
    std::istringstream input(text);
    std::vector<std::string> lines;
    for (std::string line; std::getline(input, line);)
        lines.push_back(std::move(line));
    if (lines.size() < 3 || lines.size() > 64 ||
        lines[0] != "# veld-release-manifest-v1" ||
        lines[1] != std::string("# release-version=") +
            veld::CLIENT_VERSION) {
        error = L"The signed package version or manifest format is invalid.";
        return false;
    }

    std::unordered_set<std::string> seen;
    // The current executable is added below.  Do not require a byte-identical
    // second GUI executable in bin/: one signed launcher plus the node and
    // wallet helpers is the complete runtime layout.
    std::unordered_set<std::string> required{
        "bin/veld-node.exe", "bin/veld-wallet.exe"};
    const std::string current_relative = launched_from_bin
        ? "bin/" + module.filename().string() : module.filename().string();
    required.insert(LowerAscii(current_relative));
    for (size_t i = 2; i < lines.size(); ++i) {
        const std::string& line = lines[i];
        if (line.size() < 67 || line[64] != ' ' || line[65] != '*' ||
            line.substr(0, 64).find_first_not_of("0123456789abcdef") !=
                std::string::npos) {
            error = L"The signed package manifest contains an invalid entry.";
            return false;
        }
        const std::string relative = line.substr(66);
        const std::string folded = LowerAscii(relative);
        if (!IsSafePackageRelativePath(relative) || !seen.insert(folded).second) {
            error = L"The signed package manifest contains an unsafe path.";
            return false;
        }
        const std::filesystem::path file_path =
            root / std::filesystem::path(Utf8ToWide(relative));
        HANDLE verified = OpenVerifiedTrustedFile(file_path,
                                                   line.substr(0, 64));
        if (verified == INVALID_HANDLE_VALUE) {
            error = L"A signed package file is missing or has been modified.";
            return false;
        }
        CloseHandle(verified);
        required.erase(folded);
    }
    if (!required.empty()) {
        error = L"The signed package omits a required Veld executable.";
        return false;
    }
    return true;
}

std::filesystem::path GuiStateDirectory() {
    const DWORD required = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0);
    if (required > 1 && required < 32768) {
        std::wstring raw(static_cast<size_t>(required), L'\0');
        const DWORD written = GetEnvironmentVariableW(
            L"LOCALAPPDATA", raw.data(), required);
        if (written > 0 && written < required) {
            raw.resize(written);
            return std::filesystem::path(raw) / L"Veld" / L"Node";
        }
    }
    return ModulePath().parent_path() / L"gui-state";
}

struct PassphrasePrompt {
    std::wstring title;
    std::wstring prompt;
    std::wstring value;
    HBRUSH background{nullptr};
    HBRUSH field_background{nullptr};
    HBRUSH error_background{nullptr};
    HFONT brand_font{nullptr};
    HFONT title_font{nullptr};
    HFONT body_font{nullptr};
    HFONT label_font{nullptr};
    HFONT input_font{nullptr};
    RECT field_outline{};
    bool missing_value{false};
    bool revealed{false};
    bool field_focused{false};
};

INT_PTR CALLBACK PassphraseDialogProc(HWND dialog, UINT message,
                                      WPARAM wp, LPARAM lp) {
    auto* prompt = reinterpret_cast<PassphrasePrompt*>(
        GetWindowLongPtrW(dialog, GWLP_USERDATA));
    if (message == WM_INITDIALOG) {
        prompt = reinterpret_cast<PassphrasePrompt*>(lp);
        SetWindowLongPtrW(dialog, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(prompt));
        SetWindowTextW(dialog, prompt->title.c_str());
        const BOOL dark = TRUE;
        DwmSetWindowAttribute(dialog, static_cast<DWMWINDOWATTRIBUTE>(20),
                              &dark, sizeof(dark));
        prompt->background = CreateSolidBrush(C_PANEL);
        prompt->field_background = CreateSolidBrush(C_BG);
        prompt->error_background = CreateSolidBrush(RGB(32, 19, 20));
        prompt->brand_font = CreateFontW(-10, 0, 0, 0, FW_SEMIBOLD, FALSE,
            FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
        prompt->title_font = CreateFontW(-20, 0, 0, 0, FW_SEMIBOLD, FALSE,
            FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
        prompt->body_font = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE,
            FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        prompt->label_font = CreateFontW(-11, 0, 0, 0, FW_SEMIBOLD, FALSE,
            FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Consolas");
        prompt->input_font = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE,
            FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        SendDlgItemMessageW(dialog, IDC_VELD_PASSPHRASE_BRAND, WM_SETFONT,
                            reinterpret_cast<WPARAM>(prompt->brand_font), TRUE);
        SendDlgItemMessageW(dialog, IDC_VELD_PASSPHRASE_TITLE, WM_SETFONT,
                            reinterpret_cast<WPARAM>(prompt->title_font), TRUE);
        SendDlgItemMessageW(dialog, IDC_VELD_PASSPHRASE_PROMPT, WM_SETFONT,
                            reinterpret_cast<WPARAM>(prompt->body_font), TRUE);
        SendDlgItemMessageW(dialog, IDC_VELD_PASSPHRASE_LABEL, WM_SETFONT,
                            reinterpret_cast<WPARAM>(prompt->label_font), TRUE);
        SendDlgItemMessageW(dialog, IDC_VELD_PASSPHRASE, WM_SETFONT,
                            reinterpret_cast<WPARAM>(prompt->input_font), TRUE);
        SetDlgItemTextW(dialog, IDC_VELD_PASSPHRASE_TITLE,
                        prompt->title.c_str());
        SetDlgItemTextW(dialog, IDC_VELD_PASSPHRASE_PROMPT,
                        prompt->prompt.c_str());
        const wchar_t* action = L"Continue";
        if (prompt->title.find(L"Unlock") != std::wstring::npos ||
            prompt->title.find(L"unlock") != std::wstring::npos) {
            action = L"Unlock";
        } else if (prompt->title.find(L"Import") != std::wstring::npos ||
                   prompt->title.find(L"import") != std::wstring::npos) {
            action = L"Import";
        }
        SetDlgItemTextW(dialog, IDOK, action);
        SendDlgItemMessageW(dialog, IDC_VELD_PASSPHRASE,
                            EM_SETLIMITTEXT, 1024, 0);
        SendDlgItemMessageW(dialog, IDC_VELD_PASSPHRASE,
                            EM_SETCUEBANNER, FALSE,
                            reinterpret_cast<LPARAM>(L"Enter passphrase"));
        SendDlgItemMessageW(dialog, IDC_VELD_PASSPHRASE,
                            EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                            MAKELPARAM(11, 54));
        HWND edit = GetDlgItem(dialog, IDC_VELD_PASSPHRASE);
        GetWindowRect(edit, &prompt->field_outline);
        MapWindowPoints(HWND_DESKTOP, dialog,
                        reinterpret_cast<POINT*>(&prompt->field_outline), 2);
        const int edit_width = prompt->field_outline.right -
                               prompt->field_outline.left;
        const int edit_height = prompt->field_outline.bottom -
                                prompt->field_outline.top;
        HDC edit_dc = GetDC(edit);
        HGDIOBJ prior_edit_font = SelectObject(edit_dc, prompt->input_font);
        TEXTMETRICW input_metrics{};
        GetTextMetricsW(edit_dc, &input_metrics);
        SelectObject(edit_dc, prior_edit_font);
        ReleaseDC(edit, edit_dc);
        const int centered_height = std::min(edit_height - 4,
            static_cast<int>(input_metrics.tmHeight) + 8);
        SetWindowPos(edit, nullptr, prompt->field_outline.left,
                     prompt->field_outline.top +
                         (edit_height - centered_height) / 2,
                     edit_width, std::max(1, centered_height),
                     SWP_NOZORDER | SWP_NOACTIVATE);
        RECT edit_rect{};
        GetClientRect(edit, &edit_rect);
        SetWindowRgn(edit, CreateRoundRectRgn(
            edit_rect.left, edit_rect.top, edit_rect.right + 1,
            edit_rect.bottom + 1, 12, 12), TRUE);
        SendMessageW(dialog, DM_SETDEFID, IDOK, 0);
        RECT window{};
        GetWindowRect(dialog, &window);
        SetWindowRgn(dialog, CreateRoundRectRgn(0, 0,
            window.right - window.left + 1, window.bottom - window.top + 1,
            18, 18), TRUE);
        HWND owner = GetWindow(dialog, GW_OWNER);
        RECT owner_rect{};
        if (owner && GetWindowRect(owner, &owner_rect)) {
            const int width = window.right - window.left;
            const int height = window.bottom - window.top;
            SetWindowPos(dialog, nullptr,
                owner_rect.left + (owner_rect.right - owner_rect.left - width) / 2,
                owner_rect.top + (owner_rect.bottom - owner_rect.top - height) / 2,
                0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
        SetFocus(GetDlgItem(dialog, IDC_VELD_PASSPHRASE));
        return FALSE;
    }
    if (message == WM_CTLCOLORDLG && prompt && prompt->background)
        return reinterpret_cast<INT_PTR>(prompt->background);
    if (message == WM_ERASEBKGND && prompt && prompt->background) {
        RECT client{};
        GetClientRect(dialog, &client);
        FillRect(reinterpret_cast<HDC>(wp), &client, prompt->background);
        return TRUE;
    }
    if (message == WM_CTLCOLORSTATIC && prompt && prompt->background) {
        HDC dc = reinterpret_cast<HDC>(wp);
        const int id = GetDlgCtrlID(reinterpret_cast<HWND>(lp));
        SetTextColor(dc, id == IDC_VELD_PASSPHRASE_TITLE ? C_TEXT :
                         (id == IDC_VELD_PASSPHRASE_BRAND ? C_MUTED :
                         (id == IDC_VELD_PASSPHRASE_LABEL
                            ? (prompt->missing_value ? RGB(231, 126, 126) : C_MUTED)
                            : C_SUBTEXT)));
        SetBkMode(dc, TRANSPARENT);
        return reinterpret_cast<INT_PTR>(prompt->background);
    }
    if (message == WM_CTLCOLOREDIT && prompt && prompt->field_background) {
        HDC dc = reinterpret_cast<HDC>(wp);
        SetTextColor(dc, C_TEXT);
        SetBkColor(dc, prompt->missing_value ? RGB(32, 19, 20) : C_BG);
        return reinterpret_cast<INT_PTR>(prompt->missing_value
            ? prompt->error_background : prompt->field_background);
    }
    if (message == WM_PAINT && prompt) {
        PAINTSTRUCT paint{};
        HDC dc = BeginPaint(dialog, &paint);
        RECT client{};
        GetClientRect(dialog, &client);
        FillRect(dc, &client, prompt->background);

        HPEN outer_pen = CreatePen(PS_SOLID, 1, RGB(62, 70, 65));
        HGDIOBJ old_pen = SelectObject(dc, outer_pen);
        HGDIOBJ old_brush = SelectObject(dc, GetStockObject(NULL_BRUSH));
        RoundRect(dc, client.left, client.top, client.right - 1,
                  client.bottom - 1, 18, 18);

        RECT field = prompt->field_outline;
        HBRUSH field_brush = prompt->missing_value
            ? prompt->error_background : prompt->field_background;
        HGDIOBJ prior_brush = SelectObject(dc, field_brush);
        HPEN field_pen = CreatePen(PS_SOLID, 1,
            prompt->missing_value ? RGB(145, 70, 73) :
            (prompt->field_focused ? RGB(100, 112, 104) : C_BORDER));
        SelectObject(dc, field_pen);
        RoundRect(dc, field.left, field.top, field.right, field.bottom, 10, 10);
        SelectObject(dc, prior_brush);

        SelectObject(dc, old_brush);
        SelectObject(dc, old_pen);
        DeleteObject(field_pen);
        DeleteObject(outer_pen);
        EndPaint(dialog, &paint);
        return TRUE;
    }
    if (message == WM_NCHITTEST) {
        const LRESULT hit = DefWindowProcW(dialog, message, wp, lp);
        return hit == HTCLIENT ? HTCAPTION : hit;
    }
    if (message == WM_DRAWITEM) {
        auto* item = reinterpret_cast<DRAWITEMSTRUCT*>(lp);
        if (item && (item->CtlID == IDOK || item->CtlID == IDCANCEL ||
                     item->CtlID == IDC_VELD_PASSPHRASE_REVEAL)) {
            const bool primary = item->CtlID == IDOK;
            const bool reveal = item->CtlID == IDC_VELD_PASSPHRASE_REVEAL;
            const bool pressed = (item->itemState & ODS_SELECTED) != 0;
            const COLORREF fill_color = reveal
                ? C_BG
                : primary
                ? (pressed ? RGB(66, 75, 69) : RGB(48, 56, 51))
                : (pressed ? RGB(38, 43, 40) : RGB(28, 33, 30));
            FillRect(item->hDC, &item->rcItem,
                     prompt && prompt->background
                         ? prompt->background
                         : reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
            HBRUSH fill = CreateSolidBrush(fill_color);
            HPEN border = CreatePen(PS_SOLID, 1,
                reveal ? C_BG : (primary ? RGB(91, 104, 95) : C_BORDER));
            HGDIOBJ old_fill = SelectObject(item->hDC, fill);
            HGDIOBJ old_pen = SelectObject(item->hDC, border);
            RoundRect(item->hDC, item->rcItem.left, item->rcItem.top,
                      item->rcItem.right, item->rcItem.bottom, 9, 9);
            SelectObject(item->hDC, old_fill);
            SelectObject(item->hDC, old_pen);
            DeleteObject(fill);
            DeleteObject(border);
            wchar_t label[64]{};
            GetWindowTextW(item->hwndItem, label, 64);
            SetBkMode(item->hDC, TRANSPARENT);
            SetTextColor(item->hDC, primary ? C_TEXT :
                         (reveal ? C_MUTED : C_SUBTEXT));
            HFONT font = prompt && prompt->body_font
                ? prompt->body_font : reinterpret_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
            HGDIOBJ old_font = SelectObject(item->hDC, font);
            RECT text = item->rcItem;
            DrawTextW(item->hDC, label, -1, &text,
                      DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(item->hDC, old_font);
            if ((item->itemState & ODS_FOCUS) && !reveal) {
                RECT focus = item->rcItem;
                InflateRect(&focus, -4, -4);
                DrawFocusRect(item->hDC, &focus);
            }
            return TRUE;
        }
    }
    if (message == WM_COMMAND && LOWORD(wp) == IDC_VELD_PASSPHRASE_REVEAL &&
        HIWORD(wp) == BN_CLICKED && prompt) {
        prompt->revealed = !prompt->revealed;
        HWND edit = GetDlgItem(dialog, IDC_VELD_PASSPHRASE);
        SendMessageW(edit, EM_SETPASSWORDCHAR,
                     prompt->revealed ? 0 : 0x25CF, 0);
        SetDlgItemTextW(dialog, IDC_VELD_PASSPHRASE_REVEAL,
                        prompt->revealed ? L"Hide" : L"Show");
        InvalidateRect(edit, nullptr, TRUE);
        InvalidateRect(GetDlgItem(dialog, IDC_VELD_PASSPHRASE_REVEAL),
                       nullptr, TRUE);
        SetFocus(edit);
        return TRUE;
    }
    if (message == WM_COMMAND && LOWORD(wp) == IDOK) {
        const int size = GetWindowTextLengthW(
            GetDlgItem(dialog, IDC_VELD_PASSPHRASE));
        if (!prompt || size <= 0 || size > 1024) {
            if (prompt) {
                prompt->missing_value = true;
                SetDlgItemTextW(dialog, IDC_VELD_PASSPHRASE_LABEL,
                                L"PASSPHRASE REQUIRED");
                RedrawWindow(dialog, nullptr, nullptr,
                             RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
            }
            SetFocus(GetDlgItem(dialog, IDC_VELD_PASSPHRASE));
            return TRUE;
        }
        prompt->value.assign(static_cast<size_t>(size) + 1, L'\0');
        GetDlgItemTextW(dialog, IDC_VELD_PASSPHRASE,
                        prompt->value.data(), size + 1);
        prompt->value.resize(static_cast<size_t>(size));
        EndDialog(dialog, IDOK);
        return TRUE;
    }
    if (message == WM_COMMAND && LOWORD(wp) == IDC_VELD_PASSPHRASE && prompt) {
        if (HIWORD(wp) == EN_SETFOCUS || HIWORD(wp) == EN_KILLFOCUS) {
            prompt->field_focused = HIWORD(wp) == EN_SETFOCUS;
            InvalidateRect(dialog, nullptr, FALSE);
            return FALSE;
        }
        if (HIWORD(wp) == EN_CHANGE && prompt->missing_value) {
            prompt->missing_value = false;
            SetDlgItemTextW(dialog, IDC_VELD_PASSPHRASE_LABEL, L"PASSPHRASE");
            RedrawWindow(dialog, nullptr, nullptr,
                         RDW_INVALIDATE | RDW_UPDATENOW | RDW_ALLCHILDREN);
            return TRUE;
        }
    }
    if ((message == WM_COMMAND && LOWORD(wp) == IDCANCEL)
        || message == WM_CLOSE) {
        EndDialog(dialog, IDCANCEL);
        return TRUE;
    }
    if (message == WM_DESTROY && prompt) {
        if (prompt->background) DeleteObject(prompt->background);
        if (prompt->field_background) DeleteObject(prompt->field_background);
        if (prompt->error_background) DeleteObject(prompt->error_background);
        for (HFONT font : {prompt->brand_font, prompt->title_font, prompt->body_font,
                           prompt->label_font, prompt->input_font}) {
            if (font) DeleteObject(font);
        }
        prompt->background = prompt->field_background =
            prompt->error_background = nullptr;
        prompt->brand_font = prompt->title_font = prompt->body_font = prompt->label_font =
            prompt->input_font = nullptr;
    }
    return FALSE;
}

DWORD FindNodeProcess() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    DWORD pid = 0;
    if (Process32FirstW(snap, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, L"veld-node.exe") == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return pid;
}

uint64_t ProcessUptime(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return 0;
    FILETIME created{}, exited{}, kernel{}, user{};
    uint64_t result = 0;
    if (GetProcessTimes(process, &created, &exited, &kernel, &user)) {
        FILETIME now_ft{};
        GetSystemTimeAsFileTime(&now_ft);
        ULARGE_INTEGER start{}, now{};
        start.LowPart = created.dwLowDateTime;
        start.HighPart = created.dwHighDateTime;
        now.LowPart = now_ft.dwLowDateTime;
        now.HighPart = now_ft.dwHighDateTime;
        if (now.QuadPart >= start.QuadPart)
            result = (now.QuadPart - start.QuadPart) / 10000000ULL;
    }
    CloseHandle(process);
    return result;
}

bool SendCtrlBreak(DWORD pid) {
    FreeConsole();
    if (!AttachConsole(pid)) return false;
    SetConsoleCtrlHandler(nullptr, TRUE);
    const BOOL sent = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid);
    Sleep(100);
    FreeConsole();
    SetConsoleCtrlHandler(nullptr, FALSE);
    return sent == TRUE;
}

bool RequestGuiNodeShutdown(DWORD pid) {
    if (pid == 0) return true;
    const std::wstring name = L"Local\\VeldNodeShutdown-" +
        std::to_wstring(pid);
    HANDLE event = OpenEventW(EVENT_MODIFY_STATE, FALSE, name.c_str());
    if (event) {
        const bool signaled = SetEvent(event) == TRUE;
        CloseHandle(event);
        if (signaled) return true;
    }
    // Compatibility path for older nodes that were launched with a console.
    return SendCtrlBreak(pid);
}

enum class Page {
    Overview, Blockchain, Mining, Workers, Explorer, Network, Logs, Settings
};

enum class UpdateOperation {
    None, Check, Install
};

struct LiveState {
    bool process_running{false};
    bool local_online{false};
    bool reference_online{false};
    bool snapshot_eligible{false};
    DWORD pid{0};
    uint64_t uptime_seconds{0};
    uint64_t chain_bytes{0};
    veld::node_gui::ChainStats local;
    veld::node_gui::ChainStats reference;
    bool mining_status_online{false};
    veld::node_gui::MiningStats mining;
    std::vector<veld::node_gui::BlockSummary> recent_blocks;
    bool peer_details_online{false};
    std::vector<veld::node_gui::PeerSummary> peer_details;
    bool topology_online{false};
    uint64_t local_topology_id{0};
    veld::node_gui::TopologySnapshot topology;
    uint64_t known_peer_count{0};
    uint64_t inbound_peers{0};
    uint64_t outbound_peers{0};
    uint64_t exact_tip_peers{0};
    bool port_mapped{false};
    uint64_t peer_bytes_sent{0};
    uint64_t peer_bytes_recv{0};
    double peer_send_rate{0.0};
    double peer_recv_rate{0.0};
    struct NetworkEvent {
        uint64_t timestamp{0};
        std::wstring text;
        bool warning{false};
    };
    std::vector<NetworkEvent> network_events;
    std::wstring local_error;
    std::vector<std::wstring> log_lines;
};

struct HeightPoint {
    std::chrono::steady_clock::time_point at;
    uint64_t height{0};
};

struct RatePoint {
    std::chrono::steady_clock::time_point at;
    double rate{0.0};
};

struct RemoteMonitorStatus {
    bool credential_ready{false};
    bool paired{false};
    bool report_ok{false};
    std::wstring pair_code;
    std::wstring detail{L"Disabled. No health data leaves this machine."};
    uint64_t pair_expires{0};
    uint64_t last_report{0};
};

class NodeGuiApp {
public:
    explicit NodeGuiApp(HINSTANCE instance) : instance_(instance) {
        const auto module = ModulePath();
        const auto packaged_node = module.parent_path() / L"bin" /
            L"veld-node.exe";
        node_path_ = std::filesystem::is_regular_file(packaged_node)
            ? packaged_node : module.parent_path() / L"veld-node.exe";
        const auto packaged_wallet = module.parent_path() / L"bin" /
            L"veld-wallet.exe";
        wallet_path_ = std::filesystem::is_regular_file(packaged_wallet)
            ? packaged_wallet : module.parent_path() / L"veld-wallet.exe";
        state_dir_ = GuiStateDirectory();
        if (module.parent_path().filename() == L"bin")
            data_dir_ = module.parent_path().parent_path() / L"veld-data";
        else
            data_dir_ = module.parent_path() / L"veld-data";
        ParseArguments();
        std::error_code state_error;
        std::filesystem::create_directories(state_dir_, state_error);
        (void)LoadPortalTrust(state_dir_ / L"remote-trust.dat", remote_trust_);
        LoadSettings();
        // Prefer authenticated snapshot bootstrap on a new installation. The
        // node itself keeps every service quarantined until an independent
        // genesis IBD matches the imported tip and complete state digest.
        // Keep an explicit choice already loaded from local settings.
        if (!sync_choice_explicit_) {
            full_ibd_choice_ = false;
            sync_choice_explicit_ = true;
        }
    }

    ~NodeGuiApp() {
        stop_worker_.store(true);
        worker_cv_.notify_all();
        if (worker_.joinable()) worker_.join();
        ClearSessionPassphrase();
        if (owned_process_) CloseHandle(owned_process_);
        if (wallet_process_) {
            if (WaitForSingleObject(wallet_process_, 0) == WAIT_TIMEOUT) {
                TerminateProcess(wallet_process_, ERROR_CANCELLED);
                WaitForSingleObject(wallet_process_, 2000);
            }
            CloseHandle(wallet_process_);
        }
        if (!wallet_signer_token_.empty()) {
            SecureZeroMemory(wallet_signer_token_.data(),
                             wallet_signer_token_.size());
            wallet_signer_token_.clear();
        }
        {
            std::lock_guard<std::mutex> lock(tor_process_mutex_);
            if (tor_setup_process_) CloseHandle(tor_setup_process_);
        }
        {
            std::lock_guard<std::mutex> lock(update_process_mutex_);
            if (update_process_) CloseHandle(update_process_);
        }
        DestroyFonts();
    }

    int Run(int show) {
        EnableDpiAwareness();
        NormalizeSavedWindowBounds();
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
        wc.lpfnWndProc = &NodeGuiApp::WndProcThunk;
        wc.hInstance = instance_;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(IDI_VELD_NODE));
        if (!wc.hIcon) wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
        wc.hIconSm = wc.hIcon;
        wc.hbrBackground = nullptr;
        wc.lpszClassName = L"VeldNodeGuiWindow";
        if (!RegisterClassExW(&wc)) return 2;

        RECT desired{0, 0, 1440, 900};
        AdjustWindowRectEx(&desired, WS_OVERLAPPEDWINDOW, FALSE, 0);
        hwnd_ = CreateWindowExW(
            0, wc.lpszClassName, L"Veld Node",
            WS_OVERLAPPEDWINDOW | WS_VSCROLL,
            window_x_, window_y_, window_width_ > 0 ? window_width_ :
                desired.right - desired.left,
            window_height_ > 0 ? window_height_ : desired.bottom - desired.top,
            nullptr, nullptr, instance_, this);
        if (!hwnd_) return 2;
        ShowWindow(hwnd_, window_maximized_ ? SW_SHOWMAXIMIZED : show);
        UpdateWindow(hwnd_);
        worker_ = std::thread([this] { PollLoop(); });

        MSG msg{};
        while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        return static_cast<int>(msg.wParam);
    }

private:
    HINSTANCE instance_{nullptr};
    HWND hwnd_{nullptr};
    UINT dpi_{96};
    Page page_{Page::Overview};
    std::array<int, 8> page_scroll_offsets_{};
    std::filesystem::path node_path_;
    std::filesystem::path wallet_path_;
    std::filesystem::path data_dir_;
    std::filesystem::path state_dir_;
    std::atomic<bool> stop_worker_{false};
    std::condition_variable worker_cv_;
    std::mutex worker_wait_mutex_;
    std::thread worker_;
    std::mutex state_mutex_;
    LiveState state_;
    std::deque<HeightPoint> history_;
    std::deque<RatePoint> rate_history_;
    std::atomic<DWORD> owned_pid_{0};
    HANDLE owned_process_{nullptr};
    HANDLE wallet_process_{nullptr};
    std::string wallet_signer_token_;
    std::atomic<bool> stopping_node_{false};
    std::atomic<bool> session_unlock_confirmed_{false};
    std::mutex session_passphrase_mutex_;
    std::vector<BYTE> protected_session_passphrase_;
    size_t protected_session_passphrase_chars_{0};
    std::mutex tor_process_mutex_;
    HANDLE tor_setup_process_{nullptr};
    std::atomic<bool> tor_preparing_{false};
    std::mutex update_process_mutex_;
    HANDLE update_process_{nullptr};
    std::atomic<UpdateOperation> update_operation_{UpdateOperation::None};
    bool update_available_{false};
    std::wstring update_status_{L"Not checked"};
    COLORREF update_status_color_{C_MUTED};
    std::atomic<bool> full_ibd_choice_{true};
    bool sync_choice_explicit_{false};
    std::atomic<bool> mining_enabled_{true};
    std::atomic<bool> reachable_choice_{true};
    std::atomic<bool> tor_choice_{false};
    uint32_t topology_role_index_{0};
    int mining_preset_{1};
    std::atomic<unsigned> mining_thread_count_{PresetThreadCount(1)};
    int chain_range_minutes_{15};
    int rate_range_minutes_{15};
    int window_x_{CW_USEDEFAULT};
    int window_y_{CW_USEDEFAULT};
    int window_width_{0};
    int window_height_{0};
    bool window_maximized_{false};
    bool tray_added_{false};
    bool tracking_mouse_leave_{false};
    POINT hover_point_{-1, -1};
    std::chrono::steady_clock::time_point diagnostics_copied_until_{};
    std::atomic<bool> reference_display_enabled_{true};
    std::atomic<bool> remote_monitoring_enabled_{false};
    std::mutex remote_monitor_mutex_;
    RemoteMonitorStatus remote_monitor_status_;
    std::mutex remote_command_mutex_;
    MonitoringReply::Command pending_remote_command_;
    bool remote_command_pending_{false};
    bool remote_command_active_{false};
    uint64_t last_remote_command_id_{0};
    std::mutex remote_trust_mutex_;
    PortalTrustState remote_trust_;
    std::mutex remote_ack_mutex_;
    uint64_t remote_ack_id_{0};
    std::string remote_ack_status_;
    std::string remote_ack_message_;
    RECT overview_nav_{};
    RECT blockchain_nav_{};
    RECT mining_nav_{};
    RECT workers_nav_{};
    RECT explorer_nav_{};
    RECT network_nav_{};
    RECT logs_nav_{};
    RECT settings_nav_{};
    RECT action_button_{};
    RECT follow_x_link_{};
    RECT full_ibd_card_{};
    RECT snapshot_card_{};
    RECT open_log_button_{};
    RECT reachable_toggle_{};
    RECT tor_toggle_{};
    RECT reference_toggle_{};
    RECT remote_monitor_toggle_{};
    RECT open_monitor_portal_button_{};
    RECT copy_monitor_code_button_{};
    RECT mining_mode_toggle_{};
    RECT open_data_button_{};
    RECT import_key_button_{};
    RECT create_key_button_{};
    RECT open_wallet_button_{};
    RECT open_explorer_button_{};
    RECT copy_diagnostics_button_{};
    RECT preset_eco_button_{};
    RECT preset_balanced_button_{};
    RECT preset_max_button_{};
    RECT preset_minus_button_{};
    RECT preset_plus_button_{};
    RECT check_update_button_{};
    RECT view_changelog_button_{};
    RECT chain_range_buttons_[3]{};
    RECT rate_range_buttons_[3]{};
    RECT chain_plot_rect_{};
    RECT rate_plot_rect_{};
    RECT network_graph_rect_{};
    std::vector<RECT> network_peer_rects_;
    std::vector<size_t> network_peer_indices_;
    std::vector<RECT> network_topology_rects_;
    std::vector<size_t> network_topology_indices_;

    HFONT font_brand_{nullptr};
    HFONT font_title_{nullptr};
    HFONT font_heading_{nullptr};
    HFONT font_body_{nullptr};
    HFONT font_small_{nullptr};
    HFONT font_number_{nullptr};
    HFONT font_log_{nullptr};

    int S(int value) const {
        return MulDiv(value, static_cast<int>(dpi_), 96);
    }

    size_t PageIndex() const {
        return static_cast<size_t>(page_);
    }

    int PageContentHeight(const RECT& client) const {
        const int minimum = page_ == Page::Settings ? S(930) : S(900);
        return std::max(static_cast<int>(client.bottom), minimum);
    }

    int MaxPageScroll(const RECT& client) const {
        return std::max(0, PageContentHeight(client) -
                           static_cast<int>(client.bottom));
    }

    int CurrentPageScroll(const RECT& client) {
        int& offset = page_scroll_offsets_[PageIndex()];
        offset = std::clamp(offset, 0, MaxPageScroll(client));
        return offset;
    }

    POINT ContentPoint(POINT point) {
        RECT client{};
        GetClientRect(hwnd_, &client);
        if (point.x >= S(252)) point.y += CurrentPageScroll(client);
        return point;
    }

    void SetPageScroll(int requested) {
        RECT client{};
        GetClientRect(hwnd_, &client);
        page_scroll_offsets_[PageIndex()] =
            std::clamp(requested, 0, MaxPageScroll(client));
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    void UpdatePageScrollBar(const RECT& client) {
        const int offset = CurrentPageScroll(client);
        SCROLLINFO info{};
        info.cbSize = sizeof(info);
        info.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
        info.nMin = 0;
        info.nMax = PageContentHeight(client) - 1;
        info.nPage = static_cast<UINT>(std::max<LONG>(1, client.bottom));
        info.nPos = offset;
        SetScrollInfo(hwnd_, SB_VERT, &info, TRUE);
        ShowScrollBar(hwnd_, SB_VERT, MaxPageScroll(client) > 0);
    }

    size_t NetworkHoverTarget(POINT point) const {
        for (size_t i = 0; i < network_peer_rects_.size(); ++i) {
            if (PtInRect(&network_peer_rects_[i], point)) return i + 1;
        }
        for (size_t i = 0; i < network_topology_rects_.size(); ++i) {
            if (PtInRect(&network_topology_rects_[i], point)) return i + 1;
        }
        return 0;
    }

    RECT NetworkTooltipRect(const RECT& anchor, int width, int height) const {
        RECT bounds = network_graph_rect_;
        InflateRect(&bounds, -S(8), -S(8));
        const int gap = S(12);
        int left = anchor.right + gap;
        if (left + width > bounds.right)
            left = anchor.left - gap - width;
        const int bounds_left = static_cast<int>(bounds.left);
        const int bounds_right = static_cast<int>(bounds.right);
        const int bounds_top = static_cast<int>(bounds.top);
        const int bounds_bottom = static_cast<int>(bounds.bottom);
        left = std::clamp(left, bounds_left,
                          std::max(bounds_left, bounds_right - width));
        int top = anchor.top +
            ((anchor.bottom - anchor.top) - height) / 2;
        top = std::clamp(top, bounds_top,
                         std::max(bounds_top, bounds_bottom - height));
        return RECT{left, top, left + width, top + height};
    }

    bool IsInteractivePoint(POINT point) {
        const RECT* sidebar_controls[] = {
            &overview_nav_, &blockchain_nav_, &mining_nav_, &workers_nav_,
            &explorer_nav_, &network_nav_, &logs_nav_,
            &settings_nav_, &follow_x_link_
        };
        for (const RECT* control : sidebar_controls) {
            if (control && PtInRect(control, point)) return true;
        }
        point = ContentPoint(point);
        if (PtInRect(&action_button_, point)) return true;
        auto inside_any = [&](std::initializer_list<const RECT*> controls) {
            for (const RECT* control : controls)
                if (control && PtInRect(control, point)) return true;
            return false;
        };
        if (page_ == Page::Overview) {
            for (const RECT& button : chain_range_buttons_)
                if (PtInRect(&button, point)) return true;
        } else if (page_ == Page::Blockchain) {
            if (inside_any({&full_ibd_card_, &snapshot_card_})) return true;
        } else if (page_ == Page::Mining) {
            for (const RECT& button : rate_range_buttons_)
                if (PtInRect(&button, point)) return true;
        } else if (page_ == Page::Explorer) {
            if (inside_any({&open_explorer_button_, &open_wallet_button_}))
                return true;
        } else if (page_ == Page::Logs) {
            if (inside_any({&copy_diagnostics_button_, &open_log_button_}))
                return true;
        } else if (page_ == Page::Settings) {
            if (inside_any({&reachable_toggle_, &tor_toggle_,
                    &reference_toggle_, &remote_monitor_toggle_,
                    &open_monitor_portal_button_,
                    &copy_monitor_code_button_, &mining_mode_toggle_,
                    &open_data_button_, &import_key_button_,
                    &create_key_button_, &preset_eco_button_,
                    &preset_balanced_button_, &preset_max_button_,
                    &preset_minus_button_, &preset_plus_button_,
                    &check_update_button_, &view_changelog_button_}))
                return true;
        }
        return false;
    }

    void ApplyDarkFrame() {
        const BOOL enabled = TRUE;
        const COLORREF caption = C_BG;
        const COLORREF border = C_BORDER_SOFT;
        const COLORREF text = C_TEXT;
        DwmSetWindowAttribute(hwnd_, static_cast<DWMWINDOWATTRIBUTE>(20),
                              &enabled, sizeof(enabled));
        DwmSetWindowAttribute(hwnd_, static_cast<DWMWINDOWATTRIBUTE>(35),
                              &caption, sizeof(caption));
        DwmSetWindowAttribute(hwnd_, static_cast<DWMWINDOWATTRIBUTE>(34),
                              &border, sizeof(border));
        DwmSetWindowAttribute(hwnd_, static_cast<DWMWINDOWATTRIBUTE>(36),
                              &text, sizeof(text));
    }

    void NormalizeSavedWindowBounds() {
        if (window_x_ == CW_USEDEFAULT || window_y_ == CW_USEDEFAULT) return;
        RECT desired{window_x_, window_y_, window_x_ + window_width_,
                     window_y_ + window_height_};
        HMONITOR monitor = MonitorFromRect(&desired, MONITOR_DEFAULTTONEAREST);
        MONITORINFO info{};
        info.cbSize = sizeof(info);
        if (!monitor || !GetMonitorInfoW(monitor, &info)) return;
        const int max_width = info.rcWork.right - info.rcWork.left;
        const int max_height = info.rcWork.bottom - info.rcWork.top;
        window_width_ = std::min(window_width_, max_width);
        window_height_ = std::min(window_height_, max_height);
        window_x_ = std::clamp<int>(window_x_, info.rcWork.left,
                                    info.rcWork.right - window_width_);
        window_y_ = std::clamp<int>(window_y_, info.rcWork.top,
                                    info.rcWork.bottom - window_height_);
    }

    void SaveWindowPlacement() {
        if (!hwnd_) return;
        WINDOWPLACEMENT placement{};
        placement.length = sizeof(placement);
        if (!GetWindowPlacement(hwnd_, &placement)) return;
        const RECT& normal = placement.rcNormalPosition;
        if (normal.right - normal.left >= 1050 &&
            normal.bottom - normal.top >= 760) {
            window_x_ = normal.left;
            window_y_ = normal.top;
            window_width_ = normal.right - normal.left;
            window_height_ = normal.bottom - normal.top;
        }
        window_maximized_ = placement.showCmd == SW_SHOWMAXIMIZED;
        SaveSettings();
    }

    void AddTrayIcon() {
        NOTIFYICONDATAW icon{};
        icon.cbSize = sizeof(icon);
        icon.hWnd = hwnd_;
        icon.uID = 1;
        icon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        icon.uCallbackMessage = WM_TRAY_ICON;
        icon.hIcon = reinterpret_cast<HICON>(GetClassLongPtrW(hwnd_, GCLP_HICON));
        wcscpy_s(icon.szTip, L"Veld Node");
        tray_added_ = Shell_NotifyIconW(NIM_ADD, &icon) == TRUE;
        if (tray_added_) {
            icon.uVersion = NOTIFYICON_VERSION_4;
            Shell_NotifyIconW(NIM_SETVERSION, &icon);
        }
    }

    void RemoveTrayIcon() {
        if (!tray_added_) return;
        NOTIFYICONDATAW icon{};
        icon.cbSize = sizeof(icon);
        icon.hWnd = hwnd_;
        icon.uID = 1;
        Shell_NotifyIconW(NIM_DELETE, &icon);
        tray_added_ = false;
    }

    void RestoreFromTray() {
        ShowWindow(hwnd_, SW_RESTORE);
        SetForegroundWindow(hwnd_);
    }

    void ShowTrayMenu() {
        const LiveState live = SnapshotState();
        const bool stopping = stopping_node_.load() && live.process_running;
        HMENU menu = CreatePopupMenu();
        if (!menu) return;
        AppendMenuW(menu, MF_STRING, ID_TRAY_RESTORE, L"Open Veld Node");
        std::wstring status = stopping
            ? L"Status: stopping safely"
            : (live.process_running
               ? L"Status: running · block " + FormatUnsigned(live.local.height) +
                   L" · " + FormatUnsigned(live.local.peers) + L" peers"
               : L"Status: stopped");
        AppendMenuW(menu, MF_STRING | MF_DISABLED, 0, status.c_str());
        const std::wstring toggle_label = stopping ? L"Stopping..." :
            (live.process_running ? L"Stop node" :
             (mining_enabled_ ? L"Start mining" : L"Start node"));
        AppendMenuW(menu, stopping ? MF_GRAYED : MF_STRING,
                    ID_TRAY_TOGGLE_NODE, toggle_label.c_str());
        AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, L"Exit Veld Node app");
        POINT cursor{};
        GetCursorPos(&cursor);
        SetForegroundWindow(hwnd_);
        TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                       cursor.x, cursor.y, 0, hwnd_, nullptr);
        DestroyMenu(menu);
    }

    static LRESULT CALLBACK WndProcThunk(HWND hwnd, UINT msg,
                                         WPARAM wp, LPARAM lp) {
        NodeGuiApp* self = reinterpret_cast<NodeGuiApp*>(
            GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (msg == WM_NCCREATE) {
            auto* cs = reinterpret_cast<CREATESTRUCTW*>(lp);
            self = static_cast<NodeGuiApp*>(cs->lpCreateParams);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA,
                              reinterpret_cast<LONG_PTR>(self));
            self->hwnd_ = hwnd;
        }
        return self ? self->WndProc(msg, wp, lp)
                    : DefWindowProcW(hwnd, msg, wp, lp);
    }

    LRESULT WndProc(UINT msg, WPARAM wp, LPARAM lp) {
        switch (msg) {
            case WM_CREATE:
                dpi_ = GetDpiForWindow(hwnd_);
                ApplyDarkFrame();
                CreateFonts();
                AddTrayIcon();
                SetTimer(hwnd_, TIMER_REPAINT, 1000, nullptr);
                return 0;
            case WM_GETMINMAXINFO: {
                auto* info = reinterpret_cast<MINMAXINFO*>(lp);
                info->ptMinTrackSize.x = S(1050);
                info->ptMinTrackSize.y = S(640);
                return 0;
            }
            case WM_DPICHANGED: {
                dpi_ = HIWORD(wp);
                DestroyFonts();
                CreateFonts();
                const RECT* suggested = reinterpret_cast<const RECT*>(lp);
                SetWindowPos(hwnd_, nullptr, suggested->left, suggested->top,
                             suggested->right - suggested->left,
                             suggested->bottom - suggested->top,
                             SWP_NOZORDER | SWP_NOACTIVATE);
                return 0;
            }
            case WM_LBUTTONUP:
                OnClick(GET_X_LPARAM(lp), GET_Y_LPARAM(lp));
                return 0;
            case WM_MOUSEWHEEL: {
                POINT point{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
                ScreenToClient(hwnd_, &point);
                if (point.x >= S(252)) {
                    RECT client{};
                    GetClientRect(hwnd_, &client);
                    const int steps = GET_WHEEL_DELTA_WPARAM(wp) / WHEEL_DELTA;
                    SetPageScroll(CurrentPageScroll(client) - steps * S(64));
                }
                return 0;
            }
            case WM_VSCROLL: {
                RECT client{};
                GetClientRect(hwnd_, &client);
                int requested = CurrentPageScroll(client);
                switch (LOWORD(wp)) {
                    case SB_LINEUP: requested -= S(48); break;
                    case SB_LINEDOWN: requested += S(48); break;
                    case SB_PAGEUP: requested -= std::max(1L, client.bottom); break;
                    case SB_PAGEDOWN: requested += std::max(1L, client.bottom); break;
                    case SB_THUMBPOSITION:
                    case SB_THUMBTRACK: {
                        SCROLLINFO info{};
                        info.cbSize = sizeof(info);
                        info.fMask = SIF_TRACKPOS;
                        if (GetScrollInfo(hwnd_, SB_VERT, &info))
                            requested = info.nTrackPos;
                        break;
                    }
                    case SB_TOP: requested = 0; break;
                    case SB_BOTTOM: requested = MaxPageScroll(client); break;
                    default: return 0;
                }
                SetPageScroll(requested);
                return 0;
            }
            case WM_MOUSEMOVE:
            {
                const POINT next_hover{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
                if (!tracking_mouse_leave_) {
                    TRACKMOUSEEVENT tracking{};
                    tracking.cbSize = sizeof(tracking);
                    tracking.dwFlags = TME_LEAVE;
                    tracking.hwndTrack = hwnd_;
                    tracking_mouse_leave_ = TrackMouseEvent(&tracking) == TRUE;
                }
                if (next_hover.x != hover_point_.x ||
                    next_hover.y != hover_point_.y) {
                    const POINT prior_hover = hover_point_;
                    const size_t prior_network_target =
                        NetworkHoverTarget(ContentPoint(prior_hover));
                    const size_t next_network_target =
                        NetworkHoverTarget(ContentPoint(next_hover));
                    hover_point_ = next_hover;
                    if (page_ == Page::Network &&
                        (PtInRect(&network_graph_rect_,
                                  ContentPoint(prior_hover)) ||
                         PtInRect(&network_graph_rect_,
                                  ContentPoint(next_hover)))) {
                        if (prior_network_target != next_network_target)
                            InvalidateRect(hwnd_, &network_graph_rect_, FALSE);
                    } else {
                        InvalidateRect(hwnd_, nullptr, FALSE);
                    }
                }
                return 0;
            }
            case WM_MOUSELEAVE:
                tracking_mouse_leave_ = false;
                hover_point_ = POINT{-1, -1};
                if (page_ == Page::Network)
                    InvalidateRect(hwnd_, &network_graph_rect_, FALSE);
                else
                    InvalidateRect(hwnd_, nullptr, FALSE);
                return 0;
            case WM_SETCURSOR:
                if (LOWORD(lp) == HTCLIENT) {
                    POINT cursor{};
                    GetCursorPos(&cursor);
                    ScreenToClient(hwnd_, &cursor);
                    SetCursor(LoadCursorW(nullptr,
                        IsInteractivePoint(cursor) ? IDC_HAND : IDC_ARROW));
                    return TRUE;
                }
                return DefWindowProcW(hwnd_, msg, wp, lp);
            case WM_SIZE:
                if (wp == SIZE_MINIMIZED) {
                    ShowWindow(hwnd_, SW_HIDE);
                    return 0;
                }
                return 0;
            case WM_EXITSIZEMOVE:
                SaveWindowPlacement();
                return 0;
            case WM_COMMAND:
                if (LOWORD(wp) == ID_TRAY_RESTORE) RestoreFromTray();
                else if (LOWORD(wp) == ID_TRAY_TOGGLE_NODE) ToggleNode();
                else if (LOWORD(wp) == ID_TRAY_EXIT) DestroyWindow(hwnd_);
                return 0;
            case WM_TRAY_ICON:
                if (LOWORD(lp) == WM_LBUTTONDBLCLK) RestoreFromTray();
                else if (LOWORD(lp) == WM_RBUTTONUP ||
                         LOWORD(lp) == WM_CONTEXTMENU) ShowTrayMenu();
                return 0;
            case WM_KEYDOWN:
                if (wp == VK_UP || wp == VK_DOWN || wp == VK_PRIOR ||
                    wp == VK_NEXT || wp == VK_HOME || wp == VK_END) {
                    RECT client{};
                    GetClientRect(hwnd_, &client);
                    int requested = CurrentPageScroll(client);
                    if (wp == VK_UP) requested -= S(48);
                    else if (wp == VK_DOWN) requested += S(48);
                    else if (wp == VK_PRIOR) requested -= std::max(1L, client.bottom);
                    else if (wp == VK_NEXT) requested += std::max(1L, client.bottom);
                    else if (wp == VK_HOME) requested = 0;
                    else requested = MaxPageScroll(client);
                    SetPageScroll(requested);
                    return 0;
                }
                if (wp == '1') page_ = Page::Overview;
                if (wp == '2') page_ = Page::Blockchain;
                if (wp == '3') page_ = Page::Mining;
                if (wp == '4') page_ = Page::Workers;
                if (wp == '5') page_ = Page::Explorer;
                if (wp == '6') page_ = Page::Network;
                if (wp == '7') page_ = Page::Logs;
                if (wp == '8') page_ = Page::Settings;
                InvalidateRect(hwnd_, nullptr, FALSE);
                return 0;
            case WM_TIMER:
            case WM_NODE_REFRESH:
                InvalidateRect(hwnd_, nullptr, FALSE);
                return 0;
            case WM_TOR_SETUP_COMPLETE:
                OnTorSetupComplete(static_cast<DWORD>(wp));
                return 0;
            case WM_UPDATE_CHECK_COMPLETE:
                OnUpdateProcessComplete(static_cast<DWORD>(wp));
                return 0;
            case WM_REMOTE_COMMAND:
                ExecuteRemoteCommand();
                return 0;
            case WM_ERASEBKGND:
                return 1;
            case WM_PAINT:
                Paint();
                return 0;
            case WM_DESTROY:
                SaveWindowPlacement();
                RemoveTrayIcon();
                KillTimer(hwnd_, TIMER_REPAINT);
                stop_worker_.store(true);
                worker_cv_.notify_all();
                PostQuitMessage(0);
                return 0;
            default:
                return DefWindowProcW(hwnd_, msg, wp, lp);
        }
    }

    void EnableDpiAwareness() {
        using Fn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
        auto* user32 = GetModuleHandleW(L"user32.dll");
        auto fn = reinterpret_cast<Fn>(
            GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
        if (fn) fn(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }

    void ParseArguments() {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        if (!argv) return;
        for (int i = 1; i < argc; ++i) {
            const std::wstring arg = argv[i];
            if (arg == L"--datadir" && i + 1 < argc)
                data_dir_ = argv[++i];
            else if (arg == L"--node" && i + 1 < argc)
                node_path_ = argv[++i];
        }
        LocalFree(argv);
    }

    void LoadSettings() {
        std::ifstream input(state_dir_ / L"node-gui.conf");
        std::string line;
        while (std::getline(input, line)) {
            if (line == "reachable=0") reachable_choice_ = false;
            else if (line == "reachable=1") reachable_choice_ = true;
            else if (line == "tor=0") tor_choice_ = false;
            else if (line == "tor=1") tor_choice_ = true;
            else if (line == "mining=0") mining_enabled_ = false;
            else if (line == "mining=1") mining_enabled_ = true;
            else if (line == "mining_preset=eco") mining_preset_ = 0;
            else if (line == "mining_preset=balanced") mining_preset_ = 1;
            else if (line == "mining_preset=maximum") mining_preset_ = 2;
            else if (line == "mining_preset=custom") mining_preset_ = 3;
            else if (line == "sync=full") {
                full_ibd_choice_ = true;
                sync_choice_explicit_ = true;
            } else if (line == "sync=snapshot") {
                full_ibd_choice_ = false;
                sync_choice_explicit_ = true;
            }
            else if (line == "reference_display=0")
                reference_display_enabled_.store(false);
            else if (line == "reference_display=1")
                reference_display_enabled_.store(true);
            else if (line == "remote_monitoring=0")
                remote_monitoring_enabled_.store(false);
            else if (line == "remote_monitoring=1")
                remote_monitoring_enabled_.store(true);
            else {
                auto parse_int = [&](const char* key, int minimum,
                                     int maximum, int& target) {
                    const std::string prefix = std::string(key) + "=";
                    if (line.rfind(prefix, 0) != 0) return false;
                    int value = 0;
                    const char* begin = line.data() + prefix.size();
                    const char* end = line.data() + line.size();
                    const auto parsed = std::from_chars(begin, end, value);
                    if (parsed.ec == std::errc{} && parsed.ptr == end &&
                        value >= minimum && value <= maximum)
                        target = value;
                    return true;
                };
                int threads = static_cast<int>(mining_thread_count_);
                if (parse_int("mining_threads", 1, 256, threads))
                    mining_thread_count_ = static_cast<unsigned>(threads);
                else {
                    int topology_role_index =
                        static_cast<int>(topology_role_index_);
                    if (parse_int("topology_role_index", 0, 999,
                                  topology_role_index)) {
                        topology_role_index_ = static_cast<uint32_t>(
                            topology_role_index);
                    }
                    else if (parse_int("chain_range_minutes", 5, 60,
                                       chain_range_minutes_)) {}
                    else if (parse_int("rate_range_minutes", 5, 60,
                                       rate_range_minutes_)) {}
                    else if (parse_int("window_x", -32000, 32000,
                                       window_x_)) {}
                    else if (parse_int("window_y", -32000, 32000,
                                       window_y_)) {}
                    else if (parse_int("window_width", 1050, 7680,
                                       window_width_)) {}
                    else if (parse_int("window_height", 760, 4320,
                                       window_height_)) {}
                    else if (line == "window_maximized=1")
                        window_maximized_ = true;
                    else if (line == "window_maximized=0")
                        window_maximized_ = false;
                }
            }
        }
        if (mining_preset_ >= 0 && mining_preset_ <= 2)
            mining_thread_count_ = PresetThreadCount(mining_preset_);
        if (chain_range_minutes_ != 5 && chain_range_minutes_ != 15 &&
            chain_range_minutes_ != 60) chain_range_minutes_ = 15;
        if (rate_range_minutes_ != 5 && rate_range_minutes_ != 15 &&
            rate_range_minutes_ != 60) rate_range_minutes_ = 15;
    }

    void SaveSettings() {
        std::error_code ec;
        std::filesystem::create_directories(state_dir_, ec);
        if (ec) return;
        const auto path = state_dir_ / L"node-gui.conf";
        const auto pending = state_dir_ / L"node-gui.conf.new";
        {
            std::ofstream output(pending, std::ios::binary | std::ios::trunc);
            if (!output) return;
            output << "reachable=" << (reachable_choice_ ? 1 : 0) << "\n"
                   << "tor=" << (tor_choice_ ? 1 : 0) << "\n"
                   << "mining=" << (mining_enabled_ ? 1 : 0) << "\n"
                   << "sync=" << (full_ibd_choice_ ? "full" : "snapshot")
                   << "\n"
                   << "reference_display="
                   << (reference_display_enabled_.load() ? 1 : 0) << "\n"
                   << "remote_monitoring="
                   << (remote_monitoring_enabled_.load() ? 1 : 0) << "\n"
                   << "mining_preset="
                   << (mining_preset_ == 0 ? "eco" :
                       (mining_preset_ == 1 ? "balanced" :
                        (mining_preset_ == 2 ? "maximum" : "custom"))) << "\n"
                   << "mining_threads=" << mining_thread_count_ << "\n"
                   << "topology_role_index=" << topology_role_index_ << "\n"
                   << "chain_range_minutes=" << chain_range_minutes_ << "\n"
                   << "rate_range_minutes=" << rate_range_minutes_ << "\n"
                   << "window_x=" << window_x_ << "\n"
                   << "window_y=" << window_y_ << "\n"
                   << "window_width=" << window_width_ << "\n"
                   << "window_height=" << window_height_ << "\n"
                   << "window_maximized=" << (window_maximized_ ? 1 : 0)
                   << "\n";
            output.flush();
            if (!output) return;
        }
        MoveFileExW(pending.c_str(), path.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }

    HFONT MakeFont(int px, int weight, const wchar_t* face) {
        return CreateFontW(-S(px), 0, 0, 0, weight, FALSE, FALSE, FALSE,
                           DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                           CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                           DEFAULT_PITCH | FF_DONTCARE, face);
    }

    void CreateFonts() {
        font_brand_ = MakeFont(20, FW_SEMIBOLD, L"Consolas");
        font_title_ = MakeFont(29, FW_SEMIBOLD, L"Consolas");
        font_heading_ = MakeFont(20, FW_SEMIBOLD, L"Consolas");
        font_body_ = MakeFont(15, FW_NORMAL, L"Segoe UI");
        font_small_ = MakeFont(12, FW_NORMAL, L"Segoe UI");
        font_number_ = MakeFont(25, FW_SEMIBOLD, L"Consolas");
        font_log_ = MakeFont(13, FW_NORMAL, L"Consolas");
    }

    void DestroyFonts() {
        for (HFONT* f : {&font_brand_, &font_title_, &font_heading_,
                         &font_body_, &font_small_, &font_number_, &font_log_}) {
            if (*f) DeleteObject(*f);
            *f = nullptr;
        }
    }

    void DrawTextAt(HDC dc, const std::wstring& text, RECT rect, HFONT font,
                    COLORREF color, UINT flags = DT_LEFT | DT_VCENTER |
                                                  DT_SINGLELINE | DT_NOPREFIX) {
        SelectObject(dc, font);
        SetTextColor(dc, color);
        SetBkMode(dc, TRANSPARENT);
        DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &rect, flags);
    }

    HFONT FitSingleLineFont(HDC dc, const std::wstring& text, RECT rect,
                            std::initializer_list<HFONT> candidates) {
        const int available = std::max<int>(0,
            static_cast<int>(rect.right - rect.left));
        HFONT fallback = font_small_;
        for (HFONT candidate : candidates) {
            if (!candidate) continue;
            fallback = candidate;
            SelectObject(dc, candidate);
            SIZE measured{};
            if (GetTextExtentPoint32W(dc, text.c_str(),
                    static_cast<int>(text.size()), &measured) &&
                measured.cx <= available) {
                return candidate;
            }
        }
        return fallback;
    }

    void FillRound(HDC dc, RECT r, COLORREF fill, COLORREF border,
                   int radius = 6) {
        HBRUSH brush = CreateSolidBrush(fill);
        HPEN pen = CreatePen(PS_SOLID, S(1), border);
        HGDIOBJ old_brush = SelectObject(dc, brush);
        HGDIOBJ old_pen = SelectObject(dc, pen);
        RoundRect(dc, r.left, r.top, r.right, r.bottom, S(radius), S(radius));
        SelectObject(dc, old_pen);
        SelectObject(dc, old_brush);
        DeleteObject(pen);
        DeleteObject(brush);
    }

    void DrawLogo(HDC dc, int cx, int cy, int size) {
        const int half = size / 2;
        HBRUSH fill = CreateSolidBrush(RGB(11, 13, 12));
        HPEN ring = CreatePen(PS_SOLID, S(1), C_BORDER);
        HGDIOBJ old_b = SelectObject(dc, fill);
        HGDIOBJ old_p = SelectObject(dc, ring);
        Ellipse(dc, cx - half, cy - half, cx + half, cy + half);
        SelectObject(dc, old_b);
        DeleteObject(fill);
        DeleteObject(ring);

        HPEN green = CreatePen(PS_SOLID, std::max(2, S(2)), C_GREEN);
        SelectObject(dc, green);
        POINT outer[5] = {{cx, cy - half + S(7)}, {cx + half - S(7), cy},
                          {cx, cy + half - S(7)}, {cx - half + S(7), cy},
                          {cx, cy - half + S(7)}};
        POINT inner[5] = {{cx, cy - half / 2}, {cx + half / 2, cy},
                          {cx, cy + half / 2}, {cx - half / 2, cy},
                          {cx, cy - half / 2}};
        Polyline(dc, outer, 5);
        Polyline(dc, inner, 5);
        SelectObject(dc, old_p);
        DeleteObject(green);
    }

    void DrawButton(HDC dc, RECT r, const std::wstring& label, bool enabled) {
        const bool hovered = enabled && PtInRect(&r, hover_point_);
        FillRound(dc, r, enabled ? (hovered ? C_BUTTON_HOVER : C_BUTTON)
                                 : RGB(27, 30, 28),
                  enabled ? (hovered ? RGB(111, 121, 114) : C_BUTTON_BORDER)
                          : C_BORDER_SOFT, 5);
        DrawTextAt(dc, label, r, font_body_, enabled ? C_TEXT : C_MUTED,
                   DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    }

    void DrawStatusDot(HDC dc, int x, int y, COLORREF color) {
        HBRUSH brush = CreateSolidBrush(color);
        HGDIOBJ old = SelectObject(dc, brush);
        SelectObject(dc, GetStockObject(NULL_PEN));
        Ellipse(dc, x - S(4), y - S(4), x + S(4), y + S(4));
        SelectObject(dc, old);
        DeleteObject(brush);
    }

    LiveState SnapshotState() {
        std::lock_guard<std::mutex> lock(state_mutex_);
        return state_;
    }

    void Paint() {
        PAINTSTRUCT ps{};
        HDC target = BeginPaint(hwnd_, &ps);
        RECT client{};
        GetClientRect(hwnd_, &client);
        UpdatePageScrollBar(client);
        GetClientRect(hwnd_, &client);
        const int page_scroll = CurrentPageScroll(client);
        RECT page_client = client;
        page_client.bottom = PageContentHeight(client);
        HDC dc = CreateCompatibleDC(target);
        HBITMAP bitmap = CreateCompatibleBitmap(
            target, client.right - client.left, client.bottom - client.top);
        HGDIOBJ old_bitmap = SelectObject(dc, bitmap);
        HBRUSH bg = CreateSolidBrush(C_BG);
        FillRect(dc, &client, bg);
        DeleteObject(bg);

        const LiveState live = SnapshotState();
        full_ibd_card_ = {};
        snapshot_card_ = {};
        open_log_button_ = {};
        reachable_toggle_ = {};
        tor_toggle_ = {};
        reference_toggle_ = {};
        mining_mode_toggle_ = {};
        open_data_button_ = {};
        import_key_button_ = {};
        create_key_button_ = {};
        open_wallet_button_ = {};
        open_explorer_button_ = {};
        copy_diagnostics_button_ = {};
        preset_eco_button_ = {};
        preset_balanced_button_ = {};
        preset_max_button_ = {};
        preset_minus_button_ = {};
        preset_plus_button_ = {};
        check_update_button_ = {};
        view_changelog_button_ = {};
        for (RECT& button : chain_range_buttons_) button = {};
        for (RECT& button : rate_range_buttons_) button = {};
        chain_plot_rect_ = {};
        rate_plot_rect_ = {};
        network_graph_rect_ = {};
        network_peer_rects_.clear();
        network_peer_indices_.clear();
        network_topology_rects_.clear();
        network_topology_indices_.clear();
        DrawSidebar(dc, client, live);
        const POINT raw_hover = hover_point_;
        hover_point_ = ContentPoint(raw_hover);
        const int saved_dc = SaveDC(dc);
        SetViewportOrgEx(dc, 0, -page_scroll, nullptr);
        switch (page_) {
            case Page::Overview: DrawOverview(dc, page_client, live); break;
            case Page::Blockchain: DrawBlockchain(dc, page_client, live); break;
            case Page::Mining: DrawMining(dc, page_client, live); break;
            case Page::Workers: DrawWorkers(dc, page_client, live); break;
            case Page::Explorer: DrawExplorer(dc, page_client, live); break;
            case Page::Network: DrawNetwork(dc, page_client, live); break;
            case Page::Logs: DrawLogs(dc, page_client, live); break;
            case Page::Settings: DrawSettings(dc, page_client, live); break;
        }
        RestoreDC(dc, saved_dc);
        hover_point_ = raw_hover;

        BitBlt(target, 0, 0, client.right, client.bottom, dc, 0, 0, SRCCOPY);
        SelectObject(dc, old_bitmap);
        DeleteObject(bitmap);
        DeleteDC(dc);
        EndPaint(hwnd_, &ps);
    }

    void DrawSidebar(HDC dc, const RECT& client, const LiveState& live) {
        (void)live;
        const int width = S(252);
        RECT side{0, 0, width, client.bottom};
        HBRUSH brush = CreateSolidBrush(C_SIDEBAR);
        FillRect(dc, &side, brush);
        DeleteObject(brush);
        HPEN divider = CreatePen(PS_SOLID, S(1), C_BORDER_SOFT);
        HGDIOBJ old_pen = SelectObject(dc, divider);
        MoveToEx(dc, width, 0, nullptr);
        LineTo(dc, width, client.bottom);
        SelectObject(dc, old_pen);
        DeleteObject(divider);

        DrawLogo(dc, S(39), S(39), S(42));
        RECT brand{S(72), S(17), S(225), S(60)};
        DrawTextAt(dc, L"VELD NODE", brand, font_brand_, C_TEXT);

        const int nav_x = S(20);
        const int nav_w = width - S(40);
        overview_nav_ = {nav_x, S(94), nav_x + nav_w, S(140)};
        blockchain_nav_ = {nav_x, S(144), nav_x + nav_w, S(190)};
        DrawNav(dc, overview_nav_, L"Overview", page_ == Page::Overview);
        DrawNav(dc, blockchain_nav_, L"Blockchain",
                page_ == Page::Blockchain);

        mining_nav_ = {nav_x, S(200), nav_x + nav_w, S(246)};
        workers_nav_ = {nav_x, S(250), nav_x + nav_w, S(296)};
        DrawNav(dc, mining_nav_, L"Mining", page_ == Page::Mining);
        DrawNav(dc, workers_nav_, L"Workers", page_ == Page::Workers);

        explorer_nav_ = {nav_x, S(306), nav_x + nav_w, S(352)};
        DrawNav(dc, explorer_nav_, L"Explorer", page_ == Page::Explorer);

        network_nav_ = {nav_x, S(356), nav_x + nav_w, S(402)};
        DrawNav(dc, network_nav_, L"Network", page_ == Page::Network);
        logs_nav_ = {nav_x, S(406), nav_x + nav_w, S(452)};
        DrawNav(dc, logs_nav_, L"Logs", page_ == Page::Logs);
        settings_nav_ = {nav_x, S(456), nav_x + nav_w, S(502)};
        DrawNav(dc, settings_nav_, L"Settings", page_ == Page::Settings);

        RECT version{S(28), client.bottom - S(110), width - S(22),
                     client.bottom - S(82)};
        DrawTextAt(dc, std::wstring(L"Version ") +
            Utf8ToWide(veld::CLIENT_VERSION), version, font_small_, C_MUTED);
        follow_x_link_ = {S(20), client.bottom - S(64),
                          width - S(20), client.bottom - S(30)};
        const bool follow_hovered = PtInRect(&follow_x_link_, hover_point_);
        DrawTextAt(dc, L"Follow on X @VeldNetwork", follow_x_link_,
                   font_body_, follow_hovered ? C_TEXT : C_SUBTEXT,
                   DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    }

    void DrawNav(HDC dc, const RECT& r, const std::wstring& label,
                 bool active, bool enabled = true) {
        if (active) {
            HBRUSH marker = CreateSolidBrush(RGB(190, 196, 192));
            RECT edge{r.left, r.top + S(10), r.left + S(2), r.bottom - S(10)};
            FillRect(dc, &edge, marker);
            DeleteObject(marker);
        }
        RECT text{r.left + S(22), r.top, r.right, r.bottom};
        DrawTextAt(dc, label, text, font_body_,
                   active ? C_TEXT : (enabled ? C_SUBTEXT : C_MUTED));
    }

    void DrawPageHeader(HDC dc, const RECT& client,
                        const std::wstring& title,
                        const std::wstring& subtitle,
                        const LiveState& live) {
        const int left = S(292);
        RECT title_r{left, S(34), client.right - S(300), S(78)};
        DrawTextAt(dc, title, title_r, font_title_, C_TEXT);
        RECT sub_r{left, S(78), client.right - S(300), S(108)};
        DrawTextAt(dc, subtitle, sub_r, font_body_, C_SUBTEXT);

        const bool stopping = stopping_node_.load() && live.process_running;
        const std::wstring label = tor_preparing_.load()
            ? L"Preparing Tor..."
            : (stopping ? L"Stopping..."
                        : (live.process_running ? L"Stop node" : L"Start node"));
        const int button_w = tor_preparing_.load() ? S(170) : S(126);
        action_button_ = {client.right - button_w - S(34), S(35),
                          client.right - S(34), S(79)};
        const bool enabled = !tor_preparing_.load() && !stopping;
        DrawButton(dc, action_button_, label, enabled);
    }

    void DrawOverview(HDC dc, const RECT& client, const LiveState& live) {
        DrawPageHeader(dc, client, L"Overview", L"Your node at a glance.", live);
        const int left = S(292);
        const int right = client.right - S(34);
        const int gap = S(16);
        const int top = S(130);
        const int total_w = right - left;
        const int main_w = (total_w - gap) * 2 / 3;
        RECT sync{left, top, left + main_w, top + S(142)};
        RECT mode{sync.right + gap, top, right, top + S(142)};
        FillRound(dc, sync, C_PANEL, C_BORDER);
        FillRound(dc, mode, C_PANEL, C_BORDER);
        RECT running_pill{sync.right - S(112), sync.top + S(14),
                          sync.right - S(18), sync.top + S(42)};
        const bool stopping = stopping_node_.load() && live.process_running;
        FillRound(dc, running_pill,
                  live.local_online && !stopping ? RGB(29, 39, 31) : C_PANEL_ALT,
                  live.local_online && !stopping ? RGB(69, 91, 72) : C_BORDER_SOFT, 12);
        DrawTextAt(dc, stopping ? L"Stopping" :
                   (live.local_online ? L"Running" :
                    (live.process_running ? L"Starting" : L"Stopped")),
                   running_pill, font_small_,
                   live.local_online && !stopping ? C_TEXT : C_SUBTEXT,
                   DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

        const uint64_t target = live.reference_online
            ? live.reference.height : live.local.height;
        const auto progress = veld::node_gui::ComputeSyncProgress(
            live.local.height, target);
        const bool synced = live.local_online && progress.complete;
        const std::wstring state_text = !live.process_running ? L"Node stopped"
            : (stopping ? L"Stopping node"
            : (!live.local_online ? L"Starting node"
            : (synced ? L"Fully synced" : L"Synchronizing")));
        DrawCheck(dc, sync.left + S(54), sync.top + S(70), synced);
        RECT state_r{sync.left + S(102), sync.top + S(18), running_pill.left - S(10),
                     sync.top + S(58)};
        DrawTextAt(dc, state_text, state_r, font_heading_,
                   synced ? C_GREEN : C_TEXT);
        RECT height_r{sync.left + S(102), sync.top + S(56), sync.right - S(20),
                      sync.top + S(91)};
        DrawTextAt(dc, stopping
                       ? L"Closing local services"
                       : (live.local_online
                          ? L"Block " + FormatUnsigned(live.local.height)
                          : L"Waiting for local status"),
                   height_r, font_body_, C_TEXT);
        RECT verify_r{sync.left + S(102), sync.top + S(91), sync.right - S(20),
                      sync.bottom - S(12)};
        const std::wstring attention = NeedsAttention(live);
        DrawTextAt(dc, stopping
                       ? L"The node is stopping safely"
                       : (attention.empty()
                          ? (synced ? L"Best chain tip verified"
                                    : L"Consensus validation remains inside veld-node.exe")
                          : L"Needs attention · " + attention),
                   verify_r, font_small_,
                   stopping || attention.empty() ? C_SUBTEXT : C_WARN,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX |
                   DT_END_ELLIPSIS);

        RECT mode_label{mode.left + S(24), mode.top + S(14),
                        mode.right - S(20), mode.top + S(42)};
        DrawTextAt(dc, L"Node role", mode_label, font_small_, C_SUBTEXT);
        RECT mode_title{mode.left + S(24), mode.top + S(40), mode.right - S(20),
                        mode.top + S(75)};
        DrawTextAt(dc, mining_enabled_ ? L"Mining node" : L"Full node",
                   mode_title, font_heading_, C_TEXT);
        RECT mode_sub{mode.left + S(24), mode.top + S(78), mode.right - S(20),
                      mode.bottom - S(14)};
        DrawTextAt(dc,
                   mining_enabled_
                       ? L"Mining, relay, local explorer, and automatic validator endorsements."
                       : L"Validation, relay, local explorer, and automatic validator endorsements; CPU mining is off.",
                   mode_sub, font_small_, C_SUBTEXT,
                   DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);

        const int cards_top = sync.bottom + S(18);
        const int card_w = (total_w - 3 * gap) / 4;
        DrawMetricCard(dc, {left, cards_top, left + card_w, cards_top + S(124)},
                       L"Connections", live.local_online
                           ? FormatUnsigned(live.local.peers) : L"—",
                       L"direct P2P sessions");
        DrawMetricCard(dc, {left + card_w + gap, cards_top,
                       left + 2 * card_w + gap, cards_top + S(124)},
                       L"Uptime", live.process_running
                           ? FormatUptime(live.uptime_seconds) : L"—", L"node process");
        DrawMetricCard(dc, {left + 2 * (card_w + gap), cards_top,
                       left + 3 * card_w + 2 * gap, cards_top + S(124)},
                       L"Version", Utf8ToWide(veld::CLIENT_VERSION), L"client build");
        DrawMetricCard(dc, {left + 3 * (card_w + gap), cards_top, right,
                       cards_top + S(124)},
                       L"Network", L"Mainnet", L"public profile");

        RECT graph{left, cards_top + S(142), right, client.bottom - S(112)};
        FillRound(dc, graph, C_PANEL, C_BORDER);
        RECT graph_title{graph.left + S(22), graph.top + S(13), graph.right,
                         graph.top + S(48)};
        DrawTextAt(dc, L"Chain activity", graph_title, font_body_, C_TEXT);
        DrawRangeSelector(dc, graph.right - S(22), graph.top + S(13),
                          chain_range_minutes_, chain_range_buttons_);
        DrawHistory(dc, {graph.left + S(24), graph.top + S(55),
                         graph.right - S(24), graph.bottom - S(24)});

        RECT strip{left, client.bottom - S(94), right, client.bottom - S(26)};
        FillRound(dc, strip, C_PANEL, C_BORDER);
        DrawStripItem(dc, {strip.left, strip.top, strip.left + total_w / 3,
                           strip.bottom}, L"RPC", L"Local only",
                      live.process_running ? C_GREEN : C_MUTED);
        DrawStripItem(dc, {strip.left + total_w / 3, strip.top,
                           strip.left + 2 * total_w / 3, strip.bottom},
                      L"P2P", live.local_online && live.local.peers > 0
                          ? L"Connected" : L"Waiting",
                      live.local_online && live.local.peers > 0 ? C_GREEN : C_MUTED);
        DrawStripItem(dc, {strip.left + 2 * total_w / 3, strip.top,
                           strip.right, strip.bottom}, L"Snapshot",
                      L"Disabled", C_MUTED);
    }

    void DrawCheck(HDC dc, int cx, int cy, bool good) {
        HPEN pen = CreatePen(PS_SOLID, S(2), good ? C_GREEN : C_SUBTEXT);
        HGDIOBJ old_pen = SelectObject(dc, pen);
        SelectObject(dc, GetStockObject(HOLLOW_BRUSH));
        Ellipse(dc, cx - S(28), cy - S(28), cx + S(28), cy + S(28));
        if (good) {
            MoveToEx(dc, cx - S(13), cy, nullptr);
            LineTo(dc, cx - S(3), cy + S(10));
            LineTo(dc, cx + S(17), cy - S(12));
        }
        SelectObject(dc, old_pen);
        DeleteObject(pen);
    }

    void DrawMetricCard(HDC dc, RECT r, const std::wstring& label,
                        const std::wstring& value, const std::wstring& sub,
                        COLORREF value_color = C_TEXT) {
        FillRound(dc, r, C_PANEL, C_BORDER);
        RECT label_r{r.left + S(18), r.top + S(12), r.right - S(12), r.top + S(40)};
        DrawTextAt(dc, label, label_r, font_small_, C_SUBTEXT);
        RECT value_r{r.left + S(18), r.top + S(42), r.right - S(12), r.top + S(82)};
        const HFONT value_font = FitSingleLineFont(
            dc, value, value_r, {font_number_, font_heading_, font_body_, font_small_});
        DrawTextAt(dc, value, value_r, value_font,
                   value == L"—" ? C_MUTED : value_color);
        RECT sub_r{r.left + S(18), r.top + S(86), r.right - S(12), r.bottom - S(8)};
        DrawTextAt(dc, sub, sub_r, font_small_, C_MUTED,
                   DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);
    }

    void DrawRangeSelector(HDC dc, int right, int top, int selected,
                           RECT (&buttons)[3]) {
        static constexpr int VALUES[3] = {5, 15, 60};
        static constexpr const wchar_t* LABELS[3] = {L"5m", L"15m", L"1h"};
        const int width = S(42);
        const int gap = S(5);
        for (int i = 2; i >= 0; --i) {
            buttons[i] = {right - (3 - i) * width - (2 - i) * gap, top,
                          right - (2 - i) * width - (2 - i) * gap,
                          top + S(28)};
            const bool hovered = PtInRect(&buttons[i], hover_point_);
            FillRound(dc, buttons[i], selected == VALUES[i] ? C_PANEL_ALT :
                      (hovered ? RGB(24, 28, 25) : C_BG),
                      selected == VALUES[i] ? RGB(112, 121, 115) :
                      (hovered ? C_BORDER : C_BORDER_SOFT),
                      5);
            DrawTextAt(dc, LABELS[i], buttons[i], font_small_,
                       selected == VALUES[i] ? C_TEXT : C_MUTED,
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
    }

    void DrawHistory(HDC dc, RECT r) {
        std::deque<HeightPoint> history;
        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            history = history_;
        }
        const auto cutoff = std::chrono::steady_clock::now() -
            std::chrono::minutes(chain_range_minutes_);
        while (history.size() > 1 && history.front().at < cutoff)
            history.pop_front();
        uint64_t min_h = history.empty() ? 0 : history.front().height;
        uint64_t max_h = min_h;
        for (const auto& p : history) {
            min_h = std::min(min_h, p.height);
            max_h = std::max(max_h, p.height);
        }
        if (max_h == min_h) max_h = min_h + 1;
        RECT plot{r.left + S(76), r.top + S(34), r.right - S(8),
                  r.bottom - S(42)};
        chain_plot_rect_ = plot;
        RECT y_def{r.left, r.top, plot.left + S(40), r.top + S(24)};
        DrawTextAt(dc, L"Block height", y_def, font_small_, C_MUTED,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        HPEN grid = CreatePen(PS_SOLID, S(1), C_BORDER_SOFT);
        HGDIOBJ old_pen = SelectObject(dc, grid);
        for (int i = 0; i <= 3; ++i) {
            const int y = plot.top + (plot.bottom - plot.top) * i / 3;
            MoveToEx(dc, plot.left, y, nullptr);
            LineTo(dc, plot.right, y);
            const uint64_t value = max_h -
                (max_h - min_h) * static_cast<uint64_t>(i) / 3;
            RECT label{r.left, y - S(12), plot.left - S(8), y + S(12)};
            DrawTextAt(dc, FormatUnsigned(value), label, font_small_, C_SUBTEXT,
                       DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
        SelectObject(dc, old_pen);
        DeleteObject(grid);
        const std::wstring span_label = L"-" +
            FormatUnsigned(static_cast<uint64_t>(chain_range_minutes_)) + L" min";
        RECT x_left{plot.left, plot.bottom + S(4), plot.left + S(90),
                    plot.bottom + S(28)};
        RECT x_right{plot.right - S(70), plot.bottom + S(4), plot.right,
                     plot.bottom + S(28)};
        DrawTextAt(dc, span_label, x_left, font_small_, C_SUBTEXT);
        DrawTextAt(dc, L"now", x_right, font_small_, C_SUBTEXT,
                   DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        RECT x_def{plot.left + S(104), plot.bottom + S(4),
                   plot.right - S(86), plot.bottom + S(28)};
        DrawTextAt(dc, L"Observation time", x_def,
                   font_small_, C_MUTED, DT_CENTER | DT_VCENTER |
                   DT_SINGLELINE | DT_NOPREFIX);
        if (history.size() < 2) {
            DrawTextAt(dc, L"Activity appears as new blocks arrive.", plot,
                       font_small_, C_MUTED, DT_CENTER | DT_VCENTER |
                       DT_SINGLELINE | DT_NOPREFIX);
            return;
        }
        HPEN line = CreatePen(PS_SOLID, S(2), RGB(211, 216, 212));
        SelectObject(dc, line);
        const int64_t span_ms = std::chrono::duration_cast<
            std::chrono::milliseconds>(std::chrono::minutes(
                chain_range_minutes_)).count();
        int nearest_distance = std::numeric_limits<int>::max();
        int nearest_x = 0;
        int nearest_y = 0;
        size_t nearest_index = 0;
        for (size_t i = 0; i < history.size(); ++i) {
            const int64_t elapsed = std::chrono::duration_cast<
                std::chrono::milliseconds>(history[i].at - cutoff).count();
            const int x = plot.left + static_cast<int>(
                (plot.right - plot.left) * std::clamp<int64_t>(
                    elapsed, 0, span_ms) / span_ms);
            const double ratio = static_cast<double>(history[i].height - min_h) /
                                 static_cast<double>(max_h - min_h);
            const int y = plot.bottom - static_cast<int>(
                (plot.bottom - plot.top) * ratio);
            if (i == 0) MoveToEx(dc, x, y, nullptr);
            else LineTo(dc, x, y);
            const int distance = std::abs(x - hover_point_.x);
            if (distance < nearest_distance) {
                nearest_distance = distance;
                nearest_x = x;
                nearest_y = y;
                nearest_index = i;
            }
        }
        SelectObject(dc, old_pen);
        DeleteObject(line);
        if (PtInRect(&plot, hover_point_) && nearest_distance <= S(32)) {
            HPEN guide = CreatePen(PS_DOT, S(1), C_MUTED);
            HGDIOBJ old = SelectObject(dc, guide);
            MoveToEx(dc, nearest_x, plot.top, nullptr);
            LineTo(dc, nearest_x, plot.bottom);
            SelectObject(dc, old);
            DeleteObject(guide);
            RECT tip{std::min<int>(nearest_x + S(10), plot.right - S(180)),
                     std::max<int>(plot.top, nearest_y - S(42)),
                     std::min<int>(nearest_x + S(190), plot.right),
                     std::max<int>(plot.top, nearest_y - S(42)) + S(34)};
            FillRound(dc, tip, C_PANEL_ALT, C_BORDER, 5);
            DrawTextAt(dc, L"Block " + FormatUnsigned(history[nearest_index].height),
                       tip, font_small_, C_TEXT,
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
    }

    void DrawRateHistory(HDC dc, RECT r) {
        std::deque<RatePoint> history;
        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            history = rate_history_;
        }
        const auto cutoff = std::chrono::steady_clock::now() -
            std::chrono::minutes(rate_range_minutes_);
        while (history.size() > 1 && history.front().at < cutoff)
            history.pop_front();
        double max_rate = 1.0;
        double peak_rate = 0.0;
        double total_rate = 0.0;
        for (const auto& p : history) {
            max_rate = std::max(max_rate, p.rate);
            peak_rate = std::max(peak_rate, p.rate);
            total_rate += p.rate;
        }
        const double average_rate = history.empty() ? 0.0 :
            total_rate / static_cast<double>(history.size());
        RECT plot{r.left + S(86), r.top + S(34), r.right - S(8),
                  r.bottom - S(42)};
        rate_plot_rect_ = plot;
        RECT y_def{r.left, r.top, plot.left + S(60), r.top + S(24)};
        DrawTextAt(dc, L"Hashrate (H/s)", y_def, font_small_, C_MUTED,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        HPEN grid = CreatePen(PS_SOLID, S(1), C_BORDER_SOFT);
        HGDIOBJ old_pen = SelectObject(dc, grid);
        for (int i = 0; i <= 3; ++i) {
            const int y = plot.top + (plot.bottom - plot.top) * i / 3;
            MoveToEx(dc, plot.left, y, nullptr);
            LineTo(dc, plot.right, y);
            const double value = max_rate * static_cast<double>(3 - i) / 3.0;
            RECT label{r.left, y - S(12), plot.left - S(8), y + S(12)};
            DrawTextAt(dc, FormatHashrate(value), label, font_small_, C_SUBTEXT,
                       DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
        SelectObject(dc, old_pen);
        DeleteObject(grid);
        const std::wstring span_label = L"-" +
            FormatUnsigned(static_cast<uint64_t>(rate_range_minutes_)) + L" min";
        RECT x_left{plot.left, plot.bottom + S(4), plot.left + S(90),
                    plot.bottom + S(28)};
        RECT x_right{plot.right - S(70), plot.bottom + S(4), plot.right,
                     plot.bottom + S(28)};
        DrawTextAt(dc, span_label, x_left, font_small_, C_SUBTEXT);
        DrawTextAt(dc, L"now", x_right, font_small_, C_SUBTEXT,
                   DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        RECT x_def{plot.left + S(104), plot.bottom + S(4),
                   plot.right - S(86), plot.bottom + S(28)};
        DrawTextAt(dc, L"Observation time", x_def,
                   font_small_, C_MUTED, DT_CENTER | DT_VCENTER |
                   DT_SINGLELINE | DT_NOPREFIX);
        if (history.size() < 2) {
            DrawTextAt(dc, L"Hashrate history appears while mining is active.",
                       plot, font_small_, C_MUTED,
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            return;
        }
        HPEN line = CreatePen(PS_SOLID, S(2), RGB(211, 216, 212));
        SelectObject(dc, line);
        const int64_t span_ms = std::chrono::duration_cast<
            std::chrono::milliseconds>(std::chrono::minutes(
                rate_range_minutes_)).count();
        int nearest_distance = std::numeric_limits<int>::max();
        int nearest_x = 0;
        int nearest_y = 0;
        size_t nearest_index = 0;
        for (size_t i = 0; i < history.size(); ++i) {
            const int64_t elapsed = std::chrono::duration_cast<
                std::chrono::milliseconds>(history[i].at - cutoff).count();
            const int x = plot.left + static_cast<int>(
                (plot.right - plot.left) * std::clamp<int64_t>(
                    elapsed, 0, span_ms) / span_ms);
            const int y = plot.bottom - static_cast<int>(
                (plot.bottom - plot.top) * history[i].rate / max_rate);
            if (i == 0) MoveToEx(dc, x, y, nullptr);
            else LineTo(dc, x, y);
            const int distance = std::abs(x - hover_point_.x);
            if (distance < nearest_distance) {
                nearest_distance = distance;
                nearest_x = x;
                nearest_y = y;
                nearest_index = i;
            }
        }
        SelectObject(dc, old_pen);
        DeleteObject(line);
        RECT summary{plot.left + S(190), r.top, plot.right, r.top + S(24)};
        DrawTextAt(dc, L"Average " + FormatHashrate(average_rate) +
                       L"   Peak " + FormatHashrate(peak_rate), summary,
                   font_small_, C_SUBTEXT,
                   DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        if (PtInRect(&plot, hover_point_) && nearest_distance <= S(32)) {
            HPEN guide = CreatePen(PS_DOT, S(1), C_MUTED);
            HGDIOBJ old = SelectObject(dc, guide);
            MoveToEx(dc, nearest_x, plot.top, nullptr);
            LineTo(dc, nearest_x, plot.bottom);
            SelectObject(dc, old);
            DeleteObject(guide);
            RECT tip{std::min<int>(nearest_x + S(10), plot.right - S(180)),
                     std::max<int>(plot.top, nearest_y - S(42)),
                     std::min<int>(nearest_x + S(190), plot.right),
                     std::max<int>(plot.top, nearest_y - S(42)) + S(34)};
            FillRound(dc, tip, C_PANEL_ALT, C_BORDER, 5);
            DrawTextAt(dc, FormatHashrate(history[nearest_index].rate), tip,
                       font_small_, C_TEXT,
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
    }

    void DrawStripItem(HDC dc, RECT r, const std::wstring& label,
                       const std::wstring& value, COLORREF value_color) {
        RECT label_r{r.left + S(22), r.top + S(8), r.right - S(10), r.top + S(33)};
        DrawTextAt(dc, label, label_r, font_small_, C_SUBTEXT);
        RECT value_r{r.left + S(22), r.top + S(31), r.right - S(10), r.bottom - S(5)};
        DrawTextAt(dc, value, value_r, font_small_, value_color);
    }

    std::wstring NeedsAttention(const LiveState& live) {
        if (stopping_node_.load()) return {};
        if (live.process_running && !live.local_online &&
            live.uptime_seconds > 30) return L"local status has not opened";
        if (live.local_online && live.local.peers == 0)
            return L"no peers are connected";
        if (live.mining_status_online && live.mining.work_state == "error")
            return L"mining reported an error; review Logs";
        if (std::filesystem::exists(data_dir_ / L".snapshot-fast-start-revoked"))
            return L"snapshot eligibility was revoked; use full IBD";
        return {};
    }

    double RecentBlocksPerMinute() {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (history_.size() < 2) return 0.0;
        const auto now = std::chrono::steady_clock::now();
        auto first = history_.begin();
        while (first + 1 != history_.end() &&
               first->at < now - std::chrono::minutes(2)) ++first;
        const auto& last = history_.back();
        const double seconds = std::chrono::duration<double>(last.at - first->at).count();
        if (seconds <= 0.0 || last.height <= first->height) return 0.0;
        return static_cast<double>(last.height - first->height) * 60.0 / seconds;
    }

    void DrawBlockchain(HDC dc, const RECT& client, const LiveState& live) {
        DrawPageHeader(dc, client, L"Blockchain",
                       L"Verify and follow the Veld main chain.", live);
        const int left = S(292);
        const int right = client.right - S(34);
        const int top = S(132);
        const uint64_t reference = live.reference_online
            ? live.reference.height : live.local.height;
        const auto progress = veld::node_gui::ComputeSyncProgress(
            live.local.height, reference);
        const std::wstring state_text = !live.process_running ? L"Ready to start"
            : (!live.local_online ? L"Opening chain state"
            : (progress.complete ? L"Synchronized" : L"Downloading and validating"));
        RECT heading{left, top, right - S(120), top + S(44)};
        DrawTextAt(dc, state_text, heading, font_title_, C_TEXT);
        RECT percent{right - S(120), top, right, top + S(44)};
        DrawTextAt(dc, progress.target_known ? FormatPercent(progress.percent) : L"—",
                   percent, font_heading_, progress.complete ? C_GREEN : C_TEXT,
                   DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        RECT count{left, top + S(44), right, top + S(73)};
        std::wstring count_text = live.local_online
            ? FormatUnsigned(live.local.height) + L" of " +
              (progress.target_known ? FormatUnsigned(progress.target_height)
                                     : std::wstring(L"unknown")) + L" blocks"
            : L"Waiting for local node status";
        if (live.local_online) {
            const double blocks_per_minute = RecentBlocksPerMinute();
            count_text += L" · " + FormatBytes(live.chain_bytes) + L" local data";
            if (blocks_per_minute > 0.0 && !progress.complete) {
                std::wostringstream speed;
                speed << std::fixed << std::setprecision(1)
                      << blocks_per_minute << L" blocks/min · ETA "
                      << FormatEta(static_cast<uint64_t>(
                         progress.remaining / blocks_per_minute * 60.0));
                count_text += L" · " + speed.str();
            }
            if (!full_ibd_choice_)
                count_text += L" · recovery selected; history verifies in background";
        }
        DrawTextAt(dc, count_text, count, font_body_, C_SUBTEXT);

        DrawSegmentedProgress(dc, {left, top + S(82), right, top + S(98)},
                              progress.percent, progress.complete);
        DrawStages(dc, left, right, top + S(120), live, progress);

        const int cards_top = top + S(184);
        const int gap = S(14);
        const int total_w = right - left;
        const int card_w = (total_w - 3 * gap) / 4;
        DrawMetricCard(dc, {left, cards_top, left + card_w, cards_top + S(112)},
                       L"Local height", live.local_online
                           ? FormatUnsigned(live.local.height) : L"—", L"validated");
        DrawMetricCard(dc, {left + card_w + gap, cards_top,
                       left + 2 * card_w + gap, cards_top + S(112)},
                       L"Network reference", live.reference_online
                           ? FormatUnsigned(live.reference.height) : L"—",
                       L"display only");
        DrawMetricCard(dc, {left + 2 * (card_w + gap), cards_top,
                       left + 3 * card_w + 2 * gap, cards_top + S(112)},
                       L"Remaining", progress.target_known
                           ? FormatUnsigned(progress.remaining) : L"—", L"blocks");
        DrawMetricCard(dc, {left + 3 * (card_w + gap), cards_top,
                       right, cards_top + S(112)}, L"Peer sources",
                       live.local_online ? FormatUnsigned(live.local.peers) : L"—",
                       L"connected");

        const int choice_top = cards_top + S(132);
        const int choice_w = (total_w - gap) / 2;
        full_ibd_card_ = {left, choice_top, left + choice_w, choice_top + S(120)};
        snapshot_card_ = {left + choice_w + gap, choice_top, right,
                          choice_top + S(120)};
        DrawSyncChoice(dc, full_ibd_card_, L"Full IBD",
                       live.process_running
                            ? L"Keep snapshot imports disabled on the next start."
                            : L"Sync from genesis on first use; reuse verified local history later.",
                       full_ibd_choice_, true);
        DrawSyncChoice(dc, snapshot_card_, L"Signed snapshot",
                       live.process_running
                            ? L"Use on the next start; services stay locked while genesis validation catches up."
                            : L"Start quickly from an official signed snapshot and validate it independently in the background.",
                       !full_ibd_choice_, true);

        RECT verify{left, choice_top + S(140), right, client.bottom - S(30)};
        FillRound(dc, verify, C_PANEL, C_BORDER);
        RECT verify_title{verify.left + S(22), verify.top + S(12),
                          verify.right - S(20), verify.top + S(45)};
        DrawTextAt(dc, L"Historical verification", verify_title,
                   font_body_, C_TEXT);
        RECT verify_text{verify.left + S(22), verify.top + S(46),
                         verify.right - S(22), verify.bottom - S(15)};
        const std::wstring detail =
            L"Signed snapshots are replayed before use and remain quarantined from RPC, inbound peers, mining, and wallet access until a separate genesis IBD matches the exact tip and state digest. Full IBD remains available.";
        DrawTextAt(dc, detail, verify_text, font_small_, C_SUBTEXT,
                   DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);
    }

    void DrawSegmentedProgress(HDC dc, RECT r, double percent, bool complete) {
        constexpr int SEGMENTS = 32;
        const int gap = S(3);
        const int width = (r.right - r.left - gap * (SEGMENTS - 1)) / SEGMENTS;
        const int filled = static_cast<int>(percent * SEGMENTS / 100.0 + 0.5);
        for (int i = 0; i < SEGMENTS; ++i) {
            RECT seg{r.left + i * (width + gap), r.top,
                     r.left + i * (width + gap) + width, r.bottom};
            const COLORREF color = i < filled
                ? (complete && i == SEGMENTS - 1 ? C_GREEN : RGB(210, 215, 211))
                : RGB(41, 46, 43);
            HBRUSH brush = CreateSolidBrush(color);
            FillRect(dc, &seg, brush);
            DeleteObject(brush);
        }
    }

    void DrawStages(HDC dc, int left, int right, int y,
                    const LiveState& live,
                    const veld::node_gui::SyncProgress& progress) {
        const int third = (right - left) / 3;
        const wchar_t* labels[3] = {L"Genesis", L"Block verification", L"Ready"};
        for (int i = 0; i < 3; ++i) {
            RECT r{left + i * third, y, left + (i + 1) * third, y + S(42)};
            bool active = (i == 0 && !live.local_online) ||
                          (i == 1 && live.local_online && !progress.complete) ||
                          (i == 2 && live.local_online && progress.complete);
            DrawStatusDot(dc, r.left + S(16), y + S(21),
                          active ? C_GREEN : C_MUTED);
            r.left += S(31);
            DrawTextAt(dc, labels[i], r, font_small_, active ? C_TEXT : C_MUTED);
        }
    }

    void DrawSyncChoice(HDC dc, RECT r, const std::wstring& title,
                        const std::wstring& description, bool selected,
                        bool enabled) {
        const bool hovered = enabled && PtInRect(&r, hover_point_);
        FillRound(dc, r, selected ? C_PANEL_ALT :
                  (hovered ? RGB(20, 24, 21) : C_PANEL),
                  selected ? RGB(145, 153, 148) :
                  (hovered ? RGB(78, 86, 80) : C_BORDER));
        HPEN pen = CreatePen(PS_SOLID, S(2), selected ? C_TEXT : C_MUTED);
        HGDIOBJ old_pen = SelectObject(dc, pen);
        SelectObject(dc, GetStockObject(HOLLOW_BRUSH));
        Ellipse(dc, r.left + S(20), r.top + S(22),
                r.left + S(42), r.top + S(44));
        if (selected) {
            HBRUSH dot = CreateSolidBrush(C_TEXT);
            HGDIOBJ old_b = SelectObject(dc, dot);
            Ellipse(dc, r.left + S(26), r.top + S(28),
                    r.left + S(36), r.top + S(38));
            SelectObject(dc, old_b);
            DeleteObject(dot);
        }
        SelectObject(dc, old_pen);
        DeleteObject(pen);
        RECT title_r{r.left + S(58), r.top + S(12), r.right - S(18), r.top + S(52)};
        DrawTextAt(dc, title, title_r, font_heading_, enabled ? C_TEXT : C_MUTED);
        RECT desc_r{r.left + S(58), r.top + S(52), r.right - S(18), r.bottom - S(12)};
        DrawTextAt(dc, description, desc_r, font_small_, enabled ? C_SUBTEXT : C_MUTED,
                   DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);
    }

    void DrawMining(HDC dc, const RECT& client, const LiveState& live) {
        DrawPageHeader(dc, client, L"Mining",
                       L"VeldHash performance and work admission.", live);
        const int left = S(292);
        const int right = client.right - S(34);
        const int gap = S(16);
        const int top = S(130);
        const int total_w = right - left;
        const int card_w = (total_w - 3 * gap) / 4;
        const bool mining_configured = live.mining_status_online
            ? live.mining.mining_configured : mining_enabled_.load();
        const bool active = live.mining_status_online &&
                            live.mining.mining_active;
        const std::wstring state = !live.process_running ? L"Stopped"
            : (!mining_configured ? L"Node only"
            : (!live.mining_status_online ? L"Starting"
            : MiningStateLabel(live.mining.work_state)));
        const std::wstring state_detail = !mining_configured
            ? L"CPU mining disabled"
            : (live.mining_status_online
                ? MiningStateDetail(live.mining.work_state)
                : L"waiting for node status");
        DrawMetricCard(dc, {left, top, left + card_w, top + S(124)},
                       L"Mining status", state,
                       state_detail,
                       active ? C_GREEN : C_TEXT);
        DrawMetricCard(dc, {left + card_w + gap, top,
                       left + 2 * card_w + gap, top + S(124)},
                       L"Total hashrate",
                       live.mining_status_online && mining_configured
                           ? FormatHashrate(live.mining.hashrate) : L"—",
                       L"measured by the node", C_TEXT);
        DrawMetricCard(dc, {left + 2 * (card_w + gap), top,
                       left + 3 * card_w + 2 * gap, top + S(124)},
                       L"CPU workers",
                       live.mining_status_online && mining_configured
                           ? FormatUnsigned(live.mining.threads) : L"0",
                       L"VeldHash threads", C_TEXT);
        DrawMetricCard(dc, {left + 3 * (card_w + gap), top, right,
                       top + S(124)}, L"Accepted blocks",
                       live.mining_status_online
                           ? FormatUnsigned(live.mining.blocks_mined_session)
                           : L"—", L"this node session", C_TEXT);

        RECT graph{left, top + S(142), right, client.bottom - S(208)};
        FillRound(dc, graph, C_PANEL, C_BORDER);
        RECT graph_title{graph.left + S(22), graph.top + S(12),
                         graph.right - S(22), graph.top + S(44)};
        DrawTextAt(dc, L"Hashrate history", graph_title,
                   font_body_, C_TEXT);
        DrawRangeSelector(dc, graph.right - S(22), graph.top + S(12),
                          rate_range_minutes_, rate_range_buttons_);
        RECT graph_value{graph.left + S(22), graph.top + S(40),
                         graph.right - S(22), graph.top + S(74)};
        DrawTextAt(dc, live.mining_status_online && mining_configured
                           ? FormatHashrate(live.mining.hashrate) : L"—",
                   graph_value, font_heading_, active ? C_GREEN : C_SUBTEXT);
        DrawRateHistory(dc, {graph.left + S(24), graph.top + S(80),
                             graph.right - S(24), graph.bottom - S(22)});

        RECT safety{left, client.bottom - S(190), right,
                    client.bottom - S(26)};
        FillRound(dc, safety, C_PANEL_ALT, C_BORDER);
        RECT safety_title{safety.left + S(22), safety.top + S(12),
                          safety.right - S(20), safety.top + S(43)};
        DrawTextAt(dc, L"Work admission", safety_title,
                   font_heading_, C_TEXT);
        const int col = (safety.right - safety.left) / 4;
        DrawStripItem(dc, {safety.left, safety.top + S(48),
                           safety.left + col, safety.bottom},
                      L"Chain", live.local_online ? L"Validated" : L"Waiting",
                      live.local_online ? C_GREEN : C_MUTED);
        DrawStripItem(dc, {safety.left + col, safety.top + S(48),
                           safety.left + 2 * col, safety.bottom},
                      L"Peers", live.local.peers > 0 ? L"Connected" : L"Waiting",
                      live.local.peers > 0 ? C_GREEN : C_MUTED);
        DrawStripItem(dc, {safety.left + 2 * col, safety.top + S(48),
                           safety.left + 3 * col, safety.bottom},
                      L"Hashes this session",
                      live.mining_status_online && mining_configured
                          ? FormatUnsigned(live.mining.total_hashes) : L"—",
                      C_SUBTEXT);
        DrawStripItem(dc, {safety.left + 3 * col, safety.top + S(48),
                           safety.right, safety.bottom},
                      L"Validator", L"Auto when registered", C_SUBTEXT);
    }

    void DrawWorkers(HDC dc, const RECT& client, const LiveState& live) {
        DrawPageHeader(dc, client, L"Workers",
                       L"CPU mining threads owned by this node.", live);
        const int left = S(292);
        const int right = client.right - S(34);
        const int top = S(130);
        RECT table{left, top, right, client.bottom - S(26)};
        FillRound(dc, table, C_PANEL, C_BORDER);
        RECT title{table.left + S(22), table.top + S(12),
                   table.right - S(22), table.top + S(44)};
        const uint64_t thread_count = live.mining_status_online &&
                                      live.mining.mining_configured
            ? live.mining.threads : 0;
        DrawTextAt(dc, L"Local VeldHash workers", title,
                   font_heading_, C_TEXT);
        RECT note{table.left + S(22), table.top + S(44),
                  table.right - S(22), table.top + S(74)};
        DrawTextAt(dc,
            L"Per-worker rate is an estimate from the measured aggregate; the node does not report hardware temperature, fan, or power data.",
            note, font_small_, C_SUBTEXT);

        const int header_y = table.top + S(88);
        RECT header{table.left + S(18), header_y, table.right - S(18),
                    header_y + S(38)};
        FillRound(dc, header, C_PANEL_ALT, C_BORDER_SOFT, 4);
        const int content_w = header.right - header.left;
        auto cell = [&](int start, int end, int y1, int y2) {
            return RECT{header.left + content_w * start / 100, y1,
                        header.left + content_w * end / 100, y2};
        };
        DrawTextAt(dc, L"WORKER", cell(2, 20, header.top, header.bottom),
                   font_small_, C_SUBTEXT);
        DrawTextAt(dc, L"STATE", cell(20, 42, header.top, header.bottom),
                   font_small_, C_SUBTEXT);
        DrawTextAt(dc, L"EST. RATE", cell(42, 66, header.top, header.bottom),
                   font_small_, C_SUBTEXT);
        DrawTextAt(dc, L"ALGORITHM", cell(66, 84, header.top, header.bottom),
                   font_small_, C_SUBTEXT);
        DrawTextAt(dc, L"ACTIVITY", cell(84, 98, header.top, header.bottom),
                   font_small_, C_SUBTEXT);

        if (thread_count == 0) {
            RECT empty{table.left + S(22), header.bottom + S(20),
                       table.right - S(22), table.bottom - S(20)};
            DrawTextAt(dc,
                       live.process_running
                           ? L"CPU mining is disabled for this node."
                           : L"Start the node to load worker information.",
                       empty, font_body_, C_MUTED,
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            return;
        }
        const uint64_t shown = std::min<uint64_t>(thread_count, 10);
        const int available = table.bottom - header.bottom - S(44);
        const int row_h = std::max(S(42), available / static_cast<int>(shown));
        const bool active = live.mining.mining_active;
        const std::wstring worker_state = active
            ? L"Hashing" : MiningStateLabel(live.mining.work_state);
        const double per_worker = thread_count > 0
            ? live.mining.hashrate / static_cast<double>(thread_count) : 0.0;
        for (uint64_t i = 0; i < shown; ++i) {
            const int y1 = header.bottom + S(5) + static_cast<int>(i) * row_h;
            const int y2 = y1 + row_h;
            if (i > 0) {
                HPEN divider = CreatePen(PS_SOLID, S(1), C_BORDER_SOFT);
                HGDIOBJ old = SelectObject(dc, divider);
                MoveToEx(dc, header.left, y1, nullptr);
                LineTo(dc, header.right, y1);
                SelectObject(dc, old);
                DeleteObject(divider);
            }
            DrawTextAt(dc, L"CPU " + std::to_wstring(i + 1),
                       cell(2, 20, y1, y2), font_body_, C_TEXT);
            DrawTextAt(dc, worker_state, cell(20, 42, y1, y2),
                       font_body_, active ? C_GREEN : C_SUBTEXT);
            DrawTextAt(dc, FormatHashrate(per_worker),
                       cell(42, 66, y1, y2), font_body_, C_TEXT);
            DrawTextAt(dc, L"VeldHash", cell(66, 84, y1, y2),
                       font_body_, C_SUBTEXT);
            DrawTextAt(dc, active ? L"Live" : L"Waiting",
                       cell(84, 98, y1, y2), font_body_,
                       active ? C_GREEN : C_MUTED);
        }
        if (thread_count > shown) {
            RECT more{header.left, table.bottom - S(34), header.right,
                      table.bottom - S(8)};
            DrawTextAt(dc, L"+ " + FormatUnsigned(thread_count - shown) +
                       L" additional workers", more, font_small_, C_SUBTEXT,
                       DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
    }

    void DrawExplorer(HDC dc, const RECT& client, const LiveState& live) {
        DrawPageHeader(dc, client, L"Explorer",
                       L"Inspect the chain served by this node.", live);
        const int left = S(292);
        const int right = client.right - S(34);
        const int gap = S(16);
        const int top = S(130);
        const int total_w = right - left;
        const int card_w = (total_w - 3 * gap) / 4;
        DrawMetricCard(dc, {left, top, left + card_w, top + S(124)},
                       L"Block height", live.local_online
                           ? FormatUnsigned(live.local.height) : L"—",
                       L"local canonical tip", C_TEXT);
        DrawMetricCard(dc, {left + card_w + gap, top,
                       left + 2 * card_w + gap, top + S(124)},
                       L"Direct peers", live.local_online
                           ? FormatUnsigned(live.local.peers) : L"—",
                       L"this node's P2P sessions", C_TEXT);
        DrawMetricCard(dc, {left + 2 * (card_w + gap), top,
                       left + 3 * card_w + 2 * gap, top + S(124)},
                       L"Mempool", live.local_online
                           ? FormatUnsigned(live.local.mempool_size) : L"—",
                       L"transactions", C_TEXT);
        DrawMetricCard(dc, {left + 3 * (card_w + gap), top, right,
                       top + S(124)}, L"Supply",
                       live.local_online ? FormatVeldNumber(live.local.supply_veld)
                                         : L"—",
                       L"VELD · validated locally", C_TEXT);

        RECT workspace{left, top + S(142), right, client.bottom - S(26)};
        FillRound(dc, workspace, C_PANEL, C_BORDER);
        RECT ws_title{workspace.left + S(24), workspace.top + S(22),
                      workspace.right - S(24), workspace.top + S(60)};
        DrawTextAt(dc, L"Locally verified chain", ws_title,
                   font_heading_, C_TEXT);
        const int inner_left = workspace.left + S(24);
        const int inner_top = workspace.top + S(66);
        const int inner_right = workspace.right - S(24);
        const int inner_bottom = workspace.bottom - S(24);
        const int inner_gap = S(16);
        const int chain_w = (inner_right - inner_left - inner_gap) * 3 / 5;
        RECT chain{inner_left, inner_top, inner_left + chain_w, inner_bottom};
        RECT services{chain.right + inner_gap, inner_top, inner_right,
                      inner_bottom};
        FillRound(dc, chain, C_PANEL_ALT, C_BORDER_SOFT, 5);
        FillRound(dc, services, C_PANEL_ALT, C_BORDER_SOFT, 5);

        RECT chain_title{chain.left + S(20), chain.top + S(12),
                         chain.right - S(20), chain.top + S(44)};
        DrawTextAt(dc, L"Canonical tip and recent blocks", chain_title,
                   font_body_, C_TEXT);
        RECT chain_detail{chain.left + S(20), chain.top + S(38),
                          chain.right - S(20), chain.top + S(61)};
        DrawTextAt(dc, live.local_online
            ? (full_ibd_choice_
                ? L"Consensus verified locally from genesis"
                : L"Recovered snapshot · consensus verification active")
            : L"Waiting for the local consensus engine",
            chain_detail, font_small_, C_MUTED);
        const int label_w = S(118);
        auto draw_chain_row = [&](int row, const std::wstring& label,
                                  const std::wstring& value) {
            const int y = chain.top + S(66) + row * S(34);
            RECT label_r{chain.left + S(20), y, chain.left + label_w,
                         y + S(26)};
            RECT value_r{chain.left + label_w, y, chain.right - S(20),
                          y + S(26)};
            DrawTextAt(dc, label, label_r, font_small_, C_MUTED);
            DrawTextAt(dc, value, value_r, font_log_, C_SUBTEXT,
                       DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX |
                       DT_END_ELLIPSIS);
        };
        draw_chain_row(0, L"Height",
            live.local_online ? FormatUnsigned(live.local.height) : L"—");
        draw_chain_row(1, L"Block hash",
            live.local_online ? Utf8ToWide(live.local.best_block_hash) : L"—");
        draw_chain_row(2, L"Tip age",
            live.local_online ? FormatAge(live.local.tip_timestamp) : L"—");
        draw_chain_row(3, L"Chain data",
            live.local_online ? FormatBytes(live.chain_bytes) : L"—");

        const int feed_top = chain.top + S(218);
        HPEN feed_divider = CreatePen(PS_SOLID, S(1), C_BORDER_SOFT);
        HGDIOBJ old_feed_pen = SelectObject(dc, feed_divider);
        MoveToEx(dc, chain.left + S(20), feed_top, nullptr);
        LineTo(dc, chain.right - S(20), feed_top);
        SelectObject(dc, old_feed_pen);
        DeleteObject(feed_divider);
        RECT feed_title{chain.left + S(20), feed_top + S(10),
                        chain.right - S(20), feed_top + S(38)};
        DrawTextAt(dc, L"Recent block feed", feed_title, font_small_, C_SUBTEXT);
        const size_t feed_count = std::min<size_t>(3, live.recent_blocks.size());
        for (size_t i = 0; i < feed_count; ++i) {
            const auto& block = live.recent_blocks[i];
            const int y = feed_top + S(42) + static_cast<int>(i) * S(54);
            RECT height_r{chain.left + S(20), y, chain.left + S(112), y + S(26)};
            DrawTextAt(dc, L"#" + FormatUnsigned(block.height), height_r,
                       font_body_, C_TEXT);
            std::wstring winner = Utf8ToWide(block.winner);
            if (winner.size() > 20)
                winner = winner.substr(0, 9) + L"…" +
                         winner.substr(winner.size() - 7);
            RECT winner_r{chain.left + S(116), y, chain.right - S(96), y + S(26)};
            DrawTextAt(dc, winner.empty() ? L"Winner unavailable" :
                       L"Won by " + winner, winner_r, font_small_, C_SUBTEXT,
                       DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX |
                       DT_END_ELLIPSIS);
            RECT age_r{chain.right - S(92), y, chain.right - S(20), y + S(26)};
            DrawTextAt(dc, FormatAge(block.timestamp), age_r, font_small_, C_MUTED,
                       DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            RECT detail_r{chain.left + S(20), y + S(25),
                          chain.right - S(20), y + S(49)};
            DrawTextAt(dc, FormatUnsigned(block.transaction_count) +
                       L" tx · " + FormatVeld(block.reward_veld) + L" reward",
                       detail_r, font_small_, C_MUTED);
        }
        if (feed_count == 0) {
            RECT empty{chain.left + S(20), feed_top + S(48),
                       chain.right - S(20), feed_top + S(82)};
            DrawTextAt(dc, L"Waiting for locally verified block details.",
                       empty, font_small_, C_MUTED);
        }

        RECT service_title{services.left + S(20), services.top + S(12),
                           services.right - S(20), services.top + S(44)};
        DrawTextAt(dc, L"Services", service_title, font_body_, C_TEXT);
        auto draw_service = [&](int row, const std::wstring& label,
                                const std::wstring& value) {
            const int y = services.top + S(54) + row * S(43);
            RECT label_r{services.left + S(20), y,
                         services.left + S(116), y + S(28)};
            RECT value_r{services.left + S(116), y,
                         services.right - S(20), y + S(28)};
            DrawTextAt(dc, label, label_r, font_small_, C_MUTED);
            DrawTextAt(dc, value, value_r, font_small_, C_SUBTEXT,
                       DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX |
                       DT_END_ELLIPSIS);
        };
        draw_service(0, L"Explorer", L"explorer.veld.network");
        draw_service(1, L"RPC", live.process_running
            ? L"Local only · token secured" : L"Stopped");
        draw_service(2, L"P2P", live.process_running
            ? L"Public · " + FormatUnsigned(live.local.peers) + L" direct peers"
            : L"Stopped");
        draw_service(3, L"Wallet", L"wallet.veld.network");

        const int button_gap = S(10);
        const int button_w = (services.right - services.left - S(40) -
                              button_gap) / 2;
        open_explorer_button_ = {services.left + S(20),
                                 services.bottom - S(64),
                                 services.left + S(20) + button_w,
                                 services.bottom - S(20)};
        open_wallet_button_ = {open_explorer_button_.right + button_gap,
                               services.bottom - S(64),
                               services.right - S(20),
                               services.bottom - S(20)};
        DrawButton(dc, open_explorer_button_, L"Open explorer", true);
        DrawButton(dc, open_wallet_button_, L"Open wallet", true);
    }

    COLORREF MixColor(COLORREF a, COLORREF b, int b_percent) {
        const int p = std::clamp(b_percent, 0, 100);
        auto channel = [p](BYTE x, BYTE y) {
            return static_cast<BYTE>((x * (100 - p) + y * p) / 100);
        };
        return RGB(channel(GetRValue(a), GetRValue(b)),
                   channel(GetGValue(a), GetGValue(b)),
                   channel(GetBValue(a), GetBValue(b)));
    }

    void DrawNetworkSphere(HDC dc, int cx, int cy, int radius,
                           COLORREF base, COLORREF border) {
        HPEN no_pen = CreatePen(PS_NULL, 0, 0);
        HGDIOBJ old_pen = SelectObject(dc, no_pen);
        for (int ring = radius; ring >= 2; --ring) {
            const int depth = (radius - ring) * 100 / std::max(1, radius);
            COLORREF color = MixColor(base, RGB(4, 6, 5), depth * 2 / 3);
            if (ring > radius * 2 / 3)
                color = MixColor(color, RGB(196, 205, 199),
                                 (ring - radius * 2 / 3) * 18 / radius);
            HBRUSH brush = CreateSolidBrush(color);
            HGDIOBJ old_brush = SelectObject(dc, brush);
            const int highlight = (radius - ring) / 3;
            Ellipse(dc, cx - ring - highlight, cy - ring - highlight,
                    cx + ring - highlight, cy + ring - highlight);
            SelectObject(dc, old_brush);
            DeleteObject(brush);
        }
        SelectObject(dc, old_pen);
        DeleteObject(no_pen);
        HPEN outline = CreatePen(PS_SOLID, S(2), border);
        HGDIOBJ old_outline = SelectObject(dc, outline);
        HGDIOBJ old_hollow = SelectObject(dc, GetStockObject(HOLLOW_BRUSH));
        Ellipse(dc, cx - radius, cy - radius, cx + radius, cy + radius);
        SelectObject(dc, old_hollow);
        SelectObject(dc, old_outline);
        DeleteObject(outline);
    }

    void DrawDirectPeerTopology(HDC dc, RECT card, const LiveState& live) {
        FillRound(dc, card, C_PANEL, C_BORDER);
        const std::wstring session_summary = live.local_online
            ? FormatUnsigned(live.local.peers) + L" direct · report pending"
            : L"Offline";
        const int summary_w = S(172);
        RECT summary{card.right - summary_w - S(18), card.top + S(13),
                     card.right - S(18), card.top + S(43)};
        FillRound(dc, summary, C_PANEL_ALT, C_BORDER_SOFT, 5);
        DrawTextAt(dc, session_summary, summary, font_small_, C_SUBTEXT,
                   DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        RECT title{card.left + S(20), card.top + S(12),
                   summary.left - S(12), card.top + S(44)};
        DrawTextAt(dc, L"Peer topology", title, font_heading_, C_TEXT);
        RECT subtitle{card.left + S(20), card.top + S(42),
                      card.right - S(20), card.top + S(66)};
        DrawTextAt(dc, L"Direct sessions shown live · network reports join automatically · no addresses exposed",
                   subtitle, font_small_, C_MUTED);

        RECT plot{card.left + S(18), card.top + S(70),
                  card.right - S(18), card.bottom - S(43)};
        FillRound(dc, plot, RGB(11, 14, 12), C_BORDER_SOFT, 7);
        InflateRect(&plot, -S(12), -S(10));
        network_graph_rect_ = plot;
        auto role_label = [](const std::string& role) -> std::wstring {
            if (role == "fleet") return L"Fleet";
            if (role == "mesh") return L"Node";
            if (role == "miner") return L"Miner";
            if (role == "validator") return L"Validator";
            return L"Node";
        };
        auto role_color = [](const std::string& role) -> COLORREF {
            if (role == "fleet") return RGB(111, 139, 153);
            if (role == "validator") return RGB(143, 111, 189);
            if (role == "mesh" || role == "miner" || role == "node")
                return RGB(92, 145, 124);
            return RGB(92, 145, 124);
        };
        std::vector<veld::node_gui::PeerSummary> fallback_peers;
        const std::vector<veld::node_gui::PeerSummary>* displayed_peers =
            &live.peer_details;
        const bool using_fallback = !live.peer_details_online &&
            live.local_online && live.local.peers > 0;
        if (using_fallback) {
            const size_t count = static_cast<size_t>(
                std::min<uint64_t>(live.local.peers, 16));
            fallback_peers.resize(count);
            for (size_t i = 0; i < count; ++i)
                fallback_peers[i].anonymous_id = static_cast<uint32_t>(i + 1);
            displayed_peers = &fallback_peers;
        }
        if (!live.local_online) {
            DrawTextAt(dc, L"Start the node to view live peer topology.",
                       plot, font_body_, C_MUTED,
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        } else if (displayed_peers->empty()) {
            DrawTextAt(dc, L"No peers are currently connected.", plot,
                       font_body_, C_MUTED,
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        } else {
            const size_t limit = (plot.right - plot.left >= S(620)) ? 16 : 10;
            const size_t shown = std::min(limit, displayed_peers->size());
            const int cx = (plot.left + plot.right) / 2;
            const int cy = (plot.top + plot.bottom) / 2;
            const int node_w = (plot.right - plot.left >= S(620)) ? S(92) : S(72);
            const int node_h = S(76);
            const int radius_x = std::max<int>(S(85),
                static_cast<int>(plot.right - plot.left - 2 * node_w) / 2);
            const int radius_y = std::max<int>(S(55),
                static_cast<int>(plot.bottom - plot.top - 2 * node_h) / 2);
            constexpr double PI = 3.14159265358979323846;

            std::vector<size_t> fleet_layer;
            std::vector<size_t> validator_layer;
            std::vector<size_t> operator_layer;
            fleet_layer.reserve(shown);
            validator_layer.reserve(shown);
            operator_layer.reserve(shown);
            for (size_t i = 0; i < shown; ++i) {
                const auto& peer = (*displayed_peers)[i];
                if (peer.role == "fleet")
                    fleet_layer.push_back(i);
                else if (peer.role == "validator")
                    validator_layer.push_back(i);
                else
                    operator_layer.push_back(i);
            }

            auto sort_layer = [&](std::vector<size_t>& layer) {
                std::stable_sort(layer.begin(), layer.end(),
                    [&](size_t lhs, size_t rhs) {
                        const auto& a = (*displayed_peers)[lhs];
                        const auto& b = (*displayed_peers)[rhs];
                        if (a.role_index != b.role_index)
                            return a.role_index < b.role_index;
                        return a.anonymous_id < b.anonymous_id;
                    });
            };
            sort_layer(fleet_layer);
            sort_layer(validator_layer);
            sort_layer(operator_layer);

            std::vector<POINT> centers(shown, POINT{cx, cy});
            auto place_layer = [&](const std::vector<size_t>& layer,
                                   double scale, double phase) {
                if (layer.empty()) return;
                const double step = 2.0 * PI /
                    static_cast<double>(layer.size());
                for (size_t ordinal = 0; ordinal < layer.size(); ++ordinal) {
                    const double angle = phase + step *
                        static_cast<double>(ordinal);
                    centers[layer[ordinal]] = {
                        cx + static_cast<int>(std::cos(angle) *
                                              radius_x * scale),
                        cy + static_cast<int>(std::sin(angle) *
                                              radius_y * scale)};
                }
            };
            // Keep the four public fleet anchors on diagonal lanes.  Cardinal
            // placement made Fleet 02/Fleet 04 share the same horizontal line
            // as ordinary peers, which stacked links and labels through the
            // local node.  The wider fleet orbit preserves the simple orbital
            // layout while giving every connection a distinct approach angle.
            place_layer(fleet_layer, 0.82, -PI / 4.0);
            place_layer(validator_layer, 0.91, -PI / 2.0 + PI / 7.0);
            place_layer(operator_layer, 1.0,
                        operator_layer.size() == 2 ? 0.0 : PI / 6.0);

            auto draw_orbit = [&](double scale, COLORREF color) {
                HPEN orbit = CreatePen(PS_DOT, S(1), color);
                HGDIOBJ old_orbit = SelectObject(dc, orbit);
                HGDIOBJ old_orbit_brush = SelectObject(
                    dc, GetStockObject(HOLLOW_BRUSH));
                const int orbit_x = static_cast<int>(radius_x * scale);
                const int orbit_y = static_cast<int>(radius_y * scale);
                Ellipse(dc, cx - orbit_x, cy - orbit_y,
                        cx + orbit_x, cy + orbit_y);
                SelectObject(dc, old_orbit_brush);
                SelectObject(dc, old_orbit);
                DeleteObject(orbit);
            };
            if (!fleet_layer.empty())
                draw_orbit(0.82, RGB(38, 45, 41));
            if (!validator_layer.empty())
                draw_orbit(0.91, RGB(43, 49, 46));
            if (!operator_layer.empty())
                draw_orbit(1.0, RGB(48, 55, 51));

            size_t hovered_peer_index = shown;
            for (size_t i = 0; i < shown; ++i) {
                RECT node{centers[i].x - node_w / 2,
                          centers[i].y - node_h / 2,
                          centers[i].x + node_w / 2,
                          centers[i].y + node_h / 2};
                if (PtInRect(&node, hover_point_)) {
                    hovered_peer_index = i;
                    break;
                }
            }
            for (size_t i = 0; i < shown; ++i) {
                const auto& peer = (*displayed_peers)[i];
                const bool highlighted = i == hovered_peer_index;
                const bool agreed = peer.exact_tip;
                const COLORREF base_line_color = using_fallback ? C_BORDER :
                    (agreed ? MixColor(role_color(peer.role), C_TEXT, 10) : C_WARN);
                const COLORREF line_color = highlighted
                    ? MixColor(role_color(peer.role), C_TEXT, 45)
                    : base_line_color;
                HPEN underlay = CreatePen(PS_SOLID,
                                          highlighted ? S(7) : S(3),
                                          RGB(19, 24, 21));
                HGDIOBJ old_underlay = SelectObject(dc, underlay);
                MoveToEx(dc, cx, cy, nullptr);
                LineTo(dc, centers[i].x, centers[i].y - S(10));
                SelectObject(dc, old_underlay);
                DeleteObject(underlay);
                HPEN line = CreatePen(peer.inbound ? PS_DASH : PS_SOLID,
                                     highlighted ? S(3) : S(1), line_color);
                HGDIOBJ old = SelectObject(dc, line);
                MoveToEx(dc, cx, cy, nullptr);
                LineTo(dc, centers[i].x, centers[i].y - S(10));
                SelectObject(dc, old);
                DeleteObject(line);

                const int marker_x = cx + (centers[i].x - cx) * 58 / 100;
                const int marker_y = cy + (centers[i].y - S(10) - cy) * 58 / 100;
                const int marker_r = highlighted ? S(5) :
                    S(peer.inbound ? 4 : 3);
                HPEN marker_pen = CreatePen(PS_SOLID, S(1), line_color);
                HBRUSH marker_brush = CreateSolidBrush(
                    peer.inbound ? RGB(11, 14, 12) : line_color);
                HGDIOBJ old_marker_pen = SelectObject(dc, marker_pen);
                HGDIOBJ old_marker_brush = SelectObject(dc, marker_brush);
                Ellipse(dc, marker_x - marker_r, marker_y - marker_r,
                        marker_x + marker_r, marker_y + marker_r);
                SelectObject(dc, old_marker_brush);
                SelectObject(dc, old_marker_pen);
                DeleteObject(marker_brush);
                DeleteObject(marker_pen);
            }

            for (int halo : {57, 50}) {
                HPEN halo_pen = CreatePen(PS_SOLID, S(1),
                    halo == 57 ? RGB(40, 48, 43) : RGB(58, 70, 63));
                HGDIOBJ old_halo_pen = SelectObject(dc, halo_pen);
                HGDIOBJ old_halo_brush = SelectObject(
                    dc, GetStockObject(HOLLOW_BRUSH));
                Ellipse(dc, cx - S(halo), cy - S(halo),
                        cx + S(halo), cy + S(halo));
                SelectObject(dc, old_halo_brush);
                SelectObject(dc, old_halo_pen);
                DeleteObject(halo_pen);
            }
            DrawNetworkSphere(dc, cx, cy, S(43), RGB(43, 53, 47),
                              using_fallback ? C_SUBTEXT :
                              (live.exact_tip_peers ? RGB(151, 177, 158) : C_WARN));
            RECT center_title{cx - S(45), cy - S(15), cx + S(45), cy + S(5)};
            DrawTextAt(dc, L"LOCAL NODE", center_title, font_small_, C_TEXT,
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            RECT center_state{cx - S(45), cy + S(5), cx + S(45), cy + S(25)};
            DrawTextAt(dc, using_fallback ? L"Direct peers" :
                       (live.exact_tip_peers ? L"Synchronized" : L"Checking tips"),
                       center_state, font_small_,
                       using_fallback ? C_SUBTEXT :
                       (live.exact_tip_peers ? C_GREEN : C_WARN),
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

            std::unordered_map<std::string, uint32_t> role_ordinals;
            for (size_t i = 0; i < shown; ++i) {
                const auto& peer = (*displayed_peers)[i];
                uint32_t role_number = peer.role_index;
                if (role_number == 0)
                    role_number = ++role_ordinals[peer.role];
                RECT node{centers[i].x - node_w / 2,
                          centers[i].y - node_h / 2,
                          centers[i].x + node_w / 2,
                          centers[i].y + node_h / 2};
                const bool hovered = i == hovered_peer_index;
                const COLORREF peer_role_color = using_fallback
                    ? C_SUBTEXT : role_color(peer.role);
                const COLORREF sphere_base = using_fallback
                    ? RGB(42, 48, 44)
                    : peer.exact_tip
                    ? MixColor(peer_role_color, RGB(10, 13, 11), 62)
                    : RGB(76, 58, 35);
                const COLORREF sphere_border = hovered ? C_TEXT :
                    (peer.exact_tip ? peer_role_color : C_WARN);
                if (hovered) {
                    HPEN hover_pen = CreatePen(PS_SOLID, S(1),
                                               MixColor(peer_role_color, C_TEXT, 35));
                    HGDIOBJ old_hover_pen = SelectObject(dc, hover_pen);
                    HGDIOBJ old_hover_brush = SelectObject(
                        dc, GetStockObject(HOLLOW_BRUSH));
                    Ellipse(dc, centers[i].x - S(28), centers[i].y - S(38),
                            centers[i].x + S(28), centers[i].y + S(18));
                    SelectObject(dc, old_hover_brush);
                    SelectObject(dc, old_hover_pen);
                    DeleteObject(hover_pen);
                }
                DrawNetworkSphere(dc, centers[i].x, centers[i].y - S(10),
                                  hovered ? S(24) : S(22), sphere_base,
                                  using_fallback ? C_SUBTEXT : sphere_border);
                RECT direction{centers[i].x - S(22), centers[i].y - S(21),
                               centers[i].x + S(22), centers[i].y + S(1)};
                DrawTextAt(dc, using_fallback ? L"PEER" :
                    (peer.inbound ? L"IN" : L"OUT"), direction, font_small_,
                    C_TEXT, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                const bool place_copy_above = centers[i].y < cy - S(18);
                RECT label = place_copy_above
                    ? RECT{node.left, centers[i].y - S(49),
                           node.right, centers[i].y - S(31)}
                    : RECT{node.left, centers[i].y + S(13),
                           node.right, centers[i].y + S(33)};
                const std::wstring peer_label = role_label(peer.role) + L" " +
                    (role_number < 10 ? std::wstring(L"0") : std::wstring()) +
                    FormatUnsigned(role_number);
                DrawTextAt(dc, peer_label, label,
                           FitSingleLineFont(dc, peer_label, label,
                                             {font_small_, font_log_}), C_TEXT,
                           DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                RECT detail = place_copy_above
                    ? RECT{node.left, centers[i].y - S(67),
                           node.right, centers[i].y - S(48)}
                    : RECT{node.left, centers[i].y + S(30),
                           node.right, centers[i].y + S(49)};
                DrawTextAt(dc,
                    (using_fallback ? std::wstring(L"Direct") :
                     std::wstring(peer.inbound ? L"In" : L"Out")) + L" · " +
                    (tor_choice_ ? L"Tor" : L"TCP"), detail, font_small_,
                    C_MUTED, DT_CENTER | DT_VCENTER | DT_SINGLELINE |
                    DT_NOPREFIX);
                if (!using_fallback) {
                    network_peer_rects_.push_back(node);
                    network_peer_indices_.push_back(i);
                }
            }
            if (displayed_peers->size() > shown) {
                RECT more{plot.right - S(120), plot.bottom - S(24),
                          plot.right, plot.bottom};
                DrawTextAt(dc, L"+" +
                    FormatUnsigned(displayed_peers->size() - shown) +
                    L" more", more, font_small_, C_MUTED,
                    DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            }
        }

        const int legend_y = card.bottom - S(27);
        auto legend_line = [&](int x, bool inbound, COLORREF color,
                               const wchar_t* label) {
            HPEN pen = CreatePen(PS_SOLID, S(1), color);
            HGDIOBJ old = SelectObject(dc, pen);
            if (inbound) {
                for (int segment = 0; segment < 3; ++segment) {
                    const int start = x + S(segment * 11);
                    MoveToEx(dc, start, legend_y, nullptr);
                    LineTo(dc, start + S(6), legend_y);
                }
            } else {
                MoveToEx(dc, x, legend_y, nullptr);
                LineTo(dc, x + S(28), legend_y);
            }
            SelectObject(dc, old);
            DeleteObject(pen);
            const int marker_x = x + S(14);
            const int marker_r = S(3);
            HPEN marker_pen = CreatePen(PS_SOLID, S(1), color);
            HBRUSH marker_brush = inbound
                ? static_cast<HBRUSH>(GetStockObject(HOLLOW_BRUSH))
                : CreateSolidBrush(color);
            HGDIOBJ old_marker_pen = SelectObject(dc, marker_pen);
            HGDIOBJ old_marker_brush = SelectObject(dc, marker_brush);
            Ellipse(dc, marker_x - marker_r, legend_y - marker_r,
                    marker_x + marker_r, legend_y + marker_r);
            SelectObject(dc, old_marker_brush);
            SelectObject(dc, old_marker_pen);
            if (!inbound) DeleteObject(marker_brush);
            DeleteObject(marker_pen);
            RECT text{x + S(36), legend_y - S(13), x + S(116), legend_y + S(13)};
            DrawTextAt(dc, label, text, font_small_, C_MUTED);
        };
        if (using_fallback) {
            legend_line(card.left + S(22), false, C_BORDER, L"Direct session");
            RECT detail{card.left + S(168), legend_y - S(13),
                        card.right - S(20), legend_y + S(13)};
            DrawTextAt(dc, L"Direction and tip metadata unavailable",
                       detail, font_small_, C_MUTED,
                       DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        } else {
            legend_line(card.left + S(22), false, RGB(111, 139, 153), L"Outbound");
            legend_line(card.left + S(142), true, RGB(92, 145, 124), L"Inbound");
            legend_line(card.left + S(252), false, C_WARN, L"Tip differs");
        }

        for (size_t i = 0; i < network_peer_rects_.size(); ++i) {
            if (!PtInRect(&network_peer_rects_[i], hover_point_)) continue;
            const auto& peer = live.peer_details[network_peer_indices_[i]];
            std::wstring status = peer.peer_tip_age_s < 0 ? L"Tip unavailable" :
                (peer.exact_tip ? L"Exact tip agreement" :
                 (peer.lag_blocks > 0
                    ? FormatUnsigned(static_cast<uint64_t>(peer.lag_blocks)) +
                        L" blocks behind"
                    : L"Different announced tip"));
            const RECT tip = NetworkTooltipRect(
                network_peer_rects_[i], S(270), S(88));
            FillRound(dc, tip, RGB(24, 28, 25), RGB(92, 102, 96), 6);
            RECT tip_title{tip.left + S(10), tip.top + S(5),
                           tip.right - S(10), tip.top + S(28)};
            DrawTextAt(dc, role_label(peer.role) + L" · " + status,
                       tip_title, font_small_, C_TEXT);
            RECT tip_detail{tip.left + S(10), tip.top + S(27),
                            tip.right - S(10), tip.bottom - S(5)};
            DrawTextAt(dc,
                std::wstring(peer.inbound ? L"Inbound" : L"Outbound") +
                L" TCP session\nReceived " + FormatBytes(peer.bytes_recv) +
                L" · sent " + FormatBytes(peer.bytes_sent), tip_detail,
                font_small_, C_MUTED,
                DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);
            break;
        }
    }

    void DrawReportedNetworkTopology(HDC dc, RECT card,
                                     const LiveState& live) {
        FillRound(dc, card, C_PANEL, C_BORDER);
        const std::wstring coverage = live.topology_online
            ? FormatUnsigned(live.local.peers) + L" direct · " +
              FormatUnsigned(live.topology.reporting_nodes) + L" / " +
              FormatUnsigned(live.topology.eligible_nodes) + L" reporting"
            : L"Waiting for reports";
        const int summary_w = S(208);
        RECT summary{card.right - summary_w - S(18), card.top + S(13),
                     card.right - S(18), card.top + S(43)};
        FillRound(dc, summary, C_PANEL_ALT, C_BORDER_SOFT, 5);
        DrawTextAt(dc, coverage, summary, font_small_, C_SUBTEXT,
                   DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        RECT title{card.left + S(20), card.top + S(12),
                   summary.left - S(12), card.top + S(44)};
        DrawTextAt(dc, L"Peer topology", title, font_heading_, C_TEXT);
        RECT subtitle{card.left + S(20), card.top + S(42),
                      card.right - S(20), card.top + S(78)};
        DrawTextAt(dc,
            L"Public links. Dotted means one-sided reporting, not inbound "
            L"direction. No addresses exposed.",
            subtitle, font_small_, C_MUTED,
            DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);

        RECT plot{card.left + S(18), card.top + S(82),
                  card.right - S(18), card.bottom - S(62)};
        FillRound(dc, plot, RGB(11, 14, 12), C_BORDER_SOFT, 7);
        InflateRect(&plot, -S(12), -S(10));
        network_graph_rect_ = plot;
        if (!live.topology_online) {
            RECT message{plot.left + S(24), plot.top + S(24),
                         plot.right - S(24), plot.bottom - S(24)};
            DrawTextAt(dc,
                L"A fresh network report is not available. Direct sessions remain available above.",
                message, font_body_, C_MUTED,
                DT_CENTER | DT_VCENTER | DT_WORDBREAK | DT_NOPREFIX);
            return;
        }
        if (live.topology.nodes.empty()) {
            DrawTextAt(dc, L"No network connections have been reported yet.",
                       plot, font_body_, C_MUTED,
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            return;
        }

        auto role_label = [](const std::string& role) -> std::wstring {
            if (role == "fleet") return L"Fleet";
            if (role == "miner") return L"Miner";
            if (role == "validator") return L"Validator";
            return L"Node";
        };
        auto role_color = [](const std::string& role) -> COLORREF {
            if (role == "fleet") return RGB(111, 139, 153);
            if (role == "validator") return RGB(143, 111, 189);
            return RGB(92, 145, 124);
        };

        const size_t limit = (plot.right - plot.left >= S(650)) ? 40 : 24;
        const size_t shown = std::min(limit, live.topology.nodes.size());
        const int cx = (plot.left + plot.right) / 2;
        const int cy = (plot.top + plot.bottom) / 2;
        const int radius_x = std::max<int>(
            S(95), static_cast<int>((plot.right - plot.left) / 2) - S(40));
        const int radius_y = std::max<int>(
            S(60), static_cast<int>((plot.bottom - plot.top) / 2) - S(36));
        constexpr double PI = 3.14159265358979323846;

        std::unordered_map<uint64_t, POINT> positions;
        positions.reserve(shown);
        std::unordered_map<uint64_t, std::string> node_roles;
        node_roles.reserve(shown);
        std::unordered_map<uint64_t, std::string> node_tip_states;
        node_tip_states.reserve(shown);
        std::unordered_set<uint64_t> direct_ids;
        std::unordered_map<uint64_t,
            const veld::node_gui::PeerSummary*> direct_peers;
        for (const auto& peer : live.peer_details) {
            if (!peer.identified) continue;
            direct_ids.insert(peer.anonymous_id);
            direct_peers.emplace(peer.anonymous_id, &peer);
        }
        if (live.local_topology_id != 0)
            direct_ids.insert(live.local_topology_id);

        std::vector<size_t> fleet_nodes;
        std::vector<size_t> validator_nodes;
        std::vector<size_t> operator_nodes;
        fleet_nodes.reserve(shown);
        validator_nodes.reserve(shown);
        operator_nodes.reserve(shown);
        for (size_t i = 0; i < shown; ++i) {
            const auto& node = live.topology.nodes[i];
            node_roles.emplace(node.anonymous_id, node.role);
            node_tip_states.emplace(node.anonymous_id, node.tip_state);
            if (node.role == "fleet")
                fleet_nodes.push_back(i);
            else if (node.role == "validator")
                validator_nodes.push_back(i);
            else
                operator_nodes.push_back(i);
        }

        auto sort_layer = [&](std::vector<size_t>& layer,
                              bool local_first) {
            std::stable_sort(layer.begin(), layer.end(),
                [&](size_t lhs, size_t rhs) {
                    const auto& a = live.topology.nodes[lhs];
                    const auto& b = live.topology.nodes[rhs];
                    if (local_first) {
                        const bool a_local =
                            a.anonymous_id == live.local_topology_id;
                        const bool b_local =
                            b.anonymous_id == live.local_topology_id;
                        if (a_local != b_local) return a_local;
                    }
                    if (a.role_index != b.role_index)
                        return a.role_index < b.role_index;
                    return a.anonymous_id < b.anonymous_id;
                });
        };
        sort_layer(fleet_nodes, false);
        sort_layer(validator_nodes, false);
        sort_layer(operator_nodes, true);

        auto place_layer = [&](const std::vector<size_t>& layer,
                               double scale, double phase) {
            if (layer.empty()) return;
            const double step = 2.0 * PI /
                static_cast<double>(layer.size());
            for (size_t ordinal = 0; ordinal < layer.size(); ++ordinal) {
                const auto& node = live.topology.nodes[layer[ordinal]];
                const double angle = phase + step *
                    static_cast<double>(ordinal);
                positions[node.anonymous_id] = {
                    cx + static_cast<int>(std::cos(angle) * radius_x * scale),
                    cy + static_cast<int>(std::sin(angle) * radius_y * scale)};
            }
        };
        place_layer(fleet_nodes, 0.54, -PI / 2.0);
        place_layer(validator_nodes, 0.77, -PI / 2.0 + PI / 5.0);
        place_layer(operator_nodes, 1.0, PI);

        auto draw_orbit = [&](double scale, COLORREF color) {
            HPEN orbit = CreatePen(PS_DOT, S(1), color);
            HGDIOBJ old_orbit = SelectObject(dc, orbit);
            HGDIOBJ old_brush = SelectObject(dc, GetStockObject(HOLLOW_BRUSH));
            const int orbit_x = static_cast<int>(radius_x * scale);
            const int orbit_y = static_cast<int>(radius_y * scale);
            Ellipse(dc, cx - orbit_x, cy - orbit_y,
                    cx + orbit_x, cy + orbit_y);
            SelectObject(dc, old_brush);
            SelectObject(dc, old_orbit);
            DeleteObject(orbit);
        };
        if (!fleet_nodes.empty())
            draw_orbit(0.54,
                MixColor(role_color("fleet"), RGB(11, 14, 12), 72));
        if (!validator_nodes.empty())
            draw_orbit(0.77,
                MixColor(role_color("validator"), RGB(11, 14, 12), 72));
        if (!operator_nodes.empty())
            draw_orbit(1.0,
                MixColor(role_color("node"), RGB(11, 14, 12), 72));

        uint64_t hovered_topology_id = 0;
        for (size_t i = 0; i < shown; ++i) {
            const auto& node = live.topology.nodes[i];
            const auto position = positions.find(node.anonymous_id);
            if (position == positions.end()) continue;
            RECT hit{position->second.x - S(40),
                     position->second.y - S(30),
                     position->second.x + S(40),
                     position->second.y + S(39)};
            if (PtInRect(&hit, hover_point_)) {
                hovered_topology_id = node.anonymous_id;
                break;
            }
        }
        std::unordered_set<uint64_t> hover_neighbors;
        if (hovered_topology_id != 0) {
            for (const auto& edge : live.topology.edges) {
                if (edge.first == hovered_topology_id)
                    hover_neighbors.insert(edge.second);
                else if (edge.second == hovered_topology_id)
                    hover_neighbors.insert(edge.first);
            }
        }

        auto draw_edge_path = [&](const POINT& from, const POINT& to,
                                  uint64_t first_id, uint64_t second_id) {
            const double dx = static_cast<double>(to.x - from.x);
            const double dy = static_cast<double>(to.y - from.y);
            const double length_squared = dx * dx + dy * dy;
            if (length_squared <= 1.0) return;
            double along = ((static_cast<double>(cx - from.x) * dx) +
                            (static_cast<double>(cy - from.y) * dy)) /
                           length_squared;
            along = std::max(0.0, std::min(1.0, along));
            const double nearest_x = static_cast<double>(from.x) + dx * along;
            const double nearest_y = static_cast<double>(from.y) + dy * along;
            const double center_dx = nearest_x - static_cast<double>(cx);
            const double center_dy = nearest_y - static_cast<double>(cy);
            const double center_distance = std::sqrt(
                center_dx * center_dx + center_dy * center_dy);
            if (center_distance >= static_cast<double>(S(64))) {
                MoveToEx(dc, from.x, from.y, nullptr);
                LineTo(dc, to.x, to.y);
                return;
            }

            const double length = std::sqrt(length_squared);
            double normal_x = -dy / length;
            double normal_y = dx / length;
            const double midpoint_x =
                (static_cast<double>(from.x) + to.x) / 2.0;
            const double midpoint_y =
                (static_cast<double>(from.y) + to.y) / 2.0;
            const double offset = static_cast<double>(S(78));
            const double plus_dx = midpoint_x + normal_x * offset - cx;
            const double plus_dy = midpoint_y + normal_y * offset - cy;
            const double minus_dx = midpoint_x - normal_x * offset - cx;
            const double minus_dy = midpoint_y - normal_y * offset - cy;
            const double plus_distance = plus_dx * plus_dx + plus_dy * plus_dy;
            const double minus_distance = minus_dx * minus_dx + minus_dy * minus_dy;
            if (minus_distance > plus_distance ||
                (std::abs(minus_distance - plus_distance) < 1.0 &&
                 ((first_id ^ second_id) & 1U) != 0)) {
                normal_x = -normal_x;
                normal_y = -normal_y;
            }
            POINT curve[4]{
                from,
                {from.x + static_cast<LONG>(dx / 3.0 + normal_x * offset),
                 from.y + static_cast<LONG>(dy / 3.0 + normal_y * offset)},
                {from.x + static_cast<LONG>(2.0 * dx / 3.0 + normal_x * offset),
                 from.y + static_cast<LONG>(2.0 * dy / 3.0 + normal_y * offset)},
                to};
            PolyBezier(dc, curve, 4);
        };

        for (const auto& edge : live.topology.edges) {
            const auto first = positions.find(edge.first);
            const auto second = positions.find(edge.second);
            if (first == positions.end() || second == positions.end()) continue;
            const bool direct = live.local_topology_id != 0 &&
                (edge.first == live.local_topology_id ||
                 edge.second == live.local_topology_id);
            const bool highlighted = hovered_topology_id != 0 &&
                (edge.first == hovered_topology_id ||
                 edge.second == hovered_topology_id);
            const auto first_role = node_roles.find(edge.first);
            const auto second_role = node_roles.find(edge.second);
            const COLORREF first_color = role_color(
                first_role == node_roles.end() ? "node" : first_role->second);
            const COLORREF second_color = role_color(
                second_role == node_roles.end() ? "node" : second_role->second);
            COLORREF edge_color = first_color == second_color
                ? first_color : MixColor(first_color, second_color, 50);
            const auto first_peer = direct_peers.find(edge.first);
            const auto second_peer = direct_peers.find(edge.second);
            const auto first_tip = node_tip_states.find(edge.first);
            const auto second_tip = node_tip_states.find(edge.second);
            const bool tip_differs =
                (first_peer != direct_peers.end() &&
                 first_peer->second->peer_tip_age_s >= 0 &&
                 !first_peer->second->exact_tip) ||
                (second_peer != direct_peers.end() &&
                 second_peer->second->peer_tip_age_s >= 0 &&
                 !second_peer->second->exact_tip) ||
                (first_peer == direct_peers.end() &&
                 first_tip != node_tip_states.end() &&
                 first_tip->second == "differs") ||
                (second_peer == direct_peers.end() &&
                 second_tip != node_tip_states.end() &&
                 second_tip->second == "differs");
            if (!edge.confirmed)
                edge_color = MixColor(edge_color, RGB(11, 14, 12), 48);
            else if (direct)
                edge_color = MixColor(edge_color, C_TEXT, 14);
            if (tip_differs) edge_color = C_WARN;
            if (hovered_topology_id != 0 && !highlighted)
                edge_color = MixColor(edge_color, RGB(11, 14, 12), 78);
            if (highlighted) {
                const auto hovered_role = node_roles.find(hovered_topology_id);
                const COLORREF hovered_color = role_color(
                    hovered_role == node_roles.end()
                        ? "node" : hovered_role->second);
                edge_color = MixColor(hovered_color, C_TEXT, 32);
            }
            // GDI only renders cosmetic dotted pens reliably at one pixel.
            // Keep one-sided reports visibly dotted even while a node is
            // highlighted; a thick solid underlay would erase that meaning.
            if (edge.confirmed) {
                HPEN underlay = CreatePen(PS_SOLID,
                                          highlighted ? S(7) :
                                          (direct ? S(4) : S(3)),
                                          RGB(16, 20, 17));
                HGDIOBJ old_underlay = SelectObject(dc, underlay);
                draw_edge_path(first->second, second->second,
                               edge.first, edge.second);
                SelectObject(dc, old_underlay);
                DeleteObject(underlay);
            }
            HPEN line = CreatePen(edge.confirmed ? PS_SOLID : PS_DOT,
                                  edge.confirmed
                                      ? (highlighted ? S(4) :
                                         (direct ? S(2) : S(1)))
                                      : S(1),
                                  edge_color);
            HGDIOBJ old_line = SelectObject(dc, line);
            draw_edge_path(first->second, second->second,
                           edge.first, edge.second);
            SelectObject(dc, old_line);
            DeleteObject(line);
        }

        // The center is a visual anchor for the network-wide view, not a
        // synthetic peer. Connections retain their real reported endpoints.
        const COLORREF center_color = RGB(95, 137, 116);
        for (int ring = 3; ring >= 1; --ring) {
            const int ring_radius = S(25 + ring * 5);
            HPEN center_ring = CreatePen(PS_SOLID, S(1),
                MixColor(center_color, RGB(11, 14, 12), 45 + ring * 10));
            HGDIOBJ old_ring = SelectObject(dc, center_ring);
            HGDIOBJ old_ring_brush = SelectObject(dc,
                GetStockObject(HOLLOW_BRUSH));
            Ellipse(dc, cx - ring_radius, cy - ring_radius,
                    cx + ring_radius, cy + ring_radius);
            SelectObject(dc, old_ring_brush);
            SelectObject(dc, old_ring);
            DeleteObject(center_ring);
        }
        DrawNetworkSphere(dc, cx, cy, S(25), RGB(20, 27, 23), center_color);
        RECT center_title{cx - S(34), cy - S(12),
                          cx + S(34), cy + S(4)};
        DrawTextAt(dc, L"VELD", center_title, font_small_, C_TEXT,
                   DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        RECT center_subtitle{cx - S(38), cy + S(2),
                             cx + S(38), cy + S(17)};
        DrawTextAt(dc, L"NETWORK", center_subtitle, font_small_, C_TEXT,
                   DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

        // Preserve valid public role ordinals while guaranteeing that a stale
        // or malformed report can never render two peers with the same label.
        std::unordered_map<uint64_t, uint32_t> display_ordinals;
        std::unordered_map<std::string, std::unordered_set<uint32_t>>
            used_role_ordinals;
        display_ordinals.reserve(shown);
        for (size_t i = 0; i < shown; ++i) {
            const auto& node = live.topology.nodes[i];
            if (node.role_index == 0) continue;
            auto& used = used_role_ordinals[node.role];
            if (used.insert(node.role_index).second)
                display_ordinals.emplace(node.anonymous_id, node.role_index);
        }
        for (size_t i = 0; i < shown; ++i) {
            const auto& node = live.topology.nodes[i];
            if (display_ordinals.count(node.anonymous_id) != 0) continue;
            auto& used = used_role_ordinals[node.role];
            uint32_t ordinal = 1;
            while (used.count(ordinal) != 0) ++ordinal;
            used.insert(ordinal);
            display_ordinals.emplace(node.anonymous_id, ordinal);
        }
        for (size_t i = 0; i < shown; ++i) {
            const auto& node = live.topology.nodes[i];
            const POINT center = positions[node.anonymous_id];
            const COLORREF color = role_color(node.role);
            const bool direct = direct_ids.count(node.anonymous_id) != 0;
            const auto peer_status = direct_peers.find(node.anonymous_id);
            const bool tip_unavailable = peer_status != direct_peers.end()
                ? peer_status->second->peer_tip_age_s < 0
                : node.tip_state == "unavailable" ||
                  node.tip_state == "stale";
            const bool tip_differs = peer_status != direct_peers.end()
                ? peer_status->second->peer_tip_age_s >= 0 &&
                  !peer_status->second->exact_tip
                : node.tip_state == "differs";
            const COLORREF status_color = tip_differs
                ? C_WARN : (tip_unavailable ? C_MUTED : color);
            const int radius = direct ? S(18) : S(15);
            RECT hit{center.x - S(40), center.y - S(30),
                     center.x + S(40), center.y + S(39)};
            const bool hovered = PtInRect(&hit, hover_point_);
            const bool connected_to_hover =
                hover_neighbors.count(node.anonymous_id) != 0;
            const bool unrelated_to_hover = hovered_topology_id != 0 &&
                !hovered && !connected_to_hover;
            if (direct) {
                const COLORREF ring_color = connected_to_hover
                    ? MixColor(status_color, C_TEXT, 38)
                    : MixColor(status_color, C_TEXT, 18);
                HPEN ring = CreatePen(PS_SOLID,
                    connected_to_hover ? S(2) : S(1),
                    ring_color);
                HGDIOBJ old_ring = SelectObject(dc, ring);
                HGDIOBJ old_brush = SelectObject(dc, GetStockObject(HOLLOW_BRUSH));
                Ellipse(dc, center.x - radius - S(4), center.y - radius - S(4),
                        center.x + radius + S(4), center.y + radius + S(4));
                SelectObject(dc, old_brush);
                SelectObject(dc, old_ring);
                DeleteObject(ring);
            }
            DrawNetworkSphere(dc, center.x, center.y, hovered ? radius + S(2) : radius,
                              MixColor(status_color, RGB(10, 13, 11),
                                  unrelated_to_hover ? 82 : 62),
                              (hovered || connected_to_hover)
                                  ? MixColor(status_color, C_TEXT, 46)
                                  : (unrelated_to_hover
                                      ? MixColor(status_color,
                                          RGB(10, 13, 11), 62)
                                      : status_color));
            const uint32_t ordinal = display_ordinals[node.anonymous_id];
            const std::wstring label = role_label(node.role) + L" " +
                (ordinal < 10 ? std::wstring(L"0") : std::wstring()) +
                FormatUnsigned(ordinal);
            RECT label_rect{center.x - S(45), center.y + S(18),
                            center.x + S(45), center.y + S(38)};
            DrawTextAt(dc, label, label_rect, font_small_,
                       tip_differs ? C_WARN : C_TEXT,
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            network_topology_rects_.push_back(hit);
            network_topology_indices_.push_back(i);
        }
        if (live.topology.nodes.size() > shown) {
            RECT more{plot.right - S(130), plot.bottom - S(22),
                      plot.right, plot.bottom};
            DrawTextAt(dc, L"+" +
                FormatUnsigned(live.topology.nodes.size() - shown) +
                L" more", more, font_small_, C_MUTED,
                DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }

        const int relationship_y = card.bottom - S(41);
        const int status_y = card.bottom - S(17);
        const int legend_left = card.left + S(20);
        const int legend_right = card.right - S(20);
        const int legend_col = (legend_right - legend_left) / 3;
        auto legend = [&](int x, int label_right, int y, bool dotted,
                          COLORREF color, const wchar_t* text) {
            HPEN pen = CreatePen(PS_SOLID, S(1), color);
            HGDIOBJ old = SelectObject(dc, pen);
            if (dotted) {
                const int extent = S(27);
                const int dash = std::max(1, S(3));
                const int stride = std::max(dash + 1, S(7));
                for (int offset = 0; offset < extent; offset += stride) {
                    MoveToEx(dc, x + offset, y, nullptr);
                    LineTo(dc, x + std::min(extent, offset + dash), y);
                }
            } else {
                MoveToEx(dc, x, y, nullptr);
                LineTo(dc, x + S(27), y);
            }
            SelectObject(dc, old);
            DeleteObject(pen);
            RECT label{x + S(35), y - S(10), label_right, y + S(10)};
            DrawTextAt(dc, text, label, font_small_, C_MUTED);
        };
        legend(legend_left, legend_left + legend_col, relationship_y,
               false, C_MUTED, L"Seen by both");
        legend(legend_left + legend_col,
               legend_left + 2 * legend_col, relationship_y,
               true, C_MUTED, L"One-sided");
        legend(legend_left + 2 * legend_col, legend_right, relationship_y,
               false, MixColor(C_TEXT, role_color("node"), 48),
               L"Direct session");
        const int status_x = legend_left;
        HBRUSH warning_brush = CreateSolidBrush(C_WARN);
        HGDIOBJ old_warning_brush = SelectObject(dc, warning_brush);
        HGDIOBJ old_warning_pen = SelectObject(dc, GetStockObject(NULL_PEN));
        Ellipse(dc, status_x, status_y - S(4),
                status_x + S(8), status_y + S(4));
        SelectObject(dc, old_warning_pen);
        SelectObject(dc, old_warning_brush);
        DeleteObject(warning_brush);
        RECT status_label{status_x + S(16), status_y - S(10),
                          legend_left + legend_col, status_y + S(10)};
        DrawTextAt(dc, L"Tip differs", status_label, font_small_, C_MUTED);
        const int unknown_x = legend_left + legend_col;
        HBRUSH unknown_brush = CreateSolidBrush(C_MUTED);
        HGDIOBJ old_unknown_brush = SelectObject(dc, unknown_brush);
        HGDIOBJ old_unknown_pen = SelectObject(dc, GetStockObject(NULL_PEN));
        Ellipse(dc, unknown_x, status_y - S(4),
                unknown_x + S(8), status_y + S(4));
        SelectObject(dc, old_unknown_pen);
        SelectObject(dc, old_unknown_brush);
        DeleteObject(unknown_brush);
        RECT unknown_label{unknown_x + S(16), status_y - S(10),
                           legend_right, status_y + S(10)};
        DrawTextAt(dc, L"Status unavailable", unknown_label,
                   font_small_, C_MUTED);

        for (size_t i = 0; i < network_topology_rects_.size(); ++i) {
            if (!PtInRect(&network_topology_rects_[i], hover_point_)) continue;
            const auto& node = live.topology.nodes[network_topology_indices_[i]];
            const bool direct = direct_ids.count(node.anonymous_id) != 0;
            const veld::node_gui::PeerSummary* direct_peer = nullptr;
            if (direct) {
                for (const auto& peer : live.peer_details) {
                    if (peer.identified &&
                        peer.anonymous_id == node.anonymous_id) {
                        direct_peer = &peer;
                        break;
                    }
                }
            }
            const RECT tip = NetworkTooltipRect(
                network_topology_rects_[i], S(260), S(76));
            FillRound(dc, tip, RGB(24, 28, 25), RGB(92, 102, 96), 6);
            RECT tip_title{tip.left + S(10), tip.top + S(6),
                           tip.right - S(10), tip.top + S(29)};
            DrawTextAt(dc, role_label(node.role) +
                (direct_peer
                    ? std::wstring(direct_peer->inbound
                        ? L" · inbound direct session"
                        : L" · outbound direct session")
                    : (direct ? L" · this node" : L" · network report")),
                tip_title, font_small_, C_TEXT);
            RECT tip_detail{tip.left + S(10), tip.top + S(29),
                            tip.right - S(10), tip.bottom - S(5)};
            if (direct_peer) {
                const std::wstring tip_state = direct_peer->exact_tip
                    ? L"Exact tip agreement"
                    : (direct_peer->lag_blocks > 0
                        ? FormatUnsigned(static_cast<uint64_t>(
                              direct_peer->lag_blocks)) + L" blocks behind"
                        : (direct_peer->lag_blocks < 0
                            ? FormatUnsigned(static_cast<uint64_t>(
                                  -direct_peer->lag_blocks)) + L" blocks ahead"
                            : (direct_peer->peer_tip_age_s < 0
                                ? L"Tip unavailable"
                                : L"Different tip at the same height")));
                DrawTextAt(dc, tip_state + L"\nReceived " +
                    FormatBytes(direct_peer->bytes_recv) + L" · sent " +
                    FormatBytes(direct_peer->bytes_sent), tip_detail,
                    font_small_, C_MUTED,
                    DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);
            } else {
                const std::wstring state = node.tip_state == "exact"
                    ? L"Exact network tip"
                    : (node.tip_state == "differs"
                        ? L"Reported tip differs"
                        : (node.tip_state == "stale"
                            ? L"Tip report is stale"
                            : L"Tip status unavailable"));
                DrawTextAt(dc, state + L"\nLast reported " +
                           FormatAge(node.updated_at),
                           tip_detail, font_small_, C_MUTED);
            }
            break;
        }
    }

    void DrawUnifiedNetworkTopology(HDC dc, RECT card,
                                    const LiveState& live) {
        // A public aggregate adds context, but it is never a prerequisite for
        // displaying the node's authoritative direct sessions.
        if (!live.topology_online || live.topology.nodes.empty() ||
            live.local_topology_id == 0) {
            DrawDirectPeerTopology(dc, card, live);
            return;
        }

        LiveState merged = live;
        const std::string local_role = mining_enabled_ ? "miner" : "node";
        auto normalize_role = [](const std::string& role) {
            if (role == "fleet" || role == "miner" ||
                role == "validator" || role == "node") return role;
            return std::string("node");
        };
        for (auto& node : merged.topology.nodes)
            node.role = normalize_role(node.role);
        for (auto& peer : merged.peer_details) {
            peer.role = normalize_role(peer.role);
            // Only canonical fleet anchors have a stable fleet ordinal.  Older
            // node-only binaries could advertise the shared no-mine service
            // bit and arrive here as an unindexed fleet peer.  Treat that
            // legacy form as a regular node so it merges with the public Node
            // identity instead of rendering a duplicate "Fleet 05".
            if (peer.role == "fleet" && peer.role_index == 0)
                peer.role = "node";
        }

        auto replace_topology_id = [&](uint64_t previous, uint64_t current) {
            if (previous == 0 || current == 0 || previous == current) return;
            for (auto& node : merged.topology.nodes) {
                if (node.anonymous_id == previous) {
                    node.anonymous_id = current;
                    break;
                }
            }
            for (auto& edge : merged.topology.edges) {
                if (edge.first == previous) edge.first = current;
                if (edge.second == previous) edge.second = current;
            }
        };

        auto node_for_id = [&](uint64_t id)
            -> veld::node_gui::TopologyNode* {
            for (auto& node : merged.topology.nodes) {
                if (node.anonymous_id == id) return &node;
            }
            return nullptr;
        };
        auto candidate_ids = [&](const std::string& role,
                                 uint32_t role_index,
                                 const std::unordered_set<uint64_t>& claimed) {
            std::vector<uint64_t> candidates;
            for (const auto& node : merged.topology.nodes) {
                if (node.role != role || claimed.count(node.anonymous_id) != 0)
                    continue;
                if (role_index != 0 && node.role_index != role_index) continue;
                candidates.push_back(node.anonymous_id);
            }
            std::sort(candidates.begin(), candidates.end(),
                [&](uint64_t lhs, uint64_t rhs) {
                    const auto* a = node_for_id(lhs);
                    const auto* b = node_for_id(rhs);
                    if (!a || !b) return lhs < rhs;
                    const bool a_unindexed = a->role_index == 0;
                    const bool b_unindexed = b->role_index == 0;
                    if (a_unindexed != b_unindexed) return !a_unindexed;
                    if (a->role_index != b->role_index)
                        return a->role_index < b->role_index;
                    return lhs < rhs;
                });
            return candidates;
        };
        auto update_from_peer = [&](uint64_t id,
                                    const veld::node_gui::PeerSummary& peer) {
            auto* node = node_for_id(id);
            if (!node) return;
            node->updated_at = merged.topology.generated_at;
            node->role = peer.role;
            if (peer.role_index != 0) node->role_index = peer.role_index;
            node->tip_state = peer.peer_tip_age_s < 0
                ? "unavailable" : (peer.exact_tip ? "exact" : "differs");
        };
        auto update_local = [&]() {
            auto* node = node_for_id(merged.local_topology_id);
            if (!node) return;
            node->updated_at = merged.topology.generated_at;
            node->role = local_role;
            if (topology_role_index_ != 0)
                node->role_index = topology_role_index_;
            node->tip_state = "exact";
        };

        std::unordered_set<uint64_t> claimed;

        // Direct sessions are newer than the aggregate report. Reconcile peers
        // with stable public role ordinals before considering anonymous IDs so
        // a restarted fleet node cannot appear twice or become "Fleet 05".
        for (const auto& peer : merged.peer_details) {
            if (!peer.identified || peer.anonymous_id == 0) continue;
            if (node_for_id(peer.anonymous_id)) {
                claimed.insert(peer.anonymous_id);
                update_from_peer(peer.anonymous_id, peer);
                continue;
            }
            if (peer.role_index == 0) continue;
            const auto candidates = candidate_ids(
                peer.role, peer.role_index, claimed);
            if (candidates.size() != 1) continue;
            replace_topology_id(candidates.front(), peer.anonymous_id);
            claimed.insert(peer.anonymous_id);
            update_from_peer(peer.anonymous_id, peer);
        }

        bool local_id_present = node_for_id(merged.local_topology_id) != nullptr;
        if (local_id_present) {
            claimed.insert(merged.local_topology_id);
            update_local();
        } else if (topology_role_index_ != 0) {
            const auto candidates = candidate_ids(
                local_role, topology_role_index_, claimed);
            if (candidates.size() == 1) {
                replace_topology_id(candidates.front(),
                                    merged.local_topology_id);
                claimed.insert(merged.local_topology_id);
                update_local();
                local_id_present = true;
            }
        }

        // Public operator IDs rotate independently of direct-session IDs. If
        // one aggregate entry remains after accounting for same-role peers, it
        // is this node. Reserve the first public ordinal for the local operator
        // and bind remaining entries to direct peers in ordinal order.
        if (!local_id_present) {
            const auto local_candidates = candidate_ids(local_role, 0, claimed);
            size_t unmatched_same_role = 0;
            for (const auto& peer : merged.peer_details) {
                if (!peer.identified || peer.anonymous_id == 0 ||
                    peer.role != local_role ||
                    claimed.count(peer.anonymous_id) != 0) continue;
                ++unmatched_same_role;
            }
            if (local_candidates.size() > unmatched_same_role) {
                replace_topology_id(local_candidates.front(),
                                    merged.local_topology_id);
                claimed.insert(merged.local_topology_id);
                update_local();
                local_id_present = true;
            }
        }

        for (const auto& peer : merged.peer_details) {
            if (!peer.identified || peer.anonymous_id == 0 ||
                claimed.count(peer.anonymous_id) != 0) continue;
            auto candidates = candidate_ids(peer.role, peer.role_index, claimed);
            if (candidates.empty() && peer.role_index != 0)
                candidates = candidate_ids(peer.role, 0, claimed);
            if (!candidates.empty()) {
                replace_topology_id(candidates.front(), peer.anonymous_id);
                claimed.insert(peer.anonymous_id);
                update_from_peer(peer.anonymous_id, peer);
            }
        }

        const uint64_t observed_at = merged.topology.generated_at;
        if (!local_id_present && merged.topology.nodes.size() < 256) {
            veld::node_gui::TopologyNode local;
            local.anonymous_id = merged.local_topology_id;
            local.updated_at = observed_at;
            local.role_index = topology_role_index_;
            local.role = local_role;
            local.tip_state = "exact";
            merged.topology.nodes.push_back(std::move(local));
            claimed.insert(merged.local_topology_id);
            local_id_present = true;
        }

        std::unordered_set<uint64_t> node_ids;
        for (const auto& node : merged.topology.nodes)
            node_ids.insert(node.anonymous_id);
        for (const auto& peer : merged.peer_details) {
            if (!peer.identified || peer.anonymous_id == 0) continue;
            if (node_ids.insert(peer.anonymous_id).second &&
                merged.topology.nodes.size() < 256) {
                veld::node_gui::TopologyNode node;
                node.anonymous_id = peer.anonymous_id;
                node.updated_at = observed_at;
                node.role_index = peer.role_index;
                node.role = peer.role;
                node.tip_state = peer.peer_tip_age_s < 0
                    ? "unavailable"
                    : (peer.exact_tip ? "exact" : "differs");
                merged.topology.nodes.push_back(std::move(node));
            }
            if (local_id_present && merged.topology.edges.size() < 1024)
                merged.topology.edges.push_back(
                    {merged.local_topology_id, peer.anonymous_id, true});
        }

        std::vector<veld::node_gui::TopologyEdge> normalized_edges;
        normalized_edges.reserve(merged.topology.edges.size());
        std::unordered_map<std::string, size_t> normalized_edge_indices;
        for (const auto& edge : merged.topology.edges) {
            if (edge.first == 0 || edge.second == 0 ||
                edge.first == edge.second ||
                node_ids.count(edge.first) == 0 ||
                node_ids.count(edge.second) == 0) continue;
            const uint64_t first = std::min(edge.first, edge.second);
            const uint64_t second = std::max(edge.first, edge.second);
            const std::string key = std::to_string(first) + ":" +
                std::to_string(second);
            const auto existing = normalized_edge_indices.find(key);
            if (existing == normalized_edge_indices.end()) {
                normalized_edge_indices.emplace(key,
                    normalized_edges.size());
                normalized_edges.push_back({first, second, edge.confirmed});
            } else if (edge.confirmed) {
                normalized_edges[existing->second].confirmed = true;
            }
        }
        merged.topology.edges = std::move(normalized_edges);
        merged.topology.eligible_nodes = std::max<uint64_t>(
            merged.topology.eligible_nodes, merged.topology.nodes.size());
        DrawReportedNetworkTopology(dc, card, merged);
    }

    void DrawNetwork(HDC dc, const RECT& client, const LiveState& live) {
        DrawPageHeader(dc, client, L"Network",
                       L"Network-wide map and direct peer health.", live);
        const int left = S(292);
        const int right = client.right - S(34);
        const int gap = S(14);
        const int top = S(132);
        const int metrics_h = S(96);
        const int card_w = (right - left - 3 * gap) / 4;
        DrawMetricCard(dc, {left, top, left + card_w, top + metrics_h},
                       L"Direct peers", live.local_online
                           ? FormatUnsigned(live.local.peers) : L"—",
                       L"this node's P2P sessions");
        DrawMetricCard(dc, {left + card_w + gap, top,
                       left + 2 * card_w + gap, top + metrics_h},
                       L"Inbound", live.peer_details_online
                           ? FormatUnsigned(live.inbound_peers) : L"—",
                       live.inbound_peers > 0 ? L"remote-initiated · reachable" :
                       (reachable_choice_ ? L"awaiting remote peer" :
                                            L"outbound-only mode"));
        DrawMetricCard(dc, {left + 2 * (card_w + gap), top,
                       left + 3 * card_w + 2 * gap, top + metrics_h},
                       L"Outbound", live.peer_details_online
                           ? FormatUnsigned(live.outbound_peers) : L"—",
                       L"locally dialed");
        DrawMetricCard(dc, {left + 3 * (card_w + gap), top, right,
                       top + metrics_h}, L"Exact tip agreement",
                       live.peer_details_online
                           ? FormatUnsigned(live.exact_tip_peers) + L" / " +
                             FormatUnsigned(live.peer_details.size()) : L"—",
                       L"peer-announced tips",
                       live.exact_tip_peers ? C_GREEN : C_TEXT);

        const int bottom_bottom = client.bottom - S(28);
        const int bottom_top = bottom_bottom - S(168);
        const int main_top = top + metrics_h + gap;
        const int main_bottom = bottom_top - gap;
        const int content_w = right - left;
        const int health_w = std::clamp(content_w * 30 / 100, S(280), S(330));
        const int topology_right = right - health_w - gap;
        RECT topology{left, main_top, topology_right, main_bottom};
        RECT health{topology_right + gap, main_top, right, main_bottom};
        DrawUnifiedNetworkTopology(dc, topology, live);

        FillRound(dc, health, C_PANEL, C_BORDER);
        RECT health_title{health.left + S(18), health.top + S(12),
                          health.right - S(18), health.top + S(44)};
        DrawTextAt(dc, L"Connection health", health_title,
                   FitSingleLineFont(dc, L"Connection health", health_title,
                                     {font_heading_, font_body_, font_small_}),
                   C_TEXT);
        const bool healthy = live.peer_details_online &&
            !live.peer_details.empty() && live.exact_tip_peers > 0;
        const bool waiting = !live.peer_details_online ||
            live.peer_details.empty();
        RECT health_state{health.left + S(18), health.top + S(50),
                          health.right - S(18), health.top + S(82)};
        DrawTextAt(dc, waiting ? L"Waiting" :
                   (healthy ? L"Healthy" : L"Check peer tips"), health_state,
                   font_heading_, waiting ? C_MUTED :
                   (healthy ? C_GREEN : C_WARN));
        auto health_row = [&](int row, const std::wstring& label,
                              const std::wstring& value) {
            const int y = health.top + S(86 + row * 46);
            if (row > 0) {
                HPEN divider = CreatePen(PS_SOLID, S(1), C_BORDER_SOFT);
                HGDIOBJ old = SelectObject(dc, divider);
                MoveToEx(dc, health.left + S(18), y - S(6), nullptr);
                LineTo(dc, health.right - S(18), y - S(6));
                SelectObject(dc, old);
                DeleteObject(divider);
            }
            RECT label_r{health.left + S(18), y,
                         health.right - S(18), y + S(18)};
            DrawTextAt(dc, label, label_r, font_small_, C_MUTED);
            RECT value_r{health.left + S(18), y + S(18),
                          health.right - S(18), y + S(40)};
            DrawTextAt(dc, value, value_r,
                       FitSingleLineFont(dc, value, value_r,
                                         {font_body_, font_small_}), C_TEXT);
        };
        health_row(0, L"Tip agreement", live.peer_details_online
            ? FormatUnsigned(live.exact_tip_peers) + L" of " +
              FormatUnsigned(live.peer_details.size()) : L"Unavailable");
        health_row(1, L"Traffic in", live.peer_details_online
            ? FormatByteRate(live.peer_recv_rate) : L"Unavailable");
        health_row(2, L"Traffic out", live.peer_details_online
            ? FormatByteRate(live.peer_send_rate) : L"Unavailable");
        const std::wstring transport = tor_choice_ ? L"Tor only" :
            (live.port_mapped ? L"Clearnet · automatic mapping" :
             (live.inbound_peers > 0 ? L"Clearnet · inbound verified" :
              (reachable_choice_ ? L"Clearnet · awaiting inbound" :
                                   L"Clearnet · outbound only")));
        health_row(3, L"Transport", transport);

        const int split = left + (content_w * 42) / 100;
        RECT distribution{left, bottom_top, split - gap / 2, bottom_bottom};
        RECT events{split + gap / 2, bottom_top, right, bottom_bottom};
        FillRound(dc, distribution, C_PANEL, C_BORDER);
        FillRound(dc, events, C_PANEL, C_BORDER);
        RECT dist_title{distribution.left + S(18), distribution.top + S(11),
                        distribution.right - S(18), distribution.top + S(40)};
        DrawTextAt(dc, L"Peer distribution", dist_title, font_heading_, C_TEXT);
        auto distribution_row = [&](int row, const std::wstring& label,
                                    const std::wstring& value) {
            const int y = distribution.top + S(46 + row * 27);
            RECT label_r{distribution.left + S(18), y,
                         distribution.right - S(72), y + S(24)};
            RECT value_r{distribution.right - S(72), y,
                         distribution.right - S(18), y + S(24)};
            DrawTextAt(dc, label, label_r, font_small_, C_SUBTEXT);
            DrawTextAt(dc, value, value_r, font_small_, C_TEXT,
                       DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        };
        distribution_row(0, L"Inbound / outbound",
            live.peer_details_online
                ? FormatUnsigned(live.inbound_peers) + L" / " +
                  FormatUnsigned(live.outbound_peers) : L"—");
        distribution_row(1, L"Known peer endpoints",
            live.peer_details_online
                ? FormatUnsigned(live.known_peer_count) : L"—");
        distribution_row(2, L"Data received", live.peer_details_online
            ? FormatBytes(live.peer_bytes_recv) : L"—");
        distribution_row(3, L"Data sent", live.peer_details_online
            ? FormatBytes(live.peer_bytes_sent) : L"—");

        RECT events_title{events.left + S(18), events.top + S(11),
                          events.right - S(18), events.top + S(40)};
        DrawTextAt(dc, L"Recent network events", events_title,
                   font_heading_, C_TEXT);
        if (live.network_events.empty()) {
            RECT empty{events.left + S(18), events.top + S(48),
                       events.right - S(18), events.bottom - S(12)};
            DrawTextAt(dc, L"No connection changes during this session.",
                       empty, font_small_, C_MUTED);
        } else {
            const size_t shown = std::min<size_t>(4, live.network_events.size());
            for (size_t i = 0; i < shown; ++i) {
                const int y = events.top + S(44 + static_cast<int>(i) * 28);
                const auto& event = live.network_events[i];
                RECT text{events.left + S(18), y,
                          events.right - S(92), y + S(25)};
                DrawTextAt(dc, event.text, text, font_small_,
                           event.warning ? C_WARN : C_SUBTEXT,
                           DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX |
                           DT_END_ELLIPSIS);
                RECT age{events.right - S(92), y,
                         events.right - S(18), y + S(25)};
                DrawTextAt(dc, FormatAge(event.timestamp), age, font_small_,
                           C_MUTED, DT_RIGHT | DT_VCENTER | DT_SINGLELINE |
                           DT_NOPREFIX);
            }
        }
    }

    std::wstring BuildRedactedDiagnostics(const LiveState& live) const {
        std::wostringstream out;
        out << L"Veld Node diagnostics\r\n"
            << L"Version: " << Utf8ToWide(veld::CLIENT_VERSION) << L"\r\n"
            << L"Network: Mainnet\r\n"
            << L"Node process: " << (live.process_running ? L"running" : L"stopped")
            << L"\r\n"
            << L"Local status: " << (live.local_online ? L"online" : L"offline")
            << L"\r\n"
            << L"Height: " << live.local.height << L"\r\n"
            << L"Peers: " << live.local.peers << L"\r\n"
            << L"Mempool: " << live.local.mempool_size << L"\r\n"
            << L"Local chain data: " << FormatBytes(live.chain_bytes) << L"\r\n"
            << L"Sync mode: "
            << (full_ibd_choice_ ? L"full IBD" : L"signed snapshot with independent genesis validation")
            << L"\r\n"
            << L"Snapshot bootstrap: available\r\n"
            << L"Transport: " << (tor_choice_ ? L"Tor only" :
                (reachable_choice_ ? L"Clearnet reachable" : L"Clearnet outbound"))
            << L"\r\n"
            << L"Mining configured: " << (mining_enabled_ ? L"yes" : L"no")
            << L"\r\n"
            << L"Mining state: " << (live.mining_status_online
                ? MiningStateLabel(live.mining.work_state) : L"unavailable")
            << L"\r\n"
            << L"Hashrate: " << (live.mining_status_online
                ? FormatHashrate(live.mining.hashrate) : L"unavailable")
            << L"\r\n"
            << L"Workers: " << (live.mining_status_online
                ? FormatUnsigned(live.mining.threads)
                : FormatUnsigned(mining_thread_count_)) << L"\r\n";
        return out.str();
    }

    void DrawLogs(HDC dc, const RECT& client, const LiveState& live) {
        DrawPageHeader(dc, client, L"Logs", L"Recent local node output.", live);
        const int left = S(292);
        const int right = client.right - S(34);
        RECT panel{left, S(132), right, client.bottom - S(30)};
        FillRound(dc, panel, C_PANEL, C_BORDER);
        RECT heading{panel.left + S(22), panel.top + S(14),
                     panel.right - S(380), panel.top + S(48)};
        DrawTextAt(dc, L"node-gui-node.log", heading, font_heading_, C_TEXT);
        RECT path{panel.left + S(22), panel.top + S(48),
                  panel.right - S(380), panel.top + S(78)};
        DrawTextAt(dc, (state_dir_ / L"node-gui-node.log").wstring(), path,
                   font_small_, C_MUTED, DT_LEFT | DT_VCENTER | DT_SINGLELINE |
                   DT_NOPREFIX | DT_END_ELLIPSIS);
        copy_diagnostics_button_ = {panel.right - S(354), panel.top + S(20),
                                    panel.right - S(192), panel.top + S(64)};
        const bool copied = std::chrono::steady_clock::now() <
            diagnostics_copied_until_;
        DrawButton(dc, copy_diagnostics_button_,
                   copied ? L"Diagnostics copied" : L"Copy diagnostics", true);
        open_log_button_ = {panel.right - S(184), panel.top + S(20),
                            panel.right - S(22), panel.top + S(64)};
        DrawButton(dc, open_log_button_, L"Open log folder",
                   std::filesystem::exists(state_dir_));

        RECT separator{panel.left + S(22), panel.top + S(88),
                       panel.right - S(22), panel.top + S(89)};
        HBRUSH line = CreateSolidBrush(C_BORDER_SOFT);
        FillRect(dc, &separator, line);
        DeleteObject(line);

        RECT log_area{panel.left + S(22), panel.top + S(104),
                      panel.right - S(22), panel.bottom - S(54)};
        if (live.log_lines.empty()) {
            DrawTextAt(dc,
                live.process_running
                    ? L"Waiting for app-managed node output..."
                    : L"Start the node from this app to create a local log.",
                log_area, font_body_, C_MUTED,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        } else {
            const int line_h = S(22);
            const int visible = std::max(
                1, static_cast<int>((log_area.bottom - log_area.top) / line_h));
            const size_t first = live.log_lines.size() > static_cast<size_t>(visible)
                ? live.log_lines.size() - static_cast<size_t>(visible) : 0;
            int y = log_area.top;
            for (size_t i = first; i < live.log_lines.size(); ++i, y += line_h) {
                RECT row{log_area.left, y, log_area.right, y + line_h};
                COLORREF color = C_SUBTEXT;
                if (live.log_lines[i].find(L"FATAL") != std::wstring::npos)
                    color = RGB(226, 105, 105);
                else if (live.log_lines[i].find(L"WARN") != std::wstring::npos)
                    color = C_WARN;
                DrawTextAt(dc, live.log_lines[i], row, font_log_, color,
                           DT_LEFT | DT_VCENTER | DT_SINGLELINE |
                           DT_NOPREFIX | DT_END_ELLIPSIS);
            }
        }
        RECT note{panel.left + S(22), panel.bottom - S(45),
                  panel.right - S(22), panel.bottom - S(14)};
        DrawTextAt(dc, L"Local file | bounded view | refreshes automatically",
                   note, font_small_, C_MUTED);
    }

    void DrawToggle(HDC dc, RECT r, bool on, bool enabled) {
        FillRound(dc, r, on ? RGB(50, 62, 52) : RGB(31, 35, 32),
                  enabled ? C_BORDER : C_BORDER_SOFT, 14);
        const int diameter = S(18);
        const int cx = on ? r.right - S(14) : r.left + S(14);
        const int cy = (r.top + r.bottom) / 2;
        HBRUSH brush = CreateSolidBrush(on && enabled ? C_TEXT : C_MUTED);
        HPEN pen = CreatePen(PS_NULL, 0, C_MUTED);
        HGDIOBJ old_b = SelectObject(dc, brush);
        HGDIOBJ old_p = SelectObject(dc, pen);
        Ellipse(dc, cx - diameter / 2, cy - diameter / 2,
                cx + diameter / 2, cy + diameter / 2);
        SelectObject(dc, old_p);
        SelectObject(dc, old_b);
        DeleteObject(pen);
        DeleteObject(brush);
    }

    void DrawSettingRow(HDC dc, RECT row, const std::wstring& title,
                        const std::wstring& detail, bool value, bool enabled,
                        RECT& toggle) {
        FillRound(dc, row, C_PANEL, C_BORDER);
        RECT title_r{row.left + S(22), row.top + S(8),
                     row.right - S(100), row.top + S(35)};
        DrawTextAt(dc, title, title_r, font_heading_,
                   enabled ? C_TEXT : C_MUTED,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX |
                   DT_END_ELLIPSIS);
        RECT detail_r{row.left + S(22), row.top + S(35),
                      row.right - S(100), row.bottom - S(6)};
        DrawTextAt(dc, detail, detail_r, font_small_,
                   enabled ? C_SUBTEXT : C_MUTED,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX |
                   DT_END_ELLIPSIS);
        toggle = {row.right - S(78), row.top + S(22),
                  row.right - S(22), row.top + S(50)};
        DrawToggle(dc, toggle, value, enabled);
    }

    void DrawPresetButton(HDC dc, RECT r, const std::wstring& label,
                          bool selected) {
        const bool hovered = PtInRect(&r, hover_point_);
        FillRound(dc, r, selected ? C_PANEL_ALT :
                  (hovered ? RGB(24, 28, 25) : C_BG),
                  selected ? RGB(112, 121, 115) :
                  (hovered ? C_BORDER : C_BORDER_SOFT), 5);
        DrawTextAt(dc, label, r, font_small_, selected ? C_TEXT : C_SUBTEXT,
                   DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    }

    void DrawSettings(HDC dc, const RECT& client, const LiveState& live) {
        DrawPageHeader(dc, client, L"Settings",
                       L"Local app preferences and paths.", live);
        const int left = S(292);
        const int right = client.right - S(34);
        const int top = S(132);
        const int gap = S(8);
        const int row_h = S(78);
        const int mining_row_h = S(112);
        RECT mining_row{left, top, right, top + mining_row_h};
        FillRound(dc, mining_row, C_PANEL, C_BORDER);
        RECT mining_title{left + S(22), top + S(12), right - S(100),
                          top + S(43)};
        DrawTextAt(dc, L"CPU mining", mining_title, font_heading_, C_TEXT);
        RECT mining_detail{left + S(22), top + S(39), right - S(100),
                           top + S(68)};
        DrawTextAt(dc, live.process_running
            ? L"Worker changes apply at the next app-managed start."
            : L"Capacity profiles adapt to this computer; custom sets an exact count.",
            mining_detail, font_small_, C_SUBTEXT);
        mining_mode_toggle_ = {right - S(78), top + S(22),
                               right - S(22), top + S(50)};
        DrawToggle(dc, mining_mode_toggle_, mining_enabled_, true);
        const int preset_top = top + S(78);
        const int preset_w = S(122);
        preset_eco_button_ = {left + S(22), preset_top,
                              left + S(22) + preset_w, preset_top + S(30)};
        preset_balanced_button_ = {preset_eco_button_.right + S(7), preset_top,
                                   preset_eco_button_.right + S(7) + preset_w,
                                   preset_top + S(30)};
        preset_max_button_ = {preset_balanced_button_.right + S(7), preset_top,
                              preset_balanced_button_.right + S(7) + preset_w,
                              preset_top + S(30)};
        DrawPresetButton(dc, preset_eco_button_, PresetCapacityLabel(0),
                         mining_preset_ == 0);
        DrawPresetButton(dc, preset_balanced_button_, PresetCapacityLabel(1),
                         mining_preset_ == 1);
        DrawPresetButton(dc, preset_max_button_, PresetCapacityLabel(2),
                         mining_preset_ == 2);
        preset_plus_button_ = {right - S(52), preset_top, right - S(22),
                               preset_top + S(30)};
        preset_minus_button_ = {right - S(184), preset_top, right - S(154),
                                preset_top + S(30)};
        DrawPresetButton(dc, preset_minus_button_, L"-", false);
        DrawPresetButton(dc, preset_plus_button_, L"+", false);
        RECT thread_value{preset_minus_button_.right, preset_top,
                          preset_plus_button_.left, preset_top + S(30)};
        DrawTextAt(dc, FormatUnsigned(mining_thread_count_) + L" workers",
                   thread_value, font_small_, C_TEXT,
                   DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);

        const int rows_top = top + mining_row_h + gap;
        DrawSettingRow(dc, {left, rows_top, right, rows_top + row_h},
            L"Tor-only privacy",
            live.process_running
                ? L"Available after the node stops. Applies to the next app-managed start."
                : L"Route all peer traffic through Tor. Clearnet remains the default.",
            tor_choice_, !live.process_running && !tor_preparing_.load(),
            tor_toggle_);
        DrawSettingRow(dc, {left, rows_top + row_h + gap, right,
                       rows_top + 2 * row_h + gap},
            L"Attempt inbound reachability",
            tor_choice_
                ? L"Disabled while Tor-only is selected."
                : L"Ask the router for an inbound P2P mapping at the next app-managed start.",
            reachable_choice_, !live.process_running && !tor_choice_
                && !tor_preparing_.load(), reachable_toggle_);
        DrawSettingRow(dc, {left, rows_top + 2 * (row_h + gap), right,
                       rows_top + 3 * row_h + 2 * gap},
            L"Show public height reference",
            L"Uses explorer.veld.network only to estimate visual sync progress. It is never a consensus or security input.",
            reference_display_enabled_.load(), true, reference_toggle_);

        const int monitor_top = rows_top + 3 * row_h + 3 * gap;
        RECT monitor{left, monitor_top, right, monitor_top + S(96)};
        FillRound(dc, monitor, C_PANEL, C_BORDER);
        RECT monitor_title{monitor.left + S(22), monitor.top + S(12),
                           monitor.right - S(390), monitor.top + S(41)};
        DrawTextAt(dc, L"Remote access", monitor_title, font_heading_,
                   C_TEXT);
        RemoteMonitorStatus monitor_status;
        {
            std::lock_guard<std::mutex> lock(remote_monitor_mutex_);
            monitor_status = remote_monitor_status_;
        }
        RECT monitor_detail{monitor.left + S(22), monitor.top + S(43),
                            monitor.right - S(390), monitor.bottom - S(10)};
        std::wstring monitor_text = monitor_status.detail;
        if (!monitor_status.pair_code.empty())
            monitor_text += L"  Pair code: " + monitor_status.pair_code;
        DrawTextAt(dc, monitor_text, monitor_detail, font_small_,
                   monitor_status.report_ok ? C_SUBTEXT : C_MUTED,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX |
                   DT_END_ELLIPSIS);
        remote_monitor_toggle_ = {monitor.right - S(78), monitor.top + S(11),
                                  monitor.right - S(22), monitor.top + S(39)};
        DrawToggle(dc, remote_monitor_toggle_,
                   remote_monitoring_enabled_.load(), true);
        open_monitor_portal_button_ = {
            monitor.right - S(180), monitor.top + S(48),
            monitor.right - S(22), monitor.top + S(87)};
        DrawButton(dc, open_monitor_portal_button_, L"Open portal", true);
        if (!monitor_status.pair_code.empty()) {
            copy_monitor_code_button_ = {
                monitor.right - S(320), monitor.top + S(48),
                monitor.right - S(190), monitor.top + S(87)};
            DrawButton(dc, copy_monitor_code_button_, L"Copy code", true);
        } else {
            copy_monitor_code_button_ = {};
        }

        const int paths_top = monitor.bottom + gap;
        RECT paths{left, paths_top, right, paths_top + S(144)};
        FillRound(dc, paths, C_PANEL, C_BORDER);
        RECT paths_title{paths.left + S(22), paths.top + S(14),
                         paths.right - S(200), paths.top + S(48)};
        DrawTextAt(dc, L"Local paths", paths_title, font_heading_, C_TEXT);
        RECT data_label{paths.left + S(22), paths.top + S(54),
                        paths.left + S(150), paths.top + S(80)};
        DrawTextAt(dc, L"Data directory", data_label, font_small_, C_MUTED);
        RECT data_value{paths.left + S(150), paths.top + S(54),
                        paths.right - S(210), paths.top + S(80)};
        const std::wstring data_name = data_dir_.filename().empty()
            ? data_dir_.wstring() : data_dir_.filename().wstring();
        DrawTextAt(dc, data_name, data_value, font_small_, C_SUBTEXT,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX |
                   DT_END_ELLIPSIS);
        RECT node_label{paths.left + S(22), paths.top + S(92),
                        paths.left + S(150), paths.top + S(118)};
        DrawTextAt(dc, L"Node binary", node_label, font_small_, C_MUTED);
        RECT node_value{paths.left + S(150), paths.top + S(92),
                        paths.right - S(210), paths.top + S(118)};
        const std::wstring node_name = node_path_.filename().empty()
            ? node_path_.wstring() : node_path_.filename().wstring();
        DrawTextAt(dc, node_name, node_value, font_small_, C_SUBTEXT,
                   DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX |
                   DT_END_ELLIPSIS);
        const int button_w = S(142);
        create_key_button_ = {paths.right - 3 * button_w - S(42),
                              paths.top + S(61),
                              paths.right - 2 * button_w - S(34),
                              paths.top + S(105)};
        DrawButton(dc, create_key_button_, L"Create identity",
                   !live.process_running && !tor_preparing_.load()
                       && !std::filesystem::exists(data_dir_ / L"miner.key"));
        import_key_button_ = {paths.right - 2 * button_w - S(26),
                              paths.top + S(61),
                              paths.right - button_w - S(18),
                              paths.top + S(105)};
        DrawButton(dc, import_key_button_, L"Import keyfile",
                   !live.process_running && !tor_preparing_.load());
        open_data_button_ = {paths.right - button_w - S(10), paths.top + S(61),
                             paths.right - S(10), paths.top + S(105)};
        DrawButton(dc, open_data_button_, L"Open data folder",
                   std::filesystem::exists(data_dir_));
        RECT paths_note{paths.left + S(22), paths.bottom - S(39),
                        paths.right - S(22), paths.bottom - S(12)};
        DrawTextAt(dc, L"Preferences contain no credentials or wallet material.",
                   paths_note, font_small_, C_MUTED);

        RECT release{left, paths.bottom + S(10), right,
                     std::min(client.bottom - S(20), paths.bottom + S(132))};
        FillRound(dc, release, C_PANEL_ALT, C_BORDER);
        RECT release_title{release.left + S(22), release.top + S(7),
                           release.right - S(350), release.top + S(32)};
        DrawTextAt(dc, L"Release and updates", release_title,
                   font_heading_, C_TEXT);
        RECT release_version{release.left + S(22), release.top + S(34),
                             release.right - S(350), release.top + S(58)};
        DrawTextAt(dc, L"Installed: " + Utf8ToWide(veld::CLIENT_VERSION),
                   release_version, font_body_, C_SUBTEXT);
        RECT release_status{release.left + S(22), release.top + S(59),
                            release.right - S(350), release.top + S(82)};
        const UpdateOperation update_operation = update_operation_.load();
        const bool update_busy = update_operation != UpdateOperation::None;
        const wchar_t* update_progress = update_operation == UpdateOperation::Check
            ? L"Checking signed release feed..."
            : L"Downloading and verifying signed update...";
        DrawTextAt(dc, update_busy ? update_progress : update_status_,
                   release_status, font_small_,
                   update_busy ? C_SUBTEXT : update_status_color_);
        check_update_button_ = {release.right - S(324), release.top + S(18),
                                release.right - S(176), release.top + S(62)};
        view_changelog_button_ = {release.right - S(164), release.top + S(18),
                                  release.right - S(20), release.top + S(62)};
        const wchar_t* update_action = update_operation == UpdateOperation::Check
            ? L"Checking..."
            : (update_operation == UpdateOperation::Install
                ? L"Installing..."
                : (update_available_ ? L"Update now" : L"Check now"));
        DrawButton(dc, check_update_button_, update_action, !update_busy);
        DrawButton(dc, view_changelog_button_, L"View changelog", true);
        RECT security_note{release.left + S(22), release.top + S(86),
                           release.right - S(22), release.bottom - S(10)};
        DrawTextAt(dc,
            L"Updates require the pinned release signature and exact signed package hash, then install atomically with rollback. Wallet secrets never enter the updater.",
            security_note, font_small_, C_MUTED,
            DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);
    }

    void OnClick(int x, int y) {
        POINT p = ContentPoint(POINT{x, y});
        if (PtInRect(&overview_nav_, p)) page_ = Page::Overview;
        else if (PtInRect(&blockchain_nav_, p)) page_ = Page::Blockchain;
        else if (PtInRect(&mining_nav_, p)) page_ = Page::Mining;
        else if (PtInRect(&workers_nav_, p)) page_ = Page::Workers;
        else if (PtInRect(&explorer_nav_, p)) page_ = Page::Explorer;
        else if (PtInRect(&network_nav_, p)) page_ = Page::Network;
        else if (PtInRect(&logs_nav_, p)) page_ = Page::Logs;
        else if (PtInRect(&settings_nav_, p)) page_ = Page::Settings;
        else if (PtInRect(&follow_x_link_, p)) {
            ShellExecuteW(hwnd_, L"open", L"https://x.com/VeldNetwork",
                          nullptr, nullptr, SW_SHOWNORMAL);
        }
        else if (PtInRect(&action_button_, p)) ToggleNode();
        else if (page_ == Page::Overview &&
                 (PtInRect(&chain_range_buttons_[0], p) ||
                  PtInRect(&chain_range_buttons_[1], p) ||
                  PtInRect(&chain_range_buttons_[2], p))) {
            chain_range_minutes_ = PtInRect(&chain_range_buttons_[0], p) ? 5 :
                (PtInRect(&chain_range_buttons_[1], p) ? 15 : 60);
            SaveSettings();
        } else if (page_ == Page::Mining &&
                   (PtInRect(&rate_range_buttons_[0], p) ||
                    PtInRect(&rate_range_buttons_[1], p) ||
                    PtInRect(&rate_range_buttons_[2], p))) {
            rate_range_minutes_ = PtInRect(&rate_range_buttons_[0], p) ? 5 :
                (PtInRect(&rate_range_buttons_[1], p) ? 15 : 60);
            SaveSettings();
        }
        else if (page_ == Page::Blockchain && PtInRect(&full_ibd_card_, p)) {
            full_ibd_choice_ = true;
            sync_choice_explicit_ = true;
            SaveSettings();
        } else if (page_ == Page::Blockchain &&
                   PtInRect(&snapshot_card_, p)) {
            full_ibd_choice_ = false;
            sync_choice_explicit_ = true;
            SaveSettings();
        } else if (page_ == Page::Logs &&
                   PtInRect(&copy_diagnostics_button_, p)) {
            if (CopyWideText(hwnd_, BuildRedactedDiagnostics(SnapshotState())))
                diagnostics_copied_until_ = std::chrono::steady_clock::now() +
                    std::chrono::seconds(2);
        } else if (page_ == Page::Logs && PtInRect(&open_log_button_, p)) {
            if (std::filesystem::exists(state_dir_))
                ShellExecuteW(hwnd_, L"open", state_dir_.c_str(), nullptr,
                              nullptr, SW_SHOWNORMAL);
        } else if (page_ == Page::Explorer &&
                   PtInRect(&open_explorer_button_, p)) {
            ShellExecuteW(hwnd_, L"open", L"https://explorer.veld.network/",
                          nullptr, nullptr, SW_SHOWNORMAL);
        } else if (page_ == Page::Explorer &&
                   PtInRect(&open_wallet_button_, p)) {
            OpenTrustedWallet();
        } else if (page_ == Page::Settings &&
                   PtInRect(&mining_mode_toggle_, p)) {
            mining_enabled_ = !mining_enabled_;
            SaveSettings();
        } else if (page_ == Page::Settings &&
                   PtInRect(&preset_eco_button_, p)) {
            mining_preset_ = 0;
            mining_thread_count_ = PresetThreadCount(0);
            SaveSettings();
        } else if (page_ == Page::Settings &&
                   PtInRect(&preset_balanced_button_, p)) {
            mining_preset_ = 1;
            mining_thread_count_ = PresetThreadCount(1);
            SaveSettings();
        } else if (page_ == Page::Settings &&
                   PtInRect(&preset_max_button_, p)) {
            mining_preset_ = 2;
            mining_thread_count_ = PresetThreadCount(2);
            SaveSettings();
        } else if (page_ == Page::Settings &&
                   PtInRect(&preset_minus_button_, p)) {
            mining_preset_ = 3;
            mining_thread_count_ = std::max(1u, mining_thread_count_ - 1);
            SaveSettings();
        } else if (page_ == Page::Settings &&
                   PtInRect(&preset_plus_button_, p)) {
            mining_preset_ = 3;
            mining_thread_count_ = std::min(256u, mining_thread_count_ + 1);
            SaveSettings();
        } else if (page_ == Page::Settings && PtInRect(&tor_toggle_, p)) {
            const auto live = SnapshotState();
            if (!live.process_running && !tor_preparing_.load()) {
                tor_choice_ = !tor_choice_;
                if (tor_choice_) reachable_choice_ = false;
                SaveSettings();
            }
        } else if (page_ == Page::Settings &&
                   PtInRect(&reachable_toggle_, p)) {
            const auto live = SnapshotState();
            if (!live.process_running && !tor_choice_
                && !tor_preparing_.load()) {
                reachable_choice_ = !reachable_choice_;
                SaveSettings();
            }
        } else if (page_ == Page::Settings &&
                   PtInRect(&reference_toggle_, p)) {
            reference_display_enabled_.store(
                !reference_display_enabled_.load());
            SaveSettings();
            worker_cv_.notify_all();
        } else if (page_ == Page::Settings &&
                   PtInRect(&remote_monitor_toggle_, p)) {
            const bool enabled = !remote_monitoring_enabled_.load();
            remote_monitoring_enabled_.store(enabled);
            {
                std::lock_guard<std::mutex> lock(remote_monitor_mutex_);
                remote_monitor_status_.detail = enabled
                    ? L"Connecting to the secure portal..."
                    : L"Disabled. No health data leaves this machine.";
                remote_monitor_status_.report_ok = false;
                if (!enabled) {
                    remote_monitor_status_.pair_code.clear();
                    remote_monitor_status_.paired = false;
                }
            }
            SaveSettings();
            worker_cv_.notify_all();
        } else if (page_ == Page::Settings &&
                   PtInRect(&open_monitor_portal_button_, p)) {
            ShellExecuteW(hwnd_, L"open", L"https://portal.veld.network/",
                          nullptr, nullptr, SW_SHOWNORMAL);
        } else if (page_ == Page::Settings &&
                   PtInRect(&copy_monitor_code_button_, p)) {
            std::wstring code;
            {
                std::lock_guard<std::mutex> lock(remote_monitor_mutex_);
                code = remote_monitor_status_.pair_code;
            }
            if (!code.empty()) CopyWideText(hwnd_, code);
        } else if (page_ == Page::Settings &&
                   PtInRect(&check_update_button_, p)) {
            if (update_operation_.load() == UpdateOperation::None) {
                if (update_available_) BeginUpdateInstall();
                else BeginUpdateCheck();
            }
        } else if (page_ == Page::Settings &&
                   PtInRect(&view_changelog_button_, p)) {
            OpenChangelog();
        } else if (page_ == Page::Settings &&
                   PtInRect(&open_data_button_, p)) {
            if (std::filesystem::exists(data_dir_))
                ShellExecuteW(hwnd_, L"open", data_dir_.c_str(), nullptr,
                              nullptr, SW_SHOWNORMAL);
        } else if (page_ == Page::Settings &&
                   PtInRect(&import_key_button_, p)) {
            const auto live = SnapshotState();
            if (!live.process_running && !tor_preparing_.load())
                ImportKeyfile();
        } else if (page_ == Page::Settings &&
                   PtInRect(&create_key_button_, p)) {
            const auto live = SnapshotState();
            if (!live.process_running && !tor_preparing_.load()
                && !std::filesystem::exists(data_dir_ / L"miner.key"))
                CreateIdentity();
        }
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    bool AskPassphrase(const std::wstring& title,
                       const std::wstring& prompt,
                       std::wstring& value) {
        PassphrasePrompt request{title, prompt, {}};
        const INT_PTR result = DialogBoxParamW(
            instance_, MAKEINTRESOURCEW(IDD_VELD_PASSPHRASE), hwnd_,
            PassphraseDialogProc, reinterpret_cast<LPARAM>(&request));
        if (result != IDOK || request.value.empty()) {
            if (!request.value.empty())
                SecureZeroMemory(request.value.data(),
                                 request.value.size() * sizeof(wchar_t));
            return false;
        }
        value = std::move(request.value);
        return true;
    }

    void ClearSessionPassphrase() {
        std::lock_guard<std::mutex> lock(session_passphrase_mutex_);
        if (!protected_session_passphrase_.empty()) {
            SecureZeroMemory(protected_session_passphrase_.data(),
                             protected_session_passphrase_.size());
            protected_session_passphrase_.clear();
            protected_session_passphrase_.shrink_to_fit();
        }
        protected_session_passphrase_chars_ = 0;
    }

    bool StoreSessionPassphrase(const std::wstring& passphrase) {
        if (passphrase.empty()) return false;
        const size_t clear_bytes = (passphrase.size() + 1) * sizeof(wchar_t);
        const size_t protected_bytes =
            ((clear_bytes + CRYPTPROTECTMEMORY_BLOCK_SIZE - 1) /
             CRYPTPROTECTMEMORY_BLOCK_SIZE) * CRYPTPROTECTMEMORY_BLOCK_SIZE;
        std::vector<BYTE> protected_value(protected_bytes, 0);
        std::memcpy(protected_value.data(), passphrase.c_str(), clear_bytes);
        if (!CryptProtectMemory(protected_value.data(),
                                static_cast<DWORD>(protected_value.size()),
                                CRYPTPROTECTMEMORY_SAME_PROCESS)) {
            SecureZeroMemory(protected_value.data(), protected_value.size());
            return false;
        }
        std::lock_guard<std::mutex> lock(session_passphrase_mutex_);
        if (!protected_session_passphrase_.empty())
            SecureZeroMemory(protected_session_passphrase_.data(),
                             protected_session_passphrase_.size());
        protected_session_passphrase_ = std::move(protected_value);
        protected_session_passphrase_chars_ = passphrase.size();
        return true;
    }

    bool LoadSessionPassphrase(std::wstring& passphrase) {
        std::vector<BYTE> clear_value;
        size_t chars = 0;
        {
            std::lock_guard<std::mutex> lock(session_passphrase_mutex_);
            if (protected_session_passphrase_.empty() ||
                protected_session_passphrase_chars_ == 0) return false;
            clear_value = protected_session_passphrase_;
            chars = protected_session_passphrase_chars_;
        }
        if (!CryptUnprotectMemory(clear_value.data(),
                                  static_cast<DWORD>(clear_value.size()),
                                  CRYPTPROTECTMEMORY_SAME_PROCESS)) {
            SecureZeroMemory(clear_value.data(), clear_value.size());
            ClearSessionPassphrase();
            return false;
        }
        const size_t required_bytes = (chars + 1) * sizeof(wchar_t);
        const auto* wide = reinterpret_cast<const wchar_t*>(clear_value.data());
        if (required_bytes > clear_value.size() || wide[chars] != L'\0') {
            SecureZeroMemory(clear_value.data(), clear_value.size());
            ClearSessionPassphrase();
            return false;
        }
        passphrase.assign(wide, chars);
        SecureZeroMemory(clear_value.data(), clear_value.size());
        return true;
    }

    std::vector<wchar_t> ChildEnvironmentWithValue(
            const wchar_t* key, const std::wstring& value) {
        if (!key || !*key || !wcschr(key, L'=')) return {};
        const size_t key_length = wcslen(key);
        std::vector<std::wstring> entries;
        LPWCH raw = GetEnvironmentStringsW();
        if (!raw) return {};
        for (const wchar_t* cursor = raw; *cursor; ) {
            std::wstring entry(cursor);
            cursor += entry.size() + 1;
            if (_wcsnicmp(entry.c_str(), key, key_length) != 0)
                entries.push_back(std::move(entry));
        }
        FreeEnvironmentStringsW(raw);
        std::sort(entries.begin(), entries.end(),
                  [](const std::wstring& a, const std::wstring& b) {
                      return _wcsicmp(a.c_str(), b.c_str()) < 0;
                  });
        const auto position = std::lower_bound(
            entries.begin(), entries.end(), key,
            [](const std::wstring& entry, const wchar_t* name) {
                return _wcsicmp(entry.c_str(), name) < 0;
            });
        const size_t insert_at = static_cast<size_t>(position - entries.begin());
        size_t chars = 2 + key_length + value.size();
        for (const auto& entry : entries) chars += entry.size() + 1;
        std::vector<wchar_t> block;
        block.reserve(chars);
        for (size_t i = 0; i <= entries.size(); ++i) {
            if (i == insert_at) {
                block.insert(block.end(), key, key + key_length);
                block.insert(block.end(), value.begin(), value.end());
                block.push_back(L'\0');
            }
            if (i < entries.size()) {
                block.insert(block.end(), entries[i].begin(), entries[i].end());
                block.push_back(L'\0');
            }
        }
        block.push_back(L'\0');
        return block;
    }

    std::vector<wchar_t> ChildEnvironmentWithPassphrase(
            const std::wstring& passphrase) {
        return ChildEnvironmentWithValue(
            L"VELD_VAULT_PASSPHRASE=", passphrase);
    }

    std::vector<wchar_t> ChildEnvironmentWithSignerToken(
            const std::string& token) {
        return ChildEnvironmentWithValue(
            L"VELD_LOCAL_SIGNER_TOKEN=", Utf8ToWide(token));
    }

    std::filesystem::path LogPath() const {
        return state_dir_ / L"node-gui-node.log";
    }

    std::filesystem::path InstallRoot() const {
        const auto parent = node_path_.parent_path();
        return parent.filename() == L"bin" ? parent.parent_path() : parent;
    }

    bool StopProcessForUpdate(DWORD pid) {
        if (pid == 0) return true;
        HANDLE process = OpenProcess(SYNCHRONIZE | PROCESS_TERMINATE |
                                         PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE, pid);
        if (!process) return GetLastError() == ERROR_INVALID_PARAMETER;

        wchar_t image_path[32768]{};
        DWORD image_path_size = static_cast<DWORD>(std::size(image_path));
        if (!QueryFullProcessImageNameW(process, 0, image_path,
                                        &image_path_size)) {
            CloseHandle(process);
            return false;
        }
        const std::wstring actual =
            std::filesystem::path(image_path).lexically_normal().wstring();
        const std::wstring expected = node_path_.lexically_normal().wstring();
        if (_wcsicmp(actual.c_str(), expected.c_str()) != 0) {
            CloseHandle(process);
            return false;
        }

        if (WaitForSingleObject(process, 0) == WAIT_OBJECT_0) {
            CloseHandle(process);
            return true;
        }

        const bool signaled = RequestGuiNodeShutdown(pid);
        DWORD wait_result = signaled
            ? WaitForSingleObject(process, 25000) : WAIT_TIMEOUT;

        // The node's own shutdown watchdog force-exits after 20 seconds.  This
        // fallback primarily covers upgrades from older GUI builds whose node
        // process had neither a usable console nor the named shutdown event.
        // It targets only the exact PID already identified as veld-node.exe.
        if (wait_result == WAIT_TIMEOUT &&
            TerminateProcess(process, ERROR_PROCESS_ABORTED)) {
            wait_result = WaitForSingleObject(process, 5000);
        }
        CloseHandle(process);
        return wait_result == WAIT_OBJECT_0;
    }

    bool StopServicesForUpdate() {
        update_status_ = L"Stopping local services safely…";
        update_status_color_ = C_SUBTEXT;
        InvalidateRect(hwnd_, nullptr, FALSE);
        UpdateWindow(hwnd_);

        const LiveState live = SnapshotState();
        if (live.process_running && !StopProcessForUpdate(live.pid)) {
            update_status_ = L"Node did not stop cleanly · update not started";
            update_status_color_ = RGB(231, 126, 126);
            InvalidateRect(hwnd_, nullptr, FALSE);
            return false;
        }
        return true;
    }

    bool BeginUpdateProcess(UpdateOperation operation) {
        const auto root = InstallRoot();
        const auto updater = root / L"veld-update.ps1";
        if (!std::filesystem::is_regular_file(updater)) {
            update_status_ = L"Signed update helper is missing";
            update_status_color_ = RGB(231, 126, 126);
            InvalidateRect(hwnd_, nullptr, FALSE);
            return false;
        }
        const auto powershell = SystemPowerShellPath();
        if (powershell.empty()) {
            update_status_ = L"Windows PowerShell is unavailable";
            update_status_color_ = RGB(231, 126, 126);
            InvalidateRect(hwnd_, nullptr, FALSE);
            return false;
        }
        const bool installing = operation == UpdateOperation::Install;
        if (installing && !StopServicesForUpdate()) return false;
        std::error_code ec;
        std::filesystem::create_directories(state_dir_, ec);
        SECURITY_ATTRIBUTES inherit{};
        inherit.nLength = sizeof(inherit);
        inherit.bInheritHandle = TRUE;
        const auto output_path = state_dir_ /
            (installing ? L"update-install.log" : L"update-check.log");
        HANDLE output = CreateFileW(output_path.c_str(), GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        HANDLE nul = CreateFileW(L"NUL", GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        if (output == INVALID_HANDLE_VALUE || nul == INVALID_HANDLE_VALUE) {
            if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
            if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
            update_status_ = installing
                ? L"Update install could not start"
                : L"Update check could not start";
            update_status_color_ = RGB(231, 126, 126);
            return false;
        }
        const std::wstring mode = installing ? L"Install" : L"Check";
        std::wstring command = L"\"" + powershell.wstring() +
            L"\" -NoProfile -ExecutionPolicy Bypass -File \"" +
            updater.wstring() + L"\" -Mode " + mode + L" -InstallDir \"" +
            root.wstring() + L"\" -Distribution Node";
        std::vector<wchar_t> mutable_command(command.begin(), command.end());
        mutable_command.push_back(L'\0');
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;
        si.hStdInput = nul;
        si.hStdOutput = output;
        si.hStdError = output;
        PROCESS_INFORMATION pi{};
        const BOOL created = CreateProcessW(powershell.c_str(), mutable_command.data(),
            nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, root.c_str(),
            &si, &pi);
        CloseHandle(output);
        CloseHandle(nul);
        if (!created) {
            update_status_ = installing
                ? L"Update install could not start"
                : L"Update check could not start";
            update_status_color_ = RGB(231, 126, 126);
            return false;
        }
        CloseHandle(pi.hThread);
        {
            std::lock_guard<std::mutex> lock(update_process_mutex_);
            if (update_process_) CloseHandle(update_process_);
            update_operation_.store(operation);
            update_process_ = pi.hProcess;
        }
        if (installing) update_available_ = false;
        update_status_ = installing
            ? L"Downloading and verifying signed update…"
            : L"Checking signed release feed…";
        update_status_color_ = C_SUBTEXT;
        worker_cv_.notify_all();
        InvalidateRect(hwnd_, nullptr, FALSE);
        return true;
    }

    bool BeginUpdateCheck() {
        return BeginUpdateProcess(UpdateOperation::Check);
    }

    bool BeginUpdateInstall() {
        return BeginUpdateProcess(UpdateOperation::Install);
    }

    void OnUpdateProcessComplete(DWORD exit_code) {
        const UpdateOperation operation =
            update_operation_.exchange(UpdateOperation::None);
        if (operation == UpdateOperation::Install) {
            if (exit_code == 0) {
                update_status_ = L"Signed update ready · restarting…";
                update_status_color_ = C_TEXT;
                InvalidateRect(hwnd_, nullptr, FALSE);
                UpdateWindow(hwnd_);
                DestroyWindow(hwnd_);
            } else {
                update_available_ = true;
                update_status_ = L"Update failed safely · retry or restart the node";
                update_status_color_ = RGB(231, 126, 126);
                InvalidateRect(hwnd_, nullptr, FALSE);
            }
            return;
        }

        const std::string output = ReadTextBounded(
            state_dir_ / L"update-check.log", 128U * 1024U);
        if (exit_code == 0) {
            update_available_ = false;
            update_status_ = L"Latest signed release verified · " +
                Utf8ToWide(veld::CLIENT_VERSION);
            update_status_color_ = C_TEXT;
        } else if (exit_code == 2) {
            std::string version;
            const std::string marker = "Remote version:";
            const size_t at = output.find(marker);
            if (at != std::string::npos) {
                const size_t begin = output.find_first_not_of(" \t", at + marker.size());
                const size_t end = output.find_first_of("\r\n", begin);
                if (begin != std::string::npos)
                    version = output.substr(begin, end - begin);
            }
            update_status_ = version.empty() ? L"Signed update available" :
                L"Signed update available · " + Utf8ToWide(version);
            update_status_color_ = C_WARN;
            update_available_ = true;
        } else {
            update_available_ = false;
            update_status_ = L"Signed feed could not be verified · try again";
            update_status_color_ = RGB(231, 126, 126);
        }
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    void OpenChangelog() {
        const auto local = InstallRoot() / L"CHANGES.txt";
        if (std::filesystem::is_regular_file(local)) {
            ShellExecuteW(hwnd_, L"open", local.c_str(), nullptr,
                          local.parent_path().c_str(), SW_SHOWNORMAL);
        } else {
            ShellExecuteW(hwnd_, L"open",
                          L"https://veld.network/downloads/CHANGES.txt",
                          nullptr, nullptr, SW_SHOWNORMAL);
        }
    }

    bool OpenChildLogHandles(HANDLE& log, HANDLE& nul) {
        std::error_code ec;
        std::filesystem::create_directories(state_dir_, ec);
        if (ec) return false;
        SECURITY_ATTRIBUTES inherit{};
        inherit.nLength = sizeof(inherit);
        inherit.bInheritHandle = TRUE;
        log = CreateFileW(LogPath().c_str(), FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE, &inherit, OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ |
            FILE_SHARE_WRITE, &inherit, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (log != INVALID_HANDLE_VALUE && nul != INVALID_HANDLE_VALUE)
            return true;
        if (log != INVALID_HANDLE_VALUE) CloseHandle(log);
        if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
        log = nul = INVALID_HANDLE_VALUE;
        return false;
    }

    void BeginTorSetup() {
        const auto install_root = node_path_.parent_path().filename() == L"bin"
            ? node_path_.parent_path().parent_path() : node_path_.parent_path();
        const auto helper = install_root / L"tor-setup.ps1";
        if (!std::filesystem::is_regular_file(helper)) {
            MessageBoxW(hwnd_,
                L"The signed Tor setup helper is missing from this package.",
                L"Veld Node", MB_OK | MB_ICONERROR);
            return;
        }
        const auto powershell = SystemPowerShellPath();
        if (powershell.empty()) {
            MessageBoxW(hwnd_, L"Windows PowerShell is unavailable.",
                        L"Veld Node", MB_OK | MB_ICONERROR);
            return;
        }
        HANDLE log = INVALID_HANDLE_VALUE;
        HANDLE nul = INVALID_HANDLE_VALUE;
        if (!OpenChildLogHandles(log, nul)) {
            MessageBoxW(hwnd_, L"The local app log could not be opened.",
                        L"Veld Node", MB_OK | MB_ICONERROR);
            return;
        }
        std::wstring command = L"\"" + powershell.wstring() +
            L"\" -NoProfile -ExecutionPolicy Bypass -File \"" +
            helper.wstring() + L"\" \"" + data_dir_.wstring() + L"\"";
        std::vector<wchar_t> mutable_command(command.begin(), command.end());
        mutable_command.push_back(L'\0');
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;
        si.hStdInput = nul;
        si.hStdOutput = log;
        si.hStdError = log;
        PROCESS_INFORMATION pi{};
        const BOOL created = CreateProcessW(
            powershell.c_str(), mutable_command.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW, nullptr, install_root.c_str(), &si, &pi);
        CloseHandle(log);
        CloseHandle(nul);
        if (!created) {
            MessageBoxW(hwnd_, L"Tor preparation could not be started.",
                        L"Veld Node", MB_OK | MB_ICONERROR);
            return;
        }
        CloseHandle(pi.hThread);
        {
            std::lock_guard<std::mutex> lock(tor_process_mutex_);
            if (tor_setup_process_) CloseHandle(tor_setup_process_);
            tor_setup_process_ = pi.hProcess;
        }
        tor_preparing_.store(true);
        worker_cv_.notify_all();
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    void OnTorSetupComplete(DWORD exit_code) {
        tor_preparing_.store(false);
        if (exit_code != 0) {
            MessageBoxW(hwnd_,
                L"Tor could not be prepared. Review the local app log, or select Clearnet in Settings.",
                L"Veld Node", MB_OK | MB_ICONERROR);
            return;
        }
        StartNodeEngine();
    }

    bool RunProtectedNodeUtility(const std::wstring& arguments,
                                 std::wstring& passphrase) {
        if (!std::filesystem::is_regular_file(node_path_)) return false;
        HANDLE log = INVALID_HANDLE_VALUE;
        HANDLE nul = INVALID_HANDLE_VALUE;
        if (!OpenChildLogHandles(log, nul)) return false;
        std::wstring command = L"\"" + node_path_.wstring() + L"\" "
            + arguments;
        std::vector<wchar_t> mutable_command(command.begin(), command.end());
        mutable_command.push_back(L'\0');
        auto environment = ChildEnvironmentWithPassphrase(passphrase);
        SecureZeroMemory(passphrase.data(),
                         passphrase.size() * sizeof(wchar_t));
        passphrase.clear();
        if (environment.empty()) {
            CloseHandle(log);
            CloseHandle(nul);
            return false;
        }
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;
        si.hStdInput = nul;
        si.hStdOutput = log;
        si.hStdError = log;
        PROCESS_INFORMATION pi{};
        HANDLE verified_node = OpenVerifiedTrustedFile(
            node_path_, VELD_TRUSTED_NODE_SHA256);
        if (verified_node == INVALID_HANDLE_VALUE) {
            SecureZeroMemory(environment.data(),
                             environment.size() * sizeof(wchar_t));
            CloseHandle(log);
            CloseHandle(nul);
            return false;
        }
        const BOOL created = CreateProcessW(
            node_path_.c_str(), mutable_command.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            environment.data(), node_path_.parent_path().c_str(), &si, &pi);
        CloseHandle(verified_node);
        SecureZeroMemory(environment.data(),
                         environment.size() * sizeof(wchar_t));
        CloseHandle(log);
        CloseHandle(nul);
        if (!created) return false;
        CloseHandle(pi.hThread);
        SetCursor(LoadCursor(nullptr, IDC_WAIT));
        const DWORD waited = WaitForSingleObject(pi.hProcess, 120000);
        DWORD exit_code = 1;
        if (waited == WAIT_OBJECT_0) GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hProcess);
        SetCursor(LoadCursor(nullptr, IDC_ARROW));
        return waited == WAIT_OBJECT_0 && exit_code == 0;
    }

    void CreateIdentity() {
        if (std::filesystem::exists(data_dir_ / L"miner.key")) return;
        std::wstring passphrase;
        std::wstring confirmation;
        if (!AskPassphrase(L"Create mining identity",
                L"Choose a passphrase for the new mining and validator identity.",
                passphrase)) return;
        if (!AskPassphrase(L"Confirm mining identity",
                L"Enter the same passphrase again.", confirmation)) {
            SecureZeroMemory(passphrase.data(),
                             passphrase.size() * sizeof(wchar_t));
            return;
        }
        const bool matches = passphrase.size() == confirmation.size()
            && std::equal(passphrase.begin(), passphrase.end(),
                          confirmation.begin());
        SecureZeroMemory(confirmation.data(),
                         confirmation.size() * sizeof(wchar_t));
        confirmation.clear();
        if (!matches) {
            SecureZeroMemory(passphrase.data(),
                             passphrase.size() * sizeof(wchar_t));
            MessageBoxW(hwnd_, L"The passphrases did not match.",
                        L"Veld Node", MB_OK | MB_ICONWARNING);
            return;
        }
        std::string passphrase_utf8 = WideToUtf8(passphrase);
        std::string policy_error;
        const bool policy_ok = veld::wallet_crypto::ValidateNewPassphrase(
            passphrase_utf8, &policy_error);
        SecureZeroMemory(passphrase_utf8.data(), passphrase_utf8.size());
        passphrase_utf8.clear();
        if (!policy_ok) {
            SecureZeroMemory(passphrase.data(),
                             passphrase.size() * sizeof(wchar_t));
            passphrase.clear();
            MessageBoxW(hwnd_, Utf8ToWide(policy_error).c_str(),
                        L"Veld Node", MB_OK | MB_ICONWARNING);
            return;
        }
        const std::wstring arguments = L"--datadir \"" + data_dir_.wstring()
            + L"\" --create-miner-key";
        if (!RunProtectedNodeUtility(arguments, passphrase)) {
            MessageBoxW(hwnd_,
                L"The encrypted identity could not be created. Review the local app log.",
                L"Veld Node", MB_OK | MB_ICONERROR);
            return;
        }
        ClearSessionPassphrase();
        MessageBoxW(hwnd_,
            L"A new mining identity was created. It will also endorse automatically when registered as a validator.",
            L"Veld Node", MB_OK | MB_ICONINFORMATION);
    }

    void ImportKeyfile() {
        wchar_t selected[32768]{};
        OPENFILENAMEW picker{};
        picker.lStructSize = sizeof(picker);
        picker.hwndOwner = hwnd_;
        picker.lpstrFilter = L"Veld keyfiles (*.veld-keys)\0*.veld-keys\0All files (*.*)\0*.*\0\0";
        picker.lpstrFile = selected;
        picker.nMaxFile = static_cast<DWORD>(_countof(selected));
        picker.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
                       OFN_NOCHANGEDIR | OFN_DONTADDTORECENT;
        picker.lpstrTitle = L"Import Veld mining identity";
        if (!GetOpenFileNameW(&picker)) return;

        const auto destination = data_dir_ / L"miner.key";
        if (std::filesystem::exists(destination)
            && MessageBoxW(hwnd_,
                L"Replace the current mining and validator identity?\n\nThe existing encrypted miner.key will be replaced only if the selected keyfile and passphrase validate.",
                L"Veld Node", MB_YESNO | MB_ICONWARNING) != IDYES) {
            return;
        }

        std::wstring passphrase;
        if (!AskPassphrase(L"Import Veld keyfile",
                L"Enter the passphrase for the selected .veld-keys file.",
                passphrase)) return;
        const std::wstring arguments = L"--datadir \"" + data_dir_.wstring()
            + L"\" --import-miner-key \"" + std::wstring(selected) + L"\"";
        if (!RunProtectedNodeUtility(arguments, passphrase)) {
            MessageBoxW(hwnd_,
                L"The keyfile was not imported. The passphrase may be wrong, or the selected file is not a valid Veld keyfile. The existing identity was not replaced.",
                L"Veld Node", MB_OK | MB_ICONERROR);
            return;
        }
        ClearSessionPassphrase();
        MessageBoxW(hwnd_,
            L"The mining identity was imported. It will also endorse automatically when registered as a validator.",
            L"Veld Node", MB_OK | MB_ICONINFORMATION);
    }

    void OpenTrustedWallet() {
        if (!std::filesystem::is_regular_file(wallet_path_)) {
            MessageBoxW(hwnd_,
                L"The trusted local wallet was not found in this signed Veld package. Reinstall the current package before entering a wallet key.",
                L"Veld Wallet", MB_OK | MB_ICONERROR);
            return;
        }
        const uint16_t ui_port = veld::CompiledPublicWalletUiPort();
        const uint16_t rpc_port = veld::CompiledPublicRpcPort();
        auto wallet_ready = [&]() {
            return HttpGetJson(L"127.0.0.1", ui_port, L"/manifest.json",
                               false, 500).ok;
        };
        const bool owned_wallet_running = wallet_process_ &&
            WaitForSingleObject(wallet_process_, 0) == WAIT_TIMEOUT;
        if (!owned_wallet_running) {
            if (wallet_process_) CloseHandle(wallet_process_);
            wallet_process_ = nullptr;
            if (!wallet_signer_token_.empty()) {
                SecureZeroMemory(wallet_signer_token_.data(),
                                 wallet_signer_token_.size());
                wallet_signer_token_.clear();
            }
            HANDLE verified_wallet = OpenVerifiedTrustedFile(
                wallet_path_, VELD_TRUSTED_WALLET_SHA256);
            if (verified_wallet == INVALID_HANDLE_VALUE) {
                MessageBoxW(hwnd_,
                    L"The local wallet does not match the signer built into this signed Veld Node app. Reinstall the complete current package before entering a wallet key.",
                    L"Veld Wallet", MB_OK | MB_ICONERROR);
                return;
            }
            wallet_signer_token_ = NewDeviceToken();
            if (wallet_signer_token_.size() != 43) {
                CloseHandle(verified_wallet);
                MessageBoxW(hwnd_,
                    L"A secure local wallet launch capability could not be created.",
                    L"Veld Wallet", MB_OK | MB_ICONERROR);
                return;
            }
            std::wstring command = L"\"" + wallet_path_.wstring() +
                L"\" --wallet --rpcurl http://127.0.0.1:" +
                std::to_wstring(rpc_port) + L" --uiport " +
                std::to_wstring(ui_port) + L" --datadir \"" +
                data_dir_.wstring() + L"\"";
            std::vector<wchar_t> mutable_command(command.begin(), command.end());
            mutable_command.push_back(L'\0');
            auto environment =
                ChildEnvironmentWithSignerToken(wallet_signer_token_);
            if (environment.empty()) {
                CloseHandle(verified_wallet);
                SecureZeroMemory(wallet_signer_token_.data(),
                                 wallet_signer_token_.size());
                wallet_signer_token_.clear();
                MessageBoxW(hwnd_,
                    L"A secure local wallet environment could not be created.",
                    L"Veld Wallet", MB_OK | MB_ICONERROR);
                return;
            }
            STARTUPINFOW si{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi{};
            const BOOL created = CreateProcessW(
                wallet_path_.c_str(), mutable_command.data(), nullptr, nullptr,
                FALSE, CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                environment.data(),
                wallet_path_.parent_path().c_str(), &si, &pi);
            SecureZeroMemory(environment.data(),
                             environment.size() * sizeof(wchar_t));
            if (!created) {
                CloseHandle(verified_wallet);
                SecureZeroMemory(wallet_signer_token_.data(),
                                 wallet_signer_token_.size());
                wallet_signer_token_.clear();
                MessageBoxW(hwnd_,
                    L"The trusted local wallet could not be started.",
                    L"Veld Wallet", MB_OK | MB_ICONERROR);
                return;
            }
            CloseHandle(pi.hThread);
            wallet_process_ = pi.hProcess;
            for (int attempt = 0; attempt < 50; ++attempt) {
                if (WaitForSingleObject(wallet_process_, 0) != WAIT_TIMEOUT)
                    break;
                if (wallet_ready()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            CloseHandle(verified_wallet);
        }
        if (!wallet_process_ ||
            WaitForSingleObject(wallet_process_, 0) != WAIT_TIMEOUT ||
            !wallet_ready()) {
            if (wallet_process_ &&
                WaitForSingleObject(wallet_process_, 0) == WAIT_TIMEOUT) {
                TerminateProcess(wallet_process_, ERROR_CANCELLED);
                WaitForSingleObject(wallet_process_, 2000);
            }
            if (wallet_process_) CloseHandle(wallet_process_);
            wallet_process_ = nullptr;
            if (!wallet_signer_token_.empty()) {
                SecureZeroMemory(wallet_signer_token_.data(),
                                 wallet_signer_token_.size());
                wallet_signer_token_.clear();
            }
            MessageBoxW(hwnd_,
                L"The signed local wallet did not claim its loopback listener. Another process may be using the wallet port, so no wallet page was opened.",
                L"Veld Wallet", MB_OK | MB_ICONWARNING);
            return;
        }
        std::wstring url = L"http://127.0.0.1:" +
            std::to_wstring(ui_port) + L"/";
        if (!wallet_signer_token_.empty())
            url += L"?signer=" + Utf8ToWide(wallet_signer_token_);
        const auto opened = reinterpret_cast<INT_PTR>(ShellExecuteW(
            hwnd_, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL));
        if (opened > 32 && !wallet_signer_token_.empty()) {
            SecureZeroMemory(wallet_signer_token_.data(),
                             wallet_signer_token_.size());
            wallet_signer_token_.clear();
        }
    }

    void ToggleNode() {
        if (tor_preparing_.load()
            || stopping_node_.load()
            || update_operation_.load() != UpdateOperation::None) return;
        const LiveState live = SnapshotState();
        if (!live.process_running) {
            StartNode();
            return;
        }
        if (!RequestGuiNodeShutdown(live.pid)) {
            MessageBoxW(hwnd_,
                L"The node did not accept a graceful stop signal. It was not force-terminated.",
                L"Veld Node", MB_OK | MB_ICONWARNING);
        } else {
            stopping_node_.store(true);
            worker_cv_.notify_all();
            InvalidateRect(hwnd_, nullptr, FALSE);
        }
    }

    void StartNode() {
        stopping_node_.store(false);
        if (!std::filesystem::is_regular_file(data_dir_ / L"miner.key")) {
            page_ = Page::Settings;
            MessageBoxW(hwnd_,
                L"Create a node identity or import a Veld .veld-keys file in Settings before starting the node.",
                L"Veld Node", MB_OK | MB_ICONINFORMATION);
            return;
        }
        if (tor_choice_) {
            BeginTorSetup();
            return;
        }
        StartNodeEngine();
    }

    void StartNodeEngine() {
        if (!std::filesystem::is_regular_file(node_path_)) {
            const std::wstring message = L"The signed node binary was not found beside this app:\n\n" +
                                         node_path_.wstring();
            MessageBoxW(hwnd_, message.c_str(), L"Veld Node",
                        MB_OK | MB_ICONERROR);
            return;
        }
        std::error_code ec;
        std::filesystem::create_directories(data_dir_, ec);
        if (ec) {
            MessageBoxW(hwnd_, L"The Veld data directory could not be created.",
                        L"Veld Node", MB_OK | MB_ICONERROR);
            return;
        }
        HANDLE log = INVALID_HANDLE_VALUE;
        HANDLE nul = INVALID_HANDLE_VALUE;
        if (!OpenChildLogHandles(log, nul)) {
            MessageBoxW(hwnd_, L"The local app log could not be opened.",
                        L"Veld Node", MB_OK | MB_ICONERROR);
            return;
        }
        std::wstring command = L"\"" + node_path_.wstring() + L"\" " +
            (mining_enabled_ ? L"--mine" : L"--endorse") +
            L" --no-prompt --datadir \"" + data_dir_.wstring() + L"\"";
        if (mining_enabled_)
            command += L" --threads " + std::to_wstring(mining_thread_count_);
        if (tor_choice_) command += L" --tor-only";
        else if (reachable_choice_) command += L" --reachable";
        command += full_ibd_choice_
            ? L" --full-ibd" : L" --snapshot-bootstrap";
        std::vector<wchar_t> mutable_command(command.begin(), command.end());
        mutable_command.push_back(L'\0');

        std::wstring passphrase;
        const bool reused_session_unlock = LoadSessionPassphrase(passphrase);
        if (!reused_session_unlock &&
            !AskPassphrase(L"Unlock node identity",
                L"Enter the passphrase for this identity.", passphrase)) {
            CloseHandle(log);
            CloseHandle(nul);
            return;
        }
        auto environment = ChildEnvironmentWithPassphrase(passphrase);
        if (environment.empty()) {
            SecureZeroMemory(passphrase.data(),
                             passphrase.size() * sizeof(wchar_t));
            passphrase.clear();
            CloseHandle(log);
            CloseHandle(nul);
            MessageBoxW(hwnd_, L"A child-process environment could not be created.",
                        L"Veld Node", MB_OK | MB_ICONERROR);
            return;
        }

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;
        si.hStdInput = nul;
        si.hStdOutput = log;
        si.hStdError = log;
        PROCESS_INFORMATION pi{};
        HANDLE verified_node = OpenVerifiedTrustedFile(
            node_path_, VELD_TRUSTED_NODE_SHA256);
        if (verified_node == INVALID_HANDLE_VALUE) {
            SecureZeroMemory(environment.data(),
                             environment.size() * sizeof(wchar_t));
            SecureZeroMemory(passphrase.data(),
                             passphrase.size() * sizeof(wchar_t));
            passphrase.clear();
            CloseHandle(log);
            CloseHandle(nul);
            MessageBoxW(hwnd_,
                L"The node engine does not match this signed Veld Node app. Reinstall the complete current package.",
                L"Veld package blocked", MB_OK | MB_ICONERROR);
            return;
        }
        const BOOL created = CreateProcessW(
            node_path_.c_str(), mutable_command.data(), nullptr, nullptr, TRUE,
            CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW |
                CREATE_UNICODE_ENVIRONMENT,
            environment.data(),
            node_path_.parent_path().c_str(), &si, &pi);
        CloseHandle(verified_node);
        SecureZeroMemory(environment.data(),
                         environment.size() * sizeof(wchar_t));
        if (created && !reused_session_unlock)
            (void)StoreSessionPassphrase(passphrase);
        SecureZeroMemory(passphrase.data(),
                         passphrase.size() * sizeof(wchar_t));
        passphrase.clear();
        CloseHandle(log);
        CloseHandle(nul);
        if (!created) {
            MessageBoxW(hwnd_, L"The node process could not be started.",
                        L"Veld Node", MB_OK | MB_ICONERROR);
            return;
        }
        CloseHandle(pi.hThread);
        if (owned_process_) CloseHandle(owned_process_);
        owned_process_ = pi.hProcess;
        owned_pid_.store(pi.dwProcessId);
        session_unlock_confirmed_.store(false);
        stopping_node_.store(false);
        worker_cv_.notify_all();
    }

    void AcknowledgeRemoteCommand(uint64_t id, const std::string& status,
                                  const std::string& message) {
        std::lock_guard<std::mutex> lock(remote_ack_mutex_);
        remote_ack_id_ = id;
        remote_ack_status_ = status;
        remote_ack_message_ = message.substr(0, 160);
        worker_cv_.notify_all();
    }

    std::wstring RemoteCommandDescription(
            const MonitoringReply::Command& command) const {
        if (command.action == "node.start") return L"Start the Veld node";
        if (command.action == "node.stop") return L"Stop the Veld node gracefully";
        if (command.action == "updates.check")
            return L"Check the signed Veld release feed";
        if (command.action == "updates.install")
            return L"Install the verified Veld update";
        if (command.action == "mining.enabled")
            return command.enabled
                ? L"Enable CPU mining for the next app-managed start"
                : L"Disable CPU mining for the next app-managed start";
        if (command.action == "mining.workers")
            return L"Set the CPU worker count to " +
                std::to_wstring(command.workers);
        if (command.action == "display.reference")
            return command.enabled
                ? L"Show the public height reference"
                : L"Hide the public height reference";
        if (command.action == "privacy.tor")
            return command.enabled
                ? L"Use Tor-only peer transport on the next start"
                : L"Disable Tor-only peer transport on the next start";
        if (command.action == "network.reachable")
            return command.enabled
                ? L"Attempt inbound P2P reachability on the next start"
                : L"Disable inbound P2P reachability on the next start";
        if (command.action == "sync.mode")
            return command.mode == "full"
                ? L"Use full initial block download on the next start"
                : std::wstring{};
        return {};
    }

    bool ConfirmRemoteCommand(const MonitoringReply::Command& command,
                              bool new_trust) const {
        const std::wstring action = RemoteCommandDescription(command);
        if (action.empty()) return false;
        std::wstring message = L"The Veld Portal requests this exact action:\n\n" +
            action + L"\n\n";
        if (new_trust) {
            std::wstring fingerprint = Utf8ToWide(command.key_id.substr(0, 16));
            message += L"This is a new portal pairing identity. Approving will "
                       L"also trust command key " + fingerprint +
                       L" for this pairing.\n\n";
        }
        message += L"The command is signed and time-limited. No action will be "
                   L"taken unless you choose Yes.";
        return MessageBoxW(hwnd_, message.c_str(),
            L"Approve Veld Portal action",
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND) == IDYES;
    }

    bool AuthorizeRemoteCommand(const MonitoringReply::Command& command,
                                std::string& rejection) {
        PortalTrustState current;
        {
            std::lock_guard<std::mutex> lock(remote_trust_mutex_);
            current = remote_trust_;
        }
        PortalTrustState next;
        const PortalCommandTrustVerdict verdict = EvaluatePortalCommandTrust(
            command, current, static_cast<uint64_t>(std::time(nullptr)), next,
            rejection);
        if (verdict == PortalCommandTrustVerdict::Reject) return false;
        const bool new_trust = verdict == PortalCommandTrustVerdict::NewPairing;
        if (new_trust && !ConfirmRemoteCommand(command, true)) {
            rejection = "Command was denied on the paired machine";
            return false;
        }
        if (!SavePortalTrust(state_dir_ / L"remote-trust.dat", next)) {
            MessageBoxW(hwnd_,
                L"The command was not run because replay protection could not "
                L"be saved securely.", L"Veld Portal command blocked",
                MB_OK | MB_ICONERROR);
            rejection = "Replay protection could not be saved";
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(remote_trust_mutex_);
            remote_trust_ = next;
        }
        if (!new_trust && !ConfirmRemoteCommand(command, false)) {
            rejection = "Command was denied on the paired machine";
            return false;
        }
        rejection.clear();
        return true;
    }

    void ExecuteRemoteCommand() {
        MonitoringReply::Command command;
        {
            std::lock_guard<std::mutex> lock(remote_command_mutex_);
            if (!remote_command_pending_ || remote_command_active_) return;
            command = pending_remote_command_;
            remote_command_pending_ = false;
            remote_command_active_ = true;
        }

        std::string authorization_error;
        if (!AuthorizeRemoteCommand(command, authorization_error)) {
            AcknowledgeRemoteCommand(command.id, "failed", authorization_error);
            std::lock_guard<std::mutex> lock(remote_command_mutex_);
            last_remote_command_id_ = command.id;
            remote_command_active_ = false;
            return;
        }

        const LiveState live = SnapshotState();
        const auto reject = [&](const std::string& message) {
            AcknowledgeRemoteCommand(command.id, "failed", message);
        };
        const auto complete = [&](const std::string& message) {
            AcknowledgeRemoteCommand(command.id, "completed", message);
        };

        if (command.action == "node.start") {
            if (live.process_running) {
                complete("Node is already running");
            } else {
                StartNode();
                AcknowledgeRemoteCommand(command.id, "local_confirmation",
                    "Start requested. A passphrase is required locally only when this app session is locked");
            }
        } else if (command.action == "node.stop") {
            if (!live.process_running) complete("Node is already stopped");
            else if (tor_preparing_.load() ||
                     update_operation_.load() != UpdateOperation::None) {
                reject("Node stop is unavailable during setup or update work");
            } else if (!RequestGuiNodeShutdown(live.pid)) {
                reject("Node did not accept the graceful stop request");
            } else {
                stopping_node_.store(true);
                worker_cv_.notify_all();
                InvalidateRect(hwnd_, nullptr, FALSE);
                complete("Graceful stop requested");
            }
        } else if (command.action == "updates.check") {
            if (update_operation_.load() != UpdateOperation::None)
                reject("An update operation is already running");
            else if (BeginUpdateCheck()) {
                complete("Signed release check started");
            } else
                reject("Signed release check could not start");
        } else if (command.action == "updates.install") {
            if (update_operation_.load() != UpdateOperation::None)
                reject("An update operation is already running");
            else if (!update_available_)
                reject("Check for an available signed update first");
            else if (BeginUpdateInstall()) {
                complete("Signed update installation started");
            } else
                reject("Signed update installation could not start");
        } else if (command.action == "mining.enabled") {
            mining_enabled_.store(command.enabled);
            SaveSettings();
            complete("Mining preference saved for the next app-managed start");
        } else if (command.action == "mining.workers") {
            mining_preset_ = 3;
            mining_thread_count_ = static_cast<unsigned>(command.workers);
            SaveSettings();
            complete("Worker count saved for the next app-managed start");
        } else if (command.action == "display.reference") {
            reference_display_enabled_.store(command.enabled);
            SaveSettings();
            worker_cv_.notify_all();
            complete("Public height display preference saved");
        } else if (command.action == "privacy.tor") {
            if (live.process_running || tor_preparing_.load())
                reject("Stop the node before changing Tor mode");
            else {
                tor_choice_ = command.enabled;
                if (tor_choice_) reachable_choice_ = false;
                SaveSettings();
                complete("Tor preference saved");
            }
        } else if (command.action == "network.reachable") {
            if (live.process_running || tor_choice_ || tor_preparing_.load())
                reject("Stop the clearnet node before changing reachability");
            else {
                reachable_choice_ = command.enabled;
                SaveSettings();
                complete("Inbound reachability preference saved");
            }
        } else if (command.action == "sync.mode") {
            if (live.process_running)
                reject("Stop the node before changing synchronization mode");
            else {
                full_ibd_choice_ = command.mode == "full";
                sync_choice_explicit_ = true;
                SaveSettings();
                complete("Synchronization preference saved");
            }
        } else {
            reject("Unsupported command");
        }
        InvalidateRect(hwnd_, nullptr, FALSE);
        {
            std::lock_guard<std::mutex> lock(remote_command_mutex_);
            last_remote_command_id_ = command.id;
            remote_command_active_ = false;
        }
    }

    std::string EnsureMonitoringToken(std::string& cached) {
        if (IsDeviceToken(cached)) return cached;
        const auto path = state_dir_ / L"remote-monitor.dat";
        cached = LoadDeviceToken(path);
        if (IsDeviceToken(cached)) return cached;
        cached = NewDeviceToken();
        if (cached.empty() || !SaveDeviceToken(path, cached)) {
            if (!cached.empty()) {
                SecureZeroMemory(cached.data(), cached.size());
                cached.clear();
            }
            return {};
        }
        return cached;
    }

    std::string BuildMonitoringReport(const LiveState& live,
                                      uint64_t& included_ack) {
        const uint64_t height = live.local_online ? live.local.height : 0;
        const uint64_t reference_height = live.reference_online
            ? live.reference.height : height;
        const uint64_t sync_lag = reference_height > height
            ? reference_height - height : 0;
        const uint64_t peers = live.peer_details_online
            ? static_cast<uint64_t>(live.peer_details.size())
            : (live.local_online ? live.local.peers : 0);
        const double hashrate = live.mining_status_online &&
                std::isfinite(live.mining.hashrate) && live.mining.hashrate >= 0.0
            ? live.mining.hashrate : 0.0;

        std::string state = "Stopped";
        std::string warning;
        if (live.process_running) {
            if (!mining_enabled_.load()) {
                state = "Node only";
            } else if (!live.local_online || !live.mining_status_online) {
                state = "Warning";
                warning = "Local node status is unavailable.";
            } else if (live.mining.mining_active) {
                state = "Mining";
            } else if (sync_lag > 0 ||
                       live.mining.work_state.find("sync") != std::string::npos) {
                state = "Syncing";
            } else {
                state = "Paused";
            }
            if (live.local_online && peers == 0) {
                state = "Warning";
                warning = "No peer connections are active.";
            }
        }

        uint64_t last_block_age = 0;
        const uint64_t now_seconds = static_cast<uint64_t>(std::time(nullptr));
        if (live.local_online && live.local.tip_timestamp > 0 &&
            now_seconds > live.local.tip_timestamp)
            last_block_age = now_seconds - live.local.tip_timestamp;

        std::unordered_map<std::string, uint64_t> peer_roles;
        peer_roles["fleet"] = 0;
        peer_roles["node"] = 0;
        peer_roles["miner"] = 0;
        peer_roles["validator"] = 0;
        peer_roles["unknown"] = 0;
        for (const auto& peer : live.peer_details) {
            auto it = peer_roles.find(peer.role);
            if (it == peer_roles.end()) ++peer_roles["unknown"];
            else ++it->second;
        }

        std::string ack_status;
        std::string ack_message;
        {
            std::lock_guard<std::mutex> lock(remote_ack_mutex_);
            included_ack = remote_ack_id_;
            ack_status = remote_ack_status_;
            ack_message = remote_ack_message_;
        }

        const size_t topology_node_count = std::min<size_t>(
            64, live.topology_online ? live.topology.nodes.size() : 0);
        std::unordered_set<uint64_t> topology_ids;
        for (size_t i = 0; i < topology_node_count; ++i)
            topology_ids.insert(live.topology.nodes[i].anonymous_id);

        std::ostringstream json;
        json << '{'
             << "\"portal_protocol\":3"
             << ",\"name\":\"" << JsonEscape(WideToUtf8(MonitoringMachineName()))
             << "\",\"version\":\"" << JsonEscape(veld::CLIENT_VERSION)
             << "\",\"height\":" << height
             << ",\"sync_lag\":" << sync_lag
             << ",\"hashrate\":" << std::fixed << std::setprecision(3)
             << hashrate
             << ",\"workers\":"
             << (live.mining_status_online ? live.mining.threads : 0)
             << ",\"peers\":" << peers
             << ",\"inbound\":" << live.inbound_peers
             << ",\"blocks\":"
             << (live.mining_status_online
                    ? live.mining.blocks_mined_session : 0)
             << ",\"mining_state\":\"" << state
             << "\",\"warning\":\"" << JsonEscape(warning) << "\""
             << ",\"snapshot\":{"
             << "\"process_running\":" << (live.process_running ? "true" : "false")
             << ",\"snapshot_eligible\":false"
             << ",\"full_ibd\":true"
             << ",\"tor\":" << (tor_choice_ ? "true" : "false")
             << ",\"reachable\":" << (reachable_choice_ ? "true" : "false")
             << ",\"reference\":" << (reference_display_enabled_.load() ? "true" : "false")
             << ",\"mining_enabled\":" << (mining_enabled_.load() ? "true" : "false")
             << ",\"mining_active\":" << (live.mining_status_online && live.mining.mining_active ? "true" : "false")
             << ",\"mining_ready\":" << (live.mining_status_online && live.mining.mining_ready ? "true" : "false")
             << ",\"port_mapped\":" << (live.port_mapped ? "true" : "false")
             << ",\"mempool\":" << (live.local_online ? live.local.mempool_size : 0)
             << ",\"supply\":" << std::fixed << std::setprecision(8)
             << (live.local_online ? live.local.supply_veld : 0.0)
             << ",\"chain_bytes\":" << live.chain_bytes
             << ",\"outbound\":" << live.outbound_peers
             << ",\"exact_tip\":" << live.exact_tip_peers
             << ",\"last_block_age\":" << last_block_age
             << ",\"total_hashes\":" << (live.mining_status_online ? live.mining.total_hashes : 0)
             << ",\"configured_workers\":" << mining_thread_count_
             << ",\"peer_roles\":{"
             << "\"fleet\":" << peer_roles["fleet"]
             << ",\"node\":" << peer_roles["node"]
             << ",\"miner\":" << peer_roles["miner"]
             << ",\"validator\":" << peer_roles["validator"]
             << ",\"unknown\":" << peer_roles["unknown"] << "}"
             << ",\"topology\":{"
             << "\"generated_at\":" << (live.topology_online
                    ? live.topology.generated_at : 0)
             << ",\"reporting_nodes\":" << (live.topology_online
                    ? live.topology.reporting_nodes : 0)
             << ",\"eligible_nodes\":" << (live.topology_online
                    ? live.topology.eligible_nodes : 0)
             << ",\"local_id\":" << (live.topology_online
                    ? live.local_topology_id : 0)
             << ",\"nodes\":[";
        for (size_t i = 0; i < topology_node_count; ++i) {
            const auto& node = live.topology.nodes[i];
            if (i != 0) json << ',';
            json << "{\"id\":" << node.anonymous_id
                 << ",\"role\":\"" << JsonEscape(node.role)
                 << "\",\"role_index\":" << node.role_index
                 << ",\"tip_state\":\"" << JsonEscape(node.tip_state)
                 << "\",\"updated_at\":" << node.updated_at << '}';
        }
        json << "],\"edges\":[";
        size_t topology_edge_count = 0;
        for (const auto& edge : live.topology.edges) {
            if (topology_edge_count >= 192 ||
                topology_ids.find(edge.first) == topology_ids.end() ||
                topology_ids.find(edge.second) == topology_ids.end())
                continue;
            if (topology_edge_count != 0) json << ',';
            json << "{\"first\":" << edge.first
                 << ",\"second\":" << edge.second
                 << ",\"confirmed\":"
                 << (edge.confirmed ? "true" : "false") << '}';
            ++topology_edge_count;
        }
        json << "]}"
             << ",\"recent_blocks\":[";
        const size_t first_block = live.recent_blocks.size() > 8
            ? live.recent_blocks.size() - 8 : 0;
        for (size_t i = first_block; i < live.recent_blocks.size(); ++i) {
            const auto& block = live.recent_blocks[i];
            if (i != first_block) json << ',';
            json << "{\"height\":" << block.height
                 << ",\"timestamp\":" << block.timestamp
                 << ",\"tx_count\":" << block.transaction_count
                 << ",\"reward\":" << std::fixed << std::setprecision(8)
                 << block.reward_veld
                 << ",\"hash\":\"" << JsonEscape(block.hash)
                 << "\",\"winner\":\"" << JsonEscape(block.winner) << "\"}";
        }
        json << "],\"events\":[";
        const size_t first_event = live.network_events.size() > 20
            ? live.network_events.size() - 20 : 0;
        for (size_t i = first_event; i < live.network_events.size(); ++i) {
            if (i != first_event) json << ',';
            json << '"' << JsonEscape(WideToUtf8(live.network_events[i].text))
                 << '"';
        }
        json << "]}";
        if (included_ack != 0) {
            json << ",\"ack_id\":" << included_ack
                 << ",\"ack_status\":\"" << JsonEscape(ack_status)
                 << "\",\"ack_message\":\"" << JsonEscape(ack_message)
                 << "\"";
        }
        json << '}';
        return json.str();
    }

    void ReportRemoteStatus(const LiveState& live, std::string& token) {
        if (!remote_monitoring_enabled_.load()) return;
        if (EnsureMonitoringToken(token).empty()) {
            std::lock_guard<std::mutex> lock(remote_monitor_mutex_);
            remote_monitor_status_.credential_ready = false;
            remote_monitor_status_.report_ok = false;
            remote_monitor_status_.detail =
                L"The protected device credential could not be created.";
            return;
        }

        uint64_t included_ack = 0;
        const std::string report = BuildMonitoringReport(live, included_ack);
        const HttpResult response = HttpPostJson(
            L"portal.veld.network", INTERNET_DEFAULT_HTTPS_PORT,
            L"/api/v1/device/report", report, token, 2500);
        if (!response.ok) {
            std::lock_guard<std::mutex> lock(remote_monitor_mutex_);
            remote_monitor_status_.credential_ready = true;
            remote_monitor_status_.report_ok = false;
            remote_monitor_status_.detail =
                L"Portal unavailable. Retrying automatically.";
            return;
        }

        MonitoringReply reply;
        if (!ParseMonitoringReply(response.body, reply)) {
            std::lock_guard<std::mutex> lock(remote_monitor_mutex_);
            remote_monitor_status_.credential_ready = true;
            remote_monitor_status_.report_ok = false;
            remote_monitor_status_.detail =
                L"Portal returned an invalid response. Retrying automatically.";
            return;
        }

        if (included_ack != 0) {
            std::lock_guard<std::mutex> lock(remote_ack_mutex_);
            if (remote_ack_id_ == included_ack) {
                remote_ack_id_ = 0;
                remote_ack_status_.clear();
                remote_ack_message_.clear();
            }
        }
        if (reply.command.present) {
            bool dispatch = false;
            {
                std::lock_guard<std::mutex> lock(remote_command_mutex_);
                if (!remote_command_pending_ && !remote_command_active_ &&
                    reply.command.id != last_remote_command_id_) {
                    pending_remote_command_ = reply.command;
                    remote_command_pending_ = true;
                    dispatch = true;
                }
            }
            if (dispatch) PostMessageW(hwnd_, WM_REMOTE_COMMAND, 0, 0);
        }
        std::wstring connection_detail;
        if (!reply.paired) {
            connection_detail = L"Open the portal and enter the one-time code.";
        } else if (!reply.command_key_present) {
            connection_detail =
                L"Monitoring is connected. Open the portal once to enroll secure control.";
        } else {
            PortalTrustState trusted;
            {
                std::lock_guard<std::mutex> lock(remote_trust_mutex_);
                trusted = remote_trust_;
            }
            if (trusted.Valid() && trusted.device_id == reply.device_id &&
                trusted.key_id != reply.command_key_id) {
                connection_detail =
                    L"The portal command key changed. Remote control is blocked until you re-pair locally.";
            } else if (trusted.Valid() && trusted.device_id == reply.device_id &&
                       trusted.key_id == reply.command_key_id) {
                connection_detail =
                    L"Signed control is active. Every action requires approval on this machine.";
            } else {
                connection_detail =
                    L"Signed control is enrolled. The first action will ask you to trust this pairing locally.";
            }
        }
        {
            std::lock_guard<std::mutex> lock(remote_monitor_mutex_);
            remote_monitor_status_.credential_ready = true;
            remote_monitor_status_.paired = reply.paired;
            remote_monitor_status_.report_ok = true;
            remote_monitor_status_.pair_code = Utf8ToWide(reply.pair_code);
            remote_monitor_status_.pair_expires = reply.pair_expires;
            remote_monitor_status_.last_report =
                static_cast<uint64_t>(std::time(nullptr));
            remote_monitor_status_.detail = std::move(connection_detail);
        }
    }

    void PollLoop() {
        auto last_reference = std::chrono::steady_clock::time_point{};
        auto last_topology = std::chrono::steady_clock::time_point{};
        auto last_size_scan = std::chrono::steady_clock::time_point{};
        uint64_t cached_chain_bytes = 0;
        veld::node_gui::ChainStats cached_reference;
        bool cached_reference_ok = false;
        veld::node_gui::TopologySnapshot cached_topology;
        bool cached_topology_ok = false;
        std::vector<veld::node_gui::BlockSummary> cached_blocks;
        uint64_t previous_peer_count = 0;
        std::deque<LiveState::NetworkEvent> cached_network_events;
        uint64_t previous_peer_bytes_sent = 0;
        uint64_t previous_peer_bytes_recv = 0;
        uint64_t previous_exact_tip_peers = 0;
        auto previous_peer_sample = std::chrono::steady_clock::time_point{};
        bool peer_sample_initialized = false;
        std::string monitoring_token;
        auto last_monitor_report = std::chrono::steady_clock::time_point{};
        while (!stop_worker_.load()) {
            DWORD tor_exit = STILL_ACTIVE;
            {
                std::lock_guard<std::mutex> lock(tor_process_mutex_);
                if (tor_setup_process_
                    && WaitForSingleObject(tor_setup_process_, 0) == WAIT_OBJECT_0) {
                    GetExitCodeProcess(tor_setup_process_, &tor_exit);
                    CloseHandle(tor_setup_process_);
                    tor_setup_process_ = nullptr;
                }
            }
            if (tor_exit != STILL_ACTIVE)
                PostMessageW(hwnd_, WM_TOR_SETUP_COMPLETE, tor_exit, 0);

            DWORD update_exit = STILL_ACTIVE;
            {
                std::lock_guard<std::mutex> lock(update_process_mutex_);
                if (update_process_ &&
                    WaitForSingleObject(update_process_, 0) == WAIT_OBJECT_0) {
                    GetExitCodeProcess(update_process_, &update_exit);
                    CloseHandle(update_process_);
                    update_process_ = nullptr;
                }
            }
            if (update_exit != STILL_ACTIVE)
                PostMessageW(hwnd_, WM_UPDATE_CHECK_COMPLETE, update_exit, 0);

            LiveState next;
            next.pid = FindNodeProcess();
            next.process_running = next.pid != 0;
            next.uptime_seconds = next.process_running
                ? ProcessUptime(next.pid) : 0;

            const HttpResult local = HttpGetJson(
                L"127.0.0.1", 8080, L"/api/stats", false, 900);
            if (local.ok) {
                std::string error;
                next.local_online = veld::node_gui::ParseStats(
                    local.body, next.local, error);
                if (!next.local_online) next.local_error = Utf8ToWide(error);
            } else {
                next.local_error = local.error;
            }
            if (next.local_online && (cached_blocks.empty() ||
                    cached_blocks.front().height != next.local.height)) {
                std::vector<veld::node_gui::BlockSummary> refreshed;
                const uint64_t count = std::min<uint64_t>(4, next.local.height + 1);
                refreshed.reserve(static_cast<size_t>(count));
                for (uint64_t offset = 0; offset < count; ++offset) {
                    const uint64_t height = next.local.height - offset;
                    const std::wstring path = L"/api/v1/block/" +
                        std::to_wstring(height);
                    const HttpResult block = HttpGetJson(
                        L"127.0.0.1", 8080, path.c_str(), false, 650);
                    if (!block.ok) break;
                    veld::node_gui::BlockSummary parsed;
                    std::string error;
                    if (!veld::node_gui::ParseBlockSummary(
                            block.body, parsed, error)) break;
                    refreshed.push_back(std::move(parsed));
                }
                if (!refreshed.empty()) cached_blocks = std::move(refreshed);
            }
            next.recent_blocks = cached_blocks;

            const std::string mining_body = ReadTextBounded(
                data_dir_ / L"gui-status.json");
            bool gui_status_fresh = false;
            if (!mining_body.empty()) {
                std::string error;
                veld::node_gui::MiningStats parsed;
                if (veld::node_gui::ParseMiningStats(
                        mining_body, parsed, error)) {
                    const uint64_t now_seconds = static_cast<uint64_t>(
                        std::time(nullptr));
                    if (parsed.updated_at <= now_seconds + 5 &&
                        now_seconds <= parsed.updated_at + 10) {
                        next.mining = std::move(parsed);
                        next.mining_status_online = true;
                        gui_status_fresh = true;
                    }
                }
            }
            if (gui_status_fresh) {
                std::vector<veld::node_gui::PeerSummary> parsed_peers;
                std::string error;
                if (veld::node_gui::ParseGuiPeerStatus(
                        mining_body, parsed_peers, error,
                        &next.known_peer_count, &next.port_mapped,
                        &next.local_topology_id)) {
                    next.peer_details_online = true;
                    for (const auto& peer : parsed_peers) {
                        if (peer.inbound) ++next.inbound_peers;
                        else ++next.outbound_peers;
                        if (peer.exact_tip) ++next.exact_tip_peers;
                        next.peer_bytes_sent += peer.bytes_sent;
                        next.peer_bytes_recv += peer.bytes_recv;
                    }

                    const auto sample_now = std::chrono::steady_clock::now();
                    if (previous_peer_sample.time_since_epoch().count() != 0) {
                        const double seconds = std::chrono::duration<double>(
                            sample_now - previous_peer_sample).count();
                        if (seconds > 0.0 &&
                            next.peer_bytes_sent >= previous_peer_bytes_sent) {
                            next.peer_send_rate =
                                static_cast<double>(next.peer_bytes_sent -
                                    previous_peer_bytes_sent) / seconds;
                        }
                        if (seconds > 0.0 &&
                            next.peer_bytes_recv >= previous_peer_bytes_recv) {
                            next.peer_recv_rate =
                                static_cast<double>(next.peer_bytes_recv -
                                    previous_peer_bytes_recv) / seconds;
                        }
                    }

                    auto add_event = [&](std::wstring text,
                                         bool warning = false) {
                        cached_network_events.push_front({
                            static_cast<uint64_t>(std::time(nullptr)),
                            std::move(text), warning});
                        while (cached_network_events.size() > 8)
                            cached_network_events.pop_back();
                    };
                    const uint64_t peer_count = parsed_peers.size();
                    if (!peer_sample_initialized) {
                        add_event(L"Peer topology loaded - " +
                            FormatUnsigned(peer_count) + L" connections");
                    } else {
                        if (peer_count > previous_peer_count) {
                            const uint64_t connected =
                                peer_count - previous_peer_count;
                            add_event(FormatUnsigned(connected) +
                                (connected == 1 ? L" peer connected"
                                                : L" peers connected"));
                        } else if (peer_count < previous_peer_count) {
                            const uint64_t disconnected =
                                previous_peer_count - peer_count;
                            add_event(FormatUnsigned(disconnected) +
                                (disconnected == 1 ? L" peer disconnected"
                                                   : L" peers disconnected"),
                                peer_count == 0);
                        }
                        if (previous_exact_tip_peers == 0 &&
                            next.exact_tip_peers > 0) {
                            add_event(L"Exact peer-tip agreement restored");
                        } else if (previous_exact_tip_peers > 0 &&
                                   next.exact_tip_peers == 0) {
                            add_event(L"Exact peer-tip agreement changed", true);
                        }
                    }
                    peer_sample_initialized = true;
                    previous_peer_count = peer_count;
                    previous_peer_bytes_sent = next.peer_bytes_sent;
                    previous_peer_bytes_recv = next.peer_bytes_recv;
                    previous_exact_tip_peers = next.exact_tip_peers;
                    previous_peer_sample = sample_now;
                    next.peer_details = std::move(parsed_peers);
                }
            }
            next.network_events.assign(cached_network_events.begin(),
                                       cached_network_events.end());
            const auto now = std::chrono::steady_clock::now();
            if (last_size_scan.time_since_epoch().count() == 0 ||
                now - last_size_scan >= std::chrono::seconds(15)) {
                last_size_scan = now;
                cached_chain_bytes = DirectorySizeBounded(data_dir_ / L"db");
            }
            next.chain_bytes = cached_chain_bytes;
            if (!reference_display_enabled_.load()) {
                cached_reference_ok = false;
                last_reference = {};
            } else if (last_reference.time_since_epoch().count() == 0 ||
                       now - last_reference >= std::chrono::seconds(15)) {
                last_reference = now;
                cached_reference_ok = false;
                const HttpResult remote = HttpGetJson(
                    L"explorer.veld.network", INTERNET_DEFAULT_HTTPS_PORT,
                    L"/api/stats", true, 2500);
                if (remote.ok) {
                    std::string error;
                    veld::node_gui::ChainStats parsed;
                    if (veld::node_gui::ParseStats(remote.body, parsed, error)) {
                        cached_reference = std::move(parsed);
                        cached_reference_ok = true;
                    }
                }
            }
            next.reference_online = cached_reference_ok;
            next.reference = cached_reference;
            if (last_topology.time_since_epoch().count() == 0 ||
                now - last_topology >= std::chrono::seconds(15)) {
                last_topology = now;
                cached_topology_ok = false;
                const HttpResult remote = HttpGetJson(
                    L"explorer.veld.network", INTERNET_DEFAULT_HTTPS_PORT,
                    L"/api/v1/topology", true, 2500);
                if (remote.ok) {
                    std::string error;
                    veld::node_gui::TopologySnapshot parsed;
                    if (veld::node_gui::ParseTopologySnapshot(
                            remote.body, parsed, error)) {
                        const uint64_t now_seconds = static_cast<uint64_t>(
                            std::time(nullptr));
                        if (parsed.generated_at <= now_seconds + 5 &&
                            now_seconds <= parsed.generated_at + 120) {
                            cached_topology = std::move(parsed);
                            cached_topology_ok = true;
                        }
                    }
                }
            }
            next.topology_online = cached_topology_ok;
            next.topology = cached_topology;
            next.snapshot_eligible = false;
            next.log_lines = ReadLogTail(LogPath());

            if (remote_monitoring_enabled_.load()) {
                if (last_monitor_report.time_since_epoch().count() == 0 ||
                    now - last_monitor_report >= std::chrono::seconds(5)) {
                    last_monitor_report = now;
                    ReportRemoteStatus(next, monitoring_token);
                }
            } else {
                last_monitor_report = {};
            }

            {
                std::lock_guard<std::mutex> lock(state_mutex_);
                state_ = next;
                if (next.local_online) {
                    if (history_.empty() || history_.back().height != next.local.height ||
                        now - history_.back().at >= std::chrono::seconds(20)) {
                        history_.push_back({now, next.local.height});
                    }
                    while (!history_.empty() &&
                           history_.front().at < now - std::chrono::minutes(65))
                        history_.pop_front();
                    while (history_.size() > 2400) history_.pop_front();
                }
                if (next.mining_status_online) {
                    rate_history_.push_back({now, next.mining.hashrate});
                    while (!rate_history_.empty() &&
                           rate_history_.front().at < now - std::chrono::minutes(65))
                        rate_history_.pop_front();
                    while (rate_history_.size() > 2400) rate_history_.pop_front();
                }
            }
            const DWORD managed_pid = owned_pid_.load();
            if (managed_pid != 0 && next.process_running && next.local_online)
                session_unlock_confirmed_.store(true);
            if (managed_pid != 0 && !next.process_running) {
                const bool intentional_stop = stopping_node_.load();
                if (!session_unlock_confirmed_.load() || !intentional_stop)
                    ClearSessionPassphrase();
                session_unlock_confirmed_.store(false);
                owned_pid_.store(0);
            }
            if (!next.process_running)
                stopping_node_.store(false);
            PostMessageW(hwnd_, WM_NODE_REFRESH, 0, 0);

            std::unique_lock<std::mutex> lock(worker_wait_mutex_);
            worker_cv_.wait_for(lock, std::chrono::milliseconds(1500),
                                [this] { return stop_worker_.load(); });
        }
        if (!monitoring_token.empty())
            SecureZeroMemory(monitoring_token.data(), monitoring_token.size());
    }
};

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show) {
    veld::compat::HardenDllSearchPath();
#if defined(VELD_PUBLIC_RELEASE) && !defined(VELD_GUI_TEST_INSTANCE)
    std::wstring package_error;
    if (!VerifySignedPackage(ModulePath(), package_error)) {
        const std::wstring message = package_error +
            L"\n\nNo node, wallet, updater, or helper was started. Re-download "
            L"the complete client from https://veld.network.";
        MessageBoxW(nullptr, message.c_str(), L"Veld package blocked",
                    MB_OK | MB_ICONERROR);
        return ERROR_INVALID_DATA;
    }
#endif
#ifdef VELD_GUI_TEST_INSTANCE
    if (wcsstr(GetCommandLineW(), L"--qa-passphrase") != nullptr) {
        PassphrasePrompt request{
            L"Unlock node identity",
            L"Enter the passphrase for this identity.",
            {}};
        DialogBoxParamW(instance, MAKEINTRESOURCEW(IDD_VELD_PASSPHRASE),
                        nullptr, PassphraseDialogProc,
                        reinterpret_cast<LPARAM>(&request));
        SecureZeroMemory(request.value.data(),
                         request.value.size() * sizeof(wchar_t));
        return 0;
    }
    HANDLE singleton = CreateMutexW(nullptr, FALSE, L"Local\\VeldNodeGuiQaSingleton");
#else
    HANDLE singleton = CreateMutexW(nullptr, FALSE, L"Local\\VeldNodeGuiSingleton");
#endif
    if (!singleton || GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(nullptr, L"Veld Node is already open.", L"Veld Node",
                    MB_OK | MB_ICONINFORMATION);
        if (singleton) CloseHandle(singleton);
        return 0;
    }
    NodeGuiApp app(instance);
    const int result = app.Run(show);
    CloseHandle(singleton);
    return result;
}
