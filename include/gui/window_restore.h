#pragma once
#include <windows.h>

namespace veld::node_gui {
inline const wchar_t* WindowClassName() {
#ifdef VELD_GUI_TEST_INSTANCE
    return L"VeldNodeGuiQaWindow";
#else
    return L"VeldNodeGuiWindow";
#endif
}

// A second launch only reveals the existing window. It does not start another
// worker, change the profile, or pass commands or credentials to that instance.
inline bool RestoreExistingWindow(unsigned attempts = 40) {
    for (unsigned attempt = 0; attempt < attempts; ++attempt) {
        if (HWND window = FindWindowW(WindowClassName(), nullptr)) {
            DWORD pid = 0;
            GetWindowThreadProcessId(window, &pid);
            if (pid)
                AllowSetForegroundWindow(pid);
            if (!ShowWindowAsync(window, SW_RESTORE))
                return false;
            SetForegroundWindow(window);
            return true;
        }
        if (attempt + 1 < attempts)
            Sleep(50);
    }
    return false;
}
} // namespace veld::node_gui
