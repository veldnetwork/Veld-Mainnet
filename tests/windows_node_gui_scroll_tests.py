#!/usr/bin/env python3
"""Static regression checks for the native Windows page-scroll contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUI = (ROOT / "src" / "veld-node-gui.cpp").read_text(encoding="utf-8")


def require(fragment: str, label: str) -> None:
    if fragment not in GUI:
        raise AssertionError(label)


require("page_scrollbar_.Create(hwnd_)", "window exposes an accessible native scrollbar")
require("WS_EX_COMPOSITED, wc.lpszClassName", "parent and child controls share a composited frame")
require("case WM_MOUSEWHEEL:", "mouse wheel scrolling is handled")
require("case WM_VSCROLL:", "scrollbar input is handled")
require("wp == VK_PRIOR", "keyboard page scrolling is handled")
require("std::array<int, 9> page_scroll_offsets_", "all nine pages keep their own offset")
require("page_ == Page::Settings ? S(1502) :",
        "settings receives enough virtual height for all controls")
require("point.y += CurrentPageScroll(client)",
        "content hit testing follows the visible scroll offset")
require("SetViewportOrgEx(dc, 0, -page_scroll, nullptr)",
        "page drawing uses the current scroll offset")
require("DrawSidebar(dc, client, live);", "sidebar remains separately rendered")
require("info->ptMinTrackSize.y = S(640)",
        "the app can fit on ordinary laptop displays")
require('parse_int("window_height", 640, 4320,',
        "laptop-sized windows remain the same size when reopened")

sidebar = GUI.index("DrawSidebar(dc, client, live);")
viewport = GUI.index("SetViewportOrgEx(dc, 0, -page_scroll, nullptr)")
if sidebar >= viewport:
    raise AssertionError("fixed sidebar must render before the scrolling page viewport")

print("PASS windows_node_gui_scroll_tests checks=11")

paint = GUI[GUI.index("    void Paint() {"):GUI.index("    void DrawSidebar(")]
if paint.index("pool_panel_->Show(") >= paint.index("BeginPaint("):
    raise AssertionError("pool controls must move before the paint DC clips their old positions")
resize = GUI[GUI.index("            case WM_SIZE:"):GUI.index("            case WM_EXITSIZEMOVE:")]
if "ShouldHideInTray(minimize_to_tray_, tray_added_, wp)" not in resize:
    raise AssertionError("only explicit tray opt-in with an available icon may hide a minimized window")
require("bool minimize_to_tray_{false};", "minimizing retains the taskbar entry by default")
require("veld::node_gui::RestoreExistingWindow()", "second launch restores the existing instance")
print("PASS pool scroll layout precedes paint and existing windows remain recoverable")
