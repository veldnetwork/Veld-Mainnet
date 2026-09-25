// Native clipping regression using the real panel and a disposable window.
// No node, worker, wallet, network connection or production profile is started.
#define VELD_GUI_TEST_INSTANCE
#include "gui/pool_panel.h"
#include "gui/window_restore.h"
#include <iostream>
#include <memory>

namespace {
std::unique_ptr<veld::node_gui::PoolPanel> panel;
bool layout_before_paint=true;
int top=20,scale=96;
bool vacated_visible=false;
POINT probe{24,24};
void Check(bool value,const char* name) {
    if(!value)throw std::runtime_error(name);
    std::cout<<"PASS "<<name<<'\n';
}
void Layout() {
    if(panel)panel->Show(true,20,top,680,scale,
        static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT)));
}
LRESULT CALLBACK Procedure(HWND window,UINT message,WPARAM wp,LPARAM lp) {
    if(message==WM_PAINT) {
        if(layout_before_paint)Layout();
        PAINTSTRUCT ps{};auto dc=BeginPaint(window,&ps);
        if(!layout_before_paint)Layout();
        vacated_visible=PtVisible(dc,probe.x,probe.y)!=FALSE;
        RECT rectangle{};GetClientRect(window,&rectangle);
        auto brush=CreateSolidBrush(RGB(8,10,9));FillRect(dc,&rectangle,brush);DeleteObject(brush);
        EndPaint(window,&ps);return 0;
    }
    if(message==WM_DRAWITEM && panel && panel->Draw(*reinterpret_cast<DRAWITEMSTRUCT*>(lp)))return TRUE;
    return DefWindowProcW(window,message,wp,lp);
}
void Pump() {MSG message{};while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)){TranslateMessage(&message);DispatchMessageW(&message);}}
}
int main(int argc,char** argv) try {
    if(argc==2 && std::string(argv[1])=="--legacy-paint-order")layout_before_paint=false;
    WNDCLASSW wc{};wc.lpfnWndProc=Procedure;wc.hInstance=GetModuleHandleW(nullptr);
    wc.lpszClassName=veld::node_gui::WindowClassName();
    Check(RegisterClassW(&wc)!=0,"register isolated QA window class");
    Check(!veld::node_gui::RestoreExistingWindow(1),"absent window returns without starting a replacement");
    HWND window=CreateWindowExW(WS_EX_COMPOSITED,wc.lpszClassName,L"Veld repaint regression",WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
        40,40,760,700,nullptr,nullptr,wc.hInstance,nullptr);
    Check(window!=nullptr,"native clipped parent");
    ShowWindow(window,SW_SHOWNOACTIVATE);Pump();
    const auto root=std::filesystem::temp_directory_path()/("veld-scroll-"+std::to_string(GetCurrentProcessId()));
    Check(!std::filesystem::exists(root),"unused disposable profile");
    std::string error;Check(veld::channel::secure_file::EnsurePrivateDirectory(root.string(),&error),"private fixture");
    panel=std::make_unique<veld::node_gui::PoolPanel>(window,root,root/L"absent-worker.exe",14,[]{return false;});
    for(int dpi:{96,120,144,192}) {
        scale=dpi;top=20;Layout();
        RedrawWindow(window,nullptr,nullptr,RDW_INVALIDATE|RDW_ALLCHILDREN|RDW_UPDATENOW);Pump();
        for(int repeat=0;repeat<12;++repeat) {
            top=top==20?120:20;
            probe={100,25}; // Old label, now above every child when moving down.
            InvalidateRect(window,nullptr,FALSE);UpdateWindow(window);Pump();
            if(top==120) {
                Check(vacated_visible,"scroll exposes the vacated control rectangle to parent painting");
                const HDC dc=GetDC(window);const auto pixel=GetPixel(dc,probe.x,probe.y);ReleaseDC(window,dc);
                Check(pixel==RGB(8,10,9),"vacated strip repainted with the exact parent background");
            }
        }
    }
    Check(!panel->Running(),"scrolling never starts a worker");
    panel.reset();
    ShowWindow(window,SW_MINIMIZE);Pump();
    Check(IsIconic(window) && IsWindowVisible(window),"minimized fixture retains taskbar visibility");
    Check(veld::node_gui::RestoreExistingWindow(1),"restore minimized existing window");Pump();
    Check(IsWindowVisible(window) && !IsIconic(window),"minimized window restored");
    ShowWindow(window,SW_HIDE);Pump();
    Check(veld::node_gui::RestoreExistingWindow(1),"restore legacy tray-hidden window");Pump();
    Check(IsWindowVisible(window) && !IsIconic(window),"legacy hidden window restored");
    DestroyWindow(window);std::filesystem::remove_all(root);
    std::cout<<"PASS native scroll and instance restoration; visual acceptance remains separate\n";
} catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
