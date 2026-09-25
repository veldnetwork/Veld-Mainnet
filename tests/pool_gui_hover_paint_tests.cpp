#define VELD_GUI_TEST_INSTANCE 1
#define VELD_POOL_GUI_QUALIFICATION 1
#define wWinMain veld_gui_unused_entry
#include "../src/veld-node-gui.cpp"
#undef wWinMain
#include <iostream>
namespace {
struct GuiStateQualification {
    static void Check(bool ok,const char* label) {
        if(!ok)throw std::runtime_error(label);
        std::cout<<"PASS "<<label<<'\n';
    }
    static void Run() {
        const auto dir=std::filesystem::temp_directory_path()/("veld-hover-"+std::to_string(GetCurrentProcessId()));
        Check(!std::filesystem::exists(dir),"unused disposable profile");
        NodeGuiApp app(dir);
        app.hwnd_=CreateWindowExW(0,L"STATIC",L"Paint region qualification",WS_OVERLAPPEDWINDOW,
            0,0,1100,750,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
        Check(app.hwnd_!=nullptr,"real Windows update region");
        ShowWindow(app.hwnd_,SW_SHOWNOACTIVATE);
        UpdateWindow(app.hwnd_);
        app.page_=Page::Pool;app.hover_point_={500,350};app.tracking_mouse_leave_=true;
        ValidateRect(app.hwnd_,nullptr);
        for(int i=0;i<200;++i)app.WndProc(WM_MOUSEMOVE,0,MAKELPARAM(300+i,360+i%30));
        Check(!GetUpdateRect(app.hwnd_,nullptr,FALSE),"200 pool pointer movements do not invalidate native controls");
        app.WndProc(WM_MOUSELEAVE,0,0);
        Check(!GetUpdateRect(app.hwnd_,nullptr,FALSE),"entering a child does not repaint its parent");
        app.hover_point_={500,350};app.WndProc(WM_MOUSEMOVE,0,MAKELPARAM(100,200));
        RECT region{};
        Check(GetUpdateRect(app.hwnd_,&region,FALSE)&&region.right<=app.S(252),"sidebar hover updates stay outside the pool controls");
        ValidateRect(app.hwnd_,nullptr);
        app.WndProc(WM_TIMER,0,0);
        Check(GetUpdateRect(app.hwnd_,&region,FALSE)&&region.right<=app.S(252),"timer does not repaint unchanged pool children");
        ValidateRect(app.hwnd_,nullptr);
        app.page_=Page::Overview;app.WndProc(WM_MOUSEMOVE,0,MAKELPARAM(510,300));
        Check(GetUpdateRect(app.hwnd_,&region,FALSE)&&region.right>app.S(252),"custom drawn solo pages retain hover feedback");
        DestroyWindow(app.hwnd_);app.hwnd_=nullptr;
        Check(!std::filesystem::exists(dir),"no configuration, wallets or workers created");
    }
};
}
int main()try{GuiStateQualification::Run();}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
