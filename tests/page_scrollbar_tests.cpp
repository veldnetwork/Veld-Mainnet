#define NOMINMAX
#include "gui/page_scrollbar.h"
#include <iostream>
#include <stdexcept>
void Check(bool ok,const char* why){if(!ok)throw std::runtime_error(why);std::cout<<"PASS "<<why<<'\n';}
veld::node_gui::PageScrollBar* active_bar{};
int position=0,paint_depth=0,max_paint_depth=0;
LRESULT CALLBACK Parent(HWND hwnd,UINT message,WPARAM wp,LPARAM lp) {
    if(message==WM_PAINT && active_bar) {
        ++paint_depth;max_paint_depth=std::max(max_paint_depth,paint_depth);
        PAINTSTRUCT ps{};BeginPaint(hwnd,&ps);
        RECT client{};GetClientRect(hwnd,&client);
        if(paint_depth<8)active_bar->Update(client,1600,position,96);
        EndPaint(hwnd,&ps);--paint_depth;return 0;
    }
    return DefWindowProcW(hwnd,message,wp,lp);
}
int main()try {
    WNDCLASSW wc{};wc.lpfnWndProc=Parent;wc.hInstance=GetModuleHandleW(nullptr);wc.lpszClassName=L"VeldScrollbarRegression";
    Check(RegisterClassW(&wc)!=0,"register native parent without a shared DC");
    HWND parent=CreateWindowExW(WS_EX_COMPOSITED,wc.lpszClassName,L"Scrollbar fixture",WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
        0,0,900,700,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
    Check(parent!=nullptr,"isolated composited native parent");
    veld::node_gui::PageScrollBar bar;Check(bar.Create(parent),"native scrollbar creation");
    ShowWindow(parent,SW_SHOWNOACTIVATE);
    for(int dpi:{96,120,144,192}) {
        RECT bounds{0,0,900,600};bar.Update(bounds,1200,300,dpi);
        SCROLLINFO si{};si.cbSize=sizeof(si);si.fMask=SIF_ALL;
        Check(GetScrollInfo(bar.Window(),SB_CTL,&si) && si.nPage==600 && si.nPos==300 && si.nMax==1199,
            "native range and position match the page");
        SCROLLBARINFO accessible{};accessible.cbSize=sizeof(accessible);
        Check(GetScrollBarInfo(bar.Window(),OBJID_CLIENT,&accessible) && accessible.xyThumbBottom>accessible.xyThumbTop,
            "native accessibility exposes a real draggable thumb");
        RECT client{};GetClientRect(bar.Window(),&client);
        auto dc=GetDC(bar.Window());auto memory=CreateCompatibleDC(dc);auto bitmap=CreateCompatibleBitmap(dc,client.right,client.bottom);
        auto old=SelectObject(memory,bitmap);
        SendMessageW(bar.Window(),WM_PRINTCLIENT,reinterpret_cast<WPARAM>(memory),PRF_CLIENT);
        Check(GetPixel(memory,0,client.bottom/2)==RGB(8,10,9),"scrollbar uses the page background without a white gutter");
        const int middle=(accessible.xyThumbTop+accessible.xyThumbBottom)/2;
        Check(GetPixel(memory,client.right/2,middle)==RGB(83,89,96),"thumb is charcoal at every tested DPI");
        SelectObject(memory,old);DeleteObject(bitmap);DeleteDC(memory);ReleaseDC(bar.Window(),dc);
        bar.Update(bounds,600,0,dpi);Check(!IsWindowVisible(bar.Window()),"no scrollbar when the page fits");
        bar.Update(bounds,1200,99999,dpi);si.fMask=SIF_POS;GetScrollInfo(bar.Window(),SB_CTL,&si);
        Check(si.nPos==600,"native thumb clamps beyond the final page");
    }
    active_bar=&bar;
    for(int i=0;i<120;++i) {
        position=(i*37)%800;
        InvalidateRect(parent,nullptr,FALSE);UpdateWindow(parent);
        MSG message{};
        for(int count=0;count<100 && PeekMessageW(&message,nullptr,0,0,PM_REMOVE);++count) {
            TranslateMessage(&message);DispatchMessageW(&message);
        }
    }
    Check(max_paint_depth<=1,"scrollbar updates inside composited parent paint never reenter paint");
    active_bar=nullptr;DestroyWindow(parent);return 0;
}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}
