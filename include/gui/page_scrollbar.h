#pragma once
#include <windows.h>
#include <commctrl.h>
#include <algorithm>

namespace veld::node_gui {
// Retain the native scrollbar's keyboard, drag, capture and accessibility
// behavior, but render it with the same neutral palette as the client.
class PageScrollBar {
    HWND window_{};
    RECT last_{};
    int content_=-1,page_=-1,position_=-1;
    bool visible_=false;
    static void Paint(HWND window,HDC target) {
        RECT bounds{};GetClientRect(window,&bounds);
        if(bounds.right<=0 || bounds.bottom<=0)return;
        HDC dc=CreateCompatibleDC(target);
        HBITMAP bitmap=CreateCompatibleBitmap(target,bounds.right,bounds.bottom);
        auto old=SelectObject(dc,bitmap);
        auto brush=CreateSolidBrush(RGB(8,10,9));FillRect(dc,&bounds,brush);DeleteObject(brush);
        SCROLLBARINFO info{};info.cbSize=sizeof(info);
        if(GetScrollBarInfo(window,OBJID_CLIENT,&info)) {
            const int inset=std::max<LONG>(3,bounds.right/4);
            RECT thumb{inset,info.xyThumbTop,bounds.right-inset,info.xyThumbBottom};
            if(thumb.bottom>thumb.top) {
                brush=CreateSolidBrush(RGB(83,89,96));auto pen=CreatePen(PS_SOLID,1,RGB(83,89,96));
                auto b=SelectObject(dc,brush),p=SelectObject(dc,pen);
                RoundRect(dc,thumb.left,thumb.top,thumb.right,thumb.bottom,inset*2,inset*2);
                if(GetFocus()==window) {
                    RECT focus=thumb;InflateRect(&focus,-1,-2);DrawFocusRect(dc,&focus);
                }
                SelectObject(dc,b);SelectObject(dc,p);DeleteObject(brush);DeleteObject(pen);
            }
            auto pen=CreatePen(PS_SOLID,1,RGB(134,141,150));auto prior=SelectObject(dc,pen);
            const int x=bounds.right/2,arrow=std::max<LONG>(2,bounds.right/5);
            for(int down=0;down<2;++down) {
                const int y=down?bounds.bottom-info.dxyLineButton/2:info.dxyLineButton/2;
                MoveToEx(dc,x-arrow,y+(down?-1:1)*arrow/2,nullptr);
                LineTo(dc,x,y+(down?1:-1)*arrow/2);
                LineTo(dc,x+arrow,y+(down?-1:1)*arrow/2);
            }
            SelectObject(dc,prior);DeleteObject(pen);
        }
        BitBlt(target,0,0,bounds.right,bounds.bottom,dc,0,0,SRCCOPY);
        SelectObject(dc,old);DeleteObject(bitmap);DeleteDC(dc);
    }
    static LRESULT CALLBACK Procedure(HWND window,UINT message,WPARAM wp,LPARAM lp,UINT_PTR,DWORD_PTR) {
        if(message==WM_ERASEBKGND)return 1;
        if(message==WM_PAINT) {
            PAINTSTRUCT ps{};auto dc=BeginPaint(window,&ps);Paint(window,dc);EndPaint(window,&ps);return 0;
        }
        if(message==WM_PRINTCLIENT){Paint(window,reinterpret_cast<HDC>(wp));return 0;}
        if(message==WM_MOUSEWHEEL)return SendMessageW(GetParent(window),message,wp,lp);
        const auto result=DefSubclassProc(window,message,wp,lp);
        if(message==WM_MOUSEMOVE || message==WM_LBUTTONDOWN || message==WM_LBUTTONUP ||
           message==WM_KEYDOWN || message==WM_TIMER || message==WM_SETFOCUS || message==WM_KILLFOCUS ||
           message==WM_ENABLE)
            // Never synchronously paint a composited child from inside a
            // scrollbar update: it can reenter the parent's layout/paint.
            InvalidateRect(window,nullptr,FALSE);
        return result;
    }
public:
    bool Create(HWND parent) {
        window_=CreateWindowExW(0,L"SCROLLBAR",L"Page scroll",WS_CHILD|WS_TABSTOP|SBS_VERT,
            0,0,0,0,parent,nullptr,GetModuleHandleW(nullptr),nullptr);
        return window_ && SetWindowSubclass(window_,Procedure,1,0);
    }
    HWND Window() const{return window_;}
    int TrackPosition() const {
        SCROLLINFO info{};info.cbSize=sizeof(info);info.fMask=SIF_TRACKPOS;
        return GetScrollInfo(window_,SB_CTL,&info)?info.nTrackPos:position_;
    }
    void Update(const RECT& client,int content,int position,int scale) {
        if(!window_)return;
        const bool visible=content>client.bottom;
        const int width=MulDiv(18,scale,96),margin=MulDiv(4,scale,96);
        RECT next{client.right-width-margin,margin,client.right-margin,client.bottom-margin};
        const bool moved=!EqualRect(&next,&last_);
        if(moved)SetWindowPos(window_,nullptr,next.left,next.top,next.right-next.left,next.bottom-next.top,
            SWP_NOACTIVATE|SWP_NOZORDER|SWP_NOCOPYBITS|SWP_NOREDRAW);
        if(content!=content_ || client.bottom!=page_ || position!=position_) {
            SCROLLINFO info{};info.cbSize=sizeof(info);info.fMask=SIF_RANGE|SIF_PAGE|SIF_POS;
            info.nMin=0;info.nMax=content-1;info.nPage=std::max<LONG>(1,client.bottom);info.nPos=position;
            SetScrollInfo(window_,SB_CTL,&info,FALSE);
            InvalidateRect(window_,nullptr,FALSE);
        }
        if(visible!=visible_)ShowWindow(window_,visible?SW_SHOWNA:SW_HIDE);
        if(moved)InvalidateRect(window_,nullptr,FALSE);
        last_=next;content_=content;page_=client.bottom;position_=position;visible_=visible;
    }
};
} // namespace veld::node_gui
