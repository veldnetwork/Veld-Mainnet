#define VELD_GUI_TEST_INSTANCE 1
#define VELD_POOL_GUI_QUALIFICATION 1
#define wWinMain veld_gui_unused_entry
#include "../src/veld-node-gui.cpp"
#undef wWinMain
#include <iostream>

namespace {
void Check(bool ok,const char* label) {if(!ok)throw std::runtime_error(label);std::cout<<"PASS "<<label<<'\n';}
void Bitmap(const std::filesystem::path& path,HDC dc,int width,int height) {
    BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=width;
    info.bmiHeader.biHeight=-height;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;
    std::vector<BYTE> pixels(width*height*4);HBITMAP bitmap=reinterpret_cast<HBITMAP>(GetCurrentObject(dc,OBJ_BITMAP));
    Check(GetDIBits(dc,bitmap,0,height,pixels.data(),&info,DIB_RGB_COLORS)!=0,"settings render pixels");
    BITMAPFILEHEADER file{};file.bfType=0x4d42;file.bfOffBits=sizeof(file)+sizeof(info.bmiHeader);file.bfSize=file.bfOffBits+static_cast<DWORD>(pixels.size());
    std::ofstream out(path,std::ios::binary);out.write(reinterpret_cast<char*>(&file),sizeof(file));out.write(reinterpret_cast<char*>(&info.bmiHeader),sizeof(info.bmiHeader));out.write(reinterpret_cast<char*>(pixels.data()),pixels.size());
}
struct GuiStateQualification {
    static void Run(const std::filesystem::path& dir) {
        using namespace veld::node_gui;
        NodeGuiApp app(dir);
        Check(!app.startup_enabled_&&!app.minimize_to_tray_&&!app.startup_unlock_enabled_,"startup, tray and remembered unlock default off");
        app.startup_enabled_=true;app.startup_mode_=StartupMode::Pool;app.minimize_to_tray_=true;
        Check(app.SaveSettings(false),"save startup preferences without registration or keys");
        NodeGuiApp restored(dir);restored.LoadSettings();
        Check(restored.startup_enabled_&&restored.startup_mode_==StartupMode::Pool&&restored.minimize_to_tray_,"startup and tray survive restart");
        for(auto mode:{StartupMode::App,StartupMode::Solo,StartupMode::Pool,StartupMode::Node})
            Check(ParseStartupMode(StartupModeName(mode))==mode,"four startup modes round trip");
        Check(ParseStartupMode("bogus")==StartupMode::App,"invalid startup mode does not start mining");
        app.hwnd_=CreateWindowExW(0,L"STATIC",L"Veld settings qualification",WS_OVERLAPPEDWINDOW,0,0,1100,750,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
        Check(app.hwnd_!=nullptr,"isolated native window");ShowWindow(app.hwnd_,SW_SHOWNOACTIVATE);
        app.minimize_to_tray_=false;app.tray_added_=true;app.WndProc(WM_SIZE,SIZE_MINIMIZED,0);
        Check(IsWindowVisible(app.hwnd_),"default minimize retains taskbar window");
        app.minimize_to_tray_=true;app.tray_added_=false;app.WndProc(WM_SIZE,SIZE_MINIMIZED,0);
        Check(IsWindowVisible(app.hwnd_),"failed tray registration never hides window");
        app.tray_added_=true;app.WndProc(WM_SIZE,SIZE_MINIMIZED,0);
        Check(!IsWindowVisible(app.hwnd_),"opt-in tray minimize hides native window");
        app.RestoreFromTray();Check(IsWindowVisible(app.hwnd_),"native tray restore reopens window");app.tray_added_=false;
        app.CreateFonts();HDC window=GetDC(app.hwnd_),dc=CreateCompatibleDC(window);HBITMAP bmp=CreateCompatibleBitmap(window,1050,1350);
        auto old=SelectObject(dc,bmp);RECT client{0,0,1050,1350};FillRect(dc,&client,reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
        app.DrawSettings(dc,client,LiveState{});Bitmap(dir/L"settings.bmp",dc,1050,1350);
        Check(app.startup_mode_buttons_[3].right<client.right&&app.tray_toggle_.bottom<app.mining_mode_toggle_.top,"startup, tray and CPU controls fit without overlap");
        SelectObject(dc,old);DeleteObject(bmp);DeleteDC(dc);ReleaseDC(app.hwnd_,window);DestroyWindow(app.hwnd_);app.hwnd_=nullptr;
    }
};
}
int main(int argc,char** argv)try {
    using namespace veld::node_gui;Check(argc==2,"explicit disposable directory");std::filesystem::path dir(argv[1]);Check(!std::filesystem::exists(dir),"fresh fixture");std::filesystem::create_directories(dir);
    const auto id=std::to_wstring(GetCurrentProcessId()),key=L"Software\\VeldQualification\\Startup-"+id;
    const auto target=L"VeldQualification/StartupUnlock/"+id;
    struct Cleanup {std::wstring key,target;~Cleanup(){RegDeleteTreeW(HKEY_CURRENT_USER,key.c_str());RemoveStartupUnlock(target);}} cleanup{key,target};
    std::wstring actual_run;Check(ReadStartupCommand(actual_run),"read existing Run entry without mutation");
    auto cmd=StartupCommand(L"C:\\Test path é\\Veld Node.exe",L"C:\\Data 日\\");
    int count=0;auto args=CommandLineToArgvW(cmd.c_str(),&count);
    Check(args&&count==4&&std::wstring(args[1])==L"--windows-startup"&&std::wstring(args[3])==L"C:\\Data 日\\","quoted Unicode startup command round trip");LocalFree(args);
    Check(StartupCommand(L"relative.exe",L"C:\\Data").empty()&&StartupCommand(L"C:\\app.exe",L"C:\\"+std::wstring(270,L'x')).empty(),"unsafe or Windows-truncated command refused");
    Check(WriteStartupCommand(cmd,key.c_str()),"write only disposable registry key");std::wstring value;Check(ReadStartupCommand(value,key.c_str())&&value==cmd,"exact registry command readback");
    Check(WriteStartupCommand(L"",key.c_str())&&ReadStartupCommand(value,key.c_str())&&value.empty(),"disable removes startup registration");
    const std::wstring identity(64,L'a');Check(SaveStartupUnlock(target,identity,L"disposable test passphrase"),"Windows protects opt-in startup credential");
    Check(ReadStartupUnlock(target,identity,value)&&value==L"disposable test passphrase","same-account credential round trip");
    Check(!ReadStartupUnlock(target,std::wstring(64,L'b'),value)&&value.empty(),"changed identity cannot reuse unlock");
    Check(!ReadStartupUnlock(target+L"-other",identity,value),"another installation context cannot reuse unlock");
    Check(RemoveStartupUnlock(target)&&!ReadStartupUnlock(target,identity,value),"revocation removes persistent unlock");
    GuiStateQualification::Run(dir);
    std::wstring after;Check(ReadStartupCommand(after)&&after==actual_run,"real Windows startup entry unchanged by qualification");
    std::cout<<"PASS_WINDOWS_STARTUP_SETTINGS\n";
}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
