// Native Windows regression: stable state must not repaint every child control.
#include "gui/pool_panel.h"
#include <iostream>
#include <cassert>
namespace {
struct Counts {unsigned position=0,font=0,text=0,enable=0;} counts;
LRESULT CALLBACK Observe(HWND w,UINT m,WPARAM p,LPARAM l,UINT_PTR,DWORD_PTR) {
    if(m==WM_WINDOWPOSCHANGED)++counts.position;
    if(m==WM_SETFONT)++counts.font;
    if(m==WM_SETTEXT)++counts.text;
    if(m==WM_ENABLE)++counts.enable;
    return DefSubclassProc(w,m,p,l);
}
BOOL CALLBACK ObserveChild(HWND w,LPARAM){SetWindowSubclass(w,Observe,42,0);return TRUE;}
void Check(bool ok,const char* name){if(!ok)throw std::runtime_error(name);std::cout<<"PASS "<<name<<'\n';}
BOOL CALLBACK CollectEdits(HWND w,LPARAM value) {
    wchar_t name[32]{};GetClassNameW(w,name,32);
    if(std::wstring(name)==L"Edit")reinterpret_cast<std::vector<HWND>*>(value)->push_back(w);
    return TRUE;
}
std::wstring Text(HWND w) {
    std::wstring text(size_t(GetWindowTextLengthW(w))+1,L'\0');
    const auto size=GetWindowTextW(w,text.data(),int(text.size()));text.resize(size);return text;
}
BOOL CALLBACK CollectText(HWND w,LPARAM value) {
    reinterpret_cast<std::wstring*>(value)->append(Text(w)+L"\n");return TRUE;
}
}
int main() try {
    const auto dir=std::filesystem::temp_directory_path()/("veld-pool-redraw-"+std::to_string(GetCurrentProcessId()));
    std::string error;
    Check(!std::filesystem::exists(dir),"fresh disposable profile");
    Check(veld::channel::secure_file::EnsurePrivateDirectory(dir.string(),&error),"private profile");
    HWND window=CreateWindowExW(0,L"STATIC",L"Pool redraw test",WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,
                              0,0,1200,900,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
    Check(window!=nullptr,"native parent window");
    {
        unsigned start_requests=0;
        veld::node_gui::PoolPanel panel(window,dir,dir/L"no-worker.exe",2,[&]{++start_requests;return false;});
        std::vector<HWND> edits;EnumChildWindows(window,CollectEdits,reinterpret_cast<LPARAM>(&edits));
        Check(edits.size()==4,"native endpoint, address, optional CA and CPU fields");
        Check(Text(edits[0])==L"https://pool.veld.network" && Text(edits[1]).empty() && Text(edits[2]).empty(),
              "fresh public pool default with no assigned payout address or custom CA");
        panel.Tick();
        Check(start_requests==0 && !panel.Running() && std::filesystem::is_empty(dir),
              "default endpoint does not connect, start a worker or persist consent");
        EnumChildWindows(window,ObserveChild,0);
        HFONT font=static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
        panel.Show(true,250,150,850,96,font);
        counts={};panel.Show(true,250,150,850,96,font);
        Check(counts.position==0 && counts.font==0 && counts.enable==0,"unchanged layout does not repaint children");
        panel.Show(true,250,160,840,96,font);
        Check(counts.position>0,"resize still repositions controls");
        counts={};panel.Show(true,250,160,840,96,font);
        Check(counts.position==0 && counts.font==0,"resized layout becomes stable");
        const auto path=dir/"pool-status.json";
        const std::string state=R"({"status":"Mining","accepted":"2","pending_units":"0","available_units":"0","reserved_units":"0","paid_units":"0"})";
        Check(veld::channel::secure_file::AtomicWriteText(path.string(),state,&error,true),"write actual private status file");
        panel.Tick();counts={};panel.Tick();
        Check(counts.text==0,"identical status and balance do not repaint");
        const std::string next=R"({"status":"Mining","accepted":"3","pending_units":"0","available_units":"0","reserved_units":"0","paid_units":"0"})";
        Check(veld::channel::secure_file::AtomicWriteText(path.string(),next,&error,true),"publish changed work count");
        counts={};panel.Tick();
        Check(counts.text==1,"only changed status is updated");
        const std::string failure=R"({"status":"refused","failure_code":"remote_refusal","failure_stage":"work"})";
        Check(veld::channel::secure_file::AtomicWriteText(path.string(),failure,&error,true),"publish bounded failure");
        panel.Tick();std::wstring rendered;EnumChildWindows(window,CollectText,reinterpret_cast<LPARAM>(&rendered));
        Check(rendered.find(L"Pool service refused the request (work).")!=std::wstring::npos,
              "native panel preserves specific failure and stage after worker exits");
        counts={};panel.Tick();Check(counts.text==0,"unchanged failure does not repaint");
        const std::string unknown=R"({"status":"refused","failure_code":"SECRET","failure_stage":"TOKEN"})";
        Check(veld::channel::secure_file::AtomicWriteText(path.string(),unknown,&error,true),"publish unknown diagnostic fixture");
        panel.Tick();rendered.clear();EnumChildWindows(window,CollectText,reinterpret_cast<LPARAM>(&rendered));
        Check(rendered.find(L"SECRET")==std::wstring::npos && rendered.find(L"TOKEN")==std::wstring::npos,
              "native panel never echoes arbitrary diagnostic fields");
        panel.Show(false,250,160,840,96,font);counts={};panel.Show(false,250,160,840,96,font);
        Check(counts.position==0 && counts.font==0,"hidden page stays idle");
    }
    DestroyWindow(window);
    const std::string saved=R"({"endpoint":"https://another-pool.invalid","payout_address":"saved-fixture-address","ca_file":"C:\\fixture\\pool-ca.pem","threads":"7"})";
    const std::string account=R"({"endpoint":"https://another-pool.invalid","address":"saved-fixture-address","fixture":"existing-account-record"})";
    Check(veld::channel::secure_file::AtomicWriteText((dir/"client.json").string(),saved,&error,true),"save separate existing configuration");
    Check(veld::channel::secure_file::AtomicWriteText((dir/"pool-account.json").string(),account,&error,true),"save separate existing account record");
    window=CreateWindowExW(0,L"STATIC",L"Pool existing profile test",WS_OVERLAPPEDWINDOW,
                          0,0,1200,900,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
    Check(window!=nullptr,"native existing-profile window");
    {
        unsigned start_requests=0;
        veld::node_gui::PoolPanel panel(window,dir,dir/L"no-worker.exe",2,[&]{++start_requests;return false;});
        std::vector<HWND> edits;EnumChildWindows(window,CollectEdits,reinterpret_cast<LPARAM>(&edits));
        Check(edits.size()==4 && Text(edits[0])==L"https://another-pool.invalid" &&
              Text(edits[1])==L"saved-fixture-address" && Text(edits[2])==L"C:\\fixture\\pool-ca.pem" && Text(edits[3])==L"7",
              "existing endpoint, payout address, certificate and CPU settings override defaults");
        panel.Tick();Check(start_requests==0 && !panel.Running(),"existing stopped profile stays stopped");
    }
    DestroyWindow(window);
    for(const auto& item:std::vector<std::pair<std::string,std::string>>{{"client.json",saved},{"pool-account.json",account}}) {
        std::vector<uint8_t> bytes;
        Check(veld::channel::secure_file::Read((dir/item.first).string(),bytes,&error,16384,true)==veld::channel::secure_file::ReadResult::Ok &&
              std::string(bytes.begin(),bytes.end())==item.second,"existing configuration and account bytes preserved");
    }
    std::filesystem::remove_all(dir); // Owned fresh temporary fixture only.
} catch(const std::exception& error) {std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
