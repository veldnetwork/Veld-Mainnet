#pragma once

#include "../pool/client_transport.h"
#include "../wallet/secure_channel_file.h"
#include "../core/json_escape.h"
#include "../core/constants.h"
#include "../core/script.h"
#include <functional>
#include <filesystem>
#include <vector>
#include <commctrl.h>
#include <shellapi.h>

namespace veld::node_gui {

// The GUI owns a seedless native worker, not a second wallet or signing service.
// All network and hashing activity stays off the window-message thread.
class PoolPanel {
    HWND parent_{};
    std::vector<HWND> controls_;
    HWND endpoint_{},address_{},ca_{},threads_{},start_{},stop_{},status_{},balance_{};
    std::filesystem::path directory_,account_directory_,binary_;
    HANDLE process_{};
    std::function<bool()> permitted_;
    HBRUSH background_=CreateSolidBrush(RGB(8,13,9)),field_=CreateSolidBrush(RGB(20,29,22));
    bool shown_=false,resume_pending_=false,stopping_=false,failed_=false;
    static std::wstring Wide(const std::string& value) {
        if(value.empty())return {};
        const int size=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),int(value.size()),nullptr,0);
        pool::Require(size>0,"invalid UTF-8 pool setting");
        std::wstring out(size,L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),int(value.size()),out.data(),size);return out;
    }
    static std::string Narrow(const std::wstring& value) {
        if(value.empty())return {};
        const int size=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),int(value.size()),nullptr,0,nullptr,nullptr);
        pool::Require(size>0,"invalid pool setting");
        std::string out(size,'\0');WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),int(value.size()),out.data(),size,nullptr,nullptr);return out;
    }
    static std::string Get(HWND control) {
        const auto length=GetWindowTextLengthW(control);pool::Require(length<=4096,"pool setting length");
        std::wstring value(size_t(length)+1,L'\0');GetWindowTextW(control,value.data(),int(value.size()));value.resize(length);return Narrow(value);
    }
    static LRESULT CALLBACK EditKeys(HWND control,UINT message,WPARAM wp,LPARAM lp,UINT_PTR,DWORD_PTR) {
        if(message==WM_KEYDOWN && wp=='A' && (GetKeyState(VK_CONTROL)&0x8000)) {
            SendMessageW(control,EM_SETSEL,0,-1);return 0;
        }
        return DefSubclassProc(control,message,wp,lp);
    }
    HWND Make(const wchar_t* type,const wchar_t* text,DWORD style,int id=0) {
        HWND control=CreateWindowExW(type==std::wstring(L"EDIT")?WS_EX_CLIENTEDGE:0,type,text,
            WS_CHILD|style,0,0,0,0,parent_,reinterpret_cast<HMENU>(intptr_t(id)),GetModuleHandleW(nullptr),nullptr);
        pool::Require(control!=nullptr,"pool control creation failed");
        if(type==std::wstring(L"EDIT"))SetWindowSubclass(control,EditKeys,1,0);
        controls_.push_back(control);return control;
    }
    std::filesystem::path AccountDirectory() {
        const auto endpoint=Get(endpoint_),address=Get(address_);
        // Preserve already qualified pre-profile candidate accounts. This does
        // not let a changed endpoint receive an old pool's credentials.
        std::vector<uint8_t> bytes;std::string error;
        if(channel::secure_file::Read((directory_/"pool-account.json").string(),bytes,&error,16384,true)==channel::secure_file::ReadResult::Ok) {
            const auto saved=pool::Parse(std::string(bytes.begin(),bytes.end()));
            if(pool::Text(pool::Field(saved,"endpoint"))==endpoint && pool::Text(pool::Field(saved,"address"))==address)
                return directory_;
        }
        const auto identity=endpoint+'\n'+address+'\n'+std::string(GENESIS_HASH);
        return directory_/HashToHex(Hash256d(std::vector<uint8_t>(identity.begin(),identity.end())));
    }
    std::string Config() {
        const auto endpoint=Get(endpoint_);pool::Endpoint validated(endpoint);
        const auto worker_count=pool::Number(Get(threads_),64);pool::Require(worker_count>0,"choose 1 to 64 workers");
        pool::Require(AddressToScript(Get(address_)).size()==25,"Enter a valid Veld payout address.");
        auto genesis=HexToBytes(GENESIS_HASH);std::reverse(genesis.begin(),genesis.end());
        const std::map<std::string,std::string> values={{"endpoint",endpoint},{"ca_file",Get(ca_)},{"genesis",BytesToHex(genesis)},
            {"payout_address",Get(address_)},{"state_directory",account_directory_.string()},{"threads",std::to_string(worker_count)},
            {"nonce_count","16"},{"pause_ms","0"}};
        std::string out="{";
        for(const auto& [key,value]:values){if(out.size()>1)out+=',';out+='"'+key+"\":\""+json::EscapeStringBytes(value)+'"';}
        return out+'}';
    }
    void Error(const char* message){SetWindowTextW(status_,Wide(message).c_str());}
    void Dashboard(bool copy_access) {
        try {
            const auto endpoint=Get(endpoint_);pool::Endpoint validated(endpoint);
            if(!copy_access) {
                pool::Require(reinterpret_cast<INT_PTR>(ShellExecuteW(parent_,L"open",Wide(endpoint).c_str(),nullptr,nullptr,SW_SHOWNORMAL))>32,
                              "The pool dashboard could not open.");return;
            }
            std::vector<uint8_t> bytes;std::string error;
            const auto profile=AccountDirectory();
            pool::Require(channel::secure_file::Read((profile/"pool-account.json").string(),bytes,&error,16384,true)==channel::secure_file::ReadResult::Ok,
                          "Connect to this pool first to create your private account.");
            const auto saved=pool::Parse(std::string(bytes.begin(),bytes.end()));
            pool::Require(pool::Text(pool::Field(saved,"endpoint"))==endpoint && pool::Text(pool::Field(saved,"address"))==Get(address_),"Saved pool identity mismatch.");
            const auto account=pool::Hex(pool::Field(saved,"account"),32),token=pool::Hex(pool::Field(saved,"view_token"),64);
            const auto access=Wide("{\"endpoint\":\""+json::EscapeStringBytes(endpoint)+"\",\"account\":\""+account+"\",\"token\":\""+token+"\"}");
            HGLOBAL memory=GlobalAlloc(GMEM_MOVEABLE,(access.size()+1)*sizeof(wchar_t));
            pool::Require(memory!=nullptr,"Clipboard memory unavailable.");
            auto data=GlobalLock(memory);
            if(!data){GlobalFree(memory);throw std::runtime_error("Clipboard memory unavailable.");}
            memcpy(data,access.c_str(),(access.size()+1)*sizeof(wchar_t));GlobalUnlock(memory);
            if(!OpenClipboard(parent_)){GlobalFree(memory);throw std::runtime_error("Clipboard is busy. Try again.");}
            EmptyClipboard();
            const bool copied=SetClipboardData(CF_UNICODETEXT,memory)!=nullptr;
            if(!copied)GlobalFree(memory);
            // Opt out of Windows clipboard history and cloud synchronization.
            for(const wchar_t* format:{L"CanIncludeInClipboardHistory",L"CanUploadToCloudClipboard"}) {
                HGLOBAL flag=GlobalAlloc(GMEM_MOVEABLE|GMEM_ZEROINIT,sizeof(DWORD));
                if(flag && !SetClipboardData(RegisterClipboardFormatW(format),flag))GlobalFree(flag);
            }
            CloseClipboard();pool::Require(copied,"Viewing access could not be copied.");
            Error("Viewing access copied. Paste it into this pool's dashboard.");
        } catch(const std::exception& error){Error(error.what());}
    }
    void Start() {
        if(Running() || !permitted_())return;
        if(process_){CloseHandle(process_);process_=nullptr;}
        try {
            pool::Require(std::filesystem::is_regular_file(binary_),"The packaged pool worker is missing.");
            std::string error;
            pool::Require(channel::secure_file::EnsurePrivateDirectory(directory_.string(),&error),"Private pool account folder unavailable.");
            account_directory_=AccountDirectory();
            pool::Require(channel::secure_file::EnsurePrivateDirectory(account_directory_.string(),&error),"Private pool profile unavailable.");
            // Existing account identity is checked by the worker before any
            // reconnection. Changing these fields never changes old liabilities.
            pool::Require(channel::secure_file::AtomicWriteText((directory_/"client.json").string(),Config(),&error,true),"Could not save pool settings.");
            pool::Require(channel::secure_file::AtomicWriteText((directory_/"resume.request").string(),"resume\n",&error,true),"Could not save pool resume preference.");
            std::filesystem::remove(account_directory_/"stop.request");
            SetWindowTextW(balance_,L"Waiting for this pool account's balances…");
            const std::wstring command=L"\""+binary_.wstring()+L"\" --config \""+(directory_/"client.json").wstring()+L"\"";
            std::vector<wchar_t> mutable_command(command.begin(),command.end());mutable_command.push_back(0);
            STARTUPINFOW startup{};startup.cb=sizeof(startup);startup.dwFlags=STARTF_USESHOWWINDOW;startup.wShowWindow=SW_HIDE;
            PROCESS_INFORMATION child{};
            pool::Require(CreateProcessW(binary_.c_str(),mutable_command.data(),nullptr,nullptr,FALSE,
                CREATE_NO_WINDOW,nullptr,binary_.parent_path().c_str(),&startup,&child)!=FALSE,"Pool worker could not start.");
            CloseHandle(child.hThread);process_=child.hProcess;stopping_=false;failed_=false;Error("Connecting securely to the pool…");
        } catch(const std::exception& error){Error(error.what());}
    }
    static std::wstring Money(const pool::Json& value) {
        const auto units=pool::Number(pool::Text(value));
        auto fraction=std::to_wstring(units%100000000);
        return std::to_wstring(units/100000000)+L"."+std::wstring(8-fraction.size(),L'0')+fraction+L" VELD";
    }
public:
    static constexpr int kStart=25101,kStop=25102,kDashboard=25103,kCopyAccess=25104;
    PoolPanel(HWND parent,const std::filesystem::path& directory,const std::filesystem::path& binary,
              unsigned default_threads,std::function<bool()> permitted)
        :parent_(parent),directory_(directory),account_directory_(directory),binary_(binary),permitted_(std::move(permitted)) {
        Make(L"STATIC",L"Pool endpoint (HTTPS)",SS_LEFT);
        endpoint_=Make(L"EDIT",L"",WS_TABSTOP|ES_AUTOHSCROLL);
        Make(L"STATIC",L"Your payout address",SS_LEFT);
        address_=Make(L"EDIT",L"",WS_TABSTOP|ES_AUTOHSCROLL);
        Make(L"STATIC",L"Private test CA file (leave blank only for a publicly trusted certificate)",SS_LEFT);
        ca_=Make(L"EDIT",L"",WS_TABSTOP|ES_AUTOHSCROLL);
        Make(L"STATIC",L"CPU workers",SS_LEFT);
        threads_=Make(L"EDIT",std::to_wstring(default_threads).c_str(),WS_TABSTOP|ES_NUMBER|ES_AUTOHSCROLL);
        start_=Make(L"BUTTON",L"Start pool mining",WS_TABSTOP|BS_PUSHBUTTON,kStart);
        stop_=Make(L"BUTTON",L"Stop pool mining",WS_TABSTOP|BS_PUSHBUTTON,kStop);
        status_=Make(L"STATIC",L"Choose an endpoint and payout address. No wallet passphrase is needed.",SS_LEFT);
        balance_=Make(L"STATIC",L"Balances will appear after connecting.",SS_LEFT);
        Make(L"STATIC",L"Start saves this session for the next launch; Stop disables resume. Solo mining stays on the Mining tab. For private payment history, copy viewing access and paste it into your pool dashboard. Earnings remain yours when disconnected.",SS_LEFT);
        Make(L"BUTTON",L"Open dashboard",WS_TABSTOP|BS_PUSHBUTTON,kDashboard);
        Make(L"BUTTON",L"Copy view access",WS_TABSTOP|BS_PUSHBUTTON,kCopyAccess);
        try {
            std::vector<uint8_t> bytes;std::string error;
            if(channel::secure_file::Read((directory_/"client.json").string(),bytes,&error,16384,true)==channel::secure_file::ReadResult::Ok) {
                const auto cfg=pool::Parse(std::string(bytes.begin(),bytes.end()));
                for(const auto& [control,key]:std::vector<std::pair<HWND,const char*>>{{endpoint_,"endpoint"},{address_,"payout_address"},{ca_,"ca_file"},{threads_,"threads"}})
                    SetWindowTextW(control,Wide(pool::Text(pool::Field(cfg,key))).c_str());
                account_directory_=AccountDirectory();
                bytes.clear();
                resume_pending_=channel::secure_file::Read((directory_/"resume.request").string(),bytes,&error,16,true)==channel::secure_file::ReadResult::Ok &&
                    std::string(bytes.begin(),bytes.end())=="resume\n";
            }
        } catch(const std::exception&){Error("Saved settings could not be read. Existing account records were preserved.");}
    }
    ~PoolPanel() {
        Stop(false);
        if(process_){if(WaitForSingleObject(process_,25000)==WAIT_TIMEOUT)TerminateProcess(process_,ERROR_CANCELLED);CloseHandle(process_);}
        DeleteObject(background_);DeleteObject(field_);
    }
    bool Running() {
        return process_ && WaitForSingleObject(process_,0)==WAIT_TIMEOUT;
    }
    void Stop(bool clear_resume=true) {
        resume_pending_=false;
        if(clear_resume) {
            std::string error;
            if(!channel::secure_file::AtomicWriteText((directory_/"resume.request").string(),"stopped\n",&error,true)) {
                Error("Could not save stopped state. Check the private pool folder before restarting the app.");
            }
        }
        if(!Running())return;
        std::string error;
        if(!channel::secure_file::AtomicWriteText((account_directory_/"stop.request").string(),"stop\n",&error,true)) {
            Error("Could not request a clean stop. Close the app to stop its pool worker.");return;
        }
        stopping_=true;Error("Stopping pool mining…");
    }
    bool Command(WPARAM command) {
        if(HIWORD(command)!=BN_CLICKED)return false;
        if(LOWORD(command)==kStart){Start();return true;}
        if(LOWORD(command)==kStop){Stop();return true;}
        if(LOWORD(command)==kDashboard){Dashboard(false);return true;}
        if(LOWORD(command)==kCopyAccess){Dashboard(true);return true;}return false;
    }
    HBRUSH Color(HDC dc,HWND control) {
        if(std::find(controls_.begin(),controls_.end(),control)==controls_.end())return nullptr;
        SetTextColor(dc,RGB(237,244,236));
        const bool edit=control==endpoint_||control==address_||control==ca_||control==threads_;
        SetBkColor(dc,edit?RGB(20,29,22):RGB(8,13,9));return edit?field_:background_;
    }
    void Show(bool show,int left,int top,int width,int scale,HFONT font) {
        shown_=show;
        const auto px=[scale](int value){return MulDiv(value,scale,96);};
        const int rows[]={0,28,80,108,160,188,240,268,328,328,395,455,570,328,328};
        for(size_t i=0;i<controls_.size();++i) {
            const auto control=controls_[i];
            const int button=(i==8?0:i==9?1:i==13?2:i==14?3:-1);
            const int button_width=(width-px(30))/4;
            const int x=left+(button>=0?button*(button_width+px(10)):0);
            const int w=(i==7?px(120):button>=0?button_width:width);
            const int h=i==11?px(96):i==12?px(80):(i==1||i==3||i==5||i==7)?px(38):button>=0?px(44):i<=6?px(24):px(45);
            MoveWindow(control,x,top+px(rows[i]),w,h,TRUE);SendMessageW(control,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);
            ShowWindow(control,show?SW_SHOWNA:SW_HIDE);
        }
        const bool running=Running();
        for(auto control:{endpoint_,address_,ca_,threads_,start_})EnableWindow(control,!running);
        EnableWindow(stop_,running);
    }
    void Tick() {
        if(resume_pending_){resume_pending_=false;Start();}
        DWORD exit=STILL_ACTIVE;
        const bool exited=process_ && GetExitCodeProcess(process_,&exit) && exit!=STILL_ACTIVE;
        if(exited){CloseHandle(process_);process_=nullptr;failed_=exit!=0;stopping_=false;}
        try {
            std::vector<uint8_t> bytes;std::string error;
            if(channel::secure_file::Read((account_directory_/"pool-status.json").string(),bytes,&error,16384,true)==channel::secure_file::ReadResult::Ok) {
                const auto state=pool::Parse(std::string(bytes.begin(),bytes.end()));
                std::wstring status=Wide(pool::Text(pool::Field(state,"status")))+L" · accepted work: "+Wide(pool::Text(pool::Field(state,"accepted")));
                if(failed_)status=L"Pool worker stopped with an error. Check endpoint, certificate and saved account settings.";
                else if(stopping_)status=L"Stopping pool mining…";
                else if(!Running())status=L"Stopped · accepted work this session: "+Wide(pool::Text(pool::Field(state,"accepted")));
                SetWindowTextW(status_,status.c_str());
                if(state.Get("pending_units")) {
                    const std::wstring text=L"Pending: "+Money(pool::Field(state,"pending_units"))+L"\r\nAvailable: "+Money(pool::Field(state,"available_units"))+
                        L"  In payment: "+Money(pool::Field(state,"reserved_units"))+L"\r\nPaid: "+Money(pool::Field(state,"paid_units"))+L"  (last reported by the pool)";
                    SetWindowTextW(balance_,text.c_str());
                }
            } else if(exited && exit!=0)Error("Pool worker could not connect. Check the endpoint, certificate and account settings.");
        } catch(const std::exception&){Error("Pool status unavailable; account records were preserved.");}
    }
};
} // namespace veld::node_gui
