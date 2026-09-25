#pragma once
#include "../pool/client_diagnostics.h"
#include "pool_monitor.h"

#include "../pool/client_transport.h"
#include "../wallet/secure_channel_file.h"
#include "../core/json_escape.h"
#include "../core/constants.h"
#include "../core/script.h"
#include <functional>
#include <filesystem>
#include <vector>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>

namespace veld::node_gui {

// The GUI owns a seedless native worker, not a second wallet or signing service.
// All network and hashing activity stays off the window-message thread.
class PoolPanel {
    HWND parent_{};
    std::vector<HWND> controls_;
    HWND endpoint_{},address_{},ca_{},threads_{},start_{},stop_{},status_{},balance_{};
    std::filesystem::path directory_,account_directory_,binary_;
    HANDLE process_{},worker_job_{};
    std::function<bool()> permitted_;
    HBRUSH background_=CreateSolidBrush(RGB(8,10,9)),field_=CreateSolidBrush(RGB(18,20,23));
    HFONT metric_font_{},small_metric_font_{};
    bool shown_=false,resume_pending_=false,stopping_=false,failed_=false;
    bool layout_ready_=false,enabled_ready_=false,last_running_=false,last_show_=false;
    int last_left_=0,last_top_=0,last_width_=0,last_scale_=0;
    HFONT last_font_{};
    PoolMonitor monitor_;
    std::string monitor_json_="null";
    static void SetTextIfChanged(HWND control,const std::wstring& text) {
        const int length=GetWindowTextLengthW(control);
        if(length==int(text.size())) {
            std::wstring existing(size_t(length)+1,L'\0');
            GetWindowTextW(control,existing.data(),int(existing.size()));existing.resize(length);
            if(existing==text)return;
        }
        SetWindowTextW(control,text.c_str());
    }
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
        const auto payout_script=AddressToScript(Get(address_));
        pool::Require(payout_script.size()==25 || IsSha384KeyScript(payout_script),"Enter a valid Veld payout address.");
        auto genesis=HexToBytes(GENESIS_HASH);std::reverse(genesis.begin(),genesis.end());
        const std::map<std::string,std::string> values={{"endpoint",endpoint},{"ca_file",Get(ca_)},{"genesis",BytesToHex(genesis)},
            {"payout_address",Get(address_)},{"state_directory",account_directory_.string()},{"threads",std::to_string(worker_count)},
            {"nonce_count","1024"},{"pause_ms","0"}};
        std::string out="{";
        for(const auto& [key,value]:values){if(out.size()>1)out+=',';out+='"'+key+"\":\""+json::EscapeStringBytes(value)+'"';}
        return out+'}';
    }
    void Error(const char* message){SetTextIfChanged(status_,Wide(message));}
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
    bool Start(std::string* failure=nullptr) {
        try {
            pool::Require(!stopping_,"Wait for the pool worker to stop before restarting.");
            if(Running())return true;
            pool::Require(permitted_(),"Pool mining is unavailable while another operation is active.");
            if(process_){CloseHandle(process_);process_=nullptr;}
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
            SetTextIfChanged(balance_,L"Waiting for this pool account's balances…");
            const std::wstring command=L"\""+binary_.wstring()+L"\" --config \""+(directory_/"client.json").wstring()+L"\"";
            std::vector<wchar_t> mutable_command(command.begin(),command.end());mutable_command.push_back(0);
            STARTUPINFOW startup{};startup.cb=sizeof(startup);startup.dwFlags=STARTF_USESHOWWINDOW;startup.wShowWindow=SW_HIDE;
            // Own the worker for the entire GUI lifetime. Start it suspended
            // so it cannot connect or hash before job assignment succeeds.
            // Closing the GUI's non-inherited job handle (including a crash)
            // kills its worker; the durable resume preference stays separate.
            if(!worker_job_) {
                HANDLE job=CreateJobObjectW(nullptr,nullptr);
                pool::Require(job!=nullptr,"Pool worker ownership could not be created.");
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
                limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if(!SetInformationJobObject(job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))) {
                    CloseHandle(job);throw std::runtime_error("Pool worker ownership could not be configured.");
                }
                worker_job_=job;
            }
            PROCESS_INFORMATION child{};
            pool::Require(CreateProcessW(binary_.c_str(),mutable_command.data(),nullptr,nullptr,FALSE,
                CREATE_NO_WINDOW|CREATE_SUSPENDED,nullptr,binary_.parent_path().c_str(),&startup,&child)!=FALSE,"Pool worker could not start.");
            if(!AssignProcessToJobObject(worker_job_,child.hProcess) || ResumeThread(child.hThread)==DWORD(-1)) {
                TerminateProcess(child.hProcess,ERROR_CANCELLED);
                WaitForSingleObject(child.hProcess,5000);
                CloseHandle(child.hThread);CloseHandle(child.hProcess);
                throw std::runtime_error("Pool worker ownership failed; no worker was allowed to run.");
            }
            CloseHandle(child.hThread);process_=child.hProcess;stopping_=false;failed_=false;Error("Connecting securely to the pool…");
            return true;
        } catch(const std::exception& error){if(failure)*failure=error.what();Error(error.what());return false;}
    }
    void BrowseCertificate() {
        if (Running()) return;
        wchar_t path[32768]{};
        OPENFILENAMEW dialog{};dialog.lStructSize=sizeof(dialog);dialog.hwndOwner=parent_;
        dialog.lpstrFile=path;dialog.nMaxFile=32768;
        dialog.lpstrTitle=L"Choose the certificate authority supplied for this pool";
        dialog.lpstrFilter=L"Certificate files (*.pem;*.crt;*.cer)\0*.pem;*.crt;*.cer\0All files\0*.*\0\0";
        dialog.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR|OFN_DONTADDTORECENT;
        if(GetOpenFileNameW(&dialog))SetWindowTextW(ca_,path);
    }
    static std::wstring Money(const pool::Json& value) {
        const auto units=pool::Number(pool::Text(value));
        auto fraction=std::to_wstring(units%100000000);
        return std::to_wstring(units/100000000)+L"."+std::wstring(8-fraction.size(),L'0')+fraction+L" VELD";
    }
public:
    static constexpr int kStart=25101,kStop=25102,kDashboard=25103,kCopyAccess=25104,kCertificate=25105,kBalances=25110;
    PoolPanel(HWND parent,const std::filesystem::path& directory,const std::filesystem::path& binary,
              unsigned default_threads,std::function<bool()> permitted)
        :parent_(parent),directory_(directory),account_directory_(directory),binary_(binary),permitted_(std::move(permitted)) {
        Make(L"STATIC",L"Pool endpoint (HTTPS)",SS_LEFT);
        // A suggested endpoint is not consent to connect. Only Start or an
        // existing explicit resume preference launches the seedless worker.
        endpoint_=Make(L"EDIT",L"https://pool.veld.network",WS_TABSTOP|ES_AUTOHSCROLL);
        Make(L"STATIC",L"Your payout address",SS_LEFT);
        address_=Make(L"EDIT",L"",WS_TABSTOP|ES_AUTOHSCROLL);
        Make(L"STATIC",L"Custom certificate authority (optional)",SS_LEFT);
        ca_=Make(L"EDIT",L"",WS_TABSTOP|ES_AUTOHSCROLL);
        SendMessageW(ca_,EM_SETCUEBANNER,TRUE,reinterpret_cast<LPARAM>(L"Leave blank for Veld Pool"));
        Make(L"STATIC",L"CPU workers · leave capacity for other apps",SS_LEFT);
        threads_=Make(L"EDIT",std::to_wstring(default_threads).c_str(),WS_TABSTOP|ES_NUMBER|ES_AUTOHSCROLL);
        start_=Make(L"BUTTON",L"Start pool mining",WS_TABSTOP|BS_OWNERDRAW,kStart);
        stop_=Make(L"BUTTON",L"Stop pool mining",WS_TABSTOP|BS_OWNERDRAW,kStop);
        status_=Make(L"STATIC",L"Enter your payout address to join Veld Pool, or choose another pool endpoint. No wallet passphrase is needed.",SS_LEFT);
        balance_=Make(L"STATIC",L"Balances will appear after connecting.",SS_OWNERDRAW,kBalances);
        Make(L"STATIC",L"Balances belong to this device's saved pool account. Payments go to your payout wallet. Earnings remain when disconnected. Start enables pool resume; Stop turns it off. Open the dashboard with your viewing access for reward and payment history. Solo mining stays on the Mining tab.",SS_LEFT);
        Make(L"BUTTON",L"Open dashboard",WS_TABSTOP|BS_OWNERDRAW,kDashboard);
        Make(L"BUTTON",L"Copy view access",WS_TABSTOP|BS_OWNERDRAW,kCopyAccess);
        Make(L"BUTTON",L"Choose file…",WS_TABSTOP|BS_OWNERDRAW,kCertificate);
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
        if(worker_job_)CloseHandle(worker_job_);
        DeleteObject(background_);DeleteObject(field_);
        if(metric_font_)DeleteObject(metric_font_);
        if(small_metric_font_)DeleteObject(small_metric_font_);
    }
    bool Running() {
        return process_ && WaitForSingleObject(process_,0)==WAIT_TIMEOUT;
    }
    // A remote request can only use the locally saved identity and endpoint.
    // Unsaved edits require an explicit local Start; they are never adopted by
    // a remote command. No viewing token, payout address or key is in its payload.
    bool RemoteStart(std::string& error) {
        if(Running()&&!stopping_)return true;
        try {
            std::vector<uint8_t> bytes;
            pool::Require(channel::secure_file::Read((directory_/"client.json").string(),bytes,nullptr,16384,true)==channel::secure_file::ReadResult::Ok,
                          "Configure and start pool mining once in this client's Pool tab first.");
            const auto saved=pool::Parse(std::string(bytes.begin(),bytes.end()));
            for(const auto& [control,key]:std::vector<std::pair<HWND,const char*>>{{endpoint_,"endpoint"},{address_,"payout_address"},{ca_,"ca_file"},{threads_,"threads"}})
                pool::Require(Get(control)==pool::Text(pool::Field(saved,key)),"Pool settings have unsaved local changes. Save them on this machine first.");
            return Start(&error);
        } catch(const std::exception& failure){error=failure.what();Error(error.c_str());return false;}
    }
    bool Stop(bool clear_resume=true,std::string* failure=nullptr) {
        bool saved=true;
        resume_pending_=false;
        if(clear_resume) {
            std::string error;
            if(!channel::secure_file::AtomicWriteText((directory_/"resume.request").string(),"stopped\n",&error,true)) {
                saved=false;
                if(failure)*failure="Could not save stopped state. Check the private pool folder before restarting the app.";
                Error("Could not save stopped state. Check the private pool folder before restarting the app.");
            }
        }
        if(!Running())return saved;
        std::string error;
        if(!channel::secure_file::AtomicWriteText((account_directory_/"stop.request").string(),"stop\n",&error,true)) {
            if(failure)*failure="Could not request a clean stop. Close the app to stop its pool worker.";
            Error("Could not request a clean stop. Close the app to stop its pool worker.");return false;
        }
        stopping_=true;Error("Stopping pool mining…");return saved;
    }
    bool Command(WPARAM command) {
        if(HIWORD(command)!=BN_CLICKED)return false;
        if(LOWORD(command)==kStart){Start();return true;}
        if(LOWORD(command)==kStop){Stop();return true;}
        if(LOWORD(command)==kCertificate){BrowseCertificate();return true;}
        if(LOWORD(command)==kDashboard){Dashboard(false);return true;}
        if(LOWORD(command)==kCopyAccess){Dashboard(true);return true;}return false;
    }
    bool Draw(const DRAWITEMSTRUCT& item) {
        if(item.CtlType==ODT_STATIC && item.CtlID==kBalances) {
            FillRect(item.hDC,&item.rcItem,background_);
            wchar_t text[1024]{};GetWindowTextW(balance_,text,1024);
            const std::wstring values(text);
            const wchar_t* labels[]={L"Pending",L"Available",L"In payment",L"Paid"};
            const wchar_t* captions[]={L"Awaiting maturity",L"Ready for a payout batch",L"Reserved for payment",L"Confirmed payments"};
            const COLORREF accents[]={RGB(232,175,72),RGB(194,199,205),RGB(155,168,208),RGB(126,217,73)};
            const int scale=last_scale_?last_scale_:96;
            const auto px=[scale](int n){return MulDiv(n,scale,96);};
            const int gap=px(12),width=(item.rcItem.right-item.rcItem.left-gap)/2;
            const int height=(item.rcItem.bottom-item.rcItem.top-gap)/2;
            const int saved=SaveDC(item.hDC);SetBkMode(item.hDC,TRANSPARENT);
            for(int i=0;i<4;++i) {
                RECT card{item.rcItem.left+(i%2)*(width+gap),item.rcItem.top+(i/2)*(height+gap),0,0};
                card.right=card.left+width;card.bottom=card.top+height;
                auto brush=CreateSolidBrush(RGB(21,23,26));auto pen=CreatePen(PS_SOLID,1,RGB(49,53,59));
                auto oldBrush=SelectObject(item.hDC,brush);auto oldPen=SelectObject(item.hDC,pen);
                RoundRect(item.hDC,card.left,card.top,card.right,card.bottom,px(10),px(10));
                SelectObject(item.hDC,oldBrush);SelectObject(item.hDC,oldPen);DeleteObject(brush);DeleteObject(pen);
                RECT mark{card.left,card.top+px(17),card.left+px(3),card.top+px(42)};
                brush=CreateSolidBrush(accents[i]);FillRect(item.hDC,&mark,brush);DeleteObject(brush);
                RECT line{card.left+px(16),card.top+px(12),card.right-px(10),card.top+px(32)};
                SelectObject(item.hDC,last_font_);SetTextColor(item.hDC,RGB(176,182,191));
                DrawTextW(item.hDC,labels[i],-1,&line,DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);
                const std::wstring prefix=std::wstring(labels[i])+L": ";const auto at=values.find(prefix);
                std::wstring amount=L"—";
                if(at!=std::wstring::npos) {
                    const auto begin=at+prefix.size(),end=values.find(L" VELD",begin);
                    if(end!=std::wstring::npos)amount=values.substr(begin,end-begin);
                }
                line.top=card.top+px(35);line.bottom=card.top+px(65);
                SelectObject(item.hDC,width<px(235)?small_metric_font_:metric_font_);
                SetTextColor(item.hDC,RGB(241,242,240));DrawTextW(item.hDC,amount.c_str(),-1,&line,DT_LEFT|DT_SINGLELINE|DT_NOPREFIX);
                SelectObject(item.hDC,last_font_);SetTextColor(item.hDC,RGB(160,167,177));
                line.top=card.top+px(70);line.bottom=card.bottom-px(8);
                const auto caption=std::wstring(L"VELD · ")+captions[i];
                DrawTextW(item.hDC,caption.c_str(),-1,&line,DT_LEFT|DT_WORDBREAK|DT_NOPREFIX);
            }
            RestoreDC(item.hDC,saved);return true;
        }
        if(item.CtlType!=ODT_BUTTON || item.CtlID<kStart || item.CtlID>kCertificate)return false;
        const bool disabled=(item.itemState&ODS_DISABLED)!=0;
        const bool down=(item.itemState&ODS_SELECTED)!=0;
        const bool primary=item.CtlID==kStart;
        const COLORREF background=disabled?RGB(27,29,32):primary?(down?RGB(40,44,50):RGB(53,57,64)):
            down?RGB(48,53,60):RGB(38,41,45);
        const COLORREF text=disabled?RGB(119,124,131):primary?RGB(242,243,245):RGB(240,240,237);
        FillRect(item.hDC,&item.rcItem,background_);
        auto brush=CreateSolidBrush(background);auto pen=CreatePen(PS_SOLID,1,disabled?RGB(46,50,55):primary?RGB(100,107,118):RGB(80,85,92));
        auto oldBrush=SelectObject(item.hDC,brush);auto oldPen=SelectObject(item.hDC,pen);
        RoundRect(item.hDC,item.rcItem.left,item.rcItem.top,item.rcItem.right,item.rcItem.bottom,8,8);
        SelectObject(item.hDC,oldBrush);SelectObject(item.hDC,oldPen);DeleteObject(brush);DeleteObject(pen);
        const auto oldFont=SelectObject(item.hDC,reinterpret_cast<HFONT>(SendMessageW(item.hwndItem,WM_GETFONT,0,0)));
        wchar_t label[128]{};GetWindowTextW(item.hwndItem,label,128);auto rectangle=item.rcItem;
        SetBkMode(item.hDC,TRANSPARENT);SetTextColor(item.hDC,text);
        DrawTextW(item.hDC,label,-1,&rectangle,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
        SelectObject(item.hDC,oldFont);
        if(item.itemState&ODS_FOCUS){InflateRect(&rectangle,-4,-4);DrawFocusRect(item.hDC,&rectangle);}
        return true;
    }
    HBRUSH Color(HDC dc,HWND control) {
        if(std::find(controls_.begin(),controls_.end(),control)==controls_.end())return nullptr;
        SetTextColor(dc,RGB(237,244,236));
        const bool edit=control==endpoint_||control==address_||control==ca_||control==threads_;
        SetBkColor(dc,edit?RGB(18,20,23):RGB(8,10,9));return edit?field_:background_;
    }
    void Show(bool show,int left,int top,int width,int scale,HFONT font) {
        shown_=show;
        const bool relayout=!layout_ready_ || left!=last_left_ || top!=last_top_ ||
            width!=last_width_ || scale!=last_scale_;
        const bool refont=!layout_ready_ || font!=last_font_;
        const bool visibility=!layout_ready_ || show!=last_show_;
        const auto px=[scale](int value){return MulDiv(value,scale,96);};
        if(!layout_ready_ || scale!=last_scale_) {
            if(metric_font_)DeleteObject(metric_font_);
            if(small_metric_font_)DeleteObject(small_metric_font_);
            metric_font_=CreateFontW(-px(23),0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Cascadia Mono");
            small_metric_font_=CreateFontW(-px(15),0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Consolas");
        }
        const int rows[]={0,28,80,108,160,188,240,268,324,324,440,528,796,382,382,188};
        // Suppress invalidation during child movement. The parent and all
        // controls are invalidated once after every position is final; the
        // composited parent presents the complete frame together.
        for(size_t i=0;i<controls_.size();++i) {
            const auto control=controls_[i];
            const int button=(i==8?0:i==9?1:i==13?2:i==14?3:-1);
            const int button_width=(width-px(12))/2;
            const int x=left+(i==15?width-px(120):button>=0?(button%2)*(button_width+px(12)):0);
            const int w=(i==7||i==15?px(120):i==5?width-px(132):button>=0?button_width:width);
            const int h=i==11?px(248):i==12?px(112):(i==1||i==3||i==5||i==7||i==15)?px(38):button>=0?px(44):i<=6?px(24):px(80);
            if(relayout) {
                SetWindowPos(control,nullptr,x,top+px(rows[i]),w,h,
                    SWP_NOZORDER|SWP_NOACTIVATE|SWP_NOCOPYBITS|SWP_NOREDRAW);
            }
            if(refont)SendMessageW(control,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);
            if(visibility)ShowWindow(control,show?SW_SHOWNA:SW_HIDE);
        }
        if(relayout || visibility)RedrawWindow(parent_,nullptr,nullptr,RDW_INVALIDATE|RDW_ALLCHILDREN);
        layout_ready_=true;last_left_=left;last_top_=top;last_width_=width;
        last_scale_=scale;last_font_=font;last_show_=show;
        const bool running=Running();
        if(!enabled_ready_ || last_running_!=running) {
            for(auto control:{endpoint_,address_,ca_,threads_,start_,controls_.back()})EnableWindow(control,!running);
            EnableWindow(stop_,running);last_running_=running;enabled_ready_=true;
        }
    }
    void SuppressAutomaticResume() { resume_pending_=false; }

    void Tick() {
        if(resume_pending_){resume_pending_=false;Start();}
        DWORD exit=STILL_ACTIVE;
        const bool exited=process_ && GetExitCodeProcess(process_,&exit) && exit!=STILL_ACTIVE;
        if(exited){CloseHandle(process_);process_=nullptr;failed_=exit!=0;stopping_=false;}
        const auto now=uint64_t(std::time(nullptr));
        const auto monotonic=std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
        uint64_t configured=1;
        try {configured=pool::Number(Get(threads_),64);if(!configured)configured=1;}catch(...){}
        bool observed=false;
        try {
            std::vector<uint8_t> bytes;std::string error;
            if(channel::secure_file::Read((account_directory_/"pool-status.json").string(),bytes,&error,16384,true)==channel::secure_file::ReadResult::Ok) {
                const auto state=pool::Parse(std::string(bytes.begin(),bytes.end()));
                monitor_json_=monitor_.Report(Running(),configured,&state,now,monotonic);
                observed=true;
                const auto count=[&](const char* name){const auto* value=state.Get(name);return value?Wide(pool::Text(*value)):L"0";};
                std::wstring status=Wide(pool::Text(pool::Field(state,"status")));
                if(state.Get("accepted"))status+=L"\r\nAccepted this session: "+count("accepted")+L" · verified total: "+count("verified_shares")+
                    L"\r\nCPU workers: "+Wide(Get(threads_))+L" configured · "+count("active_workers")+L" on work"+
                    L"\r\nHashes: "+count("hashes");
                const auto* failure=state.Get("failure_code");
                const auto* stage=state.Get("failure_stage");
                if(failure && stage)status=Wide(pool::FailureSummary(pool::Text(*failure),pool::Text(*stage)));
                else if(failed_)status=L"Pool worker stopped with an error. Check endpoint, certificate and saved account settings.";
                else if(stopping_)status=L"Stopping pool mining…";
                else if(!Running())status=L"Stopped · accepted this session: "+count("accepted")+L"\r\nYour account and earned balances are preserved.";
                SetTextIfChanged(status_,status);
                if(state.Get("pending_units")) {
                    const std::wstring text=L"Pending: "+Money(pool::Field(state,"pending_units"))+L"\r\nAvailable: "+Money(pool::Field(state,"available_units"))+
                        L"\r\nIn payment: "+Money(pool::Field(state,"reserved_units"))+L"\r\nPaid: "+Money(pool::Field(state,"paid_units"))+L"\r\nLast balances reported by the pool";
                    SetTextIfChanged(balance_,text);
                }
            } else if(exited && exit!=0)Error("Pool worker could not connect. Check the endpoint, certificate and account settings.");
        } catch(const std::exception&){Error("Pool status unavailable; account records were preserved.");}
        if(!observed)monitor_json_=monitor_.Report(Running(),configured,nullptr,now,monotonic);
    }
    // Called only by the GUI thread, which copies it into its locked report cache.
    const std::string& MonitoringJson() const{return monitor_json_;}
};
} // namespace veld::node_gui
