#define VELD_GUI_TEST_INSTANCE 1
#define VELD_POOL_GUI_QUALIFICATION 1
#define wWinMain veld_gui_unused_entry
#include "../src/veld-node-gui.cpp"
#undef wWinMain
#include <iostream>

namespace {
void Check(bool ok,const char* message) {
    if (!ok) throw std::runtime_error(message);
    std::cout << "PASS " << message << '\n';
}
struct GuiStateQualification {
    static void Run(const std::filesystem::path& root) {
        NodeGuiApp app(root);
        app.data_dir_=root/L"node data";app.node_path_=root/L"bin"/L"veld-node.exe";
        Check(!app.address_only_,"existing installations default to wallet mode");
        auto key=veld::GenerateKeyPair(false);
        const auto address=key.address;
        Check(app.ValidSoloAddress(address),"valid mainnet payout accepted");
        Check(!app.ValidSoloAddress(veld::GenerateKeyPair(true).address),"wrong-network payout rejected");
        Check(!app.ValidSoloAddress(address+"\nmining=1"),"settings and command injection rejected");
        auto damaged=address;damaged.back()=damaged.back()=='1'?'2':'1';
        Check(!app.ValidSoloAddress(damaged),"bad checksum rejected");
        app.SetAddressPayout(address);app.address_only_=true;app.mining_enabled_=false;
        Check(app.SaveSettings(false),"payout and mode saved without enabling mining");
        NodeGuiApp restored(root);restored.LoadSettings();
        Check(restored.address_only_&&restored.AddressPayout()==address&&!restored.mining_enabled_,"payout and stopped preference survive restart");
        const auto identity=app.RemoteIdentityFingerprint();
        Check(!identity.empty()&&!app.HasSessionUnlock(),"payout fingerprint requires no wallet unlock");
        uint64_t ack=0;const auto report=app.BuildMonitoringReport(LiveState{},ack);
        Check(report.find("\"unlock_key\":null")!=std::string::npos && !std::filesystem::exists(root/L"remote-unlock.dat"),"portal offers ordinary start without a wallet passphrase exchange");
        app.SetAddressPayout(veld::GenerateKeyPair(false).address);
        Check(identity!=app.RemoteIdentityFingerprint(),"payout changes invalidate update resume identity");
        app.SetAddressPayout(address);
        app.mining_enabled_=true;app.full_ibd_choice_=false;
        const auto command=app.NodeStartCommand();
        Check(command.find(L"--address-only --miner "+Utf8ToWide(address))!=std::wstring::npos &&
              command.find(L"--mine ")!=std::wstring::npos &&
              command.find(L"--snapshot-bootstrap")!=std::wstring::npos &&
              command.find(L"--endorse")==std::wstring::npos &&
              command.find(L"--full-ibd")==std::wstring::npos,
              "address-only launch can select signed snapshot without endorsement");
        app.full_ibd_choice_=true;
        Check(app.NodeStartCommand().find(L"--full-ibd")!=std::wstring::npos &&
              app.NodeStartCommand().find(L"--snapshot-bootstrap")==std::wstring::npos,
              "address-only full-IBD opt-out remains available");
        app.mining_enabled_=false;
        Check(app.NodeStartCommand().find(L"--nomine --address-only")!=std::wstring::npos,"node-only startup does not silently mine");
        std::string secret,again,error;
        Check(veld::mining::AddressOnlyRpcSecret(app.data_dir_,secret,&error),"Windows protects separate RPC-only credential");
        Check(veld::mining::AddressOnlyRpcSecret(app.data_dir_,again,&error)&&secret==again,"RPC credential persists through restart");
        const auto credential=app.data_dir_/L"address-only-rpc-unlock.dat";
        Check(ReadTextBounded(credential,16384).find(secret)==std::string::npos,"RPC secret is not stored as plaintext");
        Check(!std::filesystem::exists(app.data_dir_/L"miner.key")&&!std::filesystem::exists(app.data_dir_/L"rpc.token"),"no wallet key or wallet RPC token created");
        Check(veld::channel::secure_file::AtomicWriteText((app.data_dir_/L"miner.key").string(),"wallet sentinel",&error),"existing wallet sentinel fixture");
        Check(veld::channel::secure_file::AtomicWriteText(credential.string(),"corrupt credential",&error),"corruption fixture retained");
        Check(!veld::mining::AddressOnlyRpcSecret(app.data_dir_,again,&error)&&again.empty(),"corrupt credential fails closed");
        Check(ReadTextBounded(credential,16384)=="corrupt credential" && ReadTextBounded(app.data_dir_/L"miner.key",100)=="wallet sentinel","refusal preserves credential and wallet bytes");
        app.address_only_=false;
        Check(app.NodeStartCommand().find(L"--endorse")!=std::wstring::npos && app.RemoteIdentityFingerprint()!=identity,"wallet mode retains separate identity and signing path");
        app.address_only_=true;
        const auto credential_target=app.StartupCredentialTarget();
        struct CredentialCleanup {std::wstring target;~CredentialCleanup(){veld::node_gui::RemoveStartupUnlock(target);}} cleanup{credential_target};
        Check(veld::node_gui::SaveStartupUnlock(credential_target,Utf8ToWide(identity),L"disposable prior wallet unlock"),"disposable saved wallet unlock fixture");
        app.startup_unlock_enabled_=true;app.ChangeStartupUnlock();std::wstring recovered;
        Check(!app.startup_unlock_enabled_ && !veld::node_gui::ReadStartupUnlock(credential_target,Utf8ToWide(identity),recovered),"address mode can still remove an old remembered wallet unlock");
        app.hwnd_=CreateWindowExW(0,L"STATIC",L"Address-only qualification",WS_OVERLAPPEDWINDOW,0,0,1050,700,nullptr,nullptr,GetModuleHandleW(nullptr),nullptr);
        Check(app.hwnd_!=nullptr,"isolated UI window");app.CreateFonts();
        HDC window=GetDC(app.hwnd_),dc=CreateCompatibleDC(window);HBITMAP bitmap=CreateCompatibleBitmap(window,1050,1502);
        auto previous=SelectObject(dc,bitmap);RECT client{0,0,1050,1502};
        FillRect(dc,&client,reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));app.DrawSettings(dc,client,LiveState{});
        Check(app.address_edit_button_.bottom<app.mining_mode_toggle_.top && app.address_mode_toggle_.right<client.right,"address controls fit and do not overlap CPU settings");
        app.page_=Page::Settings;app.state_.process_running=true;
        app.OnClick(app.address_mode_toggle_.left+2,app.address_mode_toggle_.top+2);
        Check(app.address_only_ && app.AddressPayout()==address,"a running node prevents mode or payout changes");
        app.state_.process_running=false;
        BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=1050;info.bmiHeader.biHeight=-1502;
        info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;
        std::vector<BYTE> pixels(1050*1502*4);Check(GetDIBits(dc,bitmap,0,1502,pixels.data(),&info,DIB_RGB_COLORS)!=0,"native rendered pixels");
        BITMAPFILEHEADER file{};file.bfType=0x4d42;file.bfOffBits=sizeof(file)+sizeof(info.bmiHeader);file.bfSize=file.bfOffBits+DWORD(pixels.size());
        std::ofstream out(root/L"settings.bmp",std::ios::binary);out.write(reinterpret_cast<char*>(&file),sizeof(file));out.write(reinterpret_cast<char*>(&info.bmiHeader),sizeof(info.bmiHeader));out.write(reinterpret_cast<char*>(pixels.data()),pixels.size());out.close();
        SelectObject(dc,previous);DeleteObject(bitmap);DeleteDC(dc);ReleaseDC(app.hwnd_,window);DestroyWindow(app.hwnd_);app.hwnd_=nullptr;
        veld::WipeString(secret);veld::WipeString(again);
    }
};
}
int main(int argc,char**argv)try {
    Check(argc==2,"explicit disposable fixture required");std::filesystem::path root(argv[1]);
    Check(!std::filesystem::exists(root),"fresh fixture preserves prior evidence");
    std::filesystem::create_directories(root);GuiStateQualification::Run(root);
    std::cout<<"PASS_WINDOWS_ADDRESS_ONLY_MINING\n";
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}
