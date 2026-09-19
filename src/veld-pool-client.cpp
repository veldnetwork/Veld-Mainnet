// Managed, seedless native pool worker. No backend RPC or wallet signing keys.
#include "pool/client_transport.h"
#include "consensus/nms_pow.h"
#include "mining/veldhash.h"
#include "mining/worker_policy.h"
#include "core/block.h"
#include "core/script.h"
#include "core/json_escape.h"
#include "core/version.h"
#include "wallet/secure_channel_file.h"
#include <atomic>
#include <csignal>
#include <iostream>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <ctime>
#ifndef _WIN32
#include <sys/file.h>
#endif

#ifndef VELD_MAINNET_POW
#error "native pool client requires canonical VeldHash"
#endif
#ifdef VELD_FLEET_NO_MINE
#error "fleet-no-mine artifacts cannot contain a pool worker"
#endif

namespace {
using namespace veld;
using namespace veld::pool;
std::atomic<bool> stopping{false};
static_assert(std::atomic<bool>::is_always_lock_free);
void Stop(int) { stopping.store(true); }
std::string Quote(const std::string& value) { return '"'+json::EscapeStringBytes(value)+'"'; }
std::string Object(const std::map<std::string,std::string>& values) {
    std::string out="{";
    for (const auto& [key,value]:values) { if(out.size()>1)out+=',';out+=Quote(key)+':'+Quote(value); }
    return out+'}';
}
Json Read(const std::filesystem::path& path) {
    std::vector<uint8_t> bytes;std::string error;
    if(channel::secure_file::Read(path.string(),bytes,&error,16384,true)!=channel::secure_file::ReadResult::Ok)
        throw std::runtime_error("private pool configuration unavailable: "+error);
    return Parse(std::string(bytes.begin(),bytes.end()));
}
void Write(const std::filesystem::path& path,const std::map<std::string,std::string>& value) {
    std::string error;
    Require(channel::secure_file::AtomicWriteText(path.string(),Object(value),&error,true),"private pool state write failed");
}
void Pause(uint64_t milliseconds) {
    const auto end=std::chrono::steady_clock::now()+std::chrono::milliseconds(milliseconds);
    while (!stopping && std::chrono::steady_clock::now()<end)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
}
struct Counters { std::atomic<uint64_t> hashes{0},accepted{0},near_misses{0},stale{0},rejected{0},active{0}; } counters;
class InstanceLock {
#ifdef _WIN32
    channel::secure_file::WinHandle handle_;
#else
    int descriptor_=-1;
#endif
public:
    explicit InstanceLock(const std::filesystem::path& path) {
#ifdef _WIN32
        handle_=channel::secure_file::WinHandle(CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,
            OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        Require(bool(handle_),"pool account is already in use");
#else
        descriptor_=open(path.c_str(),O_CREAT|O_WRONLY|O_CLOEXEC|O_NOFOLLOW,0600);
        if(descriptor_<0 || flock(descriptor_,LOCK_EX|LOCK_NB)!=0) {
            if(descriptor_>=0)close(descriptor_);descriptor_=-1;
            throw std::runtime_error("pool account is already in use");
        }
#endif
    }
    ~InstanceLock() {
#ifndef _WIN32
        if(descriptor_>=0)close(descriptor_);
#endif
    }
};
}

int main(int argc,char** argv) {
    using namespace veld;
    using namespace veld::pool;
    try {
        compat::HardenDllSearchPath();
        // Identity probes are pure: no configuration, account, key, or network access.
        if(argc==2 && std::string(argv[1])=="--version") {
            std::cout<<"Veld Pool Worker "<<CLIENT_VERSION<<'\n';return 0;
        }
        if(argc==2 && std::string(argv[1])=="--deployment-info") {
            std::cout<<"VELD_DEPLOYMENT_INFO_V1_JSON {\"binary_role\":\"pool-worker\","
                     <<"\"client_version\":\""<<CLIENT_VERSION<<"\","
                     <<"\"profile_id\":\""<<DEPLOYMENT_PROFILE_ID<<"\","
                     <<"\"genesis_fingerprint\":\""<<GENESIS_HASH<<"\","
                     <<"\"worker_protocol\":\"veld-pool/1\",\"signing_authority\":false,"
                     <<"\"remote_tls_backend\":\"openssl\",\"fleet_no_mine\":false}\n";
            return 0;
        }
        Require(argc==3 || argc==5,"use --config PRIVATE_CONFIG [--rounds COUNT]");
        Require(std::string(argv[1])=="--config","configuration argument required");
        uint64_t rounds=0;
        if(argc==5){Require(std::string(argv[3])=="--rounds","rounds argument");rounds=Number(argv[4],1000000);}
        compat::InitNetwork();
        std::signal(SIGINT,Stop);std::signal(SIGTERM,Stop);
#ifndef _WIN32
        std::signal(SIGPIPE,SIG_IGN);
#endif
        const auto cfg=Read(argv[2]);
        Require(cfg.object.size()==8,"pool client configuration schema");
        const auto endpoint=Text(Field(cfg,"endpoint")),ca=Text(Field(cfg,"ca_file"));
        const auto genesis=Hex(Field(cfg,"genesis"),64),address=Text(Field(cfg,"payout_address"));
        auto compiled=HexToBytes(GENESIS_HASH);std::reverse(compiled.begin(),compiled.end());
        Require(genesis==BytesToHex(compiled),"pool configuration is for a different compiled chain");
        Require(AddressToScript(address).size()==25,"pool payout address is invalid");
        const auto threads=Number(Text(Field(cfg,"threads")),mining::MAX_MINING_WORKERS);
        Require(threads>0,"pool worker count must be positive");
        const auto count=Number(Text(Field(cfg,"nonce_count")),256);
        Require(count>0,"pool nonce count must be positive");
        const auto pause=Number(Text(Field(cfg,"pause_ms")),60000);
        const auto directory=std::filesystem::absolute(Text(Field(cfg,"state_directory")));
        std::string error;
        Require(channel::secure_file::EnsurePrivateDirectory(directory.string(),&error),"private pool state directory required");
        InstanceLock instance(directory/"pool-client.lock");
        Require(!std::filesystem::exists(directory/"stop.request"),"clear the previous stop request before starting");
        TlsClient client(endpoint,ca);
        std::string account,worker_token,view_token;
        const auto account_path=directory/"pool-account.json";
        if(std::filesystem::exists(account_path)) {
            const auto saved=Read(account_path);
            Require(saved.object.size()==6 && Text(Field(saved,"endpoint"))==endpoint &&
                    Text(Field(saved,"address"))==address && Text(Field(saved,"genesis"))==genesis,
                    "saved pool account does not match configuration");
            account=Hex(Field(saved,"account"),32);worker_token=Hex(Field(saved,"worker_token"),64);
            view_token=Hex(Field(saved,"view_token"),64);
        } else {
            Json registered;
            unsigned retry=0;
            for(;;) {
                if(stopping || std::filesystem::exists(directory/"stop.request"))return 0;
                try { registered=client.Call("register",Object({{"address",address}}));break; }
                catch(const Retry&) {
                    Write(directory/"pool-status.json",{{"address",address},{"status","Connecting; retrying"},
                          {"active_workers","0"}});
                    const unsigned steps=std::min(100u,5u*(++retry));
                    for(unsigned step=0;step<steps && !stopping;++step) {
                        if(std::filesystem::exists(directory/"stop.request"))return 0;
                        Pause(100);
                    }
                }
            }
            Require(Text(Field(registered,"version"))=="veld-pool/1","unsupported pool version");
            account=Hex(Field(registered,"account"),32);worker_token=Hex(Field(registered,"worker_token"),64);
            view_token=Hex(Field(registered,"view_token"),64);
            Write(account_path,{{"endpoint",endpoint},{"address",address},{"genesis",genesis},
                               {"account",account},{"worker_token",worker_token},{"view_token",view_token}});
        }
        std::mutex status_mutex;
        std::string detail="Connecting";bool fatal=false;
        std::atomic<uint64_t> finished{0};
        auto status=[&](const char* value,bool failure=false){
            std::lock_guard<std::mutex> lock(status_mutex);detail=value;fatal|=failure;
        };
        std::vector<std::thread> workers;
        std::map<std::string,std::string> snapshot={{"address",address},{"account",account},{"genesis",genesis}};
        try {
            for(uint64_t thread=0;thread<threads;++thread) workers.emplace_back([&] {
                uint64_t completed=0,retries=0;
                try {
                    while(!stopping && (!rounds || completed<rounds)) {
                        try {
                            const auto start_time=std::chrono::steady_clock::now();
                            const auto job=client.Call("work",Object({{"account",account},{"token",worker_token},{"count",std::to_string(count)}}));
                            Require(Text(Field(job,"version"))=="veld-pool/1" && Hex(Field(job,"chain"),64)==genesis,
                                    "pool job network or version mismatch");
                            const auto lease=Hex(Field(job,"lease"),32),encoded=Hex(Field(job,"header"),176);
                            const auto target=HexToHash(Hex(Field(job,"target"),64));
                            Require(target!=Hash256{},"zero pool accounting target");
                            const auto height=Number(Text(Field(job,"height")));
                            const auto nonce_text=Hex(Field(job,"start"),16);
                            const uint64_t first=std::stoull(nonce_text,nullptr,16);
                            const uint64_t amount=Number(Text(Field(job,"count")),count);
                            Require(amount>0 && amount-1<=UINT64_MAX-first,"pool nonce range overflow");
                            const auto ttl=Number(Text(Field(job,"ttl_ms")),10000);
                            const auto expires=start_time+std::chrono::milliseconds(ttl);
                            BlockHeader header;Require(header.Deserialize(HexToBytes(encoded)) && header.nonce==0,"pool header encoding");
                            CanonicalPowTarget network;Require(DecodeCanonicalVeldTarget(header.bits,network),"pool network target");
                            retries=0;status("Mining");++counters.active;
                            struct Active { ~Active(){--counters.active;} } active;
                            for(uint64_t offset=0;offset<amount && !stopping && std::chrono::steady_clock::now()<expires;++offset) {
                                header.nonce=first+offset;
                                const auto proof=mining::VeldHash(header.Serialize(),height,network);
                                if(!mining::g_veldhash_last_dataset_ok()) throw Retry("local hashing resources unavailable");
                                ++counters.hashes;
                                if(proof<target || proof<network.bytes || IsNmsProofInRange(proof,network)) {
                                    std::ostringstream nonce;nonce<<std::hex<<std::setfill('0')<<std::setw(16)<<header.nonce;
                                    const auto request=Object({{"account",account},{"token",worker_token},{"lease",lease},{"nonce",nonce.str()}});
                                    Json result;
                                    // Preserve the same leased proof during bounded retries.
                                    for(unsigned retry=0;;++retry) {
                                        try{result=client.Call("submit",request);break;}
                                        catch(const Retry&){if(retry==7 || stopping)throw;Pause(std::min(1000u,50u<<retry));}
                                    }
                                    const auto disposition=Text(Field(result,"status"));
                                    if(disposition=="verified")++counters.accepted;
                                    else if(disposition=="near_miss")++counters.near_misses;
                                    else if(disposition=="stale")++counters.stale;
                                    else if(disposition=="invalid")++counters.rejected;
                                    else Require(disposition=="duplicate" || disposition=="pending","pool submission status");
                                }
                                Pause(pause);
                            }
                            ++completed;
                        } catch(const Retry&) {
                            status("Connection or verification busy; retrying");Pause(std::min(uint64_t(30000),250u*(++retries)));
                        }
                    }
                } catch(const std::exception&) {
                    status("Pool request or certificate refused; check configuration",true);stopping=true;
                }
                ++finished;
            });
            auto next_balance=std::chrono::steady_clock::now();
            while(finished<threads) {
                if(std::filesystem::exists(directory/"stop.request"))stopping=true;
                {
                    std::lock_guard<std::mutex> lock(status_mutex);snapshot["status"]=detail;
                }
                snapshot["hashes"]=std::to_string(counters.hashes.load());
                snapshot["accepted"]=std::to_string(counters.accepted.load());
                snapshot["near_misses"]=std::to_string(counters.near_misses.load());
                snapshot["stale"]=std::to_string(counters.stale.load());
                snapshot["rejected"]=std::to_string(counters.rejected.load());
                snapshot["active_workers"]=std::to_string(counters.active.load());
                if(!stopping && std::chrono::steady_clock::now()>=next_balance) {
                    try {
                        const auto balance=client.Call("account",Object({{"account",account},{"token",view_token}}));
                        Require(Text(Field(balance,"account"))==account && Text(Field(balance,"address"))==address,"pool balance identity");
                        for(const auto field:{"pending_units","available_units","reserved_units","paid_units","verified_shares"}) {
                            const auto value=Text(Field(balance,field));Number(value);snapshot[field]=value;
                        }
                        snapshot["balances_updated"]=std::to_string(std::time(nullptr));
                    } catch(const Retry&) {} // Existing balance timestamp remains stale.
                    next_balance=std::chrono::steady_clock::now()+std::chrono::seconds(15);
                }
                Write(directory/"pool-status.json",snapshot);
                if(stopping)std::this_thread::sleep_for(std::chrono::milliseconds(200));else Pause(1000);
            }
        } catch(...) {
            stopping=true;for(auto& worker:workers)worker.join();throw;
        }
        for(auto& worker:workers)worker.join();
        snapshot["status"]=fatal?"Pool request refused":"Stopped";
        snapshot["active_workers"]="0";snapshot["hashes"]=std::to_string(counters.hashes.load());
        snapshot["accepted"]=std::to_string(counters.accepted.load());
        Write(directory/"pool-status.json",snapshot);
        std::cout<<Object({{"hashes",std::to_string(counters.hashes.load())},
            {"accepted",std::to_string(counters.accepted.load())},{"status",fatal?"refused":"stopped"}})<<'\n';
        return fatal?1:0;
    } catch(const std::exception& error) {
        std::cerr<<"pool client: "<<error.what()<<'\n';return 1;
    }
}
