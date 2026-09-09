// Same disk fixture on the preserved and corrected startup implementations.
#include "isolated_regtest_profile.h"
#define VELD_ENABLE_SNAPSHOT_BOOTSTRAP 1
#include "node/node.h"
#include <iostream>
#include <fstream>
int main(int argc,char**argv) {
    namespace fs=std::filesystem;
    try {
        if(argc!=2)throw std::runtime_error("new disposable directory required");
        fs::path root=argv[1];if(fs::exists(root))throw std::runtime_error("preserve prior fixture");
        std::string error;
        if(!veld::channel::secure_file::EnsurePrivateDirectory(root.string(),&error))throw std::runtime_error(error);
        fs::create_directories(root/"db");fs::create_directories(root/"blocks");
        {
            veld::db::LevelDBStore store((root/"db/index").string(),true);
            if(!store.Put("fixture:rejected-history","retained"))throw std::runtime_error("database fixture write");
        }
        const auto write=[&](const char* name,const char* body){
            if(!veld::channel::secure_file::AtomicWriteText((root/name).string(),body,&error,true))throw std::runtime_error(error);
        };
        write(".snapshot-recovery-requested","schema=1\nreason=independent-tip-mismatch\n");
        write(".snapshot-fast-start-revoked","schema=1\nreason=independent-tip-mismatch\n");
#ifdef VELD_RECOVERY_BASELINE_FIXTURE
        veld::VeldNode::EnsureDataDir(root.string());
#else
        veld::VeldNode::EnsureDataDir(root.string(),veld::RegtestConfig().magic);
#endif
        size_t quarantines=0;
        for(const auto& item:fs::directory_iterator(root))
            if(item.path().filename().string().starts_with(".snapshot-rejected-")) {
                ++quarantines;
                veld::db::LevelDBStore store((item.path()/"db/index").string(),false);
                if(store.Get("fixture:rejected-history")!="retained")throw std::runtime_error("rejected history not preserved");
            }
        if(quarantines!=1 || fs::exists(root/"db/index"))
            throw std::runtime_error("recovery request left rejected database in the active namespace");
        if(!fs::exists(root/".snapshot-recovery-requested"))throw std::runtime_error("recovery request retired before IBD");
        std::cout<<"PASS rejected database quarantined before normal storage construction\n";return 0;
    }catch(const std::exception&e){std::cerr<<"FAIL "<<e.what()<<"\n";return 1;}
}
