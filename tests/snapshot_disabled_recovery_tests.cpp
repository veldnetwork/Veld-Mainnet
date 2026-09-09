#include "isolated_regtest_profile.h"
#include "node/node.h"
#include <iostream>
#include <stdexcept>

#ifdef VELD_ENABLE_SNAPSHOT_BOOTSTRAP
#error This fixture must compile without snapshot bootstrap support.
#endif
int main(int argc,char**argv) {
    namespace fs=std::filesystem;
    namespace sr=veld::snapshot_recovery;
    try {
        if(argc!=2)throw std::runtime_error("supply a new disposable fixture directory");
        fs::path base=argv[1];if(fs::exists(base))throw std::runtime_error("fixture path already exists");
        fs::create_directories(base);
        int checks=0;
        for(const auto* marker:{sr::REQUEST,sr::REVOKED,sr::JOURNAL,sr::IMPORT}) {
            const auto root=base/std::to_string(checks);
            veld::VeldNode::EnsureDataDir(root.string(),1234);
            std::string error;
            if(!veld::channel::secure_file::EnsurePrivateDirectory(root.string(),&error))throw std::runtime_error(error);
            sr::Write(root/marker,"inspection fixture\n");
            bool refused=false;
            try{veld::VeldNode::EnsureDataDir(root.string(),1234);}catch(const std::runtime_error&){refused=true;}
            if(!refused||!fs::is_directory(root/"db")||!fs::exists(root/marker))throw std::runtime_error("disabled build bypassed recovery obligation");
            ++checks;
        }
        std::cout<<"PASS "<<checks<<" disabled-build recovery barriers\n";return 0;
    }catch(const std::exception&e){std::cerr<<e.what()<<"\n";return 1;}
}
