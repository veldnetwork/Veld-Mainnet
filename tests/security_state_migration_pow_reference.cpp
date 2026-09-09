#include "security_state_migration_profile.h"
#include "core/block.h"
#include "mining/veldhash.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>

int main(int argc,char** argv) {
    using namespace veld;
    try {
        if(argc!=2 && argc!=3) throw std::runtime_error("supply canonical test history [--separate-boundary]");
        const bool separate=argc==3 && std::string(argv[2])=="--separate-boundary";
        if(argc==3 && !separate) throw std::runtime_error("unknown reference selection");
        mining::VeldDatasetLightKat();
        std::ifstream in(std::filesystem::absolute(argv[1]),std::ios::binary);
        char magic[8]{}; in.read(magic,8);
        if(!in || std::string(magic,8)!="VLDMIG01") throw std::runtime_error("history header");
        const std::set<uint64_t> selected=separate?std::set<uint64_t>{3359,3360}:
            std::set<uint64_t>{0,1,255,256,479,480,2879,2880,2881,2891};
        uint64_t height=0;
        while(in.peek()!=std::char_traits<char>::eof()) {
            if(height>4096) throw std::runtime_error("history height bound");
            uint32_t length=0;
            for(unsigned i=0;i<4;++i) { const int byte=in.get(); if(byte<0) throw std::runtime_error("history length"); length|=uint32_t(byte)<<(i*8); }
            if(length==0 || length>MAX_BLOCK_SIZE) throw std::runtime_error("history body bound");
            std::vector<uint8_t> bytes(length); in.read(reinterpret_cast<char*>(bytes.data()),length);
            Block block;
            if(!in || Block::Deserialize(bytes,0,block)!=bytes.size() || block.Serialize()!=bytes)
                throw std::runtime_error("history encoding");
            if(selected.count(height)) {
                const auto hash=mining::VeldHash(block.header.Serialize(),height);
                if(!mining::g_veldhash_last_dataset_ok() || !(hash<block.header.GetTarget()))
                    throw std::runtime_error("reference PoW verification failed");
                std::cout<<"{\"height\":"<<height<<",\"pow_hash\":\""<<HashToHex(hash)<<"\"}"<<std::endl;
            }
            ++height;
        }
        if(height<(separate?3361u:2882u)) throw std::runtime_error("history does not cross the migration");
        return 0;
    } catch(const std::exception& e) { std::cerr<<"FAIL: "<<e.what()<<std::endl; return 1; }
}
