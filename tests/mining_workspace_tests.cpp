#include "mining/veldhash.h"
#include <fstream>
#include <iostream>
#include <thread>

// Real production VeldHash, no node or network. Light dataset computation is
// checked against retained known answers; full dataset timing is separate.
int main(int argc,char** argv) {
    using namespace veld;
    try {
        if(argc!=2)throw std::runtime_error("known-vector file required");
        struct Vector { uint64_t height;std::vector<uint8_t> header;Hash256 expected; };
        std::vector<Vector> vectors;
        std::ifstream input(argv[1]);
        uint64_t height;std::string raw,expected;
        while(input>>height>>raw>>expected) {
            if(raw.size()!=176 || expected.size()!=64 || vectors.size()>=128)
                throw std::runtime_error("vector bounds");
            vectors.push_back({height,HexToBytes(raw),HexToHash(expected)});
        }
        if(!input.eof() || vectors.size()!=28)throw std::runtime_error("incomplete vectors");
        std::atomic<unsigned> checks{0};std::atomic<bool> failed{false};
        auto run=[&](unsigned offset) {
            try {
                mining::VeldHashVMImpl<true> workspace;
                // Different worker orders force seed/height/target changes.
                for(unsigned repeat=0;repeat<2;++repeat)for(size_t i=0;i<vectors.size();++i) {
                    const auto& v=vectors[(i+offset+repeat*13)%vectors.size()];
                    uint32_t bits=0;for(unsigned j=0;j<4;++j)bits|=uint32_t(v.header[76+j])<<(8*j);
                    CanonicalPowTarget target;
                    if(!DecodeCanonicalVeldTarget(bits,target))throw std::runtime_error("vector target");
                    const auto hash=mining::VeldHashWithDataset<true>(v.header,v.height,target,&workspace);
                    if(hash!=v.expected || !mining::g_veldhash_last_dataset_ok())throw std::runtime_error("reused VM changed known answer");
                    if(hash!=mining::VeldHashWithDataset<true>(v.header,v.height,target))throw std::runtime_error("fresh VM differs");
                    auto wrong=v.header;wrong[76]^=1;
                    const auto refused=mining::VeldHashWithDataset<true>(wrong,v.height,target,&workspace);
                    Hash256 sentinel;sentinel.fill(0xff);
                    if(refused!=sentinel || mining::g_veldhash_last_dataset_ok())throw std::runtime_error("wrong target admitted");
                    if(mining::VeldHashWithDataset<true>(v.header,v.height,target,&workspace)!=v.expected || !mining::g_veldhash_last_dataset_ok())throw std::runtime_error("refusal poisoned subsequent hash");
                    ++checks;
                }
            } catch(...) { failed=true; }
        };
        std::thread a(run,0),b(run,7);a.join();b.join();
        if(failed || checks!=112)throw std::runtime_error("workspace parity failed");
        std::cout<<"PASS 112 multi-worker vector sequences; fresh/reused parity; wrong-target refusal and recovery\n";
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
