#include "mining/veldhash.h"
#include <chrono>
#include <iomanip>
#include <iostream>

// Sequential, offline full-production-parameter calls. Both paths run the same
// canonical entry point; only ownership of the scratch allocation differs.
int main() {
    using namespace veld;
#if !defined(VELD_MAINNET_POW) || defined(VELD_LIGHT_VERIFY) || defined(VELD_TEST_DATASET_BYTES)
    return 2;
#else
    using Clock=std::chrono::steady_clock;
    mining::VeldIntegerDeterminismCheck();mining::VeldDatasetLightKat();
    CanonicalPowTarget target;
    if(!DecodeCanonicalVeldTarget(GENESIS_BITS,target))return 2;
    std::vector<uint8_t> header(88);header[0]=1;
    for(unsigned i=4;i<68;++i)header[i]=uint8_t(i*11+5);
    for(unsigned i=0;i<4;++i)header[76+i]=uint8_t(GENESIS_BITS>>(8*i));
    mining::VeldHashVM workspace;
    const auto warm=mining::VeldHashWithDataset<false>(header,2880,target,&workspace);
    if(!mining::g_veldhash_last_dataset_ok())return 1;
    for(unsigned trial=0;trial<8;++trial) {
        Hash256 expected{};
        for(unsigned order=0;order<2;++order) {
            const bool reuse=(trial+order)%2;SHA256 checksum;
            const auto start=Clock::now();
            for(unsigned n=0;n<256;++n) {
                for(unsigned j=0;j<8;++j)header[80+j]=uint8_t(uint64_t(n)>>(8*j));
                const auto hash=mining::VeldHashWithDataset<false>(header,2880,target,reuse?&workspace:nullptr);
                if(!mining::g_veldhash_last_dataset_ok())return 1;
                checksum.update(hash.data(),hash.size());
            }
            const double seconds=std::chrono::duration<double>(Clock::now()-start).count();
            const auto digest=checksum.digest();
            if(!order)expected=digest;else if(digest!=expected)return 1;
            std::cout<<std::fixed<<std::setprecision(6)<<"{\"trial\":"<<trial<<",\"reuse\":"<<(reuse?"true":"false")
                <<",\"hashes\":256,\"seconds\":"<<seconds<<",\"hashrate_hs\":"<<256/seconds<<",\"checksum\":\""<<HashToHex(digest)<<"\"}\n"<<std::flush;
        }
    }
#endif
}
