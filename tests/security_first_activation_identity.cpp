#include "security_state_migration_profile.h"
#include "crypto/veld_signing.h"
#include "wallet/secure_channel_file.h"
#include <filesystem>
#include <iostream>
int main(int argc,char** argv) {
    using namespace veld;
    if(argc!=2) return 2;
    const auto directory=std::filesystem::absolute(argv[1]);
    if(std::filesystem::exists(directory)) return 3;
    std::string error;
    if(!channel::secure_file::EnsurePrivateDirectory(directory.string(),&error)) return 4;
    for(size_t i=0;i<8;++i) {
        auto wallet=GenerateKeyPair(false);
        std::string seed(reinterpret_cast<const char*>(wallet.private_key.data()),wallet.private_key.size());
        const auto path=directory/("wallet-"+std::to_string(i)+".seed");
        const bool written=channel::secure_file::AtomicWriteText(path.string(),seed,&error,true);
        compat::SecureZero(seed.data(),seed.size());
        if(!written) return 5;
        std::cout<<wallet.address<<"\n";
    }
}
