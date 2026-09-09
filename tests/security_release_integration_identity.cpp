// Disposable encrypted daemon identities and RPC vaults. No secrets on stdout.
#include "security_first_activation_profile.h"
#define main unused_validator_main
#include "../src/veld-validator.cpp"
#undef main
#include <filesystem>

int main(int argc,char** argv) {
    if(argc!=4) return 2;
    const auto run=std::filesystem::absolute(argv[1]);
    const auto node=std::filesystem::absolute(argv[2]);
    const auto target=std::filesystem::absolute(argv[3]);
    const char* input=std::getenv("VELD_VAULT_PASSPHRASE");
    if(!input || !*input) return 3;
    std::string pass=input;
    veld::compat::UnsetEnv("VELD_VAULT_PASSPHRASE");
    struct Wipe {std::string& s;~Wipe(){veld::compat::SecureZero(s.data(),s.size());}} wipe{pass};
    std::string error;
    if(!veld::channel::secure_file::EnsurePrivateDirectory(target.string(),&error)) return 4;
    for(size_t i=0;i<11;++i) {
        const auto path=run/"disposable-identities"/("wallet-"+std::to_string(i)+".seed");
        if(i>=8 && !std::filesystem::exists(path)) {
            auto key=GenerateKeyPair(false);
            std::vector<uint8_t> bytes(key.private_key.begin(),key.private_key.end());
            const bool ok=veld::channel::secure_file::AtomicWrite(path.string(),bytes,&error,true);
            veld::compat::SecureZero(bytes.data(),bytes.size());
            if(!ok) return 5;
        }
        if(std::filesystem::file_size(path)!=32) return 6;
        ValidatorKey key;
        std::ifstream stream(path,std::ios::binary);
        stream.read(reinterpret_cast<char*>(key.privkey.data()),32);
        if(!stream) return 7;
        key.pubkey=DerivePublicKey(key.privkey);
        key.pubkey_hex=to_hex(key.pubkey);
        key.address=PubKeyToAddress(key.pubkey,false);
        if(!key.HasExactIdentityBinding()) return 8;
        if(i && !key.Save((target/("validator-"+std::to_string(i)+".key")).string(),pass)) return 9;
        std::cout<<key.address<<"\n";
        veld::compat::SecureZero(key.privkey.data(),key.privkey.size());
    }
    if(node!=run) {
        std::ifstream stream(node/"test-rpc-token");std::string token;stream>>token;
        if(token.size()!=64) return 10;
        auto encrypted=veld::wallet_crypto::EncryptWallet(token,pass);
        veld::compat::SecureZero(token.data(),token.size());
        if(!veld::channel::secure_file::AtomicWrite((node/"rpc.token").string(),encrypted,&error,true)) return 11;
        veld::compat::SecureZero(encrypted.data(),encrypted.size());
    }
    return 0;
}
