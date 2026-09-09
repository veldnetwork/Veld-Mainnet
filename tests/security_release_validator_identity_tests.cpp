#define main unused_standalone_validator_entry
#include "../src/veld-validator.cpp"
#undef main
#include <cassert>
int main() {
    namespace wa=veld::work_admission;
#if defined(VELD_RELEASE_INTEGRATION_NETWORK)
    assert(compiled_work_network_magic()==RegtestConfig().magic);
#else
    assert(compiled_work_network_magic()==MAINNET_MAGIC);
#endif
    wa::Binding binding;
    binding.subject.purpose=wa::Purpose::FinalityVote;
    binding.subject.height=3360;
    binding.subject.target_hash[0]=1;
    binding.subject.parent_height=3361;
    binding.subject.parent_hash[0]=2;
    binding.validation_generation=1;
    binding.network_magic=compiled_work_network_magic();
    binding.genesis_hash=compiled_genesis_bytes();
    binding.profile_digest=Hash256d(std::string(DEPLOYMENT_PROFILE_ID));
    const auto purpose=binding.subject.purpose;
    const auto target=binding.subject.target_hash;
    assert(validate_work_binding(wa::EncodeBinding(binding),purpose,3360,target));
    binding.network_magic^=1;
    assert(!validate_work_binding(wa::EncodeBinding(binding),purpose,3360,target));
    binding.network_magic=compiled_work_network_magic();binding.genesis_hash[0]^=1;
    assert(!validate_work_binding(wa::EncodeBinding(binding),purpose,3360,target));
    binding.genesis_hash=compiled_genesis_bytes();binding.profile_digest[0]^=1;
    assert(!validate_work_binding(wa::EncodeBinding(binding),purpose,3360,target));
    const auto display=bitcoin_core_display_hash(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    assert(display && *display==
        "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");
    assert(!bitcoin_core_display_hash("not-a-hash"));
    assert(!bitcoin_core_display_hash(std::string(64,'G')));
    std::cout<<"PASS standalone network/genesis/profile and Bitcoin hash boundary checks=8\n";
}
