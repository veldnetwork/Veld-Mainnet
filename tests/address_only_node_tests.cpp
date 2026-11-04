// Reuse the bounded private peer/admission fixture. No P2P server is started.
#define main existing_local_work_path_main
#include "local_work_path_equivalence_tests.cpp"
#undef main

int main(int argc, char** argv) try {
    Check(argc == 2, "explicit disposable directory");
    const std::filesystem::path root(argv[1]);
    Check(!std::filesystem::exists(root), "fresh fixture preserves prior evidence");
    std::filesystem::create_directories(root);
    compat::InitNetwork();
    VeldNode node(MainnetConfig(), (root / "node").string());
    node.TestWireDBForDurableCommit();
    Check(node.GetChainMut()
              .AddBlockDirect(CreateGenesisBlock(), true, true, false,
                              mining::PowAdmissionContext::Internal())
              .IsAccepted(),
          "private genesis installed");
    node.TestInstallWorkAdmissionProcessServer();
    auto peers = InstallPeers(node, 0, node.GetChain().TipCopy().GetHash());
    VeldNode::TestWorkAdmissionProcessState ready;
    node.TestConfigureWorkAdmissionProcess(ready);
    auto wallet = GenerateKeyPair(false);
    const auto address = wallet.address;
    std::string error;
    Check(!node.BindAddressGenerationIdentity("invalid", &error), "invalid payout refused");
    Check(!node.BindAddressGenerationIdentity(GenerateKeyPair(true).address, &error),
          "cross-network payout refused");
    RealKeyPair no_key;
    no_key.private_key.fill(0);
    no_key.public_key.fill(0);
    no_key.address = address;
    no_key.script_override = AddressToScript(address);
    Check(!node.BindGenerationIdentity(no_key, &error),
          "ordinary wallet binding still requires a real key pair");
    Check(node.BindAddressGenerationIdentity(address, &error),
          "public payout binds without private key");
    const auto first = node.GenerateBlocksForRpc(1);
    Check(first.generated == 1 && first.error.empty() && node.GetChain().Height() == 1,
          "native address-only proof commits one canonical block");
    const auto block = node.GetChain().TipCopy();
    Check(!block.transactions.empty() && !block.transactions[0].outputs.empty(), "coinbase exists");
    Check(block.transactions[0].outputs[0].value > 0 &&
              block.transactions[0].outputs[0].script_pubkey == AddressToScript(address),
          "miner reward pays exactly the chosen public address");
    Check(!std::filesystem::exists(root / "node" / "miner.key") &&
              !std::filesystem::exists(root / "node" / "pool.key"),
          "mining creates no wallet or pool signing keys");
    RefreshPeers(node, peers);
    WaitUntilWallClockExceedsMtp(node.GetChain());
    Check(node.BindGenerationIdentity(wallet, &error),
          "explicit wallet mode can still bind its validated key");
    Check(node.GenerateBlocksForRpc(1).generated == 1,
          "wallet mining remains functional after address role");
    node.Stop();
    std::cout << "PASS_NATIVE_ADDRESS_ONLY_REWARD_AND_WALLET_SEPARATION\n";
} catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
}
