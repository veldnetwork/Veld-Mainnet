// Native full-node lab entrypoint. The ASERT test-chain identity/clock is
// isolated, but PoW, monetary amounts, signatures and validation are unchanged.
#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_ASERT_TESTCHAIN 1
#define VELD_TEST_STAKE_OUTPOINT_BACKING 1
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3840
#if defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET)
#error "pool qualification backend cannot be a public artifact"
#endif
#include "node/node.h"
#include "network/rpc_http.h"
#include <filesystem>
#include <fstream>

int main(int argc, char** argv) {
    using namespace veld;
    try {
        if (argc != 4) throw std::runtime_error("use NEW_LAB_DIRECTORY P2P_PORT RPC_PORT");
        compat::InitNetwork();
        const auto directory = std::filesystem::absolute(argv[1]);
        std::string error;
        if (!channel::secure_file::EnsurePrivateDirectory(directory.string(), &error))
            throw std::runtime_error(error);
        auto config = RegtestConfig();
        config.port = static_cast<uint16_t>(std::stoul(argv[2]));
        config.rpc_port = static_cast<uint16_t>(std::stoul(argv[3]));
        if (config.port < 20000 || config.rpc_port < 20000 || config.port == config.rpc_port)
            throw std::runtime_error("lab ports");
        VeldNode node(config, directory.string());
        node.SetQuietBoot(true);
        node.SetP2PPort(config.port);
        node.Start();
        std::array<uint8_t, 32> entropy{};
        if (!compat::SecureRandom(entropy.data(), entropy.size())) throw std::runtime_error("randomness");
        const std::string token = BytesToHex(entropy);
        if (!channel::secure_file::AtomicWriteText((directory/"lab-rpc-token").string(), token, &error, true))
            throw std::runtime_error(error);
        RpcHttpServer http(node.GetRPC(), config.rpc_port, "", token);
        if (!http.Start()) throw std::runtime_error("RPC start");
        std::cout << "POOL_LAB_READY" << std::endl;
        std::string command;
        while (std::getline(std::cin, command)) {
            if (command == "stop") break;
            if (command.rfind("clock ", 0) == 0) {
                // Historical clock is only a construction input; consensus still
                // validates median/future time and real branch-local difficulty.
                asert_qualification::candidate_time.store(std::stoull(command.substr(6)));
                std::cout << "CLOCK_SET" << std::endl;
            } else if (command.rfind("peer ", 0) == 0) {
                const auto port = std::stoul(command.substr(5));
                if (port < 20000 || port > 65535 || port == config.port)
                    throw std::runtime_error("lab peer port");
                // Normal untrusted P2P admission, confined to this namespace.
                std::cout << (node.ConnectTo("127.0.0.1",static_cast<uint16_t>(port))
                    ? "PEER_CONNECTED" : "PEER_REFUSED") << std::endl;
            } else if (command.rfind("mine ", 0) == 0) {
                // Native fixture prehistory only. MineBlocks retains its normal
                // synchronous work admission, complete settlement builder,
                // actual VeldHash, preflight and canonical commit. No target,
                // subsidy, validation, or admission-policy override is supplied.
                // This is NOT evidence of the external pool worker path.
                const std::string address=command.substr(5);
                const auto script=AddressToScript(address);
                if(script.size()!=25 || ScriptToAddress(script)!=address)
                    throw std::runtime_error("fixture miner address");
                RealKeyPair recipient;recipient.script_override=script;
                const auto mined=node.MineBlocks(recipient,1,0);
                if(mined.size()!=1 || !mined[0].success) {
                    // A normal work-admission cancellation is retryable by the
                    // lab driver. It must not terminate a healthy full node.
                    std::cout << "MINE_DEFERRED " << (mined.empty()?std::string("no result"):mined[0].error)
                              << " tag=" << Blockchain::GetLastRejectTag() << std::endl;
                } else std::cout << "MINED " << mined[0].new_height << ' '
                                 << HashToHex(mined[0].block.GetHash()) << std::endl;
            } else std::cout << "UNKNOWN" << std::endl;
        }
        http.Stop(); node.Stop();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}
