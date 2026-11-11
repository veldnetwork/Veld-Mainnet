#include "appchain_bridge_fixture.h"
int main(int argc, char** argv) {
    try {
        need(argc == 3, "mode and artifact directory required");
        std::string mode = argv[1];
        fs::path path = fs::absolute(argv[2]);
        if (mode == "genesis") {
            auto b = veld::CreateGenesisBlock();
            mine(b);
            auto h = b.GetHash();
            std::reverse(h.begin(), h.end());
            std::cout << "GENESIS {\"nonce\":" << b.header.nonce << ",\"hash\":\"" << hex(h)
                      << "\"}\n";
            return 0;
        }
        if (mode == "boundaries") {
            // Read a closed positive corpus; do not mutate any of its receipts.
            // Negative probes deliberately exercise an internal skip-scripts caller.
            // Every admitted setup block still passes full PoW and script validation.
            Fixture f;
            for (uint64_t h = 0; h <= 702; ++h)
                admit(f.chain, load(path / (std::to_string(h) + ".block"), h));
            auto valid = load(path / "703.block", 703);
            need(valid.transactions.size() == 2, "known first payout fixture");
            auto payout = valid.transactions[1];
            check(f.chain.ValidateTransactionLocking(payout),
                  "boundary corpus genuine finalized payout");
            auto probe = [&](veld::Block b, const std::string& label) {
                auto u = f.chain.UtxoDigest(), s = f.chain.SupplyDigest();
                auto bridge = f.chain.AppBridgeDigest();
                mine(b);
                check(!f.chain
                           .AddBlockDirect(b, false, true, false,
                                           veld::mining::PowAdmissionContext::Internal())
                           .IsAccepted(),
                      label);
                check(f.chain.Height() == 702 && f.chain.UtxoDigest() == u &&
                          f.chain.SupplyDigest() == s && f.chain.AppBridgeDigest() == bridge,
                      label + " no mutation");
            };
            // Re-spend a newly created reserve in an unmarked same-block child.
            veld::Transaction theft;
            veld::TxInput in;
            in.prev_tx_hash = payout.GetTxID();
            in.prev_out_index = 2;
            theft.inputs.push_back(in);
            theft.outputs.emplace_back(payout.outputs[2].value - veld::MIN_TX_FEE,
                                       f.key.GetP2PKHScript());
            auto block = valid;
            block.transactions.push_back(theft);
            block.transactions[0] = veld::Blockchain::BuildCanonicalCoinbase(
                703, f.chain.TotalSupplyUnits(), 2 * veld::MIN_TX_FEE, f.key.GetP2PKHScript());
            block.UpdateMerkleRoot();
            probe(block, "internal loader refuses same-block reserve bypass");
            // Registration must authenticate ordinary funding even on this caller.
            auto ordinaryScript =
                load(path / "1.block", 1).transactions[0].outputs[0].script_pubkey;
            auto coins = f.chain.GetUTXOsForScript(ordinaryScript);
            auto coin = std::find_if(coins.begin(), coins.end(), [](auto& u) {
                return u.value > veld::MIN_TX_FEE &&
                       u.block_height + veld::COINBASE_MATURITY <= 702;
            });
            need(coin != coins.end(), "boundary real funding");
            auto committee = f.chain.AppBridgeState()->records.begin()->second.committee;
            committee.bridge = name("unsigned-registration");
            Writer w;
            w.str(committee.encode(), 20000);
            veld::Transaction tx;
            in.prev_tx_hash = coin->tx_hash;
            in.prev_out_index = coin->output_index;
            tx.inputs.push_back(in);
            tx.outputs.emplace_back(0, br::marker(0, w.b));
            tx.outputs.emplace_back(coin->value - veld::MIN_TX_FEE, ordinaryScript);
            auto unsignedBlock = f.candidate({tx});
            probe(unsignedBlock, "internal loader refuses unsigned bridge funding");
            auto doubleMarker = valid;
            doubleMarker.transactions[1].outputs[0].script_pubkey.push_back(0);
            doubleMarker.UpdateMerkleRoot();
            probe(doubleMarker, "internal loader refuses noncanonical marker");
            admit(f.chain, valid);
            check(f.chain.AppBridgeDigest() != br::State{}.digest(),
                  "valid payout still admitted with full validation");
        } else if (mode == "replay") {
            need(fs::exists(path / "created.json") && !fs::exists(path / "replayed.json"),
                 "fresh completed corpus required");
            veld::Blockchain c;
            uint64_t h = 0;
            while (fs::exists(path / (std::to_string(h) + ".block"))) {
                admit(c, load(path / (std::to_string(h) + ".block"), h));
                ++h;
            }
            need(h > 800, "full bridge corpus required");
            summary(path / "replayed.json", c);
        } else {
            need(mode == "create" && !fs::exists(path), "fresh disposable directory");
            fs::create_directories(path);
            Fixture f;
            f.path = path;
            auto genesis = veld::CreateGenesisBlock();
            check(std::string(veld::GENESIS_HASH) != "" &&
                      std::string(veld::GENESIS_HASH) != VELD_ASERT_GENESIS_HASH,
                  "separate pinned bridge genesis");
            admit(f.chain, genesis);
            save(path / "0.block", genesis);
            f.until(101);
            std::array<Key, 10> keys;
            Committee committee;
            committee.parentGenesis = genesis.GetHash();
            committee.bridge = name("bridge");
            committee.childGenesis = name("child-state2");
            for (size_t i = 0; i < 10; ++i)
                committee.keys[i] = keys[i].pub;
            Writer reg;
            reg.str(committee.encode(), 20000);
            auto registration = f.fund(br::marker(0, reg.b));
            check(f.chain.ValidateTransactionLocking(registration),
                  "real signed descriptor registration");
            f.block({registration});
            Writer dep;
            dep.raw(name("owner"));
            dep.n(10000000, 8);
            dep.n(10000000, 8);
            auto deposit = f.fund(command(1, committee.bridge, dep.b),
                                  {{20000000, br::reserveScript(committee.bridge)}});
            auto malformed = deposit;
            malformed.outputs[1].value -= 1;
            f.sign(malformed);
            f.refused(malformed, "deposit allocation mismatch");
            auto unsignedDeposit = deposit;
            unsignedDeposit.inputs[0].script_sig.clear();
            f.refused(unsignedDeposit, "unsigned funding");
            auto mixed = deposit;
            mixed.outputs.emplace_back(0, Bytes{0x6a, 1, 0x01});
            f.sign(mixed);
            f.refused(mixed, "extra marker");
            auto forged = deposit;
            forged.outputs[0].script_pubkey = Bytes{0x6a, 1, 0};
            f.sign(forged);
            f.refused(forged, "bare reserve creation");
            auto d = f.block({deposit});
            check(f.chain.AppBridgeState()->totalReserve == 20000000, "actual reserve deposit");
            auto snapshot = f.chain.AppBridgeState();
            auto noMarker = f.fund(Bytes{0x6a, 1, 0});
            noMarker.inputs[0].prev_tx_hash = deposit.GetTxID();
            noMarker.inputs[0].prev_out_index = 1;
            noMarker.inputs[0].script_sig.clear();
            noMarker.outputs[1].value = 20000000 - veld::MIN_TX_FEE;
            f.refused(noMarker, "generic reserve theft");
            br::Leaf leaf;
            leaf.chain = committee.childGenesis;
            leaf.bridge = committee.bridge;
            leaf.owner = name("owner");
            leaf.nonce = 1;
            leaf.gross = 10000000;
            leaf.maxFee = veld::MIN_TX_FEE;
            leaf.minimum = leaf.gross - leaf.maxFee;
            leaf.recipient = f.key.GetP2PKHScript();
            br::Leaf second = leaf;
            second.nonce = 2;
            second.source = 1;
            second.gross = 5000000;
            second.minimum = second.gross - second.maxFee;
            std::vector<br::Leaf> leaves{leaf, second};
            std::sort(leaves.begin(), leaves.end(),
                      [](auto& a, auto& b) { return a.id() < b.id(); });
            Checkpoint cp;
            cp.parentGenesis = genesis.GetHash();
            cp.childGenesis = committee.childGenesis;
            cp.bridge = committee.bridge;
            cp.descriptor = committee.id();
            cp.sequence = 1;
            cp.sourceHeight = 120;
            cp.sourceHash = name("child120");
            cp.sourceWork[0] = 1;
            cp.accountsRoot = name("accounts");
            cp.assetsRoot = name("assets");
            cp.fuelRoot = name("fuel");
            cp.minerRoot = name("miners");
            cp.withdrawalsRoot = br::branch(leaves[0].digest(), leaves[1].digest());
            cp.parentAnchorHeight = 1;
            cp.parentAnchorHash = load(path / "1.block", 1).GetHash();
            cp.depositedTotal = 20000000;
            auto cert = certificate(cp, keys);
            Writer cw;
            cw.str(cert.encode(), 35000);
            f.refused(f.fund(command(2, committee.bridge, cw.b)), "immature deposit/checkpoint");
            f.until(d.height + 117);
            f.refused(f.fund(command(2, committee.bridge, cw.b)),
                      "119-confirmation deposit boundary");
            f.block();
            auto badCert = cert;
            badCert.signatures[0].bytes[0] ^= 1;
            Writer bad;
            bad.str(badCert.encode(), 35000);
            f.refused(f.fund(command(2, committee.bridge, bad.b)), "forged quorum signature");
            auto submit = f.fund(command(2, committee.bridge, cw.b));
            auto sb = f.block({submit});
            check(sb.height - d.height + 1 == 120, "exact 120-confirmation deposit admission");
            Writer fin;
            fin.raw(cp.id());
            f.refused(f.fund(command(3, committee.bridge, fin.b)), "early finalization");
            f.until(sb.height + br::DELAY - 2);
            f.refused(f.fund(command(3, committee.bridge, fin.b)),
                      "479th-block finalization boundary");
            f.block();
            auto finalized = f.block({f.fund(command(3, committee.bridge, fin.b))});
            check(finalized.height == sb.height + 480, "exact 480 further blocks");
            auto makePayout = [&](size_t which, uint64_t transition, br::Outpoint reserve,
                                  uint64_t reserveValue) {
                br::Proof proof{leaves[which], uint32_t(which), 2, {leaves[1 - which].digest()}};
                Writer w;
                w.n(transition, 8);
                w.raw(cp.id());
                w.n(veld::MIN_TX_FEE, 8);
                w.n(1, 1);
                proof.write(w);
                veld::Transaction tx;
                veld::TxInput in;
                in.prev_tx_hash = reserve.tx;
                in.prev_out_index = reserve.index;
                tx.inputs.push_back(in);
                tx.outputs.emplace_back(0, command(5, committee.bridge, w.b));
                tx.outputs.emplace_back(proof.leaf.gross - veld::MIN_TX_FEE, proof.leaf.recipient);
                if (reserveValue > proof.leaf.gross)
                    tx.outputs.emplace_back(reserveValue - proof.leaf.gross,
                                            br::reserveScript(committee.bridge));
                return tx;
            };
            auto payout = makePayout(0, 1, {deposit.GetTxID(), 1}, 20000000);
            auto redirected = payout;
            redirected.outputs[1].script_pubkey = veld::GenerateKeyPair(true).GetP2PKHScript();
            f.refused(redirected, "payout redirect");
            auto excess = payout;
            --excess.outputs[1].value;
            f.refused(excess, "extra user fee");
            auto stolen = payout;
            --stolen.outputs[2].value;
            f.refused(stolen, "extra reserve fee");
            auto malleated = payout;
            malleated.inputs[0].script_sig = {0};
            f.refused(malleated, "reserve scriptSig malleability");
            check(f.chain.ValidateTransactionLocking(payout),
                  "finalized proof authorizes exact covenant spend");
            veld::Mempool pool;
            check(pool.Add(payout, veld::MIN_TX_FEE, f.chain.Height(), f.chain) ==
                      veld::Mempool::AddResult::ACCEPTED,
                  "real payout mempool");
            auto before = f.chain.AppBridgeDigest();
            auto paid = f.block({payout});
            auto after = f.chain.AppBridgeDigest();
            auto paidUtxo = f.chain.UtxoDigest();
            check(f.chain.GetUTXO(payout.GetTxID(), 1)->value == leaves[0].gross - veld::MIN_TX_FEE,
                  "actual recipient UTXO");
            check(snapshot->totalReserve == 20000000, "unpublished historical state immutable");
            f.refused(makePayout(0, 2, {payout.GetTxID(), 2}, 20000000 - leaves[0].gross),
                      "same withdrawal with fresh reserve");
            check(f.chain.RollbackTip() && f.chain.AppBridgeDigest() == before,
                  "withdrawal undo restores nullifier and reserve");
            save(path / "withdrawal-disconnected.block", paid);
            ++paid.header.timestamp;
            mine(paid);
            admit(f.chain, paid);
            save(path / (std::to_string(paid.height) + ".block"), paid);
            check(f.chain.AppBridgeDigest() == after && f.chain.UtxoDigest() == paidUtxo,
                  "alternative inclusion reproduces complete bridge and UTXO state");
            f.until(finalized.height + br::STALE - 1);
            f.refused(f.fund(command(1, committee.bridge, dep.b),
                             {{20000000, br::reserveScript(committee.bridge)}}),
                      "960-block stale checkpoint stops new deposits");
            auto conflicting = cp;
            conflicting.sourceHash = name("conflicting-child");
            auto other = certificate(conflicting, keys);
            Writer conflict;
            conflict.str(cert.encode(), 35000);
            conflict.str(other.encode(), 35000);
            f.block({f.fund(command(4, committee.bridge, conflict.b))});
            check(f.chain.AppBridgeState()->records.at(committee.bridge).exitOnly,
                  "complete conflicting quorum enters exit-only");
            f.refused(f.fund(command(1, committee.bridge, dep.b),
                             {{20000000, br::reserveScript(committee.bridge)}}),
                      "conflict blocks new deposits");
            auto exit = makePayout(1, 2, {payout.GetTxID(), 2}, 20000000 - leaves[0].gross);
            f.block({exit});
            check(f.chain.AppBridgeState()->totalReserve == 5000000,
                  "existing finalized exit survives quorum conflict");
            f.until(f.chain.Height() + 120);
            summary(path / "created.json", f.chain);
        }
        std::cout << "RESULT {\"passed\":" << checks << ",\"failed\":0,\"skipped\":0}\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        std::cout << "RESULT {\"passed\":" << checks << ",\"failed\":1,\"skipped\":0}\n";
        return 1;
    }
}
