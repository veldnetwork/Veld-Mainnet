#include "network/rpc.h"
#include <chrono>
#include <filesystem>
#include <iostream>
#include <set>

using namespace veld;
using JB = JsonBuilder;
using Json = btc_buy::JsonValue;
static unsigned checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) { std::cerr << "FAIL " << __LINE__ << " " #x "\n"; return 1; } } while (false)

static Json Call(RpcServer& rpc, const std::string& address,
                 const std::string& minimum="1", const std::string& after="",
                 const std::string& sources="") {
    const std::string raw = rpc.Handle(JB::Object({
        {"jsonrpc",JB::String("2.0")}, {"id",JB::Number(uint64_t(1))},
        {"method",JB::String("getcustodyinventory")},
        {"params",JB::Array({JB::String(address),JB::String(minimum),JB::String(after),JB::String(sources),JB::String("")})}}));
    Json result; std::string error;
    if (!btc_buy::StrictJsonParser(raw).Parse(result,error)) throw std::runtime_error(error);
    return result;
}

int main(int argc,char** argv) {
    if (argc!=2) return 2;
    Blockchain chain; Mempool pool; StakingLedger stakes;
    CHECK(chain.AddBlockDirect(CreateGenesisBlock(), true, true, false,
        mining::PowAdmissionContext::Internal()).IsAccepted());
    StorageEngine storage(argv[1], MAINNET_MAGIC);
    RpcServer rpc(chain,pool,storage); rpc.SetStaking(&stakes);
    std::vector<uint8_t> script{0x76,0xa9,0x14};
    script.insert(script.end(),20,0x11);script.push_back(0x88);script.push_back(0xac);
    const std::string address=ScriptToAddress(script);
    CHECK(!address.empty());
    auto empty=Call(rpc,address);
    CHECK(empty.Get("result") && empty.Get("result")->Get("amount_units") && empty.Get("result")->Get("amount_units")->text=="0");
    std::vector<UTXO> coins;
    for (uint32_t i=1;i<=257;++i) {
        UTXO u;u.tx_hash=ZeroHash();
        for (unsigned j=0;j<4;++j) u.tx_hash[j]=uint8_t(i>>(8*j));
        u.output_index=i%3;u.value=i;u.block_height=0;u.script_pubkey=script;u.is_coinbase=false;
        chain.TestInjectUTXO(u);coins.push_back(u);
    }
    auto ws=rpc.ComputeWalletState(address);
    CHECK(ws.selectable.size()==257);
    std::set<std::string> seen;std::string cursor;
    unsigned pages=0;
    do {
        auto reply=Call(rpc,address,"1",cursor);const auto* r=reply.Get("result");
        CHECK(r && r->Get("complete")->boolean);
        CHECK(r->Get("amount_units")->text=="33153");
        CHECK(r->Get("outpoint_count")->text=="257");
        CHECK(r->Get("height")->text==std::to_string(chain.Height()));
        CHECK(r->Get("block_hash")->text==chain.GetBlockHashAtHeight(chain.Height()));
        const auto& page=r->Get("coins")->array;CHECK(page.size()<=64);
        for(const auto& row:page) {
            std::string key=row.Get("txid")->text+":"+row.Get("vout")->text;
            CHECK(key>cursor && seen.insert(key).second);cursor=key;
        }
        ++pages;
        if(r->Get("page_complete")->boolean){CHECK(r->Get("next")->text.empty());break;}
        CHECK(r->Get("next")->text==cursor);
    } while(pages<10);
    CHECK(seen.size()==257 && pages==5);
    const auto key=UTXOKey(coins.back().tx_hash,coins.back().output_index);
    auto filtered=Call(rpc,address,"1","",key);
    CHECK(filtered.Get("result")->Get("coins")->array.size()==1);
    CHECK(filtered.Get("result")->Get("amount_units")->text=="33153");
    auto horizon=Call(rpc,address,"2");
    CHECK(horizon.Get("result")->Get("amount_units")->text=="0");
    CHECK(horizon.Get("result")->Get("outpoint_count")->text=="257");
    for(const auto& bad:{"0","01","-1","1.0","1000001","99999999999"}) {
        CHECK(Call(rpc,address,bad).Get("error"));
    }
    CHECK(Call(rpc,address,"1","",key+","+key).Get("error"));
    CHECK(Call(rpc,address,"1",key+"0x").Get("error"));
    CHECK(Call(rpc,address,"1","",std::string(4864,'a')).Get("error"));
    CHECK(chain.TestEraseUTXO(coins.back().tx_hash,coins.back().output_index));
    CHECK(Call(rpc,address,"1","",key).Get("result")->Get("coins")->array.empty());
    for(uint32_t i=258;i<=10000;++i) {
        UTXO u;u.tx_hash=ZeroHash();for(unsigned j=0;j<4;++j)u.tx_hash[j]=uint8_t(i>>(8*j));
        u.output_index=0;u.value=i;u.block_height=0;u.script_pubkey=script;u.is_coinbase=false;
        chain.TestInjectUTXO(u);
    }
    auto start=std::chrono::steady_clock::now();
    auto large=Call(rpc,address);
    auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count();
    CHECK(large.Get("result")->Get("outpoint_count")->text=="9999");
    CHECK(large.Get("result")->Get("amount_units")->text==std::to_string(50005000-257));
    CHECK(large.Get("result")->Get("coins")->array.size()==64);
    CHECK(elapsed<8000);
    UTXO immature;immature.tx_hash.fill(0xee);immature.output_index=0;
    immature.value=12345;immature.block_height=0;immature.script_pubkey=script;immature.is_coinbase=true;
    chain.TestInjectUTXO(immature);
    auto excluded=Call(rpc,address);
    CHECK(excluded.Get("result")->Get("outpoint_count")->text=="10000");
    CHECK(excluded.Get("result")->Get("amount_units")->text==std::to_string(50005000-257));
    CHECK(rpc.ComputeWalletState(address).immature_coinbase_units==12345);
    UTXO exact=immature;exact.tx_hash.fill(0xef);exact.is_coinbase=false;exact.value=(uint64_t(1)<<53)+7;
    chain.TestInjectUTXO(exact);
    CHECK(Call(rpc,address).Get("result")->Get("amount_units")->text==std::to_string(50005000-257+exact.value));
    UTXO overflow=exact;overflow.tx_hash.fill(0xf0);overflow.value=UINT64_MAX;
    chain.TestInjectUTXO(overflow);
    CHECK(Call(rpc,address).Get("error"));
    std::cout << "PASS " << checks << " checks; 9999-output inventory " << elapsed << "ms\n";
}
