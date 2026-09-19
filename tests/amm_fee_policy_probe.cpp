// Offline component probe. No RPC, keys, state directories, or network access.
#include "core/blockchain.h"
#include "core/amm_pool.h"
#include <iostream>
#include <stdexcept>
using namespace veld;
int main() {
    char mode;
    while (std::cin >> mode) {
        int64_t v,b,av,ab,amount; unsigned direction; uint64_t height;
        if (!(std::cin >> v >> b >> av >> ab >> amount >> direction >> height)) return 2;
        AmmLedger ledger;
        ledger.SeedPool("VELD:btcVELD",100,1000,1000,1000,1000,Hash256{},0);
        auto snapshot=ledger.SnapshotState();
        // Corrupt-state vectors are injected only into this disposable fixture.
        snapshot.pools.at("VELD:btcVELD").reserve_veld=v;
        snapshot.pools.at("VELD:btcVELD").reserve_btcveld=b;
        snapshot.pools.at("VELD:btcVELD").anchor_veld=av;
        snapshot.pools.at("VELD:btcVELD").anchor_btcveld=ab;
        ledger.RestoreState(snapshot);
        const auto before=ledger.Digest();
        const auto q=ledger.QuoteSwapAtHeight("VELD:btcVELD",direction!=0,amount,height);
        if (mode=='S') {
            const auto out=ledger.SwapAtHeight("VELD:btcVELD",direction!=0,amount,height);
            const auto after=ledger.Digest();
            if (out!=q.amount_out || (q.reject && before!=after)) return 3;
            // Reconstruct into a fresh ledger, then roll back and replay the
            // same inclusion height. This is module state recovery, not a
            // claim of whole-node disk restart or a real chain reorganization.
            AmmLedger restored; restored.RestoreState(ledger.SnapshotState());
            if (restored.Digest()!=after) return 4;
            restored.RestoreState(snapshot);
            if (restored.Digest()!=before) return 5;
            if (restored.SwapAtHeight("VELD:btcVELD",direction!=0,amount,height)!=out ||
                restored.Digest()!=after) return 6;
        } else if (mode!='Q') return 2;
        if (mode=='Q' && before!=ledger.Digest()) return 7;
        std::cout << q.reject << ' ' << unsigned(q.band) << ' ' << q.fee_bps << ' '
            << q.amount_out << ' ' << q.gross_out << ' ' << q.fee_out << ' '
            << q.post_reserve_veld << ' ' << q.post_reserve_btcveld << ' '
            << q.rebalances_anchor << ' ' << AmmLedger::SwapRejectCodeName(q.reject_code) << '\n';
    }
}
