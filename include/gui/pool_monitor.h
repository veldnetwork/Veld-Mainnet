#pragma once
#include "../pool/client_transport.h"
#include <cmath>
#include <sstream>

namespace veld::node_gui {
// Sanitized, advisory telemetry only. Never contains payout addresses, account
// tokens, endpoints, local paths or transaction/signing authority.
class PoolMonitor {
    uint64_t prior_hashes_=0;
    double prior_time_=0,rate_=0;
    bool sampled_=false;
public:
    std::string Report(bool running,uint64_t configured,const pool::Json* status,
                       uint64_t now,double monotonic) {
        uint64_t active=0,hashes=0,accepted=0,verified=0,retries=0,updated=0;
        bool current=false;std::string state=running?"unavailable":"stopped";
        try {
            pool::Require(configured>=1&&configured<=64,"pool worker count");
            if(status) {
                auto number=[&](const char* field,uint64_t max=UINT64_MAX){return pool::Number(pool::Text(pool::Field(*status,field)),max);};
                updated=number("updated_at");
                current=updated<=now && now-updated<=15;
                if(current) {
                    active=number("active_workers",configured);hashes=number("hashes");
                    accepted=number("accepted");verified=number("verified_shares");retries=number("retry_count");
                    if(running)state=status->Get("failure_code")?"error":active?"hashing":
                        pool::Text(pool::Field(*status,"status"))=="Mining"?"waiting":"retrying";
                }
            }
        } catch(const std::exception&) {current=false;state=running?"unavailable":"stopped";}
        if(current&&running) {
            if(sampled_&&hashes>=prior_hashes_&&monotonic>prior_time_) {
                const double elapsed=monotonic-prior_time_;
                const double instant=double(hashes-prior_hashes_)/elapsed;
                const double alpha=std::min(1.0,elapsed/10.0);
                rate_=rate_*(1-alpha)+instant*alpha;
            } else rate_=0;
            prior_hashes_=hashes;prior_time_=monotonic;sampled_=true;
        } else {sampled_=false;rate_=0;active=0;}
        if(!std::isfinite(rate_)||rate_<0)rate_=0;
        std::ostringstream out;
        out<<"{\"schema\":1,\"running\":"<<(running?"true":"false")
           <<",\"current\":"<<(current?"true":"false")<<",\"state\":\""<<state
           <<"\",\"configured_workers\":"<<configured<<",\"active_workers\":"<<active
           <<",\"hashrate\":"<<rate_<<",\"total_hashes\":"<<hashes
           <<",\"accepted\":"<<accepted<<",\"verified_shares\":"<<verified
           <<",\"retry_count\":"<<retries<<",\"updated_at\":"<<updated<<'}';
        return out.str();
    }
};
}
