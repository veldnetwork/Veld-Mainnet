#include "pool/client_transport.h"
#include <iostream>
#include <vector>

int main() {
    using namespace veld::pool;
    using Clock=std::chrono::steady_clock;
    using namespace std::chrono_literals;
    try {
        RequestBudget budget;
        auto work=[&] {return std::make_unique<RequestBudget::Permit>(budget,true,Clock::now()+1s);};
        auto a=work(),b=work(),c=work();
        // A full work queue still leaves capacity for a found proof.
        auto proof=std::make_unique<RequestBudget::Permit>(budget,false,Clock::now()+100ms);
        bool timeout=false;
        const auto start=Clock::now();
        try {RequestBudget::Permit extra(budget,true,start+40ms);}catch(const Retry&){timeout=true;}
        if(!timeout || Clock::now()-start>1s)throw std::runtime_error("bounded queue deadline");
        a.reset();a=work();a.reset();b.reset();c.reset();proof.reset();
        try {RequestBudget::Permit unwind(budget,true,Clock::now()+1s);throw 1;}catch(int){}
        std::atomic<unsigned> active{0},working{0},peak{0},peak_work{0},done{0};
        std::atomic<bool> failed{false};std::vector<std::thread> threads;
        auto maximum=[](auto& value,unsigned count){auto old=value.load();while(old<count&&!value.compare_exchange_weak(old,count)){};};
        for(unsigned n=0;n<32;++n)threads.emplace_back([&,n] {
            try {for(unsigned round=0;round<8;++round) {
                const bool iswork=n%4!=0;
                RequestBudget::Permit permit(budget,iswork,Clock::now()+5s);
                maximum(peak,++active);if(iswork)maximum(peak_work,++working);
                std::this_thread::sleep_for(2ms);
                if(iswork)--working;--active;++done;
            }}catch(...){failed=true;}
        });
        for(auto& t:threads)t.join();
        if(failed || done!=256 || peak>4 || peak_work>3 || active || working)
            throw std::runtime_error("request budget leaked or exceeded");
        std::cout<<"PASS reserved proof capacity, bounded deadline, exception recovery, 256 concurrent admissions\n";
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
