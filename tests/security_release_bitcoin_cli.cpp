// Local test configuration adapter; forwards each observation to real Core.
#include "compat/process.h"
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
int main(int argc,char** argv) {
    if(argc!=4 || std::string(argv[1])!="getblockheader" || std::string(argv[3])!="true") return 2;
    const std::string hash=argv[2];
    if(hash.size()!=64 || hash.find_first_not_of("0123456789abcdef")!=std::string::npos) return 3;
    const char* executable=std::getenv("VELD_TEST_BITCOIN_CLI");
    const char* directory=std::getenv("VELD_TEST_BITCOIN_DATADIR");
    const char* port=std::getenv("VELD_TEST_BITCOIN_RPC_PORT");
    const char* observations=std::getenv("VELD_TEST_BITCOIN_OBSERVATIONS");
    if(!executable || !directory || !port || !observations) return 4;
    const auto result=veld::compat::RunProcess({executable,"-regtest",std::string("-datadir=")+directory,
        std::string("-rpcport=")+port,"-rpcconnect=127.0.0.1","getblockheader",hash,"true"},true,{},false,256u*1024u);
    if(result.output_truncated) return 5;
    // One append per adapter invocation; only the public hash and return code.
    std::ofstream log(observations,std::ios::app);log<<hash<<" "<<result.exit_code<<"\n";
    std::cout<<result.output;
    return result.exit_code;
}
