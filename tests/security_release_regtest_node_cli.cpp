// The standalone production daemon has no --regtest option to forward to its
// sibling node helper. This isolated adapter supplies that explicit network
// choice and invokes the actual node's encrypted-token utility unchanged.
#include "compat/process.h"
#include "compat/platform.h"
#include <filesystem>
#include <iostream>
int main(int argc,char** argv) {
    if(argc!=4 || std::string(argv[1])!="--print-rpc-token" || std::string(argv[2])!="--datadir") return 2;
    const char* allowed=std::getenv("VELD_TEST_RUN_ROOT");if(!allowed) return 3;
    const auto root=std::filesystem::canonical(allowed);
    const auto directory=std::filesystem::canonical(argv[3]);
    if(directory.parent_path()!=root || directory.filename().string().rfind("node-daemon-integration",0)!=0) return 4;
    const auto helper=std::filesystem::path(veld::compat::ExecutablePath()).parent_path()/"regtest-node-helper.exe";
    auto result=veld::compat::RunProcess({helper.string(),"--regtest","--nomine","--print-rpc-token","--datadir",directory.string()},true,{},false,65536);
    const int code=result.output_truncated?5:result.exit_code;
    if(code==0)std::cout<<result.output;
    else std::cerr<<"isolated node credential helper refused: "<<code<<"\n";
    veld::compat::SecureZero(result.output.data(),result.output.size());
    return code;
}
