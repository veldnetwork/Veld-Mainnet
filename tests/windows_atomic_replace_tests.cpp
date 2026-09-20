// Native Windows filesystem regression; no network or wallet credentials.
#include "wallet/secure_channel_file.h"
#include <chrono>
#include <iostream>
#include <thread>
#include <stdexcept>

int main() {
#ifndef _WIN32
    std::cerr<<"Native Windows required\n";return 2;
#else
    using namespace veld::channel::secure_file;
    const auto root=std::filesystem::temp_directory_path()/
        (L"veld-atomic-replace-test-"+std::to_wstring(GetCurrentProcessId()));
    unsigned checks=0;
    auto check=[&](bool value,const char* message){++checks;if(!value)throw std::runtime_error(message);};
    try {
        check(!std::filesystem::exists(root),"disposable directory already exists");
        std::string error;check(EnsurePrivateDirectory(root.string(),&error),"private directory");
        const auto file=root/L"status.json";
        check(AtomicWriteText(file.string(),"old",&error,true),"initial write");
        auto locked=[&](){return CreateFileW(file.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);};
        HANDLE handle=locked();check(handle!=INVALID_HANDLE_VALUE,"reader handle");
        std::thread reader([handle]{Sleep(250);CloseHandle(handle);});
        const bool replaced=AtomicWriteText(file.string(),"new",&error,true);reader.join();
        check(replaced,"transient sharing lock must recover");
        std::vector<uint8_t> bytes;check(Read(file.string(),bytes,&error,32,true)==ReadResult::Ok&&std::string(bytes.begin(),bytes.end())=="new","exact bytes after retry");
        handle=locked();check(handle!=INVALID_HANDLE_VALUE,"persistent reader handle");
        const auto start=std::chrono::steady_clock::now();
        const bool failed=AtomicWriteText(file.string(),"must not replace",&error,true);
        CloseHandle(handle);
        check(!failed,"persistent lock must fail closed");
        check(std::chrono::steady_clock::now()-start<std::chrono::seconds(4),"retry bound");
        check(Read(file.string(),bytes,&error,32,true)==ReadResult::Ok&&std::string(bytes.begin(),bytes.end())=="new","failed replacement preserves previous bytes");
        size_t files=0;for(const auto& entry:std::filesystem::directory_iterator(root)){++files;check(entry.path()==file,"temporary file leaked");}
        check(files==1,"only status remains");
        std::filesystem::remove(file);std::filesystem::remove(root);
        std::cout<<"PASS "<<checks<<" native Windows atomic-publication checks\n";
    }catch(const std::exception& error){std::cerr<<"FAIL "<<checks<<" "<<error.what()<<'\n';return 1;}
    return 0;
#endif
}
