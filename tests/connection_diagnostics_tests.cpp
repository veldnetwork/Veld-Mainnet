#include "isolated_regtest_profile.h"
#include "network/tcp.h"
#include <iostream>
#include <stdexcept>

using namespace veld::net;
using Socket=veld::compat::SocketHandle;
int checks=0;
void check(bool condition) { ++checks;if(!condition)throw std::runtime_error("check "+std::to_string(checks)); }
struct Pair {
    Socket local=veld::compat::kInvalidSocket,remote=veld::compat::kInvalidSocket;
    Pair() {
        Socket listener=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);check(veld::compat::IsValidSocket(listener));
        sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.sin_port=0;
        check(::bind(listener,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))==0);check(::listen(listener,1)==0);
#ifdef _WIN32
        int size=sizeof(addr);
#else
        socklen_t size=sizeof(addr);
#endif
        check(::getsockname(listener,reinterpret_cast<sockaddr*>(&addr),&size)==0);
        remote=::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);check(::connect(remote,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))==0);
        local=::accept(listener,nullptr,nullptr);VELD_CLOSE_SOCKET(listener);check(veld::compat::IsValidSocket(local));
    }
    ~Pair(){if(veld::compat::IsValidSocket(local))VELD_CLOSE_SOCKET(local);if(veld::compat::IsValidSocket(remote))VELD_CLOSE_SOCKET(remote);}
    Socket take(){auto out=local;local=veld::compat::kInvalidSocket;return out;}
};
int main() {
#ifdef _WIN32
    WSADATA data{};check(WSAStartup(MAKEWORD(2,2),&data)==0);
#endif
    uint64_t cursor=0,lost=0;
    using Reason=Connection::CloseReason;
    for(bool blocking:{false,true}) {
        for(bool reset:{false,true}) {
            Pair pair;Connection connection(pair.take(),"127.0.0.1",1,true);
            auto id=connection.DiagnosticId();check(id==connection.DiagnosticId());
            if(reset){linger option{1,0};check(::setsockopt(pair.remote,SOL_SOCKET,SO_LINGER,reinterpret_cast<const char*>(&option),sizeof(option))==0);}
            VELD_CLOSE_SOCKET(pair.remote);pair.remote=veld::compat::kInvalidSocket;
            if(blocking){uint8_t byte{};check(!connection.RecvExact(&byte,1,1000));}
            else {for(int i=0;i<1000&&connection.IsConnected();++i){connection.TryRecvMessage(0x12345678);std::this_thread::sleep_for(std::chrono::milliseconds(1));}check(!connection.IsConnected());}
            connection.Close(Reason::PolicyRejection);connection.Close();
            auto events=connection_diagnostics::Since(cursor,lost);check(lost==0);check(events.size()==2);
            check(events[0].reason==Reason::Connected);
            check(events[1].reason==(reset?Reason::ReceiveError:Reason::RemoteEof));
            check(events[0].connection==events[1].connection);
        }
    }
    std::string prior;
    for(auto reason:{Reason::NodeStop,Reason::PolicyRejection,Reason::HandshakeTimeout}) {
        Pair pair;Connection connection(pair.take(),"127.0.0.1",1);
        check(connection.DiagnosticId()!=prior);prior=connection.DiagnosticId();
        std::thread a([&]{connection.Close(reason);}),b([&]{connection.Close(reason);});a.join();b.join();
        auto events=connection_diagnostics::Since(cursor,lost);check(events.size()==2&&events.back().reason==reason);
    }
    for(bool blocking:{false,true}) {
        Pair pair;Connection connection(pair.take(),"127.0.0.1",1);
        char malformed[24]{};check(::send(pair.remote,malformed,24,0)==24);
        if(blocking)check(!connection.RecvMessage(0x12345678));
        else for(int i=0;i<1000&&connection.IsConnected();++i){connection.TryRecvMessage(0x12345678);std::this_thread::sleep_for(std::chrono::milliseconds(1));}
        auto events=connection_diagnostics::Since(cursor,lost);check(events.size()==2&&events.back().reason==Reason::InvalidFrame);
    }
    for(size_t i=0;i<connection_diagnostics::CAPACITY+10;++i)
        connection_diagnostics::Record(999,Reason::Unspecified,false,0,0);
    std::ostringstream output;connection_diagnostics::WritePending(output,cursor);
    check(output.str().find("\"overwritten\":10")!=std::string::npos);
    check(output.str().find("127.0.0.1")==std::string::npos);
    check(output.str().find("\"reason\":\"unspecified\"")!=std::string::npos);
    connection_diagnostics::WritePending(output,cursor);
    check(connection_diagnostics::Since(cursor,lost).empty());
    std::cout<<"PASS connection diagnostics checks="<<checks<<"\n";
#ifdef _WIN32
    WSACleanup();
#endif
}
