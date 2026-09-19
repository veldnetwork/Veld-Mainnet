#pragma once

#include "../compat/platform.h"
#include "../network/strict_json.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <climits>
#ifndef _WIN32
#include <fcntl.h>
#include <netdb.h>
#else
#include <wincrypt.h>
#endif
#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <map>
#include <memory>
#include <stdexcept>
#include <thread>

namespace veld::pool {
using Json = btc_buy::JsonValue;
struct Retry : std::runtime_error { using std::runtime_error::runtime_error; };
inline void Require(bool value,const char* message) {
    if (!value) throw std::runtime_error(message);
}
inline const Json& Field(const Json& object,const char* name) {
    const auto value=object.Get(name); Require(value!=nullptr,"missing pool field"); return *value;
}
inline std::string Text(const Json& value) {
    Require(value.kind==Json::Kind::String,"pool string required"); return value.text;
}
inline uint64_t Number(const std::string& text,uint64_t maximum=UINT64_MAX) {
    uint64_t value=0;const auto result=std::from_chars(text.data(),text.data()+text.size(),value);
    Require(result.ec==std::errc{} && result.ptr==text.data()+text.size() &&
            text==std::to_string(value) && value<=maximum,"pool integer encoding");return value;
}
inline Json Parse(const std::string& text) {
    Json result;std::string error;
    Require(btc_buy::StrictJsonParser(text,16384,true).Parse(result,error) &&
            result.kind==Json::Kind::Object,"pool JSON response");return result;
}
inline std::string Hex(const Json& value,size_t length) {
    const auto text=Text(value);
    Require(text.size()==length && text.find_first_not_of("0123456789abcdef")==std::string::npos,
            "pool hex encoding");return text;
}

struct Endpoint {
    std::string host,port,authority;
    explicit Endpoint(const std::string& url) {
        Require(url.rfind("https://",0)==0 && url.size()<=512,"HTTPS pool endpoint required");
        authority=url.substr(8);
        if (!authority.empty() && authority.back()=='/') authority.pop_back();
        Require(!authority.empty() && authority.find_first_of("/@?#%\\ \t\r\n") == std::string::npos,
                "pool endpoint authority");
        if (authority[0]=='[') {
            const auto close=authority.find(']');Require(close!=std::string::npos,"IPv6 pool endpoint");
            host=authority.substr(1,close-1);
            Require(close+1==authority.size() || authority[close+1]==':',"pool endpoint port");
            port=close+1==authority.size()?"443":authority.substr(close+2);
            Require(host.find_first_not_of("0123456789abcdefABCDEF:")==std::string::npos,"IPv6 pool host");
        } else {
            const auto colon=authority.find(':');
            host=authority.substr(0,colon);port=colon==std::string::npos?"443":authority.substr(colon+1);
            Require(host.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")==std::string::npos,
                    "ASCII pool host required");
        }
        Require(!host.empty() && Number(port,65535)>0,"pool endpoint port");
    }
};

struct Connection {
    compat::SocketHandle socket=compat::kInvalidSocket;
    int family=AF_UNSPEC;
    Connection(const Endpoint& endpoint,std::chrono::steady_clock::time_point deadline,int preferred_family) {
        addrinfo hints{};hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
        addrinfo* addresses=nullptr;
        if(getaddrinfo(endpoint.host.c_str(),endpoint.port.c_str(),&hints,&addresses)!=0)
            throw Retry("pool DNS lookup failed");
        std::unique_ptr<addrinfo,decltype(&freeaddrinfo)> list(addresses,freeaddrinfo);
        std::vector<const addrinfo*> ordered;
        for(auto candidate=addresses;candidate;candidate=candidate->ai_next)ordered.push_back(candidate);
        if(preferred_family!=AF_UNSPEC)
            std::stable_sort(ordered.begin(),ordered.end(),[&](const auto a,const auto b) {
                return (a->ai_family==preferred_family)>(b->ai_family==preferred_family);
            });
        for(const auto candidate:ordered) {
            if(std::chrono::steady_clock::now()>=deadline)break;
            socket=::socket(candidate->ai_family,candidate->ai_socktype,candidate->ai_protocol);
            if(!compat::IsValidSocket(socket))continue;
#ifdef _WIN32
            u_long nonblocking=1;
            const bool configured=ioctlsocket(socket,FIONBIO,&nonblocking)==0;
#else
            const bool configured=socket<FD_SETSIZE && fcntl(socket,F_SETFL,O_NONBLOCK)==0;
#endif
            if(!configured){VELD_CLOSE_SOCKET(socket);socket=compat::kInvalidSocket;continue;}
            bool connected=::connect(socket,candidate->ai_addr,int(candidate->ai_addrlen))==0;
            const auto address_deadline=std::min(deadline,std::chrono::steady_clock::now()+std::chrono::seconds(3));
            while(!connected && std::chrono::steady_clock::now()<address_deadline) {
                fd_set writable,failed;FD_ZERO(&writable);FD_ZERO(&failed);
                FD_SET(socket,&writable);FD_SET(socket,&failed);timeval wait{0,20000};
#ifdef _WIN32
                const auto ready=select(0,nullptr,&writable,&failed,&wait);
#else
                const auto ready=select(socket+1,nullptr,&writable,&failed,&wait);
#endif
                if(ready<0)break;
                if(ready>0) {
                    int error=0;
#ifdef _WIN32
                    int size=sizeof(error);
#else
                    socklen_t size=sizeof(error);
#endif
                    connected=getsockopt(socket,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&error),&size)==0 && error==0;
                    break;
                }
            }
            if(connected) {
                // OpenSSL's socket BIO accepts an int even on Windows. Refuse
                // an unrepresentable handle instead of silently truncating it.
                if(static_cast<uint64_t>(socket)<=INT_MAX){family=candidate->ai_family;return;}
            }
            VELD_CLOSE_SOCKET(socket);socket=compat::kInvalidSocket;
        }
        throw Retry("pool connection unavailable");
    }
    ~Connection(){if(compat::IsValidSocket(socket))VELD_CLOSE_SOCKET(socket);}
    Connection(const Connection&)=delete;
    Connection& operator=(const Connection&)=delete;
};

class TlsClient {
    Endpoint endpoint_;
    std::unique_ptr<SSL_CTX,decltype(&SSL_CTX_free)> context_{nullptr,SSL_CTX_free};
    mutable std::atomic<int> preferred_family_{AF_UNSPEC};
public:
    TlsClient(const std::string& endpoint,const std::string& ca):endpoint_(endpoint) {
        context_.reset(SSL_CTX_new(TLS_client_method()));Require(bool(context_),"TLS initialization failed");
        Require(SSL_CTX_set_min_proto_version(context_.get(),TLS1_2_VERSION)==1,"TLS minimum version failed");
        SSL_CTX_set_verify(context_.get(),SSL_VERIFY_PEER,nullptr);
        // Explicit CA file, or the installed trusted roots. Never disable
        // verification or import a pool certificate into the operating system.
        if(!ca.empty()) {
            Require(SSL_CTX_load_verify_locations(context_.get(),ca.c_str(),nullptr)==1,"pool CA unavailable");
        } else {
#ifdef _WIN32
            HCERTSTORE roots=CertOpenStore(CERT_STORE_PROV_SYSTEM_W,0,0,
                CERT_SYSTEM_STORE_CURRENT_USER|CERT_STORE_READONLY_FLAG,L"ROOT");
            Require(roots!=nullptr,"Windows trust store unavailable");
            PCCERT_CONTEXT certificate=nullptr;unsigned count=0,seen=0;
            while((certificate=CertEnumCertificatesInStore(roots,certificate))!=nullptr) {
                if(++seen>4096){CertFreeCertificateContext(certificate);break;}
                if(certificate->cbCertEncoded>512*1024)continue;
                const auto* bytes=certificate->pbCertEncoded;
                X509* parsed=d2i_X509(nullptr,&bytes,certificate->cbCertEncoded);
                if(parsed) {
                    count+=X509_STORE_add_cert(SSL_CTX_get_cert_store(context_.get()),parsed)==1;
                    X509_free(parsed);ERR_clear_error();
                }
            }
            CertCloseStore(roots,0);Require(count>0,"Windows trust store has no usable roots");
#else
            Require(SSL_CTX_set_default_verify_paths(context_.get())==1,"pool CA unavailable");
#endif
        }
    }
    Json Call(const std::string& action,const std::string& payload) const {
        Require(action=="register" || action=="work" || action=="submit" || action=="account", "pool action");
        Require(payload.size()<=16384,"pool request bound");
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(20);
        Connection connection(endpoint_,deadline,preferred_family_.load());
        std::unique_ptr<SSL,decltype(&SSL_free)> session(SSL_new(context_.get()),SSL_free);
        auto ssl=session.get();Require(ssl!=nullptr,"TLS session unavailable");
        Require(SSL_set_fd(ssl,static_cast<int>(connection.socket))==1,"TLS socket setup failed");
        std::array<unsigned char,16> address{};
        const bool ip=inet_pton(AF_INET,endpoint_.host.c_str(),address.data())==1 ||
                      inet_pton(AF_INET6,endpoint_.host.c_str(),address.data())==1;
        auto parameters=SSL_get0_param(ssl);
        X509_VERIFY_PARAM_set_hostflags(parameters,X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        Require(ip?X509_VERIFY_PARAM_set1_ip_asc(parameters,endpoint_.host.c_str())==1:
                SSL_set1_host(ssl,endpoint_.host.c_str())==1,"TLS peer identity setup failed");
        if (!ip) Require(SSL_set_tlsext_host_name(ssl,endpoint_.host.c_str())==1,"TLS server name failed");
        auto again=[&](int result) {
            const auto error=SSL_get_error(ssl,result);
            if (std::chrono::steady_clock::now()>=deadline ||
                (error!=SSL_ERROR_WANT_READ && error!=SSL_ERROR_WANT_WRITE))
                throw Retry("pool transport unavailable");
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        };
        for(;;) {
            ERR_clear_error();const auto result=SSL_connect(ssl);if(result==1)break;
            Require(SSL_get_verify_result(ssl)==X509_V_OK,"pool certificate verification failed");
            again(result);
        }
        Require(SSL_get_verify_result(ssl)==X509_V_OK,"pool certificate verification failed");
        std::unique_ptr<X509,decltype(&X509_free)> certificate(SSL_get1_peer_certificate(ssl),X509_free);
        Require(bool(certificate),"pool certificate missing");
        // Avoid paying a failed IPv6 (or IPv4) connection timeout on every
        // request. DNS and certificate validation still run for each session;
        // alternate addresses remain available if the preferred family fails.
        preferred_family_.store(connection.family);
        // Credentials are sent only after the authenticated TLS handshake.
        const std::string request="POST /v1/"+action+" HTTP/1.1\r\nHost: "+endpoint_.authority+
            "\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "+
            std::to_string(payload.size())+"\r\n\r\n"+payload;
        for (size_t offset=0;offset<request.size();) {
            ERR_clear_error();const auto written=SSL_write(ssl,request.data()+offset,int(request.size()-offset));
            if (written>0) offset+=size_t(written);else again(written);
        }
        std::string response;size_t body_at=std::string::npos, length=0;int status=0;
        std::array<char,2048> bytes{};
        for (;;) {
            ERR_clear_error();const int count=SSL_read(ssl,bytes.data(),int(bytes.size()));
            if (count<=0) { again(count);continue; }
            response.append(bytes.data(),size_t(count));Require(response.size()<=24576,"pool response bound");
            if (body_at==std::string::npos) {
                const auto end=response.find("\r\n\r\n");
                Require(end!=std::string::npos || response.size()<=8192,"pool HTTP header bound");
                if (end==std::string::npos) continue;
                Require(end<=8192 && response.rfind("HTTP/1.1 ",0)==0 && response.size()>12,"pool HTTP status");
                status=int(Number(response.substr(9,3),599));Require(response[12]==' ',"pool HTTP status framing");
                const auto first=response.find("\r\n");Require(first!=std::string::npos,"pool HTTP status line");
                std::map<std::string,std::string> headers;
                for (size_t pos=first+2;pos<end;) {
                    const auto next=response.find("\r\n",pos),colon=response.find(':',pos);
                    Require(next!=std::string::npos && colon<next && colon>pos,"pool HTTP header framing");
                    std::string name=response.substr(pos,colon-pos),value=response.substr(colon+1,next-colon-1);
                    Require(name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-")==std::string::npos,"pool HTTP header name");
                    std::transform(name.begin(),name.end(),name.begin(),[](unsigned char c){return char(std::tolower(c));});
                    while (!value.empty() && value.front()==' ') value.erase(0,1);
                    Require(headers.emplace(name,value).second,"duplicate pool HTTP header");pos=next+2;
                }
                Require(!headers.contains("transfer-encoding") && headers.contains("content-length") &&
                        headers["content-type"]=="application/json","pool HTTP response schema");
                length=size_t(Number(headers["content-length"],16384));Require(length>0,"empty pool response");
                body_at=end+4;
            }
            if (body_at!=std::string::npos && response.size()>=body_at+length) break;
        }
        Require(response.size()==body_at+length,"trailing pool response bytes");
        const auto result=Parse(response.substr(body_at));
        const auto& ok=Field(result,"ok");Require(ok.kind==Json::Kind::Bool,"pool response status");
        if (status!=200 || !ok.boolean) {
            const auto retry=result.Get("retryable");
            if (retry && retry->kind==Json::Kind::Bool && retry->boolean) throw Retry("pool busy; retrying");
            throw std::runtime_error("pool refused request");
        }
        const auto& value=Field(result,"result");Require(value.kind==Json::Kind::Object,"pool result schema");return value;
    }
};
} // namespace veld::pool
