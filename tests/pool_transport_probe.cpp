// Loopback TLS/HTTP fault-test driver. It carries no real account credentials.
#include "pool/client_transport.h"
#include <iostream>
int main(int argc, char** argv) {
    if (argc != 3)
        return 2;
    veld::compat::InitNetwork();
    try {
        veld::pool::TlsClient client(argv[1], argv[2]);
        client.Call("register", "{\"address\":\"transport-test-not-a-wallet\"}");
        std::cout << "PASS authenticated bounded response\n";
        return 0;
    } catch (const veld::pool::Retry& retry) {
        std::cout << "RETRY " << retry.what() << '\n';
        return 2;
    } catch (const std::exception&) {
        std::cout << "REFUSED\n";
        return 1;
    }
}
