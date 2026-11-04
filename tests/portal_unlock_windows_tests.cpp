#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "../include/compat/platform.h"
#include "../include/gui/portal_unlock.h"
#include <cassert>
#include <fstream>
#include <iostream>

int main(int argc, char** argv) {
    assert(argc == 3);
    const auto root = std::filesystem::path(argv[2]);
    std::filesystem::create_directories(root);
    const auto path = root / "unlock-private.dat";
    const std::string identity(64, 'a');
    veld::node_gui::PortalUnlockKey key;
    assert(key.Ensure(path));
    const auto public_key = key.PublicJson(identity);
    assert(public_key != "null");
    {
        veld::node_gui::PortalUnlockKey loaded;
        assert(loaded.Ensure(path));
        assert(loaded.PublicJson(identity) == public_key);
    }
    if (std::string(argv[1]) == "init") {
        std::cout << public_key << '\n';
        return 0;
    }
    assert(std::string(argv[1]) == "verify");
    std::ifstream fixture(root / "ciphertext.txt");
    assert(fixture);
    veld::node_gui::PortalUnlockPayload payload;
    for (auto* field : {&payload.ciphertext, &payload.identity, &payload.iv, &payload.key_id, &payload.wrapped_key}) {
        std::getline(fixture, *field);
        assert(!field->empty());
    }
    std::string nonce;
    std::getline(fixture, nonce);
    std::wstring passphrase;
    assert(key.Decrypt(payload, 17, nonce, identity, passphrase));
    assert(passphrase == L"Portal test \u65e5\u672c\u8a9e \u00e9 passphrase");
    SecureZeroMemory(passphrase.data(), passphrase.size() * sizeof(wchar_t));
    passphrase.clear();
    assert(!key.Decrypt(payload, 18, nonce, identity, passphrase));
    assert(passphrase.empty());
    assert(!key.Decrypt(payload, 17, std::string(22, 'A'), identity, passphrase));
    assert(!key.Decrypt(payload, 17, nonce, std::string(64, 'b'), passphrase));
    auto changed = payload;
    changed.key_id.assign(64, 'b');
    assert(!key.Decrypt(changed, 17, nonce, identity, passphrase));
    changed = payload;
    changed.ciphertext[3] = changed.ciphertext[3] == 'A' ? 'B' : 'A';
    assert(!key.Decrypt(changed, 17, nonce, identity, passphrase));
    changed = payload;
    changed.iv.push_back('=');
    assert(!changed.Valid());
    changed = payload;
    changed.wrapped_key[3] = changed.wrapped_key[3] == 'A' ? 'B' : 'A';
    assert(!key.Decrypt(changed, 17, nonce, identity, passphrase));
    assert(passphrase.empty());
    std::cout << "PASS: browser-compatible remote unlock, Unicode, durable private key, tamper and context rejection\n";
}
