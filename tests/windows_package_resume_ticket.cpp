#include "gui/update_resume.h"
#include <iostream>

int wmain(int argc, wchar_t** argv) {
    if (argc != 8)
        return 2;
    veld::node_gui::UpdateResume ticket;
    ticket.created = static_cast<uint64_t>(std::time(nullptr));
    ticket.data_directory = argv[3];
    ticket.identity = argv[4];
    ticket.previous_manifest = argv[5];
    ticket.target_manifest = argv[6];
    const bool address_only = std::wstring(argv[7]) == L"address-only";
    if (!address_only)
        return 2;
    if (!veld::node_gui::SaveUpdateResume(argv[1], argv[2], ticket, ticket.created, true))
        return 1;
    std::cout << "PASS protected disposable address-only resume ticket\n";
}
