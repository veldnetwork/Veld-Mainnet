#include "network/ui_desktop.h"
#include <fstream>
#include <string>

int main(int argc, char** argv) {
    if (argc != 2)
        return 1;
    std::ofstream(std::string(argv[1]) + "/wallet.html") << veld::WithHelpDialogs(DESKTOP_HTML);
    std::ofstream(std::string(argv[1]) + "/nested.html") << veld::WithHelpDialogs(
        "<!doctype html><html><head><meta name=viewport content=\"width=device-width\"></head>"
        "<body><h2>Syncing and trust</h2><section data-veld-help><button type=button>Details</button>"
        "<p>Keep the verified chain.</p><section data-veld-help><button type=button>Sync options</button>"
        "<p id=live-value>Retained progress</p></section></section></body></html>");
}
