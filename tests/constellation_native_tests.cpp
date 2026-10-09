#define VELD_GUI_TEST_INSTANCE 1
#define VELD_POOL_GUI_QUALIFICATION 1
#define wWinMain veld_gui_unused_entry
#include "../src/veld-node-gui.cpp"
#undef wWinMain
#include <iostream>
namespace {
struct GuiStateQualification {
    static void Check(bool v, const char* label) {
        if (!v)
            throw std::runtime_error(label);
        std::cout << "PASS " << label << '\n';
    }
    static void Run(const char* output) {
        const auto dir = std::filesystem::temp_directory_path() /
                         ("veld-constellation-" + std::to_string(GetCurrentProcessId()));
        Check(!std::filesystem::exists(dir), "disposable profile absent");
        NodeGuiApp app(dir);
        app.page_ = Page::Network;
        HDC dc = CreateCompatibleDC(nullptr);
        BITMAPINFO bi{};
        bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bi.bmiHeader.biWidth = 1200;
        bi.bmiHeader.biHeight = -1000;
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        void* pixels = nullptr;
        HBITMAP bitmap = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &pixels, nullptr, 0);
        auto old = SelectObject(dc, bitmap);
        app.hwnd_ =
            CreateWindowExW(0, L"STATIC", L"Offscreen topology fixture", WS_OVERLAPPEDWINDOW, 0, 0,
                            1200, 1000, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
        Check(app.hwnd_ && bitmap, "real offscreen Windows GDI surface");
        app.CreateFonts();
        for (unsigned dpi : {96, 144})
            for (size_t count : {1, 21, 128, 512}) {
                app.dpi_ = dpi;
                app.DestroyFonts();
                app.CreateFonts();
                LiveState live;
                live.topology_online = true;
                live.local.peers = 3;
                live.topology.reporting_nodes = 3;
                live.topology.eligible_nodes = count;
                for (size_t i = 0; i < count; ++i) {
                    veld::node_gui::TopologyNode n;
                    n.anonymous_id = 18446744073709551000ULL + i;
                    n.role = i % 9 == 0    ? "fleet"
                             : i % 11 == 0 ? "validator"
                             : i % 7 == 0  ? "node"
                                           : "miner";
                    n.tip_state = i % 17 == 0 ? "differs" : i % 13 == 0 ? "stale" : "exact";
                    live.topology.nodes.push_back(n);
                    if (i)
                        live.topology.edges.push_back(
                            {live.topology.nodes[0].anonymous_id, n.anonymous_id, i % 2 == 0});
                }
                RECT card{0, 0, app.S(700), app.S(650)};
                app.DrawReportedNetworkTopology(dc, card, live);
                Check(app.constellation_ids_.size() == count, "all reported nodes drawn");
                for (const auto& p : app.constellation_points_)
                    Check(p.x >= app.network_graph_rect_.left &&
                              p.x <= app.network_graph_rect_.right &&
                              p.y >= app.network_graph_rect_.top &&
                              p.y <= app.network_graph_rect_.bottom,
                          "glyph stays inside plot");
                const auto selected = app.constellation_selected_;
                app.OnClick(app.constellation_next_.left + 2, app.constellation_next_.top + 2);
                if (count > 1)
                    Check(app.constellation_selected_ != selected, "real native Next peer click");
                app.DrawReportedNetworkTopology(dc, card, live);
                app.WndProc(WM_KEYDOWN, VK_RIGHT, 0);
                app.DrawReportedNetworkTopology(dc, card, live);
                const auto p = app.constellation_points_.back();
                app.OnClick(int(p.x), int(p.y));
                Check(app.constellation_selected_ == app.constellation_ids_.back(),
                      "real native graph hit test");
                const auto last = app.constellation_selected_;
                std::reverse(live.topology.nodes.begin(), live.topology.nodes.end());
                app.DrawReportedNetworkTopology(dc, card, live);
                Check(last == app.constellation_selected_, "selection survives report reorder");
                if (dpi == 96 && count == 128) {
                    GdiFlush();
                    BITMAPFILEHEADER file{};
                    file.bfType = 0x4d42;
                    file.bfOffBits = sizeof(file) + sizeof(BITMAPINFOHEADER);
                    file.bfSize = file.bfOffBits + 1200 * 1000 * 4;
                    std::ofstream f(output, std::ios::binary);
                    f.write(reinterpret_cast<char*>(&file), sizeof(file));
                    f.write(reinterpret_cast<char*>(&bi.bmiHeader), sizeof(BITMAPINFOHEADER));
                    f.write(static_cast<char*>(pixels), 1200 * 1000 * 4);
                }
            }
        LiveState empty;
        app.DrawReportedNetworkTopology(dc, {0, 0, 700, 650}, empty);
        Check(app.constellation_ids_.empty(), "offline report clears clickable peers");
        LiveState local;
        local.local_topology_id = 1;
        local.peer_details_online = true;
        veld::node_gui::PeerSummary peer;
        peer.anonymous_id = 2;
        peer.identified = true;
        local.peer_details.push_back(peer);
        app.dpi_ = 96;
        app.DrawUnifiedNetworkTopology(dc, {0, 0, 700, 650}, local);
        Check(app.constellation_ids_.size() == 2,
              "direct-only reports use Constellation without aggregate data");
        local.local_topology_id = 0;
        app.DrawUnifiedNetworkTopology(dc, {0, 0, 700, 650}, local);
        Check(app.constellation_ids_.size() == 1 && app.constellation_ids_[0] == 2,
              "missing local identity is not fabricated");
        app.DestroyFonts();
        DestroyWindow(app.hwnd_);
        app.hwnd_ = nullptr;
        SelectObject(dc, old);
        DeleteObject(bitmap);
        DeleteDC(dc);
        Check(!std::filesystem::exists(dir), "no state, wallets, network or miners created");
    }
};
}
int main(int argc, char** argv) try {
    if (argc != 2)
        return 2;
    GuiStateQualification::Run(argv[1]);
} catch (const std::exception& e) {
    std::cerr << "FAIL " << e.what() << '\n';
    return 1;
}
