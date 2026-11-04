#include "../include/gui/constellation.h"
#include <iostream>
#include <iomanip>
#include <cassert>
int main() {
    std::cout << std::setprecision(17) << "[";
    bool comma = false;
    for (size_t count : {0, 1, 21, 64, 128, 512})
        for (double width : {240, 393, 1024}) {
            const auto p = veld::node_gui::ConstellationLayout(count, width, 390);
            assert(p.size() == count);
            if (count)
                assert(veld::node_gui::ConstellationNearest(p, p[0].x, p[0].y) == 0);
            assert(veld::node_gui::ConstellationNearest(p, -100, -100) == count);
            if (comma)
                std::cout << ",";
            comma = true;
            std::cout << "{\"count\":" << count << ",\"width\":" << width
                      << ",\"height\":390,\"points\":[";
            for (size_t i = 0; i < p.size(); ++i) {
                assert(p[i].x >= 12 && p[i].x <= width - 12 && p[i].y >= 12 && p[i].y <= 378);
                if (i)
                    std::cout << ",";
                std::cout << "[" << p[i].x << "," << p[i].y << "]";
            }
            std::cout << "]}";
        }
    std::cout << "]\n";
}
