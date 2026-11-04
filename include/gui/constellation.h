#pragma once
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <vector>

namespace veld::node_gui {
struct ConstellationPoint { double x, y; };
// Six fixed visual regions, not geographic or ownership claims. Input order is
// ascending lossless public topology ID on both native and browser surfaces.
inline std::vector<ConstellationPoint> ConstellationLayout(
    size_t count, double width, double height) {
    count = std::min<size_t>(count, 512);
    width = std::max(240.0, width); height = std::max(240.0, height);
    constexpr double slots[6][2] = {
        {.19,.22},{.60,.17},{.81,.53},{.46,.51},{.35,.82},{.13,.58}};
    const double aw=width-76, ah=height-60;
    std::vector<ConstellationPoint> out; out.reserve(count);
    for(size_t i=0;i<count;++i) {
        const size_t group=i%6, local=i/6, total=(count-group+5)/6;
        const double angle=local*2.399963+.5*group;
        const double r=std::sqrt((local+.55)/(total+.5));
        out.push_back({38+slots[group][0]*aw+std::cos(angle)*r*aw*.145,
                      30+slots[group][1]*ah+std::sin(angle)*r*ah*.19});
    }
    return out;
}
inline size_t ConstellationNearest(const std::vector<ConstellationPoint>& points,
                                  double x,double y,double limit=32) {
    size_t best=points.size();double distance=limit*limit;
    for(size_t i=0;i<points.size();++i) {
        const double d=std::pow(x-points[i].x,2)+std::pow(y-points[i].y,2);
        if(d<distance){distance=d;best=i;}
    }
    return best;
}
} // namespace veld::node_gui
