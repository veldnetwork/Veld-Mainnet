    void DrawReportedNetworkTopology(HDC dc, RECT card, const LiveState& live) {
        const COLORREF bg=RGB(10,16,12),panel=RGB(16,24,18),lineColor=RGB(42,54,43),text=RGB(237,243,233),muted=RGB(152,166,151);
        FillRound(dc,card,bg,lineColor,18);
        RECT brand{card.left+S(20),card.top+S(12),card.left+S(150),card.top+S(40)};
        DrawTextAt(dc,L"◇ V E L D",brand,font_small_,text);
        RECT chrome{card.left+S(150),brand.top,card.right-S(20),brand.bottom};
        DrawTextAt(dc,L"NETWORK / MAP",chrome,font_small_,muted,DT_RIGHT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
        HPEN divider=CreatePen(PS_SOLID,S(1),lineColor);auto oldDivider=SelectObject(dc,divider);
        MoveToEx(dc,card.left,card.top+S(50),nullptr);LineTo(dc,card.right,card.top+S(50));SelectObject(dc,oldDivider);DeleteObject(divider);
        RECT title{card.left+S(20),card.top+S(65),card.right-S(100),card.top+S(94)};
        DrawTextAt(dc,L"Peer topology",title,font_heading_,text);
        RECT coverage{card.left+S(20),card.top+S(96),card.right-S(100),card.top+S(116)};
        DrawTextAt(dc,FormatUnsigned(live.local.peers)+L" direct · selected peer connections",coverage,font_small_,muted);
        RECT total{card.right-S(105),card.top+S(62),card.right-S(20),card.top+S(94)};
        DrawTextAt(dc,live.topology_online?FormatUnsigned(live.topology.nodes.size()):L"—",total,font_heading_,text,DT_RIGHT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
        total.top=card.top+S(96);total.bottom=card.top+S(116);
        DrawTextAt(dc,L"reported peers",total,font_small_,muted,DT_RIGHT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
        RECT plot{card.left,card.top+S(128),card.right,card.bottom-S(164)};
        network_graph_rect_=plot;
        constellation_ids_.clear();constellation_points_.clear();
        if(!live.topology_online || live.topology.nodes.empty()) {
            DrawTextAt(dc,L"Waiting for a fresh topology report.",plot,font_body_,C_MUTED,
                       DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);return;
        }
        std::vector<size_t> order(live.topology.nodes.size());
        for(size_t i=0;i<order.size();++i)order[i]=i;
        order.erase(std::remove_if(order.begin(),order.end(),[&](size_t i){return live.topology.nodes[i].anonymous_id==0;}),order.end());
        std::sort(order.begin(),order.end(),[&](size_t a,size_t b){
            return live.topology.nodes[a].anonymous_id<live.topology.nodes[b].anonymous_id;});
        order.erase(std::unique(order.begin(),order.end(),[&](size_t a,size_t b){
            return live.topology.nodes[a].anonymous_id==live.topology.nodes[b].anonymous_id;}),order.end());
        if(order.size()>512)order.resize(512);
        if(order.empty())return;
        const double scale=dpi_/96.0;
        auto points=veld::node_gui::ConstellationLayout(order.size(),
            (plot.right-plot.left)/scale,(plot.bottom-plot.top)/scale);
        std::unordered_map<uint64_t,size_t> index;
        size_t selected=order.size();
        for(size_t i=0;i<order.size();++i){
            const auto id=live.topology.nodes[order[i]].anonymous_id;
            constellation_ids_.push_back(id);index.emplace(id,i);
            constellation_points_.push_back({plot.left+points[i].x*scale,plot.top+points[i].y*scale});
            if(id==constellation_selected_)selected=i;
        }
        if(selected==order.size()){
            selected=0;
            for(size_t i=0;i<order.size();++i)if(live.topology.nodes[order[i]].role=="miner"){selected=i;break;}
            constellation_selected_=constellation_ids_[selected];
        }
        auto color=[](const std::string& role)->COLORREF {
            if(role=="miner")return RGB(161,223,96);
            if(role=="fleet")return RGB(127,187,219);
            if(role=="validator")return RGB(189,154,217);
            return RGB(112,180,154);
        };
        std::unordered_set<uint64_t> neighbors;
        std::set<std::pair<uint64_t,uint64_t>> seen;
        std::vector<const veld::node_gui::TopologyEdge*> edges;
        for(const auto& edge:live.topology.edges){
            if(edges.size()>=8192)break;
            if(edge.first==edge.second||!index.count(edge.first)||!index.count(edge.second))continue;
            if(!seen.emplace(std::min(edge.first,edge.second),std::max(edge.first,edge.second)).second)continue;
            edges.push_back(&edge);
            if(edge.first==constellation_selected_)neighbors.insert(edge.second);
            if(edge.second==constellation_selected_)neighbors.insert(edge.first);
        }
        for(int pass=0;pass<2;++pass)for(size_t e=0;e<edges.size();++e){
            const auto& edge=*edges[e];const bool active=edge.first==constellation_selected_||edge.second==constellation_selected_;
            if(pass==0&&(order.size()>=200||e%3!=0))continue;
            if(pass==1&&!active)continue;
            const auto a=constellation_points_[index.at(edge.first)],b=constellation_points_[index.at(edge.second)];
            HPEN pen=CreatePen(!pass||edge.confirmed?PS_SOLID:PS_DOT,S(1),pass?MixColor(RGB(161,223,96),bg,30):MixColor(muted,bg,85));
            auto old=SelectObject(dc,pen);MoveToEx(dc,int(a.x),int(a.y),nullptr);LineTo(dc,int(b.x),int(b.y));SelectObject(dc,old);DeleteObject(pen);
        }
        for(size_t i=0;i<order.size();++i){
            const auto& node=live.topology.nodes[order[i]];const auto p=constellation_points_[i];
            const bool chosen=i==selected,linked=neighbors.count(node.anonymous_id)!=0;
            COLORREF ink=node.tip_state=="differs"?RGB(239,195,103):color(node.role);
            if(node.tip_state=="stale"||node.tip_state=="unavailable")ink=MixColor(ink,bg,70);
            else if(!chosen&&!linked)ink=MixColor(ink,bg,52);
            const int r=std::max(1,int((chosen?7:linked?4.5:order.size()>200?2:3.1)*scale));
            if(chosen){HPEN ring=CreatePen(PS_SOLID,S(1),ink);auto old=SelectObject(dc,ring);auto brush=SelectObject(dc,GetStockObject(HOLLOW_BRUSH));
                Ellipse(dc,int(p.x)-r-S(7),int(p.y)-r-S(7),int(p.x)+r+S(7),int(p.y)+r+S(7));SelectObject(dc,brush);SelectObject(dc,old);DeleteObject(ring);}
            HBRUSH brush=CreateSolidBrush(ink);auto old=SelectObject(dc,brush);auto pen=SelectObject(dc,GetStockObject(NULL_PEN));
            if(node.role=="fleet")Rectangle(dc,int(p.x)-r,int(p.y)-r,int(p.x)+r,int(p.y)+r);
            else if(node.role=="validator"){const int d=int(r*1.25);POINT v[4]={{int(p.x),int(p.y)-d},{int(p.x)+d,int(p.y)},{int(p.x),int(p.y)+d},{int(p.x)-d,int(p.y)}};Polygon(dc,v,4);}
            else Ellipse(dc,int(p.x)-r,int(p.y)-r,int(p.x)+r,int(p.y)+r);
            SelectObject(dc,pen);SelectObject(dc,old);DeleteObject(brush);
        }
        const auto& chosen=live.topology.nodes[order[selected]];
        const std::wstring role=chosen.role=="miner"?L"Miner":chosen.role=="fleet"?L"Fleet":chosen.role=="validator"?L"Validator":L"Node";
        const auto label=role+L" "+(selected+1<10?L"00":selected+1<100?L"0":L"")+FormatUnsigned(selected+1);
        const auto pos=constellation_points_[selected];const int lw=S(int(label.size()*6.7+20));
        const int lx=std::clamp(int(pos.x)-lw/2,int(plot.left+S(12)),int(plot.right-lw-S(12)));
        const int ly=pos.y>plot.bottom-S(75)?int(pos.y)-S(46):int(pos.y)+S(22);
        RECT bubble{lx,ly,lx+lw,ly+S(25)};FillRound(dc,bubble,panel,lineColor,5);
        DrawTextAt(dc,label,bubble,font_small_,text,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
        RECT hint{plot.left+S(20),plot.bottom-S(26),plot.right-S(20),plot.bottom-S(5)};
        DrawTextAt(dc,L"TAP A PEER TO TRACE ITS LINKS",hint,font_small_,muted);
        RECT detail{card.left+S(16),plot.bottom,card.right-S(16),plot.bottom+S(74)};
        FillRound(dc,detail,panel,lineColor,10);
        constellation_next_={detail.right-S(112),detail.top+S(18),detail.right-S(14),detail.bottom-S(18)};
        FillRound(dc,constellation_next_,RGB(23,34,25),lineColor,7);DrawTextAt(dc,L"Next peer →",constellation_next_,font_small_,text,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
        RECT marker{detail.left+S(14),detail.top+S(32),detail.left+S(24),detail.top+S(42)};
        const COLORREF selectedInk=chosen.tip_state=="differs"?RGB(239,195,103):color(chosen.role);
        FillRound(dc,marker,selectedInk,selectedInk,10);
        RECT name{detail.left+S(36),detail.top+S(12),constellation_next_.left-S(8),detail.top+S(34)};DrawTextAt(dc,label,name,font_small_,text);
        RECT info{name.left,name.bottom,name.right,detail.bottom-S(12)};
        DrawTextAt(dc,FormatUnsigned(neighbors.size())+L" reported links · "+
            (chosen.tip_state=="exact"?L"tip agrees":chosen.tip_state=="differs"?L"tip differs":L"no recent tip report"),info,font_small_,muted);
        RECT legend{card.left+S(20),detail.bottom+S(12),card.right-S(20),detail.bottom+S(37)};
        const wchar_t* roles[]={L"● Miner",L"● Node",L"■ Fleet",L"◆ Validator"};
        const char* roleIds[]={"miner","node","fleet","validator"};
        const int segment=std::min(S(100),int(legend.right-legend.left)/4);
        for(int i=0;i<4;++i){RECT cell{legend.left+i*segment,legend.top,legend.left+(i+1)*segment,legend.bottom};
            DrawTextAt(dc,roles[i],cell,font_small_,color(roleIds[i]));}
        divider=CreatePen(PS_SOLID,S(1),lineColor);oldDivider=SelectObject(dc,divider);
        MoveToEx(dc,legend.left,detail.bottom+S(46),nullptr);LineTo(dc,legend.right,detail.bottom+S(46));SelectObject(dc,oldDivider);DeleteObject(divider);
        RECT foot{legend.left,detail.bottom+S(54),legend.right,card.bottom-S(12)};
        DrawTextAt(dc,L"— Both report",foot,font_small_,muted);
        DrawTextAt(dc,L"┄ One-sided report",foot,font_small_,muted,DT_RIGHT|DT_VCENTER|DT_SINGLELINE|DT_NOPREFIX);
    }
