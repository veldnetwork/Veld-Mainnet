#pragma once

#include "../core/blockchain.h"
#include "../core/mempool.h"
#include "../core/pqc_script.h"
#include "../consensus/tiers.h"
#include "../core/constants.h"
#include "../core/version.h"
#include "../core/json_escape.h"
#include "../consensus/validators.h"
#include "../core/onchain_tokens.h"
#include "../network/rpc.h"
#include "../compat/platform.h"
#include "../network/explorer_dispatch.h"
#include "../network/listener_activation_guard.h"
#include "../network/chainparams.h"
#include "../network/trusted_proxy.h"
#include "explorer_icons.h"
#include <string>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <algorithm>
#include <ctime>
#include <fstream>
#include <filesystem>
#include <system_error>
#include <cmath>
#include <cstdio>
#include <climits>
#include <memory>
#include <vector>

#include "../compat/platform.h"

namespace veld {
namespace explorer {

using SocketHandle = veld::compat::SocketHandle;
inline constexpr size_t EXPLORER_MAX_RESPONSE_BODY = 4U * 1024U * 1024U;

struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
    std::vector<std::string> path_parts;
    bool valid = true;
    bool ambiguous_headers = false;

    static HttpRequest Parse(const std::string& raw) {
        HttpRequest req;
        std::istringstream ss(raw);
        std::string line;

        if (std::getline(ss, line)) {
            std::istringstream ls(line);
            ls >> req.method >> req.path >> req.version;
        }

        while (std::getline(ss, line) && line != "\r") {
            auto colon = line.find(':');
            if (colon == std::string::npos || colon == 0 || colon > 64) {
                req.valid = false;
                continue;
            }
            std::string key = line.substr(0, colon);
            for (char& c : key) {
                const unsigned char u = static_cast<unsigned char>(c);
                if (!(std::isalnum(u) || c == '-')) req.valid = false;
                c = static_cast<char>(std::tolower(u));
            }
            size_t start = colon + 1;
            while (start < line.size()
                   && (line[start] == ' ' || line[start] == '\t')) ++start;
            size_t end = line.size();
            if (end && line[end - 1] == '\r') --end;
            while (end > start
                   && (line[end - 1] == ' ' || line[end - 1] == '\t')) --end;
            if (end - start > 256) req.valid = false;
            std::string value = line.substr(start, end - start);
            for (unsigned char c : value)
                if (c < 0x20 && c != '\t') req.valid = false;
            if (!req.headers.emplace(std::move(key), std::move(value)).second)
                req.ambiguous_headers = true;
        }

        std::string remainder;
        std::getline(ss, remainder, '\0');
        if (!remainder.empty()) {
            req.body = remainder;
            while (!req.body.empty() && (req.body[0] == '\r' || req.body[0] == '\n'))
                req.body.erase(req.body.begin());
        }

        std::string p = req.path;
        if (!p.empty() && p[0] == '/') p = p.substr(1);
        // Strip the query string (for example, the icon cache revision) BEFORE
        // splitting into path_parts, so routes like /icon-192.png?v=... and
        // /manifest.json?v=... still match their "icon-192.png" / "manifest.json"
        // handlers. Without this they 404'd, and iOS PWAs fell back to the
        // generated "E" letter icon. (urlParam() below still reads req.path, so
        // query params remain available to handlers that need them.)
        { auto q = p.find('?'); if (q != std::string::npos) p = p.substr(0, q); }
        std::istringstream ps(p);
        std::string part;
        while (std::getline(ps, part, '/'))
            if (!part.empty()) req.path_parts.push_back(part);

        return req;
    }
};

static std::string base64_decode(const std::string& in) {
    static const std::string t =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, bits = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        auto p = t.find(c);
        if (p == std::string::npos) continue;
        val = (val << 6) | (int)p;
        bits += 6;
        if (bits >= 0) { out.push_back(char((val >> bits) & 0xFF)); bits -= 8; }
    }
    return out;
}

struct HttpResponse {
    int         status_code = 200;
    std::string status_text = "OK";
    std::string content_type = "text/html";
    std::string body;
    std::unordered_map<std::string, std::string> headers;
    std::string request_path;

    std::string Serialize() const {
        if (body.size() > EXPLORER_MAX_RESPONSE_BODY) {
            static const std::string too_large =
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                "Content-Length: 28\r\n"
                "Connection: close\r\n\r\n"
                "explorer response too large\n";
            return too_large;
        }
        std::ostringstream oss;
        oss << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";

        std::string html_body = body;
        std::string nonce_hex;
        if (content_type == "text/html") {
            uint8_t nbuf[16];
            if (!veld::compat::SecureRandom(nbuf, 16)) {
                oss.str(""); oss.clear();
                oss << "HTTP/1.1 500 Internal Server Error\r\n"
                       "Content-Type: text/plain\r\n"
                       "Content-Length: 21\r\n"
                       "Connection: close\r\n\r\n"
                       "server random fail\r\n";
                return oss.str();
            }
            static const char* hx = "0123456789abcdef";
            nonce_hex.reserve(32);
            for (int i = 0; i < 16; ++i) {
                nonce_hex.push_back(hx[nbuf[i] >> 4]);
                nonce_hex.push_back(hx[nbuf[i] & 0xF]);
            }
            {
                const std::string placeholder = "__CSP_NONCE__";
                size_t pos = 0;
                while ((pos = html_body.find(placeholder, pos)) != std::string::npos) {
                    html_body.replace(pos, placeholder.size(), nonce_hex);
                    pos += nonce_hex.size();
                }
            }
        }

        oss << "Content-Type: " << content_type << "; charset=utf-8\r\n";
        oss << "Content-Length: " << html_body.size() << "\r\n";
        oss << "Connection: close\r\n";
        bool is_api_path = (request_path.size() >= 5 &&
                            request_path.compare(0, 5, "/api/") == 0);
        bool is_per_address = (request_path.size() >= 9 &&
                               request_path.compare(0, 9, "/address/") == 0);
        if (is_api_path) {
            oss << "Access-Control-Allow-Origin: https://explorer.veld.network\r\n";
            oss << "Vary: Origin\r\n";
        }
        if (is_api_path || is_per_address) {
            oss << "Cache-Control: private, no-store\r\n";
        } else if (content_type == "text/html") {
            oss << "Cache-Control: no-cache, no-store, must-revalidate\r\n";
            oss << "Pragma: no-cache\r\n";
            oss << "Expires: 0\r\n";
        }
        if (content_type == "text/html") {
            oss << "Content-Security-Policy: default-src 'self'; "
                   "script-src 'self' 'nonce-" << nonce_hex << "'; "
                   "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                   "font-src 'self' https://fonts.gstatic.com; "
                   "connect-src 'self'; "
                   "img-src 'self' data:; "
                   "object-src 'none'; "
                   "frame-ancestors 'none'; "
                   "base-uri 'self'; "
                   "form-action 'self'\r\n";
        }
        for (const auto& [k, v] : headers)
            oss << k << ": " << v << "\r\n";
        oss << "\r\n";
        if (content_type == "text/html")
            oss << html_body;
        else
            oss << body;
        return oss.str();
    }

    static HttpResponse JSON(const std::string& json_body, int code = 200) {
        HttpResponse r;
        r.status_code   = code;
        r.content_type  = "application/json";
        r.body          = json_body;
        return r;
    }

    static HttpResponse HTML(const std::string& html_body) {
        HttpResponse r;
        r.content_type = "text/html";
        r.body = html_body;
        return r;
    }

    static std::string JsonEscape(const std::string& s) {
        return json::EscapeStringBytes(s);
    }

    static std::string EscapeHtml(const std::string& s) {
        std::string out;
        out.reserve(s.size() + 8);
        for (unsigned char c : s) {
            switch (c) {
                case '&':  out += "&amp;"; break;
                case '<':  out += "&lt;"; break;
                case '>':  out += "&gt;"; break;
                case '"':  out += "&quot;"; break;
                case '\'': out += "&#39;"; break;
                default:   out += (char)c; break;
            }
        }
        return out;
    }

    static HttpResponse NotFound(const std::string& what) {
        return JSON("{\"error\":\"Not found: " + JsonEscape(what) + "\"}", 404);
    }

    static HttpResponse Binary(const std::string& data, const std::string& mime) {
        HttpResponse r;
        r.content_type = mime;
        r.body = data;
        return r;
    }
};

// The explorer presents chain data. Network-profile warnings belong in the
// client package, launcher, and wallet identity surface.
inline std::string HtmlWrap(const std::string& title, const std::string& content, const std::string& active_nav = "") {
    std::string nav_items[]  = {"",          "blocks",  "staking", "vault",     "mining", "rich",      "validators", "mempool",    "rules"};
    std::string nav_labels[] = {"Dashboard", "Blocks",  "Staking", "Vault",     "Mining", "Rich List", "Validators", "Mempool",    "Rules"};
    std::string nav_icons[]  = {"&#x25A6;",  "&#x229E;","&#x2B21;","&#x25C8;",  "&#x2B22;","&#x2605;", "&#x2713;",   "&#x2692;",   "&#x2261;"};
    std::string nav_html;
    for (int i = 0; i < 9; ++i) {
        std::string href = nav_items[i].empty() ? "/" : "/" + nav_items[i];
        bool active = (active_nav == nav_items[i]);
        nav_html += "<a href=\"" + href + "\" class=\"nav-item" + (active ? " active" : "") + "\"><span class=\"nav-icon\">" + nav_icons[i] + "</span> " + nav_labels[i] + "</a>";
    }

    std::string head = "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "<meta charset=\"UTF-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover\">\n"
        "<title>" + title + " &mdash; VELD Explorer</title>\n"
        "<link rel=\"icon\" type=\"image/png\" href=\"/icon-192.png?v=20260819veldgradient1\">\n"
        "<link rel=\"apple-touch-icon\" sizes=\"180x180\" href=\"/icon-192.png?v=20260819veldgradient1\">\n"
        "<link rel=\"apple-touch-icon\" sizes=\"192x192\" href=\"/icon-192.png?v=20260819veldgradient1\">\n"
        "<link rel=\"apple-touch-icon\" sizes=\"512x512\" href=\"/icon-512.png?v=20260819veldgradient1\">\n"
        "<link rel=\"apple-touch-icon-precomposed\" sizes=\"180x180\" href=\"/icon-192.png?v=20260819veldgradient1\">\n"
        "<link rel=\"apple-touch-icon-precomposed\" sizes=\"192x192\" href=\"/icon-192.png?v=20260819veldgradient1\">\n"
        "<link rel=\"apple-touch-icon-precomposed\" sizes=\"512x512\" href=\"/icon-512.png?v=20260819veldgradient1\">\n"
        "<link rel=\"manifest\" href=\"/manifest.json?v=20260819veldgradient1\">\n"
        "<meta name=\"apple-mobile-web-app-capable\" content=\"yes\">\n"
        "<meta name=\"apple-mobile-web-app-title\" content=\"Explorer\">\n"
        "<meta name=\"apple-mobile-web-app-status-bar-style\" content=\"black-translucent\">\n"
        "<meta name=\"theme-color\" content=\"#020302\">\n"
        "<meta name=\"theme-color\" media=\"(prefers-color-scheme: light)\" content=\"#EFEFEF\">\n"
        "<meta name=\"theme-color\" media=\"(prefers-color-scheme: dark)\" content=\"#020302\">\n"
        "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n"
        "<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n"
        "<link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@300;400;500;600;700&family=Rajdhani:wght@400;500;600;700&display=swap\" rel=\"stylesheet\">\n"
        "<style>\n"
":root{--bg:#020302;--s1:#070907;--s2:#0C0E0C;--s3:#121412;--b1:#1a1d1a;--b2:#2a2f2a;--b3:#3a3f3a;--em:#7ED949;--em2:#7ED949;--em-dim:rgba(126,217,73,.07);--em-dark:rgba(126,217,73,.04);--gold:#FFD84A;--red:#FF4C4C;--blue:#4CB8FF;--purple:#B07CFF;--btc:#F7931A;--text:#CACACA;--muted:#707070;--muted2:#484848;--border:#1a1d1a;--border2:#2a2f2a;--font:'SF Mono','Menlo','Cascadia Code','JetBrains Mono',ui-monospace,monospace;--head:-apple-system,BlinkMacSystemFont,'Segoe UI','Helvetica Neue',Arial,sans-serif;--sans:-apple-system,BlinkMacSystemFont,'Segoe UI','Helvetica Neue',Arial,sans-serif;}\n"
"*{box-sizing:border-box;margin:0;padding:0;}html{scroll-behavior:smooth;}\n"
"body{font-family:var(--sans);background:var(--bg);color:var(--text);min-height:100vh;font-size:23px;line-height:1.6;overflow-x:hidden;scrollbar-width:thin;scrollbar-color:rgba(50,240,110,.15) transparent;}\n"
"body::before{display:none;}\n"
"::-webkit-scrollbar{width:6px;background:transparent;opacity:0;transition:opacity .3s;}::-webkit-scrollbar-thumb{background:rgba(50,240,110,.15);border-radius:3px;}.tbl-scroll::-webkit-scrollbar,.feed::-webkit-scrollbar{width:4px;}.tbl-scroll::-webkit-scrollbar-thumb,.feed::-webkit-scrollbar-thumb{background:rgba(50,240,110,.1);border-radius:2px;}\n"
"@keyframes neonPulse{0%,100%{}50%{}}\n"
"@keyframes glowText{0%,100%{}50%{}}\n"
"@keyframes shimmer{0%{left:-100%;}100%{left:200%;}}\n"
"@keyframes gridFade{0%,100%{opacity:.6;}50%{opacity:1;}}\n"
"@keyframes slideIn{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:none;}}\n"
"@keyframes hb{0%,100%{transform:scale(1);opacity:1;}50%{transform:scale(1.3);opacity:.7;}}\n"
"@keyframes progressGlow{0%,100%{}50%{}}\n"
"@keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 0 0 rgba(50,240,110,.4);}50%{opacity:.6;box-shadow:0 0 0 5px transparent;}}\n"
"@keyframes pageEntry{from{opacity:0;}to{opacity:1;}}\n"
".sidebar{width:240px;min-width:240px;height:100vh;background:#0b0d0d;border-right:1px solid rgba(255,255,255,.08);display:flex;flex-direction:column;position:fixed;z-index:10;}\n"
".logo-wrap{padding:26px 22px 22px;border-bottom:1px solid rgba(50,240,110,.08);}\n"
".logo{font-family:var(--head);font-size:26px;font-weight:800;color:var(--em);letter-spacing:5px;text-decoration:none;}\n"
".logo span{color:#fff;}\n"
".logo-sub{font-size:10px;color:var(--muted2);letter-spacing:4px;text-transform:uppercase;margin-top:4px;}\n"
".nav{flex:1;padding:8px 0;overflow-y:auto;}\n"
".nav-item{display:flex;align-items:center;gap:12px;padding:13px 22px;cursor:pointer;font-size:18px;font-weight:500;color:var(--muted);transition:all .15s;border-left:2px solid transparent;text-decoration:none;position:relative;}\n"
".nav-item:hover{color:var(--text);background:rgba(50,240,110,.03);}\n"
".nav-item.active{color:#f2f4f3;border-left-color:transparent;background:transparent;}\n"
".nav-item.active::after{display:none;}\n"
".nav-icon{width:22px;text-align:center;font-size:20px;flex-shrink:0;}\n"
".nav-item.active .nav-icon{color:var(--em);filter:none;}\n"
".sidebar-links{padding:16px 22px;border-top:1px solid rgba(50,240,110,.06);display:flex;flex-direction:column;gap:8px;}\n"
".sidebar-btn{display:block;text-align:center;padding:8px;border:1px solid rgba(50,240,110,.1);border-radius:8px;color:var(--muted);text-decoration:none;font-size:12px;letter-spacing:1px;text-transform:uppercase;transition:all .15s;}\n"
".sidebar-btn:hover{color:var(--text);border-color:rgba(50,240,110,.2);}\n"
".sidebar-btn-em{color:var(--em);border-color:rgba(50,240,110,.2);}\n"
".sidebar-btn-em:hover{background:rgba(50,240,110,.05);}\n"
".main{margin-left:240px;min-height:100vh;overflow-y:auto;}\n"
".search-bar{padding:16px 32px;border-bottom:1px solid rgba(50,240,110,.06);display:flex;align-items:center;gap:8px;}\n"
".search-bar input{flex:1;background:rgba(2,3,2,.9);border:1px solid rgba(50,240,110,.1);color:var(--text);padding:12px 18px;border-radius:10px;font-family:var(--font);font-size:14px;outline:none;transition:all .15s;}\n"
".search-bar input:focus{border-color:rgba(50,240,110,.35);}\n"
".search-bar input::placeholder{color:var(--muted2);}\n"
".search-bar button{background:none;border:none;color:var(--muted);font-size:16px;cursor:pointer;padding:8px;transition:color .15s;}\n"
".search-bar button:hover{color:var(--em);}\n"
"@keyframes navGlow{0%,100%{box-shadow:0 -4px 20px rgba(50,240,110,.05),0 -1px 6px rgba(50,240,110,.04)}50%{box-shadow:0 -6px 28px rgba(50,240,110,.1),0 -2px 10px rgba(50,240,110,.06)}}\n"
".mob-header{display:none;position:fixed;top:0;left:0;right:0;height:44px;background:rgba(2,3,2,.94);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border-bottom:1px solid rgba(50,240,110,.08);z-index:100;padding:0 16px;align-items:center;justify-content:space-between;box-shadow:0 2px 16px rgba(50,240,110,.03);}\n"
".mob-logo{font-family:var(--head);font-size:22px;font-weight:800;color:var(--em);letter-spacing:5px;text-decoration:none;}\n"
".mob-logo span{color:#fff;}\n"
".mob-menu-btn{display:none;}\n"
".mob-nav{display:none;}\n"
"#explorer-mobile-nav{display:none;position:fixed;bottom:0;left:0;right:0;z-index:500;height:68px;min-height:68px;max-height:68px;background:linear-gradient(0deg,rgba(3,5,3,.98),rgba(7,10,7,.95));backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border-top:1px solid rgba(50,240,110,.15);box-shadow:0 -8px 32px rgba(50,240,110,.06),0 -2px 8px rgba(50,240,110,.04);padding:0;box-sizing:border-box;animation:navGlow 3s ease infinite;transform:translateZ(0);-webkit-transform:translateZ(0);will-change:transform;}\n"
// ^ transform:translateZ(0) pins the fixed bottom nav to its own GPU layer. On
//   iOS standalone PWAs a position:fixed bar that is a SIBLING of a
//   -webkit-overflow-scrolling:touch container (.main) jumps up when that
//   container re-lays-out tall content (e.g. the Blocks / Mempool lists);
//   compositing it independently keeps it glued to the bottom.
".mob-tab{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;cursor:pointer;color:var(--muted2);font-size:10px;letter-spacing:.5px;text-transform:uppercase;font-family:var(--sans);font-weight:600;border:none;background:none;padding:4px 2px;transition:all .15s;-webkit-tap-highlight-color:transparent;height:68px;min-height:68px;max-height:68px;min-width:0;overflow:hidden;position:relative;text-decoration:none;box-sizing:border-box;}\n"
".mob-tab .mob-icon{font-size:24px;line-height:1;transition:all .2s;}\n"
".mob-tab .mob-label{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;}\n"
".mob-tab.active{color:var(--em);}\n"
".mob-tab.active::before{content:'';position:absolute;top:0;left:50%;transform:translateX(-50%);width:28px;height:3px;background:var(--em);border-radius:0 0 5px 5px;box-shadow:0 4px 20px rgba(50,240,110,.7),0 0 6px var(--em);}\n"
".mob-tab.active .mob-icon{filter:drop-shadow(0 0 14px rgba(50,240,110,.8));transform:translateY(-2px) scale(1.08);}\n"
".mob-tab:active{opacity:.4;}\n"
".mob-more-btn{display:flex;flex-direction:column;align-items:center;gap:5px;padding:16px 10px;border-radius:12px;background:var(--s1);border:1px solid rgba(50,240,110,.08);color:var(--muted);font-size:10px;font-family:var(--sans);letter-spacing:.3px;font-weight:600;cursor:pointer;transition:all .12s;text-transform:uppercase;-webkit-tap-highlight-color:transparent;text-decoration:none;}\n"
".mob-more-btn:active{color:var(--em);border-color:rgba(50,240,110,.25);}\n"
"#explorer-more-menu{display:none;position:fixed;bottom:68px;left:0;right:0;z-index:499;background:rgba(2,3,2,.96);border-top:1px solid var(--b1);padding:14px 16px;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);}\n"
"@media(max-width:900px){html,body{overflow:visible !important;height:auto !important;min-height:100vh !important;min-height:100dvh !important;position:static !important;width:100% !important;overscroll-behavior-y:none;}#explorer-mobile-nav{display:flex !important;}.sidebar{display:none !important;}.mob-header{display:flex !important;}.main{margin-left:0 !important;padding-top:44px;padding-bottom:88px;overflow:visible !important;height:auto !important;min-height:100vh !important;min-height:100dvh !important;}}\n"
"@media(min-width:901px){#explorer-mobile-nav{display:none !important;}#explorer-more-menu{display:none !important;}.mob-header{display:none !important;}}\n"
".container{max-width:1400px;margin:0 auto;padding:32px;position:relative;z-index:1;}\n"
".card{background:linear-gradient(175deg,var(--s2),var(--s1));border:1px solid var(--b1);border-radius:12px;padding:24px 28px;margin-bottom:16px;position:relative;overflow-x:auto;overflow-y:hidden;-webkit-overflow-scrolling:touch;transition:border-color .25s;}\n"
".card.tint-em    {background:linear-gradient(170deg,rgba(50,240,110,.05),rgba(50,240,110,.012)),linear-gradient(175deg,var(--s2),var(--s1));}\n"
".card.tint-gold  {background:linear-gradient(170deg,rgba(255,216,74,.05),rgba(255,216,74,.012)),linear-gradient(175deg,var(--s2),var(--s1));}\n"
".card.tint-purple{background:linear-gradient(170deg,rgba(176,124,255,.05),rgba(176,124,255,.012)),linear-gradient(175deg,var(--s2),var(--s1));}\n"
".card.tint-red   {background:linear-gradient(170deg,rgba(255,100,112,.06),rgba(255,100,112,.014)),linear-gradient(175deg,var(--s2),var(--s1));}\n"
".card.tint-amber {background:linear-gradient(170deg,rgba(255,180,90,.06),rgba(255,180,90,.014)),linear-gradient(175deg,var(--s2),var(--s1));}\n"
".card.tint-muted {background:linear-gradient(170deg,rgba(120,120,120,.04),rgba(120,120,120,.01)),linear-gradient(175deg,var(--s2),var(--s1));}\n"
".card:hover{border-color:rgba(255,255,255,.18);}\n"
""
".card-title{font-family:var(--sans,inherit);font-size:15px;font-weight:600;letter-spacing:.1px;color:var(--text);margin-bottom:14px;}\n"
".stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;}\n"
".stat{background:var(--s3);border:1px solid var(--b1);border-radius:10px;padding:20px 24px;transition:border-color .2s;overflow:hidden;scrollbar-width:none;}\n"
".stat::-webkit-scrollbar{display:none;}\n"
".stat:hover{border-color:var(--b2);}\n"
".stat-label{font-size:12px;color:var(--muted);margin-bottom:8px;font-family:var(--sans);font-weight:500;}\n"
".stat-value{font-family:var(--head);font-size:32px;font-weight:600;color:var(--text);letter-spacing:-.5px;}.stat-value.em{color:var(--em);}.stat-value.gold{color:var(--gold);}\n"
".stat-sub{font-size:13px;color:var(--muted);margin-top:4px;}\n"
".progress-track{background:var(--s3);border-radius:3px;height:6px;overflow:hidden;margin-top:8px;border:1px solid var(--b1);}\n"
".progress-fill{background:linear-gradient(90deg,var(--em-dark),var(--em));height:100%;border-radius:3px;transition:width .6s ease;min-width:2px;}\n"
".tbl-scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;width:100%;}\n"
".tbl{width:100%;border-collapse:collapse;min-width:480px;}\n"
".tbl th{font-size:14px;text-transform:uppercase;letter-spacing:2px;color:var(--muted);padding:14px 20px;text-align:left;border-bottom:1px solid var(--b1);white-space:nowrap;font-family:var(--sans);}\n"
".tbl td{padding:16px 20px;border-bottom:1px solid var(--b1);vertical-align:middle;font-size:18px;}\n"
".tbl tr:hover td{background:rgba(50,240,110,.03);box-shadow:inset 0 0 20px rgba(50,240,110,.01);}.tbl tr:last-child td{border-bottom:none;}\n"
".hash{font-family:var(--font);color:var(--btc);font-size:14px;text-decoration:none;max-width:180px;display:inline-block;overflow:hidden;text-overflow:ellipsis;vertical-align:bottom;transition:color .2s;}\n"
".hash:hover{color:#fff;}.hash-full{max-width:100%;word-break:break-all;}\n"
".addr{color:var(--gold);font-size:14px;text-decoration:none;max-width:160px;display:inline-block;overflow:hidden;text-overflow:ellipsis;vertical-align:bottom;transition:color .2s;}\n"
".addr:hover{color:#fff;}\n"
".miner-addr{color:var(--em);font-family:var(--font);font-size:14px;text-decoration:none;max-width:180px;display:inline-block;overflow:hidden;text-overflow:ellipsis;vertical-align:bottom;transition:color .2s;}.miner-addr:hover{color:#fff;}\n"
".mono{font-family:var(--font);font-size:14px;word-break:break-all;overflow-wrap:anywhere;}\n"
".badge{display:inline-block;padding:6px 14px;border-radius:5px;font-size:13px;font-weight:600;letter-spacing:.5px;}\n"
".badge-bootstrap{background:rgba(255,216,74,.08);color:var(--gold);border:1px solid rgba(255,216,74,.2);}\n"
".badge-active{background:var(--em-dark);color:var(--em);border:1px solid rgba(50,240,110,.2);}\n"
".badge-inactive{background:var(--s2);color:var(--muted);border:1px solid var(--b1);}\n"
".live-dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--em);margin-right:6px;box-shadow:0 0 12px var(--em),0 0 30px rgba(50,240,110,.4),0 0 60px rgba(50,240,110,.1);animation:hb 2s ease-in-out infinite;}\n"
".feed{max-height:260px;overflow-y:auto;}\n"
".feed-item{display:flex;align-items:center;gap:10px;padding:12px 0;border-bottom:1px solid var(--b1);font-size:13px;animation:slideIn .3s ease;}\n"
".feed-item:last-child{border-bottom:none;}\n"
".feed-height{color:var(--em);font-weight:600;min-width:55px;flex-shrink:0;}\n"
".feed-hash{color:var(--muted);font-size:10px;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0;}\n"
".feed-reward{color:var(--gold);min-width:90px;text-align:right;flex-shrink:0;}\n"
".vault-bar-track{background:var(--s3);border-radius:4px;height:8px;overflow:hidden;margin:12px 0;border:1px solid var(--b1);}\n"
".vault-bar-fill{background:linear-gradient(90deg,var(--em-dark),var(--em));height:100%;border-radius:4px;transition:width .8s cubic-bezier(.4,0,.2,1);min-width:2px;animation:progressGlow 3s ease-in-out infinite;}\n"
".tier-0{color:var(--muted);}.tier-1{color:#CD7F32;}.tier-2{color:#C0C0C0;}.tier-3{color:#FFD700;}.tier-4{color:#E5E4E2;}\n"
"@keyframes diamond-shimmer{0%{background-position:0% 50%}100%{background-position:200% 50%}}\n"
".tier-5,.diamond-prismatic{background:linear-gradient(100deg,#B9F2FF 0%,#FFFFFF 20%,#E0FFFF 40%,#C8F0FF 60%,#FFFFFF 80%,#B9F2FF 100%);background-size:200% 100%;-webkit-background-clip:text;background-clip:text;color:transparent!important;-webkit-text-fill-color:transparent;font-weight:700;text-shadow:none;animation:diamond-shimmer 6s ease-in-out infinite;filter:drop-shadow(0 0 4px rgba(185,242,255,.7)) drop-shadow(0 0 8px rgba(255,255,255,.3));}\n"
".diamond-badge{display:inline-block;padding:2px 8px;border-radius:4px;background:linear-gradient(100deg,rgba(185,242,255,.15),rgba(255,255,255,.22),rgba(224,255,255,.2),rgba(185,242,255,.15));background-size:200% 100%;animation:diamond-shimmer 6s ease-in-out infinite;border:1px solid rgba(185,242,255,.5);font-size:10px;font-weight:700;letter-spacing:.5px;color:#E0FFFF;margin-left:4px;}\n"
".grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px;}.grid-3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;}\n"
".input-row{display:flex;gap:8px;margin-bottom:14px;}\n"
".veld-input{flex:1;min-width:0;background:var(--s3);border:1px solid var(--b1);color:var(--text);padding:9px 12px;border-radius:6px;font-family:var(--font);font-size:12px;outline:none;transition:border-color .2s,box-shadow .2s;}\n"
".veld-input:focus{border-color:var(--em);,0 0 0 2px rgba(50,240,110,.04);}\n"
".veld-btn{background:#1A1F1F;color:#F0F0F0;border:1px solid #32F06E;padding:9px 16px;border-radius:6px;cursor:pointer;font-family:var(--sans);font-weight:600;font-size:12px;letter-spacing:.1px;transition:background .15s,box-shadow .15s,border-color .15s;white-space:nowrap;box-shadow:inset 0 0 0 1px rgba(50,240,110,.18);}\n"
".veld-btn:hover{background:#222827;box-shadow:inset 0 0 0 1px rgba(50,240,110,.28),0 0 14px rgba(50,240,110,.12);}\n"
".veld-btn-ghost{background:none;color:var(--em);border:1px solid var(--em);padding:9px 16px;border-radius:6px;cursor:pointer;font-family:var(--font);font-size:12px;transition:background .2s,box-shadow .2s;}\n"
".veld-btn-ghost:hover{background:var(--em-dim);}\n"
".fi{width:100%;background:var(--s3);border:1px solid var(--b1);color:var(--text);padding:9px 12px;border-radius:6px;font-family:var(--font);font-size:12px;outline:none;margin-bottom:8px;transition:border-color .2s,box-shadow .2s;}\n"
".fi:focus{border-color:var(--em);}\n"
".btn{padding:9px 16px;border-radius:6px;cursor:pointer;font-family:var(--sans);font-weight:600;font-size:12px;letter-spacing:.1px;background:#1A1F1F;color:#F0F0F0;border:1px solid #32F06E;box-shadow:inset 0 0 0 1px rgba(50,240,110,.18);transition:background .15s,box-shadow .15s,border-color .15s;white-space:nowrap;}\n"
".btn:hover{background:#222827;box-shadow:inset 0 0 0 1px rgba(50,240,110,.28),0 0 14px rgba(50,240,110,.12);}\n"
".btn-btc{background:#1A1F1F;color:#F0F0F0;border:1px solid #F7931A;box-shadow:inset 0 0 0 1px rgba(247,147,26,.22);}.btn-btc:hover{background:#222827;box-shadow:inset 0 0 0 1px rgba(247,147,26,.32);}\n"
".btn-red{background:#1A1F1F;color:#F0F0F0;border:1px solid #FF4C4C;box-shadow:inset 0 0 0 1px rgba(255,76,76,.22);}.btn-red:hover{background:#221b1b;box-shadow:inset 0 0 0 1px rgba(255,76,76,.32);}\n"
".alert{padding:10px 14px;border-radius:6px;font-size:12px;margin-top:8px;display:none;border:1px solid var(--b1);background:var(--s2);}\n"
".info-box{border:1px solid var(--b1);border-radius:8px;padding:12px;background:var(--s2);}\n"
".info-row{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--b1);font-size:13px;}.info-row:last-child{border-bottom:none;}\n"
".step{display:flex;align-items:flex-start;gap:12px;margin-bottom:10px;}\n"
".step-num{flex-shrink:0;width:24px;height:24px;border-radius:50%;background:var(--em-dim);border:1px solid var(--b2);color:var(--em);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;}\n"
".step-text{font-size:13px;color:var(--text);line-height:1.5;padding-top:2px;}\n"
".ticker{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-end;padding:12px 0;border-bottom:1px solid var(--b1);margin-bottom:16px;}\n"
".tk-lbl{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:2px;}\n"
".tk-price{font-size:24px;font-weight:700;color:var(--text);letter-spacing:-.5px;}\n"
".tk-val{font-size:15px;font-weight:600;color:var(--text);}\n"
".c-buy{color:var(--em);}.c-sell{color:var(--red);}.c-btc{color:#f7931a;}\n"
".ob-hdr{display:flex;justify-content:space-between;padding:6px 0;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);border-bottom:1px solid var(--b1);}\n"
".ob-row{display:flex;justify-content:space-between;padding:4px 0;font-size:12px;border-bottom:1px solid rgba(50,240,110,.03);transition:background .15s;}.ob-row:hover{background:var(--em-dim);}\n"
".footer{border-top:1px solid var(--b1);padding:20px;text-align:center;font-size:12px;color:var(--muted);letter-spacing:.5px;position:relative;z-index:1;box-shadow:0 -1px 0 rgba(50,240,110,.05);}\n"
"a{color:inherit;text-decoration:none;}\n"
"@media(max-width:900px){.grid-2,.grid-3{grid-template-columns:1fr;}.stat-grid{grid-template-columns:1fr 1fr;}.ticker{gap:12px;}.footer{margin-left:0!important;}}\n"
"@media(max-width:600px){.logo{font-size:17px;letter-spacing:3px;}.container{padding:10px 12px;}.card{padding:12px;margin-bottom:10px;}.stat-grid{gap:8px;}.stat{padding:10px;}.stat-label{font-size:12px!important;}.stat-value{font-size:22px!important;}.stat-sub{font-size:12px!important;}.tbl th{padding:6px 8px;font-size:13.5px!important;}.tbl td{padding:7px 8px;font-size:13.5px!important;}.hash,.addr{font-size:13.5px!important;max-width:100px;}.feed-item{font-size:15px!important;}.input-row{flex-direction:column;}.veld-btn,.veld-btn-ghost{width:100%;}.footer{padding:12px;}.ticker{gap:8px;}.tk-price{font-size:20px!important;}.tk-val{font-size:14px!important;}.fi{padding:8px 10px;font-size:15px!important;}.search-bar{padding:10px 12px;}.search-bar input{padding:9px 12px;font-size:15px!important;}#index-search-card{display:none!important;}.card-title{font-size:14px!important;}h1{font-size:22px!important;}h2{font-size:20px!important;}h3{font-size:17px!important;}p,.p,li{font-size:15px!important;}}\n"
"</style>\n"
        "<style>\n"
":root{--bg:#0A0B0A!important;--s1:#0E100E!important;--s2:#141614!important;--s3:#1A1D1A!important;--b1:rgba(255,255,255,.05)!important;--b2:rgba(255,255,255,.09)!important;--b3:rgba(126,217,73,.22)!important;--text:#E5E8E5!important;--muted:#B0B3B0!important;--muted2:#707570!important;--em:#7ED949!important;--em-dim:rgba(126,217,73,.09)!important;--em-dark:rgba(126,217,73,.05)!important;--gold:#FFD84A!important;--blue:#4CB8FF!important;--purple:#B07CFF!important;--red:#FF6057!important;--font:'JetBrains Mono','SF Mono','Cascadia Code',Consolas,monospace;--sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;--head:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif}\n"
"body{font-family:var(--sans)!important;font-size:16.5px!important;line-height:1.65!important;letter-spacing:-.005em;font-feature-settings:'cv11','ss01','ss02','cv01'!important;background:var(--bg)!important;-webkit-font-smoothing:antialiased!important;-moz-osx-font-smoothing:grayscale!important}\n"
"h1,h2,h3,h4{font-family:var(--head)!important;letter-spacing:-.2px!important;font-weight:600!important}\n"
"h1{font-size:26px!important}h2{font-size:22px!important}h3{font-size:18px!important}h4{font-size:15.5px!important}\n"
"p,.p,.psub,.lede,.card p,.card-body,li{font-size:15px!important;line-height:1.65!important}\n"
".ptitle{font-size:26px!important}\n"
".pheader,.page-header{display:none!important}\n"
".card-title{font-size:14px!important;letter-spacing:1.2px!important}\n"
".tbl th,.tbl td{font-size:13.5px!important}\n"
".stat-value,.stats .stat .val{font-size:22px!important}\n"
".stat-label,.stats .stat .lbl{font-size:12px!important}\n"
".stat-sub,.stats .stat .sub{font-size:12px!important}\n"
".section-label{font-size:14px!important}\n"
".nav-item{font-size:14.5px!important}\n"
"code,.mono,pre{font-family:var(--font)!important;font-size:13.5px!important;font-variant-numeric:tabular-nums!important}\n"
"body::before,body::after{display:none!important}\n"
"*{scrollbar-width:thin;scrollbar-color:rgba(50,240,110,.22) transparent}\n"
"::-webkit-scrollbar{width:6px;height:6px;background:transparent}\n"
"::-webkit-scrollbar-thumb{background:rgba(50,240,110,.18);border-radius:6px;transition:background .2s}\n"
"*:not(:hover)::-webkit-scrollbar-thumb{background:rgba(50,240,110,.06)}\n"
"*:hover::-webkit-scrollbar-thumb{background:rgba(50,240,110,.22)}\n"
".sidebar{width:220px!important;min-width:220px!important;background:#111311!important;border-right:1px solid var(--b1)!important}\n"
".logo-wrap{padding:22px 20px 18px!important;border-bottom:1px solid var(--b1)!important}\n"
".logo{font-family:var(--font)!important;font-size:19px!important;font-weight:700!important;letter-spacing:5px!important}\n"
".logo-sub{font-size:10px!important;letter-spacing:3px!important}\n"
".nav-item{padding:10px 20px!important;font-size:14px!important;color:var(--muted)!important;border-left:2px solid transparent!important}\n"
".nav-item:hover{background:#1A1D1A!important;color:var(--text)!important;text-shadow:none!important}\n"
".nav-item.active{color:#f2f4f3!important;background:transparent!important;border-left-color:transparent!important;text-shadow:none!important;box-shadow:none!important;outline:none!important}\n"
".nav-item.active::after{display:none!important}\n"
".nav-icon{font-size:16px!important;width:20px!important}\n"
".main{margin-left:220px!important}\n"
".card{background:#111311!important;border:1px solid var(--b1)!important;border-radius:8px!important;transition:border-color .25s!important}\n"
".card:hover{border-color:rgba(50,240,110,.35)!important}\n"
".stat{background:#111311!important;border:1px solid var(--b1)!important;border-radius:8px!important;padding:14px 16px!important}\n"
".stat:hover{border-color:rgba(50,240,110,.35)!important}\n"
".diamond-glow-border{animation:none!important}\n"
"@media (prefers-reduced-motion:reduce){.card,.stat{animation:none!important}}\n"
".stat-label{font-size:11.5px!important;font-weight:600!important;letter-spacing:1.5px!important;color:var(--muted2)!important;text-transform:uppercase!important}\n"
".stat-value{font-family:var(--font)!important;font-size:20px!important;font-variant-numeric:tabular-nums!important}\n"
".stat-value.em{color:var(--em)!important}\n"
".tbl th{font-size:12px!important;letter-spacing:1.5px!important;text-transform:uppercase!important;color:var(--muted2);font-weight:600!important}\n"
".tbl td{font-family:var(--font)!important;font-variant-numeric:tabular-nums!important}\n"
".tbl td:not([style*=\"color\"]):not([class*=\"tier-\"]):not([class*=\"diamond\"]){color:var(--muted)}\n"
".tbl tr:hover td{background:#1A1D1A!important}\n"
".search-bar input{background:#141614!important;border:1px solid var(--b1)!important;padding:10px 14px!important;font-family:var(--font)!important;font-size:13px!important}\n"
".search-bar input:focus{border-color:var(--em)!important;}\n"
".logo{}\n"
"@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}\n"
"*{-webkit-tap-highlight-color:transparent}\n"
"@media (hover:none){\n"
"  .card,.stat,.stats .stat,.logo,.mob-logo,.live-dot,\n"
"  .vault-bar-fill,.diamond-prismatic,.diamond-badge,\n"
"  #explorer-mobile-nav{animation:none!important}\n"
"  .card:hover,.stat:hover,.stats .stat:hover,\n"
"  .rule-card:hover,.feed-item:hover{\n"
"    transform:none!important;\n"
"    border-color:rgba(50,240,110,.12)!important;\n"
"    \n"
"    background-color:inherit!important;\n"
"  }\n"
"  .tbl tr:hover td,.tbl tr:hover{background:transparent!important}\n"
"}\n"
"@keyframes diamondShine{0%{background-position:0% 50%}100%{background-position:200% 50%}}\n"
".diamond-prismatic{background:linear-gradient(100deg,#B9F2FF 0%,#FFFFFF 20%,#E0FFFF 40%,#C8F0FF 60%,#FFFFFF 80%,#B9F2FF 100%)!important;background-size:200% 100%!important;-webkit-background-clip:text!important;background-clip:text!important;color:transparent!important;-webkit-text-fill-color:transparent!important;animation:diamondShine 6s ease-in-out infinite!important;filter:drop-shadow(0 0 6px rgba(185,242,255,.75))!important;font-weight:700!important}\n"
".diamond-badge{display:inline-block!important;padding:3px 10px!important;border-radius:6px!important;background:linear-gradient(100deg,rgba(185,242,255,.18),rgba(255,255,255,.28),rgba(185,242,255,.18))!important;background-size:200% 100%!important;animation:diamondShine 6s ease-in-out infinite!important;border:1px solid rgba(185,242,255,.6)!important;font-size:10.5px!important;font-weight:700!important;letter-spacing:1.5px!important;color:#E0FFFF!important;text-transform:uppercase!important;box-shadow:0 0 12px rgba(185,242,255,.25)!important;font-variant-emoji:text}\n"
"html[data-theme=\"light\"] .diamond-badge{color:#0c5b6e!important;background:linear-gradient(100deg,rgba(56,189,248,.18),rgba(165,243,252,.32),rgba(56,189,248,.18))!important;border:1px solid rgba(8,145,178,.45)!important;box-shadow:0 0 10px rgba(8,145,178,.18)!important}\n"
".tier-name{font-weight:700}\n"
".tier-none{color:var(--muted)}.tier-bronze{color:#CD7F32}.tier-silver{color:#C0C0C0}.tier-gold{color:#FFD700}.tier-platinum{color:#E5E4E2}\n"
"html[data-theme=\"light\"] .tier-none{color:#696F6C!important;-webkit-text-fill-color:#696F6C!important}\n"
"html[data-theme=\"light\"] .tier-bronze{color:#CD7F32!important;-webkit-text-fill-color:#CD7F32!important}\n"
"html[data-theme=\"light\"] .tier-silver{color:#7A8591!important;-webkit-text-fill-color:#7A8591!important}\n"
"html[data-theme=\"light\"] .tier-gold{color:#B77900!important;-webkit-text-fill-color:#B77900!important}\n"
"html[data-theme=\"light\"] .tier-platinum{color:#667080!important;-webkit-text-fill-color:#667080!important}\n"
// ─── Mobile fix: collapse sidebar, full-width main, responsive stat grid ───
// Default explorer CSS has .main{margin-left:240px} and does NOT drop the
// sidebar on mobile, leaving ~60% of screen empty. Force sidebar hidden
// below 900px and let .main fill the viewport.
"@media (max-width:900px){\n"
"  .sidebar{display:none!important}\n"
"  .main{margin-left:0!important}\n"
"  .stat-grid{grid-template-columns:1fr 1fr!important;gap:8px!important}\n"
"  .stat{padding:12px 14px!important}\n"
"  .stat-value{font-size:20px!important}\n"
"  .container{padding:14px 16px!important}\n"
"  .card{padding:16px 18px!important;margin-bottom:12px!important}\n"
"  .tbl th{font-size:10.5px!important;padding:7px 10px!important}\n"
"  .tbl td{font-size:11.5px!important;padding:7px 10px!important}\n"
"}\n"
"@media (max-width:420px){\n"
"  .stat-grid{grid-template-columns:1fr!important}\n"
"}\n"
".tier-bronze{color:#CD7F32!important;font-weight:600!important}\n"
".tier-silver{color:#D8D8D8!important;font-weight:600!important}\n"
".tier-gold{color:#FFD700!important;font-weight:600!important}\n"
".tier-platinum{color:#E5E4E2!important;font-weight:600!important}\n"
"@keyframes heartbeat{0%,70%,100%{transform:scale(1);}30%{transform:scale(1.35);}}\n"
".live-dot{animation:heartbeat 2.2s ease infinite!important}\n"
"@media (max-width:600px){\n"
"  body{font-size:15.5px!important;line-height:1.6!important}\n"
"  h1{font-size:22px!important}h2{font-size:19px!important}h3{font-size:16.5px!important}\n"
"  p,.p,.psub,.lede{font-size:14.5px!important}\n"
"  .ptitle{font-size:22px!important}\n"
"  .tbl th,.tbl td{font-size:13px!important}\n"
"  .stat-value,.stats .stat .val{font-size:19px!important}\n"
"  .card-title{font-size:13px!important;letter-spacing:2px!important}\n"
"  .stat-label{font-size:11.5px!important;letter-spacing:1.5px!important}\n"
"  .stat-value{font-size:18px!important}\n"
"  .stat-grid{grid-template-columns:1fr!important;gap:8px!important}\n"
"  .stat{padding:11px 13px!important}\n"
"  .grid-2,.grid-3{grid-template-columns:1fr!important;gap:10px!important}\n"
"  .tbl th{font-size:10.5px!important;padding:7px 9px!important}\n"
"  .tbl td{font-size:12px!important;padding:8px 9px!important}\n"
"  .hash,.addr,.miner-addr{font-size:12px!important;max-width:110px!important}\n"
"  .container{padding:12px 12px!important}\n"
"}\n"
".role-mining{color:var(--em)!important}\n"
".role-staking{color:var(--gold)!important}\n"
".role-comine{color:var(--blue)!important}\n"
".role-endorse{color:var(--purple)!important}\n"
".sw-mining,.sw-em{background:var(--em)}\n"
".sw-staking,.sw-gold{background:var(--gold)}\n"
".sw-comine,.sw-blue{background:var(--blue)}\n"
".sw-endorse,.sw-purple{background:var(--purple)}\n"
".rule-table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13.5px}\n"
".rule-table th{text-align:left;padding:10px 12px;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted2);font-weight:600;border-bottom:1px solid var(--b1)}\n"
".rule-table td{padding:10px 12px;border-bottom:1px solid var(--b1);color:var(--muted)}\n"
".rule-table td:first-child{color:var(--text)}\n"
".rule-table td.v,.rule-table td.mono{font-family:var(--font);color:var(--em);font-variant-numeric:tabular-nums;font-weight:500}\n"
".rule-table td.gold{color:var(--gold)}\n"
".rule-table tr:last-child td{border-bottom:0}\n"
".rule-table tr:hover td{background:#1A1D1A}\n"
".lede{color:var(--muted);font-size:14.5px;margin-bottom:22px;max-width:720px}\n"
".call{padding:18px 22px;background:#141614;border:1px solid var(--b1);border-radius:8px;margin:14px 0;font-size:13.5px;color:var(--muted);line-height:1.7}\n"
".call.keep{background:linear-gradient(170deg,rgba(50,240,110,.06),rgba(50,240,110,.015)),#141614}\n"
".call.lose{background:linear-gradient(170deg,rgba(255,100,112,.07),rgba(255,100,112,.018)),#141614}\n"
".call strong{color:var(--text)}\n"
".call h4{color:#fff;font-size:14px;margin-bottom:6px;letter-spacing:-.1px}\n"
".example{background:#141614;border:1px solid var(--b1);border-radius:8px;padding:20px 22px;margin:16px 0;font-family:var(--font);font-size:12.5px;line-height:1.8;color:var(--muted)}\n"
".example .k{color:var(--muted2)}\n"
".example .good{color:var(--em)}\n"
".example .bad{color:var(--red)}\n"
"code{font-family:var(--font);font-size:12.5px;color:var(--em);background:var(--em-dim);padding:1px 6px;border-radius:3px}\n"
".crumbs{font-size:12px;color:var(--muted2);margin-bottom:14px;font-family:var(--font)}\n"
".crumbs a{color:var(--muted)}\n"
".crumbs a:hover{color:var(--em)}\n"
".pager{display:flex;gap:6px}\n"
".pager a{font-family:var(--font);font-size:12px;padding:6px 10px;border:1px solid var(--b1);border-radius:5px;color:var(--muted);background:#141614}\n"
".pager a:hover{border-color:var(--em);color:var(--em)}\n"
".pager a.cur{background:var(--em-dim);color:var(--em);border-color:rgba(50,240,110,.25)}\n"
".md{display:grid;grid-template-columns:1fr 1fr;gap:0}\n"
".md .row{display:grid;grid-template-columns:160px 1fr;padding:10px 22px;border-bottom:1px solid var(--b1);font-size:13px;align-items:baseline}\n"
".md .row:nth-child(odd){border-right:1px solid var(--b1)}\n"
".md .k{font-size:11px;color:var(--muted2);letter-spacing:1.3px;text-transform:uppercase;font-weight:600}\n"
".md .v{font-family:var(--font);color:var(--text);word-break:break-all;font-variant-numeric:tabular-nums}\n"
".md .v.em{color:var(--em)}\n"
".md .v.mono-sm{font-size:12px;color:var(--muted)}\n"
".cb{padding:16px 22px}\n"
".cb .sum-top{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:12px}\n"
".cb .sum-top .lbl{font-size:11.5px;color:var(--muted2);text-transform:uppercase;letter-spacing:1.5px;font-weight:600}\n"
".cb .sum-top .v{font-family:var(--font);font-size:22px;color:var(--em);font-variant-numeric:tabular-nums}\n"
".split{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}\n"
".split .s{background:#141614;border:1px solid var(--b1);border-radius:6px;padding:12px 14px}\n"
".split .s .l{font-size:10.5px;letter-spacing:1.5px;color:var(--muted2);text-transform:uppercase;font-weight:600;margin-bottom:4px}\n"
".split .s .val{font-family:var(--font);font-size:15px;color:var(--text);font-variant-numeric:tabular-nums}\n"
".split .s .to{font-family:var(--font);font-size:11px;color:var(--muted2);margin-top:2px}\n"
".txs .tx{padding:14px 22px;border-bottom:1px solid var(--b1);display:grid;grid-template-columns:140px 1fr;gap:20px;align-items:start}\n"
".txs .tx:last-child{border-bottom:0}\n"
".tx-meta{font-size:12px;color:var(--muted2)}\n"
".tx-meta .txid{font-family:var(--font);font-size:11.5px;color:var(--muted);word-break:break-all}\n"
".tx-meta .type{display:inline-block;padding:2px 8px;border-radius:10px;font-family:var(--font);font-size:10px;background:var(--em-dim);color:var(--em);text-transform:uppercase;letter-spacing:1px;margin-bottom:5px}\n"
".tx-meta .type.reg{background:rgba(255,216,74,.08);color:var(--gold)}\n"
".tx-io{display:grid;grid-template-columns:1fr 28px 1fr;gap:14px;font-family:var(--font);font-size:12px}\n"
".io-side{background:#141614;border:1px solid var(--b1);border-radius:6px;padding:10px 12px}\n"
".io-side .row{display:flex;justify-content:space-between;padding:3px 0;color:var(--muted)}\n"
".io-side .row .amt{color:var(--em);font-variant-numeric:tabular-nums}\n"
".io-side.in .row .amt{color:var(--red)}\n"
".io-side .hdr{font-size:10.5px;letter-spacing:1.5px;color:var(--muted2);text-transform:uppercase;font-weight:600;margin-bottom:6px;font-family:var(--sans)}\n"
".io-arrow{display:flex;align-items:center;justify-content:center;color:var(--muted2);font-size:16px}\n"
"@media (max-width:900px){.md{grid-template-columns:1fr}.md .row:nth-child(odd){border-right:0}.split{grid-template-columns:repeat(2,1fr)}.txs .tx{grid-template-columns:1fr!important}.tx-io{grid-template-columns:1fr!important}.io-arrow{transform:rotate(90deg)}}\n"
R"COBCSS(
/* =====================================================================
    v6 — Cobalt + Veld green + teal unifier (Explorer)
   Matches wallet palette: cobalt blue / indigo / teal (unifier) /
   Veld emerald (brand green) / sky / cyan. No orange, violet, magenta.
   ===================================================================== */
:root{--cob-1:#3B82F6;--cob-2:#6366F1;--cob-3:#14B8A6;--cob-4:#32F06E;--cob-5:#0EA5E9;--cob-6:#06B6D4;--cob-bal:linear-gradient(90deg,#3B82F6 0%,#14B8A6 55%,#32F06E 100%);--cob-c1:linear-gradient(135deg,#3B82F6,#1E40FF);--cob-c2:linear-gradient(135deg,#06B6D4,#0891B2);--cob-c3:linear-gradient(135deg,#6366F1,#4338CA);--cob-c4:linear-gradient(135deg,#14B8A6,#32F06E)}
html[data-theme="light"]{
  --bg:#F7F7F7!important;--s1:#FFFFFF!important;--s2:#FAFAFA!important;--s3:#EFEFEF!important;
  --b1:#D2D4D3!important;--b2:#C2C6C4!important;--b3:#A9AFAC!important;
  --text:#121514!important;--muted:#4F5753!important;--muted2:#696F6C!important;
  --em:#15803D!important;--em2:#166534!important;--em-dim:rgba(50,240,110,.10)!important;--em-dark:rgba(50,240,110,.06)!important;
  --gold:#0F766E!important;--blue:#0EA5E9!important;--purple:#4338CA!important;--red:#DC2626!important;
  --border:rgba(15,23,42,.08)!important;--border2:rgba(15,23,42,.14)!important
}
html[data-theme="light"] body{background:var(--bg)!important;color:var(--text)!important}

/* Theme toggle button */
.theme-tog{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:14px;background:var(--s2);border:1px solid var(--b1);color:var(--text);font-family:var(--sans);font-size:11px;font-weight:600;letter-spacing:.5px;cursor:pointer;line-height:1;transition:background .15s,border-color .15s;margin-top:10px}
.theme-tog:hover{background:var(--s3);border-color:var(--b2)}
.theme-tog .ti{font-size:13px}
html[data-theme="light"] .theme-tog{background:#FAFAFA!important;border-color:#CFD1D0!important;color:#121514!important}
html[data-theme="light"] .theme-tog:hover{background:#E8E9E8!important}

/* Cobalt-gradient page headings */
.page-title,.ptitle,.pheader,.page-hd,h1.page-title,h1.pheader{background:var(--cob-bal)!important;-webkit-background-clip:text!important;background-clip:text!important;-webkit-text-fill-color:transparent!important;color:transparent!important;font-weight:700!important}

/* Stat-value accent classes mapped to new palette.
   .em → Veld emerald (brand green back), .gold → teal (unifier),
   .blue → sky, .purple → indigo. */
.stat-value.em,.val.em,.stat .v.em{color:var(--cob-4)!important}
.stat-value.gold,.val.gold,.stat .v.gold{color:var(--cob-3)!important}
.stat-value.blue,.val.blue,.stat .v.blue{color:var(--cob-1)!important}
.stat-value.purple,.val.purple,.stat .v.purple{color:var(--cob-2)!important}

/* Sans-serif heavy numbers everywhere (match wallet typography) */
.stat-value,.val,.stat .val,.stat .v,.balance-amount,.countdown{font-family:var(--sans)!important;font-weight:700!important;letter-spacing:-.5px!important;font-variant-numeric:tabular-nums!important}
.stat-value,.stat .val{font-size:30px!important;font-weight:700!important;letter-spacing:-.6px!important;line-height:1.05!important}
.stat-label,.stat .lbl{font-size:11px!important;text-transform:uppercase!important;letter-spacing:1.4px!important;font-weight:700!important;color:var(--muted)!important;margin-bottom:8px!important}
.stat-sub,.stat .sub{font-size:11.5px!important;color:var(--muted2)!important;margin-top:6px!important}
.card{border-radius:20px!important;padding:22px!important}
.stat{border-radius:16px!important;padding:18px 16px!important}
.page-title,h1.pheader,h1.page-hd,.pheader{font-size:32px!important;font-weight:800!important;letter-spacing:-.7px!important}
@media (max-width:600px){.page-title,h1.pheader,.pheader{font-size:26px!important}}

/* ========== Explorer hero rebuild — featured stat + quick-nav ========== */
.explorer-search-card{padding:14px!important;border-radius:18px!important}
.hero-search-input::placeholder{color:var(--muted2)!important}
.hero-search-input:focus{border-color:var(--cob-1)!important;box-shadow:0 0 0 3px rgba(59,130,246,.14)!important}
html[data-theme="light"] .hero-search-input{background:#FAFAFA!important;border-color:var(--b1)!important;color:var(--text)!important}

.explorer-hero{position:relative;overflow:hidden}
.explorer-hero-big{font-family:var(--sans)!important;font-size:64px!important;font-weight:800!important;letter-spacing:-2.4px!important;line-height:1.0!important;background:var(--cob-bal)!important;-webkit-background-clip:text!important;background-clip:text!important;-webkit-text-fill-color:transparent!important;color:transparent!important;font-variant-numeric:tabular-nums!important}
@media(max-width:600px){.explorer-hero-big{font-size:52px!important;letter-spacing:-2px!important}}
.explorer-hero-meta{display:flex;align-items:center;justify-content:center;gap:8px;margin-top:10px;flex-wrap:wrap}
.hero-pill{background:var(--em-dim)!important;color:var(--em)!important;font-size:12px!important;font-weight:700!important;padding:3px 9px!important;border-radius:14px!important;letter-spacing:.3px!important}
.hero-sub{color:var(--muted)!important;font-size:13px!important;font-weight:600!important}

/* 4-button quick-nav (mirrors wallet pattern) */
.explorer-quicknav{display:flex;gap:22px;justify-content:center;flex-wrap:wrap}
.explorer-quicknav .ar{display:flex;flex-direction:column;align-items:center;gap:7px;text-decoration:none;color:var(--text)!important;cursor:pointer;background:transparent!important;border:none!important}
.explorer-quicknav .ar .ic{width:56px;height:56px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;font-family:var(--sans);box-shadow:0 8px 18px rgba(0,0,0,.28);transition:transform .14s ease,box-shadow .14s ease}
.explorer-quicknav .ar:hover .ic{transform:translateY(-2px);box-shadow:0 12px 22px rgba(0,0,0,.36)}
.explorer-quicknav .ar .lbl{font-size:12px;font-weight:700;color:var(--text);letter-spacing:.2px}
/* Dark mode: all 4 buttons monochrome Veld emerald */
.explorer-quicknav .ar.explorer-blk .ic,
.explorer-quicknav .ar.explorer-val .ic,
.explorer-quicknav .ar.explorer-rich .ic,
.explorer-quicknav .ar.explorer-mp .ic{background:linear-gradient(135deg,#32F06E,#1F8A52);color:#0B1410}
/* Light mode: full color variety per button */
html[data-theme="light"] .explorer-quicknav .ar.explorer-blk .ic{background:linear-gradient(135deg,#3B82F6,#1E40FF)!important;color:#FFF!important}
html[data-theme="light"] .explorer-quicknav .ar.explorer-val .ic{background:linear-gradient(135deg,#6366F1,#4338CA)!important;color:#FFF!important}
html[data-theme="light"] .explorer-quicknav .ar.explorer-rich .ic{background:linear-gradient(135deg,#14B8A6,#0F766E)!important;color:#FFF!important}
html[data-theme="light"] .explorer-quicknav .ar.explorer-mp .ic{background:linear-gradient(135deg,#06B6D4,#0891B2)!important;color:#FFF!important}
html[data-theme="light"] .explorer-quicknav .ar .ic{box-shadow:0 6px 16px rgba(59,130,246,.20)!important}

/* Recent Blocks table polish */
.tbl#blocks-tbl{border-collapse:separate;border-spacing:0 4px}
.tbl#blocks-tbl tbody tr{transition:background .12s ease}
.tbl#blocks-tbl tbody tr:hover{background:var(--em-dim)!important}
html[data-theme="light"] .tbl#blocks-tbl tbody tr:hover{background:#F0F1F0!important}

/* ========== Global table polish (validators / rich / address / tx) ========== */
.tbl{font-family:var(--sans)!important;border-collapse:separate!important;border-spacing:0!important;width:100%!important}
.tbl th{font-size:10.5px!important;font-weight:700!important;text-transform:uppercase!important;letter-spacing:1.2px!important;color:var(--muted)!important;padding:12px 14px!important;border-bottom:1px solid var(--b1)!important;background:transparent!important;text-align:left!important}
.tbl td{padding:14px!important;border-bottom:1px solid var(--b1)!important;font-size:13px!important;color:var(--text)!important;vertical-align:middle!important}
.tbl tbody tr{transition:background .12s ease}
.tbl tbody tr:hover td{background:var(--em-dim)!important}
html[data-theme="light"] .tbl tbody tr:hover td{background:#F0F1F0!important}
.tbl td a.hash,.tbl td a.addr,.tbl td .hash,.tbl td .addr{font-family:'JetBrains Mono','SF Mono',ui-monospace,monospace!important;font-size:12px!important}
.tbl td.mono,.tbl td .mono{font-family:'JetBrains Mono','SF Mono',ui-monospace,monospace!important;font-variant-numeric:tabular-nums!important}
.tbl-scroll{overflow-x:auto;border-radius:14px;border:1px solid var(--b1)}

/* Light-mode polish for tables + cards */
html[data-theme="light"] .tbl th{color:var(--muted)!important;border-bottom:1px solid var(--b1)!important}
html[data-theme="light"] .tbl td{color:var(--text)!important;border-bottom:1px solid var(--b1)!important}

/* Inputs across the explorer (Jump-to-height, etc.) match wallet style */
input[type="number"],input[type="text"],input[type="search"],select,textarea{background:var(--s2);color:var(--text);border:1px solid var(--b1);border-radius:12px;padding:10px 14px;font-size:13px;font-family:var(--sans);outline:none;transition:border-color .12s,box-shadow .12s}
input[type="number"]:focus,input[type="text"]:focus,input[type="search"]:focus,select:focus,textarea:focus{border-color:var(--cob-1);box-shadow:0 0 0 3px rgba(59,130,246,.14)}
html[data-theme="light"] input[type="number"],html[data-theme="light"] input[type="text"],html[data-theme="light"] select,html[data-theme="light"] textarea{background:#FFF;border-color:var(--b1)}

/* veld-btn-ghost outline-style button (used in pagination, jump, etc.) */
.veld-btn-ghost{background:transparent!important;color:var(--text)!important;border:1px solid var(--b2)!important;padding:9px 14px!important;border-radius:12px!important;font-size:12.5px!important;font-weight:600!important;cursor:pointer;transition:background .12s,border-color .12s,color .12s;font-family:var(--sans)!important}
.veld-btn-ghost:hover:not(:disabled){background:var(--s2)!important;border-color:var(--cob-1)!important;color:var(--cob-1)!important}
.veld-btn-ghost:disabled{opacity:.4!important;cursor:not-allowed!important}

/* ========== Wallet-matched row-list pattern ========== */
.row-list{display:flex;flex-direction:column}
.rl-row{display:flex;align-items:center;gap:14px;padding:13px 4px;border-top:1px solid var(--b1);min-height:62px;text-decoration:none;color:inherit}
.rl-row:first-child{border-top:none}
.rl-row:hover{background:var(--em-dim)}
html[data-theme="light"] .rl-row:hover{background:#F0F1F0}
.rl-ic{width:42px;height:42px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:15px;font-family:var(--sans);flex-shrink:0;letter-spacing:-.4px;box-shadow:0 0 0 1px var(--b1);color:#0B1410}
/* DARK mode: all icons monochrome Veld emerald */
.rl-ic.ic-h,.rl-ic.ic-s,.rl-ic.ic-v,.rl-ic.ic-d,.rl-ic.ic-m,.rl-ic.ic-p,.rl-ic.ic-x,.rl-ic.ic-r,.rl-ic.ic-b{background:linear-gradient(135deg,#32F06E,#1F8A52)!important;color:#0B1410!important}
/* LIGHT mode: varied per stat */
html[data-theme="light"] .rl-ic.ic-h{background:linear-gradient(135deg,#3B82F6,#1E40FF)!important;color:#FFF!important}
html[data-theme="light"] .rl-ic.ic-s{background:linear-gradient(135deg,#6366F1,#4338CA)!important;color:#FFF!important}
html[data-theme="light"] .rl-ic.ic-v{background:linear-gradient(135deg,#14B8A6,#0F766E)!important;color:#FFF!important}
html[data-theme="light"] .rl-ic.ic-d{background:linear-gradient(135deg,#0EA5E9,#0284C7)!important;color:#FFF!important}
html[data-theme="light"] .rl-ic.ic-m{background:linear-gradient(135deg,#06B6D4,#0891B2)!important;color:#FFF!important}
html[data-theme="light"] .rl-ic.ic-p{background:linear-gradient(135deg,#818CF8,#4F46E5)!important;color:#FFF!important}
html[data-theme="light"] .rl-ic.ic-x{background:linear-gradient(135deg,#3B82F6,#1E40FF)!important;color:#FFF!important}
html[data-theme="light"] .rl-ic.ic-r{background:linear-gradient(135deg,#14B8A6,#0F766E)!important;color:#FFF!important}
html[data-theme="light"] .rl-ic.ic-b{background:linear-gradient(135deg,#32F06E,#1F8A52)!important;color:#06251A!important}
.rl-info{flex:1;min-width:0}
.rl-name{font-size:15px;font-weight:700;color:var(--text);letter-spacing:-.2px;line-height:1.2}
.rl-sub{font-size:12.5px;color:var(--muted);margin-top:3px;font-weight:500;line-height:1.3}
.rl-val{text-align:right;flex-shrink:0}
.rl-v{font-size:18px;font-weight:800;color:var(--text);font-family:var(--sans);font-variant-numeric:tabular-nums;letter-spacing:-.4px;line-height:1.05}
.rl-vs{font-size:11px;font-weight:700;color:var(--muted2);margin-top:3px;text-transform:uppercase;letter-spacing:1.2px}

/* Supply Progress slim bar inside row-list card */
.supply-bar-wrap{padding:6px 4px 14px}
/* UI-5: substantial bar; fill always visible (min-width nub) even at ~0.2%; fitted static gradient+glow; theme-correct. */
.supply-bar-track{height:16px;background:var(--s3);border-radius:99px;overflow:hidden;margin-bottom:10px;box-shadow:inset 0 1px 3px rgba(0,0,0,.28);position:relative}
/* Supply is a tiny fraction of the 21M cap for years, so the fill is very
   narrow early on. A 240%-oversized shimmering gradient on a ~14px nub looked
   like a flickering glitch ("broken bar"). Use a fitted static gradient + a
   clean rounded min-width cap so the near-zero state reads as intentional. */
.supply-bar-fill{height:100%;min-width:12px;background:linear-gradient(90deg,#1FAE55,#32F06E 70%,#7BF0AE);background-size:100% 100%;border-radius:99px;transition:width .8s cubic-bezier(.22,1,.36,1);box-shadow:0 0 10px rgba(50,240,110,.5),inset 0 1px 0 rgba(255,255,255,.35)}
html[data-theme="light"] .supply-bar-fill{background:linear-gradient(90deg,#2563EB,#14B8A6 70%,#16A34A);box-shadow:0 0 10px rgba(20,184,166,.45),inset 0 1px 0 rgba(255,255,255,.5)}
.supply-bar-meta{display:flex;justify-content:space-between;align-items:baseline;font-size:12px;color:var(--muted);font-weight:600;font-variant-numeric:tabular-nums}
.supply-bar-meta b{color:var(--text);font-weight:700;font-variant-numeric:tabular-nums}

@media (max-width:600px){
  .rl-row{gap:12px;padding:12px 4px;min-height:56px}
  .rl-ic{width:38px;height:38px;font-size:14px}
  .rl-name{font-size:14.5px}
  .rl-sub{font-size:12px}
  .rl-v{font-size:17px}
}

/* Dark mode uses Veld emerald; light mode uses the full palette. */
:root{
  --em:#7ED949!important;--em2:#7ED949!important;
  --em-dim:rgba(126,217,73,.10)!important;--em-dark:rgba(126,217,73,.06)!important;
  --gold:#7ED949!important;--blue:#7ED949!important;--purple:#7ED949!important;
  --cob-1:#7ED949!important;--cob-2:#7ED949!important;
  --cob-3:#7ED949!important;--cob-4:#7ED949!important;
  --cob-5:#7ED949!important;--cob-6:#7ED949!important;
  --cob-bal:linear-gradient(90deg,#7ED949 0%,#7ED949 100%)!important;
  --cob-c1:linear-gradient(135deg,#7ED949,#7ED949)!important;
  --cob-c2:linear-gradient(135deg,#7ED949,#7ED949)!important;
  --cob-c3:linear-gradient(135deg,#7ED949,#7ED949)!important;
  --cob-c4:linear-gradient(135deg,#7ED949,#7ED949)!important;
}
html[data-theme="light"]{
  --em:#168B4B!important;--em2:#11743E!important;
  --em-dim:#ECEEED!important;--em-dark:#F3F4F3!important;
  --gold:#0F766E!important;--blue:#0EA5E9!important;--purple:#4338CA!important;
  --cob-1:#3B82F6!important;--cob-2:#6366F1!important;
  --cob-3:#14B8A6!important;--cob-4:#32F06E!important;
  --cob-5:#0EA5E9!important;--cob-6:#06B6D4!important;
  --cob-bal:linear-gradient(90deg,#3B82F6 0%,#14B8A6 55%,#32F06E 100%)!important;
  --cob-c1:linear-gradient(135deg,#3B82F6,#1E40FF)!important;
  --cob-c2:linear-gradient(135deg,#06B6D4,#0891B2)!important;
  --cob-c3:linear-gradient(135deg,#6366F1,#4338CA)!important;
  --cob-c4:linear-gradient(135deg,#14B8A6,#32F06E)!important;
}
html:not([data-theme="light"]) #explorer-mobile-nav,
html:not([data-theme="light"]) .nav-bar{border-top-color:rgba(126,217,73,.15)!important}
html:not([data-theme="light"]) .mob-tab.active .mob-icon,
html:not([data-theme="light"]) .nb-tab.active .ic{filter:drop-shadow(0 0 10px rgba(126,217,73,.30))!important}

/* Primary buttons */
.veld-btn,.btn-gold,.btn-em{background:linear-gradient(135deg,var(--cob-1),var(--cob-2))!important;color:#FFF!important;border:none!important;box-shadow:0 4px 12px rgba(59,130,246,.20)!important;font-weight:600!important}
.veld-btn:hover,.btn-gold:hover,.btn-em:hover{background:linear-gradient(135deg,#1E40FF,var(--cob-2))!important;box-shadow:0 8px 22px rgba(59,130,246,.32)!important}

/* Card radius bump */
.card{border-radius:16px!important}

/* Light-mode container overrides */
html[data-theme="light"] .main,html[data-theme="light"] .container{background:transparent!important;color:var(--text)!important}
html[data-theme="light"] .card{background:#FFF!important;border-color:var(--b1)!important;color:var(--text)!important}
html[data-theme="light"] .card-title{color:var(--text)!important}
html[data-theme="light"] h1,html[data-theme="light"] h2,html[data-theme="light"] h3,html[data-theme="light"] h4,html[data-theme="light"] h5{color:var(--text)!important}
html[data-theme="light"] .page-title,html[data-theme="light"] .ptitle,html[data-theme="light"] .pheader,html[data-theme="light"] .page-hd,html[data-theme="light"] h1.page-title,html[data-theme="light"] h1.pheader{color:transparent!important}

/* Sidebar */
html[data-theme="light"] .sidebar{background:#FFF!important;border-right:1px solid var(--b1)!important}
html[data-theme="light"] .nav a,html[data-theme="light"] .nav .item{color:var(--text)!important}
html[data-theme="light"] .nav a:hover,html[data-theme="light"] .nav .item:hover{background:#E8E9E8!important;color:#168B4B!important}
html[data-theme="light"] .nav a.active,html[data-theme="light"] .nav .item.active{background:#E2E4E3!important;color:#168B4B!important}
html[data-theme="light"] .logo,html[data-theme="light"] .logo span{color:#121514!important}
html[data-theme="light"] .logo-sub{color:var(--muted)!important}
html[data-theme="light"] .sidebar-btn{background:#FFF!important;color:var(--text)!important;border:1px solid var(--b1)!important}
html[data-theme="light"] .sidebar-btn:hover{background:#E8E9E8!important;border-color:#AEB4B1!important}
html[data-theme="light"] .sidebar-btn-em{background:linear-gradient(135deg,var(--cob-1),var(--cob-2))!important;color:#FFF!important;border:none!important}

/* Search bar */
html[data-theme="light"] .search-bar{background:#FFF!important;border-bottom:1px solid var(--b1)!important}
html[data-theme="light"] .search-bar input{background:#FFF!important;color:var(--text)!important;border:1px solid var(--b1)!important}
html[data-theme="light"] .search-bar button{background:linear-gradient(135deg,var(--cob-1),var(--cob-2))!important;color:#FFF!important;border:none!important}

/* Stats */
html[data-theme="light"] .stat{background:#FFF!important;border-color:var(--b1)!important;color:var(--text)!important}
html[data-theme="light"] .stat-label{color:var(--muted)!important}
html[data-theme="light"] .stat-sub{color:var(--muted2)!important}

/* Tables */
html[data-theme="light"] .tbl,html[data-theme="light"] table{background:#FFF!important;color:var(--text)!important;border-color:var(--b1)!important}
html[data-theme="light"] .tbl th,html[data-theme="light"] table th{background:#F3F3F3!important;color:var(--text)!important;border-bottom:1px solid var(--b1)!important}
html[data-theme="light"] .tbl td,html[data-theme="light"] table td{color:var(--text)!important;border-color:var(--b1)!important}
html[data-theme="light"] .tbl tr:hover td,html[data-theme="light"] table tr:hover td{background:#F0F1F0!important}
html[data-theme="light"] .hash,html[data-theme="light"] .addr{color:var(--cob-1)!important}

/* Inputs */
html[data-theme="light"] input,html[data-theme="light"] select,html[data-theme="light"] textarea{background:#FFF!important;color:var(--text)!important;border:1px solid var(--b1)!important}
html[data-theme="light"] input::placeholder,html[data-theme="light"] textarea::placeholder{color:var(--muted2)!important}
html[data-theme="light"] input:focus,html[data-theme="light"] select:focus,html[data-theme="light"] textarea:focus{border-color:var(--cob-1)!important;box-shadow:0 0 0 3px rgba(59,130,246,.14)!important;outline:none!important}

/* Mobile nav */
html[data-theme="light"] #explorer-mobile-nav,html[data-theme="light"] .mob-nav{background:#FFF!important;border-bottom:1px solid var(--b1)!important}
html[data-theme="light"] .mob-tab{background:#FAFAFA!important;color:var(--text)!important;border:1px solid var(--b1)!important}
html[data-theme="light"] .mob-tab.on{background:#E2E4E3!important;color:#168B4B!important}
html[data-theme="light"] .mob-logo,html[data-theme="light"] .mob-logo span{color:#121514!important}

/* Footer */
html[data-theme="light"] .footer{background:#FFF!important;border-top:1px solid var(--b1)!important;color:var(--muted)!important}

/* Feed items, ticker */
html[data-theme="light"] .feed-item,html[data-theme="light"] .fi{background:#FFF!important;color:var(--text)!important;border:1px solid var(--b1)!important}
html[data-theme="light"] .feed-item:hover,html[data-theme="light"] .fi:hover{background:#F0F1F0!important}
html[data-theme="light"] .ticker,html[data-theme="light"] .tk{background:#FFF!important;border:1px solid var(--b1)!important}
html[data-theme="light"] .tk-label{color:var(--muted)!important}
html[data-theme="light"] .tk-price,html[data-theme="light"] .tk-val{color:var(--text)!important}

/* Breadcrumbs / crumbs */
html[data-theme="light"] .crumbs,html[data-theme="light"] .crumb{color:var(--muted)!important}
html[data-theme="light"] .crumbs a{color:var(--cob-1)!important}

/* Hash-orange links remain BTC orange in both modes (per established rule) */
)COBCSS"
"</style>\n"
        "<script nonce=\"__CSP_NONCE__\">\n"
        "(function(){\n"
        "  var theme='dark';\n"
        "  try {\n"
        "    var saved=localStorage.getItem('veld_theme');\n"
        "    if(saved==='light'||saved==='dark') theme=saved;\n"
        "    else if(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches) theme='light';\n"
        "  } catch(_){}\n"
        "  document.documentElement.dataset.theme=theme;\n"
        "  // Use DOM insertion rather than attribute mutation. Some iOS\n"
        "  // builds only re-read theme-color when the meta element is inserted.\n"
        "  window.veldSyncThemeColor=function(t){\n"
        "    var color = t==='light' ? '#EFEFEF' : '#020302';\n"
        "    var metas = document.querySelectorAll('meta[name=\"theme-color\"]');\n"
        "    for (var i=0;i<metas.length;i++){ try{ metas[i].parentNode.removeChild(metas[i]); } catch(_){} }\n"
        "    var m = document.createElement('meta');\n"
        "    m.setAttribute('name','theme-color');\n"
        "    m.setAttribute('content',color);\n"
        "    if (document.head.firstChild) document.head.insertBefore(m, document.head.firstChild);\n"
        "    else document.head.appendChild(m);\n"
        "  };\n"
        "  window.veldSyncThemeColor(theme);\n"
        "  document.addEventListener('DOMContentLoaded',function(){\n"
        "    var btn=document.getElementById('theme-tog'); if(!btn) return;\n"
        "    var t=document.documentElement.dataset.theme||'dark';\n"
        "    var ic=btn.querySelector('.ti'); var lb=btn.querySelector('.tl');\n"
        "    if(ic) ic.textContent = t==='light' ? '\xE2\x98\x80' : '\xE2\x98\xBE';\n"
        "    if(lb) lb.textContent = t==='light' ? 'LIGHT' : 'DARK';\n"
        "  });\n"
        "  window.toggleVeldTheme=function(){\n"
        "    var d=document.documentElement;\n"
        "    var n=d.dataset.theme==='light'?'dark':'light';\n"
        "    d.dataset.theme=n;\n"
        "    try{localStorage.setItem('veld_theme',n);}catch(_){}\n"
        "    if(window.veldSyncThemeColor) window.veldSyncThemeColor(n);\n"
        "    var btn=document.getElementById('theme-tog');\n"
        "    if(btn){var ic=btn.querySelector('.ti'); var lb=btn.querySelector('.tl');\n"
        "      if(ic) ic.textContent = n==='light' ? '\xE2\x98\x80' : '\xE2\x98\xBE';\n"
        "      if(lb) lb.textContent = n==='light' ? 'LIGHT' : 'DARK';\n"
        "    }\n"
        "    if(window.veldApplyExplorerAccents) window.veldApplyExplorerAccents(n);\n"
        "  };\n"
        "  // Apply chromatic distribution accents across\n"
        "  // every explorer page. Mirrors the wallet's veldApplyDashAccents:\n"
        "  // inline !important styles on known IDs so the CSS cascade can\n"
        "  // never override (the iOS PWA workaround). Cobalt = current\n"
        "  // state / chain identity / active counts. Violet = pending /\n"
        "  // forward-looking / countdowns. Other values default to the\n"
        "  // class-driven teal (em → --cob-3) or Veld emerald (gold →\n"
        "  // --cob-4) palette. Dark mode clears the inline styles so the\n"
        "  // original class colors apply.\n"
        "  window.veldApplyExplorerAccents=function(t){\n"
        "    var COBALT='#3B82F6';\n"
        "    var COBALT_SHADOW='0 1px 3px rgba(59,130,246,.22)';\n"
        "    var VIOLET='#8B5CF6';\n"
        "    var VIOLET_SHADOW='0 1px 3px rgba(139,92,246,.22)';\n"
        "    var cobaltIds=[\n"
        "      's-height-big',     // Landing hero: Block Height\n"
        "      's-height',         // Landing network row: block height\n"
        "      's-phase',          // Landing: phase / activation state\n"
        "      's-peers',          // Landing: connected peers (current)\n"
        "      'st-active',        // Staking: active stakers\n"
        "      'minetier',         // Mining tier page: current tier\n"
        "      'difficulty',       // Block detail: difficulty\n"
        "      'endorse'           // Block detail: endorser count\n"
        "    ];\n"
        "    var violetIds=[\n"
        "      's-mempool',         // Landing: mempool pending count\n"
        "      'multiplier',        // Mining: current reward multiplier\n"
        "      'stakelock',         // Mining tier: lockup multiplier\n"
        "      'poolflush'          // Mining tier: pool flush countdown\n"
        "    ];\n"
        "    function apply(id,color,shadow){\n"
        "      var el=document.getElementById(id); if(!el) return;\n"
        "      if(t==='light'){\n"
        "        el.style.setProperty('color',color,'important');\n"
        "        if(shadow) el.style.setProperty('text-shadow',shadow,'important');\n"
        "      } else {\n"
        "        el.style.removeProperty('color');\n"
        "        el.style.removeProperty('text-shadow');\n"
        "      }\n"
        "    }\n"
        "    cobaltIds.forEach(function(id){apply(id,COBALT,COBALT_SHADOW);});\n"
        "    violetIds.forEach(function(id){apply(id,VIOLET,VIOLET_SHADOW);});\n"
        "  };\n"
        "  document.addEventListener('DOMContentLoaded',function(){\n"
        "    try{ window.veldApplyExplorerAccents(document.documentElement.dataset.theme||'dark'); }catch(_){}\n"
        "  });\n"
        "  // Some explorer pages re-render stats via setInterval (e.g. /api/stats\n"
        "  // ticking #s-height every 2s on the Landing page). Those updates use\n"
        "  // textContent which preserves inline style, so we only need to apply\n"
        "  // accents ONCE per load — they survive subsequent text refreshes.\n"
        "})();\n"
        "</script>\n"
        "</head>\n"
        "<body>\n";

    std::string mob_nav_html;
    for (int i = 0; i < 9; ++i) {
        std::string href = nav_items[i].empty() ? "/" : "/" + nav_items[i];
        bool active = (active_nav == nav_items[i]);
        mob_nav_html += "<a href=\"" + href + "\"" + (active ? " class=\"active\"" : "") + ">" + nav_labels[i] + "</a>";
    }
    mob_nav_html += "<a href=\"https://wallet.veld.network\">Wallet</a>";

    struct MobTab { const char* icon; const char* label; const char* href; };
    MobTab main_tabs[] = {
        {"&#x25A6;",  "Home",    "/"},
        {"&#x229E;",  "Blocks",  "/blocks"},
        {"&#x2B21;",  "Staking", "/staking"},
        {"&#x2713;",  "Validate","/validators"},
    };
    std::string bottom_nav_html = "<nav id=\"explorer-mobile-nav\">\n";
    for (auto& t : main_tabs) {
        std::string href_str = t.href;
        bool act = (href_str == "/" && active_nav.empty()) ||
                   (!active_nav.empty() && href_str == "/" + active_nav);
        bottom_nav_html += std::string("  <a href=\"") + t.href + "\" class=\"mob-tab" + (act ? " active" : "") + "\">"
            + "<span class=\"mob-icon\">" + t.icon + "</span><span class=\"mob-label\">" + t.label + "</span></a>\n";
    }
    bottom_nav_html += "  <button class=\"mob-tab\" data-act-click=\"ef4b2d1c3\">"
        "<span class=\"mob-icon\">&#x22EF;</span><span class=\"mob-label\">More</span></button>\n"
        "</nav>\n";

    struct MoreItem { const char* icon; const char* label; const char* href; };
    MoreItem more_items[] = {
        {"&#x25C8;", "Vault",      "/vault"},
        {"&#x2B22;", "Mining",     "/mining"},
        {"&#x2606;", "Rich",       "/rich"},
        {"&#x21BB;", "Mempool",    "/mempool"},
        {"&#x2261;",  "Rules",      "/rules"},
        {"&#x25B3;",  "Wallet",     "https://wallet.veld.network"},
    };
    bottom_nav_html += "<div id=\"explorer-more-menu\">\n<div style=\"display:grid;grid-template-columns:repeat(3,1fr);gap:10px\">\n";
    for (auto& m : more_items) {
        std::string tgt = (std::string(m.href).find("http") == 0) ? " target=\"_blank\"" : "";
        bottom_nav_html += std::string("  <a href=\"") + m.href + "\" class=\"mob-more-btn\"" + tgt + ">"
            + "<span style=\"font-size:18px\">" + m.icon + "</span><span>" + m.label + "</span></a>\n";
    }
    bottom_nav_html += "</div>\n</div>\n";

    std::string mob_header_html =
        "<div class=\"mob-header\">\n"
        "  <a href=\"/\" class=\"mob-logo\">VELD<span>.</span></a>\n"
        "</div>\n"
        + bottom_nav_html;

    std::string header_html = mob_header_html + "<div class=\"sidebar\">\n"
        "  <div class=\"logo-wrap\">\n"
        "    <a href=\"/\" class=\"logo\">VELD<span>.</span></a>\n"
        "    <div class=\"logo-sub\">Block Explorer</div>\n"
        "    <button id=\"theme-tog\" class=\"theme-tog\" data-act-click=\"etog_theme\" title=\"Toggle light / dark mode\" type=\"button\"><span class=\"ti\">\xE2\x98\xBE</span><span class=\"tl\">DARK</span></button>\n"
        "  </div>\n"
        "  <nav class=\"nav\">" + nav_html + "</nav>\n"
        "  <div class=\"sidebar-links\">\n"
        "    <a href=\"https://wallet.veld.network\" class=\"sidebar-btn\">Wallet</a>\n"
        "  </div>\n"
        "</div>\n"
        "<div class=\"main\">\n"
        "  <div class=\"search-bar\">\n"
        "    <input id=\"gsearch\" placeholder=\"Search block, tx, or address...\" autocomplete=\"off\">\n"
        "    <button data-act-click=\"ec2e03555\">&#9166;</button>\n"
        "  </div>\n"
        "  <div class=\"container\">\n";

    std::string footer_html = "  </div>\n"
        "</div>\n"
        "<footer class=\"footer\" style=\"margin-left:240px\">\n"
        "  <a href=\"https://veld.network\" style=\"color:var(--muted);text-decoration:none\">veld.network</a> &nbsp;&middot;&nbsp; <a href=\"https://wallet.veld.network\" style=\"color:var(--muted);text-decoration:none\">Wallet</a>\n"
        "</footer>\n"
        "<script nonce=\"__CSP_NONCE__\">\n"
        "function escHtml(s){var d=document.createElement('div');d.appendChild(document.createTextNode(s));return d.innerHTML;}\n"
        "function doSearch(){\n"
        "  var q=document.getElementById(\'gsearch\').value.trim();\n"
        "  if(!q)return;\n"
        "  var eq=encodeURIComponent(q);\n"
        "  if(/^[0-9a-f]{64}$/i.test(q)){location.href=\'/block/\'+eq;return;}\n"
        "  if(/^\\d+$/.test(q)){location.href=\'/block/height/\'+eq;return;}\n"
        "  if(q[0]===\'V\'){location.href=\'/address/\'+eq;return;}\n"
        "  location.href=\'/tx/\'+eq;\n"
        "}\n"
        "document.getElementById(\'gsearch\').addEventListener(\'keydown\',function(e){if(e.key===\'Enter\')doSearch();});\n"
        "function fmt(n,dec){return parseFloat(n).toLocaleString(\'en-US\',{minimumFractionDigits:dec!==undefined?dec:2,maximumFractionDigits:dec!==undefined?dec:2});}\n"
        "function shortHash(h){return h?h.slice(0,8)+\'...\'+h.slice(-6):\'\';}\n"
        "function toggleExplorerMore(){var m=document.getElementById(\'explorer-more-menu\');m.style.display=m.style.display===\'block\'?\'none\':\'block\';}\n"
        "document.addEventListener(\'click\',function(e){var m=document.getElementById(\'explorer-more-menu\');if(m&&m.style.display===\'block\'&&!e.target.closest(\'#explorer-more-menu\')&&!e.target.closest(\'[data-act-click=\\\"ef4b2d1c3\\\"]\'))m.style.display=\'none\';});\n"
        "</script>\n"
        "<script nonce=\"__CSP_NONCE__\">\n"
        + std::string(veld::explorer_dispatch::kDispatchJs) +
        "\n</script>\n"
        "<script nonce=\"__CSP_NONCE__\">\n"
        "(function(){\n"
        "  var FNS = ['loadSupply','loadHistory','loadTicker','loadOrderBook',\n"
        "             'loadProposals','loadStats','loadBlocks','loadPage',\n"
        "             'loadAddressPage','loadBlockPage','loadTxPage',\n"
        "             'loadValidators','loadMempool','loadStaking','loadVault',\n"
        "             'loadRich','loadMining','loadMiningPage','loadDashboard',\n"
        "             'loadRichList','loadValidatorsPage','loadMempoolPage'];\n"
        "  var _last = 0;\n"
        "  function wake(){\n"
        "    var now = Date.now();\n"
        "    if (now - _last < 800) return;  // debounce coalesced events\n"
        "    _last = now;\n"
        "    for (var i = 0; i < FNS.length; i++) {\n"
        "      var f = window[FNS[i]];\n"
        "      if (typeof f === 'function') { try { f(); } catch(_){} }\n"
        "    }\n"
        "  }\n"
        "  document.addEventListener('visibilitychange', function(){\n"
        "    if (document.visibilityState === 'visible') wake();\n"
        "  });\n"
        "  window.addEventListener('pageshow', function(e){\n"
        "    // BFCache restoration on iOS Safari\n"
        "    if (e.persisted) wake();\n"
        "  });\n"
        "  window.addEventListener('focus', wake);\n"
        "  // While visible, top up every 15s in case the page-local timers\n"
        "  // were paused at any point. Browsers don't fire visibilitychange\n"
        "  // for some lock-screen→unlock paths on Android; this catches those.\n"
        "  setInterval(function(){ if (!document.hidden) wake(); }, 15000);\n"
        "})();\n"
        "</script>\n"
        "</body>\n"
        "</html>\n";

    return head + header_html + content + footer_html;
}

class BlockExplorer {
public:
    BlockExplorer(Blockchain& chain, Mempool& mempool,
                  uint16_t port = CompiledPublicExplorerPort())
        : chain_(chain), mempool_(mempool), port_(port), running_(false),
          fd_(veld::compat::kInvalidSocket), tokens_(nullptr),
          rpc_delegate_(nullptr), validators_(nullptr), tiers_(nullptr) {}

    void SetTokenLedger(OnChainTokenLedger* t) { tokens_ = t; }
    void SetRpcDelegate(RpcServer* rpc) { rpc_delegate_ = rpc; }
    void SetValidators(ValidatorRegistry* v) { validators_ = v; }
    void SetTiers(TierEngine* t) { tiers_ = t; }
    void SetCacheDir(const std::string& dir) {
        cache_dir_ = dir;
        LoadTrustedProxyConfiguration_();
    }
    bool ConfigureTrustedProxy(const std::string& peer,
                               const std::string& token_file,
                               std::string* error = nullptr) {
        if (running_.load(std::memory_order_acquire)) {
            if (error) *error = "cannot change proxy trust while explorer is running";
            return false;
        }
        net::trusted_proxy::Configuration replacement;
        if (!net::trusted_proxy::Configure(replacement, peer, token_file, error))
            return false;
        trusted_proxy_.peer = std::move(replacement.peer);
        trusted_proxy_.token = replacement.token;
        trusted_proxy_.enabled = true;
        proxy_configuration_error_.clear();
        return true;
    }
    const std::string& ProxyConfigurationError() const noexcept {
        return proxy_configuration_error_;
    }
    void PrewarmRichList() {
        // A persisted HTML body cannot prove which active-chain height produced
        // it. Rebuild from the current chain instead of briefly serving stale
        // balances after startup or a reorganization.
        std::lock_guard<std::mutex> lk(prewarm_thread_mu_);
        if (prewarm_thread_.joinable()) prewarm_thread_.join();
        prewarm_thread_ = std::thread([this]() {
            try { (void)ServeRichList(); }
            catch (...) {  }
        });
    }
    void SetNetworkHeightFn(std::function<uint64_t()> fn) { network_height_fn_ = fn; }
    void SetPeerCountFn(std::function<size_t()> fn) { peer_count_fn_ = std::move(fn); }
    size_t LivePeerCount() const { return peer_count_fn_ ? peer_count_fn_() : 0; }

    struct PeerStatsItem { std::string ip; uint64_t mempool_size; uint32_t peer_count; int64_t age_s; };
    void SetPeerStatsFn(std::function<std::vector<PeerStatsItem>()> fn) {
        peer_stats_fn_ = std::move(fn);
    }
    void SetAddressHistoryFn(
            std::function<std::string(const std::string&, size_t,
                                      const std::string&)> fn) {
        address_history_fn_ = std::move(fn);
    }
    std::vector<PeerStatsItem> LivePeerStats() const {
        return peer_stats_fn_ ? peer_stats_fn_() : std::vector<PeerStatsItem>{};
    }
    uint64_t BestKnownHeight() const {
        uint64_t local = chain_.Height();
        if (network_height_fn_) return std::max(local, network_height_fn_());
        return local;
    }
    ~BlockExplorer() { Stop(); }

    bool Start(const std::function<bool()>& activation_guard = {}) {
        activation_guard_refused_.store(false, std::memory_order_release);
        if (running_.load(std::memory_order_acquire) || server_thread_.joinable())
            return false;
        if (!veld::net::ListenerActivationPermitted(activation_guard)) {
            activation_guard_refused_.store(true, std::memory_order_release);
            return false;
        }
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (!veld::compat::IsValidSocket(fd_)) return false;

        int opt = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port        = htons(port_);

        if (::bind(fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            VELD_CLOSE_SOCKET(fd_); fd_ = veld::compat::kInvalidSocket; return false;
        }
        if (!veld::net::ListenerActivationPermitted(activation_guard)) {
            activation_guard_refused_.store(true, std::memory_order_release);
            VELD_CLOSE_SOCKET(fd_); fd_ = veld::compat::kInvalidSocket; return false;
        }
        if (::listen(fd_, 16) < 0) {
            VELD_CLOSE_SOCKET(fd_); fd_ = veld::compat::kInvalidSocket; return false;
        }

        if (!veld::net::ListenerActivationPermitted(activation_guard)) {
            activation_guard_refused_.store(true, std::memory_order_release);
            VELD_CLOSE_SOCKET(fd_); fd_ = veld::compat::kInvalidSocket; return false;
        }

        running_ = true;
        try {
            server_thread_ = std::thread(&BlockExplorer::ServeLoop, this);
        } catch (...) {
            running_ = false;
            VELD_CLOSE_SOCKET(fd_);
            fd_ = veld::compat::kInvalidSocket;
            return false;
        }
        return true;
    }

    bool ActivationGuardRefused() const noexcept {
        return activation_guard_refused_.load(std::memory_order_acquire);
    }

    void Stop() {
        running_ = false;
        // close() in one thread is not required to interrupt another thread's
        // blocking accept() on Linux.  The full-node AMM regression exposed
        // this as an otherwise unbounded VeldNode::Stop hang.  shutdown()
        // wakes the acceptor deterministically; close then releases the fd.
        if (veld::compat::IsValidSocket(fd_)) {
#ifdef _WIN32
            ::shutdown((SOCKET)fd_, SD_BOTH);
#else
            ::shutdown(fd_, SHUT_RDWR);
#endif
            VELD_CLOSE_SOCKET(fd_);
        }
        if (server_thread_.joinable()) server_thread_.join();
        fd_ = veld::compat::kInvalidSocket;
        JoinRequestWorkers();
        std::thread prewarm;
        {
            std::lock_guard<std::mutex> lk(prewarm_thread_mu_);
            if (prewarm_thread_.joinable())
                prewarm = std::move(prewarm_thread_);
        }
        if (prewarm.joinable()) prewarm.join();
    }

    bool IsRunning() const { return running_.load(); }
    uint16_t Port()  const { return port_; }

    HttpResponse Route(const HttpRequest& req) {
        const auto& parts = req.path_parts;

        auto urlParam = [&](const std::string& key) -> std::string {
            auto p = req.path.find(key + "=");
            if (p == std::string::npos) return "";
            auto start = p + key.size() + 1;
            auto end   = req.path.find('&', start);
            std::string raw = req.path.substr(start, end == std::string::npos ? std::string::npos : end - start);
            std::string out;
            out.reserve(raw.size());
            for (size_t i = 0; i < raw.size(); ++i) {
                char c = raw[i];
                if (c == '+') {
                    out.push_back(' ');
                } else if (c == '%' && i + 2 < raw.size()) {
                    auto hex = [](char h) -> int {
                        if (h >= '0' && h <= '9') return h - '0';
                        if (h >= 'a' && h <= 'f') return 10 + (h - 'a');
                        if (h >= 'A' && h <= 'F') return 10 + (h - 'A');
                        return -1;
                    };
                    int hi = hex(raw[i+1]), lo = hex(raw[i+2]);
                    if (hi >= 0 && lo >= 0) {
                        out.push_back((char)((hi << 4) | lo));
                        i += 2;
                    } else {
                        out.push_back(c);
                    }
                } else {
                    out.push_back(c);
                }
            }
            return out;
        };

        if (parts.empty() || req.path == "/")
            return ServeLanding();

        if (parts.size() == 1 && parts[0] == "wallet")
            return HttpResponse::HTML("<script nonce=\"__CSP_NONCE__\">window.location.replace('https://wallet.veld.network');</script>");
        if (parts.size() == 1 && (parts[0] == "exchange" || parts[0] == "tokens"))
            return HttpResponse::HTML("<script nonce=\"__CSP_NONCE__\">window.location='/';</script>");
        if (parts.size() == 1 && parts[0] == "tiers")
            return HttpResponse::HTML("<script nonce=\"__CSP_NONCE__\">window.location='/mining';</script>");
        if (parts.size() == 1 && parts[0] == "mining")
            return ServeMiningPage();
        if (parts.size() == 1 && parts[0] == "governance")
            return HttpResponse::HTML("<script nonce=\"__CSP_NONCE__\">window.location='/';</script>");
        if (parts.size() == 1 && parts[0] == "staking")
            return ServeStaking();
        if (parts.size() == 1 && parts[0] == "vault")
            return ServeVaultPage();
        if (parts.size() == 1 && parts[0] == "rich")
            return ServeRichList();
        if (parts.size() == 1 && parts[0] == "blocks")
            return ServeBlocksPage();
        if (parts.size() == 1 && parts[0] == "validators")
            return ServeValidatorsPage();
        if (parts.size() == 1 && parts[0] == "mempool")
            return ServeMempoolPage();
        if (parts.size() == 1 && parts[0] == "rules")
            return ServeRulesPage();
        if (parts.size() == 1 && parts[0] == "manifest.json") {
            std::string m = R"({"id":"/","name":"Veld Explorer","short_name":"Explorer","description":"Veld blockchain explorer","start_url":"/","scope":"/","display":"standalone","display_override":["standalone","minimal-ui"],"background_color":"#0A0B0A","theme_color":"#0A0B0A","icons":[{"src":"/icon-192.png?v=20260819veldgradient1","sizes":"192x192","type":"image/png","purpose":"any maskable"},{"src":"/icon-512.png?v=20260819veldgradient1","sizes":"512x512","type":"image/png","purpose":"any maskable"}]})";
            return HttpResponse::Binary(m, "application/manifest+json");
        }
        if (parts.size() == 1 && parts[0] == "sw.js") {
            static const std::string sw = R"VLDSW(
const CACHE_PREFIX = 'veld-explorer-shell-';
const CACHE = 'veld-explorer-shell-ui-20260903-navigation-fallback';
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.addAll(['/', '/blocks']))
      .then(() => self.skipWaiting())
  );
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(
    keys.filter(key => key.startsWith(CACHE_PREFIX))
        .map(key => caches.delete(key))
  )).then(() => self.clients.claim()));
});
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  if (event.request.mode === 'navigate' || event.request.destination === 'document') {
    event.respondWith((async () => {
      const cache = await caches.open(CACHE);
      const url = new URL(event.request.url);
      const canonical = new Request(url.origin + url.pathname, {
        method: 'GET', credentials: 'same-origin'
      });
      try {
        const response = await fetch(event.request, {cache:'no-store'});
        if (response.ok) {
          await cache.put(canonical, response.clone());
          return response;
        }
        const saved = await cache.match(canonical)
          || (url.pathname === '/blocks' ? await cache.match('/blocks') : null)
          || await cache.match('/');
        return saved || response;
      } catch (_) {
        return await cache.match(canonical)
          || (url.pathname === '/blocks' ? await cache.match('/blocks') : null)
          || await cache.match('/');
      }
    })());
  }
});
)VLDSW";
            return HttpResponse::Binary(sw, "application/javascript; charset=utf-8");
        }
        if (parts.size() == 1 && parts[0] == "icon-192.png") {
#if 0
            static const std::string b64_192 = "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";
#endif
            static const std::string png_192 = base64_decode(
                veld::explorer_assets::icon_192_b64);
            return HttpResponse::Binary(png_192, "image/png");
        }

        if (parts.size() == 1 && parts[0] == "icon-512.png") {
#if 0
            static const std::string b64_512 = "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";
#endif
            static const std::string png_512 = base64_decode(
                veld::explorer_assets::icon_512_b64);
            return HttpResponse::Binary(png_512, "image/png");
        }

        if (parts.size() == 1 && parts[0] == "icon.svg") {
            static const std::string svg =
                "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"512\" height=\"512\" viewBox=\"0 0 512 512\">"
                "<image href=\"/icon-512.png?v=20260819veldgradient1\" width=\"512\" height=\"512\"/></svg>";
            return HttpResponse::Binary(svg, "image/svg+xml");
        }

        if (parts.size() >= 3 && parts[0] == "api" && parts[1] == "v1") {
            const std::string& resource = parts[2];

            if (resource == "stats")
                return ServeAPIStats();

            if (resource == "topology")
                return ServeTopologySnapshot();

            if (resource == "staking" && rpc_delegate_) {
                auto resp = rpc_delegate_->Handle("{\"jsonrpc\":\"2.0\",\"id\":\"1\","
                    "\"method\":\"getstakinginfo\",\"params\":[]}");
                auto ri = resp.find("\"result\":");
                if (ri != std::string::npos) {
                    auto obj_start = resp.find('{', ri + 9);
                    if (obj_start != std::string::npos) {
                        int depth = 1; size_t pos = obj_start + 1;
                        while (pos < resp.size() && depth > 0) {
                            if (resp[pos] == '{') ++depth;
                            else if (resp[pos] == '}') --depth;
                            ++pos;
                        }
                        return HttpResponse::JSON(resp.substr(obj_start, pos - obj_start));
                    }
                }
                return HttpResponse::JSON(resp);
            }

            if (resource == "vault") {
                uint64_t height   = chain_.Height();
                const std::string& cur_vault = VaultAddressAtHeight(height);
                auto vault_script = AddressToScript(cur_vault);
                double vault_bal  = (double)chain_.GetBalance(vault_script) / VELD_UNITS;
                std::ostringstream j;
                j << std::fixed << std::setprecision(8);
                j << "{\"address\":\"" << cur_vault << "\","
                  << "\"balance_veld\":" << vault_bal << ","
                  << "\"next_distribution_in\":" << (VAULT_DISTRIBUTION_INTERVAL - height % VAULT_DISTRIBUTION_INTERVAL) << ","
                  << "\"next_vault_block_in\":" << (VAULT_BLOCK_INTERVAL - height % VAULT_BLOCK_INTERVAL) << "}";
                return HttpResponse::JSON(j.str());
            }

            if (resource == "address" && parts.size() >= 4) {
                std::string addr = parts[3];
                if (!IsStrictBase58Address(addr))
                    return HttpResponse::JSON("{\"error\":\"invalid address\"}");
                auto script = AddressToScript(addr);
                double balance = 0.0;
                std::vector<UTXO> utxos_list;
                if (!script.empty()) {
                    utxos_list = chain_.GetUTXOsForScript(script);
                    for (auto& u : utxos_list) balance += (double)u.value / VELD_UNITS;
                }
                std::string script_hex;
                if (script.size() == 25) script_hex = BytesToHex(script);
                uint64_t blocks_mined = chain_.GetBlocksMined(script_hex);
                int tier = 0; double mult = 1.0; std::string tier_name = "Seedling";
                if (tiers_ && !script_hex.empty()) {
                    auto ti = tiers_->GetTier(script_hex);
                    tier = ti.level;
                    mult = ti.multiplier;
                    tier_name = ti.name.empty() ? std::string("Seedling") : ti.name;
                }
                double staked_veld = 0.0;
                if (rpc_delegate_) {
                    std::string esc_addr = HttpResponse::JsonEscape(addr);
                    auto sr = rpc_delegate_->Handle("{\"jsonrpc\":\"2.0\",\"id\":\"1\","
                        "\"method\":\"getstake\",\"params\":[\"" + esc_addr + "\"]}");
                    auto ri = sr.find("\"staked_veld\":");
                    if (ri != std::string::npos) {
                        auto s = ri + 14, e = sr.find_first_of(",}", s);
                        try { staked_veld = std::stod(sr.substr(s, e-s)); } catch (...) {}
                    } else {
                        auto ri2 = sr.find("\"result\":");
                        if (ri2 != std::string::npos) {
                            auto s = ri2 + 9, e = sr.find_first_of(",}", s);
                            try { staked_veld = std::stod(sr.substr(s, e-s)); } catch (...) {}
                        }
                    }
                }
                std::ostringstream j;
                j << std::fixed << std::setprecision(8);
                j << "{\"address\":\"" << HttpResponse::JsonEscape(addr) << "\""
                  << ",\"balance_veld\":" << balance
                  << ",\"utxo_count\":" << utxos_list.size()
                  << ",\"blocks_mined\":" << blocks_mined
                  << ",\"tier\":" << tier
                  << ",\"tier_name\":\"" << tier_name << "\""
                  << ",\"multiplier\":" << std::setprecision(2) << mult
                  << ",\"staked_veld\":" << std::setprecision(8) << staked_veld
                  << ",\"is_vault\":" << ((addr == VAULT_ADDRESS) ? "true" : "false")
                  << ",\"utxos\":[";
                std::sort(utxos_list.begin(), utxos_list.end(),
                    [](const UTXO& a, const UTXO& b){ return a.value > b.value; });
                size_t json_cap = std::min(utxos_list.size(), (size_t)50);
                bool fu = true;
                for (size_t ui = 0; ui < json_cap; ++ui) {
                    auto& u = utxos_list[ui];
                    if (!fu) j << ",";
                    j << "{\"txid\":\"" << HashToHex(u.tx_hash) << "\""
                      << ",\"vout\":" << u.output_index
                      << ",\"value\":" << std::setprecision(8) << (double)u.value/VELD_UNITS
                      << ",\"block\":" << u.block_height << "}";
                    fu = false;
                }
                j << "]}";
                return HttpResponse::JSON(j.str());
            }

            if (resource == "balance" && parts.size() >= 4) {
                if (!IsStrictBase58Address(parts[3]))
                    return HttpResponse::JSON("{\"error\":\"invalid address\"}", 400);
                auto script = AddressToScript(parts[3]);
                double bal  = script.empty() ? 0.0 : (double)chain_.GetBalance(script) / VELD_UNITS;
                std::ostringstream j;
                j << std::fixed << std::setprecision(8);
                j << "{\"address\":\"" << HttpResponse::JsonEscape(parts[3]) << "\",\"balance_veld\":" << bal << "}";
                return HttpResponse::JSON(j.str());
            }

            if (resource == "addresshistory" && parts.size() == 5) {
                uint64_t limit = 0;
                if (!ParseExplorerHeight_(parts[4], limit) || limit == 0 ||
                    limit > 50)
                    return HttpResponse::JSON(
                        "{\"error\":\"limit must be an integer from 1 to 50\"}",
                        400);
                if (!address_history_fn_)
                    return HttpResponse::JSON(
                        "{\"error\":\"address history index unavailable\"}",
                        503);
                try {
                    std::string body = address_history_fn_(
                        parts[3], static_cast<size_t>(limit), "");
                    if (body.size() > 32768)
                        return HttpResponse::JSON(
                            "{\"error\":\"address history response exceeded bound\"}",
                            503);
                    return HttpResponse::JSON(body);
                } catch (const std::invalid_argument& e) {
                    return HttpResponse::JSON(
                        "{\"error\":\"" +
                        HttpResponse::JsonEscape(e.what()) + "\"}", 400);
                } catch (const std::exception& e) {
                    return HttpResponse::JSON(
                        "{\"error\":\"" +
                        HttpResponse::JsonEscape(e.what()) + "\"}", 503);
                }
            }

            // One bounded request serves a complete history page.  The old UI
            // issued 25 individual block requests, which exhausted the
            // per-client safety budget after only a few pages when requests
            // arrived through one reverse-proxy identity.
            if (resource == "blocks" && parts.size() == 5) {
                uint64_t limit_u64 = 0;
                if (!ParseExplorerHeight_(parts[4], limit_u64)
                        || limit_u64 == 0 || limit_u64 > 50) {
                    return HttpResponse::JSON(
                        "{\"error\":\"limit must be an integer from 1 to 50\"}",
                        400);
                }

                const uint64_t tip_before = chain_.Height();
                Block tip_block_before;
                try {
                    tip_block_before = chain_.GetBlock(tip_before);
                } catch (...) {
                    return HttpResponse::JSON(
                        "{\"error\":\"canonical chain is not ready\"}", 503);
                }
                const std::string tip_hash_before =
                    HashToHex(tip_block_before.GetHash());

                uint64_t start = tip_before;
                if (parts[3] != "latest") {
                    if (!ParseExplorerHeight_(parts[3], start)) {
                        return HttpResponse::JSON(
                            "{\"error\":\"start height must be an integer or latest\"}",
                            400);
                    }
                    if (start > tip_before) {
                        return HttpResponse::JSON(
                            "{\"error\":\"requested page is newer than the current tip\"}",
                            409);
                    }
                }

                const uint64_t count = std::min<uint64_t>(limit_u64, start + 1);
                const uint64_t end = start + 1 - count;
                std::vector<Block> ascending;
                try {
                    ascending = chain_.GetBlockRange(
                        end, static_cast<size_t>(count));
                } catch (...) {
                    return HttpResponse::JSON(
                        "{\"error\":\"canonical block page is unavailable\"}", 503);
                }
                if (ascending.size() != static_cast<size_t>(count)) {
                    return HttpResponse::JSON(
                        "{\"error\":\"canonical block page is incomplete\"}", 503);
                }

                const uint64_t tip_after = chain_.Height();
                std::string tip_hash_after;
                try {
                    tip_hash_after = HashToHex(chain_.GetBlock(tip_after).GetHash());
                } catch (...) {
                    return HttpResponse::JSON(
                        "{\"error\":\"canonical chain changed during page assembly\"}",
                        409);
                }
                if (tip_after != tip_before || tip_hash_after != tip_hash_before) {
                    return HttpResponse::JSON(
                        "{\"error\":\"canonical chain changed during page assembly\"}",
                        409);
                }

                std::ostringstream json;
                json << "{\"tip_height\":" << tip_before
                     << ",\"tip_hash\":\"" << tip_hash_before << "\""
                     << ",\"start\":" << start
                     << ",\"end\":" << end
                     << ",\"blocks\":[";
                for (size_t i = ascending.size(); i > 0; --i) {
                    if (i != ascending.size()) json << ",";
                    json << BlockToJSON_(ascending[i - 1], false);
                }
                json << "]}";
                return HttpResponse::JSON(json.str());
            }

            if (resource == "blocks") {
                return HttpResponse::JSON(
                    "{\"error\":\"expected /api/v1/blocks/<start|latest>/<limit>\"}",
                    400);
            }

            if (resource == "block" && parts.size() >= 4) {
                uint64_t height = 0;
                if (ParseExplorerHeight_(parts[3], height)) {
                    try {
                        return HttpResponse::JSON(
                            BlockToJSON_(chain_.GetBlock(height), true));
                    } catch (...) {
                        return HttpResponse::NotFound(
                            "block at height " + parts[3]);
                    }
                }
                Hash256 hash = HexToHash(parts[3]);
                auto block = chain_.GetBlockByHash(hash);
                if (!block) return HttpResponse::NotFound("block " + parts[3]);
                return HttpResponse::JSON(BlockToJSON_(*block, true));
            }

            // Machine-readable per-block event feed (added for the
            // Discord bot + any external indexer): classifies each tx by its
            // protocol marker and lists credited outputs, so consumers never
            // re-implement marker parsing. GET /api/v1/events/<height>
            if (resource == "events" && parts.size() >= 4) {
                uint64_t h = 0;
                try { h = std::stoull(parts[3]); }
                catch (...) { return HttpResponse::JSON("{\"error\":\"height required\"}", 400); }
                Block b;
                try { b = chain_.GetBlock(h); }
                catch (...) { return HttpResponse::NotFound("block at height " + parts[3]); }
                auto payload_of = [](const Transaction& tx) -> std::string {
                    for (const auto& o : tx.outputs) {
                        const auto& sp = o.script_pubkey;
                        if (sp.size() < 3 || sp[0] != 0x6A) continue;
                        size_t di = 1, dlen = 0;
                        if (sp[di] <= 75) { dlen = sp[di++]; }
                        else if (sp[di] == 0x4C && di + 1 < sp.size()) { di++; dlen = sp[di++]; }
                        else if (sp[di] == 0x4D && di + 2 < sp.size()) { di++; dlen = sp[di] | (sp[di+1] << 8); di += 2; }
                        if (dlen == 0 || di + dlen > sp.size()) continue;
                        return std::string(sp.begin() + di, sp.begin() + di + dlen);
                    }
                    return "";
                };
                auto classify = [](const std::string& d) -> std::string {
                    if (d.empty()) return "transfer";
                    if (d.find("VELD_DIST|STAKING")     != std::string::npos) return "staking_distribution";
                    if (d.find("VELD_DIST|ENDORSEMENT") != std::string::npos) return "endorsement_distribution";
                    if (d.find("VELD_DIST|COMINE")      != std::string::npos) return "comine_distribution";
                    if (d.rfind("VELD_TOKEN|M", 0) == 0) return "btcveld_mint";
                    if (d.rfind("VELD_TOKEN|R", 0) == 0) return "btcveld_redeem";
                    if (d.rfind("VELD_TOKEN|T", 0) == 0) return "btcveld_transfer";
                    if (d.rfind("VELD_TOKEN|",  0) == 0) return "btcveld_op";
                    if (d.rfind("VELD_MSPV|",   0) == 0) return "btcveld_spv_mint";
                    if (d.rfind("VELD_AMM|",    0) == 0) return "amm_op";
                    if (d.rfind("VELD_ANCHOR|", 0) == 0) return "anchor_post";
                    if (d.rfind("VELD_BHDR|",   0) == 0) return "btc_header_relay";
                    if (d.rfind("VELD_FRAUD|",  0) == 0) return "fraud_proof";
                    if (d.find("VELD_VALIDATOR|SLASH|") != std::string::npos) return "slash_evidence";
                    if (d.find("VELD_VALIDATOR|ENDORSE") != std::string::npos) return "endorsement";
                    if (d.find("VELD_VALIDATOR|REGISTER") != std::string::npos) return "validator_register";
                    if (d.find("VELD_VALIDATOR|DEREGISTER") != std::string::npos) return "validator_deregister";
                    if (d.rfind("VELD_STAKE|LOCK", 0) == 0) return "stake_lock";
                    if (d.rfind("VELD_STAKE|UNLOCK", 0) == 0) return "stake_unlock";
                    if (d.rfind("VELD_GOV|", 0) == 0) return "governance";
                    if (d.size() >= NMS_MAGIC_LEN &&
                        std::memcmp(d.data(), NMS_MAGIC, NMS_MAGIC_LEN) == 0) return "near_miss";
                    return "transfer";
                };
                std::ostringstream j;
                j << std::fixed << std::setprecision(8);
                j << "{\"height\":" << h << ",\"time\":" << (uint64_t)b.header.timestamp << ",\"events\":[";
                bool first_ev = true;
                for (const auto& tx : b.transactions) {
                    std::string type = tx.IsCoinbase() ? "coinbase" : classify(payload_of(tx));
                    if (!first_ev) j << ",";
                    first_ev = false;
                    j << "{\"txid\":\"" << HashToHex(tx.GetTxID()) << "\",\"type\":\"" << type << "\",\"credited\":[";
                    bool first_o = true;
                    for (const auto& o : tx.outputs) {
                        if (o.value == 0) continue;
                        std::string addr = ScriptToAddress(o.script_pubkey);
                        if (addr.empty()) continue;                    // OP_RETURN / non-standard
                        bool proto = (addr == VAULT_ADDRESS ||
                                      addr == POOL_ADDRESS || addr == ENDORSEMENT_POOL_ADDRESS);
                        if (!first_o) j << ",";
                        first_o = false;
                        j << "{\"address\":\"" << addr << "\",\"veld\":"
                          << ((double)o.value / VELD_UNITS)
                          << ",\"protocol\":" << (proto ? "true" : "false") << "}";
                    }
                    j << "]}";
                }
                j << "]}";
                return HttpResponse::JSON(j.str());
            }

            if (resource == "richlist") {
                const uint64_t richlist_height = chain_.Height();
                {
                    std::lock_guard<std::mutex> lk(richlist_json_cache_mu_);
                    if (!richlist_json_cache_body_.empty()
                        && richlist_json_cache_height_ == richlist_height
                        && std::chrono::steady_clock::now() < richlist_json_cache_until_) {
                        return HttpResponse::JSON(richlist_json_cache_body_);
                    }
                }
                auto holders = chain_.GetTopHolders(50);
                auto pin_addr = [&](const std::string& addr) {
                    for (const auto& [a, b] : holders) {
                        if (a == addr) return;
                    }
                    auto script = AddressToScript(addr);
                    double bal = (double)chain_.GetBalance(script) / VELD_UNITS;
                    holders.push_back(std::make_pair(addr, bal));
                };
                pin_addr(VAULT_ADDRESS);
                pin_addr(STAKE_VAULT_ADDRESS);
                pin_addr(BOND_YIELD_ESCROW);
                pin_addr(POOL_ADDRESS);
                pin_addr(ENDORSEMENT_POOL_ADDRESS);
                auto sys_rank = [](const std::string& a) -> int {
                    if (a == VAULT_ADDRESS)            return 0;
                    if (a == STAKE_VAULT_ADDRESS)      return 1;
                    if (a == BOND_YIELD_ESCROW)        return 2;
                    if (a == POOL_ADDRESS)             return 3;
                    if (a == ENDORSEMENT_POOL_ADDRESS) return 4;
                    return 100;
                };
                std::sort(holders.begin(), holders.end(),
                    [&](const auto& a, const auto& b) {
                        int ra = sys_rank(a.first), rb = sys_rank(b.first);
                        if (ra != rb) return ra < rb;
                        return a.second > b.second;
                    });
                double total_supply = chain_.TotalSupplyVeld();
                std::ostringstream j;
                j << std::fixed << std::setprecision(8);
                j << "[";
                bool first = true;
                int rank = 0;
                for (const auto& [addr, bal] : holders) {
                    if (!first) j << ",";
                    double pct = total_supply > 0 ? bal / total_supply * 100.0 : 0.0;
                    bool is_sys = (addr == VAULT_ADDRESS
                                || addr == STAKE_VAULT_ADDRESS
                                || addr == BOND_YIELD_ESCROW
                                || addr == POOL_ADDRESS
                                || addr == ENDORSEMENT_POOL_ADDRESS);
                    if (is_sys) {
                        j << "{\"rank\":null,\"is_system\":true"
                          << ",\"address\":\"" << addr << "\""
                          << ",\"balance_veld\":" << std::setprecision(8) << bal
                          << ",\"pct_supply\":" << std::setprecision(4) << pct << "}";
                    } else {
                        ++rank;
                        j << "{\"rank\":" << rank
                          << ",\"address\":\"" << addr << "\""
                          << ",\"balance_veld\":" << std::setprecision(8) << bal
                          << ",\"pct_supply\":" << std::setprecision(4) << pct << "}";
                    }
                    first = false;
                }
                j << "]";
                std::string body = j.str();
                if (chain_.Height() == richlist_height) {
                    std::lock_guard<std::mutex> lk(richlist_json_cache_mu_);
                    richlist_json_cache_body_ = body;
                    richlist_json_cache_height_ = richlist_height;
                    richlist_json_cache_until_ = std::chrono::steady_clock::now()
                                               + std::chrono::seconds(30);
                }
                return HttpResponse::JSON(body);
            }

            if (resource == "pool") {
                if (rpc_delegate_) {
                    std::string req = R"({"jsonrpc":"2.0","id":1,"method":"getpoolinfo","params":[]})";
                    std::string resp = rpc_delegate_->Handle(req);
                    auto rs = resp.find("\"result\":");
                    auto re = resp.rfind(",\"error\"");
                    if (rs != std::string::npos && re != std::string::npos)
                        return HttpResponse::JSON(resp.substr(rs + 9, re - rs - 9));
                    return HttpResponse::JSON(resp);
                }
                return HttpResponse::JSON("{\"window_blocks\":100,\"distribution_interval\":100}");
            }

            if (resource == "tier" && parts.size() >= 4) {
                if (!IsStrictBase58Address(parts[3]))
                    return HttpResponse::JSON("{\"error\":\"invalid address\"}", 400);
                auto script = AddressToScript(parts[3]);
                std::ostringstream hex;
                for (uint8_t b : script)
                    hex << std::hex << std::setw(2) << std::setfill('0') << (int)b;
                std::string script_hex = hex.str();
                uint64_t mined = chain_.GetBlocksMined(script_hex);
                int tier = 0;
                double mult = 1.0;
                std::string tier_name = "Seedling";
                if (tiers_) {
                    auto t = tiers_->GetTier(script_hex);
                    tier = t.level;
                    mult = t.multiplier;
                    if (!t.name.empty()) tier_name = t.name;
                }
                std::ostringstream j;
                j << std::fixed << std::setprecision(2);
                j << "{\"address\":\"" << HttpResponse::JsonEscape(parts[3]) << "\","
                  << "\"tier\":" << tier << ","
                  << "\"tier_name\":\"" << tier_name << "\","
                  << "\"multiplier\":" << mult << ","
                  << "\"blocks_mined\":" << mined << "}";
                return HttpResponse::JSON(j.str());
            }

            return HttpResponse::NotFound("REST resource not found");
        }

        if (parts.size() == 2 && parts[0] == "api" && parts[1] == "stats")
            return ServeAPIStats();

        if (parts.size() == 2 && parts[0] == "api" && parts[1] == "mempool")
            return ServeAPIMempool();

        if (parts.size() == 2 && parts[0] == "api" && parts[1] == "mining")
            return ServeAPIMining();

        if (parts.size() == 2 && parts[0] == "api" && parts[1].substr(0, 7) == "balance") {
            std::string addr = urlParam("address");
            if (!IsStrictBase58Address(addr))
                return HttpResponse::JSON("{\"error\":\"invalid address\"}", 400);
            auto script = AddressToScript(addr);
            double bal = 0.0;
            if (!script.empty()) {
                auto utxos = chain_.GetUTXOsForScript(script);
                for (auto& u : utxos) bal += (double)u.value / VELD_UNITS;
            }
            std::ostringstream j;
            j << "{\"address\":\"" << HttpResponse::JsonEscape(addr) << "\",\"balance\":" << std::fixed << std::setprecision(8) << bal << "}";
            return HttpResponse::JSON(j.str());
        }

        if (parts.size() == 2 && parts[0] == "api" && parts[1].substr(0, 5) == "utxos") {
            std::string addr = urlParam("address");
            if (!IsStrictBase58Address(addr))
                return HttpResponse::JSON("{\"utxos\":[]}");
            auto script = AddressToScript(addr);
            std::vector<UTXO> utxos;
            if (!script.empty()) utxos = chain_.GetUTXOsForScript(script);
            std::string items;
            items.reserve(std::min<size_t>(
                EXPLORER_MAX_RESPONSE_BODY / 2,
                utxos.size() > 4096 ? EXPLORER_MAX_RESPONSE_BODY / 2
                                    : utxos.size() * 128));
            bool truncated = false;
            if (!script.empty()) {
                const uint64_t tip_ = chain_.Height();
                bool first = true;
                for (auto& u : utxos) {
                    uint64_t confs_ = (u.block_height <= tip_) ? (tip_ - u.block_height + 1) : 0;
                    std::ostringstream item;
                    item << "{\"txid\":\"" << HashToHex(u.tx_hash) << "\""
                         << ",\"vout\":" << u.output_index
                         << ",\"value\":" << std::fixed << std::setprecision(8)
                         << (double)u.value / VELD_UNITS
                         << ",\"confirmations\":" << confs_ << "}";
                    const std::string encoded = item.str();
                    const size_t prefix = first ? 0 : 1;
                    // Leave ample space for the object trailer and count.
                    if (items.size() + prefix + encoded.size() + 128 >
                        EXPLORER_MAX_RESPONSE_BODY) {
                        truncated = true;
                        break;
                    }
                    if (!first) items.push_back(',');
                    items += encoded;
                    first = false;
                }
            }
            std::ostringstream j;
            j << "{\"utxos\":[" << items << "],\"total\":" << utxos.size()
              << ",\"truncated\":" << (truncated ? "true" : "false") << "}";
            return HttpResponse::JSON(j.str());
        }

        if (parts.size() == 2 && parts[0] == "api" &&
            (parts[1].substr(0, 9)  == "orderbook"   ||
             parts[1].substr(0, 5)  == "price"       ||
             parts[1].substr(0, 9)  == "postorder"   ||
             parts[1].substr(0, 11) == "cancelorder" ||
             parts[1].substr(0, 12) == "tokenbalance"||
             parts[1].substr(0, 9)  == "sendtoken"   ||
             parts[1].substr(0, 12) == "tokenhistory")) {
            return HttpResponse::JSON("{\"error\":\"Endpoint removed. The WBTC bridge and VELD/WBTC exchange were scrapped pre-launch.\"}");
        }

        if (parts.size() == 2 && parts[0] == "api" && parts[1].substr(0,10) == "tierstatus") {
            std::string addr = urlParam("address");
            if (addr.empty()) return HttpResponse::JSON("{\"error\":\"address required\"}");
            if (!IsStrictBase58Address(addr))
                return HttpResponse::JSON("{\"error\":\"invalid address\"}", 400);
            auto script = AddressToScript(addr);
            std::string script_hex;
            if (script.size() == 25) {
                script_hex = BytesToHex(script);
            }
            uint64_t mined = chain_.GetBlocksMined(script_hex);

            double staked = 0.0;
            bool is_validator = false;
            if (rpc_delegate_) {
                std::string esc_addr = HttpResponse::JsonEscape(addr);
                auto sr = rpc_delegate_->Handle(
                    R"({"jsonrpc":"2.0","id":"t","method":"getstake","params":[")" + esc_addr + R"("]})");
                auto sp = sr.find("\"staked_veld\":");
                if (sp != std::string::npos) {
                    try { staked = std::stod(sr.substr(sp + 14)); } catch (...) {}
                }
                auto vr = rpc_delegate_->Handle(
                    R"({"jsonrpc":"2.0","id":"v","method":"getvalidators","params":[]})");
                is_validator = (vr.find("\"address\":\"" + addr + "\"") != std::string::npos);
            }

            double held_veld = 0.0;
            {
                auto utxos = chain_.GetUTXOsForScript(script);
                uint64_t total = 0;
                for (auto& u : utxos) total += u.value;
                held_veld = (double)total / VELD_UNITS;
            }

            double vault_bal = (double)chain_.GetBalance(
                AddressToScript(VaultAddressAtHeight(chain_.Height()))) / VELD_UNITS;

            std::ostringstream j;
            j << std::fixed << std::setprecision(4);
            j << "{\"address\":\"" << HttpResponse::JsonEscape(addr) << "\""
              << ",\"blocks_mined\":" << mined
              << ",\"staked_veld\":" << staked
              << ",\"held_veld\":" << held_veld
              << ",\"is_validator\":" << (is_validator ? "true" : "false")
              << ",\"vault_balance\":" << std::fixed << std::setprecision(8) << vault_bal
              << ",\"req_min_blocks\":0"
              << ",\"req_min_staked\":0"
              << ",\"req_min_held\":0"
              << ",\"req_proposer_held\":0"
              << ",\"eligibility\":\"validator_only\""
              << "}";
            return HttpResponse::JSON(j.str());
        }

        if (parts.size() == 2 && parts[0] == "api" && parts[1] == "rpc") {
            return HttpResponse::JSON("{\"error\":\"Governance RPC disabled on explorer. Use the Veld Wallet app.\"}", 403);
        }

        if (parts.size() == 2 && parts[0] == "api" && parts[1].substr(0,9) == "proposals") {
            if (rpc_delegate_) {
                std::string rpc_req = "{\"jsonrpc\":\"2.0\",\"method\":\"getproposals\",\"params\":[],\"id\":1}";
                std::string resp = rpc_delegate_->Handle(rpc_req);
                auto rpos = resp.find("\"result\":");
                if (rpos != std::string::npos) {
                    auto start = rpos + 9;
                    if (start < resp.size() && resp[start] == '[') {
                        int depth = 0;
                        size_t end = start;
                        for (; end < resp.size(); ++end) {
                            if (resp[end] == '[') depth++;
                            else if (resp[end] == ']') { depth--; if (depth == 0) { end++; break; } }
                        }
                        return HttpResponse::JSON(resp.substr(start, end - start));
                    }
                }
            }
            return HttpResponse::JSON(proposals_json_);
        }

        if (parts.size() == 2 && parts[0] == "api" && parts[1].substr(0,5) == "vault") {
            const std::string& cur_vault = VaultAddressAtHeight(chain_.Height());
            auto vs = AddressToScript(cur_vault);
            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            j << "{\"balance_veld\":" << std::fixed << std::setprecision(8)
              << (double)chain_.GetBalance(vs) / VELD_UNITS
              << ",\"address\":\"" << cur_vault << "\"}";
            return HttpResponse::JSON(j.str());
        }
        if (parts.size() == 2 && parts[0] == "api" && parts[1].substr(0,11) == "stakinginfo") {
            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            uint64_t supply = chain_.TotalSupplyUnits();
            bool active = (supply >= chain_.GetStakingActivationUnits());
            uint64_t height = chain_.Height();
            uint64_t next_dist = (height == 0) ? VAULT_DISTRIBUTION_INTERVAL
                : VAULT_DISTRIBUTION_INTERVAL - (height % VAULT_DISTRIBUTION_INTERVAL);
            uint64_t total_staked = tokens_ ? 0 : 0;
            double total_staked_veld = 0.0;
            if (rpc_delegate_) {
                auto resp = rpc_delegate_->Handle("{\"jsonrpc\":\"2.0\",\"id\":\"1\","
                    "\"method\":\"getstakinginfo\",\"params\":[]}");
                auto ri = resp.find("\"total_staked_veld\":");
                if (ri != std::string::npos) {
                    auto start = ri + 20;
                    auto end = resp.find_first_of(",}", start);
                    try { total_staked_veld = std::stod(resp.substr(start, end-start)); } catch (...) {}
                }
            }
            double vault_balance = (double)chain_.GetBalance(AddressToScript(VAULT_ADDRESS)) / VELD_UNITS;
            j << "{\"staking_active\":" << (active ? "true" : "false")
              << ",\"activation_supply_veld\":" << (double)chain_.GetStakingActivationUnits() / VELD_UNITS
              << ",\"current_supply_veld\":" << (double)supply / VELD_UNITS
              << ",\"total_staked_veld\":" << total_staked_veld
              << ",\"vault_balance_veld\":" << vault_balance
              << ",\"min_stake_veld\":" << (double)MIN_STAKE_UNITS / VELD_UNITS
              << ",\"lockup_blocks\":" << STAKE_LOCKUP_BLOCKS
              << ",\"distribution_interval\":" << VAULT_DISTRIBUTION_INTERVAL
              << ",\"next_distribution_in\":" << next_dist
              << ",\"current_height\":" << height << "}";
            return HttpResponse::JSON(j.str());
        }

        if (parts.size() == 2 && parts[0] == "api" && parts[1].substr(0,7) == "mystake") {
            std::string addr = urlParam("address");
            if (!IsStrictBase58Address(addr))
                return HttpResponse::JSON("{\"error\":\"invalid address\"}", 400);
            double staked_veld = 0.0;
            if (rpc_delegate_) {
                std::string esc_addr = HttpResponse::JsonEscape(addr);
                auto resp = rpc_delegate_->Handle("{\"jsonrpc\":\"2.0\",\"id\":\"1\","
                    "\"method\":\"getstake\",\"params\":[\"" + esc_addr + "\"]}");
                auto ri = resp.find("\"staked_veld\":");
                if (ri != std::string::npos) {
                    auto start = ri + 14;
                    auto end = resp.find_first_of(",}", start);
                    try { staked_veld = std::stod(resp.substr(start, end-start)); } catch (...) {}
                } else {
                    auto ri2 = resp.find("\"result\":");
                    if (ri2 != std::string::npos) {
                        auto start = ri2 + 9;
                        auto end = resp.find_first_of(",}", start);
                        try { staked_veld = std::stod(resp.substr(start, end-start)); } catch (...) {}
                    }
                }
            }
            auto script = AddressToScript(addr);
            double balance = script.empty() ? 0.0 : (double)chain_.GetBalance(script) / VELD_UNITS;
            std::ostringstream j;
            j << std::fixed << std::setprecision(8);
            j << "{\"address\":\"" << HttpResponse::JsonEscape(addr)
              << "\",\"staked_veld\":" << staked_veld
              << ",\"balance_veld\":" << balance << "}";
            return HttpResponse::JSON(j.str());
        }

        if (parts.size() == 2 && parts[0] == "block" && parts[1].size() == 64)
            return ServeBlock(parts[1]);

        if (parts.size() == 3 && parts[0] == "block" && parts[1] == "height") {
            try { return ServeBlockByHeight(std::stoull(parts[2])); }
            catch (...) { return HttpResponse::NotFound("invalid block height"); }
        }

        if (parts.size() == 2 && parts[0] == "tx")
            return ServeTx(parts[1]);

        if (parts.size() == 2 && parts[0] == "address")
            return ServeAddress(parts[1]);

        return HttpResponse::NotFound(req.path);
    }

private:
    static bool ParseExplorerHeight_(const std::string& text,
                                     uint64_t& value) {
        if (text.empty()) return false;
        for (const unsigned char c : text)
            if (c < '0' || c > '9') return false;
        try {
            size_t consumed = 0;
            const uint64_t parsed = std::stoull(text, &consumed, 10);
            if (consumed != text.size()) return false;
            value = parsed;
            return true;
        } catch (...) {
            return false;
        }
    }

    static std::string BlockToJSON_(const Block& block,
                                    bool include_transaction_ids) {
        std::ostringstream json;
        json << std::fixed << std::setprecision(8);
        const double reward = block.transactions.empty() ? 0.0 :
            static_cast<double>(block.transactions[0].TotalOutput()) / VELD_UNITS;
        std::string miner_address;
        if (!block.transactions.empty()) {
            for (const auto& output : block.transactions[0].outputs) {
                if (output.script_pubkey.size() == 25
                        && output.script_pubkey[0] == 0x76) {
                    const std::string address = ScriptToAddress(output.script_pubkey);
                    if (!address.empty() && address != VAULT_ADDRESS) {
                        miner_address = address;
                        break;
                    }
                }
            }
        }
        json << "{"
             << "\"height\":" << block.height << ","
             << "\"hash\":\"" << HashToHex(block.GetHash()) << "\","
             << "\"prev_hash\":\"" << HashToHex(block.header.prev_block_hash) << "\","
             << "\"merkle_root\":\"" << HashToHex(block.header.merkle_root) << "\","
             << "\"time\":" << static_cast<uint64_t>(block.header.timestamp) << ","
             << "\"bits\":" << block.header.bits << ","
             << "\"nonce\":" << static_cast<uint64_t>(block.header.nonce) << ","
             << "\"size\":" << block.SerializedSize() << ","
             << "\"tx_count\":" << block.transactions.size() << ","
             << "\"reward_veld\":" << reward << ","
             << "\"miner\":\"" << miner_address << "\","
             << "\"winner\":\"" << miner_address << "\"";
        if (include_transaction_ids) {
            json << ",\"tx\":[";
            for (size_t i = 0; i < block.transactions.size(); ++i) {
                if (i) json << ",";
                json << "\"" << HashToHex(block.transactions[i].GetTxID()) << "\"";
            }
            json << "]";
        }
        json << "}";
        return json.str();
    }

    void LoadTrustedProxyConfiguration_() {
        trusted_proxy_.enabled = false;
        trusted_proxy_.peer.clear();
        veld::compat::SecureZero(trusted_proxy_.token.data(),
                                 trusted_proxy_.token.size());
        proxy_configuration_error_.clear();
        if (cache_dir_.empty()) return;

        const std::filesystem::path config_path =
            std::filesystem::path(cache_dir_) / "explorer-proxy.conf";
        std::vector<uint8_t> bytes;
        std::string read_error;
        const auto status = channel::secure_file::Read(
            config_path.string(), bytes, &read_error, 4096, true);
        if (status == channel::secure_file::ReadResult::NotFound) return;
        if (status != channel::secure_file::ReadResult::Ok) {
            proxy_configuration_error_ = "explorer proxy config refused: " + read_error;
            return;
        }
        std::string body(bytes.begin(), bytes.end());
        channel::secure_file::WipeAndClear(bytes);
        std::istringstream input(body);
        std::string version, peer_line, token_line, extra;
        const bool shape_ok = std::getline(input, version)
            && std::getline(input, peer_line)
            && std::getline(input, token_line)
            && !std::getline(input, extra);
        veld::compat::SecureZero(body.data(), body.size());
        auto strip_cr = [](std::string& value) {
            if (!value.empty() && value.back() == '\r') value.pop_back();
        };
        strip_cr(version); strip_cr(peer_line); strip_cr(token_line);
        if (!shape_ok || version != "VELD_EXPLORER_PROXY_V1"
                || peer_line.rfind("peer=", 0) != 0
                || token_line.rfind("token_file=", 0) != 0) {
            proxy_configuration_error_ = "explorer proxy config has invalid v1 format";
            return;
        }
        const std::filesystem::path token_path = token_line.substr(11);
        if (!token_path.is_absolute()) {
            proxy_configuration_error_ = "explorer proxy token path must be absolute";
            return;
        }
        std::string configure_error;
        if (!ConfigureTrustedProxy(peer_line.substr(5), token_path.string(),
                                   &configure_error)) {
            proxy_configuration_error_ =
                "explorer proxy configuration refused: " + configure_error;
        }
    }

    std::string ClassifyUTXOSource(const UTXO& u) const {
        try {
            Block blk = chain_.GetBlock(u.block_height);
            for (size_t i = 0; i < blk.transactions.size(); ++i) {
                const auto& tx = blk.transactions[i];
                if (tx.GetTxID() != u.tx_hash) continue;
                if (i == 0) return "mining_reward";
                std::string opd;
                for (const auto& out : tx.outputs) {
                    const auto& sp = out.script_pubkey;
                    if (sp.size() < 2 || sp[0] != 0x6A) continue;
                    size_t di = 1, dlen = 0;
                    if (sp[di] <= 75) { dlen = sp[di++]; }
                    else if (sp[di] == 0x4C && di+1 < sp.size()) { di++; dlen = sp[di++]; }
                    else if (sp[di] == 0x4D && di+2 < sp.size()) { di++; dlen = sp[di] | (sp[di+1]<<8); di+=2; }
                    if (dlen == 0 || di + dlen > sp.size()) continue;
                    opd.assign(sp.begin()+di, sp.begin()+di+dlen);
                    break;
                }
                std::string sender_addr;
                if (!tx.inputs.empty()) {
                    const auto& ss = tx.inputs[0].script_sig;
                    std::vector<uint8_t> sig_tmp;
                    std::array<uint8_t,1952> pk;
                    if (!ss.empty()
                        && veld::pqc::ParseScriptSig(ss, sig_tmp, pk)) {
                        Hash160 pkh = Hash160Compute(pk);
                        std::vector<uint8_t> sscript = {0x76,0xA9,0x14};
                        sscript.insert(sscript.end(), pkh.begin(), pkh.end());
                        sscript.push_back(0x88); sscript.push_back(0xAC);
                        sender_addr = ScriptToAddress(sscript);
                    } else {
                        for (const auto& inp : tx.inputs) {
                            auto prev = chain_.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                            if (prev) {
                                sender_addr = ScriptToAddress(prev->script_pubkey);
                            } else {
                                for (const auto& ptx : blk.transactions) {
                                    if (ptx.GetTxID() != inp.prev_tx_hash) continue;
                                    if (inp.prev_out_index >= ptx.outputs.size()) break;
                                    sender_addr = ScriptToAddress(
                                        ptx.outputs[inp.prev_out_index].script_pubkey);
                                    break;
                                }
                            }
                            if (!sender_addr.empty()) break;
                        }
                    }
                }
                if (opd.find("VELD_DIST|STAKING") != std::string::npos)
                    return "staking_reward";
                if (opd.find("VELD_DIST|ENDORSEMENT") != std::string::npos)
                    return "endorsement_reward";
                if (opd.find("VELD_DIST|COMINE") != std::string::npos)
                    return "pool_payout";
                if (sender_addr == POOL_ADDRESS) return "pool_payout";
                if (sender_addr == ENDORSEMENT_POOL_ADDRESS) return "endorsement_payout";
                if (sender_addr == VAULT_ADDRESS) return "vault_payout";
                if (sender_addr.empty() && !tx.inputs.empty()) {
                    try {
                        Block prev_blk = chain_.GetBlock(0);
                        const auto& in = tx.inputs[0];
                        uint64_t start = u.block_height > 300 ? u.block_height - 300 : 0;
                        for (uint64_t bh = u.block_height; bh >= start; --bh) {
                            try {
                                Block pbk = chain_.GetBlock(bh);
                                for (const auto& ptx : pbk.transactions) {
                                    if (ptx.GetTxID() == in.prev_tx_hash &&
                                        in.prev_out_index < ptx.outputs.size()) {
                                        const auto& psrc = ptx.outputs[in.prev_out_index].script_pubkey;
                                        auto pool_s   = AddressToScript(POOL_ADDRESS);
                                        auto endor_s  = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
                                        auto vault_s  = AddressToScript(VAULT_ADDRESS);
                                        if (psrc == pool_s)  return "pool_payout";
                                        if (psrc == endor_s) return "endorsement_payout";
                                        if (psrc == vault_s) return "vault_payout";
                                        goto fallback_done;
                                    }
                                }
                            } catch (...) {}
                            if (bh == 0) break;
                        }
                        fallback_done:;
                    } catch (...) {}
                }
                return "transfer_in";
            }
        } catch (...) {}
        return "unknown";
    }

    Blockchain& chain_;
    Mempool&    mempool_;
    uint16_t    port_;
    std::atomic<bool> running_;
    std::atomic<bool> activation_guard_refused_{false};
    SocketHandle fd_;
    std::thread server_thread_;
    std::atomic<uint64_t> requests_served_{0};
    std::atomic<uint64_t> active_requests_{0};
    struct RequestWorker {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::mutex request_workers_mutex_;
    std::vector<RequestWorker> request_workers_;
    std::mutex prewarm_thread_mu_;
    std::thread prewarm_thread_;
    OnChainTokenLedger* tokens_;
    RpcServer*          rpc_delegate_;
    ValidatorRegistry*  validators_{nullptr};
    TierEngine*         tiers_{nullptr};
    std::function<uint64_t()> network_height_fn_;
    std::function<size_t()>   peer_count_fn_;
    std::function<std::vector<PeerStatsItem>()> peer_stats_fn_;
    std::function<std::string(const std::string&, size_t,
                              const std::string&)> address_history_fn_;

    std::string                                cache_dir_;
    net::trusted_proxy::Configuration          trusted_proxy_;
    std::string                                proxy_configuration_error_;
    mutable std::mutex                         richlist_cache_mu_;
    std::string                                richlist_cache_body_;
    std::chrono::steady_clock::time_point      richlist_cache_until_;
    uint64_t                                   richlist_cache_height_ = 0;
    mutable std::mutex                         richlist_json_cache_mu_;
    std::string                                richlist_json_cache_body_;
    std::chrono::steady_clock::time_point      richlist_json_cache_until_;
    uint64_t                                   richlist_json_cache_height_ = 0;
    std::atomic<bool>                          richlist_refresh_in_flight_{false};

    std::string proposals_json_ = "[]";

    void SetVaultBalance(double) {}
    void SetProposalsJSON(const std::string& j){ proposals_json_ = j; }

    HttpResponse ServeMiningPage() {
        double supply = (double)chain_.TotalSupplyUnits() / VELD_UNITS;
        double reward = (double)BLOCK_REWARD_UNITS / VELD_UNITS;
        uint64_t height = chain_.Height();

        std::ostringstream page;
        page << "<div class=\"container\">";
        page << "<h1 style=\"font-family:var(--head);font-size:28px;font-weight:700;color:var(--em);margin-bottom:6px\">Mining</h1>";
        page << "<p style=\"color:var(--muted);margin-bottom:24px\">VeldHash proof-of-work &mdash; CPU mining.</p>";

        page << "<div class=\"stat-grid\">";
        page << "<div class=\"stat\"><div class=\"stat-label\">Block Height</div><div class=\"stat-value em\">" << height << "</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Block Reward</div><div class=\"stat-value gold\">" << std::fixed << std::setprecision(2) << reward << " VELD</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Miner Share</div><div class=\"stat-value\">50%</div><div class=\"stat-sub\">of block reward</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Algorithm</div><div class=\"stat-value sm\">VeldHash</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Total Supply</div><div class=\"stat-value\">" << std::setprecision(2) << supply << "</div><div class=\"stat-sub\">/ 21,000,000 VELD</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Hard Cap</div><div class=\"stat-value\">21M</div><div class=\"stat-sub\">flat reward, no halving</div></div>";
        page << "</div>";

        page << "<div class=\"card\" style=\"margin-top:18px\">";
        page << "<div class=\"card-title\">Coinbase Split</div>";
        page << "<div class=\"tbl-scroll\"><table class=\"tbl\"><thead><tr><th>Recipient</th><th>Share</th><th>Description</th></tr></thead><tbody>";
        page << "<tr><td style=\"color:var(--em);font-weight:600\">Miner</td><td><strong>50%</strong></td><td>Direct reward to block finder</td></tr>";
        page << "<tr><td style=\"color:#4CB8FF;font-weight:600\">Co-Mining Pool</td><td><strong>20%</strong></td><td>Shared among uniformly drawn eligible near-miss miners every 100 blocks</td></tr>";
        page << "<tr><td style=\"color:var(--gold);font-weight:600\">Vault</td><td><strong>20%</strong></td><td>Distributed to stakers every 480 blocks (daily)</td></tr>";
        page << "<tr><td style=\"color:#B07CFF;font-weight:600\">Validators</td><td><strong>10%</strong></td><td>Paid to active validators every 480 blocks (daily)</td></tr>";
        page << "</tbody></table></div></div>";

        page << "<div class=\"card\">";
        page << "<div class=\"card-title\">Recent Blocks</div>";
        page << "<div class=\"tbl-scroll\"><table class=\"tbl\"><thead><tr><th>Height</th><th>Hash</th><th>Miner</th><th>Reward</th><th>Txns</th><th>Time</th></tr></thead><tbody>";
        for (uint64_t h = height; h > 0 && h > height - 15; --h) {
            Block block = chain_.GetBlock(h);
            if (block.transactions.empty()) continue;
            std::string block_hash = HashToHex(block.GetHash());
            std::string miner_addr;
            if (!block.transactions[0].outputs.empty())
                miner_addr = ScriptToAddress(block.transactions[0].outputs[0].script_pubkey);
            std::string short_hash = block_hash.substr(0, 16) + "...";
            std::string short_miner = miner_addr.empty() ? "--" : miner_addr.substr(0, 12) + "...";
            double blk_reward = 0;
            for (auto& o : block.transactions[0].outputs) blk_reward += (double)o.value / VELD_UNITS;
            page << "<tr>"
                 << "<td><a href=\"/block/height/" << h << "\" style=\"color:var(--em)\">" << h << "</a></td>"
                 << "<td style=\"font-family:var(--font);font-size:12px;color:var(--gold)\">" << short_hash << "</td>"
                 << "<td style=\"font-family:var(--font);font-size:12px\">" << short_miner << "</td>"
                 << "<td style=\"color:var(--em)\">" << std::setprecision(2) << blk_reward << " VELD</td>"
                 << "<td>" << block.transactions.size() << "</td>"
                 << "<td style=\"color:var(--muted)\">" << block.header.timestamp << "</td>"
                 << "</tr>";
        }
        page << "</tbody></table></div></div>";

        page << "<div class=\"card\">";
        page << "<div class=\"card-title\">Mining Tiers</div>";
        page << "<p style=\"color:var(--text);font-size:14px;line-height:1.6;margin-bottom:16px\">Mining tier is one of the two inputs to your <strong>staking multiplier</strong> (the other is lockup tier). Your tier rises with consistent mining activity over rolling windows, and a higher tier means a bigger share of every vault distribution paid out to your staked balance &mdash; it does <em>not</em> change per-block coinbase, which is a flat 50% to whoever solves the block.</p>";
        page << "<div class=\"tbl-scroll\"><table class=\"tbl\"><thead><tr><th>Tier</th><th>Active Days</th><th>Window</th><th>Multiplier</th></tr></thead><tbody>";
        page << "<tr><td class=\"tier-name tier-none\">None</td><td>0</td><td>&mdash;</td><td>1.00&times;</td></tr>";
        page << "<tr><td class=\"tier-name tier-bronze\">Bronze</td><td>7</td><td>14 days</td><td>1.10&times;</td></tr>";
        page << "<tr><td class=\"tier-name tier-silver\">Silver</td><td>25</td><td>30 days</td><td>1.25&times;</td></tr>";
        page << "<tr><td class=\"tier-name tier-gold\">Gold</td><td>165</td><td>180 days</td><td>1.50&times;</td></tr>";
        page << "<tr><td class=\"tier-name tier-platinum\">Platinum</td><td>335</td><td>365 days</td><td>1.80&times;</td></tr>";
        page << "<tr><td class=\"diamond-prismatic\">Diamond</td><td>1,000</td><td>1,095 days</td><td class=\"diamond-prismatic\">3.00&times;</td></tr>";
        page << "</tbody></table></div></div>";

        page << "</div>";
        return HttpResponse::HTML(HtmlWrapArcade("Mining", page.str(), "mining"));
    }

    HttpResponse ServeTiers() {
        static const std::string PAGE = R"HTML(
<div class="card">
  <div class="card-title">Mining Tier System</div>
  <p style="color:var(--text);font-size:13px;line-height:1.6;margin-bottom:14px">
    Mining tiers reward consistent mining over time. Mine at least one block in a day and that day counts as <strong>active</strong>. Your tier is recomputed every block from a rolling window of recent days &mdash; keep mining to climb, stop mining and the tier drops. There&rsquo;s no permanent milestone.
  </p>
  <div class="tbl-scroll"><table class="tbl">
    <thead><tr><th>Name</th><th>Requirement</th><th>Type</th><th>Multiplier</th></tr></thead>
    <tbody>
      <tr><td style="color:var(--muted)">—</td><td>Just mine</td><td style="color:var(--muted)">—</td><td style="color:var(--muted)">1.00×</td></tr>
      <tr><td class="tier-name tier-bronze">Bronze</td><td>7 of last 14 days active</td><td style="color:var(--muted)">Rolling window</td><td class="tier-bronze">1.10×</td></tr>
      <tr><td class="tier-name tier-silver">Silver</td><td>25 of last 30 days active</td><td style="color:var(--muted)">Rolling window</td><td class="tier-silver">1.25×</td></tr>
      <tr><td class="tier-name tier-gold">Gold</td><td>165 of last 180 days active</td><td style="color:var(--muted)">Rolling window</td><td class="tier-gold">1.50×</td></tr>
      <tr><td class="tier-name tier-platinum">Platinum</td><td>335 of last 365 days active</td><td style="color:var(--muted)">Rolling window</td><td class="tier-platinum">1.80×</td></tr>
      <tr><td class="diamond-prismatic">Diamond</td><td>1000 of last 1,095 days active</td><td style="color:var(--muted)">Rolling window</td><td class="diamond-prismatic">3.00×</td></tr>
    </tbody>
  </table>
  <p style="font-size:12px;color:var(--muted);margin:16px 0 0;font-style:italic">The multiplier increases your share of vault distributions. Your payout weight = stake × multiplier.</p>
</div>

<div class="card">
  <div class="card-title">Check Your Tier</div>
  <div class="input-row">
    <input class="veld-input" id="tier-addr" placeholder="Your Veld address (V...)">
    <button class="veld-btn" data-act-click="e4d75da55">Check</button>
  </div>
  <div id="tier-result"></div>
</div>

<script nonce="__CSP_NONCE__">
function escHtml(s){var d=document.createElement('div');d.appendChild(document.createTextNode(s));return d.innerHTML;}
function checkTier() {
  var addr = document.getElementById('tier-addr').value.trim();
  if (!addr) return;
  document.getElementById('tier-result').innerHTML = '<div style="color:var(--muted);padding:12px">Loading...</div>';
  fetch('/api/tierstatus?address=' + encodeURIComponent(addr))
    .then(function(r){return r.json();})
    .then(function(d) {
      if (d.error) { document.getElementById('tier-result').innerHTML = '<div style="color:var(--red);padding:12px">'+escHtml(d.error)+'</div>'; return; }
      // Diamond tier and 3.00× multiplier always render
      // with the prismatic shimmer — same effect as the rules-tab tier ladder.
      var labels = ['—','Bronze','Silver','Gold','Platinum','<span class="diamond-prismatic">Diamond</span>'];
      var mults  = ['1.00×','1.25×','1.50×','2.00×','2.50×','<span class="diamond-prismatic">3.00×</span>'];
      var t = d.tier || 0;
      var name = d.name || labels[t];
      var pct = 0;
      if (d.type === 'block_count' && d.blocks_required > 0)
        pct = Math.min(100, d.blocks_mined / d.blocks_required * 100).toFixed(1);
      else if (d.type === 'rolling_window' && d.windows_total > 0)
        pct = Math.min(100, d.windows_active / d.windows_required * 100).toFixed(1);
      else pct = t >= 5 ? 100 : 0;
      var next = d.next_tier || '';
      // Coerce every d.* scalar that's
      // interpolated into HTML through a strict int/string filter.
      // Previously blocks_mined / blocks_required / windows_active /
      // windows_required were concatenated raw — not an XSS vector today
      // (backend only writes integers here) but a stored-XSS sink if a
      // future feature lets user-controlled names flow in. asInt()
      // parses as integer and returns 0 on anything non-numeric.
      var asInt = function(v){ var n = parseInt(v,10); return (isFinite(n) && n >= 0) ? String(n) : '0'; };
      document.getElementById('tier-result').innerHTML =
        '<div class="grid-2" style="margin-top:8px">' +
        '<div class="stat"><div class="stat-label">Address</div><div style="font-size:10px;color:var(--em);word-break:break-all">'+escHtml(addr)+'</div></div>' +
        '<div class="stat"><div class="stat-label">Current Tier</div><div class="stat-value em">'+escHtml(name)+' &mdash; '+mults[t]+'</div></div>' +
        '<div class="stat"><div class="stat-label">Blocks Mined</div><div class="stat-value em">'+asInt(d.blocks_mined)+'</div></div>' +
        '<div class="stat"><div class="stat-label">Held VELD</div><div class="stat-value">'+fmt(d.held_veld||0, 2)+'</div></div>' +
        '</div>' +
        (t < 5 ? (function(){
          var progressLabel = next ? 'Progress to '+escHtml(next) : 'Next tier';
          var progressDetail = d.type === 'block_count'
            ? (asInt(d.blocks_mined)+' / '+asInt(d.blocks_required)+' blocks')
            : d.type === 'rolling_window'
            ? (asInt(d.windows_active)+' / '+asInt(d.windows_required)+' active days')
            : '';
          return '<div style="margin-top:16px"><div style="display:flex;justify-content:space-between;font-size:10px;color:var(--muted);margin-bottom:6px"><span>'+progressLabel+'</span><span>'+progressDetail+'</span></div><div class="vault-bar-track"><div class="vault-bar-fill" style="width:'+pct+'%"></div></div></div>';
        })() : '<div style="margin-top:12px;font-size:11px"><span class="diamond-prismatic">&#9830;&#xFE0E; Diamond achieved &mdash; 3.00&times; multiplier</span></div>');
    }).catch(function(){ document.getElementById('tier-result').innerHTML = '<div style="color:var(--red);padding:12px">Could not connect to node.</div>'; });
}
</script>
)HTML";
        return HttpResponse::HTML(HtmlWrapArcade("Tiers", PAGE, "tiers"));
    }

    HttpResponse ServeRulesPage() {
        static const std::string PAGE = R"HTML(
<style>
.rule-card{margin-bottom:18px;}
/* Keep the rules page compact and readable across desktop and mobile. */
.rule-card h2{font-family:var(--sans);font-size:18px!important;font-weight:600;color:var(--text);margin-bottom:14px;letter-spacing:.1px;border-bottom:1px solid var(--b1);padding-bottom:8px;}
.rule-card h3{font-family:var(--sans);font-size:15px!important;font-weight:600;color:var(--text);margin:16px 0 8px;letter-spacing:.1px;}
.rule-card p,.rule-card li{font-size:15px!important;line-height:1.65!important;color:var(--text);}
/* Secondary / muted paragraphs (inline style color:var(--muted)) shrink
   one step so the grey "Why X" commentary is clearly subordinate to the
   white primary body. Selector targets any <p> whose inline style sets
   a muted color, regardless of font-size override elsewhere on it. */
.rule-card p[style*="muted"]{font-size:12.5px!important;line-height:1.7!important;}
.rule-card .tbl-rules th,.rule-card .tbl-rules td{font-size:13px!important;}
.rule-card ul,.rule-card ol{margin:6px 0 12px 22px;}
.rule-card .formula{display:inline-block;padding:2px 8px;background:var(--em-dim);border:1px solid var(--b2);border-radius:4px;color:var(--em);font-family:var(--font);font-size:12px;}
.rule-card .label{display:inline-block;padding:1px 7px;border-radius:10px;font-size:10px;font-weight:600;letter-spacing:.5px;text-transform:uppercase;}
.label-active{background:var(--em-dim);color:var(--em);border:1px solid var(--b2);}
.label-cap{background:rgba(255,216,74,.1);color:var(--gold);border:1px solid rgba(255,216,74,.2);}
.label-hard{background:rgba(255,76,76,.1);color:var(--red);border:1px solid rgba(255,76,76,.2);}
.tbl-rules{width:100%;border-collapse:collapse;margin:8px 0 14px;font-size:12px;}
.tbl-rules th{text-align:left;padding:8px 10px;background:var(--em-dark);color:var(--text);font-weight:600;border-bottom:1px solid var(--b2);}
.tbl-rules td{padding:8px 10px;border-bottom:1px solid var(--b1);color:var(--text);}
.tbl-rules tr:hover td{background:var(--em-dark);}
html[data-theme="light"] .tier-ladder td:not(.diamond-prismatic){color:#000!important;}
.toc{background:var(--em-dark);border:1px solid var(--b1);border-radius:8px;padding:14px 20px;margin-bottom:24px;}
.toc h3{font-family:var(--head);font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px;}
.toc ul{list-style:none;margin:0;padding:0;column-count:2;column-gap:18px;}
.toc li{padding:4px 0;font-size:13px;}
.toc a{color:var(--em);text-decoration:none;}
.toc a:hover{text-decoration:underline;}
.peg-status{padding:12px 14px;margin:0 0 14px;background:var(--em-dark);border:1px solid var(--b2);border-radius:8px;}
.peg-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin:12px 0 16px;}
.peg-item{padding:13px 14px;background:rgba(255,255,255,.018);border:1px solid var(--b1);border-radius:8px;}
.peg-item .k{display:block;margin-bottom:5px;color:var(--muted);font-size:10px;font-weight:600;letter-spacing:.8px;text-transform:uppercase;}
.peg-item .v{color:var(--text);font-size:13px;line-height:1.55;}
.peg-item strong{color:var(--em);}
@media(max-width:700px){.peg-grid{grid-template-columns:1fr;}.toc ul{column-count:1;}}
</style>

<div class="card rule-card">
  <h2>How Veld works</h2>
  <p style="color:var(--muted);font-size:13px;line-height:1.6">
    A plain-English summary of the rules every Veld node enforces.
    Full derivations, formulas, and edge-case behaviour are documented in the
    <a href="https://veld.network/whitepaper.pdf" style="color:var(--em);text-decoration:underline">whitepaper</a>.
  </p>
  <div class="toc">
    <h3>Table of Contents</h3>
    <ul>
      <li><a href="#emission">1. Block reward &amp; emission</a></li>
      <li><a href="#splits">2. Coinbase split (50 / 20 / 20 / 10)</a></li>
      <li><a href="#vault">3. Vault distribution math</a></li>
      <li><a href="#caps">4. Vault drain protection</a></li>
      <li><a href="#whale">5. Concentration limit</a></li>
      <li><a href="#multiplier">6. Multiplier system</a></li>
      <li><a href="#stakelock">7. Stake lockup tiers</a></li>
      <li><a href="#minetier">8. Mining tier ladder</a></li>
      <li><a href="#endorse">9. Validators &amp; the validator pool</a></li>
      <li><a href="#valbond">10. Validator bond, slashing &amp; yield escrow</a></li>
      <li><a href="#poolflush">11. Co-mining lottery</a></li>
      <li><a href="#governance">12. Governance</a></li>
      <li><a href="#privacy">13. Privacy &amp; safety guarantees</a></li>
      <li><a href="#difficulty">14. Difficulty retargeting</a></li>
      <li><a href="#btcveld">15. btcVELD &mdash; the Bitcoin peg</a></li>
      <li><a href="#syncing">16. Syncing &amp; trust</a></li>
      <li><a href="#chain-identity">17. Chain identity</a></li>
    </ul>
  </div>
</div>

<div class="card rule-card">
  <h2 id="emission">1. Block reward &amp; emission</h2>
  <p>The network produces a new block roughly every <strong>180 seconds</strong> and mints a fixed reward of <strong>3.13926940 VELD</strong> &mdash; flat, with no halving. That works out to about <strong>1,507 VELD per day</strong> across the network, or 550,000 VELD per year. That flat rate is mined all the way to the <strong>21,000,000 VELD</strong> hard cap in roughly <strong>38 years</strong> (21M &divide; 550K) &mdash; there is no premine and no separate reserve, every coin is issued through the block reward. Once the cap is reached, no more is ever created.</p>
</div>

<div class="card rule-card">
  <h2 id="splits">2. Where each block reward goes</h2>
  <p>Ordinary block rewards split four ways. Every node enforces the exact outputs; every 100th block is the stated exception and routes its full subsidy to the vault.</p>
  <table class="tbl-rules">
    <tr><th>Stream</th><th>Share</th><th>Goes to</th></tr>
    <tr><td style="color:var(--em);font-weight:600">Block winner</td><td style="color:var(--em)"><strong>50%</strong></td><td>Whoever solved this block&#39;s proof-of-work</td></tr>
    <tr><td style="color:#4CB8FF;font-weight:600">Co-mining pool</td><td style="color:#4CB8FF"><strong>20%</strong></td><td>Pays out to near-miss miners every 100 blocks (see &sect;11)</td></tr>
    <tr><td style="color:var(--gold);font-weight:600">Vault</td><td style="color:var(--gold)"><strong>20%</strong></td><td>Pays out to stakers every 480 blocks (daily)</td></tr>
    <tr><td style="color:#B07CFF;font-weight:600">Validator pool</td><td style="color:#B07CFF"><strong>10%</strong></td><td>Pays out to active validators every 480 blocks (daily)</td></tr>
  </table>
  <p style="color:var(--muted);font-size:12px">During the subsidy era, transaction fees flow to the vault on top of its block share. Post-cap fee routing is 50% miner, 40% vault, and 10% validator pool.</p>
</div>

<div class="card rule-card">
  <h2 id="vault">3. How vault distributions work</h2>
  <p>Staking activates once network supply reaches <strong>10,000 VELD</strong>. Until then the vault continues accumulating and no stake can be created.</p>
  <p>Every <strong>480 blocks</strong> (~24 hours) the vault pays out a portion of its inflow during that cycle to every active staker. Your share is proportional to <span class="formula">your stake &times; your multiplier</span>, normalised against the rest of the active stakers.</p>
  <p>Higher multipliers get a bigger slice; everyone else still gets paid. The full payout math is in the <a href="https://veld.network/whitepaper.pdf" style="color:var(--em);text-decoration:underline">whitepaper</a>.</p>
</div>

<div class="card rule-card">
  <h2 id="caps">4. Vault drain protection &mdash; vault never drains, always grows</h2>
  <p>The vault is the network's long-term staking reserve. A consensus-enforced rule guarantees the vault holds a positive growth rate every cycle, even at scale:</p>
  <ul>
    <li><strong>Inflow cap:</strong> at most <strong>90%</strong> of the vault inflow during a cycle (~480 blocks of coinbase splits + transaction fees + every-100th-block bonuses) is paid to stakers. The remaining <strong>10%</strong> stays as principal &mdash; the vault grows by that 10% every cycle, forever.</li>
    <li><strong>Backstop ceiling:</strong> never more than <strong>8%</strong> of the vault balance distributes in one cycle. (Defence-in-depth; the inflow cap binds first in normal operation.)</li>
    <li><strong>Pool never freezes:</strong> distributions fire whenever there's at least one active staker.</li>
  </ul>
  <p style="color:var(--muted);font-size:12px">These limits are a hard guarantee enforced at consensus time. The multiplier system can only redistribute the cycle budget between stakers; it can never enlarge it. Because at most 90% of inflow leaves per cycle, the vault grows monotonically &mdash; an early-staker bonanza is impossible by design, and the post-emission-era fee economy inherits a substantial principal that funds stakers indefinitely.</p>
</div>

<div class="card rule-card">
  <h2 id="whale">5. Concentration limit</h2>
  <p>No single staker can receive more than <strong>75%</strong> of any one distribution cycle, no matter how big their stake or multiplier is. If their share would exceed 75%, the excess <em>stays in the vault for the next cycle</em> &mdash; it is never redistributed back to other stakers.</p>
  <p style="color:var(--muted);font-size:12px">At realistic network scale (many active stakers) the limit is dormant: every staker's share is well under 75% and the full cycle distributes. The 75% number is set so a max-lockup staker still earns the full multiplier they were promised; the math is in the <a href="https://veld.network/whitepaper.pdf" style="color:var(--em);text-decoration:underline">whitepaper</a>.</p>
</div>

<div class="card rule-card">
  <h2 id="multiplier">6. How the staking multiplier is built</h2>
  <p>Your <strong>staking multiplier</strong> is the value that boosts your share of every vault distribution. It comes from two ladders:</p>
  <ul>
    <li><strong>Mining tier</strong> &mdash; rewards you for being an <em>active miner</em> over time (see &sect;8).</li>
    <li><strong>Lockup tier</strong> &mdash; rewards you for <em>committing your stake longer</em> (see &sect;7).</li>
  </ul>
  <p>The two multiply together, with a consensus-enforced maximum of <strong>3.00&times;</strong>.</p>
  <table class="tbl-rules tier-combinations">
    <tr><th>Mining tier</th><th>Lockup tier</th><th>Staking multiplier</th></tr>
    <tr><td>Base</td><td>7 days</td><td>1.00&times;</td></tr>
    <tr><td>Base</td><td>90 days</td><td>1.50&times;</td></tr>
    <tr><td class="tier-name tier-silver">Silver</td><td>90 days</td><td>1.875&times;</td></tr>
    <tr><td class="tier-name tier-platinum">Platinum</td><td>90 days</td><td>2.70&times;</td></tr>
    <tr><td><span class="diamond-prismatic">Diamond</span></td><td>30 days</td><td><span class="diamond-prismatic">3.00&times;</span></td></tr>
  </table>
</div>

<div class="card rule-card">
  <h2 id="stakelock">7. Stake lockup tiers</h2>
  <p>When you stake, you pick how long to lock it. Longer commitment = bigger multiplier. You can&#39;t unstake before the lockup expires.</p>
  <table class="tbl-rules">
    <tr><th>Lockup</th><th>Duration</th><th>Multiplier</th></tr>
    <tr><td>Base</td><td>7 days</td><td>1.00&times;</td></tr>
    <tr><td>Short</td><td>14 days</td><td>1.10&times;</td></tr>
    <tr><td>Medium</td><td>30 days</td><td>1.25&times;</td></tr>
    <tr><td>Long</td><td>90 days</td><td>1.50&times;</td></tr>
  </table>
  <p style="color:var(--muted);font-size:12px">You can hold multiple stakes at the same address with different lockups. Each one unlocks on its own schedule &mdash; adding a new stake doesn't reset older ones.</p>
</div>

<div class="card rule-card">
  <h2 id="minetier">8. Mining tier ladder</h2>
  <p>Mining tiers reward consistent mining over time. A day counts as <strong>active</strong> for your address if you mined at least one block during it &mdash; it doesn't matter whether you found 1 or 100. Your tier is recomputed every block from a rolling window of recent days.</p>
  <table class="tbl-rules tier-ladder">
    <tr><th>Tier</th><th>Requirement</th><th>Multiplier</th></tr>
    <tr><td>Base</td><td>Mine any block</td><td>1.00&times;</td></tr>
    <tr><td class="tier-name tier-bronze">Bronze</td><td>7 active days out of last 14</td><td>1.10&times;</td></tr>
    <tr><td class="tier-name tier-silver">Silver</td><td>25 out of last 30</td><td>1.25&times;</td></tr>
    <tr><td class="tier-name tier-gold">Gold</td><td>165 out of last 180</td><td>1.50&times;</td></tr>
    <tr><td class="tier-name tier-platinum">Platinum</td><td>335 out of last 365</td><td>1.80&times;</td></tr>
    <tr><td class="diamond-prismatic">Diamond</td><td>1,000 out of last 1,095</td><td class="diamond-prismatic">3.00&times;</td></tr>
  </table>
  <p style="color:var(--muted);font-size:12px">Tiers are not permanent: each tier is recalculated as active days enter and leave its rolling window. The full rolling-window logic is in the <a href="https://veld.network/whitepaper.pdf" style="color:var(--em);text-decoration:underline">whitepaper</a>.</p>
</div>

<div class="card rule-card">
  <h2 id="endorse">9. Validators &amp; the validator pool</h2>
  <p>Validators run a daemon that signs each new block &mdash; an <em>endorsement</em>. The validator pool collects <strong>10% of every block&#39;s reward</strong> and pays it out every <strong>480 blocks</strong> (daily) in proportion to each validator&#39;s endorsement count over the trailing 480-block window. Idle validators earn nothing for that cycle.</p>
  <ul>
    <li><strong>System unlock.</strong> Staking first activates when issued supply reaches 10,000 VELD. After that, the validator subsystem unlocks when aggregate ordinary stake reaches <strong>10,000 VELD</strong>. Until then, no endorsements are accepted and the 10% pool accumulates.</li>
    <li><strong>Register on-chain.</strong> You submit a <span class="formula">VELD_VALIDATOR|REGISTER</span> transaction binding your ML-DSA-65 public key. A matching <span class="formula">DEREGISTER</span> exits cleanly.</li>
    <li><strong>Bond the minimum.</strong> Registration requires posting the minimum validator bond of <strong>10,000 VELD</strong> (see &sect;10) into the sigless custody vault. The live value is shown on the <a href="/validators" style="color:var(--em);text-decoration:underline">Validators page</a>.</li>
    <li><strong>Stay online.</strong> Endorsement share is your count &divide; the network&#39;s count over the last 480 blocks &mdash; consistent uptime is what pays.</li>
  </ul>
  <p style="color:var(--muted);font-size:12px">Endorsement is one of three independent reward streams: the <em>co-mining lottery</em> is a flat draw (&sect;11), the <em>vault</em> pays every staker (&sect;3), and only the <em>validator pool</em> is endorsement-gated. They do not overlap and you can earn from more than one.</p>
</div>

<div class="card rule-card">
  <h2 id="valbond">10. Validator bond, slashing &amp; yield escrow</h2>
  <p>A validator&#39;s registration bond is not just a balance check &mdash; it is real, slashable capital. The custody, slashing, and reporter-bounty rules are compiled from genesis; validator operations become available only after the staking and aggregate-stake gates are satisfied.</p>
  <h3>The bond (custody)</h3>
  <p>At registration the minimum bond is sent into a <strong>sigless custody vault</strong> &mdash; an address whose key nobody holds, so the principal cannot be moved arbitrarily. It sits there as collateral for as long as you validate. After a clean deregistration it remains slashable through the complete <strong>43,200-block (~90-day) finality-equivocation evidence horizon</strong>, measured from the validator's last counted finality vote when that is later. It is then <strong>returned to you in full</strong> by the mandatory, zero-fee canonical transaction at the first 480-block settlement boundary strictly after that horizon (up to about 91 days after the controlling event).</p>
  <h3>Slashing &mdash; two evidence classes</h3>
  <p>Signing conflicting statements is cryptographically provable. Anyone can submit the applicable proof. A verified slash is <strong>permanent</strong>: the offending public key is banned and can <em>never</em> re-register. Ordinary endorsement double-sign evidence uses the standard settlement:</p>
  <table class="tbl-rules">
    <tr><th>Share</th><th>Goes to</th><th>Why</th></tr>
    <tr><td style="color:var(--em);font-weight:600">25%</td><td>The reporter</td><td>Bounty &mdash; pays anyone who catches and proves an equivocation</td></tr>
    <tr><td style="color:var(--gold);font-weight:600">25%</td><td>The vault</td><td>Returned to the staking reserve the validator was meant to protect</td></tr>
    <tr><td style="color:var(--muted);font-weight:600">50%</td><td>The offender</td><td>Returned principal; the other 50% is confiscated and the validator remains permanently banned</td></tr>
  </table>
  <p>A conflicting locked-finality vote is the stronger <strong>finality-equivocation</strong> class. It returns <strong>0%</strong> to the offender, pays <strong>25%</strong> to the reporter, and sends <strong>75%</strong> to a provably unspendable burn output. The two schedules are intentionally distinct and are selected by the evidence type in consensus.</p>
  <h3>Yield escrow</h3>
  <p>Idle collateral is wasteful, so the bonded principal <strong>also earns vault yield at the top lockup tier (1.5&times;)</strong>. Because it is paid at the 90-day tier rate, that yield is not paid out immediately &mdash; it is <strong>escrowed and vests on a rolling ~90-day delay</strong> (43,200 blocks), matching the multiplier it earns:</p>
  <ul>
    <li>Vested yield is released to the validator on the normal settlement schedule.</li>
    <li>If the validator is slashed, the still-<em>unvested</em> tail is clawed back along with the bond.</li>
    <li>Already-vested income is kept &mdash; behave for years then slip once and you only forfeit the recent unvested tail around the offence, not your whole earning history.</li>
  </ul>
  <p style="color:var(--muted);font-size:12px">Live custody-vault and yield-escrow balances, per-validator bond status (custodial / slashed), and the slashing-evidence ledger are all on the <a href="/validators" style="color:var(--em);text-decoration:underline">Validators page</a>. Full vesting schedule and confiscation derivation are in the <a href="https://veld.network/whitepaper.pdf" style="color:var(--em);text-decoration:underline">whitepaper</a>.</p>
</div>

<div class="card rule-card">
  <h2 id="poolflush">11. Co-mining lottery</h2>
  <p>Mining doesn't have to win the block to pay you. The 20% co-mining pool collects on every block and pays out every <strong>100 blocks</strong> through a simple uniform lottery:</p>
  <ul>
    <li>Mine the chain. Your node automatically submits "near-misses" &mdash; hashes that came close to the target but didn't quite win the block.</li>
    <li>Have the minimum stake locked at your mining address. (Same stake as for vault distributions, no double-lock.)</li>
    <li>Submit at least one valid near-miss in the 100-block window &mdash; that's it.</li>
  </ul>
  <p>At the end of each window, five eligible miners are selected uniformly; the draw expands to 20 winners once at least 1,000 miners are eligible. Each eligible address has one entry regardless of near-miss count, and each window starts fresh. Randomness derivation and consensus enforcement are documented in the <a href="https://veld.network/whitepaper.pdf#co-mining-lottery" style="color:var(--em);text-decoration:underline">whitepaper</a>.</p>
</div>

<div class="card rule-card">
  <h2 id="governance">12. Governance</h2>
  <p>Governance activates when at least five validators have bonded an aggregate <strong>50,000 VELD</strong>. Each validator contributes at most its 10,000 VELD minimum bond toward that activation threshold.</p>
  <div class="peg-grid">
    <div class="peg-item"><span class="k">Who participates</span><span class="v">Registered, recently active validators submit proposals and vote.</span></div>
    <div class="peg-item"><span class="k">Voting window</span><span class="v"><strong>6,720 blocks</strong>, approximately 14 days.</span></div>
    <div class="peg-item"><span class="k">General proposals</span><span class="v"><strong>51% yes.</strong> The quorum is seven votes when at least seven validators are recently active; below that it follows a majority of active validators.</span></div>
    <div class="peg-item"><span class="k">Protocol upgrades</span><span class="v"><strong>67% yes</strong> with a hard minimum of ten votes, followed by a seven-day timelock.</span></div>
  </div>
  <p>Passing a protocol-upgrade proposal records on-chain approval after the timelock. It does not automatically replace node binaries or mutate consensus parameters; a software upgrade still requires published source, signed artifacts, operator adoption, and an activation plan.</p>
</div>

<div class="card rule-card">
  <h2 id="privacy">13. Privacy &amp; safety</h2>
  <ul>
    <li><strong>Your private key never leaves your machine.</strong> The wallet signs every transaction locally; only the signed bytes go on the wire.</li>
    <li><strong>No deep rewrites.</strong> A branch that would remove 100 or more blocks is rejected. Once validator finality and a locally observed Bitcoin anchor floor exist, those retained checkpoints add stronger limits.</li>
    <li><strong>Vault drain protection.</strong> The 90% inflow cap (vault retains &ge;10% of every cycle's inflow as principal), 8% balance backstop, and 75% per-staker concentration limit collectively make vault drain impossible &mdash; the reserve grows monotonically.</li>
    <li><strong>Coinbase maturity.</strong> Newly-mined VELD (including co-mining and validator-pool payouts) is spendable only after 100 confirmations. Stops reorg-and-spend attacks.</li>
    <li><strong>Post-quantum signatures.</strong> Every transaction is signed with ML-DSA-65 (NIST FIPS 204), so a future quantum computer doesn&#39;t invalidate a single UTXO.</li>
  </ul>
</div>

<div class="card rule-card">
  <h2 id="difficulty">14. Difficulty retargeting</h2>
  <p>The chain aims at a <strong>180-second block time</strong>. Mining difficulty re-tunes itself once every <strong>144 blocks</strong> based on how fast the previous window of blocks was found. If miners are finding blocks too fast, difficulty rises; too slow, it falls. For the first 390 blocks after genesis the chain uses a faster 36-block window with a wider adjustment clamp, so a brand-new network settles to its real hashrate within hours no matter how many miners show up on day one.</p>
  <p>Each standard retarget clamps the window's measured block time to between <strong>0.5&times; and 1.5&times;</strong> of target before adjusting, so difficulty can at most roughly double (or fall to about two-thirds) in one step &mdash; a hashrate spike or drop can never push the chain off balance suddenly. If the network briefly stalls, mining waits for the next 144-block retarget boundary &mdash; LWMA reads the previous window's timestamps and re-targets to the current hashrate without any special-case eased-bits rule.</p>
  <p style="color:var(--muted);font-size:12px">The retarget algorithm is LWMA (Linear Weighted Moving Average) over a 144-block window. Full math, clamp rationale, and consensus-enforcement details are in the <a href="https://veld.network/whitepaper.pdf" style="color:var(--em);text-decoration:underline">whitepaper</a>.</p>
</div>

<div class="card rule-card">
  <h2 id="btcveld">15. btcVELD &mdash; the Bitcoin peg</h2>
  <div class="peg-status"><strong>Activation:</strong> btcVELD becomes available after seven qualified validators complete the finality warm-up. This is a one-time activation threshold; falling below seven later does not disable an active peg.</div>
  <div class="peg-grid">
    <div class="peg-item"><span class="k">Backing</span><span class="v"><strong>1 btcVELD = 1 BTC</strong> held in peg custody.</span></div>
    <div class="peg-item"><span class="k">Custody</span><span class="v"><strong>10 BTC aggregate hard cap.</strong> There is no per-address or per-mint cap. Issuer-assisted headroom can be lower while the network work tier matures; permissionless SPV mints share only the 10 BTC ceiling. Live capacity is shown in the wallet.</span></div>
    <div class="peg-item"><span class="k">Wrap</span><span class="v">A confirmed BTC deposit mints the same amount of btcVELD to the selected Veld address.</span></div>
    <div class="peg-item"><span class="k">Redeem</span><span class="v">Burn btcVELD to receive the matching BTC at the Bitcoin address you choose.</span></div>
  </div>
  <h3>Verification and safety</h3>
  <ul>
    <li><strong>Consensus enforcement.</strong> Every node validates each mint, transfer, redeem, custody limit, and daily redemption limit.</li>
    <li><strong>Bitcoin proofs.</strong> Nodes maintain verified Bitcoin headers and validate deposits with light-client proofs. Header relay transactions pay VELD fees and do not spend BTC.</li>
    <li><strong>Solvency watchtower.</strong> New issuance pauses if custody can no longer be proven to cover btcVELD supply.</li>
    <li><strong>Finality anchors.</strong> Once validator finality is active, confirmed Bitcoin anchors prevent reorganizations below the retained anchored checkpoint. Anchors spend ordinary Bitcoin network fees.</li>
  </ul>
  <h3>Liquidity</h3>
  <p>The on-chain VELD/btcVELD pool shares the same 10 BTC aggregate custody cap. The first successful seed establishes the reference ratio. Swap fees remain in the pool for liquidity providers and are separate from the native VELD transaction fee.</p>
  <table class="tbl-rules">
    <tr><th>Post-trade deviation from reference</th><th>Swap fee</th></tr>
    <tr><td>Improves the ratio or stays within 5%</td><td>0.30%</td></tr>
    <tr><td>Above 5% through 10%</td><td>0.50%</td></tr>
    <tr><td>Above 10% through 20%</td><td>0.75%</td></tr>
    <tr><td>Above 20%</td><td>1.00%</td></tr>
  </table>
</div>

<div class="card rule-card">
  <h2 id="syncing">16. Syncing &amp; trust</h2>
  <p>Veld 3.0.4 public-mainnet nodes can start from an <strong>official signed snapshot</strong> or perform a full IBD from genesis. Snapshot bytes are consensus-replayed locally before use and are bound to this deployment, genesis, launch-chain anchor, height, tip, and complete state schema.</p>
  <p>A snapshot is an availability optimization, not a consensus authority. RPC, inbound P2P, explorer, mining, and validator signing remain quarantined while an independent genesis IBD downloads and validates every block and proof of work into a separate chainstate. Those services activate only after the independent chain reaches the exact snapshot tip and complete state digest.</p>
  <p>If the signed snapshot is missing, stale, malformed, from a different chain, or fails validation, the client rejects it and falls back to ordinary peer synchronization. <code>--full-ibd</code> or <code>--no-snapshot</code> always selects validation from genesis without importing a snapshot.</p>
  <p>Before validator finality activates, a fresh node relies on independently verified proof of work and the bounded reorganization horizon. After it observes a confirmed Bitcoin anchor for a finalized Veld tip (see &sect;15), it retains that locally verified floor and rejects histories that conflict with it.</p>
</div>

)HTML";
        // Bind the page to the exact chain it describes. The genesis hash is
        // the chain's identity, so a Rules page can never be mistaken for one
        // served by a different network. Deliberately the hash and not the
        // profile name: the wording must read identically on every build.
        std::ostringstream identity;
        identity << PAGE
                 << "<div class=\"card rule-card\">"
                    "<h2 id=\"chain-identity\">17. Chain identity</h2>"
                    "<p>These rules describe the current launch-prep chain, whose genesis block is"
                    " <code style=\"overflow-wrap:anywhere\">"
                 << GENESIS_HASH
                 << "</code>. A node that reports a different genesis is not"
                     " this network, whatever a page says. The August 30 public network will publish a fresh genesis with the final signed release.</p></div>";
        return HttpResponse::HTML(
            HtmlWrapArcade("Rules", identity.str(), "rules"));
    }

    HttpResponse ServeGovernance() {
        size_t active_validators = 0;
        if (validators_) {
            active_validators = validators_->GetActiveValidatorCount();
        } else if (rpc_delegate_) {
            auto resp = rpc_delegate_->Handle(R"({"jsonrpc":"2.0","id":"1","method":"getvalidators","params":[]})");
            auto p = resp.find("\"validator_count\":");
            if (p != std::string::npos) {
                try { active_validators = std::stoull(resp.substr(p + 18)); } catch (...) {}
            }
        }
        bool gov_active = true;

        std::ostringstream c;

        c << "<div class=\"stat-grid\" style=\"margin-bottom:20px\">";
        c << "<div class=\"stat\"><div class=\"stat-label\">Governance Status</div>"
          << "<div class=\"stat-value " << (gov_active ? "em" : "") << "\">"
          << (gov_active ? "Active" : "Inactive") << "</div>"
          << "<div class=\"stat-sub\">"
          << (gov_active ? "Proposals and voting are open"
                         : "Requires " + std::to_string(GOV_MIN_ACTIVE_VALIDATORS) + " active validators")
          << "</div></div>";
        c << "<div class=\"stat\"><div class=\"stat-label\">Active Validators</div>"
          << "<div class=\"stat-value em\">" << active_validators << "</div>"
          << "<div class=\"stat-sub\">" << GOV_MIN_ACTIVE_VALIDATORS
          << " distinct validators bonding 50,000 VELD total unlock governance</div></div>";
        c << "<div class=\"stat\"><div class=\"stat-label\">Proposal Voting Window</div>"
          << "<div class=\"stat-value\">" << (GOV_VOTE_DURATION_DAYS * BLOCKS_PER_DAY) << " blocks</div>"
          << "<div class=\"stat-sub\">~" << GOV_VOTE_DURATION_DAYS << " days</div></div>";
        c << "<div class=\"stat\"><div class=\"stat-label\">Pass Threshold</div>"
          << "<div class=\"stat-value\">" << GOV_PASS_PCT_GENERAL << "%</div>"
          << "<div class=\"stat-sub\">simple majority (protocol: " << GOV_PASS_PCT_PROTOCOL << "% supermajority)</div></div>";
        c << "</div>";

        c << R"HTML(
<style>
/* Governance page styling matches the rest of the explorer. Buttons use
   charcoal with a colored hairline
   instead of gradient fills. Inputs match the .fi from the main CSS.
   Card / badge / progress bar palettes pulled from --gold / --em / --red. */
.fi{width:100%;background:var(--s3);border:1px solid var(--b1);color:var(--text);padding:10px 14px;border-radius:6px;font-size:14px;font-family:inherit;outline:none;margin-bottom:10px;box-sizing:border-box;transition:border-color .2s;}
.fi:focus{border-color:rgba(255,216,74,.5);}
.btn-gold{background:#1A1F1F;color:#F0F0F0;border:1px solid var(--gold);box-shadow:inset 0 0 0 1px rgba(255,216,74,.22);width:100%;}
.btn-gold:hover{background:#222827;box-shadow:inset 0 0 0 1px rgba(255,216,74,.32),0 0 14px rgba(255,216,74,.10);}
.btn-yes{background:#1A1F1F;color:#F0F0F0;border:1px solid var(--em);box-shadow:inset 0 0 0 1px rgba(50,240,110,.22);flex:1;}
.btn-yes:hover{background:#222827;box-shadow:inset 0 0 0 1px rgba(50,240,110,.32);}
.btn-no{background:#1A1F1F;color:#F0F0F0;border:1px solid var(--red);box-shadow:inset 0 0 0 1px rgba(255,76,76,.22);flex:1;}
.btn-no:hover{background:#221b1b;box-shadow:inset 0 0 0 1px rgba(255,76,76,.32);}
.btn-abs{background:#1A1F1F;color:#F0F0F0;border:1px solid #555;flex:1;}
.btn-abs:hover{background:#222827;}
.btn-sm{padding:8px 14px;font-size:12px;}
.alert{padding:12px 16px;border-radius:6px;font-size:13px;margin-top:10px;display:none;}
.alert-ok{background:rgba(50,240,110,.06);border:1px solid rgba(50,240,110,.2);color:var(--em);}
.alert-err{background:rgba(255,76,76,.06);border:1px solid rgba(255,76,76,.2);color:var(--red);}
.alert-info{background:rgba(76,184,255,.06);border:1px solid rgba(76,184,255,.2);color:var(--blue);}
.prop-card{background:var(--s2);border:1px solid var(--b1);border-radius:8px;padding:20px;margin-bottom:12px;transition:border-color .2s;}
.prop-card:hover{border-color:var(--b2);}
.prop-card.open{border-color:rgba(50,240,110,.24);}
.prop-card.passed{border-color:rgba(255,216,74,.24);}
.prop-card.rejected{border-color:rgba(255,76,76,.24);}
.prop-card.expired{border-color:rgba(85,85,85,.24);}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;}
.badge-general{background:rgba(76,184,255,.08);color:var(--blue);border:1px solid rgba(76,184,255,.25);}
.badge-open{background:rgba(50,240,110,.06);color:var(--em);border:1px solid rgba(50,240,110,.25);}
.badge-passed{background:rgba(255,216,74,.06);color:var(--gold);border:1px solid rgba(255,216,74,.25);}
.badge-rejected{background:rgba(255,76,76,.06);color:var(--red);border:1px solid rgba(255,76,76,.25);}
.badge-expired{background:rgba(85,85,85,.06);color:#888;border:1px solid rgba(85,85,85,.25);}
.prog-bar{background:var(--s3);border-radius:4px;height:10px;overflow:hidden;margin:10px 0;display:flex;}
.prog-yes-seg{background:var(--em);height:100%;transition:width .3s;}
.prog-no-seg{background:var(--red);height:100%;transition:width .3s;}
.prog-abs-seg{background:#555;height:100%;transition:width .3s;}
.req-row{display:flex;align-items:center;gap:8px;padding:6px 0;font-size:13px;}
.req-ok{color:var(--em);} .req-no{color:var(--red);}
.type-select{width:100%;background:var(--s3);border:1px solid var(--b1);color:var(--text);padding:12px 14px;border-radius:6px;font-size:14px;font-family:inherit;outline:none;margin-bottom:14px;cursor:pointer;appearance:none;-webkit-appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%23888' fill='none' stroke-width='2'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center;}
.type-select:focus{border-color:rgba(255,216,74,.5);}
.section-label{font-size:11px;color:var(--muted);margin-bottom:10px;font-weight:600;}
.req-box{background:var(--s2);border:1px solid var(--b1);border-radius:8px;padding:16px;margin-bottom:8px;}
.req-heading{font-size:13px;color:var(--gold);margin-bottom:10px;font-weight:600;display:flex;align-items:center;gap:6px;}
.cost-display{background:var(--s2);border:1px solid var(--b1);border-radius:6px;padding:12px;margin:10px 0;font-size:13px;color:var(--muted);text-align:center;}
.cost-display b{color:var(--gold);font-size:16px;}
.vote-addr-row{display:flex;gap:8px;margin-bottom:8px;}
.vote-addr-row .fi{margin-bottom:0;flex:1;}
.tab-filter{display:flex;gap:4px;margin-bottom:16px;}
.tab-filter button{background:var(--s2);border:1px solid var(--b1);color:var(--muted);padding:6px 14px;border-radius:20px;cursor:pointer;font-size:12px;font-weight:500;transition:all .15s;}
.tab-filter button.active{background:rgba(255,216,74,.08);border-color:rgba(255,216,74,.3);color:var(--gold);}
.tab-filter button:hover{border-color:var(--b2);color:var(--text);}
.empty-state{text-align:center;color:var(--muted);padding:40px;font-size:14px;}
.empty-state .empty-icon{font-size:32px;margin-bottom:12px;opacity:.3;}
</style>

<!-- ELIGIBILITY & REQUIREMENTS -->
<div class="grid-2" style="margin-bottom:24px">
  <div class="card">
    <h2 style="display:flex;align-items:center;gap:8px">&#128736; Check Your Eligibility</h2>
    <input class="fi" id="elig-addr" placeholder="Your Veld address (V...)" data-act-keydown="e9dd9760b">
    <button class="btn btn-gold" data-act-click="ea2b0b337">Check Eligibility</button>
    <div id="elig-result" style="margin-top:12px"></div>
  </div>
  <div class="card">
    <h2 style="display:flex;align-items:center;gap:8px">&#128220; Governance Rules</h2>

    <div class="req-box">
      <div class="req-heading">&#9733; Who Can Participate</div>
      <div class="req-row">&#9654; <b style="color:#e0e0e0;margin:0 4px">Active validators only</b> &mdash; must have endorsed in the last ~1 week</div>
      <div class="req-row">&#9654; Register as a validator on the <a href="/validators" style="color:#c9a84c">Validators page</a></div>
    </div>

    <div class="req-box">
      <div class="req-heading">&#9878; Voting Thresholds</div>
      <div class="req-row">&#9654; <b style="color:#e0e0e0">General proposals:</b> <b style="color:#3dba6f">51%</b> yes votes to pass</div>
      <div class="req-row">&#9654; <b style="color:#e0e0e0">Protocol upgrades:</b> <b style="color:#e0c068">67%</b> yes votes to pass (supermajority)</div>
      <div class="req-row">&#9654; Voting window: <b style="color:#e0e0e0">3,360 blocks</b> (~7 days)</div>
      <div class="req-row">&#9654; If quorum not reached, proposal expires automatically</div>
    </div>

    <div class="req-box">
      <div class="req-heading">&#9202; Protocol Upgrade Timelock</div>
      <div class="req-row">&#9654; Even after passing, protocol upgrades wait <b style="color:#e0c068">3,360 blocks</b> (~7 days) before activation</div>
      <div class="req-row">&#9654; This gives the community time to review and intervene if needed</div>
    </div>

  </div>
</div>

<!-- SUBMIT PROPOSAL -->
<div class="card" style="margin-bottom:24px">
  <h2 style="display:flex;align-items:center;gap:8px">&#128228; Submit a Proposal</h2>

  <div class="section-label">Your Address</div>
  <input class="fi" id="prop-addr" placeholder="Your Veld address (V...)">

  <div class="section-label">Proposal Type</div>
  <select class="type-select" id="gov-type" data-act-change="e4e01b891">
    <option value="general">General Proposal (Advisory)</option>
  </select>

  <!-- General Proposal Fields -->
  <div id="gov-general">
    <div style="background:#0a0a0a;border:1px solid #1a1a1a;border-radius:8px;padding:4px 12px 12px;margin-bottom:14px">
      <div style="font-size:11px;color:#6ea8fe;padding:8px 0 4px;font-weight:600">ADVISORY PROPOSAL</div>
      <div style="font-size:12px;color:#555;margin-bottom:10px">Advisory only &mdash; does not change the protocol. Anyone meeting proposer requirements can submit.</div>
      <input class="fi" id="gov-title" placeholder="Proposal title...">
      <textarea class="fi" id="gov-desc" placeholder="Describe your proposal in detail. Explain the rationale, expected impact, and any relevant context..." style="height:120px;resize:vertical"></textarea>
    </div>
  </div>

  <div style="font-size:12px;color:#888;margin-bottom:12px;padding:8px 12px;border:1px solid #222;border-radius:6px;background:#0a0a0a">&#128274; Your wallet address will be verified for eligibility before submission.</div>
  <button class="btn btn-gold" data-act-click="ef71aa4a1" style="font-size:15px;padding:12px 20px">Submit Proposal</button>
  <div class="alert" id="prop-res"></div>
</div>

<!-- ACTIVE PROPOSALS -->
<div class="card">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <h2 style="margin:0;display:flex;align-items:center;gap:8px">&#128203; Proposals</h2>
    <button class="btn btn-sm" style="background:#222;color:#aaa;border:1px solid #333" data-act-click="e638a47af">&#8635; Refresh</button>
  </div>

  <div class="tab-filter" id="prop-filters">
    <button class="active" data-act-click="e3f7ea4c9">All</button>
    <button data-act-click="e68a464f9">Open</button>
    <button data-act-click="e22f51807">Passed</button>
    <button data-act-click="e5482e327">Rejected</button>
    <button data-act-click="edebab07a">Expired</button>
  </div>

  <div id="proposals-list"><div class="empty-state"><div class="empty-icon">&#9881;</div>Loading proposals...</div></div>
</div>

<script nonce="__CSP_NONCE__">
var allProposals = [];
var currentFilter = 'all';

/* --- Eligibility Check --- */
function checkEligibility(){
  var addr = document.getElementById('elig-addr').value.trim();
  if(!addr) return;
  fetch('/api/tierstatus?address=' + encodeURIComponent(addr))
    .then(function(r){ return r.json(); })
    .then(function(d){
      var isValidator = d.is_validator || false;
      var staked = parseFloat(d.staked_veld || 0);
      var mined = d.blocks_mined || 0;
      var html = '<div style="background:#111;border:1px solid #2a2a2a;border-radius:8px;padding:16px">'
        + '<div class="req-row ' + (isValidator ? 'req-ok' : 'req-no') + '">' + (isValidator ? '&#10003;' : '&#10007;') + ' Registered Validator</div>'
        + '<div class="req-row" style="color:#888">&#9654; Staked: <b>' + staked.toFixed(2) + ' VELD</b></div>'
        + '<div class="req-row" style="color:#888">&#9654; Blocks mined: <b>' + mined + '</b></div>'
        + '<div style="border-top:1px solid #222;margin:10px 0"></div>'
        + '<div style="padding:12px;border-radius:6px;text-align:center;background:' + (isValidator ? '#0d2a1a' : '#2a0d0d') + ';color:' + (isValidator ? '#3dba6f' : '#e05252') + ';font-weight:700;font-size:14px">'
        + (isValidator ? '&#10003; Eligible &mdash; You can vote and propose' : '&#10007; Not Eligible &mdash; Register as a validator to participate') + '</div>'
        + '</div>';
      document.getElementById('elig-result').innerHTML = html;
    }).catch(function(){ document.getElementById('elig-result').innerHTML = '<div style="color:#e05252">Could not connect to node.</div>'; });
}

/* --- Submit Proposal --- */
function submitProposal(){
  var addr = document.getElementById('prop-addr').value.trim();
  var res = document.getElementById('prop-res');

  if(!addr){ showAlert(res, 'err', 'Please enter your Veld address.'); return; }

  // Warn: explorer submissions aren't signed — use wallet app for authenticated proposals
  if(!confirm('Note: Proposals submitted through the explorer are not cryptographically signed. For authenticated submissions, use the Veld Wallet app. Continue anyway?')) return;

  // Client-side eligibility check before submission
  showAlert(res, 'info', 'Verifying eligibility for address ' + escHtml(addr) + '...');
  res.style.display = 'block';

  fetch('/api/tierstatus?address=' + encodeURIComponent(addr))
    .then(function(r){ return r.json(); })
    .then(function(d){
      var mined = d.blocks_mined || 0;
      var staked = parseFloat(d.staked_veld || 0);
      var held = parseFloat(d.held_veld || 0);
      var isValidator = d.is_validator || false;

      // Use dynamic thresholds from the API response
      var reqBlocks = d.req_min_blocks || 1;
      var reqStaked = parseFloat(d.req_min_staked || 10);
      var reqHeld = parseFloat(d.req_min_held || 10);
      var reqPropHeld = parseFloat(d.req_proposer_held || 20);

      if(mined < reqBlocks){ showAlert(res, 'err', 'Ineligible: Need ' + reqBlocks + ' blocks mined (you have ' + mined + ').'); return; }
      if(staked < reqStaked){ showAlert(res, 'err', 'Ineligible: Need ' + reqStaked + ' VELD staked (you have ' + staked.toFixed(2) + ').'); return; }
      if(held < reqPropHeld){ showAlert(res, 'err', 'Ineligible: Need ' + reqPropHeld + ' VELD held (you have ' + held.toFixed(2) + ').'); return; }
      doSubmitGeneral(addr, res);
    }).catch(function(){
      showAlert(res, 'err', 'Could not verify eligibility. Please check your address and try again.');
    });
}

function doSubmitGeneral(addr, res){
    var title = document.getElementById('gov-title').value.trim();
    var desc = document.getElementById('gov-desc').value.trim();
    if(!title || !desc){ showAlert(res, 'err', 'Please fill in both the title and description.'); return; }

    fetch('/api/rpc', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({method: 'submitproposal', params: [addr, title, desc], id: 1})
    }).then(function(r){ return r.json(); })
    .then(function(d){
      if(d.error){
        showAlert(res, 'err', 'Error: ' + escHtml(d.error.message || d.error));
      } else {
        showAlert(res, 'ok', 'Proposal submitted successfully! ID: <b>' + escHtml(d.result && d.result.id ? d.result.id : 'pending') + '</b>');
        document.getElementById('gov-title').value = '';
        document.getElementById('gov-desc').value = '';
        loadProposals();
      }
    }).catch(function(){
      showAlert(res, 'ok', 'Submit via node RPC:<br><code style="font-size:11px;word-break:break-all">curl -X POST http://127.0.0.1:)HTML" << CompiledPublicRpcPort() << R"HTML( -d \'{"method":"submitproposal","params":["' + escHtml(addr) + '","' + escHtml(title) + '","' + escHtml(desc) + '"],"id":1}\'</code>');
    });
}

/* --- Load & Render Proposals --- */
function loadProposals(){
  fetch('/api/proposals').then(function(r){ return r.json(); }).then(function(proposals){
    allProposals = proposals || [];
    renderProposals();
  }).catch(function(){
    document.getElementById('proposals-list').innerHTML = '<div class="empty-state"><div class="empty-icon">&#9888;</div>Could not load proposals from the node.</div>';
  });
}

function renderProposals(){
  var el = document.getElementById('proposals-list');
  var filtered = allProposals;
  if(currentFilter !== 'all'){
    filtered = allProposals.filter(function(p){ return p.status === currentFilter; });
  }
  if(!filtered.length){
    var msg = currentFilter === 'all' ? 'No proposals yet. Be the first to propose a change.' : 'No ' + escHtml(currentFilter) + ' proposals found.';
    el.innerHTML = '<div class="empty-state"><div class="empty-icon">&#128220;</div>' + msg + '</div>';
    return;
  }
  var html = '';
  filtered.forEach(function(p){
    var total = (p.votes_yes || 0) + (p.votes_no || 0) + (p.votes_abstain || 0);
    var yes_pct = total > 0 ? (p.votes_yes / total * 100) : 0;
    var no_pct = total > 0 ? (p.votes_no / total * 100) : 0;
    var abs_pct = total > 0 ? (p.votes_abstain / total * 100) : 0;

    var typeBadge = '<span class="badge badge-general">GENERAL</span>';
    var statusBadge = '<span class="badge badge-' + escHtml(p.status) + '">' + escHtml(p.status.toUpperCase()) + '</span>';

    var timeInfo = '';
    if(p.status === 'open' && p.expires_at){
      var now = Math.floor(Date.now() / 1000);
      var remaining = p.expires_at - now;
      if(remaining > 0){
        var days = Math.floor(remaining / 86400);
        var hours = Math.floor((remaining % 86400) / 3600);
        timeInfo = days > 0 ? days + 'd ' + hours + 'h remaining' : hours + 'h remaining';
      } else {
        timeInfo = 'Closing...';
      }
    } else {
      timeInfo = 'Closed';
    }

    html += '<div class="prop-card ' + escHtml(p.status) + '">';
    /* Header row: title + badges */
    html += '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;gap:12px">';
    var pid = parseInt(p.id) || 0;
    html += '<div style="flex:1"><span style="color:#444;font-size:12px;font-weight:600">#' + pid + '</span> ';
    html += '<span style="font-size:17px;font-weight:700;color:#e0e0e0">' + escHtml(p.title || p.name || 'Untitled') + '</span></div>';
    html += '<div style="display:flex;gap:6px;flex-shrink:0">' + typeBadge + statusBadge + '</div></div>';

    html += '<div style="font-size:13px;color:#aaa;margin-bottom:12px;line-height:1.5">' + escHtml(p.description || '') + '</div>';

    /* Meta row */
    html += '<div style="display:flex;justify-content:space-between;font-size:12px;color:#555;margin-bottom:6px">';
    html += '<span>By: <span class="hash" style="color:#777">' + (p.proposer ? escHtml(p.proposer.substring(0,16)) + '...' : 'unknown') + '</span></span>';
    html += '<span>' + timeInfo + '</span></div>';

    /* Multi-segment progress bar */
    html += '<div class="prog-bar">';
    html += '<div class="prog-yes-seg" style="width:' + yes_pct + '%"></div>';
    html += '<div class="prog-no-seg" style="width:' + no_pct + '%"></div>';
    html += '<div class="prog-abs-seg" style="width:' + abs_pct + '%"></div>';
    html += '</div>';

    /* Vote counts */
    html += '<div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:12px">';
    html += '<span style="color:#3dba6f">&#9650; Yes: ' + (p.votes_yes || 0) + ' (' + yes_pct.toFixed(1) + '%)</span>';
    html += '<span style="color:#e05252">&#9660; No: ' + (p.votes_no || 0) + ' (' + no_pct.toFixed(1) + '%)</span>';
    html += '<span style="color:#888">&#9644; Abstain: ' + (p.votes_abstain || 0) + '</span>';
    html += '<span style="color:#555">Total: ' + total + ' votes</span></div>';

    /* Vote buttons (only for open proposals) */
    if(p.status === 'open'){
      html += '<div class="vote-addr-row">';
      html += '<input class="fi" id="vote-addr-' + pid + '" placeholder="Your address to vote (V...)">';
      html += '</div>';
      html += '<div style="display:flex;gap:8px">';
      html += '<button class="btn btn-yes" data-act-click="e1b5d37d9" data-vote-id="'+pid+'" data-vote-choice="yes">&#9650; YES</button>';
      html += '<button class="btn btn-no" data-act-click="e18bb4b3a" data-vote-id="'+pid+'" data-vote-choice="no">&#9660; NO</button>';
      html += '<button class="btn btn-abs" data-act-click="e33c1e1c9" data-vote-id="'+pid+'" data-vote-choice="abstain">&#9644; ABSTAIN</button>';
      html += '</div>';
      html += '<div class="alert" id="vote-res-' + pid + '"></div>';
    }

    html += '</div>';
  });
  el.innerHTML = html;
}

/* --- Vote on Proposal --- */
function voteOnProposal(id, vote){
  var addrEl = document.getElementById('vote-addr-' + id);
  var addr = addrEl ? addrEl.value.trim() : '';
  var res = document.getElementById('vote-res-' + id);
  if(!addr){ showAlert(res, 'err', 'Please enter your Veld address to vote.'); return; }

  fetch('/api/rpc', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({method: 'vote', params: [addr, id, vote], id: 1})
  }).then(function(r){ return r.json(); })
  .then(function(d){
    if(d.error){
      showAlert(res, 'err', 'Error: ' + escHtml(d.error.message || d.error));
    } else {
      showAlert(res, 'ok', 'Vote recorded! You voted <b>' + escHtml(vote.toUpperCase()) + '</b> on proposal #' + id + '.');
      loadProposals();
    }
  }).catch(function(){
    showAlert(res, 'ok', 'Submit via node RPC:<br><code style="font-size:11px">curl -X POST http://127.0.0.1:)HTML" << CompiledPublicRpcPort() << R"HTML( -d \'{"method":"vote","params":["' + escHtml(addr) + '",' + id + ',"' + escHtml(vote) + '"],"id":1}\'</code>');
  });
}

/* --- Filter Proposals --- */
function filterProposals(status, btn){
  currentFilter = status;
  var buttons = document.querySelectorAll('#prop-filters button');
  for(var i = 0; i < buttons.length; i++) buttons[i].className = '';
  if(btn) btn.className = 'active';
  renderProposals();
}

/* --- Utilities --- */
function showAlert(el, type, msg){
  el.style.display = 'block';
  var cls = type === 'ok' ? 'alert-ok' : (type === 'info' ? 'alert-info' : 'alert-err');
  el.className = 'alert ' + cls;
  el.innerHTML = msg;
  if(type === 'ok'){
    setTimeout(function(){ el.style.display = 'none'; }, 15000);
  }
}

function escHtml(s){
  var d = document.createElement('div');
  d.appendChild(document.createTextNode(s));
  return d.innerHTML;
}

/* --- Auto-load & refresh --- */
loadProposals();
setInterval(loadProposals, 30000);
</script>)HTML";
        return HttpResponse::HTML(HtmlWrapArcade("Governance", c.str(), "governance"));
    }

    static constexpr uint64_t MAX_EXPLORER_INFLIGHT = 128;
    static constexpr int      EXPLORER_RECV_TIMEOUT_S = 10;
    static constexpr size_t   EXPLORER_MAX_BODY = 256 * 1024;

    static bool SendAll_(SocketHandle fd, const char* data, size_t size) {
        size_t sent = 0;
        while (sent < size) {
            const int chunk = static_cast<int>(std::min<size_t>(
                size - sent, static_cast<size_t>(INT_MAX)));
            const int wrote = ::send(fd, data + sent, chunk, MSG_NOSIGNAL);
            if (wrote < 0) {
#ifdef _WIN32
                if (WSAGetLastError() == WSAEINTR) continue;
#else
                if (errno == EINTR) continue;
#endif
                return false;
            }
            if (wrote == 0) return false;
            sent += static_cast<size_t>(wrote);
        }
        return true;
    }

    void ReapRequestWorkers() {
        std::vector<std::thread> finished;
        {
            std::lock_guard<std::mutex> lk(request_workers_mutex_);
            for (auto it = request_workers_.begin();
                 it != request_workers_.end();) {
                if (it->done->load(std::memory_order_acquire)) {
                    finished.emplace_back(std::move(it->thread));
                    it = request_workers_.erase(it);
                } else {
                    ++it;
                }
            }
        }
        for (auto& worker : finished)
            if (worker.joinable()) worker.join();
    }

    void JoinRequestWorkers() {
        std::vector<std::thread> workers;
        {
            std::lock_guard<std::mutex> lk(request_workers_mutex_);
            workers.reserve(request_workers_.size());
            for (auto& worker : request_workers_)
                workers.emplace_back(std::move(worker.thread));
            request_workers_.clear();
        }
        for (auto& worker : workers)
            if (worker.joinable()) worker.join();
    }

    static constexpr uint32_t EXPLORER_PER_CLIENT_CAP = 60;
    static constexpr uint32_t EXPLORER_RATE_WINDOW_S  = 60;
    static constexpr size_t   EXPLORER_RATE_MAP_MAX   = 10000;
    static constexpr uint32_t EXPLORER_MEMORY_UNITS_MAX = 128; // 1 unit ~= 1 MiB
    static constexpr uint32_t EXPLORER_WORK_UNITS_MAX   = 64;
    static constexpr uint32_t EXPLORER_HISTORY_INFLIGHT_MAX = 4;

    struct ExplorerRateSlot {
        uint64_t window_start = 0;
        uint64_t count = 0;
        uint32_t window_seconds = EXPLORER_RATE_WINDOW_S;
    };
    struct ExplorerCharge {
        std::string identity;
        std::string bucket;
        uint64_t amount;
        uint64_t limit;
        uint32_t seconds;
    };
    struct ExplorerAdmissionLease {
        BlockExplorer* owner = nullptr;
        uint32_t memory_units = 0;
        uint32_t work_units = 0;
        bool history = false;
        ExplorerAdmissionLease() = default;
        ExplorerAdmissionLease(const ExplorerAdmissionLease&) = delete;
        ExplorerAdmissionLease& operator=(const ExplorerAdmissionLease&) = delete;
        ~ExplorerAdmissionLease() {
            if (!owner) return;
            std::lock_guard<std::mutex> lk(owner->explorer_rate_mutex_);
            owner->explorer_memory_units_ -= memory_units;
            owner->explorer_work_units_ -= work_units;
            if (history) --owner->explorer_history_inflight_;
        }
    };

    std::mutex explorer_rate_mutex_;
    std::unordered_map<std::string, ExplorerRateSlot> explorer_rate_slots_;
    uint32_t explorer_memory_units_ = 0;
    uint32_t explorer_work_units_ = 0;
    uint32_t explorer_history_inflight_ = 0;

#ifdef VELD_TEST_HOOKS
public:
    struct TestExplorerRateSlotState {
        bool present = false;
        uint64_t window_start = 0;
        uint64_t count = 0;
        uint32_t window_seconds = 0;
    };

    bool TestExplorerTakeChargeAt(const std::string& identity,
                                  const std::string& bucket,
                                  uint64_t amount, uint64_t limit,
                                  uint32_t seconds, uint64_t now_s) {
        const std::vector<ExplorerCharge> charges = {
            {identity, bucket, amount, limit, seconds},
        };
        std::lock_guard<std::mutex> lk(explorer_rate_mutex_);
        return ExplorerTakeChargesLocked_(charges, now_s);
    }

    TestExplorerRateSlotState TestExplorerRateSlot(
            const std::string& identity, const std::string& bucket) {
        const std::string key = identity + "\n" + bucket;
        std::lock_guard<std::mutex> lk(explorer_rate_mutex_);
        const auto it = explorer_rate_slots_.find(key);
        if (it == explorer_rate_slots_.end()) return {};
        return {true, it->second.window_start, it->second.count,
                it->second.window_seconds};
    }

    size_t TestExplorerRateSlotCount() {
        std::lock_guard<std::mutex> lk(explorer_rate_mutex_);
        return explorer_rate_slots_.size();
    }

    size_t TestExplorerRateKeyBytes(size_t* maximum = nullptr) {
        std::lock_guard<std::mutex> lk(explorer_rate_mutex_);
        size_t total = 0;
        size_t longest = 0;
        for (const auto& entry : explorer_rate_slots_) {
            total += entry.first.size();
            longest = std::max(longest, entry.first.size());
        }
        if (maximum) *maximum = longest;
        return total;
    }

    void TestExplorerClearRateSlots() {
        std::lock_guard<std::mutex> lk(explorer_rate_mutex_);
        explorer_rate_slots_.clear();
    }

    static constexpr size_t TestExplorerRateMapMax() noexcept {
        return EXPLORER_RATE_MAP_MAX;
    }
private:
#endif

    static std::string ExplorerRouteKey_(const HttpRequest& req) {
        if (req.path_parts.empty()) return "root";
        const std::string& first = req.path_parts[0];
        if (first == "api") {
            if (req.path_parts.size() < 2) return "api-other";
            const std::string& second = req.path_parts[1];
            if (second.rfind("utxos", 0) == 0) return "utxos";
            if (second == "v1" && req.path_parts.size() >= 3
                    && req.path_parts[2] == "address") return "address-api";
            if (second == "v1" && req.path_parts.size() >= 3
                    && req.path_parts[2] == "addresshistory")
                return "address-history-api";
            if (second == "v1" && req.path_parts.size() >= 3
                    && req.path_parts[2] == "blocks") return "block";
            static const std::unordered_set<std::string> cheap = {
                "stats", "blocks", "mempool", "mining", "balance",
                "supply", "validators", "topology"
            };
            return cheap.count(second) ? "api-" + second : "api-other";
        }
        if (first == "address") return "address-page";
        if (first == "rich") return "rich";
        if (first == "block") return "block";
        if (first == "tx") return "tx";
        if (first == "icon-192.png" || first == "icon-512.png"
                || first == "manifest.json" || first == "service-worker.js")
            return "static";
        return "page";
    }

    bool ExplorerTakeChargesLocked_(const std::vector<ExplorerCharge>& charges,
                                    uint64_t now_s) {
        if (explorer_rate_slots_.size() >= EXPLORER_RATE_MAP_MAX / 2) {
            for (auto it = explorer_rate_slots_.begin();
                 it != explorer_rate_slots_.end();) {
                const uint64_t expiry = it->second.window_start
                    + 2ULL * it->second.window_seconds;
                if (now_s >= expiry) it = explorer_rate_slots_.erase(it);
                else ++it;
            }
        }
        size_t new_keys = 0;
        for (const auto& charge : charges) {
            const std::string key = charge.identity + "\n" + charge.bucket;
            auto it = explorer_rate_slots_.find(key);
            uint64_t used = 0;
            if (it == explorer_rate_slots_.end()) {
                ++new_keys;
            } else if (now_s < it->second.window_start + charge.seconds) {
                used = it->second.count;
            }
            if (charge.amount > charge.limit || used > charge.limit - charge.amount)
                return false;
        }
        if (new_keys > EXPLORER_RATE_MAP_MAX - explorer_rate_slots_.size())
            return false;
        for (const auto& charge : charges) {
            const std::string key = charge.identity + "\n" + charge.bucket;
            auto& slot = explorer_rate_slots_[key];
            if (now_s >= slot.window_start + charge.seconds) {
                slot.window_start = now_s;
                slot.count = 0;
            }
            slot.window_seconds = charge.seconds;
            slot.count += charge.amount;
        }
        return true;
    }

    bool BeginExplorerAdmission_(const std::string& identity,
                                 const HttpRequest& req,
                                 ExplorerAdmissionLease& lease,
                                 bool& concurrency_exhausted) {
        concurrency_exhausted = false;
        const std::string route = ExplorerRouteKey_(req);
        const bool history = route == "history" || route == "address-page";
        const bool heavy = history || route == "utxos" || route == "address-api"
                        || route == "rich" || route == "block" || route == "tx";
        const uint32_t memory_units = history ? 16 : (heavy ? 8 : 4);
        const uint32_t work_units = history ? 16 : (heavy ? 8 : 1);
        const uint64_t route_cap = history ? 60 : (heavy ? 600 : 1200);
        std::vector<ExplorerCharge> charges = {
            {identity, "client", 1, EXPLORER_PER_CLIENT_CAP, 60},
            {"global", "requests", 1, 6000, 60},
            {"global", "route:" + route, 1, route_cap, 60},
            {"global", "memory-window", memory_units, 24576, 60},
            {"global", "work-window", work_units, 12000, 60},
        };
        if (history) {
            charges.push_back({identity, "history", 1, 8, 60});
            charges.push_back({"global", "history", 1, 60, 60});
        }

        const uint64_t now_s = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        std::lock_guard<std::mutex> lk(explorer_rate_mutex_);
        if (explorer_memory_units_ > EXPLORER_MEMORY_UNITS_MAX - memory_units
                || explorer_work_units_ > EXPLORER_WORK_UNITS_MAX - work_units
                || (history && explorer_history_inflight_
                    >= EXPLORER_HISTORY_INFLIGHT_MAX)) {
            concurrency_exhausted = true;
            return false;
        }
        if (!ExplorerTakeChargesLocked_(charges, now_s)) return false;
        explorer_memory_units_ += memory_units;
        explorer_work_units_ += work_units;
        if (history) ++explorer_history_inflight_;
        lease.owner = this;
        lease.memory_units = memory_units;
        lease.work_units = work_units;
        lease.history = history;
        return true;
    }

    bool TakeRejectedRequestBudget_(const std::string& socket_peer,
                                    const std::string& bucket) {
        std::string peer;
        if (!net::trusted_proxy::CanonicalIp(socket_peer, peer)) peer = "unknown";
        const uint64_t now_s = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        const std::vector<ExplorerCharge> charges = {
            {"peer:" + peer, bucket, 1, 60, 60},
            {"global", bucket, 1, 600, 60},
        };
        std::lock_guard<std::mutex> lk(explorer_rate_mutex_);
        return ExplorerTakeChargesLocked_(charges, now_s);
    }

    void ServeLoop() {
        while (running_) {
            ReapRequestWorkers();
            struct sockaddr_in client{};
            socklen_t len = sizeof(client);
            SocketHandle client_fd = ::accept(fd_, (struct sockaddr*)&client, &len);
            if (!veld::compat::IsValidSocket(client_fd)) { if (running_) std::this_thread::sleep_for(std::chrono::milliseconds(10)); continue; }

            char ip_buf[INET_ADDRSTRLEN] = {0};
            ::inet_ntop(AF_INET, &client.sin_addr, ip_buf, sizeof(ip_buf));
            const std::string socket_peer(ip_buf);

            const uint64_t prior = active_requests_.fetch_add(
                1, std::memory_order_acq_rel);
            if (prior >= MAX_EXPLORER_INFLIGHT) {
                active_requests_.fetch_sub(1, std::memory_order_acq_rel);
                static const char kBusy[] =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Content-Length: 24\r\n"
                    "Connection: close\r\n"
                    "Retry-After: 2\r\n"
                    "\r\n"
                    "explorer busy, retry...\n";
                (void)SendAll_(client_fd, kBusy, sizeof(kBusy) - 1);
                VELD_CLOSE_SOCKET(client_fd);
                continue;
            }

#ifdef _WIN32
            DWORD tmo_ms = EXPLORER_RECV_TIMEOUT_S * 1000;
            const bool timeouts_ok =
                ::setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO,
                             (const char*)&tmo_ms, sizeof(tmo_ms)) == 0 &&
                ::setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO,
                             (const char*)&tmo_ms, sizeof(tmo_ms)) == 0;
#else
            struct timeval tv{};
            tv.tv_sec = EXPLORER_RECV_TIMEOUT_S;
            tv.tv_usec = 0;
            const bool timeouts_ok =
                ::setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 &&
                ::setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
#endif
            if (!timeouts_ok) {
                active_requests_.fetch_sub(1, std::memory_order_acq_rel);
                VELD_CLOSE_SOCKET(client_fd);
                continue;
            }

            bool worker_started = false;
            try {
                auto done = std::make_shared<std::atomic<bool>>(false);
                std::thread worker([this, client_fd, done, socket_peer]() {
                    struct Guard {
                        std::atomic<uint64_t>* active;
                        std::atomic<bool>* done;
                        ~Guard() {
                            active->fetch_sub(1, std::memory_order_acq_rel);
                            done->store(true, std::memory_order_release);
                        }
                    } guard{&active_requests_, done.get()};
                    try { HandleRequest(client_fd, socket_peer); }
                    catch (...) {  }
                    VELD_CLOSE_SOCKET(client_fd);
                });
                worker_started = true;
                try {
                    std::lock_guard<std::mutex> lk(request_workers_mutex_);
                    request_workers_.push_back(
                        RequestWorker{std::move(worker), std::move(done)});
                } catch (...) {
                    if (worker.joinable()) worker.join();
                    throw;
                }
            } catch (const std::system_error& e) {
                if (!worker_started)
                    active_requests_.fetch_sub(1, std::memory_order_acq_rel);
                std::cerr << "  [explorer] thread spawn failed (" << e.what()
                          << ") — dropping request fd=" << client_fd << "\n";
                std::cerr.flush();
                if (!worker_started) VELD_CLOSE_SOCKET(client_fd);
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            } catch (const std::exception& e) {
                if (!worker_started)
                    active_requests_.fetch_sub(1, std::memory_order_acq_rel);
                std::cerr << "  [explorer] unexpected thread-spawn error: " << e.what() << "\n";
                std::cerr.flush();
                if (!worker_started) VELD_CLOSE_SOCKET(client_fd);
            }
        }
        ReapRequestWorkers();
    }

    void HandleRequest(SocketHandle client_fd, const std::string& socket_peer) {
        std::string buf;
        buf.reserve(8192);
        char chunk[8192];
        bool have_full_headers = false;
        size_t expected_body = 0;
        size_t headers_end = 0;
        while (buf.size() < EXPLORER_MAX_BODY) {
            int n = ::recv(client_fd, chunk, sizeof(chunk), 0);
            if (n <= 0) break;
            buf.append(chunk, (size_t)n);
            if (!have_full_headers) {
                size_t pos = buf.find("\r\n\r\n");
                if (pos != std::string::npos) {
                    have_full_headers = true;
                    headers_end = pos + 4;
                    std::string hdrs = buf.substr(0, pos);
                    std::string lower = hdrs;
                    for (auto& c : lower) c = (char)std::tolower((unsigned char)c);
                    size_t cl = lower.find("content-length:");
                    if (cl != std::string::npos) {
                        size_t v = cl + 15;
                        while (v < lower.size() && lower[v] == ' ') ++v;
                        try { expected_body = (size_t)std::stoull(lower.substr(v)); }
                        catch (...) { expected_body = 0; }
                        if (expected_body > EXPLORER_MAX_BODY) {
                            static const char k413[] =
                                "HTTP/1.1 413 Payload Too Large\r\n"
                                "Content-Length: 19\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "payload too large\r\n";
                            (void)SendAll_(client_fd, k413, sizeof(k413) - 1);
                            return;
                        }
                    }
                }
            }
            if (have_full_headers) {
                size_t have_body = buf.size() - headers_end;
                if (have_body >= expected_body) break;
            }
        }

        auto req = HttpRequest::Parse(buf);
        if (!req.valid) {
            if (!TakeRejectedRequestBudget_(socket_peer, "invalid-http")) {
                static const char kInvalidLimited[] =
                    "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 22\r\n"
                    "Connection: close\r\nRetry-After: 60\r\n\r\n"
                    "rate limit, slow down\n";
                (void)SendAll_(client_fd, kInvalidLimited,
                               sizeof(kInvalidLimited) - 1);
                return;
            }
            static const char kBadRequest[] =
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 21\r\n"
                "Connection: close\r\n\r\ninvalid HTTP request\n";
            (void)SendAll_(client_fd, kBadRequest, sizeof(kBadRequest) - 1);
            return;
        }
        const auto proxy = net::trusted_proxy::Resolve(
            trusted_proxy_, socket_peer, req.headers, req.ambiguous_headers);
        if (!proxy.accepted) {
            if (!TakeRejectedRequestBudget_(socket_peer, "invalid-proxy")) {
                static const char kProxyLimited[] =
                    "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 22\r\n"
                    "Connection: close\r\nRetry-After: 60\r\n\r\n"
                    "rate limit, slow down\n";
                (void)SendAll_(client_fd, kProxyLimited,
                               sizeof(kProxyLimited) - 1);
                return;
            }
            static const char kProxyDenied[] =
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 23\r\n"
                "Connection: close\r\n\r\nproxy metadata refused\n";
            (void)SendAll_(client_fd, kProxyDenied, sizeof(kProxyDenied) - 1);
            return;
        }
        ExplorerAdmissionLease admission;
        bool busy = false;
        if (!BeginExplorerAdmission_(proxy.identity, req, admission, busy)) {
            static const char kThrottled[] =
                "HTTP/1.1 429 Too Many Requests\r\n"
                "Content-Length: 22\r\n"
                "Connection: close\r\n"
                "Retry-After: 60\r\n\r\n"
                "rate limit, slow down\n";
            static const char kBudgetBusy[] =
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Content-Length: 26\r\n"
                "Connection: close\r\n"
                "Retry-After: 2\r\n\r\n"
                "explorer budget exhausted\n";
            if (busy)
                (void)SendAll_(client_fd, kBudgetBusy, sizeof(kBudgetBusy) - 1);
            else
                (void)SendAll_(client_fd, kThrottled, sizeof(kThrottled) - 1);
            return;
        }
        auto res = Route(req);
        res.request_path = req.path;
        auto wire = res.Serialize();
        (void)SendAll_(client_fd, wire.data(), wire.size());
        ++requests_served_;
    }

    static const std::string& ArcadeCSS() {
        static const std::string css = R"VLDCSS(<style>
*{box-sizing:border-box;margin:0;padding:0;-webkit-font-smoothing:antialiased}
:root{
  --bg:#0A0B0A; --bg2:#13141A;
  --surf:rgba(255,255,255,.045); --surfH:rgba(255,255,255,.075); --surf2:rgba(255,255,255,.025);
  --line:rgba(255,255,255,.08); --line2:rgba(255,255,255,.16); --hair:rgba(255,255,255,.05);
  --fg:#FFFFFF; --fg2:rgba(255,255,255,.66); --fg3:rgba(255,255,255,.36); --fg4:rgba(255,255,255,.18);
  --em:#7ED949; --emL:#7ED949; --emD:#7ED949;
  --em-glow:rgba(126,217,73,.30); --em-rgb:126,217,73;
  --em-bg:rgba(126,217,73,.08); --em-bg2:rgba(126,217,73,.16);
  --gold:#FFD84A; --gold-rgb:255,216,74; --gold-glow:rgba(255,216,74,.28);
  --blue:#4CB8FF; --blue-rgb:76,184,255; --blue-glow:rgba(76,184,255,.28);
  --purple:#B07CFF; --purple-rgb:176,124,255; --purple-glow:rgba(176,124,255,.28);
  --red:#FF6057; --red-rgb:255,96,87;
  --mobile-nav-height:68px;
}
html[data-theme="light"]{
  background:#F7F7F7;
  --bg:#F7F7F7; --bg2:#EFEFEF;
  --surf:#FFFFFF; --surfH:#F0F1F0; --surf2:#FAFAFA;
  --line:#D2D4D3; --line2:#C2C6C4; --hair:#E4E5E4;
  --fg:#121514; --fg2:#4F5753; --fg3:#696F6C; --fg4:#A5AAA7;
  --em:#168B4B; --emL:#20A75C; --emD:#11743E;
  --em-glow:rgba(22,139,75,.16); --em-rgb:22,139,75;
  --em-bg:#ECEEED; --em-bg2:#E2E4E3;
  --gold:#B45309; --gold-rgb:180,83,9; --gold-glow:rgba(180,83,9,.22);
  --blue:#2563EB; --blue-rgb:37,99,235; --blue-glow:rgba(37,99,235,.22);
  --purple:#7C3AED; --purple-rgb:124,58,237; --purple-glow:rgba(124,58,237,.22);
  --red:#DC2626; --red-rgb:220,38,38;
}
html,body{background:var(--bg);color:var(--fg);font-family:'Inter',-apple-system,BlinkMacSystemFont,'SF Pro Display',sans-serif;font-size:15px;line-height:1.5;min-height:100vh;min-height:100dvh;font-feature-settings:"tnum","kern","ss01";-webkit-text-size-adjust:100%;text-size-adjust:100%}
/* explicit html bg in light mode. iOS reads the underlying
   pixel color at viewport y=0 to tint the status bar (black-translucent
   mode). With viewport-fit=cover the body extends under the status bar,
   so what iOS samples is whatever color the .bar / body resolves to at
   y=0. Setting html bg explicitly (not just via --bg variable) ensures
   the read is deterministic. */
html[data-theme="light"]{background:#F7F7F7!important}
html[data-theme="light"] body{background:#F7F7F7!important}
body{padding:0;position:relative;overflow-x:hidden}

/* Subtle emerald ambient at the bottom — alive but not loud */
body::before{display:none}
html[data-theme="light"] body::before{opacity:.4}

/* ============== TOP BAR ============== */
/* fully opaque .bar bg. With black-translucent status-bar
   style, iOS reads the pixel at y=0 to decide icon tint. A semi-transparent
   bar bg blends with whatever's below in unpredictable ways across iOS
   builds. Solid colors that match the body bg guarantee the status bar
   tint follows the in-app theme reliably. */
.bar{position:sticky;top:0;z-index:30;display:flex;justify-content:space-between;align-items:center;padding:calc(14px + env(safe-area-inset-top,0)) 16px 14px;background:#0A0B0A;border-bottom:.5px solid var(--line)}
html[data-theme="light"] .bar{background:#EFEFEF}
@media(min-width:520px){.bar{padding-left:22px;padding-right:22px}}
.mark{display:flex;align-items:center;gap:10px;text-decoration:none;color:inherit}
.mark .gl{width:30px;height:30px;display:block;filter:drop-shadow(0 4px 8px rgba(var(--em-rgb),.22))}
.veld-mark{display:block;width:100%;height:100%}
html:not([data-theme="light"]) .veld-mark stop{stop-color:#7ED949!important}
.mark .nm{font-size:18px;font-weight:600;letter-spacing:-.012em;color:var(--fg)}
.bar-right{display:flex;align-items:center;gap:14px}
.theme-tog{background:transparent;border:.5px solid var(--line2);color:var(--fg);width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:15px;line-height:1;transition:background .15s,border-color .15s,color .15s;font-family:inherit}
.theme-tog:hover{background:var(--surfH);border-color:var(--em);color:var(--em)}
.live{display:flex;align-items:center;gap:8px;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--em);letter-spacing:.04em;font-weight:600}
.live .dot{width:8px;height:8px;border-radius:50%;background:var(--em);box-shadow:0 0 0 0 var(--em-glow);animation:vbl 2.4s ease-out infinite}
@keyframes vbl{0%{box-shadow:0 0 0 0 rgba(var(--em-rgb),.6)}80%{box-shadow:0 0 0 12px rgba(var(--em-rgb),0)}100%{box-shadow:0 0 0 0 rgba(var(--em-rgb),0)}}

/* Mobile navigation owns the viewport edge and is never placed by route flow. */
.nav-bar{position:fixed;left:0;right:0;bottom:0;top:auto;z-index:500;display:flex;width:100%;height:var(--mobile-nav-height);min-height:var(--mobile-nav-height);max-height:var(--mobile-nav-height);margin:0;padding:0;background:var(--bg);border-top:1px solid rgba(126,217,73,.15);box-shadow:0 -8px 32px rgba(0,0,0,.35);box-sizing:border-box;transform:translateZ(0);-webkit-transform:translateZ(0)}
.nav-bar::after{display:none}
/* Match the wallet mobile shell. The document scrolls normally while the
   navigation remains a direct, fixed child of body. */
@media (max-width:900px), (hover:none) and (pointer:coarse){
  html,body{width:100%;height:auto!important;min-height:100vh!important;min-height:100dvh!important;overflow-x:hidden!important;overflow-y:visible!important;overscroll-behavior-y:none}
  html,body{background:#0A0B0A!important}
  html[data-theme="light"],html[data-theme="light"] body{background:#EFEFEF!important}
  .bar{position:sticky!important;top:0!important;width:100%}
  .nav-bar,.nav-bar.is-sticky{display:flex!important;position:fixed!important;left:0!important;right:0!important;bottom:0!important;top:auto!important;inset:auto 0 0 0!important;z-index:500!important;width:100%!important;max-width:none!important;height:var(--mobile-nav-height)!important;min-height:var(--mobile-nav-height)!important;max-height:var(--mobile-nav-height)!important;margin:0!important;padding:0!important;overflow:hidden!important;transform:translateZ(0)!important;-webkit-transform:translateZ(0)!important;will-change:transform;background:#0A0B0A!important;border-top:1px solid var(--line)!important;box-sizing:border-box!important;box-shadow:0 96px 0 96px #0A0B0A,0 -8px 32px rgba(0,0,0,.35)!important}
  html[data-theme="light"] .nav-bar,html[data-theme="light"] .nav-bar.is-sticky{background:#EFEFEF!important;box-shadow:0 96px 0 96px #EFEFEF,0 -6px 20px rgba(18,21,20,.06)!important}
  .wrap,.liquidity-wrap{width:100%;min-height:calc(100vh - 68px);min-height:calc(100dvh - 68px);margin:0 auto!important;padding:18px clamp(12px,2.6vw,22px) calc(110px + env(safe-area-inset-bottom,0px))!important;overflow:visible!important;background:var(--bg)!important}
  .wrap{max-width:780px}
  .liquidity-wrap{max-width:1120px}
  .nav-bar::after{display:none!important}
  .nb-tab{align-self:stretch!important;height:var(--mobile-nav-height)!important;min-height:var(--mobile-nav-height)!important;max-height:var(--mobile-nav-height)!important;padding:7px 2px 6px!important}
  .nav-more{bottom:var(--mobile-nav-height)!important}
}
/* Touch-only tablets retain the same shell in either orientation. */
html[data-theme="light"] .nav-bar{background:#EFEFEF;border-top:1px solid #D2D4D3;box-shadow:0 -6px 20px rgba(18,21,20,.06)}
/* Mirrors .mob-tab in ui_desktop.h (line ~597). Same icon size, label
   size, and gap so the two apps' bottom-nav metrics are identical. */
.nb-tab{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;cursor:pointer;color:var(--fg3);font-size:10px;letter-spacing:.5px;text-transform:uppercase;font-family:'Inter',sans-serif;font-weight:600;border:none;background:transparent;padding:4px 2px;-webkit-tap-highlight-color:transparent;min-height:68px;text-decoration:none;position:relative;overflow:hidden;touch-action:manipulation;-webkit-user-select:none;user-select:none}
/* fixed-width icon box so glyphs of varying visual mass
   (▦/◫/⇄/⛏/⋯/etc.) all sit centered in identical 30px slots. Without
   this, the natural width of each Unicode glyph varies and the visual
   spacing between adjacent icons reads as uneven even though the
   underlying flex tabs are pixel-equal. */
.nb-tab .ic{font-size:24px;line-height:1;width:30px;height:24px;display:inline-flex;align-items:center;justify-content:center;transition:transform .2s,filter .2s}
.nb-tab .ic .nav-icon{width:22px;height:22px}
.nb-tab .lb,.nb-tab>span:last-child{white-space:nowrap;font-size:10px}
.nb-tab.active{color:var(--em)}
.nb-tab.active::before{content:'';position:absolute;top:0;left:50%;transform:translateX(-50%);width:28px;height:3px;background:var(--em);border-radius:0 0 5px 5px;box-shadow:0 4px 16px var(--em-glow)}
.nb-tab.active .ic{filter:drop-shadow(0 0 10px var(--em-glow));transform:translateY(-1px) scale(1.08)}
.nb-tab:active{opacity:.5}

/* The More overlay keeps its cells above the fixed control band and device
   safe area. */
.nav-more{display:none;position:fixed;left:0;right:0;bottom:68px;z-index:499;background:#0A0B0A;border-top:1px solid rgba(var(--em-rgb),.20);padding:16px 12px;animation:nmIn .18s ease-out;box-shadow:0 -12px 40px rgba(0,0,0,.55)}
html[data-theme="light"] .nav-more{background:#EFEFEF;box-shadow:0 -12px 40px rgba(18,21,20,.10)}
.nav-more[data-open="1"]{display:block}
.nm-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;max-width:780px;margin:0 auto}
/* cells are FULLY OPAQUE (was var(--surf) ~ rgba(...,.045)
   which let the foot text bleed straight through). Solid colors per
   theme so visual hierarchy is preserved against the overlay bg. */
.nm-cell{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:6px;padding:14px 8px;border-radius:12px;background:#13141A;border:.5px solid var(--line);color:var(--fg2);font-size:10.5px;font-family:'Inter',sans-serif;letter-spacing:.45px;font-weight:600;text-transform:uppercase;text-decoration:none;transition:background .15s,border-color .15s,color .15s,transform .12s;-webkit-tap-highlight-color:transparent;touch-action:manipulation}
html[data-theme="light"] .nm-cell{background:#FAFAFA;color:var(--fg2);border-color:var(--line)}
.nm-cell .ic{font-size:20px;line-height:1;width:24px;height:22px;display:inline-flex;align-items:center;justify-content:center}
.nm-cell .ic .nav-icon{width:20px;height:20px}
.nm-cell:active{transform:scale(.97)}
.nm-cell.active,.nm-cell:hover{color:var(--em);border-color:rgba(var(--em-rgb),.45);background:var(--surfH)}
@keyframes nmIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

/* ============== DESKTOP LEFT SIDEBAR (>=901px) ==============
   On phones the .bar header and bottom .nav-bar tab strip are
   the nav. On desktop those are hidden and this dedicated left rail takes
   over: logo, all sections as a vertical list (no More overflow), Live +
   theme toggle pinned to the foot. Hidden by default; shown only >=901px. */
.side-nav{display:none;flex-direction:column;position:fixed;left:0;top:0;bottom:0;width:248px;background:#0b0d0e;border-right:1px solid rgba(255,255,255,.07);z-index:600;padding:20px 14px;gap:3px;overflow-y:auto}
html[data-theme="light"] .side-nav{background:#EFEFEF}
.side-nav .sn-logo{display:flex;align-items:center;gap:11px;padding:6px 10px 20px;text-decoration:none}
.side-nav .sn-logo .gl{width:34px;height:34px;display:block;filter:drop-shadow(0 4px 8px rgba(var(--em-rgb),.18))}
.side-nav .sn-logo .nm{font-size:20px;font-weight:600;letter-spacing:-.01em;color:var(--fg)}
.side-nav .sn-link{display:flex;align-items:center;gap:13px;padding:10px 12px;border-radius:7px;text-decoration:none;color:var(--fg2);font-size:14px;font-weight:500;position:relative;transition:background .15s,color .15s}
.side-nav .sn-link .ic{font-size:16px;width:20px;height:20px;display:inline-flex;align-items:center;justify-content:center;text-align:center;opacity:.85}
.side-nav .sn-link .ic .nav-icon{width:18px;height:18px}
.nav-icon{display:block;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round;vector-effect:non-scaling-stroke}
.nav-icon .nav-icon-dot{fill:currentColor;stroke:none}
.side-nav .sn-link .lb{white-space:nowrap}
.side-nav .sn-link:hover{background:rgba(var(--em-rgb),.06);color:var(--fg)}
.side-nav .sn-link.active{color:var(--fg);background:transparent;font-weight:600;border:0;outline:0;box-shadow:none}
.side-nav .sn-link.active::before,.side-nav .sn-link.active::after{display:none;content:none}
.side-nav .sn-link.active .ic{color:var(--em);opacity:1}
html[data-theme="light"] .side-nav .sn-link.active{background:transparent;box-shadow:none}
.side-nav .sn-link:focus,.side-nav .sn-link:focus-visible{border:0;outline:none;box-shadow:none;color:var(--fg)}
.side-nav .sn-foot{margin-top:auto;display:flex;align-items:center;justify-content:space-between;padding:14px 12px 4px;border-top:1px solid rgba(var(--em-rgb),.08)}
.side-nav .sn-foot .live{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--fg2);font-weight:500}
.side-nav .sn-foot .live .dot{width:7px;height:7px;border-radius:50%;background:var(--em);box-shadow:0 0 8px var(--em-glow)}

/* .wrap takes the bottom clearance that .foot used to handle. 80 + safe
   keeps the last visible content row a few px above the navbar's top edge. */
.wrap{position:relative;z-index:2;max-width:780px;margin:14px auto 0;padding:14px 12px 90px}
@media(min-width:520px){.wrap{padding:18px 22px 90px;margin-top:20px}}
/* DESKTOP layout. The phone bottom navbar previously
   showed on PC too (the arcade wrapper had NO min-width query, unlike
   the legacy HtmlWrap). On wide viewports flip .nav-bar into a fixed
   TOP horizontal bar, lay the tabs out as inline pills, drop the More
   overlay DOWNWARD from the bar, and widen .wrap to real desktop
   width. CSS-only — no markup/JS change, the toggle still works. */
@media(min-width:901px) and (hover:hover) and (pointer:fine){
  /* desktop = left sidebar dashboard. Hide the phone header,
     bottom tab bar, and More overlay; the .side-nav rail takes over and
     the content shifts right to clear it. */
  body,body *{font-family:'JetBrains Mono','SF Mono','Cascadia Code',ui-monospace,monospace!important}
  .bar{display:none!important}
  .nav-bar{display:none!important}
  .nav-more{display:none!important}
  .side-nav{display:flex;width:248px;min-width:248px;box-sizing:border-box}
  .side-nav .sn-logo{gap:11px}
  .side-nav .sn-logo .gl{width:34px;height:34px;flex:0 0 34px}
  .side-nav .sn-link{min-height:40px}
  .side-nav .sn-link .ic{width:20px;height:20px;display:inline-flex;align-items:center;justify-content:center;font-size:16px}
  .wrap{max-width:1180px;margin:0 auto 0 248px;padding:26px 32px 56px}
}
/* Large-desktop scale-up: the desktop rule above capped content at a narrow 1180px
   column with 15px type, which read as tiny and left dead space on big monitors. Widen
   the content and step the core type up so it fills a real desktop viewport. */
@media(min-width:1400px){
  body{font-size:16.5px}
  .wrap{max-width:1500px;padding:30px 46px 60px}
  .stat-value{font-size:26px}.card-title{font-size:14.5px}.big{font-size:58px}
}
@media(min-width:1850px){
  body{font-size:18px}
  .wrap{max-width:1720px;padding:34px 60px 64px}
  .stat-value{font-size:28px}.big{font-size:66px}
}
.sec{display:block;padding:18px 0}

/* ============== HERO — frosted material card ============== */
.hero{position:relative;border-radius:22px;padding:32px 26px 28px;background:var(--surf);border:.5px solid var(--line);overflow:hidden;backdrop-filter:blur(40px) saturate(180%);-webkit-backdrop-filter:blur(40px) saturate(180%);box-shadow:0 14px 40px rgba(0,0,0,.45),inset 0 1px 0 rgba(255,255,255,.06);transition:background .2s,border-color .2s;margin-bottom:14px}
html[data-theme="light"] .hero{box-shadow:0 14px 40px rgba(0,0,0,.08),inset 0 1px 0 rgba(255,255,255,.6)}
.hero .lbl{display:inline-flex;align-items:center;gap:7px;font-size:11.5px;color:var(--fg2);font-weight:500;letter-spacing:-.005em;margin-bottom:14px}
.hero .lbl::before{display:none}
.hero .num,.hero .big{font-size:clamp(64px,11vw,96px);font-weight:200;letter-spacing:-.045em;line-height:.95;color:var(--fg);font-feature-settings:"tnum","lnum";overflow-wrap:anywhere;hyphens:none;word-break:normal}
.hero .num .com,.hero .big .com{color:var(--fg3);font-weight:200}
.hero .meta{margin-top:14px;font-family:'JetBrains Mono',monospace;font-size:12.5px;color:var(--fg2);letter-spacing:-.005em;display:flex;gap:14px;flex-wrap:wrap}
.hero .meta .it{display:flex;align-items:center;gap:6px}
.hero .meta .it .dot{display:none}
.hero .meta b{color:var(--fg);font-weight:600}

/* ============== STAT GRID ============== */
.grid2,.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:12px 0}
.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin:12px 0}
.tile,.stat{position:relative;border-radius:18px;padding:16px 18px;background:var(--surf);border:.5px solid var(--line);backdrop-filter:blur(30px) saturate(180%);-webkit-backdrop-filter:blur(30px) saturate(180%);transition:transform .25s cubic-bezier(.2,.8,.2,1),background .2s,border-color .2s}
.tile:hover,.stat:hover{transform:translateY(-1px);background:var(--surfH);border-color:var(--line2)}
.tile .l,.stat .l{font-size:11px;color:var(--fg3);font-weight:500;letter-spacing:-.005em;margin-bottom:7px}
.tile .v,.stat .v{font-size:24px;font-weight:500;letter-spacing:-.022em;color:var(--fg);font-feature-settings:"tnum","lnum"}
.tile .v .u,.stat .v .u{font-size:11.5px;color:var(--fg3);font-weight:400;margin-left:4px;letter-spacing:0}
.tile.span2,.stat.span2{grid-column:span 2}
.tile.em .v,.stat.em .v,.stat .v.em{color:var(--em)}
.tile.gold .v,.stat.gold .v,.stat .v.gold,.stat .v.gd{color:var(--gold)}
.tile.bl .v,.stat .v.bl{color:var(--blue)}
.tile.pp .v,.stat .v.pp{color:var(--purple)}

/* ============== SECTION HEADING ============== */
h3,.sh{display:flex;justify-content:space-between;align-items:baseline;margin:24px 4px 12px;font-size:13.5px;color:var(--fg);font-weight:600;letter-spacing:-.008em}
h3 .ct,.sh .ct{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--fg3);font-weight:500;letter-spacing:.01em}
h3 .ct a,.sh .ct a{color:var(--em);text-decoration:none}

/* ============== BLOCK / TX LIST (frosted grouped rows) ============== */
.list,.lst{border-radius:16px;background:var(--surf);border:.5px solid var(--line);overflow:hidden;backdrop-filter:blur(30px) saturate(180%);-webkit-backdrop-filter:blur(30px) saturate(180%)}
.bk{position:relative;display:flex;align-items:center;gap:13px;padding:14px 18px;text-decoration:none;color:inherit;border-bottom:.5px solid var(--line);transition:background .15s}
.bk:last-child{border-bottom:0}
.bk:hover{background:var(--surfH)}
.bk .ic{width:38px;height:38px;border-radius:11px;background:linear-gradient(135deg,rgba(var(--em-rgb),.18),rgba(var(--em-rgb),.06));border:.5px solid rgba(var(--em-rgb),.32);display:flex;align-items:center;justify-content:center;color:var(--emL);font-weight:600;font-size:11px;flex-shrink:0;font-family:'JetBrains Mono',monospace;letter-spacing:-.02em}
.bk .info{flex:1;min-width:0}
.bk .info .h{font-size:15px;font-weight:600;letter-spacing:-.012em;font-feature-settings:"tnum","lnum";display:flex;align-items:center;gap:9px}
.bk .info .s{font-size:12px;color:var(--fg3);font-family:'JetBrains Mono',monospace;margin-top:3px;letter-spacing:.005em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bk-badges{display:inline-flex;flex-wrap:wrap;gap:4px;vertical-align:middle;margin-left:7px}
.bk-badge{font-family:'Inter',sans-serif;font-size:8.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:1.5px 6px;border-radius:5px;line-height:1.5;color:var(--fg2);background:var(--surf2);border:.5px solid var(--line)}
.bk-badge.gold{color:var(--gold);background:rgba(var(--gold-rgb),.12);border-color:rgba(var(--gold-rgb),.30)}
.bk-badge.blue{color:var(--blue);background:rgba(var(--blue-rgb),.12);border-color:rgba(var(--blue-rgb),.30)}
.bk-badge.em{color:var(--em);background:rgba(var(--em-rgb),.12);border-color:rgba(var(--em-rgb),.30)}
.bk .right{display:flex;flex-direction:column;align-items:flex-end;gap:3px;flex-shrink:0}
.bk .right .ago,.bk .ago{font-size:12px;color:var(--fg2);font-family:'JetBrains Mono',monospace;font-weight:500}
.bk .right .tx{font-size:11px;color:var(--fg3);font-family:'JetBrains Mono',monospace}
.bk.fresh .right .ago,.bk.fresh .ago{color:var(--em);font-weight:600}
.bk.fresh .info .h::after{content:'NEW';font-family:'JetBrains Mono',monospace;font-size:9px;font-weight:700;color:var(--em);background:rgba(var(--em-rgb),.14);padding:2px 6px;border-radius:5px;letter-spacing:.06em;border:.5px solid rgba(var(--em-rgb),.30)}

.num{font-family:'JetBrains Mono',monospace;font-weight:600;color:var(--fg);font-feature-settings:"tnum","lnum"}

/* ============== INLINE OP CHIPS ============== */
.op{display:inline-flex;align-items:center;padding:2px 7px;border-radius:6px;font-size:10.5px;font-weight:600;letter-spacing:.02em;background:rgba(255,255,255,.06);color:var(--fg2);border:.5px solid var(--line);font-family:'JetBrains Mono',monospace}
.op.xfer{color:var(--em);background:rgba(var(--em-rgb),.10);border-color:rgba(var(--em-rgb),.30)}
.op.stake{color:var(--gold);background:rgba(var(--gold-rgb),.10);border-color:rgba(var(--gold-rgb),.30)}
.op.endor,.op.cy{color:var(--blue);background:rgba(var(--blue-rgb),.10);border-color:rgba(var(--blue-rgb),.30)}
.op.purple,.op.pp{color:var(--purple);background:rgba(var(--purple-rgb),.10);border-color:rgba(var(--purple-rgb),.30)}
.op.hot,.op.red{color:var(--em);background:rgba(var(--em-rgb),.16);border-color:rgba(var(--em-rgb),.45);box-shadow:0 0 10px rgba(var(--em-rgb),.32)}
.op.btc{color:#f7931a;background:rgba(247,147,26,.10);border-color:rgba(247,147,26,.32)}

/* ============== KV ROWS ============== */
.kv{border-radius:14px;background:var(--surf);border:.5px solid var(--line);overflow:hidden;backdrop-filter:blur(24px) saturate(180%);-webkit-backdrop-filter:blur(24px) saturate(180%);margin-bottom:12px}
.kv .row{display:flex;justify-content:space-between;align-items:baseline;padding:11px 16px;border-bottom:.5px solid var(--hair);gap:14px}
.kv .row:last-child{border-bottom:0}
.kv .k{font-size:11.5px;color:var(--fg3);font-weight:500;letter-spacing:-.005em;flex-shrink:0}
.kv .v{font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--fg);text-align:right;word-break:break-all;overflow-wrap:anywhere;font-weight:500;font-feature-settings:"tnum","lnum"}
.kv .v.em{color:var(--em)}
.kv .v.gd{color:var(--gold)}
.kv .v.pp{color:var(--purple)}

/* ============== TABLE ============== */
.tbl{width:100%;border-collapse:collapse;font-family:'JetBrains Mono',monospace}
.tbl thead th{text-align:left;padding:10px 14px;font-family:'Inter',sans-serif;font-size:11px;font-weight:600;letter-spacing:-.005em;color:var(--fg3);border-bottom:.5px solid var(--line);background:var(--surf2)}
.tbl thead th.r{text-align:right}
.tbl tbody td{padding:11px 14px;font-size:12.5px;color:var(--fg);border-bottom:.5px solid var(--hair);font-feature-settings:"tnum","lnum";word-break:normal;overflow-wrap:anywhere;hyphens:none}
.tbl tbody td.mono,.tbl tbody td.hash,.tbl tbody td[class*="hash"]{word-break:break-all;overflow-wrap:anywhere}
.tbl tbody td.r{text-align:right}
.tbl tbody tr:last-child td{border-bottom:0}
.tbl tbody tr:hover td{background:var(--surfH)}
.tbl tbody td.h{color:var(--em);font-weight:600}
.tbl tbody td.hash{color:var(--fg2)}
.tbl tbody td a{color:inherit;text-decoration:none}
.tbl tbody td a:hover{color:var(--em)}

.btn,.veld-btn,.btn-gold{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:10px 18px;font-family:'Inter',sans-serif;font-size:13px;font-weight:600;color:var(--fg);background:var(--surf);border:.5px solid var(--line2);border-radius:10px;cursor:pointer;text-decoration:none;transition:all .15s;letter-spacing:-.005em;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px)}
.btn:hover,.veld-btn:hover,.btn-gold:hover{background:var(--surfH);border-color:var(--em);color:var(--em)}
.btn.gd,.btn-gold{border-color:rgba(var(--gold-rgb),.5);color:var(--gold)}
.btn.gd:hover,.btn-gold:hover{background:rgba(var(--gold-rgb),.10);border-color:var(--gold);color:var(--gold)}

.note{padding:12px 14px;border-left:3px solid var(--blue);background:rgba(var(--blue-rgb),.05);font-family:'Inter',sans-serif;font-size:13px;color:var(--fg2);margin-bottom:12px;border-radius:0 10px 10px 0}
.note b{color:var(--fg);font-weight:600}
.note.em{border-color:var(--em);background:rgba(var(--em-rgb),.05)}
.note.gd{border-color:var(--gold);background:rgba(var(--gold-rgb),.05)}
.note.red{border-color:var(--red);background:rgba(var(--red-rgb),.05)}

/* ============== FOOTER ============== */
.foot{padding:22px 22px calc(100px + env(safe-area-inset-bottom,0));max-width:780px;margin:0 auto;display:flex;justify-content:center;font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--fg3);letter-spacing:.02em;border-top:.5px solid var(--line);margin-top:22px;position:relative;z-index:2;text-align:center}
.foot .lbl{opacity:.7}
.foot a{color:var(--fg);text-decoration:none;font-family:'Inter',sans-serif;font-weight:500;margin:0 10px;letter-spacing:-.005em;font-size:13px;transition:color .15s}
.foot a:hover{color:var(--em)}
.foot .lbl{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--fg3);letter-spacing:.05em;display:block;margin-top:6px}

/* search input — used by Landing + Blocks jump-to-height */
input.search,select.search,.search,.fi,.type-select,.hero-search-input{padding:10px 14px;font-family:'Inter',sans-serif;font-size:13.5px;color:var(--fg);background:var(--surf);border:.5px solid var(--line2);border-radius:10px;outline:none;transition:border-color .15s,background .15s;font-feature-settings:"tnum","kern"}
.search:focus,.fi:focus,.type-select:focus,.hero-search-input:focus,input.search:focus{border-color:var(--em);background:var(--surfH);box-shadow:0 0 0 3px rgba(var(--em-rgb),.18)}

/* ============== LEGACY COMPAT (wallet-style classes still emitted
   by some unmigrated handlers — block-detail / address / governance
   / staking / etc.) ============== */
.card{border-radius:18px;background:var(--surf);border:.5px solid var(--line);padding:18px 16px;margin-bottom:12px;backdrop-filter:blur(30px) saturate(180%);-webkit-backdrop-filter:blur(30px) saturate(180%);width:100%;box-sizing:border-box}
@media(min-width:520px){.card{padding:18px 22px}}
.card-title{font-size:13px;color:var(--fg);font-weight:600;letter-spacing:-.008em;margin-bottom:10px;text-transform:none}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;flex-wrap:wrap;gap:8px}
.card-sub{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--fg3)}
.stats,.stat-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;width:100%}
@media(min-width:640px){.stats,.stat-grid{grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}}
.stat .lbl,.stat .stat-label{font-size:11px;color:var(--fg3);font-weight:500;letter-spacing:-.005em;margin-bottom:7px;text-transform:none}
.stat .val,.stat .stat-value{font-family:'Inter',sans-serif;font-size:22px;font-weight:500;letter-spacing:-.022em;color:var(--fg);overflow-wrap:anywhere;word-break:normal;hyphens:none;line-height:1.1;font-feature-settings:"tnum","lnum"}
.stat .val.em,.stat .stat-value.em{color:var(--em)}
.stat .val.gold,.stat .stat-value.gold,.stat .val.gd{color:var(--gold)}
.stat .val.blue,.stat .stat-value.blue,.stat .val.cy{color:var(--blue)}
.stat .val.purple,.stat .stat-value.purple,.stat .val.vi{color:var(--purple)}
.stat-sub{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--fg3);margin-top:4px}
.crumbs{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--fg3);margin-bottom:10px;letter-spacing:.005em}
.crumbs a{color:var(--em);text-decoration:none}
.crumbs a:hover{color:var(--emL)}
.pheader{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;flex-wrap:wrap;gap:10px}
.ptitle{font-size:22px;font-weight:600;letter-spacing:-.018em;color:var(--fg);line-height:1.2}
.pager{display:flex;gap:6px;font-family:'Inter',sans-serif;font-size:12px;flex-wrap:wrap}
.pager a{color:var(--fg2);text-decoration:none;padding:7px 12px;border:.5px solid var(--line2);border-radius:8px;background:var(--surf);transition:all .15s;font-weight:500;letter-spacing:-.005em}
.pager a:hover{background:var(--surfH);border-color:var(--em);color:var(--em)}
.pager a.cur{color:var(--em);border-color:var(--em);background:var(--em-bg)}
.tbl-scroll{overflow-x:auto;margin:8px 0;border-radius:12px;border:.5px solid var(--line);background:var(--surf);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px)}
.addr{color:var(--em);text-decoration:none;font-family:'JetBrains Mono',monospace}
.addr:hover{color:var(--emL)}
.badge{display:inline-block;padding:3px 9px;font-family:'JetBrains Mono',monospace;font-size:10.5px;letter-spacing:.04em;text-transform:uppercase;font-weight:600;border-radius:7px}
.badge-active{color:var(--em);background:rgba(var(--em-rgb),.10);border:.5px solid rgba(var(--em-rgb),.30)}
.badge-inactive{color:var(--fg3);background:var(--surf);border:.5px solid var(--line2)}
.container{max-width:780px;margin:0 auto;padding:0 16px}
.row-list{display:flex;flex-direction:column;gap:6px}
.rl-row{display:flex;align-items:center;gap:12px;padding:11px 14px;border:.5px solid var(--line);background:var(--surf);border-radius:12px;text-decoration:none;color:inherit;transition:background .15s,border-color .15s,transform .15s;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px)}
.rl-row:hover{background:var(--surfH);border-color:var(--line2);transform:translateY(-1px)}
.rl-ic{width:34px;height:34px;display:flex;align-items:center;justify-content:center;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600;color:var(--em);border:.5px solid rgba(var(--em-rgb),.30);background:rgba(var(--em-rgb),.10);flex-shrink:0;border-radius:10px}
.rl-ic.ic-h,.rl-ic.ic-b{color:var(--em)}
.rl-ic.ic-v{color:var(--purple);border-color:rgba(var(--purple-rgb),.30);background:rgba(var(--purple-rgb),.10)}
.rl-ic.ic-p{color:var(--blue);border-color:rgba(var(--blue-rgb),.30);background:rgba(var(--blue-rgb),.10)}
.rl-ic.ic-d,.rl-ic.ic-s{color:var(--blue);border-color:rgba(var(--blue-rgb),.30);background:rgba(var(--blue-rgb),.10)}
.rl-ic.ic-m{color:var(--gold);border-color:rgba(var(--gold-rgb),.30);background:rgba(var(--gold-rgb),.10)}
.rl-info{flex:1;min-width:0}
.rl-name{font-family:'Inter',sans-serif;font-size:14px;font-weight:600;color:var(--fg);letter-spacing:-.005em;overflow-wrap:anywhere;word-break:normal;hyphens:none}
.rl-sub{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--fg3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-top:3px}
.rl-val{text-align:right;flex-shrink:0}
.rl-v{font-family:'JetBrains Mono',monospace;font-size:14px;font-weight:600;color:var(--em);font-feature-settings:"tnum","lnum"}
.rl-vs{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--fg3);margin-top:2px}
/* substantial bar; always-visible fill nub at tiny %; crisper meta.
   Supply is a tiny fraction of the 21M cap for the chain's first
   year, so the fill is a narrow nub early on. A 240%-oversized SHIMMERING
   gradient animating on a ~14px nub read as a flickering "broken bar". Use a
   fitted static gradient + glow so the honest near-zero state looks intentional.
   (This is the rule that actually applies — an earlier duplicate near the
   supply-bar-wrap block is overridden by this one.) */
.supply-bar-track,.vault-bar-track{height:16px;background:var(--surf);border:.5px solid var(--line);position:relative;overflow:hidden;border-radius:99px;box-shadow:inset 0 1px 3px rgba(0,0,0,.28)}
.supply-bar-fill,.vault-bar-fill{position:absolute;left:0;top:0;bottom:0;min-width:14px;background:linear-gradient(90deg,var(--em),var(--emL));background-size:100% 100%;box-shadow:0 0 12px var(--em-glow),inset 0 1px 0 rgba(255,255,255,.3);transition:width .8s cubic-bezier(.22,1,.36,1);border-radius:99px}
.supply-bar-meta{display:flex;justify-content:space-between;margin-top:8px;font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--fg2);font-weight:600}
.act-round,.explorer-quicknav{display:flex;gap:8px;flex-wrap:wrap;justify-content:center}
.ar{display:flex;flex-direction:column;align-items:center;gap:5px;padding:11px 16px;border:.5px solid var(--line);background:var(--surf);text-decoration:none;color:var(--fg);transition:all .15s;border-radius:12px;backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px)}
.ar:hover{border-color:var(--em);background:var(--surfH);color:var(--em)}
.ar .ic{font-size:18px;color:var(--em)}
.ar .lbl{font-family:'Inter',sans-serif;font-size:11px;font-weight:600;color:var(--fg2);letter-spacing:-.005em;text-transform:none}
.explorer-hero-big{font-size:clamp(58px,10vw,84px);font-weight:200;letter-spacing:-.04em;line-height:.95;color:var(--fg);font-feature-settings:"tnum","lnum"}
.explorer-hero-meta{margin-top:12px;font-family:'JetBrains Mono',monospace;font-size:12.5px;color:var(--fg2)}
.hero-pill{display:inline-flex;align-items:center;padding:3px 9px;border-radius:99px;background:rgba(var(--em-rgb),.10);border:.5px solid rgba(var(--em-rgb),.30);color:var(--em);font-size:11px;font-weight:600;letter-spacing:-.005em;margin-right:8px}
.hero-sub{font-size:12px;color:var(--fg2)}

@media(max-width:520px){
  .grid3{grid-template-columns:1fr 1fr}
  .hero .num,.hero .big{font-size:48px}
  .tabs a,.tabs button{font-size:12px;padding:8px 14px}
  .kv .row{flex-direction:column;align-items:flex-start;gap:4px}
  .kv .v{text-align:left}
  .pager{justify-content:center}
}

/* ============== TIER COLORS + DIAMOND PRISMATIC SHIMMER ============== */
/* Mining tier rows on /mining + /rules. Diamond rows get the cyan
   shimmer (animated gradient clipped to text); other tiers get solid
   metallic colors. Without these rules, Diamond text falls back to
   plain white because background-clip:text has no gradient to clip. */
@keyframes diamondShine{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:200% 50%}}
.tier-0,.stat .stat-value.tier-0{color:var(--fg3)!important;-webkit-text-fill-color:var(--fg3)!important}
.tier-1,.stat .stat-value.tier-1{color:#CD7F32!important;-webkit-text-fill-color:#CD7F32!important}
.tier-2,.stat .stat-value.tier-2{color:#D8D8D8!important;-webkit-text-fill-color:#D8D8D8!important}
.tier-3,.stat .stat-value.tier-3{color:#FFD700!important;-webkit-text-fill-color:#FFD700!important}
.tier-4,.stat .stat-value.tier-4{color:#E5E4E2!important;-webkit-text-fill-color:#E5E4E2!important}
html[data-theme="light"] .tier-1,html[data-theme="light"] .stat .stat-value.tier-1{color:#CD7F32!important;-webkit-text-fill-color:#CD7F32!important}
html[data-theme="light"] .tier-2,html[data-theme="light"] .stat .stat-value.tier-2{color:#7A8591!important;-webkit-text-fill-color:#7A8591!important}
html[data-theme="light"] .tier-3,html[data-theme="light"] .stat .stat-value.tier-3{color:#B77900!important;-webkit-text-fill-color:#B77900!important}
html[data-theme="light"] .tier-4,html[data-theme="light"] .stat .stat-value.tier-4{color:#667080!important;-webkit-text-fill-color:#667080!important}
.tier-5,.diamond-prismatic,td.diamond-prismatic,span.diamond-prismatic{background-image:linear-gradient(100deg,#B9F2FF 0%,#FFFFFF 18%,#E0FFFF 36%,#7DD3FC 54%,#FFFFFF 72%,#B9F2FF 100%)!important;background-size:200% 100%!important;background-color:transparent!important;-webkit-background-clip:text!important;background-clip:text!important;color:transparent!important;-webkit-text-fill-color:transparent!important;animation:diamondShine 5s ease-in-out infinite!important;font-weight:700!important;filter:drop-shadow(0 0 6px rgba(185,242,255,.55)) drop-shadow(0 0 12px rgba(165,243,252,.25))!important;text-shadow:none!important}
/* use `background-image` (not `background` shorthand) for
   the light-mode override so background-clip:text inherits from the
   dark rule. Previously `background:` reset all background-* props and
   the gradient rendered as a solid block instead of being clipped to
   the text glyph shape. */
html[data-theme="light"] .tier-5,html[data-theme="light"] .diamond-prismatic,html[data-theme="light"] td.diamond-prismatic,html[data-theme="light"] span.diamond-prismatic{background-image:linear-gradient(100deg,#0891B2 0%,#06B6D4 22%,#0EA5E9 45%,#3B82F6 65%,#06B6D4 85%,#0891B2 100%)!important;background-size:200% 100%!important;background-color:transparent!important;-webkit-background-clip:text!important;background-clip:text!important;color:transparent!important;-webkit-text-fill-color:transparent!important;filter:drop-shadow(0 0 4px rgba(8,145,178,.35))!important}
.diamond-badge{display:inline-block!important;padding:3px 10px!important;border-radius:6px!important;background:linear-gradient(100deg,rgba(185,242,255,.18),rgba(255,255,255,.28),rgba(185,242,255,.18))!important;background-size:200% 100%!important;animation:diamondShine 5s ease-in-out infinite!important;border:1px solid rgba(185,242,255,.55)!important;font-size:10.5px!important;font-weight:700!important;letter-spacing:1.5px!important;color:#E0FFFF!important;text-transform:uppercase!important;box-shadow:0 0 12px rgba(185,242,255,.22)!important;font-variant-emoji:text}
html[data-theme="light"] .diamond-badge{color:#0c5b6e!important;background:linear-gradient(100deg,rgba(56,189,248,.18),rgba(165,243,252,.34),rgba(56,189,248,.18))!important;border:1px solid rgba(8,145,178,.45)!important;box-shadow:0 0 10px rgba(8,145,178,.18)!important}

/* ============== TABLES: min-width forces horizontal scroll instead of
   compressing cells until words break per-character. The .tbl-scroll
   parent already has overflow-x:auto, so on phones < 560px the table
   becomes swipeable side-to-side. ============== */
.tbl{min-width:560px}
.tbl tbody td{white-space:normal;overflow-wrap:normal;word-break:normal;hyphens:none}
.tbl tbody td.mono,.tbl tbody td.hash,.tbl tbody td[class*="hash"]{word-break:break-all;overflow-wrap:anywhere}
.tbl-scroll{-webkit-overflow-scrolling:touch}

/* Install surface shared by desktop, Android, and Apple browsers. Apple does
   not expose a programmatic install prompt, so the same button opens the
   browser-specific Add to Home Screen steps there. */
.explorer-install{display:none;position:fixed;top:0;left:0;right:0;z-index:10000;align-items:center;gap:13px;padding:12px 14px;background:rgba(16,20,17,.98);border:1px solid #343c36;box-shadow:0 16px 42px rgba(0,0,0,.32);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px)}
.explorer-install.show{display:flex}
.explorer-install img{width:42px;height:42px;padding:2px;border-radius:11px;flex:0 0 42px;object-fit:contain;background:#070b08;box-shadow:inset 0 0 0 1px #2c352e}
.explorer-install .copy{display:grid;gap:4px;min-width:0;flex:1}
.explorer-install .copy b{color:var(--fg);font:700 13px/1.2 'JetBrains Mono',monospace}
.explorer-install .copy span{color:var(--fg2);font:500 11px/1.35 'JetBrains Mono',monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.explorer-install .install-btn,.explorer-install-sheet button{min-height:36px;border:1px solid #59645b;border-radius:9px;background:#303832;color:#f5f7f5;padding:0 16px;font:700 11px 'JetBrains Mono',monospace;cursor:pointer;box-shadow:inset 0 1px rgba(255,255,255,.05)}
.explorer-install .install-btn:hover,.explorer-install-sheet button:hover{background:#3a443c}
.explorer-install .dismiss-btn{border:0;background:transparent;color:var(--fg3);padding:6px;font-size:20px;cursor:pointer}
.explorer-install-sheet{display:none;position:fixed;inset:0;z-index:10001;align-items:flex-end;justify-content:center;padding:20px;background:rgba(0,0,0,.72);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
.explorer-install-sheet.open{display:flex}
.explorer-install-card{width:min(100%,480px);padding:20px;border:.5px solid var(--line2);border-radius:18px;background:var(--bg2);box-shadow:0 24px 80px rgba(0,0,0,.5)}
.explorer-install-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:14px}
.explorer-install-head h2{font-size:19px;letter-spacing:-.02em}
.explorer-install-head p{margin-top:4px;color:var(--fg2);font-size:12px}
.explorer-install-head .sheet-close{width:34px;height:34px;padding:0;font-size:18px;flex:0 0 auto}
.explorer-install-steps{display:grid;gap:10px;counter-reset:explorer-install-step}
.explorer-install-step{display:grid;grid-template-columns:30px 38px 1fr;gap:10px;align-items:center;padding:12px;border:.5px solid var(--line);border-radius:11px;background:var(--surf);color:var(--fg2);font-size:13px;line-height:1.45}
.explorer-install-step::before{counter-increment:explorer-install-step;content:counter(explorer-install-step);display:grid;place-items:center;width:28px;height:28px;border-radius:50%;border:1px solid #59645b;background:#303832;color:#fff;font-weight:700}
.explorer-install-step-icon{display:grid;place-items:center;width:36px;height:36px;border:.5px solid var(--line2);border-radius:9px;background:var(--bg2);color:var(--fg)}
.explorer-install-step-icon svg{width:20px;height:20px}.explorer-install-step-copy{display:grid;gap:2px;min-width:0}.explorer-install-step-copy b{color:var(--fg);font-size:13px}.explorer-install-step-copy span{color:var(--fg2);font-size:12px}
html[data-theme="light"] .explorer-install{background:rgba(239,239,239,.98);border-color:#CFD1D0;box-shadow:0 16px 42px rgba(18,21,20,.14)}
html[data-theme="light"] .explorer-install img{background:#FFFFFF;box-shadow:inset 0 0 0 1px #D2D4D3}
html[data-theme="light"] .explorer-install-card{background:#FFFFFF;border-color:#CFD1D0;box-shadow:0 24px 80px rgba(18,21,20,.18)}
html[data-theme="light"] .explorer-install-step{background:#FAFAFA;border-color:#D2D4D3}
html[data-theme="light"] .explorer-install-step-icon{background:#EFEFEF;border-color:#CFD1D0}
html[data-device-layout="mobile"] body.has-explorer-install .bar{top:auto!important;margin-top:59px}
html[data-device-layout="mobile"] body.has-explorer-install .wrap{padding-top:18px!important}
@media(min-width:901px){.explorer-install{left:auto;right:22px;top:18px;width:min(440px,calc(100% - 44px));border-radius:14px}}
</style>)VLDCSS";
        return css;
    }

    static const std::string& ArcadeThemeScript() {
        static const std::string js = R"VLDJS(<script nonce="__CSP_NONCE__">
(function(){
  try{history.scrollRestoration='manual';}catch(_){}
  function resetPageScroll(){
    try{
      var pane=document.querySelector('.wrap');
      if(pane)pane.scrollTop=0;
      else window.scrollTo(0,0);
    }catch(_){}
  }
  window.addEventListener('load',resetPageScroll);
  window.addEventListener('pageshow',resetPageScroll);
  // Direct port of the wallet's veldSyncThemeColor pattern.
  // The REMOVE-EVERY-existing-meta then INSERT-FRESH pattern is what
  // makes iOS PWA / Safari pick up the new color reliably. Mutating
  // an existing meta's content attribute does NOT trigger a status-bar
  // repaint on some iOS builds. Colors match the wallet exactly
  // (#EFEFEF light, #0A0B0A dark) so the two apps' chrome behave the
  // same way on the same device.
  window.veldSyncThemeColor=function(t){
    var color=(t==='light')?'#EFEFEF':'#0A0B0A';
    var metas=document.querySelectorAll('meta[name="theme-color"]');
    for(var i=0;i<metas.length;i++){try{metas[i].parentNode.removeChild(metas[i]);}catch(_){}}
    var m=document.createElement('meta');
    m.setAttribute('name','theme-color');
    m.setAttribute('content',color);
    if(document.head.firstChild){document.head.insertBefore(m,document.head.firstChild);}
    else{document.head.appendChild(m);}
  };
  var theme='dark';
  try{
    var saved=localStorage.getItem('veld_theme');
    if(saved==='light'||saved==='dark'){theme=saved;}
    else if(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches){theme='light';}
  }catch(_){}
  document.documentElement.dataset.theme=theme;
  window.veldSyncThemeColor(theme);
  window.addEventListener('pageshow',function(){window.veldSyncThemeColor(document.documentElement.dataset.theme||'dark');});
  function attachToggle(){
    var btns=document.querySelectorAll('[data-theme-toggle]');
    if(!btns.length)return;
    function refreshIcon(t){
      for(var i=0;i<btns.length;i++){
        btns[i].setAttribute('aria-label',(t==='light')?'Switch to dark mode':'Switch to light mode');
        btns[i].textContent=(t==='light')?'☾':'☀';
      }
    }
    refreshIcon(document.documentElement.dataset.theme||'dark');
    for(var j=0;j<btns.length;j++){
      btns[j].addEventListener('click',function(){
        var cur=document.documentElement.dataset.theme||'dark';
        var nxt=(cur==='light')?'dark':'light';
        document.documentElement.dataset.theme=nxt;
        try{localStorage.setItem('veld_theme',nxt);}catch(_){}
        window.veldSyncThemeColor(nxt);
        refreshIcon(nxt);
      });
    }
  }
  if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',attachToggle);}
  else{attachToggle();}

  // Bottom-navbar "More" overlay toggle.
  // full event delegation on document (capture phase).
  // The previous version attached a click listener directly to the More
  // <button>. After a theme toggle, iOS Safari was reporting the bound
  // listener as "missing" until the next page navigation — symptom:
  // tapping More did nothing, but tapping the theme toggle (which has
  // its own per-element listener bound at page load) still worked. With
  // pure delegation the click is caught at the document level no matter
  // what state the navbar element is in.
  function attachNavMore(){
    var pane=document.getElementById('nav-more');
    if(!pane)return;
    function setOpen(o,btn){
      if(o){pane.setAttribute('data-open','1');if(btn)btn.classList.add('active');}
      else {pane.removeAttribute('data-open');
            var b=document.querySelector('[data-nav-more="toggle"]');
            if(b&&!b.dataset.activeSticky)b.classList.remove('active');}
    }
    document.addEventListener('click',function(e){
      var btn=e.target.closest('[data-nav-more="toggle"]');
      if(btn){
        e.preventDefault();
        e.stopPropagation();
        setOpen(!pane.hasAttribute('data-open'),btn);
        return;
      }
      if(!pane.hasAttribute('data-open'))return;
      if(pane.contains(e.target))return;
      if(e.target.closest('.nav-bar'))return; // let navbar links navigate
      setOpen(false);
    },true);
    document.addEventListener('keydown',function(e){if(e.key==='Escape')setOpen(false);});
    // Persist "More" active state when the user is currently on a More-route
    var initBtn=document.querySelector('[data-nav-more="toggle"]');
    if(initBtn&&initBtn.classList.contains('active'))initBtn.dataset.activeSticky='1';
  }
  if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',attachNavMore);}
  else{attachNavMore();}
})();
</script>)VLDJS";
        return js;
    }

    static const std::string& ArcadeTabsScript() {
        static const std::string js = R"VLDTABS(<script nonce="__CSP_NONCE__">
document.querySelectorAll('.tabs button[data-tab]').forEach(function(b){b.onclick=function(){var t=b.dataset.tab;document.querySelectorAll('.sec[data-pane]').forEach(function(s){s.style.display='none';});document.querySelectorAll('.tabs button[data-tab]').forEach(function(x){x.classList.remove('active');});var tgt=document.getElementById('tab-'+t);if(tgt)tgt.style.display='block';b.classList.add('active');};});
</script>)VLDTABS";
        return js;
    }

    std::string ArcadeHead(const std::string& title) {
        std::string out;
        out.reserve(16384);
        out += "<!DOCTYPE html>\n<html lang=\"en\" data-theme=\"dark\"><head><meta charset=\"UTF-8\">\n";
        out += "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0,viewport-fit=cover\">\n";
        out += "<meta name=\"theme-color\" content=\"#0A0B0A\">\n";
        out += "<meta name=\"apple-mobile-web-app-capable\" content=\"yes\">\n";
        out += "<meta name=\"apple-mobile-web-app-status-bar-style\" content=\"black-translucent\">\n";
        out += "<meta name=\"mobile-web-app-capable\" content=\"yes\">\n";
        out += "<link rel=\"icon\" type=\"image/png\" href=\"/icon-192.png?v=20260819veldgradient1\">\n";
        out += "<link rel=\"apple-touch-icon\" sizes=\"180x180\" href=\"/icon-192.png?v=20260819veldgradient1\">\n";
        out += "<link rel=\"apple-touch-icon\" sizes=\"192x192\" href=\"/icon-192.png?v=20260819veldgradient1\">\n";
        out += "<link rel=\"apple-touch-icon\" sizes=\"512x512\" href=\"/icon-512.png?v=20260819veldgradient1\">\n";
        out += "<link rel=\"apple-touch-icon-precomposed\" sizes=\"180x180\" href=\"/icon-192.png?v=20260819veldgradient1\">\n";
        out += "<link rel=\"apple-touch-icon-precomposed\" sizes=\"192x192\" href=\"/icon-192.png?v=20260819veldgradient1\">\n";
        out += "<link rel=\"apple-touch-icon-precomposed\" sizes=\"512x512\" href=\"/icon-512.png?v=20260819veldgradient1\">\n";
        out += "<link rel=\"manifest\" href=\"/manifest.json?v=20260819veldgradient1\">\n";
        out += "<meta name=\"apple-mobile-web-app-title\" content=\"Explorer\">\n";
        out += "<title>";
        out += title;
        out += "</title>\n";
        out += "<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\"><link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n";
        out += "<link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@200;300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap\" rel=\"stylesheet\">\n";
        out += ArcadeThemeScript();
        out += ArcadeCSS();
        out += "</head><body>\n";
        out += "<div class=\"explorer-install\" id=\"explorer-install\" role=\"region\" aria-label=\"Install Veld Explorer\">\n";
        out += "  <img src=\"/icon-192.png?v=20260819veldgradient1\" alt=\"\">\n";
        out += "  <span class=\"copy\"><b>Install Veld Explorer</b><span>Open the explorer as a standalone app</span></span>\n";
        out += "  <button type=\"button\" class=\"install-btn\" id=\"explorer-install-btn\">Install</button>\n";
        out += "  <button type=\"button\" class=\"dismiss-btn\" id=\"explorer-install-dismiss\" aria-label=\"Dismiss install prompt\">&times;</button>\n";
        out += "</div>\n";
        out += "<div class=\"explorer-install-sheet\" id=\"explorer-install-sheet\" role=\"dialog\" aria-modal=\"true\" aria-labelledby=\"explorer-install-title\">\n";
        out += "  <div class=\"explorer-install-card\"><div class=\"explorer-install-head\"><div><h2 id=\"explorer-install-title\">Install Veld Explorer</h2><p>Add the explorer from your browser menu in four quick steps.</p></div><button type=\"button\" class=\"sheet-close\" aria-label=\"Close install instructions\">&times;</button></div>\n";
        out += "  <div class=\"explorer-install-steps\"><div class=\"explorer-install-step\" id=\"explorer-install-step-one\"><span class=\"explorer-install-step-icon\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M12 3v12\"/><path d=\"M8 7l4-4 4 4\"/><path d=\"M8 12H6a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5a2 2 0 0 0-2-2h-2\"/></svg></span><span class=\"explorer-install-step-copy\"><b>Open Share</b><span>Tap the Share button in your browser toolbar.</span></span></div><div class=\"explorer-install-step\"><span class=\"explorer-install-step-icon\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"m6 9 6 6 6-6\"/></svg></span><span class=\"explorer-install-step-copy\"><b>Show all actions</b><span>Tap View More if the full action list is collapsed.</span></span></div><div class=\"explorer-install-step\"><span class=\"explorer-install-step-icon\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><rect x=\"4\" y=\"4\" width=\"16\" height=\"16\" rx=\"3\"/><path d=\"M12 8v8M8 12h8\"/></svg></span><span class=\"explorer-install-step-copy\"><b>Add to Home Screen</b><span>Choose Add to Home Screen from the action list.</span></span></div><div class=\"explorer-install-step\"><span class=\"explorer-install-step-icon\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"m5 12 4 4L19 6\"/></svg></span><span class=\"explorer-install-step-copy\"><b>Confirm</b><span>Tap Add. Veld Explorer will open as a standalone app.</span></span></div></div></div>\n";
        out += "</div>\n";
        out += "<div class=\"bar\">\n";
        out += "  <a class=\"mark\" href=\"/\"><span class=\"gl\"><svg class=\"veld-mark\" viewBox=\"0 0 64 64\" aria-hidden=\"true\"><defs><linearGradient id=\"veld-mark-mobile\" x1=\"12\" y1=\"52\" x2=\"52\" y2=\"12\" gradientUnits=\"userSpaceOnUse\"><stop stop-color=\"#18B958\"/><stop offset=\"1\" stop-color=\"#9AF34A\"/></linearGradient></defs><circle cx=\"32\" cy=\"32\" r=\"30\" fill=\"#151817\" stroke=\"#303632\"/><path d=\"M32 11 53 32 32 53 11 32 32 11Z\" fill=\"none\" stroke=\"url(#veld-mark-mobile)\" stroke-width=\"5\"/><path d=\"M32 21 43 32 32 43 21 32 32 21Z\" fill=\"none\" stroke=\"url(#veld-mark-mobile)\" stroke-width=\"4\"/></svg></span><span class=\"nm\">Veld</span></a>\n";
        out += "  <div class=\"bar-right\">\n";
        out += "    <div class=\"live\"><span class=\"dot\"></span>Live</div>\n";
        out += "    <button class=\"theme-tog\" data-theme-toggle aria-label=\"Toggle theme\">&#9728;</button>\n";
        out += "  </div>\n";
        out += "</div>\n";
        // .wrap is opened at the END of ArcadePrimaryTabs (after the nav), so the
        // mobile nav-bar/nav-more are DIRECT body children — see the navbar comment.
        return out;
    }

    std::string ArcadePrimaryTabs(const std::string& active) {
        static constexpr const char* kIconHome = R"SVG(<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="m15.2 8.8-2 4.4-4.4 2 2-4.4z"/></svg>)SVG";
        static constexpr const char* kIconBlocks = R"SVG(<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m12 2 8 4-8 4-8-4zM4 10l8 4 8-4M4 14l8 4 8-4M4 6v12l8 4 8-4V6"/></svg>)SVG";
        static constexpr const char* kIconMempool = R"SVG(<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M7 6h13M7 12h13M7 18h13"/><circle cx="4" cy="6" r="1.25" fill="currentColor" stroke="none"/><circle cx="4" cy="12" r="1.25" fill="currentColor" stroke="none"/><circle cx="4" cy="18" r="1.25" fill="currentColor" stroke="none"/></svg>)SVG";
        static constexpr const char* kIconValidators = R"SVG(<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 20 6v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6zM8.5 12l2.2 2.2 4.8-5"/></svg>)SVG";
        static constexpr const char* kIconVault = R"SVG(<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m3 9 9-5 9 5M5 10h14M6 10v7M10 10v7M14 10v7M18 10v7M4 18h16M3 21h18"/></svg>)SVG";
        static constexpr const char* kIconRich = R"SVG(<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m7 4-4 6 9 10 9-10-4-6zM3 10h18M7 4l5 6 5-6M12 10v10"/></svg>)SVG";
        static constexpr const char* kIconLiquidity = R"SVG(<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7c2.5 0 2.5 2 5 2s2.5-2 5-2 2.5 2 5 2 2.5-2 3-2M3 12c2.5 0 2.5 2 5 2s2.5-2 5-2 2.5 2 5 2 2.5-2 3-2M3 17c2.5 0 2.5 2 5 2s2.5-2 5-2 2.5 2 5 2 2.5-2 3-2"/></svg>)SVG";
        static constexpr const char* kIconWallet = R"SVG(<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="6" width="18" height="14" rx="2"/><path d="M4 9h17M16 13h5M6 3h12"/></svg>)SVG";
        static constexpr const char* kIconMore = R"SVG(<svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><circle class="nav-icon-dot" cx="8" cy="12" r="1"/><circle class="nav-icon-dot" cx="12" cy="12" r="1"/><circle class="nav-icon-dot" cx="16" cy="12" r="1"/></svg>)SVG";

        std::string out;
        auto is_more = [&](const std::string& a){
            return a == "staking" || a == "validators" || a == "vault" || a == "rich" || a == "rules" || a == "liquidity" || a == "wallet";
        };
        bool more_active = is_more(active);

        auto pri = [&](const char* slug, const char* label, const char* icon, const char* href){
            out += "  <a href=\"";
            out += href;
            out += "\" class=\"nb-tab";
            if (active == slug) out += " active";
            out += "\"><span class=\"ic\">";
            out += icon;
            out += "</span><span class=\"lb\">";
            out += label;
            out += "</span></a>\n";
        };
        auto more_cell = [&](const char* slug, const char* label, const char* icon, const char* href){
            out += "    <a href=\"";
            out += href;
            out += "\" class=\"nm-cell";
            if (active == slug) out += " active";
            out += "\"><span class=\"ic\">";
            out += icon;
            out += "</span><span class=\"lb\">";
            out += label;
            out += "</span></a>\n";
        };

        auto side = [&](const char* slug, const char* label, const char* icon, const char* href){
            out += "  <a href=\"";
            out += href;
            out += "\" class=\"sn-link";
            if (active == slug) out += " active";
            out += "\"><span class=\"ic\">";
            out += icon;
            out += "</span><span class=\"lb\">";
            out += label;
            out += "</span></a>\n";
        };

        // Desktop-only left sidebar rail (CSS hides it below 901px). All ten
        // sections inline, no More overflow. Same slugs/icons/hrefs as the
        // phone nav so server-side active highlighting stays consistent.
        out += "<nav class=\"side-nav\">\n";
        out += "  <a class=\"sn-logo\" href=\"/\"><span class=\"gl\"><svg class=\"veld-mark\" viewBox=\"0 0 64 64\" aria-hidden=\"true\"><defs><linearGradient id=\"veld-mark-desktop\" x1=\"12\" y1=\"52\" x2=\"52\" y2=\"12\" gradientUnits=\"userSpaceOnUse\"><stop stop-color=\"#18B958\"/><stop offset=\"1\" stop-color=\"#9AF34A\"/></linearGradient></defs><circle cx=\"32\" cy=\"32\" r=\"30\" fill=\"#151817\" stroke=\"#303632\"/><path d=\"M32 11 53 32 32 53 11 32 32 11Z\" fill=\"none\" stroke=\"url(#veld-mark-desktop)\" stroke-width=\"5\"/><path d=\"M32 21 43 32 32 43 21 32 32 21Z\" fill=\"none\" stroke=\"url(#veld-mark-desktop)\" stroke-width=\"4\"/></svg></span><span class=\"nm\">Veld</span></a>\n";
        side("landing",    "Home",       kIconHome,                         "/");
        side("blocks",     "Blocks",     kIconBlocks,                       "/blocks");
        side("mempool",    "Mempool",    kIconMempool,                      "/mempool");
        side("mining",     "Mining",     "\xE2\x9B\x8F\xEF\xB8\x8E",  "/mining");
        side("staking",    "Stake",      "\x25",                       "/staking");
        side("validators", "Validators", kIconValidators,                   "/validators");
        side("vault",      "Vault",      kIconVault,                        "/vault");
        side("rich",       "Rich",       kIconRich,                         "/rich");
        side("rules",      "Rules",      "\xC2\xA7",                   "/rules");
        side("liquidity",  "Liquidity",  kIconLiquidity,                    "/liquidity");
        side("wallet",     "Wallet",     kIconWallet,                       "/wallet");
        out += "  <div class=\"sn-foot\"><span class=\"live\"><span class=\"dot\"></span>Live</span><button class=\"theme-tog\" data-theme-toggle aria-label=\"Toggle theme\">&#9728;</button></div>\n";
        out += "</nav>\n";

        out += "<nav class=\"nav-bar\">\n";
        pri("landing", "Home",    kIconHome,                            "/");
        pri("blocks",  "Blocks",  kIconBlocks,                          "/blocks");
        pri("mempool", "Mempool", kIconMempool,                         "/mempool");
        pri("mining",  "Mining",  "\xE2\x9B\x8F\xEF\xB8\x8E",     "/mining");
        out += "  <button type=\"button\" class=\"nb-tab nb-more-btn";
        if (more_active) out += " active";
        out += "\" data-nav-more=\"toggle\"><span class=\"ic\">";
        out += kIconMore;
        out += "</span><span class=\"lb\">More</span></button>\n";
        out += "</nav>\n";

        // Do NOT auto-open the overlay when the active route is a More-route.
        // The More button stays .active (so the user sees what tab they're on),
        // but the panel only opens on explicit tap. Auto-opening trapped users
        // who tapped a More item and saw the panel still open on the new page.
        out += "<div class=\"nav-more\" id=\"nav-more\"><div class=\"nm-grid\">\n";
        more_cell("staking",    "Stake",      "\x25",                          "/staking");
        more_cell("validators", "Validators", kIconValidators,                       "/validators");
        more_cell("vault",      "Vault",      kIconVault,                            "/vault");
        more_cell("rich",       "Rich",       kIconRich,                             "/rich");
        more_cell("rules",      "Rules",      "\xC2\xA7",                      "/rules");
        more_cell("liquidity",  "Liquidity",  kIconLiquidity,                        "/liquidity");
        more_cell("wallet",     "Wallet",     kIconWallet,                           "/wallet");
        out += "</div></div>\n";

        // Keep the header, content pane, nav, and menu as direct body children.
        // The touch layout assigns them to fixed viewport-shell rows.
        out += "<div class=\"wrap\">\n";
        return out;
    }

    static const std::string& ArcadePWAScript() {
        static const std::string js = R"VLDPWA(<script nonce="__CSP_NONCE__">
(function(){
  var compactMedia=window.matchMedia?window.matchMedia('(max-width: 900px)'):null;
  var touchTabletMedia=window.matchMedia?window.matchMedia('(hover: none) and (pointer: coarse)'):null;
  function syncLayout(){
    var compact=compactMedia?compactMedia.matches:window.innerWidth<=900;
    var touchTablet=touchTabletMedia?touchTabletMedia.matches:false;
    document.documentElement.dataset.deviceLayout=
      (compact||touchTablet)?'mobile':'desktop';
  }
  syncLayout();
  [compactMedia,touchTabletMedia].forEach(function(media){
    if(!media)return;
    if(media.addEventListener)media.addEventListener('change',syncLayout);
    else if(media.addListener)media.addListener(syncLayout);
  });
  window.addEventListener('resize',syncLayout,{passive:true});
  window.addEventListener('orientationchange',function(){
    window.setTimeout(syncLayout,0);
  });

  var installEvent=null;
  var ua=navigator.userAgent||'';
  var isIOS=/iphone|ipad|ipod/i.test(ua)||
    (navigator.platform==='MacIntel'&&(navigator.maxTouchPoints||0)>1);
  var standalone=navigator.standalone===true||
    (window.matchMedia&&window.matchMedia('(display-mode: standalone)').matches);
  var banner=document.getElementById('explorer-install');
  var button=document.getElementById('explorer-install-btn');
  var dismiss=document.getElementById('explorer-install-dismiss');
  var sheet=document.getElementById('explorer-install-sheet');
  var sheetClose=sheet?sheet.querySelector('.sheet-close'):null;

  function dismissed(){try{return sessionStorage.getItem('veld-explorer-install-dismissed')==='1';}catch(_){return false;}}
  function show(){if(!standalone&&!dismissed()&&banner){banner.classList.add('show');document.body.classList.add('has-explorer-install');}}
  function hide(){if(banner)banner.classList.remove('show');document.body.classList.remove('has-explorer-install');}
  function closeSheet(){if(sheet)sheet.classList.remove('open');}
  function appleStep(){
    return '<span class="explorer-install-step-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12"/><path d="M8 7l4-4 4 4"/><path d="M8 12H6a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-5a2 2 0 0 0-2-2h-2"/></svg></span><span class="explorer-install-step-copy"><b>Open Share</b><span>Tap the Share button in your browser toolbar.</span></span>';
  }
  function openSheet(){
    var first=document.getElementById('explorer-install-step-one');
    if(first)first.innerHTML=appleStep();
    if(sheet){sheet.classList.add('open');if(sheetClose)sheetClose.focus();}
  }
  window.addEventListener('beforeinstallprompt',function(event){
    event.preventDefault();installEvent=event;show();
  });
  window.addEventListener('appinstalled',function(){installEvent=null;hide();closeSheet();});
  if(button)button.addEventListener('click',function(){
    if(installEvent){
      installEvent.prompt();
      installEvent.userChoice.then(function(){installEvent=null;hide();});
    }else if(isIOS&&!standalone){openSheet();}
  });
  if(dismiss)dismiss.addEventListener('click',function(){try{sessionStorage.setItem('veld-explorer-install-dismissed','1');}catch(_){}hide();});
  if(sheetClose)sheetClose.addEventListener('click',closeSheet);
  if(sheet)sheet.addEventListener('click',function(event){if(event.target===sheet)closeSheet();});
  document.addEventListener('keydown',function(event){if(event.key==='Escape')closeSheet();});
  if(isIOS&&!standalone)setTimeout(show,1200);
  if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js?ui=20260903-navigation-fallback',{scope:'/',updateViaCache:'none'}).catch(function(){});}

  var txPath=/^\/tx\/[0-9a-f]{64}$/i;
  function markMempoolContext(){
    document.querySelectorAll('.nav-bar .nb-tab.active, .side-nav .sn-link.active').forEach(function(item){item.classList.remove('active');});
    var mobile=document.querySelector('.nav-bar .nb-tab[href="/mempool"]');
    var desktop=document.querySelector('.side-nav .sn-link[href="/mempool"]');
    if(mobile)mobile.classList.add('active');
    if(desktop)desktop.classList.add('active');
  }
  function eligibleSoftPath(path){return path==='/mempool'||txPath.test(path);}
  function resetContentScroll(){
    window.scrollTo(0,0);
    var wrap=document.querySelector('.wrap');
    if(wrap&&typeof wrap.scrollTo==='function')wrap.scrollTo(0,0);
  }
  async function loadExplorerContent(url,push){
    try{
      var response=await fetch(url,{cache:'no-store',credentials:'same-origin',headers:{Accept:'text/html'}});
      if(!response.ok||response.redirected){window.location.assign(response.url||url);return;}
      var parsed=new DOMParser().parseFromString(await response.text(),'text/html');
      var incoming=parsed.querySelector('.wrap');
      var current=document.querySelector('.wrap');
      if(!incoming||!current)throw new Error('Explorer content pane missing');
      current.replaceChildren.apply(current,Array.from(incoming.childNodes).map(function(node){return document.importNode(node,true);}));
      document.title=parsed.title||document.title;
      var resolved=new URL(response.url||url,window.location.href);
      if(push)history.pushState({veldExplorerSoftTxNav:true},'',resolved.pathname+resolved.search+resolved.hash);
      markMempoolContext();
      resetContentScroll();
    }catch(_){window.location.assign(url);}
  }
  if(!window.__veldExplorerSoftTxNav){
    window.__veldExplorerSoftTxNav=true;
    var enteredMempoolInShell=false;
    document.addEventListener('click',function(event){
      var link=event.target.closest?event.target.closest('a[href]'):null;
      if(!link)return;
      var target=new URL(link.href,window.location.href);
      var enteringMempool=target.origin===window.location.origin&&target.pathname==='/mempool'&&window.location.pathname!=='/mempool'&&link.matches('.nav-bar .nb-tab, .side-nav .sn-link');
      var openingTransaction=window.location.pathname==='/mempool'&&txPath.test(target.pathname);
      if(!enteringMempool&&!openingTransaction)return;
      if(event.button!==0||event.metaKey||event.ctrlKey||event.shiftKey||event.altKey)return;
      event.preventDefault();
      if(enteringMempool)enteredMempoolInShell=true;
      loadExplorerContent(link.href,true);
    });
    window.addEventListener('popstate',function(){
      if(eligibleSoftPath(window.location.pathname))loadExplorerContent(window.location.href,false);
      else if(enteredMempoolInShell)window.location.reload();
    });
  }
})();
</script>)VLDPWA";
        return js;
    }

    std::string ArcadeFoot() {
        std::string out;
        out += "</div>\n";
        out += "<script nonce=\"__CSP_NONCE__\">\n";
        out += veld::explorer_dispatch::kDispatchJs;
        out += "\n</script>\n";
        out += ArcadePWAScript();
        out += "</body></html>\n";
        return out;
    }

    std::string HtmlWrapArcade(const std::string& title,
                               const std::string& body,
                               const std::string& active_nav = "") {
        std::string out;
        out.reserve(body.size() + 16384);
        std::string full_title = title.empty() ? std::string("Veld &middot; Network")
                                               : (std::string("Veld &middot; ") + title);
        out += ArcadeHead(full_title);
        out += ArcadePrimaryTabs(active_nav);
        out += body;
        out += ArcadeFoot();
        return out;
    }

    HttpResponse ServeLanding() {
        uint64_t height    = chain_.Height();
        uint64_t best_h    = BestKnownHeight();
        uint64_t next_dist = VAULT_DISTRIBUTION_INTERVAL - (best_h % VAULT_DISTRIBUTION_INTERVAL);
        double   supply    = chain_.TotalSupplyVeld();

        std::ostringstream page;
        page << ArcadeHead("Veld &middot; Network");
        page << ArcadePrimaryTabs("landing");

        page << R"HTML(<div style="display:flex;gap:8px;margin:16px 0">
  <input type="text" id="gsearch" class="search" placeholder="Search block, hash, tx, or address…" style="flex:1">
  <button id="gsearch-btn" class="btn">Go</button>
</div>
)HTML";

        page << "<div class=\"hero\">\n";
        page << "  <div class=\"lbl\">Block height</div>\n";
        page << "  <div class=\"num\" id=\"s-height-big\">" << height << "</div>\n";
        page << "  <div class=\"meta\" id=\"s-meta-holder\">\n";
        page << "    <span class=\"it em\"><span class=\"dot\"></span>tip &middot; <b id=\"s-tip-age\">+ now</b></span>\n";
        page << "    <span class=\"it\"><span class=\"dot\"></span><b id=\"s-pending\">&mdash;</b> pending</span>\n";
        page << "    <span class=\"it\"><span class=\"dot\"></span>vault flushes in <b>" << next_dist << "</b></span>\n";
        page << "  </div>\n";
        page << "</div>\n";

        page << R"HTML(<div class="grid2">
  <div class="tile em"><div class="l">Vault</div><div class="v" id="s-vault">&mdash;<span class="u">VELD</span></div></div>
  <div class="tile"><div class="l">Next distribution</div><div class="v" id="s-next">)HTML";
        page << next_dist;
        page << R"HTML(<span class="u">blocks</span></div></div>
  <div class="tile gold"><div class="l">Total supply</div><div class="v" id="s-supply">)HTML";
        page << std::fixed << std::setprecision(0) << supply;
        page << R"HTML(<span class="u">VELD</span></div></div>
  <div class="tile"><div class="l">Hashrate</div><div class="v" id="s-hashrate">&mdash;<span class="u">KH/s</span></div></div>
  <div class="tile span2"><div class="l">Mempool</div><div class="v"><span id="s-mempool">&mdash;</span><span class="u">tx &middot; <span id="s-mempool-kb">&mdash;</span> KB &middot; <span id="s-peers">&mdash;</span> network nodes</span></div></div>
</div>

)HTML";

        double pct = (supply / (double)MAX_SUPPLY) * 100.0;
        if (pct < 0.0) pct = 0.0; else if (pct > 100.0) pct = 100.0;
        page << "<h3>Supply progress<span class=\"ct\" id=\"s-supply-pct\">"
             << std::fixed << std::setprecision(3) << pct << "% mined</span></h3>\n";
        page << "<div style=\"padding:14px 18px;border-radius:16px;background:var(--surf);border:.5px solid var(--line);backdrop-filter:blur(24px) saturate(180%);-webkit-backdrop-filter:blur(24px) saturate(180%);margin-bottom:16px\">\n";
        page << "  <div class=\"supply-bar-track\">\n";
        page << "    <div id=\"s-supply-bar\" class=\"supply-bar-fill\" style=\"width:"
             << std::fixed << std::setprecision(4) << pct << "%\"></div>\n";
        page << "  </div>\n";
        page << "  <div class=\"supply-bar-meta\">\n";
        page << "    <span>0</span><span id=\"s-supply-num\">"
             << std::fixed << std::setprecision(2) << supply
             << " VELD mined</span><span>21,000,000</span>\n";
        page << "  </div>\n";
        page << "</div>\n";

        page << R"HTML(<h3>Recent blocks <span class="ct"><a href="/blocks">view all &rarr;</a></span></h3>
<div id="blocks-list" class="list">
  <div style="color:var(--fg3);text-align:center;padding:18px;font-family:'Inter',sans-serif;font-size:13px">Loading&hellip;</div>
</div>

)HTML";

        page << ArcadeFoot();

        page << R"HTML(<script nonce="__CSP_NONCE__">
function fmt(n,d){return parseFloat(n||0).toFixed(d!==undefined?d:2);}
function fmtInt(n){return Math.floor(parseFloat(n||0)).toLocaleString();}
function shortHash(h){return h?h.slice(0,8)+'…'+h.slice(-6):'—';}
function shortAddr(a){return a?a.slice(0,6)+'…'+a.slice(-4):'—';}
function ago(t){var s=Math.floor(Date.now()/1000)-(t||0);if(s<0)s=0;if(s<60)return s+' s';if(s<3600)return Math.floor(s/60)+' m';if(s<86400)return Math.floor(s/3600)+' h';return Math.floor(s/86400)+' d';}
function doSearch(){var q=document.getElementById('gsearch').value.trim();if(!q)return;var eq=encodeURIComponent(q);if(/^[0-9]+$/.test(q))window.location='/block/height/'+eq;else if(/^[0-9a-f]{64}$/i.test(q))window.location='/block/'+eq;else if(q.charAt(0)==='V')window.location='/address/'+eq;else window.location='/tx/'+eq;}
document.getElementById('gsearch-btn').addEventListener('click',doSearch);
document.getElementById('gsearch').addEventListener('keydown',function(e){if(e.key==='Enter')doSearch();});
var knownH=0;
function loadStats(){
  fetch('/api/stats').then(function(r){if(!r.ok)throw new Error('stats unavailable');return r.json();}).then(function(d){
    var h=d.height||0;
    document.getElementById('s-height-big').textContent=h.toLocaleString();
    var sup=parseFloat(d.supply_veld||0);
    var ageEl=document.getElementById('s-tip-age');
    if(ageEl){
      if(typeof d.tip_timestamp==='number'&&d.tip_timestamp>0){
        ageEl.textContent='+'+ago(d.tip_timestamp);
      } else { ageEl.textContent='+ now'; }
    }
    document.getElementById('s-pending').textContent=(d.mempool_size||0);
    document.getElementById('s-vault').innerHTML=fmt(d.vault_balance_veld||0,2)+'<span class="u">VELD</span>';
    document.getElementById('s-mempool').textContent=(d.mempool_size||0);
    var mempoolKb=document.getElementById('s-mempool-kb');if(mempoolKb)mempoolKb.textContent=Math.round((d.mempool_bytes||0)/1024*10)/10;
    document.getElementById('s-supply').innerHTML=fmtInt(sup)+'<span class="u">VELD</span>';
    var pe=document.getElementById('s-peers');if(pe)fetch('/api/v1/topology',{cache:'no-store'}).then(function(r){if(!r.ok)throw new Error('topology unavailable');return r.json();}).then(function(t){var nodes=Array.isArray(t.nodes)?t.nodes:[];pe.textContent=new Set(nodes.map(function(node){return String(node.id);})).size||'—';}).catch(function(){pe.textContent='—';});
    var hr=parseFloat(d.hashrate||0);
    document.getElementById('s-hashrate').innerHTML=fmt(hr/1000,1)+'<span class="u">KH/s</span>';
    var pct=Math.max(0,Math.min(100,sup/21000000*100));
    var bar=document.getElementById('s-supply-bar');if(bar)bar.style.width=pct.toFixed(4)+'%';
    var pctEl=document.getElementById('s-supply-pct');if(pctEl)pctEl.textContent=pct.toFixed(3)+'% mined';
    var snum=document.getElementById('s-supply-num');if(snum)snum.textContent=fmt(sup,2)+' VELD mined';
    if(h>knownH){knownH=h;loadBlocks(h);}
  }).catch(function(){});
}
function loadBlocks(h){
  var ps=[];
  for(var i=h;i>=Math.max(0,h-9);i--){
    (function(bh){ps.push(fetch('/api/v1/block/'+bh).then(function(r){return r.json();}).catch(function(){return null;}));})(i);
  }
  Promise.all(ps).then(function(bs){
    var html='';
    var shown=bs.filter(function(b){return b&&!b.error;});
    shown.forEach(function(b){
      var tx=b.tx_count||b.ntx||0;
      var size=b.size_kb||Math.round((b.size||0)/102.4)/10;
      var isFresh=(b.height===knownH);
      html+='<a class="bk'+(isFresh?' fresh':'')+'" href="/block/height/'+b.height+'">'+
        '<div class="ic">'+(Math.floor(b.height/1000))+'k</div>'+
        '<div class="info"><div class="h">#'+b.height.toLocaleString()+'<span class="bk-badges" data-bh="'+b.height+'"></span></div>'+
        '<div class="s">'+shortHash(b.hash)+(b.miner?' &middot; '+shortAddr(b.miner):'')+'</div></div>'+
        '<div class="right"><div class="ago">'+ago(b.time)+'</div>'+
        '<div class="tx">'+tx+' tx &middot; '+size+' KB</div></div>'+
        '</a>';
    });
    var list=document.getElementById('blocks-list');
    if(list)list.innerHTML=html||'<div style="color:var(--fg3);text-align:center;padding:18px">No blocks</div>';
    // Tag blocks that carry special (non-coinbase) txs so their contents read at
    // a glance. Only blocks with more than the coinbase tx are queried (the vast
    // majority are 1-tx, so this stays cheap); routine header-relay/coinbase are
    // not badged.
    var BADGE={btcveld_mint:['Mint','gold'],btcveld_redeem:['Redeem','gold'],btcveld_transfer:['btcVELD','gold'],amm_op:['AMM','blue'],stake_lock:['Stake','em'],stake_unlock:['Unstake','em'],endorsement:['Endorse','blue'],validator_register:['Validator','blue'],staking_distribution:['Payout','em'],endorsement_distribution:['Val payout','blue'],anchor_post:['Anchor','gold'],btc_header_relay:['BTC hdr','gold']};
    shown.forEach(function(b){
      if((b.tx_count||b.ntx||0)<=1)return;
      fetch('/api/v1/events/'+b.height).then(function(r){return r.json();}).then(function(e){
        if(!e||!Array.isArray(e.events))return;
        var seen={},out='';
        e.events.forEach(function(ev){
          var t=ev&&ev.type; if(!t||seen[t])return; seen[t]=1;
          var bd=BADGE[t]; if(!bd)return;
          out+='<span class="bk-badge '+bd[1]+'">'+bd[0]+'</span>';
        });
        if(!out)return;
        var slot=document.querySelector('.bk-badges[data-bh="'+b.height+'"]');
        if(slot)slot.innerHTML=out;
      }).catch(function(){});
    });
  });
}
loadStats();
(function(){
  var _lastTip=-1,_lastHeavy=0;
  function tick(){
    var now=Date.now();
    var heartbeat=(now-_lastHeavy)>=60000;
    fetch('/api/stats').then(function(r){if(!r.ok)throw new Error('stats unavailable');return r.json();}).then(function(d){
      var h=(d&&typeof d.height==='number')?d.height:-1;
      if(h===-1)return;
      if(h!==_lastTip||heartbeat){_lastTip=h;_lastHeavy=now;loadStats();}
    }).catch(function(){});
  }
  setInterval(tick,2000);
})();
</script>
)HTML";

        return HttpResponse::HTML(page.str());
    }

    HttpResponse ServeBlock(const std::string& hash_hex) {
        if (!IsStrictLowerHex64(hash_hex)) {
            std::ostringstream err;
            err << "<div class=\"container\" style=\"padding:40px;text-align:center\">"
                << "<h1 style=\"font-size:20px;color:var(--em);margin-bottom:12px\">Invalid Block Hash</h1>"
                << "<p style=\"color:var(--muted);font-size:13px\">A Veld block hash is 64 hexadecimal characters.</p>"
                << "</div>";
            return HttpResponse::HTML(HtmlWrapArcade("Invalid Block", err.str(), "blocks"));
        }
        Hash256 hash = HexToHash(hash_hex);
        auto block = chain_.GetBlockByHash(hash);
        if (!block) return HttpResponse::NotFound("block " + hash_hex);

        std::ostringstream c;
        std::string full_hash = HashToHex(block->GetHash());

        c << "<div class=\"crumbs\"><a href=\"/blocks\">Blocks</a> / Block #" << block->height << "</div>";
        c << "<div class=\"pheader\" style=\"margin-bottom:22px;flex-wrap:wrap\">";
        c << "<div><div class=\"ptitle\">Block <span style=\"color:var(--em)\">#" << block->height << "</span></div></div>";
        {
            const char* pbtn = "display:inline-flex;align-items:center;gap:6px;text-decoration:none;padding:8px 14px;border:1px solid var(--b2);border-radius:10px;background:var(--s2);color:var(--text);font-size:12.5px;font-weight:600;font-family:var(--sans)";
            const char* pcur = "display:inline-flex;align-items:center;padding:8px 14px;border-radius:10px;background:var(--em-dim);color:var(--em);font-size:12.5px;font-weight:700;font-family:var(--sans)";
            c << "<div class=\"pager\" style=\"display:flex;gap:8px;align-items:center;flex-wrap:wrap\">";
            if (block->height > 0)
                c << "<a href=\"/block/height/" << (block->height-1) << "\" style=\"" << pbtn << "\"><span style=\"color:var(--em);font-weight:700\">&larr;</span> Block " << (block->height-1) << "</a>";
            c << "<span style=\"" << pcur << "\">Block " << block->height << "</span>";
            c << "<a href=\"/block/height/" << (block->height+1) << "\" style=\"" << pbtn << "\">Block " << (block->height+1) << " <span style=\"color:var(--em);font-weight:700\">&rarr;</span></a>";
            c << "</div></div>";
        }

        c << "<div class=\"card\">";
        c << "<div class=\"card-title\">Block #" << block->height << "</div>";
        c << "<div class=\"stats stat-grid\" style=\"margin-bottom:16px\">";
        c << "<div class=\"stat\"><div class=\"lbl stat-label\">Height</div><div class=\"val stat-value em\">" << block->height << "</div></div>";
        c << "<div class=\"stat\"><div class=\"lbl stat-label\">Transactions</div><div class=\"val stat-value\">" << block->transactions.size() << "</div></div>";
        c << "<div class=\"stat\"><div class=\"lbl stat-label\">Nonce</div><div class=\"val stat-value\" style=\"font-size:18px\">" << block->header.nonce << "</div></div>";
        c << "<div class=\"stat\"><div class=\"lbl stat-label\">Bits</div><div class=\"val stat-value\" style=\"font-size:18px\">0x" << std::hex << block->header.bits << std::dec << "</div></div>";
        c << "</div>";
        c << "<div class=\"tbl-scroll\"><table class=\"tbl\"><tbody>";
        {
            size_t endorse_count = validators_ ? validators_->GetEndorsementCount(block->height) : 0;
            size_t total_vals    = validators_ ? validators_->GetActiveValidatorCount() : 0;
            std::string badge_color = endorse_count == 0 ? "var(--muted)"
                                    : endorse_count >= total_vals && total_vals > 0 ? "var(--em)"
                                    : "var(--gold)";
            c << "<div style=\"margin-bottom:12px\">"
              << "<span style=\"font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted)\">"
              << "Validator Endorsements</span> "
              << "<span style=\"font-family:'JetBrains Mono',monospace;font-size:13px;color:" << badge_color << "\">"
              << endorse_count;
            if (total_vals > 0)
                c << " / " << total_vals;
            c << "</span></div>";

            if (validators_ && endorse_count > 0) {
                auto endorsements = validators_->GetEndorsements(block->height);
                uint64_t next_flush =
                    ((block->height / VAULT_DISTRIBUTION_INTERVAL) + 1) *
                    VAULT_DISTRIBUTION_INTERVAL;
                c << "<div style=\"margin:4px 0 12px 0;padding:10px;background:var(--s3);"
                     "border:1px solid var(--b1);border-radius:6px;box-sizing:border-box;"
                     "max-width:100%;overflow-wrap:anywhere\">"
                  << "<div style=\"font-size:10px;text-transform:uppercase;letter-spacing:1.2px;"
                     "color:var(--muted);margin-bottom:6px;white-space:normal\">Endorsing Validators "
                     "<span style=\"text-transform:none;letter-spacing:0;color:var(--muted2);"
                     "font-weight:400\"> &middot; payouts batch every 480 blocks &middot; next flush at block "
                  << "<a href=\"/block/height/" << next_flush << "\" style=\"color:var(--em)\">"
                  << next_flush << "</a></span></div>";
                for (const auto& e : endorsements) {
                    std::string addr = e.address.empty() ? "(unknown)" : e.address;
                    if (addr != "(unknown)" && !IsStrictBase58Address(addr)) {
                        std::cerr << "[explorer] skipping endorsement row with non-base58 address: "
                                  << addr.substr(0, 64) << "\n";
                        continue;
                    }
                    std::string addr_short = addr.size() > 20 ? addr.substr(0,16) + "&hellip;" + addr.substr(addr.size()-4) : addr;
                    const char* status_color = e.reward_paid ? "var(--em)" : "var(--gold)";
                    const char* status_text  = e.reward_paid ? "paid" : "queued";
                    c << "<div style=\"display:flex;justify-content:space-between;"
                         "padding:4px 0;font-size:11px;font-family:'JetBrains Mono',monospace\">"
                      << "<a href=\"/address/" << addr << "\" class=\"addr\">" << addr_short << "</a>"
                      << "<span style=\"color:" << status_color << "\" "
                      << "title=\"" << (e.reward_paid
                          ? "Endorsement reward has been paid out from the endorsement pool."
                          : "Endorsement is on-chain. Payout is queued for the next 480-block flush.")
                      << "\">" << status_text << "</span>"
                      << "</div>";
                }
                c << "</div>";
            }
        }
        auto row = [&](const std::string& k, const std::string& v, bool is_hash = false) {
            if (is_hash) {
                c << "<tr><td style=\"color:var(--muted);width:120px;white-space:nowrap;font-size:11px\">" << k << "</td>"
                  << "<td class=\"mono\" style=\"word-break:break-all;overflow-wrap:anywhere\">" << v << "</td></tr>";
            } else {
                c << "<tr><td style=\"color:var(--muted);width:120px;white-space:nowrap;font-size:11px\">" << k << "</td>"
                  << "<td style=\"font-size:11px;word-break:break-all;overflow-wrap:anywhere\">" << v << "</td></tr>";
            }
        };
        auto fmt_ts = [](uint32_t ts) -> std::string {
            if (ts == 0) return "—";
            time_t t = (time_t)ts;
            std::tm tm_utc{};
#ifdef _WIN32
            gmtime_s(&tm_utc, &t);
#else
            gmtime_r(&t, &tm_utc);
#endif
            char buf[64];
            std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_utc);
            return std::string(buf) + " (" + std::to_string(ts) + ")";
        };
        row("Hash", full_hash, true);
        row("Prev Block", HashToHex(block->header.prev_block_hash), true);
        row("Merkle Root", HashToHex(block->header.merkle_root), true);
        row("Timestamp", fmt_ts(block->header.timestamp));
        c << "</tbody></table></div>";

        if (!block->transactions.empty() && block->transactions[0].IsCoinbase()) {
            const auto& cb = block->transactions[0];
            uint64_t cb_total = 0;
            for (auto& o : cb.outputs) cb_total += o.value;
            double cb_total_veld = (double)cb_total / VELD_UNITS;
            // Sum the coinbase outputs by destination FIRST, then derive the
            // split percentages from the ACTUAL amounts. Pre-staking-activation
            // the co-mine + endorsement slices are 0, so the real split is 50/50
            // miner/vault — NOT the post-activation 50/20/20/10. Computing from
            // the block keeps the label correct in every era.
            double miner=0,comine=0,vault=0,endorse=0;
            std::string miner_addr="&mdash;",comine_addr=POOL_ADDRESS,vault_addr=VAULT_ADDRESS,endorse_addr=ENDORSEMENT_POOL_ADDRESS;
            for (auto& o : cb.outputs) {
                std::string addr = ScriptToAddress(o.script_pubkey);
                double v = (double)o.value / VELD_UNITS;
                if (addr == POOL_ADDRESS)              comine  += v;
                else if (addr == VAULT_ADDRESS)        vault   += v;
                else if (addr == ENDORSEMENT_POOL_ADDRESS) endorse += v;
                else if (!addr.empty()) { miner += v; miner_addr = addr; }
            }
            auto pct_of = [&](double amt)->int {
                return cb_total_veld > 0 ? (int)(amt / cb_total_veld * 100.0 + 0.5) : 0;
            };
            int pm = pct_of(miner), pc = pct_of(comine), pv = pct_of(vault), pe = pct_of(endorse);
            std::string split_str;
            for (int x : {pm, pc, pv, pe}) if (x > 0) {
                if (!split_str.empty()) split_str += " / ";
                split_str += std::to_string(x);
            }
            c << "<div class=\"card\"><div class=\"card-title\">Coinbase &middot; " << split_str << " split</div>";
            c << "<div style=\"display:flex;align-items:center;justify-content:space-between;padding:6px 0 14px;border-bottom:1px solid var(--b1);margin-bottom:14px\">"
              << "<span style=\"font-size:11.5px;letter-spacing:1.4px;color:var(--muted2);text-transform:uppercase\">Total coinbase output</span>"
              << "<span style=\"font-family:var(--font);font-size:22px;font-weight:700;color:var(--text);font-variant-numeric:tabular-nums\">"
              << std::fixed << std::setprecision(4) << cb_total_veld << " VELD</span></div>";
            c << "<div style=\"display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:10px;max-width:100%;box-sizing:border-box\">";
            auto split_box = [&](const std::string& name, int pct, double amt, const std::string& color, const std::string& color_bg, const std::string& addr){
                if (amt <= 0) return;  // hide slices not paid in THIS block (pool/endorsement pre-activation)
                std::string short_addr = addr.size() > 14 ? addr.substr(0,8) + "&hellip;" + addr.substr(addr.size()-3) : addr;
                c << "<div style=\"background:" << color_bg << ";border:1px solid " << color << ";border-left:3px solid " << color << ";border-radius:8px;padding:12px 14px;box-sizing:border-box;min-width:0;overflow-wrap:anywhere\">"
                  << "<div style=\"font-size:10.5px;font-weight:700;letter-spacing:1.2px;color:var(--text);opacity:.78;text-transform:uppercase;margin-bottom:6px\">" << name << " &middot; " << pct << "%</div>"
                  << "<div style=\"font-family:var(--font);font-size:19px;font-weight:700;color:var(--text);font-variant-numeric:tabular-nums\">"
                  << std::fixed << std::setprecision(4) << amt << "</div>"
                  << "<div style=\"font-family:var(--font);font-size:10.5px;color:var(--muted2);margin-top:4px\">&rarr; " << short_addr << "</div>"
                  << "</div>";
            };
            split_box("Miner",       pm, miner,   "#32F06E", "rgba(50,240,110,.06)",  miner_addr);
            split_box("Co-mining",   pc, comine,  "#4CB8FF", "rgba(76,184,255,.06)",  comine_addr);
            split_box("Vault",       pv, vault,   "#FFD84A", "rgba(255,216,74,.06)",  vault_addr);
            split_box("Endorsement", pe, endorse, "#B07CFF", "rgba(176,124,255,.06)", endorse_addr);
            c << "</div></div>";
        }

        c << "<div class=\"card\"><div class=\"card-title\">Transactions</div>";
        std::unordered_map<std::string, const Transaction*> prev_tx_index;
        std::vector<Block> prev_blocks;
        uint64_t scan_start = block->height > 150 ? block->height - 150 : 0;
        for (uint64_t h = scan_start; h <= block->height; ++h) {
            try { prev_blocks.push_back(chain_.GetBlock(h)); } catch (...) { break; }
        }
        for (const auto& pb : prev_blocks)
            for (const auto& ptx : pb.transactions)
                prev_tx_index[HashToHex(ptx.GetTxID())] = &ptx;
        c << "<div class=\"tbl-scroll\"><table class=\"tbl\"><thead><tr><th>TXID</th><th>Type</th><th>Flow</th><th>Total</th><th>Fee</th></tr></thead><tbody>";
        for (const auto& tx : block->transactions) {
            std::string txid = HashToHex(tx.GetTxID());
            bool is_cb = tx.IsCoinbase();

            std::string tx_type = is_cb ? "COINBASE" : "TRANSFER";
            std::string tx_type_color = is_cb ? "var(--em)" : "var(--muted)";
            std::string tx_type_bg = is_cb ? "rgba(50,240,110,.08)" : "rgba(255,255,255,.04)";
            std::string tx_type_border = is_cb ? "rgba(50,240,110,.2)" : "var(--border)";

            std::string op_data;
            for (const auto& out : tx.outputs) {
                auto& sp = out.script_pubkey;
                if (!sp.empty() && sp[0] == 0x6A && sp.size() > 2) {
                    size_t di = 1; size_t dlen = 0;
                                    if (sp[di] <= 75) { dlen = sp[di++]; }
                                    else if (sp[di] == 0x4C && di + 1 < sp.size()) { di++; dlen = sp[di++]; }
                                    else if (sp[di] == 0x4D && di + 2 < sp.size()) { di++; dlen = sp[di] | (sp[di+1]<<8); di+=2; }
                    if (di + dlen <= sp.size())
                        op_data = std::string(sp.begin()+di, sp.begin()+di+dlen);
                    break;
                }
            }

            std::string sender_addr;
            // A normal user transfer is SIGNED (inputs[0] carries an ML-DSA sig
            // + pubkey). The protocol reward flushes (co-mine pool / vault /
            // endorsement) are SIGLESS — POOL_ADDRESS et al. are not signing
            // keys. Track signed-ness so the sigless-only heuristics below
            // (e.g. the >10-input co-mine fallback) can never mislabel a signed
            // user send that merely aggregated many UTXOs.
            bool tx_is_signed = false;
            if (!is_cb && !tx.inputs.empty()) {
                const auto& ss = tx.inputs[0].script_sig;
                std::vector<uint8_t> sig_tmp;
                std::array<uint8_t,1952> pk;
                if (!ss.empty()
                    && veld::pqc::ParseScriptSig(ss, sig_tmp, pk)) {
                    tx_is_signed = true;
                    Hash160 pkh = Hash160Compute(pk);
                    std::vector<uint8_t> sscript = {0x76,0xA9,0x14};
                    sscript.insert(sscript.end(), pkh.begin(), pkh.end());
                    sscript.push_back(0x88); sscript.push_back(0xAC);
                    sender_addr = ScriptToAddress(sscript);
                } else {
                    for (const auto& inp : tx.inputs) {
                        auto it = prev_tx_index.find(HashToHex(inp.prev_tx_hash));
                        if (it == prev_tx_index.end()) continue;
                        const Transaction* ptx = it->second;
                        if (inp.prev_out_index >= ptx->outputs.size()) continue;
                        sender_addr = ScriptToAddress(ptx->outputs[inp.prev_out_index].script_pubkey);
                        if (!sender_addr.empty()) break;
                    }
                }
            }

            bool is_nms_tx = (op_data.size() >= NMS_MAGIC_LEN
                              && std::memcmp(op_data.data(), NMS_MAGIC, NMS_MAGIC_LEN) == 0);

            if (is_nms_tx) {
                tx_type = "NEAR-MISS"; tx_type_color = "#4CB8FF";
                tx_type_bg = "rgba(76,184,255,.06)"; tx_type_border = "rgba(76,184,255,.2)";
            } else if (!op_data.empty()) {
                if (op_data.find("VELD_DIST|STAKING") != std::string::npos && sender_addr == VAULT_ADDRESS) {
                    tx_type = "STAKING DIST"; tx_type_color = "#FFD84A";
                    tx_type_bg = "rgba(255,216,74,.06)"; tx_type_border = "rgba(255,216,74,.2)";
                } else if (op_data.find("VELD_DIST|ENDORSEMENT") != std::string::npos && sender_addr == VAULT_ADDRESS) {
                    tx_type = "ENDORSE REWARD"; tx_type_color = "#FFD84A";
                    tx_type_bg = "rgba(255,216,74,.06)"; tx_type_border = "rgba(255,216,74,.2)";
                } else if (op_data.find("VELD_VALIDATOR|ENDORSE") != std::string::npos) {
                    tx_type = "ENDORSEMENT"; tx_type_color = "#888";
                    tx_type_bg = "rgba(136,136,136,.08)"; tx_type_border = "rgba(136,136,136,.2)";
                } else if (op_data.find("VELD_STAKE|LOCK") != std::string::npos) {
                    tx_type = "STAKE"; tx_type_color = "#B07CFF";
                    tx_type_bg = "rgba(176,124,255,.08)"; tx_type_border = "rgba(176,124,255,.2)";
                } else if (op_data.find("VELD_STAKE|UNLOCK") != std::string::npos) {
                    tx_type = "UNSTAKE"; tx_type_color = "#B07CFF";
                    tx_type_bg = "rgba(176,124,255,.08)"; tx_type_border = "rgba(176,124,255,.2)";
                } else if (op_data.find("VELD_VALIDATOR|REGISTER") != std::string::npos) {
                    tx_type = "VALIDATOR REG"; tx_type_color = "#FFD84A";
                    tx_type_bg = "rgba(255,216,74,.08)"; tx_type_border = "rgba(255,216,74,.2)";
                } else if (op_data.find("VELD_VALIDATOR|DEREGISTER") != std::string::npos) {
                    tx_type = "VALIDATOR DEREG"; tx_type_color = "#FFD84A";
                    tx_type_bg = "rgba(255,216,74,.08)"; tx_type_border = "rgba(255,216,74,.2)";
                } else if (op_data.find("VELD_VALIDATOR|SLASH|") != std::string::npos) {
                    tx_type = "SLASH EVIDENCE"; tx_type_color = "#FF6B6B";
                    tx_type_bg = "rgba(255,107,107,.08)"; tx_type_border = "rgba(255,107,107,.25)";
                } else if (op_data.find("VELD_DIST|COMINE") != std::string::npos) {
                    tx_type = "CO-MINE PAYOUT"; tx_type_color = "#4CB8FF";
                    tx_type_bg = "rgba(76,184,255,.08)"; tx_type_border = "rgba(76,184,255,.2)";
                } else if (op_data.rfind("VELD_GOV|", 0) == 0) {
                    tx_type = "GOVERNANCE"; tx_type_color = "#4CB8FF";
                    tx_type_bg = "rgba(76,184,255,.06)"; tx_type_border = "rgba(76,184,255,.2)";
                } else if (op_data.rfind("VELD_AMM|", 0) == 0) {
                    std::string amm_act = op_data.substr(9);
                    if      (amm_act.rfind("SWAP_V2B", 0) == 0) tx_type = "POOL SWAP: VELD-BTCVELD";
                    else if (amm_act.rfind("SWAP_B2V", 0) == 0) tx_type = "POOL SWAP: BTCVELD-VELD";
                    else if (amm_act.rfind("ADD",      0) == 0) tx_type = "POOL LIQUIDITY ADD";
                    else if (amm_act.rfind("REMOVE",   0) == 0) tx_type = "POOL LIQUIDITY REMOVE";
                    else                                        tx_type = "POOL OPERATION";
                    tx_type_color = "#F7931A";
                    tx_type_bg = "rgba(247,147,26,.08)"; tx_type_border = "rgba(247,147,26,.25)";
                } else if (op_data.rfind("VELD_TOKEN|", 0) == 0) {
                    char tk = op_data.size() > 11 ? op_data[11] : '?';
                    tx_type = (tk == 'M') ? "BTCVELD MINT"
                            : (tk == 'R') ? "BTCVELD REDEEM"
                            : (tk == 'T') ? "BTCVELD TRANSFER" : "BTCVELD OP";
                    tx_type_color = "#F7931A";
                    tx_type_bg = "rgba(247,147,26,.08)"; tx_type_border = "rgba(247,147,26,.25)";
                } else if (op_data.rfind("VELD_MSPV|", 0) == 0) {
                    tx_type = "BTCVELD SPV MINT"; tx_type_color = "#F7931A";
                    tx_type_bg = "rgba(247,147,26,.08)"; tx_type_border = "rgba(247,147,26,.25)";
                } else if (op_data.rfind("VELD_ANCHOR|", 0) == 0) {
                    tx_type = "BTC ANCHOR"; tx_type_color = "#F7931A";
                    tx_type_bg = "rgba(247,147,26,.08)"; tx_type_border = "rgba(247,147,26,.25)";
                } else if (op_data.rfind("VELD_BHDR|", 0) == 0) {
                    tx_type = "BTC HEADER RELAY"; tx_type_color = "#F7931A";
                    tx_type_bg = "rgba(247,147,26,.08)"; tx_type_border = "rgba(247,147,26,.25)";
                } else if (op_data.rfind("VELD_FRAUD|", 0) == 0) {
                    tx_type = "FRAUD PROOF"; tx_type_color = "#FF6B6B";
                    tx_type_bg = "rgba(255,107,107,.08)"; tx_type_border = "rgba(255,107,107,.25)";
                }
            } else if (!is_cb && sender_addr == VAULT_ADDRESS) {
                tx_type = "STAKING REWARDS"; tx_type_color = "var(--gold)";
                tx_type_bg = "rgba(255,216,74,.06)"; tx_type_border = "rgba(255,216,74,.2)";
            } else if (!is_cb && sender_addr == POOL_ADDRESS) {
                tx_type = "CO-MINE PAYOUT"; tx_type_color = "#4CB8FF";
                tx_type_bg = "rgba(76,184,255,.08)"; tx_type_border = "rgba(76,184,255,.2)";
            } else if (!is_cb && sender_addr == ENDORSEMENT_POOL_ADDRESS) {
                tx_type = "VALIDATOR PAYOUT"; tx_type_color = "#B07CFF";
                tx_type_bg = "rgba(176,124,255,.08)"; tx_type_border = "rgba(176,124,255,.2)";
            } else if (!is_cb && !tx_is_signed && tx.inputs.size() > 10) {
                // SIGLESS multi-input flush only — a signed user send with many
                // aggregated UTXOs is a TRANSFER, never a co-mine payout.
                tx_type = "CO-MINE PAYOUT"; tx_type_color = "#4CB8FF";
                tx_type_bg = "rgba(76,184,255,.08)"; tx_type_border = "rgba(76,184,255,.2)";
            }

            // ── Smart-Payment (covenant) detection ─────────────────────────────
            // Covenant txs carry no OP_RETURN tag and aren't sigless protocol
            // flushes, so without this they fall through to a plain TRANSFER. A
            // covenant SPEND reveals its redeemScript as the last data push of the
            // scriptSig; a covenant LOCK pays to a P2SH output. We walk the script
            // OPCODES (skipping data pushes — a 1952-byte ML-DSA key can hold any
            // byte) so keys can never false-match an opcode.
            if (tx_type == "TRANSFER" && !is_cb) {
                auto last_push = [](const std::vector<uint8_t>& ss) -> std::vector<uint8_t> {
                    size_t i = 0; std::vector<uint8_t> last;
                    while (i < ss.size()) {
                        uint8_t op = ss[i++]; size_t len = 0; bool push = true;
                        if (op >= 0x01 && op <= 0x4B) len = op;
                        else if (op == 0x4C && i < ss.size()) len = ss[i++];
                        else if (op == 0x4D && i + 1 < ss.size()) { len = (size_t)ss[i] | ((size_t)ss[i+1] << 8); i += 2; }
                        else if (op == 0x4E && i + 3 < ss.size()) { len = (size_t)ss[i] | ((size_t)ss[i+1] << 8) | ((size_t)ss[i+2] << 16) | ((size_t)ss[i+3] << 24); i += 4; }
                        else push = false;
                        if (!push) continue;
                        if (i + len <= ss.size()) { last.assign(ss.begin() + i, ss.begin() + i + len); i += len; }
                        else break;
                    }
                    return last;
                };
                // -2 = hashlocked HTLC (OP_SHA256); n = OP_<n> OP_CHECKMULTISIG; -3 = other covenant.
                auto redeem_kind = [](const std::vector<uint8_t>& r) -> int {
                    size_t i = 0; uint8_t prev = 0; bool sha = false, cms = false; int n = -1;
                    while (i < r.size()) {
                        uint8_t op = r[i++];
                        if (op >= 0x01 && op <= 0x4B) { i += op; prev = 0; }
                        else if (op == 0x4C && i < r.size()) { i += 1 + (size_t)r[i]; prev = 0; }
                        else if (op == 0x4D && i + 1 < r.size()) { i += 2 + ((size_t)r[i] | ((size_t)r[i+1] << 8)); prev = 0; }
                        else if (op == 0x4E && i + 3 < r.size()) { i += 4 + ((size_t)r[i] | ((size_t)r[i+1] << 8) | ((size_t)r[i+2] << 16) | ((size_t)r[i+3] << 24)); prev = 0; }
                        else { if (op == 0xA8) sha = true; if (op == 0xAE) { cms = true; if (prev >= 0x51 && prev <= 0x60) n = prev - 0x50; } prev = op; }
                    }
                    if (sha) return -2;
                    if (cms) return n;
                    return -3;
                };
                if (!tx_is_signed && !tx.inputs.empty()) {
                    std::vector<uint8_t> redeem = last_push(tx.inputs[0].script_sig);
                    if (redeem.size() > 30) {
                        int k = redeem_kind(redeem);
                        if (k == -2) {
                            tx_type = "ATOMIC SWAP"; tx_type_color = "#2DD4BF";
                            tx_type_bg = "rgba(45,212,191,.08)"; tx_type_border = "rgba(45,212,191,.25)";
                        } else if (k == 2) {
                            tx_type = "COVENANT SPEND"; tx_type_color = "#818CF8";
                            tx_type_bg = "rgba(129,140,248,.08)"; tx_type_border = "rgba(129,140,248,.25)";
                        } else if (k >= 3) {
                            tx_type = "ESCROW"; tx_type_color = "#FBBF24";
                            tx_type_bg = "rgba(251,191,36,.08)"; tx_type_border = "rgba(251,191,36,.25)";
                        }
                    }
                }
                if (tx_type == "TRANSFER") {
                    for (const auto& o : tx.outputs) {
                        const auto& s = o.script_pubkey;
                        if (s.size() == 23 && s[0] == 0xA9 && s[1] == 0x14 && s[22] == 0x87) {
                            tx_type = "COVENANT FUND"; tx_type_color = "#5EEAD4";
                            tx_type_bg = "rgba(94,234,212,.07)"; tx_type_border = "rgba(94,234,212,.22)";
                            break;
                        }
                    }
                }
            }

            std::string flow_html = "<div style=\"display:flex;flex-direction:column;gap:4px\">";

            if (tx_type == "ENDORSEMENT") {
                std::string val_addr = sender_addr;
                if (val_addr.empty()) {
                    val_addr = ScriptToAddress(block->transactions[0].outputs[0].script_pubkey);
                }
                flow_html += "<div style=\"font-size:10px;color:var(--muted)\">"
                    "Endorsed by <a href=\"/address/" + val_addr + "\" class=\"addr\" style=\"color:var(--muted);font-size:10px\">" + val_addr.substr(0,14) + "...</a>"
                    "</div>";
            } else if (is_cb) {
                uint64_t cb_sum = 0;
                for (const auto& out : tx.outputs) cb_sum += out.value;
                for (const auto& out : tx.outputs) {
                    std::string addr = ScriptToAddress(out.script_pubkey);
                    bool iv = (addr == VAULT_ADDRESS);
                    bool ip = (addr == POOL_ADDRESS);
                    bool iep = (addr == ENDORSEMENT_POOL_ADDRESS);
                    // Percentage derived from THIS block's actual outputs: reads
                    // 50/50 (miner/vault) pre-staking-activation and flips to
                    // 50/20/20/10 automatically once the pool + endorsement
                    // slices begin paying. No hardcoded era assumption.
                    int opct = cb_sum > 0 ? (int)((double)out.value / (double)cb_sum * 100.0 + 0.5) : 0;
                    std::string role;
                    std::string col;
                    if (iv) { role = "Vault (" + std::to_string(opct) + "%)"; col = "var(--gold)"; }
                    else if (ip) { role = "Co-Mine Pool (" + std::to_string(opct) + "%)"; col = "#4CB8FF"; }
                    else if (iep) { role = "Validator Pool (" + std::to_string(opct) + "%)"; col = "#B07CFF"; }
                    else { role = "Miner (" + std::to_string(opct) + "%)"; col = "var(--em)"; }
                    if (iv && block->height % VAULT_BLOCK_INTERVAL == 0 && tx.outputs.size() == 1)
                        role = "Vault (100% \xe2\x80\x94 vault block)";
                    std::ostringstream val; val << std::fixed << std::setprecision(2) << (double)out.value/VELD_UNITS;
                    flow_html += "<div style=\"display:flex;gap:6px;align-items:baseline;font-size:10px\">"
                        "<span style=\"color:" + col + ";min-width:120px\">" + role + "</span>"
                        "<span style=\"color:var(--gold);font-family:'JetBrains Mono',monospace\">" + val.str() + "</span>"
                        " <a href=\"/address/" + addr + "\" class=\"addr\" style=\"color:var(--muted);font-size:9px\">" + addr.substr(0,10) + "...</a>"
                        "</div>";
                }
            } else if (tx_type == "CO-MINE PAYOUT" || tx_type == "VALIDATOR PAYOUT") {
                std::string pcolor = (tx_type == "VALIDATOR PAYOUT") ? "#B07CFF" : "#4CB8FF";
                std::string plabel = (tx_type == "VALIDATOR PAYOUT") ? "validator pool" : "pool";
                flow_html += "<div style=\"font-size:10px;color:" + pcolor + ";margin-bottom:2px\">"
                    + std::to_string(tx.inputs.size()) + " " + plabel + " UTXOs \xe2\x86\x92</div>";
                for (const auto& out : tx.outputs) {
                    std::string addr = ScriptToAddress(out.script_pubkey);
                    if (addr.empty()) continue;
                    std::ostringstream val; val << std::fixed << std::setprecision(2) << (double)out.value/VELD_UNITS;
                    flow_html += "<div style=\"display:flex;gap:6px;align-items:baseline;font-size:10px\">"
                        "<a href=\"/address/" + addr + "\" class=\"addr\" style=\"color:var(--em);font-size:10px\">" + addr.substr(0,14) + "...</a>"
                        " <span style=\"color:var(--gold);font-family:'JetBrains Mono',monospace\">" + val.str() + " VELD</span></div>";
                }
            } else if (tx_type == "STAKING REWARDS" || tx_type == "STAKING DIST" || tx_type == "ENDORSE REWARD") {
                std::string dist_color = (tx_type == "ENDORSE REWARD") ? "#FFD84A" : "var(--gold)";
                std::string dist_label = (tx_type == "ENDORSE REWARD") ? "Vault \xe2\x86\x92 Validators" : "Vault \xe2\x86\x92 Stakers";
                flow_html += "<div style=\"font-size:10px;color:" + dist_color + ";margin-bottom:2px\">" + dist_label + "</div>";
                for (const auto& out : tx.outputs) {
                    std::string addr = ScriptToAddress(out.script_pubkey);
                    if (addr.empty()) continue;
                    if (addr == VAULT_ADDRESS) continue;
                    std::ostringstream val; val << std::fixed << std::setprecision(2) << (double)out.value/VELD_UNITS;
                    flow_html += "<div style=\"display:flex;gap:6px;align-items:baseline;font-size:10px\">"
                        "<a href=\"/address/" + addr + "\" class=\"addr\" style=\"color:" + dist_color + ";font-size:10px\">" + addr.substr(0,14) + "...</a>"
                        " <span style=\"color:" + dist_color + ";font-family:'JetBrains Mono',monospace\">" + val.str() + " VELD</span></div>";
                }
            } else {
                for (const auto& out : tx.outputs) {
                    std::string addr = ScriptToAddress(out.script_pubkey);
                    if (addr.empty()) {
                        // OP_RETURN. If it's a plain user memo (not a VELD_*
                        // system op or NMS submission) with no control bytes,
                        // show it as readable text — HTML-escaped, since a memo
                        // is attacker-controlled (stored-XSS guard).
                        bool sys = (op_data.rfind("VELD_", 0) == 0) ||
                                   (op_data.size() >= NMS_MAGIC_LEN &&
                                    std::memcmp(op_data.data(), NMS_MAGIC, NMS_MAGIC_LEN) == 0);
                        bool ctrl = false;
                        for (unsigned char c : op_data) { if (c < 0x20) { ctrl = true; break; } }
                        if (!op_data.empty() && !sys && !ctrl) {
                            flow_html += "<div style=\"font-size:9px;color:var(--muted)\">Memo: "
                                "<span style=\"color:var(--em)\">"
                                + HttpResponse::EscapeHtml(op_data) + "</span></div>";
                        } else if (op_data.rfind("VELD_TOKEN|", 0) == 0) {
                            // btcVELD token op — surface the amount that actually moved
                            // (field 5: VELD_TOKEN|ACTION|token|from|to|AMOUNT|memo) so a
                            // mint/redeem/transfer shows how much btcVELD, not a bare OP_RETURN.
                            char tk = op_data.size() > 11 ? op_data[11] : '?';
                            const char* verb = (tk=='M') ? "Minted" : (tk=='R') ? "Redeemed"
                                             : (tk=='T') ? "Transferred" : "btcVELD op";
                            std::string amt; size_t st = 0; int fld = 0;
                            for (size_t i = 0; i <= op_data.size(); ++i) {
                                if (i == op_data.size() || op_data[i] == '|') {
                                    if (fld == 5) { amt = op_data.substr(st, i - st); break; }
                                    ++fld; st = i + 1;
                                }
                            }
                            bool alldig = !amt.empty() && amt.find_first_not_of("0123456789") == std::string::npos;
                            long long sats = 0; if (alldig) { try { sats = std::stoll(amt); } catch (...) { sats = 0; } }
                            if (sats > 0) {
                                std::ostringstream bv; bv << std::fixed << std::setprecision(8) << (double)sats / 1e8;
                                flow_html += "<div style=\"font-size:10px;color:var(--gold);font-family:'JetBrains Mono',monospace\">"
                                    + std::string(verb) + " " + bv.str() + " btcVELD</div>";
                            } else {
                                flow_html += "<div style=\"font-size:9px;color:var(--muted)\">OP_RETURN</div>";
                            }
                        } else {
                            flow_html += "<div style=\"font-size:9px;color:var(--muted)\">OP_RETURN</div>";
                        }
                        continue;
                    }
                    bool iv = (addr == VAULT_ADDRESS), ip = (addr == POOL_ADDRESS);
                    std::string col = iv ? "var(--gold)" : ip ? "#4CB8FF" : "var(--em)";
                    std::ostringstream val; val << std::fixed << std::setprecision(2) << (double)out.value/VELD_UNITS;
                    flow_html += "<div style=\"display:flex;gap:6px;align-items:baseline;font-size:10px\">"
                        "<a href=\"/address/" + addr + "\" class=\"addr\" style=\"color:" + col + ";font-size:10px\">" + addr.substr(0,14) + "...</a>"
                        " <span style=\"color:var(--gold);font-family:'JetBrains Mono',monospace\">" + val.str() + " VELD</span>";
                    if (iv) flow_html += " <span style=\"font-size:8px;color:var(--gold)\">VAULT</span>";
                    if (ip) flow_html += " <span style=\"font-size:8px;color:#4CB8FF\">POOL</span>";
                    flow_html += "</div>";
                }
                if (!sender_addr.empty()) {
                    flow_html = "<div style=\"font-size:9px;color:var(--muted);margin-bottom:3px\">From: "
                        "<a href=\"/address/" + sender_addr + "\" class=\"addr\" style=\"color:var(--muted);font-size:9px\">" + sender_addr.substr(0,14) + "...</a></div>" + flow_html;
                }
            }
            flow_html += "</div>";

            std::ostringstream total_val;
            std::string total_color = "var(--gold)";
            if (tx_type == "ENDORSEMENT") {
                total_val << "—";
                total_color = "var(--muted)";
            } else if (tx_type == "STAKING REWARDS" || tx_type == "STAKING DIST"
                    || tx_type == "ENDORSE REWARD") {
                uint64_t recipient_units = 0;
                for (const auto& out : tx.outputs) {
                    std::string oaddr = ScriptToAddress(out.script_pubkey);
                    if (oaddr.empty()) continue;
                    if (oaddr == VAULT_ADDRESS
                     || oaddr == POOL_ADDRESS
                     || oaddr == ENDORSEMENT_POOL_ADDRESS) continue;
                    recipient_units += out.value;
                }
                total_val << std::fixed << std::setprecision(2)
                          << (double)recipient_units / VELD_UNITS;
            } else if (tx_type == "STAKE" || tx_type == "UNSTAKE") {
                total_color = "#B07CFF";
                double stake_amt = 0;
                auto p1 = op_data.find('|');
                if (p1 != std::string::npos) {
                    auto p2 = op_data.find('|', p1+1);
                    if (p2 != std::string::npos) {
                        auto p3 = op_data.find('|', p2+1);
                        if (p3 != std::string::npos) {
                            auto p4 = op_data.find('|', p3+1);
                            std::string amt_str = (p4 != std::string::npos) ? op_data.substr(p3+1, p4-p3-1) : op_data.substr(p3+1);
                            try { stake_amt = (double)std::stoull(amt_str) / VELD_UNITS; } catch (...) {}
                        }
                    }
                }
                if (stake_amt > 0) {
                    total_val << std::fixed << std::setprecision(2) << stake_amt;
                } else {
                    total_val << std::fixed << std::setprecision(2) << (double)tx.TotalOutput()/VELD_UNITS;
                }
            } else {
                total_val << std::fixed << std::setprecision(2) << (double)tx.TotalOutput()/VELD_UNITS;
            }

            std::string fee_cell = "<td style=\"color:var(--muted);font-size:11px\">—</td>";
            if (!is_cb) {
                uint64_t in_total = 0, out_total = tx.TotalOutput();
                bool all_resolved = true;
                for (const auto& in : tx.inputs) {
                    auto it = prev_tx_index.find(HashToHex(in.prev_tx_hash));
                    if (it != prev_tx_index.end() && in.prev_out_index < it->second->outputs.size()) {
                        in_total += it->second->outputs[in.prev_out_index].value;
                    } else {
                        all_resolved = false;
                        break;
                    }
                }
                if (all_resolved && in_total >= out_total) {
                    uint64_t fee_units = in_total - out_total;
                    if (fee_units == 0) {
                        fee_cell = "<td style=\"color:var(--muted);font-size:11px\">—</td>";
                    } else {
                        std::ostringstream fv;
                        fv << std::fixed << std::setprecision(3) << (double)fee_units / VELD_UNITS;
                        fee_cell = "<td style=\"color:var(--red,#ff5c5c);white-space:nowrap;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600\" title=\"Network fee paid to the block miner\">-" + fv.str() + "</td>";
                    }
                }
            }

            c << "<tr>"
              << "<td><a href=\"/tx/" << txid << "\" class=\"hash\">" << txid.substr(0,12) << "..." << txid.substr(56) << "</a></td>"
              << "<td><span class=\"badge\" style=\"font-size:8px;color:" << tx_type_color
              << ";background:" << tx_type_bg << ";border:1px solid " << tx_type_border << "\">"
              << tx_type << "</span></td>"
              << "<td>" << flow_html << "</td>"
              << "<td style=\"color:" << total_color << ";white-space:nowrap;font-family:'JetBrains Mono',monospace;font-size:11px\">" << total_val.str() << "</td>"
              << fee_cell
              << "</tr>";
        }
        c << "</tbody></table></div>";

        {
            const char* nb   = "display:inline-flex;align-items:center;gap:10px;text-decoration:none;padding:11px 18px;border:1px solid var(--b2);border-radius:12px;background:var(--s2);color:var(--text);font-family:var(--sans)";
            const char* nArr = "font-size:20px;font-weight:700;line-height:1;color:var(--em);flex-shrink:0";
            const char* nTxt = "display:flex;flex-direction:column;gap:2px;line-height:1.15";
            const char* nCap = "font-size:9.5px;letter-spacing:1.3px;text-transform:uppercase;font-weight:700;color:var(--muted)";
            const char* nH   = "font-size:14px;font-weight:700;color:var(--text)";
            c << "<div style=\"display:flex;justify-content:space-between;gap:12px;margin-top:18px\">";
            if (block->height > 0)
                c << "<a href=\"/block/height/" << (block->height-1) << "\" style=\"" << nb << "\">"
                  << "<span style=\"" << nArr << "\">&larr;</span>"
                  << "<span style=\"" << nTxt << "\"><span style=\"" << nCap << "\">Previous block</span>"
                  << "<span style=\"" << nH << "\">#" << (block->height-1) << "</span></span></a>";
            else c << "<span></span>";
            c << "<a href=\"/block/height/" << (block->height+1) << "\" style=\"" << nb << "\">"
              << "<span style=\"" << nTxt << ";text-align:right\"><span style=\"" << nCap << "\">Next block</span>"
              << "<span style=\"" << nH << "\">#" << (block->height+1) << "</span></span>"
              << "<span style=\"" << nArr << "\">&rarr;</span></a>";
            c << "</div>";
        }

        return HttpResponse::HTML(HtmlWrapArcade("Block " + std::to_string(block->height), c.str(), "blocks"));
    }

    HttpResponse ServeBlockByHeight(uint64_t height) {
        try {
            Block block = chain_.GetBlock(height);
            return ServeBlock(HashToHex(block.GetHash()));
        } catch (...) {
            return HttpResponse::NotFound("block at height " + std::to_string(height));
        }
    }

    static bool IsStrictLowerHex64(const std::string& s) {
        if (s.size() != 64) return false;
        for (char c : s) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    HttpResponse ServeTx(const std::string& txid_hex) {
        if (!IsStrictLowerHex64(txid_hex)) {
            std::ostringstream err;
            err << "<div class=\"container\" style=\"padding:40px;text-align:center\">"
                << "<h1 style=\"font-size:20px;color:var(--em);margin-bottom:12px\">Invalid Transaction ID</h1>"
                << "<p style=\"color:var(--muted);font-size:13px\">A Veld transaction ID is 64 hexadecimal characters.</p>"
                << "</div>";
            return HttpResponse::HTML(HtmlWrapArcade("Invalid Transaction", err.str(), ""));
        }
        uint64_t tip = chain_.Height();
        uint64_t scan_from = tip > 500 ? tip - 500 : 0;
        for (uint64_t h = tip; h >= scan_from; --h) {
            try {
                Block blk = chain_.GetBlock(h);
                for (const auto& tx : blk.transactions) {
                    if (HashToHex(tx.GetTxID()) == txid_hex) {
                        HttpResponse r;
                        r.status_code = 302;
                        r.status_text = "Found";
                        r.headers["Location"] = "/block/height/" + std::to_string(h);
                        r.body = "";
                        r.content_type = "text/html";
                        return r;
                    }
                }
            } catch (...) {}
            if (h == 0) break;
        }
        std::ostringstream content;
        content << "<div class=\"card\"><div class=\"card-title\">Transaction</div>";
        content << "<div class=\"hash\" style=\"word-break:break-all;margin-bottom:16px;font-size:11px;color:var(--em)\">" << txid_hex << "</div>";
        content << "<p style=\"color:var(--muted);font-size:12px\">Transaction not found in the last 500 blocks. It may be older or not yet confirmed.</p></div>";
        // An unconfirmed transaction is reached from the mempool list. Keep the
        // mempool tab active so the persistent mobile shell does not visually
        // reset while the detail route loads. Confirmed transactions redirect
        // to their block page above, where the Blocks tab is active.
        return HttpResponse::HTML(HtmlWrapArcade("Transaction", content.str(), "mempool"));
    }

    static bool IsStrictBase58Address(const std::string& s) {
        if (s.size() < 25 || s.size() > 48) return false;
        if (s[0] != 'V') return false;
        for (char c : s) {
            if (!( (c >= '1' && c <= '9') ||
                   (c >= 'A' && c <= 'H') ||
                   (c >= 'J' && c <= 'N') ||
                   (c >= 'P' && c <= 'Z') ||
                   (c >= 'a' && c <= 'k') ||
                   (c >= 'm' && c <= 'z') )) return false;
        }
        return true;
    }

    HttpResponse ServeAddress(const std::string& address) {
        if (!IsStrictBase58Address(address)) {
            std::ostringstream err;
            err << "<div class=\"container\" style=\"padding:40px;text-align:center\">"
                << "<h1 style=\"font-size:20px;color:var(--em);margin-bottom:12px\">Invalid Address</h1>"
                << "<p style=\"color:var(--muted);font-size:13px\">The requested address is not a valid Veld address.</p>"
                << "</div>";
            return HttpResponse::HTML(HtmlWrapArcade("Invalid Address", err.str(), ""));
        }
        struct AddrCacheEntry {
            std::string body;
            std::chrono::steady_clock::time_point expires_at;
        };
        static std::mutex addr_cache_mu;
        static std::unordered_map<std::string, AddrCacheEntry> addr_cache;
        {
            std::lock_guard<std::mutex> lk(addr_cache_mu);
            auto it = addr_cache.find(address);
            if (it != addr_cache.end()
                && std::chrono::steady_clock::now() < it->second.expires_at) {
                return HttpResponse::HTML(it->second.body);
            }
        }
        double balance = 0.0;
        std::vector<UTXO> utxos_list;
        {
            auto script = AddressToScript(address);
            if (!script.empty()) {
                utxos_list = chain_.GetUTXOsForScript(script);
                for (auto& u : utxos_list) balance += (double)u.value / VELD_UNITS;
            }
        }
        uint64_t blocks_mined = 0;
        int tier = 0; double mult = 1.0;
        {
            auto script = AddressToScript(address);
            std::string script_hex;
            if (script.size() == 25) script_hex = BytesToHex(script);
            blocks_mined = chain_.GetBlocksMined(script_hex);
            if (tiers_ && !script_hex.empty()) {
                auto ti = tiers_->GetTier(script_hex);
                tier = ti.level;
                mult = ti.multiplier;
            }
        }
        bool is_vault = (address == VAULT_ADDRESS);
        bool is_pool  = (address == POOL_ADDRESS);
        bool is_endorse_pool = (address == ENDORSEMENT_POOL_ADDRESS);
        std::string tier_names[] = {"Base","Bronze","Silver","Gold","Platinum","Diamond"};
        std::ostringstream c;

        std::string header_border = is_vault ? "var(--gold)"
                                    : is_pool ? "var(--blue)"
                                    : is_endorse_pool ? "#B07CFF"
                                    : "var(--border)";
        std::string header_title  = is_vault ? "Vault Address"
                                    : is_pool ? "Co-Mining Pool Address"
                                    : is_endorse_pool ? "Validator Pool Address"
                                    : "Address";
        c << "<div class=\"card\" style=\"border-color:" << header_border << "\">";
        c << "<div style=\"display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap\">";
        c << "<div style=\"flex:1;min-width:0\">";
        c << "<div class=\"card-title\">" << header_title << "</div><div class=\"mono\" style=\"word-break:break-all;margin-bottom:12px;color:var(--gold);font-size:11px\">" << address;
        if (is_vault) c << "&nbsp;<span class=\"badge badge-active\" style=\"font-size:9px\">VAULT</span>";
        if (is_pool)  c << "&nbsp;<span class=\"badge\" style=\"font-size:9px;background:rgba(76,184,255,.08);color:#4CB8FF;border:1px solid rgba(76,184,255,.2)\">CO-MINE POOL</span>";
        if (is_endorse_pool) c << "&nbsp;<span class=\"badge\" style=\"font-size:9px;background:rgba(176,124,255,.10);color:#B07CFF;border:1px solid rgba(176,124,255,.25)\">VALIDATOR POOL</span>";
        c << "</div>";
        c << "<button data-act-click=\"e1b7713ed\" data-copy-text=\"" << address << "\" "
          << "style=\"padding:5px 12px;font-size:11px;border:1px solid var(--border);background:var(--surface2);color:var(--muted);border-radius:4px;cursor:pointer;font-family:monospace\">Copy Address</button>";
        c << "</div>";

        c << "</div>";

        c << "<div class=\"stat-grid\" style=\"margin-top:16px\">";
        c << "<div class=\"stat\"><div class=\"stat-label\">Balance</div><div class=\"stat-value gold\">" << std::fixed << std::setprecision(2) << balance << "</div><div class=\"stat-sub\">VELD</div></div>";
        c << "<div class=\"stat\"><div class=\"stat-label\">UTXOs</div><div class=\"stat-value\">" << utxos_list.size() << "</div></div>";
        c << "<div class=\"stat\"><div class=\"stat-label\">Blocks Mined</div><div class=\"stat-value em\">" << blocks_mined << "</div></div>";
        if (tier >= 5) {
            c << "<div class=\"stat\"><div class=\"stat-label\">Mining Tier</div><div class=\"stat-value\"><span class=\"diamond-prismatic\">" << tier_names[tier] << " &mdash; " << std::setprecision(2) << mult << "&times;</span></div></div>";
        } else {
            c << "<div class=\"stat\"><div class=\"stat-label\">Mining Tier</div><div class=\"stat-value tier-" << tier << "\">" << tier_names[tier] << " &mdash; " << std::setprecision(2) << mult << "&times;</div></div>";
        }
        c << "<div class=\"stat\"><div class=\"stat-label\">Staked</div><div class=\"stat-value\" id=\"addr-staked\">Loading...</div></div>";
        c << "</div>";
        c << "</div>";

        size_t total_utxo_count = utxos_list.size();
        if (!utxos_list.empty()) {
            std::sort(utxos_list.begin(), utxos_list.end(),
                [](const UTXO& a, const UTXO& b){ return a.value > b.value; });
            if (utxos_list.size() > 25) utxos_list.resize(25);
        }

        if (!utxos_list.empty()) {
            size_t show_count = utxos_list.size();
            c << "<div class=\"card\" style=\"padding:14px 18px\">";
            c << "<div class=\"card-header\" style=\"display:flex;align-items:baseline;justify-content:space-between;padding:6px 4px 4px\">";
            c << "<div class=\"card-title\" style=\"margin:0\">Unspent outputs</div>";
            c << "<span style=\"font-size:11px;color:var(--muted);font-weight:600\">" << total_utxo_count << " UTXOs"
              << (total_utxo_count > 25 ? " &middot; top 25 by value" : "") << "</span>";
            c << "</div>";
            c << "<div class=\"row-list\">";
            for (size_t ui = 0; ui < show_count; ++ui) {
                auto& u = utxos_list[ui];
                std::string txid = HashToHex(u.tx_hash);
                std::string source = ClassifyUTXOSource(u);
                std::string ic_class = "ic-v";
                std::string type_label = "Output";
                if      (source == "mining_reward")     { ic_class = "ic-b"; type_label = "Mining reward"; }
                else if (source == "staking_reward")    { ic_class = "ic-s"; type_label = "Staking reward"; }
                else if (source == "endorsement_reward"){ ic_class = "ic-p"; type_label = "Validator reward"; }
                else if (source == "pool_payout")       { ic_class = "ic-d"; type_label = "Co-mine payout"; }
                else if (source == "endorsement_payout"){ ic_class = "ic-p"; type_label = "Validator reward"; }
                else if (source == "vault_payout")      { ic_class = "ic-v"; type_label = "Staking rewards"; }
                else if (source == "transfer_in")       { ic_class = "ic-h"; type_label = "Transfer received"; }
                c << "<a class=\"rl-row\" href=\"/tx/" << txid << "\" style=\"text-decoration:none\">";
                c << "<div class=\"rl-ic " << ic_class << "\" style=\"font-size:11px\">"
                  << type_label.substr(0, 1) << "</div>";
                c << "<div class=\"rl-info\">";
                c << "<div class=\"rl-name\">" << type_label << "</div>";
                c << "<div class=\"rl-sub\" style=\"font-family:'JetBrains Mono',monospace;font-size:11.5px\">"
                  << txid.substr(0,12) << "&hellip;" << txid.substr(56) << " #" << u.output_index
                  << " &middot; block " << u.block_height << "</div>";
                c << "</div>";
                c << "<div class=\"rl-val\">";
                c << "<div class=\"rl-v\" style=\"color:var(--em);font-size:16px\">"
                  << std::fixed << std::setprecision(2) << (double)u.value / VELD_UNITS << "</div>";
                c << "<div class=\"rl-vs\">VELD</div>";
                c << "</div>";
                c << "</a>";
            }
            if (utxos_list.size() > 50) {
                uint64_t remaining_val = 0;
                for (size_t ui = 50; ui < utxos_list.size(); ++ui) remaining_val += utxos_list[ui].value;
                c << "<div class=\"rl-row\" style=\"color:var(--muted);justify-content:center;font-style:italic\">"
                  << "... and " << (utxos_list.size() - 50) << " more UTXOs totaling "
                  << std::fixed << std::setprecision(2) << (double)remaining_val/VELD_UNITS << " VELD</div>";
            }
            c << "</div></div>";
        }

        c << "<div class=\"card\"><div class=\"card-title\">Transaction History</div>";
        c << "<div id=\"tx-hist\"><div style=\"color:var(--muted);text-align:center;padding:24px\">Loading...</div></div>";
        c << "<script nonce=\"__CSP_NONCE__\">"
          << "function escHtml(s){var d=document.createElement('div');d.appendChild(document.createTextNode(s));return d.innerHTML;}"
          << "function fmt(n,d){return parseFloat(n||0).toFixed(d!==undefined?d:2);}"
          << "var EXP_HIST_PAGE_SIZE = 25;"
          << "window._expHist = [];"
          << "window._expHistPage = 1;"
          << "function expHistTypeMap(){return{"
          << "    coinbase:{label:'Block Reward',color:'var(--em)'},"
          << "    block_reward:{label:'Block Reward',color:'var(--em)'},"
          << "    miner_reward:{label:'Block Reward',color:'var(--em)'},"
          << "    vault_distribution:{label:'Staking Rewards',color:'#FFD84A'},"
          << "    staking_distribution:{label:'Staking Rewards',color:'#FFD84A'},"
          << "    endorsement_reward:{label:'Validator Reward',color:'#FFD84A'},"
          << "    comine_payout:{label:'Co-Mine Payout',color:'#4CB8FF'},"
          << "    endorsement:{label:'Block Endorsement',color:'#888'},"
          << "    stake_lock:{label:'Stake Lock',color:'#B07CFF'},"
          << "    stake_unlock:{label:'Stake Unlock',color:'#B07CFF'},"
          << "    validator_register:{label:'Validator Reg',color:'#FFD84A'},"
          << "    validator_deregister:{label:'Validator Dereg',color:'#FFD84A'},"
          << "    slash_evidence:{label:'Slash Evidence',color:'#FF6B6B'},"
          << "    fraud_proof:{label:'Fraud Proof',color:'#FF6B6B'},"
          << "    amm_swap_v2b:{label:'Pool Swap: VELD to btcVELD',color:'#F7931A'},"
          << "    amm_swap_b2v:{label:'Pool Swap: btcVELD to VELD',color:'#F7931A'},"
          << "    amm_add:{label:'Added Pool Liquidity',color:'#F7931A'},"
          << "    amm_remove:{label:'Removed Pool Liquidity',color:'#F7931A'},"
          << "    amm_op:{label:'Pool Operation',color:'#F7931A'},"
          << "    btcveld_mint:{label:'btcVELD Mint',color:'#F7931A'},"
          << "    btcveld_redeem:{label:'btcVELD Redeem',color:'#F7931A'},"
          << "    btcveld_transfer:{label:'btcVELD Transfer',color:'#F7931A'},"
          << "    btcveld_spv_mint:{label:'btcVELD SPV Mint',color:'#F7931A'},"
          << "    btcveld_op:{label:'btcVELD Operation',color:'#F7931A'},"
          << "    anchor_post:{label:'BTC Anchor Post',color:'#F7931A'},"
          << "    btc_header_relay:{label:'BTC Header Relay',color:'#F7931A'},"
          << "    gov_other:{label:'Governance',color:'#4CB8FF'},"
          << "    near_miss_submission:{label:'Near-miss submission',color:'#4CB8FF'},"
          << "    sent:{label:'Sent',color:'var(--red)'},"
          << "    received:{label:'Received',color:'var(--em)'}"
          << "};}"
          << "function expHistRender(){"
          << "  var d = window._expHist || [];"
          << "  var host = document.getElementById('tx-hist');"
          << "  if(!host) return;"
          << "  if(!d.length){host.innerHTML='<div style=\"color:var(--muted);text-align:center;padding:16px;font-size:11px\">No transactions found.</div>';return;}"
          << "  var totalPages = Math.max(1, Math.ceil(d.length / EXP_HIST_PAGE_SIZE));"
          << "  var page = Math.min(Math.max(1, window._expHistPage || 1), totalPages);"
          << "  window._expHistPage = page;"
          << "  var pageStart = (page - 1) * EXP_HIST_PAGE_SIZE;"
          << "  var pageEnd   = Math.min(d.length, pageStart + EXP_HIST_PAGE_SIZE);"
          << "  var pageData  = d.slice(pageStart, pageEnd);"
          << "  var typeMap = expHistTypeMap();"
          << "  var feeOnlyTypes={endorsement:1,stake_lock:1,stake_unlock:1,validator_register:1,validator_deregister:1,"
          << "    near_miss_submission:1,slash_evidence:1,fraud_proof:1,gov_other:1,"
          << "    btcveld_mint:1,btcveld_redeem:1,btcveld_transfer:1,btcveld_spv_mint:1,btcveld_op:1,anchor_post:1,btc_header_relay:1};"
          << "  var html='<div class=\"row-list\">';"
          << "  function _icForType(t){"
          << "    if(t==='sent') return 'ic-h';"
          << "    if(t==='received') return 'ic-h';"
          << "    if(t==='coinbase'||t==='block_reward'||t==='miner_reward') return 'ic-b';"
          << "    if(t==='vault_distribution'||t==='staking_distribution') return 'ic-v';"
          << "    if(t==='endorsement_reward'||t==='endorsement'||t==='validator_register') return 'ic-p';"
          << "    if(t==='comine_payout') return 'ic-d';"
          << "    if(t==='stake_lock'||t==='stake_unlock') return 'ic-s';"
          << "    return 'ic-h';"
          << "  }"
          << "  pageData.forEach(function(t){"
          << "    var pos=parseFloat(t.net_veld||0)>=0;"
          << "    var tm=typeMap[t.type]||{label:escHtml(t.type),color:pos?'var(--em)':'var(--red)'};"
          << "    var fee=parseFloat(t.fee_veld||0);"
          << "    var isFeeOnly=feeOnlyTypes[t.type];"
          << "    var amtStr=isFeeOnly?'&mdash;':(pos?'+':'')+fmt(t.net_veld,4);"
          << "    var amtColor=isFeeOnly?'var(--muted)':(pos?'var(--em)':'var(--red)');"
          << "    var feeStr=fee>0?'&minus;'+fmt(fee,4)+' fee':'';"
          << "    var ic=_icForType(t.type);"
          << "    var label=(t.type||'').substring(0,1).toUpperCase()||'T';"
          << "    html+='<a class=\"rl-row\" href=\"/tx/'+escHtml(t.txid)+'\" style=\"text-decoration:none\">'"
          << "      +'<div class=\"rl-ic '+ic+'\">'+label+'</div>'"
          << "      +'<div class=\"rl-info\">'"
          << "        +'<div class=\"rl-name\">'+tm.label+'</div>'"
          << "        +'<div class=\"rl-sub\" style=\"font-family:\\'JetBrains Mono\\',monospace;font-size:11.5px\">'"
          << "          +'block '+t.block_height+' &middot; '+escHtml(t.txid.slice(0,10))+'&hellip;'+escHtml(t.txid.slice(58))"
          << "          +(feeStr?' &middot; '+feeStr:'')"
          << "        +'</div>'"
          << "      +'</div>'"
          << "      +'<div class=\"rl-val\">'"
          << "        +'<div class=\"rl-v\" style=\"color:'+amtColor+';font-size:15px\">'+amtStr+'</div>'"
          << "        +'<div class=\"rl-vs\">VELD</div>'"
          << "      +'</div>'"
          << "      +'</a>';"
          << "  });"
          << "  html+='</div>';"
          << "  if(totalPages > 1){"
          << "    var prevDisabled = page <= 1;"
          << "    var nextDisabled = page >= totalPages;"
          << "    var btnEnabled  = 'background:none;border:1px solid var(--b1);color:var(--text);padding:6px 14px;border-radius:6px;cursor:pointer;font-family:inherit';"
          << "    var btnDisabled = 'background:none;border:1px solid var(--b1);color:var(--muted);padding:6px 14px;border-radius:6px;opacity:.4;cursor:not-allowed';"
          << "    html += '<div style=\"display:flex;justify-content:space-between;align-items:center;margin-top:14px;font-size:12px;color:var(--muted)\">'"
          << "      + '<button data-exp-page=\"prev\" ' + (prevDisabled ? 'disabled ' : '') + 'style=\"' + (prevDisabled ? btnDisabled : btnEnabled) + '\">&laquo; Prev</button>'"
          << "      + '<span>' + (pageStart + 1) + '&ndash;' + pageEnd + ' of ' + d.length + ' &middot; page ' + page + '/' + totalPages + '</span>'"
          << "      + '<button data-exp-page=\"next\" ' + (nextDisabled ? 'disabled ' : '') + 'style=\"' + (nextDisabled ? btnDisabled : btnEnabled) + '\">Next &raquo;</button>'"
          << "      + '</div>';"
          << "  }"
          << "  host.innerHTML = html;"
          << "}"
          << "document.addEventListener('click', function(e){"
          << "  var t = e.target;"
          << "  while (t && t !== document) {"
          << "    if (t.getAttribute && t.getAttribute('data-exp-page')) {"
          << "      if (t.hasAttribute('disabled')) return;"
          << "      var dir = t.getAttribute('data-exp-page');"
          << "      window._expHistPage = (window._expHistPage || 1) + (dir === 'next' ? 1 : -1);"
          << "      expHistRender();"
          << "      return;"
          << "    }"
          << "    t = t.parentNode;"
          << "  }"
          << "});"
          << "fetch('/api/v1/addresshistory/" << address << "/50',{cache:'no-store'}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.error||'History unavailable');return d;});}).then(function(d){window._expHist=Array.isArray(d.entries)?d.entries:[];window._expHistPage=1;expHistRender();}).catch(function(e){document.getElementById('tx-hist').innerHTML='<div style=\"color:var(--muted);text-align:center;padding:16px\">'+escHtml(e.message||'History unavailable')+'</div>';});"
          << "fetch('/api/v1/address/" << address << "').then(r=>r.json()).then(function(d){"
          << "  document.getElementById('addr-staked').textContent=d.staked_veld!==undefined?parseFloat(d.staked_veld).toFixed(2)+' VELD':'0.00 VELD';"
          << "}).catch(function(){document.getElementById('addr-staked').textContent='--';});"
          << "</script></div>";

        std::string body = HtmlWrapArcade("Address " + address.substr(0,8) + "...", c.str(), "");
        {
            std::lock_guard<std::mutex> lk(addr_cache_mu);
            auto now = std::chrono::steady_clock::now();
            static constexpr size_t kMaxAddressPageCacheEntries = 200;
            if (addr_cache.size() >= kMaxAddressPageCacheEntries) {
                for (auto it = addr_cache.begin(); it != addr_cache.end();) {
                    if (it->second.expires_at < now) it = addr_cache.erase(it);
                    else ++it;
                }
            }
            // An attacker can generate effectively unlimited valid Base58
            // addresses.  If all 200 entries are still live, evict the one
            // closest to expiry before inserting; the prior `> 200` check kept
            // adding forever whenever traffic arrived inside the 30s TTL.
            if (addr_cache.find(address) == addr_cache.end() &&
                addr_cache.size() >= kMaxAddressPageCacheEntries) {
                auto oldest = std::min_element(
                    addr_cache.begin(), addr_cache.end(),
                    [](const auto& a, const auto& b) {
                        return a.second.expires_at < b.second.expires_at;
                    });
                if (oldest != addr_cache.end()) addr_cache.erase(oldest);
            }
            addr_cache[address] = AddrCacheEntry{body,
                now + std::chrono::seconds(30)};
        }
        return HttpResponse::HTML(body);
    }

    HttpResponse ServeTopologySnapshot() {
        if (cache_dir_.empty())
            return HttpResponse::JSON(
                "{\"error\":\"topology unavailable\"}", 503);
        try {
            const std::filesystem::path path =
                std::filesystem::path(cache_dir_) / "topology-network.json";
            std::error_code ec;
            const uintmax_t size = std::filesystem::file_size(path, ec);
            if (ec || size == 0 || size > 256U * 1024U)
                return HttpResponse::JSON(
                    "{\"error\":\"topology unavailable\"}", 503);
            std::ifstream file(path, std::ios::binary);
            if (!file.good())
                return HttpResponse::JSON(
                    "{\"error\":\"topology unavailable\"}", 503);
            std::string body(static_cast<size_t>(size), '\0');
            file.read(body.data(), static_cast<std::streamsize>(body.size()));
            const size_t first = body.find_first_not_of(" \t\r\n");
            const size_t last = body.find_last_not_of(" \t\r\n");
            if (!file || first == std::string::npos || last == std::string::npos ||
                body[first] != '{' || body[last] != '}') {
                return HttpResponse::JSON(
                    "{\"error\":\"topology unavailable\"}", 503);
            }
            HttpResponse response = HttpResponse::JSON(body);
            response.headers["Cache-Control"] = "public, max-age=15";
            return response;
        } catch (...) {
            return HttpResponse::JSON(
                "{\"error\":\"topology unavailable\"}", 503);
        }
    }

    HttpResponse ServeAPIStats() {
        static std::mutex            cache_mtx;
        static std::string           cached_body;
        static int64_t               cached_at_ms = 0;
        constexpr int64_t TTL_MS = 1500;
        int64_t now_ms = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        {
            std::lock_guard<std::mutex> lk(cache_mtx);
            if (!cached_body.empty() && (now_ms - cached_at_ms) < TTL_MS) {
                return HttpResponse::JSON(cached_body);
            }
        }
        std::ostringstream j;
        uint64_t height  = chain_.Height();
        double   supply  = chain_.TotalSupplyVeld();
        uint64_t s_units = chain_.TotalSupplyUnits();

        auto vault_script = AddressToScript(VAULT_ADDRESS);
        double vault_bal  = (double)chain_.GetBalance(vault_script) / VELD_UNITS;

        uint64_t next_vault_blk  = VAULT_BLOCK_INTERVAL  - (height % VAULT_BLOCK_INTERVAL);
        uint64_t next_stk_dist   = VAULT_DISTRIBUTION_INTERVAL - (height % VAULT_DISTRIBUTION_INTERVAL);
        uint64_t next_pool_dist  = 100 - (height % 100);
        bool     staking_active  = s_units >= chain_.GetStakingActivationUnits();
        bool     emission_done   = s_units >= MAX_SUPPLY_UNITS;

        j << std::fixed << std::setprecision(8);
        j << "{";
        j << "\"height\":" << height << ",";
        j << "\"supply_veld\":" << supply << ",";
        j << "\"max_supply\":" << MAX_SUPPLY << ",";
        j << "\"supply_pct\":" << std::setprecision(4) << (supply / MAX_SUPPLY * 100.0) << ",";
        j << "\"emission_pct\":" << std::setprecision(4) << (supply / MAX_SUPPLY * 100.0) << ",";
        j << "\"emission_complete\":" << (emission_done ? "true" : "false") << ",";
        j << "\"vault_balance_veld\":" << std::setprecision(8) << vault_bal << ",";
        j << "\"vault_address\":\"" << VAULT_ADDRESS << "\",";
        j << "\"next_vault_block_in\":" << next_vault_blk << ",";
        j << "\"next_staking_dist_in\":" << next_stk_dist << ",";
        j << "\"next_pool_dist_in\":" << next_pool_dist << ",";
        j << "\"staking_active\":" << (staking_active ? "true" : "false") << ",";
        j << "\"staking_activation_supply\":" << STAKING_ACTIVATION_VELD << ",";
        j << "\"block_reward_veld\":" << std::setprecision(8) << (double)BLOCK_REWARD_UNITS / VELD_UNITS << ",";
        uint64_t local_mempool = mempool_.Size();
        size_t   local_peers   = LivePeerCount();
        uint64_t fleet_mempool_max = local_mempool;
        size_t   fleet_responsive  = 1;
        std::vector<uint64_t> per_host_peer_counts;
        per_host_peer_counts.reserve(8);
        per_host_peer_counts.push_back(local_peers);
        {
            auto stats = LivePeerStats();
            for (const auto& s : stats) {
                if (s.age_s > 600) continue;
                if (s.mempool_size > fleet_mempool_max)
                    fleet_mempool_max = s.mempool_size;
                per_host_peer_counts.push_back(s.peer_count);
                fleet_responsive++;
            }
        }
        uint64_t external_max = 0;
        const uint64_t fleet_share = (fleet_responsive > 0) ? (fleet_responsive - 1) : 0;
        for (uint64_t pc : per_host_peer_counts) {
            uint64_t ext = (pc > fleet_share) ? (pc - fleet_share) : 0;
            if (ext > external_max) external_max = ext;
        }
        uint64_t fleet_peer_total = (uint64_t)fleet_responsive + external_max;

        uint64_t mempool_bytes_local = mempool_.Bytes();

        // Public explorer pages describe this node's mempool. Peer-advertised
        // counts are telemetry only and may briefly differ as transactions
        // propagate or confirm.
        j << "\"mempool_size\":" << local_mempool << ",";
        j << "\"mempool_size_local\":" << local_mempool << ",";
        j << "\"mempool_size_network_max\":" << fleet_mempool_max << ",";
        j << "\"mempool_bytes\":" << mempool_bytes_local << ",";
        j << "\"peers\":" << fleet_peer_total << ",";
        j << "\"peers_local\":" << local_peers << ",";
        j << "\"fleet_responsive\":" << fleet_responsive << ",";
        j << "\"block_time_target\":" << TARGET_BLOCK_TIME << ",";
        uint32_t bits = 0;
        uint32_t tip_ts = 0;
        try {
            auto tip = chain_.TipCopy();
            bits = tip.header.bits;
            tip_ts = tip.header.timestamp;
        } catch (...) {}
        double difficulty = 0.0;
        if (bits != 0) {
            uint32_t exp = bits >> 24;
            uint32_t mant = bits & 0xFFFFFF;
            if (exp >= 3 && exp <= 32 && mant > 0)
                difficulty = (double)0x00000808 / (double)mant * pow(256.0, (int)(0x1f - exp));
        }
        double hashrate_hps = 0.0;
        if (difficulty > 0.0 && TARGET_BLOCK_TIME > 0) {
            hashrate_hps = difficulty * 4294967296.0 / (double)TARGET_BLOCK_TIME;
        }
        j << "\"best_block_hash\":\"" << HashToHex(chain_.TipCopy().GetHash()) << "\","
          << "\"difficulty\":" << std::setprecision(4) << difficulty << ","
          << "\"hashrate\":" << std::setprecision(2) << hashrate_hps << ","
          << "\"tip_timestamp\":" << tip_ts << ","
          << "\"phase\":\"" << (staking_active ? "standard" : "bootstrap") << "\","
          << "\"supply\":" << std::setprecision(8) << supply << ","
          << "\"blocks\":" << height;
        j << "}";
        std::string body = j.str();
        {
            std::lock_guard<std::mutex> lk(cache_mtx);
            cached_body  = body;
            cached_at_ms = now_ms;
        }
        return HttpResponse::JSON(body);
    }

    HttpResponse ServeAPIMempool() {
        std::ostringstream j;
        j << "{";
        j << "\"count\":" << mempool_.Size() << ",";
        j << "\"bytes\":" << mempool_.Bytes() << ",";
        j << "\"max_count\":" << Mempool::MAX_TX_COUNT << ",";
        j << "\"max_bytes\":" << Mempool::MAX_MEMPOOL_BYTES << ",";
        j << "\"min_fee_rate\":" << Mempool::MIN_FEE_RATE;
        j << "}";
        return HttpResponse::JSON(j.str());
    }

    HttpResponse ServeAPIMining() {
        std::ostringstream j;
        j << "{";
        j << "\"algorithm\":\"VeldHash\",";
        j << "\"phase\":\"" << (chain_.TotalSupplyUnits() < chain_.GetStakingActivationUnits() ? "bootstrap" : "standard") << "\",";

        j << "\"max_reward_per_miner\":" << std::fixed << std::setprecision(8)
          << (double)BLOCK_REWARD_UNITS / VELD_UNITS << ",";
        j << "\"min_miners_per_block\":1,";
        j << "\"block_reward\":" << std::fixed << std::setprecision(8)
          << (double)BLOCK_REWARD_UNITS / VELD_UNITS << ",";
        j << "\"staking_active\":" << (chain_.TotalSupplyUnits() >= chain_.GetStakingActivationUnits() ? "true" : "false");
        j << "}";
        return HttpResponse::JSON(j.str());
    }

    HttpResponse ServeStaking() {
        double total_staked = 0.0;
        uint64_t staker_count = 0;
        bool staking_active = chain_.TotalSupplyUnits() >= chain_.GetStakingActivationUnits();
        double supply = (double)chain_.TotalSupplyUnits() / VELD_UNITS;
        double vault_bal = 0.0;
        {
            uint64_t _tip = chain_.Height();
            auto script = AddressToScript(VaultAddressAtHeight(_tip));
            if (!script.empty()) {
                auto utxos = chain_.GetUTXOsForScript(script);
                for (auto& u : utxos) vault_bal += (double)u.value / VELD_UNITS;
            }
        }

        std::string staking_resp;
        if (rpc_delegate_) {
            staking_resp = rpc_delegate_->Handle("{\"jsonrpc\":\"2.0\",\"id\":\"1\","
                "\"method\":\"getstakinginfo\",\"params\":[]}");
            if (staking_resp.find("\"staking_active\":true") != std::string::npos) staking_active = true;
            { auto p = staking_resp.find("\"total_staked_veld\":");
              if (p != std::string::npos) { auto s = p + 20; auto e = staking_resp.find_first_of(",}", s); try { total_staked = std::stod(staking_resp.substr(s, e-s)); } catch (...) {} } }
            { size_t pos = 0; size_t cnt = 0;
              while ((pos = staking_resp.find("\"address\":", pos)) != std::string::npos) { ++cnt; pos += 10; }
              staker_count = cnt; }
        }

        // Total Bonded: validator custodial bonds are NOT in total_staked, but
        // they DO draw vault yield as synthetic top-tier staked positions
        // (validators.h ComputeEligibleBondWeights). Surface them so the staking
        // picture isn't misread as stake-only.
        double total_bonded = 0.0;
        uint64_t bonded_validator_count = 0;
        if (rpc_delegate_) {
            std::string bond_resp = rpc_delegate_->Handle("{\"jsonrpc\":\"2.0\",\"id\":\"1\","
                "\"method\":\"getbondvaultinfo\",\"params\":[]}");
            { auto p = bond_resp.find("\"custodied_principal_veld\":");
              if (p != std::string::npos) { auto s = p + 27; auto e = bond_resp.find_first_of(",}", s);
                try { total_bonded = std::stod(bond_resp.substr(s, e - s)); } catch (...) {} } }
            { auto p = bond_resp.find("\"custodial_validator_count\":");
              if (p != std::string::npos) { auto s = p + 28; auto e = bond_resp.find_first_of(",}", s);
                try { bonded_validator_count = (uint64_t)std::stoull(bond_resp.substr(s, e - s)); } catch (...) {} } }
        }

        std::ostringstream page;
        page << R"HTML(
<div class="stat-grid" style="margin-bottom:20px">
  <div class="stat"><div class="stat-label">Staking Status</div><div id="st-active" class="stat-value" style="font-size:14px">)HTML";
        page << (staking_active ? "<span class='badge badge-active'>ACTIVE</span>" : "<span class='badge badge-inactive'>INACTIVE</span>");
        page << R"HTML(</div></div>
  <div class="stat"><div class="stat-label">Total Staked</div><div class="stat-value em" id="st-total">)HTML";
        page << std::fixed << std::setprecision(2) << total_staked;
        page << R"HTML( VELD</div></div>
  <div class="stat"><div class="stat-label">Total Bonded</div><div class="stat-value" style="color:#B07CFF" id="st-bonded">)HTML";
        page << std::fixed << std::setprecision(2) << total_bonded;
        page << " VELD</div><div class=\"stat-sub\" style=\"color:var(--muted)\">"
             << bonded_validator_count << " validator bond" << (bonded_validator_count == 1 ? "" : "s")
             << " &middot; draw vault yield at 1.5&times;</div></div>\n";
        page << R"HTML(  <div class="stat"><div class="stat-label">Active Stakers</div><div class="stat-value" id="st-count">)HTML";
        page << staker_count;
        page << R"HTML(</div></div>
  <div class="stat"><div class="stat-label">Vault Balance</div><div class="stat-value gold" id="st-vault">)HTML";
        page << std::fixed << std::setprecision(2) << vault_bal;
        page << R"HTML( VELD</div></div>
  )HTML";
        {
            double live_unlock_veld = (double)STAKING_UNLOCK_SUPPLY / (double)VELD_UNITS;
            page << "<div class=\"stat\"><div class=\"stat-label\">Activation Supply</div>"
                 << "<div class=\"stat-value\" style=\"font-size:20px\">"
                 << std::fixed << std::setprecision(0) << live_unlock_veld << " VELD MINED</div>"
                 << "<div class=\"stat-sub\" style=\"color:var(--muted)\">staking activates here</div></div>";
        }
        page << R"HTML(  <div class="stat"><div class="stat-label">Distribution Interval</div><div class="stat-value" style="font-size:20px">480 blocks</div></div>
</div>

)HTML";

        if (!staking_active) {
            double live_unlock_veld = (double)STAKING_UNLOCK_SUPPLY / (double)VELD_UNITS;
            double supply_pct = (live_unlock_veld > 0)
                ? (supply / live_unlock_veld) * 100.0 : 0.0;
            page << "<div class=\"card\">";
            page << "<div class=\"card-title\">Staking Activation Progress</div>";
            page << "<p style=\"color:var(--muted);font-size:11px;margin-bottom:16px\">"
                 << "Staking activates once <span style=\"color:var(--em)\">"
                 << std::fixed << std::setprecision(0) << live_unlock_veld
                 << " VELD</span> has been mined. Mining rewards accumulate in the vault during this period.</p>";
            page << "<div style=\"display:flex;justify-content:space-between;font-size:11px;color:var(--muted);margin-bottom:6px\">";
            page << "<span>Current supply</span><span>" << std::fixed << std::setprecision(2)
                 << supply << " / " << std::setprecision(0) << live_unlock_veld
                 << " VELD</span></div>";
            page << "<div class=\"vault-bar-track\"><div class=\"vault-bar-fill\" style=\"width:"
                 << std::fixed << std::setprecision(4) << supply_pct << "%\"></div></div>";
            page << "<div style=\"margin-top:8px;font-size:11px;color:var(--muted)\">"
                 << std::setprecision(2) << supply_pct << "% complete &mdash; staking activates at &asymp; block ";
            double blocks_left = (live_unlock_veld - supply) / 3.13926940;
            if (blocks_left < 0) blocks_left = 0;
            uint64_t target_block = chain_.Height() + (uint64_t)(blocks_left + 0.5);
            page << target_block << " (" << std::setprecision(0) << blocks_left << " blocks to go)</div></div>";
        }

        page << R"HTML(
<div class="card">
  <div class="card-title">Staking Parameters</div>
  <div class="tbl-scroll"><table class="tbl">
    <thead><tr><th>Parameter</th><th>Value</th><th>Notes</th></tr></thead>
    <tbody>
)HTML";
        {
            double live_min_stake = (double)MIN_STAKE_UNITS / (double)VELD_UNITS;
            double live_max_stake = (double)MAX_STAKE_UNITS / (double)VELD_UNITS;
            page << "      <tr><td>Minimum Stake</td><td style=\"color:var(--em)\">"
                 << std::fixed << std::setprecision(0) << live_min_stake
                 << " VELD</td><td style=\"color:var(--muted)\">Sybil floor</td></tr>";
            page << "      <tr><td>Maximum Stake</td><td style=\"color:var(--em)\">"
                 << std::setprecision(0) << live_max_stake
                 << " VELD</td><td style=\"color:var(--muted)\">10,000 VELD per address &mdash; protocol-wide cap</td></tr>";
        }
        page << R"HTML(      <tr><td>Lockup Periods</td><td style="color:var(--em)">7 / 14 / 30 / 90 days</td><td style="color:var(--muted)">3,360 / 6,720 / 14,400 / 43,200 blocks</td></tr>
      <tr><td>Distribution Budget</td><td style="color:var(--em)">Up to 90% of cycle inflow</td><td style="color:var(--muted)">Also limited to 8% of vault balance and 75% per staker</td></tr>
      <tr><td>Distribution Interval</td><td style="color:var(--em)">480 blocks</td><td style="color:var(--muted)">~24 hours</td></tr>
      <tr><td>Multiplier Range</td><td style="color:var(--em)">1.0× &ndash; 3.0×</td><td style="color:var(--muted)">All tiers use rolling windows &mdash; mine consistently to earn and keep each tier</td></tr>
    </tbody>
  </table>
</div>

<div class="card">
  <div class="card-title">Active Stakers</div>
  <div id="stakers-list"><div style="color:var(--muted);text-align:center;padding:20px">Loading stakers...</div></div>
</div>

<script nonce="__CSP_NONCE__">
function escHtml(s){var d=document.createElement('div');d.appendChild(document.createTextNode(s));return d.innerHTML;}
// the global fmt() (explorer.h header script)
// is NOT emitted on this page — only escHtml was local here. Every
// fmt(...) call in this <script> (vault balance, the stakers table, the
// Total Staked header) threw "ReferenceError: fmt is not defined",
// which the stakers-list .catch turned into a permanent "No staking
// data available." (pre-existing — the old per-UTXO renderer called
// fmt() too). Define a self-contained, null-safe fmt locally so this
// page never depends on an external global again.
function fmt(n,d){var x=parseFloat(n);if(!isFinite(x))x=0;return x.toLocaleString('en-US',{minimumFractionDigits:(d!==undefined?d:2),maximumFractionDigits:(d!==undefined?d:2)});}
// st-total / st-count are now set authoritatively by the
// /api/v1/staking per-address aggregation below, so the "Total Staked"
// header is the EXACT sum of the per-address rows the user sees and the
// count is distinct addresses. The old /api/v1/stats writer used a
// per-UTXO staker_count and a separately-sourced total — precisely what
// made "Total Staked" disagree with the per-address list. Removed (the
// server still renders correct gross totals as the pre-JS fallback).

// Load stakers from getstakinginfo via vault endpoint
fetch('/api/v1/vault').then(r=>r.json()).then(function(d){
  if (d.balance_veld !== undefined) document.getElementById('st-vault').textContent = fmt(d.balance_veld, 2) + ' VELD';
});

// Try to load stakers list
fetch('/api/v1/staking').then(r=>r.json()).then(function(d){
  if (d.stakers && d.stakers.length > 0) {
    // Do not map a combined multiplier to a mining tier name. A staker with
    // no mining tier but a 1.50x lockup multiplier would otherwise be
    // being labeled "Silver" because Silver mining tier is also 1.50x.
    // The multiplier here is the COMBINED mining*lockup product, so it
    // can't be reduced back to a single mining tier. Show the breakdown
    // (mining mult x lockup mult) instead.
    // aggregate by ADDRESS. getstakinginfo returns ONE entry
    // PER STAKED UTXO, so an address with N staked UTXOs appeared as N
    // rows each carrying a PARTIAL amount; the visible list therefore
    // never summed to the network-gross "Total Staked" header (the user
    // report). Group per address: sum staked + share, stake-weight the
    // effective multiplier, take the max mining/lockup multiplier and the
    // latest unlock height, render ONE row per address, and set the
    // header to the EXACT sum of those rows + the distinct-address count
    // so they can never visibly disagree again. Display-only — no
    // consensus path touched (GetTotalStake is correct and unchanged).
    var byAddr = {};
    d.stakers.forEach(function(s) {
      var a = s.address;
      var st = parseFloat(s.staked_veld) || 0;
      if (!byAddr[a]) byAddr[a] = { address:a, staked:0, share:0, wmul:0, mm:1.0, lm:1.0, unlock:0 };
      var r = byAddr[a];
      r.staked += st;
      r.share  += (parseFloat(s.share_pct) || 0);
      r.wmul   += st * ((s.multiplier != null) ? parseFloat(s.multiplier) : 1.0);
      r.mm      = Math.max(r.mm, (s.mining_multiplier != null) ? parseFloat(s.mining_multiplier) : 1.0);
      r.lm      = Math.max(r.lm, (s.lockup_multiplier != null) ? parseFloat(s.lockup_multiplier) : 1.0);
      r.unlock  = Math.max(r.unlock, s.unlock_height ? parseInt(s.unlock_height, 10) : 0);
    });
    var rows = Object.keys(byAddr).map(function(k){ return byAddr[k]; });
    rows.sort(function(x,y){ return y.staked - x.staked; });
    var totalAgg = 0;
    rows.forEach(function(r){ totalAgg += r.staked; });
    // paginate 10/page. Header total/count stay the
    // FULL network aggregate (not per-page) so they remain authoritative.
    var STK_PGSZ = 10;
    var stkPage = 1;
    var stkTotalPages = Math.max(1, Math.ceil(rows.length / STK_PGSZ));
    function renderStakersPage(p) {
      if (p < 1) p = 1; if (p > stkTotalPages) p = stkTotalPages; stkPage = p;
      var start = (p - 1) * STK_PGSZ;
      var end = Math.min(rows.length, start + STK_PGSZ);
      var html = '<div class="tbl-scroll"><table class="tbl"><thead><tr><th>#</th><th>Address</th><th>Staked</th><th>Mining</th><th>Lockup</th><th>Multiplier</th><th>Share</th><th>Unlock Block</th></tr></thead><tbody>';
      for (var i = start; i < end; i++) {
        var r = rows[i];
        var eff = (r.staked > 0) ? (r.wmul / r.staked) : 1.0;
        html += '<tr><td style="color:var(--muted2)">'+(i+1)+'</td>' +
          '<td><a href="/address/'+escHtml(r.address)+'" class="addr">'+escHtml(r.address.slice(0,16))+'...</a></td>' +
          '<td style="color:var(--em)">'+fmt(r.staked,2)+' VELD</td>' +
          '<td style="color:var(--muted)">'+r.mm.toFixed(2)+'&times;</td>' +
          '<td style="color:var(--muted)">'+r.lm.toFixed(2)+'&times;</td>' +
          '<td style="color:var(--em)">'+eff.toFixed(2)+'&times;</td>' +
          '<td style="color:var(--muted)">'+fmt(r.share,2)+'%</td>' +
          '<td style="color:var(--muted)">'+(r.unlock?escHtml(String(r.unlock)):'&mdash;')+'</td></tr>';
      }
      html += '</tbody></table></div>';
      if (stkTotalPages > 1) {
        var pd = stkPage <= 1, nd = stkPage >= stkTotalPages;
        var be = 'background:none;border:1px solid var(--b1);color:var(--text);padding:6px 14px;border-radius:6px;cursor:pointer;font-family:inherit';
        var bx = 'background:none;border:1px solid var(--b1);color:var(--muted);padding:6px 14px;border-radius:6px;opacity:.4;cursor:not-allowed;font-family:inherit';
        html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-top:14px;font-size:12px;color:var(--muted)">' +
          '<button id="stk-prev" '+(pd?'disabled ':'')+'style="'+(pd?bx:be)+'">&laquo; Prev</button>' +
          '<span>'+(start+1)+'&ndash;'+end+' of '+rows.length+' &middot; page '+stkPage+'/'+stkTotalPages+'</span>' +
          '<button id="stk-next" '+(nd?'disabled ':'')+'style="'+(nd?bx:be)+'">Next &raquo;</button>' +
          '</div>';
      }
      var host = document.getElementById('stakers-list');
      host.innerHTML = html;
      var pv = document.getElementById('stk-prev'); if (pv) pv.onclick = function(){ renderStakersPage(stkPage-1); };
      var nx = document.getElementById('stk-next'); if (nx) nx.onclick = function(){ renderStakersPage(stkPage+1); };
    }
    renderStakersPage(1);
    // Header == exact sum of ALL per-address rows + distinct count.
    var stt = document.getElementById('st-total'); if (stt) stt.textContent = fmt(totalAgg, 2) + ' VELD';
    var stc = document.getElementById('st-count'); if (stc) stc.textContent = rows.length;
  } else {
    document.getElementById('stakers-list').innerHTML = '<div style="color:var(--muted);text-align:center;padding:20px;font-size:11px">No active stakers yet &mdash; staking activates once the supply threshold is reached (see card above).</div>';
  }
}).catch(function(){
  document.getElementById('stakers-list').innerHTML = '<div style="color:var(--muted);text-align:center;padding:20px">No staking data available.</div>';
});
</script>
)HTML";

        return HttpResponse::HTML(HtmlWrapArcade("Staking", page.str(), "staking"));
    }

    HttpResponse ServeVaultPage() {
        uint64_t height = chain_.Height();
        uint64_t best_h = BestKnownHeight();
        const std::string& current_vault_addr =
            VaultAddressAtHeight(best_h > 0 ? best_h : height);
        double vault_bal = 0.0;
        {
            auto script = AddressToScript(current_vault_addr);
            if (!script.empty()) {
                auto utxos = chain_.GetUTXOsForScript(script);
                for (auto& u : utxos) vault_bal += (double)u.value / VELD_UNITS;
            }
        }
        double supply = (double)chain_.TotalSupplyUnits() / VELD_UNITS;
        double vault_pct = supply > 0 ? vault_bal / supply * 100.0 : 0.0;
        uint64_t next_dist = VAULT_DISTRIBUTION_INTERVAL - (best_h % VAULT_DISTRIBUTION_INTERVAL);
        uint64_t next_vault_blk = VAULT_BLOCK_INTERVAL - (best_h % VAULT_BLOCK_INTERVAL);
        constexpr double BLOCKS_PER_DAY      = 480.0;
        constexpr double VAULT_BLOCK_FRACTION = 1.0 / 100.0;
        const double reward_veld = (double)BLOCK_REWARD_UNITS / VELD_UNITS;
        double daily_inflow = BLOCKS_PER_DAY * reward_veld * 0.20;
        daily_inflow += BLOCKS_PER_DAY * VAULT_BLOCK_FRACTION * reward_veld * 0.80;
        double payout_rate = (best_h >= VAULT_INFLOW_CAP_ACTIVATION_HEIGHT)
                           ? (double)VAULT_INFLOW_PAYOUT_PPM / 1'000'000.0
                           : 0.90;
        double daily_payout    = daily_inflow * payout_rate;
        double daily_retention = daily_inflow - daily_payout;

        std::ostringstream page;
        page << "<div class=\"stat-grid\" style=\"margin-bottom:20px\">";
        page << "<div class=\"stat\"><div class=\"stat-label\">Vault Balance</div><div class=\"stat-value gold\">" << std::fixed << std::setprecision(2) << vault_bal << " VELD</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">% of Supply</div><div class=\"stat-value\">" << std::setprecision(3) << vault_pct << "%</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Next Distribution</div><div class=\"stat-value em\">" << next_dist << "</div><div class=\"stat-sub\">blocks (~" << (next_dist*3) << " min)</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Next Vault Block</div><div class=\"stat-value\">" << next_vault_blk << "</div><div class=\"stat-sub\">blocks</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Daily Inflow</div><div class=\"stat-value\">~" << std::setprecision(1) << daily_inflow << "</div><div class=\"stat-sub\">VELD/day into vault</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Daily Payout</div><div class=\"stat-value em\">~" << std::setprecision(1) << daily_payout << "</div><div class=\"stat-sub\">VELD/day to stakers (90% inflow cap)</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Daily Retention</div><div class=\"stat-value gold\">~" << std::setprecision(1) << daily_retention << "</div><div class=\"stat-sub\">VELD/day vault growth (10%)</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Dist. Interval</div><div class=\"stat-value\">480</div><div class=\"stat-sub\">blocks (~24h)</div></div>";
        page << "</div>";

        page << "<div class=\"card\" style=\"border-color:var(--gold)\">";
        page << "<div class=\"card-title\">Vault Address</div>";
        page << "<div style=\"font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--gold);word-break:break-all;padding:10px 14px;background:var(--surface2);border-radius:4px;border:1px solid #c9a84c33\">" << current_vault_addr << "</div>";
        page << "<div style=\"margin-top:12px\"><a href=\"/address/" << current_vault_addr << "\" style=\"display:inline-flex;align-items:center;gap:7px;text-decoration:none;padding:9px 16px;border:1px solid var(--b2);border-radius:10px;background:var(--s2);color:var(--text);font-size:12px;font-weight:600;font-family:var(--sans)\">View full history <span style=\"color:var(--em);font-weight:700\">&rarr;</span></a></div>";
        page << "</div>";

        page << R"HTML(
<div class="card">
  <div class="card-title">Vault Funding Sources</div>
  <div class="tbl-scroll"><table class="tbl">
    <thead><tr><th>Source</th><th>Amount</th><th>Frequency</th></tr></thead>
    <tbody>
      <tr><td>Block reward cut (20%)</td><td style="color:var(--em)">~0.62785 VELD</td><td style="color:var(--muted)">Every block</td></tr>
      <tr><td>Vault block (100% reward)</td><td style="color:var(--em)">3.1393 VELD</td><td style="color:var(--muted)">Every 100th block</td></tr>
      <tr><td>Transaction fees</td><td style="color:var(--em)">Variable (0.001 VELD/tx)</td><td style="color:var(--muted)">Per transaction</td></tr>
    </tbody>
  </table>
</div>

<div class="card">
  <div class="card-title">Vault Protection System</div>
  <div class="tbl-scroll"><table class="tbl">
    <thead><tr><th>#</th><th>Rule</th><th>Effect</th></tr></thead>
    <tbody>
      <tr><td style="color:var(--em)">1</td><td>Inflow cap 90%</td><td style="color:var(--muted)">At most 90% of cycle inflow paid out; vault retains &ge;10% as principal growth</td></tr>
      <tr><td style="color:var(--em)">2</td><td>Backstop ceiling 8%</td><td style="color:var(--muted)">Never more than 8% of vault balance per cycle (defence-in-depth)</td></tr>
      <tr><td style="color:var(--em)">3</td><td>One dist per cycle</td><td style="color:var(--muted)">No catch-up on missed distributions</td></tr>
      <tr><td style="color:var(--em)">4</td><td>Liveness check</td><td style="color:var(--muted)">Skip if chain stalled for 2+ hours</td></tr>
      <tr><td style="color:var(--em)">5</td><td>Min threshold</td><td style="color:var(--muted)">Skip if distribution &lt; 0.0001 VELD</td></tr>
      <tr><td style="color:var(--em)">6</td><td>Concentration cap 75%</td><td style="color:var(--muted)">No staker receives &gt; 75% of any cycle; excess stays in vault</td></tr>
      <tr><td style="color:var(--em)">7</td><td>Post-emission inheritance</td><td style="color:var(--muted)">Vault principal accumulated during emission era funds stakers from fees alone after year ~38</td></tr>
    </tbody>
  </table>
</div>

)HTML";
        return HttpResponse::HTML(HtmlWrapArcade("Vault", page.str(), "vault"));
    }

    HttpResponse ServeRichList() {
        // Serve the cached body only while it reflects the CURRENT block. A new
        // block changes balances, so a height change invalidates the cache and we
        // rebuild synchronously — the page is always current when you open it (no
        // stale-while-revalidate that served a stale copy and needed a second
        // click to pick up the rebuild). The 60s TTL is a secondary safety bound.
        uint64_t cur_h = chain_.Height();
        {
            std::lock_guard<std::mutex> lk(richlist_cache_mu_);
            if (!richlist_cache_body_.empty()
                && richlist_cache_height_ == cur_h
                && std::chrono::steady_clock::now() < richlist_cache_until_) {
                return HttpResponse::HTML(richlist_cache_body_);
            }
        }
        return ServeRichListBuild(cur_h);
    }

    HttpResponse ServeRichListBuild(uint64_t requested_height) {
        auto holders = chain_.GetTopHolders(50);
        auto pin_address = [&](const std::string& addr) {
            for (const auto& [a, b] : holders) {
                if (a == addr) return;
            }
            auto script = AddressToScript(addr);
            double bal = (double)chain_.GetBalance(script) / VELD_UNITS;
            holders.push_back(std::make_pair(addr, bal));
        };
        pin_address(VAULT_ADDRESS);
        pin_address(STAKE_VAULT_ADDRESS);
        pin_address(BOND_YIELD_ESCROW);
        pin_address(POOL_ADDRESS);
        pin_address(ENDORSEMENT_POOL_ADDRESS);
        auto sys_rank = [](const std::string& a) -> int {
            if (a == VAULT_ADDRESS)            return 0;
            if (a == STAKE_VAULT_ADDRESS)      return 1;
            if (a == BOND_YIELD_ESCROW)        return 2;
            if (a == POOL_ADDRESS)             return 3;
            if (a == ENDORSEMENT_POOL_ADDRESS) return 4;
            return 100;
        };
        std::sort(holders.begin(), holders.end(),
            [&](const auto& a, const auto& b) {
                int ra = sys_rank(a.first), rb = sys_rank(b.first);
                if (ra != rb) return ra < rb;
                return a.second > b.second;
            });
        double total_supply = chain_.TotalSupplyVeld();
        auto is_system_addr = [](const std::string& a) {
            return a == VAULT_ADDRESS
                || a == STAKE_VAULT_ADDRESS
                || a == BOND_YIELD_ESCROW
                || a == POOL_ADDRESS
                || a == ENDORSEMENT_POOL_ADDRESS;
        };
        size_t real_count = 0;
        double top10 = 0;
        double top1  = 0;
        for (const auto& [a, b] : holders) {
            if (is_system_addr(a)) continue;
            ++real_count;
            if (real_count == 1) top1 = b;
            if (real_count <= 10) top10 += b;
        }
        double top10pct = total_supply > 0 ? top10 / total_supply * 100.0 : 0.0;
        double top1pct  = total_supply > 0 ? top1  / total_supply * 100.0 : 0.0;

        std::ostringstream page;
        page << "<div class=\"stat-grid\" style=\"margin-bottom:20px\">";
        page << "<div class=\"stat\"><div class=\"stat-label\">Unique Holders</div><div class=\"stat-value em\">" << real_count << "</div><div class=\"stat-sub\">excl. system addresses</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Total Supply</div><div class=\"stat-value gold\">" << std::fixed << std::setprecision(2) << total_supply << " VELD</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Top 10 Hold</div><div class=\"stat-value\">" << std::setprecision(1) << top10pct << "%</div><div class=\"stat-sub\">of supply</div></div>";
        page << "<div class=\"stat\"><div class=\"stat-label\">Largest Holder</div><div class=\"stat-value\">" << std::setprecision(1) << top1pct << "%</div><div class=\"stat-sub\">of supply</div></div>";
        page << "</div>";

        page << "<div class=\"card\" style=\"padding:14px 18px\">";
        page << "<div class=\"card-header\" style=\"display:flex;align-items:baseline;justify-content:space-between;padding:6px 4px 4px\">";
        page << "<div class=\"card-title\" style=\"margin:0\">Top 50 holders</div>";
        page << "<span style=\"font-size:11px;color:var(--muted);font-weight:600\">ranked by unspent balance</span>";
        page << "</div>";
        page << "<div class=\"row-list\">";

        int rank = 0;
        double max_pct = 0.0;
        for (const auto& [a, b] : holders) {
            if (is_system_addr(a)) continue;
            double p = total_supply > 0 ? b / total_supply * 100.0 : 0.0;
            if (p > max_pct) max_pct = p;
        }
        if (max_pct == 0.0) max_pct = 1.0;
        for (const auto& [addr, bal] : holders) {
            double pct = total_supply > 0 ? bal / total_supply * 100.0 : 0.0;
            double bar_w = max_pct > 0 ? pct / max_pct * 100.0 : 0.0;
            if (bar_w > 100.0) bar_w = 100.0;
            bool is_vault = (addr == VAULT_ADDRESS);
            bool is_custody_vault = (addr == STAKE_VAULT_ADDRESS);
            bool is_yield_escrow = (addr == BOND_YIELD_ESCROW);
            bool is_pool = (addr == POOL_ADDRESS);
            bool is_endorse_pool = (addr == ENDORSEMENT_POOL_ADDRESS);
            bool is_sys = (is_vault || is_custody_vault || is_yield_escrow || is_pool || is_endorse_pool);
            std::string bar_color = is_vault ? "linear-gradient(90deg,#0EA5E9,#14B8A6)"
                                    : is_custody_vault ? "linear-gradient(90deg,#F59E0B,#D97706)"
                                    : is_yield_escrow ? "linear-gradient(90deg,#10B981,#14B8A6)"
                                    : is_pool ? "linear-gradient(90deg,#0EA5E9,#3B82F6)"
                                    : is_endorse_pool ? "linear-gradient(90deg,#6366F1,#4338CA)"
                                    : "linear-gradient(90deg,var(--em),var(--cob-3,#14B8A6))";
            bool is_diamond = false;
            if (tiers_ && !is_sys) {
                auto addr_script = AddressToScript(addr);
                std::string script_hex = BytesToHex(addr_script);
                auto ti = tiers_->GetTier(script_hex);
                is_diamond = (ti.level >= 5);
            }
            std::string addr_short = addr.substr(0, 12) + "&hellip;" + addr.substr(addr.size() - 6);
            std::string rank_label = is_sys ? "&middot;" : std::to_string(++rank);
            std::string ic_class = is_sys ? "ic-s" : "ic-h";

            page << "<a class=\"rl-row\" href=\"/address/" << addr << "\" style=\"text-decoration:none\">";
            page << "<div class=\"rl-ic " << ic_class << "\" style=\"font-size:13px\">" << rank_label << "</div>";
            page << "<div class=\"rl-info\">";
            page << "<div class=\"rl-name\">";
            if (is_diamond) page << "<span class=\"diamond-prismatic\">" << addr_short << "</span>";
            else            page << addr_short;
            // Badges render on their OWN line BELOW the address so every badge
            // sits in the same place regardless of text width. (Previously each
            // was appended inline after the address, so the short VAULT badge fit
            // on the address line while longer ones — BOND CUSTODY, YIELD ESCROW,
            // etc. — wrapped to the next line: inconsistent placement.)
            std::string rl_badges;
            if (is_vault) rl_badges += "<span class=\"badge badge-active\" style=\"font-size:9.5px\">VAULT</span>";
            if (is_custody_vault) rl_badges += "<span class=\"badge\" style=\"font-size:9.5px;background:rgba(245,158,11,.12);color:#F59E0B;border:1px solid rgba(245,158,11,.32)\">BOND CUSTODY</span>";
            if (is_yield_escrow) rl_badges += "<span class=\"badge\" style=\"font-size:9.5px;background:rgba(16,185,129,.12);color:#10B981;border:1px solid rgba(16,185,129,.32)\">YIELD ESCROW</span>";
            if (is_pool)  rl_badges += "<span class=\"badge\" style=\"font-size:9.5px;background:rgba(14,165,233,.10);color:#0EA5E9;border:1px solid rgba(14,165,233,.30)\">CO-MINE POOL</span>";
            if (is_endorse_pool) rl_badges += "<span class=\"badge\" style=\"font-size:9.5px;background:rgba(99,102,241,.12);color:#818CF8;border:1px solid rgba(99,102,241,.32)\">VALIDATOR POOL</span>";
            if (is_diamond) rl_badges += "<span class=\"diamond-badge\" style=\"font-size:9.5px\">\xe2\x97\x86\xef\xb8\x8e DIAMOND</span>";
            if (!rl_badges.empty())
                page << "<div style=\"margin-top:4px;display:flex;flex-wrap:wrap;gap:5px\">" << rl_badges << "</div>";
            page << "</div>";
            page << "<div class=\"rl-sub\" style=\"display:flex;align-items:center;gap:10px\">";
            page << "<div style=\"background:var(--s3);border-radius:3px;height:6px;width:120px;overflow:hidden;flex-shrink:0\">"
                 << "<div style=\"background:" << bar_color << ";height:100%;width:" << std::fixed << std::setprecision(2) << bar_w << "%;border-radius:3px;transition:width .3s\"></div></div>";
            page << "<span style=\"font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--muted)\">" << std::setprecision(4) << pct << "% of supply</span>";
            page << "</div>";
            page << "</div>";
            page << "<div class=\"rl-val\">";
            page << "<div class=\"rl-v\" style=\"color:var(--em);font-size:16px\">" << std::fixed << std::setprecision(8) << bal << "</div>";
            page << "<div class=\"rl-vs\">VELD</div>";
            page << "</div>";
            page << "</a>";
        }
        if (holders.empty())
            page << "<div class=\"rl-row\" style=\"color:var(--muted);justify-content:center;font-style:italic\">No UTXO data yet.</div>";
        page << "</div></div>";
        std::string body = HtmlWrapArcade("Rich List", page.str(), "rich");
        if (chain_.Height() == requested_height) {
            std::lock_guard<std::mutex> lk(richlist_cache_mu_);
            richlist_cache_body_   = body;
            richlist_cache_height_ = requested_height;
            richlist_cache_until_  = std::chrono::steady_clock::now()
                                   + std::chrono::seconds(60);
        }
        return HttpResponse::HTML(body);
    }

    HttpResponse ServeMempoolPage() {
        auto pending = mempool_.GetAllTransactions();
        uint64_t tip = chain_.Height();

        std::ostringstream page;
        page << std::fixed << std::setprecision(8);

        struct TxEntry {
            std::string txid;
            std::string type_name;
            std::string ic_label;
            std::string op_class;   // badge COLOR class only (xfer/stake/cy/pp/btc/red)
            std::string badge;      // badge LABEL text (the category shown to the user)
            uint64_t fee;
            uint64_t out_total;
            size_t size;
            size_t n_in;
            size_t n_out;
        };
        std::vector<TxEntry> entries;
        entries.reserve(pending.size());

        uint64_t total_bytes = 0;
        uint64_t total_fee_units = 0;
        uint64_t stake_ops = 0;
        uint64_t endorse_ops = 0;
        uint64_t validator_ops = 0;
        uint64_t transfers = 0;

        for (const auto& tx : pending) {
            auto raw = tx.Serialize();
            total_bytes += raw.size();
            uint64_t in_total = 0, out_total = tx.TotalOutput();
            for (const auto& inp : tx.inputs) {
                auto u = chain_.GetUTXO(inp.prev_tx_hash, inp.prev_out_index);
                if (u) in_total += u->value;
            }
            uint64_t fee = in_total > out_total ? (in_total - out_total) : 0;
            total_fee_units += fee;

            std::string tx_type = "Transfer";
            std::string ic_label = "XF";
            std::string op_class = "xfer";
            std::string badge    = "transfer";
            bool classified = false;
            for (const auto& out : tx.outputs) {
                const auto& sp = out.script_pubkey;
                if (sp.size() < 2 || sp[0] != 0x6A) continue;
                size_t off = 1, plen = 0;
                if (sp[off] <= 75) { plen = sp[off++]; }
                else if (sp[off] == 0x4C && sp.size() > off+1) { off++; plen = sp[off++]; }
                else if (sp[off] == 0x4D && sp.size() > off+2) {
                    off++; plen = sp[off] | (sp[off+1] << 8); off += 2;
                }
                if (off + plen > sp.size()) continue;
                std::string pl(sp.begin()+off, sp.begin()+off+plen);
                if (pl.rfind("VELD_STAKE|LOCK",    0) == 0) { tx_type = "Stake lock";        ic_label = "ST"; op_class = "stake"; badge = "stake";     stake_ops++;     classified = true; break; }
                if (pl.rfind("VELD_STAKE|UNLOCK",  0) == 0) { tx_type = "Stake unlock";      ic_label = "ST"; op_class = "stake"; badge = "unstake";   stake_ops++;     classified = true; break; }
                if (pl.rfind("VELD_VALIDATOR|ENDORSE",  0)== 0) { tx_type = "Endorsement";   ic_label = "EN"; op_class = "cy";    badge = "endorse";   endorse_ops++;   classified = true; break; }
                if (pl.rfind("VELD_VALIDATOR|REGISTER",  0)==0) { tx_type = "Validator reg"; ic_label = "RG"; op_class = "cy";    badge = "validator"; validator_ops++; classified = true; break; }
                if (pl.rfind("VELD_VALIDATOR|DEREGISTER",0)==0) { tx_type = "Validator dereg";ic_label= "DR"; op_class = "cy";    badge = "validator"; validator_ops++; classified = true; break; }
                if (pl.rfind("VELD_DIST|COMINE", 0) == 0) { tx_type = "Co-mine payout";  ic_label = "CM"; op_class = "pp";    badge = "co-mine";   classified = true; break; }
                if (pl.rfind("VELD_DIST|",   0) == 0) { tx_type = "Staking rewards"; ic_label = "DI"; op_class = "pp";    badge = "reward";    classified = true; break; }
                if (pl.rfind("VELD_AMM|SWAP", 0) == 0) { tx_type = "Pool swap";       ic_label = "PS"; op_class = "cy";    badge = "swap";      classified = true; break; }
                if (pl.rfind("VELD_AMM|ADD",  0) == 0) { tx_type = "Pool liquidity add"; ic_label = "PL"; op_class = "cy";    badge = "liquidity"; classified = true; break; }
                if (pl.rfind("VELD_AMM|REMOVE",0) == 0) { tx_type = "Pool liquidity remove"; ic_label = "PL"; op_class = "cy"; badge = "liquidity"; classified = true; break; }
                if (pl.rfind("VELD_AMM|",    0) == 0) { tx_type = "Pool operation";  ic_label = "PL"; op_class = "cy";    badge = "amm";       classified = true; break; }
                if (pl.rfind("VELD_TOKEN|M", 0) == 0) { tx_type = "btcVELD mint";    ic_label = "BV"; op_class = "btc";   badge = "wrap";      classified = true; break; }
                if (pl.rfind("VELD_TOKEN|R", 0) == 0) { tx_type = "btcVELD redeem";  ic_label = "BV"; op_class = "btc";   badge = "redeem";    classified = true; break; }
                if (pl.rfind("VELD_TOKEN|T", 0) == 0) { tx_type = "btcVELD transfer";ic_label = "BV"; op_class = "btc";   badge = "btcVELD";   classified = true; break; }
                if (pl.rfind("VELD_TOKEN|",  0) == 0) { tx_type = "btcVELD op";      ic_label = "BV"; op_class = "btc";   badge = "btcVELD";   classified = true; break; }
                if (pl.rfind("VELD_MSPV|",   0) == 0) { tx_type = "btcVELD SPV mint";ic_label = "BV"; op_class = "btc";   badge = "wrap";      classified = true; break; }
                if (pl.rfind("VELD_ANCHOR|", 0) == 0) { tx_type = "BTC anchor";      ic_label = "BA"; op_class = "btc";   badge = "anchor";    classified = true; break; }
                if (pl.rfind("VELD_BHDR|",   0) == 0) { tx_type = "BTC header relay";ic_label = "BH"; op_class = "btc";   badge = "relay";     classified = true; break; }
                if (pl.rfind("VELD_FRAUD|",  0) == 0) { tx_type = "Fraud proof";     ic_label = "FP"; op_class = "red";   badge = "fraud";     classified = true; break; }
                if (pl.rfind("VELD_GOV|",    0) == 0) { tx_type = "Governance";      ic_label = "GV"; op_class = "pp";    badge = "gov";       classified = true; break; }
            }
            if (!classified) transfers++;

            entries.push_back({HashToHex(tx.GetTxID()), tx_type, ic_label, op_class, badge,
                               fee, out_total, raw.size(),
                               tx.inputs.size(), tx.outputs.size()});
        }

        std::sort(entries.begin(), entries.end(),
                  [](const TxEntry& a, const TxEntry& b){ return a.fee > b.fee; });

        page << ArcadeHead("Veld &middot; Mempool");
        page << ArcadePrimaryTabs("mempool");

        page << "<div class=\"hero\">\n";
        page << "  <div class=\"lbl\">Pending in mempool</div>\n";
        page << "  <div class=\"num\">" << pending.size() << "</div>\n";
        page << "  <div class=\"meta\">\n";
        page << "    <span class=\"it em\"><span class=\"dot\"></span><b>";
        if (total_bytes >= 1024) page << (total_bytes / 1024) << " KB";
        else                     page << total_bytes << " B";
        page << "</b> &middot; <b>" << std::fixed << std::setprecision(4)
             << ((double)total_fee_units / VELD_UNITS)
             << " VELD</b> pending fees</span>\n";
        page << "    <span class=\"it\"><span class=\"dot\"></span>density sorted</span>\n";
        page << "    <span class=\"it\"><span class=\"dot\"></span>tip h=" << tip << "</span>\n";
        page << "  </div>\n";
        page << "</div>\n";

        double lifetime_fees_veld = chain_.TotalFeesCollectedVeld();

        page << "<div class=\"grid2\">\n";
        page << "  <div class=\"tile gold span2\"><div class=\"l\">Lifetime fees collected &middot; chain-wide</div><div class=\"v\">"
             << std::fixed << std::setprecision(4) << lifetime_fees_veld
             << "<span class=\"u\">VELD</span></div></div>\n";
        page << "  <div class=\"tile em\"><div class=\"l\">Transfers</div><div class=\"v\">"   << transfers  << "</div></div>\n";
        page << "  <div class=\"tile\"><div class=\"l\">Stake ops</div><div class=\"v\">"      << stake_ops  << "</div></div>\n";
        page << "  <div class=\"tile\"><div class=\"l\">Endorsements</div><div class=\"v\">"   << endorse_ops<< "</div></div>\n";
        page << "  <div class=\"tile\"><div class=\"l\">Mempool fees &middot; pending</div><div class=\"v\">"
             << std::fixed << std::setprecision(4) << ((double)total_fee_units / VELD_UNITS)
             << "<span class=\"u\">VELD</span></div></div>\n";
        page << "</div>\n";

        page << "<h3>Top by fee <span class=\"ct\">" << entries.size() << " pending</span></h3>\n";

        if (entries.empty()) {
            page << "<div class=\"note em\" style=\"text-align:center;padding:28px 14px;border-radius:16px;border-left:none;border:.5px solid rgba(34,197,94,.30)\">\n"
                 << "  <div style=\"font-size:14px;font-weight:600;color:var(--em);margin-bottom:6px\">Mempool is empty</div>\n"
                 << "  <div style=\"color:var(--fg2);font-size:12.5px\">Next transactions appear here within seconds of broadcast.</div>\n"
                 << "</div>\n";
        } else {
            page << "<div class=\"list\">\n";
            bool first = true;
            for (const auto& e : entries) {
                std::string short_txid = e.txid.substr(0, 8) + "…" + e.txid.substr(e.txid.size() - 6);
                page << "  <a class=\"bk" << (first ? " fresh" : "") << "\" href=\"/tx/" << e.txid << "\">\n"
                     << "    <div class=\"ic\">" << e.ic_label << "</div>\n"
                     << "    <div class=\"info\"><div class=\"h\">" << e.type_name
                     << " &middot; " << std::fixed << std::setprecision(4)
                     << ((double)e.out_total / VELD_UNITS) << " VELD"
                     << "<span class=\"op " << e.op_class << "\">" << e.badge << "</span></div>"
                     << "<div class=\"s\">" << e.size << " B &middot; " << short_txid << "</div></div>\n"
                     << "    <div class=\"right\"><div class=\"ago\">" << (first ? "hot" : "+") << "</div>"
                     << "<div class=\"tx\">fee " << std::fixed << std::setprecision(4) << ((double)e.fee / VELD_UNITS) << "</div></div>\n"
                     << "  </a>\n";
                first = false;
            }
            page << "</div>\n";
        }

        page << ArcadeFoot();

        return HttpResponse::HTML(page.str());
    }

    HttpResponse ServeValidatorsPage() {
        bool sys_active = false;
        double total_staked = 0.0;
        double min_stake = (double)MIN_VALIDATOR_STAKE / VELD_UNITS;
        size_t val_count = 0;
        struct VInfo { std::string address; std::string pubkey; uint64_t reg_height = 0; double staked = 0.0; };
        std::vector<VInfo> vlist;

        if (rpc_delegate_) {
            auto resp = rpc_delegate_->Handle(R"({"jsonrpc":"2.0","id":"1","method":"getvalidators","params":[]})");
            if (resp.find("\"system_active\":true") != std::string::npos) sys_active = true;
            {   auto p = resp.find("\"total_staked_veld\":");
                if (p != std::string::npos) { auto s = p + 20; auto e = resp.find_first_of(",}", s); try { total_staked = std::stod(resp.substr(s, e-s)); } catch (...) {} }
            }
            {   auto p = resp.find("\"min_stake_veld\":");
                if (p != std::string::npos) { auto s = p + 17; auto e = resp.find_first_of(",}", s); try { min_stake = std::stod(resp.substr(s, e-s)); } catch (...) {} }
            }
            {   auto p = resp.find("\"validator_count\":");
                if (p != std::string::npos) { auto s = p + 18; auto e = resp.find_first_of(",}", s); try { val_count = (size_t)std::stoull(resp.substr(s, e-s)); } catch (...) {} }
            }
            auto arr_start = resp.find("\"validators\":[");
            if (arr_start != std::string::npos) {
                size_t pos = arr_start + 14;
                while (pos < resp.size()) {
                    auto obj_start = resp.find('{', pos);
                    if (obj_start == std::string::npos) break;
                    auto obj_end = resp.find('}', obj_start);
                    if (obj_end == std::string::npos) break;
                    std::string obj = resp.substr(obj_start, obj_end - obj_start + 1);
                    VInfo vi;
                    { auto p2 = obj.find("\"pubkey\":\""); if (p2 != std::string::npos) { auto s = p2+10; auto e = obj.find('"', s); vi.pubkey = obj.substr(s, e-s); } }
                    { auto p2 = obj.find("\"address\":\""); if (p2 != std::string::npos) { auto s = p2+11; auto e = obj.find('"', s); vi.address = obj.substr(s, e-s); } }
                    if (!vi.address.empty() && !IsStrictBase58Address(vi.address)) {
                        std::cerr << "[explorer] dropping validator row with non-base58 address: "
                                  << vi.address.substr(0, 64) << "\n";
                        pos = obj_end + 1;
                        continue;
                    }
                    { auto p2 = obj.find("\"registered_height\":"); if (p2 != std::string::npos) { auto s = p2+20; auto e = obj.find_first_of(",}", s); try { vi.reg_height = std::stoull(obj.substr(s, e-s)); } catch (...) { vi.reg_height = 0; } } }
                    { auto p2 = obj.find("\"staked_veld\":"); if (p2 != std::string::npos) {
                        bool is_total = (p2 >= 6 && obj.substr(p2 - 6, 6) == "total_");
                        if (!is_total) {
                            auto s = p2+14; auto e = obj.find_first_of(",} \t\r\n", s);
                            std::string val_str = obj.substr(s, e-s);
                            try { vi.staked = std::stod(val_str); } catch (...) { vi.staked = 0.0; }
                        }
                    } }
                    if (vi.staked <= 0.0 && !vi.address.empty() && rpc_delegate_) {
                        std::string esc_addr = HttpResponse::JsonEscape(vi.address);
                        auto sr = rpc_delegate_->Handle("{\"jsonrpc\":\"2.0\",\"id\":\"1\","
                            "\"method\":\"getstake\",\"params\":[\"" + esc_addr + "\"]}");
                        auto ri = sr.find("\"staked_veld\":");
                        if (ri != std::string::npos) {
                            auto s = ri + 14; auto e = sr.find_first_of(",} \t\r\n", s);
                            try { vi.staked = std::stod(sr.substr(s, e-s)); } catch (...) {}
                        }
                    }
                    if (!vi.address.empty()) vlist.push_back(vi);
                    pos = obj_end + 1;
                }
            }
        } else if (validators_) {
            sys_active = validators_->IsValidatorSystemActive();
            val_count = validators_->GetActiveValidatorCount();
            auto records = validators_->GetValidators();
            for (auto& r : records) {
                VInfo vi;
                vi.address = r.address;
                vi.pubkey = r.pubkey_hex;
                vi.reg_height = r.registered_height;
                vi.staked = 0.0;
                vlist.push_back(vi);
            }
        }

        // ALWAYS recompute total_staked as the sum of actual validator
        // stake amounts. The "total_staked_veld" field in getvalidators
        // is the NETWORK-WIDE total stake (all stakers, validator or
        // not), which is misleading on this page. Stakers who are NOT
        // registered validators should not contribute to "Validator
        // Stake" shown here. Fixes user report:
        //   "it shows how much is staked from validators but the card
        //    only says 'total staked' which is a different amount that
        //    whats actually staked since its showing total staked
        //    amount of validators across network"
        double network_total_staked = total_staked;
        total_staked = 0.0;
        for (auto& v : vlist) total_staked += v.staked;

        std::ostringstream page;
        page << std::fixed << std::setprecision(2);

        page << "<div class=\"stat-grid\" style=\"margin-bottom:20px\">";
        page << "<div class=\"stat\"><div class=\"stat-label\">System Status</div><div class=\"stat-value " << (sys_active ? "em" : "") << "\">"
             << (sys_active ? "Active" : "Locked") << "</div><div class=\"stat-sub\">";
        if (sys_active) {
            page << "Validators are endorsing blocks";
        } else {
            page << "Needs " << std::fixed << std::setprecision(0)
                 << ((double)VALIDATOR_UNLOCK_STAKED / (double)VELD_UNITS)
                 << " VELD staked to unlock";
        }
        page << "</div></div>";
        (void)total_staked;  // Validator Stake box removed (operator-directed) -- irrelevant on the validator page
        page << "<div class=\"stat\"><div class=\"stat-label\">Validators</div><div class=\"stat-value em\">" << val_count << "</div></div>";
        {
            double live_min_validator =
                (double)MIN_VALIDATOR_STAKE / (double)VELD_UNITS;
            page << "<div class=\"stat\"><div class=\"stat-label\">Min Stake to Register</div>"
                 << "<div class=\"stat-value\">" << std::fixed << std::setprecision(0)
                 << live_min_validator << " VELD</div>"
                 << "<div class=\"stat-sub\">required validator bond</div></div>";
        }
        {
            auto ep_script = AddressToScript(ENDORSEMENT_POOL_ADDRESS);
            double ep_bal = 0;
            if (!ep_script.empty()) {
                auto utxos = chain_.GetUTXOsForScript(ep_script);
                for (auto& u : utxos) ep_bal += (double)u.value / VELD_UNITS;
            }
            page << "<div class=\"stat\"><div class=\"stat-label\">Validator Pool</div><div class=\"stat-value gold\">"
                 << std::fixed << std::setprecision(2) << ep_bal << " VELD</div>"
                 << "<div class=\"stat-sub\">accumulated</div></div>";
        }
        page << "<div class=\"stat\"><div class=\"stat-label\">Reward Distribution</div><div class=\"stat-value\">Every "
             << VAULT_DISTRIBUTION_INTERVAL << " blocks</div><div class=\"stat-sub\">~"
             << (VAULT_DISTRIBUTION_INTERVAL * TARGET_BLOCK_TIME / 60) << " min between distributions</div></div>";
        {
            uint64_t height = BestKnownHeight();
            uint64_t next_dist = ((height / VAULT_DISTRIBUTION_INTERVAL) + 1) * VAULT_DISTRIBUTION_INTERVAL;
            uint64_t remaining = next_dist - height;
            uint64_t mins = (remaining * TARGET_BLOCK_TIME + 30) / 60;
            page << "<div class=\"stat\"><div class=\"stat-label\">Next Distribution</div>"
                 << "<div class=\"stat-value em\">~Block " << next_dist << "</div>"
                 << "<div class=\"stat-sub\">" << remaining << " blocks (~" << mins << " min)</div></div>";
        }
        page << "</div>";

        page << "<div class=\"card\" style=\"margin-bottom:16px\">";
        page << "<div class=\"card-title\">Validator Rewards</div>";
        page << "<p style=\"color:var(--text);font-size:13px;line-height:1.6\">"
             << "Active validators earn from a shared validator pool funded by <span style=\"color:var(--gold);font-weight:600\">10% of every block&#39;s coinbase</span>. "
             << "The pool is flushed every 480 blocks and split proportionally by each validator&#39;s endorsement count over the last 480 blocks.</p>";
        page << "</div>";

        {
            std::string r;
            if (rpc_delegate_)
                r = rpc_delegate_->Handle(
                    R"({"jsonrpc":"2.0","id":"1","method":"getbondvaultinfo","params":[]})");
            auto num = [&](const std::string& key) -> double {
                auto p = r.find(key); if (p == std::string::npos) return 0.0;
                auto s = p + key.size(); auto e = r.find_first_of(",}", s);
                try { return std::stod(r.substr(s, e - s)); } catch (...) { return 0.0; }
            };
            auto flag = [&](const std::string& key) -> bool {
                auto p = r.find(key); if (p == std::string::npos) return false;
                return r.compare(p + key.size(), 4, "true") == 0;
            };
            auto str = [&](const std::string& key) -> std::string {
                auto p = r.find(key); if (p == std::string::npos) return "";
                auto s = p + key.size();
                if (s < r.size() && r[s] == '"') s++;
                auto e = r.find('"', s);
                return (e == std::string::npos) ? "" : r.substr(s, e - s);
            };
            double   custodied = num("\"custodied_principal_veld\":");
            double   escrow_bal= num("\"escrow_balance_veld\":");
            double   gross_acc = num("\"escrow_gross_accrued_veld\":");
            uint64_t act_h     = (uint64_t)num("\"yield_escrow_activation_height\":");
            bool     act       = flag("\"yield_escrow_activated\":");
            uint64_t b_until   = (uint64_t)num("\"blocks_until_activation\":");
            uint64_t since_h   = (uint64_t)num("\"custody_active_since_height\":");
            uint64_t vest_blk  = (uint64_t)num("\"vest_horizon_blocks\":");
            uint64_t cust_n    = (uint64_t)num("\"custodial_validator_count\":");
            std::string cust_addr = str("\"stake_vault_address\":");
            std::string esc_addr  = str("\"bond_yield_escrow_address\":");
            if (cust_addr.empty() || !IsStrictBase58Address(cust_addr)) cust_addr = "";
            if (esc_addr.empty()  || !IsStrictBase58Address(esc_addr))  esc_addr  = "";
            uint64_t vest_days = (vest_blk * (uint64_t)TARGET_BLOCK_TIME) / 86400;

            page << "<div class=\"card\" style=\"margin-bottom:16px\">";
            page << "<div class=\"card-title\">Validator Bond Custody &amp; Yield Escrow</div>";
            page << "<div class=\"stat-grid\" style=\"margin-bottom:14px\">";
            page << "<div class=\"stat\"><div class=\"stat-label\">Custody Vault (bonded principal)</div>"
                 << "<div class=\"stat-value gold\">" << std::fixed << std::setprecision(2)
                 << custodied << " VELD</div><div class=\"stat-sub\">slashable &middot; live since block "
                 << since_h << "</div></div>";
            page << "<div class=\"stat\"><div class=\"stat-label\">Yield Escrow Vault</div>"
                 << "<div class=\"stat-value em\">" << std::fixed << std::setprecision(2)
                 << escrow_bal << " VELD</div><div class=\"stat-sub\">"
                 << (act ? std::string("active &middot; vesting")
                         : ("activates at block " + std::to_string(act_h)))
                 << "</div></div>";
            if (!act) {
                page << "<div class=\"stat\"><div class=\"stat-label\">Escrow Activation</div>"
                     << "<div class=\"stat-value\">~Block " << act_h << "</div>"
                     << "<div class=\"stat-sub\">" << b_until << " blocks away</div></div>";
            } else {
                double avg_bond = (cust_n > 0) ? (custodied / (double)cust_n) : 0.0;
                page << "<div class=\"stat\"><div class=\"stat-label\">Avg Bond / Validator</div>"
                     << "<div class=\"stat-value\">" << std::fixed << std::setprecision(2)
                     << avg_bond << " VELD</div><div class=\"stat-sub\">per custodial validator</div></div>";
            }
            page << "<div class=\"stat\"><div class=\"stat-label\">Active Bonds</div>"
                 << "<div class=\"stat-value\">" << cust_n
                 << "</div><div class=\"stat-sub\">custodial validators</div></div>";
            page << "</div>";
            (void)vest_days;
            if (!cust_addr.empty() || !esc_addr.empty()) {
                page << "<div style=\"font-size:11px;color:var(--muted);border-top:1px solid var(--b1);"
                        "padding-top:10px;line-height:1.7;word-break:break-all\">";
                if (!cust_addr.empty())
                    page << "Custody vault: <span style=\"color:var(--text);font-family:monospace\">"
                         << cust_addr << "</span><br>";
                if (!esc_addr.empty())
                    page << "Yield escrow: <span style=\"color:var(--text);font-family:monospace\">"
                         << esc_addr << "</span>";
                page << "</div>";
            }
            page << "</div>";
        }

        uint64_t _tip_h = chain_.Height();
        uint64_t _win_start = _tip_h > VAULT_DISTRIBUTION_INTERVAL
                            ? _tip_h - VAULT_DISTRIBUTION_INTERVAL + 1 : 1;
        std::unordered_map<std::string, uint64_t> recent_endorse_count;
        if (validators_) {
            for (uint64_t h = _win_start; h <= _tip_h; ++h) {
                auto endorsements = validators_->GetEndorsements(h);
                for (const auto& e : endorsements)
                    if (!e.pubkey_hex.empty()) recent_endorse_count[e.pubkey_hex]++;
            }
        }

        struct BondRec { double bond = 0.0; bool custodial = false; bool slashed = false; };
        std::unordered_map<std::string, BondRec> bond_by_addr;
        if (rpc_delegate_) {
            auto bvr = rpc_delegate_->Handle(
                R"({"jsonrpc":"2.0","id":"1","method":"getbondvaultinfo","params":[]})");
            auto va = bvr.find("\"validators\":[");
            if (va != std::string::npos) {
                size_t p = va + 14;
                while (p < bvr.size()) {
                    auto os = bvr.find('{', p);
                    if (os == std::string::npos) break;
                    auto oe = bvr.find('}', os);
                    if (oe == std::string::npos) break;
                    std::string o = bvr.substr(os, oe - os + 1);
                    std::string a;
                    { auto k = o.find("\"address\":\"");
                      if (k != std::string::npos) { auto s = k + 11; auto e = o.find('"', s); if (e != std::string::npos) a = o.substr(s, e - s); } }
                    if (!a.empty() && IsStrictBase58Address(a)) {
                        BondRec br;
                        { auto k = o.find("\"bond_veld\":");
                          if (k != std::string::npos) { auto s = k + 12; auto e = o.find_first_of(",}", s);
                            try { br.bond = std::stod(o.substr(s, e - s)); } catch (...) {} } }
                        br.custodial = (o.find("\"bond_custodial\":true") != std::string::npos);
                        br.slashed   = (o.find("\"slashed\":true") != std::string::npos);
                        bond_by_addr[a] = br;
                    }
                    p = oe + 1;
                }
            }
        }

        page << "<div class=\"card\" style=\"padding:14px 18px\">";
        page << "<div class=\"card-header\" style=\"display:flex;align-items:baseline;justify-content:space-between;padding:6px 4px 4px\">";
        page << "<div class=\"card-title\" style=\"margin:0\">Registered validators</div>";
        page << "<span style=\"font-size:11px;color:var(--muted);font-weight:600\">last " << VAULT_DISTRIBUTION_INTERVAL << "-block window</span>";
        page << "</div>";
        page << "<div class=\"row-list\" id=\"val-rows\">";

        int rank = 1;
        for (auto& v : vlist) {
            if (!IsStrictBase58Address(v.address)) {
                std::cerr << "[explorer] skipping validator row with non-base58 address: "
                          << v.address.substr(0, 64) << "\n";
                ++rank;
                continue;
            }
            std::string pk_short = v.pubkey.size() > 16 ? v.pubkey.substr(0, 10) + "..." + v.pubkey.substr(v.pubkey.size() - 6) : v.pubkey;
            std::string addr_short = v.address.substr(0, 12) + "&hellip;" + v.address.substr(v.address.size() - 6);
            int tier_level = 0;
            if (tiers_ && !v.address.empty()) {
                auto addr_script = AddressToScript(v.address);
                if (!addr_script.empty()) {
                    auto ti = tiers_->GetTier(BytesToHex(addr_script));
                    tier_level = ti.level;
                }
            }
            uint64_t ec = recent_endorse_count.count(v.pubkey) ? recent_endorse_count[v.pubkey] : 0;
            page << "<a class=\"rl-row\" href=\"/address/" << v.address << "\" style=\"text-decoration:none\">";
            page << "<div class=\"rl-ic ic-h\" style=\"font-size:13px\">" << rank << "</div>";
            page << "<div class=\"rl-info\">";
            page << "<div class=\"rl-name\">" << addr_short;
            if (tier_level >= 5) page << " &nbsp;<span class=\"diamond-badge\" style=\"font-size:9.5px\">\xe2\x97\x86\xef\xb8\x8e DIAMOND</span>";
            page << "</div>";
            page << "<div class=\"rl-sub\" style=\"font-family:'JetBrains Mono',monospace;font-size:11.5px\">"
                 << "pk " << pk_short << " &middot; reg h=" << v.reg_height
                 << " &middot; <span style=\"color:" << (ec > 0 ? "var(--em)" : "var(--muted2)") << ";font-weight:600\">"
                 << ec << " endorsements</span></div>";
            page << "</div>";
            BondRec br;
            { auto bi = bond_by_addr.find(v.address); if (bi != bond_by_addr.end()) br = bi->second; }
            const char* bond_color = br.slashed ? "var(--red)" : "var(--gold)";
            const char* bond_label = br.slashed ? "SLASHED" : "VELD BOND";
            page << "<div class=\"rl-val\">";
            page << "<div class=\"rl-v\" style=\"color:" << bond_color << ";font-size:16px\">" << std::fixed << std::setprecision(2) << br.bond << "</div>";
            page << "<div class=\"rl-vs\">" << bond_label << "</div>";
            page << "</div>";
            page << "</a>";
            ++rank;
        }
        if (vlist.empty())
            page << "<div class=\"rl-row\" style=\"color:var(--muted);justify-content:center;font-style:italic\">No validators registered yet.</div>";
        page << "</div>";
        page << "<div id=\"val-pager\" style=\"display:flex;justify-content:space-between;align-items:center;margin-top:14px;font-size:12px;color:var(--muted)\"></div>";
        page << "</div>";
        page << "<script nonce=\"__CSP_NONCE__\">(function(){"
                "var c=document.getElementById('val-rows');if(!c)return;"
                "var rows=[].slice.call(c.querySelectorAll('.rl-row'));"
                "var PG=10,pg=1,tp=Math.max(1,Math.ceil(rows.length/PG));"
                "var pager=document.getElementById('val-pager');"
                "function show(p){if(p<1)p=1;if(p>tp)p=tp;pg=p;"
                "var s=(p-1)*PG,e=Math.min(rows.length,s+PG);"
                "for(var i=0;i<rows.length;i++){rows[i].style.display=(i>=s&&i<e)?'':'none';}"
                "if(!pager)return;if(tp<=1){pager.innerHTML='';return;}"
                "var pd=pg<=1,nd=pg>=tp;"
                "var be='background:none;border:1px solid var(--b1);color:var(--text);padding:6px 14px;border-radius:6px;cursor:pointer;font-family:inherit';"
                "var bx='background:none;border:1px solid var(--b1);color:var(--muted);padding:6px 14px;border-radius:6px;opacity:.4;cursor:not-allowed;font-family:inherit';"
                "pager.innerHTML='<button id=\\'vpp\\' '+(pd?'disabled ':'')+'style=\\''+(pd?bx:be)+'\\'>&laquo; Prev</button>'"
                "+'<span>'+(s+1)+'&ndash;'+e+' of '+rows.length+' &middot; page '+pg+'/'+tp+'</span>'"
                "+'<button id=\\'vpn\\' '+(nd?'disabled ':'')+'style=\\''+(nd?bx:be)+'\\'>Next &raquo;</button>';"
                "var a=document.getElementById('vpp');if(a)a.onclick=function(){show(pg-1);};"
                "var b=document.getElementById('vpn');if(b)b.onclick=function(){show(pg+1);};}"
                "show(1);})();</script>";

        return HttpResponse::HTML(HtmlWrapArcade("Validators", page.str(), "validators"));
    }

    HttpResponse ServeBlocksPage() {
        std::ostringstream page;
        page << ArcadeHead("Veld &middot; Blocks");
        page << ArcadePrimaryTabs("blocks");

        page << R"HTML(<h3 style="margin-top:18px">All blocks <span class="ct" id="page-info">&hellip;</span></h3>

<div style="display:flex;gap:8px;margin-bottom:14px;align-items:center">
  <input type="number" id="jump-height" class="search" placeholder="Jump to height" style="flex:1">
  <button id="jump-go" class="btn">Go</button>
</div>

<div id="blocks-error" role="status" style="display:none;margin-bottom:12px;padding:10px 12px;border:1px solid var(--gold);border-radius:6px;color:var(--gold);font-size:12px"></div>

<div id="blocks-container" class="list">)HTML";
        // 25 skeleton rows (same .bk height as real rows) so the page is already
        // full-height while loading — the real 25 rows swap in 1:1 with NO height
        // jump, so the sticky bottom nav has nothing to bounce against on load.
        for (int i = 0; i < 25; i++) page << "<div class=\"bk\" aria-hidden=\"true\" style=\"opacity:.5;pointer-events:none\"><div class=\"ic\"></div><div class=\"info\"><div class=\"h\"><span style=\"display:inline-block;height:11px;width:84px;background:var(--s3);border-radius:3px\"></span></div><div class=\"s\"><span style=\"display:inline-block;height:9px;width:150px;background:var(--s3);border-radius:3px;margin-top:6px\"></span></div></div><div class=\"right\"><span style=\"display:inline-block;height:9px;width:38px;background:var(--s3);border-radius:3px\"></span><span style=\"display:inline-block;height:9px;width:66px;background:var(--s3);border-radius:3px;margin-top:6px\"></span></div></div>";
        page << R"HTML(</div>

<div style="display:flex;justify-content:space-between;align-items:center;margin-top:16px;gap:8px;flex-wrap:wrap">
  <button id="prev-btn" class="btn" disabled>&larr; Older</button>
  <span id="page-count" style="font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--fg3);letter-spacing:.04em">Page 1</span>
  <button id="next-btn" class="btn" disabled>Newer &rarr;</button>
</div>
)HTML";

        page << ArcadeFoot();

        page << R"HTML(<script nonce="__CSP_NONCE__">
var curPage=0,pageSize=25,tipHeight=null,tipHash='',loading=false,retryTimer=null;
function fmt(n,d){return parseFloat(n||0).toFixed(d!==undefined?d:2);}
function shortHash(h){return h?h.slice(0,8)+'…'+h.slice(-6):'—';}
function shortAddr(a){return a?a.slice(0,6)+'…'+a.slice(-4):'—';}
function ago(t){var s=Math.floor(Date.now()/1000)-(t||0);if(s<0)s=0;if(s<60)return s+' s';if(s<3600)return Math.floor(s/60)+' m';if(s<86400)return Math.floor(s/3600)+' h';return Math.floor(s/86400)+' d';}
function fetchJSON(url){
  return fetch(url,{cache:'no-store'}).then(function(r){
    if(!r.ok){var e=new Error('HTTP '+r.status);e.status=r.status;throw e;}
    return r.json();
  });
}
function loadPage(){
  if(loading)return;
  loading=true;
  var prev=document.getElementById('prev-btn'),next=document.getElementById('next-btn');
  prev.disabled=true;next.disabled=true;
  var requestedStart=(curPage===0||tipHeight===null)?'latest':String(Math.max(0,tipHeight-curPage*pageSize));
  fetchJSON('/api/v1/blocks/'+requestedStart+'/'+pageSize).then(function(d){
      if(!d||!Number.isSafeInteger(d.tip_height)||d.tip_height<0||
          typeof d.tip_hash!=='string'||!/^[0-9a-f]{64}$/.test(d.tip_hash)||
          !Number.isSafeInteger(d.start)||!Number.isSafeInteger(d.end)||
          d.start<d.end||!Array.isArray(d.blocks)||
          d.blocks.length!==d.start-d.end+1){
        throw new Error('invalid block-history response');
      }
      for(var vi=0;vi<d.blocks.length;vi++){
        var vb=d.blocks[vi];
        if(!vb||vb.height!==d.start-vi||typeof vb.hash!=='string'||
            !/^[0-9a-f]{64}$/.test(vb.hash)){
          throw new Error('invalid block-history row');
        }
      }
      if(curPage===0){tipHeight=d.tip_height;tipHash=d.tip_hash;}
      var shownTip=(tipHeight===null)?d.tip_height:tipHeight;
      document.getElementById('page-info').textContent=d.end.toLocaleString()+' – '+d.start.toLocaleString()+' of '+shownTip.toLocaleString();
      document.getElementById('page-count').textContent='Page '+(curPage+1);
      next.disabled=(curPage===0);
      prev.disabled=(d.end===0);
      var bs=d.blocks;
      var html='';
      bs.forEach(function(b){
        var tx=b.tx_count||b.ntx||0;
        var size=b.size_kb||Math.round((b.size||0)/102.4)/10;
        var reward=b.reward_veld?fmt(b.reward_veld,2):'—';
        var fee=b.fee_total_veld?fmt(b.fee_total_veld,4):'';
        var isFresh=(curPage===0&&b.height===d.tip_height);
        html+='<a class="bk'+(isFresh?' fresh':'')+'" href="/block/height/'+b.height+'">'+
          '<div class="ic">'+(Math.floor(b.height/1000))+'k</div>'+
          '<div class="info"><div class="h">#'+b.height.toLocaleString()+'</div>'+
          '<div class="s">'+shortHash(b.hash)+(b.miner?' · '+shortAddr(b.miner):'')+'</div></div>'+
          '<div class="right"><div class="ago">'+ago(b.time)+'</div>'+
          '<div class="tx">'+tx+' tx · '+size+' KB</div></div>'+
          '</a>';
      });
      var c=document.getElementById('blocks-container');
      if(c)c.innerHTML=html;
      var err=document.getElementById('blocks-error');err.style.display='none';err.textContent='';
      loading=false;
    }).catch(function(e){
      loading=false;
      next.disabled=(curPage===0);
      prev.disabled=false;
      var err=document.getElementById('blocks-error');
      err.textContent='Block history could not refresh. The last verified page is still shown; retrying.';
      err.style.display='block';
      if(e&&e.status===409){curPage=0;tipHeight=null;tipHash='';}
      clearTimeout(retryTimer);retryTimer=setTimeout(loadPage,1000);
  });
}
document.getElementById('prev-btn').addEventListener('click',function(){curPage++;loadPage();});
document.getElementById('next-btn').addEventListener('click',function(){if(curPage>0){curPage--;loadPage();}});
function jumpHeight(){
  var text=document.getElementById('jump-height').value.trim();
  if(!/^\d+$/.test(text))return;
  var h=Number(text);if(!Number.isSafeInteger(h))return;
  function jump(){
    curPage=Math.floor((tipHeight-h)/pageSize);
    if(curPage<0)curPage=0;
    loadPage();
  }
  if(tipHeight!==null){jump();return;}
  fetchJSON('/api/v1/blocks/latest/1').then(function(d){
    if(!d||!Number.isSafeInteger(d.tip_height)||typeof d.tip_hash!=='string')return;
    tipHeight=d.tip_height;tipHash=d.tip_hash;jump();
  }).catch(function(){});
}
document.getElementById('jump-go').addEventListener('click',jumpHeight);
document.getElementById('jump-height').addEventListener('keydown',function(e){if(e.key==='Enter')jumpHeight();});
loadPage();
setInterval(function(){if(curPage===0)loadPage();},15000);
</script>
)HTML";

        return HttpResponse::HTML(page.str());
    }

    HttpResponse ServeWallet() {
        std::ostringstream c;
        c << R"HTML(
<style>
.fi{width:100%;background:#1a1a1a;border:1px solid #333;color:#e0e0e0;padding:10px 14px;border-radius:6px;font-size:14px;font-family:monospace;outline:none;margin-bottom:12px;}
.fi:focus{border-color:#c9a84c;}
.btn{background:#c9a84c;color:#000;border:none;padding:10px 24px;border-radius:6px;cursor:pointer;font-weight:bold;font-size:14px;}
.btn:hover{background:#dbb855;}
.res{margin-top:16px;padding:16px;background:#1a1a1a;border-radius:6px;border:1px solid #333;display:none;}
.err{border-color:#e05252;color:#e05252;}
.ok{border-color:#3dba6f;color:#3dba6f;}
</style>
<div class="card">
<h2>Check Balance</h2>
<input class="fi" id="addr" placeholder="V... (your Veld address)">
<br><button class="btn" data-act-click="e8162979f">Check Balance</button>
<div class="res" id="bal-res"></div>
</div>
<div class="card">
<h2>List UTXOs</h2>
<input class="fi" id="utxo-addr" placeholder="V... (your Veld address)">
<br><button class="btn" data-act-click="e1b711487">List UTXOs</button>
<div id="utxo-res" style="margin-top:16px"></div>
</div>
<script nonce="__CSP_NONCE__">
function escHtml(s){var d=document.createElement('div');d.appendChild(document.createTextNode(s));return d.innerHTML;}
function checkBal(){
  var a=document.getElementById('addr').value.trim();
  if(!a)return;
  fetch('/api/balance?address='+encodeURIComponent(a))
    .then(function(r){return r.json();})
    .then(function(d){
      var el=document.getElementById('bal-res');
      el.style.display='block';
      if(d.error){el.className='res err';el.textContent='Error: '+d.error;return;}
      el.className='res ok';
      el.innerHTML='<span style="font-size:11px;color:#666;text-transform:uppercase;letter-spacing:1px">Balance</span><br>'
        +'<span style="font-size:28px;font-weight:bold;color:#c9a84c">'+parseFloat(d.balance).toFixed(2)+' VELD</span>'
        +'<br><span style="font-size:12px;color:#666">'+escHtml(a)+'</span>';
    }).catch(function(e){
      var el=document.getElementById('bal-res');
      el.style.display='block';el.className='res err';el.textContent='Could not connect to node.';
    });
}
function listUTXOs(){
  var a=document.getElementById('utxo-addr').value.trim();
  if(!a)return;
  fetch('/api/utxos?address='+encodeURIComponent(a))
    .then(function(r){return r.json();})
    .then(function(d){
      var el=document.getElementById('utxo-res');
      if(!d.utxos||!d.utxos.length){el.innerHTML='<div class="card">No UTXOs found.</div>';return;}
      var rows='';
      d.utxos.forEach(function(u){
        rows+='<tr><td class="hash">'+escHtml(u.txid.substr(0,16))+'...</td><td>'+u.vout+'</td>'
          +'<td style="color:#c9a84c">'+parseFloat(u.value).toFixed(2)+' VELD</td>'
          +'<td>'+u.confirmations+'</td></tr>';
      });
      el.innerHTML='<div class="card"><h2>UTXOs ('+d.utxos.length+')</h2>'
        +'<div class="tbl-scroll"><div class="tbl-scroll"><table class="tbl"><thead><tr><th>TXID</th><th>Index</th><th>Amount</th><th>Confirms</th></tr></thead>'
        +'<tbody>'+rows+'</tbody></table></div>';
    }).catch(function(){document.getElementById('utxo-res').innerHTML='<div class="card">Error loading UTXOs.</div>';});
}
</script>)HTML";
        return HttpResponse::HTML(HtmlWrapArcade("Wallet", c.str(), "wallet"));
    }

};

}
}
