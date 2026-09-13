#!/usr/bin/env python3
"""Exercise the native status renderer with inert, current RPC responses."""

import os
import shlex
import subprocess
import tempfile
from pathlib import Path


root = Path(__file__).resolve().parents[1]
source = (root / 'src/veld-validator.cpp').read_text()


def section(begin, end):
    start = source.index(begin)
    return source[start:source.index(end, start)]


helpers = section('static const veld::btc_buy::JsonValue* strict_rpc_result(',
                  'static bool decode_lower_hex(')
helpers += section('static bool json_u64(', 'static bool json_string(')
renderer = section('static int cmd_status(', 'static std::string sign_block(')
program = r'''
#include "core/constants.h"
#include "network/strict_json.h"
#include <cmath>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace veld;
static const char* GRN="";
static const char* RED="";
static const char* YEL="";
static const char* CYN="";
static const char* RST="";
struct ValidatorKey { std::string address="Vfixture"; std::string pubkey_hex="fixture-key"; };
static std::map<std::string,std::string> replies;
static std::vector<std::string> calls;
static bool unavailable=false;
static void log(const char*, const std::string& message) { std::cout << message << '\n'; }
static std::string json_rpc(const std::string&, uint16_t, const std::string& method,
                            const std::string& params="[]") {
    calls.push_back(method);
    if (unavailable) throw std::runtime_error("Node unavailable");
    if (method=="getstake" && params!="[\"Vfixture\"]")
        throw std::runtime_error("Wrong wallet address");
    if (method=="getvalidatorinfo" && params!="[\"fixture-key\"]")
        throw std::runtime_error("Wrong validator identity");
    return replies.at(method);
}
'''
program += helpers + renderer
program += r'''
static unsigned checks=0;
static void require(bool value, const char* message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}
static std::string envelope(const std::string& result) {
    return "{\"jsonrpc\":\"2.0\",\"id\":\"val1\",\"error\":null,\"result\":"+result+"}";
}
static void normal() {
    calls.clear(); unavailable=false;
    replies={
        {"getblockchaininfo",envelope(R"({"blocks":6201,"supply_units":1750012345678})")},
        {"getvalidators",envelope(R"({"system_active":true,"unlock_threshold_veld":0.0,"total_staked_veld":500.0,"validator_count":1})")},
        {"getvalidatorinfo",envelope(R"({"registered":true})")},
        {"getstake",envelope(R"({"staked_veld":0.0})")}
    };
}
static std::pair<int,std::string> run() {
    std::ostringstream output;
    auto* previous=std::cout.rdbuf(output.rdbuf());
    const int status=cmd_status("127.0.0.1",8334,ValidatorKey{});
    std::cout.rdbuf(previous);
    return {status,output.str()};
}
int main() {
    normal(); auto current=run();
    require(current.first==0,"Normal registered status failed");
    require(current.second.find("Supply:            17500.12 VELD")!=std::string::npos,"Supply field mismatch");
    require(current.second.find("Wallet stake:      0.00 VELD")!=std::string::npos,"Real zero stake is missing");
    require(current.second.find("Bond minimum:      10000 VELD")!=std::string::npos,"Separate bond minimum missing");
    require(current.second.find("below 10,000")==std::string::npos,"Stake was mistaken for bond funding");
    require(current.second.find("Network floor at tip")==std::string::npos,"Removed network floor still displayed");
    require(calls==std::vector<std::string>{"getblockchaininfo","getvalidators","getvalidatorinfo","getstake"},"Unexpected RPC contract");

    normal(); replies["getstake"]=envelope(R"({"staked_veld":500.0})");
    auto staked=run();
    require(staked.first==0 && staked.second.find("Wallet stake:      500.00 VELD")!=std::string::npos,"Current wallet stake was not shown");

    normal(); replies["getvalidators"]=envelope(R"({"system_active":false,"unlock_threshold_veld":10000.0,"total_staked_veld":500.0,"validator_count":0})");
    replies["getvalidatorinfo"]=envelope(R"({"registered":false})");
    auto prior=run();
    require(prior.first==0 && prior.second.find("Network floor at tip: 10000.00 VELD")!=std::string::npos,"Pre-activation floor is missing");
    require(prior.second.find("NOT REGISTERED")!=std::string::npos,"Registration state mismatch");

    normal(); replies["getvalidators"]=envelope(R"({"system_active":false,"existing_operations_active":true,"unlock_threshold_veld":10000.0,"total_staked_veld":500.0,"validator_count":1})");
    auto existing=run();
    require(existing.first==0 && existing.second.find("Validator operations: ACTIVE")!=std::string::npos,"Existing operations were incorrectly paused");
    require(existing.second.find("Registration at tip: PAUSED")!=std::string::npos,"Registration state lost its tip scope");

    for (unsigned height : {6198u,6199u,6200u}) {
        normal();
        replies["getblockchaininfo"]=envelope("{\"blocks\":"+std::to_string(height)+",\"supply_units\":1750012345678}");
        if (height<6200)
            replies["getvalidators"]=envelope(R"({"system_active":false,"existing_operations_active":true,"unlock_threshold_veld":10000.0,"total_staked_veld":500.0,"validator_count":1})");
        auto boundary=run();
        require(boundary.first==0 && boundary.second.find("Registration at tip:")!=std::string::npos,"Policy lost its current-tip label");
        require((boundary.second.find("Network floor at tip:")!=std::string::npos)==(height<6200),"Node-reported floor was overridden");
    }
    normal();
    replies["getvalidators"]=envelope(R"({"system_active":false,"existing_operations_active":true,"unlock_threshold_veld":10000.0,"total_staked_veld":500.0,"validator_count":1})");
    auto older=run();
    require(older.first==0 && older.second.find("Network floor at tip: 10000.00 VELD")!=std::string::npos,"Older node policy was replaced by the client fork constant");

    normal(); replies["getstake"]=R"({"jsonrpc":"2.0","result":null,"error":{"code":-28,"message":"Node warming up"}})";
    auto waiting=run();
    require(waiting.first==1 && waiting.second.find("Validator status unavailable")!=std::string::npos,"Unavailable RPC did not fail clearly");
    require(waiting.second.find("Wallet stake:")==std::string::npos,"Unavailable stake was converted to zero");

    normal(); replies["getstake"]=envelope("{}");
    auto missing=run();
    require(missing.first==1 && missing.second.find("Wallet stake:")==std::string::npos,"Missing stake was converted to zero");

    normal(); unavailable=true; auto offline=run();
    require(offline.first==1 && offline.second.find("Node unavailable")!=std::string::npos,"Offline node did not report unavailable");
    std::cout << "PASS validator_status_contract_tests checks=" << checks << '\n';
}
'''
with tempfile.TemporaryDirectory(prefix='veld-validator-status-') as directory:
    build = Path(directory)
    fixture = build / 'status.cpp'
    fixture.write_text(program)
    binary = build / ('status.exe' if os.name == 'nt' else 'status')
    compiler = shlex.split(os.environ.get('CXX', 'c++'))
    subprocess.run(compiler + ['-std=c++20', '-O2', '-DVELD_MAINNET_POW',
                               '-DVELD_PUBLIC_RELEASE', '-DVELD_PUBLIC_MAINNET',
                               '-I', str(root / 'include'), str(fixture), '-o', str(binary)],
                   check=True, timeout=120)
    subprocess.run([str(binary)], check=True, timeout=15)
