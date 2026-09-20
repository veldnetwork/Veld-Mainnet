#pragma once

#include <exception>
#include <string>
#include <string_view>

namespace veld::pool {
enum class ClientStage { Configuration, Registration, Work, Hashing, Submission, Balance, State };
inline const char* StageName(ClientStage stage) noexcept {
    switch(stage) {
    case ClientStage::Configuration:return "configuration";
    case ClientStage::Registration:return "registration";
    case ClientStage::Work:return "work";
    case ClientStage::Hashing:return "hashing";
    case ClientStage::Submission:return "submission";
    case ClientStage::Balance:return "balance";
    case ClientStage::State:return "state";
    }
    return "unknown";
}
struct ClientFailure { const char* code; const char* message; };
// Both inputs and outputs are exact, fixed categories. Never persist error.what(),
// URLs, HTTP bodies, credentials, or remote messages in a diagnostic/status file.
inline ClientFailure FailureFromCode(std::string_view code) noexcept {
    if(code=="certificate")return {"certificate","Pool certificate verification failed"};
    if(code=="trust_store")return {"trust_store","Pool trust configuration unavailable"};
    if(code=="remote_refusal")return {"remote_refusal","Pool service refused the request"};
    if(code=="http_response")return {"http_response","Pool returned an invalid HTTP response"};
    if(code=="response_schema")return {"response_schema","Pool returned invalid response data"};
    if(code=="work_identity")return {"work_identity","Pool supplied invalid work or chain identity"};
    if(code=="account_identity")return {"account_identity","Pool account identity does not match"};
    if(code=="private_state")return {"private_state","Private pool state is unavailable"};
    return {"local_failure","Pool worker stopped after a local or unclassified failure"};
}
inline ClientFailure ClassifyFailure(const std::exception& error) noexcept {
    const std::string_view message(error.what());
    if(message=="pool certificate verification failed" || message=="pool certificate missing")
        return FailureFromCode("certificate");
    if(message=="pool CA unavailable" || message=="Windows trust store unavailable" ||
       message=="Windows trust store has no usable roots")return FailureFromCode("trust_store");
    if(message=="pool refused request")return FailureFromCode("remote_refusal");
    for(const auto value:{"pool response bound","pool HTTP header bound","pool HTTP status",
            "pool HTTP status framing","pool HTTP status line","pool HTTP header framing",
            "pool HTTP header name","duplicate pool HTTP header","pool HTTP response schema",
            "empty pool response","trailing pool response bytes"})
        if(message==value)return FailureFromCode("http_response");
    for(const auto value:{"missing pool field","pool string required","pool integer encoding",
            "pool JSON response","pool hex encoding","pool response status","pool result schema",
            "pool submission status"})
        if(message==value)return FailureFromCode("response_schema");
    for(const auto value:{"pool job network or version mismatch","unsupported pool version",
            "zero pool accounting target","pool nonce range overflow","pool header encoding",
            "pool network target","pool configuration is for a different compiled chain"})
        if(message==value)return FailureFromCode("work_identity");
    if(message=="pool balance identity" || message=="saved pool account does not match configuration")
        return FailureFromCode("account_identity");
    if(message=="private pool state write failed" || message=="private pool state directory required" ||
       message=="private pool configuration unavailable")return FailureFromCode("private_state");
    return FailureFromCode("local_failure");
}
inline std::string FailureSummary(std::string_view code,std::string_view stage) {
    std::string result=FailureFromCode(code).message;
    for(const auto value:{ClientStage::Configuration,ClientStage::Registration,ClientStage::Work,
                         ClientStage::Hashing,ClientStage::Submission,ClientStage::Balance,ClientStage::State})
        if(stage==StageName(value))return result+" ("+StageName(value)+").";
    return result+".";
}
} // namespace veld::pool
