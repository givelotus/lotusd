// Copyright (c) 2026 The Lotus developers
#include "avalanche_protocol.h"
#include <avalanche/validation.h>
#include <hash.h>
namespace lotus::v2::ava {
uint256 HelloDigest(const ::avalanche::Delegation &delegation, const ConnectionTranscript &t) {
    return (HashWriter{} << delegation.getId() << t.sender_nonce << t.receiver_nonce
            << t.sender_entropy << t.receiver_entropy).GetHash();
}
bool AuthenticateHello(const ::avalanche::Delegation &delegation, const SchnorrSig &signature,
                       const ConnectionTranscript &t, uint32_t max_elements,
                       AuthenticatedHello &out, std::string &error) {
    if (max_elements < 16 || max_elements > 1024) { error = "invalid-max-elements"; return false; }
    ::avalanche::DelegationState state;
    CPubKey key;
    if (!delegation.verify(state, key)) { error = state.GetRejectReason(); return false; }
    if (!key.VerifySchnorr(HelloDigest(delegation, t), signature)) {
        error = "invalid-hello-signature"; return false;
    }
    out = {delegation.getProofId(), key, max_elements}; error.clear(); return true;
}
uint256 ResponseDigest(const ::avalanche::Response &response) {
    return (HashWriter{} << response).GetHash();
}
bool AuthenticateResponse(const CPubKey &key, const SignedResponse &response, std::string &error) {
    if (!key.VerifySchnorr(ResponseDigest(response.response), response.signature)) {
        error = "invalid-response-signature"; return false;
    }
    error.clear(); return true;
}
}
