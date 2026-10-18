// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_AVALANCHE_PROTOCOL_H
#define LOTUS_V2_AVALANCHE_PROTOCOL_H
#include <avalanche/delegation.h>
#include <nodeid.h>
#include <avalanche/protocol.h>
#include "avalanche_proof.h"
namespace lotus::v2::ava {
constexpr uint64_t REQUIRED_CAPABILITY = 16;
struct ConnectionTranscript {
    uint64_t sender_nonce{}, receiver_nonce{};
    uint64_t sender_entropy{}, receiver_entropy{};
};
struct AuthenticatedHello {
    ::avalanche::ProofId proof_id;
    CPubKey session_key;
    uint32_t max_elements{};
};
struct SignedResponse { ::avalanche::Response response; SchnorrSig signature{}; };
uint256 HelloDigest(const ::avalanche::Delegation &, const ConnectionTranscript &);
bool AuthenticateHello(const ::avalanche::Delegation &, const SchnorrSig &,
                       const ConnectionTranscript &, uint32_t max_elements,
                       AuthenticatedHello &, std::string &);
uint256 ResponseDigest(const ::avalanche::Response &);
bool AuthenticateResponse(const CPubKey &, const SignedResponse &, std::string &);
} // namespace lotus::v2::ava
#endif
