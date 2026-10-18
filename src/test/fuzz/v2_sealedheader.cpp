// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lotus_v2/block_template.h>
#include <lotus_v2/block_wire.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/header.h>
#include <lotus_v2/sparse_state.h>
#include <lotus_v2/tagged_hash.h>
#include <lotus_v2/transaction.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace {

lotus::v2::Hash ConsumeHash(FuzzedDataProvider &fdp) {
    lotus::v2::Hash h{};
    const auto b = fdp.ConsumeBytes<uint8_t>(32);
    std::copy(b.begin(), b.end(), h.begin());
    return h;
}

// Compute Subtree A root over CTOR-sorted non-coinbase (TxID, TxHash) pairs,
// and combine with CoinbaseLeaf in O(1) as specified in Section 3.6.
lotus::v2::Hash ComputeCoinbaseLeaf(const lotus::v2::TxIdentityPair &cb) {
    std::array<uint8_t, 65> payload{};
    payload[0] = 0x00;
    std::copy(cb.tx_hash.begin(), cb.tx_hash.end(), payload.begin() + 1);
    std::copy(cb.tx_id.begin(), cb.tx_id.end(), payload.begin() + 33);
    return lotus::v2::TaggedHash(lotus::v2::HashDomain::TxRoot, payload);
}

lotus::v2::Hash CombineCoinbaseAndSubtreeA(const lotus::v2::Hash &cb_leaf,
                                           const lotus::v2::Hash &subtree_a) {
    std::array<uint8_t, 65> payload{};
    payload[0] = 0x03;
    std::copy(cb_leaf.begin(), cb_leaf.end(), payload.begin() + 1);
    std::copy(subtree_a.begin(), subtree_a.end(), payload.begin() + 33);
    return lotus::v2::TaggedHash(lotus::v2::HashDomain::TxRoot, payload);
}

struct CandidateOverlayStub {
    lotus::v2::Hash subtree_a_root{};
    lotus::v2::Hash utxo_root{};
    lotus::v2::MonetaryState monetary{};
    uint64_t total_body_bytes = 0;
};

} // namespace

FUZZ_TARGET(v2_sealedheader) {
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    const lotus::v2::ChainId chain_id = ConsumeHash(fdp);
    lotus::v2::Hash max_pow_limit{};
    max_pow_limit.fill(0xff);

    // 1. Fuzz 134-byte V2 Header parsing, serialization, PoW hashing & child template.
    {
        const std::vector<uint8_t> raw_hdr =
            fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 160));
        lotus::v2::Header parsed{};
        if (lotus::v2::ParseHeader(raw_hdr.data(), raw_hdr.size(), parsed)) {
            Assert(raw_hdr.size() == lotus::v2::HEADER_SIZE);
            Assert(parsed.time <= lotus::v2::MAX_TIME);

            std::array<uint8_t, lotus::v2::HEADER_SIZE> ser{};
            Assert(lotus::v2::SerializeHeader(parsed, ser));
            Assert(std::equal(ser.begin(), ser.end(), raw_hdr.begin()));

            lotus::v2::Header reparsed{};
            Assert(lotus::v2::ParseHeader(ser.data(), ser.size(), reparsed));
            Assert(reparsed.prev_id == parsed.prev_id);
            Assert(reparsed.bits == parsed.bits);
            Assert(reparsed.time == parsed.time);
            Assert(reparsed.nonce == parsed.nonce);
            Assert(reparsed.version == parsed.version);
            Assert(reparsed.size == parsed.size);
            Assert(reparsed.height == parsed.height);
            Assert(reparsed.tx_root == parsed.tx_root);
            Assert(reparsed.state_root == parsed.state_root);

            const lotus::v2::Hash body_hash =
                lotus::v2::BodyHash(chain_id, parsed);
            lotus::v2::Hash work_hash{}, block_id{};
            Assert(lotus::v2::WorkHash(chain_id, parsed, work_hash));
            Assert(lotus::v2::BlockId(chain_id, parsed, block_id));
            (void)body_hash;

            lotus::v2::Hash target{};
            if (lotus::v2::DecodeTarget(parsed.bits, max_pow_limit, target)) {
                (void)lotus::v2::MeetsTarget(block_id, target);
                auto child = lotus::v2::BuildChildHeader(
                    parsed, chain_id, ConsumeHash(fdp), ConsumeHash(fdp),
                    parsed.time, 512, parsed.bits);
                if (child.has_value()) {
                    Assert(child->prev_id == block_id);
                    Assert(child->height == parsed.height + 1);
                    lotus::v2::Header search_hdr = *child;
                    (void)lotus::v2::SearchNonce(search_hdr, chain_id,
                                                 max_pow_limit, 0, 4);
                }
            }
        }
    }

    // 2. Fuzz DecodeBlockWire / EncodeBlockWire on arbitrary byte streams.
    {
        const lotus::v2::TxProfile tx_profile{8, 8, 4, 256, 4, 512, 16};
        const std::vector<uint8_t> raw_block =
            fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 512));
        lotus::v2::FramedBlock framed{};
        std::string err;
        if (lotus::v2::DecodeBlockWire(raw_block, tx_profile, chain_id, framed,
                                       err)) {
            Assert(err.empty());
            std::vector<uint8_t> reencoded;
            Assert(lotus::v2::EncodeBlockWire(framed.header, framed.transactions,
                                              tx_profile, reencoded, err));
            Assert(reencoded == raw_block);

            lotus::v2::Hash tx_root{};
            Assert(lotus::v2::CompleteTransactionRoot(
                framed.transactions, tx_profile, chain_id, tx_root, err));
        }
    }

    // 3. Fuzz sealedheader (Header || CoinbaseTx) Pre-Allocation PoW Gate &
    // Stage 1 Candidate Overlay Root Match ({L_k, L_{k-1}, L_0, L_spec}).
    {
        std::array<CandidateOverlayStub, 4> overlays{};
        for (auto &ov : overlays) {
            ov.subtree_a_root = ConsumeHash(fdp);
            ov.utxo_root = ConsumeHash(fdp);
            ov.monetary.bootstrap_reserve = fdp.ConsumeIntegral<uint64_t>();
            ov.monetary.tail_subsidy = fdp.ConsumeIntegral<uint64_t>();
            ov.monetary.prev_work = ConsumeHash(fdp);
            ov.monetary.ema_block_cost = fdp.ConsumeIntegral<uint64_t>();
            ov.total_body_bytes = fdp.ConsumeIntegralInRange<uint64_t>(0, 1'000'000);
        }

        // Construct a valid CoinbaseTx and matching/mismatched Header.
        const size_t chosen_idx = fdp.ConsumeIntegralInRange<size_t>(0, 3);
        const CandidateOverlayStub &chosen = overlays[chosen_idx];

        const lotus::v2::TxIdentityPair cb_pair{ConsumeHash(fdp),
                                                ConsumeHash(fdp)};
        const lotus::v2::Hash cb_leaf = ComputeCoinbaseLeaf(cb_pair);
        const lotus::v2::Hash expected_tx_root =
            CombineCoinbaseAndSubtreeA(cb_leaf, chosen.subtree_a_root);
        const uint64_t height = fdp.ConsumeIntegralInRange<uint64_t>(1, 100'000);
        const lotus::v2::Hash expected_state_root = lotus::v2::StateRoot(
            chain_id, height, chosen.utxo_root, chosen.monetary);

        lotus::v2::Header hdr{};
        hdr.prev_id = ConsumeHash(fdp);
        hdr.bits = 0x207fffffU;
        hdr.time = fdp.ConsumeIntegralInRange<uint64_t>(0, lotus::v2::MAX_TIME);
        hdr.nonce = fdp.ConsumeIntegral<uint64_t>();
        hdr.version = lotus::v2::kHeaderVersion;
        const uint64_t cb_framed_len = fdp.ConsumeIntegralInRange<uint64_t>(64, 512);
        hdr.size = lotus::v2::HEADER_SIZE +
                   lotus::v2::CompactSizeWidth(10) + cb_framed_len +
                   chosen.total_body_bytes;
        hdr.height = height;
        hdr.tx_root = expected_tx_root;
        hdr.state_root = expected_state_root;

        const bool corrupt_root = fdp.ConsumeBool();
        if (corrupt_root) {
            if (fdp.ConsumeBool()) {
                hdr.tx_root[0] ^= 0x01;
            } else {
                hdr.state_root[0] ^= 0x01;
            }
        }

        // Stage 1 Candidate Root Check across {L_k, L_{k-1}, L_0, L_spec}:
        std::optional<size_t> matched;
        for (size_t i = 0; i < overlays.size(); ++i) {
            const lotus::v2::Hash cand_tx_root =
                CombineCoinbaseAndSubtreeA(cb_leaf, overlays[i].subtree_a_root);
            if (cand_tx_root == hdr.tx_root) {
                const lotus::v2::Hash cand_state_root = lotus::v2::StateRoot(
                    chain_id, hdr.height, overlays[i].utxo_root,
                    overlays[i].monetary);
                if (cand_state_root == hdr.state_root) {
                    matched = i;
                    break;
                }
            }
        }

        if (!corrupt_root) {
            Assert(matched.has_value());
            Assert( overlays[*matched].subtree_a_root == chosen.subtree_a_root);
            Assert( overlays[*matched].utxo_root == chosen.utxo_root);
        } else {
            Assert(!matched.has_value());
        }
    }
}
