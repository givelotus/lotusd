// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <consensus/amount.h>
#include <core_memusage.h>
#include <limits>
#include <hash.h>
#include <lotus_v2/mempool_overlay.h>
#include <lotus_v2/tagged_hash.h>
#include <tinyformat.h>

#include <algorithm>
#include <cstring>

BlockHash CBlockHeader::GetHash() const {
    return BlockHash{(HashWriter{} << *this).GetHash()};
}

std::string CBlock::ToString() const {
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, "
                   "hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, "
                   "vtx=%u)\n",
                   GetHash().ToString(), nVersion, hashPrevBlock.ToString(),
                   hashMerkleRoot.ToString(), nTime, nBits, nNonce, vtx.size());
    for (const auto &tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}

namespace {

lotus::v2::Output ConvertTxOutToV2Output(const CTxOut &txout) {
    const uint64_t val =
        static_cast<uint64_t>(std::max<int64_t>(0, txout.nValue / SATOSHI));
    if (txout.scriptPubKey.size() >= 43) {
        std::string err;
        lotus::v2::Output decoded;
        const std::vector<uint8_t> raw(txout.scriptPubKey.begin(),
                                       txout.scriptPubKey.end());
        if (lotus::v2::DecodeOutput(raw, decoded, err)) {
            decoded.value = val;
            return decoded;
        }
        if (raw[0] == 0x6a && raw.size() >= 44) {
            const std::vector<uint8_t> sub(raw.begin() + 1, raw.end());
            if (lotus::v2::DecodeOutput(sub, decoded, err)) {
                decoded.value = val;
                return decoded;
            }
        }
    }
    lotus::v2::Output out;
    out.value = val;
    const std::vector<uint8_t> script_bytes(txout.scriptPubKey.begin(),
                                            txout.scriptPubKey.end());
    out.branches = {lotus::v2::BranchLeaf(script_bytes)};
    if (!script_bytes.empty() && script_bytes[0] == 0x6a) {
        out.flags = 2;
        out.paths = {};
    } else {
        out.flags = 0;
        out.paths = {{0}};
    }
    return out;
}

void ExtractOverlayTxData(
    const CTransaction &tx,
    uint64_t nHeight,
    uint64_t nParentMtp,
    lotus::v2::Hash &tx_id,
    lotus::v2::Hash &tx_hash,
    uint64_t &linear_cost,
    std::vector<lotus::v2::Outpoint> &spent_outpoints,
    std::vector<lotus::v2::Coin> &created_coins) {
    std::memcpy(tx_id.data(), tx.GetId().begin(), 32);
    std::memcpy(tx_hash.data(), tx.GetHash().begin(), 32);
    linear_cost = tx.GetTotalSize() +
                  uint64_t(tx.vin.size() * 64 + tx.vout.size() * 64);

    spent_outpoints.clear();
    if (!tx.IsCoinBase()) {
        spent_outpoints.reserve(tx.vin.size());
        for (const auto &txin : tx.vin) {
            lotus::v2::Outpoint op{};
            std::memcpy(op.tx_id.data(), txin.prevout.GetTxId().begin(), 32);
            op.index = txin.prevout.GetN();
            spent_outpoints.push_back(op);
        }
    }

    created_coins.clear();
    created_coins.reserve(tx.vout.size());
    for (size_t j = 0; j < tx.vout.size(); ++j) {
        if (tx.vout[j].scriptPubKey.IsUnspendable()) {
            continue;
        }
        const lotus::v2::Output v2out = ConvertTxOutToV2Output(tx.vout[j]);
        if (!v2out.IsBurn()) {
            lotus::v2::Coin coin{
                {tx_id, static_cast<uint32_t>(j)},
                v2out,
                nHeight,
                nParentMtp,
                tx.IsCoinBase()};
            created_coins.push_back(std::move(coin));
        }
    }
}

} // namespace

uint256 ComputeV2TxRootFromSubtreeA(const CTransaction &coinbase_tx,
                                    const lotus::v2::Hash &subtree_a_root) {
    std::array<uint8_t, 65> cb_buf{};
    cb_buf[0] = 0x00;
    std::memcpy(cb_buf.data() + 1, coinbase_tx.GetId().begin(), 32);
    std::memcpy(cb_buf.data() + 33, coinbase_tx.GetHash().begin(), 32);
    const lotus::v2::Hash cb_leaf =
        lotus::v2::TaggedHash(lotus::v2::HashDomain::TxRoot, cb_buf);

    std::array<uint8_t, 65> top{};
    top[0] = 0x03;
    std::memcpy(top.data() + 1, cb_leaf.data(), 32);
    std::memcpy(top.data() + 33, subtree_a_root.data(), 32);
    const lotus::v2::Hash tx_root =
        lotus::v2::TaggedHash(lotus::v2::HashDomain::TxRoot, top);

    uint256 out;
    std::memcpy(out.begin(), tx_root.data(), 32);
    return out;
}

namespace {
//! Retained-body charge for pinned reconciliation views; matches the former
//! full-mempool snapshot capture charge max(serialized, recursive usage).
uint32_t OverlayPayloadBytes(const CTransactionRef &ptx) {
    const size_t bytes = std::max<size_t>(GetSerializeSize(*ptx),
                                          RecursiveDynamicUsage(ptx));
    return static_cast<uint32_t>(
        std::min<size_t>(bytes, std::numeric_limits<uint32_t>::max()));
}
} // namespace

bool AddTransactionToOverlay(lotus::v2::MempoolOverlayLayer &overlay,
                             const CTransactionRef &ptx,
                             int64_t fee_sats,
                             int64_t sigchecks) {
    if (!ptx || ptx->IsCoinBase()) {
        return false;
    }
    lotus::v2::Hash tx_id{};
    lotus::v2::Hash tx_hash{};
    uint64_t linear_cost = 0;
    std::vector<lotus::v2::Outpoint> spent;
    std::vector<lotus::v2::Coin> created;
    ExtractOverlayTxData(*ptx, overlay.GetHeight(), overlay.GetParentMtp(),
                         tx_id, tx_hash, linear_cost, spent, created);
    return overlay.AddTransaction(tx_id, tx_hash, linear_cost, spent, created,
                                  fee_sats, sigchecks, ptx,
                                  OverlayPayloadBytes(ptx));
}

bool AddTransactionToOverlay(lotus::v2::MerklixOverlayManager &manager,
                             const CTransactionRef &ptx,
                             int64_t fee_sats,
                             int64_t sigchecks) {
    return AddTransactionToOverlay(manager.GetSpeculativeOverlay(), ptx,
                                   fee_sats, sigchecks);
}

size_t AddTransactionsToOverlayBatch(
    lotus::v2::MempoolOverlayLayer &overlay,
    std::span<const std::tuple<CTransactionRef, int64_t, int64_t>> txs) {
    if (txs.empty()) {
        return 0;
    }
    if (txs.size() == 1) {
        const auto &[ptx, fee_sats, sigchecks] = txs[0];
        return AddTransactionToOverlay(overlay, ptx, fee_sats, sigchecks) ? 1 : 0;
    }

    const uint64_t nHeight = overlay.GetHeight();
    const uint64_t nParentMtp = overlay.GetParentMtp();
    std::vector<lotus::v2::OverlayTxEntry> entries(txs.size());

    for (size_t i = 0; i < txs.size(); ++i) {
        const auto &[ptx, fee_sats, sigchecks] = txs[i];
        if (!ptx || ptx->IsCoinBase()) {
            continue;
        }
        auto &e = entries[i];
        ExtractOverlayTxData(*ptx, nHeight, nParentMtp, e.tx_id, e.tx_hash,
                             e.linear_cost, e.spent_outpoints, e.created_coins);
        e.fee_sats = fee_sats;
        e.sigchecks = sigchecks;
        e.payload_bytes = OverlayPayloadBytes(ptx);
        e.tx_ref = ptx;
    }

    size_t write_idx = 0;
    for (size_t i = 0; i < entries.size(); ++i) {
        if (entries[i].tx_ref) {
            if (write_idx != i) {
                entries[write_idx] = std::move(entries[i]);
            }
            ++write_idx;
        }
    }
    entries.resize(write_idx);

    return overlay.AddTransactionBatch(entries);
}

size_t AddTransactionsToOverlayBatch(
    lotus::v2::MerklixOverlayManager &manager,
    std::span<const std::tuple<CTransactionRef, int64_t, int64_t>> txs) {
    return AddTransactionsToOverlayBatch(manager.GetSpeculativeOverlay(), txs);
}

bool RemoveTransactionFromOverlay(lotus::v2::MempoolOverlayLayer &overlay,
                                  const CTransaction &tx) {
    lotus::v2::Hash tx_id{};
    std::memcpy(tx_id.data(), tx.GetId().begin(), 32);
    return overlay.RemoveTransaction(tx_id);
}

bool RemoveTransactionFromOverlay(lotus::v2::MerklixOverlayManager &manager,
                                  const CTransaction &tx) {
    return RemoveTransactionFromOverlay(manager.GetSpeculativeOverlay(), tx);
}
