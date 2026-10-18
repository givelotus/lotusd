// Copyright (c) 2026 The Lotus developers
#include "avalanche_proof.h"
#include "commitment.h"
#include <avalanche/validation.h>
#include <algorithm>
#include <cmath>
#include <limits>
namespace lotus::v2::ava {
bool ValidateProfile(const Profile &p, std::string &error) {
    const Hash zero{};
    if (p.chain_id == zero || p.genesis_id == zero || p.validation_digest == zero ||
        p.stake_dust <= Amount::zero() || !MoneyRange(p.stake_dust) || !MoneyRange(p.min_quorum_stake) ||
        p.stake_confirmations == 0 || !std::isfinite(p.min_connected_ratio) ||
        p.min_connected_ratio < 0 || p.min_connected_ratio > 1 ||
        p.max_element_poll < 16 || p.max_element_poll > 1024 ||
        p.stale_vote_threshold < AVALANCHE_VOTE_STALE_MIN_THRESHOLD || p.stale_vote_factor == 0 ||
        p.query_timeout_ms == 0 || p.max_proofs == 0 || p.max_nodes == 0 || p.max_queries == 0) {
        error = "invalid-avalanche-profile"; return false;
    }
    error.clear(); return true;
}
bool AdmitProof(const Profile &p, const ChainSnapshot &snapshot, const CoinLookup &lookup,
                const ProofEnvelope &env, AdmittedProof &out, const SnapshotReader &read,
                std::string &error) {
    auto fail = [&](const char *reason) { error = reason; return false; };
    if (!ValidateProfile(p, error)) return false;
    if (!lookup || !read || read() != snapshot) return fail("stale-chain-snapshot");
    if (!env.proof) return fail("missing-proof");
    ::avalanche::ProofValidationState state;
    if (!env.proof->verify(p.stake_dust, state)) { error = state.GetRejectReason(); return false; }
    const auto expiry = env.proof->getExpirationTime();
    if (expiry > 0 && snapshot.median_time_past >= uint64_t(expiry)) return fail("expired-proof");
    const auto &stakes = env.proof->getStakes();
    if (env.payment_locks.size() != stakes.size()) return fail("payment-lock-count");
    for (size_t i = 0; i < stakes.size(); ++i) {
        const auto &stake = stakes[i].getStake();
        const auto &native = stake.getUTXO();
        Outpoint point{};
        std::copy(native.GetTxId().begin(), native.GetTxId().end(), point.tx_id.begin());
        point.index = native.GetN();
        std::optional<Coin> coin;
        if (!lookup(point, coin, error)) return false;
        if (!coin) return fail("utxo-missing-or-spent");
        if (coin->outpoint != point) return fail("lookup-outpoint-mismatch");
        if (coin->creation_height != stake.getHeight()) return fail("height-mismatch");
        if (coin->coinbase != stake.isCoinbase()) return fail("coinbase-mismatch");
        if (coin->output.value > uint64_t(std::numeric_limits<int64_t>::max()) ||
            int64_t(coin->output.value) * SATOSHI != stake.getAmount()) return fail("amount-mismatch");
        if (coin->creation_height > snapshot.height ||
            snapshot.height - coin->creation_height < uint64_t(p.stake_confirmations - 1))
            return fail("immature-utxo");
        const auto &lock = env.payment_locks[i];
        const auto &key = stake.getPubkey();
        if (!key.IsFullyValid() || !key.IsCompressed() || lock.size() != 35 || lock[0] != 0x20 ||
            lock[33] != 0xbc || lock[34] != 0x4e ||
            !std::equal(lock.begin() + 1, lock.begin() + 33, key.begin() + 1))
            return fail("payment-lock-key-mismatch");
        const auto &output = coin->output;
        if (output.flags != 0 || output.token_id != Hash32{} ||
            output.paths != std::vector<std::vector<uint8_t>>{{0}} ||
            output.branches != std::vector<Hash32>{BranchLeaf(lock)}) return fail("payment-lock-mismatch");
    }
    if (read() != snapshot) return fail("stale-chain-snapshot");
    out = {env, snapshot}; error.clear(); return true;
}
}
