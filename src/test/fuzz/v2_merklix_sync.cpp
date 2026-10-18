// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/siphash.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/tagged_hash.h>
#include <uint256.h>

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/check.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace {

// GF(2^64) arithmetic modulo P_64(X) = X^64 + X^4 + X^3 + X + 1 (0x1B).
constexpr uint64_t kGf64Poly = 0x1BULL;

uint64_t Gf64Mul(uint64_t a, uint64_t b) {
    uint64_t res = 0;
    for (int i = 0; i < 64; ++i) {
        if ((b >> i) & 1ULL) {
            res ^= a;
        }
        const bool hi = (a & (1ULL << 63)) != 0;
        a <<= 1;
        if (hi) {
            a ^= kGf64Poly;
        }
    }
    return res;
}

uint64_t Gf64Sqr(uint64_t a) { return Gf64Mul(a, a); }

uint64_t Gf64Cube(uint64_t a) { return Gf64Mul(Gf64Sqr(a), a); }

uint64_t Gf64Inv(uint64_t a) {
    Assert(a != 0);
    // a^(2^64 - 2) in GF(2^64)
    uint64_t res = 1;
    uint64_t cur = Gf64Sqr(a); // a^2
    for (int i = 1; i < 64; ++i) {
        res = Gf64Mul(res, cur);
        cur = Gf64Sqr(cur);
    }
    return res;
}

// Half-trace solver for z^2 + z = c in GF(2^64) when Tr(c) == 0.
std::optional<std::pair<uint64_t, uint64_t>>
SolveQuadraticGf64(uint64_t s1, uint64_t s3) {
    if (s1 == 0) {
        return std::nullopt;
    }
    // For two distinct elements x1, x2:
    // s1 = x1 ^ x2 != 0
    // s3 = x1^3 ^ x2^3 = s1^3 ^ s1 * (x1 * x2)
    // Let p = x1 * x2 = (s3 ^ s1^3) / s1
    // Substitute x = s1 * z => z^2 + z = p / s1^2 = (s3 ^ s1^3) / s1^3.
    const uint64_t s1_3 = Gf64Cube(s1);
    const uint64_t num = s3 ^ s1_3;
    if (num == 0) {
        return std::nullopt;
    }
    const uint64_t c = Gf64Mul(num, Gf64Inv(s1_3));

    // Basis table for z^2 + z = c over GF(2^64): solve via Gaussian elimination
    // over GF(2) on the 64x64 linear operator L(z) = z^2 ^ z.
    uint64_t rows[64];
    uint64_t rhs[64];
    for (int i = 0; i < 64; ++i) {
        const uint64_t e = 1ULL << i;
        rows[i] = Gf64Sqr(e) ^ e;
        rhs[i] = 1ULL << i;
    }

    // Transpose so row r represents bit r of L(z).
    uint64_t mat[64]{};
    uint64_t inv_mat[64]{};
    for (int r = 0; r < 64; ++r) {
        inv_mat[r] = 1ULL << r;
        for (int col = 0; col < 64; ++col) {
            if ((rows[col] >> r) & 1ULL) {
                mat[r] |= (1ULL << col);
            }
        }
    }

    int pivot_col_for_row[64];
    std::fill(std::begin(pivot_col_for_row), std::end(pivot_col_for_row), -1);
    int row = 0;
    for (int col = 0; col < 64 && row < 64; ++col) {
        int sel = -1;
        for (int r = row; r < 64; ++r) {
            if ((mat[r] >> col) & 1ULL) {
                sel = r;
                break;
            }
        }
        if (sel == -1) {
            continue;
        }
        std::swap(mat[row], mat[sel]);
        std::swap(inv_mat[row], inv_mat[sel]);
        pivot_col_for_row[row] = col;
        for (int r = 0; r < 64; ++r) {
            if (r != row && ((mat[r] >> col) & 1ULL)) {
                mat[r] ^= mat[row];
                inv_mat[r] ^= inv_mat[row];
            }
        }
        ++row;
    }

    uint64_t z = 0;
    for (int r = 0; r < 64; ++r) {
        const uint64_t parity =
            static_cast<uint64_t>(__builtin_popcountll(inv_mat[r] & c) & 1);
        if (pivot_col_for_row[r] == -1) {
            if (parity != 0) {
                return std::nullopt; // Trace != 0, no solution in GF(2^64)
            }
        } else if (parity != 0) {
            z |= (1ULL << pivot_col_for_row[r]);
        }
    }

    if ((Gf64Sqr(z) ^ z) != c) {
        return std::nullopt;
    }
    const uint64_t x1 = Gf64Mul(s1, z);
    const uint64_t x2 = x1 ^ s1;
    if (x1 == 0 || x2 == 0 || x1 == x2) {
        return std::nullopt;
    }
    return std::make_pair(std::min(x1, x2), std::max(x1, x2));
}

lotus::v2::Hash ConsumeHash(FuzzedDataProvider &fdp) {
    lotus::v2::Hash h{};
    const auto b = fdp.ConsumeBytes<uint8_t>(32);
    std::copy(b.begin(), b.end(), h.begin());
    return h;
}

uint64_t ShortIdForTxHash(uint64_t k0, uint64_t k1,
                          const lotus::v2::Hash &tx_hash) {
    CSipHasher hasher(k0, k1);
    hasher.Write(Span<const uint8_t>{tx_hash});
    const uint64_t sid = hasher.Finalize();
    return sid == 0 ? 1ULL : sid;
}

struct BucketSyndrome {
    uint32_t count = 0;
    lotus::v2::Hash root{};
    uint64_t s1 = 0;
    uint64_t s3 = 0;
};

BucketSyndrome ComputeBucketSyndrome(
    const lotus::v2::TxIdentityPair &coinbase,
    const std::vector<lotus::v2::TxIdentityPair> &non_coinbase, uint64_t k0,
    uint64_t k1) {
    BucketSyndrome out{};
    out.count = static_cast<uint32_t>(non_coinbase.size());
    std::vector<lotus::v2::TxIdentityPair> all;
    all.reserve(1 + non_coinbase.size());
    all.push_back(coinbase);
    for (const auto &tx : non_coinbase) {
        all.push_back(tx);
        const uint64_t x = ShortIdForTxHash(k0, k1, tx.tx_hash);
        out.s1 ^= x;
        out.s3 ^= Gf64Cube(x);
    }
    Assert(lotus::v2::TransactionRoot(all, out.root));
    return out;
}

} // namespace

FUZZ_TARGET(v2_merklix_sync) {
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    const uint64_t k0 = fdp.ConsumeIntegral<uint64_t>();
    const uint64_t k1 = fdp.ConsumeIntegral<uint64_t>();

    // 1. Fuzz IndexedTreeRoot & IndexedProofRoot.
    {
        const size_t n_leaves = fdp.ConsumeIntegralInRange<size_t>(1, 16);
        std::vector<lotus::v2::Hash> leaves;
        leaves.reserve(n_leaves);
        for (size_t i = 0; i < n_leaves; ++i) {
            leaves.push_back(ConsumeHash(fdp));
        }
        const lotus::v2::Hash tree_root = lotus::v2::IndexedTreeRoot(leaves);
        const lotus::v2::Hash tree_root_again =
            lotus::v2::IndexedTreeRoot(leaves);
        Assert(tree_root == tree_root_again);
    }

    // 2. Fuzz Merklix TransactionRoot & GF(2^64) (s1, s3) set reconciliation
    // with the Strict 256-Bit Root-Verification Gate.
    lotus::v2::TxIdentityPair coinbase{ConsumeHash(fdp), ConsumeHash(fdp)};

    const size_t base_count = fdp.ConsumeIntegralInRange<size_t>(0, 12);
    std::map<lotus::v2::Hash, lotus::v2::TxIdentityPair> map_a;
    std::map<uint64_t, lotus::v2::TxIdentityPair> universe_by_sid;

    auto add_to_universe = [&](const lotus::v2::TxIdentityPair &pair) -> bool {
        const uint64_t sid = ShortIdForTxHash(k0, k1, pair.tx_hash);
        if (universe_by_sid.count(sid) != 0) {
            return false;
        }
        universe_by_sid.emplace(sid, pair);
        return true;
    };

    for (size_t i = 0; i < base_count; ++i) {
        lotus::v2::TxIdentityPair p{ConsumeHash(fdp), ConsumeHash(fdp)};
        if (map_a.count(p.tx_id) == 0 && add_to_universe(p)) {
            map_a.emplace(p.tx_id, p);
        }
    }

    std::map<lotus::v2::Hash, lotus::v2::TxIdentityPair> map_b = map_a;
    const size_t diff_mode = fdp.ConsumeIntegralInRange<size_t>(0, 3);
    size_t actual_diff = 0;
    for (size_t d = 0; d < diff_mode; ++d) {
        lotus::v2::TxIdentityPair extra{ConsumeHash(fdp), ConsumeHash(fdp)};
        if (map_a.count(extra.tx_id) == 0 && map_b.count(extra.tx_id) == 0 &&
            add_to_universe(extra)) {
            if (fdp.ConsumeBool()) {
                map_b.emplace(extra.tx_id, extra);
            } else {
                map_a.emplace(extra.tx_id, extra);
            }
            ++actual_diff;
        }
    }

    std::vector<lotus::v2::TxIdentityPair> vec_a, vec_b;
    for (const auto &[_, tx] : map_a) vec_a.push_back(tx);
    for (const auto &[_, tx] : map_b) vec_b.push_back(tx);

    const BucketSyndrome syn_a = ComputeBucketSyndrome(coinbase, vec_a, k0, k1);
    const BucketSyndrome syn_b = ComputeBucketSyndrome(coinbase, vec_b, k0, k1);

    const uint64_t ds1 = syn_a.s1 ^ syn_b.s1;
    const uint64_t ds3 = syn_a.s3 ^ syn_b.s3;

    if (actual_diff == 0) {
        Assert(syn_a.root == syn_b.root);
        Assert(ds1 == 0 && ds3 == 0);
    } else if (actual_diff == 1) {
        Assert(ds1 != 0);
        Assert(Gf64Cube(ds1) == ds3);
        const auto it = universe_by_sid.find(ds1);
        Assert(it != universe_by_sid.end());

        // Apply symmetric difference to A and verify 256-bit Merklix root!
        auto reconciled = map_a;
        if (!reconciled.erase(it->second.tx_id)) {
            reconciled.emplace(it->second.tx_id, it->second);
        }
        std::vector<lotus::v2::TxIdentityPair> rec_vec;
        for (const auto &[_, tx] : reconciled) rec_vec.push_back(tx);
        const BucketSyndrome syn_rec =
            ComputeBucketSyndrome(coinbase, rec_vec, k0, k1);
        Assert(syn_rec.root == syn_b.root);
    } else if (actual_diff == 2) {
        const auto roots = SolveQuadraticGf64(ds1, ds3);
        Assert(roots.has_value());
        const auto it1 = universe_by_sid.find(roots->first);
        const auto it2 = universe_by_sid.find(roots->second);
        Assert(it1 != universe_by_sid.end());
        Assert(it2 != universe_by_sid.end());

        auto reconciled = map_a;
        for (const auto *it : {&it1, &it2}) {
            if (!reconciled.erase((*it)->second.tx_id)) {
                reconciled.emplace((*it)->second.tx_id, (*it)->second);
            }
        }
        std::vector<lotus::v2::TxIdentityPair> rec_vec;
        for (const auto &[_, tx] : reconciled) rec_vec.push_back(tx);
        const BucketSyndrome syn_rec =
            ComputeBucketSyndrome(coinbase, rec_vec, k0, k1);
        Assert(syn_rec.root == syn_b.root);
    } else {
        // Strict 256-Bit Root-Verification Gate: even if a >=3-tx difference
        // or adversarial syndrome happens to yield a 1-tx or 2-tx candidate,
        // the recomputed 32-byte Merklix root will NOT equal syn_b.root.
        Assert(syn_a.root != syn_b.root);
    }
}
