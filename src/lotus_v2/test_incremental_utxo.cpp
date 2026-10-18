#include "incremental_utxo.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>

using namespace lotus::v2;

namespace {
void Check(bool condition, const char *message) {
    if (!condition) {
        std::cerr << "V2 incremental UTXO: " << message << '\n';
        std::exit(1);
    }
}

Coin MakeCoin(uint32_t index) {
    Coin coin;
    for (unsigned i = 0; i < 32; ++i) coin.outpoint.tx_id[i] = i;
    coin.outpoint.index = index;
    coin.output.flags = 0;
    coin.output.value = 1000 + index;
    Hash branch;
    branch.fill(0x11);
    coin.output.branches = {branch};
    coin.output.paths = {{0}};
    coin.creation_height = index + 7;
    coin.creation_parent_mtp = index + 1234;
    coin.coinbase = index % 2 == 0;
    return coin;
}

void CheckProof(const IncrementalUtxoSet &incremental, const UtxoSet &scalar,
                const Outpoint &query) {
    const CoinProof fast = incremental.Prove(query);
    const CoinProof slow = scalar.Prove(query);
    Check(fast.presence == slow.presence, "presence agrees with scalar");
    Check(fast.bitmap == slow.bitmap, "bitmap agrees with scalar");
    Check(fast.siblings == slow.siblings, "bottom-up siblings agree with scalar");
    Check(fast.coin.has_value() == slow.coin.has_value(), "terminal coin presence agrees");
    if (fast.coin) {
        std::vector<uint8_t> fast_bytes, slow_bytes;
        Check(EncodeCoin(*fast.coin, fast_bytes) && EncodeCoin(*slow.coin, slow_bytes) &&
                  fast_bytes == slow_bytes,
              "terminal coin bytes agree with scalar");
    }
    Check(VerifyCoinProof(query, fast, incremental.Root()), "incremental proof verifies");
}

void CheckState(const IncrementalUtxoSet &incremental, const UtxoSet &scalar,
                const std::vector<Coin> &coins, uint32_t absent_index) {
    Check(incremental.Root() == scalar.Root(), "root agrees with scalar");
    Check(incremental.Size() == scalar.Size(), "size agrees with scalar");
    for (const Coin &coin : coins) CheckProof(incremental, scalar, coin.outpoint);
    CheckProof(incremental, scalar, MakeCoin(absent_index).outpoint);
}
} // namespace

int main() {
    IncrementalUtxoSet incremental;
    UtxoSet scalar;
    std::vector<Coin> fixtures{MakeCoin(0), MakeCoin(47), MakeCoin(1)};
    CheckState(incremental, scalar, {}, 0);
    for (size_t i = 0; i < fixtures.size(); ++i) {
        Check(incremental.Insert(fixtures[i]) && scalar.Insert(fixtures[i]),
              "insert shared-prefix fixture");
        CheckState(incremental, scalar,
                   std::vector<Coin>(fixtures.begin(), fixtures.begin() + i + 1), 200);
    }
    const Hash fixture_root = incremental.Root();
    Check(!incremental.Insert(fixtures[0]) && incremental.Root() == fixture_root &&
              incremental.Size() == fixtures.size(),
          "duplicate cannot overwrite root or size");
    Coin burn = MakeCoin(201);
    burn.output.flags = 2;
    burn.output.paths.clear();
    Check(!incremental.Insert(burn) && incremental.Root() == fixture_root,
          "burn output rejects without mutation");
    Coin malformed = MakeCoin(202);
    malformed.output.paths.clear();
    Check(!incremental.Insert(malformed) && incremental.Root() == fixture_root,
          "malformed output rejects without mutation");
    Check(!incremental.Erase(MakeCoin(203).outpoint) && incremental.Root() == fixture_root,
          "missing deletion leaves root unchanged");
    for (auto it = fixtures.rbegin(); it != fixtures.rend(); ++it) {
        Check(incremental.Erase(it->outpoint) && scalar.Erase(it->outpoint),
              "delete shared-prefix fixture");
        Check(incremental.Root() == scalar.Root(), "delete collapses like scalar");
    }
    Check(incremental.Root() == EmptyUtxoRoot(), "deletion restores empty root");

    // Deterministic randomized sequence stresses path-local splits, partial
    // empty sibling chains, proof order, and reverse-order undo.
    uint64_t rng = 0x7a6d43bc53a49e27ULL;
    auto Next = [&]() {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        return rng;
    };
    std::vector<Coin> coins;
    std::vector<Hash> roots{incremental.Root()};
    for (unsigned n = 0; n < 96; ++n) {
        const uint32_t index = static_cast<uint32_t>(Next());
        Coin coin = MakeCoin(index);
        Check(incremental.Insert(coin) && scalar.Insert(coin), "random insert");
        coins.push_back(coin);
        roots.push_back(incremental.Root());
        Check(incremental.Root() == scalar.Root(), "random insert root agreement");
        if (n % 8 == 0) {
            CheckProof(incremental, scalar, coins[n / 2].outpoint);
            CheckProof(incremental, scalar, MakeCoin(index ^ 0x80000000U).outpoint);
        }
    }
    const Hash final_root = incremental.Root();
    IncrementalUtxoSet reversed;
    for (auto it = coins.rbegin(); it != coins.rend(); ++it) {
        Check(reversed.Insert(*it), "reverse-order insert");
    }
    Check(reversed.Root() == final_root, "root independent of insertion order");
    for (size_t n = coins.size(); n > 0; --n) {
        Check(incremental.Erase(coins[n - 1].outpoint) &&
                  scalar.Erase(coins[n - 1].outpoint),
              "reverse undo deletion");
        Check(incremental.Root() == scalar.Root() && incremental.Root() == roots[n - 1],
              "reverse undo restores exact recorded root");
        if (n % 11 == 0) {
            CheckProof(incremental, scalar, coins[n - 1].outpoint);
        }
    }
    Check(incremental.Root() == EmptyUtxoRoot() && incremental.Size() == 0,
          "full undo restores initial tree");
    for (const Coin &coin : coins) Check(incremental.Insert(coin), "reinsert after undo");
    Check(incremental.Root() == final_root, "reinsert restores final root");

    // Mix inserts and deletes from a nonempty tree to exercise repeated
    // collapse/re-expansion and absent proofs at changing roots.
    UtxoSet mixed_scalar;
    IncrementalUtxoSet mixed_incremental;
    std::vector<Coin> active;
    uint32_t next_index = 100000;
    for (unsigned step = 0; step < 240; ++step) {
        if (active.empty() || (Next() & 3) != 0) {
            Coin coin = MakeCoin(next_index++);
            Check(mixed_scalar.Insert(coin) && mixed_incremental.Insert(coin),
                  "mixed insert");
            active.push_back(coin);
        } else {
            const size_t index = Next() % active.size();
            const Outpoint spent = active[index].outpoint;
            Check(mixed_scalar.Erase(spent) && mixed_incremental.Erase(spent),
                  "mixed delete");
            active.erase(active.begin() + index);
            CheckProof(mixed_incremental, mixed_scalar, spent);
        }
        Check(mixed_incremental.Root() == mixed_scalar.Root() &&
                  mixed_incremental.Size() == active.size(),
              "mixed root and size agree");
        if (!active.empty()) {
            CheckProof(mixed_incremental, mixed_scalar, active[Next() % active.size()].outpoint);
        }
        CheckProof(mixed_incremental, mixed_scalar, MakeCoin(next_index + 1000).outpoint);
    }
    std::cout << "V2 incremental UTXO differential cases passed\n";
}
