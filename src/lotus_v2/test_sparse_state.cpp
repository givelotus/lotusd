#include "sparse_state.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>

using namespace lotus::v2;

namespace {
void Check(bool condition, const char *message) {
    if (!condition) {
        std::cerr << "V2 sparse state: " << message << '\n';
        std::exit(1);
    }
}

std::string Hex(const uint8_t *data, size_t size) {
    constexpr char chars[] = "0123456789abcdef";
    std::string result;
    for (size_t i = 0; i < size; ++i) {
        result.push_back(chars[data[i] >> 4]);
        result.push_back(chars[data[i] & 15]);
    }
    return result;
}
std::string Hex(const Hash &hash) { return Hex(hash.data(), hash.size()); }

Coin MakeCoin(uint32_t index) {
    Coin coin;
    for (unsigned i = 0; i < 32; ++i) coin.outpoint.tx_id[i] = i;
    coin.outpoint.index = index;
    coin.output.flags = 0;
    coin.output.value = 1000;
    Hash branch;
    branch.fill(0x11);
    coin.output.branches = {branch};
    coin.output.paths = {{0}};
    coin.creation_height = 7;
    coin.creation_parent_mtp = 1234;
    coin.coinbase = true;
    return coin;
}
} // namespace

int main() {
    // Constants generated independently by generate_sparse_vectors.py with
    // Python blake3 1.0.11 and a separate scalar tree implementation.
    const Coin c0 = MakeCoin(0);
    const Coin c47 = MakeCoin(48); // OutpointKey shares low 228 bits with c0.
    const Coin c1 = MakeCoin(1); // Opposite key bit 224 from c0.
    Check(Hex(OutpointKey(c0.outpoint)) ==
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
          "outpoint key vector");
    std::vector<uint8_t> encoded;
    Check(EncodeCoin(c0, encoded) && Hex(encoded.data(), encoded.size()) ==
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000"
              "2d00e803000000000000011111111111111111111111111111111111111111111111111111111111111111010100"
              "0700000000000000d2040000000000000102000000000000000007cd400100000000",
          "canonical Coin bytes including output length and metadata");
    Coin largest = MakeCoin(4);
    largest.output.flags = 1;
    largest.output.token_id[0] = 1;
    largest.output.branches.clear();
    largest.output.paths.clear();
    for (uint8_t i = 0; i < 16; ++i) {
        Hash branch{};
        branch[0] = i;
        largest.output.branches.push_back(branch);
    }
    for (int omitted = 15; omitted >= 0; --omitted) {
        if (omitted == 0) continue;
        std::vector<uint8_t> path;
        for (uint8_t i = 0; i < 16; ++i) {
            if (i != omitted) path.push_back(i);
        }
        largest.output.paths.push_back(std::move(path));
    }
    std::vector<uint8_t> full_path;
    for (uint8_t i = 0; i < 16; ++i) full_path.push_back(i);
    largest.output.paths.push_back(std::move(full_path));
    std::sort(largest.output.paths.begin(), largest.output.paths.end());
    Check(EncodeCoin(largest, encoded) && encoded.size() == 885,
          "maximum stateless V2 Coin is exactly 885 bytes");
    Hash leaf;
    Check(UtxoLeaf(c0, leaf) && Hex(leaf) ==
              "927c546dbc432596769cd2ff7261757a5536c17560c60f5ba4dd9ac5bb5d1ab6",
          "keyed leaf and Bytes(Coin) vector");
    Check(Hex(EmptyUtxoRoot()) ==
              "8006a077938a575c157a0d537fea697a65538c100ce5c6a8ad750e7226418e7c",
          "empty UTXO root domain");
    Hash bounded;
    bounded.fill(0xa5);
    Check(!UtxoNode(256, leaf, leaf, bounded) && bounded[0] == 0xa5,
          "reject depth 256 without changing output");

    UtxoSet set;
    const Hash empty = set.Root();
    Check(empty == EmptyUtxoRoot(), "empty model root");
    const CoinProof empty_absence = set.Prove(c0.outpoint);
    Check(empty_absence.presence == ProofPresence::Empty &&
              VerifyCoinProof(c0.outpoint, empty_absence, empty),
          "absence mode 0 at empty root");
    Check(set.Insert(c0) && set.Root() == leaf, "single leaf collapses to leaf hash");
    Check(!set.Insert(c0) && set.Size() == 1 && set.Root() == leaf,
          "duplicate outpoint cannot overwrite");
    Coin invalid = MakeCoin(3);
    invalid.output.flags = 2;
    invalid.output.paths.clear();
    Check(!set.Insert(invalid), "burn output never enters UTXO set");
    const CoinProof singleton_member = set.Prove(c0.outpoint);
    Check(singleton_member.presence == ProofPresence::Present &&
              VerifyCoinProof(c0.outpoint, singleton_member, set.Root()),
          "membership mode 1 at single leaf");
    const CoinProof singleton_absence = set.Prove(c47.outpoint);
    Check(singleton_absence.presence == ProofPresence::OtherLeaf &&
              VerifyCoinProof(c47.outpoint, singleton_absence, set.Root()),
          "absence mode 2 at single leaf");

    Check(set.Insert(c47) && Hex(set.Root()) ==
              "453cf262fd2a3413cdcfea213da93b7a0e27b8e6006f01e0e15a83d0f8a604e2",
          "shared-prefix two-coin root");
    const CoinProof empty_branch = set.Prove(c1.outpoint);
    Check(empty_branch.presence == ProofPresence::Empty &&
              VerifyCoinProof(c1.outpoint, empty_branch, set.Root()),
          "absence mode 0 with nonempty interior sibling");
    Check(set.Insert(c1) && Hex(set.Root()) ==
              "9bc534d62c1d1ee4b5ac61c56f835ad5d0abff4d09b33e8afdef3b4e9000f114",
          "three-coin root with branch directions");
    const Hash original = set.Root();
    UtxoSet reverse;
    Check(reverse.Insert(c1) && reverse.Insert(c47) && reverse.Insert(c0) &&
              reverse.Root() == original,
          "insertion order does not affect root");
    for (const Coin *coin : {&c0, &c47, &c1}) {
        const CoinProof proof = set.Prove(coin->outpoint);
        Check(proof.presence == ProofPresence::Present &&
                  VerifyCoinProof(coin->outpoint, proof, original),
              "membership proof for each branch direction");
    }
    bool checked_prefix_absence = false;
    for (uint32_t index = 2; index < 100; ++index) {
        const Outpoint query = MakeCoin(index).outpoint;
        const CoinProof proof = set.Prove(query);
        if (proof.presence != ProofPresence::OtherLeaf || proof.bitmap == Hash{}) continue;
        Check(VerifyCoinProof(query, proof, original), "non-root prefix absence proof");
        CoinProof wrong_prefix = proof;
        wrong_prefix.coin->outpoint = c0.outpoint == proof.coin->outpoint
                                          ? c1.outpoint : c0.outpoint;
        if ((OutpointKey(wrong_prefix.coin->outpoint)[28] & 1) !=
            (OutpointKey(query)[28] & 1)) {
            Check(!VerifyCoinProof(query, wrong_prefix, original),
                  "reject wrong-prefix absence leaf");
            checked_prefix_absence = true;
            break;
        }
    }
    Check(checked_prefix_absence, "exercised wrong-prefix absence rejection");
    CoinProof tampered = set.Prove(c47.outpoint);
    Check(!tampered.siblings.empty(), "nonempty sibling path");
    std::reverse(tampered.siblings.begin(), tampered.siblings.end());
    if (tampered.siblings.size() > 1) {
        Check(!VerifyCoinProof(c47.outpoint, tampered, original),
              "reject reordered deepest-first siblings");
    }
    tampered = set.Prove(c47.outpoint);
    tampered.siblings.pop_back();
    Check(!VerifyCoinProof(c47.outpoint, tampered, original), "reject truncated sibling list");
    tampered = set.Prove(c47.outpoint);
    tampered.siblings.push_back(leaf);
    Check(!VerifyCoinProof(c47.outpoint, tampered, original), "reject trailing sibling");
    tampered = set.Prove(c47.outpoint);
    tampered.siblings[0] = EmptyUtxoRoot();
    Check(!VerifyCoinProof(c47.outpoint, tampered, original),
          "reject explicit empty-root sibling");
    tampered = set.Prove(c47.outpoint);
    tampered.bitmap.fill(0);
    Check(!VerifyCoinProof(c47.outpoint, tampered, original), "reject mismatched bitmap");
    tampered = set.Prove(c47.outpoint);
    tampered.presence = ProofPresence::OtherLeaf;
    Check(!VerifyCoinProof(c47.outpoint, tampered, original), "reject wrong presence mode");

    Coin metadata = c0;
    metadata.creation_height++;
    UtxoSet changed;
    Check(changed.Insert(metadata) && changed.Insert(c47) && changed.Insert(c1) &&
              Hex(changed.Root()) == "34a40d071ab9f7177a2cb441058a950234d7ce93428568755f917f853cf63c9d",
          "coin metadata changes authenticated root");
    Check(set.Erase(c1.outpoint) && Hex(set.Root()) ==
              "453cf262fd2a3413cdcfea213da93b7a0e27b8e6006f01e0e15a83d0f8a604e2",
          "delete restores shared-prefix two-coin root");
    Check(set.Erase(c47.outpoint) && set.Root() == leaf, "delete collapses to single leaf");
    Check(set.Erase(c0.outpoint) && set.Root() == empty, "delete restores initial empty root");
    Check(!set.Erase(c0.outpoint), "cannot delete absent outpoint");

    MonetaryState money;
    money.bootstrap_reserve = 11;
    money.tail_subsidy = 22;
    for (unsigned i = 0; i < 32; ++i) money.prev_work[i] = i;
    money.ema_block_cost = 33;
    const auto monetary = EncodeMonetaryState(money);
    Check(Hex(monetary.data(), monetary.size()) ==
              "0b000000000000001600000000000000000102030405060708090a0b0c0d0e0f"
              "101112131415161718191a1b1c1d1e1f2100000000000000",
          "exact 56-byte monetary envelope");
    ChainId chain;
    for (unsigned i = 0; i < 32; ++i) chain[i] = i + 32;
    const Hash state = StateRoot(chain, 9, original, money);
    Check(Hex(state) == "2033de4619ebbf5eb53a3b9fa0762a00f13e47a01a5d3f01bf04355f50045b50",
          "130-byte state envelope vector");
    money.ema_block_cost++;
    Check(StateRoot(chain, 9, original, money) != state, "monetary mutation changes state root");
    money.ema_block_cost--;
    Check(StateRoot(chain, 9, original, money) == state, "monetary undo restores state root");
    Check(StateRoot(chain, 10, original, money) != state, "height binds state root");
    std::cout << "V2 sparse UTXO and state vectors passed\n";
}
