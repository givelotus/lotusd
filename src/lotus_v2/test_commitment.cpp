#include "commitment.h"
#include "tagged_hash.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

using namespace lotus::v2;

namespace {
void Check(bool condition, const char *message) {
    if (!condition) {
        std::cerr << "V2 commitment: " << message << '\n';
        std::exit(1);
    }
}

std::string Hex(const Hash &hash) {
    constexpr char chars[] = "0123456789abcdef";
    std::string result;
    for (uint8_t byte : hash) {
        result.push_back(chars[byte >> 4]);
        result.push_back(chars[byte & 15]);
    }
    return result;
}
} // namespace

int main() {
    // Constants from generate_commitment_vectors.py, Python blake3 1.0.11.
    const std::array<uint8_t, 1> script_a{0x51};
    const std::array<uint8_t, 1> script_b{0x52};
    const Hash a = BranchLeaf(script_a);
    const Hash b = BranchLeaf(script_b);
    Check(Hex(a) == "112bec3cbe47c045afc47092808c25f75028eab2992558d036dcce16170f68ad",
          "branch leaf domain and Bytes prefix");
    Check(Hex(b) == "3fa652740616a55f4b2916d429b1a714784776415a7f50ab43713b149e344f01",
          "second branch leaf");
    Check(Hex(BranchLeaf(std::vector<uint8_t>(253, 0x51))) ==
              "47c9f907c4db2fd08781b286fc43d000c36ce657479ed0f7a4f3c1edfc004972",
          "CompactSize 253 boundary");
    Check(Hex(BranchNode(a, b)) ==
              "fcaeff7068646f8fa9d94cbf75b2ed6903aa0b5861696687556a42621ec7fd5c",
          "branch node little-endian sorted children");
    Check(BranchNode(a, b) == BranchNode(b, a), "branch pair commutes");
    Check(BranchProofRoot(a, {}) == a, "zero-sibling branch proof");
    Check(BranchProofRoot(a, std::array<Hash, 1>{b}) == BranchNode(a, b),
          "bottom-up branch proof");

    const std::array<uint8_t, 1> one{1};
    const std::array<uint8_t, 3> output{1, 2, 3};
    Check(Hex(InputCoreLeaf(one)) ==
              "a21f839febf04a7c01cfb92da2b64139fef2f3a0b4fd95aee20d68aaaab564e3",
          "core input leaf");
    Check(Hex(InputFullLeaf(one)) ==
              "f6b2491ca3eddd54b2e507bf743e41a17ae5ccf3839c65a03aed150195cb82fb",
          "full input leaf domain separation");
    Check(Hex(OutputLeaf(output)) ==
              "2a1a059e0bba7e8f104b20c957f0f513dc3e858c4e393fe9cf1bca13e5ca5481",
          "output leaf Bytes prefix");
    Check(Hex(CoinEntryLeaf({})) ==
              "e52dcda03b190fbbf9aa3f01500b77571b4b20692ad12bef4f62bb4f65f85a01",
          "mint coin entry is Bytes(empty)");
    Check(OutputLeaf(output) != CoinEntryLeaf(output), "output and coin domains differ");
    const Hash own_input = TaggedHash(HashDomain::OwnInput, one);
    const Hash sighash = TaggedHash(HashDomain::Sighash, one);
    Check(Hex(own_input) == "b2658f901ab19e72f66bedb13ed74ac4a13fbc0f8b7d1af17b695cbca53287e5",
          "independent own-input tag vector");
    Check(Hex(sighash) == "152e69663b11475f32adbe5b718e3fa817076b9017dfe8478c04d8d066afb76b",
          "independent sighash tag vector");
    Check(own_input != sighash && own_input != InputCoreLeaf(one),
          "signing domains remain separated from each other and input core");

    const char *indexed_expected[] = {
        "42717c875691058000ff7d89bae835b2d60733fd2082c120aa813124f68cf638",
        "a21f839febf04a7c01cfb92da2b64139fef2f3a0b4fd95aee20d68aaaab564e3",
        "6f5aabd435d78ab6907939b84ba1918f0132ac19f92682ac2860724941bbb6b2",
        "2441dcdcb316227c6f323b933dc3126b509f34cb09bf013e992f74e6b5f3ff75",
        "7d5dcfaedc0466bc9e14eec742941d1df6cc345be9bf246450a1da0acccc7bec",
        "0cf95145c656b9452d42b34672fae162fc4fde764175902397a2b06fc2390ea2",
    };
    std::vector<Hash> leaves;
    for (unsigned i = 1; i <= 5; ++i) {
        const std::array<uint8_t, 1> value{static_cast<uint8_t>(i)};
        leaves.push_back(InputCoreLeaf(value));
    }
    for (size_t n = 0; n <= leaves.size(); ++n) {
        Check(Hex(IndexedTreeRoot(std::span(leaves).first(n))) == indexed_expected[n],
              "independent indexed root at every count 0..5");
    }
    Check(IndexedNode(0, leaves[0], leaves[1]) != IndexedNode(0, leaves[1], leaves[0]),
          "indexed sibling order matters");
    Check(IndexedNode(0, leaves[0], leaves[1]) != IndexedNode(1, leaves[0], leaves[1]),
          "indexed layer domain matters");
    std::array<Hash, 2> proof_for_last{Hash{}, IndexedNode(0, leaves[0], leaves[1])};
    Hash proof_root;
    Check(IndexedProofRoot(leaves[2], 2, 3, proof_for_last, proof_root) &&
              proof_root == IndexedTreeRoot(std::span(leaves).first(3)),
          "odd-tail indexed proof");
    proof_for_last[0] = leaves[1];
    proof_root.fill(0xa5);
    Check(!IndexedProofRoot(leaves[2], 2, 3, proof_for_last, proof_root) && proof_root[0] == 0xa5,
          "reject nonzero padding and preserve failure output");
    proof_for_last[0] = Hash{};
    Check(!IndexedProofRoot(leaves[2], 3, 3, proof_for_last, proof_root),
          "reject out-of-range proof index");
    Check(!IndexedProofRoot(leaves[2], 2, 3, std::span(proof_for_last).first(1), proof_root),
          "reject missing proof sibling");
    Check(!IndexedProofRoot(leaves[2], 0, 1, proof_for_last, proof_root),
          "reject excess proof sibling");

    // Exercise the public uint32 count domain without allocating billions of
    // leaves. Ceil(width / 2) must not wrap at the first level.
    const uint32_t maximum_count = std::numeric_limits<uint32_t>::max();
    std::array<Hash, 32> maximum_proof{};
    proof_root.fill(0xa5);
    Check(!IndexedProofRoot(leaves[0], 0, maximum_count,
                            std::span(maximum_proof).first(1), proof_root) &&
              proof_root[0] == 0xa5,
          "maximum count rejects a truncated proof without changing output");
    Hash maximum_expected = leaves[0];
    for (uint16_t layer = 0; layer < maximum_proof.size(); ++layer) {
        maximum_expected = IndexedNode(layer, maximum_expected, maximum_proof[layer]);
    }
    Check(IndexedProofRoot(leaves[0], 0, maximum_count, maximum_proof, proof_root) &&
              proof_root == maximum_expected,
          "maximum count consumes all 32 proof levels");

    ChainId chain;
    TxHeaderCore header;
    for (unsigned i = 0; i < 32; ++i) chain[i] = i;
    for (unsigned i = 0; i < 16; ++i) header[i] = i + 32;
    const Hash inputs = IndexedTreeRoot(std::span(leaves).first(3));
    const Hash outputs = IndexedTreeRoot(std::array<Hash, 1>{OutputLeaf(output)});
    Check(Hex(TransactionId(chain, header, inputs, outputs)) ==
              "6f624e542cc6dd97e8bd6ca4e6f62334eaa2bb215de3cca4ef32a53705ad610b",
          "112-byte TxID preimage");
    Check(Hex(TransactionHash(chain, header, inputs, outputs)) ==
              "b8a0ac4394cafdbf04368907385d071014a4cefc4265bc1bc2dac9750ed2aab7",
          "112-byte TxHash preimage and domain separation");
    const char *tx_expected[] = {
        "24518f458e1e543b742619b81b0f24839a1753a447ff5322ca80fcfa705b0856",
        "79ef432f88e47dc9ee21acfd5262e3b464974ceee7298a46a34c5bb6db16fa7a",
        "f7c9fcf8c4e900a32619ff2ef62dcf49c2f48c5bb0d92e3765249aefbd55ebc1",
        "c189e9f413ac1b2b7042af4d88f1bc1953144f472ceb62d3858693d33f146285",
        "79745a49217a50d5b14f40d5f2773157254a239fb843cf82fd53b08236f986ce",
        "1949ad5d15ae127397638bcf31321189819a47b9dd96d86c7e1e8f1146777a8b",
    };
    std::vector<TxIdentityPair> txs;
    for (uint8_t i = 1; i <= 5; ++i) {
        TxIdentityPair pair{};
        pair.tx_hash.fill(i);
        pair.tx_id.fill(i + 16);
        txs.push_back(pair);
    }
    for (size_t n = 0; n <= txs.size(); ++n) {
        Hash root;
        Check(TransactionRoot(std::span(txs).first(n), root) && Hex(root) == tx_expected[n],
              "independent Merklix transaction root 0..5");
    }
    Hash original;
    TransactionRoot(std::span(txs).first(3), original);
    std::swap(txs[1], txs[2]);
    Hash subtree_reordered;
    Check(TransactionRoot(std::span(txs).first(3), subtree_reordered) &&
              subtree_reordered == original,
          "non-coinbase Subtree A is TxID-keyed and order-independent");
    std::swap(txs[1], txs[2]);
    std::swap(txs[0], txs[1]);
    Hash reordered;
    TransactionRoot(std::span(txs).first(3), reordered);
    Check(reordered != original, "coinbase leaf position is distinguished from Subtree A");
    std::vector<TxIdentityPair> dup_txs = {txs[0], txs[1], txs[1]};
    Hash untouched;
    untouched.fill(0xa5);
    Check(!TransactionRoot(dup_txs, untouched) && untouched[0] == 0xa5,
          "reject duplicate TxID in TransactionRoot");
    std::cout << "V2 commitment vectors and proof boundaries passed\n";
}
