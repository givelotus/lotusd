#include "commitment.h"

#include "tagged_hash.h"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <vector>

#include <future>

namespace lotus::v2 {
namespace {

std::vector<uint8_t> EncodeBytes(std::span<const uint8_t> bytes) {
    const uint64_t n = bytes.size();
    std::vector<uint8_t> out;
    out.reserve(bytes.size() + 9);
    if (n < 253) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffff) {
        out.push_back(253);
        out.push_back(static_cast<uint8_t>(n));
        out.push_back(static_cast<uint8_t>(n >> 8));
    } else if (n <= 0xffffffffU) {
        out.push_back(254);
        for (unsigned i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(n >> (8 * i)));
    } else {
        out.push_back(255);
        for (unsigned i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(n >> (8 * i)));
    }
    out.insert(out.end(), bytes.begin(), bytes.end());
    return out;
}

bool LessLittleEndian(const Hash &a, const Hash &b) {
    for (int i = 31; i >= 0; --i) {
        if (a[i] != b[i]) return a[i] < b[i];
    }
    return false;
}

bool TxKeyBit(const Hash &tx_id, unsigned depth) {
    return (tx_id[depth / 8] >> (depth % 8)) & 1;
}

Hash EmptyTxRoot() {
    static const Hash kEmpty =
        TaggedHash(HashDomain::TxRoot, std::array<uint8_t, 1>{2});
    return kEmpty;
}

Hash TxLeaf(const TxIdentityPair &tx) {
    std::array<uint8_t, 65> input{};
    input[0] = 0;
    std::copy(tx.tx_id.begin(), tx.tx_id.end(), input.begin() + 1);
    std::copy(tx.tx_hash.begin(), tx.tx_hash.end(), input.begin() + 33);
    return TaggedHash(HashDomain::TxRoot, input);
}

Hash TxNodeAtDepth(unsigned depth, const Hash &left, const Hash &right) {
    std::array<uint8_t, 67> input{};
    input[0] = 1;
    input[1] = static_cast<uint8_t>(depth);
    input[2] = static_cast<uint8_t>(depth >> 8);
    std::copy(left.begin(), left.end(), input.begin() + 3);
    std::copy(right.begin(), right.end(), input.begin() + 35);
    return TaggedHash(HashDomain::TxRoot, input);
}

Hash TransactionSubtreeA(std::span<const TxIdentityPair *> entries,
                         unsigned depth) {
    if (entries.empty()) return EmptyTxRoot();
    if (entries.size() == 1) return TxLeaf(*entries[0]);
    if (depth >= 256) {
        throw std::invalid_argument("duplicate transaction identifier in subtree");
    }
    // The public call owns one pointer array. Descendants reorder disjoint
    // portions of it; transaction identities themselves are immutable. No
    // recursive left/right vectors or per-level partition allocations.
    const auto split = std::partition(entries.begin(), entries.end(),
        [depth](const TxIdentityPair *entry) {
            return !TxKeyBit(entry->tx_id, depth);
        });
    const auto left = entries.first(static_cast<size_t>(split - entries.begin()));
    const auto right = entries.subspan(left.size());
    if (depth < 4 && entries.size() >= 64 && !left.empty() && !right.empty()) {
        auto left_future = std::async(std::launch::async, [left, depth]() {
            return TransactionSubtreeA(left, depth + 1);
        });
        const Hash right_hash = TransactionSubtreeA(right, depth + 1);
        return TxNodeAtDepth(depth, left_future.get(), right_hash);
    }
    return TxNodeAtDepth(depth, TransactionSubtreeA(left, depth + 1),
                         TransactionSubtreeA(right, depth + 1));
}

Hash TransactionIdentity(HashDomain domain, const ChainId &chain_id,
                         const TxHeaderCore &header_core, const Hash &input_root,
                         const Hash &output_root) {
    std::array<uint8_t, 112> input{};
    std::copy(chain_id.begin(), chain_id.end(), input.begin());
    std::copy(header_core.begin(), header_core.end(), input.begin() + 32);
    std::copy(input_root.begin(), input_root.end(), input.begin() + 48);
    std::copy(output_root.begin(), output_root.end(), input.begin() + 80);
    return TaggedHash(domain, input);
}

} // namespace

Hash InputCoreLeaf(std::span<const uint8_t> encoded_input_core) {
    return TaggedHash(HashDomain::InputCore, encoded_input_core);
}
Hash InputFullLeaf(std::span<const uint8_t> encoded_input) {
    return TaggedHash(HashDomain::InputFull, encoded_input);
}
Hash OutputLeaf(std::span<const uint8_t> serialized_output) {
    if (serialized_output.size() < 253) {
        std::array<uint8_t, 253> buf{};
        buf[0] = static_cast<uint8_t>(serialized_output.size());
        if (!serialized_output.empty()) {
            std::memcpy(buf.data() + 1, serialized_output.data(),
                        serialized_output.size());
        }
        return TaggedHash(
            HashDomain::Output,
            std::span<const uint8_t>(buf.data(), 1 + serialized_output.size()));
    }
    return TaggedHash(HashDomain::Output, EncodeBytes(serialized_output));
}
Hash CoinEntryLeaf(std::span<const uint8_t> serialized_resolved_output) {
    if (serialized_resolved_output.size() < 253) {
        std::array<uint8_t, 253> buf{};
        buf[0] = static_cast<uint8_t>(serialized_resolved_output.size());
        if (!serialized_resolved_output.empty()) {
            std::memcpy(buf.data() + 1, serialized_resolved_output.data(),
                        serialized_resolved_output.size());
        }
        return TaggedHash(
            HashDomain::CoinEntry,
            std::span<const uint8_t>(buf.data(),
                                     1 + serialized_resolved_output.size()));
    }
    return TaggedHash(HashDomain::CoinEntry, EncodeBytes(serialized_resolved_output));
}
Hash BranchLeaf(std::span<const uint8_t> script) {
    if (script.size() < 253) {
        std::array<uint8_t, 254> buf{};
        buf[0] = 0;
        buf[1] = static_cast<uint8_t>(script.size());
        if (!script.empty()) {
            std::memcpy(buf.data() + 2, script.data(), script.size());
        }
        return TaggedHash(
            HashDomain::Branch,
            std::span<const uint8_t>(buf.data(), 2 + script.size()));
    }
    const auto bytes = EncodeBytes(script);
    std::vector<uint8_t> input;
    input.reserve(1 + bytes.size());
    input.push_back(0);
    input.insert(input.end(), bytes.begin(), bytes.end());
    return TaggedHash(HashDomain::Branch, input);
}
Hash LegacyBridgeLeaf(std::span<const uint8_t> coin_script,
                      std::span<const uint8_t> witness_script) {
    const auto coin = EncodeBytes(coin_script);
    const auto witness = EncodeBytes(witness_script);
    std::vector<uint8_t> input;
    input.reserve(1 + coin.size() + witness.size());
    input.push_back(3);
    input.insert(input.end(), coin.begin(), coin.end());
    input.insert(input.end(), witness.begin(), witness.end());
    return TaggedHash(HashDomain::Branch, input);
}
Hash BranchNode(const Hash &a, const Hash &b) {
    std::array<uint8_t, 65> input{};
    const Hash &low = LessLittleEndian(a, b) ? a : b;
    const Hash &high = LessLittleEndian(a, b) ? b : a;
    input[0] = 1;
    std::copy(low.begin(), low.end(), input.begin() + 1);
    std::copy(high.begin(), high.end(), input.begin() + 33);
    return TaggedHash(HashDomain::Branch, input);
}
Hash BranchProofRoot(const Hash &leaf, std::span<const Hash> bottom_up_siblings) {
    Hash root = leaf;
    for (const Hash &sibling : bottom_up_siblings) root = BranchNode(root, sibling);
    return root;
}
Hash IndexedNode(uint16_t layer, const Hash &left, const Hash &right) {
    std::array<uint8_t, 67> input{};
    input[0] = 1;
    input[1] = static_cast<uint8_t>(layer);
    input[2] = static_cast<uint8_t>(layer >> 8);
    std::copy(left.begin(), left.end(), input.begin() + 3);
    std::copy(right.begin(), right.end(), input.begin() + 35);
    return TaggedHash(HashDomain::MerkleIndex, input);
}
Hash IndexedTreeRoot(std::span<const Hash> leaves) {
    if (leaves.empty()) return TaggedHash(HashDomain::MerkleIndex, std::array<uint8_t, 1>{2});
    if (leaves.size() == 1) return leaves[0];
    if (leaves.size() == 2) return IndexedNode(0, leaves[0], leaves[1]);
    if (leaves.size() <= 16) {
        std::array<Hash, 16> cur{};
        size_t n = leaves.size();
        std::copy(leaves.begin(), leaves.end(), cur.begin());
        uint16_t layer = 0;
        while (n > 1) {
            if (n & 1) cur[n++] = Hash{};
            const size_t half = n / 2;
            for (size_t i = 0; i < half; ++i) {
                cur[i] = IndexedNode(layer, cur[2 * i], cur[2 * i + 1]);
            }
            n = half;
            ++layer;
        }
        return cur[0];
    }
    std::vector<Hash> cur(leaves.begin(), leaves.end());
    uint16_t layer = 0;
    while (cur.size() > 1) {
        if (cur.size() & 1) cur.push_back(Hash{});
        std::vector<Hash> next;
        next.reserve(cur.size() / 2);
        for (size_t i = 0; i < cur.size(); i += 2) {
            next.push_back(IndexedNode(layer, cur[i], cur[i + 1]));
        }
        cur = std::move(next);
        ++layer;
    }
    return cur[0];
}
bool IndexedProofRoot(const Hash &leaf, uint32_t index, uint32_t count,
                      std::span<const Hash> siblings, Hash &out) {
    if (count == 0 || index >= count) return false;
    uint32_t width = count;
    uint32_t offset = index;
    size_t layer = 0;
    Hash root = leaf;
    while (width > 1) {
        if (layer >= siblings.size()) return false;
        const Hash &sibling = siblings[layer];
        if ((offset & 1) == 0 && offset + 1 == width && sibling != Hash{}) return false;
        root = (offset & 1) ? IndexedNode(layer, sibling, root)
                            : IndexedNode(layer, root, sibling);
        offset >>= 1;
        width = width / 2 + (width & 1);
        ++layer;
    }
    if (layer != siblings.size()) return false;
    out = root;
    return true;
}
Hash TransactionId(const ChainId &chain_id, const TxHeaderCore &header_core,
                   const Hash &inputs_root, const Hash &outputs_root) {
    return TransactionIdentity(HashDomain::TxId, chain_id, header_core, inputs_root, outputs_root);
}
Hash TransactionHash(const ChainId &chain_id, const TxHeaderCore &header_core,
                     const Hash &full_inputs_root, const Hash &outputs_root) {
    return TransactionIdentity(HashDomain::TxHash, chain_id, header_core, full_inputs_root, outputs_root);
}
bool TransactionRoot(std::span<const TxIdentityPair> transactions, Hash &out) {
    if (transactions.size() > std::numeric_limits<uint32_t>::max()) return false;
    if (transactions.empty()) {
        out = EmptyTxRoot();
        return true;
    }
    if (transactions.size() > 1) {
        std::vector<const Hash *> ids;
        ids.reserve(transactions.size());
        for (const auto &tx : transactions) {
            ids.push_back(&tx.tx_id);
        }
        std::sort(ids.begin(), ids.end(),
                  [](const Hash *a, const Hash *b) { return *a < *b; });
        for (size_t i = 1; i < ids.size(); ++i) {
            if (*ids[i - 1] == *ids[i]) return false;
        }
    }
    std::vector<const TxIdentityPair *> entries;
    entries.reserve(transactions.size() - 1);
    for (size_t i = 1; i < transactions.size(); ++i) {
        entries.push_back(&transactions[i]);
    }
    const Hash subtree_a = TransactionSubtreeA(entries, 0);
    out = TransactionRootFromSubtreeA(transactions[0], subtree_a);
    return true;
}

Hash TransactionSubtreeARoot(
    std::span<const TxIdentityPair> non_coinbase_transactions) {
    std::vector<const TxIdentityPair *> entries;
    entries.reserve(non_coinbase_transactions.size());
    for (const auto &tx : non_coinbase_transactions) {
        entries.push_back(&tx);
    }
    // A key has exactly 256 bits. Equal keys never split and must not reach
    // the recursive bit walker (even when their witness hashes differ).
    std::sort(entries.begin(), entries.end(), [](const auto *a, const auto *b) {
        return a->tx_id < b->tx_id;
    });
    for (size_t i = 1; i < entries.size(); ++i) {
        if (entries[i - 1]->tx_id == entries[i]->tx_id) {
            throw std::invalid_argument("duplicate transaction identifier in subtree");
        }
    }
    return TransactionSubtreeA(entries, 0);
}

Hash TransactionRootFromSubtreeA(const TxIdentityPair &coinbase_tx,
                                 const Hash &subtree_a_root) {
    const Hash coinbase_leaf = TxLeaf(coinbase_tx);
    std::array<uint8_t, 65> input{};
    input[0] = 3;
    std::copy(coinbase_leaf.begin(), coinbase_leaf.end(), input.begin() + 1);
    std::copy(subtree_a_root.begin(), subtree_a_root.end(), input.begin() + 33);
    return TaggedHash(HashDomain::TxRoot, input);
}

Hash BuildTxSubtreeA(
    std::span<const TxIdentityPair> non_coinbase_transactions) {
    return TransactionSubtreeARoot(non_coinbase_transactions);
}

Hash CombineCoinbaseAndSubtreeA(const TxIdentityPair &coinbase_tx,
                                const Hash &subtree_a_root) {
    return TransactionRootFromSubtreeA(coinbase_tx, subtree_a_root);
}

} // namespace lotus::v2
