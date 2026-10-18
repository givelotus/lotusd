// Copyright (c) 2026 The Lotus developers
#include "block_wire.h"
#include "signing.h"
#include <algorithm>
#include <limits>
#include <set>
namespace lotus::v2 {
namespace {
    void Put(std::vector<uint8_t> &out, uint64_t value, unsigned width) {
        for (unsigned i = 0; i < width; ++i)
            out.push_back(value >> (8 * i));
    }
    void Compact(std::vector<uint8_t> &out, uint64_t value) {
        if (value < 253)
            out.push_back(value);
        else {
            const unsigned width = value <= 65535        ? 2
                                   : value <= UINT32_MAX ? 4
                                                         : 8;
            out.push_back(width == 2 ? 253 : width == 4 ? 254 : 255);
            Put(out, value, width);
        }
    }
    bool Read(const std::vector<uint8_t> &wire, size_t &pos, unsigned width,
              uint64_t &v) {
        if (wire.size() - pos < width) return false;
        v = 0;
        for (unsigned i = 0; i < width; ++i)
            v |= uint64_t(wire[pos++]) << (8 * i);
        return true;
    }
    bool Frame(const std::vector<uint8_t> &wire, size_t &pos, uint64_t &v) {
        uint64_t lead;
        if (!Read(wire, pos, 1, lead)) return false;
        if (lead < 253) {
            v = lead;
            return true;
        }
        unsigned width = lead == 253 ? 2 : lead == 254 ? 4 : 8;
        return Read(wire, pos, width, v) && v >= (width == 2   ? 253ULL
                                                  : width == 4 ? 65536ULL
                                                               : 4294967296ULL);
    }
} // namespace
uint64_t CompactSizeWidth(uint64_t v) {
    return v < 253 ? 1 : v <= 65535 ? 3 : v <= UINT32_MAX ? 5 : 9;
}
namespace {
    bool CompleteTransactionRootImpl(
        const std::vector<Transaction> &txs, const TxProfile &profile,
        const ChainId &chain, bool wire_already_validated,
        std::vector<IdentityDigests> *identities_out, Hash &out,
        std::string &error) {
        if (txs.empty() || txs.size() > UINT32_MAX) {
            error = "missing coinbase or count";
            return false;
        }
        std::set<Hash> ids;
        std::vector<TxIdentityPair> pairs;
        pairs.reserve(txs.size());
        if (identities_out != nullptr) {
            identities_out->clear();
            identities_out->reserve(txs.size());
        }
        for (size_t n = 0; n < txs.size(); ++n) {
            bool coinbase = false;
            for (const auto &i : txs[n].inputs)
                coinbase |= i.flags == 2;
            if (coinbase != (n == 0)) {
                error = "first-and-only coinbase";
                return false;
            }
            IdentityDigests d;
            const bool ok =
                wire_already_validated
                    ? ComputeIdentitiesValidated(txs[n], profile, chain, d,
                                                 error)
                    : ComputeIdentities(txs[n], profile, chain, d, error);
            if (!ok) return false;
            if (!ids.insert(d.txid).second) {
                error = "duplicate transaction id";
                return false;
            }
            pairs.push_back({d.txhash, d.txid});
            if (identities_out != nullptr)
                identities_out->push_back(std::move(d));
        }
        Hash root;
        if (!TransactionRoot(pairs, root)) {
            error = "transaction root";
            return false;
        }
        out = root;
        error.clear();
        return true;
    }
} // namespace
bool CompleteTransactionRoot(const std::vector<Transaction> &txs,
                             const TxProfile &profile, const ChainId &chain,
                             Hash &out, std::string &error) {
    return CompleteTransactionRootImpl(txs, profile, chain, false, nullptr, out,
                                       error);
}
bool DecodeBlockWire(const std::vector<uint8_t> &wire, const TxProfile &profile,
                     const ChainId &chain, FramedBlock &out,
                     std::string &error) {
    FramedBlock b;
    if (wire.size() < HEADER_SIZE + 4 ||
        !ParseHeader(wire.data(), HEADER_SIZE, b.header)) {
        error = "block header frame";
        return false;
    }
    if (b.header.size != wire.size()) {
        error = "block size";
        return false;
    }
    size_t pos = HEADER_SIZE;
    uint64_t count;
    if (!Read(wire, pos, 4, count) || count == 0 ||
        count > (wire.size() - pos) / 17) {
        error = "block transaction count";
        return false;
    }
    // No reserve(count): malformed frames cannot trigger count-sized
    // allocation.
    for (uint64_t i = 0; i < count; ++i) {
        size_t start = pos;
        uint64_t len;
        if (!Frame(wire, pos, len) || len < 16 || len > wire.size() - pos) {
            error = "transaction frame";
            return false;
        }
        Transaction tx;
        if (!DecodeTransaction(std::vector<uint8_t>(wire.begin() + pos,
                                                    wire.begin() + pos + len),
                               profile, tx, error))
            return false;
        b.frame_prefix_bytes.push_back(pos - start);
        b.transaction_bytes.push_back(len);
        b.transactions.push_back(std::move(tx));
        pos += static_cast<size_t>(len);
    }
    if (pos != wire.size()) {
        error = "trailing block bytes";
        return false;
    }
    Hash root;
    if (!CompleteTransactionRootImpl(b.transactions, profile, chain, true,
                                     &b.transaction_identities, root, error))
        return false;
    if (root != b.header.tx_root) {
        error = "block transaction root";
        return false;
    }
    b.wire_bytes = wire.size();
    out = std::move(b);
    error.clear();
    return true;
}
bool EncodeBlockWire(const Header &header, const std::vector<Transaction> &txs,
                     const TxProfile &profile, std::vector<uint8_t> &out,
                     std::string &error) {
    if (txs.size() > UINT32_MAX) {
        error = "block transaction count";
        return false;
    }
    std::array<uint8_t, HEADER_SIZE> h;
    if (!SerializeHeader(header, h)) {
        error = "block header frame";
        return false;
    }
    std::vector<uint8_t> wire(h.begin(), h.end());
    Put(wire, txs.size(), 4);
    for (const auto &tx : txs) {
        std::vector<uint8_t> raw;
        if (!EncodeTransaction(tx, profile, raw, error)) return false;
        Compact(wire, raw.size());
        wire.insert(wire.end(), raw.begin(), raw.end());
    }
    if (header.size != wire.size()) {
        error = "block size";
        return false;
    }
    out = std::move(wire);
    error.clear();
    return true;
}
} // namespace lotus::v2
