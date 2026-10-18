// Copyright (c) 2026 The Lotus developers
#include "disk_body.h"
#include "block_wire.h"
#include <stdexcept>
#include <algorithm>
namespace lotus::v2 {
namespace {
MonetaryInteger Integer(const Hash &hash) {
    MonetaryInteger n = 0;
    for (auto i = hash.rbegin(); i != hash.rend(); ++i) { n <<= 8; n += *i; }
    return n;
}
}
RetainedBodyStatus ReadRetainedBlockBody(
    const Hash &id, uint64_t max_body_bytes, const HeaderChainProfile &hp,
    const OrdinaryCandidateProfile &op, const MonetaryProfile &mp,
    const BlockCostProfile &cp, const DiskStateStore &store,
    std::vector<uint8_t> &out, std::string &error) {
    using Status = RetainedBodyStatus;
    auto corrupt = [&](const char *message) { error = message; return Status::StorageError; };
    try {
        if (hp.genesis_id == Hash{} ||
            !store.MatchesProfile(hp.chain_id, BlockValidationProfileDigest(hp, op, mp, cp)))
            return corrupt("retained body validator profile mismatch");
        std::optional<RetainedDiskState> retained;
        DiskStateError failure;
        if (!store.ReadRetainedState(id, retained, failure)) {
            error = failure.message; return Status::StorageError;
        }
        if (!retained) { error.clear(); return Status::Missing; }
        const auto &meta = retained->metadata;
        if (meta.tip != id) return corrupt("retained body identity mismatch");
        // Refuse oversized replies before copying the body out of auxiliary.
        // The backend has already read the undo record; this bounds the next
        // copy/decoding step, not the database read itself.
        Header stored;
        if (!ParseHeader(meta.header.data(), meta.header.size(), stored))
            return corrupt("retained body header encoding");
        const auto &aux = meta.auxiliary;
        const std::array<uint8_t, 5> prefix{'L', 'V', '2', 'C', 1};
        if (aux.size() < 6 || !std::equal(prefix.begin(), prefix.end(), aux.begin()) ||
            !aux[5] || aux[5] > 11)
            return corrupt("retained body history framing");
        const size_t offset = 6 + size_t(aux[5]) * HEADER_SIZE;
        if (aux.size() < offset) return corrupt("retained body history framing");
        const size_t body_size = aux.size() - offset;
        if (body_size && (body_size != stored.size || body_size < HEADER_SIZE ||
            !std::equal(meta.header.begin(), meta.header.end(), aux.begin() + offset)))
            return corrupt("retained body header/length binding");
        if (body_size > max_body_bytes) {
            error = "retained body exceeds local response capacity"; return Status::CapacityRefused;
        }
        std::vector<Header> history;
        std::vector<uint8_t> body;
        if (!ReadDiskChainContext(meta, hp, history, body, error)) return Status::StorageError;
        if (body.empty()) { error.clear(); return Status::Missing; }
        FramedBlock block;
        if (!DecodeBlockWire(body, op.transaction, hp.chain_id, block, error)) return Status::StorageError;
        Hash actual, target;
        if (!BlockId(hp.chain_id, block.header, actual) || actual != id ||
            !DecodeTarget(block.header.bits, hp.pow_limit, target) || !MeetsTarget(id, target))
            return corrupt("retained body identity or proof of work");
        if (block.header.height == 0 && id != hp.genesis_id)
            return corrupt("retained body genesis identity");
        const auto money = DecodeMonetaryState(meta.monetary);
        if (Integer(money.prev_work) != (MonetaryInteger(1) << 256) / (Integer(target) + 1))
            return corrupt("retained body monetary target work");
        if (StateRoot(hp.chain_id, block.header.height, retained->root, money) != block.header.state_root)
            return corrupt("retained body state commitment");
        out = std::move(body); error.clear(); return Status::Available;
    } catch (const std::exception &e) { error = e.what(); return Status::StorageError; }
}
} // namespace lotus::v2
