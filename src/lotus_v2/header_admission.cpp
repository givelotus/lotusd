// Copyright (c) 2026 The Lotus developers
#include "header_admission.h"
#include "chain_index.h"
#include <exception>
namespace lotus::v2 {
HeaderAdmission AdmitDevelopmentHeader(
    const Header &candidate, const HeaderChainProfile &hp,
    const OrdinaryCandidateProfile &op, const MonetaryProfile &mp,
    const BlockCostProfile &cp, DiskStateStore &store, std::string &error) {
    using Result = HeaderAdmission;
    try {
        if (hp.genesis_id == Hash{} ||
            !store.MatchesProfile(hp.chain_id, BlockValidationProfileDigest(hp, op, mp, cp))) {
            error = "header admission validator profile mismatch"; return Result::StorageError;
        }
        Hash id, target;
        if (candidate.version != hp.version || candidate.size < HEADER_SIZE + 4 ||
            !BlockId(hp.chain_id, candidate, id) ||
            !DecodeTarget(candidate.bits, hp.pow_limit, target) || !MeetsTarget(id, target)) {
            error = "header encoding, profile, target or proof of work"; return Result::Invalid;
        }
        DiskStateError failure;
        std::optional<IndexedHeader> known;
        if (!store.ReadIndexedHeader(id, known, failure)) {
            error = failure.message; return Result::StorageError;
        }
        if (known) { error.clear(); return Result::Known; }
        if (candidate.height == 0) {
            error = id == hp.genesis_id ? "indexed genesis unavailable" : "peer genesis differs from manifest";
            return id == hp.genesis_id ? Result::StorageError : Result::Invalid;
        }
        std::optional<IndexedHeader> parent;
        if (!store.ReadIndexedHeader(candidate.prev_id, parent, failure)) {
            error = failure.message; return Result::StorageError;
        }
        if (!parent) { error = "header parent unavailable"; return Result::MissingParent; }
        // At most eleven indexed ancestors, independent of chain height.
        const size_t count = parent->header.height >= 10 ? 11 : size_t(parent->header.height) + 1;
        std::vector<Header> history;
        history.reserve(count);
        auto cursor = *parent;
        for (size_t i = 0; i < count; ++i) {
            history.push_back(cursor.header);
            if (i + 1 == count) break;
            std::optional<IndexedHeader> previous;
            if (!store.ReadIndexedHeader(cursor.header.prev_id, previous, failure)) {
                error = failure.message; return Result::StorageError;
            }
            if (!previous) {
                error = "indexed ancestry unavailable"; return Result::StorageError;
            }
            cursor = *previous;
        }
        if (!ParentMedianTime(hp, parent->header, history)) {
            error = "indexed parent history corrupt"; return Result::StorageError;
        }
        // These roots/size remain untrusted commitments until full body admission.
        if (!ValidateChildHeader(hp, parent->header, history, candidate,
                                 candidate.tx_root, candidate.state_root, candidate.size, error))
            return Result::Invalid;
        if (!store.PutCheckedHeader(candidate, failure)) {
            error = failure.message; return Result::StorageError;
        }
        error.clear(); return Result::Stored;
    } catch (const std::exception &e) { error = e.what(); return Result::StorageError; }
}
} // namespace lotus::v2
