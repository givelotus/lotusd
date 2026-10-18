// Copyright (c) 2026 The Lotus developers
#include "disk_block.h"
#include <stdexcept>
#include <algorithm>
#include <limits>
namespace lotus::v2 {
namespace {
class Adapter final : public BlockStateTransaction {
public:
    DiskStateTransaction &tx;
    DiskStateError last_failure;
    explicit Adapter(DiskStateTransaction &value) : tx(value) {}
    CoinReadResult Read(const Outpoint &key, Coin &coin, std::string &error) override {
        std::optional<Coin> found;
        DiskStateError failure;
        if (!tx.ReadCoin(key, found, failure)) {
            last_failure = failure; error = failure.message; return CoinReadResult::Error;
        }
        if (!found) return CoinReadResult::Missing;
        coin = std::move(*found); return CoinReadResult::Found;
    }
    bool Insert(const Coin &coin, std::string &error) override {
        DiskStateError failure;
        if (tx.Insert(coin, failure)) return true;
        last_failure = failure; error = failure.message; return false;
    }
    bool Erase(const Outpoint &key, std::string &error) override {
        DiskStateError failure;
        if (tx.Erase(key, failure)) return true;
        last_failure = failure; error = failure.message; return false;
    }
    Hash Root() const override { return tx.Root(); }
    void Abort() noexcept override { tx.Abort(); }
};
} // namespace
std::vector<uint8_t> EncodeDiskChainContext(const std::vector<Header> &history,
                                          const std::vector<uint8_t> &block) {
    if (history.empty() || history.size() > 11)
        throw std::invalid_argument("disk history count");
    std::vector<uint8_t> bytes{'L', 'V', '2', 'C', 1, uint8_t(history.size())};
    for (const auto &header : history) {
        std::array<uint8_t, HEADER_SIZE> encoded;
        if (!SerializeHeader(header, encoded))
            throw std::invalid_argument("disk history header");
        bytes.insert(bytes.end(), encoded.begin(), encoded.end());
    }
    if (!block.empty() && (block.size() != history.front().size ||
        block.size() < HEADER_SIZE ||
        !std::equal(bytes.begin() + 6, bytes.begin() + 6 + HEADER_SIZE, block.begin())))
        throw std::invalid_argument("disk history block binding");
    bytes.insert(bytes.end(), block.begin(), block.end());
    return bytes;
}
bool ReadDiskChainContext(const DiskStateMetadata &meta, const HeaderChainProfile &hp,
                          std::vector<Header> &history, std::vector<uint8_t> &block,
                          std::string &error) {
    const auto &bytes = meta.auxiliary;
    const std::vector<uint8_t> prefix{'L', 'V', '2', 'C', 1};
    auto fail = [&]() { error = "stored chain history encoding or binding"; return false; };
    if (bytes.size() < 6 || !std::equal(prefix.begin(), prefix.end(), bytes.begin()) ||
        bytes[5] == 0 || bytes[5] > 11) return fail();
    const size_t end = 6 + size_t(bytes[5]) * HEADER_SIZE;
    if (bytes.size() < end) return fail();
    std::vector<Header> decoded(bytes[5]);
    for (size_t i = 0; i < decoded.size(); ++i)
        if (!ParseHeader(bytes.data() + 6 + i * HEADER_SIZE, HEADER_SIZE, decoded[i])) return fail();
    Header parent;
    Hash id;
    if (!ParseHeader(meta.header.data(), meta.header.size(), parent) ||
        !BlockId(hp.chain_id, parent, id) || id != meta.tip ||
        !ParentMedianTime(hp, parent, decoded)) return fail();
    const size_t body_size = bytes.size() - end;
    if (body_size && (body_size != parent.size || body_size < HEADER_SIZE ||
        !std::equal(meta.header.begin(), meta.header.end(), bytes.begin() + end))) return fail();
    std::vector<uint8_t> body(bytes.begin() + end, bytes.end());
    history = std::move(decoded); block = std::move(body); error.clear(); return true;
}
static CandidateCheckResult ConnectDiskBlockImpl(
    const std::vector<uint8_t> &, const std::vector<Header> &,
    const HeaderChainProfile &, const OrdinaryCandidateProfile &,
    const MonetaryProfile &, const BlockCostProfile &, const DiskRecoveryUpdate *,
    DiskStateStore &, StagedBlockTransition &, std::string &, DeterministicBlockFailure *);
static CandidateCheckResult ConnectStoredDiskBlockImpl(
    const std::vector<uint8_t> &wire, const HeaderChainProfile &hp,
    OrdinaryCandidateProfile op, const MonetaryProfile &mp, const BlockCostProfile &cp,
    const DiskRecoveryUpdate *recovery, DiskStateStore &store,
    StagedBlockTransition &out, std::string &error,
    DeterministicBlockFailure *failure) {
    if (failure) *failure = DeterministicBlockFailure{};
    try {
        std::vector<Header> history;
        std::vector<uint8_t> block;
        if (!ReadDiskChainContext(store.Metadata(), hp, history, block, error))
            return CandidateCheckResult::StorageError;
        if (history.front().height == std::numeric_limits<uint64_t>::max()) {
            error = "stored chain height exhausted"; return CandidateCheckResult::StorageError;
        }
        op.candidate_height = history.front().height + 1;
        op.parent_mtp = *ParentMedianTime(hp, history.front(), history);
        return ConnectDiskBlockImpl(wire, history, hp, op, mp, cp, recovery, store, out, error, failure);
    } catch (const std::exception &e) {
        error = e.what(); return CandidateCheckResult::StorageError;
    }
}
CandidateCheckResult ConnectStoredDiskBlock(
    const std::vector<uint8_t> &wire, const HeaderChainProfile &hp,
    OrdinaryCandidateProfile op, const MonetaryProfile &mp, const BlockCostProfile &cp,
    DiskStateStore &store, StagedBlockTransition &out, std::string &error,
    DeterministicBlockFailure *failure) {
    if (failure) *failure = DeterministicBlockFailure{};
    return ConnectStoredDiskBlockImpl(wire, hp, std::move(op), mp, cp, nullptr, store, out, error, failure);
}
namespace {
BlockPreviewResult PreviewStorageResult(const DiskStateError &error) {
    if (error.code == DiskStateErrorCode::Resource) return BlockPreviewResult::CapacityRefused;
    if (error.code == DiskStateErrorCode::TransactionAborted) return BlockPreviewResult::Inconclusive;
    return BlockPreviewResult::StorageError;
}
struct AbortDiskPreview {
    DiskStateTransaction &tx;
    ~AbortDiskPreview() { tx.Abort(); }
};
} // namespace
BlockPreviewResult PreviewStoredBlockTemplate(
    const std::vector<Transaction> &transactions, uint64_t time,
    const BlockPreviewLimits &limits, const HeaderChainProfile &hp,
    OrdinaryCandidateProfile op, const MonetaryProfile &mp, const BlockCostProfile &cp,
    DiskStateStore &store, BlockPreview &out, std::string &error) {
    using Result = BlockPreviewResult;
    try {
        if (!store.IsOpen()) { error = "chainstate database unavailable"; return Result::StorageError; }
        const Hash profile = BlockValidationProfileDigest(hp, op, mp, cp);
        if (!store.MatchesProfile(hp.chain_id, profile)) {
            error = "stored validator profile mismatch"; return Result::StorageError;
        }
        const auto before = store.Metadata(); const Hash root = store.Root();
        // Read the checksummed persisted head as well as the cached snapshot.
        // Store creation caps bound these metadata copies separately from limits.
        DiskStateError storage_error; std::optional<RetainedDiskState> persisted;
        if (!store.ReadRetainedState(before.tip, persisted, storage_error)) {
            error = storage_error.message; return PreviewStorageResult(storage_error);
        }
        if (!persisted || persisted->metadata != before || persisted->root != root) {
            error = "stored preview parent changed"; return Result::StorageError;
        }
        std::vector<Header> history; std::vector<uint8_t> previous_block;
        if (!ReadDiskChainContext(before, hp, history, previous_block, error)) return Result::StorageError;
        OrdinaryParentContext parent; parent.chain_id = hp.chain_id;
        if (!ParseHeader(before.header.data(), before.header.size(), parent.header)) {
            error = "stored parent header encoding"; return Result::StorageError;
        }
        parent.monetary = DecodeMonetaryState(before.monetary); Hash parent_id;
        if (!BlockId(parent.chain_id, parent.header, parent_id) || parent_id != before.tip ||
            StateRoot(parent.chain_id, parent.header.height, root, parent.monetary) != parent.header.state_root) {
            error = "stored parent tip or state mismatch"; return Result::StorageError;
        }
        const auto mtp = ParentMedianTime(hp, parent.header, history);
        if (!mtp || parent.header.height == UINT64_MAX) {
            error = "stored preview parent context unavailable"; return Result::StorageError;
        }
        op.candidate_height = parent.header.height + 1; op.parent_mtp = *mtp;
        DiskStateTransaction tx;
        if (!store.Begin(tx, storage_error)) { error = storage_error.message; return PreviewStorageResult(storage_error); }
        AbortDiskPreview abort{tx}; Adapter adapter(tx); BlockPreview preview;
        const auto result = PreviewBlockTemplate(transactions, time, limits, parent, history,
                                                 hp, op, mp, cp, adapter, preview, error);
        if (result != Result::Ready) {
            if (adapter.last_failure.code != DiskStateErrorCode::None) return PreviewStorageResult(adapter.last_failure);
            return result;
        }
        if (store.Metadata() != before || store.Root() != root || preview.parent_id != before.tip ||
            preview.parent_utxo_root != root || preview.profile_digest != profile) {
            error = "chainstate parent changed during preview"; return Result::StorageError;
        }
        out = std::move(preview); error.clear(); return Result::Ready;
    } catch (const std::bad_alloc &) {
        error = "disk preview allocation failure"; return Result::CapacityRefused;
    } catch (const std::length_error &) {
        error = "disk preview allocation length"; return Result::CapacityRefused;
    } catch (const std::exception &exception) {
        error = exception.what(); return Result::StorageError;
    }
}
CandidateCheckResult ConnectStoredRecoveryBlock(
    const std::vector<uint8_t> &wire, const HeaderChainProfile &hp,
    OrdinaryCandidateProfile op, const MonetaryProfile &mp, const BlockCostProfile &cp,
    const DiskRecoveryUpdate &recovery, DiskStateStore &store,
    StagedBlockTransition &out, std::string &error,
    DeterministicBlockFailure *failure) {
    if (failure) *failure = DeterministicBlockFailure{};
    return ConnectStoredDiskBlockImpl(wire, hp, std::move(op), mp, cp, &recovery, store, out, error, failure);
}
DiskBlockAdmission ConnectEligibleDiskBlock(
    const std::vector<uint8_t> &wire, uint64_t now, uint64_t future_window,
    const HeaderChainProfile &hp, OrdinaryCandidateProfile op,
    const MonetaryProfile &mp, const BlockCostProfile &cp,
    DiskStateStore &store, StagedBlockTransition &out, std::string &error,
    DeterministicBlockFailure *failure) {
    if (failure) *failure = DeterministicBlockFailure{};
    Header header;
    if (wire.size() < HEADER_SIZE || !ParseHeader(wire.data(), HEADER_SIZE, header)) {
        error = "block header encoding"; return DiskBlockAdmission::Invalid;
    }
    // Subtraction avoids overflow in now + future_window. A clock moving
    // backwards changes only eligibility; no database mutation has happened.
    if (header.time > now && header.time - now > future_window) {
        error = "block time not yet eligible"; return DiskBlockAdmission::Deferred;
    }
    switch (ConnectStoredDiskBlock(wire, hp, std::move(op), mp, cp, store, out, error, failure)) {
    case CandidateCheckResult::Accepted: return DiskBlockAdmission::Accepted;
    case CandidateCheckResult::Invalid: return DiskBlockAdmission::Invalid;
    case CandidateCheckResult::StorageError: return DiskBlockAdmission::StorageError;
    case CandidateCheckResult::Inconclusive: return DiskBlockAdmission::Inconclusive;
    }
    error = "unknown block validation result";
    return DiskBlockAdmission::StorageError;
}
static CandidateCheckResult ConnectDiskBlockImpl(
    const std::vector<uint8_t> &wire, const std::vector<Header> &history,
    const HeaderChainProfile &hp, const OrdinaryCandidateProfile &op,
    const MonetaryProfile &mp, const BlockCostProfile &cp, const DiskRecoveryUpdate *recovery,
    DiskStateStore &store, StagedBlockTransition &out, std::string &error,
    DeterministicBlockFailure *failure) {
    if (failure) *failure = DeterministicBlockFailure{};
    using Result = CandidateCheckResult;
    try {
        if (!store.IsOpen()) { error = "chainstate database unavailable"; return Result::StorageError; }
        if (!store.MatchesProfile(hp.chain_id, BlockValidationProfileDigest(hp, op, mp, cp))) {
            error = "stored validator profile mismatch"; return Result::StorageError;
        }
        const auto before = store.Metadata();
        OrdinaryParentContext parent;
        parent.chain_id = hp.chain_id;
        if (!ParseHeader(before.header.data(), before.header.size(), parent.header)) {
            error = "stored parent header encoding"; return Result::StorageError;
        }
        parent.monetary = DecodeMonetaryState(before.monetary);
        Hash parent_id;
        if (!BlockId(parent.chain_id, parent.header, parent_id) || parent_id != before.tip ||
            StateRoot(parent.chain_id, parent.header.height, store.Root(), parent.monetary) !=
                parent.header.state_root) {
            error = "stored parent tip or state mismatch"; return Result::StorageError;
        }
        DiskStateTransaction tx;
        DiskStateError storage_error;
        const bool begun = recovery ? store.BeginRecovery(*recovery, tx, storage_error) : store.Begin(tx, storage_error);
        if (!begun) { error = storage_error.message; return Result::StorageError; }
        Adapter adapter(tx);
        StagedBlockTransition staged;
        const auto result = StageCompleteBlock(wire, parent, history, hp, op, mp, cp,
                                               adapter, staged, error, failure);
        if (result != Result::Accepted) return result;
        // Single-writer API plus this fence prohibits publication against a
        // different tip. Store's active transaction also prevents disconnect.
        if (store.Metadata() != before) {
            error = "chainstate parent changed during validation";
            return Result::StorageError;
        }
        DiskStateMetadata next;
        next.tip = staged.block_id;
        std::array<uint8_t, HEADER_SIZE> header;
        if (!SerializeHeader(staged.header, header)) {
            error = "validated header serialization"; return Result::StorageError;
        }
        next.header.assign(header.begin(), header.end());
        const auto money = EncodeMonetaryState(staged.monetary.state);
        next.monetary.assign(money.begin(), money.end());
        // Persist exact complete bytes with the same atomic state transition.
        // Backend limits are operational; no partial/truncated block is stored.
        std::vector<Header> recent{staged.header};
        recent.insert(recent.end(), history.begin(), history.begin() + std::min(size_t(10), history.size()));
        next.auxiliary = EncodeDiskChainContext(recent, wire);
        if (!tx.Commit(next, staged.header, storage_error)) { error = storage_error.message; return Result::StorageError; }
        out = std::move(staged);
        error.clear();
        return Result::Accepted;
    } catch (const std::exception &e) {
        error = e.what();
        return Result::StorageError;
    }
}
CandidateCheckResult ConnectDiskBlock(
    const std::vector<uint8_t> &wire, const std::vector<Header> &history,
    const HeaderChainProfile &hp, const OrdinaryCandidateProfile &op,
    const MonetaryProfile &mp, const BlockCostProfile &cp,
    DiskStateStore &store, StagedBlockTransition &out, std::string &error,
    DeterministicBlockFailure *failure) {
    if (failure) *failure = DeterministicBlockFailure{};
    return ConnectDiskBlockImpl(wire, history, hp, op, mp, cp, nullptr, store, out, error, failure);
}
} // namespace lotus::v2
