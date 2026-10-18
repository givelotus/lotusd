// Copyright (c) 2026 The Lotus developers
#include "block.h"

#include "header.h"
#include "signing.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace lotus::v2 {
namespace {
    constexpr uint32_t SNAPSHOT_COIN_CAP = 65535;

    bool SameMonetary(const MonetaryState &a, const MonetaryState &b) {
        return a.bootstrap_reserve == b.bootstrap_reserve &&
               a.tail_subsidy == b.tail_subsidy && a.prev_work == b.prev_work &&
               a.ema_block_cost == b.ema_block_cost;
    }

    MonetaryInteger WideToInteger(VmCostUnits value) {
        MonetaryInteger out = 0;
        for (int byte = 0; byte < 16; ++byte) {
            out += MonetaryInteger(static_cast<unsigned>(
                       static_cast<uint8_t>(value >> (8 * byte))))
                   << (8 * byte);
        }
        return out;
    }

    MonetaryInteger WorkOf(const Hash &work) {
        MonetaryInteger value = 0;
        for (size_t i = work.size(); i > 0; --i) {
            value <<= 8;
            value += work[i - 1];
        }
        return value;
    }

    bool ViewAgrees(const DevelopmentUtxoView &view,
                    const IncrementalUtxoSet &utxo, std::string &error) {
        UtxoSet scalar;
        for (const auto &entry : view) {
            if (entry.first != entry.second.outpoint ||
                !scalar.Insert(entry.second)) {
                error = "development view is not a utxo set";
                return false;
            }
        }
        if (scalar.Size() != utxo.Size() || scalar.Root() != utxo.Root()) {
            error = "incremental utxo view diverges from development view";
            return false;
        }
        return true;
    }

    void ReverseApplied(DevelopmentUtxoView &view,
                        const std::vector<Coin> &removed,
                        const OrdinaryCandidateEffects &effects) {
        for (const Coin &coin : effects.created)
            view.erase(coin.outpoint);
        for (const Coin &coin : removed)
            view.emplace(coin.outpoint, coin);
    }

    bool PutU32(std::vector<uint8_t> &out, uint32_t value) {
        for (int byte = 0; byte < 4; ++byte)
            out.push_back(static_cast<uint8_t>(value >> (8 * byte)));
        return true;
    }

    bool TakeU32(const std::vector<uint8_t> &bytes, size_t &offset,
                 uint32_t &value) {
        if (offset > bytes.size() || bytes.size() - offset < 4) return false;
        value = 0;
        for (int byte = 0; byte < 4; ++byte)
            value |= uint32_t(bytes[offset + byte]) << (8 * byte);
        offset += 4;
        return true;
    }

    uint64_t ReadLE(const uint8_t *data, unsigned width) {
        uint64_t value = 0;
        for (unsigned i = 0; i < width; ++i)
            value |= uint64_t(data[i]) << (8 * i);
        return value;
    }

    bool ReadCompact(const uint8_t *data, size_t size, size_t &offset,
                     uint64_t cap, uint64_t &value) {
        if (offset >= size) return false;
        const uint64_t lead = data[offset++];
        if (lead < 253) {
            value = lead;
        } else {
            const unsigned width = lead == 253 ? 2 : lead == 254 ? 4 : 8;
            if (offset > size || size - offset < width) return false;
            value = ReadLE(data + offset, width);
            offset += width;
            const uint64_t min_value = width == 2   ? 253
                                       : width == 4 ? 65536ULL
                                                    : 4294967296ULL;
            if (value < min_value) return false;
        }
        return value <= cap;
    }

    bool DecodeSnapshotCoin(const std::vector<uint8_t> &encoded, Coin &coin) {
        if (encoded.size() > MAX_COIN_BYTES) return false;
        size_t offset = 0;
        const uint8_t *raw = encoded.data();
        if (encoded.size() < 36) return false;
        std::copy_n(raw, 32, coin.outpoint.tx_id.begin());
        coin.outpoint.index = static_cast<uint32_t>(ReadLE(raw + 32, 4));
        offset = 36;
        uint64_t output_len = 0;
        if (!ReadCompact(raw, encoded.size(), offset, MAX_COIN_BYTES,
                         output_len) ||
            offset > encoded.size() || encoded.size() - offset < output_len)
            return false;
        std::string error;
        Output output;
        if (!DecodeOutput(
                std::vector<uint8_t>(raw + offset, raw + offset + output_len),
                output, error))
            return false;
        offset += static_cast<size_t>(output_len);
        if (encoded.size() - offset != COIN_METADATA_BYTES) return false;
        coin.output = std::move(output);
        coin.creation_height = ReadLE(raw + offset, 8);
        coin.creation_parent_mtp = ReadLE(raw + offset + 8, 8);
        const uint8_t flag = raw[offset + 16];
        if (flag > 1) return false;
        coin.coinbase = flag == 1;
        if (raw[offset + 17] != COIN_ENCODING_VERSION) return false;
        coin.fee_per_output = ReadLE(raw + offset + 18, 8);
        coin.expiration_height = ReadLE(raw + offset + 26, 8);
        return true;
    }

    bool IsCoinbaseTransaction(const Transaction &tx) {
        for (const Input &input : tx.inputs) {
            if (input.flags == 2) return true;
        }
        return false;
    }

    // Ordinary slice allows no coinbase; complete wire boundary requires one.
    bool CoinbasePlacement(const std::vector<Transaction> &transactions,
                           std::string &error) {
        bool seen = false;
        for (size_t i = 0; i < transactions.size(); ++i) {
            if (!IsCoinbaseTransaction(transactions[i])) continue;
            if (seen || i != 0) {
                error = "coinbase position";
                return false;
            }
            seen = true;
        }
        return true;
    }

    // Development candidate only. EncodeTransaction rejects a bad coinbase
    // shape. Non-burn outputs become coins; burn outputs are summed and not
    // inserted.
    bool StageDevelopmentCoinbase(
        const Transaction &tx, const OrdinaryParentContext &parent,
        const OrdinaryCandidateProfile &profile, DevelopmentUtxoView &view,
        IncrementalUtxoSet &utxo, OrdinaryBlockUndo &undo,
        MonetaryInteger &native_outputs, MonetaryInteger &native_burn,
        uint64_t &coinbase_bytes, std::string &error,
        const uint64_t *precomputed_wire_bytes = nullptr,
        const IdentityDigests *precomputed_identities = nullptr) {
        Hash parent_id{};
        if (!BlockId(parent.chain_id, parent.header, parent_id)) {
            error = "coinbase parent id";
            return false;
        }
        // prev_txid is the parent header's BlockId. prev_index is this block's
        // height. A zero id is not the development genesis id.
        if (!CheckCoinbaseContext(tx, parent_id, profile.candidate_height,
                                  error))
            return false;
        uint64_t wire_size = 0;
        if (precomputed_wire_bytes != nullptr) {
            wire_size = *precomputed_wire_bytes;
        } else {
            std::vector<uint8_t> wire;
            if (!EncodeTransaction(tx, profile.transaction, wire, error))
                return false;
            wire_size = static_cast<uint64_t>(wire.size());
        }
        IdentityDigests computed_identities;
        const IdentityDigests *identities = precomputed_identities;
        if (identities == nullptr) {
            if (!ComputeIdentitiesValidated(tx, profile.transaction,
                                            parent.chain_id,
                                            computed_identities, error))
                return false;
            identities = &computed_identities;
        }
        MonetaryInteger outputs = 0;
        MonetaryInteger burned = 0;
        std::vector<Coin> created;
        for (size_t j = 0; j < tx.outputs.size(); ++j) {
            const Output &output = tx.outputs[j];
            outputs += output.value;
            if (output.IsBurn()) {
                burned += output.value;
                continue;
            }
            Coin coin;
            coin.outpoint.tx_id = identities->txid;
            coin.outpoint.index = static_cast<uint32_t>(j);
            coin.output = output;
            coin.creation_height = profile.candidate_height;
            coin.creation_parent_mtp = profile.parent_mtp;
            coin.coinbase = true;
            created.push_back(std::move(coin));
        }
        size_t viewed = 0;
        for (; viewed < created.size(); ++viewed) {
            if (view.find(created[viewed].outpoint) != view.end() ||
                !view.emplace(created[viewed].outpoint, created[viewed]).second)
                break;
        }
        if (viewed != created.size()) {
            for (size_t i = viewed; i-- > 0;)
                view.erase(created[i].outpoint);
            error = "created outpoint already occupied";
            return false;
        }
        size_t inserted = 0;
        for (; inserted < created.size(); ++inserted) {
            if (!utxo.Insert(created[inserted])) break;
        }
        if (inserted != created.size()) {
            for (size_t i = inserted; i-- > 0;)
                utxo.Erase(created[i].outpoint);
            for (const Coin &coin : created)
                view.erase(coin.outpoint);
            error = "incremental utxo update failed";
            return false;
        }
        for (const Coin &coin : created)
            undo.steps.push_back(OrdinaryUndoStep{true, coin});
        native_outputs = outputs;
        native_burn = burned;
        coinbase_bytes = wire_size;
        return true;
    }
} // namespace

bool DisconnectOrdinaryBlock(const OrdinaryBlockUndo &undo,
                             DevelopmentUtxoView &view,
                             IncrementalUtxoSet &utxo, MonetaryState &monetary,
                             std::string &error) {
    for (size_t i = undo.steps.size(); i-- > 0;) {
        const OrdinaryUndoStep &step = undo.steps[i];
        if (step.coin.output.branches.empty()) {
            error = "undo coin is empty";
            return false;
        }
        if (step.created) {
            if (view.erase(step.coin.outpoint) != 1 ||
                !utxo.Erase(step.coin.outpoint)) {
                error = "undo missing created coin";
                return false;
            }
        } else if (!view.emplace(step.coin.outpoint, step.coin).second ||
                   !utxo.Insert(step.coin)) {
            error = "undo cannot restore spent coin";
            return false;
        }
    }
    monetary = undo.prior_monetary;
    if (EncodeMonetaryState(monetary) != undo.prior_monetary_bytes) {
        error = "undo did not restore monetary root";
        return false;
    }
    if (!ViewAgrees(view, utxo, error)) return false;
    if (utxo.Root() != undo.prior_utxo_root) {
        error = "undo did not restore utxo root";
        return false;
    }
    error.clear();
    return true;
}

namespace {
    struct CompleteAccounting {
        const BlockCostProfile &profile;
        uint64_t frames;
        MonetaryInteger work;
        MonetaryInteger envelope;
        const std::vector<uint64_t> *transaction_bytes = nullptr;
        const std::vector<IdentityDigests> *transaction_identities = nullptr;
    };
} // namespace
static bool ConnectBlockImpl(const std::vector<Transaction> &transactions,
                             const OrdinaryParentContext &parent,
                             const OrdinaryCandidateProfile &profile,
                             const MonetaryProfile &monetary_profile,
                             DevelopmentUtxoView &view,
                             IncrementalUtxoSet &utxo, MonetaryState &monetary,
                             OrdinaryBlockConnected &connected,
                             std::string &error,
                             const CompleteAccounting *complete) {
    if (parent.header.height == std::numeric_limits<uint64_t>::max() ||
        profile.candidate_height != parent.header.height + 1 ||
        (complete == nullptr && profile.parent_mtp != parent.header.time) ||
        parent.header.time > MAX_TIME) {
        error = "parent header context";
        return false;
    }
    if (!SameMonetary(monetary, parent.monetary)) {
        error = "parent monetary context";
        return false;
    }
    if (!ViewAgrees(view, utxo, error)) return false;
    if (StateRoot(parent.chain_id, parent.header.height, utxo.Root(),
                  monetary) != parent.header.state_root) {
        error = "parent state root";
        return false;
    }
    if (!CoinbasePlacement(transactions, error)) return false;

    OrdinaryBlockUndo undo;
    undo.prior_monetary = monetary;
    undo.prior_utxo_root = utxo.Root();
    undo.prior_monetary_bytes = EncodeMonetaryState(monetary);
    auto rollback = [&](std::string &why) {
        std::string undo_error;
        if (!DisconnectOrdinaryBlock(undo, view, utxo, monetary, undo_error)) {
            why += "; undo failed: ";
            why += undo_error;
        }
    };

    const bool has_precomputed =
        complete != nullptr && complete->transaction_bytes != nullptr &&
        complete->transaction_identities != nullptr &&
        complete->transaction_bytes->size() == transactions.size() &&
        complete->transaction_identities->size() == transactions.size();
    const CoinLookup view_lookup = [&view](const Outpoint &outpoint, Coin &coin,
                                           std::string &) {
        const auto found = view.find(outpoint);
        if (found == view.end()) return CoinReadResult::Missing;
        coin = found->second;
        return CoinReadResult::Found;
    };

    VmCostUnits invocation_cost = 0;
    std::vector<MonetaryOrdinaryTx> accounted;
    accounted.reserve(transactions.size());
    MonetaryInteger coinbase_native_outputs = 0;
    MonetaryInteger coinbase_native_burn = 0;
    uint64_t coinbase_bytes = 0;
    std::vector<uint64_t> account_linear, enforce_linear;
    for (size_t index = 0; index < transactions.size(); ++index) {
        const Transaction &tx = transactions[index];
        const uint64_t *pre_bytes =
            has_precomputed ? &(*complete->transaction_bytes)[index] : nullptr;
        const IdentityDigests *pre_ids =
            has_precomputed ? &(*complete->transaction_identities)[index]
                            : nullptr;
        if (IsCoinbaseTransaction(tx)) {
            if (complete != nullptr) {
                try {
                    const auto cost = AuthenticatedTransactionCostsResolved(
                        tx, profile.transaction, {}, profile.candidate_height,
                        profile.parent_mtp, 0, complete->profile, pre_bytes);
                    account_linear.push_back(cost.account_linear);
                    enforce_linear.push_back(cost.enforce_linear);
                } catch (const std::invalid_argument &failure) {
                    error = failure.what();
                    rollback(error);
                    return false;
                }
            }
            if (index != 0) {
                error = "coinbase position";
                rollback(error);
                return false;
            }
            if (!StageDevelopmentCoinbase(
                    tx, parent, profile, view, utxo, undo,
                    coinbase_native_outputs, coinbase_native_burn,
                    coinbase_bytes, error, pre_bytes, pre_ids)) {
                rollback(error);
                return false;
            }
            continue;
        }
        OrdinaryCandidateEffects effects;
        if (CheckOrdinaryWithLookup(tx, profile, parent.chain_id, view_lookup,
                                    effects, error, pre_bytes, pre_ids) !=
            CandidateCheckResult::Accepted) {
            rollback(error);
            return false;
        }
        std::vector<Coin> removed;
        removed.reserve(effects.consumed.size());
        for (const Outpoint &outpoint : effects.consumed) {
            const auto found = view.find(outpoint);
            if (found == view.end()) {
                error = "spend disappeared";
                rollback(error);
                return false;
            }
            removed.push_back(found->second);
        }
        if (complete != nullptr) {
            try {
                const auto cost = AuthenticatedTransactionCostsResolved(
                    tx, profile.transaction, removed, profile.candidate_height,
                    profile.parent_mtp, effects.invocation_cost,
                    complete->profile, &effects.serialized_bytes);
                account_linear.push_back(cost.account_linear);
                enforce_linear.push_back(cost.enforce_linear);
            } catch (const std::invalid_argument &failure) {
                error = failure.what();
                rollback(error);
                return false;
            }
        }
        DevelopmentUtxoView next_view = view;
        bool view_applied = true;
        for (const Outpoint &outpoint : effects.consumed) {
            if (next_view.erase(outpoint) != 1) {
                error = "staged spend disappeared";
                view_applied = false;
                break;
            }
        }
        if (view_applied) {
            for (const Coin &coin : effects.created) {
                if (!next_view.emplace(coin.outpoint, coin).second) {
                    error = "staged output collision";
                    view_applied = false;
                    break;
                }
            }
        }
        if (!view_applied) {
            rollback(error);
            return false;
        }
        view.swap(next_view);
        size_t erased = 0;
        for (; erased < removed.size(); ++erased) {
            if (!utxo.Erase(removed[erased].outpoint)) break;
        }
        size_t inserted = 0;
        bool staged = erased == removed.size();
        if (staged) {
            for (; inserted < effects.created.size(); ++inserted) {
                if (!utxo.Insert(effects.created[inserted])) break;
            }
            staged = inserted == effects.created.size();
        }
        if (!staged) {
            for (size_t i = inserted; i-- > 0;)
                utxo.Erase(effects.created[i].outpoint);
            for (size_t i = erased; i-- > 0;)
                utxo.Insert(removed[i]);
            ReverseApplied(view, removed, effects);
            error = "incremental utxo update failed";
            rollback(error);
            return false;
        }
        for (const Coin &coin : removed)
            undo.steps.push_back(OrdinaryUndoStep{false, coin});
        for (const Coin &coin : effects.created)
            undo.steps.push_back(OrdinaryUndoStep{true, coin});
        if (effects.invocation_cost > ~VmCostUnits(0) - invocation_cost) {
            error = "block invocation cost overflow";
            rollback(error);
            return false;
        }
        invocation_cost += effects.invocation_cost;
        if (invocation_cost > profile.max_total_invocation_cost) {
            error = "block invocation cost over cap";
            rollback(error);
            return false;
        }
        try {
            accounted.push_back(AccountValidatedOrdinary(
                tx, effects, profile.transaction, monetary_profile,
                &effects.serialized_bytes));
        } catch (const std::invalid_argument &failure) {
            error = failure.what();
            rollback(error);
            return false;
        }
    }

    MonetaryTransition transition;
    try {
        const MonetaryInteger account_cost =
            complete == nullptr
                ? WideToInteger(invocation_cost)
                : BlockEffectiveCost(complete->envelope, account_linear,
                                     monetary_profile);
        const MonetaryInteger enforce_cost =
            complete == nullptr
                ? WideToInteger(invocation_cost)
                : BlockEffectiveCost(complete->envelope, enforce_linear,
                                     monetary_profile);
        transition = AdvanceMonetary(
            monetary_profile, undo.prior_monetary,
            complete == nullptr ? WorkOf(monetary.prev_work) : complete->work,
            accounted, coinbase_native_outputs, coinbase_native_burn,
            coinbase_bytes, complete == nullptr ? 0 : complete->frames,
            account_cost, enforce_cost);
    } catch (const std::invalid_argument &failure) {
        error = failure.what();
        rollback(error);
        return false;
    }

    monetary = transition.state;
    OrdinaryBlockConnected staged;
    staged.utxo_root = utxo.Root();
    staged.monetary_bytes = EncodeMonetaryState(monetary);
    staged.state_root = StateRoot(parent.chain_id, profile.candidate_height,
                                  staged.utxo_root, monetary);
    staged.monetary = std::move(transition);
    staged.undo = std::move(undo);
    staged.invocation_cost = invocation_cost;
    if (!ViewAgrees(view, utxo, error)) {
        std::string ignored;
        DisconnectOrdinaryBlock(staged.undo, view, utxo, monetary, ignored);
        return false;
    }
    connected = std::move(staged);
    error.clear();
    return true;
}

bool ConnectOrdinaryBlock(const std::vector<Transaction> &transactions,
                          const OrdinaryParentContext &parent,
                          const OrdinaryCandidateProfile &profile,
                          const MonetaryProfile &monetary_profile,
                          DevelopmentUtxoView &view, IncrementalUtxoSet &utxo,
                          MonetaryState &monetary,
                          OrdinaryBlockConnected &connected,
                          std::string &error) {
    return ConnectBlockImpl(transactions, parent, profile, monetary_profile,
                            view, utxo, monetary, connected, error, nullptr);
}

bool ConnectCompleteBlock(const std::vector<uint8_t> &wire,
                          const OrdinaryParentContext &parent,
                          const std::vector<Header> &history,
                          const HeaderChainProfile &header_profile,
                          const OrdinaryCandidateProfile &ordinary_profile,
                          const MonetaryProfile &monetary_profile,
                          const BlockCostProfile &cost_profile,
                          DevelopmentUtxoView &view, IncrementalUtxoSet &utxo,
                          MonetaryState &monetary,
                          OrdinaryBlockConnected &connected,
                          std::string &error) {
    Header claimed;
    if (wire.size() < HEADER_SIZE + 4 ||
        !ParseHeader(wire.data(), HEADER_SIZE, claimed)) {
        error = "block header frame";
        return false;
    }
    const auto mtp = ParentMedianTime(header_profile, parent.header, history);
    if (!mtp || header_profile.chain_id != parent.chain_id ||
        ordinary_profile.parent_mtp != *mtp ||
        ordinary_profile.candidate_height != claimed.height) {
        error = "complete block context";
        return false;
    }
    // Cheap contextual target/PoW gate precedes transaction decoding, hashing,
    // VM execution and state copying. Claimed roots are not yet authenticated:
    // DecodeBlockWire verifies tx_root and the final gate verifies state_root.
    if (!ValidateChildHeader(header_profile, parent.header, history, claimed,
                             claimed.tx_root, claimed.state_root, wire.size(),
                             error))
        return false;
    FramedBlock block;
    if (!DecodeBlockWire(wire, ordinary_profile.transaction, parent.chain_id,
                         block, error))
        return false;
    Hash parent_target, child_target;
    if (!DecodeTarget(parent.header.bits, header_profile.pow_limit,
                      parent_target) ||
        !DecodeTarget(block.header.bits, header_profile.pow_limit,
                      child_target)) {
        error = "complete block target";
        return false;
    }
    // The monetary baseline must describe the authenticated parent's target.
    const MonetaryInteger parent_work =
        (MonetaryInteger(1) << 256) / (WorkOf(parent_target) + 1);
    if (WorkOf(parent.monetary.prev_work) != parent_work) {
        error = "parent monetary work does not match target";
        return false;
    }
    try {
        if (parent.monetary.tail_subsidy != AbsoluteTail(monetary_profile, parent_work)) {
            error = "parent cached tail mismatch";
            return false;
        }
    } catch (const std::invalid_argument &failure) {
        error = failure.what();
        return false;
    }
    // Derive work from accepted candidate bits; P06 reward is parent-work
    // fixed, while this work updates the NEXT tail and prev_work record.
    const MonetaryInteger child_work =
        (MonetaryInteger(1) << 256) / (WorkOf(child_target) + 1);
    uint64_t frames = 0;
    for (uint64_t prefix : block.frame_prefix_bytes)
        frames += prefix;
    DevelopmentUtxoView staged_view = view;
    IncrementalUtxoSet staged_utxo;
    if (!ViewAgrees(view, utxo, error)) return false;
    for (const auto &entry : staged_view) {
        if (!staged_utxo.Insert(entry.second)) {
            error = "staging parent utxo";
            return false;
        }
    }
    MonetaryState staged_money = monetary;
    OrdinaryBlockConnected staged;
    try {
        const CompleteAccounting accounting{
            cost_profile,
            frames,
            child_work,
            AuthenticatedEnvelopeCost(frames, block.transactions.size(),
                                      cost_profile),
            &block.transaction_bytes,
            &block.transaction_identities};
        if (!ConnectBlockImpl(block.transactions, parent, ordinary_profile,
                              monetary_profile, staged_view, staged_utxo,
                              staged_money, staged, error, &accounting))
            return false;
    } catch (const std::invalid_argument &failure) {
        error = failure.what();
        return false;
    }
    if (!ValidateChildHeader(header_profile, parent.header, history,
                             block.header, block.header.tx_root,
                             staged.state_root, wire.size(), error))
        return false;
    view.swap(staged_view);
    utxo = std::move(staged_utxo);
    monetary = staged_money;
    connected = std::move(staged);
    error.clear();
    return true;
}

bool WriteInMemorySnapshot(const DevelopmentUtxoView &view,
                           const MonetaryState &monetary,
                           std::vector<uint8_t> &bytes, std::string &error) {
    if (view.size() > SNAPSHOT_COIN_CAP) {
        error = "snapshot coin cap";
        return false;
    }
    std::vector<uint8_t> encoded;
    encoded.push_back('L');
    encoded.push_back('V');
    encoded.push_back('2');
    encoded.push_back('S');
    PutU32(encoded, static_cast<uint32_t>(view.size()));
    for (const auto &entry : view) {
        if (entry.first != entry.second.outpoint) {
            error = "snapshot coin outpoint mismatch";
            return false;
        }
        std::vector<uint8_t> coin;
        if (!EncodeCoin(entry.second, coin) || coin.size() > MAX_COIN_BYTES) {
            error = "snapshot coin encoding";
            return false;
        }
        PutU32(encoded, static_cast<uint32_t>(coin.size()));
        encoded.insert(encoded.end(), coin.begin(), coin.end());
    }
    const auto record = EncodeMonetaryState(monetary);
    encoded.insert(encoded.end(), record.begin(), record.end());
    bytes = std::move(encoded);
    error.clear();
    return true;
}

bool LoadInMemorySnapshot(const std::vector<uint8_t> &bytes,
                          DevelopmentUtxoView &view, IncrementalUtxoSet &utxo,
                          MonetaryState &monetary, std::string &error) {
    if (bytes.size() < 4 + 4 + 56 || bytes[0] != 'L' || bytes[1] != 'V' ||
        bytes[2] != '2' || bytes[3] != 'S') {
        error = "snapshot header";
        return false;
    }
    size_t offset = 4;
    uint32_t count = 0;
    if (!TakeU32(bytes, offset, count) || count > SNAPSHOT_COIN_CAP) {
        error = "snapshot coin count";
        return false;
    }
    DevelopmentUtxoView loaded_view;
    IncrementalUtxoSet loaded_utxo;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t length = 0;
        if (!TakeU32(bytes, offset, length) || length == 0 ||
            length > MAX_COIN_BYTES || offset > bytes.size() ||
            bytes.size() - offset < length) {
            error = "snapshot coin frame";
            return false;
        }
        Coin coin;
        if (!DecodeSnapshotCoin(
                std::vector<uint8_t>(bytes.begin() + offset,
                                     bytes.begin() + offset + length),
                coin) ||
            !loaded_view.emplace(coin.outpoint, coin).second ||
            !loaded_utxo.Insert(coin)) {
            error = "snapshot coin rejected";
            return false;
        }
        offset += length;
    }
    if (bytes.size() - offset != 56) {
        error = "snapshot monetary frame";
        return false;
    }
    MonetaryState loaded_monetary;
    try {
        loaded_monetary = DecodeMonetaryState(
            std::vector<uint8_t>(bytes.begin() + offset, bytes.end()));
    } catch (const std::invalid_argument &failure) {
        error = failure.what();
        return false;
    }
    std::string agree;
    if (!ViewAgrees(loaded_view, loaded_utxo, agree)) {
        error = agree;
        return false;
    }
    view.swap(loaded_view);
    utxo = std::move(loaded_utxo);
    monetary = loaded_monetary;
    error.clear();
    return true;
}

} // namespace lotus::v2
