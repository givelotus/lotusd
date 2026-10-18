// Copyright (c) 2026 The Lotus developers
#include "block_transition.h"
#include "signing.h"
#include "asert_candidate.h"
#include "vendor/blake3/blake3.h"
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <limits>
#include <mutex>
#include <set>
#include <stdexcept>
#include <thread>
namespace lotus::v2 {
namespace {
MonetaryInteger Integer(const Hash &bytes) {
    MonetaryInteger value = 0;
    for (size_t i = bytes.size(); i > 0; --i) {
        value <<= 8;
        value += bytes[i - 1];
    }
    return value;
}
class StorageFailure : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
template <typename F> auto StorageCall(F &&call) {
    try { return call(); }
    catch (const std::exception &e) { throw StorageFailure(e.what()); }
}
struct AbortOnFailure {
    BlockStateTransaction &state;
    bool accepted = false;
    ~AbortOnFailure() { if (!accepted) state.Abort(); }
};

class ParallelTaskRunner {
public:
    static ParallelTaskRunner &Instance() {
        static ParallelTaskRunner runner;
        return runner;
    }

    template <typename F>
    void Run(size_t task_count, F &&fn) {
        if (task_count == 0) return;
        if (task_count == 1) {
            fn(0);
            return;
        }
        std::unique_lock<std::mutex> dispatch_lock(dispatch_mutex_);
        EnsureStarted();
        if (workers_.empty()) {
            dispatch_lock.unlock();
            for (size_t i = 0; i < task_count; ++i) fn(i);
            return;
        }
        std::atomic<size_t> next_index{0};
        std::function<void(size_t)> task_fn = std::forward<F>(fn);
        {
            std::lock_guard<std::mutex> work_lock(work_mutex_);
            current_fn_ = &task_fn;
            next_index_ = &next_index;
            total_tasks_ = task_count;
            active_workers_ = workers_.size();
            ++generation_;
        }
        work_cv_.notify_all();
        for (;;) {
            const size_t i = next_index.fetch_add(1, std::memory_order_relaxed);
            if (i >= task_count) break;
            try {
                task_fn(i);
            } catch (...) {
            }
        }
        {
            std::unique_lock<std::mutex> work_lock(work_mutex_);
            done_cv_.wait(work_lock, [&] { return active_workers_ == 0; });
            current_fn_ = nullptr;
            next_index_ = nullptr;
            total_tasks_ = 0;
        }
    }

    ~ParallelTaskRunner() {
        {
            std::lock_guard<std::mutex> work_lock(work_mutex_);
            stop_ = true;
        }
        work_cv_.notify_all();
        for (auto &worker : workers_) {
            if (worker.joinable()) worker.join();
        }
    }

private:
    ParallelTaskRunner() = default;

    void EnsureStarted() {
        if (started_) return;
        started_ = true;
        const size_t hw = std::thread::hardware_concurrency();
        const size_t total_threads =
            std::min<size_t>(std::max<size_t>(hw, 2), 8);
        const size_t helper_count = total_threads > 1 ? total_threads - 1 : 0;
        workers_.reserve(helper_count);
        for (size_t i = 0; i < helper_count; ++i) {
            workers_.emplace_back([this] { WorkerLoop(); });
        }
    }

    void WorkerLoop() {
        uint64_t seen_generation = 0;
        for (;;) {
            std::function<void(size_t)> *fn = nullptr;
            std::atomic<size_t> *next = nullptr;
            size_t total = 0;
            {
                std::unique_lock<std::mutex> work_lock(work_mutex_);
                work_cv_.wait(work_lock, [&] {
                    return stop_ || generation_ != seen_generation;
                });
                if (stop_) return;
                seen_generation = generation_;
                fn = current_fn_;
                next = next_index_;
                total = total_tasks_;
            }
            for (;;) {
                const size_t i = next->fetch_add(1, std::memory_order_relaxed);
                if (i >= total) break;
                try {
                    (*fn)(i);
                } catch (...) {
                }
            }
            {
                std::lock_guard<std::mutex> work_lock(work_mutex_);
                if (--active_workers_ == 0) {
                    done_cv_.notify_one();
                }
            }
        }
    }

    std::mutex dispatch_mutex_;
    std::mutex work_mutex_;
    std::condition_variable work_cv_;
    std::condition_variable done_cv_;
    std::vector<std::thread> workers_;
    std::function<void(size_t)> *current_fn_ = nullptr;
    std::atomic<size_t> *next_index_ = nullptr;
    size_t total_tasks_ = 0;
    size_t active_workers_ = 0;
    uint64_t generation_ = 0;
    bool started_ = false;
    bool stop_ = false;
};
} // namespace
Hash BlockValidationProfileDigest(const HeaderChainProfile &hp,
                                  const OrdinaryCandidateProfile &op,
                                  const MonetaryProfile &mp,
                                  const BlockCostProfile &cp) {
    std::vector<uint8_t> bytes;
    auto put = [&](VmCostUnits value, unsigned width = 8) {
        for (unsigned i = 0; i < width; ++i)
            bytes.push_back(uint8_t(value >> (8 * i)));
    };
    auto hash = [&](const Hash &value) {
        bytes.insert(bytes.end(), value.begin(), value.end());
    };
    put(2);
    hash(hp.chain_id);
    hash(hp.genesis_id);
    put(hp.version);
    put(hp.genesis_time);
    put(hp.genesis_bits);
    hash(hp.pow_limit);
    put(uint64_t(hp.half_life_seconds));
    put(uint64_t(hp.spacing_seconds));
    const auto &t = op.transaction;
    for (auto value :
         {t.max_inputs, t.max_outputs, t.max_mints, t.max_script_bytes,
          t.max_arguments, t.max_argument_bytes, t.max_branch_proof_depth})
        put(value);
    const auto &v = op.vm;
    for (auto value : {v.max_script_bytes, v.max_arguments, v.max_element_bytes,
                       v.max_stack_items, v.max_altstack_items, v.max_vm_bytes,
                       v.max_ast_depth, v.max_steps})
        put(value);
    put(op.coinbase_maturity);
    put(op.dust_limit);
    put(op.max_total_invocation_cost, 16);
    put(op.vm_cost.max_invocation_cost, 16);
    put(op.vm_cost.structural_byte_cost);
    for (const auto &cost : op.vm_cost.opcode) {
        put(cost.base);
        put(cost.per_operand_byte);
        put(cost.per_result_byte);
    }
    put(op.vm_cost.field_sizes.size());
    for (const auto &[opcode, sizes] : op.vm_cost.field_sizes) {
        put(opcode, 1);
        put(sizes.size());
        for (auto value : sizes)
            put(value);
    }
    put(mp.boot_shift);
    put(mp.tx_knee_shift);
    put(mp.ema_shift);
    put(mp.ema_min);
    put(mp.linear_shift);
    put(mp.quad_shift);
    put(mp.tail_min);
    put(mp.tail_max);
    put(mp.dust_limit);
    put(mp.min_fee_per_kb);
    put(ABSOLUTE_TAIL_FORMULA_VERSION);
    put(mp.genesis_tail);
    bytes.insert(bytes.end(), mp.genesis_work.begin(), mp.genesis_work.end());
    put(cp.hash_base);
    put(cp.hash_byte);
    put(cp.resolve_byte);
    put(cp.asset_comparison);
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    constexpr char domain[] = "Lotus/v2/storage-validator-profile";
    blake3_hasher_update(&hasher, domain, sizeof(domain));
    blake3_hasher_update(&hasher, bytes.data(), bytes.size());
    Hash digest;
    blake3_hasher_finalize(&hasher, digest.data(), digest.size());
    return digest;
}

namespace {
    // Shared contextual transaction transition. Header/parent authentication
    // and final proof-of-work validation remain the responsibility of each
    // boundary.
    CandidateCheckResult EvaluateBoundTransactions(
        const FramedBlock &block, const OrdinaryParentContext &parent,
        const Hash &parent_id, const MonetaryInteger &child_work,
        const OrdinaryCandidateProfile &op, const MonetaryProfile &mp,
        const BlockCostProfile &cp, BlockStateTransaction &state,
        StagedBlockTransition &staged, uint64_t &coinbase_bytes,
        uint64_t &frames, std::string &error) {
        using Result = CandidateCheckResult;
        const Header &claimed = block.header;
        frames = 0;
        coinbase_bytes = 0;
        for (auto prefix : block.frame_prefix_bytes)
            frames += prefix;
        MonetaryInteger cb_outputs = 0, cb_burn = 0;
        VmCostUnits invocation = 0;
        std::vector<MonetaryOrdinaryTx> accounted;
        std::vector<uint64_t> account_linear, enforce_linear;
        const bool has_precomputed =
            block.transaction_bytes.size() == block.transactions.size() &&
            block.transaction_identities.size() == block.transactions.size();
        if (block.transactions.empty()) {
            error = "empty block";
            return Result::Invalid;
        }
        // Validate and apply coinbase (transaction 0).
        {
            const Transaction &tx = block.transactions[0];
            std::vector<Coin> resolved;
            OrdinaryCandidateEffects effects;
            if (!CheckCoinbaseContext(tx, parent_id, claimed.height, error))
                return Result::Invalid;
            IdentityDigests computed_ids;
            const IdentityDigests *ids = nullptr;
            if (has_precomputed) {
                coinbase_bytes = block.transaction_bytes[0];
                ids = &block.transaction_identities[0];
            } else {
                std::vector<uint8_t> bytes;
                if (!EncodeTransaction(tx, op.transaction, bytes, error) ||
                    !ComputeIdentitiesValidated(tx, op.transaction,
                                                parent.chain_id, computed_ids,
                                                error))
                    return Result::Invalid;
                coinbase_bytes = bytes.size();
                ids = &computed_ids;
            }
            const uint64_t tx_wire_bytes = coinbase_bytes;
            for (size_t j = 0; j < tx.outputs.size(); ++j) {
                const Output &output = tx.outputs[j];
                cb_outputs += output.value;
                if (output.IsBurn()) {
                    cb_burn += output.value;
                    continue;
                }
                Coin coin{{ids->txid, uint32_t(j)},
                          output,
                          claimed.height,
                          op.parent_mtp,
                          true,
                          0,
                          ComputeUtxoExpirationHeight(claimed.height, true, 0)};
                Coin occupied;
                const auto read = StorageCall([&] {
                    return state.Read(coin.outpoint, occupied, error);
                });
                if (read == CoinReadResult::Error)
                    return Result::StorageError;
                if (read == CoinReadResult::Found) {
                    if (occupied.outpoint != coin.outpoint) {
                        error = "coin lookup returned a different outpoint";
                        return Result::StorageError;
                    }
                    error = "created outpoint already occupied";
                    return Result::Invalid;
                }
                effects.created.push_back(std::move(coin));
            }
            const auto costs = StorageCall([&] {
                return AuthenticatedTransactionCostsResolved(
                    tx, op.transaction, resolved, claimed.height, op.parent_mtp,
                    effects.invocation_cost, cp, &tx_wire_bytes);
            });
            account_linear.push_back(costs.account_linear);
            enforce_linear.push_back(costs.enforce_linear);
            for (const auto &coin : effects.created)
                if (!StorageCall([&] { return state.Insert(coin, error); }))
                    return Result::StorageError;
        }
        // Fast single-ordinary-transaction path.
        if (block.transactions.size() == 2) {
            const Transaction &tx = block.transactions[1];
            std::vector<Coin> resolved;
            OrdinaryCandidateEffects effects;
            DevelopmentUtxoView read_coins;
            CoinLookup lookup = [&](const Outpoint &key, Coin &coin,
                                    std::string &why) {
                const auto read =
                    StorageCall([&] { return state.Read(key, coin, why); });
                if (read == CoinReadResult::Found)
                    read_coins.emplace(key, coin);
                return read;
            };
            const auto result = CheckOrdinaryWithLookup(
                tx, op, parent.chain_id, lookup, effects, error,
                has_precomputed ? &block.transaction_bytes[1] : nullptr,
                has_precomputed ? &block.transaction_identities[1] : nullptr);
            if (result != Result::Accepted) return result;
            const uint64_t tx_wire_bytes = effects.serialized_bytes;
            for (const auto &key : effects.consumed)
                resolved.push_back(read_coins.at(key));
            if (effects.invocation_cost > ~VmCostUnits{0} - invocation ||
                (invocation += effects.invocation_cost) >
                    op.max_total_invocation_cost) {
                error = "block invocation cost over budget";
                return Result::Invalid;
            }
            accounted.push_back(StorageCall([&] {
                return AccountValidatedOrdinary(tx, effects, op.transaction, mp,
                                                &tx_wire_bytes);
            }));
            const auto costs = StorageCall([&] {
                return AuthenticatedTransactionCostsResolved(
                    tx, op.transaction, resolved, claimed.height, op.parent_mtp,
                    effects.invocation_cost, cp, &tx_wire_bytes);
            });
            account_linear.push_back(costs.account_linear);
            enforce_linear.push_back(costs.enforce_linear);
            for (const auto &key : effects.consumed)
                if (!StorageCall([&] { return state.Erase(key, error); }))
                    return Result::StorageError;
            for (const auto &coin : effects.created)
                if (!StorageCall([&] { return state.Insert(coin, error); }))
                    return Result::StorageError;
        } else if (block.transactions.size() > 2) {
            if (!ValidateOrdinaryProfile(op, error))
                return Result::Inconclusive;
            const Hash ordinary_profile_digest =
                OrdinaryValidationProfileDigest(op);
            struct BatchItem {
                size_t tx_index{};
                uint64_t wire_size{};
                IdentityDigests identities{};
                std::vector<Coin> spent;
                ResolvedCoins resolved;
                std::vector<Outpoint> deferred_state_reads;
                Hash resolved_coins_digest{};
                OrdinaryCandidateEffects effects;
                BatchSigCollector sigs;
                Result result = Result::Inconclusive;
                std::string error;
                bool needs_cpu_verify = false;
                bool has_pre_error = false;
            };
            size_t cursor = 1;
            while (cursor < block.transactions.size()) {
                std::set<Outpoint, OutpointLess> batch_spent;
                DevelopmentUtxoView batch_created;
                std::vector<BatchItem> batch;
                std::vector<size_t> miss_indices;
                batch.reserve(block.transactions.size() - cursor);
                for (size_t n = cursor; n < block.transactions.size(); ++n) {
                    const Transaction &tx = block.transactions[n];
                    // If this transaction attempts to spend an outpoint
                    // already consumed earlier in this batch, flush the
                    // current batch first so state.Erase is applied before n
                    // reads state.
                    if (n > cursor) {
                        bool touches_batch_spent = false;
                        for (const Input &input : tx.inputs) {
                            if (input.flags == 1 &&
                                batch_spent.contains(
                                    Outpoint{input.prev_txid,
                                             input.prev_index})) {
                                touches_batch_spent = true;
                                break;
                            }
                        }
                        if (touches_batch_spent) break;
                    }
                    BatchItem item;
                    item.tx_index = n;
                    if (has_precomputed) {
                        item.wire_size = block.transaction_bytes[n];
                        item.identities = block.transaction_identities[n];
                    } else {
                        std::vector<uint8_t> wire;
                        if (!EncodeTransaction(tx, op.transaction, wire,
                                               item.error)) {
                            item.has_pre_error = true;
                            item.result = Result::Invalid;
                            batch.push_back(std::move(item));
                            break;
                        }
                        item.wire_size = wire.size();
                    }
                    item.effects.serialized_bytes = item.wire_size;
                    item.resolved.resize(tx.inputs.size());
                    item.spent.reserve(tx.inputs.size());
                    std::set<Outpoint, OutpointLess> seen;
                    blake3_hasher coins_hasher;
                    blake3_hasher_init(&coins_hasher);
                    constexpr char coins_domain[] =
                        "Lotus/v2/ordinary-resolved-coins";
                    blake3_hasher_update(&coins_hasher, coins_domain,
                                         sizeof(coins_domain));
                    for (size_t i = 0; i < tx.inputs.size(); ++i) {
                        const Input &input = tx.inputs[i];
                        if (input.flags == 2) {
                            item.has_pre_error = true;
                            item.result = Result::Invalid;
                            item.error =
                                "coinbase is not an ordinary transaction";
                            break;
                        }
                        if (input.flags != 1) continue;
                        const Outpoint outpoint{input.prev_txid,
                                                input.prev_index};
                        if (!seen.insert(outpoint).second) {
                            item.has_pre_error = true;
                            item.result = Result::Invalid;
                            item.error = "repeated spend";
                            break;
                        }
                        Coin coin;
                        const auto created_it = batch_created.find(outpoint);
                        if (created_it != batch_created.end()) {
                            coin = created_it->second;
                            item.deferred_state_reads.push_back(outpoint);
                        } else {
                            const auto read = StorageCall([&] {
                                return state.Read(outpoint, coin, item.error);
                            });
                            if (read == CoinReadResult::Error) {
                                item.has_pre_error = true;
                                item.result = Result::StorageError;
                                break;
                            }
                            if (read == CoinReadResult::Missing) {
                                item.has_pre_error = true;
                                item.result = Result::Invalid;
                                item.error = "unresolved spend";
                                break;
                            }
                            if (coin.outpoint != outpoint) {
                                item.has_pre_error = true;
                                item.result = Result::StorageError;
                                item.error =
                                    "coin lookup returned a different outpoint";
                                break;
                            }
                        }
                        std::vector<uint8_t> encoded_coin;
                        if (!EncodeCoin(coin, encoded_coin)) {
                            item.has_pre_error = true;
                            item.result = Result::StorageError;
                            item.error = "invalid resolved coin";
                            break;
                        }
                        uint8_t len_le[8];
                        const uint64_t coin_len = encoded_coin.size();
                        for (unsigned b = 0; b < 8; ++b)
                            len_le[b] = uint8_t(coin_len >> (8 * b));
                        blake3_hasher_update(&coins_hasher, len_le,
                                             sizeof(len_le));
                        blake3_hasher_update(&coins_hasher, encoded_coin.data(),
                                             encoded_coin.size());
                        item.spent.push_back(coin);
                        item.resolved[i] = coin.output;
                        item.effects.consumed.push_back(outpoint);
                    }
                    if (item.has_pre_error) {
                        batch.push_back(std::move(item));
                        break;
                    }
                    blake3_hasher_finalize(&coins_hasher,
                                           item.resolved_coins_digest.data(),
                                           item.resolved_coins_digest.size());
                    if (!CheckOrdinaryLocks(tx, item.spent, op, item.error)) {
                        item.has_pre_error = true;
                        item.result = Result::Invalid;
                        batch.push_back(std::move(item));
                        break;
                    }
                    if (!has_precomputed &&
                        !ComputeIdentities(tx, op.transaction, parent.chain_id,
                                           item.identities, item.error)) {
                        item.has_pre_error = true;
                        item.result = Result::Invalid;
                        batch.push_back(std::move(item));
                        break;
                    }
                    if (TryGetCachedOrdinaryResolved(
                            op, parent.chain_id, item.wire_size,
                            item.identities, item.resolved_coins_digest,
                            &ordinary_profile_digest, item.effects, item.result,
                            item.error)) {
                        if (item.result != Result::Accepted) {
                            item.has_pre_error = true;
                            batch.push_back(std::move(item));
                            break;
                        }
                    } else {
                        item.needs_cpu_verify = true;
                        miss_indices.push_back(batch.size());
                    }
                    for (const auto &consumed_op : item.effects.consumed) {
                        batch_spent.insert(consumed_op);
                        batch_created.erase(consumed_op);
                    }
                    for (size_t j = 0; j < tx.outputs.size(); ++j) {
                        if (tx.outputs[j].IsBurn()) continue;
                        const Outpoint created_op{item.identities.txid,
                                                  uint32_t(j)};
                        batch_created.emplace(
                            created_op,
                            Coin{created_op, tx.outputs[j], claimed.height,
                                 op.parent_mtp, false, 0,
                                 ComputeUtxoExpirationHeight(claimed.height,
                                                             false, 0)});
                    }
                    batch.push_back(std::move(item));
                }

                // Step 2: Parallel CPU-heavy VM & signature verification for
                // all cache-miss transactions in this batch, collecting BIP340
                // Schnorr signatures into per-tx BatchSigCollectors for a
                // unified multi-scalar multiplication batch verification pass.
                if (!miss_indices.empty()) {
                    ParallelTaskRunner::Instance().Run(
                        miss_indices.size(), [&](size_t task_i) {
                            BatchItem &item = batch[miss_indices[task_i]];
                            const Transaction &tx =
                                block.transactions[item.tx_index];
                            item.result = VerifyOrdinaryUncached(
                                tx, op, parent.chain_id, item.wire_size,
                                item.identities, item.spent, item.resolved,
                                item.resolved_coins_digest,
                                &ordinary_profile_digest, item.effects,
                                item.error, &item.sigs);
                        });
                    BatchSigCollector combined_sigs;
                    for (size_t idx : miss_indices) {
                        BatchItem &item = batch[idx];
                        if (item.result == Result::Accepted &&
                            !item.sigs.Empty()) {
                            combined_sigs.Merge(item.sigs);
                        }
                    }
                    if (combined_sigs.VerifyAll()) {
                        for (size_t idx : miss_indices) {
                            BatchItem &item = batch[idx];
                            if (item.result == Result::Accepted) {
                                PutCachedOrdinaryResolved(
                                    op, parent.chain_id, item.wire_size,
                                    item.identities, item.resolved_coins_digest,
                                    &ordinary_profile_digest, item.effects);
                            }
                        }
                    } else {
                        for (size_t idx : miss_indices) {
                            BatchItem &item = batch[idx];
                            if (item.result != Result::Accepted) continue;
                            if (!item.sigs.VerifyAll(1)) {
                                const Transaction &tx =
                                    block.transactions[item.tx_index];
                                item.result = VerifyOrdinaryUncached(
                                    tx, op, parent.chain_id, item.wire_size,
                                    item.identities, item.spent, item.resolved,
                                    item.resolved_coins_digest,
                                    &ordinary_profile_digest, item.effects,
                                    item.error, nullptr);
                            } else {
                                PutCachedOrdinaryResolved(
                                    op, parent.chain_id, item.wire_size,
                                    item.identities, item.resolved_coins_digest,
                                    &ordinary_profile_digest, item.effects);
                            }
                        }
                    }
                }

                // Step 3: Sequential commit and accounting in exact block
                // order.
                for (BatchItem &item : batch) {
                    const Transaction &tx = block.transactions[item.tx_index];
                    for (const Outpoint &deferred_op :
                         item.deferred_state_reads) {
                        Coin state_coin;
                        const auto read = StorageCall([&] {
                            return state.Read(deferred_op, state_coin, error);
                        });
                        if (read == CoinReadResult::Error)
                            return Result::StorageError;
                        if (read == CoinReadResult::Missing) {
                            error = "unresolved spend";
                            return Result::Invalid;
                        }
                        if (state_coin.outpoint != deferred_op) {
                            error = "coin lookup returned a different outpoint";
                            return Result::StorageError;
                        }
                    }
                    if (item.has_pre_error || item.result != Result::Accepted) {
                        error = item.error;
                        return item.result;
                    }
                    size_t spendable_outputs = 0;
                    for (const Output &out : tx.outputs) {
                        if (!out.IsBurn()) ++spendable_outputs;
                    }
                    const uint64_t fee_u64 =
                        item.effects.native_fee > __uint128_t(UINT64_MAX)
                            ? UINT64_MAX
                            : static_cast<uint64_t>(item.effects.native_fee);
                    const uint64_t fee_per_output =
                        ComputeTxFeePerSpendableOutput(fee_u64,
                                                       spendable_outputs);
                    const uint64_t exp_height = ComputeUtxoExpirationHeight(
                        claimed.height, false, fee_per_output);
                    for (size_t j = 0; j < tx.outputs.size(); ++j) {
                        if (tx.outputs[j].IsBurn()) continue;
                        const Outpoint outpoint{item.identities.txid,
                                                uint32_t(j)};
                        Coin occupied;
                        const auto read = StorageCall([&] {
                            return state.Read(outpoint, occupied, error);
                        });
                        if (read == CoinReadResult::Error)
                            return Result::StorageError;
                        if (read == CoinReadResult::Found) {
                            if (occupied.outpoint != outpoint) {
                                error =
                                    "coin lookup returned a different outpoint";
                                return Result::StorageError;
                            }
                            error = "created outpoint already occupied";
                            return Result::Invalid;
                        }
                        item.effects.created.push_back(
                            Coin{outpoint, tx.outputs[j], claimed.height,
                                 op.parent_mtp, false, fee_per_output,
                                 exp_height});
                    }
                    if (item.effects.invocation_cost >
                            ~VmCostUnits{0} - invocation ||
                        (invocation += item.effects.invocation_cost) >
                            op.max_total_invocation_cost) {
                        error = "block invocation cost over budget";
                        return Result::Invalid;
                    }
                    const uint64_t tx_wire_bytes =
                        item.effects.serialized_bytes;
                    accounted.push_back(StorageCall([&] {
                        return AccountValidatedOrdinary(
                            tx, item.effects, op.transaction, mp,
                            &tx_wire_bytes);
                    }));
                    const auto costs = StorageCall([&] {
                        return AuthenticatedTransactionCostsResolved(
                            tx, op.transaction, item.spent, claimed.height,
                            op.parent_mtp, item.effects.invocation_cost, cp,
                            &tx_wire_bytes);
                    });
                    account_linear.push_back(costs.account_linear);
                    enforce_linear.push_back(costs.enforce_linear);
                    for (const auto &key : item.effects.consumed)
                        if (!StorageCall(
                                [&] { return state.Erase(key, error); }))
                            return Result::StorageError;
                    for (const auto &coin : item.effects.created)
                        if (!StorageCall(
                                [&] { return state.Insert(coin, error); }))
                            return Result::StorageError;
                }
                cursor += batch.size();
            }
        }
        const auto envelope =
            AuthenticatedEnvelopeCost(frames, block.transactions.size(), cp);
        staged.header = claimed;
        staged.utxo_root = StorageCall([&] { return state.Root(); });
        staged.account_cost = BlockEffectiveCost(envelope, account_linear, mp);
        staged.enforce_cost = BlockEffectiveCost(envelope, enforce_linear, mp);
        try {
            staged.monetary =
                AdvanceMonetary(mp, parent.monetary, child_work, accounted,
                                cb_outputs, cb_burn, coinbase_bytes, frames,
                                staged.account_cost, staged.enforce_cost);
        } catch (const std::invalid_argument &exception) {
            error = exception.what();
            return Result::Invalid;
        }
        staged.state_root = StateRoot(parent.chain_id, claimed.height,
                                      staged.utxo_root, staged.monetary.state);
        staged.invocation_cost = invocation;
        return Result::Accepted;
    }
} // namespace

BlockPreviewResult PreviewBlockTemplate(
    const std::vector<Transaction> &txs, uint64_t time,
    const BlockPreviewLimits &limits, const OrdinaryParentContext &parent,
    const std::vector<Header> &history, const HeaderChainProfile &hp,
    const OrdinaryCandidateProfile &op, const MonetaryProfile &mp,
    const BlockCostProfile &cp, BlockStateTransaction &state, BlockPreview &out,
    std::string &error) {
    using Result = BlockPreviewResult;
    AbortOnFailure guard{state}; // Never accepted: previews always abort.
    try {
        const auto mtp = ParentMedianTime(hp, parent.header, history);
        if (!mtp || hp.chain_id != parent.chain_id || op.parent_mtp != *mtp ||
            parent.header.height == UINT64_MAX ||
            op.candidate_height != parent.header.height + 1 ||
            !ValidateOrdinaryProfile(op, error)) {
            error = "preview local parent history or profile context mismatch";
            return Result::Inconclusive;
        }
        if (!limits.max_transactions || !limits.max_block_bytes) {
            error = "preview requires explicit nonzero limits";
            return Result::Inconclusive;
        }
        (void)RequiredBlockBurn(0, parent.monetary.ema_block_cost, mp);
        (void)AuthenticatedEnvelopeCost(0, 1, cp);
        Hash parent_target, parent_id;
        const auto genesis =
            DecodeCompactTarget(hp.genesis_bits, Integer(hp.pow_limit));
        const auto required =
            genesis ? RequiredAsertCandidateBits(
                          hp.half_life_seconds, hp.spacing_seconds, *genesis,
                          hp.genesis_time, Integer(hp.pow_limit),
                          {parent.header.time, parent.header.height})
                    : std::nullopt;
        Hash child_target;
        if (!required || hp.genesis_time > MAX_TIME ||
            !DecodeTarget(parent.header.bits, hp.pow_limit, parent_target) ||
            !DecodeTarget(required->bits, hp.pow_limit, child_target) ||
            !BlockId(parent.chain_id, parent.header, parent_id)) {
            error = "preview target or parent identity context";
            return Result::Inconclusive;
        }
        const auto parent_root = StorageCall([&] { return state.Root(); });
        if (StateRoot(parent.chain_id, parent.header.height, parent_root,
                      parent.monetary) != parent.header.state_root ||
            Integer(parent.monetary.prev_work) !=
                (MonetaryInteger(1) << 256) / (Integer(parent_target) + 1)) {
            error = "preview parent storage or monetary work mismatch";
            return Result::StorageError;
        }
        if (parent.monetary.tail_subsidy < mp.tail_min ||
            parent.monetary.tail_subsidy > mp.tail_max ||
            parent.monetary.tail_subsidy != AbsoluteTail(mp, Integer(parent.monetary.prev_work)) || time > MAX_TIME ||
            time <= *mtp) {
            error = "preview monetary tail or candidate time context";
            return Result::Inconclusive;
        }
        if (txs.size() > limits.max_transactions || txs.size() > UINT32_MAX ||
            limits.max_block_bytes < HEADER_SIZE + 4) {
            error = "preview transaction count or block byte cap";
            return Result::CapacityRefused;
        }
        FramedBlock block;
        block.transactions = txs;
        block.frame_prefix_bytes.reserve(txs.size());
        block.transaction_bytes.reserve(txs.size());
        block.transaction_identities.reserve(txs.size());
        uint64_t size = HEADER_SIZE + 4;
        for (const auto &tx : txs) {
            std::vector<uint8_t> bytes;
            if (!EncodeTransaction(tx, op.transaction, bytes, error))
                return Result::InvalidTransactions;
            const uint64_t prefix = CompactSizeWidth(bytes.size());
            const uint64_t remaining = limits.max_block_bytes - size;
            if (prefix > remaining || bytes.size() > remaining - prefix) {
                error = "preview block byte cap";
                return Result::CapacityRefused;
            }
            size += prefix + bytes.size();
            block.frame_prefix_bytes.push_back(prefix);
            block.transaction_bytes.push_back(bytes.size());
        }
        if (txs.empty()) {
            error = "empty block";
            return Result::InvalidTransactions;
        }
        if (txs[0].inputs.size() != 1 || txs[0].inputs[0].flags != 2) {
            error = "first transaction must be coinbase";
            return Result::InvalidTransactions;
        }
        std::set<Hash> seen_ids;
        std::vector<TxIdentityPair> leaves(txs.size());
        for (size_t i = 0; i < txs.size(); ++i) {
            if (i > 0) {
                for (const auto &input : txs[i].inputs) {
                    if (input.flags == 2) {
                        error = "ordinary transaction contains coinbase input";
                        return Result::InvalidTransactions;
                    }
                }
            }
            IdentityDigests ids;
            if (!ComputeIdentitiesValidated(txs[i], op.transaction,
                                            parent.chain_id, ids, error))
                return Result::InvalidTransactions;
            if (!seen_ids.insert(ids.txid).second) {
                error = "duplicate transaction id";
                return Result::InvalidTransactions;
            }
            leaves[i] = {ids.txhash, ids.txid};
            block.transaction_identities.push_back(ids);
        }
        Header header;
        header.version = hp.version;
        header.prev_id = parent_id;
        header.height = op.candidate_height;
        header.time = time;
        header.bits = required->bits;
        header.size = size;
        header.nonce = 0;
        if (!TransactionRoot(leaves, header.tx_root)) {
            error = "transaction root";
            return Result::InvalidTransactions;
        }
        block.header = header;
        StagedBlockTransition staged;
        uint64_t coinbase_bytes{}, frames{};
        const MonetaryInteger child_work =
            (MonetaryInteger(1) << 256) / (Integer(child_target) + 1);
        const auto result = EvaluateBoundTransactions(
            block, parent, parent_id, child_work, op, mp, cp, state, staged,
            coinbase_bytes, frames, error);
        if (result != CandidateCheckResult::Accepted)
            return result == CandidateCheckResult::Invalid
                       ? Result::InvalidTransactions
                   : result == CandidateCheckResult::StorageError
                       ? Result::StorageError
                       : Result::Inconclusive;
        BlockPreview preview;
        preview.header = header;
        preview.header.state_root = staged.state_root;
        preview.parent_id = parent_id;
        preview.parent_utxo_root = parent_root;
        preview.profile_digest = BlockValidationProfileDigest(hp, op, mp, cp);
        preview.utxo_root = staged.utxo_root;
        preview.state_root = staged.state_root;
        preview.monetary = std::move(staged.monetary);
        preview.account_cost = std::move(staged.account_cost);
        preview.enforce_cost = std::move(staged.enforce_cost);
        preview.invocation_cost = staged.invocation_cost;
        preview.coinbase_bytes = coinbase_bytes;
        preview.frame_prefix_bytes = frames;
        out = std::move(preview);
        error.clear();
        return Result::Ready;
    } catch (const StorageFailure &e) {
        error = e.what();
        return Result::StorageError;
    } catch (const std::exception &e) {
        error = e.what();
        return Result::Inconclusive;
    }
}

CandidateCheckResult StageCompleteBlock(
    const std::vector<uint8_t> &wire, const OrdinaryParentContext &parent,
    const std::vector<Header> &history, const HeaderChainProfile &hp,
    const OrdinaryCandidateProfile &op, const MonetaryProfile &mp,
    const BlockCostProfile &cp, BlockStateTransaction &state,
    StagedBlockTransition &out, std::string &error,
    DeterministicBlockFailure *failure) {
    using Result = CandidateCheckResult;
    if (failure) *failure = {};
    bool bound = false;
    Hash proof_block{}, proof_parent{}, proof_profile{}, proof_root{};
    auto invalid = [&] {
        if (failure && bound) {
            failure->valid_ = true;
            failure->block_ = proof_block;
            failure->parent_ = proof_parent;
            failure->profile_ = proof_profile;
            failure->root_ = proof_root;
        }
        return Result::Invalid;
    };
    AbortOnFailure guard{state};
    try {
        Header claimed;
        if (wire.size() < HEADER_SIZE + 4 ||
            !ParseHeader(wire.data(), HEADER_SIZE, claimed)) {
            error = "block header frame";
            return Result::Invalid;
        }
        const auto mtp = ParentMedianTime(hp, parent.header, history);
        if (!mtp || hp.chain_id != parent.chain_id || op.parent_mtp != *mtp ||
            parent.header.height == std::numeric_limits<uint64_t>::max() ||
            op.candidate_height != parent.header.height + 1) {
            error = "local parent history or profile context mismatch";
            return Result::StorageError;
        }
        // Configuration is trusted local input; its errors must not poison a
        // peer's block ID. Validate these schedules before processing its body.
        try {
            (void)RequiredBlockBurn(0, parent.monetary.ema_block_cost, mp);
            (void)AuthenticatedEnvelopeCost(0, 1, cp);
        } catch (const std::invalid_argument &e) {
            throw StorageFailure(e.what());
        }
        if (op.candidate_height != claimed.height) {
            error = "complete block context";
            return Result::Invalid;
        }
        const auto header_check = ValidateChildHeaderChecked(
            hp, parent.header, history, claimed, claimed.tx_root,
            claimed.state_root, wire.size(), error);
        if (header_check != HeaderCheckResult::Valid)
            return header_check == HeaderCheckResult::Invalid
                       ? Result::Invalid
                       : Result::Inconclusive;
        // Parent mismatch is local state inconsistency, not a bad child block.
        const auto parent_root = StorageCall([&] { return state.Root(); });
        if (StateRoot(parent.chain_id, parent.header.height, parent_root,
                      parent.monetary) != parent.header.state_root) {
            error = "parent storage state root mismatch";
            return Result::StorageError;
        }
        FramedBlock block;
        if (!DecodeBlockWire(wire, op.transaction, parent.chain_id, block, error))
            return Result::Invalid;
        Hash parent_target, child_target, parent_id;
        if (!DecodeTarget(parent.header.bits, hp.pow_limit, parent_target) ||
            !DecodeTarget(claimed.bits, hp.pow_limit, child_target) ||
            !BlockId(parent.chain_id, parent.header, parent_id)) {
            error = "complete block target or parent id";
            return Result::Inconclusive;
        }
        const MonetaryInteger parent_work = (MonetaryInteger(1) << 256) /
                                 (Integer(parent_target) + 1);
        if (Integer(parent.monetary.prev_work) != parent_work) {
            error = "parent monetary work does not match target";
            return Result::StorageError;
        }
        // Invalid parent monetary state is a local-context problem. Validation
        // of a child must never certify an invalid-root fact from it.
        if (parent.monetary.tail_subsidy < mp.tail_min ||
            parent.monetary.tail_subsidy > mp.tail_max ||
            parent.monetary.tail_subsidy != AbsoluteTail(mp, parent_work)) {
            error = "parent monetary tail context";
            return Result::Inconclusive;
        }
        std::string profile_error;
        bound = ValidateOrdinaryProfile(op, profile_error) &&
                BlockId(parent.chain_id, claimed, proof_block);
        proof_parent = parent_id;
        proof_root = parent_root;
        if (bound) proof_profile = BlockValidationProfileDigest(hp, op, mp, cp);
        if (claimed.prev_id != parent_id) {
            error = "candidate is not bound to this authenticated parent";
            return Result::Inconclusive;
        }
        const MonetaryInteger child_work = (MonetaryInteger(1) << 256) /
                                (Integer(child_target) + 1);
        StagedBlockTransition staged;
        uint64_t coinbase_bytes{}, frames{};
        const auto evaluated = EvaluateBoundTransactions(
            block, parent, parent_id, child_work, op, mp, cp, state, staged,
            coinbase_bytes, frames, error);
        if (evaluated != Result::Accepted)
            return evaluated == Result::Invalid ? invalid() : evaluated;
        const auto final_header = ValidateChildHeaderChecked(
            hp, parent.header, history, claimed, claimed.tx_root,
            staged.state_root, wire.size(), error);
        if (final_header != HeaderCheckResult::Valid)
            return final_header == HeaderCheckResult::Invalid
                       ? invalid()
                       : Result::Inconclusive;
        if (!BlockId(parent.chain_id, claimed, staged.block_id)) {
            error = "child block id";
            return invalid();
        }
        out = std::move(staged);
        guard.accepted = true;
        error.clear();
        return Result::Accepted;
    } catch (const StorageFailure &e) {
        error = e.what();
        return Result::StorageError;
    } catch (const std::invalid_argument &e) {
        error = e.what();
        return Result::Inconclusive;
    } catch (const std::bad_alloc &) {
        error = "block transition allocation failure";
        return Result::Inconclusive;
    } catch (const std::exception &exception) {
        error = exception.what();
        return Result::Inconclusive;
    }
}
} // namespace lotus::v2
