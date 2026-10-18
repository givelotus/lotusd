// Copyright (c) 2026 The Lotus developers
#include "block_assembler.h"
#include "block_template.h"
#include <algorithm>
#include <cstdio>
#include <limits>
#include <stdexcept>
namespace lotus::v2 {
namespace {
#ifdef LOTUS_V2_BLOCK_ASSEMBLER_TEST_INSTRUMENTATION
std::function<void()> build_test_hook;
#endif
using Result = LocalBlockBuildResult;
Result PreviewResult(BlockPreviewResult result) {
    switch (result) {
    case BlockPreviewResult::Ready: return Result::Ready;
    case BlockPreviewResult::InvalidTransactions: return Result::InvalidTransactions;
    case BlockPreviewResult::CapacityRefused: return Result::CapacityRefused;
    case BlockPreviewResult::Inconclusive: return Result::Inconclusive;
    case BlockPreviewResult::StorageError: return Result::StorageError;
    }
    return Result::Inconclusive;
}
// Canonical encoders remain authoritative. This bounds aggregate transaction
// copying/encoding before making a complete transaction-list copy. A temporary
// individual encoding retains the existing caller-selected TxProfile bounds.
bool AddFrameSize(uint64_t bytes, uint64_t cap, uint64_t &total) {
    const uint64_t prefix = CompactSizeWidth(bytes);
    if (total > cap || prefix > cap - total || bytes > cap - total - prefix) return false;
    total += prefix + bytes; return true;
}
bool SameParent(const BlockPreview &a, const BlockPreview &b) {
    return a.parent_id == b.parent_id && a.parent_utxo_root == b.parent_utxo_root &&
        a.profile_digest == b.profile_digest && a.header.prev_id == b.header.prev_id &&
        a.header.version == b.header.version && a.header.height == b.header.height &&
        a.header.time == b.header.time && a.header.bits == b.header.bits;
}
bool SameQuoteShape(const BlockPreview &quote, const BlockPreview &final, uint64_t claim) {
    return quote.coinbase_bytes == final.coinbase_bytes && quote.frame_prefix_bytes == final.frame_prefix_bytes &&
        quote.header.size == final.header.size && quote.account_cost == final.account_cost &&
        quote.enforce_cost == final.enforce_cost && quote.invocation_cost == final.invocation_cost &&
        EncodeMonetaryState(quote.monetary.state) == EncodeMonetaryState(final.monetary.state) &&
        quote.monetary.subsidy == final.monetary.subsidy && quote.monetary.total_fees == final.monetary.total_fees &&
        quote.monetary.token_burn == final.monetary.token_burn && quote.monetary.burned_fees == final.monetary.burned_fees &&
        quote.monetary.required_underclaim == final.monetary.required_underclaim &&
        final.monetary.actual_underclaim == quote.monetary.actual_underclaim - claim;
}
} // namespace
#ifdef LOTUS_V2_BLOCK_ASSEMBLER_TEST_INSTRUMENTATION
void SetLocalBlockBuildTestHook(std::function<void()> hook) {
    build_test_hook = std::move(hook);
}
#endif
LocalBlockBuildResult BuildLocalDiskBlockTemplate(
    const LocalBlockRequest &request, const LocalBlockLimits &limits,
    const HeaderChainProfile &hp, OrdinaryCandidateProfile op,
    const MonetaryProfile &mp, const BlockCostProfile &cp, DiskStateStore &store,
    LocalBlockTemplate &out, std::string &error) {
    try {
#ifdef LOTUS_V2_BLOCK_ASSEMBLER_TEST_INSTRUMENTATION
        if (build_test_hook) build_test_hook();
#endif
        if (request.ordinary.size() > limits.max_ordinary_transactions || request.ordinary.size() >= UINT32_MAX ||
            limits.max_block_bytes < HEADER_SIZE + 4) {
            error = "local block transaction or byte capacity"; return Result::CapacityRefused;
        }
        if (request.coinbase_data && (request.coinbase_data->empty() || request.coinbase_data->size() > 8192)) {
            error = "local coinbase data shape"; return Result::InvalidTransactions;
        }
        if (request.coinbase_data && request.coinbase_data->size() > limits.max_coinbase_data_bytes) {
            error = "local coinbase data capacity"; return Result::CapacityRefused;
        }
        if (!store.IsOpen()) { error = "chainstate database unavailable"; return Result::StorageError; }
        const Hash profile = BlockValidationProfileDigest(hp, op, mp, cp);
        if (!store.MatchesProfile(hp.chain_id, profile)) {
            error = "stored validator profile mismatch"; return Result::StorageError;
        }
        const auto before = store.Metadata(); const Hash parent_root = store.Root();
        if (request.expected_parent != before.tip) { error = "local template parent changed"; return Result::StaleParent; }
        Header parent;
        if (!ParseHeader(before.header.data(), before.header.size(), parent)) {
            error = "stored parent header encoding"; return Result::StorageError;
        }
        if (parent.height >= UINT32_MAX) {
            error = "local derived coinbase height exceeds u32"; return Result::Inconclusive;
        }
        const auto &supplied_destination = request.coinbase_destination;
        if (supplied_destination.branches.size() > MAX_OUTPUT_BRANCHES || supplied_destination.paths.size() > MAX_OUTPUT_PATHS ||
            std::any_of(supplied_destination.paths.begin(), supplied_destination.paths.end(),
                        [](const auto &path) { return path.size() > MAX_OUTPUT_BRANCHES; })) {
            error = "local coinbase destination shape"; return Result::InvalidTransactions;
        }
        Output destination = supplied_destination; destination.value = 0;
        if (destination.HasToken() || destination.IsBurn()) {
            error = "local coinbase destination must be native and spendable"; return Result::InvalidTransactions;
        }
        std::vector<uint8_t> bytes;
        if (!EncodeOutput(destination, bytes, error)) return Result::InvalidTransactions;
        Transaction coinbase; Input input; input.flags = 2; input.prev_txid = before.tip;
        input.prev_index = uint32_t(parent.height + 1); input.sequence = UINT32_MAX;
        if (request.coinbase_data) { input.has_coinbase_data = true; input.coinbase_data = *request.coinbase_data; }
        coinbase.inputs.push_back(std::move(input)); coinbase.outputs.push_back(std::move(destination));
        if (!EncodeTransaction(coinbase, op.transaction, bytes, error)) return Result::InvalidTransactions;
        const uint64_t zero_coinbase_bytes = bytes.size(); uint64_t block_bytes = HEADER_SIZE + 4;
        if (!AddFrameSize(bytes.size(), limits.max_block_bytes, block_bytes)) {
            error = "local block byte capacity"; return Result::CapacityRefused;
        }
        for (const auto &tx : request.ordinary) {
            if (!EncodeTransaction(tx, op.transaction, bytes, error)) return Result::InvalidTransactions;
            if (std::any_of(tx.inputs.begin(), tx.inputs.end(), [](const Input &i) { return i.flags == 2; })) {
                error = "local supplied list contains coinbase"; return Result::InvalidTransactions;
            }
            if (!AddFrameSize(bytes.size(), limits.max_block_bytes, block_bytes)) {
                error = "local block byte capacity"; return Result::CapacityRefused;
            }
        }
        std::vector<Transaction> transactions;
        transactions.reserve(request.ordinary.size() + 1); transactions.push_back(std::move(coinbase));
        transactions.insert(transactions.end(), request.ordinary.begin(), request.ordinary.end());
        const BlockPreviewLimits preview_limits{uint64_t(transactions.size()), limits.max_block_bytes};
        BlockPreview quote;
        auto result = PreviewStoredBlockTemplate(transactions, request.time, preview_limits, hp, op, mp, cp, store, quote, error);
        if (result != BlockPreviewResult::Ready) return PreviewResult(result);
        if (quote.parent_id != request.expected_parent || quote.parent_utxo_root != parent_root || quote.profile_digest != profile ||
            store.Metadata() != before || store.Root() != parent_root) {
            error = "local parent changed during quote"; return Result::StaleParent;
        }
        if (quote.coinbase_bytes != zero_coinbase_bytes || quote.header.size != block_bytes) {
            error = "local quote framing mismatch"; return Result::Inconclusive;
        }
        // AdvanceMonetary already checked all entitlement, token/fee burn and
        // cost arithmetic. With zero coinbase outputs actual_underclaim is the
        // complete entitlement; explicit policy may claim less than available.
        const MonetaryInteger available = quote.monetary.actual_underclaim - quote.monetary.required_underclaim;
        if (available < 0) { error = "local monetary quote inconsistent"; return Result::Inconclusive; }
        const MonetaryInteger capped = std::min(available, MonetaryInteger(request.max_claim));
        if (capped < 0 || capped > std::numeric_limits<uint64_t>::max()) {
            error = "local coinbase claim width"; return Result::Inconclusive;
        }
        const uint64_t claim = capped.convert_to<uint64_t>(); transactions.front().outputs.front().value = claim;
        if (!EncodeTransaction(transactions.front(), op.transaction, bytes, error)) return Result::InvalidTransactions;
        if (bytes.size() != zero_coinbase_bytes) { error = "local coinbase value changed encoding size"; return Result::Inconclusive; }
        BlockPreview final;
        result = PreviewStoredBlockTemplate(transactions, request.time, preview_limits, hp, op, mp, cp, store, final, error);
        if (result != BlockPreviewResult::Ready) return PreviewResult(result);
        if (!SameParent(quote, final) || store.Metadata() != before || store.Root() != parent_root) {
            error = "local parent changed between previews"; return Result::StaleParent;
        }
        if (!SameQuoteShape(quote, final, claim)) {
            error = "local coinbase claim changed cost or monetary quote"; return Result::Inconclusive;
        }
        LocalBlockTemplate built; built.preview = std::move(final);
        if (!EncodeBlockWire(built.preview.header, transactions, op.transaction, built.wire, error)) return Result::InvalidTransactions;
        if (built.wire.size() > limits.max_block_bytes || built.wire.size() != block_bytes) {
            error = "local encoded block capacity or size mismatch"; return Result::Inconclusive;
        }
        if (store.Metadata() != before || store.Root() != parent_root) {
            error = "local parent changed before template return"; return Result::StaleParent;
        }
        out = std::move(built); error.clear(); return Result::Ready;
    } catch (const std::bad_alloc &) {
        error = "local block allocation failure"; return Result::CapacityRefused;
    } catch (const std::length_error &) {
        error = "local block allocation length"; return Result::CapacityRefused;
    } catch (const std::exception &exception) {
        error = std::string("unexpected local block builder exception: ") + exception.what();
        std::fprintf(stderr, "%s\n", error.c_str());
        return Result::StorageError;
    } catch (...) {
        error = "unexpected non-standard local block builder exception";
        std::fprintf(stderr, "%s\n", error.c_str());
        return Result::StorageError;
    }
}
LocalNonceResult SearchLocalBlockNonce(
    const LocalBlockTemplate &block, const ChainId &chain, const Hash &pow_limit,
    uint64_t start, uint64_t attempts, LocalBlockTemplate &out, std::string &error) {
    using Result = LocalNonceResult;
    if (attempts > MAX_NONCE_ATTEMPTS) { error = "local nonce attempt capacity"; return Result::CapacityRefused; }
    try {
        std::array<uint8_t, HEADER_SIZE> header; Hash target;
        if (block.wire.size() < HEADER_SIZE + 4 || block.preview.header.size != block.wire.size() ||
            block.preview.header.prev_id != block.preview.parent_id || block.preview.header.state_root != block.preview.state_root ||
            !SerializeHeader(block.preview.header, header) || !std::equal(header.begin(), header.end(), block.wire.begin()) ||
            !DecodeTarget(block.preview.header.bits, pow_limit, target)) {
            error = "local nonce template header binding"; return Result::InvalidTemplate;
        }
        Header found = block.preview.header;
        if (!SearchNonce(found, chain, target, start, attempts)) {
            error = "local nonce range exhausted"; return Result::Exhausted;
        }
        Hash id;
        if (!BlockId(chain, found, id) || !SerializeHeader(found, header)) {
            error = "local nonce result unavailable"; return Result::Inconclusive;
        }
        LocalBlockTemplate mined = block; mined.preview.header = found; mined.mined_id = id;
        std::copy(header.begin(), header.end(), mined.wire.begin());
        out = std::move(mined); error.clear(); return Result::Found;
    } catch (const std::bad_alloc &) {
        error = "local nonce output allocation failure"; return Result::CapacityRefused;
    } catch (const std::length_error &) {
        error = "local nonce output allocation length"; return Result::CapacityRefused;
    } catch (const std::exception &exception) {
        error = exception.what(); return Result::Inconclusive;
    }
}
} // namespace lotus::v2
