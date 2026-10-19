// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of chronik-indexer query/group_history.rs (QueryGroupHistory).

#include <core/query/query.h>

#include <chronik/native/codec/hex.h>
#include <chronik/native/error.h>
#include <chronik/native/index/group_history.h>
#include <chronik/native/mem/mempool.h>

#include <algorithm>

namespace chronik::native::query {

namespace {

[[noreturn]] void MissingMempoolTx(const TxId &txid) {
    throw ChronikError("500: Inconsistent mempool: Transaction " +
                       HashToHex(txid) + " not in mempool");
}

void CheckPageSize(size_t request_page_size) {
    if (request_page_size < MIN_HISTORY_PAGE_SIZE) {
        throw ChronikError("400: Requested page size " +
                           std::to_string(request_page_size) +
                           " is too small, minimum is " +
                           std::to_string(MIN_HISTORY_PAGE_SIZE));
    }
    if (request_page_size > MAX_HISTORY_PAGE_SIZE) {
        throw ChronikError("400: Requested page size " +
                           std::to_string(request_page_size) +
                           " is too big, maximum is " +
                           std::to_string(MAX_HISTORY_PAGE_SIZE));
    }
}

size_t SatMul(size_t a, size_t b) {
    return b != 0 && a > SIZE_MAX / b ? SIZE_MAX : a * b;
}
size_t SatSub(size_t a, size_t b) { return a > b ? a - b : 0; }
size_t DivCeil(size_t a, size_t b) { return a / b + (a % b != 0 ? 1 : 0); }

/** The member's mempool history in Rust's (time, TxId BE) order. */
std::vector<std::pair<int64_t, TxId>>
MempoolMemberHistory(const mem::MempoolGroupHistory *history,
                     ByteView member_ser) {
    std::vector<std::pair<int64_t, TxId>> txs;
    if (!history) {
        return txs;
    }
    if (const auto *member_txs = history->MemberHistory(member_ser)) {
        txs.assign(member_txs->begin(), member_txs->end());
        std::sort(txs.begin(), txs.end(), TimeTxidLessBe);
    }
    return txs;
}

TxPagePlan EmptyPage() { return TxPagePlan{}; }

} // namespace

std::optional<Bytes>
GroupHistoryQuery::MemberSer(const GroupMemberArg &member,
                             const index::GroupHistoryReader &db) const {
    if (member.member) {
        return group.SerMember(*member.member);
    }
    if (!is_scripthash_index_enabled) {
        throw ChronikError("400: Script hash index disabled");
    }
    // Check the mempool first, then the db. The script is more likely to be
    // in the db, but accessing the mempool's hashmap is faster.
    if (mempool_history) {
        if (auto member_ser =
                mempool_history->MemberSerByMemberHash(member.member_hash)) {
            return Bytes(member_ser->begin(), member_ser->end());
        }
    }
    return db.MemberSerByMemberHash(member.member_hash);
}

DbTxJob GroupHistoryQuery::ResolveDbTx(TxNum tx_num) const {
    const index::TxReader tx_reader(snap.Store(), snap.Txn());
    const index::BlockReader block_reader(snap.Store(), snap.Txn());
    const std::optional<index::BlockTx> block_tx = tx_reader.TxByTxNum(tx_num);
    if (!block_tx) {
        throw ChronikError("500: Inconsistent DB: Transaction num " +
                           std::to_string(tx_num) + " not in DB");
    }
    const std::optional<index::DbBlock> block =
        block_reader.ByHeight(block_tx->block_height);
    if (!block) {
        throw ChronikError("500: Inconsistent DB: Transaction num " +
                           std::to_string(tx_num) + " has no block");
    }
    DbTxJob job;
    job.tx_num = tx_num;
    job.entry = block_tx->entry;
    job.block = *block;
    job.mempool_spent = CopyMempoolSpent(snap, block_tx->entry.txid);
    return job;
}

TxPagePlan GroupHistoryQuery::ConfirmedTxs(const GroupMemberArg &member,
                                           size_t request_page_num,
                                           size_t request_page_size,
                                           bool include_spent_by) const {
    CheckPageSize(request_page_size);
    const index::GroupHistoryReader db_reader(snap.Store(), snap.Txn(), group);
    const std::optional<Bytes> member_ser = MemberSer(member, db_reader);
    if (!member_ser) {
        return EmptyPage();
    }
    const auto [num_db_pages, num_db_txs] =
        db_reader.MemberNumPagesAndTxs(*member_ser);
    const size_t num_request_pages = DivCeil(num_db_txs, request_page_size);

    TxPagePlan plan;
    plan.db_opts.include_spent_by = include_spent_by;
    plan.db_opts.wrap_read_failure = false;
    plan.num_pages = uint32_t(num_request_pages);
    plan.num_txs = uint32_t(num_db_txs);

    // Initial index in the list of all txs of this script.
    const size_t first_tx_idx = SatMul(request_page_num, request_page_size);
    // Calculate how many txs we're going to return.
    const size_t num_returned_txs =
        std::min(request_page_size, SatSub(num_db_txs, first_tx_idx));
    // Short-circuit so we don't fetch DB again if no results.
    if (num_returned_txs == 0) {
        return plan;
    }
    const size_t page_size = db_reader.PageSize();
    // First DB page to start reading from.
    const size_t db_page_num_start = first_tx_idx / page_size;
    // First tx index with that page.
    size_t first_inner_idx = first_tx_idx % page_size;
    try {
        for (size_t current_page_num = db_page_num_start;
             current_page_num < num_db_pages; ++current_page_num) {
            const std::vector<TxNum> db_page_tx_nums =
                db_reader.PageTxs(*member_ser, index::PageNum(current_page_num))
                    .value_or(std::vector<TxNum>{});
            for (size_t i = first_inner_idx; i < db_page_tx_nums.size(); ++i) {
                plan.jobs.emplace_back(ResolveDbTx(db_page_tx_nums[i]));
                // We filled up the requested page size -> return
                if (plan.jobs.size() == request_page_size) {
                    return plan;
                }
            }
            first_inner_idx = 0;
        }
    } catch (...) {
        plan.deferred = std::current_exception();
        return plan;
    }
    if (plan.jobs.size() != num_returned_txs) {
        // We should've predicted exactly how many txs we'll return.
        snap.Indexer().GetHost().Log(LogLevel::Info,
                                     "WARNING: Allocated more txs than needed\n");
    }
    // Couldn't fill requested page size completely
    return plan;
}

TxPagePlan GroupHistoryQuery::RevHistory(const GroupMemberArg &member,
                                         size_t request_page_num,
                                         size_t request_page_size) const {
    CheckPageSize(request_page_size);
    const index::GroupHistoryReader db_reader(snap.Store(), snap.Txn(), group);
    const std::optional<Bytes> member_ser = MemberSer(member, db_reader);
    if (!member_ser) {
        return EmptyPage();
    }
    const size_t num_db_txs = db_reader.MemberNumPagesAndTxs(*member_ser).second;

    // How many txs in total to skip, beginning from the mempool txs, and then
    // continuing backwards into the DB txs.
    const size_t request_tx_offset =
        SatMul(request_page_num, request_page_size);

    // All the mempool txs for this member
    const std::vector<std::pair<int64_t, TxId>> mempool_txs =
        MempoolMemberHistory(mempool_history, *member_ser);

    const size_t total_num_txs = mempool_txs.size() + num_db_txs;
    TxPagePlan plan;
    plan.num_pages = uint32_t(DivCeil(total_num_txs, request_page_size));
    plan.num_txs = uint32_t(total_num_txs);

    // Number of mempool txs in the result.
    const size_t num_page_mempool_txs = std::min(
        request_page_size, SatSub(mempool_txs.size(), request_tx_offset));
    // Backwards offset into the DB.
    const size_t request_db_tx_offset =
        SatSub(request_tx_offset, mempool_txs.size());
    // DB txs left after skipping the requested offset.
    const size_t num_db_txs_available =
        SatSub(num_db_txs, request_db_tx_offset);
    // How many DB txs we can return at most
    const size_t max_page_db_txs = request_page_size - num_page_mempool_txs;
    // How many DB txs we return.
    const size_t num_page_db_txs =
        std::min(max_page_db_txs, num_db_txs_available);

    try {
        // Add the requested mempool txs, we skip over the requested offset,
        // and take only as many as we can put on the page.
        size_t skipped = 0;
        size_t taken = 0;
        for (auto it = mempool_txs.rbegin();
             it != mempool_txs.rend() && taken < request_page_size; ++it) {
            if (skipped < request_tx_offset) {
                ++skipped;
                continue;
            }
            std::optional<MempoolTxJob> job = MakeMempoolJob(snap, it->second);
            if (!job) {
                MissingMempoolTx(it->second);
            }
            plan.jobs.emplace_back(std::move(*job));
            ++taken;
        }

        // If we filled up the page with mempool txs, or there's no DB txs on
        // this page, we can return early to avoid reading the DB.
        if (num_page_mempool_txs == request_page_size || num_page_db_txs == 0) {
            return plan;
        }

        // Initial index to start reading from in the list of all DB txs of
        // this member. We then iterate this backwards, until we fill the page
        // or hit the first DB tx of the member.
        const size_t first_db_tx_idx = num_db_txs_available - 1;
        const size_t page_size = db_reader.PageSize();
        const size_t db_page_num_start = first_db_tx_idx / page_size;
        size_t first_inner_idx = first_db_tx_idx % page_size;

        plan.sort_db_from = num_page_mempool_txs;
        for (size_t page = db_page_num_start + 1; page-- > 0;) {
            const std::vector<TxNum> db_page_tx_nums =
                db_reader.PageTxs(*member_ser, index::PageNum(page))
                    .value_or(std::vector<TxNum>{});
            for (size_t inner_idx = first_inner_idx + 1; inner_idx-- > 0;) {
                plan.jobs.emplace_back(
                    ResolveDbTx(db_page_tx_nums.at(inner_idx)));
                // Filled up page: break out of outer loop.
                if (plan.jobs.size() == request_page_size) {
                    return plan;
                }
            }
            first_inner_idx = page_size - 1;
        }
    } catch (...) {
        plan.deferred = std::current_exception();
    }
    return plan;
}

TxPagePlan
GroupHistoryQuery::UnconfirmedTxs(const GroupMemberArg &member) const {
    const index::GroupHistoryReader db_reader(snap.Store(), snap.Txn(), group);
    const std::optional<Bytes> member_ser = MemberSer(member, db_reader);
    if (!member_ser) {
        return EmptyPage();
    }
    TxPagePlan plan;
    plan.counts_from_txs = true;
    for (const auto &[time, txid] :
         MempoolMemberHistory(mempool_history, *member_ser)) {
        std::optional<MempoolTxJob> job = MakeMempoolJob(snap, txid);
        if (!job) {
            MissingMempoolTx(txid);
        }
        plan.jobs.emplace_back(std::move(*job));
    }
    return plan;
}

} // namespace chronik::native::query
