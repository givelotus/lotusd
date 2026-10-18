// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <index/coinstatsindex.h>
#include <logging/values.h>

#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/amount.h>
#include <consensus/tx_verify.h>
#include <crypto/muhash.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <primitives/blockhash.h>
#include <serialize.h>
#include <txdb.h>
#include <undo.h>
#include <util/check.h>
#include <validation.h>

#include <set>

using kernel::CCoinsStats;
using kernel::GetBogoSize;
using kernel::TxOutSer;

static constexpr uint8_t DB_BLOCK_HASH{'s'};
static constexpr uint8_t DB_BLOCK_HEIGHT{'t'};
static constexpr uint8_t DB_MUHASH{'M'};
static constexpr uint8_t DB_NATIVE_VERSION{'V'};
static constexpr uint32_t NATIVE_INDEX_VERSION{2};

namespace {

// Reconstruct paid lifetime from the accepted block's durable undo, never from
// the mutable current UTXO view (the index may be syncing an old block).
static bool OutputFeeShare(const CTransaction &tx, const CTxUndo *undo,
                           int height, uint64_t &fee_share, Amount &fee) {
    fee_share = 0;
    fee = Amount::zero();
    if (tx.IsCoinBase()) {
        return true;
    }
    TxValidationState state;
    if (!undo || undo->vprevout.size() != tx.vin.size() ||
        !Consensus::CheckTxInputsFromSpentCoins(tx, undo->vprevout, state, height,
                                               fee)) {
        LogError("%s: inconsistent accepted transaction undo at height %d, tx=%s\n",
                 __func__, height, tx.GetId().ToString());
        return false;
    }
    size_t spendable_outputs = 0;
    for (const auto &out : tx.vout) {
        if (!out.scriptPubKey.IsUnspendable() && (out.nFlags & 0x02) == 0) {
            ++spendable_outputs;
        }
    }
    fee_share = lotus::v2::ComputeTxFeePerSpendableOutput(
        static_cast<uint64_t>(fee / SATOSHI), spendable_outputs);
    return true;
}

// CTOR can spend an output before its creator is visited. Such a Coin never
// enters the final UTXO set; positional undo can predate the creator's paid
// lifetime update, so it must not be used to cancel that output's MuHash.
static std::set<COutPoint> IntraBlockSpent(const CBlock &block) {
    std::set<TxId> created;
    for (const auto &tx : block.vtx) {
        created.insert(tx->GetId());
    }
    std::set<COutPoint> spent;
    for (const auto &tx : block.vtx) {
        if (tx->IsCoinBase()) {
            continue;
        }
        for (const auto &in : tx->vin) {
            if (in.nFlags != 3 && created.count(in.prevout.GetTxId())) {
                spent.insert(in.prevout);
            }
        }
    }
    return spent;
}

struct DBVal {
    uint256 muhash;
    uint64_t transaction_output_count;
    uint64_t bogo_size;
    Amount total_amount;
    Amount total_subsidy;
    Amount total_unspendable_amount;
    Amount total_prevout_spent_amount;
    Amount total_new_outputs_ex_coinbase_amount;
    Amount total_coinbase_amount;
    Amount total_unspendables_genesis_block;
    Amount total_unspendables_bip30;
    Amount total_unspendables_scripts;
    Amount total_unspendables_unclaimed_rewards;
    Amount total_unspendables_expired;
    Amount total_cleaning_bounty;

    SERIALIZE_METHODS(DBVal, obj) {
        READWRITE(obj.muhash);
        READWRITE(obj.transaction_output_count);
        READWRITE(obj.bogo_size);
        READWRITE(obj.total_amount);
        READWRITE(obj.total_subsidy);
        READWRITE(obj.total_unspendable_amount);
        READWRITE(obj.total_prevout_spent_amount);
        READWRITE(obj.total_new_outputs_ex_coinbase_amount);
        READWRITE(obj.total_coinbase_amount);
        READWRITE(obj.total_unspendables_genesis_block);
        READWRITE(obj.total_unspendables_bip30);
        READWRITE(obj.total_unspendables_scripts);
        READWRITE(obj.total_unspendables_unclaimed_rewards);
        READWRITE(obj.total_unspendables_expired, obj.total_cleaning_bounty);
    }
};

struct DBHeightKey {
    int height;

    explicit DBHeightKey(int height_in) : height(height_in) {}

    template <typename Stream> void Serialize(Stream &s) const {
        ser_writedata8(s, DB_BLOCK_HEIGHT);
        ser_writedata32be(s, height);
    }

    template <typename Stream> void Unserialize(Stream &s) {
        const uint8_t prefix{ser_readdata8(s)};
        if (prefix != DB_BLOCK_HEIGHT) {
            throw std::ios_base::failure(
                "Invalid format for coinstatsindex DB height key");
        }
        height = ser_readdata32be(s);
    }
};

struct DBHashKey {
    BlockHash block_hash;

    explicit DBHashKey(const BlockHash &hash_in) : block_hash(hash_in) {}

    SERIALIZE_METHODS(DBHashKey, obj) {
        uint8_t prefix{DB_BLOCK_HASH};
        READWRITE(prefix);
        if (prefix != DB_BLOCK_HASH) {
            throw std::ios_base::failure(
                "Invalid format for coinstatsindex DB hash key");
        }

        READWRITE(obj.block_hash);
    }
};

}; // namespace

std::unique_ptr<CoinStatsIndex> g_coin_stats_index;

CoinStatsIndex::CoinStatsIndex(std::unique_ptr<interfaces::Chain> chain,
                               size_t n_cache_size, bool f_memory, bool f_wipe)
    : BaseIndex(std::move(chain), "coinstatsindex") {
    fs::path path{gArgs.GetDataDirNet() / "indexes" / "coinstats"};
    fs::create_directories(path);

    m_db = std::make_unique<CoinStatsIndex::DB>(path / "db", n_cache_size,
                                                f_memory, f_wipe);
}

bool CoinStatsIndex::WriteBlock(const CBlock &block,
                                const CBlockIndex *pindex) {
    CBlockUndo block_undo;
    const auto intra_block_spent = IntraBlockSpent(block);
    Amount block_fees = Amount::zero();
    const Amount block_subsidy{
        GetBlockSubsidy(pindex->nHeight, Params().GetConsensus())};
    m_total_subsidy += block_subsidy;

    // Ignore genesis block
    if (pindex->nHeight > 0) {
        if (!m_chainstate->m_blockman.ReadBlockUndo(block_undo, *pindex)) {
            return false;
        }

        std::pair<BlockHash, DBVal> read_out;
        if (!m_db->Read(DBHeightKey(pindex->nHeight - 1), read_out)) {
            return false;
        }

        BlockHash expected_block_hash{pindex->pprev->GetBlockHash()};
        if (read_out.first != expected_block_hash) {
            LogInfoEvent(
                BCLog::ALL, "coinstats_previous_block_unexpected",
                "WARNING: previous block header belongs to unexpected block {block_hash}; expected {expected_block_hash}")
                .Field(BCLog::LogField::BlockHash, read_out.first)
                .Field(BCLog::LogField::ExpectedBlockHash, expected_block_hash);

            if (!m_db->Read(DBHashKey(expected_block_hash), read_out)) {
                LogErrorEvent(
                    BCLog::ALL, "coinstats_previous_header_missing",
                    "{source_function}: previous block header not found; expected {expected_block_hash}")
                    .Field(BCLog::LogField::SourceFunction, __func__)
                    .Field(BCLog::LogField::ExpectedBlockHash,
                           expected_block_hash);
                return false;
            }
        }

        // TODO: Deduplicate BIP30 related code
        bool is_bip30_block{
            (pindex->nHeight == 91722 &&
             pindex->GetBlockHash() ==
                 BlockHash{uint256S("0x00000000000271a2dc26e7667f8419f2e15416dc"
                                    "6955e5a6c6cdf3f2574dd08e")}) ||
            (pindex->nHeight == 91812 &&
             pindex->GetBlockHash() ==
                 BlockHash{uint256S("0x00000000000af0aed4792b1acee3d966af36cf5d"
                                    "ef14935db8de83d6f9306f2f")})};

        // Add the new utxos created from the block
        for (size_t i = 0; i < block.vtx.size(); ++i) {
            const auto &tx{block.vtx.at(i)};

            // Skip duplicate txid coinbase transactions (BIP30).
            if (is_bip30_block && tx->IsCoinBase()) {
                m_total_unspendable_amount += block_subsidy;
                m_total_unspendables_bip30 += block_subsidy;
                continue;
            }

            uint64_t fee_share;
            Amount fee;
            if (!OutputFeeShare(
                    *tx,
                    tx->IsCoinBase() ? nullptr : &block_undo.vtxundo.at(i - 1),
                    pindex->nHeight, fee_share, fee)) {
                return false;
            }
            block_fees += fee;
            for (uint32_t j = 0; j < tx->vout.size(); ++j) {
                const CTxOut &out{tx->vout[j]};
                Coin coin{out, static_cast<uint32_t>(pindex->nHeight),
                          tx->IsCoinBase(), fee_share};
                COutPoint outpoint{tx->GetId(), j};

                // Skip unspendable coins
                if (coin.GetTxOut().scriptPubKey.IsUnspendable()) {
                    m_total_unspendable_amount += coin.GetTxOut().nValue;
                    m_total_unspendables_scripts += coin.GetTxOut().nValue;
                    continue;
                }

                if (!intra_block_spent.count(outpoint)) {
                    m_muhash.Insert(MakeUCharSpan(TxOutSer(outpoint, coin)));
                }

                if (tx->IsCoinBase()) {
                    m_total_coinbase_amount += coin.GetTxOut().nValue;
                } else {
                    m_total_new_outputs_ex_coinbase_amount +=
                        coin.GetTxOut().nValue;
                }

                ++m_transaction_output_count;
                m_total_amount += coin.GetTxOut().nValue;
                m_bogo_size += GetBogoSize(coin.GetTxOut().scriptPubKey);
            }

            // The coinbase tx has no undo data since no former output is spent
            if (!tx->IsCoinBase()) {
                const auto &tx_undo{block_undo.vtxundo.at(i - 1)};

                for (size_t j = 0; j < tx_undo.vprevout.size(); ++j) {
                    if (tx->vin[j].nFlags == 3) {
                        continue;
                    }
                    Coin coin{tx_undo.vprevout[j]};
                    COutPoint outpoint{tx->vin[j].prevout.GetTxId(),
                                       tx->vin[j].prevout.GetN()};

                    if (!intra_block_spent.count(outpoint)) {
                        m_muhash.Remove(MakeUCharSpan(TxOutSer(outpoint, coin)));
                    }

                    m_total_prevout_spent_amount += coin.GetTxOut().nValue;

                    --m_transaction_output_count;
                    m_total_amount -= coin.GetTxOut().nValue;
                    m_bogo_size -= GetBogoSize(coin.GetTxOut().scriptPubKey);
                }
            }
        }
    } else {
        // genesis block
        m_total_unspendable_amount += block_subsidy;
        m_total_unspendables_genesis_block += block_subsidy;
    }

    // Expiry burns an existing UTXO without spending a transaction input.
    // Preserve its authenticated undo metadata and account for it separately.
    for (const auto &expired : block_undo.vexpired) {
        const Coin &coin = expired.coin;
        m_muhash.Remove(MakeUCharSpan(TxOutSer(expired.outpoint, coin)));
        --m_transaction_output_count;
        m_total_amount -= coin.GetTxOut().nValue;
        m_bogo_size -= GetBogoSize(coin.GetTxOut().scriptPubKey);
        m_total_unspendable_amount += coin.GetTxOut().nValue;
        m_total_unspendables_expired += coin.GetTxOut().nValue;
    }
    m_total_cleaning_bounty +=
        static_cast<int64_t>(lotus::v2::ComputeCleaningCrewBounty(
            block_undo.vexpired.size(),
            static_cast<uint64_t>(block_fees / SATOSHI))) *
        SATOSHI;

    // If spent prevouts + block subsidy are still a higher amount than
    // new outputs + coinbase + current unspendable amount this means
    // the miner did not claim the full block reward. Unclaimed block
    // rewards are also unspendable.
    const Amount unclaimed_rewards{
        (m_total_prevout_spent_amount + m_total_subsidy +
         m_total_cleaning_bounty + m_total_unspendables_expired) -
        (m_total_new_outputs_ex_coinbase_amount + m_total_coinbase_amount +
         m_total_unspendable_amount)};
    m_total_unspendable_amount += unclaimed_rewards;
    m_total_unspendables_unclaimed_rewards += unclaimed_rewards;

    StoreStats(pindex);
    return true;
}

void CoinStatsIndex::StoreStats(const CBlockIndex *pindex) {
    std::pair<BlockHash, DBVal> value;
    value.first = pindex->GetBlockHash();
    value.second.transaction_output_count = m_transaction_output_count;
    value.second.bogo_size = m_bogo_size;
    value.second.total_amount = m_total_amount;
    value.second.total_subsidy = m_total_subsidy;
    value.second.total_unspendable_amount = m_total_unspendable_amount;
    value.second.total_prevout_spent_amount = m_total_prevout_spent_amount;
    value.second.total_new_outputs_ex_coinbase_amount =
        m_total_new_outputs_ex_coinbase_amount;
    value.second.total_coinbase_amount = m_total_coinbase_amount;
    value.second.total_unspendables_genesis_block =
        m_total_unspendables_genesis_block;
    value.second.total_unspendables_bip30 = m_total_unspendables_bip30;
    value.second.total_unspendables_scripts = m_total_unspendables_scripts;
    value.second.total_unspendables_unclaimed_rewards =
        m_total_unspendables_unclaimed_rewards;
    value.second.total_unspendables_expired = m_total_unspendables_expired;
    value.second.total_cleaning_bounty = m_total_cleaning_bounty;

    uint256 out;
    m_muhash.Finalize(out);
    value.second.muhash = out;

    // Intentionally do not update DB_MUHASH here so it stays in sync with
    // DB_BEST_BLOCK, and the index is not corrupted if there is an unclean
    // shutdown.
    m_db->Write(DBHeightKey(pindex->nHeight), value);
}

static bool CopyHeightIndexToHashIndex(CDBIterator &db_it, CDBBatch &batch,
                                       const std::string &index_name,
                                       int start_height, int stop_height) {
    DBHeightKey key{start_height};
    db_it.Seek(key);

    for (int height = start_height; height <= stop_height; ++height) {
        if (!db_it.GetKey(key) || key.height != height) {
            LogErrorEvent(
                BCLog::ALL, "coinstats_database_key_unexpected",
                "{source_function}: unexpected key in {name}: expected ({database_key_prefix}, {height})")
                .Field(BCLog::LogField::SourceFunction, __func__)
                .Field(BCLog::LogField::Name, index_name)
                .Field(BCLog::LogField::DatabaseKeyPrefix,
                       BCLog::LogChar{DB_BLOCK_HEIGHT})
                .Field(BCLog::LogField::Height, height);
            return false;
        }

        std::pair<BlockHash, DBVal> value;
        if (!db_it.GetValue(value)) {
            LogErrorEvent(
                BCLog::ALL, "coinstats_database_height_read_failed",
                "{source_function}: unable to read value in {name} at key ({database_key_prefix}, {height})")
                .Field(BCLog::LogField::SourceFunction, __func__)
                .Field(BCLog::LogField::Name, index_name)
                .Field(BCLog::LogField::DatabaseKeyPrefix,
                       BCLog::LogChar{DB_BLOCK_HEIGHT})
                .Field(BCLog::LogField::Height, height);
            return false;
        }

        batch.Write(DBHashKey(value.first), std::move(value.second));

        db_it.Next();
    }
    return true;
}

bool CoinStatsIndex::Rewind(const CBlockIndex *current_tip,
                            const CBlockIndex *new_tip) {
    assert(current_tip->GetAncestor(new_tip->nHeight) == new_tip);

    CDBBatch batch(*m_db);
    std::unique_ptr<CDBIterator> db_it(m_db->NewIterator());

    // During a reorg, we need to copy all hash digests for blocks that are
    // getting disconnected from the height index to the hash index so we can
    // still find them when the height index entries are overwritten.
    if (!CopyHeightIndexToHashIndex(*db_it, batch, m_name, new_tip->nHeight,
                                    current_tip->nHeight)) {
        return false;
    }

    m_db->WriteBatch(batch);

    {
        LOCK(cs_main);
        const CBlockIndex *iter_tip{m_chainstate->m_blockman.LookupBlockIndex(
            current_tip->GetBlockHash())};

        do {
            CBlock block;

            if (!m_chainstate->m_blockman.ReadBlock(block, *iter_tip)) {
                LogErrorEvent(
                    BCLog::ALL, "coinstats_block_read_failed",
                    "{source_function}: Failed to read block {block_hash} from disk")
                    .Field(BCLog::LogField::SourceFunction, __func__)
                    .Field(BCLog::LogField::BlockHash,
                           iter_tip->GetBlockHash());
                return false;
            }

            ReverseBlock(block, iter_tip);

            iter_tip = iter_tip->GetAncestor(iter_tip->nHeight - 1);
        } while (new_tip != iter_tip);
    }

    return BaseIndex::Rewind(current_tip, new_tip);
}

static bool LookUpOne(const CDBWrapper &db, const interfaces::BlockKey &block,
                      DBVal &result) {
    // First check if the result is stored under the height index and the value
    // there matches the block hash. This should be the case if the block is on
    // the active chain.
    std::pair<BlockHash, DBVal> read_out;
    if (!db.Read(DBHeightKey(block.height), read_out)) {
        return false;
    }
    if (read_out.first == block.hash) {
        result = std::move(read_out.second);
        return true;
    }

    // If value at the height index corresponds to an different block, the
    // result will be stored in the hash index.
    return db.Read(DBHashKey(block.hash), result);
}

std::optional<CCoinsStats>
CoinStatsIndex::LookUpStats(const CBlockIndex *block_index) const {
    CCoinsStats stats{Assert(block_index)->nHeight,
                      block_index->GetBlockHash()};
    stats.index_used = true;

    DBVal entry;
    if (!LookUpOne(*m_db, {block_index->GetBlockHash(), block_index->nHeight},
                   entry)) {
        return std::nullopt;
    }

    stats.hashSerialized = entry.muhash;
    stats.nTransactionOutputs = entry.transaction_output_count;
    stats.nBogoSize = entry.bogo_size;
    stats.total_amount = entry.total_amount;
    stats.total_subsidy = entry.total_subsidy;
    stats.total_unspendable_amount = entry.total_unspendable_amount;
    stats.total_prevout_spent_amount = entry.total_prevout_spent_amount;
    stats.total_new_outputs_ex_coinbase_amount =
        entry.total_new_outputs_ex_coinbase_amount;
    stats.total_coinbase_amount = entry.total_coinbase_amount;
    stats.total_unspendables_genesis_block =
        entry.total_unspendables_genesis_block;
    stats.total_unspendables_bip30 = entry.total_unspendables_bip30;
    stats.total_unspendables_scripts = entry.total_unspendables_scripts;
    stats.total_unspendables_unclaimed_rewards =
        entry.total_unspendables_unclaimed_rewards;
    stats.total_unspendables_expired = entry.total_unspendables_expired;
    stats.total_cleaning_bounty = entry.total_cleaning_bounty;

    return stats;
}

bool CoinStatsIndex::CustomInit(
    const std::optional<interfaces::BlockKey> &block) {
    uint32_t version;
    if (!m_db->Read(DB_NATIVE_VERSION, version)) {
        if (!m_db->IsEmpty()) {
            LogError("%s: Native coinstats index predates paid-lifetime/expiry "
                     "accounting; "
                     "restart with -reindex to rebuild it\n",
                     __func__);
            return false;
        }
        m_db->Write(DB_NATIVE_VERSION, NATIVE_INDEX_VERSION);
    } else if (version != NATIVE_INDEX_VERSION) {
        LogError("%s: Unsupported native coinstats index version %u; "
                 "restart with -reindex to rebuild it\n",
                 __func__, version);
        return false;
    }
    if (!m_db->Read(DB_MUHASH, m_muhash)) {
        // Check that the cause of the read failure is that the key does not
        // exist. Any other errors indicate database corruption or a disk
        // failure, and starting the index would cause further corruption.
        if (m_db->Exists(DB_MUHASH)) {
            LogErrorEvent(
                BCLog::ALL, "coinstats_state_read_failed",
                "{source_function}: Cannot read current {name} state; index may be corrupted")
                .Field(BCLog::LogField::SourceFunction, __func__)
                .Field(BCLog::LogField::Name, GetName());
            return false;
        }
    }

    if (block) {
        DBVal entry;
        if (!LookUpOne(*m_db, *block, entry)) {
            LogErrorEvent(
                BCLog::ALL, "coinstats_state_read_failed",
                "{source_function}: Cannot read current {name} state; index may be corrupted")
                .Field(BCLog::LogField::SourceFunction, __func__)
                .Field(BCLog::LogField::Name, GetName());
            return false;
        }

        uint256 out;
        m_muhash.Finalize(out);
        if (entry.muhash != out) {
            LogErrorEvent(
                BCLog::ALL, "coinstats_state_read_failed",
                "{source_function}: Cannot read current {name} state; index may be corrupted")
                .Field(BCLog::LogField::SourceFunction, __func__)
                .Field(BCLog::LogField::Name, GetName());
            return false;
        }

        m_transaction_output_count = entry.transaction_output_count;
        m_bogo_size = entry.bogo_size;
        m_total_amount = entry.total_amount;
        m_total_subsidy = entry.total_subsidy;
        m_total_unspendable_amount = entry.total_unspendable_amount;
        m_total_prevout_spent_amount = entry.total_prevout_spent_amount;
        m_total_new_outputs_ex_coinbase_amount =
            entry.total_new_outputs_ex_coinbase_amount;
        m_total_coinbase_amount = entry.total_coinbase_amount;
        m_total_unspendables_genesis_block =
            entry.total_unspendables_genesis_block;
        m_total_unspendables_bip30 = entry.total_unspendables_bip30;
        m_total_unspendables_scripts = entry.total_unspendables_scripts;
        m_total_unspendables_unclaimed_rewards =
            entry.total_unspendables_unclaimed_rewards;
        m_total_unspendables_expired = entry.total_unspendables_expired;
        m_total_cleaning_bounty = entry.total_cleaning_bounty;
    }

    return true;
}

bool CoinStatsIndex::CustomCommit(CDBBatch &batch) {
    // DB_MUHASH should always be committed in a batch together with
    // DB_BEST_BLOCK to prevent an inconsistent state of the DB.
    batch.Write(DB_MUHASH, m_muhash);
    return true;
}

// Reverse a single block as part of a reorg
bool CoinStatsIndex::ReverseBlock(const CBlock &block,
                                  const CBlockIndex *pindex) {
    CBlockUndo block_undo;
    const auto intra_block_spent = IntraBlockSpent(block);
    Amount block_fees = Amount::zero();
    std::pair<BlockHash, DBVal> read_out;

    const Amount block_subsidy{
        GetBlockSubsidy(pindex->nHeight, Params().GetConsensus())};
    m_total_subsidy -= block_subsidy;

    // Ignore genesis block
    if (pindex->nHeight > 0) {
        if (!m_chainstate->m_blockman.ReadBlockUndo(block_undo, *pindex)) {
            return false;
        }

        if (!m_db->Read(DBHeightKey(pindex->nHeight - 1), read_out)) {
            return false;
        }

        BlockHash expected_block_hash{pindex->pprev->GetBlockHash()};
        if (read_out.first != expected_block_hash) {
            LogInfoEvent(
                BCLog::ALL, "coinstats_previous_block_unexpected",
                "WARNING: previous block header belongs to unexpected block {block_hash}; expected {expected_block_hash}")
                .Field(BCLog::LogField::BlockHash, read_out.first)
                .Field(BCLog::LogField::ExpectedBlockHash, expected_block_hash);

            if (!m_db->Read(DBHashKey(expected_block_hash), read_out)) {
                LogErrorEvent(
                    BCLog::ALL, "coinstats_previous_header_missing",
                    "{source_function}: previous block header not found; expected {expected_block_hash}")
                    .Field(BCLog::LogField::SourceFunction, __func__)
                    .Field(BCLog::LogField::ExpectedBlockHash,
                           expected_block_hash);
                return false;
            }
        }
    }

    // Remove the new UTXOs that were created from the block
    for (size_t i = 0; i < block.vtx.size(); ++i) {
        const auto &tx{block.vtx.at(i)};

        uint64_t fee_share;
        Amount fee;
        if (!OutputFeeShare(
                *tx, tx->IsCoinBase() ? nullptr : &block_undo.vtxundo.at(i - 1),
                pindex->nHeight, fee_share, fee)) {
            return false;
        }
        block_fees += fee;
        for (uint32_t j = 0; j < tx->vout.size(); ++j) {
            const CTxOut &out{tx->vout[j]};
            COutPoint outpoint{tx->GetId(), j};
            Coin coin{out, static_cast<uint32_t>(pindex->nHeight),
                      tx->IsCoinBase(), fee_share};

            // Skip unspendable coins
            if (coin.GetTxOut().scriptPubKey.IsUnspendable()) {
                m_total_unspendable_amount -= coin.GetTxOut().nValue;
                m_total_unspendables_scripts -= coin.GetTxOut().nValue;
                continue;
            }

            if (!intra_block_spent.count(outpoint)) {
                m_muhash.Remove(MakeUCharSpan(TxOutSer(outpoint, coin)));
            }

            if (tx->IsCoinBase()) {
                m_total_coinbase_amount -= coin.GetTxOut().nValue;
            } else {
                m_total_new_outputs_ex_coinbase_amount -=
                    coin.GetTxOut().nValue;
            }

            --m_transaction_output_count;
            m_total_amount -= coin.GetTxOut().nValue;
            m_bogo_size -= GetBogoSize(coin.GetTxOut().scriptPubKey);
        }

        // The coinbase tx has no undo data since no former output is spent
        if (!tx->IsCoinBase()) {
            const auto &tx_undo{block_undo.vtxundo.at(i - 1)};

            for (size_t j = 0; j < tx_undo.vprevout.size(); ++j) {
                if (tx->vin[j].nFlags == 3) {
                    continue;
                }
                Coin coin{tx_undo.vprevout[j]};
                COutPoint outpoint{tx->vin[j].prevout.GetTxId(),
                                   tx->vin[j].prevout.GetN()};

                if (!intra_block_spent.count(outpoint)) {
                    m_muhash.Insert(MakeUCharSpan(TxOutSer(outpoint, coin)));
                }

                m_total_prevout_spent_amount -= coin.GetTxOut().nValue;

                m_transaction_output_count++;
                m_total_amount += coin.GetTxOut().nValue;
                m_bogo_size += GetBogoSize(coin.GetTxOut().scriptPubKey);
            }
        }
    }

    for (const auto &expired : block_undo.vexpired) {
        const Coin &coin = expired.coin;
        m_muhash.Insert(MakeUCharSpan(TxOutSer(expired.outpoint, coin)));
        ++m_transaction_output_count;
        m_total_amount += coin.GetTxOut().nValue;
        m_bogo_size += GetBogoSize(coin.GetTxOut().scriptPubKey);
        m_total_unspendable_amount -= coin.GetTxOut().nValue;
        m_total_unspendables_expired -= coin.GetTxOut().nValue;
    }
    m_total_cleaning_bounty -=
        static_cast<int64_t>(lotus::v2::ComputeCleaningCrewBounty(
            block_undo.vexpired.size(),
            static_cast<uint64_t>(block_fees / SATOSHI))) *
        SATOSHI;

    const Amount unclaimed_rewards{
        (m_total_new_outputs_ex_coinbase_amount + m_total_coinbase_amount +
         m_total_unspendable_amount) -
        (m_total_prevout_spent_amount + m_total_subsidy +
         m_total_cleaning_bounty + m_total_unspendables_expired)};
    m_total_unspendable_amount -= unclaimed_rewards;
    m_total_unspendables_unclaimed_rewards -= unclaimed_rewards;

    // Check that the rolled back internal values are consistent with the DB
    // read out
    uint256 out;
    m_muhash.Finalize(out);
    Assert(read_out.second.muhash == out);

    Assert(m_transaction_output_count ==
           read_out.second.transaction_output_count);
    Assert(m_total_amount == read_out.second.total_amount);
    Assert(m_bogo_size == read_out.second.bogo_size);
    Assert(m_total_subsidy == read_out.second.total_subsidy);
    Assert(m_total_unspendable_amount ==
           read_out.second.total_unspendable_amount);
    Assert(m_total_prevout_spent_amount ==
           read_out.second.total_prevout_spent_amount);
    Assert(m_total_new_outputs_ex_coinbase_amount ==
           read_out.second.total_new_outputs_ex_coinbase_amount);
    Assert(m_total_coinbase_amount == read_out.second.total_coinbase_amount);
    Assert(m_total_unspendables_genesis_block ==
           read_out.second.total_unspendables_genesis_block);
    Assert(m_total_unspendables_bip30 ==
           read_out.second.total_unspendables_bip30);
    Assert(m_total_unspendables_scripts ==
           read_out.second.total_unspendables_scripts);
    Assert(m_total_unspendables_unclaimed_rewards ==
           read_out.second.total_unspendables_unclaimed_rewards);
    Assert(m_total_unspendables_expired ==
           read_out.second.total_unspendables_expired);
    Assert(m_total_cleaning_bounty == read_out.second.total_cleaning_bounty);

    return true;
}
