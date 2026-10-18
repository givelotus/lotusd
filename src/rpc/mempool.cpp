// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/mempool_entry.h>
#include <kernel/mempool_persist.h>

#include <chainparams.h>
#include <common/args.h>
#include <core_io.h>
#include <lotus_v2/fee_hysteresis.h>
#include <lotus_v2/signing.h>
#include <net/v2_protocol_handler.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <node/context.h>
#include <node/mempool_persist_args.h>
#include <node/snapshot.h>
#include <node/types.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/moneystr.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <thread>
#include <vector>

using kernel::DumpMempool;

using node::DEFAULT_MAX_RAW_TX_FEE_RATE;
using node::MempoolPath;
using node::NodeContext;
using node::TransactionError;
using util::ToString;

static bool IsDisallowedNonV7Tx(const CTransaction &tx,
                                const NodeContext &node) {
    const bool allow_legacy_tx =
        (node.args && node.args->GetBoolArg("-allowlegacytx", false)) ||
        gArgs.GetBoolArg("-allowlegacytx", false) ||
        (std::getenv("LOTUS_ALLOW_LEGACY_TX") != nullptr);
    if (allow_legacy_tx) {
        return false;
    }
    return tx.nVersion != 7 || tx.vin.empty() || tx.vin[0].nFlags == 0;
}

static RPCHelpMan sendrawtransaction() {
    return RPCHelpMan{
        "sendrawtransaction",
        "Submits raw transaction (serialized, hex-encoded) to local node and "
        "network.\n"
        "\nThe node announces transactions it originated to all of its "
        "peers at the next relay tick, without delay, so peers can tell "
        "which node they came from. For privacy, submit each transaction to "
        "several independent nodes rather than to one.\n"
        "\nAlso see createrawtransaction and "
        "signrawtransactionwithkey calls.\n",
        {
            {"hexstring", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The hex string of the raw transaction"},
            {"maxfeerate", RPCArg::Type::AMOUNT,
             RPCArg::Default{
                 FormatMoney(DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK())},
             "Reject transactions whose fee rate is higher than the specified "
             "value, expressed in " +
                 Currency::getTicker() +
                 "/kB\nSet to 0 to accept any fee rate.\n"},
        },
        RPCResult{RPCResult::Type::STR_HEX, "", "The transaction hash in hex"},
        RPCExamples{
            "\nCreate a transaction\n" +
            HelpExampleCli(
                "createrawtransaction",
                "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" "
                "\"{\\\"myaddress\\\":10000}\"") +
            "Sign the transaction, and get back the hex\n" +
            HelpExampleCli("signrawtransactionwithwallet", "\"myhex\"") +
            "\nSend the transaction (signed hex)\n" +
            HelpExampleCli("sendrawtransaction", "\"signedhex\"") +
            "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("sendrawtransaction", "\"signedhex\"")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            // parse hex string from parameter
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                   "TX decode failed");
            }

            CTransactionRef tx(MakeTransactionRef(std::move(mtx)));

            const CFeeRate max_raw_tx_fee_rate =
                request.params[1].isNull()
                    ? DEFAULT_MAX_RAW_TX_FEE_RATE
                    : CFeeRate(AmountFromValue(request.params[1]));

            int64_t virtual_size = GetVirtualTransactionSize(*tx);
            Amount max_raw_tx_fee = max_raw_tx_fee_rate.GetFee(virtual_size);

            std::string err_string;
            AssertLockNotHeld(cs_main);
            NodeContext &node = EnsureAnyNodeContext(request.context);
            if (IsDisallowedNonV7Tx(*tx, node)) {
                throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                                   "bad-txns-non-v7-format");
            }
            const int64_t now_ms =
                TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
            const auto &fee_ctrl =
                lotus::v2::GetGlobalFeeHysteresisController();
            const TransactionError err = BroadcastTransaction(
                node, tx, err_string, max_raw_tx_fee, /*relay*/ true,
                /*wait_callback*/ true, /*rpc_fee_hysteresis=*/true,
                /*use_rpc_admission_queue=*/true);
            if (err != TransactionError::OK) {
                if (err == TransactionError::MEMPOOL_REJECTED &&
                    (err_string.find("min relay fee not met") !=
                         std::string::npos ||
                     err_string.find("mempool min fee not met") !=
                         std::string::npos)) {
                    const auto fee_info = fee_ctrl.GetFeeRateInfo(now_ms);
                    const uint64_t tx_cu =
                        static_cast<uint64_t>(std::max<int64_t>(0, virtual_size));
                    const lotus::v2::FeeCheckResult fee_eval =
                        fee_ctrl.EvaluateTransactionFee(
                            lotus::v2::FeeTier::RpcAdmission, tx_cu, 0, now_ms);
                    err_string += strprintf(
                        " (required_fee_sats=%llu, required_rate_per_kcu=%llu, "
                        "recommended_sdk_feerate_per_kcu=%llu)",
                        static_cast<unsigned long long>(
                            fee_eval.required_fee_sats),
                        static_cast<unsigned long long>(
                            fee_eval.required_rate_per_kcu),
                        static_cast<unsigned long long>(
                            fee_info.recommended_sdk_feerate_per_kcu));
                }
                throw JSONRPCTransactionError(err, err_string);
            }

            // Block to make sure wallet/indexers sync before returning
            CHECK_NONFATAL(node.validation_signals)
                ->SyncWithValidationInterfaceQueue();

            return tx->GetId().GetHex();
        },
    };
}

static RPCHelpMan testmempoolaccept() {
    const auto ticker = Currency::getTicker();
    return RPCHelpMan{
        "testmempoolaccept",
        "\nReturns result of mempool acceptance tests indicating if raw "
        "transaction(s) (serialized, hex-encoded) would be accepted by "
        "mempool.\n"
        "\nIf multiple transactions are passed in, parents must come before "
        "children and package policies apply: the transactions cannot conflict "
        "with any mempool transactions or each other.\n"
        "\nIf one transaction fails, other transactions may not be fully "
        "validated (the 'allowed' key will be blank).\n"
        "\nThe maximum number of transactions allowed is " +
            ToString(MAX_PACKAGE_COUNT) +
            ".\n"
            "\nThis checks if transactions violate the consensus or policy "
            "rules.\n"
            "\nSee sendrawtransaction call.\n",
        {
            {
                "rawtxs",
                RPCArg::Type::ARR,
                RPCArg::Optional::NO,
                "An array of hex strings of raw transactions.",
                {
                    {"rawtx", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                     ""},
                },
            },
            {"maxfeerate", RPCArg::Type::AMOUNT,
             RPCArg::Default{
                 FormatMoney(DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK())},
             "Reject transactions whose fee rate is higher than the specified "
             "value, expressed in " +
                 ticker + "/kB\n"},
        },
        RPCResult{
            RPCResult::Type::ARR,
            "",
            "The result of the mempool acceptance test for each raw "
            "transaction in the input array.\n"
            "Returns results for each transaction in the same order they were "
            "passed in.\n"
            "Transactions that cannot be fully validated due to failures in "
            "other transactions will not contain an 'allowed' result.\n",
            {
                {RPCResult::Type::OBJ,
                 "",
                 "",
                 {
                     {RPCResult::Type::STR_HEX, "txid",
                      "The transaction hash in hex"},
                     {RPCResult::Type::STR, "package-error",
                      "Package validation error, if any (only possible if "
                      "rawtxs had more than 1 transaction)."},
                     {RPCResult::Type::BOOL, "allowed",
                      "Whether this tx would be accepted to the mempool and "
                      "pass client-specified maxfeerate. "
                      "If not present, the tx was not fully validated due to a "
                      "failure in another tx in the list."},
                     {RPCResult::Type::NUM, "size", "The transaction size"},
                     {RPCResult::Type::OBJ,
                      "fees",
                      "Transaction fees (only present if 'allowed' is true)",
                      {
                          {RPCResult::Type::STR_AMOUNT, "base",
                           "transaction fee in " + ticker},
                          {RPCResult::Type::STR_AMOUNT, "effective-feerate",
                           "the effective feerate in " + ticker +
                               " per KvB. May differ from the base feerate if, "
                               "for example, there are modified fees from "
                               "prioritisetransaction or a package feerate was "
                               "used."},
                          {RPCResult::Type::ARR,
                           "effective-includes",
                           "transactions whose fees and vsizes are included in "
                           "effective-feerate.",
                           {
                               RPCResult{RPCResult::Type::STR_HEX, "",
                                         "transaction txid in hex"},
                           }},
                      }},
                     {RPCResult::Type::STR, "reject-reason", /*optional=*/true,
                      "Rejection string (only present when 'allowed' is "
                      "false)"},
                     {RPCResult::Type::STR, "reject-details", /*optional=*/true,
                      "Rejection details (only present when 'allowed' is false "
                      "and rejection details exist)"},

                 }},
            }},
        RPCExamples{
            "\nCreate a transaction\n" +
            HelpExampleCli(
                "createrawtransaction",
                "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" "
                "\"{\\\"myaddress\\\":10000}\"") +
            "Sign the transaction, and get back the hex\n" +
            HelpExampleCli("signrawtransactionwithwallet", "\"myhex\"") +
            "\nTest acceptance of the transaction (signed hex)\n" +
            HelpExampleCli("testmempoolaccept", R"('["signedhex"]')") +
            "\nAs a JSON-RPC call\n" +
            HelpExampleRpc("testmempoolaccept", "[\"signedhex\"]")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const UniValue raw_transactions = request.params[0].get_array();
            if (raw_transactions.size() < 1 ||
                raw_transactions.size() > MAX_PACKAGE_COUNT) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Array must contain between 1 and " +
                                       ToString(MAX_PACKAGE_COUNT) +
                                       " transactions.");
            }

            const CFeeRate max_raw_tx_fee_rate =
                request.params[1].isNull()
                    ? DEFAULT_MAX_RAW_TX_FEE_RATE
                    : CFeeRate(AmountFromValue(request.params[1]));

            std::vector<CTransactionRef> txns;
            txns.reserve(raw_transactions.size());
            for (const auto &rawtx : raw_transactions.getValues()) {
                CMutableTransaction mtx;
                if (!DecodeHexTx(mtx, rawtx.get_str())) {
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                       "TX decode failed: " + rawtx.get_str());
                }
                txns.emplace_back(MakeTransactionRef(std::move(mtx)));
            }

            NodeContext &node = EnsureAnyNodeContext(request.context);
            CTxMemPool &mempool = EnsureMemPool(node);
            ChainstateManager &chainman = EnsureChainman(node);
            Chainstate &chainstate = chainman.ActiveChainstate();
            const PackageMempoolAcceptResult package_result = [&] {
                LOCK(::cs_main);
                if (txns.size() > 1) {
                    return ProcessNewPackage(chainstate, mempool, txns,
                                             /* test_accept */ true);
                }
                return PackageMempoolAcceptResult(
                    txns[0]->GetId(),
                    chainman.ProcessTransaction(txns[0],
                                                /* test_accept*/ true));
            }();

            UniValue rpc_result(UniValue::VARR);
            // We will check transaction fees while we iterate through txns in
            // order. If any transaction fee exceeds maxfeerate, we will leave
            // the rest of the validation results blank, because it doesn't make
            // sense to return a validation result for a transaction if its
            // ancestor(s) would not be submitted.
            bool exit_early{false};
            for (const auto &tx : txns) {
                UniValue result_inner(UniValue::VOBJ);
                result_inner.pushKV("txid", tx->GetId().GetHex());
                if (package_result.m_state.GetResult() ==
                    PackageValidationResult::PCKG_POLICY) {
                    result_inner.pushKV(
                        "package-error",
                        package_result.m_state.GetRejectReason());
                }
                auto it = package_result.m_tx_results.find(tx->GetId());
                if (exit_early || it == package_result.m_tx_results.end()) {
                    // Validation unfinished. Just return the txid.
                    rpc_result.push_back(std::move(result_inner));
                    continue;
                }
                const auto &tx_result = it->second;
                // Package testmempoolaccept doesn't allow transactions to
                // already be in the mempool.
                CHECK_NONFATAL(tx_result.m_result_type !=
                               MempoolAcceptResult::ResultType::MEMPOOL_ENTRY);
                if (tx_result.m_result_type ==
                    MempoolAcceptResult::ResultType::VALID) {
                    const Amount fee = tx_result.m_base_fees.value();
                    // Check that fee does not exceed maximum fee
                    const int64_t virtual_size = tx_result.m_vsize.value();
                    const Amount max_raw_tx_fee =
                        max_raw_tx_fee_rate.GetFee(virtual_size);
                    if (max_raw_tx_fee != Amount::zero() &&
                        fee > max_raw_tx_fee) {
                        result_inner.pushKV("allowed", false);
                        result_inner.pushKV("reject-reason",
                                            "max-fee-exceeded");
                        exit_early = true;
                    } else {
                        // Only return the fee and size if the transaction
                        // would pass ATMP.
                        // These can be used to calculate the feerate.
                        result_inner.pushKV("allowed", true);
                        result_inner.pushKV("size", virtual_size);
                        UniValue fees(UniValue::VOBJ);
                        fees.pushKV("base", fee);
                        fees.pushKV(
                            "effective-feerate",
                            tx_result.m_effective_feerate.value().GetFeePerK());
                        UniValue effective_includes_res(UniValue::VARR);
                        for (const auto &txid :
                             tx_result.m_txids_fee_calculations.value()) {
                            effective_includes_res.push_back(txid.ToString());
                        }
                        fees.pushKV("effective-includes",
                                    std::move(effective_includes_res));
                        result_inner.pushKV("fees", std::move(fees));
                    }
                } else {
                    result_inner.pushKV("allowed", false);
                    const TxValidationState state = tx_result.m_state;
                    if (state.GetResult() ==
                        TxValidationResult::TX_MISSING_INPUTS) {
                        result_inner.pushKV("reject-reason", "missing-inputs");
                    } else {
                        result_inner.pushKV("reject-reason",
                                            state.GetRejectReason());
                        result_inner.pushKV("reject-details", state.ToString());
                    }
                }
                rpc_result.push_back(std::move(result_inner));
            }
            return rpc_result;
        },
    };
}

static std::vector<RPCResult> MempoolEntryDescription() {
    const auto ticker = Currency::getTicker();
    return {
        RPCResult{RPCResult::Type::NUM, "size", "transaction size."},
        RPCResult{RPCResult::Type::NUM_TIME, "time",
                  "local time transaction entered pool in seconds since 1 Jan "
                  "1970 GMT"},
        RPCResult{RPCResult::Type::NUM, "height",
                  "block height when transaction entered pool"},
        RPCResult{RPCResult::Type::OBJ,
                  "fees",
                  "",
                  {{
                      RPCResult{RPCResult::Type::STR_AMOUNT, "base",
                                "transaction fee in " + ticker},
                      RPCResult{RPCResult::Type::STR_AMOUNT, "modified",
                                "transaction fee with fee deltas used for "
                                "mining priority in " +
                                    ticker},
                  }}},
        RPCResult{
            RPCResult::Type::ARR,
            "depends",
            "unconfirmed transactions used as inputs for this transaction",
            {RPCResult{RPCResult::Type::STR_HEX, "transactionid",
                       "parent transaction id"}}},
        RPCResult{
            RPCResult::Type::ARR,
            "spentby",
            "unconfirmed transactions spending outputs from this transaction",
            {RPCResult{RPCResult::Type::STR_HEX, "transactionid",
                       "child transaction id"}}},
        RPCResult{RPCResult::Type::BOOL, "unbroadcast",
                  "Whether this transaction is currently unbroadcast (initial "
                  "broadcast not yet acknowledged by any peers)"},
    };
}

static void entryToJSON(const CTxMemPool &pool, UniValue &info,
                        const CTxMemPoolEntryRef &e)
    EXCLUSIVE_LOCKS_REQUIRED(pool.cs) {
    AssertLockHeld(pool.cs);

    UniValue fees(UniValue::VOBJ);
    fees.pushKV("base", e->GetFee());
    fees.pushKV("modified", e->GetModifiedFee());
    info.pushKV("fees", fees);

    info.pushKV("size", (int)e->GetTxSize());
    info.pushKV("time", count_seconds(e->GetTime()));
    info.pushKV("height", (int)e->GetHeight());
    const CTransaction &tx = e->GetTx();
    std::set<std::string> setDepends;
    for (const CTxIn &txin : tx.vin) {
        if (pool.exists(txin.prevout.GetTxId())) {
            setDepends.insert(txin.prevout.GetTxId().ToString());
        }
    }

    UniValue depends(UniValue::VARR);
    for (const std::string &dep : setDepends) {
        depends.push_back(dep);
    }

    info.pushKV("depends", std::move(depends));

    UniValue spent(UniValue::VARR);
    for (const auto &child : e->GetMemPoolChildrenConst()) {
        spent.push_back(child.get()->GetTx().GetId().ToString());
    }

    info.pushKV("spentby", std::move(spent));
    info.pushKV("unbroadcast", pool.IsUnbroadcastTx(tx.GetId()));
}

static void entrySnapshotToJSON(UniValue &info,
                                const node::MempoolEntrySnapshot &e) {
    UniValue fees(UniValue::VOBJ);
    fees.pushKV("base", e.fee);
    fees.pushKV("modified", e.modified_fee);
    info.pushKV("fees", std::move(fees));

    info.pushKV("size", static_cast<int>(e.tx_size));
    info.pushKV("time", e.time);
    info.pushKV("height", e.height);

    UniValue depends(UniValue::VARR);
    depends.reserve(e.depends.size());
    for (const std::string &dep : e.depends) {
        depends.push_back(dep);
    }
    info.pushKV("depends", std::move(depends));

    UniValue spent(UniValue::VARR);
    spent.reserve(e.spentby.size());
    for (const std::string &child : e.spentby) {
        spent.push_back(child);
    }
    info.pushKV("spentby", std::move(spent));
    info.pushKV("unbroadcast", e.unbroadcast);
}

static std::shared_ptr<const node::ChainAndMempoolSnapshot>
LoadOrInitMempoolSnapshot(const CTxMemPool &pool) {
    auto snap = node::GetGlobalSnapshotPublisher().Load();
    if (snap && snap->mempool_valid && snap->mempool_ptr == &pool) {
        return snap;
    }
    {
        LOCK(pool.cs);
        node::PublishMempoolSnapshot(pool);
    }
    return node::GetGlobalSnapshotPublisher().Load();
}

UniValue MempoolToJSON(const CTxMemPool &pool, bool verbose,
                       bool include_mempool_sequence) {
    if (verbose) {
        if (include_mempool_sequence) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Verbose results cannot contain mempool sequence values.");
        }
        const auto snap_ptr = LoadOrInitMempoolSnapshot(pool);
        const node::ChainAndMempoolSnapshot &snap = *CHECK_NONFATAL(snap_ptr);
        snap.EnsureMempoolVectors();
        UniValue o(UniValue::VOBJ);
        for (const node::MempoolEntrySnapshot &e : snap.mempool_entries) {
            UniValue info(UniValue::VOBJ);
            entrySnapshotToJSON(info, e);
            // Mempool has unique entries so there is no advantage in using
            // UniValue::pushKV, which checks if the key already exists in O(N).
            // UniValue::pushKVEnd is used instead which currently is O(1).
            o.pushKVEnd(e.txid.ToString(), std::move(info));
        }
        return o;
    } else {
        const auto snap_ptr = LoadOrInitMempoolSnapshot(pool);
        const node::ChainAndMempoolSnapshot &snap = *CHECK_NONFATAL(snap_ptr);
        snap.EnsureMempoolVectors();
        UniValue a(UniValue::VARR);
        a.reserve(snap.mempool_txids.size());
        for (const TxId &txid : snap.mempool_txids) {
            a.push_back(txid.ToString());
        }

        if (!include_mempool_sequence) {
            return a;
        } else {
            UniValue o(UniValue::VOBJ);
            o.pushKV("txids", std::move(a));
            o.pushKV("mempool_sequence", snap.mempool_sequence);
            return o;
        }
    }
}

static RPCHelpMan getrawmempool() {
    return RPCHelpMan{
        "getrawmempool",
        "Returns all transaction ids in memory pool as a json array of "
        "string transaction ids.\n"
        "\nHint: use getmempoolentry to fetch a specific transaction from the "
        "mempool.\n",
        {
            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false},
             "True for a json object, false for array of transaction ids"},
            {"mempool_sequence", RPCArg::Type::BOOL, RPCArg::Default{false},
             "If verbose=false, returns a json object with transaction list "
             "and mempool sequence number attached."},
        },
        {
            RPCResult{"for verbose = false",
                      RPCResult::Type::ARR,
                      "",
                      "",
                      {
                          {RPCResult::Type::STR_HEX, "", "The transaction id"},
                      }},
            RPCResult{"for verbose = true",
                      RPCResult::Type::OBJ_DYN,
                      "",
                      "",
                      {
                          {RPCResult::Type::OBJ, "transactionid", "",
                           MempoolEntryDescription()},
                      }},
            RPCResult{
                "for verbose = false and mempool_sequence = true",
                RPCResult::Type::OBJ,
                "",
                "",
                {
                    {RPCResult::Type::ARR,
                     "txids",
                     "",
                     {
                         {RPCResult::Type::STR_HEX, "", "The transaction id"},
                     }},
                    {RPCResult::Type::NUM, "mempool_sequence",
                     "The mempool sequence value."},
                }},
        },
        RPCExamples{HelpExampleCli("getrawmempool", "true") +
                    HelpExampleRpc("getrawmempool", "true")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            bool fVerbose = false;
            if (!request.params[0].isNull()) {
                fVerbose = request.params[0].get_bool();
            }

            bool include_mempool_sequence = false;
            if (!request.params[1].isNull()) {
                include_mempool_sequence = request.params[1].get_bool();
            }

            return MempoolToJSON(EnsureAnyMemPool(request.context), fVerbose,
                                 include_mempool_sequence);
        },
    };
}

static RPCHelpMan getmempoolancestors() {
    return RPCHelpMan{
        "getmempoolancestors",
        "If txid is in the mempool, returns all in-mempool ancestors.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The transaction id (must be in mempool)"},
            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false},
             "True for a json object, false for array of transaction ids"},
        },
        {
            RPCResult{
                "for verbose = false",
                RPCResult::Type::ARR,
                "",
                "",
                {{RPCResult::Type::STR_HEX, "",
                  "The transaction id of an in-mempool ancestor transaction"}}},
            RPCResult{"for verbose = true",
                      RPCResult::Type::OBJ_DYN,
                      "",
                      "",
                      {
                          {RPCResult::Type::OBJ, "transactionid", "",
                           MempoolEntryDescription()},
                      }},
        },
        RPCExamples{HelpExampleCli("getmempoolancestors", "\"mytxid\"") +
                    HelpExampleRpc("getmempoolancestors", "\"mytxid\"")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            bool fVerbose = false;
            if (!request.params[1].isNull()) {
                fVerbose = request.params[1].get_bool();
            }

            TxId txid(ParseHashV(request.params[0], "parameter 1"));

            const CTxMemPool &mempool = EnsureAnyMemPool(request.context);
            LOCK(mempool.cs);

            CTxMemPool::txiter it = mempool.mapTx.find(txid);
            if (it == mempool.mapTx.end()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   "Transaction not in mempool");
            }

            CTxMemPool::setEntries setAncestors;
            mempool.CalculateMemPoolAncestors(*it, setAncestors, false);

            if (!fVerbose) {
                UniValue o(UniValue::VARR);
                for (CTxMemPool::txiter ancestorIt : setAncestors) {
                    o.push_back((*ancestorIt)->GetTx().GetId().ToString());
                }
                return o;
            } else {
                UniValue o(UniValue::VOBJ);
                for (CTxMemPool::txiter ancestorIt : setAncestors) {
                    const CTxMemPoolEntryRef &e = *ancestorIt;
                    const TxId &_txid = e->GetTx().GetId();
                    UniValue info(UniValue::VOBJ);
                    entryToJSON(mempool, info, e);
                    o.pushKV(_txid.ToString(), std::move(info));
                }
                return o;
            }
        },
    };
}

static RPCHelpMan getmempooldescendants() {
    return RPCHelpMan{
        "getmempooldescendants",
        "If txid is in the mempool, returns all in-mempool descendants.\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The transaction id (must be in mempool)"},
            {"verbose", RPCArg::Type::BOOL, RPCArg::Default{false},
             "True for a json object, false for array of transaction ids"},
        },
        {
            RPCResult{"for verbose = false",
                      RPCResult::Type::ARR,
                      "",
                      "",
                      {{RPCResult::Type::STR_HEX, "",
                        "The transaction id of an in-mempool descendant "
                        "transaction"}}},
            RPCResult{"for verbose = true",
                      RPCResult::Type::OBJ_DYN,
                      "",
                      "",
                      {
                          {RPCResult::Type::OBJ, "transactionid", "",
                           MempoolEntryDescription()},
                      }},
        },
        RPCExamples{HelpExampleCli("getmempooldescendants", "\"mytxid\"") +
                    HelpExampleRpc("getmempooldescendants", "\"mytxid\"")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            bool fVerbose = false;
            if (!request.params[1].isNull()) {
                fVerbose = request.params[1].get_bool();
            }

            TxId txid(ParseHashV(request.params[0], "parameter 1"));

            const CTxMemPool &mempool = EnsureAnyMemPool(request.context);
            LOCK(mempool.cs);

            CTxMemPool::txiter it = mempool.mapTx.find(txid);
            if (it == mempool.mapTx.end()) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   "Transaction not in mempool");
            }

            CTxMemPool::setEntries setDescendants;
            mempool.CalculateDescendants(it, setDescendants);
            // CTxMemPool::CalculateDescendants will include the given tx
            setDescendants.erase(it);

            if (!fVerbose) {
                UniValue o(UniValue::VARR);
                for (CTxMemPool::txiter descendantIt : setDescendants) {
                    o.push_back((*descendantIt)->GetTx().GetId().ToString());
                }

                return o;
            } else {
                UniValue o(UniValue::VOBJ);
                for (CTxMemPool::txiter descendantIt : setDescendants) {
                    const CTxMemPoolEntryRef &e = *descendantIt;
                    const TxId &_txid = e->GetTx().GetId();
                    UniValue info(UniValue::VOBJ);
                    entryToJSON(mempool, info, e);
                    o.pushKV(_txid.ToString(), std::move(info));
                }
                return o;
            }
        },
    };
}

static RPCHelpMan getmempoolentry() {
    return RPCHelpMan{
        "getmempoolentry",
        "Returns mempool data for given transaction\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The transaction id (must be in mempool)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", MempoolEntryDescription()},
        RPCExamples{HelpExampleCli("getmempoolentry", "\"mytxid\"") +
                    HelpExampleRpc("getmempoolentry", "\"mytxid\"")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            TxId txid(ParseHashV(request.params[0], "parameter 1"));

            const CTxMemPool &mempool = EnsureAnyMemPool(request.context);
            const auto snap_ptr = LoadOrInitMempoolSnapshot(mempool);
            const node::ChainAndMempoolSnapshot &snap =
                *CHECK_NONFATAL(snap_ptr);

            const node::MempoolEntrySnapshot *entry =
                snap.FindMempoolEntry(txid);
            if (!entry) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   "Transaction not in mempool");
            }

            UniValue info(UniValue::VOBJ);
            entrySnapshotToJSON(info, *entry);
            return info;
        },
    };
}

UniValue MempoolInfoToJSON(const CTxMemPool &pool) {
    const auto snap_ptr = LoadOrInitMempoolSnapshot(pool);
    const node::ChainAndMempoolSnapshot &snap = *CHECK_NONFATAL(snap_ptr);
    double rolling_fee = snap.rolling_minimum_fee_rate;
    if (snap.block_since_last_rolling_fee_bump && rolling_fee != 0) {
        const int64_t time = GetTime();
        if (time > snap.last_rolling_fee_update + 10) {
            double halflife = CTxMemPool::ROLLING_FEE_HALFLIFE;
            if (snap.mempool_usage < snap.max_mempool / 4) {
                halflife /= 4;
            } else if (snap.mempool_usage < snap.max_mempool / 2) {
                halflife /= 2;
            }
            rolling_fee =
                rolling_fee /
                pow(2.0, (time - snap.last_rolling_fee_update) / halflife);
        }
    }
    const int64_t now_ms =
        TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    const lotus::v2::FeeRateInfo fee_info =
        lotus::v2::GetGlobalFeeHysteresisController().GetFeeRateInfo(now_ms);
    const CFeeRate hysteresis_admission_fee(Amount(
        static_cast<int64_t>(fee_info.rpc_admission_feerate_per_kcu) * SATOSHI));
    const CFeeRate decayed_min_fee = std::max(
        {CFeeRate(int64_t(ceill(rolling_fee)) * SATOSHI), snap.min_relay_tx_fee,
         hysteresis_admission_fee});
    UniValue ret(UniValue::VOBJ);
    ret.pushKV("loaded", snap.mempool_loaded);
    ret.pushKV("size", (int64_t)snap.mempool_size);
    ret.pushKV("bytes", (int64_t)snap.mempool_bytes);
    ret.pushKV("finalized_txs_size", (int64_t)snap.finalized_txs_size);
    ret.pushKV("finalized_txs_bytes", (int64_t)snap.finalized_txs_bytes);
    ret.pushKV("finalized_txs_sigchecks",
               (int64_t)snap.finalized_txs_sigchecks);
    ret.pushKV("usage", (int64_t)snap.mempool_usage);
    ret.pushKV("total_fee", snap.total_fee);
    ret.pushKV("maxmempool", snap.max_mempool);
    ret.pushKV("mempoolminfee", decayed_min_fee.GetFeePerK());
    ret.pushKV("minrelaytxfee", snap.min_relay_tx_fee.GetFeePerK());
    ret.pushKV("rpc_admission_feerate_sats_per_kb",
               fee_info.rpc_admission_feerate_per_kcu);
    ret.pushKV("recommended_feerate_sats_per_kb",
               fee_info.recommended_sdk_feerate_per_kcu);
    ret.pushKV("p2p_relay_feerate_sats_per_kb",
               fee_info.p2p_relay_feerate_per_kcu);
    ret.pushKV("unbroadcastcount", uint64_t{snap.unbroadcast_count});
    return ret;
}

static RPCHelpMan getmempoolinfo() {
    const auto ticker = Currency::getTicker();
    return RPCHelpMan{
        "getmempoolinfo",
        "Returns details on the active state of the TX memory pool.\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::BOOL, "loaded",
                 "True if the initial load attempt of the persisted mempool "
                 "finished"},
                {RPCResult::Type::NUM, "size", "Current tx count"},
                {RPCResult::Type::NUM, "bytes", "Sum of all transaction sizes"},
                {RPCResult::Type::NUM, "finalized_txs_size",
                 "Current finalized tx count"},
                {RPCResult::Type::NUM, "finalized_txs_bytes",
                 "Sum of all finalized transaction sizes"},
                {RPCResult::Type::NUM, "finalized_txs_sigchecks",
                 "Sum of all finalized transaction sigchecks"},
                {RPCResult::Type::NUM, "usage",
                 "Total memory usage for the mempool"},
                {RPCResult::Type::NUM, "maxmempool",
                 "Maximum memory usage for the mempool"},
                {RPCResult::Type::STR_AMOUNT, "total_fee",
                 "Total fees for the mempool in " + ticker +
                     ", ignoring modified fees through prioritisetransaction"},
                {RPCResult::Type::STR_AMOUNT, "mempoolminfee",
                 "Minimum fee rate in " + ticker +
                     "/kB for tx to be accepted. Is the maximum of "
                     "minrelaytxfee, minimum mempool fee, and RPC admission "
                     "fee hysteresis rate"},
                {RPCResult::Type::STR_AMOUNT, "minrelaytxfee",
                 "Current minimum relay fee for transactions"},
                {RPCResult::Type::NUM, "rpc_admission_feerate_sats_per_kb",
                 "Tier 1 local RPC admission fee rate in satoshis per kB"},
                {RPCResult::Type::NUM, "recommended_feerate_sats_per_kb",
                 "Recommended wallet/SDK fee rate in satoshis per kB (+5% "
                 "anti-bounce cushion)"},
                {RPCResult::Type::NUM, "p2p_relay_feerate_sats_per_kb",
                 "Tier 2 P2P relay hysteresis fee rate in satoshis per kB"},
                {RPCResult::Type::NUM, "unbroadcastcount",
                 "Current number of transactions that haven't passed initial "
                 "broadcast yet"},
            }},
        RPCExamples{HelpExampleCli("getmempoolinfo", "") +
                    HelpExampleRpc("getmempoolinfo", "")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            return MempoolInfoToJSON(EnsureAnyMemPool(request.context));
        },
    };
}

static RPCHelpMan importmempool() {
    return RPCHelpMan{
        "importmempool",
        "Import a mempool.dat file and attempt to add its contents to the "
        "mempool.\n"
        "Warning: Importing untrusted files is dangerous, especially if "
        "metadata from the file is taken over.",
        {
            {"filepath", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The mempool file"},
            {"options",
             RPCArg::Type::OBJ_NAMED_PARAMS,
             RPCArg::Optional::OMITTED,
             "",
             {
                 {"use_current_time", RPCArg::Type::BOOL, RPCArg::Default{true},
                  "Whether to use the current system time or use the entry "
                  "time metadata from the mempool file.\n"
                  "Warning: Importing untrusted metadata may lead to "
                  "unexpected issues and undesirable behavior."},
                 {"apply_fee_delta_priority", RPCArg::Type::BOOL,
                  RPCArg::Default{false},
                  "Whether to apply the fee delta metadata from the mempool "
                  "file.\n"
                  "It will be added to any existing fee deltas.\n"
                  "The fee delta can be set by the prioritisetransaction RPC.\n"
                  "Warning: Importing untrusted metadata may lead to "
                  "unexpected issues and undesirable behavior.\n"
                  "Only set this bool if you understand what it does."},
                 {"apply_unbroadcast_set", RPCArg::Type::BOOL,
                  RPCArg::Default{false},
                  "Whether to apply the unbroadcast set metadata from the "
                  "mempool file.\n"
                  "Warning: Importing untrusted metadata may lead to "
                  "unexpected issues and undesirable behavior."},
             },
             RPCArgOptions{.oneline_description = "\"options\""}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", std::vector<RPCResult>{}},
        RPCExamples{HelpExampleCli("importmempool", "/path/to/mempool.dat") +
                    HelpExampleRpc("importmempool", "/path/to/mempool.dat")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const NodeContext &node{EnsureAnyNodeContext(request.context)};

            CTxMemPool &mempool{EnsureMemPool(node)};
            ChainstateManager &chainman = EnsureChainman(node);
            Chainstate &chainstate = chainman.ActiveChainstate();

            if (chainman.IsInitialBlockDownload()) {
                throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD,
                                   "Can only import the mempool after the "
                                   "block download and sync is done.");
            }

            const fs::path load_path{fs::u8path(request.params[0].get_str())};
            const UniValue &use_current_time{
                request.params[1]["use_current_time"]};
            const UniValue &apply_fee_delta{
                request.params[1]["apply_fee_delta_priority"]};
            const UniValue &apply_unbroadcast{
                request.params[1]["apply_unbroadcast_set"]};
            kernel::ImportMempoolOptions opts{
                .use_current_time = use_current_time.isNull()
                                        ? true
                                        : use_current_time.get_bool(),
                .apply_fee_delta_priority = apply_fee_delta.isNull()
                                                ? false
                                                : apply_fee_delta.get_bool(),
                .apply_unbroadcast_set = apply_unbroadcast.isNull()
                                             ? false
                                             : apply_unbroadcast.get_bool(),
            };

            if (!kernel::LoadMempool(mempool, load_path, chainstate,
                                     std::move(opts))) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "Unable to import mempool file, see "
                                   "debug.log for details.");
            }

            UniValue ret{UniValue::VOBJ};
            return ret;
        },
    };
}

static RPCHelpMan savemempool() {
    return RPCHelpMan{
        "savemempool",
        "Dumps the mempool to disk. It will fail until the previous dump is "
        "fully loaded.\n",
        {},
        RPCResult{RPCResult::Type::OBJ,
                  "",
                  "",
                  {
                      {RPCResult::Type::STR, "filename",
                       "the directory and file where the mempool was saved"},
                  }},
        RPCExamples{HelpExampleCli("savemempool", "") +
                    HelpExampleRpc("savemempool", "")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const ArgsManager &args{EnsureAnyArgsman(request.context)};
            const CTxMemPool &mempool = EnsureAnyMemPool(request.context);

            if (!mempool.GetLoadTried()) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "The mempool was not loaded yet");
            }

            const fs::path &dump_path = MempoolPath(args);

            if (!DumpMempool(mempool, dump_path)) {
                throw JSONRPCError(RPC_MISC_ERROR,
                                   "Unable to dump mempool to disk");
            }

            UniValue ret(UniValue::VOBJ);
            ret.pushKV("filename", dump_path.u8string());

            return ret;
        },
    };
}

static RPCHelpMan submitpackage() {
    const auto ticker = Currency::getTicker();
    return RPCHelpMan{
        "submitpackage",
        "Submit a package of raw transactions (serialized, hex-encoded) to "
        "local node.\n"
        "The package must consist of a child with its parents, and none of the "
        "parents may depend on one another.\n"
        "The package will be validated according to consensus and mempool "
        "policy rules. If any transaction passes, it will be accepted to "
        "mempool.\n"
        "This RPC is experimental and the interface may be unstable. Refer to "
        "doc/policy/packages.md for documentation on package policies.\n"
        "Warning: successful submission does not mean the transactions will "
        "propagate throughout the network.\n",
        {
            {
                "package",
                RPCArg::Type::ARR,
                RPCArg::Optional::NO,
                "An array of raw transactions.",
                {
                    {"rawtx", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                     ""},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::STR, "package_msg",
                 "The transaction package result message. \"success\" "
                 "indicates all transactions were accepted into or are already "
                 "in the mempool."},
                {RPCResult::Type::OBJ_DYN,
                 "tx-results",
                 "transaction results keyed by txid",
                 {{RPCResult::Type::OBJ,
                   "txid",
                   "transaction txid",
                   {
                       {RPCResult::Type::NUM, "vsize", /*optional=*/true,
                        "Virtual transaction size."},
                       {RPCResult::Type::OBJ,
                        "fees",
                        /*optional=*/true,
                        "Transaction fees",
                        {
                            {RPCResult::Type::STR_AMOUNT, "base",
                             "transaction fee in " + ticker},
                            {RPCResult::Type::STR_AMOUNT, "effective-feerate",
                             "the effective feerate in " + ticker +
                                 " per KvB. May differ from the base feerate "
                                 "if, for example, there are modified fees "
                                 "from prioritisetransaction or a package "
                                 "feerate was used."},
                            {RPCResult::Type::ARR,
                             "effective-includes",
                             "transactions whose fees and vsizes are included "
                             "in effective-feerate.",
                             {
                                 RPCResult{RPCResult::Type::STR_HEX, "",
                                           "transaction txid in hex"},
                             }},
                        }},
                       {RPCResult::Type::STR, "error", /*optional=*/true,
                        "The transaction error string, if it was rejected by "
                        "the mempool"},
                   }}}},
            },
        },
        RPCExamples{HelpExampleCli("testmempoolaccept", "[rawtx1, rawtx2]") +
                    HelpExampleCli("submitpackage", "[rawtx1, rawtx2]")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const UniValue &raw_transactions = request.params[0].get_array();
            if (raw_transactions.size() < 1 ||
                raw_transactions.size() > MAX_PACKAGE_COUNT) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Array must contain between 1 and " +
                                       ToString(MAX_PACKAGE_COUNT) +
                                       " transactions.");
            }

            std::vector<CTransactionRef> txns;
            txns.reserve(raw_transactions.size());
            for (const auto &rawtx : raw_transactions.getValues()) {
                CMutableTransaction mtx;
                if (!DecodeHexTx(mtx, rawtx.get_str())) {
                    throw JSONRPCError(
                        RPC_DESERIALIZATION_ERROR,
                        "TX decode failed: " + rawtx.get_str() +
                            " Make sure the tx has at least one input.");
                }
                txns.emplace_back(MakeTransactionRef(std::move(mtx)));
            }
            if (!IsChildWithParentsTree(txns)) {
                throw JSONRPCTransactionError(
                    TransactionError::INVALID_PACKAGE,
                    "package topology disallowed. not child-with-parents or "
                    "parents depend on each other.");
            }

            NodeContext &node = EnsureAnyNodeContext(request.context);
            CTxMemPool &mempool = EnsureMemPool(node);
            Chainstate &chainstate = EnsureChainman(node).ActiveChainstate();
            const auto package_result = WITH_LOCK(
                ::cs_main, return ProcessNewPackage(chainstate, mempool, txns,
                                                    /*test_accept=*/false));

            std::string package_msg = "success";

            // First catch package-wide errors, continue if we can
            switch (package_result.m_state.GetResult()) {
                case PackageValidationResult::PCKG_RESULT_UNSET: {
                    // Belt-and-suspenders check; everything should be
                    // successful here
                    CHECK_NONFATAL(package_result.m_tx_results.size() ==
                                   txns.size());
                    for (const auto &tx : txns) {
                        CHECK_NONFATAL(mempool.exists(tx->GetId()));
                    }
                    break;
                }
                case PackageValidationResult::PCKG_MEMPOOL_ERROR: {
                    // This only happens with internal bug; user should stop and
                    // report
                    throw JSONRPCTransactionError(
                        TransactionError::MEMPOOL_ERROR,
                        package_result.m_state.GetRejectReason());
                }
                case PackageValidationResult::PCKG_POLICY:
                case PackageValidationResult::PCKG_TX: {
                    // Package-wide error we want to return, but we also want to
                    // return individual responses
                    package_msg = package_result.m_state.GetRejectReason();
                    CHECK_NONFATAL(package_result.m_tx_results.size() ==
                                       txns.size() ||
                                   package_result.m_tx_results.empty());
                    break;
                }
            }
            size_t num_broadcast{0};
            for (const auto &tx : txns) {
                // We don't want to re-submit the txn for validation in
                // BroadcastTransaction
                if (!mempool.exists(tx->GetId())) {
                    continue;
                }

                // We do not expect an error here; we are only broadcasting
                // things already/still in mempool
                std::string err_string;
                const auto err = BroadcastTransaction(
                    node, tx, err_string, /*max_tx_fee=*/Amount::zero(),
                    /*relay=*/true, /*wait_callback=*/true);
                if (err != TransactionError::OK) {
                    throw JSONRPCTransactionError(
                        err,
                        strprintf("transaction broadcast failed: %s (%d "
                                  "transactions were broadcast successfully)",
                                  err_string, num_broadcast));
                }
                num_broadcast++;
            }

            UniValue rpc_result{UniValue::VOBJ};
            rpc_result.pushKV("package_msg", package_msg);
            UniValue tx_result_map{UniValue::VOBJ};
            for (const auto &tx : txns) {
                UniValue result_inner{UniValue::VOBJ};
                auto it = package_result.m_tx_results.find(tx->GetId());
                if (it == package_result.m_tx_results.end()) {
                    // No results, report error and continue
                    result_inner.pushKV("error", "unevaluated");
                    continue;
                }
                const auto &tx_result = it->second;
                switch (it->second.m_result_type) {
                    case MempoolAcceptResult::ResultType::INVALID:
                        result_inner.pushKV("error",
                                            it->second.m_state.ToString());
                        break;
                    case MempoolAcceptResult::ResultType::VALID:
                    case MempoolAcceptResult::ResultType::MEMPOOL_ENTRY:
                        result_inner.pushKV(
                            "vsize", int64_t{it->second.m_vsize.value()});
                        UniValue fees(UniValue::VOBJ);
                        fees.pushKV("base", it->second.m_base_fees.value());
                        if (tx_result.m_result_type ==
                            MempoolAcceptResult::ResultType::VALID) {
                            // Effective feerate is not provided for
                            // MEMPOOL_ENTRY (already in mempool) transactions
                            // even though modified fees is known, because it is
                            // unknown whether package feerate was used when it
                            // was originally submitted.
                            fees.pushKV("effective-feerate",
                                        tx_result.m_effective_feerate.value()
                                            .GetFeePerK());
                            UniValue effective_includes_res(UniValue::VARR);
                            for (const auto &txid :
                                 tx_result.m_txids_fee_calculations.value()) {
                                effective_includes_res.push_back(
                                    txid.ToString());
                            }
                            fees.pushKV("effective-includes",
                                        std::move(effective_includes_res));
                        }
                        result_inner.pushKV("fees", std::move(fees));
                        break;
                }
                tx_result_map.pushKV(tx->GetId().GetHex(),
                                     std::move(result_inner));
            }
            rpc_result.pushKV("tx-results", std::move(tx_result_map));

            return rpc_result;
        },
    };
}

static void DecodeRawTxBatchParallel(const UniValue &raw_transactions,
                                     std::vector<CTransactionRef> &txns,
                                     std::vector<std::string> &txid_hexes,
                                     UniValue *txids_arr,
                                     std::vector<PrecomputedBatchTxData>
                                         *precomputed_out = nullptr) {
    const auto &raw_vals = raw_transactions.getValues();
    const size_t n = raw_vals.size();
    for (const auto &rawtx : raw_vals) {
        (void)rawtx.get_str();
    }
    txns.resize(n);
    txid_hexes.resize(n);
    if (precomputed_out != nullptr) {
        precomputed_out->resize(n);
    }
    if (n < 32) {
        for (size_t i = 0; i < n; ++i) {
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, raw_vals[i].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                   "TX decode failed: " +
                                       raw_vals[i].get_str());
            }
            txns[i] = MakeTransactionRef(std::move(mtx));
            if (precomputed_out != nullptr) {
                PrecomputeSingleTxData(*txns[i], (*precomputed_out)[i]);
            }
            txid_hexes[i] = txns[i]->GetId().GetHex();
            if (txids_arr != nullptr) {
                txids_arr->push_back(txid_hexes[i]);
            }
        }
        return;
    }

    std::atomic<size_t> first_fail{n};
    lotus::v2::RunParallelSigningWork(
        n, /*min_grain=*/8, [&](size_t begin, size_t end) {
            for (size_t i = begin; i < end; ++i) {
                if (i >= first_fail.load(std::memory_order_relaxed)) {
                    break;
                }
                CMutableTransaction mtx;
                if (!DecodeHexTx(mtx, raw_vals[i].get_str())) {
                    size_t cur = first_fail.load(std::memory_order_relaxed);
                    while (i < cur &&
                           !first_fail.compare_exchange_weak(
                               cur, i, std::memory_order_relaxed)) {
                    }
                    break;
                }
                txns[i] = MakeTransactionRef(std::move(mtx));
                if (precomputed_out != nullptr) {
                    PrecomputeSingleTxData(*txns[i], (*precomputed_out)[i]);
                }
                txid_hexes[i] = txns[i]->GetId().GetHex();
            }
        });

    const size_t bad = first_fail.load(std::memory_order_relaxed);
    if (bad < n) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                           "TX decode failed: " + raw_vals[bad].get_str());
    }
    if (txids_arr != nullptr) {
        for (size_t i = 0; i < n; ++i) {
            txids_arr->push_back(txid_hexes[i]);
        }
    }
}

static RPCHelpMan testrawtxbatch() {
    const auto ticker = Currency::getTicker();
    return RPCHelpMan{
        "testrawtxbatch",
        "Test acceptance of a batch of raw transactions (serialized, "
        "hex-encoded) in dependency order under a single cs_main lock "
        "acquisition.\n"
        "Returns an all-or-nothing summary ('allowed') along with per-tx "
        "validation results.\n",
        {
            {
                "rawtxs",
                RPCArg::Type::ARR,
                RPCArg::Optional::NO,
                "An array of hex strings of raw transactions.",
                {
                    {"rawtx", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                     ""},
                },
            },
            {"maxfeerate", RPCArg::Type::AMOUNT,
             RPCArg::Default{
                 FormatMoney(DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK())},
             "Reject transactions whose fee rate is higher than the specified "
             "value, expressed in " +
                 ticker + "/kB\n"},
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::BOOL, "allowed",
                 "True if and only if every transaction in the batch is valid "
                 "and within maxfeerate"},
                {RPCResult::Type::STR, "package-error", /*optional=*/true,
                 "Package validation error, if any"},
                {RPCResult::Type::ARR,
                 "results",
                 "Per-transaction validation results in input order",
                 {
                     {RPCResult::Type::OBJ,
                      "",
                      "",
                      {
                          {RPCResult::Type::STR_HEX, "txid",
                           "The transaction id in hex"},
                          {RPCResult::Type::BOOL, "allowed", /*optional=*/true,
                           "Whether this transaction passed validation"},
                          {RPCResult::Type::NUM, "size", /*optional=*/true,
                           "Virtual transaction size"},
                          {RPCResult::Type::OBJ,
                           "fees",
                           /*optional=*/true,
                           "Transaction fees",
                           {
                               {RPCResult::Type::STR_AMOUNT, "base",
                                "transaction fee in " + ticker},
                               {RPCResult::Type::STR_AMOUNT,
                                "effective-feerate",
                                "effective feerate in " + ticker + " per KvB"},
                               {RPCResult::Type::ARR,
                                "effective-includes",
                                "txids included in effective-feerate",
                                {
                                    RPCResult{RPCResult::Type::STR_HEX, "",
                                              "transaction txid in hex"},
                                }},
                           }},
                          {RPCResult::Type::STR, "reject-reason",
                           /*optional=*/true, "Rejection reason string"},
                          {RPCResult::Type::STR, "reject-details",
                           /*optional=*/true, "Rejection details string"},
                          {RPCResult::Type::NUM, "required_cu",
                           /*optional=*/true,
                           "Required transaction compute units (CU)"},
                          {RPCResult::Type::NUM, "required_fee_sats",
                           /*optional=*/true,
                           "Minimum required RPC admission fee in satoshis"},
                          {RPCResult::Type::NUM, "recommended_sdk_fee_sats",
                           /*optional=*/true,
                           "Recommended SDK fee in satoshis (includes +5% "
                           "anti-bounce cushion)"},
                      }},
                 }},
            },
        },
        RPCExamples{HelpExampleCli("testrawtxbatch", R"('["signedhex"]')") +
                    HelpExampleRpc("testrawtxbatch", "[\"signedhex\"]")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const UniValue &raw_transactions = request.params[0].get_array();
            if (raw_transactions.size() < 1 ||
                raw_transactions.size() > MAX_RAWTX_BATCH_COUNT) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Array must contain between 1 and " +
                                       ToString(MAX_RAWTX_BATCH_COUNT) +
                                       " transactions.");
            }

            const CFeeRate max_raw_tx_fee_rate =
                request.params[1].isNull()
                    ? DEFAULT_MAX_RAW_TX_FEE_RATE
                    : CFeeRate(AmountFromValue(request.params[1]));

            std::vector<CTransactionRef> txns;
            std::vector<std::string> txid_hexes;
            std::vector<PrecomputedBatchTxData> precomputed_batch;
            DecodeRawTxBatchParallel(raw_transactions, txns, txid_hexes,
                                     nullptr, &precomputed_batch);

            NodeContext &node = EnsureAnyNodeContext(request.context);
            CTxMemPool &mempool = EnsureMemPool(node);
            ChainstateManager &chainman = EnsureChainman(node);
            Chainstate &chainstate = chainman.ActiveChainstate();

            const PackageMempoolAcceptResult package_result = [&] {
                LOCK(::cs_main);
                return ProcessRawTxBatch(chainstate, mempool, txns,
                                         /*test_accept=*/true,
                                         max_raw_tx_fee_rate,
                                         &precomputed_batch);
            }();

            UniValue results_arr(UniValue::VARR);
            bool all_allowed =
                package_result.m_state.GetResult() !=
                PackageValidationResult::PCKG_POLICY;
            bool exit_early{false};
            const int64_t now_ms =
                TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
            const auto &fee_ctrl = lotus::v2::GetGlobalFeeHysteresisController();
            const lotus::v2::FeeRateInfo fee_info =
                fee_ctrl.GetFeeRateInfo(now_ms);
            results_arr.reserve(txns.size());

            for (size_t idx = 0; idx < txns.size(); ++idx) {
                const auto &tx = txns[idx];
                const std::string &txid_hex = txid_hexes[idx];
                UniValue result_inner(UniValue::VOBJ);
                result_inner.pushKV("txid", txid_hex);
                if (IsDisallowedNonV7Tx(*tx, node)) {
                    all_allowed = false;
                    result_inner.pushKV("allowed", false);
                    result_inner.pushKV("reject-reason",
                                        "bad-txns-non-v7-format");
                    result_inner.pushKV(
                        "reject-details",
                        "bad-txns-non-v7-format, transaction must use Lotus V2 "
                        "version 7 format");
                    results_arr.push_back(std::move(result_inner));
                    continue;
                }
                auto it = package_result.m_tx_results.find(tx->GetId());
                if (exit_early || it == package_result.m_tx_results.end()) {
                    all_allowed = false;
                    results_arr.push_back(std::move(result_inner));
                    continue;
                }
                const auto &tx_result = it->second;
                const uint64_t tx_cu = static_cast<uint64_t>(std::max<int64_t>(
                    0, tx_result.m_vsize.has_value()
                           ? tx_result.m_vsize.value()
                           : GetVirtualTransactionSize(*tx)));
                const uint64_t paid_fee_sats =
                    tx_result.m_base_fees.has_value()
                        ? static_cast<uint64_t>(std::max<int64_t>(
                              0, tx_result.m_base_fees.value() / SATOSHI))
                        : 0ULL;
                const uint64_t required_fee_sats =
                    lotus::v2::FeeHysteresisController::ComputeFeeForCu(
                        tx_cu, fee_info.rpc_admission_feerate_per_kcu);
                const uint64_t recommended_sdk_fee_sats = std::max(
                    required_fee_sats,
                    lotus::v2::FeeHysteresisController::ComputeFeeForCu(
                        tx_cu, fee_info.recommended_sdk_feerate_per_kcu));
                const lotus::v2::FeeCheckResult fee_eval{
                    .accepted = paid_fee_sats >= required_fee_sats,
                    .tier = lotus::v2::FeeTier::RpcAdmission,
                    .tx_cu = tx_cu,
                    .paid_fee_sats = paid_fee_sats,
                    .required_fee_sats = required_fee_sats,
                    .required_rate_per_kcu =
                        fee_info.rpc_admission_feerate_per_kcu,
                    .recommended_sdk_fee_sats = recommended_sdk_fee_sats,
                };
                result_inner.pushKV("required_cu", fee_eval.tx_cu);
                result_inner.pushKV("required_fee_sats",
                                    fee_eval.required_fee_sats);
                result_inner.pushKV("recommended_sdk_fee_sats",
                                    fee_eval.recommended_sdk_fee_sats);

                if (tx_result.m_result_type ==
                        MempoolAcceptResult::ResultType::VALID &&
                    (fee_eval.accepted ||
                     fee_ctrl.GetRpcAdmissionRatePerKCu(now_ms) <=
                         fee_ctrl.GetConsensusFloorPerKCu())) {
                    const Amount fee = tx_result.m_base_fees.value();
                    const int64_t virtual_size = tx_result.m_vsize.value();
                    result_inner.pushKV("allowed", true);
                    result_inner.pushKV("size", virtual_size);
                    UniValue fees(UniValue::VOBJ);
                    fees.pushKV("base", fee);
                    fees.pushKV(
                        "effective-feerate",
                        tx_result.m_effective_feerate.value().GetFeePerK());
                    UniValue effective_includes_res(UniValue::VARR);
                    const auto &inc =
                        tx_result.m_txids_fee_calculations.value();
                    if (inc.size() == 1 && inc[0] == tx->GetId()) {
                        effective_includes_res.push_back(txid_hex);
                    } else {
                        for (const auto &txid : inc) {
                            effective_includes_res.push_back(txid.ToString());
                        }
                    }
                    fees.pushKV("effective-includes",
                                std::move(effective_includes_res));
                    result_inner.pushKV("fees", std::move(fees));
                } else if (tx_result.m_result_type ==
                               MempoolAcceptResult::ResultType::VALID &&
                           !fee_eval.accepted) {
                    all_allowed = false;
                    result_inner.pushKV("allowed", false);
                    result_inner.pushKV("reject-reason",
                                        "rpc-fee-hysteresis-insufficient");
                    result_inner.pushKV(
                        "reject-details",
                        strprintf("paid %llu sats < required %llu sats "
                                  "(recommended SDK fee: %llu sats)",
                                  static_cast<unsigned long long>(paid_fee_sats),
                                  static_cast<unsigned long long>(
                                      fee_eval.required_fee_sats),
                                  static_cast<unsigned long long>(
                                      fee_eval.recommended_sdk_fee_sats)));
                } else {
                    all_allowed = false;
                    result_inner.pushKV("allowed", false);
                    const TxValidationState state = tx_result.m_state;
                    if (state.GetResult() ==
                        TxValidationResult::TX_MISSING_INPUTS) {
                        result_inner.pushKV("reject-reason", "missing-inputs");
                    } else if (state.GetRejectReason() == "max-fee-exceeded") {
                        result_inner.pushKV("reject-reason",
                                            "max-fee-exceeded");
                        exit_early = true;
                    } else {
                        result_inner.pushKV("reject-reason",
                                            state.GetRejectReason());
                        result_inner.pushKV("reject-details", state.ToString());
                    }
                }
                results_arr.push_back(std::move(result_inner));
            }

            UniValue ret(UniValue::VOBJ);
            ret.pushKV("allowed", all_allowed);
            if (package_result.m_state.GetResult() ==
                PackageValidationResult::PCKG_POLICY) {
                ret.pushKV("package-error",
                           package_result.m_state.GetRejectReason());
            }
            ret.pushKV("results", std::move(results_arr));
            return ret;
        },
    };
}

static RPCHelpMan submitrawtxbatch() {
    const auto ticker = Currency::getTicker();
    return RPCHelpMan{
        "submitrawtxbatch",
        "Submit a batch of raw transactions (serialized, hex-encoded) in "
        "dependency order with two-phase all-or-nothing semantics.\n"
        "Phase 1 validates the entire batch under cs_main without mutating the "
        "mempool. If any transaction fails validation or exceeds maxfeerate, "
        "no transactions in the batch are accepted.\n"
        "Phase 2 commits all validated transactions to the mempool under the "
        "same cs_main lock acquisition, refreshes the RCU snapshot, and "
        "broadcasts them.\n"
        "\nThe node announces transactions it originated to all of its "
        "peers at the next relay tick, without delay, so peers can tell "
        "which node they came from. For privacy, submit each transaction to "
        "several independent nodes rather than to one.\n",
        {
            {
                "rawtxs",
                RPCArg::Type::ARR,
                RPCArg::Optional::NO,
                "An array of hex strings of raw transactions.",
                {
                    {"rawtx", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED,
                     ""},
                },
            },
            {"maxfeerate", RPCArg::Type::AMOUNT,
             RPCArg::Default{
                 FormatMoney(DEFAULT_MAX_RAW_TX_FEE_RATE.GetFeePerK())},
             "Reject transactions whose fee rate is higher than the specified "
             "value, expressed in " +
                 ticker +
                 "/kB\nSet to 0 to accept any fee rate.\n"},
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::BOOL, "accepted",
                 "True if all transactions in the batch were accepted into the "
                 "mempool"},
                {RPCResult::Type::STR, "package-error", /*optional=*/true,
                 "Package validation error, if any"},
                {RPCResult::Type::ARR,
                 "txids",
                 "Transaction IDs in input order",
                 {
                     RPCResult{RPCResult::Type::STR_HEX, "",
                               "The transaction id in hex"},
                 }},
                {RPCResult::Type::ARR,
                 "results",
                 "Per-transaction validation results in input order",
                 {
                     {RPCResult::Type::OBJ,
                      "",
                      "",
                      {
                          {RPCResult::Type::STR_HEX, "txid",
                           "The transaction id in hex"},
                          {RPCResult::Type::BOOL, "allowed", /*optional=*/true,
                           "Whether this transaction passed validation"},
                          {RPCResult::Type::NUM, "size", /*optional=*/true,
                           "Virtual transaction size"},
                          {RPCResult::Type::OBJ,
                           "fees",
                           /*optional=*/true,
                           "Transaction fees",
                           {
                               {RPCResult::Type::STR_AMOUNT, "base",
                                "transaction fee in " + ticker},
                               {RPCResult::Type::STR_AMOUNT,
                                "effective-feerate",
                                "effective feerate in " + ticker + " per KvB"},
                               {RPCResult::Type::ARR,
                                "effective-includes",
                                "txids included in effective-feerate",
                                {
                                    RPCResult{RPCResult::Type::STR_HEX, "",
                                              "transaction txid in hex"},
                                }},
                           }},
                          {RPCResult::Type::STR, "reject-reason",
                           /*optional=*/true, "Rejection reason string"},
                          {RPCResult::Type::STR, "reject-details",
                           /*optional=*/true, "Rejection details string"},
                          {RPCResult::Type::NUM, "required_cu",
                           /*optional=*/true,
                           "Required transaction compute units (CU)"},
                          {RPCResult::Type::NUM, "required_fee_sats",
                           /*optional=*/true,
                           "Minimum required RPC admission fee in satoshis"},
                          {RPCResult::Type::NUM, "recommended_sdk_fee_sats",
                           /*optional=*/true,
                           "Recommended SDK fee in satoshis (includes +5% "
                           "anti-bounce cushion)"},
                      }},
                 }},
            },
        },
        RPCExamples{HelpExampleCli("submitrawtxbatch", R"('["signedhex"]')") +
                    HelpExampleRpc("submitrawtxbatch", "[\"signedhex\"]")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const UniValue &raw_transactions = request.params[0].get_array();
            if (raw_transactions.size() < 1 ||
                raw_transactions.size() > MAX_RAWTX_BATCH_COUNT) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Array must contain between 1 and " +
                                       ToString(MAX_RAWTX_BATCH_COUNT) +
                                       " transactions.");
            }

            const CFeeRate max_raw_tx_fee_rate =
                request.params[1].isNull()
                    ? DEFAULT_MAX_RAW_TX_FEE_RATE
                    : CFeeRate(AmountFromValue(request.params[1]));

            std::vector<CTransactionRef> txns;
            std::vector<std::string> txid_hexes;
            UniValue txids_arr(UniValue::VARR);
            std::vector<PrecomputedBatchTxData> precomputed_batch;
            DecodeRawTxBatchParallel(raw_transactions, txns, txid_hexes,
                                     &txids_arr, &precomputed_batch);

            AssertLockNotHeld(cs_main);
            NodeContext &node = EnsureAnyNodeContext(request.context);
            CTxMemPool &mempool = EnsureMemPool(node);
            ChainstateManager &chainman = EnsureChainman(node);

            const bool has_disallowed_non_v7 = std::any_of(
                txns.begin(), txns.end(), [&](const CTransactionRef &tx) {
                    return IsDisallowedNonV7Tx(*tx, node);
                });

            UniValue results_arr(UniValue::VARR);
            bool all_allowed = false;
            std::string package_error_str;
            const int64_t now_ms =
                TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
            const auto &fee_ctrl = lotus::v2::GetGlobalFeeHysteresisController();
            const lotus::v2::FeeRateInfo fee_info =
                fee_ctrl.GetFeeRateInfo(now_ms);
            results_arr.reserve(txns.size());

            const PackageMempoolAcceptResult package_result = [&] {
                LOCK2(::cs_main, mempool.cs);
                Chainstate &chainstate = chainman.ActiveChainstate();
                CTxMemPool::ScopedSnapshotDefer snap_defer(mempool);
                // [Patch 036 optimization] Single-pass two-phase batch
                // validation and commit under cs_main + ScopedSnapshotDefer:
                // Phase 1 runs PreChecks + maxfeerate across all workspaces
                // without mutating the mempool; Phase 2 commits the prechecked
                // workspaces directly via SubmitPackage and publishes a single
                // RCU snapshot when snap_defer exits.
                PackageMempoolAcceptResult res =
                    ProcessRawTxBatch(chainstate, mempool, txns,
                                      /*test_accept=*/has_disallowed_non_v7,
                                      max_raw_tx_fee_rate,
                                      &precomputed_batch);

                if (!has_disallowed_non_v7 && res.m_state.IsValid() &&
                    res.m_tx_results.size() == txns.size()) {
                    for (const auto &tx : txns) {
                        mempool.AddUnbroadcastTx(tx->GetId());
                    }
                    const auto cur_snap =
                        node::GetGlobalSnapshotPublisher().Load();
                    if (!cur_snap || !cur_snap->chain_valid ||
                        cur_snap->chainman_ptr != &chainman) {
                        node::PublishChainTipSnapshot(chainman, &mempool);
                    }
                }
                return res;
            }();

            if (package_result.m_state.GetResult() ==
                PackageValidationResult::PCKG_POLICY) {
                package_error_str = package_result.m_state.GetRejectReason();
            }

            all_allowed =
                !has_disallowed_non_v7 && package_result.m_state.IsValid();
            bool exit_early{false};

            for (size_t idx = 0; idx < txns.size(); ++idx) {
                const auto &tx = txns[idx];
                const std::string &txid_hex = txid_hexes[idx];
                UniValue result_inner(UniValue::VOBJ);
                result_inner.pushKV("txid", txid_hex);
                if (IsDisallowedNonV7Tx(*tx, node)) {
                    all_allowed = false;
                    result_inner.pushKV("allowed", false);
                    result_inner.pushKV("reject-reason",
                                        "bad-txns-non-v7-format");
                    result_inner.pushKV(
                        "reject-details",
                        "bad-txns-non-v7-format, transaction must use Lotus V2 "
                        "version 7 format");
                    results_arr.push_back(std::move(result_inner));
                    continue;
                }
                auto it = package_result.m_tx_results.find(tx->GetId());
                if (exit_early || it == package_result.m_tx_results.end()) {
                    all_allowed = false;
                    results_arr.push_back(std::move(result_inner));
                    continue;
                }
                const auto &tx_result = it->second;
                const uint64_t tx_cu =
                    static_cast<uint64_t>(std::max<int64_t>(
                        0, tx_result.m_vsize.has_value()
                               ? tx_result.m_vsize.value()
                               : GetVirtualTransactionSize(*tx)));
                const uint64_t paid_fee_sats =
                    tx_result.m_base_fees.has_value()
                        ? static_cast<uint64_t>(std::max<int64_t>(
                              0, tx_result.m_base_fees.value() / SATOSHI))
                        : 0ULL;
                const uint64_t required_fee_sats =
                    lotus::v2::FeeHysteresisController::ComputeFeeForCu(
                        tx_cu, fee_info.rpc_admission_feerate_per_kcu);
                const uint64_t recommended_sdk_fee_sats = std::max(
                    required_fee_sats,
                    lotus::v2::FeeHysteresisController::ComputeFeeForCu(
                        tx_cu, fee_info.recommended_sdk_feerate_per_kcu));
                const lotus::v2::FeeCheckResult fee_eval{
                    .accepted = paid_fee_sats >= required_fee_sats,
                    .tier = lotus::v2::FeeTier::RpcAdmission,
                    .tx_cu = tx_cu,
                    .paid_fee_sats = paid_fee_sats,
                    .required_fee_sats = required_fee_sats,
                    .required_rate_per_kcu =
                        fee_info.rpc_admission_feerate_per_kcu,
                    .recommended_sdk_fee_sats = recommended_sdk_fee_sats,
                };
                result_inner.pushKV("required_cu", fee_eval.tx_cu);
                result_inner.pushKV("required_fee_sats",
                                    fee_eval.required_fee_sats);
                result_inner.pushKV("recommended_sdk_fee_sats",
                                    fee_eval.recommended_sdk_fee_sats);

                if (tx_result.m_result_type ==
                    MempoolAcceptResult::ResultType::VALID) {
                    const Amount fee = tx_result.m_base_fees.value();
                    const int64_t virtual_size = tx_result.m_vsize.value();
                    result_inner.pushKV("allowed", true);
                    result_inner.pushKV("size", virtual_size);
                    UniValue fees(UniValue::VOBJ);
                    fees.pushKV("base", fee);
                    fees.pushKV(
                        "effective-feerate",
                        tx_result.m_effective_feerate.value().GetFeePerK());
                    UniValue effective_includes_res(UniValue::VARR);
                    const auto &inc =
                        tx_result.m_txids_fee_calculations.value();
                    if (inc.size() == 1 && inc[0] == tx->GetId()) {
                        effective_includes_res.push_back(txid_hex);
                    } else {
                        for (const auto &txid : inc) {
                            effective_includes_res.push_back(txid.ToString());
                        }
                    }
                    fees.pushKV("effective-includes",
                                std::move(effective_includes_res));
                    result_inner.pushKV("fees", std::move(fees));
                } else {
                    all_allowed = false;
                    result_inner.pushKV("allowed", false);
                    const TxValidationState state = tx_result.m_state;
                    if (state.GetResult() ==
                        TxValidationResult::TX_MISSING_INPUTS) {
                        result_inner.pushKV("reject-reason", "missing-inputs");
                    } else if (state.GetRejectReason() == "max-fee-exceeded") {
                        result_inner.pushKV("reject-reason",
                                            "max-fee-exceeded");
                        exit_early = true;
                    } else {
                        result_inner.pushKV("reject-reason",
                                            state.GetRejectReason());
                        result_inner.pushKV("reject-details", state.ToString());
                    }
                }
                results_arr.push_back(std::move(result_inner));
            }

            if (all_allowed) {
                if (node.validation_signals && txns.size() <= 64) {
                    node.validation_signals->SyncWithValidationInterfaceQueue();
                }
                // Locally originated batches use the ordinary first-hop
                // trickle; SendMessages may still coalesce the eventual relay.
                if (node.peerman) {
                    node.peerman->RelayTransactionBatch(txns);
                }
            }

            UniValue ret(UniValue::VOBJ);
            ret.pushKV("accepted", all_allowed);
            if (!package_error_str.empty()) {
                ret.pushKV("package-error", package_error_str);
            }
            ret.pushKV("txids", std::move(txids_arr));
            ret.pushKV("results", std::move(results_arr));
            return ret;
        },
    };
}

static RPCHelpMan getfeerateinfo() {
    return RPCHelpMan{
        "getfeerateinfo",
        "Returns the active Lotus V2 three-tier fee hysteresis schedule "
        "(consensus floor, P2P relay hysteresis rate, RPC admission rate, and "
        "recommended SDK fee rate with anti-bounce cushion).\n",
        {},
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::NUM, "consensus_floor_per_kcu",
                 "Tier 3 consensus floor fee rate in satoshis per 1,000 CU"},
                {RPCResult::Type::NUM, "p2p_relay_feerate_per_kcu",
                 "Tier 2 P2P relay and orphan admission fee rate in satoshis "
                 "per 1,000 CU"},
                {RPCResult::Type::NUM, "rpc_admission_feerate_per_kcu",
                 "Tier 1 local RPC admission fee rate in satoshis per 1,000 "
                 "CU"},
                {RPCResult::Type::NUM, "recommended_sdk_feerate_per_kcu",
                 "Recommended wallet/SDK fee rate in satoshis per 1,000 CU "
                 "(+5% anti-bounce cushion above Tier 1)"},
                {RPCResult::Type::NUM, "marginal_burn_feerate_per_kcu",
                 "Marginal P05 burn fee rate in satoshis per 1,000 CU"},
                {RPCResult::Type::NUM, "hysteresis_window_ms",
                 "Rolling P2P relay hysteresis window in milliseconds"},
                {RPCResult::Type::NUM, "hysteresis_discount_permille",
                 "Hysteresis discount below rolling minimum RPC rate in "
                 "permille"},
                {RPCResult::Type::BOOL, "adaptive_history_available",
                 "Whether complete ancestor block sizes are available for deterministic adaptive capacity"},
                {RPCResult::Type::NUM, "ema_block_size_bytes",
                 "Exponential moving average of connected block size in bytes"},
                {RPCResult::Type::NUM, "adaptive_target_block_size",
                 "Target block size before fee pressure rises"},
                {RPCResult::Type::NUM, "adaptive_max_block_size",
                 "Adaptive maximum excessive block size in bytes"},
                {RPCResult::Type::NUM, "adaptive_max_generated_block_size",
                 "Adaptive maximum miner generated block size in bytes"},
                {RPCResult::Type::NUM, "mempool_backlog_bytes",
                 "Current mempool backlog in bytes"},
            }},
        RPCExamples{HelpExampleCli("getfeerateinfo", "") +
                    HelpExampleRpc("getfeerateinfo", "")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const int64_t now_ms =
                TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
            const lotus::v2::FeeRateInfo info =
                lotus::v2::GetGlobalFeeHysteresisController().GetFeeRateInfo(
                    now_ms);
            UniValue ret(UniValue::VOBJ);
            ret.pushKV("consensus_floor_per_kcu",
                       info.consensus_floor_per_kcu);
            ret.pushKV("p2p_relay_feerate_per_kcu",
                       info.p2p_relay_feerate_per_kcu);
            ret.pushKV("rpc_admission_feerate_per_kcu",
                       info.rpc_admission_feerate_per_kcu);
            ret.pushKV("recommended_sdk_feerate_per_kcu",
                       info.recommended_sdk_feerate_per_kcu);
            ret.pushKV("marginal_burn_feerate_per_kcu",
                       info.marginal_burn_feerate_per_kcu);
            ret.pushKV("hysteresis_window_ms", info.hysteresis_window_ms);
            ret.pushKV("hysteresis_discount_permille",
                       info.hysteresis_discount_permille);
            ret.pushKV("adaptive_history_available", info.adaptive_history_available);
            ret.pushKV("ema_block_size_bytes", info.ema_block_size_bytes);
            ret.pushKV("adaptive_target_block_size",
                       info.adaptive_target_block_size);
            ret.pushKV("adaptive_max_block_size", info.adaptive_max_block_size);
            ret.pushKV("adaptive_max_generated_block_size",
                       info.adaptive_max_generated_block_size);
            ret.pushKV("mempool_backlog_bytes", info.mempool_backlog_bytes);
            return ret;
        },
    };
}

void RegisterMempoolRPCCommands(CRPCTable &t) {
    static const CRPCCommand commands[]{
        // category     actor (function)
        // --------     ----------------
        {"rawtransactions", sendrawtransaction},
        {"rawtransactions", testmempoolaccept},
        {"rawtransactions", testrawtxbatch},
        {"rawtransactions", submitrawtxbatch},
        {"blockchain", getfeerateinfo},
        {"blockchain", getmempoolancestors},
        {"blockchain", getmempooldescendants},
        {"blockchain", getmempoolentry},
        {"blockchain", getmempoolinfo},
        {"blockchain", getrawmempool},
        {"blockchain", importmempool},
        {"blockchain", savemempool},
        {"rawtransactions", submitpackage},
    };
    for (const auto &c : commands) {
        t.appendCommand(c.name, &c);
    }
}
