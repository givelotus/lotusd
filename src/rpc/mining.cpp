// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <avalanche/processor.h>
#include <blockvalidity.h>
#include <cashaddrenc.h>
#include <chain.h>
#include <chainparams.h>
#include <clientversion.h>
#include <common/args.h>
#include <common/system.h>
#include <config.h>
#include <consensus/activation.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <key_io.h>
#include <lotus_v2/fee_hysteresis.h>
#include <lotus_v2/mempool_overlay.h>
#include <node/snapshot.h>
#include <minerfund.h>
#include <net.h>
#include <node/context.h>
#include <node/miner.h>
#include <policy/block/rtt.h>
#include <policy/block/stakingrewards.h>
#include <policy/policy.h>
#include <pow/pow.h>
#include <rpc/blockchain.h>
#include <rpc/mining.h>
#include <rpc/async_waiter.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/standard.h>
#include <shutdown.h>
#include <streams.h>
#include <timedata.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <warnings.h>

#include <cstdint>
#include <cstring>

using node::BlockAssembler;
using node::CBlockTemplate;
using node::NodeContext;
using node::UpdateTime;
using util::ToString;

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is nonpositive. If 'height' is
 * nonnegative, compute the estimate at the time when a given block was found.
 */
static UniValue GetNetworkHashPS(int lookup, int height,
                                 const CChain &active_chain) {
    const CBlockIndex *pb = active_chain.Tip();

    if (height >= 0 && height < active_chain.Height()) {
        pb = active_chain[height];
    }

    if (pb == nullptr || !pb->nHeight) {
        return 0;
    }

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup <= 0) {
        lookup = pb->nHeight %
                     Params().GetConsensus().DifficultyAdjustmentInterval() +
                 1;
    }

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight) {
        lookup = pb->nHeight;
    }

    const CBlockIndex *pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a
    // divide by zero exception.
    if (minTime == maxTime) {
        return 0;
    }

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;

    return workDiff.getdouble() / timeDiff;
}

static RPCHelpMan getnetworkhashps() {
    return RPCHelpMan{
        "getnetworkhashps",
        "Returns the estimated network hashes per second based on the last n "
        "blocks.\n"
        "Pass in [blocks] to override # of blocks, -1 specifies since last "
        "difficulty change.\n"
        "Pass in [height] to estimate the network speed at the time when a "
        "certain block was found.\n",
        {
            {"nblocks", RPCArg::Type::NUM, RPCArg::Default{120},
             "The number of blocks, or -1 for blocks since last difficulty "
             "change."},
            {"height", RPCArg::Type::NUM, RPCArg::Default{-1},
             "To estimate at the time of the given height."},
        },
        RPCResult{RPCResult::Type::NUM, "", "Hashes per second estimated"},
        RPCExamples{HelpExampleCli("getnetworkhashps", "") +
                    HelpExampleRpc("getnetworkhashps", "")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            ChainstateManager &chainman = EnsureAnyChainman(request.context);
            LOCK(cs_main);
            return GetNetworkHashPS(self.Arg<int>("nblocks"),
                                    self.Arg<int>("height"),
                                    chainman.ActiveChain());
        },
    };
}

static bool GenerateBlock(ChainstateManager &chainman,
                          avalanche::Processor *const avalanche, CBlock &block,
                          uint64_t &max_tries, BlockHash &block_hash) {
    block_hash.SetNull();
    block.hashMerkleRoot = BlockMerkleRoot(block);

    const Consensus::Params &params = chainman.GetConsensus();

    while (max_tries > 0 &&
           block.nNonce < std::numeric_limits<uint32_t>::max() &&
           !CheckProofOfWork(block.GetHash(), block.nBits, params) &&
           !ShutdownRequested()) {
        ++block.nNonce;
        --max_tries;
    }
    if (max_tries == 0 || ShutdownRequested()) {
        return false;
    }
    if (block.nNonce == std::numeric_limits<uint32_t>::max()) {
        return true;
    }

    std::shared_ptr<const CBlock> shared_pblock =
        std::make_shared<const CBlock>(block);
    if (!chainman.ProcessNewBlock(shared_pblock,
                                  /*force_processing=*/true,
                                  /*min_pow_checked=*/true, nullptr,
                                  avalanche)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "ProcessNewBlock, block not accepted");
    }

    block_hash = block.GetHash();
    return true;
}

static UniValue generateBlocks(ChainstateManager &chainman,
                               const CTxMemPool &mempool,
                               avalanche::Processor *const avalanche,
                               const CScript &coinbase_script, int nGenerate,
                               uint64_t nMaxTries) {
    UniValue blockHashes(UniValue::VARR);
    while (nGenerate > 0 && !ShutdownRequested()) {
        std::unique_ptr<CBlockTemplate> pblocktemplate(
            BlockAssembler{chainman.GetConfig(), chainman.ActiveChainstate(),
                           &mempool, avalanche}
                .CreateNewBlock(coinbase_script));

        if (!pblocktemplate.get()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
        }

        CBlock *pblock = &pblocktemplate->block;

        BlockHash block_hash;
        if (!GenerateBlock(chainman, avalanche, *pblock, nMaxTries,
                           block_hash)) {
            break;
        }

        if (!block_hash.IsNull()) {
            --nGenerate;
            blockHashes.push_back(block_hash.GetHex());
        }
    }

    // Block to make sure wallet/indexers sync before returning
    CHECK_NONFATAL(chainman.m_options.signals)
        ->SyncWithValidationInterfaceQueue();

    return blockHashes;
}

static bool getScriptFromDescriptor(const std::string &descriptor,
                                    CScript &script, std::string &error) {
    FlatSigningProvider key_provider;
    const auto desc =
        Parse(descriptor, key_provider, error, /* require_checksum = */ false);
    if (desc) {
        if (desc->IsRange()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "Ranged descriptor not accepted. Maybe pass "
                               "through deriveaddresses first?");
        }

        FlatSigningProvider provider;
        std::vector<CScript> scripts;
        if (!desc->Expand(0, key_provider, scripts, provider)) {
            throw JSONRPCError(
                RPC_INVALID_ADDRESS_OR_KEY,
                strprintf("Cannot derive script without private keys"));
        }

        // Combo descriptors can have 2 scripts, so we can't just check
        // scripts.size() == 1
        CHECK_NONFATAL(scripts.size() > 0 && scripts.size() <= 2);

        if (scripts.size() == 1) {
            script = scripts.at(0);
        } else {
            // Else take the 2nd script, since it is p2pkh
            script = scripts.at(1);
        }

        return true;
    }

    return false;
}

static RPCHelpMan generatetodescriptor() {
    return RPCHelpMan{
        "generatetodescriptor",
        "Mine blocks immediately to a specified descriptor (before the RPC "
        "call returns)\n",
        {
            {"num_blocks", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "How many blocks are generated immediately."},
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The descriptor to send the newly generated bitcoin to."},
            {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES},
             "How many iterations to try."},
        },
        RPCResult{RPCResult::Type::ARR,
                  "",
                  "hashes of blocks generated",
                  {
                      {RPCResult::Type::STR_HEX, "", "blockhash"},
                  }},
        RPCExamples{"\nGenerate 11 blocks to mydesc\n" +
                    HelpExampleCli("generatetodescriptor", "11 \"mydesc\"")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const int num_blocks{self.Arg<int>("num_blocks")};
            const auto max_tries{self.Arg<uint64_t>("maxtries")};

            CScript coinbase_script;
            std::string error;
            if (!getScriptFromDescriptor(self.Arg<std::string>("descriptor"),
                                         coinbase_script, error)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
            }

            NodeContext &node = EnsureAnyNodeContext(request.context);
            const CTxMemPool &mempool = EnsureMemPool(node);
            ChainstateManager &chainman = EnsureChainman(node);

            return generateBlocks(chainman, mempool, node.avalanche.get(),
                                  coinbase_script, num_blocks, max_tries);
        },
    };
}

static RPCHelpMan generate() {
    return RPCHelpMan{"generate",
                      "has been replaced by the -generate cli option. Refer to "
                      "-help for more information.",
                      {},
                      {},
                      RPCExamples{""},
                      [&](const RPCHelpMan &self, const Config &config,
                          const JSONRPCRequest &request) -> UniValue {
                          throw JSONRPCError(RPC_METHOD_NOT_FOUND,
                                             self.ToString());
                      }};
}

static RPCHelpMan generatetoaddress() {
    return RPCHelpMan{
        "generatetoaddress",
        "Mine blocks immediately to a specified address before the "
        "RPC call returns)\n",
        {
            {"nblocks", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "How many blocks are generated immediately."},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The address to send the newly generated bitcoin to."},
            {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES},
             "How many iterations to try."},
        },
        RPCResult{RPCResult::Type::ARR,
                  "",
                  "hashes of blocks generated",
                  {
                      {RPCResult::Type::STR_HEX, "", "blockhash"},
                  }},
        RPCExamples{
            "\nGenerate 11 blocks to myaddress\n" +
            HelpExampleCli("generatetoaddress", "11 \"myaddress\"") +
            "If you are using the " PACKAGE_NAME " wallet, you can "
            "get a new address to send the newly generated bitcoin to with:\n" +
            HelpExampleCli("getnewaddress", "")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const int num_blocks{request.params[0].getInt<int>()};
            const uint64_t max_tries{request.params[2].isNull()
                                         ? DEFAULT_MAX_TRIES
                                         : request.params[2].getInt<int64_t>()};

            CTxDestination destination = DecodeDestination(
                request.params[1].get_str(), config.GetChainParams());
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   "Error: Invalid address");
            }

            NodeContext &node = EnsureAnyNodeContext(request.context);
            const CTxMemPool &mempool = EnsureMemPool(node);
            ChainstateManager &chainman = EnsureChainman(node);

            CScript coinbase_script = GetScriptForDestination(destination);

            return generateBlocks(chainman, mempool, node.avalanche.get(),
                                  coinbase_script, num_blocks, max_tries);
        },
    };
}

static RPCHelpMan generateblock() {
    return RPCHelpMan{
        "generateblock",
        "Mine a block with a set of ordered transactions immediately to a "
        "specified address or descriptor (before the RPC call returns)\n",
        {
            {"output", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The address or descriptor to send the newly generated bitcoin "
             "to."},
            {
                "transactions",
                RPCArg::Type::ARR,
                RPCArg::Optional::NO,
                "An array of hex strings which are either txids or raw "
                "transactions.\n"
                "Txids must reference transactions currently in the mempool.\n"
                "All transactions must be valid and in valid order, otherwise "
                "the block will be rejected.",
                {
                    {"rawtx/txid", RPCArg::Type::STR_HEX,
                     RPCArg::Optional::OMITTED, ""},
                },
            },
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::STR_HEX, "hash", "hash of generated block"},
            }},
        RPCExamples{
            "\nGenerate a block to myaddress, with txs rawtx and "
            "mempool_txid\n" +
            HelpExampleCli("generateblock",
                           R"("myaddress" '["rawtx", "mempool_txid"]')")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const auto address_or_descriptor = request.params[0].get_str();
            CScript coinbase_script;
            std::string error;

            const CChainParams &chainparams = config.GetChainParams();

            if (!getScriptFromDescriptor(address_or_descriptor, coinbase_script,
                                         error)) {
                const auto destination =
                    DecodeDestination(address_or_descriptor, chainparams);
                if (!IsValidDestination(destination)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                       "Error: Invalid address or descriptor");
                }

                coinbase_script = GetScriptForDestination(destination);
            }

            NodeContext &node = EnsureAnyNodeContext(request.context);
            const CTxMemPool &mempool = EnsureMemPool(node);

            std::vector<CTransactionRef> txs;
            const auto raw_txs_or_txids = request.params[1].get_array();
            for (size_t i = 0; i < raw_txs_or_txids.size(); i++) {
                const auto &str{raw_txs_or_txids[i].get_str()};

                CMutableTransaction mtx;
                if (auto txid{TxId::FromHex(str)}) {
                    const auto tx = mempool.get(*txid);
                    if (!tx) {
                        throw JSONRPCError(
                            RPC_INVALID_ADDRESS_OR_KEY,
                            strprintf("Transaction %s not in mempool.", str));
                    }

                    txs.emplace_back(tx);

                } else if (DecodeHexTx(mtx, str)) {
                    txs.push_back(MakeTransactionRef(std::move(mtx)));
                } else {
                    throw JSONRPCError(
                        RPC_DESERIALIZATION_ERROR,
                        strprintf("Transaction decode failed for %s", str));
                }
            }

            CBlock block;

            ChainstateManager &chainman = EnsureChainman(node);
            {
                LOCK(cs_main);

                std::unique_ptr<CBlockTemplate> blocktemplate(
                    BlockAssembler{config, chainman.ActiveChainstate(), nullptr,
                                   node.avalanche.get()}
                        .CreateNewBlock(coinbase_script));
                if (!blocktemplate) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                                       "Couldn't create new block");
                }
                block = blocktemplate->block;
            }

            CHECK_NONFATAL(block.vtx.size() == 1);

            // Add transactions
            block.vtx.insert(block.vtx.end(), txs.begin(), txs.end());

            {
                LOCK(cs_main);

                BlockValidationState state;
                if (!TestBlockValidity(state, chainparams,
                                       chainman.ActiveChainstate(), block,
                                       chainman.m_blockman.LookupBlockIndex(
                                           block.hashPrevBlock),
                                       GetAdjustedTime,
                                       BlockValidationOptions(config)
                                           .withCheckPoW(false)
                                           .withCheckMerkleRoot(false))) {
                    throw JSONRPCError(RPC_VERIFY_ERROR,
                                       strprintf("TestBlockValidity failed: %s",
                                                 state.ToString()));
                }
            }

            BlockHash block_hash;
            uint64_t max_tries{DEFAULT_MAX_TRIES};

            if (!GenerateBlock(chainman, node.avalanche.get(), block, max_tries,
                               block_hash) ||
                block_hash.IsNull()) {
                throw JSONRPCError(RPC_MISC_ERROR, "Failed to make block.");
            }

            // Block to make sure wallet/indexers sync before returning
            CHECK_NONFATAL(chainman.m_options.signals)
                ->SyncWithValidationInterfaceQueue();

            UniValue obj(UniValue::VOBJ);
            obj.pushKV("hash", block_hash.GetHex());
            return obj;
        },
    };
}

// Versioned, declarative inputs for compiled mining implementations. This is
// not executable code and does not authorize an RPC or relax block validation.
static UniValue MiningProofOfWork(const CChainParams &) {
    UniValue pow(UniValue::VOBJ);
    pow.pushKV("version", 1);
    pow.pushKV("algorithm", "sha256d");
    pow.pushKV("headerbytes", 80);
    pow.pushKV("nonceoffset", 76);
    pow.pushKV("noncebytes", 4);
    pow.pushKV("noncebyteorder", "little");
    pow.pushKV("hashbyteorder", "little");
    pow.pushKV("targetbyteorder", "big");
    pow.pushKV("template_rpc", "getrawunsolvedblock");
    pow.pushKV("submit_rpc", "submitblock");
    return pow;
}

static RPCHelpMan getchainconfig() {
    return RPCHelpMan{
        "getchainconfig",
        "Return one versioned chain, currency, address and mining capability "
        "snapshot.\n"
        "Clients must reject unknown schema versions or algorithm "
        "identifiers.\n"
        "Capabilities describe implementation support, not RPC "
        "authorization.\n",
        {},
        RPCResult{
            RPCResult::Type::ANY, "",
            "Schema version 1 configuration; see doc/mining/pow-descriptor.md"},
        RPCExamples{HelpExampleCli("getchainconfig", "") +
                    HelpExampleRpc("getchainconfig", "")},
        [&](const RPCHelpMan &, const Config &config,
            const JSONRPCRequest &) -> UniValue {
            const CChainParams &params = config.GetChainParams();
            const std::string kind = "ecash";
            const std::string network = params.GetChainTypeString();
            const std::string genesis =
                params.GenesisBlock().GetHash().GetHex();
            UniValue chain(UniValue::VOBJ);
            chain.pushKV("family", "bitcoin");
            chain.pushKV("kind", kind);
            chain.pushKV("network", network);
            chain.pushKV("identifier", kind + "-" + network + ":" + genesis);
            chain.pushKV("genesis", genesis);

            const UniValue denomination = CurrencyInfoToJSON();
            UniValue currency(UniValue::VOBJ);
            currency.pushKV("ticker", denomination["ticker"]);
            currency.pushKV("atomsperunit",
                            denomination["satoshisperunit"].getValStr());
            currency.pushKV("rpcdecimals", denomination["decimals"]);
            currency.pushKV("displaydecimals", 2);

            UniValue address(UniValue::VOBJ);
            address.pushKV("format", config.UseCashAddrEncoding()
                                         ? "cashaddr"
                                         : "base58check");
            address.pushKV("hrp", params.CashAddrPrefix());
            UniValue types(UniValue::VARR);
            types.push_back(int(PUBKEY_TYPE));
            types.push_back(int(SCRIPT_TYPE));
            address.pushKV("types", std::move(types));
            UniValue formats(UniValue::VARR);
            formats.push_back("cashaddr");
            formats.push_back("base58check");
            address.pushKV("acceptedformats", std::move(formats));
            UniValue prefixes(UniValue::VOBJ);
            prefixes.pushKV("pubkeyhash", HexStr(params.Base58Prefix(
                                              CChainParams::PUBKEY_ADDRESS)));
            prefixes.pushKV("scripthash", HexStr(params.Base58Prefix(
                                              CChainParams::SCRIPT_ADDRESS)));
            address.pushKV("base58prefixes", std::move(prefixes));

            UniValue mining(UniValue::VOBJ);
            mining.pushKV("pow", MiningProofOfWork(params));
            mining.pushKV("testgeneration", params.MineBlocksOnDemand());
            UniValue features(UniValue::VOBJ);
            features.pushKV("legacytransactions", true);
            features.pushKV("nativetransactions", false);
            features.pushKV("message_signing", "legacy-p2pkh");
            UniValue node(UniValue::VOBJ);
            node.pushKV("client", CLIENT_NAME);
            node.pushKV("version", CLIENT_VERSION);

            UniValue result(UniValue::VOBJ);
            result.pushKV("version", 1);
            result.pushKV("chain", std::move(chain));
            result.pushKV("currency", std::move(currency));
            result.pushKV("address", std::move(address));
            result.pushKV("mining", std::move(mining));
            result.pushKV("features", std::move(features));
            result.pushKV("node", std::move(node));
            return result;
        },
    };
}

static RPCHelpMan getmininginfo() {
    return RPCHelpMan{
        "getmininginfo",
        "Returns a json object containing mining-related "
        "information.",
        {},
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::NUM, "blocks", "The current block"},
                {RPCResult::Type::NUM, "currentblocksize", /* optional */ true,
                 "The block size of the last assembled block (only present if "
                 "a block was ever assembled)"},
                {RPCResult::Type::NUM, "currentblocktx", /* optional */ true,
                 "The number of block transactions of the last assembled block "
                 "(only present if a block was ever assembled)"},
                {RPCResult::Type::NUM, "difficulty", "The current difficulty"},
                {RPCResult::Type::NUM, "networkhashps",
                 "The network hashes per second"},
                {RPCResult::Type::NUM, "pooledtx", "The size of the mempool"},
                {RPCResult::Type::STR, "chain",
                 "current network name (main, test, regtest)"},
                {RPCResult::Type::OBJ,
                 "pow",
                 "Mining format (schema version 1)",
                 {
                     {RPCResult::Type::NUM, "version",
                      "Descriptor schema version"},
                     {RPCResult::Type::STR, "algorithm",
                      "Compiled proof-of-work algorithm identifier"},
                     {RPCResult::Type::NUM, "headerbytes",
                      "Serialized header size"},
                     {RPCResult::Type::NUM, "nonceoffset",
                      "Nonce byte offset in the header"},
                     {RPCResult::Type::NUM, "noncebytes", "Nonce byte width"},
                     {RPCResult::Type::STR, "noncebyteorder",
                      "Nonce integer byte order"},
                     {RPCResult::Type::STR, "hashbyteorder",
                      "Raw digest integer byte order for target comparison"},
                     {RPCResult::Type::STR, "targetbyteorder",
                      "getrawunsolvedblock target hex byte order"},
                     {RPCResult::Type::STR, "template_rpc",
                      "RPC returning a complete unsolved block"},
                     {RPCResult::Type::STR, "submit_rpc",
                      "RPC validating a complete solved block"},
                 }},
                {RPCResult::Type::STR, "warnings",
                 "any network and blockchain warnings"},
            }},
        RPCExamples{HelpExampleCli("getmininginfo", "") +
                    HelpExampleRpc("getmininginfo", "")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            NodeContext &node = EnsureAnyNodeContext(request.context);
            const CTxMemPool &mempool = EnsureMemPool(node);
            ChainstateManager &chainman = EnsureChainman(node);
            LOCK(cs_main);
            const CChain &active_chain = chainman.ActiveChain();

            UniValue obj(UniValue::VOBJ);
            obj.pushKV("blocks", active_chain.Height());
            if (BlockAssembler::m_last_block_size) {
                obj.pushKV("currentblocksize",
                           *BlockAssembler::m_last_block_size);
            }
            if (BlockAssembler::m_last_block_num_txs) {
                obj.pushKV("currentblocktx",
                           *BlockAssembler::m_last_block_num_txs);
            }
            obj.pushKV("difficulty",
                       GetDifficulty(*CHECK_NONFATAL(active_chain.Tip())));
            obj.pushKV("networkhashps",
                       getnetworkhashps().HandleRequest(config, request));
            obj.pushKV("pooledtx", uint64_t(mempool.size()));
            obj.pushKV("chain", config.GetChainParams().GetChainTypeString());
            obj.pushKV("pow", MiningProofOfWork(config.GetChainParams()));
            obj.pushKV("warnings", GetWarnings(false).original);
            return obj;
        },
    };
}

// NOTE: Unlike wallet RPC (which use XEC values), mining RPCs follow GBT (BIP
// 22) in using satoshi amounts
static RPCHelpMan prioritisetransaction() {
    return RPCHelpMan{
        "prioritisetransaction",
        "Accepts the transaction into mined blocks at a higher "
        "(or lower) priority\n",
        {
            {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The transaction id."},
            {"dummy", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
             "API-Compatibility for previous API. Must be zero or null.\n"
             "                  DEPRECATED. For forward compatibility "
             "use named arguments and omit this parameter."},
            {"fee_delta", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "The fee value (in satoshis) to add (or subtract, if negative).\n"
             "                        The fee is not actually paid, only the "
             "algorithm for selecting transactions into a block\n"
             "                  considers the transaction as it would "
             "have paid a higher (or lower) fee."},
        },
        RPCResult{RPCResult::Type::BOOL, "", "Returns true"},
        RPCExamples{
            HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000") +
            HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            LOCK(cs_main);

            TxId txid(ParseHashV(request.params[0], "txid"));
            const auto dummy{self.MaybeArg<double>(1)};
            Amount nAmount = request.params[2].getInt<int64_t>() * SATOSHI;

            if (dummy && *dummy != 0) {
                throw JSONRPCError(
                    RPC_INVALID_PARAMETER,
                    "Priority is no longer supported, dummy argument to "
                    "prioritisetransaction must be 0.");
            }

            EnsureAnyMemPool(request.context)
                .PrioritiseTransaction(txid, nAmount);
            return true;
        },
    };
}

// NOTE: Assumes a conclusive result; if result is inconclusive, it must be
// handled by caller
static UniValue BIP22ValidationResult(const Config &config,
                                      const BlockValidationState &state) {
    if (state.IsValid()) {
        return NullUniValue;
    }

    if (state.IsError()) {
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    }

    if (state.IsInvalid()) {
        std::string strRejectReason = state.GetRejectReason();
        if (strRejectReason.empty()) {
            return "rejected";
        }
        return strRejectReason;
    }

    // Should be impossible.
    return "valid?";
}

static std::optional<uint32_t> ComputeNextRTTWorkRequiredFromSnapshot(
    const node::ChainAndMempoolSnapshot &snap, int64_t now,
    const Consensus::Params &consensusParams) {
    if (now == 0 || snap.height < 16) {
        return std::nullopt;
    }
    for (size_t i = 1; i < 18; ++i) {
        if (snap.prev_header_received_time[i] == 0) {
            return std::nullopt;
        }
    }
    arith_uint256 prevTarget;
    if (!NBitsToTarget(consensusParams, snap.nBits, prevTarget)) {
        return std::nullopt;
    }
    static constexpr double kRttK{6.};
    static const double kFactor1 =
        kRttK * std::pow(std::tgamma(1. + 1. / kRttK), kRttK) /
        std::pow(30., kRttK - 1.);
    static const double kFactor2 =
        kRttK * std::pow(std::tgamma(1. + 1. / kRttK), kRttK) /
        std::pow(120., kRttK - 1.);
    static const double kFactor5 =
        kRttK * std::pow(std::tgamma(1. + 1. / kRttK), kRttK) /
        std::pow(480., kRttK - 1.);
    static const double kFactor11 =
        kRttK * std::pow(std::tgamma(1. + 1. / kRttK), kRttK) /
        std::pow(1200., kRttK - 1.);
    static const double kFactor17 =
        kRttK * std::pow(std::tgamma(1. + 1. / kRttK), kRttK) /
        std::pow(1920., kRttK - 1.);
    static const double kFactors[18] = {0.,       kFactor1, kFactor2, 0., 0.,
                                        kFactor5, 0.,       0.,       0., 0.,
                                        0.,       kFactor11, 0.,      0., 0.,
                                        0.,       0.,       kFactor17};

    const double prevTargetDouble = prevTarget.getdouble();
    const double powLimitDouble =
        UintToArith256(consensusParams.powLimit).getdouble();
    double minTarget = std::numeric_limits<double>::infinity();
    for (size_t i : {1, 2, 5, 11, 17}) {
        const int64_t diffTime =
            std::max<int64_t>(1, now - snap.prev_header_received_time[i]);
        const double target =
            prevTargetDouble * kFactors[i] * std::pow(double(diffTime), kRttK - 1.);
        minTarget = std::min(minTarget, target);
    }
    arith_uint256 nextTarget = arith_uint256::fromDouble(minTarget);
    if (minTarget < 1. || minTarget > powLimitDouble ||
        nextTarget > UintToArith256(consensusParams.powLimit)) {
        return std::nullopt;
    }
    return nextTarget.GetCompact();
}

static RPCHelpMan getblocktemplate() {
    return RPCHelpMan{
        "getblocktemplate",
        "If the request parameters include a 'mode' key, that is used to "
        "explicitly select between the default 'template' request or a "
        "'proposal'.\n"
        "It returns data needed to construct a block to work on.\n"
        "For full specification, see BIPs 22, 23, 9, and 145:\n"
        "    "
        "https://github.com/bitcoin/bips/blob/master/"
        "bip-0022.mediawiki\n"
        "    "
        "https://github.com/bitcoin/bips/blob/master/"
        "bip-0023.mediawiki\n"
        "    "
        "https://github.com/bitcoin/bips/blob/master/"
        "bip-0009.mediawiki#getblocktemplate_changes\n"
        "    ",
        {
            {"template_request",
             RPCArg::Type::OBJ,
             RPCArg::Default{UniValue::VOBJ},
             "Format of the template",
             {
                 {"mode", RPCArg::Type::STR, /* treat as named arg */
                  RPCArg::Optional::OMITTED,
                  "This must be set to \"template\", \"compact_template\", "
                  "\"proposal\" (see BIP 23), or omitted"},
                 {"mineraddress", RPCArg::Type::STR, /* treat as named arg */
                  RPCArg::Optional::OMITTED,
                  "Optional destination address for the coinbase miner payout "
                  "(overrides default OP_TRUE script in coinbasetxhex and "
                  "headerhex)"},
                 {
                     "capabilities",
                     RPCArg::Type::ARR,
                     /* treat as named arg */
                     RPCArg::Optional::OMITTED,
                     "A list of strings",
                     {
                         {"support", RPCArg::Type::STR,
                          RPCArg::Optional::OMITTED,
                          "client side supported feature, 'longpoll', "
                          "'coinbasetxn', 'coinbasevalue', 'proposal', "
                          "'serverlist', 'workid'"},
                     },
                 },
             },
             RPCArgOptions{.oneline_description = "\"template_request\""}},
        },
        {
            RPCResult{"If the proposal was accepted with mode=='proposal'",
                      RPCResult::Type::NONE, "", ""},
            RPCResult{"If the proposal was not accepted with mode=='proposal'",
                      RPCResult::Type::STR, "", "According to BIP22"},
            RPCResult{
                "Otherwise",
                RPCResult::Type::OBJ,
                "",
                "",
                {
                    {RPCResult::Type::NUM, "version",
                     "The preferred block version"},
                    {RPCResult::Type::STR, "previousblockhash",
                     "The hash of current highest block"},
                    {RPCResult::Type::ARR,
                     "transactions",
                     "contents of non-coinbase transactions that should be "
                     "included in the next block",
                     {
                         {RPCResult::Type::OBJ,
                          "",
                          "",
                          {
                              {RPCResult::Type::STR_HEX, "data",
                               "transaction data encoded in hexadecimal "
                               "(byte-for-byte)"},
                              {RPCResult::Type::STR_HEX, "txid",
                               "transaction id encoded in little-endian "
                               "hexadecimal"},
                              {RPCResult::Type::STR_HEX, "hash",
                               "hash encoded in little-endian hexadecimal"},
                              {RPCResult::Type::ARR,
                               "depends",
                               "array of numbers",
                               {
                                   {RPCResult::Type::NUM, "",
                                    "transactions before this one (by 1-based "
                                    "index in 'transactions' list) that must "
                                    "be present in the final block if this one "
                                    "is"},
                               }},
                              {RPCResult::Type::NUM, "fee",
                               "difference in value between transaction inputs "
                               "and outputs (in satoshis); for coinbase "
                               "transactions, this is a negative Number of the "
                               "total collected block fees (ie, not including "
                               "the block subsidy); "
                               "if key is not present, fee is unknown and "
                               "clients MUST NOT assume there isn't one"},
                              {RPCResult::Type::NUM, "sigchecks",
                               "total sigChecks, as counted for purposes of "
                               "block limits; if key is not present, sigChecks "
                               "are unknown and clients MUST NOT assume it is "
                               "zero"},
                          }},
                     }},
                    {RPCResult::Type::OBJ,
                     "coinbaseaux",
                     "data that should be included in the coinbase's scriptSig "
                     "content",
                     {
                         {RPCResult::Type::ELISION, "", ""},
                     }},
                    {RPCResult::Type::NUM, "coinbasevalue",
                     "maximum allowable input to coinbase transaction, "
                     "including the generation award and transaction fees (in "
                     "satoshis)"},
                    {RPCResult::Type::OBJ,
                     "coinbasetxn",
                     "information for coinbase transaction",
                     {
                         {RPCResult::Type::OBJ,
                          "minerfund",
                          "information related to the coinbase miner fund."
                          "This will NOT be set if -simplegbt is enabled",
                          {

                              {RPCResult::Type::ARR,
                               "addresses",
                               "List of valid addresses for the miner fund "
                               "output",
                               {
                                   {RPCResult::Type::ELISION, "", ""},
                               }},

                              {RPCResult::Type::STR_AMOUNT, "minimumvalue",
                               "The minimum value the miner fund output must "
                               "pay"},

                          }},
                         {RPCResult::Type::OBJ,
                          "stakingrewards",
                          "information related to the coinbase staking reward "
                          "output, only set if the -avalanchestakingrewards "
                          "option is enabled and if the node is able to "
                          "determine a winner. This will NOT be set if "
                          "-simplegbt is enabled",
                          {
                              {RPCResult::Type::OBJ,
                               "payoutscript",
                               "The proof payout script",
                               {
                                   {RPCResult::Type::STR, "asm",
                                    "Decoded payout script"},
                                   {RPCResult::Type::STR_HEX, "hex",
                                    "Raw payout script in hex format"},
                                   {RPCResult::Type::STR, "type",
                                    "The output type (e.g. " +
                                        GetAllOutputTypes() + ")"},
                                   {RPCResult::Type::NUM, "reqSigs",
                                    "The required signatures"},
                                   {RPCResult::Type::ARR,
                                    "addresses",
                                    "",
                                    {
                                        {RPCResult::Type::STR, "address",
                                         "eCash address"},
                                    }},
                               }},
                              {RPCResult::Type::STR_AMOUNT, "minimumvalue",
                               "The minimum value the staking reward output "
                               "must pay"},
                          }},
                         {RPCResult::Type::ELISION, "", ""},
                     }},
                    {RPCResult::Type::STR, "target", "The hash target"},
                    {RPCResult::Type::NUM_TIME, "mintime",
                     "The minimum timestamp appropriate for the next block "
                     "time, expressed in " +
                         UNIX_EPOCH_TIME},
                    {RPCResult::Type::ARR,
                     "mutable",
                     "list of ways the block template may be changed",
                     {
                         {RPCResult::Type::STR, "value",
                          "A way the block template may be changed, e.g. "
                          "'time', 'transactions', 'prevblock'"},
                     }},
                    {RPCResult::Type::STR_HEX, "noncerange",
                     "A range of valid nonces"},
                    {RPCResult::Type::NUM, "sigchecklimit",
                     "limit of sigChecks in blocks"},
                    {RPCResult::Type::NUM, "sizelimit", "limit of block size"},
                    {RPCResult::Type::NUM_TIME, "curtime",
                     "current timestamp in " + UNIX_EPOCH_TIME},
                    {RPCResult::Type::STR, "bits",
                     "compressed target of next block"},
                    {RPCResult::Type::NUM, "height",
                     "The height of the next block"},
                    {RPCResult::Type::NUM, "templateid",
                     "Monotonic template ID for submitsealedheader/submitsealedblock"},
                    {RPCResult::Type::STR_HEX, "subtreearoot",
                     "Merklix Subtree-A root for non-coinbase transactions"},
                    {RPCResult::Type::STR_HEX, "merkleroot",
                     "Positional SHA-256d Merkle root with default/mineraddress coinbase"},
                    {RPCResult::Type::STR_HEX, "coinbasetxhex",
                     "Serialized coinbase transaction in hex"},
                    {RPCResult::Type::STR_HEX, "headerhex",
                     "Serialized 80-byte CBlockHeader in hex (160 hex chars)"},
                    {RPCResult::Type::NUM, "blocksize",
                     "Total serialized block size in bytes"},
                    {RPCResult::Type::OBJ,
                     "rtt",
                     "The real-time target parameters. Only present after the "
                     "Nov. 15, 2024 upgrade activated and if -enablertt is set",
                     {
                         {RPCResult::Type::ARR,
                          "prevheadertime",
                          "The time the preview block headers were received, "
                          "expressed in " +
                              UNIX_EPOCH_TIME +
                              ". Contains 4 values for headers at height N-2, "
                              "N-5, N-11 and N-17.",
                          {
                              {RPCResult::Type::NUM_TIME, "prevheadertime",
                               "The time the block header was received, "
                               "expressed in " +
                                   UNIX_EPOCH_TIME},
                          }},
                         {RPCResult::Type::STR, "prevbits",
                          "The previous block compressed target"},
                         {RPCResult::Type::NUM_TIME, "nodetime",
                          "The node local time in " + UNIX_EPOCH_TIME},
                         {RPCResult::Type::STR_HEX, "nexttarget",
                          "The real-time target in compact format"},
                     }},
                    {RPCResult::Type::OBJ,
                     "minerfund",
                     "information related to the coinbase miner fund."
                     "This will ONLY be set if -simplegbt is enabled",
                     {
                         {RPCResult::Type::STR_HEX, "script",
                          "The scriptpubkey for the miner fund output in "
                          "hex format"},
                         {RPCResult::Type::STR_AMOUNT, "amount",
                          "The minimum value the miner fund output must "
                          "pay in satoshis"},

                     }},
                    {RPCResult::Type::OBJ,
                     "stakingrewards",
                     "information related to the coinbase staking reward "
                     "output, only set if the -avalanchestakingrewards "
                     "option is enabled and if the node is able to "
                     "determine a winner. This will ONLY be set if "
                     "-simplegbt is enabled",
                     {
                         {RPCResult::Type::STR_HEX, "script",
                          "The scriptpubkey for the staking reward "
                          "output in hex format"},
                         {RPCResult::Type::STR_AMOUNT, "amount",
                          "The minimum value the staking reward output must "
                          "pay in satoshis"},
                     }},
                }},
        },
        RPCExamples{HelpExampleCli("getblocktemplate", "") +
                    HelpExampleRpc("getblocktemplate", "")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request,
            boost::asio::any_io_executor executor)
            -> boost::asio::awaitable<UniValue> {
            NodeContext &node = EnsureAnyNodeContext(request.context);
            ChainstateManager &chainman = EnsureChainman(node);
            ArgsManager &argsman = EnsureArgsman(node);
            const CChainParams &chainparams = config.GetChainParams();

            std::string strMode = "template";
            UniValue lpval = NullUniValue;
            CScript minerScriptPubKey = CScript() << OP_TRUE;
            if (!request.params[0].isNull()) {
                const UniValue &oparam = request.params[0].get_obj();
                const UniValue &modeval = oparam.find_value("mode");
                if (modeval.isStr()) {
                    strMode = modeval.get_str();
                } else if (modeval.isNull()) {
                    /* Do nothing */
                } else {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
                }
                lpval = oparam.find_value("longpollid");

                const UniValue &addrval = oparam.find_value("mineraddress");
                if (!addrval.isNull()) {
                    if (!addrval.isStr() || addrval.get_str().empty()) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER,
                                           "mineraddress must be a non-empty string");
                    }
                    const CTxDestination dest =
                        DecodeDestination(addrval.get_str(), chainparams);
                    if (!IsValidDestination(dest)) {
                        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                           "Invalid mineraddress");
                    }
                    minerScriptPubKey = GetScriptForDestination(dest);
                }

                if (strMode == "proposal") {
                    const UniValue &dataval = oparam.find_value("data");
                    if (!dataval.isStr()) {
                        throw JSONRPCError(
                            RPC_TYPE_ERROR,
                            "Missing data String key for proposal");
                    }

                    CBlock block;
                    if (!DecodeHexBlk(block, dataval.get_str())) {
                        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                           "Block decode failed");
                    }

                    LOCK(cs_main);
                    Chainstate &active_chainstate = chainman.ActiveChainstate();
                    CChain &active_chain = active_chainstate.m_chain;
                    const BlockHash hash = block.GetHash();
                    const CBlockIndex *pindex =
                        chainman.m_blockman.LookupBlockIndex(hash);
                    if (pindex) {
                        if (pindex->IsValid(BlockValidity::SCRIPTS)) {
                            co_return "duplicate";
                        }
                        if (pindex->nStatus.isInvalid()) {
                            co_return "duplicate-invalid";
                        }
                        co_return "duplicate-inconclusive";
                    }

                    CBlockIndex *const pindexPrev = active_chain.Tip();
                    if (block.hashPrevBlock != pindexPrev->GetBlockHash()) {
                        co_return "inconclusive-not-best-prevblk";
                    }
                    BlockValidationState state;
                    TestBlockValidity(state, chainparams, active_chainstate,
                                      block, pindexPrev, GetAdjustedTime,
                                      BlockValidationOptions(config)
                                          .withCheckPoW(false)
                                          .withCheckMerkleRoot(true));
                    co_return BIP22ValidationResult(config, state);
                }
            }

            if (strMode != "template" && strMode != "compact_template") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
            }
            const bool compact_template = (strMode == "compact_template");

            const CConnman &connman = EnsureConnman(node);
            if (!chainparams.MineBlocksOnDemand() &&
                !argsman.GetBoolArg("-gbtwithoutpeers", false) &&
                connman.GetNodeCount(ConnectionDirection::Both) == 0) {
                throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED,
                                   "Bitcoin is not connected!");
            }

            if (chainman.IsInitialBlockDownload()) {
                throw JSONRPCError(
                    RPC_CLIENT_IN_INITIAL_DOWNLOAD, PACKAGE_NAME
                    " is in initial sync and waiting for blocks...");
            }

            static std::atomic<unsigned int> nTransactionsUpdatedLast{0};
            const CTxMemPool &mempool = EnsureMemPool(node);
            const Consensus::Params &consensusParams =
                chainparams.GetConsensus();

            if (!lpval.isNull()) {
                uint256 hashWatchedChain;
                std::chrono::steady_clock::time_point checktxtime;
                unsigned int nTransactionsUpdatedLastLP;

                if (lpval.isStr()) {
                    const std::string &lpstr = lpval.get_str();
                    hashWatchedChain =
                        ParseHashV(lpstr.substr(0, 64), "longpollid");
                    nTransactionsUpdatedLastLP =
                        LocaleIndependentAtoi<int64_t>(lpstr.substr(64));
                } else {
                    const auto snap = node::GetGlobalSnapshotPublisher().Load();
                    if (snap && snap->chain_valid) {
                        hashWatchedChain = snap->best_block_hash;
                    } else {
                        LOCK(cs_main);
                        hashWatchedChain =
                            chainman.ActiveChain().Tip()->GetBlockHash();
                    }
                    nTransactionsUpdatedLastLP =
                        nTransactionsUpdatedLast.load(
                            std::memory_order_relaxed);
                }

                const bool isRegtest = chainparams.MineBlocksOnDemand();
                const auto initialLongpollDelay = isRegtest ? 5s : 1min;
                const auto newTxCheckLongpollDelay = isRegtest ? 1s : 10s;
                checktxtime =
                    std::chrono::steady_clock::now() + initialLongpollDelay;

                while (IsRPCRunning()) {
                    {
                        LOCK(g_best_block_mutex);
                        if (!g_best_block ||
                            g_best_block->GetBlockHash() != hashWatchedChain) {
                            break;
                        }
                    }

                    co_await GetRPCBlockChangeWaiter().WaitUntilDeadline(
                        executor, checktxtime, [hashWatchedChain]() {
                            LOCK(g_best_block_mutex);
                            return !g_best_block ||
                                   g_best_block->GetBlockHash() !=
                                       hashWatchedChain ||
                                   !IsRPCRunning();
                        });

                    {
                        LOCK(g_best_block_mutex);
                        if (!g_best_block ||
                            g_best_block->GetBlockHash() != hashWatchedChain ||
                            !IsRPCRunning()) {
                            break;
                        }
                    }
                    if (mempool.GetTransactionsUpdated() !=
                        nTransactionsUpdatedLastLP) {
                        break;
                    }
                    checktxtime += newTxCheckLongpollDelay;
                }

                if (node.avalanche) {
                    const CBlockIndex *best_blk = nullptr;
                    {
                        WAIT_LOCK(g_best_block_mutex, lock);
                        best_blk = g_best_block;
                    }
                    if (IsStakingRewardsActivated(consensusParams, best_blk)) {
                        node.avalanche->computeStakingReward(best_blk);
                    }
                }

                if (!IsRPCRunning()) {
                    throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED,
                                       "Shutting down");
                }
            }

            // Reuse the completed immutable template from the published snapshot
            // whenever Avalanche preconsensus mining is not overriding
            // normal mempool selection.
            const bool avalanche_preconsensus_mining =
                node.avalanche &&
                argsman.GetBoolArg(
                    "-avalanchepreconsensusmining",
                    DEFAULT_AVALANCHE_MINING_PRECONSENSUS) &&
                node.avalanche->isPreconsensusActivated(nullptr);

            auto snap = node::GetGlobalSnapshotPublisher().Load();
            if ((!snap || !snap->chain_valid ||
                 snap->chainman_ptr != &chainman ||
                 !snap->GetMiningTemplate().template_valid) &&
                !avalanche_preconsensus_mining) {
                LOCK(cs_main);
                node::PublishChainTipSnapshot(chainman, &mempool);
                snap = node::GetGlobalSnapshotPublisher().Load();
            }

            if (snap && snap->chain_valid && snap->chainman_ptr == &chainman &&
                snap->GetMiningTemplate().template_valid &&
                !avalanche_preconsensus_mining) {
                snap->EnsureMiningTemplate();
                const auto &tmpl = snap->GetMiningTemplate();
                nTransactionsUpdatedLast.store(snap->transactions_updated,
                                               std::memory_order_relaxed);

                const int64_t adjustedTime =
                    TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
                const int64_t curtime =
                    std::max(tmpl.min_time, adjustedTime);

                uint32_t nBits = tmpl.nBits;
                if (consensusParams.fPowAllowMinDifficultyBlocks &&
                    curtime > snap->time +
                                  2 * consensusParams.nPowTargetSpacing) {
                    nBits = UintToArith256(consensusParams.powLimit)
                                .GetCompact();
                }

                UniValue aCaps(UniValue::VARR);
                aCaps.push_back("proposal");

                const Amount coinbasevalue = tmpl.block_reward;

                UniValue transactions(UniValue::VARR);
                if (!compact_template) {
                    const auto &hex_vec = tmpl.EnsureTxHex();
                    transactions.reserve(tmpl.non_coinbase_txs.size());
                    for (size_t i = 0; i < tmpl.non_coinbase_txs.size(); ++i) {
                        const CTransaction &tx = *tmpl.non_coinbase_txs[i];
                        UniValue entry(UniValue::VOBJ);
                        entry.reserve(5);
                        entry.pushKVEnd("data", i < hex_vec.size()
                                                    ? hex_vec[i]
                                                    : EncodeHexTx(tx));
                        entry.pushKVEnd("txid", tx.GetId().GetHex());
                        entry.pushKVEnd("hash", tx.GetHash().GetHex());
                        entry.pushKVEnd("fee", tmpl.tx_fees[i] / SATOSHI);
                        entry.pushKVEnd("sigchecks", tmpl.tx_sigchecks[i]);
                        transactions.push_back(std::move(entry));
                    }
                }

                const bool simplifyGbt = argsman.GetBoolArg("-simplegbt", false);

                UniValue result(UniValue::VOBJ);
                UniValue aux(UniValue::VOBJ);
                UniValue coinbasetxn(UniValue::VOBJ);

                const auto minerFundWhitelist =
                    GetMinerFundWhitelist(consensusParams);
                const bool minerFundEnabled = !minerFundWhitelist.empty();
                const Amount minerFundAmount =
                    minerFundEnabled
                        ? (snap->miner_fund_ratio * coinbasevalue / 100)
                        : Amount::zero();
                const int64_t minerFundMinValue =
                    snap->miner_fund_active ? int64_t(minerFundAmount / SATOSHI) : 0;

                std::vector<CScript> stakingRewardsPayoutScripts;
                const Amount stakingRewardsAmountVal =
                    GetStakingRewardsAmount(coinbasevalue);
                const int64_t stakingRewardsAmount =
                    stakingRewardsAmountVal / SATOSHI;
                const bool stakingRewardsEnabled =
                    argsman.GetBoolArg("-avalanchestakingrewards",
                                       consensusParams.enableStakingRewards);
                if (node.avalanche && stakingRewardsEnabled && snap->staking_rewards_active) {
                    if (!node.avalanche->getStakingRewardWinners(
                            tmpl.prev_block_hash,
                            stakingRewardsPayoutScripts)) {
                        stakingRewardsPayoutScripts.clear();
                    }
                }

                // Construct the coinbase transaction (using minerScriptPubKey,
                // which defaults to OP_TRUE when mineraddress is omitted)
                // and compute the positional SHA-256d Merkle root in O(log N).
                CMutableTransaction coinbaseTx;
                coinbaseTx.vin.resize(1);
                coinbaseTx.vin[0].prevout = COutPoint();
                coinbaseTx.vout.resize(1);
                coinbaseTx.vout[0].scriptPubKey = minerScriptPubKey;
                coinbaseTx.vout[0].nValue = coinbasevalue;
                coinbaseTx.vin[0].scriptSig =
                    CScript() << tmpl.next_height << OP_0;
                if (minerFundEnabled) {
                    coinbaseTx.vout[0].nValue -= minerFundAmount;
                    coinbaseTx.vout.emplace_back(
                        minerFundAmount,
                        GetScriptForDestination(*minerFundWhitelist.begin()));
                }
                if (!stakingRewardsPayoutScripts.empty()) {
                    coinbaseTx.vout[0].nValue -= stakingRewardsAmountVal;
                    coinbaseTx.vout.emplace_back(
                        stakingRewardsAmountVal,
                        stakingRewardsPayoutScripts[0]);
                }
                uint64_t coinbaseSize = ::GetSerializeSize(coinbaseTx);
                if (coinbaseSize < MIN_TX_SIZE) {
                    coinbaseTx.vin[0].scriptSig << std::vector<uint8_t>(
                        MIN_TX_SIZE - coinbaseSize - 1);
                    coinbaseSize = ::GetSerializeSize(coinbaseTx);
                }

                const CTransaction coinbaseTxFinal(coinbaseTx);
                const TxId cb_txid = coinbaseTxFinal.GetId();
                lotus::v2::Hash cb_txid_bytes{};
                std::memcpy(cb_txid_bytes.data(), cb_txid.begin(), 32);
                tmpl.EnsureTemplateRoots();
                const lotus::v2::Hash merkle_root_bytes =
                    lotus::v2::ComputeMerkleRootFromLeftSpine(
                        cb_txid_bytes, tmpl.coinbase_merkle_branch);
                uint256 merkle_root;
                std::memcpy(merkle_root.begin(), merkle_root_bytes.data(), 32);

                uint256 subtree_a_uint;
                std::memcpy(subtree_a_uint.begin(), tmpl.subtree_a_root.data(),
                            32);

                const uint64_t num_txs = 1 + tmpl.non_coinbase_txs.size();
                const uint64_t vtx_varint_bytes = GetSizeOfCompactSize(num_txs);
                const uint64_t total_block_bytes =
                    80 + vtx_varint_bytes + coinbaseSize +
                    tmpl.non_cb_serialized_size;

                CBlockHeader solved_hdr;
                solved_hdr.nHeaderVersion = tmpl.nHeaderVersion;
                solved_hdr.hashPrevBlock = tmpl.prev_block_hash;
                solved_hdr.hashMerkleRoot = merkle_root;
                solved_hdr.SetBlockTime(curtime);
                solved_hdr.nBits = nBits;
                solved_hdr.nNonce = 0;

                // Cold assembly validates the exact selected transactions and
                // parent UTXO/script context once. Overlay membership and a
                // Merkle match are not validation provenance. Warm reads take
                // only this cache-local mutex, never cs_main or mempool.cs.
                {
                    std::lock_guard<std::mutex> lock(snap->mining->validation_mutex);
                    if (!snap->mining->validated) {
                        CBlock candidate;
                        static_cast<CBlockHeader &>(candidate) = solved_hdr;
                        candidate.vtx.push_back(MakeTransactionRef(coinbaseTx));
                        candidate.vtx.insert(candidate.vtx.end(),
                            tmpl.non_coinbase_txs.begin(), tmpl.non_coinbase_txs.end());
                        LOCK(cs_main);
                        auto &chainstate = chainman.ActiveChainstate();
                        auto *tip = chainstate.m_chain.Tip();
                        if (!tip || tip->GetBlockHash() != tmpl.prev_block_hash) {
                            throw JSONRPCError(RPC_VERIFY_ERROR,
                                               "Template parent changed during assembly; retry");
                        }
                        BlockValidationState state;
                        if (!TestBlockValidity(state, chainparams, chainstate, candidate,
                                tip, GetAdjustedTime,
                                BlockValidationOptions(config).withCheckPoW(false)
                                                              .withCheckMerkleRoot(true))) {
                            throw std::runtime_error("getblocktemplate: " + state.ToString());
                        }
                        snap->mining->validated = true;
                    }
                }

                DataStream ss_hdr{};
                ss_hdr << solved_hdr;

                BlockAssembler::m_last_block_num_txs =
                    int64_t(tmpl.non_coinbase_txs.size());
                BlockAssembler::m_last_block_size =
                    int64_t(1000 + tmpl.non_cb_serialized_size);

                if (simplifyGbt) {
                    UniValue minerFund(UniValue::VOBJ);
                    if (!minerFundWhitelist.empty()) {
                        minerFund.pushKV("script",
                                         HexStr(GetScriptForDestination(
                                             *minerFundWhitelist.begin())));
                        minerFund.pushKV("amount", minerFundMinValue);
                    }
                    result.pushKV("minerfund", std::move(minerFund));

                    if (!stakingRewardsPayoutScripts.empty()) {
                        UniValue stakingRewards(UniValue::VOBJ);
                        stakingRewards.pushKV(
                            "script", HexStr(stakingRewardsPayoutScripts[0]));
                        stakingRewards.pushKV("amount", stakingRewardsAmount);
                        result.pushKV("stakingrewards",
                                      std::move(stakingRewards));
                    }
                } else {
                    UniValue minerFund(UniValue::VOBJ);
                    UniValue minerFundList(UniValue::VARR);
                    for (const auto &fundDestination : minerFundWhitelist) {
                        minerFundList.push_back(
                            EncodeDestination(fundDestination, config));
                    }

                    minerFund.pushKV("addresses", std::move(minerFundList));
                    minerFund.pushKV("minimumvalue", minerFundMinValue);

                    coinbasetxn.pushKV("minerfund", std::move(minerFund));

                    if (!stakingRewardsPayoutScripts.empty()) {
                        UniValue stakingRewards(UniValue::VOBJ);
                        UniValue stakingRewardsPayoutScriptObj(UniValue::VOBJ);
                        ScriptPubKeyToUniv(stakingRewardsPayoutScripts[0],
                                           stakingRewardsPayoutScriptObj,
                                           /*fIncludeHex=*/true);
                        stakingRewards.pushKV(
                            "payoutscript",
                            std::move(stakingRewardsPayoutScriptObj));
                        stakingRewards.pushKV("minimumvalue",
                                              stakingRewardsAmount);

                        coinbasetxn.pushKV("stakingrewards",
                                           std::move(stakingRewards));
                    }
                }

                arith_uint256 hashTarget =
                    arith_uint256().SetCompact(nBits);

                UniValue aMutable(UniValue::VARR);
                aMutable.push_back("time");
                aMutable.push_back("transactions");
                aMutable.push_back("prevblock");

                result.pushKV("capabilities", std::move(aCaps));
                result.pushKV("version", int64_t(tmpl.nHeaderVersion));
                result.pushKV("previousblockhash",
                              tmpl.prev_block_hash.GetHex());
                result.pushKV("transactions", std::move(transactions));
                result.pushKV("coinbaseaux", std::move(aux));
                result.pushKV("coinbasetxn", std::move(coinbasetxn));
                result.pushKV("coinbasevalue",
                              int64_t(coinbasevalue / SATOSHI));
                result.pushKV("longpollid",
                              tmpl.prev_block_hash.GetHex() +
                                  ToString(snap->transactions_updated));
                result.pushKV("target", hashTarget.GetHex());
                result.pushKV("mintime", tmpl.min_time);
                result.pushKV("mutable", std::move(aMutable));
                result.pushKV("noncerange", "00000000ffffffff");
                const uint64_t maxBlockSize = config.GetMaxBlockSize();
                const uint64_t sigCheckLimit =
                    GetMaxBlockSigChecksCount(maxBlockSize);
                result.pushKV("sigchecklimit", sigCheckLimit);
                result.pushKV("sizelimit", maxBlockSize);
                result.pushKV("curtime", curtime);
                result.pushKV("bits", strprintf("%08x", nBits));
                result.pushKV("height", int64_t(tmpl.next_height));
                result.pushKV("templateid", int64_t(tmpl.template_id));
                result.pushKV("subtreearoot", subtree_a_uint.GetHex());
                result.pushKV("merkleroot", merkle_root.GetHex());
                result.pushKV("coinbasetxhex", EncodeHexTx(coinbaseTxFinal));
                result.pushKV("headerhex", HexStr(ss_hdr));
                result.pushKV("blocksize", int64_t(total_block_bytes));

                if (argsman.GetBoolArg("-enablertt", DEFAULT_ENABLE_RTT)) {
                    uint32_t nextTarget = nBits;
                    if (!consensusParams.fPowAllowMinDifficultyBlocks ||
                        (curtime <=
                         snap->time + 2 * consensusParams.nPowTargetSpacing)) {
                        auto rttTarget = ComputeNextRTTWorkRequiredFromSnapshot(
                            *snap, adjustedTime, consensusParams);
                        if (rttTarget &&
                            arith_uint256().SetCompact(*rttTarget) <
                                hashTarget) {
                            nextTarget = *rttTarget;
                        }
                    }

                    UniValue rtt(UniValue::VOBJ);
                    UniValue prevHeaderTimes(UniValue::VARR);
                    for (size_t i : {1, 2, 5, 11, 17}) {
                        prevHeaderTimes.push_back(
                            snap->prev_header_received_time[i]);
                    }
                    rtt.pushKV("prevheadertime", std::move(prevHeaderTimes));
                    rtt.pushKV("prevbits", strprintf("%08x", snap->nBits));
                    rtt.pushKV("nodetime", adjustedTime);
                    rtt.pushKV("nexttarget", strprintf("%08x", nextTarget));

                    result.pushKV("rtt", std::move(rtt));
                }

                co_return result;
            }

            LOCK(cs_main);
            Chainstate &active_chainstate = chainman.ActiveChainstate();
            CChain &active_chain = active_chainstate.m_chain;

            // Update block
            static CBlockIndex *pindexPrev;
            static int64_t time_start;
            static std::unique_ptr<CBlockTemplate> pblocktemplate;
            static uint64_t fallback_template_id{0};
            static CScript last_miner_script;
            if (pindexPrev != active_chain.Tip() ||
                last_miner_script != minerScriptPubKey ||
                (mempool.GetTransactionsUpdated() !=
                     nTransactionsUpdatedLast.load(std::memory_order_relaxed) &&
                 GetTime() - time_start > 5)) {
                pindexPrev = nullptr;

                nTransactionsUpdatedLast.store(mempool.GetTransactionsUpdated(),
                                               std::memory_order_relaxed);
                CBlockIndex *pindexPrevNew = active_chain.Tip();
                time_start = GetTime();

                pblocktemplate = BlockAssembler{config, active_chainstate,
                                                &mempool, node.avalanche.get()}
                                     .CreateNewBlock(minerScriptPubKey);
                if (!pblocktemplate) {
                    throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
                }

                pindexPrev = pindexPrevNew;
                last_miner_script = minerScriptPubKey;
                fallback_template_id =
                    node::GetGlobalSnapshotPublisher().AllocateTemplateId();

                node::MiningTemplateSnapshot fb_tmpl{};
                fb_tmpl.template_id = fallback_template_id;
                fb_tmpl.prev_block_hash = pindexPrev->GetBlockHash();
                fb_tmpl.next_height = pindexPrev->nHeight + 1;
                fb_tmpl.nHeaderVersion = pblocktemplate->block.nHeaderVersion;
                fb_tmpl.nBits = pblocktemplate->block.nBits;
                fb_tmpl.parent_mtp = pindexPrev->GetMedianTimePast();
                fb_tmpl.min_time = fb_tmpl.parent_mtp + 1;
                for (size_t i = 1; i < pblocktemplate->block.vtx.size(); ++i) {
                    fb_tmpl.non_coinbase_txs.push_back(
                        pblocktemplate->block.vtx[i]);
                }
                fb_tmpl.template_valid = true;
                node::GetGlobalSnapshotPublisher().RecordMiningTemplate(
                    fb_tmpl);
            }

            CHECK_NONFATAL(pindexPrev);
            CBlock *pblock = &pblocktemplate->block;

            int64_t adjustedTime =
                TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
            UpdateTime(pblock, chainparams, pindexPrev, adjustedTime);
            pblock->nNonce = 0;

            UniValue aCaps(UniValue::VARR);
            aCaps.push_back("proposal");

            Amount coinbasevalue = Amount::zero();

            UniValue transactions(UniValue::VARR);
            transactions.reserve(pblock->vtx.size());
            int index_in_template = 0;
            for (const auto &it : pblock->vtx) {
                const CTransaction &tx = *it;
                const TxId txId = tx.GetId();

                if (tx.IsCoinBase()) {
                    index_in_template++;

                    for (const auto &o : pblock->vtx[0]->vout) {
                        coinbasevalue += o.nValue;
                    }

                    continue;
                }

                if (!compact_template) {
                    UniValue entry(UniValue::VOBJ);
                    entry.reserve(5);
                    entry.pushKVEnd("data", EncodeHexTx(tx));
                    entry.pushKVEnd("txid", txId.GetHex());
                    entry.pushKVEnd("hash", tx.GetHash().GetHex());
                    entry.pushKVEnd(
                        "fee", pblocktemplate->entries[index_in_template].fees /
                                   SATOSHI);
                    const int64_t sigChecks =
                        pblocktemplate->entries[index_in_template].sigChecks;
                    entry.pushKVEnd("sigchecks", sigChecks);

                    transactions.push_back(std::move(entry));
                }
                index_in_template++;
            }

            const bool simplifyGbt = argsman.GetBoolArg("-simplegbt", false);

            UniValue result(UniValue::VOBJ);
            UniValue aux(UniValue::VOBJ);
            UniValue coinbasetxn(UniValue::VOBJ);

            const auto minerFundWhitelist =
                GetMinerFundWhitelist(consensusParams);
            int64_t minerFundMinValue =
                int64_t(GetMinerFundAmount(consensusParams, coinbasevalue,
                                           pindexPrev) /
                        SATOSHI);

            std::vector<CScript> stakingRewardsPayoutScripts;
            int64_t stakingRewardsAmount =
                GetStakingRewardsAmount(coinbasevalue) / SATOSHI;
            if (node.avalanche &&
                IsStakingRewardsActivated(consensusParams, pindexPrev)) {
                if (!node.avalanche->getStakingRewardWinners(
                        pindexPrev->GetBlockHash(),
                        stakingRewardsPayoutScripts)) {
                    stakingRewardsPayoutScripts.clear();
                }
            }

            if (simplifyGbt) {
                UniValue minerFund(UniValue::VOBJ);
                if (!minerFundWhitelist.empty()) {
                    minerFund.pushKV("script",
                                     HexStr(GetScriptForDestination(
                                         *minerFundWhitelist.begin())));
                    minerFund.pushKV("amount", minerFundMinValue);
                }
                result.pushKV("minerfund", std::move(minerFund));

                if (!stakingRewardsPayoutScripts.empty()) {
                    UniValue stakingRewards(UniValue::VOBJ);
                    stakingRewards.pushKV(
                        "script", HexStr(stakingRewardsPayoutScripts[0]));
                    stakingRewards.pushKV("amount", stakingRewardsAmount);
                    result.pushKV("stakingrewards", std::move(stakingRewards));
                }
            } else {
                UniValue minerFund(UniValue::VOBJ);
                UniValue minerFundList(UniValue::VARR);
                for (const auto &fundDestination : minerFundWhitelist) {
                    minerFundList.push_back(
                        EncodeDestination(fundDestination, config));
                }

                minerFund.pushKV("addresses", std::move(minerFundList));
                minerFund.pushKV("minimumvalue", minerFundMinValue);

                coinbasetxn.pushKV("minerfund", std::move(minerFund));

                if (!stakingRewardsPayoutScripts.empty()) {
                    UniValue stakingRewards(UniValue::VOBJ);
                    UniValue stakingRewardsPayoutScriptObj(UniValue::VOBJ);
                    ScriptPubKeyToUniv(stakingRewardsPayoutScripts[0],
                                       stakingRewardsPayoutScriptObj,
                                       /*fIncludeHex=*/true);
                    stakingRewards.pushKV(
                        "payoutscript",
                        std::move(stakingRewardsPayoutScriptObj));
                    stakingRewards.pushKV("minimumvalue", stakingRewardsAmount);

                    coinbasetxn.pushKV("stakingrewards",
                                       std::move(stakingRewards));
                }
            }

            arith_uint256 hashTarget =
                arith_uint256().SetCompact(pblock->nBits);

            UniValue aMutable(UniValue::VARR);
            aMutable.push_back("time");
            aMutable.push_back("transactions");
            aMutable.push_back("prevblock");

            result.pushKV("capabilities", std::move(aCaps));
            result.pushKV("version", pblock->nHeaderVersion);
            result.pushKV("previousblockhash", pblock->hashPrevBlock.GetHex());
            result.pushKV("transactions", std::move(transactions));
            result.pushKV("coinbaseaux", std::move(aux));
            result.pushKV("coinbasetxn", std::move(coinbasetxn));
            result.pushKV("coinbasevalue", int64_t(coinbasevalue / SATOSHI));
            result.pushKV(
                "longpollid",
                active_chain.Tip()->GetBlockHash().GetHex() +
                    ToString(nTransactionsUpdatedLast.load(
                        std::memory_order_relaxed)));
            result.pushKV("target", hashTarget.GetHex());
            result.pushKV("mintime",
                          int64_t(pindexPrev->GetMedianTimePast()) + 1);
            result.pushKV("mutable", std::move(aMutable));
            result.pushKV("noncerange", "00000000ffffffff");
            const uint64_t maxBlockSize = config.GetMaxBlockSize();
            const uint64_t sigCheckLimit =
                GetMaxBlockSigChecksCount(maxBlockSize);
            result.pushKV("sigchecklimit", sigCheckLimit);
            result.pushKV("sizelimit", maxBlockSize);
            result.pushKV("curtime", pblock->GetBlockTime());
            result.pushKV("bits", strprintf("%08x", pblock->nBits));
            result.pushKV("height", int64_t(pindexPrev->nHeight) + 1);
            result.pushKV("templateid", int64_t(fallback_template_id));
            lotus::v2::TxOverlayArena tx_arena;
            uint32_t tx_root_idx = lotus::v2::TxOverlayArena::kNullIdx;
            for (size_t i = 1; i < pblock->vtx.size(); ++i) {
                lotus::v2::Hash tid{};
                lotus::v2::Hash thash{};
                std::memcpy(tid.data(), pblock->vtx[i]->GetId().begin(), 32);
                std::memcpy(thash.data(), pblock->vtx[i]->GetHash().begin(), 32);
                tx_root_idx = tx_arena.InsertTxLeaf(tx_root_idx, tid, thash);
            }
            const lotus::v2::Hash sub_a = tx_arena.SubtreeARoot(tx_root_idx);
            uint256 sub_a_uint;
            std::memcpy(sub_a_uint.begin(), sub_a.data(), 32);
            result.pushKV("subtreearoot", sub_a_uint.GetHex());
            if (pblock->hashMerkleRoot.IsNull()) {
                pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
            }
            result.pushKV("merkleroot", pblock->hashMerkleRoot.GetHex());
            DataStream ss_fb_hdr{};
            ss_fb_hdr << pblock->GetBlockHeader();
            result.pushKV("coinbasetxhex", EncodeHexTx(*pblock->vtx[0]));
            result.pushKV("headerhex", HexStr(ss_fb_hdr));
            result.pushKV("blocksize", int64_t(::GetSerializeSize(*pblock)));

            if (isRTTEnabled(consensusParams, pindexPrev)) {
                uint32_t nextTarget = pblock->nBits;
                if (!consensusParams.fPowAllowMinDifficultyBlocks ||
                    (pblock->GetBlockTime() <=
                     pindexPrev->GetBlockTime() +
                         2 * consensusParams.nPowTargetSpacing)) {
                    auto rttTarget = GetNextRTTWorkRequired(
                        pindexPrev, adjustedTime, consensusParams);
                    if (rttTarget &&
                        arith_uint256().SetCompact(*rttTarget) < hashTarget) {
                        nextTarget = *rttTarget;
                    }
                }

                const CBlockIndex *previousIndex = pindexPrev;
                std::vector<int64_t> prevHeaderReceivedTime(18, 0);
                for (size_t i = 1; i < 18; i++) {
                    if (!previousIndex) {
                        break;
                    }

                    prevHeaderReceivedTime[i] =
                        previousIndex->GetHeaderReceivedTime();
                    previousIndex = previousIndex->pprev;
                }

                UniValue rtt(UniValue::VOBJ);
                UniValue prevHeaderTimes(UniValue::VARR);
                for (size_t i : {1, 2, 5, 11, 17}) {
                    prevHeaderTimes.push_back(prevHeaderReceivedTime[i]);
                }

                rtt.pushKV("prevheadertime", std::move(prevHeaderTimes));
                rtt.pushKV("prevbits", strprintf("%08x", pindexPrev->nBits));
                rtt.pushKV("nodetime", adjustedTime);
                rtt.pushKV("nexttarget", strprintf("%08x", nextTarget));

                result.pushKV("rtt", std::move(rtt));
            }

            co_return result;
        },
    };
}

class submitblock_StateCatcher final : public CValidationInterface {
public:
    uint256 hash;
    bool found{false};
    BlockValidationState state{};

    explicit submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn) {}

protected:
    void BlockChecked(const CBlock &block,
                      const BlockValidationState &stateIn) override {
        if (block.GetHash() != hash) {
            return;
        }

        found = true;
        state = stateIn;
    }
};

static RPCHelpMan submitblock() {
    // We allow 2 arguments for compliance with BIP22. Argument 2 is ignored.
    return RPCHelpMan{
        "submitblock",
        "Attempts to submit new block to network.\n"
        "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n",
        {
            {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "the hex-encoded block data to submit"},
            {"dummy", RPCArg::Type::STR, RPCArg::Default{"ignored"},
             "dummy value, for compatibility with BIP22. This value is "
             "ignored."},
        },
        {
            RPCResult{"If the block was accepted", RPCResult::Type::NONE, "",
                      ""},
            RPCResult{"Otherwise", RPCResult::Type::STR, "",
                      "According to BIP22"},
        },
        RPCExamples{HelpExampleCli("submitblock", "\"mydata\"") +
                    HelpExampleRpc("submitblock", "\"mydata\"")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
            CBlock &block = *blockptr;
            if (!DecodeHexBlk(block, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                   "Block decode failed");
            }

            if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                   "Block does not start with a coinbase");
            }

            NodeContext &node = EnsureAnyNodeContext(request.context);
            ChainstateManager &chainman = EnsureChainman(node);
            const BlockHash hash = block.GetHash();
            {
                LOCK(cs_main);
                const CBlockIndex *pindex =
                    chainman.m_blockman.LookupBlockIndex(hash);
                if (pindex) {
                    if (pindex->IsValid(BlockValidity::SCRIPTS)) {
                        return "duplicate";
                    }
                    if (pindex->nStatus.isInvalid()) {
                        return "duplicate-invalid";
                    }
                }
            }

            bool new_block;
            auto sc =
                std::make_shared<submitblock_StateCatcher>(block.GetHash());
            CHECK_NONFATAL(chainman.m_options.signals)
                ->RegisterSharedValidationInterface(sc);
            bool accepted = chainman.ProcessNewBlock(blockptr,
                                                     /*force_processing=*/true,
                                                     /*min_pow_checked=*/true,
                                                     /*new_block=*/&new_block,
                                                     node.avalanche.get());
            CHECK_NONFATAL(chainman.m_options.signals)
                ->UnregisterSharedValidationInterface(sc);
            if (!new_block && accepted) {
                return "duplicate";
            }

            if (!sc->found) {
                return "inconclusive";
            }

            // Block to make sure wallet/indexers sync before returning
            CHECK_NONFATAL(chainman.m_options.signals)
                ->SyncWithValidationInterfaceQueue();

            return BIP22ValidationResult(config, sc->state);
        },
    };
}

static RPCHelpMan submitsealedheader_impl(const char *method_name) {
    return RPCHelpMan{
        method_name,
        "Submit a solved 80-byte block header and coinbase transaction "
        "against a cached mining template snapshot without re-uploading the "
        "non-coinbase transaction list.\n",
        {
            {"headerhex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The 80-byte solved block header in hex (160 hex chars)"},
            {"coinbasetxhex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The serialized coinbase transaction in hex"},
            {"templateid", RPCArg::Type::NUM, RPCArg::Default{0},
             "Optional template ID returned by getblocktemplate (0 = latest "
             "matching prev_block_hash)"},
        },
        {
            RPCResult{"If the block was accepted", RPCResult::Type::NONE, "",
                      ""},
            RPCResult{"Otherwise", RPCResult::Type::STR, "",
                      "According to BIP22"},
        },
        RPCExamples{
            HelpExampleCli(method_name,
                           "\"headerhex\" \"coinbasetxhex\" 1") +
            HelpExampleRpc(method_name,
                           "\"headerhex\", \"coinbasetxhex\", 1")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            CBlockHeader header;
            if (!DecodeHexBlockHeader(header, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                   "Block header decode failed");
            }

            CMutableTransaction coinbase_mtx;
            if (!DecodeHexTx(coinbase_mtx, request.params[1].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                   "Coinbase transaction decode failed");
            }
            CTransactionRef coinbase_tx =
                MakeTransactionRef(std::move(coinbase_mtx));
            if (!coinbase_tx->IsCoinBase()) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                   "Provided transaction is not a coinbase");
            }

            uint64_t template_id = 0;
            if (!request.params[2].isNull()) {
                template_id = request.params[2].getInt<uint64_t>();
            }

            const auto tmpl_opt =
                node::GetGlobalSnapshotPublisher().FindMiningTemplate(
                    template_id, header.hashPrevBlock);
            if (!tmpl_opt) {
                throw JSONRPCError(RPC_VERIFY_ERROR,
                                   "Template not found in snapshot history");
            }

            std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
            CBlock &block = *blockptr;
            static_cast<CBlockHeader &>(block) = header;
            block.vtx.reserve(1 + tmpl_opt->non_coinbase_txs.size());
            block.vtx.push_back(std::move(coinbase_tx));
            block.vtx.insert(block.vtx.end(),
                             tmpl_opt->non_coinbase_txs.begin(),
                             tmpl_opt->non_coinbase_txs.end());

            // Verify the positional SHA-256d Merkle root in O(log N) using the
            // cached coinbase Merkle branch so CheckBlock can skip full O(N)
            // BlockMerkleRoot rehashing.
            tmpl_opt->EnsureTemplateRoots();
            lotus::v2::Hash cb_txid_bytes{};
            std::memcpy(cb_txid_bytes.data(), block.vtx[0]->GetId().begin(), 32);
            const lotus::v2::Hash expected_mroot =
                lotus::v2::ComputeMerkleRootFromLeftSpine(
                    cb_txid_bytes, tmpl_opt->coinbase_merkle_branch);
            if (tmpl_opt->merkle_cache_safe &&
                std::memcmp(block.hashMerkleRoot.begin(), expected_mroot.data(),
                            32) == 0) {
                block.m_checked_merkle_root = true;
            }

            NodeContext &node = EnsureAnyNodeContext(request.context);
            ChainstateManager &chainman = EnsureChainman(node);
            const BlockHash hash = block.GetHash();
            {
                LOCK(cs_main);
                const CBlockIndex *pindex =
                    chainman.m_blockman.LookupBlockIndex(hash);
                if (pindex) {
                    if (pindex->IsValid(BlockValidity::SCRIPTS)) {
                        return "duplicate";
                    }
                    if (pindex->nStatus.isInvalid()) {
                        return "duplicate-invalid";
                    }
                }
            }

            bool new_block = false;
            auto sc = std::make_shared<submitblock_StateCatcher>(hash);
            CHECK_NONFATAL(chainman.m_options.signals)
                ->RegisterSharedValidationInterface(sc);
            bool accepted = chainman.ProcessNewBlock(
                blockptr,
                /*force_processing=*/true,
                /*min_pow_checked=*/true,
                /*new_block=*/&new_block, node.avalanche.get());
            CHECK_NONFATAL(chainman.m_options.signals)
                ->UnregisterSharedValidationInterface(sc);
            if (!new_block && accepted) {
                return "duplicate";
            }

            if (!sc->found) {
                return "inconclusive";
            }

            CHECK_NONFATAL(chainman.m_options.signals)
                ->SyncWithValidationInterfaceQueue();

            return BIP22ValidationResult(config, sc->state);
        },
    };
}

static RPCHelpMan submitminedheader() {
    return submitsealedheader_impl("submitminedheader");
}

static RPCHelpMan submitsealedheader() {
    return submitsealedheader_impl("submitsealedheader");
}

static RPCHelpMan submitsealedblock() {
    return submitsealedheader_impl("submitsealedblock");
}

static RPCHelpMan getrawunsolvedblock() {
    return RPCHelpMan{
        "getrawunsolvedblock",
        "Assembles an unsolved block to a specified address (without PoW "
        "grinding) and returns its serialized block hex, 80-byte header hex, "
        "and coinbase transaction hex for external/parallel miners.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The address to send the newly generated lotus to."},
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::STR_HEX, "blockhex",
                  "Full serialized unsolved block in hex"},
                {RPCResult::Type::STR_HEX, "headerhex",
                 "80-byte unsolved header in hex (160 hex chars)"},
                {RPCResult::Type::STR_HEX, "coinbasetxhex",
                 "Serialized coinbase transaction in hex"},
                {RPCResult::Type::NUM, "templateid",
                 "Template ID for submitsealedheader"},
                {RPCResult::Type::STR_HEX, "bits", "Compact target nBits"},
                {RPCResult::Type::STR_HEX, "target", "256-bit PoW target"},
                {RPCResult::Type::NUM, "height", "Block height"},
                {RPCResult::Type::NUM, "txcount",
                 "Total transactions in block (including coinbase)"},
            }},
        RPCExamples{HelpExampleCli("getrawunsolvedblock", "\"myaddress\"") +
                    HelpExampleRpc("getrawunsolvedblock", "\"myaddress\"")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            CTxDestination destination = DecodeDestination(
                request.params[0].get_str(), config.GetChainParams());
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                   "Error: Invalid address");
            }

            NodeContext &node = EnsureAnyNodeContext(request.context);
            const CTxMemPool &mempool = EnsureMemPool(node);
            ChainstateManager &chainman = EnsureChainman(node);
            CScript coinbase_script = GetScriptForDestination(destination);

            std::unique_ptr<CBlockTemplate> pblocktemplate;
            int next_height = 0;
            uint64_t template_id = 0;
            {
                LOCK(cs_main);
                next_height = chainman.ActiveChain().Height() + 1;
                pblocktemplate =
                    BlockAssembler{config, chainman.ActiveChainstate(),
                                   &mempool, node.avalanche.get()}
                        .CreateNewBlock(coinbase_script);
                if (!pblocktemplate) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                                       "Couldn't create new block");
                }
                template_id =
                    node::GetGlobalSnapshotPublisher().AllocateTemplateId();
                node::MiningTemplateSnapshot tmpl{};
                tmpl.template_id = template_id;
                tmpl.prev_block_hash = pblocktemplate->block.hashPrevBlock;
                tmpl.next_height = next_height;
                tmpl.nHeaderVersion = pblocktemplate->block.nHeaderVersion;
                tmpl.nBits = pblocktemplate->block.nBits;
                for (size_t i = 1; i < pblocktemplate->block.vtx.size(); ++i) {
                    tmpl.non_coinbase_txs.push_back(
                        pblocktemplate->block.vtx[i]);
                }
                tmpl.template_valid = true;
                node::GetGlobalSnapshotPublisher().RecordMiningTemplate(tmpl);
            }

            CBlock &block = pblocktemplate->block;
            if (block.hashMerkleRoot.IsNull()) {
                block.hashMerkleRoot = BlockMerkleRoot(block);
            }

            DataStream ss_block{};
            ss_block << block;
            DataStream ss_hdr{};
            ss_hdr << block.GetBlockHeader();

            arith_uint256 hashTarget =
                arith_uint256().SetCompact(block.nBits);

            UniValue ret(UniValue::VOBJ);
            ret.pushKV("blockhex", HexStr(ss_block));
            ret.pushKV("headerhex", HexStr(ss_hdr));
            ret.pushKV("coinbasetxhex", EncodeHexTx(*block.vtx[0]));
            ret.pushKV("templateid", int64_t(template_id));
            ret.pushKV("bits", strprintf("%08x", block.nBits));
            ret.pushKV("target", hashTarget.GetHex());
            ret.pushKV("height", next_height);
            ret.pushKV("txcount", int64_t(block.vtx.size()));
            return ret;
        },
    };
}

static RPCHelpMan submitheader() {
    return RPCHelpMan{
        "submitheader",
        "Decode the given hexdata as a header and submit it as a candidate "
        "chain tip if valid."
        "\nThrows when the header is invalid.\n",
        {
            {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
              "the hex-encoded block header data"},
        },
        RPCResult{RPCResult::Type::NONE, "", "None"},
        RPCExamples{HelpExampleCli("submitheader", "\"aabbcc\"") +
                    HelpExampleRpc("submitheader", "\"aabbcc\"")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            CBlockHeader h;
            if (!DecodeHexBlockHeader(h, request.params[0].get_str())) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                                   "Block header decode failed");
            }
            ChainstateManager &chainman = EnsureAnyChainman(request.context);
            {
                LOCK(cs_main);
                if (!chainman.m_blockman.LookupBlockIndex(h.hashPrevBlock)) {
                    throw JSONRPCError(RPC_VERIFY_ERROR,
                                       "Must submit previous header (" +
                                           h.hashPrevBlock.GetHex() +
                                           ") first");
                }
            }

            BlockValidationState state;
            chainman.ProcessNewBlockHeaders({h},
                                            /*min_pow_checked=*/true, state);
            if (state.IsValid()) {
                return NullUniValue;
            }
            if (state.IsError()) {
                throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
            }
            throw JSONRPCError(RPC_VERIFY_ERROR, state.GetRejectReason());
        },
    };
}

static RPCHelpMan estimatefee() {
    return RPCHelpMan{
        "estimatefee",
        "Estimates the approximate fee per kilobyte needed for a "
        "transaction\n",
        {},
        RPCResult{RPCResult::Type::NUM, "", "estimated fee-per-kilobyte"},
        RPCExamples{HelpExampleCli("estimatefee", "")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const CTxMemPool &mempool = EnsureAnyMemPool(request.context);
            return mempool.estimateFee().GetFeePerK();
        },
    };
}

static RPCHelpMan estimatesmartfee() {
    return RPCHelpMan{
        "estimatesmartfee",
        "Estimates the approximate fee per kilobyte needed for a transaction "
        "to be admitted and mined, incorporating live mempool congestion, "
        "adaptive block size targets, and three-tier fee hysteresis.\n",
        {
            {"conf_target", RPCArg::Type::NUM, RPCArg::Default{1},
             "Confirmation target in blocks (1 - 1008)"},
            {"estimate_mode", RPCArg::Type::STR,
             RPCArg::Default{"CONSERVATIVE"},
             "The fee estimate mode.\n"
             "                   Whether to return the exact RPC admission "
             "floor (\"ECONOMICAL\") or include the +5% SDK anti-bounce "
             "cushion (\"CONSERVATIVE\" / \"UNSET\")."},
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::STR_AMOUNT, "feerate",
                 "estimate fee rate in " + Currency::getTicker() + "/kB"},
                {RPCResult::Type::NUM, "feerate_sats_per_kb",
                 "estimate fee rate in satoshis per kB"},
                {RPCResult::Type::NUM, "rpc_admission_feerate_per_kcu",
                 "Tier 1 local RPC admission fee rate in satoshis per 1,000 CU"},
                {RPCResult::Type::NUM, "recommended_sdk_feerate_per_kcu",
                 "Recommended wallet/SDK fee rate in satoshis per 1,000 CU "
                 "(+5% anti-bounce cushion)"},
                {RPCResult::Type::NUM, "p2p_relay_feerate_per_kcu",
                 "Tier 2 P2P relay hysteresis fee rate in satoshis per 1,000 CU"},
                {RPCResult::Type::NUM, "blocks",
                 "block number where estimate was found"},
            }},
        RPCExamples{HelpExampleCli("estimatesmartfee", "1") +
                    HelpExampleCli("estimatesmartfee", "1 \"ECONOMICAL\"") +
                    HelpExampleRpc("estimatesmartfee", "1, \"CONSERVATIVE\"")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            int64_t conf_target = 1;
            if (!request.params[0].isNull()) {
                conf_target = request.params[0].getInt<int64_t>();
                if (conf_target < 1) {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "Invalid conf_target, must be at least 1");
                }
            }

            bool economical = false;
            if (!request.params[1].isNull()) {
                const std::string mode = ToUpper(request.params[1].get_str());
                if (mode == "ECONOMICAL") {
                    economical = true;
                } else if (mode == "CONSERVATIVE" || mode == "UNSET") {
                    economical = false;
                } else {
                    throw JSONRPCError(
                        RPC_INVALID_PARAMETER,
                        "Invalid estimate_mode parameter, must be one of: "
                        "\"UNSET\", \"ECONOMICAL\", \"CONSERVATIVE\"");
                }
            }

            const CTxMemPool &mempool = EnsureAnyMemPool(request.context);
            const int64_t now_ms =
                TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
            const lotus::v2::FeeRateInfo info =
                lotus::v2::GetGlobalFeeHysteresisController().GetFeeRateInfo(
                    now_ms);

            const uint64_t target_hysteresis_sats_per_kb =
                economical ? info.rpc_admission_feerate_per_kcu
                           : info.recommended_sdk_feerate_per_kcu;
            const CFeeRate hysteresis_feerate(Amount(
                static_cast<int64_t>(target_hysteresis_sats_per_kb) * SATOSHI));
            const CFeeRate final_feerate =
                std::max(mempool.estimateFee(), hysteresis_feerate);
            const uint64_t feerate_sats_per_kb = static_cast<uint64_t>(
                std::max<int64_t>(0, final_feerate.GetFeePerK() / SATOSHI));

            UniValue ret(UniValue::VOBJ);
            ret.pushKV("feerate", final_feerate.GetFeePerK());
            ret.pushKV("feerate_sats_per_kb", feerate_sats_per_kb);
            ret.pushKV("rpc_admission_feerate_per_kcu",
                       info.rpc_admission_feerate_per_kcu);
            ret.pushKV("recommended_sdk_feerate_per_kcu",
                       info.recommended_sdk_feerate_per_kcu);
            ret.pushKV("p2p_relay_feerate_per_kcu",
                       info.p2p_relay_feerate_per_kcu);
            ret.pushKV("blocks", conf_target);
            return ret;
        },
    };
}

void RegisterMiningRPCCommands(CRPCTable &t) {
    // clang-format off
    static const CRPCCommand commands[] = {
        //  category    actor (function)
        //  ----------  ----------------------
        {"mining",      getnetworkhashps,      },
        {"mining",      getchainconfig,        },
        {"mining",      getmininginfo,         },
        {"mining",      prioritisetransaction, },
        {"mining",      getblocktemplate,      },
        {"mining",      submitblock,           },
        {"mining",      submitminedheader,     },
        {"mining",      submitsealedheader,    },
        {"mining",      submitsealedblock,     },
        {"mining",      getrawunsolvedblock,   },
        {"mining",      submitheader,          },

        {"generating",  generatetoaddress,     },
        {"generating",  generatetodescriptor,  },
        {"generating",  generateblock,         },

        {"util",        estimatefee,           },
        {"util",        estimatesmartfee,      },

        {"hidden",      generate,              },
    };
    // clang-format on
    for (const auto &c : commands) {
        t.appendCommand(c.name, &c);
    }
}
