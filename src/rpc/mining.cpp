// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <avalanche/avalanche.h>
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
#include <lotus_v2/commitment.h>
#include <lotus_v2/fee_hysteresis.h>
#include <node/snapshot.h>
#include <minerfund.h>
#include <net.h>
#include <node/context.h>
#include <node/miner.h>
#include <node/mining_pool.h>
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
#include <timedata.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <warnings.h>

#include <cmath>
#include <cstdint>
#include <cstring>

#include <lotus_v2/address.h>
#include <primitives/v2_outputs.h>

using node::BlockAssembler;
using node::BlockFitter;
using node::CBlockTemplate;
using node::IsCoinbaseVersion;
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
    const bool had_merkle_root = !block.hashMerkleRoot.IsNull();
    if (!had_merkle_root) {
        block.hashMerkleRoot = BlockMerkleRoot(block);
    }
    if (!had_merkle_root || block.hashStateRoot.IsNull()) {
        LOCK(cs_main);
        const CBlockIndex *pindexPrev =
            chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
        const uint64_t mtp =
            pindexPrev ? uint64_t(pindexPrev->GetMedianTimePast()) : 0;
        block.hashStateRoot = ComputeV2BlockStateRoot(
            block, block.hashPrevBlock, block.nHeight, mtp, false);
    }
    if (block.GetSize() == 0) {
        block.SetSize(GetSerializeSize(block));
    }

    const Consensus::Params &params = chainman.GetConsensus();

    while (max_tries > 0 &&
           block.nNonce < std::numeric_limits<uint64_t>::max() &&
           !CheckProofOfWork(block.GetHash(), block.nBits, params) &&
           !ShutdownRequested()) {
        ++block.nNonce;
        --max_tries;
    }
    if (max_tries == 0 || ShutdownRequested()) {
        return false;
    }
    if (block.nNonce == std::numeric_limits<uint64_t>::max()) {
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

static constexpr const char *COINBASE_VERSION_ARG_DOC =
    "Version of the coinbase transaction: 7 (V2 coinbase), or 1 or 2 "
    "(legacy coinbase, regtest only).";

/**
 * Block assembler options for a mining RPC: the node's options, with the
 * coinbase version taken from the request when it gives one.
 */
static BlockAssembler::Options
MiningRpcOptions(const UniValue &coinbase_version,
                 const Consensus::Params &params) {
    BlockAssembler::Options options;
    ApplyArgsManOptions(gArgs, options);
    if (!coinbase_version.isNull()) {
        const int64_t v = coinbase_version.getInt<int64_t>();
        if (v < 0 || v > 7 || !IsCoinbaseVersion(uint32_t(v))) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "coinbase_version must be 1, 2 or 7");
        }
        options.coinbase_version = uint32_t(v);
    }
    if (options.coinbase_version != 7 && !params.allowLegacyCoinbase) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("coinbase version %u is not allowed on "
                                     "this network",
                                     options.coinbase_version));
    }
    return options;
}

// A native address describes a native output policy. A legacy address only
// describes a legacy script and cannot be translated without its public key.
static CTxOut CoinbaseDestination(const std::string &address,
                                  const CChainParams &params,
                                  uint32_t coinbase_version) {
    if (coinbase_version != 7) {
        const auto destination = DecodeDestination(address, params);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                               "Error: Invalid legacy address");
        }
        return CTxOut(Amount::zero(), GetScriptForDestination(destination));
    }
    std::string error;
    const auto native = lotus::v2::DecodeAddress(address, error);
    const auto network = params.GetChainTypeString() == "main"
                             ? lotus::v2::AddressNetwork::MAINNET
                         : params.GetChainTypeString() == "regtest"
                             ? lotus::v2::AddressNetwork::REGTEST
                             : lotus::v2::AddressNetwork::TESTNET;
    if (!native || native->network != network) {
        throw JSONRPCError(
            RPC_INVALID_ADDRESS_OR_KEY,
            "Native coinbase requires a native address for this network; "
            "legacy address payouts are unsupported");
    }
    lotus::v2::Output output;
    output.branches = {native->BranchRoot()};
    output.paths = {{0}};
    return CTxOut::FromV2Output(output);
}

static UniValue generateBlocks(ChainstateManager &chainman,
                               const CTxMemPool &mempool,
                               avalanche::Processor *const avalanche,
                               const CTxOut &coinbase_output, int nGenerate,
                               uint64_t nMaxTries,
                               const BlockAssembler::Options &options) {
    UniValue blockHashes(UniValue::VARR);
    while (nGenerate > 0 && !ShutdownRequested()) {
        std::unique_ptr<CBlockTemplate> pblocktemplate(
            BlockAssembler{BlockFitter(chainman.GetConfig()),
                           chainman.ActiveChainstate(), &mempool, options,
                           avalanche}
                .CreateNewBlock(coinbase_output));

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
        "Mine blocks immediately to a specified legacy descriptor. Native "
        "coinbases require generatetoaddress with a native address.\n",
        {
            {"num_blocks", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "How many blocks are generated immediately."},
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The descriptor to send the newly generated bitcoin to."},
            {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES},
             "How many iterations to try."},
            {"coinbase_version", RPCArg::Type::NUM,
             RPCArg::DefaultHint{"-coinbaseversion"}, COINBASE_VERSION_ARG_DOC},
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

            const auto options =
                MiningRpcOptions(request.params[3], chainman.GetConsensus());
            if (options.coinbase_version == 7) {
                throw JSONRPCError(
                    RPC_INVALID_ADDRESS_OR_KEY,
                    "Legacy descriptors are unsupported for native coinbases; "
                    "use generatetoaddress with a native address");
            }
            return generateBlocks(chainman, mempool, node.avalanche.get(),
                                  CTxOut(Amount::zero(), coinbase_script),
                                  num_blocks, max_tries, options);
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
        "RPC call returns. Version 7 requires a native address; legacy "
        "addresses require a permitted legacy coinbase version.\n",
        {
            {"nblocks", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "How many blocks are generated immediately."},
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The address to send the newly generated bitcoin to."},
            {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES},
             "How many iterations to try."},
            {"coinbase_version", RPCArg::Type::NUM,
             RPCArg::DefaultHint{"-coinbaseversion"}, COINBASE_VERSION_ARG_DOC},
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

            NodeContext &node = EnsureAnyNodeContext(request.context);
            const CTxMemPool &mempool = EnsureMemPool(node);
            ChainstateManager &chainman = EnsureChainman(node);

            const auto options =
                MiningRpcOptions(request.params[3], chainman.GetConsensus());
            const CTxOut payout = CoinbaseDestination(
                request.params[1].get_str(), config.GetChainParams(),
                options.coinbase_version);

            return generateBlocks(chainman, mempool, node.avalanche.get(),
                                  payout, num_blocks, max_tries, options);
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
             "The payout address: native for version 7, legacy address or "
             "descriptor for a permitted legacy coinbase version."},
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
            {"coinbase_version", RPCArg::Type::NUM,
             RPCArg::DefaultHint{"-coinbaseversion"}, COINBASE_VERSION_ARG_DOC},
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
            NodeContext &node = EnsureAnyNodeContext(request.context);
            const CTxMemPool &mempool = EnsureMemPool(node);

            ChainstateManager &chainman = EnsureChainman(node);
            const CChainParams &chainparams = config.GetChainParams();
            const auto options =
                MiningRpcOptions(request.params[2], chainman.GetConsensus());
            CTxOut coinbase_output;
            if (options.coinbase_version == 7) {
                coinbase_output = CoinbaseDestination(
                    address_or_descriptor, config.GetChainParams(), 7);
            } else {
                CScript script;
                std::string error;
                if (getScriptFromDescriptor(address_or_descriptor, script,
                                            error)) {
                    coinbase_output = CTxOut(Amount::zero(), script);
                } else {
                    coinbase_output = CoinbaseDestination(
                        address_or_descriptor, config.GetChainParams(),
                        options.coinbase_version);
                }
            }

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

            {
                LOCK(cs_main);

                std::unique_ptr<CBlockTemplate> blocktemplate(
                    BlockAssembler{BlockFitter(config),
                                   chainman.ActiveChainstate(), nullptr,
                                   options, node.avalanche.get()}
                        .CreateNewBlock(coinbase_output));
                if (!blocktemplate) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                                       "Couldn't create new block");
                }
                block = blocktemplate->block;
            }

            CHECK_NONFATAL(block.vtx.size() == 1);

            // Add transactions
            block.vtx.insert(block.vtx.end(), txs.begin(), txs.end());
            block.hashMerkleRoot = BlockMerkleRoot(block);
            block.SetSize(GetSerializeSize(block));

            {
                LOCK(cs_main);

                CBlockIndex *pindexPrev =
                    chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
                const int64_t mtp =
                    pindexPrev ? pindexPrev->GetMedianTimePast() : 0;
                block.hashStateRoot = ComputeV2BlockStateRoot(
                    block, block.hashPrevBlock, block.nHeight, mtp, false);

                BlockValidationState state;
                if (!TestBlockValidity(state, chainparams,
                                       chainman.ActiveChainstate(), block,
                                       pindexPrev, GetAdjustedTime,
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
        "explicitly select between the default 'template' request, "
        "'compact_template', or a 'proposal'.\n"
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
                  "Optional Lotus address for the coinbase miner payout "
                  "output"},
                 {"coinbase_version", RPCArg::Type::NUM,
                  /* treat as named arg */
                  RPCArg::DefaultHint{"-coinbaseversion"},
                  COINBASE_VERSION_ARG_DOC},
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
                    {RPCResult::Type::NUM, "templateid", /* optional */ true,
                     "The template identifier for submitsealedblock / "
                     "submitsealedheader"},
                    {RPCResult::Type::STR_HEX, "subtreearoot",
                     /* optional */ true,
                     "The BLAKE3 Merkle root of non-coinbase transactions"},
                    {RPCResult::Type::STR_HEX, "merkleroot",
                     /* optional */ true,
                     "The block transaction Merkle root for the template "
                     "coinbase"},
                    {RPCResult::Type::STR_HEX, "stateroot",
                     /* optional */ true,
                     "The block state root for the template coinbase"},
                    {RPCResult::Type::STR_HEX, "headerhex",
                     /* optional */ true,
                     "The 134-byte serialized V2 candidate block header "
                     "(nonce=0)"},
                    {RPCResult::Type::STR_HEX, "coinbasetxhex",
                     /* optional */ true,
                     "The serialized coinbase transaction (vtx[0]) matching "
                     "headerhex"},
                    {RPCResult::Type::STR_HEX, "chainid",
                     /* optional */ true,
                     "The 32-byte Lotus V2 ChainId in consensus byte order"},
                    {RPCResult::Type::STR_HEX, "v2target",
                     /* optional */ true,
                     "The 32-byte difficulty target in consensus little-endian "
                     "byte order"},
                    {RPCResult::Type::NUM, "blocksize",
                     /* optional */ true,
                     "The exact serialized block size in bytes for the "
                     "template coinbase"},
                    {RPCResult::Type::ARR,
                     "transactions",
                     /* optional */ true,
                     "contents of non-coinbase transactions that should be "
                     "included in the next block (omitted in compact_template "
                     "mode)",
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
            std::set<std::string> setClientRules;
            CTxOut coinbase_output;
            bool has_custom_miner_address = false;
            BlockAssembler::Options gbt_options =
                MiningRpcOptions(NullUniValue, chainman.GetConsensus());
            if (!request.params[0].isNull()) {
                const UniValue &oparam = request.params[0].get_obj();
                const UniValue &cb_version_val =
                    oparam.find_value("coinbase_version");
                if (!cb_version_val.isNull()) {
                    gbt_options = MiningRpcOptions(cb_version_val,
                                                   chainman.GetConsensus());
                }
                const UniValue &modeval = oparam.find_value("mode");
                if (modeval.isStr()) {
                    strMode = modeval.get_str();
                } else if (modeval.isNull()) {
                    /* Do nothing */
                } else {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
                }
                lpval = oparam.find_value("longpollid");
                const UniValue &mineraddr_val =
                    oparam.find_value("mineraddress");
                if (mineraddr_val.isStr()) {
                    coinbase_output = CoinbaseDestination(
                        mineraddr_val.get_str(), chainparams,
                        gbt_options.coinbase_version);
                    has_custom_miner_address = true;
                } else if (!mineraddr_val.isNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       "Invalid mineraddress");
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
                    // TestBlockValidity only supports blocks built on the
                    // current Tip
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
            if (!has_custom_miner_address) {
                coinbase_output =
                    gbt_options.coinbase_version == 7
                        ? OpTrueOutput(Amount::zero())
                        : CTxOut(Amount::zero(), CScript() << OP_TRUE);
            }
            const bool compact_template = (strMode == "compact_template");

            if (node.connman &&
                node.connman->GetNodeCount(ConnectionDirection::Both) == 0 &&
                !argsman.GetBoolArg("-gbtwithoutpeers", false)) {
                throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED,
                                   "Bitcoin is not connected!");
            }

            if (chainman.IsInitialBlockDownload()) {
                throw JSONRPCError(
                    RPC_CLIENT_IN_INITIAL_DOWNLOAD, PACKAGE_NAME
                    " is in initial sync and waiting for blocks...");
            }

            static unsigned int nTransactionsUpdatedLast;
            const CTxMemPool &mempool = EnsureMemPool(node);

            const Consensus::Params &consensusParams =
                chainparams.GetConsensus();

            node::SnapshotPublisher &publisher =
                node.snapshot_publisher ? *node.snapshot_publisher
                                        : node::GetGlobalSnapshotPublisher();

            if (!lpval.isNull()) {
                // Wait to respond until either the best block changes, OR a
                // minute has passed and there are more transactions
                uint256 hashWatchedChain;
                std::chrono::steady_clock::time_point checktxtime;
                unsigned int nTransactionsUpdatedLastLP;

                if (lpval.isStr()) {
                    // Format: <hashBestChain><nTransactionsUpdatedLast>
                    const std::string &lpstr = lpval.get_str();

                    hashWatchedChain =
                        ParseHashV(lpstr.substr(0, 64), "longpollid");
                    nTransactionsUpdatedLastLP =
                        LocaleIndependentAtoi<int64_t>(lpstr.substr(64));
                } else {
                    // NOTE: Spec does not specify behaviour for non-string
                    // longpollid, but this makes testing easier
                    auto lp_snap = publisher.Load();
                    if (lp_snap && lp_snap->chain_valid &&
                        lp_snap->chainman_ptr == &chainman) {
                        hashWatchedChain = lp_snap->best_block_hash;
                        nTransactionsUpdatedLastLP =
                            lp_snap->transactions_updated;
                    } else {
                        LOCK(cs_main);
                        hashWatchedChain =
                            chainman.ActiveChain().Tip()->GetBlockHash();
                        nTransactionsUpdatedLastLP = nTransactionsUpdatedLast;
                    }
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
                        executor, checktxtime, [&hashWatchedChain]() {
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

                    // Timeout: Check transactions for update without holding
                    // the mempool lock to avoid deadlocks.
                    if (mempool.GetTransactionsUpdated() !=
                        nTransactionsUpdatedLastLP) {
                        break;
                    }
                    checktxtime += newTxCheckLongpollDelay;
                }

                {
                    LOCK(g_best_block_mutex);
                    if (node.avalanche && IsStakingRewardsActivated(
                                              consensusParams, g_best_block)) {
                        // At this point the staking reward winner might not be
                        // computed yet. Make sure we don't miss the staking
                        // reward winner on first return of getblocktemplate
                        // after a block is found when using longpoll.
                        // Note that if the computation was done already this is
                        // a no-op. It can only be done now because we're not
                        // holding cs_main, which would cause a lock order issue
                        // otherwise.
                        node.avalanche->computeStakingReward(g_best_block);
                    }
                }

                if (!IsRPCRunning()) {
                    throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED,
                                       "Shutting down");
                }
                // TODO: Maybe recheck connections/IBD and (if something wrong)
                // send an expires-immediately template to stop miners?
            }

            const int64_t configured_block_version =
                chainparams.MineBlocksOnDemand()
                    ? gArgs.GetIntArg("-blockversion",
                                      lotus::v2::kHeaderVersion)
                    : lotus::v2::kHeaderVersion;
            const bool avalanche_preconsensus_mining =
                node.avalanche &&
                argsman.GetBoolArg(
                    "-avalanchepreconsensusmining",
                    DEFAULT_AVALANCHE_MINING_PRECONSENSUS) &&
                node.avalanche->isPreconsensusActivated(nullptr);

            auto snap = publisher.Load();
            if ((!snap || !snap->chain_valid ||
                 snap->chainman_ptr != &chainman ||
                 !snap->mining_template.template_valid) &&
                configured_block_version == lotus::v2::kHeaderVersion &&
                !avalanche_preconsensus_mining) {
                LOCK(cs_main);
                node::PublishChainTipSnapshot(chainman, &mempool);
                snap = publisher.Load();
            }

            if (snap && snap->chain_valid &&
                snap->chainman_ptr == &chainman &&
                snap->mining_template.template_valid &&
                configured_block_version == lotus::v2::kHeaderVersion &&
                !avalanche_preconsensus_mining) {
                snap->EnsureMiningTemplate();
                const node::MiningTemplateSnapshot &tmpl =
                    snap->mining_template;
                const int64_t adjustedTime =
                    TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
                const int64_t curtime =
                    std::max<int64_t>(tmpl.min_time, adjustedTime);
                uint32_t nBits = tmpl.nBits;
                if (!consensusParams.fPowNoRetargeting &&
                    consensusParams.fPowAllowMinDifficultyBlocks &&
                    snap->height >= 1 &&
                    curtime >
                        snap->time + 2 * consensusParams.nPowTargetSpacing) {
                    nBits = UintToArith256(consensusParams.powLimit).GetCompact();
                }
                const Amount coinbasevalue = tmpl.block_reward;

                CMutableTransaction coinbaseTx = node::CreateCoinbaseShell(
                    gbt_options.coinbase_version, tmpl.prev_block_hash,
                    int(tmpl.next_height));
                coinbaseTx.vout.resize(1);
                coinbaseTx.vout[0] = coinbase_output;
                coinbaseTx.vout[0].nValue = coinbasevalue;

                const auto minerFundWhitelist =
                    GetMinerFundWhitelist(consensusParams);
                const Amount minerFundAmount =
                    !minerFundWhitelist.empty()
                        ? GetMinerFundAmount(consensusParams, coinbasevalue,
                                             nullptr)
                        : Amount::zero();
                const int64_t minerFundMinValue =
                    int64_t(minerFundAmount / SATOSHI);
                if (!minerFundWhitelist.empty()) {
                    coinbaseTx.vout[0].nValue -= minerFundAmount;
                    coinbaseTx.vout.emplace_back(
                        minerFundAmount,
                        GetScriptForDestination(*minerFundWhitelist.begin()));
                }

                std::vector<CScript> stakingRewardsPayoutScripts;
                const Amount stakingRewardsAmountVal =
                    GetStakingRewardsAmount(coinbasevalue);
                const int64_t stakingRewardsAmount =
                    stakingRewardsAmountVal / SATOSHI;
                if (node.avalanche &&
                    gArgs.GetBoolArg("-avalanchestakingrewards",
                                     consensusParams.enableStakingRewards)) {
                    if (node.avalanche->getStakingRewardWinners(
                            tmpl.prev_block_hash,
                            stakingRewardsPayoutScripts) &&
                        !stakingRewardsPayoutScripts.empty()) {
                        coinbaseTx.vout[0].nValue -= stakingRewardsAmountVal;
                        coinbaseTx.vout.emplace_back(
                            stakingRewardsAmountVal,
                            stakingRewardsPayoutScripts[0]);
                    } else {
                        stakingRewardsPayoutScripts.clear();
                    }
                }

                node::SetCoinbaseOutputs(coinbaseTx,
                                         std::vector<CTxOut>(coinbaseTx.vout));
                node::PadCoinbaseToMinSize(coinbaseTx);
                const uint64_t coinbaseSize = ::GetSerializeSize(coinbaseTx);
                const CTransaction coinbaseConst(coinbaseTx);

                // Compute merkle root in 2 BLAKE3 hashes from pre-computed
                // Subtree A root (resolved lazily on the snapshot if needed).
                tmpl.EnsureRoots();
                lotus::v2::TxIdentityPair cb_pair{};
                const uint256 cb_hash = coinbaseConst.GetHash();
                const TxId cb_id = coinbaseConst.GetId();
                std::memcpy(cb_pair.tx_hash.data(), cb_hash.begin(), 32);
                std::memcpy(cb_pair.tx_id.data(), cb_id.begin(), 32);
                const lotus::v2::Hash merkle_root_bytes =
                    lotus::v2::TransactionRootFromSubtreeA(cb_pair,
                                                           tmpl.subtree_a_root);
                uint256 hashMerkleRoot;
                std::memcpy(hashMerkleRoot.begin(), merkle_root_bytes.data(),
                            32);
                uint256 hashSubtreeARoot;
                std::memcpy(hashSubtreeARoot.begin(),
                            tmpl.subtree_a_root.data(), 32);

                // Compute state root in ~27 BLAKE3 hashes from pre-computed
                // UTXO root and effective cost sum.
                const uint256 hashStateRoot = ComputeV2StateRootFromTemplate(
                    tmpl.v2_base_state, coinbaseConst, nBits);

                const uint64_t blocksize =
                    lotus::v2::HEADER_SIZE +
                    GetSizeOfCompactSize(1 + tmpl.non_coinbase_txs.size()) +
                    coinbaseSize + tmpl.non_cb_serialized_size;
                CBlockHeader candidate_header;
                candidate_header.hashPrevBlock = tmpl.prev_block_hash;
                candidate_header.nBits = nBits;
                candidate_header.SetBlockTime(static_cast<uint64_t>(curtime));
                candidate_header.nNonce = 0;
                candidate_header.nHeaderVersion = tmpl.nHeaderVersion;
                candidate_header.SetSize(blocksize);
                candidate_header.nHeight =
                    static_cast<uint64_t>(tmpl.next_height);
                candidate_header.hashMerkleRoot = hashMerkleRoot;
                candidate_header.hashStateRoot = hashStateRoot;
                // Overlay membership authenticates neither scripts nor input
                // provenance. Validate the pinned selection once; warm reads
                // retain the native cached-root path without writer locks.
                {
                    std::lock_guard<std::mutex> validation_lock(*tmpl.validation_mutex);
                    if (!tmpl.validated) {
                        CBlock candidate(candidate_header);
                        candidate.vtx.push_back(MakeTransactionRef(coinbaseTx));
                        candidate.vtx.insert(candidate.vtx.end(),
                            tmpl.non_coinbase_txs.begin(), tmpl.non_coinbase_txs.end());
                        LOCK(cs_main);
                        auto &chainstate = chainman.ActiveChainstate();
                        auto *tip = chainstate.m_chain.Tip();
                        if (!tip || tip->GetBlockHash() != tmpl.prev_block_hash) {
                            throw JSONRPCError(RPC_VERIFY_ERROR,
                                               "Template parent changed during "
                                               "assembly; retry");
                        }
                        BlockValidationState state;
                        if (!TestBlockValidity(state, chainparams, chainstate, candidate,
                                tip, GetAdjustedTime,
                                BlockValidationOptions(config).withCheckPoW(false)
                                                              .withCheckMerkleRoot(true))) {
                            throw JSONRPCError(RPC_VERIFY_ERROR, "getblocktemplate: " + state.ToString());
                        }
                        tmpl.validated = true;
                    }
                }
                DataStream ss_header{};
                ss_header << candidate_header;
                lotus::v2::Hash pow_limit_bytes{};
                std::memcpy(pow_limit_bytes.data(),
                            consensusParams.powLimit.begin(), 32);
                lotus::v2::Hash v2_target_bytes{};
                lotus::v2::DecodeTarget(nBits, pow_limit_bytes,
                                        v2_target_bytes);

                BlockAssembler::m_last_block_num_txs =
                    int64_t(tmpl.non_coinbase_txs.size());
                BlockAssembler::m_last_block_size =
                    int64_t(1000 + tmpl.non_cb_serialized_size);
                nTransactionsUpdatedLast = snap->transactions_updated;

                UniValue aCaps(UniValue::VARR);
                aCaps.push_back("proposal");

                UniValue transactions(UniValue::VARR);
                if (!compact_template) {
                    const auto &tx_hex_vec = tmpl.EnsureTxHex();
                    transactions.reserve(tmpl.non_coinbase_txs.size());
                    for (size_t i = 0; i < tmpl.non_coinbase_txs.size(); ++i) {
                        const CTransaction &tx = *tmpl.non_coinbase_txs[i];
                        UniValue entry(UniValue::VOBJ);
                        entry.reserve(5);
                        entry.pushKVEnd("data", tx_hex_vec[i]);
                        entry.pushKVEnd("txid", tx.GetId().GetHex());
                        entry.pushKVEnd("hash", tx.GetHash().GetHex());
                        entry.pushKVEnd("fee", tmpl.tx_fees[i] / SATOSHI);
                        entry.pushKVEnd("sigchecks", tmpl.tx_sigchecks[i]);
                        transactions.push_back(std::move(entry));
                    }
                }

                const bool simplifyGbt =
                    argsman.GetBoolArg("-simplegbt", false);
                UniValue result(UniValue::VOBJ);
                UniValue aux(UniValue::VOBJ);
                UniValue coinbasetxn(UniValue::VOBJ);

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

                arith_uint256 hashTarget = arith_uint256().SetCompact(nBits);

                UniValue aMutable(UniValue::VARR);
                aMutable.push_back("time");
                aMutable.push_back("transactions");
                aMutable.push_back("prevblock");

                result.pushKV("capabilities", std::move(aCaps));
                result.pushKV("version", uint64_t(tmpl.nHeaderVersion));
                result.pushKV("previousblockhash",
                              tmpl.prev_block_hash.GetHex());
                result.pushKV("templateid", tmpl.template_id);
                result.pushKV("subtreearoot", hashSubtreeARoot.GetHex());
                result.pushKV("merkleroot", hashMerkleRoot.GetHex());
                result.pushKV("stateroot", hashStateRoot.GetHex());
                result.pushKV("headerhex", HexStr(ss_header));
                result.pushKV("coinbasetxhex", EncodeHexTx(coinbaseConst));
                result.pushKV("chainid", HexStr(GetActiveV2ChainId()));
                result.pushKV("v2target", HexStr(v2_target_bytes));
                result.pushKV("blocksize", blocksize);
                if (!compact_template) {
                    result.pushKV("transactions", std::move(transactions));
                }
                result.pushKV("coinbaseaux", std::move(aux));
                result.pushKV("coinbasetxn", std::move(coinbasetxn));
                result.pushKV("coinbasevalue",
                              int64_t(coinbasevalue / SATOSHI));
                result.pushKV("longpollid",
                              snap->best_block_hash.GetHex() +
                                  ToString(snap->transactions_updated));
                result.pushKV("target", hashTarget.GetHex());
                result.pushKV("mintime", tmpl.min_time);
                result.pushKV("mutable", std::move(aMutable));
                result.pushKV("noncerange", "00000000ffffffff");
                const uint64_t sigCheckLimit =
                    GetMaxBlockSigChecksCount(DEFAULT_MAX_BLOCK_SIZE);
                result.pushKV("sigchecklimit", sigCheckLimit);
                result.pushKV("sizelimit", DEFAULT_MAX_BLOCK_SIZE);
                result.pushKV("curtime", curtime);
                result.pushKV("bits", strprintf("%08x", nBits));
                result.pushKV("height", int64_t(tmpl.next_height));

                if (gArgs.GetBoolArg("-enablertt", DEFAULT_ENABLE_RTT)) {
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
            if (pindexPrev != active_chain.Tip() || has_custom_miner_address ||
                (pblocktemplate &&
                 uint32_t(pblocktemplate->block.vtx[0]->nVersion) !=
                     gbt_options.coinbase_version) ||
                (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast &&
                 GetTime() - time_start > 5)) {
                // Clear pindexPrev so future calls make a new block, despite
                // any failures from here on
                pindexPrev = nullptr;

                // Store the pindexBest used before CreateNewBlock, to avoid
                // races
                nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
                CBlockIndex *pindexPrevNew = active_chain.Tip();
                time_start = GetTime();

                // Create new block
                pblocktemplate =
                    BlockAssembler{BlockFitter(config), active_chainstate,
                                   &mempool, gbt_options, node.avalanche.get()}
                        .CreateNewBlock(coinbase_output);
                if (!pblocktemplate) {
                    throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
                }

                // Need to update only after we know CreateNewBlock succeeded
                pindexPrev = pindexPrevNew;
            }

            CHECK_NONFATAL(pindexPrev);
            // pointer for convenience
            CBlock *pblock = &pblocktemplate->block;

            // Update nTime
            int64_t adjustedTime =
                TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
            UpdateTime(pblock, chainparams, pindexPrev, adjustedTime);
            pblock->nNonce = 0;
            pblock->SetSize(GetSerializeSize(*pblock));
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
            pblock->hashStateRoot = ComputeV2BlockStateRoot(
                *pblock, pindexPrev->GetBlockHash(), pblock->nHeight,
                uint64_t(pindexPrev->GetMedianTimePast()), false);

            node::MiningTemplateSnapshot fallback_tmpl{};
            fallback_tmpl.template_id = publisher.AllocateTemplateId();
            fallback_tmpl.prev_block_hash = pblock->hashPrevBlock;
            fallback_tmpl.next_height = int(pblock->nHeight);
            fallback_tmpl.nHeaderVersion = pblock->nHeaderVersion;
            fallback_tmpl.nBits = pblock->nBits;
            fallback_tmpl.parent_mtp = pindexPrev->GetMedianTimePast();
            fallback_tmpl.min_time = fallback_tmpl.parent_mtp + 1;
            std::vector<lotus::v2::TxIdentityPair> id_pairs;
            if (pblock->vtx.size() > 1) {
                id_pairs.reserve(pblock->vtx.size() - 1);
                fallback_tmpl.non_coinbase_txs.reserve(pblock->vtx.size() - 1);
                for (size_t i = 1; i < pblock->vtx.size(); ++i) {
                    fallback_tmpl.non_coinbase_txs.push_back(pblock->vtx[i]);
                    lotus::v2::TxIdentityPair pair{};
                    std::memcpy(pair.tx_hash.data(),
                                pblock->vtx[i]->GetHash().begin(), 32);
                    std::memcpy(pair.tx_id.data(),
                                pblock->vtx[i]->GetId().begin(), 32);
                    id_pairs.push_back(pair);
                }
            }
            fallback_tmpl.subtree_a_root =
                lotus::v2::TransactionSubtreeARoot(id_pairs);
            fallback_tmpl.template_valid = true;
            publisher.RecordMiningTemplate(fallback_tmpl);
            uint256 hashSubtreeARoot;
            std::memcpy(hashSubtreeARoot.begin(),
                        fallback_tmpl.subtree_a_root.data(), 32);

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
                    entry.pushKVEnd("fee", pblocktemplate
                                               ->entries[index_in_template]
                                               .fees /
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

            // Compute the miner fund parameters
            const auto minerFundWhitelist =
                GetMinerFundWhitelist(consensusParams);
            int64_t minerFundMinValue =
                int64_t(GetMinerFundAmount(consensusParams, coinbasevalue,
                                           pindexPrev) /
                        SATOSHI);

            // Compute the staking reward parameters
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

            DataStream ss_fallback_header{};
            ss_fallback_header << pblock->GetBlockHeader();
            lotus::v2::Hash pow_limit_bytes{};
            std::memcpy(pow_limit_bytes.data(),
                        consensusParams.powLimit.begin(), 32);
            lotus::v2::Hash v2_target_bytes{};
            lotus::v2::DecodeTarget(pblock->nBits, pow_limit_bytes,
                                    v2_target_bytes);

            result.pushKV("capabilities", std::move(aCaps));

            result.pushKV("version", uint64_t(pblock->nHeaderVersion));

            result.pushKV("previousblockhash", pblock->hashPrevBlock.GetHex());
            result.pushKV("templateid", fallback_tmpl.template_id);
            result.pushKV("subtreearoot", hashSubtreeARoot.GetHex());
            result.pushKV("merkleroot", pblock->hashMerkleRoot.GetHex());
            result.pushKV("stateroot", pblock->hashStateRoot.GetHex());
            result.pushKV("headerhex", HexStr(ss_fallback_header));
            if (!pblock->vtx.empty()) {
                result.pushKV("coinbasetxhex", EncodeHexTx(*pblock->vtx[0]));
            }
            result.pushKV("chainid", HexStr(GetActiveV2ChainId()));
            result.pushKV("v2target", HexStr(v2_target_bytes));
            result.pushKV("blocksize", pblock->GetSize());
            if (!compact_template) {
                result.pushKV("transactions", std::move(transactions));
            }
            result.pushKV("coinbaseaux", std::move(aux));
            result.pushKV("coinbasetxn", std::move(coinbasetxn));
            result.pushKV("coinbasevalue", int64_t(coinbasevalue / SATOSHI));
            result.pushKV("longpollid",
                          active_chain.Tip()->GetBlockHash().GetHex() +
                              ToString(nTransactionsUpdatedLast));
            result.pushKV("target", hashTarget.GetHex());
            result.pushKV("mintime",
                          int64_t(pindexPrev->GetMedianTimePast()) + 1);
            result.pushKV("mutable", std::move(aMutable));
            result.pushKV("noncerange", "00000000ffffffff");
            const uint64_t sigCheckLimit =
                GetMaxBlockSigChecksCount(DEFAULT_MAX_BLOCK_SIZE);
            result.pushKV("sigchecklimit", sigCheckLimit);
            result.pushKV("sizelimit", DEFAULT_MAX_BLOCK_SIZE);
            result.pushKV("curtime", pblock->GetBlockTime());
            result.pushKV("bits", strprintf("%08x", pblock->nBits));
            result.pushKV("height", int64_t(pindexPrev->nHeight) + 1);

            if (isRTTEnabled(consensusParams, pindexPrev)) {
                // Compute the target for RTT
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

                // Let the miner recompute RTT on their end if they want to do
                // so
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

static UniValue SubmitSealedBlockImpl(const Config &config,
                                      const JSONRPCRequest &request) {
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
                           "Block does not start with a coinbase");
    }

    uint64_t template_id = 0;
    if (!request.params[2].isNull()) {
        const int64_t raw_id = request.params[2].getInt<int64_t>();
        if (raw_id < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid templateid");
        }
        template_id = static_cast<uint64_t>(raw_id);
    }

    NodeContext &node = EnsureAnyNodeContext(request.context);
    ChainstateManager &chainman = EnsureChainman(node);
    node::SnapshotPublisher &publisher =
        node.snapshot_publisher ? *node.snapshot_publisher
                                : node::GetGlobalSnapshotPublisher();

    auto tmpl_opt =
        publisher.FindMiningTemplate(template_id, header.hashPrevBlock);
    if (!tmpl_opt) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Mining template not found");
    }
    if (header.hashPrevBlock != tmpl_opt->prev_block_hash ||
        header.nHeight != uint64_t(tmpl_opt->next_height)) {
        return "template-prevblock-mismatch";
    }

    auto blockptr = std::make_shared<CBlock>(header);
    CBlock &block = *blockptr;
    block.vtx.reserve(1 + tmpl_opt->non_coinbase_txs.size());
    block.vtx.push_back(std::move(coinbase_tx));
    block.vtx.insert(block.vtx.end(), tmpl_opt->non_coinbase_txs.begin(),
                     tmpl_opt->non_coinbase_txs.end());
    const TxId &cb_txid = block.vtx[0]->GetId();
    const auto lb = std::lower_bound(
        tmpl_opt->non_coinbase_txs.begin(), tmpl_opt->non_coinbase_txs.end(),
        cb_txid, [](const CTransactionRef &a, const TxId &b) {
            return a->GetId() < b;
        });
    const bool cb_collides =
        (lb != tmpl_opt->non_coinbase_txs.end() && (*lb)->GetId() == cb_txid);
    if (!cb_collides &&
        ComputeV2TxRootFromSubtreeA(*block.vtx[0], tmpl_opt->subtree_a_root) ==
            block.hashMerkleRoot) {
        block.m_checked_merkle_root = true;
    }

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

    CHECK_NONFATAL(chainman.m_options.signals)
        ->SyncWithValidationInterfaceQueue();

    return BIP22ValidationResult(config, sc->state);
}

static RPCHelpMan MakeSubmitSealedBlockHelpMan(const char *method_name) {
    return RPCHelpMan{
        method_name,
        "Reconstructs a full block from a solved 134-byte header, coinbase "
        "transaction, and cached template transactions, then submits it to the "
        "network.\n",
        {
            {"hexheader", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "the hex-encoded solved block header (134 bytes, or 160 bytes "
             "with trailing padding)"},
            {"hexcoinbasetx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "the hex-encoded coinbase transaction (vtx[0])"},
            {"templateid", RPCArg::Type::NUM, RPCArg::Default{0},
             "the template identifier returned by getblocktemplate (0 for "
             "latest matching template)"},
        },
        {
            RPCResult{"If the block was accepted", RPCResult::Type::NONE, "",
                      ""},
            RPCResult{"Otherwise", RPCResult::Type::STR, "",
                      "According to BIP22"},
        },
        RPCExamples{HelpExampleCli(method_name,
                                   "\"hexheader\" \"hexcoinbasetx\" 1") +
                    HelpExampleRpc(method_name,
                                   "\"hexheader\", \"hexcoinbasetx\", 1")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            return SubmitSealedBlockImpl(config, request);
        },
    };
}

static RPCHelpMan submitminedheader() {
    return MakeSubmitSealedBlockHelpMan("submitminedheader");
}

static RPCHelpMan submitsealedheader() {
    return MakeSubmitSealedBlockHelpMan("submitsealedheader");
}

static RPCHelpMan submitsealedblock() {
    return MakeSubmitSealedBlockHelpMan("submitsealedblock");
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

static RPCHelpMan getrawunsolvedblock() {
    return RPCHelpMan{
        "getrawunsolvedblock",
        "Get a serialized block candidate with coinbase sending to the "
        "specified address",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The address to send the newly generated coins to."},
        },
        RPCResult{
            RPCResult::Type::OBJ,
            "",
            "",
            {
                {RPCResult::Type::STR_HEX, "blockhex",
                 "Serialized block as hex."},
                {RPCResult::Type::STR_HEX, "target", "The difficulty target."},
            },
        },
        RPCExamples{"\nCreate an unsolved block to myaddress\n" +
                    HelpExampleCli("getrawunsolvedblock", "\"myaddress\"") +
                    "If you are running the Lotus wallet, you can get a new "
                    "address to send the newly generated coins to with:\n" +
                    HelpExampleCli("getnewaddress", "")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            const CChainParams &chainparams = config.GetChainParams();
            const bool isTestnet = chainparams.IsTestChain();

            NodeContext &node = EnsureAnyNodeContext(request.context);
            const CConnman &connman = EnsureConnman(node);
            if (!isTestnet &&
                connman.GetNodeCount(ConnectionDirection::Both) == 0) {
                throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED,
                                   "Node is not connected!");
            }

            ChainstateManager &chainman = EnsureChainman(node);
            if (!isTestnet && chainman.IsInitialBlockDownload()) {
                throw JSONRPCError(
                    RPC_CLIENT_IN_INITIAL_DOWNLOAD, PACKAGE_NAME
                    " is in initial sync and waiting for blocks...");
            }

            LOCK(cs_main);
            const CTxMemPool &mempool = EnsureMemPool(node);
            Chainstate &active_chainstate = chainman.ActiveChainstate();
            CChain &active_chain = active_chainstate.m_chain;

            CBlockIndex *pindexPrevNew = active_chain.Tip();

            const auto options =
                MiningRpcOptions(NullUniValue, chainman.GetConsensus());
            const CTxOut coinbase_output =
                CoinbaseDestination(request.params[0].get_str(), chainparams,
                                    options.coinbase_version);
            std::unique_ptr<CBlockTemplate> pblocktemplate =
                BlockAssembler{BlockFitter(config), active_chainstate, &mempool,
                               options, node.avalanche.get()}
                    .CreateNewBlock(coinbase_output);
            if (!pblocktemplate) {
                throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
            }

            CHECK_NONFATAL(pindexPrevNew);

            CBlock *pblock = &pblocktemplate->block;
            int64_t adjustedTime =
                TicksSinceEpoch<std::chrono::seconds>(GetAdjustedTime());
            UpdateTime(pblock, chainparams, pindexPrevNew, adjustedTime);
            pblock->nNonce = 0;
            pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
            pblock->hashStateRoot = ComputeV2BlockStateRoot(
                *pblock, pindexPrevNew->GetBlockHash(), pblock->nHeight,
                uint64_t(pindexPrevNew->GetMedianTimePast()), false);
            pblock->SetSize(GetSerializeSize(*pblock));

            DataStream ssBlock{};
            ssBlock << *pblock;
            arith_uint256 hashTarget =
                arith_uint256().SetCompact(pblock->nBits);
            UniValue result(UniValue::VOBJ);
            result.pushKV("blockhex", HexStr(ssBlock));
            result.pushKV("target", hashTarget.GetHex());
            return result;
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

static bool ParsePoolUint64Param(const UniValue &val, uint64_t &out) {
    if (val.isNum()) {
        out = val.getInt<uint64_t>();
        return true;
    }
    if (!val.isStr()) {
        return false;
    }
    std::string s = val.get_str();
    if (s.empty()) {
        return false;
    }
    int base = 10;
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) {
        s = s.substr(2);
        base = 16;
    } else {
        for (char c : s) {
            if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                base = 16;
                break;
            }
        }
    }
    char *endptr = nullptr;
    errno = 0;
    const unsigned long long parsed =
        std::strtoull(s.c_str(), &endptr, base);
    if (errno != 0 || endptr == s.c_str() || *endptr != '\0') {
        return false;
    }
    out = static_cast<uint64_t>(parsed);
    return true;
}

static std::shared_ptr<node::MiningPoolManager>
EnsureMiningPool(NodeContext &node) {
    if (node.args &&
        !node.args->GetBoolArg("-miningpool",
                               lotus::v2::node::DEFAULT_MINING_POOL_ENABLED)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Built-in mining pool is disabled");
    }
    auto pool = node::GetMiningPool(node);
    if (!pool || !pool->IsEnabled()) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "Built-in mining pool is unavailable");
    }
    return pool;
}

static RPCHelpMan getminingjob() {
    return RPCHelpMan{
        "getminingjob",
        "Returns a Lotus V2 134-byte header mining job from the built-in PPLNS "
        "mining pool.\n",
        {
            {"worker_id", RPCArg::Type::STR, RPCArg::Default{"default"},
             "Worker identifier (native address, symbolic label, or sub:<user>)"},
            {"longpoll", RPCArg::Type::BOOL, RPCArg::Default{false},
             "Wait for the next block tip change before returning"},
        },
        RPCResult{RPCResult::Type::ANY, "", "Mining job JSON object"},
        RPCExamples{HelpExampleCli("getminingjob", "\"sub:alice\"") +
                    HelpExampleRpc("getminingjob", "\"sub:alice\", false")},
        [](const RPCHelpMan &self, const Config &config,
           const JSONRPCRequest &request,
           boost::asio::any_io_executor executor)
            -> boost::asio::awaitable<UniValue> {
            NodeContext &node = EnsureAnyNodeContext(request.context);
            auto pool = EnsureMiningPool(node);
            const std::string worker_id =
                request.params[0].isNull() ? "default"
                                           : request.params[0].get_str();
            const bool longpoll =
                !request.params[1].isNull() && request.params[1].get_bool();

            if (longpoll && node.chainman) {
                BlockHash watched_tip;
                {
                    LOCK(cs_main);
                    if (const CBlockIndex *tip = node.chainman->ActiveTip()) {
                        watched_tip = tip->GetBlockHash();
                    }
                }
                const auto deadline =
                    std::chrono::steady_clock::now() +
                    std::chrono::seconds(15);
                co_await GetRPCBlockChangeWaiter().WaitUntilDeadline(
                    executor, deadline, [&node, &watched_tip]() {
                        LOCK(cs_main);
                        const CBlockIndex *tip =
                            node.chainman ? node.chainman->ActiveTip()
                                          : nullptr;
                        return !tip || tip->GetBlockHash() != watched_tip ||
                               !IsRPCRunning();
                    });
            }

            co_return pool->GetMiningJobJSON(config, node, worker_id);
        },
    };
}

static RPCHelpMan submitminingshare() {
    return RPCHelpMan{
        "submitminingshare",
        "Submits a mined share to the built-in Lotus V2 PPLNS mining pool.\n",
        {
            {"job_id", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The job identifier returned by getminingjob",
             RPCArgOptions{.skip_type_check = true}},
            {"worker_id", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The worker identifier"},
            {"nonce", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "The 64-bit nonce (integer or hex string)",
             RPCArgOptions{.skip_type_check = true}},
            {"ntime", RPCArg::Type::NUM, RPCArg::Optional::OMITTED,
             "Optional 64-bit block timestamp",
             RPCArgOptions{.skip_type_check = true}},
        },
        RPCResult{RPCResult::Type::ANY, "", "Share validation result"},
        RPCExamples{
            HelpExampleCli("submitminingshare", "\"1\" \"sub:alice\" 12345") +
            HelpExampleRpc("submitminingshare", "\"1\", \"sub:alice\", 12345")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            NodeContext &node = EnsureAnyNodeContext(request.context);
            auto pool = EnsureMiningPool(node);

            uint64_t job_id = 0;
            if (!ParsePoolUint64Param(request.params[0], job_id)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid job_id");
            }
            const std::string worker_id = request.params[1].get_str();
            uint64_t nonce = 0;
            if (!ParsePoolUint64Param(request.params[2], nonce)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid nonce");
            }
            std::optional<uint64_t> ntime_opt;
            if (!request.params[3].isNull()) {
                uint64_t parsed_time = 0;
                if (!ParsePoolUint64Param(request.params[3], parsed_time)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid ntime");
                }
                ntime_opt = parsed_time;
            }

            const auto res = pool->SubmitShare(config, node, job_id, worker_id,
                                               ntime_opt, nonce);
            return res.ToUniValue();
        },
    };
}

static RPCHelpMan getpoolinfo() {
    return RPCHelpMan{
        "getpoolinfo",
        "Returns summary statistics for the built-in Lotus V2 PPLNS mining "
        "pool.\n",
        {},
        RPCResult{RPCResult::Type::ANY, "", "Pool info JSON object"},
        RPCExamples{HelpExampleCli("getpoolinfo", "") +
                    HelpExampleRpc("getpoolinfo", "")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            NodeContext &node = EnsureAnyNodeContext(request.context);
            auto pool = EnsureMiningPool(node);
            return pool->GetPoolInfoJSON();
        },
    };
}

static RPCHelpMan getpoolworker() {
    return RPCHelpMan{
        "getpoolworker",
        "Returns per-worker statistics and newsletter credits from the "
        "built-in Lotus V2 PPLNS mining pool.\n",
        {
            {"worker_id", RPCArg::Type::STR, RPCArg::Optional::NO,
             "The worker identifier (Lotus address, script hex, or sub:<user>)"},
        },
        RPCResult{RPCResult::Type::ANY, "", "Worker statistics JSON object"},
        RPCExamples{HelpExampleCli("getpoolworker", "\"sub:alice\"") +
                    HelpExampleRpc("getpoolworker", "\"sub:alice\"")},
        [&](const RPCHelpMan &self, const Config &config,
            const JSONRPCRequest &request) -> UniValue {
            NodeContext &node = EnsureAnyNodeContext(request.context);
            auto pool = EnsureMiningPool(node);
            return pool->GetWorkerStatsJSON(request.params[0].get_str());
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
        {"mining",      getrawunsolvedblock,   },
        {"mining",      submitblock,           },
        {"mining",      submitminedheader,     },
        {"mining",      submitsealedheader,    },
        {"mining",      submitsealedblock,     },
        {"mining",      submitheader,          },
        {"mining",      getminingjob,          },
        {"mining",      submitminingshare,     },
        {"mining",      getpoolinfo,           },
        {"mining",      getpoolworker,         },

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
