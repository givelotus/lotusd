// Copyright (c) 2022 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <blockindex.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <common/args.h>
#include <config.h>
#include <logging.h>
#include <lotus_v2/block_wire.h>
#include <lotus_v2/chronik_explorer.h>
#include <lotus_v2/header.h>
#include <lotus_v2/output.h>
#include <lotus_v2/tagged_hash.h>
#include <lotus_v2/transaction.h>
#include <node/context.h>
#include <node/metrics.h>
#include <node/ui_interface.h>
#include <primitives/block.h>
#include <script/script.h>
#include <util/chaintype.h>
#include <util/result.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>

#include <chronik-cpp/chronik.h>
#include <chronik-cpp/chronik_bridge.h>
#include <chronik-cpp/chronik_inprocess.h>
#include <chronik-cpp/chronik_validationinterface.h>
#include <chronik_lib/src/ffi.rs.h>
#include <chronik_lib/src/v2_ffi.rs.h>

#include <tinyformat.h>

#include <cstring>
#include <limits>
#include <span>

namespace chronik {

// Duration between WebSocket pings initiated by Chronik.
// 45s has been empirically established as a reliable duration for both browser
// and NodeJS WebSockets.
static constexpr std::chrono::seconds WS_PING_INTERVAL_DEFAULT{45s};

// Ping duration is just 5s on regtest to speed up ping tests and make
// functional tests more reliable.
static constexpr std::chrono::seconds WS_PING_INTERVAL_REGTEST{5s};

template <typename T, typename C> rust::Vec<T> ToRustVec(const C &container) {
    rust::Vec<T> vec;
    vec.reserve(container.size());
    std::copy(container.begin(), container.end(), std::back_inserter(vec));
    return vec;
}

chronik_bridge::Net ParseNet(const ChainType chain_type) {
    if (chain_type == ChainType::MAIN) {
        return chronik_bridge::Net::Mainnet;
    } else if (chain_type == ChainType::TESTNET) {
        return chronik_bridge::Net::Testnet;
    } else if (chain_type == ChainType::REGTEST) {
        return chronik_bridge::Net::Regtest;
    }
    throw std::runtime_error("Unknown chain type");
}

util::Result<chronik_bridge::SetupParams>
ParseChronikParams(const ArgsManager &args, const Config &config, bool fWipe) {
    const bool is_pause_allowed = args.GetBoolArg("-chronikallowpause", false);
    const CChainParams &params = config.GetChainParams();
    if (is_pause_allowed && !params.IsTestChain()) {
        return {{_("Using -chronikallowpause on a mainnet chain is not allowed "
                   "for security reasons.")}};
    }

    const auto electrum_hosts = args.GetArgs("-chronikelectrumbind");
    const bool is_scripthashindex_enabled =
        args.GetBoolArg("-chronikscripthashindex", !electrum_hosts.empty());
    if (!electrum_hosts.empty()) {
        if (args.IsArgSet("-chronikelectrumcert") ^
            args.IsArgSet("-chronikelectrumprivkey")) {
            return {{_("The -chronikelectrumcert and -chronikelectrumprivkey "
                       "options should both be set or unset.")}};
        }
        if (args.IsArgSet("-chronikscripthashindex") &&
            !is_scripthashindex_enabled) {
            return {{_("The -chronikelectrumbind option requires "
                       "-chronikscripthashindex to be true.")}};
        }
    }

    const int64_t electrum_max_history = args.GetIntArg(
        "-chronikelectrummaxhistory", DEFAULT_ELECTRUM_MAX_HISTORY);
    if (electrum_max_history < 1 ||
        electrum_max_history > std::numeric_limits<uint32_t>::max()) {
        return {{_(strprintf("The -chronikelectrummaxhistory value should be "
                             "within the range [1, %d].",
                             std::numeric_limits<uint32_t>::max())
                       .c_str())}};
    }

    const std::string donation_address =
        args.GetArg("-chronikelectrumdonationaddress", "");
    if (donation_address.length() > MAX_LENGTH_DONATION_ADDRESS) {
        return {
            {_(strprintf(
                   "The -chronikelectrumdonationaddress parameter must be at "
                   "most %u characters long.",
                   MAX_LENGTH_DONATION_ADDRESS)
                   .c_str())}};
    }

    const int64_t electrum_peers_validation_interval =
        args.GetIntArg("-chronikelectrumpeersvalidationinterval",
                       std::chrono::duration_cast<std::chrono::seconds>(
                           chronik::DEFAULT_ELECTRUM_PEER_VALIDATION_INTERVAL)
                           .count());
    if (electrum_peers_validation_interval < 0 ||
        electrum_peers_validation_interval >
            std::numeric_limits<uint32_t>::max()) {
        return {{_(strprintf("The -chronikelectrumpeersvalidationinterval "
                             "value should be within the range [0, %d]",
                             std::numeric_limits<uint32_t>::max())
                       .c_str())}};
    }

    const int64_t electrum_idle_timeout =
        args.GetIntArg("-chronikelectrumidletimeout",
                       std::chrono::duration_cast<std::chrono::seconds>(
                           chronik::DEFAULT_ELECTRUM_IDLE_TIMEOUT)
                           .count());
    if (electrum_idle_timeout < 0 ||
        electrum_idle_timeout > std::numeric_limits<uint32_t>::max()) {
        return {{_(strprintf("The -chronikelectrumidletimeout value should be "
                             "within the range [0, %d]",
                             std::numeric_limits<uint32_t>::max())
                       .c_str())}};
    }

    const int64_t max_subs =
        args.GetIntArg("-chronikmaxsubs", chronik::DEFAULT_MAX_SUBS);
    if (max_subs < 1 ||
        static_cast<uint64_t>(max_subs) > std::numeric_limits<size_t>::max()) {
        return {{_(strprintf("The -chronikmaxsubs value should be within the "
                             "range [1, %llu].",
                             static_cast<unsigned long long>(
                                 std::numeric_limits<size_t>::max()))
                       .c_str())}};
    }

    const int64_t max_subs_per_ip = args.GetIntArg(
        "-chronikmaxsubsperip", chronik::DEFAULT_MAX_SUBS_PER_IP);
    if (max_subs_per_ip < 1 || static_cast<uint64_t>(max_subs_per_ip) >
                                   std::numeric_limits<size_t>::max()) {
        return {
            {_(strprintf("The -chronikmaxsubsperip value should be within the "
                         "range [1, %llu].",
                         static_cast<unsigned long long>(
                             std::numeric_limits<size_t>::max()))
                   .c_str())}};
    }

    const int64_t subscription_max_script_size =
        args.GetIntArg("-chroniksubsmaxscriptsize",
                       chronik::DEFAULT_SUBSCRIPTION_MAX_SCRIPT_SIZE);
    if (subscription_max_script_size < 1 ||
        subscription_max_script_size > MAX_SCRIPT_SIZE) {
        return {{_(strprintf("The -chroniksubsmaxscriptsize value should "
                             "be within the range [1, %d].",
                             MAX_SCRIPT_SIZE)
                       .c_str())}};
    }

    const int64_t subscription_max_plugin_size =
        args.GetIntArg("-chroniksubsmaxpluginsize",
                       chronik::DEFAULT_SUBSCRIPTION_MAX_PLUGIN_SIZE);
    if (subscription_max_plugin_size < 1 ||
        subscription_max_plugin_size > 2 * MAX_SCRIPT_SIZE) {
        return {{_(strprintf("The -chroniksubsmaxpluginsize value should "
                             "be within the range [1, %d].",
                             2 * MAX_SCRIPT_SIZE)
                       .c_str())}};
    }

    // Lotus V2 nodes (recognised by their V2 output fields) do not index
    // SLP/ALP tokens (user decision 2026-10-19), as in the native Chronik:
    // the token index defaults to off and cannot be enabled.
    constexpr bool is_lotus_v2_node =
        requires(const CTxOut &output) { output.vBranches; };
    const bool enable_token_index =
        args.GetBoolArg("-chroniktokenindex", !is_lotus_v2_node);
    if (is_lotus_v2_node && enable_token_index) {
        return {{_("-chroniktokenindex=1 is not supported: Lotus V2 nodes do "
                   "not index SLP/ALP tokens. Remove it or use "
                   "-chroniktokenindex=0.")}};
    }

    return {{
        .net = ParseNet(params.GetChainType()),
        .datadir = args.GetDataDirBase().u8string(),
        .datadir_net = args.GetDataDirNet().u8string(),
        .hosts = ToRustVec<rust::String>(args.IsArgSet("-chronikbind")
                                             ? args.GetArgs("-chronikbind")
                                             : DEFAULT_BINDS),
        .default_port = BaseParams().ChronikPort(),
        .wipe_db = fWipe,
        .enable_token_index = enable_token_index,
        .enable_lokad_id_index = args.GetBoolArg("-chroniklokadidindex", true),
        .enable_scripthash_index = is_scripthashindex_enabled,
        .is_pause_allowed = is_pause_allowed,
        .enable_perf_stats = args.GetBoolArg("-chronikperfstats", false),
        .ws_ping_interval_secs =
            params.GetChainType() == ChainType::REGTEST
                ? uint64_t(count_seconds(WS_PING_INTERVAL_REGTEST))
                : uint64_t(count_seconds(WS_PING_INTERVAL_DEFAULT)),
        .enable_cors = args.GetBoolArg("-chronikcors", false),
        .tx_num_cache =
            {
                .num_buckets = (size_t)args.GetIntArg(
                    "-chroniktxnumcachebuckets", DEFAULT_TX_NUM_CACHE_BUCKETS),
                .bucket_size =
                    (size_t)args.GetIntArg("-chroniktxnumcachebucketsize",
                                           DEFAULT_TX_NUM_CACHE_BUCKET_SIZE),
            },
        .electrum_hosts = ToRustVec<rust::String>(electrum_hosts),
        .electrum_url = args.GetArg("-chronikelectrumurl", "127.0.0.1"),
        .electrum_default_port = BaseParams().ChronikElectrumPort(),
        .electrum_default_protocol = 's',
        .electrum_cert_path = args.GetArg("-chronikelectrumcert", ""),
        .electrum_privkey_path = args.GetArg("-chronikelectrumprivkey", ""),
        .electrum_max_history = static_cast<uint32_t>(electrum_max_history),
        .electrum_donation_address =
            args.GetArg("-chronikelectrumdonationaddress", ""),
        .electrum_peers_validation_interval =
            static_cast<uint32_t>(electrum_peers_validation_interval),
        .electrum_idle_timeout = static_cast<uint32_t>(electrum_idle_timeout),
        .max_subs = static_cast<size_t>(max_subs),
        .max_subs_per_ip = static_cast<size_t>(max_subs_per_ip),
        .subscription_max_script_size =
            static_cast<size_t>(subscription_max_script_size),
        .subscription_max_plugin_size =
            static_cast<size_t>(subscription_max_plugin_size),
    }};
}

bool Start(const ArgsManager &args, const Config &config,
           const node::NodeContext &node, bool fWipe) {
    util::Result<chronik_bridge::SetupParams> params =
        ParseChronikParams(args, config, fWipe);
    if (!params) {
        return InitError(ErrorString(params));
    }
    if (!chronik_bridge::setup_chronik(*params, node)) {
        return false;
    }
    // Chronik synced to the tip it found before indexing new blocks
    if (node.chainman) {
        node::SetChronikIndexedHeight(
            WITH_LOCK(::cs_main, return node.chainman->ActiveHeight()));
    }
    return true;
}

void Interrupt() {
    // Stop taking /chronik requests and close their WebSocket sessions first,
    // so none reaches Chronik's runtime while it shuts down.
    UnregisterChronikInProcess();
    InterruptChronikRequestHandlers();
}

void Stop() {
    LogPrintf("Stopping Chronik...\n");
    StopChronikValidationInterface();
}

} // namespace chronik

#include <chronik-cpp/util/hash.h>

namespace chronik_v2 {

Binding get_v2_binding(const chronik_bridge::ChronikBridge &) {
    const auto genesis_id =
        chronik::util::HashToArray(Params().GenesisBlock().GetHash());
    const auto chain_id = GetActiveV2ChainId();
    const auto profile_id =
        lotus::v2::TaggedHash(lotus::v2::HashDomain::HeaderBody, genesis_id);
    return Binding{
        .chain_id = chain_id,
        .genesis = genesis_id,
        .profile = profile_id,
    };
}

NativeBlock bridge_v2_native_block(const CBlock &block,
                                   const CBlockIndex &bindex) {
    if (bindex.nHeight < 0) {
        throw std::runtime_error("Block height cannot be negative");
    }
    const uint64_t height = static_cast<uint64_t>(bindex.nHeight);
    const Anchor anchor{
        .block_id = chronik::util::HashToArray(bindex.GetBlockHash()),
        .height = height,
    };
    const Anchor parent =
        height == 0
            ? anchor
            : Anchor{
                  .block_id = chronik::util::HashToArray(
                      bindex.pprev ? bindex.pprev->GetBlockHash() : BlockHash()),
                  .height = height - 1,
              };

    std::array<uint8_t, lotus::v2::HEADER_SIZE> header_wire{};
    lotus::v2::SerializeHeader(block.GetBlockHeader().ToV2Header(),
                               header_wire);
    if (height == 0) {
        std::fill_n(header_wire.begin(), 32, uint8_t{0});
    } else {
        std::copy_n(parent.block_id.begin(), 32, header_wire.begin());
    }
    for (size_t i = 0; i < 8; ++i) {
        header_wire[62 + i] = static_cast<uint8_t>((height >> (8 * i)) & 0xffU);
    }

    rust::Vec<NativeTx> transactions;
    transactions.reserve(block.vtx.size());
    for (size_t n = 0; n < block.vtx.size(); ++n) {
        const CTransaction &ctx = *block.vtx[n];
        lotus::v2::Transaction v2tx = ctx.ToV2Transaction();
        if (n == 0) {
            v2tx.lock = 0;
            if (v2tx.inputs.size() != 1) {
                v2tx.inputs.resize(1);
            }
            auto &cb_in = v2tx.inputs[0];
            cb_in.prev_txid.fill(0);
            cb_in.prev_index = std::numeric_limits<uint32_t>::max();
            cb_in.sequence = std::numeric_limits<uint32_t>::max();
            cb_in.flags = 2;
            cb_in.path_index = 0;
            cb_in.witnesses.clear();
            if (cb_in.coinbase_data.size() > 8192) {
                cb_in.coinbase_data.resize(8192);
            }
            if (cb_in.has_coinbase_data && cb_in.coinbase_data.empty()) {
                cb_in.has_coinbase_data = false;
            } else if (!cb_in.has_coinbase_data) {
                cb_in.coinbase_data.clear();
            }
            for (auto &out : v2tx.outputs) {
                out.flags &= static_cast<uint8_t>(~1U);
                out.token_id.fill(0);
            }
        } else {
            for (auto &in : v2tx.inputs) {
                in.has_coinbase_data = false;
                in.coinbase_data.clear();
                if (in.flags != 1 && in.flags != 3) {
                    in.flags = 1;
                }
                if (in.flags == 1) {
                    if (in.path_index >= lotus::v2::MAX_OUTPUT_PATHS) {
                        in.path_index = 0;
                    }
                    if (in.sequence != std::numeric_limits<uint32_t>::max() &&
                        (in.sequence & ~0x40ffffU) != 0) {
                        in.sequence = std::numeric_limits<uint32_t>::max();
                    }
                    if (in.witnesses.empty()) {
                        lotus::v2::BranchWitness w;
                        w.script = {0x4e};
                        in.witnesses.push_back(std::move(w));
                    } else if (in.witnesses.size() >
                               lotus::v2::MAX_OUTPUT_BRANCHES) {
                        in.witnesses.resize(lotus::v2::MAX_OUTPUT_BRANCHES);
                    }
                }
                for (auto &w : in.witnesses) {
                    if (w.script.size() >
                        lotus::v2::DefaultTxProfile.max_script_bytes) {
                        w.script.resize(
                            lotus::v2::DefaultTxProfile.max_script_bytes);
                    }
                }
            }
        }

        std::vector<uint8_t> tx_wire;
        std::string err;
        if (!lotus::v2::EncodeTransaction(v2tx, lotus::v2::DefaultTxProfile,
                                          tx_wire, err)) {
            throw std::runtime_error("V2 EncodeTransaction failed: " + err);
        }

        std::vector<uint8_t> fact_wire;
        std::vector<lotus::v2::ChronikFullInput> fact_inputs;
        if (!lotus::v2::MakeChronikExplorerFacts(
                v2tx, lotus::v2::DefaultTxProfile,
                std::span<const uint8_t>(tx_wire.data(), tx_wire.size()),
                fact_wire, fact_inputs, err)) {
            throw std::runtime_error("MakeChronikExplorerFacts failed: " + err);
        }

        rust::Vec<Input> spend_inputs;
        rust::Vec<NativeFullInput> full_inputs;
        full_inputs.reserve(fact_inputs.size());
        for (size_t i = 0; i < fact_inputs.size(); ++i) {
            const auto &fi = fact_inputs[i];
            if (fi.flags == 1) {
                spend_inputs.push_back(Input{
                    .txid = fi.prev_txid,
                    .out_idx = fi.prev_index,
                    .input_index = static_cast<uint32_t>(i),
                });
            }
            rust::Vec<NativeWitness> witnesses;
            witnesses.reserve(fi.witnesses.size());
            for (const auto &w : fi.witnesses) {
                witnesses.push_back(NativeWitness{
                    .script =
                        WireRange{
                            .offset = w.script.offset,
                            .length = w.script.length,
                        },
                    .siblings_table =
                        WireRange{
                            .offset = w.siblings_table.offset,
                            .length = w.siblings_table.length,
                        },
                    .siblings_count = w.siblings_count,
                    .arguments_table =
                        WireRange{
                            .offset = w.arguments_table.offset,
                            .length = w.arguments_table.length,
                        },
                    .arguments_count = w.arguments_count,
                });
            }
            full_inputs.push_back(NativeFullInput{
                .prev_txid = fi.prev_txid,
                .prev_index = fi.prev_index,
                .sequence = fi.sequence,
                .flags = fi.flags,
                .path_index = fi.path_index,
                .has_coinbase_data = fi.has_coinbase_data,
                .coinbase_data =
                    WireRange{
                        .offset = fi.coinbase_data.offset,
                        .length = fi.coinbase_data.length,
                    },
                .witnesses = std::move(witnesses),
            });
        }

        rust::Vec<NativeOutput> outputs;
        outputs.reserve(v2tx.outputs.size());
        for (const auto &out : v2tx.outputs) {
            std::vector<uint8_t> out_wire;
            if (!lotus::v2::EncodeOutput(out, out_wire, err)) {
                throw std::runtime_error("V2 EncodeOutput failed: " + err);
            }
            outputs.push_back(NativeOutput{
                .wire = chronik::ToRustVec<uint8_t>(out_wire),
            });
        }

        transactions.push_back(NativeTx{
            .txid = chronik::util::HashToArray(ctx.GetId()),
            .txhash = chronik::util::HashToArray(ctx.GetHash()),
            .index = static_cast<uint32_t>(n),
            .inputs = std::move(spend_inputs),
            .outputs = std::move(outputs),
            .wire = chronik::ToRustVec<uint8_t>(fact_wire),
            .lock = v2tx.lock,
            .full_inputs = std::move(full_inputs),
        });
    }

    return NativeBlock{
        .anchor = anchor,
        .parent = parent,
        .transactions = std::move(transactions),
        .header_wire = header_wire,
    };
}

} // namespace chronik_v2
