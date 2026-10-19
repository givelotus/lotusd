// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Entry points of the native Chronik for the ABC/eCash node, with the
// signatures of chronik/chronik-cpp/chronik.h so init.cpp is unchanged.
// Port of chronik/chronik-cpp/chronik.cpp (ParseChronikParams) and
// chronik-lib/src/bridge.rs (try_setup_chronik), without Electrum and plugins.

#include <chainparams.h>
#include <chainparamsbase.h>
#include <clientversion.h>
#include <common/args.h>
#include <config.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <node/context.h>
#include <node/metrics.h>
#include <node/ui_interface.h>
#include <script/script.h>
#include <util/chaintype.h>
#include <util/result.h>
#include <util/time.h>
#include <util/translation.h>

#include <chronik-cpp/chronik.h>

#include <chronik/native/error.h>
#ifdef CHRONIK_NATIVE_HAVE_LEVELDB
#include <chronik/native/leveldb_store.h>
#endif
#ifdef CHRONIK_NATIVE_HAVE_MDBX
#include <chronik/native/mdbx_store.h>
#endif
#include <chronik/native/service.h>
#include <chronik/native/token_io/token_index.h>
#include <hosts/abc/abc_host.h>
#include <hosts/abc/abc_http.h>
#include <hosts/abc/abc_subscriber.h>

#include <tinyformat.h>

#include <limits>

namespace chronik {

namespace {

/** Lotus V2 nodes are recognised by their native output fields. */
template <typename TxOutT>
constexpr bool IsLotusV2Output = requires(const TxOutT &o) { o.vBranches; };
constexpr bool kLotusV2Node = IsLotusV2Output<CTxOut>;

/** Registers the storage backends linked into this build (idempotent). */
void RegisterStoreBackends() {
#ifdef CHRONIK_NATIVE_HAVE_MDBX
    native::RegisterMdbxStore();
#endif
#ifdef CHRONIK_NATIVE_HAVE_LEVELDB
    native::RegisterLevelDbStore();
#endif
}

// Duration between WebSocket pings initiated by Chronik.
// 45s has been empirically established as a reliable duration for both browser
// and NodeJS WebSockets.
constexpr std::chrono::seconds WS_PING_INTERVAL_DEFAULT{45s};

// Ping duration is just 5s on regtest to speed up ping tests and make
// functional tests more reliable.
constexpr std::chrono::seconds WS_PING_INTERVAL_REGTEST{5s};

const std::vector<std::string> ELECTRUM_ARGS = {
    "-chronikelectrumbind",
    "-chronikelectrumcert",
    "-chronikelectrumprivkey",
    "-chronikelectrumurl",
    "-chronikelectrummaxhistory",
    "-chronikelectrumdonationaddress",
    "-chronikelectrumpeersvalidationinterval",
    "-chronikelectrumidletimeout",
};

std::unique_ptr<native::abc::AbcHost> g_host;
std::shared_ptr<native::Service> g_service;

std::string NetworkName(ChainType chain_type) {
    switch (chain_type) {
        case ChainType::MAIN:
            return "main";
        case ChainType::TESTNET:
            return "test";
        case ChainType::REGTEST:
            return "regtest";
    }
    throw std::runtime_error("Unknown chain type");
}

util::Result<native::ServiceParams>
ParseChronikParams(const ArgsManager &args, const Config &config, bool fWipe) {
    for (const std::string &arg : ELECTRUM_ARGS) {
        if (args.IsArgSet(arg)) {
            return {{_("Electrum is not supported by the native Chronik "
                       "implementation")}};
        }
    }

    const bool is_pause_allowed = args.GetBoolArg("-chronikallowpause", false);
    const CChainParams &params = config.GetChainParams();
    if (is_pause_allowed && !params.IsTestChain()) {
        return {{_("Using -chronikallowpause on a mainnet chain is not allowed "
                   "for security reasons.")}};
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

    native::ServiceParams out;
    out.indexer.datadir_net = args.GetDataDirNet();
    out.indexer.wipe = fWipe;
    out.indexer.token_index = args.GetBoolArg("-chroniktokenindex", true);
    out.indexer.lokad_id_index = args.GetBoolArg("-chroniklokadidindex", true);
    // Without Electrum, the scripthash index defaults to off (as in Rust).
    out.indexer.scripthash_index =
        args.GetBoolArg("-chronikscripthashindex", false);
    out.indexer.perf_stats = args.GetBoolArg("-chronikperfstats", false);
    out.indexer.tx_num_cache_buckets = (size_t)args.GetIntArg(
        "-chroniktxnumcachebuckets", DEFAULT_TX_NUM_CACHE_BUCKETS);
    out.indexer.tx_num_cache_bucket_size = (size_t)args.GetIntArg(
        "-chroniktxnumcachebucketsize", DEFAULT_TX_NUM_CACHE_BUCKET_SIZE);
#ifdef CHRONIK_NATIVE_HAVE_MDBX
    const std::string default_backend = "mdbx";
#else
    const std::string default_backend = "leveldb";
#endif
    const std::string backend_name =
        args.GetArg("-chronikdbbackend", default_backend);
    const std::optional<native::StoreBackend> backend =
        native::ParseStoreBackend(backend_name);
    if (!backend) {
        return {{_(strprintf("Unknown -chronikdbbackend %s (expected mdbx "
                             "or leveldb).",
                             backend_name)
                       .c_str())}};
    }
    RegisterStoreBackends();
    if (!native::HasStoreBackend(*backend)) {
        return {{_(strprintf("-chronikdbbackend=%s is not available in this "
                             "build.",
                             backend_name)
                       .c_str())}};
    }
    out.indexer.backend = *backend;
    out.indexer.token_index_factory = native::token_io::MakeEcashTokenIndex;
    out.indexer.decompress_pubkey =
        [](native::ByteView form) -> std::optional<native::Bytes> {
        // Compressed-script P2PK forms 0x04/0x05 hold the x coordinate.
        if (form.size() != 33 || (form[0] != 4 && form[0] != 5)) {
            return std::nullopt;
        }
        std::vector<uint8_t> vch(form.begin(), form.end());
        vch[0] = form[0] - 2;
        CPubKey pubkey(vch);
        if (!pubkey.Decompress()) {
            return std::nullopt;
        }
        return native::Bytes(pubkey.begin(), pubkey.end());
    };
    out.hosts = args.IsArgSet("-chronikbind") ? args.GetArgs("-chronikbind")
                                              : DEFAULT_BINDS;
    out.default_port = BaseParams().ChronikPort();
    out.is_pause_allowed = is_pause_allowed;
    out.ws_ping_interval = params.GetChainType() == ChainType::REGTEST
                               ? WS_PING_INTERVAL_REGTEST
                               : WS_PING_INTERVAL_DEFAULT;
    out.enable_cors = args.GetBoolArg("-chronikcors", false);
    out.max_subs = static_cast<size_t>(max_subs);
    out.max_subs_per_ip = static_cast<size_t>(max_subs_per_ip);
    out.subscription_max_script_size =
        static_cast<size_t>(subscription_max_script_size);
    out.subscription_max_plugin_size =
        static_cast<size_t>(subscription_max_plugin_size);
    out.query_workers = (size_t)std::max<int64_t>(
        0, args.GetIntArg("-chronikqueryworkers", 0));
    return out;
}

} // namespace

bool Start(const ArgsManager &args, const Config &config,
           const node::NodeContext &node, bool fWipe) {
    util::Result<native::ServiceParams> params =
        ParseChronikParams(args, config, fWipe);
    if (!params) {
        return InitError(ErrorString(params));
    }
    const CChainParams &chain_params = config.GetChainParams();

    // No registry work or host locks from callbacks. Chronik workers/listeners
    // drain before node metrics teardown; GetNodeMetrics also permits -metrics=0.
    params->observe_request = [](std::string_view route, uint16_t status,
                                 uint64_t nanos) noexcept {
        node::RecordChronikRequest(route, status, nanos);
    };
    params->observe_ws_connections = [](int32_t delta) noexcept {
        if (auto *m = node::GetNodeMetrics()) m->chronik_ws_connections.Add(delta);
    };
    params->observe_ws_subscriptions = [](int32_t delta) noexcept {
        if (auto *m = node::GetNodeMetrics()) m->chronik_ws_subscriptions.Add(delta);
    };
    params->observe_indexed_height = [](int32_t height) noexcept {
        node::SetChronikIndexedHeight(height);
    };

    native::HostCapabilities caps;
    caps.avalanche = true;
    // SLP/ALP token indexing is on for eCash and off on Lotus V2 nodes (user
    // decision 2026-10-19), which are recognised by their V2 output fields.
    caps.slp_alp_tokens = !kLotusV2Node;
    caps.allow_pause_on_this_chain = chain_params.IsTestChain();
    caps.witness = false;
    caps.network = NetworkName(chain_params.GetChainType());
    caps.default_http_port = BaseParams().ChronikPort();
    caps.client_name = CLIENT_NAME;

    g_host = std::make_unique<native::abc::AbcHost>(node, std::move(caps));
    try {
        std::unique_ptr<native::Service> service =
            native::Service::Start(*g_host, std::move(*params));
        if (!service) {
            // Shutdown was requested during resync
            return true;
        }
        g_service = std::move(service);
    } catch (const std::exception &e) {
        g_host->Log(native::LogLevel::Debug, std::string(e.what()) + "\n");
        return InitError(Untranslated(e.what()));
    }
    native::abc::RegisterInProcessHttp(g_service);
    native::abc::StartSubscriber(node, *g_host, g_service);
    return true;
}

void Interrupt() {
    native::abc::UnregisterInProcessHttp();
    native::abc::InterruptSubscriber();
}

void Stop() {
    LogPrintf("Stopping Chronik...\n");
    native::abc::StopSubscriber();
    g_service.reset();
    g_host.reset();
}

} // namespace chronik
