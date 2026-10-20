// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_quic/node_webtransport.h>

#include <common/args.h>
#include <httpserver.h>
#include <logging.h>
#include <net.h>
#include <net_quic/quic_engine.h>
#include <net_webtransport.h>
#include <netbase.h>
#include <random.h>
#include <tls_util.h>
#include <util/string.h>

#include <memory>

namespace {
std::unique_ptr<QuicEngine> g_engine;

/** The certificate for QUIC: -tlscert/-tlskey, else the node's datadir
 * certificate (as the HTTP server uses), created if missing */
bool CertificateFiles(const ArgsManager &args, fs::path &cert, fs::path &key,
                      bilingual_str &error) {
    if (args.IsArgSet("-tlscert") && args.IsArgSet("-tlskey")) {
        cert = args.GetPathArg("-tlscert");
        key = args.GetPathArg("-tlskey");
        return true;
    }
    cert = args.GetDataDirNet() / HTTP_TLS_CERT_FILENAME;
    key = args.GetDataDirNet() / HTTP_TLS_KEY_FILENAME;
    if (fs::exists(cert) && fs::exists(key)) {
        return true;
    }
    // A neutral random name, as the HTTP server's generated certificates.
    FastRandomContext rng;
    std::string name(8, 'a');
    for (char &c : name) {
        c = char('a' + rng.randrange(26));
    }
    name += ".net";
    const auto pem{tls::GenerateSelfSigned(name, {name}, {},
                                           std::chrono::hours{24 * 90})};
    if (!pem || !tls::WritePemFiles(*pem, cert, key)) {
        error = Untranslated("unable to create a TLS certificate for "
                             "WebTransport");
        return false;
    }
    return true;
}
} // namespace

bool StartNodeWebTransport(const ArgsManager &args, bilingual_str &error) {
    QuicEngineOptions opts;
    fs::path cert, key;
    if (!CertificateFiles(args, cert, key, error)) {
        return false;
    }
    opts.cert_file = cert;
    opts.key_file = key;
    opts.application = QuicApplication::WEBTRANSPORT;
    if (args.IsArgSet("-p2pwebtransportbind")) {
        for (const std::string &bind : args.GetArgs("-p2pwebtransportbind")) {
            const std::optional<CService> addr{
                Lookup(bind, GetListenPort(), false)};
            if (!addr || !addr->IsValid()) {
                error = strprintf(
                    Untranslated("Invalid -p2pwebtransportbind '%s'"), bind);
                return false;
            }
            opts.binds.push_back(*addr);
        }
    } else if (args.GetBoolArg("-listen", true)) {
        // UDP on the P2P port, beside the TCP listener.
        in_addr any4{};
        any4.s_addr = htonl(INADDR_ANY);
        opts.binds.emplace_back(any4, GetListenPort());
        opts.binds.emplace_back(in6addr_any, GetListenPort());
    }
    opts.bind_optional = true;
    opts.wt_path = args.GetArg("-p2pwebtransportpath", P2P_WEBTRANSPORT_PATH);
    if (opts.wt_path.empty() || opts.wt_path[0] != '/' ||
        opts.wt_path.find_first_of("?# ") != std::string::npos) {
        error = strprintf(Untranslated("Invalid -p2pwebtransportpath '%s'"),
                          opts.wt_path);
        return false;
    }
    opts.wt_token = args.GetArg("-p2pwebtransporttoken", "");
    if (!opts.wt_token.empty() && !IsValidWebSocketToken(opts.wt_token)) {
        error = Untranslated("Invalid -p2pwebtransporttoken (use 1-256 of "
                             "A-Z a-z 0-9 . _ ~ -)");
        return false;
    }
    for (const std::string &list : args.GetArgs("-p2pwebtransportorigins")) {
        for (const std::string &origin : util::SplitString(list, ',')) {
            const std::string o{util::TrimString(origin)};
            if (!o.empty()) {
                opts.wt_origins.push_back(o);
            }
        }
    }
    const std::string cc{args.GetArg("-p2pwebtransportcc", "cubic")};
    if (cc != "cubic" && cc != "bbr") {
        error = Untranslated("-p2pwebtransportcc must be cubic or bbr");
        return false;
    }
    opts.bbr = cc == "bbr";
    opts.idle_timeout = std::chrono::seconds{
        std::max<int64_t>(5, args.GetIntArg("-p2pwebtransportidle", 30))};
    opts.wt_echo = args.GetBoolArg("-p2pwebtransportecho", false);

    std::string why;
    g_engine = QuicEngine::Start(opts, why);
    if (!g_engine) {
        error = strprintf(Untranslated("Unable to start P2P over "
                                       "WebTransport: %s"),
                          why);
        return false;
    }
    for (const CService &addr : g_engine->BoundAddresses()) {
        LogPrintf("P2P over WebTransport listening on UDP %s%s\n",
                  addr.ToStringAddrPort(),
                  opts.wt_echo ? " (echo mode, for tests)" : "");
    }
    return true;
}

void StopNodeWebTransport() {
    if (g_engine) {
        g_engine->Stop();
        g_engine.reset();
    }
}

QuicEngine *GetNodeQuicEngine() {
    return g_engine.get();
}
