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
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>
#include <map>
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

bool StartNodeWebTransport(const ArgsManager &args, CConnman &connman,
                           bilingual_str &error) {
    QuicEngineOptions opts;
    fs::path cert, key;
    if (!CertificateFiles(args, cert, key, error)) {
        return false;
    }
    opts.cert_file = cert;
    opts.key_file = key;
    opts.application = QuicApplication::WEBTRANSPORT;
    // -listen=0 suppresses every P2P listener, including explicit UDP
    // binds. Outbound WebTransport remains available.
    if (args.GetBoolArg("-listen", true)) {
        const auto add_bind = [&](const CService &addr) {
            if (std::find(opts.binds.begin(), opts.binds.end(), addr) ==
                opts.binds.end()) {
                opts.binds.push_back(addr);
            }
        };
        const bool explicit_wt{args.IsArgSet("-p2pwebtransportbind")};
        std::vector<std::string> binds{args.GetArgs(
            explicit_wt ? "-p2pwebtransportbind" : "-bind")};
        if (!explicit_wt) {
            for (const auto &bind : args.GetArgs("-publicbind")) {
                binds.push_back(bind);
            }
            for (const auto &bind : args.GetArgs("-whitebind")) {
                NetWhitebindPermissions parsed;
                bilingual_str why;
                if (NetWhitebindPermissions::TryParse(bind, parsed, why)) {
                    add_bind(parsed.m_service);
                }
            }
        }
        for (const std::string &bind : binds) {
            // Onion-only TCP listeners have no direct QUIC counterpart.
            if (!explicit_wt && bind.ends_with("=onion")) {
                continue;
            }
            const auto addr{Lookup(bind, GetListenPort(), false)};
            if (!addr || (!addr->IsValid() && !addr->IsBindAny()) ||
                addr->GetPort() == 0) {
                error = strprintf(Untranslated("Invalid WebTransport bind '%s'"), bind);
                return false;
            }
            add_bind(*addr);
        }
        if (!explicit_wt && !args.IsArgSet("-bind") &&
            !args.IsArgSet("-whitebind")) {
            in_addr any4{};
            any4.s_addr = htonl(INADDR_ANY);
            add_bind(CService{any4, GetListenPort()});
            add_bind(CService{in6addr_any, GetListenPort()});
        }
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
    // Ask for client certificates when keys grant permissions.
    opts.request_client_cert = args.IsArgSet("-p2pwebsocketpeer") ||
                               args.GetBoolArg("-tlsmutual", false);
    // -p2pwebsocketpin=<host>=<pin> applies to wt:// dials of that host.
    std::map<std::string, std::vector<unsigned char>> host_pins;
    for (const std::string &entry : args.GetArgs("-p2pwebsocketpin")) {
        const size_t eq{entry.find('=')};
        if (eq == std::string::npos || eq == 0) {
            continue;
        }
        if (const auto pin{DecodeSpkiPin(entry.substr(eq + 1))}) {
            host_pins[ToLower(entry.substr(0, eq))] = *pin;
        }
    }

    std::string why;
    g_engine = QuicEngine::Start(opts, why);
    if (!g_engine) {
        error = strprintf(Untranslated("Unable to start P2P over "
                                       "WebTransport: %s"),
                          why);
        return false;
    }
    for (const CService &addr : g_engine->BoundAddresses()) {
        LogPrintf("P2P over WebTransport listening on UDP %s\n",
                  addr.ToStringAddrPort());
    }
    // The service bit carries no path, token or alternate UDP port. Only
    // advertise an endpoint peers can derive from an ordinary address.
    const auto bound{g_engine->BoundAddresses()};
    const auto has_port = [&](uint16_t port) {
        return std::any_of(bound.begin(), bound.end(), [&](const CService &a) {
            return a.GetPort() == port;
        });
    };
    bool advertise{opts.wt_token.empty() &&
                   opts.wt_path == P2P_WEBTRANSPORT_PATH &&
                   has_port(GetListenPort())};
    for (const auto &domain : args.GetArgs("-externaldomain")) {
        uint16_t port{443};
        std::string host;
        advertise &= SplitHostPort(domain, port, host) && has_port(port);
    }
    for (const auto &bind : args.GetArgs("-publicbind")) {
        const auto addr{Lookup(bind, GetListenPort(), false)};
        advertise &= addr && has_port(addr->GetPort());
    }
    if (advertise) {
        connman.AddLocalServices(NODE_WEBTRANSPORT);
    }
    SetP2PWebTransportAcceptor(
        [&connman](std::unique_ptr<Sock> &&sock, const CAddress &addr,
                   const CAddress &addr_bind,
                   std::shared_ptr<QuicTransportInfo> info) {
            connman.AcceptWebTransportPeer(std::move(sock), addr, addr_bind,
                                           std::move(info));
        });
    SetWebTransportDialer(
        [engine = g_engine.get(), host_pins](
            const CService &target, const ParsedWebTransportURL &url,
            std::chrono::milliseconds timeout, CThreadInterrupt &interrupt,
            WebTransportDialError &error)
            -> std::optional<WebTransportDialResult> {
            ParsedWebTransportURL u{url};
            if (!u.spki_pin && !u.cert_sha256) {
                if (const auto it{host_pins.find(ToLower(u.host))};
                    it != host_pins.end()) {
                    u.spki_pin = it->second;
                }
            }
            return engine->Dial(target, u, timeout, interrupt, error);
        });
    return true;
}

void InterruptNodeWebTransport() {
    SetP2PWebTransportAcceptor(nullptr);
    SetWebTransportDialer(nullptr);
}

void StopNodeWebTransport() {
    InterruptNodeWebTransport();
    if (g_engine) {
        g_engine->Stop();
        g_engine.reset();
    }
}

QuicEngine *GetNodeQuicEngine() {
    return g_engine.get();
}
