// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net_webtransport.h>

#include <crypto/common.h>
#include <net_websocket.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <algorithm>
#include <string>
#include <unordered_map>

const char *StreamClassName(StreamClass c) {
    switch (c) {
        case StreamClass::CONTROL:
            return "control";
        case StreamClass::AVALANCHE:
            return "avalanche";
        case StreamClass::TX_ANNOUNCE:
            return "tx_announce";
        case StreamClass::TX_BODY:
            return "tx_body";
        case StreamClass::BLOCK:
            return "block";
        case StreamClass::MIXED:
            return "mixed";
    }
    return "unknown";
}

namespace {
/**
 * Classes of the message types that do not carry inventory vectors.
 * Request/response pairs whose order matters share a class: getheaders/
 * headers, getblocktxn/blocktxn, avapoll/avaresponse, getmerklixbuck/
 * merklixbuck, getshorttx/shorttx; version/verack come first on CONTROL.
 * Feature negotiation that gates how a later message is read travels with
 * that message (sendinvshort with invshort). Unknown types are CONTROL.
 */
const std::unordered_map<std::string_view, StreamClass> &MessageClasses() {
    static const std::unordered_map<std::string_view, StreamClass> classes{
        // Connection control and address relay.
        {"version", StreamClass::CONTROL},
        {"verack", StreamClass::CONTROL},
        {"ping", StreamClass::CONTROL},
        {"pong", StreamClass::CONTROL},
        {"sendheaders", StreamClass::CONTROL},
        {"sendcmpct", StreamClass::CONTROL},
        {"feefilter", StreamClass::CONTROL},
        {"sendaddrv2", StreamClass::CONTROL},
        {"addr", StreamClass::CONTROL},
        {"addrv2", StreamClass::CONTROL},
        {"getaddr", StreamClass::CONTROL},
        {"filterload", StreamClass::CONTROL},
        {"filteradd", StreamClass::CONTROL},
        {"filterclear", StreamClass::CONTROL},
        {"avahello", StreamClass::CONTROL},
        {"getavaaddr", StreamClass::CONTROL},
        // Avalanche polls, votes and proofs.
        {"avapoll", StreamClass::AVALANCHE},
        {"avaresponse", StreamClass::AVALANCHE},
        {"avaproof", StreamClass::AVALANCHE},
        {"avaproofs", StreamClass::AVALANCHE},
        {"getavaproofs", StreamClass::AVALANCHE},
        {"avaproofsreq", StreamClass::AVALANCHE},
        {"avatreasury", StreamClass::AVALANCHE},
        {"avabatch", StreamClass::AVALANCHE},
        // Transaction announcement and reconciliation.
        {"merklixsync", StreamClass::TX_ANNOUNCE},
        {"getmerklixbuck", StreamClass::TX_ANNOUNCE},
        {"merklixbuck", StreamClass::TX_ANNOUNCE},
        {"mempool", StreamClass::TX_ANNOUNCE},
        // Transaction bodies.
        {"tx", StreamClass::TX_BODY},
        {"getshorttx", StreamClass::TX_BODY},
        {"shorttx", StreamClass::TX_BODY},
        // Blocks, headers, filters and chain state.
        {"getblocks", StreamClass::BLOCK},
        {"getheaders", StreamClass::BLOCK},
        {"headers", StreamClass::BLOCK},
        {"block", StreamClass::BLOCK},
        {"merkleblock", StreamClass::BLOCK},
        {"cmpctblock", StreamClass::BLOCK},
        {"getblocktxn", StreamClass::BLOCK},
        {"blocktxn", StreamClass::BLOCK},
        {"minedheader", StreamClass::BLOCK},
        {"sealedheader", StreamClass::BLOCK},
        {"sealedblock", StreamClass::BLOCK},
        {"getblockundo", StreamClass::BLOCK},
        {"blockundo", StreamClass::BLOCK},
        {"getutxoroots", StreamClass::BLOCK},
        {"utxoroots", StreamClass::BLOCK},
        {"getutxoshard", StreamClass::BLOCK},
        {"utxoshard", StreamClass::BLOCK},
        {"getcfilters", StreamClass::BLOCK},
        {"cfilter", StreamClass::BLOCK},
        {"getcfheaders", StreamClass::BLOCK},
        {"cfheaders", StreamClass::BLOCK},
        {"getcfcheckpt", StreamClass::BLOCK},
        {"cfcheckpt", StreamClass::BLOCK},
    };
    return classes;
}

constexpr size_t INV_ENTRY_SIZE = 4 + 32;

bool IsInventoryMessage(std::string_view type) {
    return type == "inv" || type == "getdata" || type == "notfound";
}

/** Where the entries of an inventory vector start, and how many there are;
 * std::nullopt if the payload is not a well-formed vector */
std::optional<std::pair<size_t, uint64_t>>
ParseInventory(Span<const uint8_t> payload) {
    try {
        SpanReader reader{payload};
        const uint64_t count{ReadCompactSize(reader, /*range_check=*/false)};
        const size_t start{payload.size() - reader.size()};
        if (count > (payload.size() - start) / INV_ENTRY_SIZE ||
            payload.size() - start != count * INV_ENTRY_SIZE) {
            return std::nullopt;
        }
        return std::make_pair(start, count);
    } catch (const std::ios_base::failure &) {
        return std::nullopt;
    }
}

uint32_t InventoryType(Span<const uint8_t> payload, size_t start, size_t i) {
    return ReadLE32(payload.data() + start + i * INV_ENTRY_SIZE);
}

/** The class of an inventory message with no (usable) entries */
StreamClass DefaultInventoryClass(std::string_view type) {
    return type == "inv" ? StreamClass::TX_ANNOUNCE : StreamClass::TX_BODY;
}
} // namespace

StreamClass ClassifyInventoryType(uint32_t inv_type, bool announcement) {
    const uint32_t kind{inv_type == MSG_AVA_MEMPOOL_BATCH
                            ? inv_type
                            : inv_type & MSG_TYPE_MASK};
    switch (kind) {
        case MSG_TX:
            return announcement ? StreamClass::TX_ANNOUNCE
                                : StreamClass::TX_BODY;
        case MSG_BLOCK:
        case MSG_FILTERED_BLOCK:
        case MSG_CMPCT_BLOCK:
        case MSG_MINED_HEADER:
            return StreamClass::BLOCK;
        case MSG_AVA_PROOF:
        case MSG_AVA_STAKE_CONTENDER:
        case MSG_AVA_STATE_ANCHOR:
        case MSG_AVA_MEMPOOL_BATCH:
            return StreamClass::AVALANCHE;
        default:
            return StreamClass::CONTROL;
    }
}

StreamClass ClassifyMessage(std::string_view type,
                            Span<const uint8_t> payload) {
    if (IsInventoryMessage(type)) {
        const auto inv{ParseInventory(payload)};
        if (!inv || inv->second == 0) {
            // Malformed or empty: deliver as is; the receiver judges it.
            return DefaultInventoryClass(type);
        }
        const bool announcement{type == "inv"};
        const StreamClass first{ClassifyInventoryType(
            InventoryType(payload, inv->first, 0), announcement)};
        for (uint64_t i = 1; i < inv->second; ++i) {
            if (ClassifyInventoryType(InventoryType(payload, inv->first, i),
                                      announcement) != first) {
                return StreamClass::MIXED;
            }
        }
        return first;
    }
    const auto &classes{MessageClasses()};
    const auto it{classes.find(type)};
    return it == classes.end() ? StreamClass::CONTROL : it->second;
}

bool HasExplicitStreamClass(std::string_view type) {
    return IsInventoryMessage(type) || MessageClasses().count(type) > 0;
}

std::vector<std::pair<StreamClass, std::vector<uint8_t>>>
SplitByClass(std::string_view type, Span<const uint8_t> payload) {
    std::vector<std::pair<StreamClass, std::vector<uint8_t>>> out;
    const StreamClass cls{ClassifyMessage(type, payload)};
    if (cls != StreamClass::MIXED) {
        out.emplace_back(cls,
                         std::vector<uint8_t>(payload.begin(), payload.end()));
        return out;
    }
    const auto inv{ParseInventory(payload)};
    // MIXED implies a well-formed vector.
    const bool announcement{type == "inv"};
    std::vector<std::pair<StreamClass, std::vector<size_t>>> groups;
    for (uint64_t i = 0; i < inv->second; ++i) {
        const StreamClass c{ClassifyInventoryType(
            InventoryType(payload, inv->first, i), announcement)};
        auto it{std::find_if(groups.begin(), groups.end(),
                             [c](const auto &g) { return g.first == c; })};
        if (it == groups.end()) {
            groups.emplace_back(c, std::vector<size_t>{});
            it = groups.end() - 1;
        }
        it->second.push_back(i);
    }
    for (const auto &[c, entries] : groups) {
        std::vector<uint8_t> msg;
        VectorWriter writer{msg, 0};
        WriteCompactSize(writer, entries.size());
        msg.reserve(msg.size() + entries.size() * INV_ENTRY_SIZE);
        for (const size_t i : entries) {
            const uint8_t *entry{payload.data() + inv->first +
                                 i * INV_ENTRY_SIZE};
            msg.insert(msg.end(), entry, entry + INV_ENTRY_SIZE);
        }
        out.emplace_back(c, std::move(msg));
    }
    return out;
}

const char *WebTransportDialErrorName(WebTransportDialError e) {
    switch (e) {
        case WebTransportDialError::NONE:
            return "none";
        case WebTransportDialError::TIMEOUT:
            return "timeout";
        case WebTransportDialError::HANDSHAKE:
            return "handshake";
        case WebTransportDialError::UNSUPPORTED:
            return "unsupported";
        case WebTransportDialError::REFUSED:
            return "refused";
        case WebTransportDialError::INTERRUPTED:
            return "interrupted";
    }
    return "unknown";
}

bool IsWebTransportURL(std::string_view str) {
    return str.substr(0, 5) == "wt://";
}

std::string RedactWebTransportURL(std::string_view url) {
    std::string out{url};
    for (size_t pos{out.find("t=")}; pos != std::string::npos;
         pos = out.find("t=", pos + 1)) {
        if (pos == 0 || (out[pos - 1] != '?' && out[pos - 1] != '&')) {
            continue;
        }
        const size_t start{pos + 2};
        const size_t end{out.find_first_of("&#", start)};
        out.replace(start,
                    (end == std::string::npos ? out.size() : end) - start,
                    "***");
    }
    return out;
}

std::optional<ParsedWebTransportURL>
ParseWebTransportURL(std::string_view url) {
    ParsedWebTransportURL out;
    if (const size_t hash{url.find('#')}; hash != std::string_view::npos) {
        const std::string_view fragment{url.substr(hash + 1)};
        url = url.substr(0, hash);
        if (fragment.substr(0, 5) == "spki=") {
            out.spki_pin = DecodeSpkiPin(fragment.substr(5));
            if (!out.spki_pin) {
                return std::nullopt;
            }
        } else if (fragment.substr(0, 5) == "cert=") {
            const std::string_view hex{fragment.substr(5)};
            if (hex.size() != 64 || !IsHex(hex)) {
                return std::nullopt;
            }
            out.cert_sha256 = ParseHex(hex);
        } else {
            return std::nullopt;
        }
    }
    if (!IsWebTransportURL(url)) {
        return std::nullopt;
    }
    url.remove_prefix(5);
    std::string_view query;
    if (const size_t q{url.find('?')}; q != std::string_view::npos) {
        query = url.substr(q + 1);
        url = url.substr(0, q);
    }
    const size_t slash{url.find('/')};
    const std::string authority{url.substr(0, slash)};
    out.path = slash == std::string_view::npos ? std::string{P2P_WEBTRANSPORT_PATH}
                                              : std::string{url.substr(slash)};
    if (out.path.find_first_of(" \t\r\n") != std::string::npos) {
        return std::nullopt;
    }
    while (!query.empty()) {
        const size_t amp{query.find('&')};
        const std::string_view param{query.substr(0, amp)};
        if (param.substr(0, 2) == "t=") {
            out.token = std::string{param.substr(2)};
            if (!IsValidWebSocketToken(out.token)) {
                return std::nullopt;
            }
        } else if (!param.empty()) {
            return std::nullopt;
        }
        query = amp == std::string_view::npos ? std::string_view{}
                                              : query.substr(amp + 1);
    }
    uint16_t port{DEFAULT_WEBTRANSPORT_URL_PORT};
    std::string host;
    if (authority.empty() || !SplitHostPort(authority, port, host) ||
        host.empty() || port == 0) {
        return std::nullopt;
    }
    out.host = host;
    out.port = port;
    const bool ipv6{host.find(':') != std::string::npos};
    out.authority = strprintf(ipv6 ? "[%s]:%u" : "%s:%u", host, port);
    return out;
}

static GlobalMutex g_wt_registry_mutex;
static P2PWebTransportAcceptor
    g_wt_acceptor GUARDED_BY(g_wt_registry_mutex);
static WebTransportDialer g_wt_dialer GUARDED_BY(g_wt_registry_mutex);
static WebTransportInfoProvider g_wt_info GUARDED_BY(g_wt_registry_mutex);

void SetWebTransportInfoProvider(WebTransportInfoProvider provider) {
    LOCK(g_wt_registry_mutex);
    g_wt_info = std::move(provider);
}

UniValue GetWebTransportInfo(bool public_only) {
    WebTransportInfoProvider provider;
    {
        LOCK(g_wt_registry_mutex);
        provider = g_wt_info;
    }
    if (provider) return provider(public_only);
    UniValue result{UniValue::VOBJ};
    result.pushKV("enabled", false);
    return result;
}

void SetP2PWebTransportAcceptor(P2PWebTransportAcceptor acceptor) {
    LOCK(g_wt_registry_mutex);
    g_wt_acceptor = std::move(acceptor);
}

P2PWebTransportAcceptor GetP2PWebTransportAcceptor() {
    LOCK(g_wt_registry_mutex);
    return g_wt_acceptor;
}

void SetWebTransportDialer(WebTransportDialer dialer) {
    LOCK(g_wt_registry_mutex);
    g_wt_dialer = std::move(dialer);
}

WebTransportDialer GetWebTransportDialer() {
    LOCK(g_wt_registry_mutex);
    return g_wt_dialer;
}

void WebTransportNegativeCache::SetRetryAfter(
    std::chrono::seconds retry_after) {
    LOCK(m_mutex);
    m_retry_after = retry_after;
    m_entries.clear();
    m_lru.clear();
}

bool WebTransportNegativeCache::Contains(const CService &addr,
                                         Clock::time_point now) {
    LOCK(m_mutex);
    const auto it{m_entries.find(addr)};
    if (it == m_entries.end()) {
        return false;
    }
    if (now >= it->second.expires) {
        m_lru.erase(it->second.lru);
        m_entries.erase(it);
        return false;
    }
    m_lru.splice(m_lru.begin(), m_lru, it->second.lru);
    return true;
}

void WebTransportNegativeCache::Record(const CService &addr,
                                       Clock::time_point now) {
    LOCK(m_mutex);
    if (m_capacity == 0 || m_retry_after <= std::chrono::seconds::zero()) {
        return;
    }
    if (const auto it{m_entries.find(addr)}; it != m_entries.end()) {
        it->second.expires = now + m_retry_after;
        m_lru.splice(m_lru.begin(), m_lru, it->second.lru);
        return;
    }
    if (m_entries.size() == m_capacity) {
        m_entries.erase(m_lru.back());
        m_lru.pop_back();
    }
    m_lru.push_front(addr);
    m_entries.emplace(addr, Entry{now + m_retry_after, m_lru.begin()});
}

void WebTransportNegativeCache::Erase(const CService &addr) {
    LOCK(m_mutex);
    if (const auto it{m_entries.find(addr)}; it != m_entries.end()) {
        m_lru.erase(it->second.lru);
        m_entries.erase(it);
    }
}

size_t WebTransportNegativeCache::Size(Clock::time_point now) {
    LOCK(m_mutex);
    for (auto it{m_entries.begin()}; it != m_entries.end();) {
        if (now >= it->second.expires) {
            m_lru.erase(it->second.lru);
            it = m_entries.erase(it);
        } else {
            ++it;
        }
    }
    return m_entries.size();
}
