// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_VALUES_H
#define BITCOIN_LOGGING_VALUES_H

#include <logging/event.h>
#include <netaddress.h>
#include <primitives/transaction.h>

#include <algorithm>
#include <cstring>

/**
 * How node types are logged as structured field values (see
 * BCLog::LogValue and BCLog::LogRef in logging/event.h). Include this
 * where such values are logged.
 */
namespace BCLog {

/** Network addresses: copied as raw bytes, rendered in canonical form */
template <> struct LogValue<CNetAddr> {
    //! Network, scope id, uint16 length, then the full address payload.
    static constexpr size_t MAX_SIZE{1 + 4 + 2 + ADDR_WSS_MAX_SIZE};
    static size_t Size(const CNetAddr &addr) {
        return 1 + 4 + 2 + addr.RawAddrBytes().size();
    }
    static size_t Pack(const CNetAddr &addr, std::span<std::byte> out) {
        const auto bytes{addr.RawAddrBytes()};
        const uint16_t len{uint16_t(bytes.size())};
        const uint8_t net{uint8_t(addr.RawNetwork())};
        const uint32_t scope{addr.RawScopeId()};
        std::memcpy(out.data(), &net, 1);
        std::memcpy(out.data() + 1, &scope, 4);
        std::memcpy(out.data() + 5, &len, 2);
        std::memcpy(out.data() + 7, bytes.data(), len);
        return 7 + len;
    }
    static CNetAddr Unpack(std::span<const std::byte> in) {
        uint8_t net;
        uint16_t len;
        uint32_t scope;
        std::memcpy(&net, in.data(), 1);
        std::memcpy(&scope, in.data() + 1, 4);
        std::memcpy(&len, in.data() + 5, 2);
        return CNetAddr::FromRaw(
            Network(net),
            Span{reinterpret_cast<const uint8_t *>(in.data() + 7), len}, scope);
    }
    static void Render(std::span<const std::byte> in, std::string &out) {
        out += Unpack(in).ToStringAddr();
    }
};

/** Network address and port */
template <> struct LogValue<CService> {
    static constexpr size_t MAX_SIZE{2 + LogValue<CNetAddr>::MAX_SIZE};
    static size_t Size(const CService &service) {
        return 2 + LogValue<CNetAddr>::Size(service);
    }
    static size_t Pack(const CService &service, std::span<std::byte> out) {
        const uint16_t port{service.GetPort()};
        std::memcpy(out.data(), &port, 2);
        return 2 + LogValue<CNetAddr>::Pack(service, out.subspan(2));
    }
    static void Render(std::span<const std::byte> in, std::string &out) {
        uint16_t port;
        std::memcpy(&port, in.data(), 2);
        out += CService{LogValue<CNetAddr>::Unpack(in.subspan(2)), port}
                   .ToStringAddrPort();
    }
};

/** Transactions, by reference: rendered as their txid */
template <> struct LogRef<CTransaction> {
    static void Render(const CTransaction &tx, std::string &out) {
        out += tx.GetId().GetHex();
    }
};

} // namespace BCLog

#endif // BITCOIN_LOGGING_VALUES_H
