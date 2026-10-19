// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LOGGING_VALUES_H
#define BITCOIN_LOGGING_VALUES_H

#include <consensus/validation.h>
#include <feerate.h>
#include <logging/event.h>
#include <netaddress.h>
#include <primitives/transaction.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <type_traits>

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

/** Fee rates: copy their single Amount value; format on the consumer. */
template <> struct LogValue<CFeeRate> {
    // This is an in-process value snapshot, not a new wire serialization.
    // Avoid GetFeePerK(): it performs arithmetic which can overflow for rates
    // outside the monetary range even though ToString itself accepts them.
    static_assert(std::is_trivially_copyable_v<CFeeRate>);
    static_assert(std::has_unique_object_representations_v<CFeeRate>);
    static_assert(sizeof(CFeeRate) == sizeof(Amount));
    static constexpr size_t MAX_SIZE{sizeof(CFeeRate)};
    static size_t Pack(const CFeeRate &rate, std::span<std::byte> out) {
        std::memcpy(out.data(), &rate, sizeof(rate));
        return sizeof(rate);
    }
    static void Render(std::span<const std::byte> in, std::string &out) {
        CFeeRate rate;
        std::memcpy(&rate, in.data(), sizeof(rate));
        out += rate.ToString();
    }
};

/** Snapshot validation diagnostics without formatting or owning-string copies. */
template <typename State> struct ValidationStateLogValue {
    // A saturated size forces omission from the fixed record with
    // fields_truncated, never a partial state or overflow.
    static constexpr size_t MAX_SIZE{std::numeric_limits<uint16_t>::max()};
    static size_t Size(const State &state) {
        if (state.IsValid()) return 1;
        return std::min(MAX_SIZE, size_t{3} +
            std::min(MAX_SIZE, state.GetRejectReasonView().size()) +
            std::min(MAX_SIZE, state.GetDebugMessageView().size()));
    }
    static size_t Pack(const State &state, std::span<std::byte> out) {
        out[0] = std::byte(state.IsValid());
        if (state.IsValid()) return 1;
        const auto reason{state.GetRejectReasonView()};
        const auto debug{state.GetDebugMessageView()};
        assert(out.size() == Size(state) && out.size() < MAX_SIZE);
        const uint16_t reason_size{uint16_t(reason.size())};
        std::memcpy(out.data() + 1, &reason_size, sizeof(reason_size));
        std::memcpy(out.data() + 3, reason.data(), reason.size());
        std::memcpy(out.data() + 3 + reason.size(), debug.data(), debug.size());
        return out.size();
    }
    static void Render(std::span<const std::byte> in, std::string &out) {
        if (in[0] != std::byte{0}) {
            out += "Valid";
            return;
        }
        uint16_t size;
        std::memcpy(&size, in.data() + 1, sizeof(size));
        in = in.subspan(3);
        assert(size <= in.size());
        out.append(reinterpret_cast<const char *>(in.data()), size);
        if (size < in.size()) {
            out += ", ";
            out.append(reinterpret_cast<const char *>(in.data() + size),
                       in.size() - size);
        }
    }
};
template <>
struct LogValue<TxValidationState> : ValidationStateLogValue<TxValidationState> {};
template <>
struct LogValue<BlockValidationState>
    : ValidationStateLogValue<BlockValidationState> {};

/** Transactions, by reference: rendered as their txid */
template <> struct LogRef<CTransaction> {
    static void Render(const CTransaction &tx, std::string &out) {
        out += tx.GetId().GetHex();
    }
};

} // namespace BCLog

#endif // BITCOIN_LOGGING_VALUES_H
