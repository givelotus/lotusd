// Copyright (c) 2026 The Lotus developers
#ifndef BITCOIN_WALLET_V2_NODE_PROVIDER_H
#define BITCOIN_WALLET_V2_NODE_PROVIDER_H

#include <wallet/v2_payment.h>
#include <functional>
#include <string_view>

namespace lotus::v2::wallet {

// Local transport limits include the single terminating LF. Transport must
// enforce these while reading, and enforce its caller-selected deadline.
constexpr size_t NODE_WALLET_REQUEST_LIMIT = (2 << 20);
constexpr size_t NODE_WALLET_RESPONSE_LIMIT = 32768;
using NodeJsonlExchange = std::function<bool(std::string_view request,
                                           std::string &response,
                                           std::string &error)>;

// Caller-serialized adapter for one explicitly selected local full node.
// No socket, database, wallet secret, event stream or implicit network defaults.
// The callback exchanges one bounded context, submission or status JSONL command.
// Header/state/proof consistency is checked here; this is not a chain-validity
// proof or a chain lock. The caller's full node remains validation authority.
class NodePaymentChainProvider final : public PaymentChainProvider {
public:
    NodePaymentChainProvider(ChainProfile, NodeJsonlExchange);
    NodePaymentChainProvider(const NodePaymentChainProvider &) = delete;
    NodePaymentChainProvider &operator=(const NodePaymentChainProvider &) = delete;

    Result ReadAnchor(const Profile &, ChainAnchor &, std::string &) override;
    Result Lookup(const ChainAnchor &, const Outpoint &, std::optional<Coin> &,
                  std::string &) override;
    Result Recheck(const ChainAnchor &, std::string &) override;

    Result Submit(const std::vector<uint8_t> &, const Hash &, Submission &,
                  std::string &) override;
    Result Status(const Hash &, const Hash &, const std::vector<uint8_t> &,
                  TransactionState &, std::string &) override;
private:
    Result ExchangeCommand(const std::string &, const std::vector<uint8_t> &,
                           const Hash &, const Hash &, const Hash &,
                           Submission *, TransactionState *, std::string &);
    ChainProfile profile_;
    Profile binding_;
    NodeJsonlExchange exchange_;
    uint64_t next_id_{1};
    Result Context(const ChainAnchor *, const Outpoint *, ChainAnchor &,
                   std::optional<Coin> &, std::string &);
};

} // namespace lotus::v2::wallet
#endif
