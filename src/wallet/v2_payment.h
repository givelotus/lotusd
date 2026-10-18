// Copyright (c) 2026 The Lotus developers
#ifndef BITCOIN_WALLET_V2_PAYMENT_H
#define BITCOIN_WALLET_V2_PAYMENT_H

#include <lotus_v2/disk_block.h>
#include <lotus_v2/signing.h>
#include <wallet/v2_wallet.h>

namespace lotus::v2::wallet {

struct ChainProfile {
    HeaderChainProfile header;
    OrdinaryCandidateProfile ordinary;
    MonetaryProfile monetary;
    BlockCostProfile costs;
    Profile Binding() const;
};
struct Snapshot {
    Hash tip{}, root{};
    uint64_t height{}, parent_mtp{};
    bool operator==(const Snapshot &) const = default;
};
// An observed chain view, not a lock or a distributed transaction token.
// Providers authenticate all fields before publishing a successful anchor.
struct ChainAnchor {
    Profile profile;
    Snapshot snapshot;
    bool operator==(const ChainAnchor &) const = default;
};
struct Submission {
    std::string result;
    Hash txid{}, txhash{};
    std::vector<Outpoint> missing;
};
struct TransactionState {
    std::string state;
    Hash txid{}, txhash{}, confirmation_block{};
    uint64_t confirmation_height{};
};
class PaymentChainProvider {
public:
    virtual ~PaymentChainProvider() = default;
    // Success publishes an authenticated current anchor for exactly expected.
    // Node providers verify header/history/MTP and state commitments against
    // the explicitly selected local full-node authority; a proof alone does
    // not establish independent chain validity.
    virtual Result ReadAnchor(const Profile &expected, ChainAnchor &out,
                              std::string &error) = 0;
    // Success + nullopt means authenticated absence at this exact anchor.
    // Found requires a complete canonical Coin and verified inclusion proof
    // (or an authenticated disk read). Outputs change only on Success.
    virtual Result Lookup(const ChainAnchor &, const Outpoint &,
                          std::optional<Coin> &out, std::string &error) = 0;
    // Reobserve exact profile/tip/root/height/MTP; changed anchor is Stale.
    // This is the latest observation, never a lock through SQLite commit.
    virtual Result Recheck(const ChainAnchor &, std::string &error) = 0;
    virtual Result Submit(const std::vector<uint8_t> &, const Hash &,
                          Submission &, std::string &error) {
        error = "submission unavailable"; return Result::Inconclusive;
    }
    virtual Result Status(const Hash &, const Hash &, const std::vector<uint8_t> &,
                          TransactionState &, std::string &error) {
        error = "transaction history unavailable"; return Result::Inconclusive;
    }
    // Stale: changed anchor. Inconclusive: temporarily unavailable authority.
    // StorageError: I/O, malformed response, invalid proof or broken provider
    // contract. Invalid: unsupported request/profile configuration. Failures
    // must never be reported as Success + absence or permanent invalidity.
};
struct CoinStatus {
    Outpoint outpoint;
    bool present{}, reserved{}, mature{};
    uint64_t value{};
};
struct Reconciled {
    Snapshot chain;
    std::vector<CoinStatus> coins;
    // Missing coins do not distinguish spending, orphaning, or no confirmation.
    // Retained historical bodies are never treated as active-chain membership.
};
class PaymentPlan {
public:
    PaymentPlan() = default;
    const Transaction &UnsignedTransaction() const { return transaction_; }
    const Snapshot &Anchor() const { return anchor_; }
    uint64_t Fee() const { return fee_; }

private:
    bool ready_{};
    Profile profile_;
    Hash owner_{}, digest_{};
    Snapshot anchor_;
    Coin coin_;
    Transaction transaction_;
    uint64_t fee_{};
    friend class PaymentEngine;
};
struct ExportedPayment {
    Hash txid{}, txhash{}, digest{};
    std::vector<uint8_t> wire;
};

class PaymentEngine {
public:
    // Provider methods require caller-serialized wallet/provider access.
    // Proof/context verification belongs to the provider. Every lookup and
    // final Recheck is pinned to the returned exact ChainAnchor. The wallet
    // atomically commits only its own outgoing record and input reservation.
    static Result TrackFunding(Wallet &, const ChainProfile &,
                               PaymentChainProvider &, const Outpoint &,
                               std::string &error);
    static Result Reconcile(Wallet &, const ChainProfile &,
                            PaymentChainProvider &, Reconciled &,
                            std::string &error);
    static Result Prepare(const Wallet &, const ChainProfile &,
                          PaymentChainProvider &, const Output &recipient,
                          uint64_t fee, PaymentPlan &, std::string &error);
    static Result SignAndReserve(Wallet &, const ChainProfile &,
                                 PaymentChainProvider &, const PaymentPlan &,
                                 ExportedPayment &, std::string &error);
    // Recovers persisted bytes, never signs or releases an input reservation.
    static Result Broadcast(const Wallet &, const ChainProfile &,
                            PaymentChainProvider &, const Hash &txid,
                            Submission &, std::string &error);
    static Result Status(const Wallet &, const ChainProfile &,
                         PaymentChainProvider &, const Hash &txid,
                         TransactionState &, std::string &error);
    // The disk overloads adapt the authenticated store into this same engine.
    // Every method requires caller-serialized access to wallet and store.
    // Only existing authenticated native coins matching the registered policy
    // can be tracked; supplied coin bytes or maturity assertions are not
    // trusted.
    static Result TrackFunding(Wallet &, const ChainProfile &, DiskStateStore &,
                               const Outpoint &, std::string &error);
    static Result Reconcile(Wallet &, const ChainProfile &, DiskStateStore &,
                            Reconciled &, std::string &error);
    // Deterministically chooses one present, mature, unreserved native coin.
    // Recipient is a canonical explicit native Output; no address format.
    static Result Prepare(const Wallet &, const ChainProfile &,
                          DiskStateStore &, const Output &recipient,
                          uint64_t fee, PaymentPlan &, std::string &error);
    // Rechecks tip, profile, coin and reservation; signs FULL mode only, then
    // validates the complete ordinary transaction. Persists outgoing bytes and
    // reservation in one SQLite transaction before returning anything to
    // export.
    static Result SignAndReserve(Wallet &, const ChainProfile &,
                                 DiskStateStore &, const PaymentPlan &,
                                 ExportedPayment &, std::string &error);
};

} // namespace lotus::v2::wallet
#endif
