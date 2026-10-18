// Copyright (c) 2026 The Lotus developers
#ifndef BITCOIN_WALLET_V2_WALLET_H
#define BITCOIN_WALLET_V2_WALLET_H

#include <lotus_v2/sparse_state.h>
#include <memory>
#include <string>
#include <vector>
#include <wallet/crypter.h>
#include <wallet/db.h>

namespace lotus::v2::wallet {

struct Profile {
    ChainId chain_id{};
    Hash genesis_id{};
    Hash validation_digest{};
    bool operator==(const Profile &) const = default;
    // Versioned local storage identity, not a consensus hash or network
    // address.
    std::string StorageIdentity() const;
};

enum class Result {
    Success,
    Invalid,
    Locked,
    Stale,
    InsufficientFunds,
    StorageError,
    // Local validation could not finish; no signed bytes/reservation exported.
    Inconclusive
};
class PaymentEngine;

// One encrypted, freshly generated key and its exact supported Payment policy.
// Caller initializes ABC randomness/ECC and serializes all wallet/chain access.
// No inherited wallet transactions, descriptors, addresses or key import API.
class Wallet {
public:
    Wallet(const Wallet &) = delete;
    Wallet &operator=(const Wallet &) = delete;
    ~Wallet();
    static bool Create(const fs::path &, const Profile &,
                       const SecureString &passphrase,
                       std::unique_ptr<Wallet> &, std::string &error);
    static bool Open(const fs::path &, const Profile &,
                     std::unique_ptr<Wallet> &, std::string &error);
    const Profile &Binding() const { return profile_; }
    Hash PublicKey() const;
    bool Unlock(const SecureString &, std::string &error);
    void Lock();
    bool IsLocked() const { return master_secret_.empty(); }
    // Only PUSH32 owner, CHECKSIGVERIFY, TRUE with an empty proof is supported.
    // Script bytes must match this wallet's generated x-only public key.
    bool RegisterPayment(const std::vector<uint8_t> &script,
                         const std::vector<Hash> &proof, std::string &error);
    bool PaymentOutput(uint64_t value, Output &, std::string &error) const;
    bool Backup(const std::string &destination, std::string &error) const;
    // Explicitly releases an exported transaction's local reservation. It does
    // not revoke bytes previously exported or remove a transaction from a
    // chain.
    bool Abandon(const Hash &txid, std::string &error);
    // Read-only recovery of already persisted outgoing transactions. Available
    // while locked; no signing, reservation release or chain acceptance.
    // IDs are bounded by the wallet's existing outgoing record limit. Outputs
    // are unchanged on failure, including reopen-required and byte-cap refusal.
    bool ListOutgoing(std::vector<Hash> &out, std::string &error) const;
    bool ExportOutgoing(const Hash &txid, size_t max_bytes,
                        std::vector<uint8_t> &out, std::string &error) const;

private:
    Wallet(std::unique_ptr<WalletDatabase>, Profile);
    struct Outgoing {
        Hash txid{}, previous{};
        uint32_t index{};
        std::vector<uint8_t> wire;
        SERIALIZE_METHODS(Outgoing, obj) {
            READWRITE(obj.txid, obj.previous, obj.index, obj.wire);
        }
    };
    using Tracked = std::vector<std::pair<Hash, uint32_t>>;
    std::unique_ptr<WalletDatabase> database_;
    Profile profile_;
    CMasterKey master_;
    CPubKey public_key_;
    std::vector<uint8_t> encrypted_key_, script_;
    CKeyingMaterial master_secret_;
    bool reopen_required_{};
    Tracked tracked_;
    std::vector<Outgoing> outgoing_;
    bool Load(std::string &);
    bool Owns(const Output &) const;
    bool Reserved(const Outpoint &) const;
    bool Decrypt(CKey &, std::string &) const;
    bool WriteState(Tracked, std::vector<Outgoing>, std::string &);
    friend class PaymentEngine;
};

} // namespace lotus::v2::wallet
#endif
