// Copyright (c) 2026 The Lotus developers
#include <wallet/v2_wallet.h>

#include <key.h>
#include <lotus_v2/commitment.h>
#include <random.h>
#include <util/translation.h>
#include <wallet/sqlite.h>

#include <algorithm>
#include <set>
#include <stdexcept>

namespace lotus::v2::wallet {
namespace {
    constexpr size_t MAX_TRACKED = 10000, MAX_OUTGOING = 1000;
    std::string Hex(const Hash &hash) {
        static constexpr char chars[] = "0123456789abcdef";
        std::string out;
        for (uint8_t byte : hash) {
            out += chars[byte >> 4];
            out += chars[byte & 15];
        }
        return out;
    }
    bool Fail(std::string &error, const char *message) {
        error = message;
        return false;
    }
    bool Valid(const Profile &profile) {
        return profile.chain_id != Hash{} && profile.genesis_id != Hash{} &&
               profile.validation_digest != Hash{};
    }
    std::vector<uint8_t> Script(const CPubKey &pub) {
        std::vector<uint8_t> script{0x20};
        script.insert(script.end(), pub.begin() + 1, pub.end());
        script.insert(script.end(), {0xbc, 0x4e});
        return script;
    }
    std::unique_ptr<WalletDatabase> Database(const fs::path &path,
                                             const Profile &profile,
                                             bool create, std::string &error) {
        if (!Valid(profile)) {
            error = "explicit nonzero V2 wallet profile required";
            return {};
        }
        if ((fs::exists(path) && !fs::is_directory(path)) ||
            fs::exists(path / "wallet.dat")) {
            error = "V2 wallet requires a SQLite directory; legacy wallets are "
                    "unsupported";
            return {};
        }
        const bool existing = fs::exists(path / WALLET_DATABASE_FILENAME);
        if (existing == create) {
            error = create ? "V2 wallet already exists"
                           : "V2 wallet does not exist";
            return {};
        }
        DatabaseOptions options;
        options.wallet_profile = profile.StorageIdentity();
        DatabaseStatus status;
        bilingual_str detail;
        auto db = MakeSQLiteDatabase(path, options, status, detail);
        if (!db) error = detail.original;
        return db;
    }
} // namespace

std::string Profile::StorageIdentity() const {
    return "lotus-v2-native-payment-wallet/1:" + Hex(chain_id) + ":" +
           Hex(genesis_id) + ":" + Hex(validation_digest);
}
Wallet::Wallet(std::unique_ptr<WalletDatabase> database, Profile profile)
    : database_(std::move(database)), profile_(profile) {}
Wallet::~Wallet() {
    Lock();
}
Hash Wallet::PublicKey() const {
    Hash out{};
    std::copy(public_key_.begin() + 1, public_key_.end(), out.begin());
    return out;
}
bool Wallet::Create(const fs::path &path, const Profile &profile,
                    const SecureString &passphrase,
                    std::unique_ptr<Wallet> &out, std::string &error) {
    try {
        if (passphrase.empty())
            return Fail(error, "nonempty encryption passphrase required");
        auto db = Database(path, profile, true, error);
        if (!db) return false;
        std::unique_ptr<Wallet> wallet(new Wallet(std::move(db), profile));
        CKey key = CKey::MakeCompressedKey();
        wallet->public_key_ = key.GetPubKey();
        wallet->master_.vchSalt.resize(WALLET_CRYPTO_SALT_SIZE);
        GetStrongRandBytes(wallet->master_.vchSalt);
        CKeyingMaterial master(WALLET_CRYPTO_KEY_SIZE);
        GetStrongRandBytes(master);
        CCrypter crypter;
        if (!crypter.SetKeyFromPassphrase(passphrase, wallet->master_.vchSalt,
                                          wallet->master_.nDeriveIterations,
                                          wallet->master_.nDerivationMethod) ||
            !crypter.Encrypt(master, wallet->master_.vchCryptedKey))
            return Fail(error, "wallet master key encryption failed");
        CKeyingMaterial secret(key.begin(), key.end());
        if (!EncryptSecret(master, secret, wallet->public_key_.GetHash(),
                           wallet->encrypted_key_))
            return Fail(error, "wallet private key encryption failed");
        auto batch = wallet->database_->MakeBatch();
        if (!batch->TxnBegin() ||
            !batch->Write(std::string("v2.schema"), uint32_t{1}, false) ||
            !batch->Write(std::string("v2.master"), wallet->master_, false) ||
            !batch->Write(std::string("v2.public"), wallet->public_key_,
                          false) ||
            !batch->Write(std::string("v2.encrypted"), wallet->encrypted_key_,
                          false) ||
            !batch->Write(std::string("v2.tracked"), wallet->tracked_, false) ||
            !batch->Write(std::string("v2.outgoing"), wallet->outgoing_,
                          false) ||
            !batch->TxnCommit())
            return Fail(error, "wallet encrypted creation transaction failed; "
                               "incomplete wallet retained");
        out = std::move(wallet);
        error.clear();
        return true;
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
}
bool Wallet::Open(const fs::path &path, const Profile &profile,
                  std::unique_ptr<Wallet> &out, std::string &error) {
    try {
        auto db = Database(path, profile, false, error);
        if (!db) return false;
        std::unique_ptr<Wallet> wallet(new Wallet(std::move(db), profile));
        if (!wallet->Load(error)) return false;
        out = std::move(wallet);
        error.clear();
        return true;
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
}
bool Wallet::Load(std::string &error) {
    auto batch = database_->MakeBatch();
    uint32_t version = 0;
    if (!batch->Read(std::string("v2.schema"), version) || version != 1 ||
        !batch->Read(std::string("v2.master"), master_) ||
        !batch->Read(std::string("v2.public"), public_key_) ||
        !batch->Read(std::string("v2.encrypted"), encrypted_key_) ||
        !batch->Read(std::string("v2.tracked"), tracked_) ||
        !batch->Read(std::string("v2.outgoing"), outgoing_))
        return Fail(error, "incomplete or unsupported V2 wallet records");
    if (!public_key_.IsCompressed() || !public_key_.IsFullyValid() ||
        encrypted_key_.size() != 48 || master_.vchCryptedKey.size() != 48 ||
        master_.vchSalt.size() != WALLET_CRYPTO_SALT_SIZE ||
        master_.nDerivationMethod != 0 || master_.nDeriveIterations < 25000 ||
        master_.nDeriveIterations > 10000000 || tracked_.size() > MAX_TRACKED ||
        outgoing_.size() > MAX_OUTGOING)
        return Fail(error, "invalid V2 encrypted wallet records");
    if (!std::is_sorted(tracked_.begin(), tracked_.end()) ||
        std::adjacent_find(tracked_.begin(), tracked_.end()) != tracked_.end())
        return Fail(error, "invalid V2 tracked outpoint order");
    std::set<Hash> txids;
    std::set<std::pair<Hash, uint32_t>> reservations;
    for (const auto &row : outgoing_)
        if (row.wire.empty() || row.wire.size() > (8 << 20) ||
            !txids.insert(row.txid).second ||
            !reservations.emplace(row.previous, row.index).second)
            return Fail(error, "invalid V2 outgoing records");
    if (batch->Exists(std::string("v2.payment"))) {
        if (!batch->Read(std::string("v2.payment"), script_) ||
            script_ != Script(public_key_))
            return Fail(error, "unsupported V2 Payment policy");
    }
    return true;
}
bool Wallet::Decrypt(CKey &key, std::string &error) const {
    if (IsLocked()) return Fail(error, "V2 wallet is locked");
    if (!DecryptKey(master_secret_, encrypted_key_, public_key_, key))
        return Fail(error, "V2 wallet key authentication failed");
    return true;
}
bool Wallet::Unlock(const SecureString &passphrase, std::string &error) {
    try {
        CCrypter crypter;
        CKeyingMaterial candidate;
        CKey key;
        if (!crypter.SetKeyFromPassphrase(passphrase, master_.vchSalt,
                                          master_.nDeriveIterations,
                                          master_.nDerivationMethod) ||
            !crypter.Decrypt(master_.vchCryptedKey, candidate) ||
            !DecryptKey(candidate, encrypted_key_, public_key_, key))
            return Fail(error,
                        "incorrect passphrase or corrupted V2 wallet key");
        master_secret_ = std::move(candidate);
        error.clear();
        return true;
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
}
void Wallet::Lock() {
    if (!master_secret_.empty())
        memory_cleanse(master_secret_.data(), master_secret_.size());
    master_secret_.clear();
}
bool Wallet::RegisterPayment(const std::vector<uint8_t> &script,
                             const std::vector<Hash> &proof,
                             std::string &error) {
    try {
        if (reopen_required_) return Fail(error, "wallet reopen required");
        if (!proof.empty() || script != Script(public_key_))
            return Fail(error,
                        "unsupported Payment script, proof or owner binding");
        if (!script_.empty()) {
            error.clear();
            return true;
        }
        auto copy = script;
        reopen_required_ = true;
        auto batch = database_->MakeBatch();
        if (!batch->Write(std::string("v2.payment"), script, false))
            return Fail(error, "failed to persist Payment policy");
        script_.swap(copy);
        reopen_required_ = false;
        error.clear();
        return true;
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
}
bool Wallet::PaymentOutput(uint64_t value, Output &out,
                           std::string &error) const {
    if (script_.empty()) return Fail(error, "Payment policy is not registered");
    Output result;
    result.value = value;
    result.branches = {BranchLeaf(script_)};
    result.paths = {{0}};
    out = std::move(result);
    error.clear();
    return true;
}
bool Wallet::Owns(const Output &output) const {
    return !script_.empty() && output.flags == 0 && output.token_id == Hash{} &&
           output.branches == std::vector<Hash>{BranchLeaf(script_)} &&
           output.paths == std::vector<std::vector<uint8_t>>{{0}};
}
bool Wallet::Reserved(const Outpoint &point) const {
    return std::any_of(
        outgoing_.begin(), outgoing_.end(), [&](const auto &row) {
            return row.previous == point.tx_id && row.index == point.index;
        });
}
bool Wallet::WriteState(Tracked tracked, std::vector<Outgoing> outgoing,
                        std::string &error) {
    if (tracked.size() > MAX_TRACKED || outgoing.size() > MAX_OUTGOING)
        return Fail(error, "V2 wallet local record capacity exceeded");
    reopen_required_ = true;
    auto batch = database_->MakeBatch();
    if (!batch->TxnBegin() ||
        !batch->Write(std::string("v2.tracked"), tracked) ||
        !batch->Write(std::string("v2.outgoing"), outgoing) ||
        !batch->TxnCommit()) {
        reopen_required_ = true;
        return Fail(error, "V2 wallet state transaction failed; reopen and "
                           "reconcile before retry");
    }
    tracked_.swap(tracked);
    outgoing_.swap(outgoing);
    reopen_required_ = false;
    return true;
}
bool Wallet::Backup(const std::string &destination, std::string &error) const {
    try {
        if (!database_->Backup(destination))
            return Fail(error, "V2 wallet backup failed");
        error.clear();
        return true;
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
}
bool Wallet::ListOutgoing(std::vector<Hash> &out, std::string &error) const {
    try {
        if (reopen_required_) return Fail(error, "wallet reopen required");
        if (outgoing_.size() > MAX_OUTGOING)
            return Fail(error, "V2 outgoing record capacity exceeded");
        std::vector<Hash> ids;
        ids.reserve(outgoing_.size());
        for (const auto &row : outgoing_)
            ids.push_back(row.txid);
        out.swap(ids);
        error.clear();
        return true;
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
}
bool Wallet::ExportOutgoing(const Hash &txid, size_t max_bytes,
                            std::vector<uint8_t> &out,
                            std::string &error) const {
    try {
        if (reopen_required_) return Fail(error, "wallet reopen required");
        const auto item =
            std::find_if(outgoing_.begin(), outgoing_.end(),
                         [&](const auto &row) { return row.txid == txid; });
        if (item == outgoing_.end())
            return Fail(error, "unknown exported V2 transaction");
        if (item->wire.size() > max_bytes)
            return Fail(error, "V2 outgoing transaction exceeds byte capacity");
        auto bytes = item->wire;
        out.swap(bytes);
        error.clear();
        return true;
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
}
bool Wallet::Abandon(const Hash &txid, std::string &error) {
    try {
        if (reopen_required_) return Fail(error, "wallet reopen required");
        auto outgoing = outgoing_;
        auto item =
            std::find_if(outgoing.begin(), outgoing.end(),
                         [&](const auto &row) { return row.txid == txid; });
        if (item == outgoing.end())
            return Fail(error, "unknown exported V2 transaction");
        outgoing.erase(item);
        if (!WriteState(tracked_, outgoing, error)) return false;
        error.clear();
        return true;
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
}
} // namespace lotus::v2::wallet
