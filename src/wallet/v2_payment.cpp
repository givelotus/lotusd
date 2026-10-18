// Copyright (c) 2026 The Lotus developers
#include <wallet/v2_payment.h>

#include <algorithm>
#include <key.h>
#include <limits>
#include <random.h>
#include <support/cleanse.h>

namespace lotus::v2::wallet {
namespace {
    Result Error(Result result, std::string &error, const char *message) {
        error = message;
        return result;
    }
    bool SameCoin(const Coin &a, const Coin &b) {
        std::vector<uint8_t> x, y;
        return EncodeCoin(a, x) && EncodeCoin(b, y) && x == y;
    }
    bool Mature(const Coin &coin, uint64_t height, uint64_t maturity) {
        return height >= coin.creation_height &&
               (!coin.coinbase || height - coin.creation_height >= maturity);
    }
    Result ReadSnapshot(const Profile &binding, const ChainProfile &profile,
                        DiskStateStore &store, Snapshot &out,
                        std::string &error) {
        if (!store.IsOpen())
            return Error(Result::StorageError, error, "chain store is closed");
        if (profile.Binding() != binding ||
            !store.MatchesProfile(binding.chain_id, binding.validation_digest))
            return Error(Result::Invalid, error,
                         "V2 wallet/chain profile mismatch");
        const auto metadata = store.Metadata();
        std::vector<Header> history;
        std::vector<uint8_t> body;
        if (!ReadDiskChainContext(metadata, profile.header, history, body,
                                  error) ||
            body.empty())
            return Error(Result::StorageError, error,
                         "authenticated active chain context unavailable");
        const auto &tip = history.front();
        const auto mtp = ParentMedianTime(profile.header, tip, history);
        if (!mtp || tip.height == UINT64_MAX ||
            StateRoot(binding.chain_id, tip.height, store.Root(),
                      DecodeMonetaryState(metadata.monetary)) != tip.state_root)
            return Error(Result::StorageError, error,
                         "active chain state commitment mismatch");
        out = {metadata.tip, store.Root(), tip.height, *mtp};
        return Result::Success;
    }
    bool Unchanged(const Snapshot &snapshot, const DiskStateStore &store) {
        return store.Metadata().tip == snapshot.tip &&
               store.Root() == snapshot.root;
    }
    Result ReadDiskCoin(DiskStateStore &store, const Outpoint &point,
                        std::optional<Coin> &coin, std::string &error) {
        DiskStateError failure;
        if (!store.ReadCoin(point, coin, failure)) {
            error = failure.message;
            return Result::StorageError;
        }
        if (coin && coin->outpoint != point)
            return Error(Result::StorageError, error,
                         "authenticated coin outpoint mismatch");
        return Result::Success;
    }
    class DiskProvider final : public PaymentChainProvider {
    public:
        DiskProvider(const ChainProfile &profile, DiskStateStore &store)
            : profile_(profile), store_(store) {}
        Result ReadAnchor(const Profile &expected, ChainAnchor &out,
                          std::string &error) override {
            Snapshot snapshot;
            const auto result =
                ReadSnapshot(expected, profile_, store_, snapshot, error);
            if (result != Result::Success) return result;
            out = {expected, snapshot};
            error.clear();
            return Result::Success;
        }
        Result Lookup(const ChainAnchor &anchor, const Outpoint &point,
                      std::optional<Coin> &out, std::string &error) override {
            auto result = Recheck(anchor, error);
            if (result != Result::Success) return result;
            std::optional<Coin> coin;
            result = ReadDiskCoin(store_, point, coin, error);
            if (result != Result::Success) return result;
            result = Recheck(anchor, error);
            if (result != Result::Success) return result;
            out = std::move(coin);
            error.clear();
            return Result::Success;
        }
        Result Recheck(const ChainAnchor &anchor, std::string &error) override {
            if (!store_.IsOpen())
                return Error(Result::StorageError, error,
                             "chain store is closed");
            if (profile_.Binding() != anchor.profile ||
                !store_.MatchesProfile(anchor.profile.chain_id,
                                       anchor.profile.validation_digest))
                return Error(Result::Invalid, error,
                             "V2 wallet/chain profile mismatch");
            if (!Unchanged(anchor.snapshot, store_))
                return Error(Result::Stale, error, "chain anchor changed");
            error.clear();
            return Result::Success;
        }

    private:
        const ChainProfile &profile_;
        DiskStateStore &store_;
    };
    Result ReadAnchor(const Profile &binding, const ChainProfile &profile,
                      PaymentChainProvider &provider, ChainAnchor &out,
                      std::string &error) {
        if (profile.Binding() != binding)
            return Error(Result::Invalid, error,
                         "V2 wallet/chain profile mismatch");
        ChainAnchor anchor;
        const auto result = provider.ReadAnchor(binding, anchor, error);
        if (result != Result::Success) return result;
        if (anchor.profile != binding || anchor.snapshot.height == UINT64_MAX)
            return Error(Result::StorageError, error,
                         "provider returned an invalid chain anchor");
        out = std::move(anchor);
        return Result::Success;
    }
    Result Read(PaymentChainProvider &provider, const ChainAnchor &anchor,
                const Outpoint &point, std::optional<Coin> &out,
                std::string &error) {
        std::optional<Coin> coin;
        const auto result = provider.Lookup(anchor, point, coin, error);
        if (result != Result::Success) return result;
        std::vector<uint8_t> canonical;
        if (coin && (coin->outpoint != point || !EncodeCoin(*coin, canonical)))
            return Error(Result::StorageError, error,
                         "provider returned an invalid authenticated coin");
        out = std::move(coin);
        return Result::Success;
    }
    bool Digest(const Transaction &tx, const Coin &coin,
                const ChainProfile &profile, Hash &digest, std::string &error) {
        PreparedSigningContext signing;
        return PrepareSigningContext(tx, profile.ordinary.transaction,
                                     profile.header.chain_id, {coin.output},
                                     signing, error) &&
               SigningMessage(signing, 0, 0, 0, std::nullopt, digest, error);
    }
    struct SecretBytes {
        std::array<uint8_t, 32> value{};
        ~SecretBytes() { memory_cleanse(value.data(), value.size()); }
    };
} // namespace

Profile ChainProfile::Binding() const {
    return {header.chain_id, header.genesis_id,
            BlockValidationProfileDigest(header, ordinary, monetary, costs)};
}
Result PaymentEngine::TrackFunding(Wallet &wallet, const ChainProfile &profile,
                                   PaymentChainProvider &provider,
                                   const Outpoint &point, std::string &error) {
    try {
        if (wallet.reopen_required_)
            return Error(Result::StorageError, error, "wallet reopen required");
        ChainAnchor anchor;
        auto result =
            ReadAnchor(wallet.profile_, profile, provider, anchor, error);
        if (result != Result::Success) return result;
        std::optional<Coin> coin;
        result = Read(provider, anchor, point, coin, error);
        if (result != Result::Success) return result;
        if (!coin || !wallet.Owns(coin->output))
            return Error(
                Result::Invalid, error,
                "funding coin is missing or not an owned native Payment");
        result = provider.Recheck(anchor, error);
        if (result != Result::Success) return result;
        auto tracked = wallet.tracked_;
        const auto row = std::make_pair(point.tx_id, point.index);
        auto place = std::lower_bound(tracked.begin(), tracked.end(), row);
        if (place != tracked.end() && *place == row) {
            error.clear();
            return Result::Success;
        }
        tracked.insert(place, row);
        if (!wallet.WriteState(std::move(tracked), wallet.outgoing_, error))
            return Result::StorageError;
        error.clear();
        return Result::Success;
    } catch (const std::exception &e) {
        error = e.what();
        return Result::StorageError;
    }
}
Result PaymentEngine::Reconcile(Wallet &wallet, const ChainProfile &profile,
                                PaymentChainProvider &provider, Reconciled &out,
                                std::string &error) {
    try {
        if (wallet.reopen_required_)
            return Error(Result::StorageError, error, "wallet reopen required");
        Reconciled result;
        ChainAnchor anchor;
        auto status =
            ReadAnchor(wallet.profile_, profile, provider, anchor, error);
        if (status != Result::Success) return status;
        result.chain = anchor.snapshot;
        // Outgoing records are local reservations, never chain acceptance
        // evidence.
        for (const auto &row : wallet.outgoing_) {
            Transaction tx;
            IdentityDigests ids;
            if (!DecodeTransaction(row.wire, profile.ordinary.transaction, tx,
                                   error) ||
                !ComputeIdentities(tx, profile.ordinary.transaction,
                                   profile.header.chain_id, ids, error) ||
                ids.txid != row.txid || tx.inputs.size() != 1 ||
                tx.inputs[0].prev_txid != row.previous ||
                tx.inputs[0].prev_index != row.index)
                return Error(Result::StorageError, error,
                             "corrupted outgoing V2 transaction");
        }
        for (const auto &[id, index] : wallet.tracked_) {
            Outpoint point{id, index};
            std::optional<Coin> coin;
            status = Read(provider, anchor, point, coin, error);
            if (status != Result::Success) return status;
            if (coin && !wallet.Owns(coin->output))
                return Error(Result::StorageError, error,
                             "tracked coin policy mismatch");
            result.coins.push_back(
                {point, coin.has_value(), wallet.Reserved(point),
                 coin && Mature(*coin, result.chain.height + 1,
                                profile.ordinary.coinbase_maturity),
                 coin ? coin->output.value : 0});
        }
        status = provider.Recheck(anchor, error);
        if (status != Result::Success) return status;
        // This is a diagnostic checkpoint, never a spendability cache or a
        // transaction with chainstate. All spending resolves active coins
        // again.
        auto batch = wallet.database_->MakeBatch();
        const auto checkpoint = std::make_pair(
            std::make_pair(result.chain.tip, result.chain.root),
            std::make_pair(result.chain.height, result.chain.parent_mtp));
        if (!batch->Write(std::string("v2.checkpoint"), checkpoint)) {
            wallet.reopen_required_ = true;
            return Error(Result::StorageError, error,
                         "wallet reconciliation write failed; reopen required");
        }
        out = std::move(result);
        error.clear();
        return Result::Success;
    } catch (const std::exception &e) {
        error = e.what();
        return Result::StorageError;
    }
}
Result PaymentEngine::Prepare(const Wallet &wallet, const ChainProfile &profile,
                              PaymentChainProvider &provider,
                              const Output &recipient, uint64_t fee,
                              PaymentPlan &out, std::string &error) {
    try {
        if (wallet.reopen_required_)
            return Error(Result::StorageError, error, "wallet reopen required");
        std::vector<uint8_t> encoded;
        if (recipient.flags != 0 || recipient.value == 0 ||
            recipient.token_id != Hash{} ||
            !EncodeOutput(recipient, encoded, error) ||
            recipient.value > UINT64_MAX - fee)
            return Error(Result::Invalid, error,
                         "invalid native recipient or amount/fee overflow");
        ChainAnchor anchor;
        auto status =
            ReadAnchor(wallet.profile_, profile, provider, anchor, error);
        const auto &snapshot = anchor.snapshot;
        if (status != Result::Success) return status;
        bool enough = false;
        for (const auto &[id, index] : wallet.tracked_) {
            const Outpoint point{id, index};
            if (wallet.Reserved(point)) continue;
            std::optional<Coin> coin;
            status = Read(provider, anchor, point, coin, error);
            if (status != Result::Success) return status;
            if (!coin || !wallet.Owns(coin->output) ||
                !Mature(*coin, snapshot.height + 1,
                        profile.ordinary.coinbase_maturity) ||
                coin->output.value < recipient.value + fee)
                continue;
            enough = true;
            PaymentPlan plan;
            plan.profile_ = wallet.profile_;
            plan.owner_ = wallet.PublicKey();
            plan.anchor_ = snapshot;
            plan.coin_ = *coin;
            plan.fee_ = fee;
            Input input;
            input.prev_txid = id;
            input.prev_index = index;
            input.sequence = UINT32_MAX;
            input.flags = 1;
            input.witnesses = {{wallet.script_, {}, {{}}}};
            plan.transaction_.inputs = {input};
            plan.transaction_.outputs = {recipient};
            const uint64_t change = coin->output.value - recipient.value - fee;
            if (change) {
                Output output;
                if (!wallet.PaymentOutput(change, output, error))
                    return Result::Invalid;
                plan.transaction_.outputs.push_back(std::move(output));
            }
            auto projected = plan.transaction_;
            projected.inputs[0].witnesses[0].arguments[0].resize(64);
            if (!EncodeTransaction(projected, profile.ordinary.transaction,
                                   encoded, error))
                return Result::Invalid;
            if (fee < encoded.size()) continue;
            if (!Digest(plan.transaction_, *coin, profile, plan.digest_, error))
                return Result::Invalid;
            status = provider.Recheck(anchor, error);
            if (status != Result::Success) return status;
            plan.ready_ = true;
            out = std::move(plan);
            error.clear();
            return Result::Success;
        }
        return Error(
            enough ? Result::Invalid : Result::InsufficientFunds, error,
            enough ? "explicit fee is below the final transaction byte floor"
                   : "no single mature unreserved native Payment coin covers "
                     "amount and fee");
    } catch (const std::exception &e) {
        error = e.what();
        return Result::StorageError;
    }
}
Result PaymentEngine::SignAndReserve(Wallet &wallet,
                                     const ChainProfile &profile,
                                     PaymentChainProvider &provider,
                                     const PaymentPlan &plan,
                                     ExportedPayment &out, std::string &error) {
    try {
        if (wallet.reopen_required_)
            return Error(Result::StorageError, error, "wallet reopen required");
        if (wallet.IsLocked())
            return Error(Result::Locked, error, "V2 wallet is locked");
        if (!plan.ready_ || plan.profile_ != wallet.profile_ ||
            plan.owner_ != wallet.PublicKey())
            return Error(Result::Invalid, error,
                         "payment plan wallet/profile mismatch");
        ChainAnchor anchor;
        auto status =
            ReadAnchor(wallet.profile_, profile, provider, anchor, error);
        const auto &snapshot = anchor.snapshot;
        if (status != Result::Success) return status;
        if (snapshot != plan.anchor_)
            return Error(Result::Stale, error,
                         "stale payment plan chain anchor");
        if (wallet.Reserved(plan.coin_.outpoint))
            return Error(Result::Stale, error,
                         "payment input already reserved");
        std::optional<Coin> coin;
        status = Read(provider, anchor, plan.coin_.outpoint, coin, error);
        if (status != Result::Success) return status;
        if (!coin || !SameCoin(*coin, plan.coin_) || !wallet.Owns(coin->output))
            return Error(Result::Stale, error,
                         "payment input missing or changed");
        auto tx = plan.transaction_;
        if (tx.inputs.size() != 1 ||
            tx.inputs[0].prev_txid != coin->outpoint.tx_id ||
            tx.inputs[0].prev_index != coin->outpoint.index ||
            tx.inputs[0].flags != 1 || tx.inputs[0].sequence != UINT32_MAX ||
            tx.inputs[0].path_index != 0 || tx.lock != 0 ||
            tx.inputs[0].witnesses.size() != 1 ||
            tx.inputs[0].witnesses[0].script != wallet.script_ ||
            !tx.inputs[0].witnesses[0].siblings.empty() ||
            tx.inputs[0].witnesses[0].arguments !=
                std::vector<std::vector<uint8_t>>{{}})
            return Error(Result::Invalid, error,
                         "unsupported or modified Payment plan");
        ExportedPayment exported;
        if (!Digest(tx, *coin, profile, exported.digest, error) ||
            exported.digest != plan.digest_)
            return Error(Result::Invalid, error, "modified Payment intent");
        std::vector<uint8_t> signature;
        {
            CKey key;
            if (!wallet.Decrypt(key, error)) return Result::Locked;
            SecretBytes scalar, auxiliary;
            std::copy(key.begin(), key.end(), scalar.value.begin());
            GetStrongRandBytes(auxiliary.value);
            if (!SignBip340Message(scalar.value, exported.digest, 0,
                                   auxiliary.value, signature, error))
                return Result::Invalid;
        } // Cleanse scalar and auxiliary copies before validation or storage.
        if (VerifyBip340Signature(wallet.PublicKey(), signature,
                                  exported.digest,
                                  false) != SignatureStatus::Valid)
            return Error(Result::Invalid, error,
                         "generated BIP340 signature failed verification");
        tx.inputs[0].witnesses[0].arguments[0] = std::move(signature);
        OrdinaryCandidateEffects effects;
        auto ordinary = profile.ordinary;
        ordinary.candidate_height = snapshot.height + 1;
        ordinary.parent_mtp = snapshot.parent_mtp;
        Result lookup_failure = Result::Success;
        const auto checked = CheckOrdinaryWithLookup(
            tx, ordinary, profile.header.chain_id,
            [&](const Outpoint &point, Coin &resolved, std::string &detail) {
                std::optional<Coin> found;
                const auto read = Read(provider, anchor, point, found, detail);
                if (read != Result::Success) {
                    lookup_failure = read;
                    return CoinReadResult::Error;
                }
                if (point == coin->outpoint &&
                    (!found || !SameCoin(*found, *coin))) {
                    lookup_failure = Error(Result::Stale, detail,
                                           "payment input missing or changed");
                    return CoinReadResult::Error;
                }
                if (!found) return CoinReadResult::Missing;
                resolved = std::move(*found);
                return CoinReadResult::Found;
            },
            effects, error);
        if (lookup_failure != Result::Success) return lookup_failure;
        if (checked != CandidateCheckResult::Accepted)
            return checked == CandidateCheckResult::StorageError
                       ? Result::StorageError
                   : checked == CandidateCheckResult::Inconclusive
                       ? Result::Inconclusive
                       : Result::Invalid;
        if (effects.native_fee != plan.fee_)
            return Error(Result::Invalid, error, "Payment fee changed");

        if (!EncodeTransaction(tx, profile.ordinary.transaction, exported.wire,
                               error))
            return Result::Invalid;
        exported.txid = effects.txid;
        exported.txhash = effects.txhash;
        auto outgoing = wallet.outgoing_;
        outgoing.push_back({exported.txid, coin->outpoint.tx_id,
                            coin->outpoint.index, exported.wire});
        auto tracked = wallet.tracked_;
        for (size_t i = 0; i < tx.outputs.size(); ++i) {
            if (!wallet.Owns(tx.outputs[i])) continue;
            const auto row = std::make_pair(exported.txid, uint32_t(i));
            auto place = std::lower_bound(tracked.begin(), tracked.end(), row);
            if (place == tracked.end() || *place != row)
                tracked.insert(place, row);
        }
        status = provider.Recheck(anchor, error);
        if (status != Result::Success) return status;
        if (!wallet.WriteState(std::move(tracked), std::move(outgoing), error))
            return Result::StorageError;
        out = std::move(exported);
        error.clear();
        return Result::Success;
    } catch (const std::exception &e) {
        error = e.what();
        return Result::StorageError;
    }
}
Result PaymentEngine::TrackFunding(Wallet &wallet, const ChainProfile &profile,
                                   DiskStateStore &store, const Outpoint &point,
                                   std::string &error) {
    DiskProvider provider(profile, store);
    return TrackFunding(wallet, profile, provider, point, error);
}
Result PaymentEngine::Reconcile(Wallet &wallet, const ChainProfile &profile,
                                DiskStateStore &store, Reconciled &out,
                                std::string &error) {
    DiskProvider provider(profile, store);
    return Reconcile(wallet, profile, provider, out, error);
}
Result PaymentEngine::Prepare(const Wallet &wallet, const ChainProfile &profile,
                              DiskStateStore &store, const Output &recipient,
                              uint64_t fee, PaymentPlan &out,
                              std::string &error) {
    DiskProvider provider(profile, store);
    return Prepare(wallet, profile, provider, recipient, fee, out, error);
}
Result PaymentEngine::SignAndReserve(Wallet &wallet,
                                     const ChainProfile &profile,
                                     DiskStateStore &store,
                                     const PaymentPlan &plan,
                                     ExportedPayment &out, std::string &error) {
    DiskProvider provider(profile, store);
    return SignAndReserve(wallet, profile, provider, plan, out, error);
}
namespace {
Result Recover(const Wallet &wallet, const ChainProfile &profile, const Hash &id,
               ExportedPayment &out, std::string &error) {
    if (wallet.Binding() != profile.Binding()) {
        error = "wallet profile mismatch"; return Result::Invalid;
    }
    if (!wallet.ExportOutgoing(id, 1 << 20, out.wire, error))
        return Result::StorageError;
    Transaction tx;
    IdentityDigests ids;
    std::vector<uint8_t> canonical;
    if (!DecodeTransaction(out.wire, profile.ordinary.transaction, tx, error) ||
        !EncodeTransaction(tx, profile.ordinary.transaction, canonical, error) ||
        canonical != out.wire ||
        !ComputeIdentities(tx, profile.ordinary.transaction,
                           profile.header.chain_id, ids, error) || ids.txid != id) {
        error = "persisted outgoing identity mismatch";
        return Result::StorageError;
    }
    out.txid = ids.txid; out.txhash = ids.txhash;
    return Result::Success;
}
}
Result PaymentEngine::Broadcast(const Wallet &wallet, const ChainProfile &profile,
                               PaymentChainProvider &provider, const Hash &id,
                               Submission &out, std::string &error) {
    ExportedPayment payment;
    auto result = Recover(wallet, profile, id, payment, error);
    if (result != Result::Success) return result;
    ChainAnchor anchor;
    result = ReadAnchor(wallet.Binding(), profile, provider, anchor, error);
    if (result != Result::Success) return result;
    Submission receipt;
    result = provider.Submit(payment.wire, anchor.snapshot.tip, receipt, error);
    if (result != Result::Success) return result;
    if (receipt.txid != payment.txid || receipt.txhash != payment.txhash)
        return Error(Result::Inconclusive, error, "submission receipt identity mismatch");
    out = std::move(receipt);
    return Result::Success;
}
Result PaymentEngine::Status(const Wallet &wallet, const ChainProfile &profile,
                            PaymentChainProvider &provider, const Hash &id,
                            TransactionState &out, std::string &error) {
    ExportedPayment payment;
    auto result = Recover(wallet, profile, id, payment, error);
    if (result != Result::Success) return result;
    TransactionState observed;
    result = provider.Status(payment.txid, payment.txhash, payment.wire, observed, error);
    if (result != Result::Success) return result;
    if (observed.txid != payment.txid || observed.txhash != payment.txhash)
        return Error(Result::Inconclusive, error, "transaction status identity mismatch");
    out = std::move(observed);
    return Result::Success;
}
} // namespace lotus::v2::wallet
