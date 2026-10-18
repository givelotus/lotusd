// Copyright (c) 2026 The Lotus developers
#include <functional>
#include <key.h>
#include <random.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/v2_node_provider.h>
#include <wallet/v2_provider_test/fixtures.h>

const std::function<std::string(const char *)> G_TRANSLATION_FUN = nullptr;
namespace {
using namespace provider_fixture;
class DiskProofProvider : public PaymentChainProvider {
public:
    Chain &chain;
    unsigned reads{}, lookups{}, rechecks{};
    unsigned stale_read{}, stale_lookup{}, stale_recheck{};
    Result lookup_failure{Result::Success};
    unsigned failure_lookup{};
    bool wrong_profile{}, wrong_point{}, max_height{};
    V2Hash receipt_id{}, receipt_hash{};
    unsigned submits{}, statuses{};
    Result Submit(const std::vector<uint8_t> &, const V2Hash &, Submission &out,
                  std::string &) override {
        ++submits;
        out = {"accepted", receipt_id, receipt_hash, {}};
        return Result::Success;
    }
    Result Status(const V2Hash &, const V2Hash &, const std::vector<uint8_t> &,
                  TransactionState &out, std::string &) override {
        ++statuses;
        out = {"pending", receipt_id, receipt_hash, {}, 0};
        return Result::Success;
    }
    explicit DiskProofProvider(Chain &c) : chain(c) {}
    Result ReadAnchor(const Profile &expected, ChainAnchor &out,
                      std::string &error) override {
        if (++reads == stale_read) return Result::Stale;
        Check(expected == chain.profile.Binding(), "provider expected binding");
        const auto mtp = ParentMedianTime(chain.profile.header,
                                          chain.history.front(), chain.history);
        Check(mtp.has_value(), "provider MTP");
        out = {expected,
               {chain.store.Metadata().tip, chain.store.Root(),
                chain.history.front().height, *mtp}};
        if (wrong_profile) out.profile.validation_digest[0] ^= 1;
        if (max_height) out.snapshot.height = UINT64_MAX;
        error.clear();
        return Result::Success;
    }
    Result Lookup(const ChainAnchor &anchor, const Outpoint &point,
                  std::optional<Coin> &out, std::string &error) override {
        if (++lookups == stale_lookup) return Result::Stale;
        if (lookup_failure != Result::Success &&
            (!failure_lookup || lookups == failure_lookup))
            return lookup_failure;
        if (anchor.snapshot.tip != chain.store.Metadata().tip ||
            anchor.snapshot.root != chain.store.Root())
            return Result::Stale;
        CoinProof proof;
        DiskStateError failure;
        Check(chain.store.Prove(point, proof, failure), failure.message);
        Check(VerifyCoinProof(point, proof, anchor.snapshot.root),
              "real proof");
        out = proof.presence == ProofPresence::Present ? proof.coin
                                                       : std::nullopt;
        if (wrong_point && out) out->outpoint.index ^= 1;
        error.clear();
        return Result::Success;
    }
    Result Recheck(const ChainAnchor &anchor, std::string &error) override {
        if (++rechecks == stale_recheck) return Result::Stale;
        ChainAnchor current;
        auto result = ReadAnchor(anchor.profile, current, error);
        if (result != Result::Success) return result;
        return current == anchor ? Result::Success : Result::Stale;
    }
};
UniValue ContextResponse(Chain &chain, const UniValue &request) {
    UniValue response(UniValue::VOBJ);
    response.pushKV("id", request["id"]);
    response.pushKV("ok", true);
    const auto binding = chain.profile.Binding();
    response.pushKV("chain_id", HexStr(binding.chain_id));
    response.pushKV("genesis_id", HexStr(binding.genesis_id));
    response.pushKV("profile_digest", HexStr(binding.validation_digest));
    response.pushKV("tip", HexStr(chain.store.Metadata().tip));
    response.pushKV("height", chain.history.front().height);
    response.pushKV("utxo_root", HexStr(chain.store.Root()));
    response.pushKV("state_root", HexStr(chain.history.front().state_root));
    response.pushKV("monetary_bytes", HexStr(EncodeMonetaryState(chain.money)));
    response.pushKV("tip_header", HexStr(chain.store.Metadata().header));
    UniValue history(UniValue::VARR);
    for (const auto &header : chain.history) {
        std::array<uint8_t, HEADER_SIZE> bytes{};
        Check(SerializeHeader(header, bytes), "serialize fixture history");
        history.push_back(HexStr(bytes));
    }
    response.pushKV("history", history);
    UniValue proof;
    if (!request["outpoint"].isNull()) {
        Outpoint point;
        const auto bytes = ParseHex(request["outpoint"]["txid"].get_str());
        std::copy(bytes.begin(), bytes.end(), point.tx_id.begin());
        point.index = request["outpoint"]["index"].getInt<uint32_t>();
        CoinProof actual;
        DiskStateError failure;
        Check(chain.store.Prove(point, actual, failure), failure.message);
        proof.setObject();
        proof.pushKV("presence", unsigned(actual.presence));
        UniValue coin;
        if (actual.coin) {
            std::vector<uint8_t> encoded;
            Check(EncodeCoin(*actual.coin, encoded), "fixture encode coin");
            coin = UniValue(HexStr(encoded));
        }
        proof.pushKV("coin", coin);
        proof.pushKV("bitmap", HexStr(actual.bitmap));
        UniValue siblings(UniValue::VARR);
        for (const auto &hash : actual.siblings)
            siblings.push_back(HexStr(hash));
        proof.pushKV("siblings", siblings);
    }
    response.pushKV("proof", proof);
    return response;
}
void NodeVerification(const std::string &directory) {
    Chain chain(directory + "/node-chain");
    Output funding;
    funding.value = 100000;
    funding.branches = {BranchLeaf(std::vector<uint8_t>{0x4e})};
    funding.paths = {{0}};
    const auto point = chain.Append(funding);
    chain.Append(Chain::Burn());
    std::function<void(UniValue &)> mutate;
    std::string suffix;
    bool unavailable = false;
    std::string remote_failure;
    unsigned requests = 0;
    NodePaymentChainProvider provider(
        chain.profile,
        [&](std::string_view wire, std::string &out, std::string &error) {
            ++requests;
            Check(wire.size() <= NODE_WALLET_REQUEST_LIMIT,
                  "bounded provider request");
            if (unavailable) {
                error = "unavailable fixture";
                return false;
            }
            UniValue request;
            Check(request.read(std::string(wire)), "parse provider request");
            auto response = ContextResponse(chain, request);
            if (!remote_failure.empty()) {
                response.setObject();
                response.pushKV("id", request["id"]);
                response.pushKV("ok", false);
                response.pushKV("result", remote_failure);
                response.pushKV("error", "typed fixture refusal");
            }
            if (mutate) mutate(response);
            out = response.write() + "\n" + suffix;
            return true;
        });
    std::string error;
    ChainAnchor anchor;
    Success(provider.ReadAnchor(chain.profile.Binding(), anchor, error), error);
    std::optional<Coin> coin;
    Success(provider.Lookup(anchor, point, coin, error), error);
    Check(coin && coin->outpoint == point &&
              coin->output.value == funding.value,
          "node verifies actual inclusion proof");
    Outpoint absent{};
    Success(provider.Lookup(anchor, absent, coin, error), error);
    Check(!coin, "node verifies actual nonmembership proof");
    Success(provider.Recheck(anchor, error), error);
    const auto original = anchor;
    for (const std::string field :
         {"chain_id", "genesis_id", "profile_digest", "utxo_root", "state_root",
          "monetary_bytes", "tip_header"}) {
        mutate = [field](UniValue &value) {
            auto bytes = value[field].get_str();
            bytes[0] = bytes[0] == '0' ? '1' : '0';
            value.pushKV(field, bytes);
        };
        ChainAnchor sentinel = original;
        Check(provider.ReadAnchor(chain.profile.Binding(), sentinel, error) ==
                  Result::StorageError,
              "node rejects context mutation: " + field);
        Check(sentinel == original, "context rejection preserves anchor");
    }
    mutate = [](UniValue &value) {
        UniValue history = value["history"];
        auto bytes = history[1].get_str();
        bytes[0] = bytes[0] == '0' ? '1' : '0';
        UniValue changed(UniValue::VARR);
        for (size_t i = 0; i < history.size(); ++i)
            changed.push_back(i == 1 ? UniValue(bytes) : history[i]);
        value.pushKV("history", changed);
    };
    Check(provider.ReadAnchor(chain.profile.Binding(), anchor, error) ==
              Result::StorageError,
          "node rejects broken history link");
    for (const std::string field : {"coin", "bitmap"}) {
        mutate = [field](UniValue &value) {
            auto proof = value["proof"];
            auto bytes = proof[field].get_str();
            bytes[0] = bytes[0] == '0' ? '1' : '0';
            proof.pushKV(field, bytes);
            value.pushKV("proof", proof);
        };
        coin = Coin{};
        Check(provider.Lookup(original, point, coin, error) ==
                  Result::StorageError,
              "node rejects proof mutation: " + field);
        Check(coin && coin->outpoint == Outpoint{},
              "proof failure preserves coin sentinel");
    }
    mutate = [](UniValue &value) {
        auto proof = value["proof"];
        UniValue siblings(UniValue::VARR);
        for (unsigned i = 0; i < 257; ++i)
            siblings.push_back(HexStr(V2Hash{}));
        proof.pushKV("siblings", siblings);
        value.pushKV("proof", proof);
    };
    Check(provider.Lookup(original, point, coin, error) == Result::StorageError,
          "oversized sibling count rejected");
    mutate = [](UniValue &value) {
        UniValue history(UniValue::VARR);
        for (unsigned i = 0; i < 12; ++i)
            history.push_back(value["tip_header"]);
        value.pushKV("history", history);
    };
    Check(provider.ReadAnchor(chain.profile.Binding(), anchor, error) ==
              Result::StorageError,
          "oversized history count rejected");
    mutate = [](UniValue &value) { value.pushKV("unexpected", true); };
    Check(provider.ReadAnchor(chain.profile.Binding(), anchor, error) ==
              Result::StorageError,
          "unknown response field rejected");
    mutate = [](UniValue &value) {
        value.pushKVEnd("height", value["height"]);
    };
    Check(provider.ReadAnchor(chain.profile.Binding(), anchor, error) ==
              Result::StorageError,
          "duplicate response field rejected");
    mutate = {};
    suffix = "{}\n";
    Check(provider.ReadAnchor(chain.profile.Binding(), anchor, error) ==
              Result::StorageError,
          "extra response line rejected");
    suffix.assign(NODE_WALLET_RESPONSE_LIMIT, ' ');
    Check(provider.ReadAnchor(chain.profile.Binding(), anchor, error) ==
              Result::StorageError,
          "oversized response rejected");
    suffix.clear();
    unavailable = true;
    Check(provider.ReadAnchor(chain.profile.Binding(), anchor, error) ==
              Result::StorageError,
          "exchange failure cannot authenticate absence");
    unavailable = false;
    for (const auto &[name, expected] :
         std::vector<std::pair<std::string, Result>>{
             {"stale", Result::Stale},
             {"inconclusive", Result::Inconclusive},
             {"storage_error", Result::StorageError},
             {"invalid", Result::Invalid}}) {
        remote_failure = name;
        ChainAnchor untouched = original;
        Check(provider.ReadAnchor(chain.profile.Binding(), untouched, error) ==
                  expected,
              "remote typed failure preserved: " + name);
        Check(untouched == original, "typed remote failure preserves anchor");
    }
    remote_failure.clear();
    chain.Append(Chain::Burn());
    Check(provider.Lookup(original, point, coin, error) == Result::Stale,
          "changed valid anchor before lookup is stale");
    Check(provider.Recheck(original, error) == Result::Stale,
          "changed valid anchor before final check is stale");
    Check(requests > 15, "node mutation exchange exercised");
}
void Unexported(const ExportedPayment &out) {
    Check(out.wire == std::vector<uint8_t>{99} && out.txid[0] == 99,
          "failure preserves export sentinel");
}
void EngineProvider(const std::string &directory) {
    Chain chain(directory + "/chain");
    std::string error;
    const SecureString passphrase("provider-test-ephemeral-passphrase");
    std::unique_ptr<Wallet> wallet;
    Check(Wallet::Create(fs::PathFromString(directory + "/wallet"),
                         chain.profile.Binding(), passphrase, wallet, error),
          error);
    Check(
        wallet->RegisterPayment(PaymentScript(wallet->PublicKey()), {}, error),
        error);
    Check(wallet->Unlock(passphrase, error), error);
    Output funding;
    Check(wallet->PaymentOutput(100000, funding, error), error);
    const auto point = chain.Append(funding);
    DiskProofProvider provider(chain);
    NodePaymentChainProvider node(
        chain.profile, [&](std::string_view request_wire, std::string &response,
                           std::string &) {
            UniValue request;
            Check(request.read(std::string(request_wire)),
                  "engine node request");
            response = ContextResponse(chain, request).write() + "\n";
            return true;
        });
    Success(
        PaymentEngine::TrackFunding(*wallet, chain.profile, node, point, error),
        error);
    Output recipient;
    recipient.value = 1000;
    recipient.branches = {BranchLeaf(std::vector<uint8_t>{0x4e})};
    recipient.paths = {{0}};
    PaymentPlan immature;
    Check(PaymentEngine::Prepare(*wallet, chain.profile, provider, recipient,
                                 1000, immature,
                                 error) == Result::InsufficientFunds,
          "authenticated immature coin unavailable");
    chain.Append(Chain::Burn());
    PaymentPlan disk, remote;
    Success(PaymentEngine::Prepare(*wallet, chain.profile, chain.store,
                                   recipient, 1000, disk, error),
            error);
    Success(PaymentEngine::Prepare(*wallet, chain.profile, node, recipient,
                                   1000, remote, error),
            error);
    std::vector<uint8_t> a, b;
    Check(EncodeTransaction(disk.UnsignedTransaction(),
                            chain.profile.ordinary.transaction, a, error),
          error);
    Check(EncodeTransaction(remote.UnsignedTransaction(),
                            chain.profile.ordinary.transaction, b, error),
          error);
    Check(a == b && disk.Anchor() == remote.Anchor() &&
              disk.Fee() == remote.Fee(),
          "disk/provider exact unsigned semantics");
    for (unsigned phase = 0; phase != 4; ++phase) {
        DiskProofProvider stale(chain);
        if (phase == 0) stale.stale_read = 1;
        if (phase == 1) stale.stale_lookup = 1;
        if (phase == 2) stale.stale_recheck = 1;
        if (phase == 3) stale.stale_lookup = 2;
        ExportedPayment unchanged;
        unchanged.wire = {99};
        unchanged.txid[0] = 99;
        Check(PaymentEngine::SignAndReserve(*wallet, chain.profile, stale,
                                            remote, unchanged,
                                            error) == Result::Stale,
              "stale provider before lookup/sign/final check");
        Unexported(unchanged);
        PaymentPlan retry;
        Success(PaymentEngine::Prepare(*wallet, chain.profile, provider,
                                       recipient, 1000, retry, error),
                error);
    }
    for (auto failure : {Result::StorageError, Result::Inconclusive}) {
        DiskProofProvider failed(chain);
        failed.lookup_failure = failure;
        ExportedPayment unchanged;
        unchanged.wire = {99};
        unchanged.txid[0] = 99;
        Check(PaymentEngine::SignAndReserve(*wallet, chain.profile, failed,
                                            remote, unchanged,
                                            error) == failure,
              "provider failure retains classification");
        Unexported(unchanged);
    }
    for (auto failure : {Result::StorageError, Result::Inconclusive}) {
        DiskProofProvider failed(chain);
        failed.lookup_failure = failure;
        failed.failure_lookup = 2;
        ExportedPayment unchanged;
        unchanged.wire = {99};
        unchanged.txid[0] = 99;
        Check(PaymentEngine::SignAndReserve(*wallet, chain.profile, failed,
                                            remote, unchanged,
                                            error) == failure,
              "ordinary callback retains provider failure classification");
        Unexported(unchanged);
        PaymentPlan retry;
        Success(PaymentEngine::Prepare(*wallet, chain.profile, provider,
                                       recipient, 1000, retry, error),
                error);
    }
    auto mismatched = chain.profile;
    mismatched.header.chain_id[0] ^= 1;
    DiskProofProvider untouched(chain);
    PaymentPlan invalid_profile;
    Check(PaymentEngine::Prepare(*wallet, mismatched, untouched, recipient,
                                 1000, invalid_profile,
                                 error) == Result::Invalid &&
              untouched.reads == 0 && untouched.lookups == 0,
          "caller profile mismatch refuses before provider lookup");
    DiskProofProvider broken(chain);
    broken.wrong_profile = true;
    PaymentPlan unchanged;
    Check(PaymentEngine::Prepare(*wallet, chain.profile, broken, recipient,
                                 1000, unchanged,
                                 error) == Result::StorageError,
          "successful wrong provider binding is broken contract");
    DiskProofProvider wrong_point(chain);
    wrong_point.wrong_point = true;
    Check(PaymentEngine::Prepare(*wallet, chain.profile, wrong_point, recipient,
                                 1000, unchanged,
                                 error) == Result::StorageError,
          "successful wrong coin outpoint is broken contract");
    ExportedPayment exported;
    Success(PaymentEngine::SignAndReserve(*wallet, chain.profile, node, remote,
                                          exported, error),
            error);
    Transaction signed_tx;
    Check(DecodeTransaction(exported.wire, chain.profile.ordinary.transaction,
                            signed_tx, error),
          error);
    Check(VerifyBip340Signature(
              wallet->PublicKey(),
              signed_tx.inputs.at(0).witnesses.at(0).arguments.at(0),
              exported.digest, false) == SignatureStatus::Valid,
          "provider BIP340 signature");
    signed_tx.inputs[0].witnesses[0].arguments[0].clear();
    Check(EncodeTransaction(signed_tx, chain.profile.ordinary.transaction, b,
                            error),
          error);
    Check(a == b, "signed provider transaction preserves unsigned intent");
    Reconciled reconciled;
    Success(PaymentEngine::Reconcile(*wallet, chain.profile, node, reconciled,
                                     error),
            error);
    const auto tracked = std::find_if(
        reconciled.coins.begin(), reconciled.coins.end(),
        [&](const CoinStatus &status) { return status.outpoint == point; });
    Check(tracked != reconciled.coins.end() && tracked->reserved,
          "successful export reserves input");
    PaymentPlan reserved;
    Check(PaymentEngine::Prepare(*wallet, chain.profile, provider, recipient,
                                 1000, reserved,
                                 error) == Result::InsufficientFunds,
          "reserved funding unavailable");
    DiskProofProvider bad_receipt(chain);
    bad_receipt.receipt_id = exported.txid;
    bad_receipt.receipt_hash = exported.txhash;
    Submission guarded_receipt{"sentinel", {}, {}, {}};
    for (bool maximum : {false, true}) {
        bad_receipt.wrong_profile = !maximum;
        bad_receipt.max_height = maximum;
        Check(PaymentEngine::Broadcast(*wallet, chain.profile, bad_receipt,
                                       exported.txid, guarded_receipt, error) == Result::StorageError,
              "generic provider invalid anchor rejected before submission");
        Check(bad_receipt.submits == 0 && guarded_receipt.result == "sentinel",
              "invalid anchor cannot submit or publish receipt");
    }
    bad_receipt.wrong_profile = bad_receipt.max_height = false;
    for (bool hash : {false, true}) {
        bad_receipt.receipt_id = exported.txid;
        bad_receipt.receipt_hash = exported.txhash;
        if (hash) bad_receipt.receipt_hash[0] ^= 1;
        else bad_receipt.receipt_id[0] ^= 1;
        Check(PaymentEngine::Broadcast(*wallet, chain.profile, bad_receipt,
                                       exported.txid, guarded_receipt, error) == Result::Inconclusive,
              "generic provider wrong submission identity inconclusive");
        Check(guarded_receipt.result == "sentinel", "wrong receipt leaves output untouched");
        TransactionState guarded_state{"sentinel", {}, {}, {}, 0};
        Check(PaymentEngine::Status(*wallet, chain.profile, bad_receipt,
                                    exported.txid, guarded_state, error) == Result::Inconclusive,
              "generic provider wrong status identity inconclusive");
        Check(guarded_state.state == "sentinel", "wrong status leaves output untouched");
    }
    Success(PaymentEngine::Reconcile(*wallet, chain.profile, node, reconciled, error), error);
    Check(std::any_of(reconciled.coins.begin(), reconciled.coins.end(),
                      [](const CoinStatus &coin) { return coin.reserved; }),
          "bad_receipt generic provider cannot release reservation");
    // Reopen locked, requery authoritative history, and retry exactly the
    // persisted transaction after an ambiguous send. No signing occurs.
    std::vector<uint8_t> submitted;
    std::string authoritative = "pending";
    bool ambiguous = true;
    NodePaymentChainProvider history(chain.profile,
        [&](std::string_view wire, std::string &response, std::string &) {
            UniValue request;
            Check(request.read(std::string(wire)), "history request parse");
            if (request["command"].get_str() == "walletcontext") {
                response = ContextResponse(chain, request).write() + "\n";
                return true;
            }
            Check(request["wire"].get_str() == HexStr(exported.wire), "retry identical signed bytes");
            UniValue answer(UniValue::VOBJ);
            answer.pushKV("id", request["id"]);
            answer.pushKV("ok", true);
            answer.pushKV("txid", HexStr(exported.txid));
            answer.pushKV("txhash", HexStr(exported.txhash));
            answer.pushKV("error", "");
            if (request["command"].get_str() == "submittransaction") {
                if (ambiguous) { ambiguous = false; return false; }
                answer.pushKV("result", "duplicate");
                answer.pushKV("missing", UniValue(UniValue::VARR));
                submitted = exported.wire;
            } else {
                answer.pushKV("state", authoritative);
                if (authoritative == "confirmed") {
                    answer.pushKV("block_id", HexStr(chain.store.Metadata().tip));
                    answer.pushKV("height", uint64_t(chain.history.front().height));
                }
            }
            response = answer.write() + "\n";
            return true;
        });
    wallet.reset();
    Check(Wallet::Open(fs::PathFromString(directory + "/wallet"),
                      chain.profile.Binding(), wallet, error), error);
    Check(wallet->IsLocked(), "restart remains locked");
    Submission receipt;
    Check(PaymentEngine::Broadcast(*wallet, chain.profile, history, exported.txid,
                                   receipt, error) == Result::Inconclusive,
          "ambiguous submit remains recoverable");
    Success(PaymentEngine::Broadcast(*wallet, chain.profile, history, exported.txid,
                                     receipt, error), error);
    Check(receipt.result == "duplicate" && submitted == exported.wire,
          "restart duplicate retry preserves bytes");
    for (const auto &state : {"pending", "confirmed", "pending", "conflicted", "unknown"}) {
        authoritative = state;
        TransactionState observed;
        Success(PaymentEngine::Status(*wallet, chain.profile, history, exported.txid,
                                      observed, error), error);
        Check(observed.state == state, "authoritative reorg state replaces previous observation");
    }
    Success(PaymentEngine::Reconcile(*wallet, chain.profile, node, reconciled, error), error);
    Check(std::any_of(reconciled.coins.begin(), reconciled.coins.end(),
                      [](const CoinStatus &coin) { return coin.reserved; }),
          "ambiguous send and history transitions retain reservation");
    Check(wallet->Unlock(passphrase, error), error);
    Check(wallet->Abandon(exported.txid, error), error);
    ExportedPayment disk_export;
    Success(PaymentEngine::SignAndReserve(*wallet, chain.profile, chain.store,
                                          disk, disk_export, error),
            error);
    Transaction disk_signed;
    Check(DecodeTransaction(disk_export.wire,
                            chain.profile.ordinary.transaction, disk_signed,
                            error),
          error);
    Check(disk_export.digest == exported.digest &&
              VerifyBip340Signature(
                  wallet->PublicKey(),
                  disk_signed.inputs.at(0).witnesses.at(0).arguments.at(0),
                  disk_export.digest, false) == SignatureStatus::Valid,
          "disk/provider verified signed meaning and digest agree");
    disk_signed.inputs[0].witnesses[0].arguments[0].clear();
    Check(EncodeTransaction(disk_signed, chain.profile.ordinary.transaction, b,
                            error),
          error);
    Check(a == b,
          "disk/provider signed intent matches without random-byte comparison");
    Check(wallet->Abandon(disk_export.txid, error), error);
    Outpoint missing{};
    Check(PaymentEngine::TrackFunding(*wallet, chain.profile, provider, missing,
                                      error) == Result::Invalid,
          "authenticated absence is not owned funding");
}
} // namespace
int main() {
    char pattern[] = "/tmp/lotus-v2-wallet-provider-XXXXXX";
    if (!mkdtemp(pattern)) return 1;
    RandomInit();
    ECC_Start();
    try {
        EngineProvider(pattern);
        NodeVerification(pattern);
        ECC_Stop();
        std::cout << "wallet provider tests passed: " << checks << " checks\n";
        return 0;
    } catch (const std::exception &error) {
        ECC_Stop();
        std::cerr << error.what() << '\n';
        return 1;
    }
}
