// Copyright (c) 2026 The Lotus developers
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <lotus_v2/block_wire.h>
#include <lotus_v2/incremental_utxo.h>
#include <stdexcept>
#include <streams.h>
#include <wallet/sqlite.h>
#include <wallet/v2_payment.h>

#ifndef LOTUS_V2_WALLET_STANDALONE
#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>
#endif

namespace {
using namespace lotus::v2;
using V2Hash = lotus::v2::Hash;
using namespace lotus::v2::wallet;
unsigned checks = 0;
void Check(bool value, const std::string &why) {
    ++checks;
    if (!value) throw std::runtime_error(why);
}
void Success(Result result, const std::string &error) {
    Check(result == Result::Success, "wallet operation: " + error);
}
std::vector<uint8_t> PaymentScript(const V2Hash &owner) {
    std::vector<uint8_t> script{0x20};
    script.insert(script.end(), owner.begin(), owner.end());
    script.insert(script.end(), {0xbc, 0x4e});
    return script;
}
std::vector<uint8_t> File(const fs::path &path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), {}};
}
// Synthetic authenticated store fixture isolates wallet behavior. Append
// commits directly through DiskStateTransaction; this is not complete block
// acceptance. The separate compiler pilot must supply actual complete-block
// acceptance.
struct Chain {
    ChainProfile profile;
    DiskStateStore store;
    std::vector<Header> history;
    MonetaryState money{9, 200, {}, 4};
    std::string path;
    explicit Chain(const std::string &directory) : path(directory) {
        auto &hp = profile.header;
        hp.chain_id[0] = 71;
        hp.version = 2;
        hp.genesis_time = 1000;
        hp.genesis_bits = 0x207fffff;
        hp.pow_limit.fill(255);
        hp.half_life_seconds = 172800;
        hp.spacing_seconds = 120;
        auto &op = profile.ordinary;
        op.transaction = {32, 32, 8, 512, 8, 8192, 64};
        op.vm = {512, 8, 8192, 32, 32, 65536, 16, 1000000};
        op.coinbase_maturity = 2;
        op.dust_limit = 1;
        op.max_total_invocation_cost = 1000000;
        op.vm_cost.max_invocation_cost = 1000000;
        op.vm_cost.structural_byte_cost = 1;
        for (auto &cost : op.vm_cost.opcode)
            cost.base = 1;
        profile.monetary = {.boot_shift = 1, .tx_knee_shift = 1,
                            .ema_shift = 1000, .ema_min = 1,
                            .linear_shift = 1, .quad_shift = 1,
                            .tail_min = 1, .tail_max = 10000000,
                            .dust_limit = 10000000, .min_fee_per_kb = 1000,
                            .genesis_tail = money.tail_subsidy,
                            .genesis_work = {}};
        profile.costs = {1, 1, 1, 1};
        money.prev_work[0] = 2;
        profile.monetary.genesis_work = money.prev_work;
        Check(AbsoluteTail(profile.monetary, 2) == money.tail_subsidy,
              "valid monetary genesis anchors");
        Header genesis;
        genesis.version = hp.version;
        genesis.time = hp.genesis_time;
        genesis.bits = hp.genesis_bits;
        genesis.state_root = StateRoot(hp.chain_id, 0, EmptyUtxoRoot(), money);
        auto cb = Coinbase({}, 0, Burn());
        std::string error;
        Check(CompleteTransactionRoot({cb}, op.transaction, hp.chain_id,
                                      genesis.tx_root, error),
              error);
        std::vector<uint8_t> txbytes;
        Check(EncodeTransaction(cb, op.transaction, txbytes, error), error);
        genesis.size =
            HEADER_SIZE + 4 + CompactSizeWidth(txbytes.size()) + txbytes.size();
        Mine(genesis);
        Check(BlockId(hp.chain_id, genesis, hp.genesis_id), "genesis ID");
        history = {genesis};
        DiskStateOptions options;
        options.identity = hp.chain_id;
        options.profile_digest = profile.Binding().validation_digest;
        DiskStateError failure;
        Check(DiskStateStore::Open(path, options, {}, store, failure),
              failure.message);
        DiskStateTransaction tx;
        Check(store.Begin(tx, failure), failure.message);
        auto metadata = Metadata(genesis, {cb});
        Check(tx.Commit(metadata, failure), failure.message);
    }
    static Output Burn() {
        Output out;
        out.flags = 2;
        out.branches = {BranchLeaf(std::vector<uint8_t>{0x4e})};
        return out;
    }
    static Transaction Coinbase(const V2Hash &previous, uint64_t height,
                                const Output &out) {
        Input input;
        input.flags = 2;
        input.prev_txid = previous;
        input.prev_index = uint32_t(height);
        input.sequence = UINT32_MAX;
        return {0, {input}, {out}};
    }
    void Mine(Header &header) {
        V2Hash target, id;
        Check(DecodeTarget(header.bits, profile.header.pow_limit, target),
              "target");
        for (header.nonce = 0;; ++header.nonce) {
            Check(BlockId(profile.header.chain_id, header, id), "block ID");
            if (MeetsTarget(id, target)) break;
        }
    }
    DiskStateMetadata Metadata(const Header &header,
                               const std::vector<Transaction> &transactions) {
        std::string error;
        std::vector<uint8_t> wire;
        Check(EncodeBlockWire(header, transactions,
                              profile.ordinary.transaction, wire, error),
              error);
        DiskStateMetadata metadata;
        Check(BlockId(profile.header.chain_id, header, metadata.tip), "tip ID");
        metadata.header.assign(wire.begin(), wire.begin() + HEADER_SIZE);
        auto encoded = EncodeMonetaryState(money);
        metadata.monetary.assign(encoded.begin(), encoded.end());
        metadata.auxiliary = EncodeDiskChainContext(history, wire);
        return metadata;
    }
    Outpoint Append(const Output &funding,
                    const std::optional<Transaction> &payment = {}) {
        Header header;
        header.version = profile.header.version;
        header.bits = profile.header.genesis_bits;
        header.time = history.front().time + 120;
        header.height = history.front().height + 1;
        header.prev_id = store.Metadata().tip;
        std::vector<Transaction> transactions{
            Coinbase(header.prev_id, header.height, funding)};
        if (payment) transactions.push_back(*payment);
        auto mtp = ParentMedianTime(profile.header, history.front(), history);
        Check(mtp.has_value(), "fixture parent MTP");
        DiskStateTransaction tx;
        DiskStateError failure;
        Check(store.Begin(tx, failure), failure.message);
        std::string error;
        Outpoint first;
        for (size_t n = 0; n < transactions.size(); ++n) {
            const auto &transaction = transactions[n];
            if (n)
                for (const auto &input : transaction.inputs)
                    Check(
                        tx.Erase({input.prev_txid, input.prev_index}, failure),
                        failure.message);
            IdentityDigests ids;
            Check(ComputeIdentities(transaction, profile.ordinary.transaction,
                                    profile.header.chain_id, ids, error),
                  error);
            if (!n) first = {ids.txid, 0};
            for (size_t i = 0; i < transaction.outputs.size(); ++i)
                if (!transaction.outputs[i].IsBurn())
                    Check(tx.Insert({{ids.txid, uint32_t(i)},
                                     transaction.outputs[i],
                                     header.height,
                                     *mtp,
                                     n == 0},
                                    failure),
                          failure.message);
        }
        header.state_root =
            StateRoot(profile.header.chain_id, header.height, tx.Root(), money);
        Check(CompleteTransactionRoot(
                  transactions, profile.ordinary.transaction,
                  profile.header.chain_id, header.tx_root, error),
              error);
        uint64_t size = HEADER_SIZE + 4;
        for (const auto &transaction : transactions) {
            std::vector<uint8_t> bytes;
            Check(EncodeTransaction(transaction, profile.ordinary.transaction,
                                    bytes, error),
                  error);
            size += CompactSizeWidth(bytes.size()) + bytes.size();
        }
        header.size = size;
        Mine(header);
        history.insert(history.begin(), header);
        if (history.size() > 11) history.resize(11);
        Check(tx.Commit(Metadata(header, transactions), failure),
              failure.message);
        return first;
    }
    void Disconnect() {
        DiskStateError error;
        Check(store.Disconnect(store.Metadata().tip, error), error.message);
        std::vector<uint8_t> body;
        std::string detail;
        Check(ReadDiskChainContext(store.Metadata(), profile.header, history,
                                   body, detail),
              detail);
    }
};
void RejectOutgoing(const fs::path &directory, bool reject) {
    sqlite3 *db{};
    Check(sqlite3_open(
              fs::PathToString(directory / WALLET_DATABASE_FILENAME).c_str(),
              &db) == SQLITE_OK,
          "open fault fixture");
    const char *sql =
        reject ? "CREATE TRIGGER reject_outgoing BEFORE INSERT ON main WHEN "
                 "NEW.key = x'0b76322e6f7574676f696e67' BEGIN SELECT "
                 "RAISE(ABORT, 'injected outgoing write failure'); END"
               : "DROP TRIGGER reject_outgoing";
    Check(sqlite3_exec(db, sql, nullptr, nullptr, nullptr) == SQLITE_OK,
          "SQLite fault trigger");
    sqlite3_close(db);
}
} // namespace

void RunV2WalletTests(const std::string &directory) {
    fs::create_directories(fs::PathFromString(directory));
    Chain chain(directory + "/chain");
    const auto binding = chain.profile.Binding();
    const fs::path home = fs::PathFromString(directory) / "wallet";
    const SecureString passphrase("ephemeral-native-wallet-test-passphrase");
    std::unique_ptr<Wallet> wallet;
    std::string error;
    Check(!Wallet::Create(home, binding, {}, wallet, error),
          "empty passphrase rejection");
    Check(!fs::exists(home), "empty passphrase leaves no wallet");
    Check(Wallet::Create(home, binding, passphrase, wallet, error), error);
    Check(wallet->IsLocked(), "created wallet locked");
    const V2Hash owner = wallet->PublicKey();
    auto script = PaymentScript(owner);
    auto wrong = script;
    wrong[1] ^= 1;
    Check(!wallet->RegisterPayment(wrong, {}, error), "wrong Payment owner");
    Check(!wallet->RegisterPayment(script, {V2Hash{}}, error),
          "nonempty Payment proof");
    Check(wallet->RegisterPayment(script, {}, error), error);
    Output own;
    Check(wallet->PaymentOutput(100000, own, error), error);
    const auto funding = chain.Append(own);
    Success(PaymentEngine::TrackFunding(*wallet, chain.profile, chain.store,
                                        funding, error),
            error);
    Output recipient;
    recipient.value = 50000;
    recipient.branches = {BranchLeaf(std::vector<uint8_t>{0x4e})};
    recipient.paths = {{0}};
    PaymentPlan plan;
    Check(PaymentEngine::Prepare(*wallet, chain.profile, chain.store, recipient,
                                 1000, plan,
                                 error) == Result::InsufficientFunds,
          "immature coin rejected");
    chain.Append(Chain::Burn());
    Success(PaymentEngine::Prepare(*wallet, chain.profile, chain.store,
                                   recipient, 1000, plan, error),
            error);
    recipient.value = 1;
    Check(plan.UnsignedTransaction().outputs[0].value == 50000,
          "recipient copied into immutable intent");
    recipient.value = 50000;
    ExportedPayment exported;
    exported.wire = {0xaa};
    Check(PaymentEngine::SignAndReserve(*wallet, chain.profile, chain.store,
                                        plan, exported,
                                        error) == Result::Locked,
          "locked signer");
    Check(exported.wire == std::vector<uint8_t>{0xaa},
          "locked output unchanged");
    Check(!wallet->Unlock(SecureString("incorrect"), error),
          "wrong passphrase");
    Check(wallet->Unlock(passphrase, error), error);
    auto modified = plan;
    const_cast<Transaction &>(modified.UnsignedTransaction())
        .outputs[0]
        .value--;
    Check(PaymentEngine::SignAndReserve(*wallet, chain.profile, chain.store,
                                        modified, exported,
                                        error) == Result::Invalid,
          "mutated recipient intent rejected");
    PaymentPlan low_fee;
    Check(PaymentEngine::Prepare(*wallet, chain.profile, chain.store, recipient,
                                 1, low_fee, error) == Result::Invalid,
          "final signature byte fee floor");
    auto mismatched = chain.profile;
    mismatched.ordinary.coinbase_maturity++;
    Check(PaymentEngine::Prepare(*wallet, mismatched, chain.store, recipient,
                                 1000, low_fee, error) == Result::Invalid,
          "validator profile mismatch");
    const fs::path backup = fs::PathFromString(directory) / "backup";
    fs::create_directory(backup);
    Check(wallet->Backup(fs::PathToString(backup), error), error);
    Success(PaymentEngine::SignAndReserve(*wallet, chain.profile, chain.store,
                                          plan, exported, error),
            error);
    Check(exported.wire != std::vector<uint8_t>{0xaa}, "signed bytes exported");
    const auto persisted_wire = exported.wire;
    const auto persisted_txid = exported.txid;
    std::vector<V2Hash> outgoing_ids{V2Hash{}};
    Check(wallet->ListOutgoing(outgoing_ids, error) &&
              outgoing_ids == std::vector<V2Hash>{persisted_txid},
          "persisted signed transaction listed without signing again");
    std::vector<uint8_t> recovered{0x77};
    Check(wallet->ExportOutgoing(persisted_txid, persisted_wire.size(),
                                 recovered, error) &&
              recovered == persisted_wire,
          "exact byte cap exports original persisted signed bytes");
    recovered = {0x77};
    Check(!wallet->ExportOutgoing(persisted_txid, persisted_wire.size() - 1,
                                  recovered, error) &&
              recovered == std::vector<uint8_t>{0x77},
          "below byte cap preserves export output");
    auto unknown_txid = persisted_txid;
    unknown_txid[0] ^= 1;
    Check(!wallet->ExportOutgoing(unknown_txid, persisted_wire.size(),
                                  recovered, error) &&
              recovered == std::vector<uint8_t>{0x77},
          "unknown outgoing ID preserves export output");

    Transaction signed_tx;
    Check(DecodeTransaction(exported.wire, chain.profile.ordinary.transaction,
                            signed_tx, error),
          error);
    Check(VerifyBip340Signature(
              owner, signed_tx.inputs[0].witnesses[0].arguments[0],
              exported.digest, false) == SignatureStatus::Valid,
          "wallet BIP340 signature");
    Check(PaymentEngine::SignAndReserve(*wallet, chain.profile, chain.store,
                                        plan, exported, error) == Result::Stale,
          "duplicate reservation rejected");
    Reconciled state;
    Success(PaymentEngine::Reconcile(*wallet, chain.profile, chain.store, state,
                                     error),
            error);
    Check(state.coins.size() == 2, "funding and change tracked");
    Check(std::count_if(state.coins.begin(), state.coins.end(),
                        [](const auto &coin) {
                            return coin.present && coin.reserved;
                        }) == 1,
          "export reserves present funding without claiming confirmation");
    wallet.reset();
    const auto before = File(home / WALLET_DATABASE_FILENAME);
    auto bad_binding = binding;
    bad_binding.chain_id[0] ^= 1;
    Check(!Wallet::Open(home, bad_binding, wallet, error),
          "different chain rejected");
    bad_binding = binding;
    bad_binding.genesis_id[0] ^= 1;
    Check(!Wallet::Open(home, bad_binding, wallet, error),
          "different genesis rejected");
    bad_binding = binding;
    bad_binding.validation_digest[0] ^= 1;
    Check(!Wallet::Open(home, bad_binding, wallet, error),
          "different validator rejected");
    Check(File(home / WALLET_DATABASE_FILENAME) == before,
          "profile rejection leaves wallet bytes unchanged");
    Check(Wallet::Open(home, binding, wallet, error), error);
    Check(wallet->IsLocked() && wallet->PublicKey() == owner,
          "restart preserves locked key owner");
    Check(wallet->ListOutgoing(outgoing_ids, error) &&
              outgoing_ids == std::vector<V2Hash>{persisted_txid},
          "outgoing IDs survive close/reopen while locked");
    Check(
        wallet->ExportOutgoing(persisted_txid, persisted_wire.size(), recovered,
                               error) &&
            recovered == persisted_wire && wallet->IsLocked(),
        "locked recovery returns exact original signed wire without unlocking");

    Check(wallet->Unlock(passphrase, error), error);
    Check(PaymentEngine::Prepare(*wallet, chain.profile, chain.store, recipient,
                                 1000, low_fee,
                                 error) == Result::InsufficientFunds,
          "reservation survives restart");
    chain.Append(Chain::Burn(), signed_tx);
    Success(PaymentEngine::Reconcile(*wallet, chain.profile, chain.store, state,
                                     error),
            error);
    Check(std::count_if(state.coins.begin(), state.coins.end(),
                        [](const auto &coin) {
                            return coin.present && !coin.reserved;
                        }) == 1,
          "accepted synthetic transition exposes change");
    chain.Disconnect();
    Success(PaymentEngine::Reconcile(*wallet, chain.profile, chain.store, state,
                                     error),
            error);
    Check(std::count_if(state.coins.begin(), state.coins.end(),
                        [](const auto &coin) {
                            return coin.present && coin.reserved;
                        }) == 1,
          "disconnect restores funding and retains outgoing reservation");
    Check(wallet->Abandon(exported.txid, error), error);
    Check(wallet->ListOutgoing(outgoing_ids, error) && outgoing_ids.empty(),
          "Abandon removes outgoing recovery entry");
    recovered = {0x77};
    Check(!wallet->ExportOutgoing(persisted_txid, persisted_wire.size(),
                                  recovered, error) &&
              recovered == std::vector<uint8_t>{0x77},
          "abandoned transaction cannot be retrieved and preserves output");

    Success(PaymentEngine::Prepare(*wallet, chain.profile, chain.store,
                                   recipient, 1000, plan, error),
            error);
    chain.Append(Chain::Burn());
    Check(PaymentEngine::SignAndReserve(*wallet, chain.profile, chain.store,
                                        plan, exported, error) == Result::Stale,
          "stale tip despite unchanged funding rejected");

    // Restore the pre-export backup and use a real SQLite trigger to make the
    // second state write fail after tracked outputs were staged in the batch.
    std::unique_ptr<Wallet> fault;
    RejectOutgoing(backup, true);
    Check(Wallet::Open(backup, binding, fault, error), error);
    Check(fault->Unlock(passphrase, error), error);
    Success(PaymentEngine::Prepare(*fault, chain.profile, chain.store,
                                   recipient, 1000, plan, error),
            error);
    ExportedPayment unchanged;
    unchanged.wire = {0x55};
    Check(PaymentEngine::SignAndReserve(*fault, chain.profile, chain.store,
                                        plan, unchanged,
                                        error) == Result::StorageError,
          "outgoing write failure distinguished");
    Check(unchanged.wire == std::vector<uint8_t>{0x55},
          "no bytes exported on failed reservation");
    Check(PaymentEngine::Prepare(*fault, chain.profile, chain.store, recipient,
                                 1000, low_fee, error) == Result::StorageError,
          "failed write requires reopen");
    outgoing_ids = {persisted_txid};
    recovered = {0x77};
    Check(!fault->ListOutgoing(outgoing_ids, error) &&
              outgoing_ids == std::vector<V2Hash>{persisted_txid},
          "reopen-required listing preserves output");
    Check(!fault->ExportOutgoing(persisted_txid, persisted_wire.size(),
                                 recovered, error) &&
              recovered == std::vector<uint8_t>{0x77},
          "reopen-required export preserves output");

    fault.reset();
    RejectOutgoing(backup, false);
    Check(Wallet::Open(backup, binding, fault, error), error);
    Check(fault->PublicKey() == owner && fault->Unlock(passphrase, error),
          "backup encrypted key usable");
    Success(PaymentEngine::Reconcile(*fault, chain.profile, chain.store, state,
                                     error),
            error);
    Check(state.coins.size() == 1 && !state.coins[0].reserved,
          "failed batch rolls back both tracked change and reservation");
    Success(PaymentEngine::Prepare(*fault, chain.profile, chain.store,
                                   recipient, 1000, plan, error),
            error);
    Success(PaymentEngine::SignAndReserve(*fault, chain.profile, chain.store,
                                          plan, unchanged, error),
            error);
    Transaction final_tx;
    IdentityDigests final_ids;
    Check(DecodeTransaction(unchanged.wire, chain.profile.ordinary.transaction,
                            final_tx, error),
          error);
    Check(ComputeIdentities(final_tx, chain.profile.ordinary.transaction,
                            binding.chain_id, final_ids, error),
          error);
    Check(unchanged.txid == final_ids.txid &&
              unchanged.txhash == final_ids.txhash,
          "exported identities match exact native bytes");
    // Independent fresh key plus two eligible coins, tracked in reverse order.
    Chain selection(directory + "/selection-chain");
    std::unique_ptr<Wallet> second;
    Check(Wallet::Create(fs::PathFromString(directory) / "second-wallet",
                         selection.profile.Binding(), passphrase, second,
                         error),
          error);
    Check(second->PublicKey() != owner,
          "fresh wallet key is independently generated");
    Check(
        second->RegisterPayment(PaymentScript(second->PublicKey()), {}, error),
        error);
    Output second_output;
    Check(second->PaymentOutput(100000, second_output, error), error);
    const auto first_coin = selection.Append(second_output);
    const auto second_coin = selection.Append(second_output);
    selection.Append(Chain::Burn());
    Success(PaymentEngine::TrackFunding(*second, selection.profile,
                                        selection.store, second_coin, error),
            error);
    Success(PaymentEngine::TrackFunding(*second, selection.profile,
                                        selection.store, first_coin, error),
            error);
    Success(PaymentEngine::TrackFunding(*second, selection.profile,
                                        selection.store, first_coin, error),
            error);
    Success(PaymentEngine::Prepare(*second, selection.profile, selection.store,
                                   recipient, 1000, plan, error),
            error);
    Check(plan.UnsignedTransaction().inputs[0].prev_txid ==
              std::min(first_coin.tx_id, second_coin.tx_id),
          "deterministic outpoint-order selection");
    const Outpoint missing{{}, 123};
    Check(PaymentEngine::TrackFunding(*second, selection.profile,
                                      selection.store, missing,
                                      error) == Result::Invalid,
          "caller cannot assert nonexistent funding");
    auto wrong_policy_coin = selection.Append(own);
    Check(PaymentEngine::TrackFunding(*second, selection.profile,
                                      selection.store, wrong_policy_coin,
                                      error) == Result::Invalid,
          "foreign owner funding rejected");
    selection.store = DiskStateStore{};
    Check(PaymentEngine::Prepare(*second, selection.profile, selection.store,
                                 recipient, 1000, plan,
                                 error) == Result::StorageError,
          "closed store is operational failure");
    const auto legacy = fs::PathFromString(directory) / "legacy";
    fs::create_directory(legacy);
    {
        std::ofstream file(legacy / "wallet.dat");
        file << "unsupported legacy fixture";
    }
    Check(!Wallet::Create(legacy, binding, passphrase, second, error),
          "legacy wallet.dat never opened or migrated");
    Check(!fs::exists(legacy / WALLET_DATABASE_FILENAME),
          "legacy rejection creates no SQLite sibling");
    std::cout << "V2 wallet checks passed: " << checks << '\n';
}

#ifndef LOTUS_V2_WALLET_STANDALONE
BOOST_FIXTURE_TEST_SUITE(v2_wallet_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(encrypted_native_payment) {
    RunV2WalletTests(fs::PathToString(gArgs.GetDataDirNet() / "v2-wallet"));
}
BOOST_AUTO_TEST_SUITE_END()
#endif
