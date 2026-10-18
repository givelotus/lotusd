// Copyright (c) 2026 The Lotus developers
// Synthetic authenticated parent for module checks; no genesis funding claim.
#include "block.h"
#include "block_transition.h"
#ifdef LOTUS_V2_TEST_DISK
#include "disk_block.h"
#include <filesystem>
#include <cstdlib>
#endif
#include "dev_genesis.h"
#include "signing.h"
#include <iostream>
#include <stdexcept>
using namespace lotus::v2;
namespace {
void Check(bool v, const std::string &why) {
    if (!v) throw std::runtime_error(why);
}
class TestState final : public BlockStateTransaction {
public:
    DevelopmentUtxoView coins;
    IncrementalUtxoSet tree;
    bool aborted = false, fail_reads = false, fail_writes = false;
    bool throw_writes = false;
    unsigned writes = 0;
    explicit TestState(const DevelopmentUtxoView &initial) : coins(initial) {
        for (const auto &[key, coin] : initial) {
            (void)key;
            Check(tree.Insert(coin), "test state init");
        }
    }
    CoinReadResult Read(const Outpoint &key, Coin &coin, std::string &error) override {
        if (fail_reads) { error = "injected storage read"; return CoinReadResult::Error; }
        auto it = coins.find(key);
        if (it == coins.end()) return CoinReadResult::Missing;
        coin = it->second; return CoinReadResult::Found;
    }
    bool Insert(const Coin &coin, std::string &error) override {
        if (throw_writes && ++writes == 2)
            throw std::invalid_argument("injected backend exception after mutation");
        if (fail_writes) { error = "injected storage write"; return false; }
        return coins.emplace(coin.outpoint, coin).second && tree.Insert(coin);
    }
    bool Erase(const Outpoint &key, std::string &error) override {
        if (throw_writes && ++writes == 2)
            throw std::invalid_argument("injected backend exception after mutation");
        if (fail_writes) { error = "injected storage write"; return false; }
        return coins.erase(key) == 1 && tree.Erase(key);
    }
    Hash Root() const override { return tree.Root(); }
    void Abort() noexcept override {
        aborted = true; coins.clear(); tree = IncrementalUtxoSet{};
    }
};
const TxProfile TX{32, 32, 8, 512, 8, 8192, 64};
const BlockCostProfile COST{1, 1, 1, 1};
Output Native(uint64_t value, bool burn = false) {
    Output o;
    o.value = value;
    o.flags = burn ? 2 : 0;
    o.branches = {BranchLeaf(std::vector<uint8_t>{0x4e})};
    if (!burn) o.paths = {{0}};
    return o;
}
Transaction Coinbase(const Hash &parent, uint64_t height, bool burn = true) {
    Transaction tx;
    Input i;
    i.prev_txid = parent;
    i.prev_index = height;
    i.sequence = UINT32_MAX;
    i.flags = 2;
    tx.inputs = {i};
    tx.outputs = {Native(0, burn)};
    return tx;
}
Transaction Payment(const Outpoint &outpoint) {
    Transaction tx;
    Input i;
    i.prev_txid = outpoint.tx_id;
    i.prev_index = outpoint.index;
    i.sequence = UINT32_MAX;
    i.flags = 1;
    i.witnesses = {BranchWitness{{0x4e}, {}, {}}};
    tx.inputs = {i};
    tx.outputs = {Native(1000)};
    return tx;
}
std::vector<uint8_t> Wire(Header &h, const std::vector<Transaction> &txs) {
    std::string error;
    h.size = 138;
    for (const auto &tx : txs) {
        std::vector<uint8_t> raw;
        Check(EncodeTransaction(tx, TX, raw, error), error);
        h.size += raw.size() + CompactSizeWidth(raw.size());
    }
    Check(CompleteTransactionRoot(txs, TX, {}, h.tx_root, error), error);
    std::vector<uint8_t> raw;
    Check(EncodeBlockWire(h, txs, TX, raw, error), error);
    return raw;
}
void WireChecks() {
    Header h;
    h.version = 2;
    h.bits = 0x1d00ffff;
    h.height = 1;
    h.time = 1;
    auto tx = Coinbase({}, 1);
    auto wire = Wire(h, {tx});
    FramedBlock decoded;
    std::string error;
    Check(wire.size() == 240, "minimum full coinbase size");
    Check(DecodeBlockWire(wire, TX, {}, decoded, error), error);
    const auto charge =
        AuthenticatedTransactionCosts(tx, TX, {}, 1, 0, 0, COST);
    Check(charge.account_linear == 1570 && charge.enforce_linear == 1570,
          "independent minimum cost vector");
    Check(AuthenticatedEnvelopeCost(1, 1, COST) == 993,
          "independent envelope vector");
    Check(BlockEffectiveCost(993, {1570}, DevelopmentGenesis) == 310675,
          "independent parabolic vector");
    auto rejects = [&](const std::vector<uint8_t> &bad) {
        const auto before = decoded.header.tx_root;
        Check(!DecodeBlockWire(bad, TX, {}, decoded, error),
              "wire mutation accepted");
        Check(decoded.header.tx_root == before, "decode failure wrote result");
    };
    for (size_t cut = 0; cut < wire.size(); ++cut)
        rejects({wire.begin(), wire.begin() + cut});
    auto bad = wire;
    bad.push_back(0);
    rejects(bad);
    bad = wire;
    bad[134] = 0;
    rejects(bad);
    bad = wire;
    std::fill(bad.begin() + 134, bad.begin() + 138, 255);
    rejects(bad);
    bad = wire;
    bad[139] = 8;
    rejects(bad);
    bad = wire;
    bad[70] ^= 1;
    rejects(bad); // tx root
    bad = wire;
    bad.insert(bad.begin() + 138, {253, 101});
    bad[140] = 0;
    Header longer = h;
    longer.size = bad.size();
    std::array<uint8_t, HEADER_SIZE> hb;
    Check(SerializeHeader(longer, hb), "header encode");
    std::copy(hb.begin(), hb.end(), bad.begin());
    rejects(bad);
    Hash root;
    Transaction spend = Payment(Outpoint{});
    Check(!CompleteTransactionRoot({}, TX, {}, root, error), "empty block");
    Check(!CompleteTransactionRoot({spend}, TX, {}, root, error),
          "missing coinbase");
    Check(!CompleteTransactionRoot({spend, tx}, TX, {}, root, error),
          "misplaced coinbase");
    Check(!CompleteTransactionRoot({tx, tx}, TX, {}, root, error),
          "second coinbase");
    spend.outputs.clear();
    Transaction witness_changed = spend;
    witness_changed.inputs[0].witnesses[0].arguments = {{9}};
    Check(!CompleteTransactionRoot({tx, spend, witness_changed}, TX, {}, root,
                                   error) &&
              error == "duplicate transaction id",
          "zero-output duplicate id");
    spend.outputs = {Native(0, true)};
    witness_changed = spend;
    witness_changed.inputs[0].witnesses[0].arguments = {{9}};
    Check(!CompleteTransactionRoot({tx, spend, witness_changed}, TX, {}, root,
                                   error) &&
              error == "duplicate transaction id",
          "burn-only duplicate id");
    Check(!CheckCoinbaseContext(tx, {}, uint64_t{1} << 32, error),
          "derived coinbase height must fit u32");
    MonetaryState initial;
    initial.bootstrap_reserve = 9;
    initial.tail_subsidy = 200;
    initial.prev_work[0] = 9;
    initial.ema_block_cost = 4;
    bool failed = false;
    try {
        AdvanceMonetary(DevelopmentGenesis, initial, 9, {}, 0, 0, 101, 1, 0, 0);
    } catch (const std::invalid_argument &e) {
        failed = std::string(e.what()) == "insufficient entitlement";
    }
    Check(failed, "bare old genesis cannot afford K=240 from entitlement202");
}
#ifdef LOTUS_V2_TEST_DISK
void DiskHistoryRolloverChecks() {
    // An explicitly trusted synthetic height-ten seed, not a genesis-derived
    // funding history. Subsequent children use actual complete-block
    // validation.
    Coin funding;
    funding.outpoint.tx_id[0] = 17;
    funding.output = Native(1000000000000000000ULL);
    DevelopmentUtxoView view{{funding.outpoint, funding}};
    IncrementalUtxoSet tree;
    Check(tree.Insert(funding), "rollover funding");
    MonetaryState money;
    money.bootstrap_reserve = 9;
    money.tail_subsidy = 94; // AbsoluteTail(DevelopmentGenesis, 2) for synthetic parent.
    money.prev_work[0] = 2;
    money.ema_block_cost = 4;
    Hash limit;
    limit.fill(255);
    const HeaderChainProfile hp{{}, 2, 1000, 0x207fffff, limit, 172800, 120};
    OrdinaryCandidateProfile profile{
        TX,
        VmProfile{512, 8, 8192, 32, 32, 65536, 16, 1000000},
        VmCostProfile{},
        999,
        999,
        2,
        3,
        1000000};
    profile.vm_cost.max_invocation_cost = 1000000;
    profile.vm_cost.structural_byte_cost = 1;
    for (auto &op : profile.vm_cost.opcode)
        op = {1, 1, 1};
    std::vector<Header> history;
    for (uint64_t height = 0; height <= 10; ++height) {
        Header h;
        h.version = 2;
        h.bits = hp.genesis_bits;
        h.height = height;
        h.time = 1000 + height * 120;
        h.size = HEADER_SIZE;
        if (!history.empty())
            Check(BlockId({}, history.front(), h.prev_id), "seed ancestry");
        if (height == 10)
            h.state_root = StateRoot({}, height, tree.Root(), money);
        history.insert(history.begin(), h);
    }
    DiskStateMetadata seed;
    Check(BlockId({}, history.front(), seed.tip), "rollover seed tip");
    std::array<uint8_t, HEADER_SIZE> raw_header;
    Check(SerializeHeader(history.front(), raw_header), "rollover seed header");
    seed.header.assign(raw_header.begin(), raw_header.end());
    const auto monetary_bytes = EncodeMonetaryState(money);
    seed.monetary.assign(monetary_bytes.begin(), monetary_bytes.end());
    seed.auxiliary = EncodeDiskChainContext(history, {});
    char directory[] = "/private/tmp/lotus-v2-disk-rollover-XXXXXX";
    Check(mkdtemp(directory) != nullptr, "rollover directory");
    {
        DiskStateOptions options;
        options.cache_bytes = 1024;
        options.write_buffer_bytes = 64 << 10;
        options.identity = hp.chain_id;
        options.profile_digest =
            BlockValidationProfileDigest(hp, profile, DevelopmentGenesis, COST);
        DiskStateStore db;
        DiskStateError failure;
        Check(DiskStateStore::Open(directory, options, {}, db, failure),
              failure.message);
        {
            DiskStateTransaction initial;
            Check(db.Begin(initial, failure) &&
                      initial.Insert(funding, failure) &&
                      initial.Commit(seed, failure),
                  failure.message);
        }
        std::string error;
        for (uint64_t height : {uint64_t{11}, uint64_t{12}}) {
            const auto before = db.Metadata();
            const auto before_root = db.Root();
            const auto mtp = ParentMedianTime(hp, history.front(), history);
            Check(mtp && *mtp == 1000 + (height - 6) * 120,
                  "independent parent eleven-header MTP");
            auto context = profile;
            context.candidate_height = height;
            context.parent_mtp = *mtp;
            Hash parent_id;
            Check(BlockId({}, history.front(), parent_id),
                  "rollover parent ID");
            auto cb = Coinbase(parent_id, height);
            auto spend = Payment(view.begin()->first);
            spend.outputs[0].value = view.begin()->second.output.value / 2;
            OrdinaryCandidateEffects effects;
            Check(CheckOrdinaryCandidate(spend, context, {}, view, effects,
                                         error),
                  error);
            const auto cb_cost = AuthenticatedTransactionCosts(
                cb, TX, view, height, *mtp, 0, COST);
            const auto spend_cost = AuthenticatedTransactionCosts(
                spend, TX, view, height, *mtp, effects.invocation_cost, COST);
            std::vector<uint8_t> cb_bytes, spend_bytes;
            Check(EncodeTransaction(cb, TX, cb_bytes, error) &&
                      EncodeTransaction(spend, TX, spend_bytes, error),
                  error);
            const auto frames = CompactSizeWidth(cb_bytes.size()) +
                                CompactSizeWidth(spend_bytes.size());
            const auto cost = BlockEffectiveCost(
                AuthenticatedEnvelopeCost(frames, 2, COST),
                {cb_cost.account_linear, spend_cost.account_linear},
                DevelopmentGenesis);
            const auto record = AccountValidatedOrdinary(spend, effects, TX,
                                                         DevelopmentGenesis);
            const auto monetary =
                AdvanceMonetary(DevelopmentGenesis, money, 2, {record}, 0, 0,
                                cb_bytes.size(), frames, cost, cost);
            IncrementalUtxoSet expected;
            DevelopmentUtxoView next_view;
            for (const auto &coin : effects.created) {
                Check(expected.Insert(coin), "rollover expected coin");
                next_view.emplace(coin.outpoint, coin);
            }
            Header child;
            child.version = 2;
            child.bits = hp.genesis_bits;
            child.height = height;
            child.time = 1000 + height * 120;
            child.prev_id = parent_id;
            child.state_root =
                StateRoot({}, height, expected.Root(), monetary.state);
            auto wire = Wire(child, {cb, spend});
            Hash target, id;
            Check(DecodeTarget(child.bits, limit, target), "rollover target");
            for (;; ++child.nonce) {
                Check(BlockId({}, child, id), "rollover PoW");
                if (MeetsTarget(id, target)) break;
            }
            wire = Wire(child, {cb, spend});
            StagedBlockTransition connected;
            Check(ConnectStoredDiskBlock(wire, hp, profile, DevelopmentGenesis,
                                         COST, db, connected, error) ==
                      CandidateCheckResult::Accepted,
                  error);
            const auto after = db.Metadata();
            auto check_window = [&]() {
                std::vector<Header> restored;
                std::vector<uint8_t> restored_wire;
                Check(ReadDiskChainContext(db.Metadata(), hp, restored,
                                           restored_wire, error),
                      error);
                Check(restored.size() == 11 && restored_wire == wire,
                      "rollover exact body and eleven headers");
                for (size_t i = 0; i < restored.size(); ++i)
                    Check(
                        restored[i].height == height - i &&
                            restored[i].time == 1000 + (height - i) * 120,
                        "rollover retained exact newest eleven heights/times");
                Check(ParentMedianTime(hp, restored.front(), restored) ==
                          1000 + (height - 5) * 120,
                      "rollover independent child MTP");
                Check(db.Root() == expected.Root(), "rollover UTXO root");
                return restored;
            };
            check_window();
            Check(
                db.Disconnect(connected.block_id, failure) &&
                    db.Metadata() == before && db.Root() == before_root,
                "rollover disconnect restores previous eleven and state tuple");
            db = DiskStateStore{};
            Check(DiskStateStore::Open(directory, options, {}, db, failure),
                  failure.message);
            Check(db.Metadata() == before && db.Root() == before_root,
                  "rollover restart preserves undone tuple");
            Check(ConnectStoredDiskBlock(wire, hp, profile, DevelopmentGenesis,
                                         COST, db, connected, error) ==
                      CandidateCheckResult::Accepted,
                  error);
            Check(db.Metadata() == after,
                  "rollover deterministic reconnect tuple");
            db = DiskStateStore{};
            Check(DiskStateStore::Open(directory, options, {}, db, failure),
                  failure.message);
            history = check_window();
            view = std::move(next_view);
            money = monetary.state;
        }
    }
    std::filesystem::remove_all(directory);
}
#endif

void CompleteChecks() {
    // A synthetic parent owns a large coin solely to isolate complete-block
    // validation; no fixture claims this coin arose from development genesis.
    Coin funding;
    funding.outpoint.tx_id[0] = 7;
    funding.output = Native(1000000000000000000ULL);
    funding.creation_height = 0;
    funding.creation_parent_mtp = 1000;
    DevelopmentUtxoView view{{funding.outpoint, funding}};
    IncrementalUtxoSet utxo;
    Check(utxo.Insert(funding), "funding");
    MonetaryState money;
    money.bootstrap_reserve = 9;
    money.tail_subsidy = 94; // AbsoluteTail(DevelopmentGenesis, 2) for synthetic parent.
    money.prev_work[0] = 2;
    money.ema_block_cost = 4;
    Header genesis;
    genesis.version = 2;
    genesis.bits = 0x207fffff;
    genesis.time = 1000;
    genesis.size = 134;
    OrdinaryParentContext parent;
    parent.header = genesis;
    parent.header.height = 1;
    parent.header.time = 1120;
    parent.monetary = money;
    Check(BlockId({}, genesis, parent.header.prev_id), "genesis id");
    parent.header.state_root = StateRoot({}, 1, utxo.Root(), money);
    Hash limit;
    limit.fill(255);
    const HeaderChainProfile hp{{}, 2, 1000, 0x207fffff, limit, 172800, 120};
    OrdinaryCandidateProfile profile{
        TX,
        VmProfile{512, 8, 8192, 32, 32, 65536, 16, 1000000},
        VmCostProfile{},
        2,
        1120,
        2,
        3,
        1000000};
    profile.vm_cost.max_invocation_cost = 1000000;
    profile.vm_cost.structural_byte_cost = 1;
    for (auto &op : profile.vm_cost.opcode)
        op = {1, 1, 1};
    Hash parent_id;
    Check(BlockId({}, parent.header, parent_id), "parent id");
    Transaction cb = Coinbase(parent_id, 2), spend = Payment(funding.outpoint);
    OrdinaryCandidateEffects effects;
    std::string error;
    Check(CheckOrdinaryCandidate(spend, profile, {}, view, effects, error),
          error);
    const auto c =
        AuthenticatedTransactionCosts(cb, TX, view, 2, 1120, 0, COST);
    const auto s = AuthenticatedTransactionCosts(spend, TX, view, 2, 1120,
                                                 effects.invocation_cost, COST);
    const auto resolved_cost = AuthenticatedTransactionCostsResolved(
        spend, TX, {funding}, 2, 1120, effects.invocation_cost, COST);
    Check(resolved_cost.account_linear == s.account_linear &&
              resolved_cost.enforce_linear == s.enforce_linear,
          "resolved cost matches map oracle");
    const auto cb_cost = AuthenticatedTransactionCostsResolved(
        cb, TX, {}, 2, 1120, 0, COST);
    Check(cb_cost.account_linear == c.account_linear,
          "coinbase needs no resolved spends");
    Coin wrong = funding;
    ++wrong.outpoint.index;
    for (const auto &coins : std::vector<std::vector<Coin>>{
             {}, {wrong}, {funding, funding}}) {
        bool rejected = false;
        try {
            AuthenticatedTransactionCostsResolved(
                spend, TX, coins, 2, 1120, effects.invocation_cost, COST);
        } catch (const std::invalid_argument &) { rejected = true; }
        Check(rejected, "reject missing mismatched or surplus cost coins");
    }
    std::vector<uint8_t> cbraw, spraw;
    Check(EncodeTransaction(cb, TX, cbraw, error) &&
              EncodeTransaction(spend, TX, spraw, error),
          error);
    const uint64_t frames =
        CompactSizeWidth(cbraw.size()) + CompactSizeWidth(spraw.size());
    const auto cost = BlockEffectiveCost(
        AuthenticatedEnvelopeCost(frames, 2, COST),
        {c.account_linear, s.account_linear}, DevelopmentGenesis);
    const auto record =
        AccountValidatedOrdinary(spend, effects, TX, DevelopmentGenesis);
    const auto transition =
        AdvanceMonetary(DevelopmentGenesis, money, 2, {record}, 0, 0,
                        cbraw.size(), frames, cost, cost);
    IncrementalUtxoSet expected;
    for (const auto &coin : effects.created)
        Check(expected.Insert(coin), "expected coin");
    Header child;
    child.version = 2;
    child.bits = 0x207fffff;
    child.height = 2;
    child.time = 1121;
    child.prev_id = parent_id;
    child.state_root = StateRoot({}, 2, expected.Root(), transition.state);
    auto wire = Wire(child, {cb, spend});
    Hash target, id;
    Check(DecodeTarget(child.bits, limit, target), "target");
    for (;; ++child.nonce) {
        Check(BlockId({}, child, id), "child id");
        if (MeetsTarget(id, target)) break;
    }
    wire = Wire(child, {cb, spend});
    TestState stored(view);
    StagedBlockTransition disk_result;
    Check(StageCompleteBlock(wire, parent, {parent.header, genesis}, hp, profile,
                             DevelopmentGenesis, COST, stored, disk_result, error)
              == CandidateCheckResult::Accepted, error);
    Check(!stored.aborted && disk_result.utxo_root == expected.Root() &&
              disk_result.state_root == child.state_root &&
              EncodeMonetaryState(disk_result.monetary.state) ==
                  EncodeMonetaryState(transition.state) &&
              disk_result.invocation_cost == effects.invocation_cost,
          "storage transition matches oracle roots money and costs");
    // Header-invalid persistence requires an opaque, exact-body/parent proof.
    // Reuse the proof output to prove every inconclusive path clears stale
    // facts.
    DeterministicBlockFailure proof;
    auto classified = [&](Header header, std::vector<Transaction> txs,
                          const OrdinaryCandidateProfile &local,
                          CandidateCheckResult expected_result,
                          bool expected_proof) {
        auto bytes = Wire(header, txs);
        Hash candidate_target{}, candidate_id{};
        Check(DecodeTarget(header.bits, limit, candidate_target),
              "typed target");
        while (true) {
            Check(BlockId({}, header, candidate_id), "typed id");
            if (MeetsTarget(candidate_id, candidate_target)) break;
            ++header.nonce;
        }
        bytes = Wire(header, txs);
        TestState state(view);
        StagedBlockTransition untouched;
        Check(StageCompleteBlock(bytes, parent, {parent.header, genesis}, hp,
                                 local, DevelopmentGenesis, COST, state,
                                 untouched, error, &proof) == expected_result,
              "typed classification: " + error);
        Check(proof.Valid() == expected_proof, "typed invalid proof presence");
        if (expected_proof)
            Check(proof.BlockId() == candidate_id &&
                      proof.ParentId() == parent_id &&
                      proof.ParentRoot() == utxo.Root() &&
                      proof.ProfileDigest() ==
                          BlockValidationProfileDigest(
                              hp, local, DevelopmentGenesis, COST),
                  "typed invalid proof binds exact identity/profile/parent "
                  "state");
    };
    auto overclaim = cb;
    overclaim.outputs[0].value = UINT64_MAX;
    classified(child, {overclaim, spend}, profile,
               CandidateCheckResult::Invalid, true);
    auto wrong_witness = spend;
    wrong_witness.inputs[0].witnesses[0].script = {0x66};
    classified(child, {cb, wrong_witness}, profile,
               CandidateCheckResult::Invalid, true);
    auto local_configuration = profile;
    local_configuration.vm_cost.field_sizes = {{0xe7, {1}}};
    classified(child, {cb, spend}, local_configuration,
               CandidateCheckResult::Inconclusive, false);
    {
        auto tampered = wire;
        tampered.back() ^= 0xff;
        TestState state(view);
        StagedBlockTransition untouched;
        Check(StageCompleteBlock(tampered, parent, {parent.header, genesis}, hp,
                                 profile, DevelopmentGenesis, COST, state,
                                 untouched, error,
                                 &proof) == CandidateCheckResult::Invalid &&
                  !proof.Valid(),
              "unbound supplied body cannot certify header invalidity");
    }
    for (bool write_failure : {false, true}) {
        TestState failed(view);
        failed.fail_reads = !write_failure;
        failed.fail_writes = write_failure;
        StagedBlockTransition untouched;
        untouched.block_id[0] = 123;
        Check(StageCompleteBlock(wire, parent, {parent.header, genesis}, hp, profile,
                                 DevelopmentGenesis, COST, failed, untouched, error)
                  == CandidateCheckResult::StorageError,
              "backend failure is operational");
        Check(failed.aborted && untouched.block_id[0] == 123,
              "failed staging aborts without publishing result");
    }
    TestState bad_context(view);
    auto wrong_context = profile;
    ++wrong_context.parent_mtp;
    StagedBlockTransition no_context;
    Check(StageCompleteBlock(wire, parent, {parent.header, genesis}, hp,
                             wrong_context, DevelopmentGenesis, COST, bad_context,
                             no_context, error) == CandidateCheckResult::StorageError &&
              bad_context.aborted, "bad local context is operational");
    TestState throwing(view);
    throwing.throw_writes = true;
    StagedBlockTransition untouched_throw;
    Check(StageCompleteBlock(wire, parent, {parent.header, genesis}, hp, profile,
                             DevelopmentGenesis, COST, throwing, untouched_throw, error)
              == CandidateCheckResult::StorageError && throwing.aborted &&
              throwing.coins.empty() && throwing.writes == 2,
          "backend exception after mutation aborts as operational failure");
#ifdef LOTUS_V2_TEST_DISK
    char directory[] = "/private/tmp/lotus-v2-disk-block-XXXXXX";
    Check(mkdtemp(directory) != nullptr, "disk test directory");
    {
        DiskStateOptions options;
        options.cache_bytes = 1024;
        options.write_buffer_bytes = 64 << 10;
        options.identity = hp.chain_id;
        options.profile_digest = BlockValidationProfileDigest(hp, profile, DevelopmentGenesis, COST);
        DiskStateStore db;
        DiskStateError failure;
        Check(DiskStateStore::Open(directory, options, {}, db, failure), failure.message);
        DiskStateMetadata parent_meta;
        Check(BlockId({}, parent.header, parent_meta.tip), "stored parent id");
        std::array<uint8_t, HEADER_SIZE> header_bytes;
        Check(SerializeHeader(parent.header, header_bytes), "stored parent header");
        parent_meta.header.assign(header_bytes.begin(), header_bytes.end());
        const auto monetary_bytes = EncodeMonetaryState(parent.monetary);
        parent_meta.monetary.assign(monetary_bytes.begin(), monetary_bytes.end());
        parent_meta.auxiliary = EncodeDiskChainContext({parent.header, genesis}, {});
        std::vector<Header> recovered;
        std::vector<uint8_t> recovered_wire;
        Check(ReadDiskChainContext(parent_meta, hp, recovered, recovered_wire, error) &&
                  recovered.size() == 2 && recovered_wire.empty(), "initial history recovery");
        auto corrupt_meta = parent_meta;
        corrupt_meta.auxiliary[6 + HEADER_SIZE + 4] ^= 1;
        Check(!ReadDiskChainContext(corrupt_meta, hp, recovered, recovered_wire, error),
              "corrupted ancestor history rejected");
        corrupt_meta = parent_meta;
        corrupt_meta.auxiliary[5] = 12;
        Check(!ReadDiskChainContext(corrupt_meta, hp, recovered, recovered_wire, error),
              "oversized history rejected before allocation");
        corrupt_meta = parent_meta;
        corrupt_meta.auxiliary.pop_back();
        Check(!ReadDiskChainContext(corrupt_meta, hp, recovered, recovered_wire, error),
              "truncated history rejected");
        {
            DiskStateTransaction seed;
            Check(db.Begin(seed, failure) && seed.Insert(funding, failure) &&
                      seed.Commit(parent_meta, failure), failure.message);
        }
        // The stored-context path derives these values; caller leftovers must
        // neither select another spend clock nor prevent restart validation.
        auto stale_context = profile;
        stale_context.candidate_height = 999;
        stale_context.parent_mtp = 999;
        StagedBlockTransition durable;
        auto different_genesis = hp;
        different_genesis.genesis_id[0] ^= 1;
        Check(BlockValidationProfileDigest(different_genesis, profile, DevelopmentGenesis, COST) !=
                  options.profile_digest, "exact genesis participates in storage profile");
        Check(!db.MatchesProfile(hp.chain_id, BlockValidationProfileDigest(
                  different_genesis, profile, DevelopmentGenesis, COST)),
              "stored profile rejects another genesis independently of history");
        Check(ConnectStoredDiskBlock(wire, different_genesis, profile,
                  DevelopmentGenesis, COST, db, durable, error) == CandidateCheckResult::StorageError &&
                  db.Metadata() == parent_meta, "another genesis cannot reuse existing validator state");
        auto wrong_cost = COST;
        ++wrong_cost.hash_byte;
        Check(ConnectDiskBlock(wire, {parent.header, genesis}, hp, profile,
                               DevelopmentGenesis, wrong_cost, db, durable, error)
                  == CandidateCheckResult::StorageError && db.Metadata() == parent_meta,
              "changed validator schedule cannot reuse stored profile");
        durable.block_id[0] = 77;
        Check(ConnectEligibleDiskBlock(wire, child.time - 11, 10, hp,
                                       stale_context, DevelopmentGenesis, COST,
                                       db, durable,
                                       error) == DiskBlockAdmission::Deferred,
              "future admission is deferred, not permanently invalid");
        Check(db.Metadata() == parent_meta && db.Root() == utxo.Root() &&
                  durable.block_id[0] == 77,
              "future deferral leaves exact stored tuple and result unchanged");
        // Advancing the caller's clock by one second admits the identical bytes
        // exactly at the explicitly supplied eligibility boundary.
        Check(ConnectEligibleDiskBlock(wire, child.time - 10, 10, hp,
                                       stale_context, DevelopmentGenesis, COST,
                                       db, durable,
                                       error) == DiskBlockAdmission::Accepted,
              error);
        Check(db.Root() == expected.Root() && db.Metadata().tip == durable.block_id &&
                  ReadDiskChainContext(db.Metadata(), hp, recovered, recovered_wire, error) &&
                  recovered_wire == wire && recovered.size() == 3,
              "atomic block bytes, history and tip");
        db = DiskStateStore{};
        Check(DiskStateStore::Open(directory, options, {}, db, failure), failure.message);
        Check(db.Root() == expected.Root() && db.Metadata().tip == durable.block_id,
              "reopened complete state");
        Check(ReadDiskChainContext(db.Metadata(), hp, recovered, recovered_wire, error) &&
                  recovered_wire == wire && recovered.size() == 3,
              "reopened authenticated history and exact block bytes");
        Check(db.Disconnect(durable.block_id, failure), failure.message);
        Check(db.Root() == utxo.Root() && db.Metadata() == parent_meta,
              "durable disconnect restores exact parent tuple");
        durable.block_id[0] = 78;
        Check(ConnectEligibleDiskBlock(wire, child.time - 11, 10, hp,
                                       stale_context, DevelopmentGenesis, COST,
                                       db, durable,
                                       error) == DiskBlockAdmission::Deferred &&
                  db.Metadata() == parent_meta && db.Root() == utxo.Root() &&
                  durable.block_id[0] == 78,
              "backward clock after disconnect defers without state mutation");
        for (const auto &[now, window] :
             std::vector<std::pair<uint64_t, uint64_t>>{
                 {UINT64_MAX, 0}, {UINT64_MAX, UINT64_MAX}, {0, UINT64_MAX}}) {
            Check(ConnectEligibleDiskBlock(
                      wire, now, window, hp, stale_context, DevelopmentGenesis,
                      COST, db, durable, error) == DiskBlockAdmission::Accepted,
                  "large now/window admission must not overflow");
            Check(db.Disconnect(durable.block_id, failure) &&
                      db.Metadata() == parent_meta && db.Root() == utxo.Root(),
                  "large-clock test restores exact parent tuple");
        }
        Check(ConnectEligibleDiskBlock({}, UINT64_MAX, UINT64_MAX, hp,
                                       stale_context, DevelopmentGenesis, COST,
                                       db, durable,
                                       error) == DiskBlockAdmission::Invalid &&
                  db.Metadata() == parent_meta && db.Root() == utxo.Root(),
              "malformed wire remains invalid rather than deferred");
        const std::vector<uint8_t> truncated_header(wire.begin(), wire.begin() + HEADER_SIZE - 1);
        auto truncated_body = wire;
        truncated_body.pop_back();
        for (const auto &invalid_wire : {truncated_header, truncated_body}) {
            Check(ConnectEligibleDiskBlock(invalid_wire, UINT64_MAX, 0, hp,
                                           stale_context, DevelopmentGenesis,
                                           COST, db, durable, error) ==
                      DiskBlockAdmission::Invalid &&
                      db.Metadata() == parent_meta && db.Root() == utxo.Root(),
                  "eligible truncated header/body is invalid without mutation");
        }
        auto incompatible_profile = stale_context;
        ++incompatible_profile.vm.max_steps;
        Check(ConnectEligibleDiskBlock(wire, UINT64_MAX, 0, hp,
                                       incompatible_profile, DevelopmentGenesis,
                                       COST, db, durable, error) ==
                  DiskBlockAdmission::StorageError &&
                  db.Metadata() == parent_meta && db.Root() == utxo.Root(),
              "eligible block with stored profile mismatch is storage error");
        db = DiskStateStore{};
        Check(DiskStateStore::Open(directory, options, {}, db, failure), failure.message);
        Check(db.Metadata() == parent_meta && db.Root() == utxo.Root(),
              "reopened disconnected parent");
        Check(ConnectStoredDiskBlock(wire, hp, stale_context,
                               DevelopmentGenesis, COST, db, durable, error)
                  == CandidateCheckResult::Accepted, error);
    }
    std::filesystem::remove_all(directory);
#endif
    const auto before_root = utxo.Root();
    const auto before_money = EncodeMonetaryState(money);
    // Invalid absolute anchors are reported through the bool/error API and
    // must preserve both caller state and the output record.
    auto invalid_anchor = DevelopmentGenesis;
    invalid_anchor.genesis_work = {};
    OrdinaryBlockConnected anchor_rejected;
    anchor_rejected.state_root[0] = 123;
    Check(!ConnectCompleteBlock(wire, parent, {parent.header, genesis}, hp,
                                profile, invalid_anchor, COST, view, utxo,
                                money, anchor_rejected, error) &&
              error == "zero genesis work anchor",
          "invalid anchor returns failure without throwing");
    Check(utxo.Root() == before_root &&
              EncodeMonetaryState(money) == before_money && view.size() == 1 &&
              anchor_rejected.state_root[0] == 123,
          "invalid anchor preserves caller state and output");
    // Invalid PoW wins over malformed transaction bytes: no body hashing/VM
    // or state copying happens before the cheap contextual header gate.
    Header bad_pow = child;
    for (;; ++bad_pow.nonce) {
        Check(BlockId({}, bad_pow, id), "bad pow id");
        if (!MeetsTarget(id, target)) break;
    }
    auto bad_pow_wire = Wire(bad_pow, {cb, spend});
    bad_pow_wire[139] = 8;
    OrdinaryBlockConnected pow_rejected;
    Check(!ConnectCompleteBlock(bad_pow_wire, parent, {parent.header, genesis},
                                hp, profile, DevelopmentGenesis, COST, view,
                                utxo, money, pow_rejected, error) &&
              error == "proof of work",
          "header gate precedes body decoding");
    auto reject = [&](Header h, std::vector<Transaction> txs,
                      const std::string &why) {
        auto mutated = Wire(h, txs);
        Hash mutation_target, mutation_id;
        Check(DecodeTarget(h.bits, limit, mutation_target), "mutation target");
        for (;; ++h.nonce) {
            Check(BlockId({}, h, mutation_id), "mutation id");
            if (MeetsTarget(mutation_id, mutation_target)) break;
        }
        mutated = Wire(h, txs);
        TestState failed(view);
        StagedBlockTransition untouched;
        untouched.block_id[0] = 123;
        Check(StageCompleteBlock(mutated, parent, {parent.header, genesis}, hp,
                                 profile, DevelopmentGenesis, COST, failed,
                                 untouched, error) == CandidateCheckResult::Invalid,
              "storage path rejects same invalid block: " + why);
        Check(failed.aborted && failed.coins.empty() && untouched.block_id[0] == 123,
              "invalid staged block discarded");
        OrdinaryBlockConnected rejected;
        Check(!ConnectCompleteBlock(mutated, parent, {parent.header, genesis},
                                    hp, profile, DevelopmentGenesis, COST, view,
                                    utxo, money, rejected, error),
              why);
        Check(utxo.Root() == before_root &&
                  EncodeMonetaryState(money) == before_money &&
                  view.size() == 1,
              "atomic complete rejection");
    };
    auto h = child;
    h.state_root[0] ^= 1;
    reject(h, {cb, spend}, "state mutation");
    h = child;
    h.prev_id[0] ^= 1;
    reject(h, {cb, spend}, "parent mutation");
    h = child;
    h.bits = 0x207ffffe;
    reject(h, {cb, spend}, "required target mutation");
    h = child;
    h.version++;
    reject(h, {cb, spend}, "version mutation");
    auto invalidcb = cb;
    invalidcb.inputs[0].prev_txid[0] ^= 1;
    reject(child, {invalidcb, spend}, "coinbase parent mutation");
    invalidcb = cb;
    invalidcb.inputs[0].prev_index++;
    reject(child, {invalidcb, spend}, "coinbase height mutation");
    auto invalidspend = spend;
    invalidspend.inputs[0].witnesses[0].script = {0x4d};
    reject(child, {cb, invalidspend}, "script mutation");
    OrdinaryBlockConnected connected;
    Check(ConnectCompleteBlock(wire, parent, {parent.header, genesis}, hp,
                               profile, DevelopmentGenesis, COST, view, utxo,
                               money, connected, error),
          error);
    Check(connected.state_root == child.state_root &&
              connected.monetary_bytes == EncodeMonetaryState(transition.state),
          "complete roots and EMA");
    Check(connected.monetary.total_fees ==
                  record.native_inputs - record.native_outputs &&
              connected.monetary.required_underclaim >= 240,
          "complete fees and coinbase charge");
    Check(DisconnectOrdinaryBlock(connected.undo, view, utxo, money, error),
          error);
    Check(utxo.Root() == before_root &&
              EncodeMonetaryState(money) == before_money,
          "full undo");
    std::cout << "synthetic complete costs " << c.account_linear << " "
              << s.account_linear << " " << cost << "\n";
}
} // namespace
int main() {
    try {
        WireChecks();
        CompleteChecks();
#ifdef LOTUS_V2_TEST_DISK
        DiskHistoryRolloverChecks();
#endif
        std::cout << "complete block checks passed\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
}
