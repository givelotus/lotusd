#include "ordinary_validation.h"

#include "commitment.h"
#include "ordinary_test/compiler_mint_fixture.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace lotus::v2;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition))                                                      \
            throw std::runtime_error("check failed: " #condition);            \
    } while (false)

namespace {
std::vector<uint8_t> Hex(const char *hex) {
    std::vector<uint8_t> result;
    auto digit = [](char c) -> uint8_t {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::runtime_error("bad fixture hex");
    };
    for (size_t i = 0; hex[i]; i += 2) {
        CHECK(hex[i + 1]);
        result.push_back((digit(hex[i]) << 4) | digit(hex[i + 1]));
    }
    return result;
}

Hash HashHex(const char *hex) {
    const auto bytes = Hex(hex);
    CHECK(bytes.size() == 32);
    Hash out{};
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

const std::vector<uint8_t> TRUE_SCRIPT{0x4e};
const std::vector<uint8_t> MINT_SCRIPT{0x79, 0x4e};

Output Native(uint64_t value) {
    Output out;
    out.value = value;
    out.branches = {BranchLeaf(TRUE_SCRIPT)};
    out.paths = {{0}};
    return out;
}

Output Token(uint64_t value, const Hash &token_id) {
    Output out = Native(value);
    out.flags = 1;
    out.token_id = token_id;
    return out;
}

OrdinaryCandidateProfile Profile() {
    OrdinaryCandidateProfile p{
        TxProfile{32, 32, 8, 512, 8, 8192, 64},
        VmProfile{512, 8, 8192, 32, 32, 65536, 16, 100000},
        VmCostProfile{}, 100, 50000, 2, 100, 10000000};
    p.vm_cost.max_invocation_cost = 1000000;
    p.vm_cost.structural_byte_cost = 1;
    for (auto &opcode : p.vm_cost.opcode) opcode = {1, 1, 1};
    return p;
}

struct Fixture {
    Transaction tx;
    DevelopmentUtxoView view;
    Hash token_id;
    ChainId chain{};
    Fixture() {
        token_id = BranchLeaf(MINT_SCRIPT);
        Coin funding;
        funding.outpoint.tx_id[0] = 0x71;
        funding.outpoint.index = 3;
        funding.output = Native(5000);
        funding.creation_height = 90;
        funding.creation_parent_mtp = 49000;
        CHECK(view.emplace(funding.outpoint, funding).second);

        Input spend;
        spend.prev_txid = funding.outpoint.tx_id;
        spend.prev_index = funding.outpoint.index;
        spend.sequence = UINT32_MAX;
        spend.flags = 1;
        spend.witnesses = {BranchWitness{TRUE_SCRIPT, {}, {}}};
        tx.inputs.push_back(spend);

        Input mint;
        mint.prev_txid = token_id;
        mint.sequence = UINT32_MAX;
        mint.flags = 3;
        mint.witnesses = {BranchWitness{MINT_SCRIPT, {}, {}}};
        tx.inputs.push_back(mint);
        tx.outputs = {Native(4000), Token(10, token_id)};
    }
};

void RejectWithoutMutation(const Transaction &tx,
                           const OrdinaryCandidateProfile &profile,
                           DevelopmentUtxoView &view,
                           const ChainId &chain) {
    const size_t before = view.size();
    const Outpoint original = view.begin()->first;
    OrdinaryCandidateEffects effects;
    effects.native_fee = 123456;
    std::string error;
    static unsigned rejection_case = 0;
    ++rejection_case;
    if (ApplyOrdinaryCandidate(tx, profile, chain, view, effects, error))
        throw std::runtime_error("accepted invalid case " +
                                 std::to_string(rejection_case));
    CHECK(!error.empty());
    CHECK(view.size() == before && view.contains(original));
    CHECK(effects.native_fee == 123456);
}

void ValidMintAndAccounting() {
    Fixture fixture;
    const auto profile = Profile();
    OrdinaryCandidateEffects effects;
    std::string error;
    CHECK(CheckOrdinaryCandidate(fixture.tx, profile, fixture.chain,
                                 fixture.view, effects, error));
    CHECK(fixture.view.size() == 1);
    CHECK(effects.native_fee == 1000);
    CHECK(effects.token_output_burn_floor == 200);
    CHECK(effects.consumed.size() == 1 && effects.created.size() == 2);
    CHECK(effects.invocation_cost > 0);
    CHECK(ApplyOrdinaryCandidate(fixture.tx, profile, fixture.chain,
                                 fixture.view, effects, error));
    CHECK(fixture.view.size() == 2);
    CHECK(!fixture.view.contains(effects.consumed[0]));
    CHECK(fixture.view.contains(effects.created[0].outpoint));
    CHECK(fixture.view.contains(effects.created[1].outpoint));
    CHECK(effects.created[0].creation_height == profile.candidate_height);
}

void InvalidAccountingAndCoverage() {
    Fixture fixture;
    auto profile = Profile();
    auto tx = fixture.tx;
    std::vector<uint8_t> wire;
    std::string error;
    CHECK(EncodeTransaction(tx, profile.transaction, wire, error));
    CHECK(wire.size() < 5000);
    profile.dust_limit = 1;
    tx.outputs[0].value = 5000 - wire.size();
    OrdinaryCandidateEffects boundary;
    CHECK(CheckOrdinaryCandidate(tx, profile, fixture.chain, fixture.view,
                                 boundary, error));
    CHECK(boundary.native_fee == wire.size());
    tx.outputs[0].value++;
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    profile = Profile();
    tx = fixture.tx;
    tx.outputs[0].value = 5001;
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    tx = fixture.tx;
    tx.outputs[0].value = 4999;
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    tx = fixture.tx;
    profile.dust_limit = 1000;
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    profile = Profile();
    tx.inputs.pop_back();
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    tx = fixture.tx;
    tx.outputs[1].token_id[0] ^= 1;
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    tx = fixture.tx;
    tx.outputs[1].value = 0;
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    tx = fixture.tx;
    tx.inputs.push_back(tx.inputs[0]);
    tx.inputs.back().sequence = 0; // Same outpoint despite different input data.
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    tx = fixture.tx;
    tx.inputs[0].prev_index++;
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    fixture.view.begin()->second.outpoint.index++;
    RejectWithoutMutation(fixture.tx, profile, fixture.view, fixture.chain);
    fixture.view.begin()->second.outpoint.index--;
    tx = fixture.tx;
    tx.inputs.push_back(tx.inputs[1]); // Repeated mint ID, same pseudo-outpoint.
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
}

void InvalidVmAndContext() {
    Fixture fixture;
    auto profile = Profile();
    auto tx = fixture.tx;
    tx.inputs[0].witnesses[0].script = {0x4d}; // false final stack
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    tx = fixture.tx;
    tx.inputs[1].witnesses[0].script = {0x4e}; // wrong mint root
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    tx = fixture.tx;
    tx.inputs[0].witnesses[0].script = {0xbd}; // unsupported opcode
    fixture.view.begin()->second.output.branches[0] =
        BranchLeaf(std::vector<uint8_t>{0xbd});
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    fixture.view.begin()->second.output.branches[0] = BranchLeaf(TRUE_SCRIPT);
    tx = fixture.tx;
    const std::vector<uint8_t> success_script{0x5e};
    const std::vector<uint8_t> false_script{0x4d};
    tx.inputs[0].witnesses = {
        BranchWitness{success_script, {}, {}},
        BranchWitness{false_script, {}, {}}};
    fixture.view.begin()->second.output.branches = {
        BranchLeaf(success_script), BranchLeaf(false_script)};
    fixture.view.begin()->second.output.paths = {{0, 1}};
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    tx.inputs[0].witnesses.pop_back();
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    tx.inputs[0].witnesses.push_back(
        BranchWitness{false_script, {}, {}});
    tx.inputs[0].witnesses.push_back(
        BranchWitness{TRUE_SCRIPT, {}, {}});
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    fixture.view.begin()->second.output = Native(5000);
    tx = fixture.tx;
    const std::vector<uint8_t> mint_coin_read{0x79, 0x4e, 0xd6, 0x4e};
    tx.inputs[1].witnesses[0].script = mint_coin_read;
    tx.inputs[1].prev_txid = BranchLeaf(mint_coin_read);
    tx.outputs[1].token_id = tx.inputs[1].prev_txid;
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    profile.max_total_invocation_cost = 1;
    RejectWithoutMutation(fixture.tx, profile, fixture.view, fixture.chain);
    profile = Profile();
    profile.candidate_height = 89;
    RejectWithoutMutation(fixture.tx, profile, fixture.view, fixture.chain);
    profile = Profile();
    tx = fixture.tx;
    tx.lock = (uint64_t(101) << 8) | 1;
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    tx = fixture.tx;
    tx.inputs[0].sequence = 11;
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    tx = fixture.tx;
    tx.inputs[0].sequence = 0x400000 | 2;
    RejectWithoutMutation(tx, profile, fixture.view, fixture.chain);
    fixture.view.begin()->second.coinbase = true;
    profile.coinbase_maturity = 11;
    RejectWithoutMutation(fixture.tx, profile, fixture.view, fixture.chain);
}

void WideNativeAggregates() {
    Fixture fixture;
    const uint64_t max = UINT64_MAX;
    fixture.view.begin()->second.output.value = max;
    Coin second = fixture.view.begin()->second;
    second.outpoint.tx_id[0] = 0x72;
    CHECK(fixture.view.emplace(second.outpoint, second).second);
    Input second_spend = fixture.tx.inputs[0];
    second_spend.prev_txid = second.outpoint.tx_id;
    fixture.tx.inputs.insert(fixture.tx.inputs.begin() + 1, second_spend);
    fixture.tx.outputs = {Native(max), Native(max - 1000),
                          Token(10, fixture.token_id)};
    OrdinaryCandidateEffects effects;
    std::string error;
    CHECK(CheckOrdinaryCandidate(fixture.tx, Profile(), fixture.chain,
                                 fixture.view, effects, error));
    CHECK(effects.native_fee == 1000);
    fixture.tx.outputs.push_back(Native(1001));
    RejectWithoutMutation(fixture.tx, Profile(), fixture.view,
                          fixture.chain);
}

void CompilerMintAndTransfer() {
    const TxProfile tx_profile{32, 32, 8, 8192, 16, 8192, 64};
    Transaction mint, transfer;
    Output funding_output;
    std::string error;
    CHECK(DecodeTransaction(Hex(compiler_fixture::mint_wire), tx_profile,
                             mint, error));
    CHECK(DecodeTransaction(Hex(compiler_fixture::transfer_wire), tx_profile,
                             transfer, error));
    CHECK(DecodeOutput(Hex(compiler_fixture::funding_coin_wire),
                       funding_output, error));
    DevelopmentUtxoView view;
    Coin funding;
    funding.outpoint = {mint.inputs[0].prev_txid, mint.inputs[0].prev_index};
    funding.output = funding_output;
    funding.creation_height = 90;
    funding.creation_parent_mtp = 49000;
    CHECK(view.emplace(funding.outpoint, funding).second);
    const ChainId chain_id = HashHex(compiler_fixture::chain_id);
    auto profile = Profile();
    profile.transaction = tx_profile;
    profile.dust_limit = 500;
    DevelopmentUtxoView tampered = view;
    tampered.begin()->second.output.value++;
    ResolvedCoins original_coins{view.begin()->second.output, std::nullopt};
    ResolvedCoins tampered_coins{tampered.begin()->second.output, std::nullopt};
    Hash original_coins_root, tampered_coins_root;
    CHECK(ComputeCoinsRoot(mint, original_coins, original_coins_root, error));
    CHECK(ComputeCoinsRoot(mint, tampered_coins, tampered_coins_root, error));
    CHECK(original_coins_root != tampered_coins_root);
    RejectWithoutMutation(mint, profile, tampered, chain_id);
    Transaction amount_changed = mint;
    amount_changed.outputs[0].value++;
    RejectWithoutMutation(amount_changed, profile, view, chain_id);
    OrdinaryCandidateEffects effects;
    CHECK(ApplyOrdinaryCandidate(mint, profile, chain_id, view, effects,
                                 error));
    CHECK(effects.txid == HashHex(compiler_fixture::mint_txid));
    CHECK(effects.txhash == HashHex(compiler_fixture::mint_txhash));
    CHECK(effects.native_fee == 3000 && view.size() == 2);
    profile.candidate_height = 101;
    profile.parent_mtp = 50100;
    CHECK(ApplyOrdinaryCandidate(transfer, profile, chain_id, view, effects,
                                 error));
    CHECK(effects.txid == HashHex(compiler_fixture::transfer_txid));
    CHECK(effects.txhash == HashHex(compiler_fixture::transfer_txhash));
    CHECK(effects.native_fee == 3000 && view.size() == 3);
    CHECK(effects.token_output_burn_floor == 2000);

    // Merge both transfer token outputs (700 + 250) into one 950-unit output.
    Transaction merge;
    CHECK(DecodeTransaction(Hex(compiler_fixture::merge_wire), tx_profile,
                            merge, error));
    CHECK(mint.outputs[0].HasToken());
    const Hash token_id = mint.outputs[0].token_id;
    size_t token_inputs = 0;
    for (const Input &input : merge.inputs) {
        CHECK(input.flags == 1 &&
              input.prev_txid == HashHex(compiler_fixture::transfer_txid));
        const auto coin = view.find({input.prev_txid, input.prev_index});
        CHECK(coin != view.end());
        if (coin->second.output.HasToken() &&
            coin->second.output.token_id == token_id) {
            ++token_inputs;
            CHECK(input.witnesses.size() == 2); // wallet and rules branches
        }
    }
    CHECK(token_inputs == 2 && merge.outputs.size() == 2);
    CHECK(merge.outputs[0].HasToken() && merge.outputs[0].token_id == token_id &&
          merge.outputs[0].value == 950 && !merge.outputs[0].IsBurn());
    // Altering the merged amount, dropping one token input, or omitting one
    // required witness must reject without changing the view.
    Transaction inflated = merge;
    inflated.outputs[0].value = 951;
    RejectWithoutMutation(inflated, profile, view, chain_id);
    Transaction one_input = merge;
    one_input.inputs.erase(one_input.inputs.begin() + 1);
    RejectWithoutMutation(one_input, profile, view, chain_id);
    Transaction missing_rules = merge;
    missing_rules.inputs[1].witnesses.pop_back();
    RejectWithoutMutation(missing_rules, profile, view, chain_id);
    profile.candidate_height = 102;
    profile.parent_mtp = 50200;
    CHECK(ApplyOrdinaryCandidate(merge, profile, chain_id, view, effects,
                                 error));
    CHECK(effects.txid == HashHex(compiler_fixture::merge_txid));
    CHECK(effects.txhash == HashHex(compiler_fixture::merge_txhash));
    CHECK(effects.native_fee == 1500 && effects.token_output_burn_floor == 1000);
    CHECK(effects.consumed.size() == 3 && effects.created.size() == 2);
    CHECK(view.size() == 2);
    const Coin &merged = effects.created[0];
    CHECK(view.contains(merged.outpoint) && merged.output.value == 950 &&
          merged.output.HasToken() && merged.output.token_id == token_id);
}
void LookupBoundary() {
    Fixture f;
    const auto profile = Profile();
    OrdinaryCandidateEffects expected, actual;
    std::string error;
    CHECK(CheckOrdinaryCandidate(f.tx, profile, f.chain, f.view, expected, error));
    size_t reads = 0;
    CoinLookup lookup = [&](const Outpoint &key, Coin &coin, std::string &) {
        ++reads;
        auto it = f.view.find(key);
        if (it == f.view.end()) return CoinReadResult::Missing;
        coin = it->second;
        return CoinReadResult::Found;
    };
    CHECK(CheckOrdinaryWithLookup(f.tx, profile, f.chain, lookup, actual, error)
          == CandidateCheckResult::Accepted);
    CHECK(actual.txid == expected.txid && actual.txhash == expected.txhash);
    CHECK(actual.native_fee == expected.native_fee &&
          actual.invocation_cost == expected.invocation_cost);
    CHECK(actual.consumed == expected.consumed &&
          actual.created.size() == expected.created.size());
    CHECK(reads == 1 + expected.created.size());
    // Fail each read, including output collision checks. No staged effects
    // escape, and an I/O failure cannot be classified as invalid consensus.
    for (size_t fail_at = 1; fail_at <= 1 + expected.created.size(); ++fail_at) {
        size_t calls = 0;
        CoinLookup fail = [&](const Outpoint &key, Coin &coin, std::string &why) {
            if (++calls == fail_at) {
                why = "injected disk read failure";
                return CoinReadResult::Error;
            }
            return lookup(key, coin, why);
        };
        OrdinaryCandidateEffects untouched;
        untouched.native_fee = 123;
        CHECK(CheckOrdinaryWithLookup(f.tx, profile, f.chain, fail, untouched,
                                      error) == CandidateCheckResult::StorageError);
        CHECK(untouched.native_fee == 123 && untouched.consumed.empty() &&
              untouched.created.empty());
        CHECK(error == "injected disk read failure");
    }
    for (unsigned kind = 0; kind < 4; ++kind) {
        auto local = profile;
        if (kind == 0) local.vm.max_steps = 1;
        if (kind == 1) local.vm.max_steps = 0;
        if (kind == 2) local.vm_cost.opcode[0x4e].base = 0;
        if (kind == 3) local.vm_cost.field_sizes = {{0xe7, {1}}};
        OrdinaryCandidateEffects untouched;
        untouched.native_fee = 123;
        CHECK(CheckOrdinaryWithLookup(f.tx, local, f.chain, lookup, untouched,
                                      error) ==
              CandidateCheckResult::Inconclusive);
        CHECK(untouched.native_fee == 123 && untouched.created.empty());
    }
    CoinLookup absent = [](const Outpoint &, Coin &, std::string &) {
        return CoinReadResult::Missing;
    };
    CHECK(CheckOrdinaryWithLookup(f.tx, profile, f.chain, absent, actual, error)
          == CandidateCheckResult::Invalid);
    CoinLookup corrupt = [&](const Outpoint &, Coin &coin, std::string &) {
        coin = f.view.begin()->second;
        ++coin.outpoint.index;
        return CoinReadResult::Found;
    };
    CHECK(CheckOrdinaryWithLookup(f.tx, profile, f.chain, corrupt, actual, error)
          == CandidateCheckResult::StorageError);
}

} // namespace

int main() {
    LookupBoundary();
    ValidMintAndAccounting();
    InvalidAccountingAndCoverage();
    InvalidVmAndContext();
    WideNativeAggregates();
    CompilerMintAndTransfer();
    std::cout << "V2 ordinary candidate checks and atomic application pass\n";
}
