// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Two-phase (deferred) V2 checks in block connection. A V2 transaction that
// needs the VM runs one check per input on the script check queue; the check
// completing its last input runs the transaction's final rules. These tests
// validate the same blocks with no script threads (-par=1) and with several
// (-par=4): validity and reject reasons must not depend on the schedule.

#include <config.h>
#include <consensus/validation.h>
#include <key.h>
#include <lotus_v2/deferred_checks.h>
#include <lotus_v2/output.h>
#include <lotus_v2/tagged_hash.h>
#include <lotus_v2/transaction.h>
#include <node/miner.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/setup_common.h>
#include <timedata.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<uint8_t>;

constexpr uint64_t kFee = 10'000;
constexpr uint64_t kCoin = 100'000;

const lotus::v2::Hash kRoot = [] {
    lotus::v2::Hash h;
    h.fill(0x11);
    return h;
}();
const Bytes kOpTrue{0x4e};
// N0: leaves a false top stack element.
const Bytes kFail{0x00};

Bytes Num(int64_t n) {
    Bytes out(16, n < 0 ? 0xff : 0x00);
    uint64_t u = uint64_t(n);
    for (size_t i = 0; i < 8; ++i) out[i] = uint8_t(u >> (8 * i));
    return out;
}

Bytes Push(const Bytes &data) {
    Bytes out;
    if (data.size() <= 75) {
        out.push_back(uint8_t(data.size()));
    } else {
        out = {0x4c, uint8_t(data.size())};
    }
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

// An OutputTemplate pinning branch slot 0 to kRoot, optionally with an
// exact value.
Bytes Template(std::optional<uint64_t> exact_value) {
    Bytes t{uint8_t(exact_value ? 1 : 0)};
    if (exact_value) {
        for (size_t i = 0; i < 8; ++i) t.push_back(uint8_t(*exact_value >> (8 * i)));
    }
    // branch_count, branch_mask (u16), stack mask (u16), state, output.
    for (uint8_t b : {0, 1, 0, 0, 0, 0, 0}) t.push_back(b);
    t.insert(t.end(), kRoot.begin(), kRoot.end());
    return t;
}

// <template> <claim> ENFORCEOUTPUT TRUE
Bytes Pay(uint64_t claim, std::optional<uint64_t> exact_value = std::nullopt) {
    Bytes s = Push(Template(exact_value));
    const Bytes n = Push(Num(int64_t(claim)));
    s.insert(s.end(), n.begin(), n.end());
    s.push_back(0xeb);
    s.push_back(0x4e);
    return s;
}

CTxOut V2Out(uint64_t value, const lotus::v2::Hash &root) {
    lotus::v2::Output o;
    o.value = value;
    o.branches = {root};
    o.paths = {{0}};
    return CTxOut::FromV2Output(o);
}

CTxOut V2Leaf(uint64_t value, const Bytes &script) {
    return V2Out(value, lotus::v2::BranchLeaf(script));
}

CTxIn V2In(const COutPoint &prevout, const Bytes &script) {
    CTxIn in(prevout, CScript(), CTxIn::SEQUENCE_FINAL);
    in.nFlags = 1;
    in.nPathIndex = 0;
    lotus::v2::BranchWitness w;
    w.script = script;
    in.vWitnesses = {w};
    return in;
}

CMutableTransaction V2Tx(std::vector<CTxIn> ins, std::vector<CTxOut> outs) {
    CMutableTransaction mtx;
    mtx.nVersion = 7;
    mtx.nV2Lock = 0;
    mtx.nLockTime = 0;
    mtx.vin = std::move(ins);
    mtx.vout = std::move(outs);
    return mtx;
}

const std::string kValid = "valid";

// Validates the same scenarios on one node and reports, per scenario, the
// outcome and the reason the test expects from block order.
struct Scenarios : TestChain100Setup {
    explicit Scenarios(const char *par)
        : TestChain100Setup(ChainType::REGTEST, {par}) {}

    CScript coinbase_spk;
    std::map<std::string, COutPoint> coins;

    void Fund() {
        coinbase_spk = CScript() << ToByteVector(coinbaseKey.GetPubKey())
                                 << OP_CHECKSIG;
        const std::vector<std::pair<std::string, Bytes>> wanted = {
            {"pay_b1", Pay(20'000)},
            {"pay_a1", Pay(20'000, 20'000)},
            {"pay_b2", Pay(20'000)},
            {"true1", kOpTrue},
            {"fail1", kFail},
        };
        // A V2 coinbase pays the V2 coins.
        std::vector<CTxOut> outputs;
        for (const auto &[_, script] : wanted) {
            outputs.push_back(V2Leaf(kCoin, script));
        }
        const TxId fund_id = MineV2Coinbase(outputs)->GetId();
        {
            LOCK(cs_main);
            BOOST_REQUIRE(m_node.chainman->ActiveChainstate().CoinsTip().HaveCoin(
                COutPoint(fund_id, 0)));
        }
        for (size_t i = 0; i < wanted.size(); ++i) {
            coins[wanted[i].first] = COutPoint(fund_id, uint32_t(i));
        }
    }

    // pay_b1 (any R output, claim 20k) and pay_a1 (exact 20k R output,
    // claim 20k): first match puts both on o0; the flow moves pay_b1 to o1
    // when o1 has 20k.
    CMutableTransaction Claims(uint64_t o1) {
        return V2Tx({V2In(coins["pay_b1"], Pay(20'000)),
                     V2In(coins["pay_a1"], Pay(20'000, 20'000))},
                    {V2Out(20'000, kRoot), V2Out(o1, kRoot),
                     V2Leaf(2 * kCoin - 20'000 - o1 - kFee, kOpTrue)});
    }
    // A single feasible claim.
    CMutableTransaction SingleClaim() {
        return V2Tx({V2In(coins["pay_b2"], Pay(20'000))},
                    {V2Out(20'000, kRoot),
                     V2Leaf(kCoin - 20'000 - kFee, kOpTrue)});
    }
    // A fast-path spend: no VM, no deferred records.
    CMutableTransaction Plain() {
        return V2Tx({V2In(coins["true1"], kOpTrue)},
                    {V2Leaf(kCoin - kFee, kOpTrue)});
    }
    // A failing script on its own.
    CMutableTransaction Failing() {
        return V2Tx({V2In(coins["fail1"], kFail)},
                    {V2Leaf(kCoin - kFee, kOpTrue)});
    }
    // Input 0 records an over-claim; input 1 fails its script. The failed
    // input means phase 2 never runs: the reason is the script failure.
    CMutableTransaction FailedInputWithClaim() {
        return V2Tx({V2In(coins["pay_b2"], Pay(20'000)),
                     V2In(coins["fail1"], kFail)},
                    {V2Out(10'000, kRoot),
                     V2Leaf(2 * kCoin - 10'000 - kFee, kOpTrue)});
    }

    std::string Validate(const std::vector<CMutableTransaction> &txs,
                         std::string *debug = nullptr) {
        auto &chainstate = m_node.chainman->ActiveChainstate();
        const CBlock block = CreateBlock(txs, coinbase_spk, chainstate);
        LOCK(cs_main);
        BlockValidationState state;
        const bool ok = TestBlockValidity(
            state, GetConfig().GetChainParams(), chainstate, block,
            m_node.chainman->ActiveTip(), GetAdjustedTime,
            BlockValidationOptions(GetConfig()).withCheckPoW(false));
        if (debug) *debug = state.GetDebugMessage();
        return ok ? kValid : state.GetRejectReason();
    }

    // The reason of the failing transaction that comes first in block
    // (canonical txid) order.
    static std::string FirstInBlockOrder(
        std::vector<std::pair<CMutableTransaction, std::string>> failing) {
        std::sort(failing.begin(), failing.end(), [](auto &a, auto &b) {
            return a.first.GetId() < b.first.GetId();
        });
        return failing.front().second;
    }

    std::vector<std::string> Run() {
        Fund();
        const std::string script_false =
            "mandatory-script-verify-flag-failed (Script evaluated without "
            "error but finished with a false/empty top stack element)";
        std::vector<std::string> out;
        // Each scenario is validated repeatedly: with script threads the
        // order inputs complete in varies between runs.
        auto check = [&](const std::vector<CMutableTransaction> &txs,
                         const std::string &expected) {
            for (int i = 0; i < 8; ++i) {
                const std::string got = Validate(txs);
                BOOST_CHECK_EQUAL(got, expected);
                if (i == 0) out.push_back(got);
            }
        };
        // Feasible by maximum flow, beside a fast-path transaction and a
        // single-claim transaction.
        check({Claims(30'000), Plain(), SingleClaim()}, kValid);
        // Infeasible: o1 lacks room for pay_b1.
        check({Claims(19'999), Plain()}, "output-overclaimed");
        // Two failing transactions: the first in block order is reported.
        check({Claims(19'999), Failing(), Plain()},
              FirstInBlockOrder({{Claims(19'999), "output-overclaimed"},
                                 {Failing(), script_false}}));
        // A failed input's records never reach phase 2.
        check({FailedInputWithClaim(), Plain()}, script_false);
        {
            std::string debug;
            Validate({FailedInputWithClaim()}, &debug);
            BOOST_CHECK(debug.find("input 1") != std::string::npos);
        }
        // The valid block connects.
        const CBlock block =
            CreateAndProcessBlock({Claims(30'000), Plain(), SingleClaim()},
                                  coinbase_spk);
        {
            LOCK(cs_main);
            BOOST_CHECK_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(),
                              block.GetHash());
        }
        return out;
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(v2_deferred_block_tests)

BOOST_AUTO_TEST_CASE(parallel_and_sequential_block_validation_agree) {
    std::vector<std::string> sequential;
    {
        Scenarios node{"-par=1"};
        sequential = node.Run();
    }
    std::vector<std::string> parallel;
    {
        Scenarios node{"-par=4"};
        parallel = node.Run();
    }
    BOOST_CHECK_EQUAL_COLLECTIONS(sequential.begin(), sequential.end(),
                                  parallel.begin(), parallel.end());
    BOOST_CHECK_EQUAL(sequential.size(), 4U);
}

BOOST_AUTO_TEST_CASE(deferred_records_bypass_script_cache) {
    // A transaction whose inputs stage deferred records is never stored in
    // the script execution cache; one without records is.
    Scenarios node{"-par=1"};
    node.Fund();
    const CTransaction claims{node.SingleClaim()};
    const CTransaction plain{node.Plain()};
    LOCK(cs_main);
    auto &cache = node.m_node.chainman->m_validation_cache;
    const CCoinsViewCache &view =
        node.m_node.chainman->ActiveChainstate().CoinsTip();
    auto cached = [&](const CTransaction &tx) {
        ScriptCacheKey key(tx, /*flags=*/0, cache.ScriptExecutionCacheHasher());
        ScriptCacheElement elem(key, 0);
        return cache.m_script_execution_cache.get(elem, /*erase=*/false);
    };
    for (const CTransaction *tx : {&claims, &plain}) {
        for (int round = 0; round < 2; ++round) {
            TxValidationState state;
            TxSigCheckLimiter limiter;
            int sigchecks = 0;
            // Different policy/consensus flags may share preparation, never
            // their execution verdict or the deferred records of a run.
            const uint32_t flags = round == 0 ? 0 : SCRIPT_VERIFY_NULLFAIL;
            BOOST_CHECK(CheckInputScripts(
                *tx, state, view, flags, /*sigCacheStore=*/false,
                /*scriptCacheStore=*/true, tx->GetPrecomputedData(), cache,
                sigchecks, limiter, nullptr, nullptr));
        }
    }
    BOOST_CHECK(!cached(claims));
    BOOST_CHECK(cached(plain));
}

BOOST_AUTO_TEST_CASE(block_check_bypasses_script_cache_for_records) {
    // TestBlockValidity caches script results (ConnectBlock with
    // fJustCheck). Transactions whose inputs staged deferred records are
    // left out; the fast-path spend beside them is cached.
    Scenarios node{"-par=4"};
    node.Fund();
    const CTransaction claims{node.Claims(30'000)};
    const CTransaction single{node.SingleClaim()};
    const CTransaction plain{node.Plain()};
    BOOST_REQUIRE_EQUAL(node.Validate({node.Claims(30'000), node.SingleClaim(),
                                       node.Plain()}),
                        kValid);
    LOCK(cs_main);
    auto &cache = node.m_node.chainman->m_validation_cache;
    // The block's script flags, with and without replay protection.
    const uint32_t base =
        SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG |
        SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
        SCRIPT_VERIFY_STRICTENC | SCRIPT_ENABLE_SIGHASH_FORKID |
        SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLFAIL |
        SCRIPT_VERIFY_SIGPUSHONLY | SCRIPT_VERIFY_CLEANSTACK |
        SCRIPT_ENABLE_SCHNORR_MULTISIG | SCRIPT_VERIFY_MINIMALDATA |
        SCRIPT_ENFORCE_SIGCHECKS;
    auto cached = [&](const CTransaction &tx) {
        for (uint32_t flags : {base, base | SCRIPT_ENABLE_REPLAY_PROTECTION}) {
            ScriptCacheKey key(tx, flags, cache.ScriptExecutionCacheHasher());
            ScriptCacheElement elem(key, 0);
            if (cache.m_script_execution_cache.get(elem, /*erase=*/false))
                return true;
        }
        return false;
    };
    BOOST_CHECK(cached(plain));
    BOOST_CHECK(!cached(claims));
    BOOST_CHECK(!cached(single));
}

BOOST_AUTO_TEST_SUITE_END()
