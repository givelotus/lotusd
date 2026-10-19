// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <core_io.h>
#include <pow/pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <util/chaintype.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <future>
#include <stdexcept>

BOOST_FIXTURE_TEST_SUITE(lotus_v2_genesis_tests, BasicTestingSetup)

static void CheckPlaceholderGenesis(ChainType type) {
    const auto params = CreateChainParams(ArgsManager{}, type);
    const ScopedV2ChainId scoped_chain_id(params->V2ChainId());
    const CBlock &genesis = params->GenesisBlock();

    BOOST_CHECK(params->IsPlaceholderGenesis());
    BOOST_CHECK_EQUAL(genesis.GetHash(),
                      params->GetConsensus().hashGenesisBlock);

    // Valid proof of work on its own, without CheckProofOfWork's genesis
    // exemption.
    Consensus::Params consensus = params->GetConsensus();
    consensus.hashGenesisBlock = BlockHash{};
    BOOST_CHECK(CheckProofOfWork(genesis.GetHash(), genesis.nBits, consensus));

    DataStream stream{};
    stream << genesis;
    CBlock decoded;
    stream >> decoded;
    BOOST_CHECK_EQUAL(decoded.GetHash(), genesis.GetHash());
    BOOST_CHECK_EQUAL(decoded.hashMerkleRoot, genesis.hashMerkleRoot);

    // The second transaction spends Bitcoin's genesis coinbase output.
    BOOST_REQUIRE_EQUAL(genesis.vtx.size(), 2U);
    // A V2 coinbase and a legacy version 1 transaction: a transaction is
    // either all legacy or all V2.
    BOOST_CHECK_EQUAL(genesis.vtx[0]->nVersion, 7);
    BOOST_CHECK(genesis.vtx[0]->IsCoinBase());
    BOOST_CHECK_EQUAL(genesis.vtx[1]->nVersion, 1);
    BOOST_CHECK(genesis.vtx[1]->vin[0].IsLegacy());
    BOOST_CHECK(genesis.vtx[1]->vout[0].IsLegacy());
    BOOST_CHECK(genesis.vtx[1]->GetId() == TxId(genesis.vtx[1]->GetHash()));
    const CTxIn &in = genesis.vtx[1]->vin[0];
    BOOST_CHECK_EQUAL(in.prevout.GetTxId().ToString(),
                      "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7a"
                      "fdeda33b");
    BOOST_CHECK_EQUAL(in.prevout.GetN(), 0U);
    BOOST_CHECK(genesis.vtx[1]->vout[0].nValue == 50 * COIN);
}

BOOST_AUTO_TEST_CASE(mainnet_placeholder_genesis) {
    CheckPlaceholderGenesis(ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(testnet_placeholder_genesis) {
    CheckPlaceholderGenesis(ChainType::TESTNET);
}

BOOST_AUTO_TEST_CASE(regtest_genesis_is_not_placeholder) {
    const auto params = CreateChainParams(ArgsManager{}, ChainType::REGTEST);
    BOOST_CHECK(!params->IsPlaceholderGenesis());
    BOOST_CHECK_EQUAL(params->GenesisBlock().vtx.size(), 1U);
}


namespace {
CMutableTransaction IdentityDomainFixture(bool fallback) {
    lotus::v2::Transaction tx;
    lotus::v2::Input input;
    input.prev_txid.fill(0x11);
    input.sequence = CTxIn::SEQUENCE_FINAL;
    input.flags = 1;
    input.witnesses.push_back({{0x51}, {}, {}});
    tx.inputs.push_back(input);
    lotus::v2::Output output;
    output.value = 1000;
    output.branches.push_back(lotus::v2::Hash32{});
    output.branches[0].fill(0x33);
    output.paths.push_back({0});
    // One output exercises InitHashes' fast path; seventeen use its general
    // ComputeTransactionIdentities fallback. Neither needs admission/UTXO state.
    tx.outputs.assign(fallback ? 17 : 1, output);
    return CMutableTransaction::FromV2Transaction(tx);
}

bool IdentityMatchesDomain(const CTransaction &tx,
                           const lotus::v2::ChainId &domain) {
    lotus::v2::Hash32 id{}, hash{};
    std::string error;
    return lotus::v2::ComputeTransactionIdentities(
               tx.ToV2Transaction(), lotus::v2::DefaultTxProfile, domain,
               id, hash, error) &&
           std::equal(id.begin(), id.end(), tx.GetId().begin()) &&
           std::equal(hash.begin(), hash.end(), tx.GetHash().begin());
}

bool DecodeIdentityInDomain(const CMutableTransaction &fixture,
                            const lotus::v2::ChainId &domain) {
    const auto original = MakeTransactionRef(fixture);
    const auto wire = EncodeHexTx(*original);
    CMutableTransaction decoded;
    if (!DecodeHexTx(decoded, wire)) return false;
    const auto immutable = MakeTransactionRef(decoded);
    // The RPC decode path caches identities when mutable bytes become an
    // immutable transaction. A later domain restoration cannot repair them.
    if (!IdentityMatchesDomain(*immutable, domain) ||
        decoded.GetId() != immutable->GetId() ||
        decoded.GetHash() != immutable->GetHash()) return false;
    DataStream stream;
    stream << *immutable;
    const CTransaction roundtrip(deserialize, stream);
    return IdentityMatchesDomain(roundtrip, domain) &&
           EncodeHexTx(roundtrip) == wire;
}
} // namespace

BOOST_AUTO_TEST_CASE(scoped_chain_domain_is_owned_nested_and_thread_local) {
    const auto selected = GetActiveV2ChainId();
    const auto main = CreateChainParams(ArgsManager{}, ChainType::MAIN);
    const auto test = CreateChainParams(ArgsManager{}, ChainType::TESTNET);
    const auto outer_domain = main->V2ChainId() == selected
                                  ? test->V2ChainId() : main->V2ChainId();
    const auto inner_domain = outer_domain == main->V2ChainId()
                                  ? test->V2ChainId() : main->V2ChainId();
    const std::array fixtures{IdentityDomainFixture(false),
                              IdentityDomainFixture(true)};
    {
        auto borrowed = outer_domain;
        const ScopedV2ChainId scope(borrowed);
        borrowed.fill(0x7f); // The scope owns its value.
        BOOST_CHECK(GetActiveV2ChainId() == outer_domain);
        // This call must complete while the main-network scope is still held.
        // A process-global temporary selector leaks that domain into this
        // unscoped RPC-like reader and gives permanently incorrect cached IDs.
        auto reader = std::async(std::launch::async, [&] {
            const bool selected_domain = GetActiveV2ChainId() == selected;
            const bool fast_identity = DecodeIdentityInDomain(fixtures[0], selected);
            const bool fallback_identity = DecodeIdentityInDomain(fixtures[1], selected);
            return selected_domain && fast_identity && fallback_identity;
        });
        for (const auto &fixture : fixtures)
            BOOST_CHECK(DecodeIdentityInDomain(fixture, outer_domain));
        // Join before nesting changes even the control's process domain: the
        // old implementation fails deterministically, without a raced write.
        BOOST_CHECK(reader.get());
        try {
            const ScopedV2ChainId nested(inner_domain);
            BOOST_CHECK(GetActiveV2ChainId() == inner_domain);
            for (const auto &fixture : fixtures)
                BOOST_CHECK(DecodeIdentityInDomain(fixture, inner_domain));
            throw std::runtime_error("restore nested construction domain");
        } catch (const std::runtime_error &) {
        }
        BOOST_CHECK(GetActiveV2ChainId() == outer_domain);
    }
    BOOST_CHECK(GetActiveV2ChainId() == selected);
}

BOOST_AUTO_TEST_CASE(parallel_chain_factories_preserve_selected_rpc_identity) {
    const auto selected = GetActiveV2ChainId();
    const std::array types{ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST};
    std::array<BlockHash, 3> genesis_ids;
    for (size_t i = 0; i < types.size(); ++i)
        genesis_ids[i] = CreateChainParams(ArgsManager{}, types[i])
                             ->GetConsensus().hashGenesisBlock;
    const std::array fixtures{IdentityDomainFixture(false),
                              IdentityDomainFixture(true)};
    std::vector<std::future<bool>> workers;
    for (size_t i = 0; i < types.size(); ++i) {
        workers.push_back(std::async(std::launch::async, [&, i] {
            for (unsigned iteration = 0; iteration < 12; ++iteration) {
                const auto params = CreateChainParams(ArgsManager{}, types[i]);
                if (params->GetConsensus().hashGenesisBlock != genesis_ids[i] ||
                    GetActiveV2ChainId() != selected) return false;
                for (const auto &tx : params->GenesisBlock().vtx) {
                    if (tx->nVersion == 7 &&
                        !IdentityMatchesDomain(*tx, params->V2ChainId()))
                        return false;
                }
                {
                    const ScopedV2ChainId scope(params->V2ChainId());
                    if (params->GenesisBlock().GetHash() != genesis_ids[i])
                        return false;
                    for (const auto &fixture : fixtures)
                        if (!DecodeIdentityInDomain(fixture, params->V2ChainId()))
                            return false;
                }
                if (GetActiveV2ChainId() != selected) return false;
            }
            return true;
        }));
    }
    workers.push_back(std::async(std::launch::async, [&] {
        for (unsigned iteration = 0; iteration < 36; ++iteration) {
            if (GetActiveV2ChainId() != selected) return false;
            for (const auto &fixture : fixtures)
                if (!DecodeIdentityInDomain(fixture, selected)) return false;
        }
        return true;
    }));
    // Drain every owned task before fixtures/expectations leave scope. Worker
    // callbacks return owned verdicts; Boost assertions stay on this thread.
    for (auto &worker : workers) BOOST_CHECK(worker.get());
    BOOST_CHECK(GetActiveV2ChainId() == selected);
}

BOOST_AUTO_TEST_SUITE_END()
