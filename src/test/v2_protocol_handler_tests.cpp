// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net/v2_protocol_handler.h>

#include <avalanche/processor.h>
#include <avalanche/stateanchor.h>
#include <lotus_v2/fast_sync.h>
#include <lotus_v2/legacy_coin.h>
#include <node/snapshot.h>

#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/merkle.h>
#include <logging.h>
#include <net.h>
#include <net_processing.h>
#include <netmessagemaker.h>
#include <pow/pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <script/script.h>
#include <streams.h>
#include <txmempool.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <test/util/metrics.h>
#include <test/util/mining.h>
#include <test/util/net.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <memory>
#include <vector>

#include <script/signingprovider.h>
#include <script/standard.h>

using namespace lotus::v2::net;

namespace {

/** Mock the transaction relay tick clock for the duration of a test */
struct MockRelayTick {
    explicit MockRelayTick(std::chrono::milliseconds t) { Set(t); }
    ~MockRelayTick() { MockableSteadyClock::ClearMockTime(); }
    void Set(std::chrono::milliseconds t) {
        MockableSteadyClock::SetMockTime(t);
    }
};

CService MakeTestIp(uint32_t i) {
    struct in_addr s;
    s.s_addr = i;
    return CService(CNetAddr(s), Params().GetDefaultPort());
}

CScript MakeRedeemScriptForAttempt(uint32_t attempt) {
    const std::vector<uint8_t> pad(48, 0x42);
    return CScript() << int64_t(attempt) << pad << OP_2DROP << OP_TRUE;
}

CTransactionRef MakeNonCoinbaseTx(FastRandomContext &rng, uint8_t target_byte0,
                                  Amount value = 10000 * SATOSHI) {
    const CScript out_spk =
        GetScriptForDestination(ScriptHash(CScript() << OP_TRUE));
    for (uint32_t attempt = 0; attempt < 100000; ++attempt) {
        const CScript redeem_script = MakeRedeemScriptForAttempt(attempt);
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.vin.resize(1);
        mtx.vin[0].prevout = COutPoint(TxId(rng.rand256()), attempt);
        mtx.vin[0].scriptSig = CScript() << ToByteVector(redeem_script);
        mtx.vout.resize(1);
        mtx.vout[0].nValue = value;
        mtx.vout[0].scriptPubKey = out_spk;
        CTransactionRef tx = MakeTransactionRef(std::move(mtx));
        if (tx->GetId().begin()[0] == target_byte0) {
            return tx;
        }
    }
    return nullptr;
}

void FundTxInputInCoinsTip(ChainstateManager &chainman,
                           const CTransaction &tx) {
    LOCK(cs_main);
    CCoinsViewCache &coins = chainman.ActiveChainstate().CoinsTip();
    for (const CTxIn &txin : tx.vin) {
        const CScript redeem_script =
            MakeRedeemScriptForAttempt(txin.prevout.GetN());
        const CScript p2sh_spk =
            GetScriptForDestination(ScriptHash(redeem_script));
        coins.AddCoin(
            txin.prevout,
            Coin(CTxOut(tx.GetValueOut() + 10000 * SATOSHI, p2sh_spk),
                 /*nHeightIn=*/1, /*Coinbase=*/false),
            /*possible_overwrite=*/true);
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(v2_protocol_handler_tests, RegTestingSetup)

BOOST_AUTO_TEST_CASE(v2_protocol_message_types_and_headers) {
    BOOST_CHECK_EQUAL(std::string(NetMsgType::SEALEDHEADER), "sealedheader");
    BOOST_CHECK_EQUAL(std::string(NetMsgType::MERKLIXSYNC), "merklixsync");
    BOOST_CHECK_EQUAL(std::string(NetMsgType::GETMERKLIXBUCK),
                      "getmerklixbuck");
    BOOST_CHECK_EQUAL(std::string(NetMsgType::MERKLIXBUCK), "merklixbuck");
    BOOST_CHECK_EQUAL(std::string(NetMsgType::GETSHORTTX), "getshorttx");
    BOOST_CHECK_EQUAL(std::string(NetMsgType::SHORTTX), "shorttx");

    BOOST_CHECK(NetMsgType::IsBlockLike(NetMsgType::SEALEDHEADER));

    CInv sealed_inv(MSG_SEALED_HEADER, uint256{1});
    BOOST_CHECK(sealed_inv.IsMsgSealedHeader());
    BOOST_CHECK(sealed_inv.IsGenBlkMsg());
    BOOST_CHECK_EQUAL(sealed_inv.GetMessageType(), NetMsgType::SEALEDHEADER);

    const auto &all_types = getAllNetMessageTypes();
    for (const char *msg :
         {NetMsgType::SEALEDHEADER, NetMsgType::MERKLIXSYNC,
          NetMsgType::GETMERKLIXBUCK, NetMsgType::MERKLIXBUCK,
          NetMsgType::GETSHORTTX, NetMsgType::SHORTTX}) {
        BOOST_CHECK(std::find(all_types.begin(), all_types.end(),
                              std::string(msg)) != all_types.end());

        CMessageHeader hdr(Params().NetMagic(), msg, 42);
        BOOST_CHECK(hdr.IsMessageTypeValid());
        BOOST_CHECK_EQUAL(hdr.GetMessageType(), std::string(msg));
    }


}

BOOST_AUTO_TEST_CASE(gf64_arithmetic_and_syndrome_recovery) {
    FastRandomContext rng(uint256{77});

    // Identity & inverse checks in GF(2^64)
    BOOST_CHECK_EQUAL(GF64Mul(0, 12345), 0ULL);
    BOOST_CHECK_EQUAL(GF64Mul(1, 12345), 12345ULL);
    for (int i = 0; i < 64; ++i) {
        const uint64_t a = rng.rand64() | 1ULL;
        const uint64_t inv_a = GF64Inv(a);
        BOOST_CHECK_NE(inv_a, 0ULL);
        BOOST_CHECK_EQUAL(GF64Mul(a, inv_a), 1ULL);
        BOOST_CHECK_EQUAL(GF64Cube(a), GF64Mul(GF64Square(a), a));

        const uint64_t c = GF64Square(a) ^ a;
        uint64_t y = 0;
        BOOST_CHECK(GF64SolveQuadratic(c, y));
        BOOST_CHECK((y == a) || (y == (a ^ 1ULL)));
    }

    // 0-element difference
    {
        auto res = RecoverGF64Syndromes(0, 0);
        BOOST_REQUIRE(res.has_value());
        BOOST_CHECK(res->empty());
    }

    // 1-element difference
    for (int i = 0; i < 32; ++i) {
        const uint64_t x1 = (rng.rand64() & ~1ULL) | 3ULL;
        const uint64_t s1 = x1;
        const uint64_t s3 = GF64Cube(x1);
        auto res = RecoverGF64Syndromes(s1, s3);
        BOOST_REQUIRE(res.has_value());
        BOOST_REQUIRE_EQUAL(res->size(), 1U);
        BOOST_CHECK_EQUAL((*res)[0], x1);
    }

    // 2-element difference
    for (int i = 0; i < 64; ++i) {
        uint64_t x1 = rng.rand64() | 1ULL;
        uint64_t x2 = (rng.rand64() | 2ULL) ^ (uint64_t(i + 1) << 17);
        if (x1 == x2) {
            x2 ^= 0x100ULL;
        }
        if (x1 > x2) {
            std::swap(x1, x2);
        }
        const uint64_t s1 = x1 ^ x2;
        const uint64_t s3 = GF64Cube(x1) ^ GF64Cube(x2);
        auto res = RecoverGF64Syndromes(s1, s3);
        BOOST_REQUIRE(res.has_value());
        BOOST_REQUIRE_EQUAL(res->size(), 2U);
        BOOST_CHECK_EQUAL((*res)[0], x1);
        BOOST_CHECK_EQUAL((*res)[1], x2);
    }
}

BOOST_AUTO_TEST_CASE(sealedheader_fast_path_and_fallback_getdata) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    ScopedNodeMetrics metrics;
    using node::SealedHeaderOutcome;

    const Config &config = m_node.chainman->GetConfig();
    auto connman = std::make_unique<ConnmanTestMsg>(config, 0x1337, 0x1337,
                                                    *m_node.addrman);
    auto peerman =
        PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman,
                          *m_node.mempool, /*avalanche=*/nullptr, {});

    CConnman::Options options;
    options.m_msgproc = {peerman.get()};
    options.nSendBufferMaxSize = 1024 * 1024;
    connman->Init(options);

    CAddress addr(MakeTestIp(0xa0b0c010), NODE_NONE);
    CNode peer_node(/*id=*/101, /*sock=*/nullptr, addr,
                    /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                    /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
                    ConnectionType::OUTBOUND_FULL_RELAY,
                    /*inbound_onion=*/false);
    connman->Handshake(
        /*node=*/peer_node,
        /*successfully_connected=*/true,
        /*remote_services=*/ServiceFlags(NODE_NETWORK),
        /*local_services=*/ServiceFlags(NODE_NETWORK),
        /*version=*/PROTOCOL_VERSION,
        /*relay_txs=*/true);

    V2PeerProtocolHandler *v2_handler = peerman->GetV2ProtocolHandler();
    BOOST_REQUIRE(v2_handler != nullptr);

    // 1. Fallback path: send a sealedheader whose merkle root involves a missing
    // transaction not in the local mempool or candidate overlay.
    FastRandomContext rng(uint256{123});
    std::shared_ptr<CBlock> fallback_block =
        PrepareBlock(config, m_node, CScript() << OP_TRUE);
    CTransactionRef missing_tx = MakeNonCoinbaseTx(rng, 0x12);
    BOOST_REQUIRE(missing_tx != nullptr);
    fallback_block->vtx.push_back(missing_tx);
    {
        LOCK(cs_main);
        fallback_block->hashMerkleRoot = BlockMerkleRoot(*fallback_block);
    }
    while (!CheckProofOfWork(fallback_block->GetHash(), fallback_block->nBits,
                             config.GetChainParams().GetConsensus())) {
        ++fallback_block->nNonce;
    }

    {
        LOCK(peer_node.cs_vSend);
        peer_node.vSendMsg.clear();
    }

    SealedHeader fallback_sealed(*fallback_block);
    DataStream fallback_stream{};
    fallback_stream << fallback_sealed;
    std::atomic<bool> interrupt{false};
    peerman->ProcessMessage(config, peer_node, NetMsgType::SEALEDHEADER,
                            fallback_stream, 1000us, interrupt);

    const auto stats_after_miss = v2_handler->GetStats();
    BOOST_CHECK_EQUAL(stats_after_miss.sealedheader_received, 1U);
    BOOST_CHECK_EQUAL(stats_after_miss.sealedheader_reconstructed, 0U);
    BOOST_CHECK_EQUAL(stats_after_miss.sealedheader_fallback_getdata, 1U);
    BOOST_CHECK(!peer_node.fDisconnect);

    auto last_inv = v2_handler->GetLastFallbackInv();
    BOOST_REQUIRE(last_inv.has_value());
    BOOST_CHECK_EQUAL(last_inv->type, uint32_t(MSG_CMPCT_BLOCK));
    BOOST_CHECK_EQUAL(last_inv->hash, fallback_block->GetHash());

    {
        LOCK(peer_node.cs_vSend);
        BOOST_CHECK(!peer_node.vSendMsg.empty());
        peer_node.vSendMsg.clear();
    }

    // 2. Fast-path O(1) reconstruction: prepare a valid V2 block on top of
    // ActiveTip(), send only SealedHeader (header + coinbase_tx), and
    // verify the chain tip advances by 1 without any getdata round trip.
    int height_before = 0;
    {
        LOCK(cs_main);
        height_before = m_node.chainman->ActiveChain().Height();
    }

    std::shared_ptr<CBlock> valid_block =
        PrepareBlock(config, m_node, CScript() << OP_TRUE);
    while (!CheckProofOfWork(valid_block->GetHash(), valid_block->nBits,
                             config.GetChainParams().GetConsensus())) {
        ++valid_block->nNonce;
    }

    SealedHeader valid_sealed(*valid_block);
    DataStream valid_stream{};
    valid_stream << valid_sealed;
    peerman->ProcessMessage(config, peer_node, NetMsgType::SEALEDHEADER,
                            valid_stream, 2000us, interrupt);

    const auto stats_after_hit = v2_handler->GetStats();
    BOOST_CHECK_EQUAL(stats_after_hit.sealedheader_received, 2U);
    BOOST_CHECK_EQUAL(stats_after_hit.sealedheader_reconstructed, 1U);
    BOOST_CHECK_EQUAL(stats_after_hit.sealedheader_fallback_getdata, 1U);
    // The metrics count the same outcomes
    BOOST_CHECK_EQUAL(
        metrics.m.sealed_headers.Value(size_t(SealedHeaderOutcome::FALLBACK)),
        1U);
    BOOST_CHECK_EQUAL(
        metrics.m.sealed_headers.Value(size_t(SealedHeaderOutcome::REBUILT)),
        1U);
    BOOST_CHECK_EQUAL(
        metrics.m.sealed_headers.Value(size_t(SealedHeaderOutcome::INVALID)),
        0U);

    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveChain().Height(),
                          height_before + 1);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(),
                          valid_block->GetHash());
    }

    // A requested compact header must be served through the public GETDATA path.
    {
        LOCK(peer_node.cs_vSend);
        peer_node.vSendMsg.clear();
    }
    BOOST_REQUIRE(!peer_node.fPauseSend);
    DataStream request{};
    request << std::vector<CInv>{CInv(MSG_SEALED_HEADER, valid_block->GetHash())};
    peerman->ProcessMessage(config, peer_node, NetMsgType::GETDATA,
                            request, 3000us, interrupt);
    size_t served_headers = 0;
    {
        V1TransportDeserializer decoder(config, peer_node.GetId());
        LOCK(peer_node.cs_vSend);
        for (const auto &chunk : peer_node.vSendMsg) {
            Span<const uint8_t> bytes{chunk};
            while (!bytes.empty()) {
                BOOST_REQUIRE_GE(decoder.Read(config, bytes), 0);
                if (decoder.Complete()) {
                    bool reject = false;
                    auto message = decoder.GetMessage(0us, reject);
                    BOOST_CHECK(!reject);
                    if (message.m_type == NetMsgType::SEALEDHEADER) {
                        SealedHeader served;
                        message.m_recv >> served;
                        BOOST_CHECK_EQUAL(served.header.GetHash(), valid_block->GetHash());
                        ++served_headers;
                    }
                }
            }
        }
    }
    BOOST_CHECK_EQUAL(served_headers, 1U);

    peerman->FinalizeNode(config, peer_node);
}

BOOST_AUTO_TEST_CASE(merklix_reconciliation_all_scopes_and_limits) {
    ScopedNodeMetrics metrics;
    LOCK(NetEventsInterface::g_msgproc_mutex);

    const Config &config = m_node.chainman->GetConfig();
    auto connman = std::make_unique<ConnmanTestMsg>(config, 0x2448, 0x2448,
                                                    *m_node.addrman);
    auto peerman =
        PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman,
                          *m_node.mempool, /*avalanche=*/nullptr, {});

    CConnman::Options options;
    options.m_msgproc = {peerman.get()};
    connman->Init(options);

    CAddress addr(MakeTestIp(0xa0b0c020), NODE_NONE);
    CNode peer_node(/*id=*/202, /*sock=*/nullptr, addr,
                    /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                    /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
                    ConnectionType::OUTBOUND_FULL_RELAY,
                    /*inbound_onion=*/false);
    connman->Handshake(
        /*node=*/peer_node,
        /*successfully_connected=*/true,
        /*remote_services=*/ServiceFlags(NODE_NETWORK),
        /*local_services=*/ServiceFlags(NODE_NETWORK),
        /*version=*/PROTOCOL_VERSION,
        /*relay_txs=*/true);

    V2PeerProtocolHandler *v2_handler = peerman->GetV2ProtocolHandler();
    BOOST_REQUIRE(v2_handler != nullptr);

    FastRandomContext rng(uint256{99});
    std::atomic<bool> interrupt{false};
    std::chrono::microseconds cur_time{10'000};

    // Test all 4 ReconScope values:
    // - 1-tx difference in bucket 0x2 (byte0 = 0x21) recovered directly from
    //   MerklixSyncSummary
    // - 2-tx difference in bucket 0x5, sub-bucket 0x9 (byte0 = 0x59) recovered
    //   via GF(2^64) MerklixSubBucketSummary
    CTransactionRef shared_tx = MakeNonCoinbaseTx(rng, 0x10);
    CTransactionRef single_missing_tx = MakeNonCoinbaseTx(rng, 0x21);
    CTransactionRef pair_missing_tx1 = MakeNonCoinbaseTx(rng, 0x59);
    CTransactionRef pair_missing_tx2 = MakeNonCoinbaseTx(rng, 0x59);
    BOOST_REQUIRE(shared_tx && single_missing_tx && pair_missing_tx1 &&
                  pair_missing_tx2);
    BOOST_REQUIRE(pair_missing_tx1->GetId() != pair_missing_tx2->GetId());

    // Fund UTXOs so HandleShortTx validates and accepts incoming transactions
    // through m_chainman.ProcessTransaction(tx, /*test_accept=*/false).
    FundTxInputInCoinsTip(*m_node.chainman, *shared_tx);
    FundTxInputInCoinsTip(*m_node.chainman, *single_missing_tx);
    FundTxInputInCoinsTip(*m_node.chainman, *pair_missing_tx1);
    FundTxInputInCoinsTip(*m_node.chainman, *pair_missing_tx2);

    V2PeerProtocolHandler remote_handler(*m_node.chainman, *m_node.mempool,
                                         *connman, *peerman);

    for (const ReconScope scope :
         {ReconScope::LIVE_MEMPOOL, ReconScope::EPOCH_BATCH,
          ReconScope::BLOCK_RECON, ReconScope::AVA_CONFLICT_SET}) {
        cur_time += 2'000'000us; // Advance past rate-limit window per scope
        const uint256 context_id = rng.rand256();
        const auto [salt_k0, salt_k1] =
            DeriveReconSipHashKey(scope, context_id, 0);

        v2_handler->SetScopedTransactions(scope, context_id, {shared_tx});
        remote_handler.SetScopedTransactions(
            scope, context_id,
            {shared_tx, single_missing_tx, pair_missing_tx1, pair_missing_tx2});

        // Step 1: Remote builds depth-4 MerklixSyncSummary and sends it to
        // local handler.
        MerklixSyncSummary remote_sync = remote_handler.BuildSyncSummary(
            scope, context_id, salt_k0, salt_k1);

        MerklixSyncDiffResult sync_diff =
            v2_handler->DiffSyncSummary(remote_sync);
        BOOST_CHECK(!sync_diff.root_matched);
        BOOST_CHECK(sync_diff.single_missing_short_ids.empty());
        BOOST_CHECK_EQUAL(sync_diff.mismatched_bucket_mask,
                          uint16_t((1U << 0x2) | (1U << 0x5)));

        DataStream sync_stream{};
        sync_stream << remote_sync;
        peerman->ProcessMessage(config, peer_node, NetMsgType::MERKLIXSYNC,
                                sync_stream, cur_time, interrupt);

        // Step 2: Remote receives GETMERKLIXBUCK for buckets 0x2/0x5 and builds
        // MerklixSubBucketSummary.
        MerklixBucketRequest buck_req;
        buck_req.scope = static_cast<uint8_t>(scope);
        buck_req.context_id = context_id;
        buck_req.salt_k0 = salt_k0;
        buck_req.salt_k1 = salt_k1;
        buck_req.bucket_mask = sync_diff.mismatched_bucket_mask;

        DataStream getbuck_stream{};
        getbuck_stream << buck_req;
        peerman->ProcessMessage(config, peer_node, NetMsgType::GETMERKLIXBUCK,
                                getbuck_stream, cur_time + 10us, interrupt);

        MerklixSubBucketSummary remote_sub =
            remote_handler.BuildSubBucketSummary(scope, context_id, salt_k0,
                                                 salt_k1, 0x5);
        MerklixSubBucketDiffResult sub_diff =
            v2_handler->DiffSubBucketSummary(remote_sub);
        BOOST_CHECK(sub_diff.unresolved_sub_buckets.empty());
        BOOST_REQUIRE_EQUAL(sub_diff.missing_short_ids.size(), 2U);

        DataStream buck_stream{};
        buck_stream << remote_sub;
        peerman->ProcessMessage(config, peer_node, NetMsgType::MERKLIXBUCK,
                                buck_stream, cur_time + 20us, interrupt);

        MerklixSubBucketSummary single_sub =
            remote_handler.BuildSubBucketSummary(scope, context_id, salt_k0,
                                                 salt_k1, 0x2);
        const auto single_diff{v2_handler->DiffSubBucketSummary(single_sub)};
        BOOST_CHECK(single_diff.unresolved_sub_buckets.empty());
        BOOST_REQUIRE_EQUAL(single_diff.missing_short_ids.size(), 1U);
        BOOST_CHECK_EQUAL(single_diff.missing_short_ids[0],
            ComputeMerklixShortId(salt_k0, salt_k1, single_missing_tx->GetId()));
        DataStream single_stream{};
        single_stream << single_sub;
        peerman->ProcessMessage(config, peer_node, NetMsgType::MERKLIXBUCK,
                                single_stream, cur_time + 21us, interrupt);

        // Step 3: Resolve all 3 missing short IDs via GETSHORTTX / SHORTTX
        std::vector<uint64_t> all_missing = single_diff.missing_short_ids;
        all_missing.insert(all_missing.end(),
                           sub_diff.missing_short_ids.begin(),
                           sub_diff.missing_short_ids.end());

        ShortTxRequest stx_req;
        stx_req.scope = static_cast<uint8_t>(scope);
        stx_req.context_id = context_id;
        stx_req.salt_k0 = salt_k0;
        stx_req.salt_k1 = salt_k1;
        stx_req.short_ids = all_missing;

        std::vector<CTransactionRef> resolved = remote_handler.ResolveShortIds(
            scope, context_id, salt_k0, salt_k1, all_missing);
        BOOST_REQUIRE_EQUAL(resolved.size(), 3U);

        ShortTxResponse stx_resp;
        stx_resp.scope = static_cast<uint8_t>(scope);
        stx_resp.context_id = context_id;
        stx_resp.txs = resolved;

        DataStream stx_stream{};
        stx_stream << stx_resp;
        peerman->ProcessMessage(config, peer_node, NetMsgType::SHORTTX,
                                stx_stream, cur_time + 30us, interrupt);

        // After applying SHORTTX, local and remote depth-4 summaries and
        // 256-bit candidate_root match identically!
        MerklixSyncDiffResult post_diff =
            v2_handler->DiffSyncSummary(remote_sync);
        BOOST_CHECK(post_diff.root_matched);
        BOOST_CHECK_EQUAL(post_diff.mismatched_bucket_mask, 0U);
        BOOST_CHECK(post_diff.single_missing_short_ids.empty());
    }

    // One summary and two bucket rounds per scope find differences. The
    // summary requests proof; the bucket rounds recover all three IDs.
    {
        auto &rounds{metrics.m.merklix_rounds};
        const std::array<size_t, 2> summary_diff{0, 1}, bucket_diff{1, 1},
            summary_match{0, 0}, bucket_match{1, 0};
        BOOST_CHECK_EQUAL(rounds.Value(rounds.SeriesIndex(summary_diff)), 4U);
        BOOST_CHECK_EQUAL(rounds.Value(rounds.SeriesIndex(bucket_diff)), 8U);
        BOOST_CHECK_EQUAL(rounds.Value(rounds.SeriesIndex(summary_match)), 0U);
        BOOST_CHECK_EQUAL(rounds.Value(rounds.SeriesIndex(bucket_match)), 0U);
        BOOST_CHECK_EQUAL(metrics.m.merklix_overflows.Value(), 0U);
        const std::string r{metrics.Render()};
        BOOST_CHECK(
            r.find("merklix_difference_size_sum{round=\"summary\"} 0\n") !=
            std::string::npos);
        BOOST_CHECK(r.find("merklix_difference_size_count{round=\"summary\"} "
                           "0\n") != std::string::npos);
        BOOST_CHECK(
            r.find("merklix_difference_size_sum{round=\"bucket\"} 12\n") !=
            std::string::npos);
    }

    // Malformed scope and oversized ShortTxRequest rejection:
    cur_time += 2'000'000us;
    const uint64_t malformed_before = v2_handler->GetStats().malformed_messages;
    {
        MerklixSyncSummary bad_scope_sync;
        bad_scope_sync.scope = 0x99; // invalid ReconScope
        DataStream ss{};
        ss << bad_scope_sync;
        peerman->ProcessMessage(config, peer_node, NetMsgType::MERKLIXSYNC, ss,
                                cur_time, interrupt);
    }
    {
        ShortTxRequest oversized_req;
        oversized_req.scope = static_cast<uint8_t>(ReconScope::LIVE_MEMPOOL);
        oversized_req.short_ids.resize(ShortTxRequest::MAX_SHORT_IDS + 1, 1ULL);
        DataStream ss{};
        ss << oversized_req;
        peerman->ProcessMessage(config, peer_node, NetMsgType::GETSHORTTX, ss,
                                cur_time + 1us, interrupt);
    }
    BOOST_CHECK_EQUAL(v2_handler->GetStats().malformed_messages,
                      malformed_before + 2);

    // Per-peer rate limit enforcement within a single 1s window:
    cur_time += 2'000'000us;
    const uint64_t rate_limited_before =
        v2_handler->GetStats().rate_limited_messages;
    const auto [live_k0, live_k1] =
        DeriveReconSipHashKey(ReconScope::LIVE_MEMPOOL, uint256{}, 0);
    for (size_t i = 0; i < V2PeerProtocolHandler::MAX_SYNC_MESSAGES_PER_WINDOW + 5;
         ++i) {
        MerklixSyncSummary sync;
        sync.scope = static_cast<uint8_t>(ReconScope::LIVE_MEMPOOL);
        sync.salt_k0 = live_k0;
        sync.salt_k1 = live_k1;
        DataStream ss{};
        ss << sync;
        peerman->ProcessMessage(config, peer_node, NetMsgType::MERKLIXSYNC, ss,
                                cur_time + std::chrono::microseconds(i),
                                interrupt);
    }
    BOOST_CHECK_EQUAL(v2_handler->GetStats().rate_limited_messages,
                      rate_limited_before + 5);

    peerman->FinalizeNode(config, peer_node);
}

BOOST_AUTO_TEST_CASE(adversarial_c1_d1_d2_hardening_gates) {
    LOCK(NetEventsInterface::g_msgproc_mutex);

    const Config &config = m_node.chainman->GetConfig();
    auto connman = std::make_unique<ConnmanTestMsg>(config, 0x466a, 0x466a,
                                                    *m_node.addrman);
    auto peerman =
        PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman,
                          *m_node.mempool, /*avalanche=*/nullptr, {});

    CConnman::Options options;
    options.m_msgproc = {peerman.get()};
    connman->Init(options);

    CAddress addr(MakeTestIp(0xa0b0c040), NODE_NONE);
    CNode peer_node(/*id=*/404, /*sock=*/nullptr, addr,
                    /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                    /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
                    ConnectionType::OUTBOUND_FULL_RELAY,
                    /*inbound_onion=*/false);
    connman->Handshake(
        /*node=*/peer_node,
        /*successfully_connected=*/true,
        /*remote_services=*/ServiceFlags(NODE_NETWORK),
        /*local_services=*/ServiceFlags(NODE_NETWORK),
        /*version=*/PROTOCOL_VERSION,
        /*relay_txs=*/true);

    V2PeerProtocolHandler *v2_handler = peerman->GetV2ProtocolHandler();
    BOOST_REQUIRE(v2_handler != nullptr);

    std::atomic<bool> interrupt{false};
    std::chrono::microseconds cur_time{100'000};

    // -------------------------------------------------------------------------
    // Defect C1 Gate 1: Oversized coinbase_tx (> 10,000 bytes) in sealedheader
    // must be rejected BEFORE AcceptBlockHeader, MatchCandidateOverlay, or
    // GETDATA(MSG_CMPCT_BLOCK).
    // -------------------------------------------------------------------------
    std::shared_ptr<CBlock> base_block =
        PrepareBlock(config, m_node, CScript() << OP_TRUE);
    {
        CMutableTransaction oversized_cb(*base_block->vtx[0]);
        oversized_cb.vout.push_back(CTxOut(
            0 * SATOSHI,
            CScript() << OP_RETURN
                      << std::vector<uint8_t>(
                             V2PeerProtocolHandler::MAX_SEALEDHEADER_COINBASE_BYTES +
                                 128,
                             0xaa)));
        SealedHeader oversized_sealed;
        oversized_sealed.header = base_block->GetBlockHeader();
        oversized_sealed.coinbase_tx =
            MakeTransactionRef(std::move(oversized_cb));
        BOOST_REQUIRE_GT(::GetSerializeSize(*oversized_sealed.coinbase_tx),
                         V2PeerProtocolHandler::MAX_SEALEDHEADER_COINBASE_BYTES);

        {
            LOCK(peer_node.cs_vSend);
            peer_node.vSendMsg.clear();
        }
        DataStream ss{};
        ss << oversized_sealed;
        peerman->ProcessMessage(config, peer_node, NetMsgType::SEALEDHEADER, ss,
                                cur_time, interrupt);

        const auto stats = v2_handler->GetStats();
        BOOST_CHECK_EQUAL(stats.sealedheader_received, 1U);
        BOOST_CHECK_EQUAL(stats.sealedheader_rejected, 1U);
        BOOST_CHECK_EQUAL(stats.sealedheader_reconstructed, 0U);
        BOOST_CHECK_EQUAL(stats.sealedheader_fallback_getdata, 0U);
        BOOST_CHECK(!v2_handler->GetLastFallbackInv().has_value());
        {
            LOCK(peer_node.cs_vSend);
            BOOST_CHECK(peer_node.vSendMsg.empty());
        }
    }

    // -------------------------------------------------------------------------
    // Defect C1 Gate 2: Zero-PoW / invalid header sealedheader must be rejected by
    // AcceptBlockHeader BEFORE MatchCandidateOverlay or GETDATA(MSG_CMPCT_BLOCK).
    // -------------------------------------------------------------------------
    {
        SealedHeader bad_pow_sealed(*base_block);
        // Set impossible difficulty target so CheckProofOfWork fails inside
        // AcceptBlockHeader.
        bad_pow_sealed.header.nBits = 0x03000001U;

        DataStream ss{};
        ss << bad_pow_sealed;
        peerman->ProcessMessage(config, peer_node, NetMsgType::SEALEDHEADER, ss,
                                cur_time + 100us, interrupt);

        const auto stats = v2_handler->GetStats();
        BOOST_CHECK_EQUAL(stats.sealedheader_received, 2U);
        BOOST_CHECK_EQUAL(stats.sealedheader_rejected, 2U);
        BOOST_CHECK_EQUAL(stats.sealedheader_reconstructed, 0U);
        BOOST_CHECK_EQUAL(stats.sealedheader_fallback_getdata, 0U);
        BOOST_CHECK(!v2_handler->GetLastFallbackInv().has_value());
        {
            LOCK(peer_node.cs_vSend);
            BOOST_CHECK(peer_node.vSendMsg.empty());
        }
    }

    // -------------------------------------------------------------------------
    // Defect C1 Gate 3: O(1) CandidateOverlayEntry subtree_a_root matching
    // reconstructs a valid V2 block whose transactions live in the registered
    // candidate overlay (not in the mempool).
    // -------------------------------------------------------------------------
    FastRandomContext rng(uint256{44});
    CTransactionRef overlay_tx = MakeNonCoinbaseTx(rng, 0x34);
    BOOST_REQUIRE(overlay_tx != nullptr);
    FundTxInputInCoinsTip(*m_node.chainman, *overlay_tx);

    std::shared_ptr<CBlock> overlay_block =
        PrepareBlock(config, m_node, CScript() << OP_TRUE);
    overlay_block->vtx.push_back(overlay_tx);
    {
        LOCK(cs_main);
        overlay_block->hashMerkleRoot = BlockMerkleRoot(*overlay_block);
    }
    while (!CheckProofOfWork(overlay_block->GetHash(), overlay_block->nBits,
                             config.GetChainParams().GetConsensus())) {
        ++overlay_block->nNonce;
    }

    uint256 overlay_null_root;
    std::vector<uint256> overlay_cb_branch;
    lotus::v2::ComputeBlockCoinbaseMerkleBranch(
        *overlay_block, overlay_null_root, overlay_cb_branch);

    // Register candidate overlay & scoped transactions, test explicit
    // MatchCandidateOverlay (including std::binary_search comparator lambda),
    // then clear candidate overlay and test O(1) reconstruction directly from
    // m_mempool.GetOverlayManager() frozen epoch layer!
    v2_handler->RegisterCandidateOverlay(overlay_block->hashPrevBlock,
                                         {overlay_tx});
    v2_handler->RegisterCandidateOverlay(
        BlockHash(overlay_block->hashMerkleRoot), {overlay_tx});
    v2_handler->SetScopedTransactions(ReconScope::BLOCK_RECON,
                                      overlay_block->hashPrevBlock,
                                      {overlay_tx});
    v2_handler->SetScopedTransactions(ReconScope::BLOCK_RECON,
                                      overlay_block->GetHash(), {overlay_tx});
    {
        auto matched_explicit = v2_handler->MatchCandidateOverlay(
            *overlay_block, overlay_block->vtx[0], overlay_cb_branch);
        BOOST_REQUIRE(matched_explicit != nullptr);
        BOOST_CHECK_EQUAL(matched_explicit->vtx.size(), 2U);
        BOOST_CHECK(!matched_explicit->m_checked_merkle_root);
        // A reconstructed block must still run the duplicate-tail mutation
        // check: [coinbase,a,b] and [coinbase,a,b,b] share a Merkle root.
        auto mutation = *matched_explicit;
        auto tail = MakeNonCoinbaseTx(rng, 0x35);
        mutation.vtx.push_back(tail);
        mutation.hashMerkleRoot = BlockMerkleRoot(mutation);
        mutation.vtx.push_back(tail);
        BOOST_CHECK(mutation.hashMerkleRoot == BlockMerkleRoot(mutation));
        BlockValidationState mutation_state;
        BOOST_CHECK(!CheckBlock(mutation, mutation_state,
            config.GetChainParams().GetConsensus(),
            BlockValidationOptions(config).withCheckPoW(false)));
        BOOST_CHECK_EQUAL(mutation_state.GetRejectReason(), "bad-txns-duplicate");

        // Merkle root mismatch in explicit candidate loop
        CBlockHeader bad_mr_hdr = *overlay_block;
        bad_mr_hdr.hashMerkleRoot.begin()[0] ^= 0xFF;
        BOOST_CHECK(v2_handler->MatchCandidateOverlay(
                        bad_mr_hdr, overlay_block->vtx[0], overlay_cb_branch) ==
                    nullptr);

        // Tampered coinbase Merkle branch in explicit candidate loop
        std::vector<uint256> bad_branch = overlay_cb_branch;
        bad_branch[0].begin()[0] ^= 0xFF;
        BOOST_CHECK(v2_handler->MatchCandidateOverlay(
                        *overlay_block, overlay_block->vtx[0], bad_branch) ==
                    nullptr);

        // Coinbase txid collision with candidate tx
        CBlock dup_cb_blk = *overlay_block;
        dup_cb_blk.vtx[0] = overlay_tx;
        dup_cb_blk.hashMerkleRoot = BlockMerkleRoot(dup_cb_blk);
        BOOST_CHECK(v2_handler->MatchCandidateOverlay(
                        dup_cb_blk, overlay_tx, overlay_cb_branch) == nullptr);
    }
    v2_handler->ClearCandidateOverlays();
    v2_handler->SetScopedTransactions(ReconScope::BLOCK_RECON,
                                      overlay_block->hashPrevBlock, {});
    v2_handler->SetScopedTransactions(ReconScope::BLOCK_RECON,
                                      overlay_block->GetHash(), {});
    {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, m_node.mempool->cs);
        const CBlockIndex *tip = m_node.chainman->ActiveTip();
        m_node.mempool->SyncMerklixOverlayToTip(
            overlay_block->hashPrevBlock, uint32_t(tip->nHeight + 2),
            uint64_t(tip->GetMedianTimePast()));
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(overlay_tx));
    }
    {
        BOOST_CHECK(v2_handler->MatchCandidateOverlay(
                        *overlay_block, overlay_block->vtx[0],
                        overlay_cb_branch) != nullptr);
        CBlockHeader bad_mr_hdr = *overlay_block;
        bad_mr_hdr.hashMerkleRoot.begin()[0] ^= 0xFF;
        BOOST_CHECK(v2_handler->MatchCandidateOverlay(
                        bad_mr_hdr, overlay_block->vtx[0], overlay_cb_branch) ==
                    nullptr);
    }
    {
        LOCK2(cs_main, m_node.mempool->cs);
        const CBlockIndex *tip = m_node.chainman->ActiveTip();
        m_node.mempool->SyncMerklixOverlayToTip(
            overlay_block->hashPrevBlock, uint32_t(tip->nHeight + 1),
            uint64_t(tip->GetMedianTimePast()));
        m_node.mempool->FreezeEpochBatch();
    }
    {
        CBlockHeader bad_mr_hdr = *overlay_block;
        bad_mr_hdr.hashMerkleRoot.begin()[0] ^= 0xFF;
        BOOST_CHECK(v2_handler->MatchCandidateOverlay(
                        bad_mr_hdr, overlay_block->vtx[0], overlay_cb_branch) ==
                    nullptr);
    }

    SealedHeader overlay_sealed(*overlay_block);
    DataStream overlay_ss{};
    overlay_ss << overlay_sealed;
    peerman->ProcessMessage(config, peer_node, NetMsgType::SEALEDHEADER,
                            overlay_ss, cur_time + 200us, interrupt);

    {
        const auto stats = v2_handler->GetStats();
        BOOST_CHECK_EQUAL(stats.sealedheader_received, 3U);
        BOOST_CHECK_EQUAL(stats.sealedheader_rejected, 2U);
        BOOST_CHECK_EQUAL(stats.sealedheader_reconstructed, 1U);
        BOOST_CHECK_EQUAL(stats.sealedheader_fallback_getdata, 0U);
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(),
                          overlay_block->GetHash());
    }

    // -------------------------------------------------------------------------
    // Defect D1: Reject peer-chosen SipHash salt not derived via
    // DeriveReconSipHashKey, and require 256-bit candidate_root equality in
    // DiffSyncSummary before declaring convergence.
    // -------------------------------------------------------------------------
    cur_time += 2'000'000us;
    const uint64_t malformed_before = v2_handler->GetStats().malformed_messages;
    {
        MerklixSyncSummary forged_salt_sync;
        forged_salt_sync.scope = static_cast<uint8_t>(ReconScope::BLOCK_RECON);
        forged_salt_sync.context_id = rng.rand256();
        forged_salt_sync.salt_k0 = 0xdeadbeefcafebabeULL;
        forged_salt_sync.salt_k1 = 0x0123456789abcdefULL;
        DataStream ss{};
        ss << forged_salt_sync;
        peerman->ProcessMessage(config, peer_node, NetMsgType::MERKLIXSYNC, ss,
                                cur_time, interrupt);
        BOOST_CHECK_EQUAL(v2_handler->GetStats().malformed_messages,
                          malformed_before + 1);
    }
    {
        // Even if all 16 64-bit bucket fingerprints match, a different 256-bit
        // candidate_root must prevent false convergence.
        const uint256 ctx_id = rng.rand256();
        const auto [k0, k1] =
            DeriveReconSipHashKey(ReconScope::BLOCK_RECON, ctx_id, 0);
        v2_handler->SetScopedTransactions(ReconScope::BLOCK_RECON, ctx_id,
                                          {overlay_tx});
        MerklixSyncSummary summary_with_forged_root =
            v2_handler->BuildSyncSummary(ReconScope::BLOCK_RECON, ctx_id, k0,
                                         k1);
        summary_with_forged_root.candidate_root = rng.rand256();
        MerklixSyncDiffResult diff =
            v2_handler->DiffSyncSummary(summary_with_forged_root);
        BOOST_CHECK(!diff.root_matched);
        BOOST_CHECK_EQUAL(diff.mismatched_bucket_mask, 0xFFFFU);
    }

    // -------------------------------------------------------------------------
    // Defect D2: Invalid transactions in SHORTTX must be rejected by
    // ProcessTransaction and must NEVER pollute m_scoped_txs.
    // -------------------------------------------------------------------------
    cur_time += 2'000'000us;
    {
        const uint256 recon_ctx = rng.rand256();
        v2_handler->SetScopedTransactions(ReconScope::BLOCK_RECON, recon_ctx,
                                          {});

        // Create an invalid transaction spending a non-existent UTXO (not in
        // CoinsTip or mempool).
        CTransactionRef invalid_tx = MakeNonCoinbaseTx(rng, 0x77);
        BOOST_REQUIRE(invalid_tx != nullptr);

        const auto [bad_k0, bad_k1] =
            DeriveReconSipHashKey(ReconScope::BLOCK_RECON, recon_ctx, 0);
        v2_handler->RecordPendingShortTxRequest(
            peer_node.GetId(), ReconScope::BLOCK_RECON, recon_ctx, bad_k0,
            bad_k1,
            {ComputeMerklixShortId(bad_k0, bad_k1, invalid_tx->GetId())});

        ShortTxResponse bad_shorttx;
        bad_shorttx.scope = static_cast<uint8_t>(ReconScope::BLOCK_RECON);
        bad_shorttx.context_id = recon_ctx;
        bad_shorttx.txs = {invalid_tx};

        DataStream ss{};
        ss << bad_shorttx;
        peerman->ProcessMessage(config, peer_node, NetMsgType::SHORTTX, ss,
                                cur_time, interrupt);

        // m_scoped_txs[BLOCK_RECON, recon_ctx] must remain completely empty!
        const auto scoped_after_bad = v2_handler->GetScopedTransactions(
            ReconScope::BLOCK_RECON, recon_ctx);
        BOOST_CHECK(scoped_after_bad.empty());
    }

    // -------------------------------------------------------------------------
    // Additional protocol edge-case coverage: zero-salt defaults, bounded
    // m_scoped_txs eviction, DiffSubBucketSummary overflow/mismatch branches,
    // and malformed wire frames across all V2 message types.
    // -------------------------------------------------------------------------
    cur_time += 2'000'000us;
    {
        // Bounded m_scoped_txs eviction (MAX_TRACKED_RECON_SCOPES == 64)
        for (size_t i = 0; i < V2PeerProtocolHandler::MAX_TRACKED_RECON_SCOPES + 2;
             ++i) {
            v2_handler->SetScopedTransactions(ReconScope::BLOCK_RECON,
                                              rng.rand256(), {overlay_tx});
        }
        BOOST_CHECK(
            v2_handler
                ->GetScopedTransactions(ReconScope::BLOCK_RECON, rng.rand256())
                .empty());

        const uint256 z_ctx = rng.rand256();
        v2_handler->SetScopedTransactions(ReconScope::BLOCK_RECON, z_ctx,
                                          {overlay_tx});
        MerklixSyncSummary z_sync =
            v2_handler->BuildSyncSummary(ReconScope::BLOCK_RECON, z_ctx, 0, 0);
        z_sync.salt_k0 = 0;
        z_sync.salt_k1 = 0;
        z_sync.candidate_root = rng.rand256();
        (void)v2_handler->DiffSyncSummary(z_sync);

        MerklixSyncSummary invalid_scope_sync = z_sync;
        invalid_scope_sync.scope = 0x99;
        BOOST_CHECK(!v2_handler->DiffSyncSummary(invalid_scope_sync).root_matched);

        const uint8_t b_idx = GetMerklixBucketIndex(overlay_tx->GetId());
        MerklixSubBucketSummary z_sub = v2_handler->BuildSubBucketSummary(
            ReconScope::BLOCK_RECON, z_ctx, 0, 0, b_idx);
        z_sub.salt_k0 = 0;
        z_sub.salt_k1 = 0;
        // Inject unrecoverable syndrome in sub_bucket 0 and count mismatch in sub_bucket 1
        z_sub.sub_buckets[0].s1 = 0;
        z_sub.sub_buckets[0].s3 = 1;
        z_sub.sub_buckets[1].s1 ^= 1ULL;
        z_sub.sub_buckets[1].s3 ^= 1ULL;
        z_sub.sub_buckets[1].s5 ^= 1ULL;
        z_sub.sub_buckets[1].count += 10;
        const auto sub_diff = v2_handler->DiffSubBucketSummary(z_sub);
        BOOST_CHECK(!sub_diff.unresolved_sub_buckets.empty());

        MerklixSubBucketSummary bad_sub = z_sub;
        bad_sub.parent_bucket = 16;
        BOOST_CHECK(
            v2_handler->DiffSubBucketSummary(bad_sub).missing_short_ids.empty());

        BOOST_CHECK(
            v2_handler
                ->ResolveShortIds(ReconScope::BLOCK_RECON, z_ctx, 0, 0, {})
                .empty());
        const auto [zk0, zk1] =
            DeriveReconSipHashKey(ReconScope::BLOCK_RECON, z_ctx, 0);
        const uint64_t z_sid =
            ComputeMerklixShortId(zk0, zk1, overlay_tx->GetId());
        BOOST_CHECK_EQUAL(
            v2_handler
                ->ResolveShortIds(ReconScope::BLOCK_RECON, z_ctx, 0, 0, {z_sid})
                .size(),
            1U);

        // Truncated streams & malformed fields across SEALEDHEADER, MERKLIXSYNC,
        // GETMERKLIXBUCK, MERKLIXBUCK, GETSHORTTX, SHORTTX:
        for (const auto *msg_type :
             {NetMsgType::SEALEDHEADER, NetMsgType::MERKLIXSYNC,
              NetMsgType::GETMERKLIXBUCK, NetMsgType::MERKLIXBUCK,
              NetMsgType::GETSHORTTX, NetMsgType::SHORTTX}) {
            DataStream trunc{};
            trunc << uint8_t{0x01};
            peerman->ProcessMessage(config, peer_node, msg_type, trunc,
                                    cur_time, interrupt);
        }

        // Invalid SealedHeader (non-coinbase tx)
        SealedHeader invalid_cb_sealed;
        invalid_cb_sealed.header = overlay_block->GetBlockHeader();
        invalid_cb_sealed.coinbase_tx = overlay_tx;
        {
            DataStream ss{};
            ss << invalid_cb_sealed;
            peerman->ProcessMessage(config, peer_node, NetMsgType::SEALEDHEADER, ss,
                                    cur_time, interrupt);
        }

        // MERKLIXSYNC with zero salt (derives default salt)
        {
            MerklixSyncSummary zero_salt_sync = z_sync;
            zero_salt_sync.salt_k0 = 0;
            zero_salt_sync.salt_k1 = 0;
            DataStream ss{};
            ss << zero_salt_sync;
            peerman->ProcessMessage(config, peer_node, NetMsgType::MERKLIXSYNC,
                                    ss, cur_time, interrupt);
        }

        // GETMERKLIXBUCK: bucket_mask == 0, invalid salt, and zero salt
        {
            MerklixBucketRequest req;
            req.scope = static_cast<uint8_t>(ReconScope::BLOCK_RECON);
            req.context_id = z_ctx;
            req.bucket_mask = 0;
            DataStream ss1{};
            ss1 << req;
            peerman->ProcessMessage(config, peer_node,
                                    NetMsgType::GETMERKLIXBUCK, ss1, cur_time,
                                    interrupt);

            req.bucket_mask = 1;
            req.salt_k0 = 12345ULL;
            DataStream ss2{};
            ss2 << req;
            peerman->ProcessMessage(config, peer_node,
                                    NetMsgType::GETMERKLIXBUCK, ss2, cur_time,
                                    interrupt);

            req.salt_k0 = 0;
            req.salt_k1 = 0;
            DataStream ss3{};
            ss3 << req;
            peerman->ProcessMessage(config, peer_node,
                                    NetMsgType::GETMERKLIXBUCK, ss3, cur_time,
                                    interrupt);
        }

        // MERKLIXBUCK: parent_bucket >= 16, invalid salt, and zero salt
        {
            MerklixSubBucketSummary sub = z_sub;
            sub.parent_bucket = 16;
            DataStream ss1{};
            ss1 << sub;
            peerman->ProcessMessage(config, peer_node, NetMsgType::MERKLIXBUCK,
                                    ss1, cur_time, interrupt);

            sub.parent_bucket = b_idx;
            sub.salt_k0 = 12345ULL;
            DataStream ss2{};
            ss2 << sub;
            peerman->ProcessMessage(config, peer_node, NetMsgType::MERKLIXBUCK,
                                    ss2, cur_time, interrupt);

            sub.salt_k0 = 0;
            sub.salt_k1 = 0;
            DataStream ss3{};
            ss3 << sub;
            peerman->ProcessMessage(config, peer_node, NetMsgType::MERKLIXBUCK,
                                    ss3, cur_time, interrupt);
        }

        // GETSHORTTX: invalid salt and zero salt resolving z_sid
        {
            ShortTxRequest sreq;
            sreq.scope = static_cast<uint8_t>(ReconScope::BLOCK_RECON);
            sreq.context_id = z_ctx;
            sreq.short_ids = {z_sid};
            sreq.salt_k0 = 12345ULL;
            DataStream ss1{};
            ss1 << sreq;
            peerman->ProcessMessage(config, peer_node, NetMsgType::GETSHORTTX,
                                    ss1, cur_time, interrupt);

            sreq.salt_k0 = 0;
            sreq.salt_k1 = 0;
            DataStream ss2{};
            ss2 << sreq;
            peerman->ProcessMessage(config, peer_node, NetMsgType::GETSHORTTX,
                                    ss2, cur_time, interrupt);
        }

        // SHORTTX: empty txs and coinbase tx rejection
        {
            ShortTxResponse sresp;
            sresp.scope = static_cast<uint8_t>(ReconScope::BLOCK_RECON);
            sresp.context_id = z_ctx;
            DataStream ss1{};
            ss1 << sresp;
            peerman->ProcessMessage(config, peer_node, NetMsgType::SHORTTX, ss1,
                                    cur_time, interrupt);

            sresp.txs = {overlay_block->vtx[0]};
            DataStream ss2{};
            ss2 << sresp;
            peerman->ProcessMessage(config, peer_node, NetMsgType::SHORTTX, ss2,
                                    cur_time, interrupt);
        }

        // GF64Inv(0), GF64SolveQuadratic(0, y) and unsolvable trace-1 quadratic
        BOOST_CHECK_EQUAL(GF64Inv(0ULL), 0ULL);
        uint64_t y_zero = 42ULL;
        BOOST_CHECK(GF64SolveQuadratic(0ULL, y_zero));
        BOOST_CHECK_EQUAL(y_zero, 0ULL);
        for (int b = 0; b < 64; ++b) {
            (void)RecoverGF64Syndromes(1ULL, (1ULL << b) ^ 1ULL);
        }

        // RegisterCandidateOverlay eviction at MAX_OVERLAYS_PER_PREV (16)
        const BlockHash cap_prev(rng.rand256());
        for (size_t i = 0; i < 18; ++i) {
            v2_handler->RegisterCandidateOverlay(cap_prev, {overlay_tx});
        }

        // DiffSubBucketSummary 2-element symmetric diff with 1 local + 1 remote tx
        const uint8_t sb_idx = GetMerklixSubBucketIndex(overlay_tx->GetId());
        MerklixSubBucketSummary sym2_sub = v2_handler->BuildSubBucketSummary(
            ReconScope::BLOCK_RECON, z_ctx, zk0, zk1, b_idx);
        const uint64_t remote_only_sid = z_sid ^ 7ULL;
        sym2_sub.sub_buckets[sb_idx].count = 1;
        sym2_sub.sub_buckets[sb_idx].s1 = remote_only_sid;
        sym2_sub.sub_buckets[sb_idx].s3 = GF64Cube(remote_only_sid);
        sym2_sub.sub_buckets[sb_idx].s5 = GF64Pow5(remote_only_sid);
        const auto sym2_diff = v2_handler->DiffSubBucketSummary(sym2_sub);
        BOOST_CHECK_EQUAL(sym2_diff.missing_short_ids.size(), 1U);
        BOOST_CHECK_EQUAL(sym2_diff.missing_short_ids[0], remote_only_sid);

        // SetScopedTransactions cap at MAX_SCOPED_TXS (4096)
        std::vector<CTransactionRef> many_txs;
        many_txs.reserve(V2PeerProtocolHandler::MAX_SCOPED_TXS + 2);
        CMutableTransaction base_mtx(*overlay_tx);
        for (size_t i = 0; i < V2PeerProtocolHandler::MAX_SCOPED_TXS + 2; ++i) {
            base_mtx.nLockTime = static_cast<uint32_t>(i + 1);
            many_txs.push_back(MakeTransactionRef(base_mtx));
        }
        const uint256 cap_ctx = rng.rand256();
        v2_handler->SetScopedTransactions(ReconScope::BLOCK_RECON, cap_ctx,
                                          std::move(many_txs));
        BOOST_CHECK_EQUAL(
            v2_handler->GetScopedTransactions(ReconScope::BLOCK_RECON, cap_ctx)
                .size(),
            V2PeerProtocolHandler::MAX_SCOPED_TXS);

        // Rate-limit exhaustion across GETMERKLIXBUCK, MERKLIXBUCK, GETSHORTTX, SHORTTX
        cur_time += 5'000'000us;
        for (size_t i = 0;
             i < V2PeerProtocolHandler::MAX_SYNC_MESSAGES_PER_WINDOW + 1; ++i) {
            DataStream trunc{};
            trunc << uint8_t{0x01};
            peerman->ProcessMessage(config, peer_node, NetMsgType::MERKLIXSYNC,
                                    trunc, cur_time, interrupt);
        }
        for (const auto *msg_type :
             {NetMsgType::GETMERKLIXBUCK, NetMsgType::MERKLIXBUCK,
              NetMsgType::GETSHORTTX, NetMsgType::SHORTTX}) {
            DataStream trunc{};
            trunc << uint8_t{0x01};
            peerman->ProcessMessage(config, peer_node, msg_type, trunc,
                                    cur_time, interrupt);
        }
    }

    peerman->FinalizeNode(config, peer_node);
}

BOOST_AUTO_TEST_CASE(
    merklix_s5_checksum_and_deep_sub_bucket_overflow_bisection) {
    LOCK(NetEventsInterface::g_msgproc_mutex);

    const Config &config = m_node.chainman->GetConfig();
    auto connman = std::make_unique<ConnmanTestMsg>(config, 0x466a, 0x466a,
                                                    *m_node.addrman);
    auto peerman =
        PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman,
                          *m_node.mempool, /*avalanche=*/nullptr, {});

    CConnman::Options options;
    options.m_msgproc = {peerman.get()};
    connman->Init(options);

    CAddress addr(MakeTestIp(0xa0b0c040), NODE_NONE);
    CNode peer_node(/*id=*/404, /*sock=*/nullptr, addr,
                    /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                    /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
                    ConnectionType::OUTBOUND_FULL_RELAY,
                    /*inbound_onion=*/false);
    connman->Handshake(
        /*node=*/peer_node,
        /*successfully_connected=*/true,
        /*remote_services=*/ServiceFlags(NODE_NETWORK),
        /*local_services=*/ServiceFlags(NODE_NETWORK),
        /*version=*/PROTOCOL_VERSION,
        /*relay_txs=*/true);

    V2PeerProtocolHandler *local_handler = peerman->GetV2ProtocolHandler();
    BOOST_REQUIRE(local_handler != nullptr);
    V2PeerProtocolHandler remote_handler(*m_node.chainman, *m_node.mempool,
                                         *connman, *peerman);

    FastRandomContext rng(uint256{0x77});
    std::atomic<bool> interrupt{false};
    std::chrono::microseconds cur_time{10'000'000};

    // =========================================================================
    // 1. Sub-bucket with 3 missing + 1 extra transaction (|delta_count| = 2,
    //    d = 4) where Tr(c) == 0:
    //    Verify that without s5 the 2-syndrome solver would find 2 bogus roots,
    //    whereas with s5 = XOR(x_i^5) both RecoverGF64Syndromes(s1, s3, s5) and
    //    DiffSubBucketSummary deterministically detect overflow (zero false
    //    positives!).
    // =========================================================================
    {
        const ReconScope scope = ReconScope::BLOCK_RECON;
        const uint256 ctx_id = rng.rand256();
        const auto [k0, k1] = DeriveReconSipHashKey(scope, ctx_id, 0);

        // Find 4 transactions in the exact same depth-8 sub-bucket 0x59 such
        // that the symmetric difference {tx0, tx1, tx2, tx3} has Tr(c) == 0
        // (i.e. 2-arg RecoverGF64Syndromes(ds1, ds3) returns 2 bogus roots).
        std::vector<CTransactionRef> pool_59;
        for (int i = 0; i < 24; ++i) {
            CTransactionRef tx = MakeNonCoinbaseTx(rng, 0x59);
            BOOST_REQUIRE(tx != nullptr);
            FundTxInputInCoinsTip(*m_node.chainman, *tx);
            pool_59.push_back(tx);
        }

        std::array<CTransactionRef, 4> chosen{};
        bool found_tr_zero_quad = false;
        for (size_t i = 0; i < pool_59.size() && !found_tr_zero_quad; ++i) {
            for (size_t j = i + 1; j < pool_59.size() && !found_tr_zero_quad;
                 ++j) {
                for (size_t k = j + 1;
                     k < pool_59.size() && !found_tr_zero_quad; ++k) {
                    for (size_t l = k + 1;
                         l < pool_59.size() && !found_tr_zero_quad; ++l) {
                        const uint64_t x0 = ComputeMerklixShortId(
                            k0, k1, pool_59[i]->GetId());
                        const uint64_t x1 = ComputeMerklixShortId(
                            k0, k1, pool_59[j]->GetId());
                        const uint64_t x2 = ComputeMerklixShortId(
                            k0, k1, pool_59[k]->GetId());
                        const uint64_t x3 = ComputeMerklixShortId(
                            k0, k1, pool_59[l]->GetId());
                        const uint64_t ds1 = x0 ^ x1 ^ x2 ^ x3;
                        const uint64_t ds3 = GF64Cube(x0) ^ GF64Cube(x1) ^
                                             GF64Cube(x2) ^ GF64Cube(x3);
                        const uint64_t ds5 = GF64Pow5(x0) ^ GF64Pow5(x1) ^
                                             GF64Pow5(x2) ^ GF64Pow5(x3);
                        auto bogus_deg2 = RecoverGF64Syndromes(ds1, ds3);
                        if (bogus_deg2.has_value() &&
                            bogus_deg2->size() == 2U) {
                            // 3-syndrome solver with s5 MUST reject these bogus
                            // roots!
                            BOOST_CHECK(
                                !RecoverGF64Syndromes(ds1, ds3, ds5).has_value());
                            chosen = {pool_59[i], pool_59[j], pool_59[k],
                                      pool_59[l]};
                            found_tr_zero_quad = true;
                        }
                    }
                }
            }
        }
        BOOST_REQUIRE(found_tr_zero_quad);

        // Local has 1 extra tx (chosen[3]); Remote has 3 missing txs
        // (chosen[0], chosen[1], chosen[2]). Count delta is +3 - 1 = +2.
        local_handler->SetScopedTransactions(scope, ctx_id, {chosen[3]});
        remote_handler.SetScopedTransactions(
            scope, ctx_id, {chosen[0], chosen[1], chosen[2]});

        const MerklixSubBucketSummary remote_sub8 =
            remote_handler.BuildSubBucketSummary(scope, ctx_id, k0, k1, 0x5);
        const MerklixSubBucketDiffResult diff8 =
            local_handler->DiffSubBucketSummary(remote_sub8);
        // Zero false-positive root decodes at depth 8, and sub-bucket 0x9 is
        // flagged as unresolved!
        BOOST_CHECK(diff8.missing_short_ids.empty());
        BOOST_REQUIRE_EQUAL(diff8.unresolved_sub_buckets.size(), 1U);
        BOOST_CHECK_EQUAL(diff8.unresolved_sub_buckets[0], 0x9);
    }

    // =========================================================================
    // 2. Deep Sub-Bucket Overflow Bisection (10 missing transactions in the
    //    exact same depth-8 sub-bucket 0x59):
    //    Verify that the full P2P message exchange (MERKLIXSYNC ->
    //    GETMERKLIXBUCK(depth 4) -> MERKLIXBUCK(depth 8) ->
    //    GETMERKLIXBUCK(depth 8) -> MERKLIXBUCK(depth 12) [-> depth 16] ->
    //    GETSHORTTX -> SHORTTX) recovers 100% of the 10 missing transactions!
    // =========================================================================
    {
        const ReconScope scope = ReconScope::BLOCK_RECON;
        const uint256 ctx_id = rng.rand256();
        const auto [k0, k1] = DeriveReconSipHashKey(scope, ctx_id, 0);

        CTransactionRef shared_tx = MakeNonCoinbaseTx(rng, 0x12);
        BOOST_REQUIRE(shared_tx != nullptr);
        FundTxInputInCoinsTip(*m_node.chainman, *shared_tx);

        std::vector<CTransactionRef> remote_txs{shared_tx};
        for (int i = 0; i < 10; ++i) {
            CTransactionRef tx = MakeNonCoinbaseTx(rng, 0x59);
            BOOST_REQUIRE(tx != nullptr);
            FundTxInputInCoinsTip(*m_node.chainman, *tx);
            remote_txs.push_back(tx);
        }

        local_handler->SetScopedTransactions(scope, ctx_id, {shared_tx});
        remote_handler.SetScopedTransactions(scope, ctx_id, remote_txs);

        {
            LOCK(peer_node.cs_vSend);
            peer_node.vSendMsg.clear();
        }

        // Start reconciliation: remote sends MERKLIXSYNC to local.
        const MerklixSyncSummary remote_sync =
            remote_handler.BuildSyncSummary(scope, ctx_id, k0, k1);
        {
            DataStream ss{};
            ss << remote_sync;
            peerman->ProcessMessage(config, peer_node, NetMsgType::MERKLIXSYNC,
                                    ss, cur_time, interrupt);
        }

        // Pump P2P messages between local_handler (via peerman/peer_node) and
        // remote_handler until all messages settle.
        V1TransportDeserializer local_to_remote(config, peer_node.GetId());
        size_t saw_depth12_buck = 0;
        for (int round = 0; round < 8; ++round) {
            cur_time += 2'000'000us;
            std::vector<std::vector<uint8_t>> outbound_chunks;
            {
                LOCK(peer_node.cs_vSend);
                if (peer_node.vSendMsg.empty()) {
                    break;
                }
                outbound_chunks.assign(peer_node.vSendMsg.begin(),
                                       peer_node.vSendMsg.end());
                peer_node.vSendMsg.clear();
            }

            for (const auto &chunk : outbound_chunks) {
                Span<const uint8_t> sp{chunk};
                while (!sp.empty()) {
                    const int ret = local_to_remote.Read(config, sp);
                    BOOST_REQUIRE_GE(ret, 0);
                    if (!local_to_remote.Complete()) {
                        continue;
                    }
                    bool reject = false;
                    CNetMessage msg =
                        local_to_remote.GetMessage(0us, reject);
                    BOOST_REQUIRE(!reject);

                    if (msg.m_type == NetMsgType::GETMERKLIXBUCK) {
                        MerklixBucketRequest req;
                        msg.m_recv >> req;
                        const uint8_t req_depth =
                            req.depth_bits == 0 ? 4 : req.depth_bits;
                        for (uint8_t b = 0; b < 16; ++b) {
                            if ((req.bucket_mask & (1U << b)) == 0) {
                                continue;
                            }
                            const uint8_t child_depth =
                                req_depth == 16
                                    ? 16
                                    : static_cast<uint8_t>(req_depth + 4);
                            const uint16_t child_prefix =
                                req_depth == 16
                                    ? req.parent_prefix
                                    : static_cast<uint16_t>(
                                          (req.parent_prefix << 4) | b);
                            if (child_depth == 12) {
                                ++saw_depth12_buck;
                            }
                            MerklixSubBucketSummary sub =
                                remote_handler.BuildSubBucketSummary(
                                    scope, req.context_id, req.salt_k0,
                                    req.salt_k1, child_prefix, child_depth);
                            DataStream sub_ss{};
                            sub_ss << sub;
                            peerman->ProcessMessage(config, peer_node,
                                                    NetMsgType::MERKLIXBUCK,
                                                    sub_ss, cur_time,
                                                    interrupt);
                            if (req_depth == 16) {
                                break;
                            }
                        }
                    } else if (msg.m_type == NetMsgType::GETSHORTTX) {
                        ShortTxRequest sreq;
                        msg.m_recv >> sreq;
                        std::vector<CTransactionRef> resolved =
                            remote_handler.ResolveShortIds(
                                scope, sreq.context_id, sreq.salt_k0,
                                sreq.salt_k1, sreq.short_ids);
                        BOOST_REQUIRE(!resolved.empty());
                        ShortTxResponse sresp;
                        sresp.scope = sreq.scope;
                        sresp.context_id = sreq.context_id;
                        sresp.txs = std::move(resolved);
                        DataStream sresp_ss{};
                        sresp_ss << sresp;
                        peerman->ProcessMessage(config, peer_node,
                                                NetMsgType::SHORTTX, sresp_ss,
                                                cur_time, interrupt);
                    }
                }
            }
        }

        BOOST_CHECK_GE(saw_depth12_buck, 1U);
        const auto reconciled_txs =
            local_handler->GetScopedTransactions(scope, ctx_id);
        BOOST_CHECK_EQUAL(reconciled_txs.size(), 11U);

        const MerklixSyncDiffResult final_diff =
            local_handler->DiffSyncSummary(remote_sync);
        BOOST_CHECK(final_diff.root_matched);
        BOOST_CHECK_EQUAL(final_diff.mismatched_bucket_mask, 0U);
        BOOST_CHECK(final_diff.single_missing_short_ids.empty());
    }

    peerman->FinalizeNode(config, peer_node);
}


BOOST_AUTO_TEST_CASE(ecash_rejects_v2_commitment_in_legacy_header) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    const Config &config = m_node.chainman->GetConfig();
    auto connman = std::make_unique<ConnmanTestMsg>(config, 91, 92,
                                                   *m_node.addrman);
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr,
        *m_node.chainman, *m_node.mempool, nullptr, {});
    auto *handler = peerman->GetV2ProtocolHandler();
    BOOST_REQUIRE(handler != nullptr);
    FastRandomContext rng(uint256{91});
    const auto tx = MakeNonCoinbaseTx(rng, 0x45);
    BOOST_REQUIRE(tx != nullptr);
    auto block = PrepareBlock(config, m_node, CScript() << OP_TRUE);
    block->vtx.push_back(tx);
    handler->RegisterCandidateOverlay(block->hashPrevBlock, {tx});
    const auto root = ComputeScopedMerklixRoot({tx});
    lotus::v2::Hash subtree{};
    std::copy(root.begin(), root.end(), subtree.begin());
    block->hashMerkleRoot = lotus::v2::net::ComputeV2TxRootFromSubtreeA(
        *block->vtx[0], subtree);
    BOOST_REQUIRE(block->hashMerkleRoot != BlockMerkleRoot(*block));
    BOOST_CHECK(handler->MatchCandidateOverlay(*block, block->vtx[0]) == nullptr);

    // Exercise the speculative-overlay path independently of explicit candidates.
    handler->ClearCandidateOverlays();
    {
        LOCK(m_node.mempool->cs);
        TestMemPoolEntryHelper entry;
        m_node.mempool->addUnchecked(entry.FromTx(tx));
        block->hashMerkleRoot = lotus::v2::net::ComputeV2TxRootFromSubtreeA(
            *block->vtx[0], m_node.mempool->GetMerklixOverlay()
                                .GetSpeculativeOverlay().GetSubtreeARoot());
    }
    BOOST_REQUIRE(block->hashMerkleRoot != BlockMerkleRoot(*block));
    BOOST_CHECK(handler->MatchCandidateOverlay(*block, block->vtx[0]) == nullptr);
}

BOOST_AUTO_TEST_CASE(outbound_inv_queue_suppression_window) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    MockRelayTick tick{std::chrono::milliseconds{7'000'001}};

    const Config &config = m_node.chainman->GetConfig();
    auto connman = std::make_unique<ConnmanTestMsg>(config, 0x3559, 0x3559,
                                                    *m_node.addrman);
    PeerManager::Options peer_opts;
    peer_opts.deterministic_rng = true;
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr,
                                     *m_node.chainman, *m_node.mempool,
                                     /*avalanche=*/nullptr, peer_opts);

    CConnman::Options options;
    options.m_msgproc = {peerman.get()};
    options.nSendBufferMaxSize = 1024 * 1024;
    connman->Init(options);

    const int64_t base_time = 1'700'000'000;
    SetMockTime(base_time);

    CAddress addr(MakeTestIp(0xa0b0c030), NODE_NONE);
    CNode peer_node(/*id=*/303, /*sock=*/nullptr, addr,
                    /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                    /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
                    ConnectionType::OUTBOUND_FULL_RELAY,
                    /*inbound_onion=*/false);
    connman->Handshake(
        /*node=*/peer_node,
        /*successfully_connected=*/true,
        /*remote_services=*/ServiceFlags(NODE_NETWORK),
        /*local_services=*/ServiceFlags(NODE_NETWORK),
        /*version=*/PROTOCOL_VERSION,
        /*relay_txs=*/true);

    // Prime the outbound inv send timer via an initial SendMessages call.
    BOOST_CHECK(peerman->SendMessages(config, &peer_node));
    {
        LOCK(peer_node.cs_vSend);
        peer_node.vSendMsg.clear();
    }

    // Add two transactions to the mempool and queue both for relay to peer_node.
    FastRandomContext rng(uint256{55});
    CTransactionRef tx_suppressed = MakeNonCoinbaseTx(rng, 0x31);
    CTransactionRef tx_unsuppressed = MakeNonCoinbaseTx(rng, 0x32);
    BOOST_REQUIRE(tx_suppressed && tx_unsuppressed);

    TestMemPoolEntryHelper entry;
    {
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->addUnchecked(entry.FromTx(tx_suppressed));
        m_node.mempool->addUnchecked(entry.FromTx(tx_unsuppressed));
    }

    peerman->RelayTransaction(tx_suppressed->GetId());
    peerman->RelayTransaction(tx_unsuppressed->GetId());

    // Simulate receiving a remote INV for tx_suppressed during the outbound
    // suppression window (before mocktime advances).
    {
        std::vector<CInv> remote_invs{CInv(MSG_TX, tx_suppressed->GetId())};
        DataStream inv_stream{};
        inv_stream << remote_invs;
        std::atomic<bool> interrupt{false};
        peerman->ProcessMessage(config, peer_node, NetMsgType::INV, inv_stream,
                                std::chrono::seconds{base_time}, interrupt);
    }

    // Advance to the next relay tick so the queue flushes; an INV received
    // before then still suppresses the announcement.
    SetMockTime(base_time + 5);
    tick.Set(std::chrono::milliseconds{7'000'010});
    BOOST_CHECK(peerman->SendMessages(config, &peer_node));

    // Inspect sent INV messages: tx_unsuppressed must be announced, while
    // tx_suppressed must have been suppressed by the incoming INV.
    bool saw_suppressed = false;
    bool saw_unsuppressed = false;
    V1TransportDeserializer deserializer(config, peer_node.GetId());
    {
        LOCK(peer_node.cs_vSend);
        for (const auto &chunk : peer_node.vSendMsg) {
            Span<const uint8_t> sp{chunk};
            while (!sp.empty()) {
                const int ret = deserializer.Read(config, sp);
                BOOST_REQUIRE_GE(ret, 0);
                if (deserializer.Complete()) {
                    bool reject_message = false;
                    CNetMessage msg = deserializer.GetMessage(0us, reject_message);
                    BOOST_CHECK(!reject_message);
                    if (msg.m_type == NetMsgType::INV) {
                        std::vector<CInv> sent_invs;
                        msg.m_recv >> sent_invs;
                        for (const CInv &inv : sent_invs) {
                            if (inv.IsMsgTx()) {
                                if (inv.hash == tx_suppressed->GetId()) {
                                    saw_suppressed = true;
                                }
                                if (inv.hash == tx_unsuppressed->GetId()) {
                                    saw_unsuppressed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    BOOST_CHECK(!saw_suppressed);
    BOOST_CHECK(saw_unsuppressed);

    SetMockTime(0);
    peerman->FinalizeNode(config, peer_node);
}

// READY0035 permission matrix retained under the new fixed-tick policy.
// Same frozen clocks, actual SendMessages,
// permissions and serialized INV/SHORTTX output; transaction admission is
// deliberately outside this relay-scheduling component test.
BOOST_AUTO_TEST_CASE(permissions_follow_fixed_relay_tick) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    const Config &config = m_node.chainman->GetConfig();
    for (unsigned scenario = 0; scenario < 8; ++scenario) {
        const bool high_bandwidth = scenario & 1;
        const bool local = scenario & 2;
        const bool noban = scenario & 4;
        auto connman = std::make_unique<ConnmanTestMsg>(
            config, 123, 456, *m_node.addrman);
        PeerManager::Options peer_opts;
        peer_opts.deterministic_rng = true;
        auto peerman = PeerManager::make(
            *connman, *m_node.addrman, nullptr, *m_node.chainman,
            *m_node.mempool, nullptr, peer_opts);
        CConnman::Options opts;
        opts.m_msgproc = {peerman.get()};
        opts.nSendBufferMaxSize = 1024 * 1024;
        connman->Init(opts);
        SetMockTime(1'700'000'000);
        MockRelayTick tick{std::chrono::milliseconds{8'000'001}};
        CAddress addr(MakeTestIp(0xa0b0c080 + scenario), NODE_NONE);
        CNodeOptions node_opts;
        if (noban) node_opts.permission_flags = NetPermissionFlags::NoBan;
        CNode node(800 + scenario, nullptr, addr, 0, 0, 0, CAddress(), "",
                   ConnectionType::OUTBOUND_FULL_RELAY, false,
                   std::move(node_opts));
        connman->Handshake(node, true, NODE_NETWORK, NODE_NETWORK,
                           PROTOCOL_VERSION, true);
        peerman->GetV2ProtocolHandler()->SetHighBandwidthShortTxPeer(
            node.GetId(), high_bandwidth);
        // Prime both clocks before any transaction exists. A single relay
        // cannot trigger the 16-item fast-burst threshold.
        BOOST_REQUIRE(peerman->SendMessages(config, &node));
        WITH_LOCK(node.cs_vSend, node.vSendMsg.clear());
        FastRandomContext rng(uint256{static_cast<uint8_t>(150 + scenario)});
        auto tx = MakeNonCoinbaseTx(rng, 0x90 + scenario);
        BOOST_REQUIRE(tx);
        {
            LOCK2(cs_main, m_node.mempool->cs);
            TestMemPoolEntryHelper entry;
            m_node.mempool->addUnchecked(entry.FromTx(tx));
            if (local) m_node.mempool->AddUnbroadcastTx(tx->GetId());
        }
        peerman->RelayTransaction(tx->GetId());
        auto count_announced = [&]() {
            size_t count = 0;
            V1TransportDeserializer deser(config, node.GetId());
            LOCK(node.cs_vSend);
            for (const auto &chunk : node.vSendMsg) {
                Span<const uint8_t> bytes{chunk};
                while (!bytes.empty()) {
                    BOOST_REQUIRE_GE(deser.Read(config, bytes), 0);
                    if (!deser.Complete()) continue;
                    bool rejected = false;
                    auto msg = deser.GetMessage(0us, rejected);
                    BOOST_REQUIRE(!rejected);
                    if (msg.m_type == NetMsgType::INV) {
                        std::vector<CInv> invs;
                        msg.m_recv >> invs;
                        for (const auto &inv : invs)
                            count += inv.IsMsgTx() && inv.hash == tx->GetId();
                    } else if (msg.m_type == NetMsgType::SHORTTX) {
                        ShortTxResponse response;
                        msg.m_recv >> response;
                        for (const auto &sent : response.txs)
                            count += sent->GetId() == tx->GetId();
                    }
                }
            }
            node.vSendMsg.clear();
            return count;
        };
        BOOST_REQUIRE(peerman->SendMessages(config, &node));
        BOOST_CHECK_EQUAL(count_announced(), 0U);
        // Advancing the relay tick serves every permission class exactly once.
        SetMockTime(1'700'000'060);
        tick.Set(std::chrono::milliseconds{8'000'010});
        BOOST_REQUIRE(peerman->SendMessages(config, &node));
        BOOST_CHECK_EQUAL(count_announced(), 1U);
        peerman->FinalizeNode(config, node);
        WITH_LOCK(m_node.mempool->cs, m_node.mempool->clear());
    }
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(single_tx_relays_wait_for_the_relay_tick) {
    // Transactions relayed one at a time, local or not, are announced at
    // the next relay tick; a high-bandwidth peer gets the burst pushed.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    const Config &config = m_node.chainman->GetConfig();
    for (unsigned scenario = 0; scenario < 4; ++scenario) {
        const bool high_bandwidth = scenario & 1;
        const bool local = scenario & 2;
        auto connman =
            std::make_unique<ConnmanTestMsg>(config, 123, 456, *m_node.addrman);
        PeerManager::Options peer_opts;
        peer_opts.deterministic_rng = true;
        auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr,
                                         *m_node.chainman, *m_node.mempool,
                                         nullptr, peer_opts);
        CConnman::Options opts;
        opts.m_msgproc = {peerman.get()};
        opts.nSendBufferMaxSize = 1024 * 1024;
        connman->Init(opts);
        SetMockTime(1'700'000'000);
        MockRelayTick tick{std::chrono::milliseconds{6'000'001}};
        CAddress addr(MakeTestIp(0xa0b0c040 + scenario), NODE_NONE);
        CNode node(400 + scenario, nullptr, addr, 0, 0, 0, CAddress(), "",
                   ConnectionType::OUTBOUND_FULL_RELAY, false);
        connman->Handshake(node, true, NODE_NETWORK, NODE_NETWORK,
                           PROTOCOL_VERSION, true);
        BOOST_CHECK(peerman->SendMessages(config, &node));
        WITH_LOCK(node.cs_vSend, node.vSendMsg.clear());
        peerman->GetV2ProtocolHandler()->SetHighBandwidthShortTxPeer(
            node.GetId(), high_bandwidth);
        FastRandomContext rng(uint256{static_cast<uint8_t>(100 + scenario)});
        std::vector<CTransactionRef> txs;
        TestMemPoolEntryHelper entry;
        for (unsigned i = 0; i < 17; ++i) {
            auto tx = MakeNonCoinbaseTx(rng, 0x60 + i);
            BOOST_REQUIRE(tx);
            {
                LOCK2(cs_main, m_node.mempool->cs);
                m_node.mempool->addUnchecked(entry.FromTx(tx));
                if (local) m_node.mempool->AddUnbroadcastTx(tx->GetId());
            }
            txs.push_back(tx);
        }
        for (const auto &tx : txs)
            peerman->RelayTransaction(tx->GetId());
        // The fast path must retain known-inventory suppression as well.
        peerman->MarkPeerKnownTx(node.GetId(), txs.back()->GetId());
        tick.Set(std::chrono::milliseconds{6'000'010});
        BOOST_CHECK(peerman->SendMessages(config, &node));
        size_t announced = 0;
        size_t pushed = 0;
        V1TransportDeserializer deserializer(config, node.GetId());
        {
            LOCK(node.cs_vSend);
            for (const auto &chunk : node.vSendMsg) {
                Span<const uint8_t> bytes{chunk};
                while (!bytes.empty()) {
                    BOOST_REQUIRE_GE(deserializer.Read(config, bytes), 0);
                    if (!deserializer.Complete()) continue;
                    bool rejected = false;
                    auto msg = deserializer.GetMessage(0us, rejected);
                    BOOST_CHECK(!rejected);
                    if (msg.m_type == NetMsgType::INV) {
                        std::vector<CInv> invs;
                        msg.m_recv >> invs;
                        for (const auto &inv : invs)
                            announced += inv.IsMsgTx();
                    } else if (msg.m_type == NetMsgType::SHORTTX) {
                        ShortTxResponse response;
                        msg.m_recv >> response;
                        announced += response.txs.size();
                        pushed += response.txs.size();
                        for (const auto &tx : response.txs)
                            BOOST_CHECK(tx->GetId() != txs.back()->GetId());
                    }
                }
            }
        }
        BOOST_CHECK_EQUAL(announced, 16U);
        BOOST_CHECK_EQUAL(pushed, high_bandwidth ? 16U : 0U);
        peerman->FinalizeNode(config, node);
    }
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(malformed_later_tx_does_not_discard_decoded_prefix) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    const Config &config = m_node.chainman->GetConfig();
    auto connman =
        std::make_unique<ConnmanTestMsg>(config, 987, 654, *m_node.addrman);
    auto peerman =
        PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman,
                          *m_node.mempool, nullptr, {});
    CConnman::Options opts;
    opts.m_msgproc = {peerman.get()};
    opts.nSendBufferMaxSize = 1024 * 1024;
    connman->Init(opts);
    WITH_LOCK(cs_main, SetMockTime(m_node.chainman->ActiveChain().Tip()->GetBlockTime()));
    BOOST_REQUIRE(!m_node.chainman->IsInitialBlockDownload());
    CAddress addr(MakeTestIp(0xa0b0c050), NODE_NONE);
    CNode node(500, nullptr, addr, 0, 0, 0, CAddress(), "",
               ConnectionType::OUTBOUND_FULL_RELAY, false);
    connman->Handshake(node, true, NODE_NETWORK, NODE_NETWORK, PROTOCOL_VERSION,
                       true);
    FastRandomContext rng(uint256{57});
    auto tx = MakeNonCoinbaseTx(rng, 0x51);
    BOOST_REQUIRE(tx);
    FundTxInputInCoinsTip(*m_node.chainman, *tx);
    auto good = NetMsg::Make(NetMsgType::TX, tx);
    CSerializedNetMsg malformed;
    malformed.m_type = NetMsgType::TX;
    malformed.data = {0xff};
    BOOST_REQUIRE(connman->ReceiveMsgFrom(node, good));
    BOOST_REQUIRE(connman->ReceiveMsgFrom(node, malformed));
    connman->ProcessMessagesOnce(node);
    BOOST_CHECK(m_node.mempool->exists(tx->GetId()));
    peerman->FinalizeNode(config, node);
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(invalid_last_member_does_not_double_burst_admission_work) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    const Config &config = m_node.chainman->GetConfig();
    auto connman =
        std::make_unique<ConnmanTestMsg>(config, 987, 655, *m_node.addrman);
    auto peerman =
        PeerManager::make(*connman, *m_node.addrman, nullptr, *m_node.chainman,
                          *m_node.mempool, nullptr, {});
    CConnman::Options opts;
    opts.m_msgproc = {peerman.get()};
    opts.nSendBufferMaxSize = 1024 * 1024;
    connman->Init(opts);
    WITH_LOCK(cs_main, SetMockTime(m_node.chainman->ActiveChain().Tip()->GetBlockTime()));
    BOOST_REQUIRE(!m_node.chainman->IsInitialBlockDownload());
    CAddress addr(MakeTestIp(0xa0b0c051), NODE_NONE);
    CNode node(501, nullptr, addr, 0, 0, 0, CAddress(), "",
               ConnectionType::OUTBOUND_FULL_RELAY, false);
    connman->Handshake(node, true, NODE_NETWORK, NODE_NETWORK, PROTOCOL_VERSION,
                       true);
    FastRandomContext rng(uint256{64});
    std::vector<TxId> valid_ids;
    for (unsigned i = 0; i < 256; ++i) {
        auto tx = MakeNonCoinbaseTx(rng, i);
        BOOST_REQUIRE(tx);
        FundTxInputInCoinsTip(*m_node.chainman, *tx);
        if (i == 255) {
            CMutableTransaction invalid(*tx);
            invalid.vin[0].scriptSig = CScript() << OP_FALSE;
            tx = MakeTransactionRef(std::move(invalid));
        } else
            valid_ids.push_back(tx->GetId());
        auto msg = NetMsg::Make(NetMsgType::TX, tx);
        BOOST_REQUIRE(connman->ReceiveMsgFrom(node, msg));
    }
    const bool logged_before = LogInstance().WillLogCategory(BCLog::TXPACKAGES);
    LogInstance().EnableCategory(BCLog::TXPACKAGES);
    std::atomic<size_t> checks{0};
    auto callback =
        LogInstance().PushBackCallback([&](const std::string &line) {
            if (line.find("tx-admission-precheck txid=") != std::string::npos)
                ++checks;
        });
    const auto started_at = std::chrono::steady_clock::now();
    connman->ProcessMessagesOnce(node);
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started_at);
    // The logger thread runs the callback: deliver queued lines first.
    LogInstance().Flush();
    BOOST_TEST_MESSAGE("256-TX burst admission_prechecks=" << checks.load()
                       << " diagnostic_elapsed_us=" << elapsed.count());
    LogInstance().DeleteCallback(callback);
    if (!logged_before) LogInstance().DisableCategory(BCLog::TXPACKAGES);
    BOOST_CHECK_GT(checks.load(), 0);
    BOOST_CHECK_LE(checks.load(), 257);
    for (const auto &id : valid_ids)
        BOOST_CHECK(m_node.mempool->exists(id));
    BOOST_CHECK_EQUAL(m_node.mempool->size(), 255);
    peerman->FinalizeNode(config, node);    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(bursts_wait_for_the_relay_tick) {
    // Since Nucleation relay every transaction, local or relayed, waits for
    // the fixed relay tick; high-bandwidth peers then get the burst pushed.
    LOCK(NetEventsInterface::g_msgproc_mutex);
    const Config &config = m_node.chainman->GetConfig();
    for (unsigned scenario = 0; scenario < 4; ++scenario) {
        const bool high_bandwidth = scenario & 1;
        const bool local = scenario & 2;
        auto connman =
            std::make_unique<ConnmanTestMsg>(config, 123, 456, *m_node.addrman);
        PeerManager::Options peer_opts;
        peer_opts.deterministic_rng = true;
        auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr,
                                         *m_node.chainman, *m_node.mempool,
                                         nullptr, peer_opts);
        CConnman::Options opts;
        opts.m_msgproc = {peerman.get()};
        opts.nSendBufferMaxSize = 1024 * 1024;
        connman->Init(opts);
        SetMockTime(1'700'000'000);
        MockRelayTick tick{std::chrono::milliseconds{5'000'001}};
        CAddress addr(MakeTestIp(0xa0b0c040 + scenario), NODE_NONE);
        CNode node(400 + scenario, nullptr, addr, 0, 0, 0, CAddress(), "",
                   ConnectionType::OUTBOUND_FULL_RELAY, false);
        connman->Handshake(node, true, NODE_NETWORK, NODE_NETWORK,
                           PROTOCOL_VERSION, true);
        BOOST_CHECK(peerman->SendMessages(config, &node));
        WITH_LOCK(node.cs_vSend, node.vSendMsg.clear());
        peerman->GetV2ProtocolHandler()->SetHighBandwidthShortTxPeer(
            node.GetId(), high_bandwidth);
        FastRandomContext rng(uint256{static_cast<uint8_t>(100 + scenario)});
        std::vector<CTransactionRef> txs;
        TestMemPoolEntryHelper entry;
        for (unsigned i = 0; i < 17; ++i) {
            auto tx = MakeNonCoinbaseTx(rng, 0x60 + i);
            BOOST_REQUIRE(tx);
            {
                LOCK2(cs_main, m_node.mempool->cs);
                m_node.mempool->addUnchecked(entry.FromTx(tx));
                if (local) m_node.mempool->AddUnbroadcastTx(tx->GetId());
            }
            txs.push_back(tx);
        }
        peerman->RelayTransactionBatch(txs);
        // The fast path must retain known-inventory suppression as well.
        peerman->MarkPeerKnownTx(node.GetId(), txs.back()->GetId());
        // (Nothing is sent before the tick; see txrelay_tests.)
        tick.Set(std::chrono::milliseconds{5'000'010});
        BOOST_CHECK(peerman->SendMessages(config, &node));
        size_t announced = 0;
        size_t pushed = 0;
        V1TransportDeserializer deserializer(config, node.GetId());
        {
            LOCK(node.cs_vSend);
            for (const auto &chunk : node.vSendMsg) {
                Span<const uint8_t> bytes{chunk};
                while (!bytes.empty()) {
                    BOOST_REQUIRE_GE(deserializer.Read(config, bytes), 0);
                    if (!deserializer.Complete()) continue;
                    bool rejected = false;
                    auto msg = deserializer.GetMessage(0us, rejected);
                    BOOST_CHECK(!rejected);
                    if (msg.m_type == NetMsgType::INV) {
                        std::vector<CInv> invs;
                        msg.m_recv >> invs;
                        for (const auto &inv : invs)
                            announced += inv.IsMsgTx();
                    } else if (msg.m_type == NetMsgType::SHORTTX) {
                        ShortTxResponse response;
                        msg.m_recv >> response;
                        announced += response.txs.size();
                        pushed += response.txs.size();
                        for (const auto &tx : response.txs)
                            BOOST_CHECK(tx->GetId() != txs.back()->GetId());
                    }
                }
            }
        }
        BOOST_CHECK_EQUAL(announced, 16U);
        BOOST_CHECK_EQUAL(pushed, high_bandwidth ? 16U : 0U);
        peerman->FinalizeNode(config, node);
    }
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(inventory_broadcast_constants) {
    // Verify Stage H1 inventory broadcast constants
    static_assert(INBOUND_INVENTORY_BROADCAST_INTERVAL ==
                  std::chrono::milliseconds{5000});
    static_assert(OUTBOUND_INVENTORY_BROADCAST_INTERVAL ==
                  std::chrono::milliseconds{2000});
    static_assert(INVENTORY_MAX_RECENT_RELAY == 350000);
    BOOST_CHECK_EQUAL(INBOUND_INVENTORY_BROADCAST_INTERVAL.count(), 5000);
    BOOST_CHECK_EQUAL(OUTBOUND_INVENTORY_BROADCAST_INTERVAL.count(), 2000);
    BOOST_CHECK_EQUAL(INVENTORY_MAX_RECENT_RELAY, 350000U);
}


BOOST_AUTO_TEST_CASE(tachyon_avalanche_snapsync_reverse_peel_and_opt_out) {
    LOCK(NetEventsInterface::g_msgproc_mutex);

    // 1. Verify wire message types and MSG_AVA_STATE_ANCHOR inventory type
    const auto &all_types = getAllNetMessageTypes();
    for (const char *msg :
         {NetMsgType::GETUTXOROOTS, NetMsgType::UTXOROOTS,
          NetMsgType::GETUTXOSHARD, NetMsgType::UTXOSHARD,
          NetMsgType::GETBLOCKUNDO, NetMsgType::BLOCKUNDO}) {
        BOOST_CHECK(std::find(all_types.begin(), all_types.end(),
                              std::string(msg)) != all_types.end());
        CMessageHeader hdr(Params().NetMagic(), msg, 64);
        BOOST_CHECK(hdr.IsMessageTypeValid());
    }
    CInv anchor_inv(MSG_AVA_STATE_ANCHOR, uint256{42});
    BOOST_CHECK(anchor_inv.IsMsgStateAnchor());

    // 2. Verify lossless bijective CTxOut::ToV2Output() / lotus::v2::LegacyTxOutput()
    //    across standard and arbitrary scripts
    {
        std::vector<CScript> test_scripts;
        CScript p2pkh;
        p2pkh << OP_DUP << OP_HASH160 << std::vector<uint8_t>(20, 0x11)
              << OP_EQUALVERIFY << OP_CHECKSIG;
        test_scripts.push_back(p2pkh);

        CScript p2sh;
        p2sh << OP_HASH160 << std::vector<uint8_t>(20, 0x22) << OP_EQUAL;
        test_scripts.push_back(p2sh);

        CScript taproot;
        taproot << uint8_t(0x62) << OP_1 << std::vector<uint8_t>(33, 0x02);
        test_scripts.push_back(taproot);

        CScript taproot_state;
        taproot_state << uint8_t(0x62) << OP_1 << std::vector<uint8_t>(33, 0x03)
                      << std::vector<uint8_t>(32, 0xaa);
        test_scripts.push_back(taproot_state);

        CScript op_return;
        op_return << OP_RETURN << std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef};
        test_scripts.push_back(op_return);

        CScript raw_custom = MakeRedeemScriptForAttempt(7);
        test_scripts.push_back(raw_custom);

        for (const CScript &spk : test_scripts) {
            CTxOut orig(12345678 * SATOSHI, spk);
            lotus::v2::Output v2_out = lotus::v2::LegacyStateOutput(orig);
            CTxOut roundtrip = lotus::v2::LegacyTxOutput(v2_out);
            BOOST_CHECK(orig == roundtrip);
        }
    }

    // 3. Mine 102 authentic blocks on top of Genesis:
    //    - Block 1 pays coinbase to p2sh_spk
    //    - Blocks 2..100 mature Block 1's coinbase
    //    - Block 101 spends Block 1's coinbase output
    //    - Block 102 spends Block 101's output (prior-block spend) AND includes
    //      a CTOR-ordered child transaction spending that transaction's output
    //      within Block 102 (intra-block spend)
    const Config &config = m_node.chainman->GetConfig();
    const Consensus::Params &params = config.GetChainParams().GetConsensus();
    const CScript redeem_script = MakeRedeemScriptForAttempt(1);
    const CScript p2sh_spk =
        GetScriptForDestination(ScriptHash(redeem_script));

    TxId block1_cb_txid;
    TxId block101_txid;
    for (int b = 1; b <= 102; ++b) {
        std::shared_ptr<CBlock> blk =
            PrepareBlock(config, m_node, p2sh_spk);
        if (b == 1) {
            block1_cb_txid = blk->vtx[0]->GetId();
        } else if (b == 101) {
            CMutableTransaction mtx_101;
            mtx_101.nVersion = 2;
            mtx_101.vin.resize(1);
            mtx_101.vin[0].prevout = COutPoint(block1_cb_txid, 0);
            mtx_101.vin[0].scriptSig = CScript() << ToByteVector(redeem_script);
            mtx_101.vout.resize(1);
            mtx_101.vout[0].nValue =
                blk->vtx[0]->GetValueOut() - 10000 * SATOSHI;
            mtx_101.vout[0].scriptPubKey = p2sh_spk;
            CTransactionRef tx_101 = MakeTransactionRef(std::move(mtx_101));
            block101_txid = tx_101->GetId();
            blk->vtx.push_back(tx_101);
        } else if (b == 102) {
            CMutableTransaction mtx_parent;
            mtx_parent.nVersion = 2;
            mtx_parent.vin.resize(1);
            mtx_parent.vin[0].prevout = COutPoint(block101_txid, 0);
            mtx_parent.vin[0].scriptSig =
                CScript() << ToByteVector(redeem_script);
            mtx_parent.vout.resize(1);
            mtx_parent.vout[0].nValue =
                blk->vtx[0]->GetValueOut() - 20000 * SATOSHI;
            mtx_parent.vout[0].scriptPubKey = p2sh_spk;
            CTransactionRef tx_parent =
                MakeTransactionRef(std::move(mtx_parent));

            // Grind nLockTime on tx_child so tx_parent->GetId() < tx_child->GetId()
            // (satisfying CTOR while spending tx_parent intra-block).
            CTransactionRef tx_child;
            for (uint32_t lt = 0; lt < 10000; ++lt) {
                CMutableTransaction mtx_child;
                mtx_child.nVersion = 2;
                mtx_child.nLockTime = lt;
                mtx_child.vin.resize(1);
                mtx_child.vin[0].prevout = COutPoint(tx_parent->GetId(), 0);
                mtx_child.vin[0].scriptSig =
                    CScript() << ToByteVector(redeem_script);
                mtx_child.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
                mtx_child.vout.resize(1);
                mtx_child.vout[0].nValue =
                    blk->vtx[0]->GetValueOut() - 30000 * SATOSHI;
                mtx_child.vout[0].scriptPubKey = p2sh_spk;
                CTransactionRef cand = MakeTransactionRef(std::move(mtx_child));
                if (tx_parent->GetId() < cand->GetId()) {
                    tx_child = cand;
                    break;
                }
            }
            BOOST_REQUIRE(tx_child != nullptr);

            blk->vtx.push_back(tx_parent);
            blk->vtx.push_back(tx_child);
        }
        {
            LOCK(cs_main);
            blk->hashMerkleRoot = BlockMerkleRoot(*blk);
        }
        while (!CheckProofOfWork(blk->GetHash(), blk->nBits, params)) {
            ++blk->nNonce;
        }
        BOOST_REQUIRE(m_node.chainman->ProcessNewBlock(
            blk, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr));
    }

    CBlockIndex *pivot_index = nullptr;
    BlockHash pivot_hash;
    lotus::v2::Hash pivot_utxo_root{};
    {
        LOCK(cs_main);
        pivot_index = m_node.chainman->ActiveTip();
        BOOST_REQUIRE(pivot_index != nullptr);
        BOOST_REQUIRE_EQUAL(pivot_index->nHeight, 102);
        pivot_hash = pivot_index->GetBlockHash();

        Chainstate::FastSyncBlockState pivot_state;
        std::string err;
        BOOST_REQUIRE(
            m_node.chainman->ActiveChainstate()
                .ExportV2BlockStateCoinsAndMonetary(pivot_index, pivot_state,
                                                    err));
        pivot_utxo_root = pivot_state.utxo_root;
    }

    // 4. Verify deterministic Avalanche StateAnchorId computation
    uint256 anchor_root_u256;
    std::memcpy(anchor_root_u256.begin(), pivot_utxo_root.data(), 32);
    const avalanche::StateAnchorId anchor_id(pivot_hash, anchor_root_u256);
    const avalanche::StateAnchorId anchor_id_dup(pivot_hash, anchor_root_u256);
    BOOST_CHECK(anchor_id == anchor_id_dup);

    uint256 conflicting_root_u256 = anchor_root_u256;
    conflicting_root_u256.begin()[0] ^= 0xff;
    const avalanche::StateAnchorId conflicting_anchor_id(pivot_hash,
                                                         conflicting_root_u256);
    BOOST_CHECK(anchor_id != conflicting_anchor_id);

    // Set up PeerManager + V2PeerProtocolHandler with two peers:
    // - peer_bad (sends Byzantine/corrupted shards & undo coins)
    // - peer_honest (serves valid UTXOROOTS, UTXOSHARD, and BLOCKUNDO)
    auto connman = std::make_unique<ConnmanTestMsg>(config, 0x7788, 0x7788,
                                                    *m_node.addrman);
    PeerManager::Options peer_opts;
    peer_opts.deterministic_rng = true;
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr,
                                     *m_node.chainman, *m_node.mempool,
                                     /*avalanche=*/nullptr, peer_opts);
    CConnman::Options options;
    options.m_msgproc = {peerman.get()};
    connman->Init(options);

    V2PeerProtocolHandler *v2_handler = peerman->GetV2ProtocolHandler();
    BOOST_REQUIRE(v2_handler != nullptr);

    CAddress addr_legacy(MakeTestIp(0xa0b0c05f), NODE_NONE);
    CNode peer_legacy(/*id=*/959, /*sock=*/nullptr, addr_legacy,
                      /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                      /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
                      ConnectionType::OUTBOUND_FULL_RELAY,
                      /*inbound_onion=*/false);
    connman->Handshake(peer_legacy, /*successfully_connected=*/true,
                       ServiceFlags(NODE_NETWORK), ServiceFlags(NODE_NETWORK),
                       PROTOCOL_VERSION, /*relay_txs=*/true);
    v2_handler->RegisterPeerNode(peer_legacy);

    CAddress addr_bad(MakeTestIp(0xa0b0c060), NODE_NONE);
    CNode peer_bad(/*id=*/960, /*sock=*/nullptr, addr_bad,
                   /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                   /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
                   ConnectionType::OUTBOUND_FULL_RELAY,
                   /*inbound_onion=*/false);
    connman->Handshake(peer_bad, /*successfully_connected=*/true,
                       ServiceFlags(NODE_NETWORK | NODE_UTXO_SHARD),
                       ServiceFlags(NODE_NETWORK | NODE_UTXO_SHARD),
                       PROTOCOL_VERSION, /*relay_txs=*/true);
    v2_handler->RegisterPeerNode(peer_bad);

    CAddress addr_honest(MakeTestIp(0xa0b0c061), NODE_NONE);
    CNode peer_honest(/*id=*/961, /*sock=*/nullptr, addr_honest,
                      /*nKeyedNetGroupIn=*/1, /*nLocalHostNonceIn=*/0,
                      /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
                      ConnectionType::OUTBOUND_FULL_RELAY,
                      /*inbound_onion=*/false);
    connman->Handshake(peer_honest, /*successfully_connected=*/true,
                       ServiceFlags(NODE_NETWORK | NODE_UTXO_SHARD),
                       ServiceFlags(NODE_NETWORK | NODE_UTXO_SHARD),
                       PROTOCOL_VERSION, /*relay_txs=*/true);
    v2_handler->RegisterPeerNode(peer_honest);

    // 5. Verify opt-out to traditional sync (-snapsync=0 and -reversesync=0) and
    //    NODE_UTXO_SHARD service capability filtering
    {
        std::string cap_err;
        BOOST_CHECK(!v2_handler->StartFastSyncSwarm(
            pivot_hash, {peer_legacy.GetId()}, /*auto_peel=*/false, cap_err));
        BOOST_CHECK(cap_err.find("NODE_UTXO_SHARD") != std::string::npos);

        v2_handler->SetSnapSyncEnabled(false);
        BOOST_CHECK(!v2_handler->IsSnapSyncEnabled());
        {
            LOCK(cs_main);
            BOOST_CHECK(!m_node.chainman->ActiveChainstate().IsSnapSyncEnabled());
        }
        std::string opt_out_err;
        BOOST_CHECK(!v2_handler->StartFastSyncSwarm(
            pivot_hash, {peer_honest.GetId()}, /*auto_peel=*/false,
            opt_out_err));
        BOOST_CHECK(opt_out_err.find("disabled") != std::string::npos);

        v2_handler->SetSnapSyncEnabled(true);
        v2_handler->SetReverseSyncEnabled(false);
        BOOST_CHECK(!v2_handler->IsReverseSyncEnabled());
        BOOST_CHECK(!v2_handler->IsSnapSyncEnabled());
        BOOST_CHECK(!v2_handler->StartReversePeelSwarm(
            {peer_honest.GetId()}, opt_out_err));
        BOOST_CHECK(opt_out_err.find("disabled") != std::string::npos);

        // Re-enable SnapSync and ReverseSync
        v2_handler->SetSnapSyncEnabled(true);
        v2_handler->SetReverseSyncEnabled(true);
        BOOST_CHECK(v2_handler->IsSnapSyncEnabled());
        BOOST_CHECK(v2_handler->IsReverseSyncEnabled());
    }

    // 6. Export valid UtxoRootsMessage and non-empty depth-8 UtxoShardMessages for the pivot
    //    and verify O(256) ExportUtxoRootsFromSmt / O(k+|shard|) ExportUtxoShardFromSmt
    //    match full UtxoSet exports bit-for-bit, and VerifyUtxoRootsAgainstAnchor
    //    rejects missing (std::nullopt) state anchors!
    lotus::v2::Hash pivot_v2_hash{};
    std::memcpy(pivot_v2_hash.data(), pivot_hash.begin(), 32);
    lotus::v2::UtxoRootsMessage valid_roots_msg;
    std::vector<lotus::v2::UtxoShardMessage> valid_shards;
    {
        LOCK(cs_main);
        Chainstate::FastSyncBlockState pivot_state;
        std::string err;
        BOOST_REQUIRE(
            m_node.chainman->ActiveChainstate()
                .ExportV2BlockStateCoinsAndMonetary(pivot_index, pivot_state,
                                                    err));
        BOOST_REQUIRE(pivot_state.smt_root != nullptr);
        BOOST_REQUIRE(lotus::v2::ExportUtxoRootsForBlock(
            pivot_state.utxo, pivot_v2_hash, pivot_state.height,
            pivot_state.monetary, valid_roots_msg, err));

        lotus::v2::UtxoRootsMessage smt_roots_msg;
        BOOST_REQUIRE(lotus::v2::ExportUtxoRootsFromSmt(
            pivot_state.smt_root, pivot_v2_hash, pivot_state.height,
            pivot_state.monetary, smt_roots_msg, err));
        BOOST_CHECK(lotus::v2::EncodeUtxoRootsMessage(valid_roots_msg) ==
                    lotus::v2::EncodeUtxoRootsMessage(smt_roots_msg));

        // Mandatory finalized state anchor check: std::nullopt anchor MUST be rejected!
        lotus::v2::Hash dummy_folded{};
        std::string anchor_err;
        BOOST_CHECK(!lotus::v2::VerifyUtxoRootsAgainstAnchor(
            pivot_v2_hash, pivot_state.height, std::nullopt, valid_roots_msg,
            dummy_folded, anchor_err));
        BOOST_CHECK(anchor_err.find("missing finalized") !=
                    std::string::npos);

        std::vector<lotus::v2::UtxoShardMessage> adaptive_shards;
        BOOST_REQUIRE(lotus::v2::ExportAdaptiveUtxoShards(
            pivot_state.utxo, pivot_v2_hash, adaptive_shards, err,
            /*max_shard_leaves=*/1));
        BOOST_CHECK(!adaptive_shards.empty());

        // Export all non-empty depth-8 shards for the P2P swarm test
        for (uint16_t s = 0; s < 256; ++s) {
            if (valid_roots_msg.shards[s].cardinality_tag == 0) {
                continue;
            }
            lotus::v2::UtxoShardMessage shard_msg;
            BOOST_REQUIRE(lotus::v2::ExportUtxoShard(
                pivot_state.utxo, pivot_v2_hash, /*prefix_depth=*/8, s,
                shard_msg, err));
            lotus::v2::UtxoShardMessage smt_shard_msg;
            BOOST_REQUIRE(lotus::v2::ExportUtxoShardFromSmt(
                pivot_state.smt_root, pivot_v2_hash, /*prefix_depth=*/8, s,
                smt_shard_msg, err));
            std::vector<uint8_t> b1, b2;
            BOOST_REQUIRE(lotus::v2::EncodeUtxoShardMessage(shard_msg, b1, err));
            BOOST_REQUIRE(
                lotus::v2::EncodeUtxoShardMessage(smt_shard_msg, b2, err));
            BOOST_CHECK(b1 == b2);
            valid_shards.push_back(std::move(shard_msg));
        }
        BOOST_REQUIRE(!valid_shards.empty());
    }

    // 7. Start FastSyncSwarm across [peer_bad, peer_honest]:
    //    - peer_bad is queried first for GETUTXOROOTS; we send a forged UTXOROOTS
    //      from peer_bad and verify peer_bad is banned/disconnected and the swarm
    //      fails over to peer_honest!
    std::atomic<bool> interrupt{false};
    std::chrono::microseconds cur_time{500'000};
    {
        LOCK(peer_bad.cs_vSend);
        peer_bad.vSendMsg.clear();
    }
    {
        LOCK(peer_honest.cs_vSend);
        peer_honest.vSendMsg.clear();
    }

    std::string swarm_err;
    BOOST_REQUIRE(v2_handler->StartFastSyncSwarm(
        pivot_hash, {peer_bad.GetId(), peer_honest.GetId()},
        /*auto_peel=*/false, swarm_err));

    // A silent supplier must fail over through the normal SendMessages tick,
    // even when no incoming message calls the swarm handler.
    const auto timeout_start = GetTime<std::chrono::seconds>();
    SetMockTime(timeout_start + 31s);
    BOOST_CHECK(peerman->SendMessages(config, &peer_bad));
    BOOST_CHECK_EQUAL(v2_handler->GetFastSyncSwarmStatus().banned_swarm_peers, 1U);
    BOOST_CHECK_EQUAL(v2_handler->GetFastSyncSwarmStatus().active_peers, 1U);
    BOOST_CHECK(peerman->SendMessages(config, &peer_honest));
    BOOST_CHECK_EQUAL(v2_handler->GetFastSyncSwarmStatus().banned_swarm_peers, 1U);
    SetMockTime(0s);
    // Restart the session to retain the independent forged-root regression.
    BOOST_REQUIRE(v2_handler->StartFastSyncSwarm(
        pivot_hash, {peer_bad.GetId(), peer_honest.GetId()},
        /*auto_peel=*/false, swarm_err));

    // Deliver forged UTXOROOTS from peer_bad -> must disconnect peer_bad and
    // fail over to peer_honest!
    {
        lotus::v2::UtxoRootsMessage forged_roots = valid_roots_msg;
        forged_roots.shards[valid_shards[0].prefix_bits & 0xFFu].subtree_root[0] ^= 0xff;
        const std::vector<uint8_t> encoded_forged =
            lotus::v2::EncodeUtxoRootsMessage(forged_roots);
        DataStream ss{encoded_forged};
        peerman->ProcessMessage(config, peer_bad, NetMsgType::UTXOROOTS, ss,
                                cur_time, interrupt);
        BOOST_CHECK(peer_bad.fDisconnect);
    }

    // Deliver valid UTXOROOTS from peer_honest -> schedules non-empty shards!
    cur_time += 100us;
    {
        const std::vector<uint8_t> encoded_roots =
            lotus::v2::EncodeUtxoRootsMessage(valid_roots_msg);
        DataStream ss{encoded_roots};
        peerman->ProcessMessage(config, peer_honest, NetMsgType::UTXOROOTS, ss,
                                cur_time, interrupt);
    }
    auto swarm_status = v2_handler->GetFastSyncSwarmStatus();
    BOOST_CHECK(swarm_status.state == FastSyncSwarmState::FETCHING_SHARDS);
    BOOST_CHECK_EQUAL(swarm_status.total_non_empty_shards, valid_shards.size());

    // Deliver all non-empty valid UTXOSHARD messages from peer_honest -> activates
    // the verified pivot!
    for (const auto &shard_msg : valid_shards) {
        cur_time += 2'000'000us;
        std::vector<uint8_t> encoded_shard;
        std::string enc_err;
        BOOST_REQUIRE(lotus::v2::EncodeUtxoShardMessage(
            shard_msg, encoded_shard, enc_err));
        DataStream ss{encoded_shard};
        peerman->ProcessMessage(config, peer_honest, NetMsgType::UTXOSHARD, ss,
                                cur_time, interrupt);
    }

    swarm_status = v2_handler->GetFastSyncSwarmStatus();
    BOOST_CHECK(swarm_status.state == FastSyncSwarmState::COMPLETED);
    BOOST_CHECK_EQUAL(swarm_status.verified_shards, valid_shards.size());
    {
        LOCK(cs_main);
        m_node.chainman->CheckBlockIndex();
        BOOST_CHECK(m_node.chainman->ActiveChainstate().IsFastSyncActive());
        BOOST_CHECK_EQUAL(
            m_node.chainman->ActiveChainstate().GetEarliestVerifiedHeight(),
            pivot_index->nHeight);
        // Allow peeling all 102 blocks down to genesis in this test:
        m_node.chainman->ActiveChainstate().SetFastSyncMaxPeelBlocks(102);
    }
    const auto snap_after_pivot = node::GetChainTipSnapshot();
    BOOST_REQUIRE(snap_after_pivot != nullptr);
    BOOST_CHECK(snap_after_pivot->fast_sync_active);
    BOOST_CHECK_EQUAL(snap_after_pivot->earliest_verified_height,
                      pivot_index->nHeight);

    // 8. Verify ReverseSyncCoordinator peels all blocks from pivot_index->nHeight
    //    down to Genesis (height 0) without any Merklix state root in the 80-byte
    //    block header!
    //    - Add a second peer (peer_bad2) to test Byzantine forged undo coin
    //      rejection and failover during reverse peeling.
    CAddress addr_bad2(MakeTestIp(0xa0b0c062), NODE_NONE);
    CNode peer_bad2(/*id=*/962, /*sock=*/nullptr, addr_bad2,
                    /*nKeyedNetGroupIn=*/2, /*nLocalHostNonceIn=*/0,
                    /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
                    ConnectionType::OUTBOUND_FULL_RELAY,
                    /*inbound_onion=*/false);
    connman->Handshake(peer_bad2, /*successfully_connected=*/true,
                       ServiceFlags(NODE_NETWORK | NODE_UTXO_SHARD),
                       ServiceFlags(NODE_NETWORK | NODE_UTXO_SHARD),
                       PROTOCOL_VERSION, /*relay_txs=*/true);
    v2_handler->RegisterPeerNode(peer_bad2);

    BOOST_REQUIRE(v2_handler->StartReversePeelSwarm(
        {peer_bad2.GetId(), peer_honest.GetId()}, swarm_err));

    // Pump GETBLOCKUNDO / BLOCKUNDO until earliest_verified_height reaches 0
    bool injected_forged_undo = false;
    for (int step = 0; step < 110; ++step) {
        int cur_earliest = 0;
        CBlockIndex *cur_pindex = nullptr;
        {
            LOCK(cs_main);
            cur_earliest =
                m_node.chainman->ActiveChainstate().GetEarliestVerifiedHeight();
            cur_pindex = m_node.chainman->ActiveChain()[cur_earliest];
        }
        if (cur_earliest <= 0) {
            break;
        }
        BOOST_REQUIRE(cur_pindex != nullptr);

        // Build the authentic BlockUndoMessage for cur_pindex using HandleGetBlockUndo
        // on peer_honest.
        lotus::v2::GetBlockUndoRequest ureq{};
        std::memcpy(ureq.block_id.data(),
                    cur_pindex->GetBlockHash().begin(), 32);
        {
            LOCK(peer_honest.cs_vSend);
            peer_honest.vSendMsg.clear();
        }
        {
            const std::vector<uint8_t> encoded_ureq =
                lotus::v2::EncodeGetBlockUndoRequest(ureq);
            DataStream getundo_ss{encoded_ureq};
            cur_time += 2'000'000us;
            peerman->ProcessMessage(config, peer_honest,
                                    NetMsgType::GETBLOCKUNDO, getundo_ss,
                                    cur_time, interrupt);
        }

        lotus::v2::BlockUndoMessage valid_undo_msg;
        bool decoded_undo = false;
        {
            V1TransportDeserializer deser(config, peer_honest.GetId());
            LOCK(peer_honest.cs_vSend);
            for (const auto &chunk : peer_honest.vSendMsg) {
                Span<const uint8_t> sp{chunk};
                while (!sp.empty()) {
                    const int ret = deser.Read(config, sp);
                    BOOST_REQUIRE_GE(ret, 0);
                    if (deser.Complete()) {
                        bool reject = false;
                        CNetMessage msg = deser.GetMessage(0us, reject);
                        BOOST_REQUIRE(!reject);
                        if (msg.m_type == NetMsgType::BLOCKUNDO) {
                            const auto u_span = MakeUCharSpan(msg.m_recv);
                            const std::vector<uint8_t> u_bytes(u_span.begin(),
                                                               u_span.end());
                            std::string dec_err;
                            decoded_undo = lotus::v2::DecodeBlockUndoMessage(
                                u_bytes, valid_undo_msg, dec_err);
                        }
                    }
                }
            }
            peer_honest.vSendMsg.clear();
        }
        BOOST_REQUIRE(decoded_undo);

        // On the first block with spent coins, first send a forged BlockUndoMessage
        // from peer_bad2 and verify it is rejected & peer_bad2 is disconnected!
        if (!injected_forged_undo &&
            !valid_undo_msg.prior_spent_coins.empty()) {
            injected_forged_undo = true;
            lotus::v2::BlockUndoMessage forged_undo = valid_undo_msg;
            forged_undo.prior_spent_coins[0].output.value += 1000;
            std::vector<uint8_t> encoded_forged_undo;
            std::string enc_err;
            BOOST_REQUIRE(lotus::v2::EncodeBlockUndoMessage(
                forged_undo, encoded_forged_undo, enc_err));
            DataStream bad_ss{encoded_forged_undo};
            cur_time += 100us;
            peerman->ProcessMessage(config, peer_bad2, NetMsgType::BLOCKUNDO,
                                    bad_ss, cur_time, interrupt);
            BOOST_CHECK(peer_bad2.fDisconnect);
        }

        // Exercise undo-before-body ordering once. Hide an already stored
        // historical body (as after pruning), then deliver it through the real
        // BLOCK message path. The undo must wait for ABC to accept the body.
        const bool missing_body = (step == 1);
        CBlock pending_body;
        if (missing_body) {
            LOCK(cs_main);
            BOOST_REQUIRE(m_node.chainman->m_blockman.ReadBlock(pending_body, *cur_pindex));
            m_node.chainman->m_blockman.m_have_pruned = true;
            cur_pindex->nStatus = cur_pindex->nStatus.withData(false).withUndo(false);
        }

        // Now deliver the authentic BlockUndoMessage from peer_honest
        {
            std::vector<uint8_t> encoded_ok_undo;
            std::string enc_err;
            BOOST_REQUIRE(lotus::v2::EncodeBlockUndoMessage(
                valid_undo_msg, encoded_ok_undo, enc_err));
            DataStream ok_ss{encoded_ok_undo};
            cur_time += 100us;
            peerman->ProcessMessage(config, peer_honest, NetMsgType::BLOCKUNDO,
                                    ok_ss, cur_time, interrupt);
        }
        if (missing_body) {
            BOOST_CHECK_EQUAL(v2_handler->GetFastSyncSwarmStatus().blocks_peeled, 1U);
            BOOST_CHECK(v2_handler->IsFastSyncBlockRequested(cur_pindex->GetBlockHash()));
            // Same header, invalid body: no storage and no reverse progress.
            CBlock corrupt_body = pending_body;
            corrupt_body.vtx.clear();
            DataStream corrupt_stream{};
            corrupt_stream << corrupt_body;
            peerman->ProcessMessage(config, peer_honest, NetMsgType::BLOCK,
                                    corrupt_stream, cur_time, interrupt);
            BOOST_CHECK_EQUAL(v2_handler->GetFastSyncSwarmStatus().blocks_peeled, 1U);
            { LOCK(cs_main); BOOST_CHECK(!cur_pindex->nStatus.hasData()); }
            DataStream body_stream{};
            body_stream << pending_body;
            peerman->ProcessMessage(config, peer_honest, NetMsgType::BLOCK,
                                    body_stream, cur_time, interrupt);
            { LOCK(cs_main); BOOST_CHECK(cur_pindex->nStatus.hasData()); }
            BOOST_CHECK_EQUAL(v2_handler->GetFastSyncSwarmStatus().blocks_peeled, 2U);
        }
    }

    BOOST_CHECK(injected_forged_undo);
    swarm_status = v2_handler->GetFastSyncSwarmStatus();
    BOOST_CHECK(swarm_status.state == FastSyncSwarmState::COMPLETED);
    BOOST_CHECK_EQUAL(swarm_status.blocks_peeled, 102U);
    {
        LOCK(cs_main);
        m_node.chainman->CheckBlockIndex();
        BOOST_CHECK(!m_node.chainman->ActiveChainstate().IsFastSyncActive());
        BOOST_CHECK_EQUAL(
            m_node.chainman->ActiveChainstate().GetEarliestVerifiedHeight(), 0);
    }
    const auto snap_after_peel = node::GetChainTipSnapshot();
    BOOST_REQUIRE(snap_after_peel != nullptr);
    BOOST_CHECK(!snap_after_peel->fast_sync_active);
    BOOST_CHECK_EQUAL(snap_after_peel->earliest_verified_height, 0);

    peerman->FinalizeNode(config, peer_legacy);
    peerman->FinalizeNode(config, peer_bad);
    peerman->FinalizeNode(config, peer_bad2);
    peerman->FinalizeNode(config, peer_honest);
    // Disconnected peers must not remain eligible through the fallback node map.
    BOOST_CHECK(!v2_handler->StartFastSyncSwarm(
        pivot_hash, {peer_honest.GetId()}, false, swarm_err));
    BOOST_CHECK(swarm_err.find("no NODE_UTXO_SHARD") != std::string::npos);
}


BOOST_AUTO_TEST_CASE(shorttx_batch_admission_fallback_and_proactive_push) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    MockRelayTick tick{std::chrono::milliseconds{9'000'001}};

    const Config &config = m_node.chainman->GetConfig();
    auto connman = std::make_unique<ConnmanTestMsg>(config, 0x3560, 0x3560,
                                                    *m_node.addrman);
    PeerManager::Options peer_opts;
    peer_opts.deterministic_rng = true;
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr,
                                     *m_node.chainman, *m_node.mempool,
                                     /*avalanche=*/nullptr, peer_opts);

    CConnman::Options options;
    options.m_msgproc = {peerman.get()};
    connman->Init(options);

    V2PeerProtocolHandler *v2_handler = peerman->GetV2ProtocolHandler();
    BOOST_REQUIRE(v2_handler != nullptr);

    const int64_t base_time = 1'700'000'000;
    SetMockTime(base_time);

    CAddress addr_from(MakeTestIp(0xa0b0c040), NODE_NONE);
    CNode peer_from(/*id=*/910, /*sock=*/nullptr, addr_from,
                    /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
                    /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
                    ConnectionType::OUTBOUND_FULL_RELAY,
                    /*inbound_onion=*/false);
    connman->Handshake(
        /*node=*/peer_from,
        /*successfully_connected=*/true,
        /*remote_services=*/ServiceFlags(NODE_NETWORK),
        /*local_services=*/ServiceFlags(NODE_NETWORK),
        /*version=*/PROTOCOL_VERSION,
        /*relay_txs=*/true);

    CAddress addr_to(MakeTestIp(0xa0b0c041), NODE_NONE);
    CNode peer_to(/*id=*/911, /*sock=*/nullptr, addr_to,
                  /*nKeyedNetGroupIn=*/1, /*nLocalHostNonceIn=*/0,
                  /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
                  ConnectionType::OUTBOUND_FULL_RELAY,
                  /*inbound_onion=*/false);
    connman->Handshake(
        /*node=*/peer_to,
        /*successfully_connected=*/true,
        /*remote_services=*/ServiceFlags(NODE_NETWORK),
        /*local_services=*/ServiceFlags(NODE_NETWORK),
        /*version=*/PROTOCOL_VERSION,
        /*relay_txs=*/true);

    CAddress addr_hb(MakeTestIp(0xa0b0c042), NODE_NONE);
    CNode peer_hb(/*id=*/912, /*sock=*/nullptr, addr_hb,
                  /*nKeyedNetGroupIn=*/2, /*nLocalHostNonceIn=*/0,
                  /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
                  ConnectionType::OUTBOUND_FULL_RELAY,
                  /*inbound_onion=*/false);
    connman->Handshake(
        /*node=*/peer_hb,
        /*successfully_connected=*/true,
        /*remote_services=*/ServiceFlags(NODE_NETWORK),
        /*local_services=*/ServiceFlags(NODE_NETWORK),
        /*version=*/PROTOCOL_VERSION,
        /*relay_txs=*/true);
    peer_hb.m_bip152_highbandwidth_from = true;

    BOOST_CHECK(peerman->SendMessages(config, &peer_from));
    BOOST_CHECK(peerman->SendMessages(config, &peer_to));
    BOOST_CHECK(peerman->SendMessages(config, &peer_hb));
    {
        LOCK(peer_from.cs_vSend);
        peer_from.vSendMsg.clear();
    }
    {
        LOCK(peer_to.cs_vSend);
        peer_to.vSendMsg.clear();
    }
    {
        LOCK(peer_hb.cs_vSend);
        peer_hb.vSendMsg.clear();
    }

    FastRandomContext rng(uint256{88});
    std::atomic<bool> interrupt{false};
    auto cur_time = std::chrono::microseconds{base_time * 1'000'000};

    // 1. Batch of 20 valid transactions in SHORTTX (including a parent-child
    //    pair placed out of topological order: child before parent):
    std::vector<CTransactionRef> valid_batch;
    for (int i = 0; i < 18; ++i) {
        CTransactionRef tx = MakeNonCoinbaseTx(rng, static_cast<uint8_t>(0x10 + i));
        BOOST_REQUIRE(tx != nullptr);
        FundTxInputInCoinsTip(*m_node.chainman, *tx);
        valid_batch.push_back(tx);
    }

    // Create a parent tx and a child tx spending parent's output 0, and place
    // child BEFORE parent in the SHORTTX payload to test topological sorting.
    const CScript parent_redeem = MakeRedeemScriptForAttempt(8);
    const CScript parent_spk =
        GetScriptForDestination(ScriptHash(parent_redeem));
    CMutableTransaction parent_mtx;
    parent_mtx.nVersion = 2;
    parent_mtx.vin.resize(1);
    parent_mtx.vin[0].prevout = COutPoint(TxId(rng.rand256()), 7);
    parent_mtx.vin[0].scriptSig =
        CScript() << ToByteVector(MakeRedeemScriptForAttempt(7));
    parent_mtx.vout.resize(1);
    parent_mtx.vout[0].nValue = 50000 * SATOSHI;
    parent_mtx.vout[0].scriptPubKey = parent_spk;
    CTransactionRef parent_tx = MakeTransactionRef(std::move(parent_mtx));
    FundTxInputInCoinsTip(*m_node.chainman, *parent_tx);

    CMutableTransaction child_mtx;
    child_mtx.nVersion = 2;
    child_mtx.vin.resize(1);
    child_mtx.vin[0].prevout = COutPoint(parent_tx->GetId(), 0);
    child_mtx.vin[0].scriptSig = CScript() << ToByteVector(parent_redeem);
    child_mtx.vout.resize(1);
    child_mtx.vout[0].nValue = 40000 * SATOSHI;
    child_mtx.vout[0].scriptPubKey = parent_spk;
    CTransactionRef child_tx = MakeTransactionRef(std::move(child_mtx));

    // Put child_tx before parent_tx!
    valid_batch.push_back(child_tx);
    valid_batch.push_back(parent_tx);
    BOOST_REQUIRE_EQUAL(valid_batch.size(), 20U);

    // 1a. Unsolicited SHORTTX from a non-HB peer without a preceding GETSHORTTX
    //     MUST be dropped with 0 transactions admitted to the mempool!
    {
        ShortTxResponse resp;
        resp.scope = static_cast<uint8_t>(ReconScope::LIVE_MEMPOOL);
        resp.context_id = uint256::ZERO;
        resp.txs = valid_batch;
        DataStream ss{};
        ss << resp;
        peerman->ProcessMessage(config, peer_from, NetMsgType::SHORTTX, ss,
                                cur_time, interrupt);
    }
    BOOST_CHECK_EQUAL(v2_handler->GetStats().unsolicited_shorttx_dropped, 1U);
    for (const auto &tx : valid_batch) {
        BOOST_CHECK(!m_node.mempool->exists(tx->GetId()));
    }

    // 1b. Solicited SHORTTX (matching a recorded GETSHORTTX request) for the
    //     first 2 transactions is accepted and batch-admitted!
    cur_time += 2'000'000us;
    {
        const auto [k0, k1] = DeriveReconSipHashKey(
            ReconScope::LIVE_MEMPOOL, uint256::ZERO, 0);
        v2_handler->RecordPendingShortTxRequest(
            peer_from.GetId(), ReconScope::LIVE_MEMPOOL, uint256::ZERO, k0, k1,
            {ComputeMerklixShortId(k0, k1, valid_batch[0]->GetId()),
             ComputeMerklixShortId(k0, k1, valid_batch[1]->GetId())});

        ShortTxResponse solicited_resp;
        solicited_resp.scope = static_cast<uint8_t>(ReconScope::LIVE_MEMPOOL);
        solicited_resp.context_id = uint256::ZERO;
        solicited_resp.txs = {valid_batch[0], valid_batch[1], valid_batch[2]};
        DataStream ss{};
        ss << solicited_resp;
        peerman->ProcessMessage(config, peer_from, NetMsgType::SHORTTX, ss,
                                cur_time, interrupt);
    }
    BOOST_CHECK(m_node.mempool->exists(valid_batch[0]->GetId()));
    BOOST_CHECK(m_node.mempool->exists(valid_batch[1]->GetId()));
    // A peer without high-bandwidth opt-in cannot smuggle an unrequested body
    // beside the two bodies we solicited.
    BOOST_CHECK(!m_node.mempool->exists(valid_batch[2]->GetId()));

    // 1c. Preemptive SHORTTX from an opted-in High-Bandwidth peer
    //     (m_bip152_highbandwidth_to = true or SetHighBandwidthShortTxPeer) is
    //     accepted and batch-ingested without needing a prior GETSHORTTX!
    cur_time += 2'000'000us;
    peer_from.m_bip152_highbandwidth_to = true;
    v2_handler->SetHighBandwidthShortTxPeer(peer_from.GetId(), true);
    BOOST_CHECK(v2_handler->IsHighBandwidthShortTxPeer(peer_from.GetId()));
    // A delayed solicited response and a proactive body batch can overlap.
    // One pending match must not discard the other bodies we opted to accept.
    {
        const auto [k0, k1] = DeriveReconSipHashKey(
            ReconScope::LIVE_MEMPOOL, uint256::ZERO, 0);
        v2_handler->RecordPendingShortTxRequest(
            peer_from.GetId(), ReconScope::LIVE_MEMPOOL, uint256::ZERO, k0, k1,
            {ComputeMerklixShortId(k0, k1, valid_batch[0]->GetId())});
    }
    {
        ShortTxResponse resp;
        resp.scope = static_cast<uint8_t>(ReconScope::LIVE_MEMPOOL);
        resp.context_id = uint256::ZERO;
        resp.txs = valid_batch;
        DataStream ss{};
        ss << resp;
        peerman->ProcessMessage(config, peer_from, NetMsgType::SHORTTX, ss,
                                cur_time, interrupt);
    }

    // All 20 transactions must be admitted through ordinary transaction validation.
    for (const auto &tx : valid_batch) {
        BOOST_CHECK(m_node.mempool->exists(tx->GetId()));
    }

    // 2. Verify outgoing relay:
    //    - peer_from (originator) receives neither SHORTTX nor INV
    //    - peer_to (normal low-bandwidth peer) receives INV (and NEVER
    //    unsolicited SHORTTX)
    //    - peer_hb (opted-in High-Bandwidth peer) receives preemptive SHORTTX!
    // Every peer announces at the next relay tick.
    tick.Set(std::chrono::milliseconds{9'000'100});
    BOOST_CHECK(peerman->SendMessages(config, &peer_from));
    BOOST_CHECK(peerman->SendMessages(config, &peer_hb));
    SetMockTime(base_time + 60);
    BOOST_CHECK(peerman->SendMessages(config, &peer_to));

    {
        V1TransportDeserializer deser_from(config, peer_from.GetId());
        LOCK(peer_from.cs_vSend);
        for (const auto &chunk : peer_from.vSendMsg) {
            Span<const uint8_t> sp{chunk};
            while (!sp.empty()) {
                const int ret = deser_from.Read(config, sp);
                BOOST_REQUIRE_GE(ret, 0);
                if (deser_from.Complete()) {
                    bool reject = false;
                    CNetMessage msg = deser_from.GetMessage(0us, reject);
                    BOOST_CHECK(!reject);
                    BOOST_CHECK_NE(msg.m_type, NetMsgType::SHORTTX);
                    BOOST_CHECK_NE(msg.m_type, NetMsgType::INV);
                }
            }
        }
    }

    size_t inv_relayed_to_normal_peer = 0;
    {
        V1TransportDeserializer deser_to(config, peer_to.GetId());
        LOCK(peer_to.cs_vSend);
        for (const auto &chunk : peer_to.vSendMsg) {
            Span<const uint8_t> sp{chunk};
            while (!sp.empty()) {
                const int ret = deser_to.Read(config, sp);
                BOOST_REQUIRE_GE(ret, 0);
                if (deser_to.Complete()) {
                    bool reject = false;
                    CNetMessage msg = deser_to.GetMessage(0us, reject);
                    BOOST_CHECK(!reject);
                    BOOST_CHECK_NE(msg.m_type, NetMsgType::SHORTTX);
                    if (msg.m_type == NetMsgType::INV) {
                        std::vector<CInv> vInv;
                        msg.m_recv >> vInv;
                        inv_relayed_to_normal_peer += vInv.size();
                    }
                }
            }
        }
    }
    BOOST_CHECK_EQUAL(inv_relayed_to_normal_peer, 20U);

    size_t shorttx_relayed_to_hb_peer = 0;
    {
        V1TransportDeserializer deser_hb(config, peer_hb.GetId());
        LOCK(peer_hb.cs_vSend);
        for (const auto &chunk : peer_hb.vSendMsg) {
            Span<const uint8_t> sp{chunk};
            while (!sp.empty()) {
                const int ret = deser_hb.Read(config, sp);
                BOOST_REQUIRE_GE(ret, 0);
                if (deser_hb.Complete()) {
                    bool reject = false;
                    CNetMessage msg = deser_hb.GetMessage(0us, reject);
                    BOOST_CHECK(!reject);
                    if (msg.m_type == NetMsgType::SHORTTX) {
                        ShortTxResponse relayed_resp;
                        msg.m_recv >> relayed_resp;
                        shorttx_relayed_to_hb_peer += relayed_resp.txs.size();
                    }
                }
            }
        }
    }
    BOOST_CHECK_EQUAL(shorttx_relayed_to_hb_peer, 20U);

    // 3. Partial-valid fallback when one transaction in a SHORTTX batch is invalid:
    cur_time += 2'000'000us;
    CTransactionRef mixed_valid_1 = MakeNonCoinbaseTx(rng, 0x41);
    CTransactionRef mixed_valid_2 = MakeNonCoinbaseTx(rng, 0x42);
    CTransactionRef mixed_invalid = MakeNonCoinbaseTx(rng, 0x43); // unfunded!
    BOOST_REQUIRE(mixed_valid_1 && mixed_valid_2 && mixed_invalid);
    FundTxInputInCoinsTip(*m_node.chainman, *mixed_valid_1);
    FundTxInputInCoinsTip(*m_node.chainman, *mixed_valid_2);

    const uint256 mixed_ctx = rng.rand256();
    {
        ShortTxResponse mixed_resp;
        mixed_resp.scope = static_cast<uint8_t>(ReconScope::BLOCK_RECON);
        mixed_resp.context_id = mixed_ctx;
        mixed_resp.txs = {mixed_valid_1, mixed_invalid, mixed_valid_2};
        DataStream ss{};
        ss << mixed_resp;
        peerman->ProcessMessage(config, peer_from, NetMsgType::SHORTTX, ss,
                                cur_time, interrupt);
    }

    BOOST_CHECK(m_node.mempool->exists(mixed_valid_1->GetId()));
    BOOST_CHECK(m_node.mempool->exists(mixed_valid_2->GetId()));
    BOOST_CHECK(!m_node.mempool->exists(mixed_invalid->GetId()));

    const auto scoped_mixed =
        v2_handler->GetScopedTransactions(ReconScope::BLOCK_RECON, mixed_ctx);
    BOOST_CHECK_EQUAL(scoped_mixed.size(), 2U);

    SetMockTime(0);
    peerman->FinalizeNode(config, peer_from);
    peerman->FinalizeNode(config, peer_to);
    peerman->FinalizeNode(config, peer_hb);
}

BOOST_AUTO_TEST_CASE(high_bandwidth_sealedheader_push_and_peer_cleanup) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    SetMockTime(
        WITH_LOCK(cs_main, return m_node.chainman->ActiveTip()->GetBlockTime()));

    const Config &config = m_node.chainman->GetConfig();
    const Consensus::Params &params = config.GetChainParams().GetConsensus();

    auto connman = std::make_unique<ConnmanTestMsg>(config, 0x3570, 0x3570,
                                                    *m_node.addrman);
    PeerManager::Options peer_opts;
    peer_opts.deterministic_rng = true;
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr,
                                     *m_node.chainman, *m_node.mempool,
                                     /*avalanche=*/nullptr, peer_opts);

    CConnman::Options options;
    options.m_msgproc = {peerman.get()};
    options.m_max_outbound_full_relay = 8;
    connman->Init(options);
    m_node.validation_signals->RegisterValidationInterface(peerman.get());

    V2PeerProtocolHandler *v2_handler = peerman->GetV2ProtocolHandler();
    BOOST_REQUIRE(v2_handler != nullptr);

    CAddress addr_sender(MakeTestIp(0xa0b0c050), NODE_NONE);
    CNode *peer_sender = new CNode(
        /*id=*/920, /*sock=*/nullptr, addr_sender,
        /*nKeyedNetGroupIn=*/0, /*nLocalHostNonceIn=*/0,
        /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
        ConnectionType::OUTBOUND_FULL_RELAY, /*inbound_onion=*/false);
    connman->Handshake(*peer_sender, /*successfully_connected=*/true,
                       ServiceFlags(NODE_NETWORK), ServiceFlags(NODE_NETWORK),
                       PROTOCOL_VERSION, /*relay_txs=*/true);

    CAddress addr_hb(MakeTestIp(0xa0b0c051), NODE_NONE);
    CNode *peer_hb = new CNode(
        /*id=*/921, /*sock=*/nullptr, addr_hb,
        /*nKeyedNetGroupIn=*/1, /*nLocalHostNonceIn=*/0,
        /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
        ConnectionType::OUTBOUND_FULL_RELAY, /*inbound_onion=*/false);
    connman->Handshake(*peer_hb, /*successfully_connected=*/true,
                       ServiceFlags(NODE_NETWORK), ServiceFlags(NODE_NETWORK),
                       PROTOCOL_VERSION, /*relay_txs=*/true);

    CAddress addr_normal(MakeTestIp(0xa0b0c052), NODE_NONE);
    CNode *peer_normal = new CNode(
        /*id=*/922, /*sock=*/nullptr, addr_normal,
        /*nKeyedNetGroupIn=*/2, /*nLocalHostNonceIn=*/0,
        /*nLocalExtraEntropyIn=*/0, CAddress(), /*pszDest=*/"",
        ConnectionType::OUTBOUND_FULL_RELAY, /*inbound_onion=*/false);
    connman->Handshake(*peer_normal, /*successfully_connected=*/true,
                       ServiceFlags(NODE_NETWORK), ServiceFlags(NODE_NETWORK),
                       PROTOCOL_VERSION, /*relay_txs=*/true);

    for (CNode *p : {peer_sender, peer_hb, peer_normal}) {
        BOOST_CHECK(peerman->SendMessages(config, p));
        LOCK(p->cs_vSend);
        p->vSendMsg.clear();
    }
    for (CNode *p : {peer_sender, peer_hb, peer_normal}) {
        connman->AddTestNode(*p);
    }

    // Opt in peer_sender and peer_hb as high-bandwidth V2 peers; keep peer_normal
    // as a standard low-bandwidth peer.
    peer_sender->m_bip152_highbandwidth_to = true;
    peer_sender->m_bip152_highbandwidth_from = true;
    v2_handler->SetHighBandwidthShortTxPeer(peer_sender->GetId(), true);

    peer_hb->m_bip152_highbandwidth_to = true;
    peer_hb->m_bip152_highbandwidth_from = true;
    v2_handler->SetHighBandwidthShortTxPeer(peer_hb->GetId(), true);

    peer_normal->m_bip152_highbandwidth_to = false;
    peer_normal->m_bip152_highbandwidth_from = false;
    v2_handler->SetHighBandwidthShortTxPeer(peer_normal->GetId(), false);

    // 1. Build a valid V2 block containing tx1 on top of the current tip, and
    //    add tx1 to the mempool WITHOUT manually calling SyncMerklixOverlayToTip
    //    first (simulating a peer whose tip just advanced and received mempool
    //    transactions via SHORTTX).
    FastRandomContext rng(uint256{99});
    CTransactionRef tx1 = MakeNonCoinbaseTx(rng, 0x51);
    BOOST_REQUIRE(tx1 != nullptr);
    FundTxInputInCoinsTip(*m_node.chainman, *tx1);

    std::shared_ptr<CBlock> v2_block =
        PrepareBlock(config, m_node, CScript() << OP_TRUE);
    v2_block->vtx.push_back(tx1);
    {
        LOCK(cs_main);
        v2_block->hashMerkleRoot = BlockMerkleRoot(*v2_block);
    }
    while (!CheckProofOfWork(v2_block->GetHash(), v2_block->nBits, params)) {
        ++v2_block->nNonce;
    }

    {
        TestMemPoolEntryHelper entry;
        LOCK2(cs_main, m_node.mempool->cs);
        m_node.mempool->addUnchecked(entry.Fee(1000 * SATOSHI).FromTx(tx1));
    }

    // 2. Deliver SEALEDHEADER from peer_sender.
    //    Verify:
    //    - MatchCandidateOverlay re-anchors the speculative overlay to the active
    //      tip and hits the O(1) ComputeV2StateRootFromOverlay fast path
    //      (sealedheader_overlay_fastpath increments).
    //    - peer_sender is recorded as knowing v2_block->GetHash() and does NOT
    //      receive a redundant SEALEDHEADER or CMPCTBLOCK back.
    //    - peer_hb receives a direct SEALEDHEADER push via NewPoWValidBlock!
    const auto stats_before = v2_handler->GetStats();
    std::atomic<bool> interrupt{false};
    std::chrono::microseconds cur_time{100'000};
    {
        SealedHeader sealed(*v2_block);
        DataStream ss{};
        ss << sealed;
        peerman->ProcessMessage(config, *peer_sender, NetMsgType::SEALEDHEADER,
                                ss, cur_time, interrupt);
    }

    const auto stats_after = v2_handler->GetStats();
    BOOST_CHECK_EQUAL(stats_after.sealedheader_received,
                      stats_before.sealedheader_received + 1);
    BOOST_CHECK_EQUAL(stats_after.sealedheader_invalid,
                      stats_before.sealedheader_invalid);
    BOOST_CHECK_EQUAL(stats_after.sealedheader_rejected,
                      stats_before.sealedheader_rejected);
    BOOST_CHECK_EQUAL(stats_after.sealedheader_fallback_getdata,
                      stats_before.sealedheader_fallback_getdata);
    BOOST_CHECK_EQUAL(stats_after.sealedheader_reconstructed,
                      stats_before.sealedheader_reconstructed + 1);
    BOOST_CHECK_EQUAL(stats_after.sealedheader_overlay_fastpath,
                      stats_before.sealedheader_overlay_fastpath + 1);
    BOOST_CHECK(
        v2_handler->PeerKnowsBlock(peer_sender->GetId(), v2_block->GetHash()));

    // Verify peer_sender received NO redundant block announcement for v2_block.
    {
        V1TransportDeserializer deser_sender(config, peer_sender->GetId());
        LOCK(peer_sender->cs_vSend);
        for (const auto &chunk : peer_sender->vSendMsg) {
            Span<const uint8_t> sp{chunk};
            while (!sp.empty()) {
                const int ret = deser_sender.Read(config, sp);
                BOOST_REQUIRE_GE(ret, 0);
                if (deser_sender.Complete()) {
                    bool reject = false;
                    CNetMessage msg = deser_sender.GetMessage(0us, reject);
                    BOOST_CHECK(!reject);
                    BOOST_CHECK_NE(msg.m_type, NetMsgType::SEALEDHEADER);
                    BOOST_CHECK_NE(msg.m_type, NetMsgType::CMPCTBLOCK);
                }
            }
        }
    }

    // Verify peer_hb received SEALEDHEADER directly during NewPoWValidBlock!
    size_t hb_sealedheader_count = 0;
    {
        V1TransportDeserializer deser_hb(config, peer_hb->GetId());
        LOCK(peer_hb->cs_vSend);
        for (const auto &chunk : peer_hb->vSendMsg) {
            Span<const uint8_t> sp{chunk};
            while (!sp.empty()) {
                const int ret = deser_hb.Read(config, sp);
                BOOST_REQUIRE_GE(ret, 0);
                if (deser_hb.Complete()) {
                    bool reject = false;
                    CNetMessage msg = deser_hb.GetMessage(0us, reject);
                    BOOST_CHECK(!reject);
                    if (msg.m_type == NetMsgType::SEALEDHEADER) {
                        SealedHeader pushed_sh;
                        msg.m_recv >> pushed_sh;
                        BOOST_CHECK_EQUAL(pushed_sh.header.GetHash(),
                                          v2_block->GetHash());
                        ++hb_sealedheader_count;
                    }
                }
            }
        }
    }
    BOOST_CHECK_EQUAL(hb_sealedheader_count, 1U);

    // 3. Verify duplicate SEALEDHEADER from peer_hb for an already-connected
    //    block is a no-op (no fallback GETDATA(MSG_CMPCT_BLOCK) emitted).
    {
        LOCK(peer_hb->cs_vSend);
        peer_hb->vSendMsg.clear();
    }
    {
        SealedHeader dup_sealed(*v2_block);
        DataStream ss{};
        ss << dup_sealed;
        peerman->ProcessMessage(config, *peer_hb, NetMsgType::SEALEDHEADER, ss,
                                cur_time + 100us, interrupt);
    }
    BOOST_CHECK_EQUAL(v2_handler->GetStats().sealedheader_fallback_getdata,
                      stats_after.sealedheader_fallback_getdata);

    // 4. Verify FinalizeNode calls RemovePeer and cleans up all per-peer state.
    {
        const auto [k0, k1] =
            DeriveReconSipHashKey(ReconScope::LIVE_MEMPOOL, uint256::ZERO, 0);
        v2_handler->RecordPendingShortTxRequest(
            peer_hb->GetId(), ReconScope::LIVE_MEMPOOL, uint256::ZERO, k0, k1,
            {111ULL, 222ULL});
    }
    BOOST_CHECK(v2_handler->HasPendingShortTxRequests(peer_hb->GetId()));
    BOOST_CHECK(v2_handler->IsHighBandwidthShortTxPeer(peer_hb->GetId()));
    BOOST_CHECK(
        v2_handler->PeerKnowsBlock(peer_hb->GetId(), v2_block->GetHash()));

    // Raw callback registration does not own peerman or wait for an active
    // callback on unregister. Drain after producers stop, before destruction.
    AssertLockNotHeld(cs_main);
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
    m_node.validation_signals->UnregisterValidationInterface(peerman.get());
    SetMockTime(0);
    peerman->FinalizeNode(config, *peer_sender);
    peerman->FinalizeNode(config, *peer_hb);
    peerman->FinalizeNode(config, *peer_normal);

    BOOST_CHECK(!v2_handler->IsHighBandwidthShortTxPeer(peer_hb->GetId()));
    BOOST_CHECK(!v2_handler->HasPendingShortTxRequests(peer_hb->GetId()));
    BOOST_CHECK(
        !v2_handler->PeerKnowsBlock(peer_hb->GetId(), v2_block->GetHash()));

    connman->ClearTestNodes();
}

BOOST_AUTO_TEST_CASE(root_count_one_xor_requires_bucket_proof) {
    LOCK(NetEventsInterface::g_msgproc_mutex);
    const auto &config{m_node.chainman->GetConfig()};
    auto connman = std::make_unique<ConnmanTestMsg>(
        config, 0x95, 0x96, *m_node.addrman);
    PeerManager::Options opts;
    auto peerman = PeerManager::make(*connman, *m_node.addrman, nullptr,
        *m_node.chainman, *m_node.mempool, nullptr, opts);
    V2PeerProtocolHandler local(*m_node.chainman, *m_node.mempool,
                                *connman, *peerman);
    V2PeerProtocolHandler remote(*m_node.chainman, *m_node.mempool,
                                 *connman, *peerman);
    FastRandomContext rng{uint256{0x95}};
    const uint256 context{rng.rand256()};
    const auto [k0, k1]{DeriveReconSipHashKey(ReconScope::BLOCK_RECON, context)};
    std::vector<CTransactionRef> locals, remotes;
    for (int i = 0; i < 5; ++i) {
        const auto tx{MakeNonCoinbaseTx(rng, 0x59)};
        BOOST_REQUIRE(tx);
        (i < 2 ? locals : remotes).push_back(tx);
    }
    local.SetScopedTransactions(ReconScope::BLOCK_RECON, context, locals);
    remote.SetScopedTransactions(ReconScope::BLOCK_RECON, context, remotes);
    const auto theirs{remote.BuildSyncSummary(ReconScope::BLOCK_RECON, context)};
    const auto ours{local.BuildSyncSummary(ReconScope::BLOCK_RECON, context)};
    BOOST_REQUIRE_EQUAL(theirs.buckets[5].count, 3U);
    BOOST_REQUIRE_EQUAL(ours.buckets[5].count, 2U);
    const auto hint{theirs.buckets[5].xor_short_id ^ ours.buckets[5].xor_short_id};
    BOOST_REQUIRE(std::none_of(remotes.begin(), remotes.end(), [&](const auto &tx) {
        return ComputeMerklixShortId(k0, k1, tx->GetId()) == hint;
    }));
    const auto diff{local.DiffSyncSummary(theirs)};
    BOOST_CHECK(!diff.root_matched);
    BOOST_CHECK_MESSAGE((diff.mismatched_bucket_mask & (1U << 5)) != 0,
        "a nonresolving count-one XOR hint must not terminate bucket recovery");
}

BOOST_AUTO_TEST_SUITE_END()
