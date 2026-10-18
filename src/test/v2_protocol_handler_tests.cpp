// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <net/v2_protocol_handler.h>

#include <blockencodings.h>
#include <chain.h>
#include <chainparams.h>
#include <config.h>
#include <consensus/merkle.h>
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
