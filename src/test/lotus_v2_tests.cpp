// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <key.h>
#include <lotus_v2/commitment.h>
#include <lotus_v2/disk_state.h>
#include <lotus_v2/fast_sync.h>
#include <lotus_v2/header.h>
#include <lotus_v2/incremental_utxo.h>
#include <lotus_v2/mempool_overlay.h>
#include <lotus_v2/monetary.h>
#include <lotus_v2/ordinary_validation.h>
#include <lotus_v2/set_reconciliation.h>
#include <lotus_v2/signing.h>
#include <lotus_v2/sparse_state.h>
#include <lotus_v2/tagged_hash.h>
#include <lotus_v2/transaction.h>
#include <lotus_v2/vendor/blake3/blake3.h>
#include <lotus_v2/vendor/blake3/blake3_impl.h>
#include <lotus_v2/vm.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <undo.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

enum class Blake3Mode {
    Regular,
    Keyed,
    DeriveKey,
};

struct PortableOutput {
    uint32_t input_cv[8];
    uint64_t counter;
    uint8_t block[BLAKE3_BLOCK_LEN];
    uint8_t block_len;
    uint8_t flags;
};

static void PortableCompressChunk(const uint8_t *chunk, size_t chunk_len,
                                  const uint32_t key[8], uint64_t chunk_counter,
                                  uint8_t flags, PortableOutput &out) {
    uint32_t cv[8];
    std::memcpy(cv, key, BLAKE3_KEY_LEN);
    uint8_t blocks_compressed = 0;

    while (chunk_len > BLAKE3_BLOCK_LEN) {
        const uint8_t start_flag = (blocks_compressed == 0) ? CHUNK_START : 0;
        blake3_compress_in_place_portable(cv, chunk, BLAKE3_BLOCK_LEN,
                                          chunk_counter, flags | start_flag);
        chunk += BLAKE3_BLOCK_LEN;
        chunk_len -= BLAKE3_BLOCK_LEN;
        blocks_compressed += 1;
    }

    std::memcpy(out.input_cv, cv, 32);
    out.counter = chunk_counter;
    std::memset(out.block, 0, BLAKE3_BLOCK_LEN);
    if (chunk_len > 0) {
        std::memcpy(out.block, chunk, chunk_len);
    }
    out.block_len = static_cast<uint8_t>(chunk_len);
    const uint8_t start_flag = (blocks_compressed == 0) ? CHUNK_START : 0;
    out.flags = flags | start_flag | CHUNK_END;
}

static void PortableOutputChainingValue(const PortableOutput &out,
                                        uint8_t cv_bytes[32]) {
    uint32_t cv_words[8];
    std::memcpy(cv_words, out.input_cv, 32);
    blake3_compress_in_place_portable(cv_words, out.block, out.block_len,
                                      out.counter, out.flags);
    store_cv_words(cv_bytes, cv_words);
}

static void PortableOutputRootBytes(const PortableOutput &out, uint8_t *dest,
                                    size_t dest_len) {
    uint64_t output_block_counter = 0;
    while (dest_len > 0) {
        uint8_t wide_buf[64];
        blake3_compress_xof_portable(out.input_cv, out.block, out.block_len,
                                     output_block_counter, out.flags | ROOT,
                                     wide_buf);
        const size_t take = (dest_len < 64) ? dest_len : 64;
        std::memcpy(dest, wide_buf, take);
        dest += take;
        dest_len -= take;
        output_block_counter += 1;
    }
}

static PortableOutput PortableSubtreeOutput(const uint8_t *input,
                                            size_t input_len,
                                            const uint32_t key[8],
                                            uint64_t chunk_counter,
                                            uint8_t flags) {
    if (input_len <= BLAKE3_CHUNK_LEN) {
        PortableOutput out{};
        PortableCompressChunk(input, input_len, key, chunk_counter, flags, out);
        return out;
    }
    const size_t full_chunks = (input_len - 1) / BLAKE3_CHUNK_LEN;
    const size_t left_chunks = round_down_to_power_of_2(full_chunks);
    const size_t left_len = left_chunks * BLAKE3_CHUNK_LEN;

    const PortableOutput left_out =
        PortableSubtreeOutput(input, left_len, key, chunk_counter, flags);
    const PortableOutput right_out = PortableSubtreeOutput(
        input + left_len, input_len - left_len, key,
        chunk_counter + left_chunks, flags);

    PortableOutput parent{};
    std::memcpy(parent.input_cv, key, 32);
    parent.counter = 0;
    PortableOutputChainingValue(left_out, parent.block);
    PortableOutputChainingValue(right_out, parent.block + 32);
    parent.block_len = BLAKE3_BLOCK_LEN;
    parent.flags = flags | PARENT;
    return parent;
}

// Reference BLAKE3 evaluation that exclusively calls *_portable C primitives.
static void PortableBlake3Hash(const uint8_t *input, size_t input_len,
                               Blake3Mode mode,
                               const uint8_t keyed_key[BLAKE3_KEY_LEN],
                               const char *derive_context, uint8_t *out,
                               size_t out_len) {
    uint32_t key_words[8];
    uint8_t flags = 0;

    if (mode == Blake3Mode::Regular) {
        std::memcpy(key_words, IV, 32);
        flags = 0;
    } else if (mode == Blake3Mode::Keyed) {
        load_key_words(keyed_key, key_words);
        flags = KEYED_HASH;
    } else {
        const size_t ctx_len = std::strlen(derive_context);
        const PortableOutput ctx_out = PortableSubtreeOutput(
            reinterpret_cast<const uint8_t *>(derive_context), ctx_len, IV, 0,
            DERIVE_KEY_CONTEXT);
        uint8_t context_key[BLAKE3_KEY_LEN];
        PortableOutputRootBytes(ctx_out, context_key, BLAKE3_KEY_LEN);
        load_key_words(context_key, key_words);
        flags = DERIVE_KEY_MATERIAL;
    }

    const PortableOutput root_out =
        PortableSubtreeOutput(input, input_len, key_words, 0, flags);
    PortableOutputRootBytes(root_out, out, out_len);
}

static void SimdBlake3Hash(const uint8_t *input, size_t input_len,
                           Blake3Mode mode,
                           const uint8_t keyed_key[BLAKE3_KEY_LEN],
                           const char *derive_context, uint8_t *out,
                           size_t out_len, size_t stream_step = 0) {
    blake3_hasher hasher;
    if (mode == Blake3Mode::Regular) {
        blake3_hasher_init(&hasher);
    } else if (mode == Blake3Mode::Keyed) {
        blake3_hasher_init_keyed(&hasher, keyed_key);
    } else {
        blake3_hasher_init_derive_key(&hasher, derive_context);
    }

    if (stream_step == 0 || input_len == 0) {
        blake3_hasher_update(&hasher, input, input_len);
    } else {
        size_t pos = 0;
        while (pos < input_len) {
            const size_t n =
                (input_len - pos < stream_step) ? (input_len - pos) : stream_step;
            blake3_hasher_update(&hasher, input + pos, n);
            pos += n;
        }
    }
    blake3_hasher_finalize(&hasher, out, out_len);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(lotus_v2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(end_to_end_bulk_preconsensus_and_overlay_commit) {
    // 1. Initialize DiskStateStore at Genesis + Block 1 with 20 spendable UTXOs
    const fs::path db_dir = m_args.GetDataDirNet() / "v2_e2e_overlay_db";
    fs::create_directories(db_dir);

    lotus::v2::DiskStateOptions opts{};
    opts.identity[0] = 0x11;
    opts.profile_digest[0] = 0x22;

    lotus::v2::DiskStateMetadata gen_meta{};
    gen_meta.tip[0] = 0x01;

    lotus::v2::DiskStateStore store;
    lotus::v2::DiskStateError err;
    BOOST_REQUIRE_MESSAGE(
        lotus::v2::DiskStateStore::Open(fs::PathToString(db_dir), opts,
                                        gen_meta, store, err),
        err.message);

    lotus::v2::DiskStateMetadata b1_meta{};
    b1_meta.tip[0] = 0x11;
    std::shared_ptr<const lotus::v2::SmtNode> base_utxo_root;
    std::vector<lotus::v2::Coin> b1_coins;
    {
        lotus::v2::DiskStateTransaction txn;
        BOOST_REQUIRE_MESSAGE(store.Begin(txn, err), err.message);
        for (uint32_t i = 0; i < 20; ++i) {
            lotus::v2::Hash txid{};
            txid[0] = 0x50;
            txid[1] = static_cast<uint8_t>(i);
            lotus::v2::Coin coin{};
            coin.outpoint = {txid, 0};
            coin.output.value = 100000;
            coin.output.branches = {lotus::v2::Hash32{1}};
            coin.output.paths = {{0}};
            coin.creation_height = 1;
            coin.creation_parent_mtp = 1000;
            coin.coinbase = false;
            BOOST_REQUIRE_MESSAGE(txn.Insert(coin, err), err.message);
            lotus::v2::SmtInsert(base_utxo_root, coin);
            b1_coins.push_back(coin);
        }
        BOOST_REQUIRE_MESSAGE(txn.Commit(b1_meta, err), err.message);
    }
    BOOST_CHECK(store.Root() == lotus::v2::SmtRoot(base_utxo_root));

    // 2. Simulate two nodes A and B building epoch overlays on top of Block 1,
    //    where Node A has all 10 transactions and Node B is missing 2 of them
    //    in the same syndrome bucket.
    const auto [k0, k1] = lotus::v2::DeriveEpochSipHashKey(b1_meta.tip, 1);

    lotus::v2::MerklixOverlayManager mgr_a;
    mgr_a.ResetToTip(b1_meta.tip, base_utxo_root,
                     lotus::v2::GetInitialV2MonetaryState(), 2, 1120);

    lotus::v2::BucketSyndrome syn_a{};
    lotus::v2::BucketSyndrome syn_b{};
    std::vector<uint64_t> missing_short_ids;

    for (uint32_t i = 0; i < 10; ++i) {
        lotus::v2::Hash txid{}, txhash{};
        txid[0] = 0x60;
        txid[1] = static_cast<uint8_t>(i);
        txhash = txid;

        lotus::v2::Coin out_coin{};
        out_coin.outpoint = {txid, 0};
        out_coin.output.value = 95000;
        out_coin.output.branches = {lotus::v2::Hash32{1}};
        out_coin.output.paths = {{0}};
        out_coin.creation_height = 2;
        out_coin.creation_parent_mtp = 1120;

        BOOST_REQUIRE(mgr_a.AddTransaction(
            txid, txhash, 250, {b1_coins[i].outpoint}, {out_coin}, 5000, 1));

        const uint64_t sid = lotus::v2::ComputeShortTxId(k0, k1, txid);
        syn_a.Add(sid);
        if (i != 3 && i != 7) {
            syn_b.Add(sid);
        } else {
            missing_short_ids.push_back(sid);
        }
    }
    std::sort(missing_short_ids.begin(), missing_short_ids.end());

    // 3. Reconcile Node A and Node B's bucket syndromes via GF(2^64) BCH decoding
    const lotus::v2::BucketSyndrome diff_syn =
        syn_a.SymmetricDifference(syn_b);
    const auto decoded = lotus::v2::DecodeBucketSyndrome(diff_syn);
    BOOST_REQUIRE(decoded.status == lotus::v2::ReconcileStatus::Decoded);
    BOOST_REQUIRE_EQUAL(decoded.roots.size(), 2U);
    BOOST_CHECK_EQUAL(decoded.roots[0], missing_short_ids[0]);
    BOOST_CHECK_EQUAL(decoded.roots[1], missing_short_ids[1]);

    // 4. Freeze Epoch 1 on Node A and commit finalized overlay to DiskStateStore
    const auto &frozen = mgr_a.FreezeEpochBatch();
    BOOST_CHECK_EQUAL(frozen.GetTxCount(), 10U);

    lotus::v2::DiskStateMetadata b2_meta{};
    b2_meta.tip[0] = 0x22;
    BOOST_REQUIRE_MESSAGE(
        store.CommitFinalizedOverlay(frozen, {}, b2_meta, err), err.message);
    BOOST_CHECK(store.Root() == frozen.GetUtxoRootDigest());
}

BOOST_AUTO_TEST_CASE(blake3_simd_bit_identical_to_portable) {
    const size_t simd_deg = blake3_simd_degree();
#if defined(__aarch64__) || defined(_M_ARM64)
    BOOST_CHECK_EQUAL(simd_deg, 4U);
#elif defined(__x86_64__) || defined(_M_X64)
    BOOST_CHECK_GE(simd_deg, 4U);
#else
    BOOST_CHECK_GE(simd_deg, 1U);
#endif

    // Standard BLAKE3 test key and context string from official test vectors.
    static constexpr const char *kTestKeyStr =
        "whats the Elvish word for friend";
    static constexpr const char *kTestContext =
        "BLAKE3 2019-12-27 16:29:52 test vectors context";
    uint8_t key[BLAKE3_KEY_LEN];
    std::memcpy(key, kTestKeyStr, BLAKE3_KEY_LEN);

    const std::array<size_t, 11> kTestLengths = {
        0, 1, 63, 64, 65, 134, 1023, 1024, 1025, 4096, 65536};

    std::vector<uint8_t> input_buf(65536);
    for (size_t i = 0; i < input_buf.size(); ++i) {
        input_buf[i] = static_cast<uint8_t>(i % 251);
    }

    for (size_t len : kTestLengths) {
        for (Blake3Mode mode :
             {Blake3Mode::Regular, Blake3Mode::Keyed, Blake3Mode::DeriveKey}) {
            std::array<uint8_t, 128> out_portable{};
            std::array<uint8_t, 128> out_simd_oneshot{};
            std::array<uint8_t, 128> out_simd_step1{};
            std::array<uint8_t, 128> out_simd_step63{};
            std::array<uint8_t, 128> out_simd_step1023{};

            PortableBlake3Hash(input_buf.data(), len, mode, key, kTestContext,
                               out_portable.data(), out_portable.size());
            SimdBlake3Hash(input_buf.data(), len, mode, key, kTestContext,
                           out_simd_oneshot.data(), out_simd_oneshot.size(), 0);
            SimdBlake3Hash(input_buf.data(), len, mode, key, kTestContext,
                           out_simd_step1.data(), out_simd_step1.size(), 1);
            SimdBlake3Hash(input_buf.data(), len, mode, key, kTestContext,
                           out_simd_step63.data(), out_simd_step63.size(), 63);
            SimdBlake3Hash(input_buf.data(), len, mode, key, kTestContext,
                           out_simd_step1023.data(), out_simd_step1023.size(),
                           1023);

            BOOST_CHECK_MESSAGE(
                out_simd_oneshot == out_portable,
                "SIMD one-shot mismatch vs portable at len=" << len);
            BOOST_CHECK_MESSAGE(
                out_simd_step1 == out_portable,
                "SIMD 1-byte streaming mismatch vs portable at len=" << len);
            BOOST_CHECK_MESSAGE(
                out_simd_step63 == out_portable,
                "SIMD 63-byte streaming mismatch vs portable at len=" << len);
            BOOST_CHECK_MESSAGE(
                out_simd_step1023 == out_portable,
                "SIMD 1023-byte streaming mismatch vs portable at len=" << len);
        }
    }

    // Verify official BLAKE3 test vectors for len=0 and len=1 across all 3 modes.
    std::array<uint8_t, 32> digest32{};
    SimdBlake3Hash(input_buf.data(), 0, Blake3Mode::Regular, key, kTestContext,
                   digest32.data(), digest32.size());
    BOOST_CHECK_EQUAL(
        HexStr(digest32),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");

    SimdBlake3Hash(input_buf.data(), 0, Blake3Mode::Keyed, key, kTestContext,
                   digest32.data(), digest32.size());
    BOOST_CHECK_EQUAL(
        HexStr(digest32),
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26");

    SimdBlake3Hash(input_buf.data(), 0, Blake3Mode::DeriveKey, key, kTestContext,
                   digest32.data(), digest32.size());
    BOOST_CHECK_EQUAL(
        HexStr(digest32),
        "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d");

    SimdBlake3Hash(input_buf.data(), 1, Blake3Mode::Regular, key, kTestContext,
                   digest32.data(), digest32.size());
    BOOST_CHECK_EQUAL(
        HexStr(digest32),
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213");

    // Also test blake3_hash_many directly across batch sizes 1..64.
    std::vector<const uint8_t *> chunk_ptrs(64);
    for (size_t i = 0; i < 64; ++i) {
        chunk_ptrs[i] = input_buf.data() + i * BLAKE3_CHUNK_LEN;
    }
    for (size_t num_inputs : {size_t{1}, size_t{2}, size_t{3}, size_t{4},
                              size_t{7}, size_t{8}, size_t{15}, size_t{16},
                              size_t{31}, size_t{32}, size_t{64}}) {
        std::vector<uint8_t> many_simd(num_inputs * BLAKE3_OUT_LEN);
        std::vector<uint8_t> many_port(num_inputs * BLAKE3_OUT_LEN);

        blake3_hash_many(chunk_ptrs.data(), num_inputs,
                         BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, IV, 0, true, 0,
                         CHUNK_START, CHUNK_END, many_simd.data());
        blake3_hash_many_portable(chunk_ptrs.data(), num_inputs,
                                  BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, IV, 0,
                                  true, 0, CHUNK_START, CHUNK_END,
                                  many_port.data());
        BOOST_CHECK_MESSAGE(many_simd == many_port,
                            "blake3_hash_many chunk mismatch at num_inputs="
                                << num_inputs);

        // Parent node mode (blocks = 1, increment_counter = false)
        blake3_hash_many(chunk_ptrs.data(), num_inputs, 1, IV, 0, false, PARENT,
                         0, 0, many_simd.data());
        blake3_hash_many_portable(chunk_ptrs.data(), num_inputs, 1, IV, 0,
                                  false, PARENT, 0, 0, many_port.data());
        BOOST_CHECK_MESSAGE(many_simd == many_port,
                            "blake3_hash_many parent mismatch at num_inputs="
                                << num_inputs);
    }
}

BOOST_AUTO_TEST_CASE(blake3_simd_microbenchmark) {
    constexpr size_t kBufSize = 65536;
    constexpr size_t kIterations = 256; // 16 MiB total per benchmark leg
    std::vector<uint8_t> buf(kBufSize);
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>((i * 131 + 17) & 0xff);
    }

    std::vector<const uint8_t *> chunk_ptrs(kBufSize / BLAKE3_CHUNK_LEN);
    for (size_t i = 0; i < chunk_ptrs.size(); ++i) {
        chunk_ptrs[i] = buf.data() + i * BLAKE3_CHUNK_LEN;
    }

    std::vector<uint8_t> cvs_port(chunk_ptrs.size() * BLAKE3_OUT_LEN);
    std::vector<uint8_t> cvs_simd(chunk_ptrs.size() * BLAKE3_OUT_LEN);

    const auto t0 = std::chrono::steady_clock::now();
    for (size_t iter = 0; iter < kIterations; ++iter) {
        blake3_hash_many_portable(chunk_ptrs.data(), chunk_ptrs.size(),
                                  BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, IV, iter,
                                  true, 0, CHUNK_START, CHUNK_END,
                                  cvs_port.data());
    }
    const auto t1 = std::chrono::steady_clock::now();
    for (size_t iter = 0; iter < kIterations; ++iter) {
        blake3_hash_many(chunk_ptrs.data(), chunk_ptrs.size(),
                         BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, IV, iter, true, 0,
                         CHUNK_START, CHUNK_END, cvs_simd.data());
    }
    const auto t2 = std::chrono::steady_clock::now();

    BOOST_CHECK(cvs_port == cvs_simd);

    const double port_sec =
        std::chrono::duration<double>(t1 - t0).count();
    const double simd_sec =
        std::chrono::duration<double>(t2 - t1).count();
    const double total_mib =
        static_cast<double>(kBufSize * kIterations) / (1024.0 * 1024.0);
    const double port_mibs = (port_sec > 0.0) ? (total_mib / port_sec) : 0.0;
    const double simd_mibs = (simd_sec > 0.0) ? (total_mib / simd_sec) : 0.0;
    const double speedup = (simd_sec > 0.0) ? (port_sec / simd_sec) : 1.0;

    std::array<uint8_t, 32> h_port{}, h_simd{};
    uint8_t dummy_key[32]{};
    const auto t3 = std::chrono::steady_clock::now();
    for (size_t iter = 0; iter < kIterations; ++iter) {
        buf[0] = static_cast<uint8_t>(iter);
        PortableBlake3Hash(buf.data(), buf.size(), Blake3Mode::Regular,
                           dummy_key, "", h_port.data(), h_port.size());
    }
    const auto t4 = std::chrono::steady_clock::now();
    for (size_t iter = 0; iter < kIterations; ++iter) {
        buf[0] = static_cast<uint8_t>(iter);
        SimdBlake3Hash(buf.data(), buf.size(), Blake3Mode::Regular, dummy_key,
                       "", h_simd.data(), h_simd.size());
    }
    const auto t5 = std::chrono::steady_clock::now();
    BOOST_CHECK(h_port == h_simd);

    const double full_port_sec =
        std::chrono::duration<double>(t4 - t3).count();
    const double full_simd_sec =
        std::chrono::duration<double>(t5 - t4).count();
    const double full_port_mibs =
        (full_port_sec > 0.0) ? (total_mib / full_port_sec) : 0.0;
    const double full_simd_mibs =
        (full_simd_sec > 0.0) ? (total_mib / full_simd_sec) : 0.0;
    const double full_speedup =
        (full_simd_sec > 0.0) ? (full_port_sec / full_simd_sec) : 1.0;

    BOOST_TEST_MESSAGE("BLAKE3 hash_many SIMD degree=" << blake3_simd_degree()
                       << " portable=" << port_mibs << " MiB/s"
                       << " simd=" << simd_mibs << " MiB/s"
                       << " speedup=" << speedup << "x");
    BOOST_TEST_MESSAGE("BLAKE3 64KB hasher SIMD degree=" << blake3_simd_degree()
                       << " portable=" << full_port_mibs << " MiB/s"
                       << " simd=" << full_simd_mibs << " MiB/s"
                       << " speedup=" << full_speedup << "x");
}

// These integration fixtures must create native coins before measuring or
// testing native validation. Legacy signing helpers cannot spend native
// outputs.
static std::vector<uint8_t> NativeBenchmarkProgram() {
    auto program = ParseHex(
        "20f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9bb");
    return program;
}

static CMutableTransaction
NativeBenchmarkSpend(const CTransaction &previous, uint32_t index,
                     const std::vector<Amount> &values, uint8_t mode = 0) {
    using namespace lotus::v2;
    const auto program = NativeBenchmarkProgram();
    CMutableTransaction tx;
    tx.nVersion = 7;
    tx.nV2Lock = 0;
    CTxIn input(COutPoint(previous.GetId(), index));
    input.nFlags = 1;
    input.nPathIndex = 0;
    BranchWitness witness;
    witness.script = program;
    input.vWitnesses = {witness};
    tx.vin.push_back(std::move(input));
    for (Amount value : values) {
        Output output;
        output.value = value / SATOSHI;
        output.branches = {BranchLeaf(program)};
        output.paths = {{0}};
        tx.vout.push_back(CTxOut::FromV2Output(output));
    }
    PreparedSigningContext prepared;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        PrepareSigningContext(
            tx.ToV2Transaction(), DefaultTxProfile, GetActiveV2ChainId(),
            {previous.vout[index].ToV2Output()}, prepared, error),
        error);
    lotus::v2::Hash message{};
    BOOST_REQUIRE_MESSAGE(
        SigningMessage(prepared, 0, 0, mode, std::nullopt, message, error),
        error);
    std::array<uint8_t, 32> secret{}, aux{};
    secret[31] = 3;
    std::vector<uint8_t> signature;
    BOOST_REQUIRE_MESSAGE(
        SignBip340Message(secret, message, mode, aux, signature, error), error);
    tx.vin[0].vWitnesses[0].arguments = {std::move(signature)};
    return tx;
}

BOOST_FIXTURE_TEST_CASE(v2_kernel_throughput_benchmark, TestChain100Setup) {
    const unsigned int hw_threads =
        std::max(1U, std::thread::hardware_concurrency());

    // =========================================================================
    // 1. BLAKE3 NEON SIMD Hashing (Single-Core & Multi-Core)
    // =========================================================================
    constexpr size_t kChunkCount = 64;
    constexpr size_t kBufSize = kChunkCount * BLAKE3_CHUNK_LEN; // 64 KiB
    constexpr size_t kItersPerThread = 512; // 32 MiB per thread
    std::vector<uint8_t> buf(kBufSize);
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>((i * 131 + 17) & 0xff);
    }
    std::vector<const uint8_t *> chunk_ptrs(kChunkCount);
    for (size_t i = 0; i < kChunkCount; ++i) {
        chunk_ptrs[i] = buf.data() + i * BLAKE3_CHUNK_LEN;
    }

    // 1a. Single-core blake3_hash_many (1KB chunks)
    std::vector<uint8_t> cvs_sc(kChunkCount * BLAKE3_OUT_LEN);
    const auto b3_sc_t0 = std::chrono::steady_clock::now();
    for (size_t iter = 0; iter < kItersPerThread; ++iter) {
        blake3_hash_many(chunk_ptrs.data(), kChunkCount,
                         BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, IV, iter, true, 0,
                         CHUNK_START, CHUNK_END, cvs_sc.data());
    }
    const auto b3_sc_t1 = std::chrono::steady_clock::now();
    const double b3_sc_sec =
        std::chrono::duration<double>(b3_sc_t1 - b3_sc_t0).count();
    const double b3_sc_mb =
        static_cast<double>(kBufSize * kItersPerThread) / (1000.0 * 1000.0);
    const double b3_sc_mbs = b3_sc_mb / b3_sc_sec;
    const double b3_sc_chunk_hps =
        static_cast<double>(kChunkCount * kItersPerThread) / b3_sc_sec;

    // 1b. Multi-core blake3_hash_many (1KB chunks)
    const auto b3_mc_t0 = std::chrono::steady_clock::now();
    {
        std::vector<std::thread> workers;
        workers.reserve(hw_threads);
        for (unsigned int tid = 0; tid < hw_threads; ++tid) {
            workers.emplace_back([&, tid]() {
                std::vector<uint8_t> local_cvs(kChunkCount * BLAKE3_OUT_LEN);
                for (size_t iter = 0; iter < kItersPerThread; ++iter) {
                    blake3_hash_many(chunk_ptrs.data(), kChunkCount,
                                     BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN, IV,
                                     iter + tid * 10000, true, 0, CHUNK_START,
                                     CHUNK_END, local_cvs.data());
                }
                if (local_cvs[0] == 0xff) {
                    std::atomic_signal_fence(std::memory_order_seq_cst);
                }
            });
        }
        for (auto &w : workers) {
            w.join();
        }
    }
    const auto b3_mc_t1 = std::chrono::steady_clock::now();
    const double b3_mc_sec =
        std::chrono::duration<double>(b3_mc_t1 - b3_mc_t0).count();
    const double b3_mc_mb =
        b3_sc_mb * static_cast<double>(hw_threads);
    const double b3_mc_mbs = b3_mc_mb / b3_mc_sec;
    const double b3_mc_chunk_hps =
        static_cast<double>(kChunkCount * kItersPerThread * hw_threads) /
        b3_mc_sec;

    // 1c. 250-byte Transaction Hashing (single-core & multi-core)
    constexpr size_t kTxHashIters = 200000;
    std::array<uint8_t, 250> sample_tx_bytes{};
    for (size_t i = 0; i < sample_tx_bytes.size(); ++i) {
        sample_tx_bytes[i] = static_cast<uint8_t>(i * 7 + 3);
    }
    uint8_t tx_digest[32]{};
    const auto b3_tx_sc_t0 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < kTxHashIters; ++i) {
        sample_tx_bytes[0] = static_cast<uint8_t>(i);
        blake3_hasher h;
        blake3_hasher_init(&h);
        blake3_hasher_update(&h, sample_tx_bytes.data(), sample_tx_bytes.size());
        blake3_hasher_finalize(&h, tx_digest, 32);
    }
    const auto b3_tx_sc_t1 = std::chrono::steady_clock::now();
    const double b3_tx_sc_sec =
        std::chrono::duration<double>(b3_tx_sc_t1 - b3_tx_sc_t0).count();
    const double b3_tx_sc_hps =
        static_cast<double>(kTxHashIters) / b3_tx_sc_sec;

    const auto b3_tx_mc_t0 = std::chrono::steady_clock::now();
    {
        std::vector<std::thread> workers;
        workers.reserve(hw_threads);
        for (unsigned int tid = 0; tid < hw_threads; ++tid) {
            workers.emplace_back([tid]() {
                std::array<uint8_t, 250> local_tx{};
                local_tx[1] = static_cast<uint8_t>(tid);
                uint8_t out[32]{};
                for (size_t i = 0; i < kTxHashIters; ++i) {
                    local_tx[0] = static_cast<uint8_t>(i);
                    blake3_hasher h;
                    blake3_hasher_init(&h);
                    blake3_hasher_update(&h, local_tx.data(), local_tx.size());
                    blake3_hasher_finalize(&h, out, 32);
                }
            });
        }
        for (auto &w : workers) {
            w.join();
        }
    }
    const auto b3_tx_mc_t1 = std::chrono::steady_clock::now();
    const double b3_tx_mc_sec =
        std::chrono::duration<double>(b3_tx_mc_t1 - b3_tx_mc_t0).count();
    const double b3_tx_mc_hps =
        static_cast<double>(kTxHashIters * hw_threads) / b3_tx_mc_sec;

    // =========================================================================
    // 2. TxOverlayArena + SmtNode Persistent Merklix Overlay Insertion
    // =========================================================================
    constexpr size_t kOverlayTxCount = 10000;
    const fs::path db_dir = m_args.GetDataDirNet() / "v2_kernel_bench_db";
    fs::create_directories(db_dir);

    lotus::v2::DiskStateOptions opts{};
    opts.identity[0] = 0x42;
    opts.profile_digest[0] = 0x99;
    lotus::v2::DiskStateMetadata gen_meta{};
    gen_meta.tip[0] = 0x01;
    lotus::v2::DiskStateStore store;
    lotus::v2::DiskStateError err;
    BOOST_REQUIRE_MESSAGE(
        lotus::v2::DiskStateStore::Open(fs::PathToString(db_dir), opts,
                                        gen_meta, store, err),
        err.message);

    lotus::v2::DiskStateMetadata b1_meta{};
    b1_meta.tip[0] = 0x11;
    std::shared_ptr<const lotus::v2::SmtNode> base_utxo_root;
    std::vector<lotus::v2::Coin> base_coins;
    base_coins.reserve(kOverlayTxCount);
    {
        lotus::v2::DiskStateTransaction txn;
        BOOST_REQUIRE_MESSAGE(store.Begin(txn, err), err.message);
        for (uint32_t i = 0; i < kOverlayTxCount; ++i) {
            lotus::v2::Hash txid{};
            txid[0] = 0x70;
            std::memcpy(&txid[4], &i, sizeof(i));
            lotus::v2::Coin coin{};
            coin.outpoint = {txid, 0};
            coin.output.value = 100000;
            coin.output.branches = {lotus::v2::Hash32{1}};
            coin.output.paths = {{0}};
            coin.creation_height = 1;
            coin.creation_parent_mtp = 1000;
            coin.coinbase = false;
            BOOST_REQUIRE_MESSAGE(txn.Insert(coin, err), err.message);
            lotus::v2::SmtInsert(base_utxo_root, coin);
            base_coins.push_back(coin);
        }
        BOOST_REQUIRE_MESSAGE(txn.Commit(b1_meta, err), err.message);
    }

    // Pre-build 10,000 overlay transactions in memory
    struct PrebuiltOverlayTx {
        lotus::v2::Hash txid;
        lotus::v2::Hash txhash;
        lotus::v2::Outpoint spent_op;
        lotus::v2::Coin out_coin;
    };
    std::vector<PrebuiltOverlayTx> overlay_txs(kOverlayTxCount);
    for (uint32_t i = 0; i < kOverlayTxCount; ++i) {
        lotus::v2::Hash txid{};
        txid[0] = 0x80;
        std::memcpy(&txid[4], &i, sizeof(i));
        overlay_txs[i].txid = txid;
        overlay_txs[i].txhash = txid;
        overlay_txs[i].spent_op = base_coins[i].outpoint;
        overlay_txs[i].out_coin.outpoint = {txid, 0};
        overlay_txs[i].out_coin.output.value = 99000;
        overlay_txs[i].out_coin.output.branches = {lotus::v2::Hash32{1}};
        overlay_txs[i].out_coin.output.paths = {{0}};
        overlay_txs[i].out_coin.creation_height = 2;
        overlay_txs[i].out_coin.creation_parent_mtp = 1120;
    }

    // 2a. Measure TxOverlayArena::InsertTxLeaf alone (pure Subtree A Merklix radix arena)
    lotus::v2::TxOverlayArena pure_tx_arena;
    pure_tx_arena.Reserve(kOverlayTxCount * 2 + 16);
    uint32_t arena_root_idx = lotus::v2::TxOverlayArena::kNullIdx;
    const auto arena_t0 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < kOverlayTxCount; ++i) {
        arena_root_idx = pure_tx_arena.InsertTxLeaf(
            arena_root_idx, overlay_txs[i].txid, overlay_txs[i].txhash);
    }
    const auto arena_t1 = std::chrono::steady_clock::now();
    BOOST_CHECK_EQUAL(pure_tx_arena.Count(arena_root_idx), kOverlayTxCount);
    const double arena_sec =
        std::chrono::duration<double>(arena_t1 - arena_t0).count();
    const double arena_tps =
        static_cast<double>(kOverlayTxCount) / arena_sec;

    // 2b. Measure full MerklixOverlayManager::AddTransaction (TxOverlayArena +
    // persistent SmtNode UTXO delete & insert + fee accumulators)
    lotus::v2::MerklixOverlayManager mgr;
    mgr.ResetToTip(b1_meta.tip, base_utxo_root,
                   lotus::v2::GetInitialV2MonetaryState(), 2, 1120);
    const auto ovl_t0 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < kOverlayTxCount; ++i) {
        BOOST_REQUIRE(mgr.AddTransaction(
            overlay_txs[i].txid, overlay_txs[i].txhash, 250,
            {overlay_txs[i].spent_op}, {overlay_txs[i].out_coin}, 1000, 1));
    }
    const auto ovl_t1 = std::chrono::steady_clock::now();
    const double ovl_sec =
        std::chrono::duration<double>(ovl_t1 - ovl_t0).count();
    const double ovl_tps =
        static_cast<double>(kOverlayTxCount) / ovl_sec;

    // 2c. Measure FreezeEpochBatch + O(1) root extraction + DiskStateStore::CommitFinalizedOverlay
    const auto freeze_t0 = std::chrono::steady_clock::now();
    const auto &frozen = mgr.FreezeEpochBatch();
    const lotus::v2::Hash utxo_digest = frozen.GetUtxoRootDigest();
    const auto freeze_t1 = std::chrono::steady_clock::now();
    const double freeze_us =
        std::chrono::duration<double, std::micro>(freeze_t1 - freeze_t0).count();
    BOOST_CHECK(!utxo_digest.empty());

    lotus::v2::DiskStateMetadata b2_meta{};
    b2_meta.tip[0] = 0x22;
    const auto disk_t0 = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        store.CommitFinalizedOverlay(frozen, {}, b2_meta, err), err.message);
    const auto disk_t1 = std::chrono::steady_clock::now();
    const double disk_sec =
        std::chrono::duration<double>(disk_t1 - disk_t0).count();
    const double disk_tps =
        static_cast<double>(kOverlayTxCount) / disk_sec;

    // =========================================================================
    // 3. GF(2^64) BCH Syndrome Computation & Root Solving
    // =========================================================================
    constexpr size_t kSyndromeTxCount = 1000000;
    const auto [k0, k1] = lotus::v2::DeriveEpochSipHashKey(b1_meta.tip, 1);
    lotus::v2::BucketSyndrome syn_sc{};
    const auto syn_sc_t0 = std::chrono::steady_clock::now();
    for (uint32_t i = 0; i < kSyndromeTxCount; ++i) {
        lotus::v2::Hash txid{};
        std::memcpy(txid.data(), &i, sizeof(i));
        const uint64_t sid = lotus::v2::ComputeShortTxId(k0, k1, txid);
        syn_sc.Add(sid);
    }
    const auto syn_sc_t1 = std::chrono::steady_clock::now();
    const double syn_sc_sec =
        std::chrono::duration<double>(syn_sc_t1 - syn_sc_t0).count();
    const double syn_sc_tps =
        static_cast<double>(kSyndromeTxCount) / syn_sc_sec;

    // Multi-core syndrome accumulation
    const auto syn_mc_t0 = std::chrono::steady_clock::now();
    {
        std::vector<std::thread> workers;
        workers.reserve(hw_threads);
        for (unsigned int tid = 0; tid < hw_threads; ++tid) {
            workers.emplace_back([&, tid]() {
                lotus::v2::BucketSyndrome local_syn{};
                for (uint32_t i = 0; i < kSyndromeTxCount; ++i) {
                    lotus::v2::Hash txid{};
                    txid[8] = static_cast<uint8_t>(tid);
                    std::memcpy(txid.data(), &i, sizeof(i));
                    const uint64_t sid =
                        lotus::v2::ComputeShortTxId(k0, k1, txid);
                    local_syn.Add(sid);
                }
                if (local_syn.s1 == 1ULL) {
                    std::atomic_signal_fence(std::memory_order_seq_cst);
                }
            });
        }
        for (auto &w : workers) {
            w.join();
        }
    }
    const auto syn_mc_t1 = std::chrono::steady_clock::now();
    const double syn_mc_sec =
        std::chrono::duration<double>(syn_mc_t1 - syn_mc_t0).count();
    const double syn_mc_tps =
        static_cast<double>(kSyndromeTxCount * hw_threads) / syn_mc_sec;

    // Degree-2 BCH root solving in GF(2^64)
    constexpr size_t kDecodeIters = 100000;
    std::vector<lotus::v2::BucketSyndrome> deg2_syndromes(kDecodeIters);
    for (size_t i = 0; i < kDecodeIters; ++i) {
        const uint64_t r1 = (uint64_t(i + 1) * 0x9e3779b97f4a7c15ULL) | 1ULL;
        const uint64_t r2 = (uint64_t(i + 1) * 0xbf58476d1ce4e5b9ULL) | 2ULL;
        deg2_syndromes[i].Add(r1);
        deg2_syndromes[i].Add(r2);
    }
    size_t decoded_roots_total = 0;
    const auto bch_sc_t0 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < kDecodeIters; ++i) {
        auto res = lotus::v2::DecodeBucketSyndrome(deg2_syndromes[i]);
        decoded_roots_total += res.roots.size();
    }
    const auto bch_sc_t1 = std::chrono::steady_clock::now();
    BOOST_CHECK_EQUAL(decoded_roots_total, kDecodeIters * 2);
    const double bch_sc_sec =
        std::chrono::duration<double>(bch_sc_t1 - bch_sc_t0).count();
    const double bch_sc_buckets_ps =
        static_cast<double>(kDecodeIters) / bch_sc_sec;
    const double bch_sc_roots_ps =
        static_cast<double>(decoded_roots_total) / bch_sc_sec;

    const auto bch_mc_t0 = std::chrono::steady_clock::now();
    {
        std::vector<std::thread> workers;
        workers.reserve(hw_threads);
        for (unsigned int tid = 0; tid < hw_threads; ++tid) {
            workers.emplace_back([&]() {
                size_t local_roots = 0;
                for (size_t i = 0; i < kDecodeIters; ++i) {
                    auto res =
                        lotus::v2::DecodeBucketSyndrome(deg2_syndromes[i]);
                    local_roots += res.roots.size();
                }
                if (local_roots == 0) {
                    std::atomic_signal_fence(std::memory_order_seq_cst);
                }
            });
        }
        for (auto &w : workers) {
            w.join();
        }
    }
    const auto bch_mc_t1 = std::chrono::steady_clock::now();
    const double bch_mc_sec =
        std::chrono::duration<double>(bch_mc_t1 - bch_mc_t0).count();
    const double bch_mc_buckets_ps =
        static_cast<double>(kDecodeIters * hw_threads) / bch_mc_sec;
    const double bch_mc_roots_ps =
        static_cast<double>(decoded_roots_total * hw_threads) / bch_mc_sec;

    // =========================================================================
    // 4. CheckTxInputs + Script/Signature Verification + ConnectBlock Throughput
    // =========================================================================
    constexpr size_t kValTxCount = 2000;
    const auto program = NativeBenchmarkProgram();
    const CScript coinbase_spk(program.begin(), program.end());
    // A transaction has at most MAX_V2_TX_OUTPUTS outputs, so kFanouts native
    // transactions share the kValTxCount outputs. Their inputs come from a V2
    // coinbase (a legacy transaction cannot create V2 outputs).
    constexpr size_t kFanouts = 8;
    constexpr size_t kOutsPerFanout = kValTxCount / kFanouts;
    static_assert(kOutsPerFanout <= MAX_V2_TX_OUTPUTS);
    const Amount fanout_in =
        m_coinbase_txns[0]->vout[0].nValue / int64_t(kFanouts);
    lotus::v2::Output funding_output;
    funding_output.value = fanout_in / SATOSHI;
    funding_output.branches = {lotus::v2::BranchLeaf(program)};
    funding_output.paths = {{0}};
    const CTransactionRef funding = MineV2Coinbase(std::vector<CTxOut>(
        kFanouts, CTxOut::FromV2Output(funding_output)));

    const Amount per_out =
        (fanout_in - 100000 * SATOSHI) / int64_t(kOutsPerFanout);
    std::vector<CMutableTransaction> fanout_mtxs;
    std::vector<CTransactionRef> fanout_txs;
    for (size_t f = 0; f < kFanouts; ++f) {
        fanout_mtxs.push_back(NativeBenchmarkSpend(
            *funding, uint32_t(f),
            std::vector<Amount>(kOutsPerFanout, per_out)));
        fanout_txs.push_back(MakeTransactionRef(fanout_mtxs.back()));
    }
    m_coinbase_version = 7;
    const CBlock fanout_block = CreateAndProcessBlock(fanout_mtxs, coinbase_spk);
    BOOST_REQUIRE_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(),
                        fanout_block.GetHash());

    std::vector<CMutableTransaction> signed_mtxs;
    std::vector<CTransactionRef> signed_txs;
    signed_mtxs.reserve(kValTxCount);
    signed_txs.reserve(kValTxCount);
    for (size_t i = 0; i < kValTxCount; ++i) {
        auto tx = NativeBenchmarkSpend(*fanout_txs[i / kOutsPerFanout],
                                       uint32_t(i % kOutsPerFanout),
                                       {per_out - 1000 * SATOSHI});
        signed_txs.push_back(MakeTransactionRef(tx));
        signed_mtxs.push_back(std::move(tx));
    }

    // 4a. Consensus::CheckTxInputs single-core throughput
    double check_inputs_tps = 0.0;
    {
        LOCK(cs_main);
        const CCoinsViewCache &view =
            m_node.chainman->ActiveChainstate().CoinsTip();
        const int spend_height =
            m_node.chainman->ActiveChain().Height() + 1;
        constexpr size_t kCheckLoops = 50;
        const auto ci_t0 = std::chrono::steady_clock::now();
        for (size_t loop = 0; loop < kCheckLoops; ++loop) {
            for (const auto &tx : signed_txs) {
                TxValidationState state;
                Amount fee = Amount::zero();
                BOOST_REQUIRE_MESSAGE(Consensus::CheckTxInputs(
                                          *tx, state, view, spend_height, fee),
                                      state.ToString());
            }
        }
        const auto ci_t1 = std::chrono::steady_clock::now();
        const double ci_sec =
            std::chrono::duration<double>(ci_t1 - ci_t0).count();
        check_inputs_tps =
            static_cast<double>(kValTxCount * kCheckLoops) / ci_sec;
    }

    // 4b. Native VM + BIP340 signature verification (single- and multi-core).
    std::vector<PrecomputedTransactionData> txdata_vec;
    txdata_vec.reserve(kValTxCount);
    for (const auto &tx : signed_txs)
        txdata_vec.emplace_back(*tx);
    auto verify_signature = [&](size_t i) {
        CScriptCheck check(
            fanout_txs[i / kOutsPerFanout]->vout[i % kOutsPerFanout],
            *signed_txs[i],
            m_node.chainman->m_validation_cache.m_signature_cache, 0, 0, false,
            txdata_vec[i]);
        return !check().has_value();
    };
    const auto vs_sc_t0 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < kValTxCount; ++i) {
        BOOST_REQUIRE(verify_signature(i));
    }
    const auto vs_sc_t1 = std::chrono::steady_clock::now();
    const double vs_sc_sec =
        std::chrono::duration<double>(vs_sc_t1 - vs_sc_t0).count();
    const double vs_sc_tps = static_cast<double>(kValTxCount) / vs_sc_sec;

    std::atomic<bool> signatures_valid{true};
    const auto vs_mc_t0 = std::chrono::steady_clock::now();
    {
        std::vector<std::thread> workers;
        workers.reserve(hw_threads);
        for (unsigned int tid = 0; tid < hw_threads; ++tid) {
            workers.emplace_back([&]() {
                for (size_t i = 0; i < kValTxCount; ++i) {
                    if (!verify_signature(i)) signatures_valid = false;
                }
            });
        }
        for (auto &worker : workers)
            worker.join();
    }
    BOOST_REQUIRE(signatures_valid.load());
    const auto vs_mc_t1 = std::chrono::steady_clock::now();
    const double vs_mc_sec =
        std::chrono::duration<double>(vs_mc_t1 - vs_mc_t0).count();
    const double vs_mc_tps =
        static_cast<double>(kValTxCount * hw_threads) / vs_mc_sec;

    // 4c. Full Block Assembly + ConnectBlock (2,000 txs)
    const auto cb_t0 = std::chrono::steady_clock::now();
    CBlock big_block = CreateAndProcessBlock(signed_mtxs, coinbase_spk);
    const auto cb_t1 = std::chrono::steady_clock::now();
    const double cb_sec =
        std::chrono::duration<double>(cb_t1 - cb_t0).count();
    const double cb_tps = static_cast<double>(kValTxCount) / cb_sec;
    BOOST_REQUIRE_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(),
                        big_block.GetHash());
    BOOST_CHECK_EQUAL(big_block.vtx.size(), kValTxCount + 1);

    std::cout << "LOTUS_V2_WORKLOAD=native_v7_bip340_p2pk_2000tx_v1\n"
              << "\n=== V2 KERNEL THROUGHPUT BENCHMARK RESULTS (threads="
              << hw_threads << ") ===\n"
              << "BLAKE3_HASH_MANY_SC_MBPS=" << b3_sc_mbs
              << " BLAKE3_HASH_MANY_SC_HPS=" << b3_sc_chunk_hps << "\n"
              << "BLAKE3_HASH_MANY_MC_MBPS=" << b3_mc_mbs
              << " BLAKE3_HASH_MANY_MC_HPS=" << b3_mc_chunk_hps << "\n"
              << "BLAKE3_250B_TX_SC_HPS=" << b3_tx_sc_hps
              << " BLAKE3_250B_TX_MC_HPS=" << b3_tx_mc_hps << "\n"
              << "TX_OVERLAY_ARENA_INSERT_TPS=" << arena_tps << "\n"
              << "MERKLIX_OVERLAY_MGR_ADD_TX_TPS=" << ovl_tps << "\n"
              << "MERKLIX_FREEZE_EPOCH_US=" << freeze_us << "\n"
              << "DISK_STATE_COMMIT_FINALIZED_OVERLAY_TPS=" << disk_tps << "\n"
              << "GF64_SYNDROME_ACCUM_SC_TPS=" << syn_sc_tps
              << " GF64_SYNDROME_ACCUM_MC_TPS=" << syn_mc_tps << "\n"
              << "GF64_BCH_DEG2_SOLVE_SC_BUCKETS_PS=" << bch_sc_buckets_ps
              << " GF64_BCH_DEG2_SOLVE_SC_ROOTS_PS=" << bch_sc_roots_ps << "\n"
              << "GF64_BCH_DEG2_SOLVE_MC_BUCKETS_PS=" << bch_mc_buckets_ps
              << " GF64_BCH_DEG2_SOLVE_MC_ROOTS_PS=" << bch_mc_roots_ps << "\n"
              << "CHECK_TX_INPUTS_SC_TPS=" << check_inputs_tps << "\n"
              << "VERIFY_SCRIPT_SIG_SC_TPS=" << vs_sc_tps
              << " VERIFY_SCRIPT_SIG_MC_TPS=" << vs_mc_tps << "\n"
              << "CREATE_AND_CONNECT_BLOCK_2000TX_TPS=" << cb_tps
              << " CREATE_AND_CONNECT_BLOCK_2000TX_MS=" << (cb_sec * 1000.0)
              << "\n=== END V2 KERNEL THROUGHPUT BENCHMARK ===\n"
              << std::endl;
}

BOOST_AUTO_TEST_CASE(v2_nullfail_and_batch_sig_collector) {
    using namespace lotus::v2;
    const VmProfile vm_profile{512, 8, 128, 16, 8, 256, 8, 100000};
    std::array<uint8_t, 32> secret{};
    secret[31] = 3;
    std::array<uint8_t, 32> aux{};
    const auto pubkey = ParseHex(
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");

    // 1. Verify mandatory NULLFAIL on OP_CHECKDATASIG (0xbd)
    VmBytes alg0(16, 0);
    lotus::v2::Hash msg0{};
    msg0.fill(0x42);
    std::vector<uint8_t> valid_sig;
    std::string err;
    BOOST_REQUIRE(SignBip340Message(secret, msg0, 0, aux, valid_sig, err));
    VmBytes msg_bytes(msg0.begin(), msg0.end());

    // Valid signature succeeds
    BOOST_CHECK(EvaluateVm(ParseHex("bd"),
                           {valid_sig, msg_bytes, pubkey, alg0}, vm_profile)
                    .status == VmStatus::Success);

    // Empty signature pushes false (0), so OP_CHECKDATASIG OP_NOT (bd9c) succeeds
    BOOST_CHECK(EvaluateVm(ParseHex("bd9c"),
                           {VmBytes{}, msg_bytes, pubkey, alg0}, vm_profile)
                    .status == VmStatus::Success);

    // Non-empty invalid signature immediately aborts with CHECKDATASIG NULLFAIL
    auto bad_sig = valid_sig;
    bad_sig[10] ^= 0x01;
    const auto nf_res = EvaluateVm(
        ParseHex("bd9c"), {bad_sig, msg_bytes, pubkey, alg0}, vm_profile);
    BOOST_CHECK(nf_res.status == VmStatus::Invalid);
    BOOST_CHECK_EQUAL(nf_res.error, "CHECKDATASIG NULLFAIL");

    // 2. Verify 256-signature BatchSigCollector multi-scalar batch verification
    //    and bisection pinpointing of single-bit-flip failures
    constexpr size_t kBatchCount = 256;
    BatchSigCollector collector;
    collector.Reserve(kBatchCount);
    std::vector<lotus::v2::Hash> msgs(kBatchCount);
    std::vector<std::vector<uint8_t>> sigs(kBatchCount);
    for (size_t i = 0; i < kBatchCount; ++i) {
        msgs[i].fill(0);
        msgs[i][0] = uint8_t(i & 0xff);
        msgs[i][1] = uint8_t((i >> 8) & 0xff);
        msgs[i][2] = 0xa5;
        aux[0] = uint8_t(i & 0xff);
        BOOST_REQUIRE(SignBip340Message(secret, msgs[i], 0, aux, sigs[i], err));
        VmBytes m(msgs[i].begin(), msgs[i].end());
        BOOST_REQUIRE(EvaluateVm(ParseHex("bd"), {sigs[i], m, pubkey, alg0},
                                 vm_profile, 0, 0, &collector)
                          .status == VmStatus::Success);
    }
    BOOST_CHECK_EQUAL(collector.Size(), kBatchCount);

    const auto seq_t0 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < kBatchCount; ++i) {
        BOOST_REQUIRE(VerifyBip340Signature(pubkey, sigs[i], msgs[i], false) ==
                      SignatureStatus::Valid);
    }
    const auto seq_t1 = std::chrono::steady_clock::now();

    const auto batch_st_t0 = std::chrono::steady_clock::now();
    BOOST_CHECK(collector.VerifyAll(1));
    const auto batch_st_t1 = std::chrono::steady_clock::now();

    const auto batch_mt_t0 = std::chrono::steady_clock::now();
    BOOST_CHECK(collector.VerifyAll(4));
    const auto batch_mt_t1 = std::chrono::steady_clock::now();

    const double seq_us =
        std::chrono::duration<double, std::micro>(seq_t1 - seq_t0).count();
    const double batch_st_us =
        std::chrono::duration<double, std::micro>(batch_st_t1 - batch_st_t0)
            .count();
    const double batch_mt_us =
        std::chrono::duration<double, std::micro>(batch_mt_t1 - batch_mt_t0)
            .count();
    std::cout << "BIP340_256_SIG_SEQ_US=" << seq_us
              << " BATCH_ST_US=" << batch_st_us
              << " BATCH_MT_US=" << batch_mt_us << "\n";

    for (size_t corrupt_idx : {size_t(0), size_t(41), size_t(129), size_t(255)}) {
        BatchSigCollector bad_collector;
        bad_collector.Reserve(kBatchCount);
        for (size_t i = 0; i < kBatchCount; ++i) {
            auto s = sigs[i];
            if (i == corrupt_idx) {
                s[19] ^= 0x04;
            }
            BOOST_REQUIRE(bad_collector.Add(pubkey, s, msgs[i]));
        }
        BOOST_CHECK(!bad_collector.VerifyAll(1));
        BOOST_CHECK(!bad_collector.VerifyAll(4));
        const auto fail_st = bad_collector.FirstFailingIndex(1);
        const auto fail_mt = bad_collector.FirstFailingIndex(4);
        BOOST_REQUIRE(fail_st.has_value());
        BOOST_REQUIRE(fail_mt.has_value());
        BOOST_CHECK_EQUAL(*fail_st, corrupt_idx);
        BOOST_CHECK_EQUAL(*fail_mt, corrupt_idx);
    }

    // 3. Verify BatchSigCollector::FirstFailingIndex on mixed BIP340 + legacy
    //    Schnorr items (both single-threaded and multi-threaded worker pool).
    CKey legacy_key;
    legacy_key.Set(secret.begin(), secret.end(), true);
    const CPubKey legacy_pubkey = legacy_key.GetPubKey();
    std::vector<uint256> legacy_msgs(64);
    std::vector<std::vector<uint8_t>> legacy_sigs(64);
    for (size_t j = 0; j < 64; ++j) {
        legacy_msgs[j] = uint256{};
        legacy_msgs[j].begin()[0] = static_cast<uint8_t>(j);
        legacy_msgs[j].begin()[1] = 0x77;
        BOOST_REQUIRE(legacy_key.SignSchnorr(legacy_msgs[j], legacy_sigs[j]));
    }
    for (size_t corrupt_leg : {size_t(0), size_t(19), size_t(63)}) {
        BatchSigCollector mixed;
        for (size_t i = 0; i < 32; ++i) {
            BOOST_REQUIRE(mixed.Add(pubkey, sigs[i], msgs[i]));
        }
        for (size_t j = 0; j < 64; ++j) {
            auto ls = legacy_sigs[j];
            if (j == corrupt_leg) {
                ls[11] ^= 0x02;
            }
            BOOST_REQUIRE(mixed.AddLegacySchnorr(
                std::span<const uint8_t>(legacy_pubkey.data(),
                                         legacy_pubkey.size()),
                ls, legacy_msgs[j].begin()));
        }
        BOOST_CHECK(!mixed.VerifyAll(1));
        BOOST_CHECK(!mixed.VerifyAll(4));
        const auto fail_st = mixed.FirstFailingIndex(1);
        const auto fail_mt = mixed.FirstFailingIndex(4);
        BOOST_REQUIRE(fail_st.has_value());
        BOOST_REQUIRE(fail_mt.has_value());
        BOOST_CHECK_EQUAL(*fail_st, 32U + corrupt_leg);
        BOOST_CHECK_EQUAL(*fail_mt, 32U + corrupt_leg);
    }
}

BOOST_FIXTURE_TEST_CASE(v2_parallel_utxo_dependency_validation,
                        TestChain100Setup) {
    const auto program = NativeBenchmarkProgram();
    const CScript coinbase_spk(program.begin(), program.end());
    // Native funding needs a V2 coinbase; a legacy coinbase pays the program
    // as a legacy script, which a version 7 input cannot spend.
    m_coinbase_version = 7;
    const CBlock funding = CreateAndProcessBlock({}, coinbase_spk);
    BOOST_REQUIRE_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(),
                        funding.GetHash());
    this->mineBlocks(100);

    // Eight independent chains of depth four exercise intra-batch resolution.
    constexpr size_t kChains = 8;
    constexpr size_t kChainDepth = 4;
    const Amount total_in = funding.vtx[0]->vout[0].nValue;
    const Amount per_chain = (total_in - 50000 * SATOSHI) / int64_t(kChains);
    const CMutableTransaction fanout_mtx = NativeBenchmarkSpend(
        *funding.vtx[0], 0, std::vector<Amount>(kChains, per_chain));
    CTransactionRef fanout_tx = MakeTransactionRef(fanout_mtx);
    const CBlock fanout_block =
        CreateAndProcessBlock({fanout_mtx}, coinbase_spk);
    BOOST_REQUIRE_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(),
                        fanout_block.GetHash());

    std::vector<CTransactionRef> batch_txs;
    std::vector<CMutableTransaction> batch_mtxs;
    batch_txs.reserve(kChains * kChainDepth);
    batch_mtxs.reserve(kChains * kChainDepth);

    for (size_t c = 0; c < kChains; ++c) {
        CTransactionRef previous = fanout_tx;
        uint32_t index = uint32_t(c);
        Amount value = per_chain;
        for (size_t d = 0; d < kChainDepth; ++d) {
            value -= 2000 * SATOSHI;
            auto tx = NativeBenchmarkSpend(*previous, index, {value});
            previous = MakeTransactionRef(tx);
            index = 0;
            batch_mtxs.push_back(std::move(tx));
            batch_txs.push_back(previous);
        }
    }

    // 1. Corrupting a signature in the middle of the batch must fail cleanly
    {
        std::vector<CTransactionRef> bad_batch = batch_txs;
        CMutableTransaction bad_mtx = batch_mtxs[17];
        BOOST_REQUIRE_EQUAL(bad_mtx.vin[0].vWitnesses[0].arguments[0].size(),
                            64U);
        bad_mtx.vin[0].vWitnesses[0].arguments[0][10] ^= 0x01;
        bad_batch[17] = MakeTransactionRef(std::move(bad_mtx));

        LOCK(cs_main);
        const auto bad_res = ProcessRawTxBatch(
            m_node.chainman->ActiveChainstate(), *m_node.mempool, bad_batch,
            /*test_accept=*/false);
        BOOST_REQUIRE(bad_res.m_state.IsInvalid());
        const auto rejected = bad_res.m_tx_results.find(bad_batch[17]->GetId());
        BOOST_REQUIRE(rejected != bad_res.m_tx_results.end());
        BOOST_CHECK_MESSAGE(rejected->second.m_state.GetRejectReason().find(
                                "mandatory-script-verify-flag-failed") !=
                                std::string::npos,
                            rejected->second.m_state.ToString());
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
    }

    // 2. Valid dependency-chain batch succeeds via static UTXO resolution +
    //    multi-core parallel script verification
    {
        LOCK(cs_main);
        const auto ok_res = ProcessRawTxBatch(
            m_node.chainman->ActiveChainstate(), *m_node.mempool, batch_txs,
            /*test_accept=*/false);
        BOOST_CHECK_MESSAGE(ok_res.m_state.IsValid(),
                            ok_res.m_state.ToString());
        BOOST_CHECK_EQUAL(ok_res.m_tx_results.size(), batch_txs.size());
        BOOST_CHECK_EQUAL(m_node.mempool->size(), batch_txs.size());
    }

    // 3. ConnectBlock validates and connects the 32 chained transactions
    CBlock connected = CreateAndProcessBlock(batch_mtxs, coinbase_spk);
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(),
                          connected.GetHash());
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
    }
}

BOOST_FIXTURE_TEST_CASE(v2_native_v7_chained_schnorr_batch_and_block,
                        TestChain100Setup) {
    using namespace lotus::v2;
    const auto program = NativeBenchmarkProgram();
    const CScript coinbase_spk(program.begin(), program.end());
    // Native funding needs a V2 coinbase; a legacy coinbase pays the program
    // as a legacy script, which a version 7 input cannot spend.
    m_coinbase_version = 7;
    const CBlock funding = CreateAndProcessBlock({}, coinbase_spk);
    BOOST_REQUIRE_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(),
                        funding.GetHash());
    this->mineBlocks(100);

    std::array<uint8_t, 32> secret{};
    secret[31] = 3;
    std::array<uint8_t, 32> aux{};
    const auto pubkey = ParseHex(
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9");

    std::vector<uint8_t> v2_p2pk_script;
    v2_p2pk_script.reserve(34);
    v2_p2pk_script.push_back(0x20);
    v2_p2pk_script.insert(v2_p2pk_script.end(), pubkey.begin(), pubkey.end());
    v2_p2pk_script.push_back(0xbb); // OP_CHECKSIG (V2 BIP340 Schnorr)
    const lotus::v2::Hash branch_leaf = BranchLeaf(v2_p2pk_script);

    auto make_v2_txout = [&](Amount val) -> CTxOut {
        Output o;
        o.flags = 0;
        o.value = static_cast<uint64_t>(val / SATOSHI);
        o.branches = {branch_leaf};
        o.paths = {{0}};
        return CTxOut::FromV2Output(o);
    };

    constexpr size_t kChains = 8;
    constexpr size_t kChainDepth = 4;

    // Fan out an actual mature native coinbase, with a native BIP340 witness.
    const Amount total_in = funding.vtx[0]->vout[0].nValue;
    const Amount per_chain = (total_in - 50000 * SATOSHI) / int64_t(kChains);
    const CMutableTransaction fanout_mtx = NativeBenchmarkSpend(
        *funding.vtx[0], 0, std::vector<Amount>(kChains, per_chain));
    CTransactionRef fanout_tx = MakeTransactionRef(fanout_mtx);
    const CBlock fanout_block =
        CreateAndProcessBlock({fanout_mtx}, coinbase_spk);
    BOOST_REQUIRE_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(),
                        fanout_block.GetHash());

    std::vector<CTransactionRef> batch_txs;
    std::vector<CMutableTransaction> batch_mtxs;
    batch_txs.reserve(kChains * kChainDepth);
    batch_mtxs.reserve(kChains * kChainDepth);

    for (size_t c = 0; c < kChains; ++c) {
        TxId prev_txid = fanout_tx->GetId();
        uint32_t prev_vout = uint32_t(c);
        Amount prev_val = per_chain;
        CTxOut prev_txout = fanout_tx->vout[c];

        for (size_t d = 0; d < kChainDepth; ++d) {
            CMutableTransaction mtx;
            mtx.nVersion = 7;
            mtx.nV2Lock = 0;
            mtx.nLockTime = 0;

            CTxIn txin(COutPoint(prev_txid, prev_vout), CScript(),
                       CTxIn::SEQUENCE_FINAL);
            txin.nFlags = 1;
            txin.nPathIndex = 0;
            BranchWitness wit;
            wit.script = v2_p2pk_script;
            txin.vWitnesses = {wit};
            mtx.vin.push_back(std::move(txin));

            const Amount next_val = prev_val - 2000 * SATOSHI;
            CTxOut next_txout = make_v2_txout(next_val);
            mtx.vout.push_back(next_txout);

            // Alternate between mode=0 (64-byte) and mode=1 (65-byte) BIP340
            const uint8_t sighash_mode =
                static_cast<uint8_t>((c + d) % 2 == 0 ? 0 : 1);
            const Transaction v2tx_unsigned = mtx.ToV2Transaction();
            ResolvedCoins resolved = {prev_txout.ToV2Output()};
            PreparedSigningContext prep;
            std::string err;
            BOOST_REQUIRE_MESSAGE(
                PrepareSigningContext(v2tx_unsigned, DefaultTxProfile,
                                      GetActiveV2ChainId(), resolved, prep,
                                      err),
                err);
            lotus::v2::Hash sighash_msg{};
            BOOST_REQUIRE_MESSAGE(SigningMessage(prep, 0, 0, sighash_mode,
                                                 std::nullopt, sighash_msg,
                                                 err),
                                  err);
            aux[0] = static_cast<uint8_t>(c);
            aux[1] = static_cast<uint8_t>(d);
            std::vector<uint8_t> sig_bytes;
            BOOST_REQUIRE_MESSAGE(
                SignBip340Message(secret, sighash_msg, sighash_mode, aux,
                                  sig_bytes, err),
                err);
            BOOST_CHECK_EQUAL(sig_bytes.size(),
                              sighash_mode == 0 ? 64U : 65U);
            mtx.vin[0].vWitnesses[0].arguments = {std::move(sig_bytes)};

            // Verify pure v7 wire serialization roundtrip
            DataStream ss{};
            ss << mtx;
            CTransactionRef tx_ref =
                MakeTransactionRef(CMutableTransaction(deserialize, ss));
            BOOST_CHECK_EQUAL(tx_ref->nVersion, 7U);
            BOOST_CHECK_EQUAL(tx_ref->GetId(), mtx.GetId());
            BOOST_CHECK_EQUAL(tx_ref->GetHash(), mtx.GetHash());

            prev_txid = tx_ref->GetId();
            prev_vout = 0;
            prev_val = next_val;
            prev_txout = next_txout;
            batch_mtxs.push_back(std::move(mtx));
            batch_txs.push_back(std::move(tx_ref));
        }
    }

    // 1. Corrupting a V2 witness signature in the batch must fail cleanly
    {
        std::vector<CTransactionRef> bad_batch = batch_txs;
        CMutableTransaction bad_mtx = batch_mtxs[11];
        bad_mtx.vin[0].vWitnesses[0].arguments[0][15] ^= 0x01;
        bad_batch[11] = MakeTransactionRef(std::move(bad_mtx));

        LOCK(cs_main);
        const auto bad_res = ProcessRawTxBatch(
            m_node.chainman->ActiveChainstate(), *m_node.mempool, bad_batch,
            /*test_accept=*/false);
        BOOST_REQUIRE(bad_res.m_state.IsInvalid());
        const auto rejected = bad_res.m_tx_results.find(bad_batch[11]->GetId());
        BOOST_REQUIRE(rejected != bad_res.m_tx_results.end());
        BOOST_CHECK_MESSAGE(rejected->second.m_state.GetRejectReason().find(
                                "mandatory-script-verify-flag-failed") !=
                                std::string::npos,
                            rejected->second.m_state.ToString());
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
    }

    // 2. Valid 32-tx chained nVersion==7 batch succeeds via ProcessRawTxBatch
    {
        LOCK(cs_main);
        const auto ok_res = ProcessRawTxBatch(
            m_node.chainman->ActiveChainstate(), *m_node.mempool, batch_txs,
            /*test_accept=*/false);
        BOOST_CHECK_MESSAGE(ok_res.m_state.IsValid(),
                            ok_res.m_state.ToString());
        BOOST_CHECK_EQUAL(ok_res.m_tx_results.size(), batch_txs.size());
        BOOST_CHECK_EQUAL(m_node.mempool->size(), batch_txs.size());
    }

    // 3. ConnectBlock validates and connects all 32 chained nVersion==7 txs
    CBlock connected = CreateAndProcessBlock(batch_mtxs, coinbase_spk);
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(m_node.chainman->ActiveTip()->GetBlockHash(),
                          connected.GetHash());
        BOOST_CHECK_EQUAL(m_node.mempool->size(), 0U);
    }
}

BOOST_AUTO_TEST_CASE(c17a_fee_backed_utxo_expiry_and_cleaning_crew) {
    // 1. Consensus constants & fee-backed lifespan math
    BOOST_CHECK_EQUAL(lotus::v2::UTXO_MIN_LIFESPAN_BLOCKS, 131400ULL);
    BOOST_CHECK_EQUAL(lotus::v2::UTXO_MAX_LIFESPAN_BLOCKS, 21024000ULL);
    BOOST_CHECK_EQUAL(lotus::v2::UTXO_RENT_ATOMS_PER_BLOCK, 1ULL);
    BOOST_CHECK_EQUAL(lotus::v2::MAX_EXPIRY_SWEEPS_PER_BLOCK, 1024ULL);
    BOOST_CHECK_EQUAL(lotus::v2::CLEANING_CREW_BASE_REWARD_ATOMS, 2000ULL);

    BOOST_CHECK_EQUAL(lotus::v2::ComputeTxFeePerSpendableOutput(1000000ULL, 4),
                      250000ULL);
    BOOST_CHECK_EQUAL(lotus::v2::ComputeTxFeePerSpendableOutput(1000000ULL, 0),
                      0ULL);

    // Zero fee uses 6-month baseline (131,400 blocks); positive fee adds 1 block per atom
    BOOST_CHECK_EQUAL(lotus::v2::ComputeUtxoLifespanBlocks(false, 0),
                      131400ULL);
    BOOST_CHECK_EQUAL(lotus::v2::ComputeUtxoLifespanBlocks(false, 50000),
                      181400ULL);
    // Proportional fee extension: 131,400 + 1,000,000 = 1,131,400 blocks
    BOOST_CHECK_EQUAL(lotus::v2::ComputeUtxoLifespanBlocks(false, 1000000),
                      1131400ULL);
    // Large fee clamps to 80 years (21,024,000 blocks)
    BOOST_CHECK_EQUAL(lotus::v2::ComputeUtxoLifespanBlocks(false, 50000000),
                      21024000ULL);
    // Coinbase outputs always receive 80-year maximum lifespan
    BOOST_CHECK_EQUAL(lotus::v2::ComputeUtxoLifespanBlocks(true, 0),
                      21024000ULL);

    BOOST_CHECK_EQUAL(lotus::v2::ComputeUtxoExpirationHeight(100, false, 0),
                      131500ULL);
    BOOST_CHECK_EQUAL(
        lotus::v2::ComputeUtxoExpirationHeight(100, false, 500000), 631500ULL);
    BOOST_CHECK_EQUAL(lotus::v2::ComputeUtxoExpirationHeight(100, true, 0),
                      21024100ULL);

    // 2. HAS_TOKEN output receives fee-backed lifespan and does not inflate burned XPI atoms
    {
        lotus::v2::UtxoSet token_utxo;
        lotus::v2::Coin tok_coin{};
        tok_coin.outpoint.tx_id[0] = 0xAA;
        tok_coin.outpoint.index = 0;
        tok_coin.output.flags = 0x01; // HAS_TOKEN
        tok_coin.output.token_id[0] = 0x77;
        tok_coin.output.value = 999999999ULL; // token units, not native XPI
        tok_coin.output.branches = {lotus::v2::Hash32{1}};
        tok_coin.output.paths = {{0}};
        tok_coin.creation_height = 10;
        tok_coin.creation_parent_mtp = 1000;
        tok_coin.coinbase = false;
        tok_coin.fee_per_output = 200000;
        tok_coin.expiration_height = lotus::v2::ComputeUtxoExpirationHeight(
            tok_coin.creation_height, false, tok_coin.fee_per_output);
        BOOST_CHECK_EQUAL(tok_coin.expiration_height, 331410ULL);
        BOOST_REQUIRE(token_utxo.Insert(tok_coin));

        // Not expired at h_exp - 1
        const auto sweep_early = token_utxo.SweepExpired(331409ULL);
        BOOST_CHECK_EQUAL(sweep_early.swept_coins.size(), 0U);
        BOOST_CHECK(token_utxo.Find(tok_coin.outpoint) != nullptr);

        // Swept at h_exp = 331410, burned_value_atoms == 0 for token output
        const auto sweep_at_exp = token_utxo.SweepExpired(331410ULL);
        BOOST_CHECK_EQUAL(sweep_at_exp.swept_coins.size(), 1U);
        BOOST_CHECK_EQUAL(sweep_at_exp.burned_value_atoms, 0ULL);
        BOOST_CHECK(token_utxo.Find(tok_coin.outpoint) == nullptr);
    }

    // 3. Boundary spend validation at h_exp - 1 (valid) vs h_exp (rejected)
    //    in both CheckOrdinaryCandidate and Consensus::CheckTxInputs
    {
        const lotus::v2::VmBytes true_script = {0x4e}; // Lotus V2 OP_1
        const lotus::v2::Hash branch_leaf = lotus::v2::BranchLeaf(true_script);

        lotus::v2::Coin min_coin{};
        min_coin.outpoint.tx_id[0] = 0x11;
        min_coin.outpoint.index = 0;
        min_coin.output.flags = 0;
        min_coin.output.value = 50000;
        min_coin.output.branches = {branch_leaf};
        min_coin.output.paths = {{0}};
        min_coin.creation_height = 10;
        min_coin.creation_parent_mtp = 1000;
        min_coin.coinbase = false;
        min_coin.fee_per_output = 0;
        min_coin.expiration_height = 131410ULL;

        lotus::v2::Coin fee_extended_coin = min_coin;
        fee_extended_coin.outpoint.tx_id[0] = 0x22;
        fee_extended_coin.fee_per_output = 500000;
        fee_extended_coin.expiration_height = 500010ULL;

        lotus::v2::DevelopmentUtxoView dev_view;
        dev_view.emplace(min_coin.outpoint, min_coin);
        dev_view.emplace(fee_extended_coin.outpoint, fee_extended_coin);

        auto make_v2_spend_tx = [&](const lotus::v2::Outpoint &prev) {
            lotus::v2::Transaction tx{};
            lotus::v2::Input in{};
            in.flags = 1;
            in.prev_txid = prev.tx_id;
            in.prev_index = prev.index;
            in.sequence = UINT32_MAX;
            in.path_index = 0;
            in.witnesses = {lotus::v2::BranchWitness{true_script, {}, {}}};
            tx.inputs = {in};
            lotus::v2::Output out{};
            out.flags = 0;
            out.value = 49000;
            out.branches = {branch_leaf};
            out.paths = {{0}};
            tx.outputs = {out};
            return tx;
        };

        const auto tx_min = make_v2_spend_tx(min_coin.outpoint);
        const auto tx_ext = make_v2_spend_tx(fee_extended_coin.outpoint);

        lotus::v2::OrdinaryCandidateProfile ord_profile{
            lotus::v2::DefaultTxProfile,
            lotus::v2::VmProfile{512, 8, 8192, 32, 32, 65536, 16, 100000},
            lotus::v2::VmCostProfile{},
            131409ULL,
            2000ULL,
            2ULL,
            100ULL,
            10000000ULL};
        ord_profile.vm_cost.max_invocation_cost = 1000000;
        ord_profile.vm_cost.structural_byte_cost = 1;
        for (auto &opcode : ord_profile.vm_cost.opcode) {
            opcode = {1, 1, 1};
        }
        const lotus::v2::ChainId chain_id = GetActiveV2ChainId();

        // 3a. Spend min_coin at h = 131409 (h_exp - 1) -> Accepted
        ord_profile.candidate_height = 131409ULL;
        lotus::v2::OrdinaryCandidateEffects effects{};
        std::string ord_err;
        BOOST_CHECK(lotus::v2::CheckOrdinaryCandidate(
            tx_min, ord_profile, chain_id, dev_view, effects, ord_err));
        BOOST_REQUIRE_EQUAL(effects.created.size(), 1U);
        BOOST_CHECK_EQUAL(effects.created[0].fee_per_output, 1000ULL);
        BOOST_CHECK_EQUAL(effects.created[0].expiration_height,
                          131409ULL + lotus::v2::UTXO_MIN_LIFESPAN_BLOCKS + 1000ULL);

        // 3b. Spend min_coin at h = 131410 (h_exp) -> Rejected with bad-txns-input-expired
        ord_profile.candidate_height = 131410ULL;
        BOOST_CHECK(!lotus::v2::CheckOrdinaryCandidate(
            tx_min, ord_profile, chain_id, dev_view, effects, ord_err));
        BOOST_CHECK_EQUAL(ord_err, "bad-txns-input-expired");

        // 3c. Spend fee_extended_coin at h = 131410 -> Accepted (extended to 500010)
        BOOST_CHECK(lotus::v2::CheckOrdinaryCandidate(
            tx_ext, ord_profile, chain_id, dev_view, effects, ord_err));

        // 3d. Spend fee_extended_coin at h = 500010 -> Rejected with bad-txns-input-expired
        ord_profile.candidate_height = 500010ULL;
        BOOST_CHECK(!lotus::v2::CheckOrdinaryCandidate(
            tx_ext, ord_profile, chain_id, dev_view, effects, ord_err));
        BOOST_CHECK_EQUAL(ord_err, "bad-txns-input-expired");

        // 3e. Consensus::CheckTxInputs boundary check at h_exp - 1 vs h_exp
        CCoinsView coins_dummy;
        CCoinsViewCache cache(&coins_dummy);
        const TxId legacy_txid = TxId(uint256::ONE);
        const COutPoint legacy_op(legacy_txid, 0);
        cache.AddCoin(legacy_op,
                      ::Coin(CTxOut(50000 * SATOSHI, CScript() << OP_TRUE), 10,
                             false, 0, 131410ULL),
                      false);

        CMutableTransaction spend_mtx;
        spend_mtx.nVersion = 2;
        spend_mtx.vin.emplace_back(legacy_op);
        spend_mtx.vout.emplace_back(49000 * SATOSHI, CScript() << OP_TRUE);
        const CTransaction spend_tx(spend_mtx);

        TxValidationState tx_state_ok;
        Amount txfee = Amount::zero();
        BOOST_CHECK(Consensus::CheckTxInputs(spend_tx, tx_state_ok, cache,
                                             131409, txfee));

        TxValidationState tx_state_exp;
        BOOST_CHECK(!Consensus::CheckTxInputs(spend_tx, tx_state_exp, cache,
                                              131410, txfee));
        BOOST_CHECK_EQUAL(tx_state_exp.GetRejectReason(),
                          "bad-txns-input-expired");
    }

    // 4. Deterministic sweep ordering by (expiration_height, OutpointKey) and
    //    MAX_EXPIRY_SWEEPS_PER_BLOCK (1,024) cap across UtxoSet, SmtNode, and CCoinsViewCache
    {
        constexpr size_t kExpiredCount = 1100;
        constexpr size_t kAliveCount = 50;
        constexpr uint64_t kSweepHeight = 200000ULL;

        lotus::v2::UtxoSet utxo_set;
        std::shared_ptr<const lotus::v2::SmtNode> smt_root;
        CCoinsView coins_dummy;
        CCoinsViewCache coins_cache(&coins_dummy);

        for (size_t i = 0; i < kExpiredCount + kAliveCount; ++i) {
            lotus::v2::Coin c{};
            c.outpoint.tx_id[0] = static_cast<uint8_t>((i >> 8) & 0xff);
            c.outpoint.tx_id[1] = static_cast<uint8_t>(i & 0xff);
            c.outpoint.tx_id[2] = 0x5A;
            c.outpoint.index = static_cast<uint32_t>(i % 3);
            c.output.flags = 0;
            c.output.value = 1000 + i;
            c.output.branches = {lotus::v2::Hash32{1}};
            c.output.paths = {{0}};
            c.coinbase = false;
            if (i < kExpiredCount) {
                c.creation_height = 10 + (i % 20);
                c.fee_per_output = (i % 7) * 100;
                c.expiration_height = lotus::v2::ComputeUtxoExpirationHeight(
                    c.creation_height, false, c.fee_per_output);
                BOOST_REQUIRE(c.expiration_height <= kSweepHeight);
            } else {
                c.creation_height = 100000;
                c.fee_per_output = 200000;
                c.expiration_height = lotus::v2::ComputeUtxoExpirationHeight(
                    c.creation_height, false, c.fee_per_output);
                BOOST_REQUIRE(c.expiration_height > kSweepHeight);
            }
            c.creation_parent_mtp = 1000;

            BOOST_REQUIRE(utxo_set.Insert(c));
            lotus::v2::SmtInsert(smt_root, c);

            const COutPoint cop(
                TxId(uint256(Span<const uint8_t>(c.outpoint.tx_id.data(), 32))),
                c.outpoint.index);
            coins_cache.AddCoin(
                cop,
                ::Coin(CTxOut::FromV2Output(c.output),
                       static_cast<uint32_t>(c.creation_height), c.coinbase,
                       c.fee_per_output, c.expiration_height),
                false);
        }

        BOOST_CHECK(utxo_set.Root() == lotus::v2::SmtRoot(smt_root));

        // Sweep 1 at kSweepHeight: must cap at 1,024 in identical canonical order
        const auto sweep1_utxo = utxo_set.SweepExpired(kSweepHeight);
        const auto sweep1_smt = lotus::v2::SmtSweepExpired(smt_root, kSweepHeight);
        const auto sweep1_cache = coins_cache.SweepExpiredCoins(kSweepHeight);

        BOOST_REQUIRE_EQUAL(sweep1_utxo.swept_coins.size(),
                            lotus::v2::MAX_EXPIRY_SWEEPS_PER_BLOCK);
        BOOST_REQUIRE_EQUAL(sweep1_smt.swept_coins.size(),
                            lotus::v2::MAX_EXPIRY_SWEEPS_PER_BLOCK);
        BOOST_REQUIRE_EQUAL(sweep1_cache.size(),
                            lotus::v2::MAX_EXPIRY_SWEEPS_PER_BLOCK);
        BOOST_CHECK_EQUAL(sweep1_utxo.burned_value_atoms,
                          sweep1_smt.burned_value_atoms);
        BOOST_CHECK(utxo_set.Root() == lotus::v2::SmtRoot(smt_root));

        for (size_t i = 0; i < sweep1_utxo.swept_coins.size(); ++i) {
            BOOST_CHECK(sweep1_utxo.swept_coins[i].outpoint ==
                        sweep1_smt.swept_coins[i].outpoint);
            const COutPoint expected_cop(
                TxId(uint256(Span<const uint8_t>(
                    sweep1_utxo.swept_coins[i].outpoint.tx_id.data(), 32))),
                sweep1_utxo.swept_coins[i].outpoint.index);
            BOOST_CHECK(sweep1_cache[i].first == expected_cop);
            if (i > 0) {
                const uint64_t prev_exp =
                    sweep1_utxo.swept_coins[i - 1].expiration_height;
                const uint64_t cur_exp =
                    sweep1_utxo.swept_coins[i].expiration_height;
                BOOST_CHECK(prev_exp <= cur_exp);
                if (prev_exp == cur_exp) {
                    BOOST_CHECK(
                        lotus::v2::OutpointKey(
                            sweep1_utxo.swept_coins[i - 1].outpoint) <
                        lotus::v2::OutpointKey(
                            sweep1_utxo.swept_coins[i].outpoint));
                }
            }
        }

        // Sweep 2 at kSweepHeight + 1: sweeps the remaining 76 expired coins
        const auto sweep2_utxo = utxo_set.SweepExpired(kSweepHeight + 1);
        const auto sweep2_smt =
            lotus::v2::SmtSweepExpired(smt_root, kSweepHeight + 1);
        const auto sweep2_cache =
            coins_cache.SweepExpiredCoins(kSweepHeight + 1);

        BOOST_CHECK_EQUAL(sweep2_utxo.swept_coins.size(),
                          kExpiredCount - lotus::v2::MAX_EXPIRY_SWEEPS_PER_BLOCK);
        BOOST_CHECK_EQUAL(sweep2_smt.swept_coins.size(),
                          kExpiredCount - lotus::v2::MAX_EXPIRY_SWEEPS_PER_BLOCK);
        BOOST_CHECK_EQUAL(sweep2_cache.size(),
                          kExpiredCount - lotus::v2::MAX_EXPIRY_SWEEPS_PER_BLOCK);
        BOOST_CHECK_EQUAL(utxo_set.Coins().size(), kAliveCount);
        BOOST_CHECK(utxo_set.Root() == lotus::v2::SmtRoot(smt_root));
    }

    // 5. Fee-capped Cleaning Crew bounty & monetary accounting
    {
        // Zero fees -> 0 bounty even when many UTXOs are swept (zero net inflation)
        BOOST_CHECK_EQUAL(lotus::v2::ComputeCleaningCrewBounty(100, 0), 0ULL);
        // Capped at F_block / 2 when raw bounty > F_block / 2
        BOOST_CHECK_EQUAL(lotus::v2::ComputeCleaningCrewBounty(10, 10000),
                          5000ULL);
        // Full 2,000 atoms per swept coin when raw bounty <= F_block / 2
        BOOST_CHECK_EQUAL(lotus::v2::ComputeCleaningCrewBounty(10, 100000),
                          20000ULL);
        // Capped at MAX_EXPIRY_SWEEPS_PER_BLOCK (1,024 * 2,000 = 2,048,000)
        BOOST_CHECK_EQUAL(lotus::v2::ComputeCleaningCrewBounty(5000, 100000000),
                          2048000ULL);

        const lotus::v2::MonetaryProfile profile{
            2, 3, 2, 4, 3, 5, 2, 2000, 3, 1000, 200, lotus::v2::Hash{9}};
        const lotus::v2::MonetaryState parent =
            lotus::v2::InitializeMonetaryGenesis(
                profile, lotus::v2::MonetaryState{9, 200, lotus::v2::Hash{9}, 4},
                0);
        const lotus::v2::MonetaryOrdinaryTx ord_tx{
            /*native_inputs=*/lotus::v2::MonetaryInteger(50000),
            /*native_outputs=*/lotus::v2::MonetaryInteger(40000),
            /*serialized_bytes=*/100,
            /*token_outputs=*/0,
            /*explicit_native_burn=*/lotus::v2::MonetaryInteger(500)};
        // Total fee = 10,000 -> half_fee = 5,000.
        // With 10 swept expired coins (raw bounty = 20,000), bounty is capped at 5,000.
        // Subsidy = 2 + 200 = 202, payable_fees = 5,000, bounty = 5,000 -> entitlement = 10,202.
        // Required coinbase deduction k = (1 + 134 + 4 + 1) * 2 = 280 -> max outputs = 9,922.
        const lotus::v2::MonetaryTransition trans = lotus::v2::AdvanceMonetary(
            profile, parent, /*work=*/lotus::v2::MonetaryInteger(9), {ord_tx},
            /*coinbase_native_outputs=*/lotus::v2::MonetaryInteger(9922),
            /*coinbase_native_burn=*/lotus::v2::MonetaryInteger(0),
            /*coinbase_bytes=*/1, /*tx_frame_prefix_bytes=*/1,
            /*account_block_cost=*/lotus::v2::MonetaryInteger(4),
            /*enforce_block_cost=*/lotus::v2::MonetaryInteger(4),
            /*expired_swept_count=*/10,
            /*expired_burned_atoms=*/lotus::v2::MonetaryInteger(77777));
        BOOST_CHECK_EQUAL(trans.expired_swept_count, 10U);
        BOOST_CHECK(trans.expired_burned_atoms ==
                    lotus::v2::MonetaryInteger(77777));
        BOOST_CHECK(trans.cleaning_crew_bounty ==
                    lotus::v2::MonetaryInteger(5000));
        BOOST_CHECK(trans.burned_fees == lotus::v2::MonetaryInteger(0));
        BOOST_CHECK(trans.burned_total ==
                    trans.burned_fees + lotus::v2::MonetaryInteger(500) +
                        trans.expired_burned_atoms);
        BOOST_CHECK(trans.spendable_supply_delta ==
                    lotus::v2::MonetaryInteger(9922) -
                        lotus::v2::MonetaryInteger(10000) -
                        lotus::v2::MonetaryInteger(500) -
                        lotus::v2::MonetaryInteger(77777));
    }

    // 6. CBlockUndo + ApplyBlockUndo and BlockUndoMessage + PeelBlockStateReverse restoration
    {
        CCoinsView coins_dummy;
        CCoinsViewCache view(&coins_dummy);

        CBlock block;
        CMutableTransaction cb_mtx;
        cb_mtx.vin.resize(1);
        cb_mtx.vout.emplace_back(5000 * SATOSHI, CScript() << OP_TRUE);
        block.vtx.push_back(MakeTransactionRef(cb_mtx));
        AddCoins(view, *block.vtx[0], 300000);

        const COutPoint exp_op(TxId(m_rng.rand256()), 1);
        const ::Coin orig_exp_coin(CTxOut(12345 * SATOSHI, CScript() << OP_TRUE),
                                   50, false, 150000, 281450);
        view.AddCoin(exp_op, orig_exp_coin, false);

        auto swept = view.SweepExpiredCoins(300000);
        BOOST_REQUIRE_EQUAL(swept.size(), 1U);
        BOOST_CHECK(!view.HaveCoin(exp_op));

        CBlockUndo block_undo;
        block_undo.vexpired.push_back(
            ExpiredCoinUndo{swept[0].first, swept[0].second});

        DataStream undo_stream{};
        undo_stream << block_undo;
        CBlockUndo decoded_undo;
        undo_stream >> decoded_undo;
        BOOST_REQUIRE_EQUAL(decoded_undo.vexpired.size(), 1U);
        BOOST_CHECK(decoded_undo.vexpired[0].outpoint == exp_op);
        BOOST_CHECK_EQUAL(decoded_undo.vexpired[0].coin.GetFeePerOutput(),
                          150000ULL);
        BOOST_CHECK_EQUAL(decoded_undo.vexpired[0].coin.GetExpirationHeight(),
                          281450ULL);

        CBlockIndex pindex;
        pindex.nHeight = 300000;
        BOOST_CHECK(ApplyBlockUndo(std::move(decoded_undo), block, &pindex,
                                   view) == DisconnectResult::OK);
        BOOST_CHECK(view.HaveCoin(exp_op));
        const ::Coin &restored = view.AccessCoin(exp_op);
        BOOST_CHECK_EQUAL(restored.GetHeight(), 50U);
        BOOST_CHECK_EQUAL(restored.GetFeePerOutput(), 150000ULL);
        BOOST_CHECK_EQUAL(restored.GetExpirationHeight(), 281450ULL);
        BOOST_CHECK_EQUAL(restored.GetTxOut().nValue, 12345 * SATOSHI);

        // BlockUndoMessage wire roundtrip with non-empty expired_swept_coins
        lotus::v2::BlockUndoMessage umsg{};
        umsg.block_id[0] = 0x33;
        lotus::v2::Coin v2_exp_coin{};
        v2_exp_coin.outpoint.tx_id[0] = 0x44;
        v2_exp_coin.outpoint.index = 2;
        v2_exp_coin.output.flags = 0;
        v2_exp_coin.output.value = 12345;
        v2_exp_coin.output.branches = {lotus::v2::Hash32{1}};
        v2_exp_coin.output.paths = {{0}};
        v2_exp_coin.creation_height = 50;
        v2_exp_coin.creation_parent_mtp = 1000;
        v2_exp_coin.coinbase = false;
        v2_exp_coin.fee_per_output = 150000;
        v2_exp_coin.expiration_height = 281450;
        umsg.expired_swept_coins.push_back(v2_exp_coin);

        std::vector<uint8_t> ubytes;
        std::string uerr;
        BOOST_REQUIRE_MESSAGE(
            lotus::v2::EncodeBlockUndoMessage(umsg, ubytes, uerr), uerr);
        lotus::v2::BlockUndoMessage udecoded{};
        BOOST_REQUIRE_MESSAGE(
            lotus::v2::DecodeBlockUndoMessage(ubytes, udecoded, uerr), uerr);
        BOOST_REQUIRE_EQUAL(udecoded.expired_swept_coins.size(), 1U);
        BOOST_CHECK(udecoded.expired_swept_coins[0].outpoint ==
                    v2_exp_coin.outpoint);
        BOOST_CHECK_EQUAL(udecoded.expired_swept_coins[0].fee_per_output,
                          150000ULL);
        BOOST_CHECK_EQUAL(udecoded.expired_swept_coins[0].expiration_height,
                          281450ULL);
    }
}

BOOST_AUTO_TEST_SUITE_END()

