// Copyright (c) 2026 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Per-peer costs of serving one block message: serializing it, its P2P
// checksum, and the WebSocket p2p-zstd-v1 stream compression, against
// compress-once independent frames. Run with
// -filter='WsServe.*'. See contrib/bench/ws-block-frames/README.md.

#include <bench/bench.h>

#include <hash.h>
#include <net_websocket_codec.h>
#include <net_zstd_dict.h>
#include <net_zstd_independent.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <protocol.h>
#include <random.h>
#include <script/script.h>
#include <streams.h>

#include <cassert>
#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace {
/**
 * A block of about `bytes` serialized bytes of P2PKH-shaped transactions:
 * one input with random 71-byte signature and 33-byte key pushes, two
 * outputs to random key hashes. Random where real transactions are
 * random, so compression ratios resemble ordinary traffic.
 */
CBlock MakeBlock(size_t bytes) {
    FastRandomContext rng{/*fDeterministic=*/true};
    CBlock block;
    block.SetBlockTime(1700000000);
    block.nBits = 0x207fffff;
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].scriptSig = CScript() << 1 << OP_0;
    coinbase.vout.emplace_back(50 * COIN, CScript() << OP_TRUE);
    block.vtx.push_back(MakeTransactionRef(coinbase));
    size_t size{80 + 3 + GetSerializeSize(coinbase)};
    while (size < bytes) {
        CMutableTransaction tx;
        tx.nVersion = 2;
        tx.vin.emplace_back(
            COutPoint{TxId{rng.rand256()}, uint32_t(rng.randrange(4))});
        tx.vin[0].scriptSig = CScript() << rng.randbytes<uint8_t>(71)
                                        << rng.randbytes<uint8_t>(33);
        for (int i = 0; i < 2; ++i) {
            tx.vout.emplace_back(int64_t(rng.randrange(1000000)) * SATOSHI,
                                 CScript() << OP_DUP << OP_HASH160
                                           << rng.randbytes<uint8_t>(20)
                                           << OP_EQUALVERIFY << OP_CHECKSIG);
        }
        size += GetSerializeSize(tx);
        block.vtx.push_back(MakeTransactionRef(tx));
    }
    return block;
}

struct Fixture {
    CBlock block;
    //! The block message payload and its 24-byte P2P header
    std::vector<uint8_t> payload, header, message;
};

const Fixture &GetFixture(size_t bytes) {
    static std::map<size_t, std::unique_ptr<Fixture>> fixtures;
    auto &f{fixtures[bytes]};
    if (!f) {
        f = std::make_unique<Fixture>();
        f->block = MakeBlock(bytes);
        VectorWriter{f->payload, 0, f->block};
        CMessageHeader hdr{CMessageHeader::MessageMagic{0xda, 0xb5, 0xbf, 0xfa},
                           NetMsgType::BLOCK, uint32_t(f->payload.size())};
        const uint256 hash{Hash(f->payload)};
        std::memcpy(hdr.pchChecksum, hash.begin(),
                    CMessageHeader::CHECKSUM_SIZE);
        VectorWriter{f->header, 0, hdr};
        f->message = f->header;
        f->message.insert(f->message.end(), f->payload.begin(),
                          f->payload.end());
    }
    return *f;
}

void Setup(benchmark::Bench &bench, const Fixture &f) {
    // Large blocks take tens of milliseconds per run.
    bench.unit("byte").batch(f.message.size()).epochs(5).epochIterations(1);
}

/** Serialize a block held in memory (as for the most recent block) */
void BenchSerialize(benchmark::Bench &bench, size_t bytes) {
    const auto &f{GetFixture(bytes)};
    Setup(bench, f);
    bench.run([&] {
        std::vector<uint8_t> out;
        VectorWriter{out, 0, f.block};
        assert(out.size() == f.payload.size());
    });
}

/** The P2P header checksum, computed for each peer (prepareForTransport) */
void BenchChecksum(benchmark::Bench &bench, size_t bytes) {
    const auto &f{GetFixture(bytes)};
    Setup(bench, f);
    bench.run([&] {
        const uint256 hash{Hash(f.payload)};
        ankerl::nanobench::doNotOptimizeAway(hash);
    });
}

/** p2p-zstd-v1: compress the message for one peer (a fresh stream) */
void BenchStreamCompress(benchmark::Bench &bench, size_t bytes) {
    const auto &f{GetFixture(bytes)};
    Setup(bench, f);
    std::vector<uint8_t> out;
    bench.run([&] {
        P2PZstdSession session{/*use_dict=*/true};
        out.clear();
        session.CompressFrame(f.message, out);
        ankerl::nanobench::doNotOptimizeAway(out.data());
    });
}

/** p2p-zstd-v1: what each receiving peer spends decompressing it */
void BenchStreamDecompress(benchmark::Bench &bench, size_t bytes) {
    const auto &f{GetFixture(bytes)};
    std::vector<uint8_t> wire;
    P2PZstdSession{true}.CompressFrame(f.message, wire);
    Setup(bench, f);
    std::vector<uint8_t> out;
    bench.run([&] {
        P2PZstdSession session{true};
        out.clear();
        session.DecompressFrame(wire, out);
        assert(out.size() == f.message.size());
    });
}

/** independent frames: the one compression of a block for all peers */
void BenchIndependentCompress(benchmark::Bench &bench, size_t bytes) {
    const auto &f{GetFixture(bytes)};
    Setup(bench, f);
    bench.run([&] {
        const auto frame{CompressP2PIndependent(f.header, f.payload)};
        ankerl::nanobench::doNotOptimizeAway(frame.data());
    });
}

/**
 * independent frames: each further peer, served from the cache and copied
 * into that peer's WebSocket frame (server role: unmasked)
 */
void BenchIndependentPerPeer(benchmark::Bench &bench, size_t bytes) {
    const auto &f{GetFixture(bytes)};
    P2PIndependentFrameCache cache;
    cache.Encode(f.header, f.payload);
    WebSocketCodec codec{WebSocketCodec::Role::SERVER,
                         P2PWebSocketCompression::ZSTD_DICT};
    Setup(bench, f);
    std::vector<uint8_t> wire;
    bench.run([&] {
        const auto frame{cache.Encode(f.header, f.payload)};
        wire.clear();
        codec.EncodeIndependent(*frame, wire);
        ankerl::nanobench::doNotOptimizeAway(wire.data());
    });
    assert(cache.GetStats().encodes == 1);
}

/** p2p-zstd-v1: each peer, compressed and framed for it */
void BenchStreamPerPeer(benchmark::Bench &bench, size_t bytes) {
    const auto &f{GetFixture(bytes)};
    Setup(bench, f);
    std::vector<uint8_t> wire;
    bench.run([&] {
        WebSocketCodec codec{WebSocketCodec::Role::SERVER,
                             P2PWebSocketCompression::ZSTD_DICT};
        wire.clear();
        codec.EncodeMessage(f.message, wire);
        ankerl::nanobench::doNotOptimizeAway(wire.data());
    });
}

/** independent frames: what each receiving peer spends decompressing it */
void BenchIndependentDecompress(benchmark::Bench &bench, size_t bytes) {
    const auto &f{GetFixture(bytes)};
    const auto frame{CompressP2PIndependent(f.header, f.payload)};
    Setup(bench, f);
    std::vector<uint8_t> out;
    bench.run([&] {
        out.clear();
        DecompressP2PIndependent(frame, out, f.message.size());
        assert(out.size() == f.message.size());
    });
}
} // namespace

#define WS_SERVE_BENCH(name, fn)                                               \
    static void WsServe##name##1MB(benchmark::Bench & b) {                     \
        fn(b, 1000000);                                                        \
    }                                                                          \
    static void WsServe##name##8MB(benchmark::Bench & b) {                     \
        fn(b, 8000000);                                                        \
    }                                                                          \
    static void WsServe##name##32MB(benchmark::Bench & b) {                    \
        fn(b, 31900000);                                                       \
    }                                                                          \
    BENCHMARK(WsServe##name##1MB);                                             \
    BENCHMARK(WsServe##name##8MB);                                             \
    BENCHMARK(WsServe##name##32MB);

WS_SERVE_BENCH(BlockSerialize, BenchSerialize)
WS_SERVE_BENCH(BlockChecksum, BenchChecksum)
WS_SERVE_BENCH(StreamCompress, BenchStreamCompress)
WS_SERVE_BENCH(StreamDecompress, BenchStreamDecompress)
WS_SERVE_BENCH(IndependentCompress, BenchIndependentCompress)
WS_SERVE_BENCH(IndependentPerPeer, BenchIndependentPerPeer)
WS_SERVE_BENCH(StreamPerPeer, BenchStreamPerPeer)
WS_SERVE_BENCH(IndependentDecompress, BenchIndependentDecompress)
