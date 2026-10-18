#include "header.h"
#include "sparse_state.h"

#include <primitives/block.h>
#include <streams.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <vector>

using namespace lotus::v2;

namespace {
void Check(bool condition, const char *message) {
    if (!condition) {
        std::cerr << "V2 header boundary: " << message << '\n';
        std::exit(1);
    }
}

bool NonZero(const Hash &hash) {
    return std::any_of(hash.begin(), hash.end(),
                       [](uint8_t byte) { return byte != 0; });
}

bool Same(const Header &a, const Header &b) {
    return a.prev_id == b.prev_id && a.bits == b.bits && a.time == b.time &&
           a.nonce == b.nonce && a.version == b.version && a.size == b.size &&
           a.height == b.height && a.tx_root == b.tx_root &&
           a.state_root == b.state_root;
}
} // namespace

int main() {
    // Distinct nonzero fields, so a zero or repeated encoding cannot pass.
    ChainId chain_id;
    Header header;
    for (unsigned i = 0; i < 32; ++i) {
        chain_id[i] = static_cast<uint8_t>(i + 1);
        header.prev_id[i] = static_cast<uint8_t>(i + 32);
        header.tx_root[i] = static_cast<uint8_t>(i + 64);
        header.state_root[i] = static_cast<uint8_t>(i + 96);
    }
    header.bits = 0x1d00ffff;
    header.time = 0x010203040506;
    header.nonce = 0x08090a0b0c0d0e0f;
    header.version = 2;
    header.size = 0x1122334455667788;
    header.height = 0x99aabbccddeeff00;
    Check(NonZero(chain_id) && NonZero(header.prev_id) &&
              NonZero(header.tx_root) && NonZero(header.state_root),
          "hash fields are nonzero");
    Check(header.prev_id != header.tx_root &&
              header.tx_root != header.state_root &&
              header.prev_id != header.state_root && chain_id != header.prev_id,
          "hash fields are distinct");
    Check(header.bits != 0 && header.time != 0 && header.nonce != 0 &&
              header.version != 0 && header.size != 0 && header.height != 0,
          "scalar fields are nonzero");
    Check(header.bits != header.version && header.time != header.nonce &&
              header.size != header.height && header.time != header.size,
          "scalar fields are distinct");

    std::array<uint8_t, HEADER_SIZE> bytes{};
    Check(SerializeHeader(header, bytes), "serialize V2 header");
    const std::vector<uint8_t> encoded(bytes.begin(), bytes.end());
    Check(encoded.size() == 134, "serialized V2 header is 134 bytes");

    // CBlockHeader now represents the 134-byte Lotus V2 header.
    SetActiveV2ChainId(chain_id);
    CBlockHeader v2_block_hdr;
    SpanReader reader{encoded};
    bool read_failed = false;
    try {
        reader >> v2_block_hdr;
    } catch (const std::ios_base::failure &) {
        read_failed = true;
    }

    Check(!read_failed, "CBlockHeader reads 134-byte V2 header");
    const size_t remainder = reader.size();
    const size_t consumed = encoded.size() - remainder;
    Check(consumed == 134, "CBlockHeader consumed all 134 bytes");
    Check(remainder == 0, "CBlockHeader left 0 remainder bytes");
    Check(Same(v2_block_hdr.ToV2Header(), header),
          "CBlockHeader round-trips all V2 header fields");

    const BlockHash hdr_hash = v2_block_hdr.GetHash();
    Hash v2_id{};
    Check(BlockId(chain_id, header, v2_id), "V2 header id");
    Check(hdr_hash.size() == v2_id.size(), "both ids are 32 bytes");
    Check(std::equal(v2_id.begin(), v2_id.end(), hdr_hash.begin()),
          "CBlockHeader hash matches V2 header id");
    SetActiveV2ChainId(ChainId{});

    Header parsed;
    parsed.version = 0xdeadbeef;
    Check(ParseHeader(encoded.data(), encoded.size(), parsed),
          "V2 parser accepts the 134-byte encoding");
    Check(Same(parsed, header), "V2 parser returns the original fields");

    Header untouched;
    untouched.prev_id.fill(0xa5);
    untouched.tx_root.fill(0x5a);
    untouched.state_root.fill(0x3c);
    untouched.bits = 0xa5a5a5a5u;
    untouched.time = 0x010203040506;
    untouched.nonce = 0x1112131415161718ull;
    untouched.version = 0xdeadbeef;
    untouched.size = 0x2222222222222222ull;
    untouched.height = 0x3333333333333333ull;
    const Header before = untouched;
    std::array<uint8_t, 133> truncated{};
    std::copy_n(encoded.begin(), truncated.size(), truncated.begin());
    Check(truncated.size() == 133, "truncated buffer is 133 bytes");
    Check(!ParseHeader(truncated.data(), truncated.size(), untouched),
          "V2 parser rejects a 133-byte buffer");
    Check(Same(untouched, before),
          "failed V2 parse leaves the output unchanged");

    // Verify CTransaction v7 wire serialization and TxId/TxHash match Lotus V2.
    SetActiveV2ChainId(chain_id);
    Transaction v2_tx;
    v2_tx.lock = (42ULL << 8) | 1ULL;
    Input v2_in;
    v2_in.prev_txid = header.prev_id;
    v2_in.prev_index = 1;
    v2_in.sequence = 0xffffffffU;
    v2_in.flags = 1;
    v2_in.path_index = 0;
    BranchWitness wit;
    wit.script = {0x4e};
    wit.arguments = {{0x01, 0x02}};
    v2_in.witnesses = {wit};
    v2_tx.inputs = {v2_in};
    Output v2_out;
    v2_out.flags = 0;
    v2_out.value = 1000;
    v2_out.branches = {BranchLeaf(std::vector<uint8_t>{0x4e})};
    v2_out.paths = {{0}};
    v2_tx.outputs = {v2_out};
    std::vector<uint8_t> tx_wire;
    std::string tx_err;
    Check(EncodeTransaction(v2_tx, DefaultTxProfile, tx_wire, tx_err),
          "EncodeTransaction succeeds");
    SpanReader tx_reader{tx_wire};
    CTransaction ctx(deserialize, tx_reader);
    Check(tx_reader.size() == 0, "CTransaction consumed full V2 v7 wire");
    Hash32 exp_txid{}, exp_txhash{};
    Check(ComputeTransactionIdentities(v2_tx, DefaultTxProfile, chain_id,
                                       exp_txid, exp_txhash, tx_err),
          "ComputeTransactionIdentities succeeds");
    Check(std::equal(exp_txid.begin(), exp_txid.end(), ctx.GetId().begin()),
          "CTransaction::GetId matches V2 TxId");
    Check(std::equal(exp_txhash.begin(), exp_txhash.end(),
                     ctx.GetHash().begin()),
          "CTransaction::GetHash matches V2 TxHash");
    Check(ctx.GetId() != ctx.GetHash(),
          "CTransaction::GetId and GetHash are distinct for spend with witness args");

    // Verify 64-bit V2 lock round-trips losslessly even when kind/value crosses
    // legacy 500000000 or 32-bit boundaries.
    for (uint64_t test_lock : {0ULL, (600000000ULL << 8) | 1ULL,
                               (123ULL << 8) | 2ULL,
                               (0x123456789abcULL << 8) | 1ULL}) {
        Transaction lock_tx = v2_tx;
        lock_tx.lock = test_lock;
        std::vector<uint8_t> lock_wire;
        Check(EncodeTransaction(lock_tx, DefaultTxProfile, lock_wire, tx_err),
              "EncodeTransaction for lock test succeeds");
        SpanReader lock_reader{lock_wire};
        CTransaction lock_ctx(deserialize, lock_reader);
        Check(lock_ctx.ToV2Transaction().lock == test_lock,
              "CTransaction preserves full 64-bit V2 lock");
        std::vector<uint8_t> reencoded_bytes;
        VectorWriter reencoder{reencoded_bytes, 0};
        reencoder << lock_ctx;
        Check(reencoded_bytes == lock_wire,
              "CTransaction re-serializes identical V2 wire bytes");
    }

    // Verify CTxIn::operator== and CTxOut::operator== compare V2 fields.
    CTxIn in_a = ctx.vin[0];
    CTxIn in_b = ctx.vin[0];
    Check(in_a == in_b, "identical CTxIn compare equal");
    in_b.vWitnesses[0].arguments = {{0x99}};
    Check(in_a != in_b, "CTxIn::operator== detects vWitnesses difference");

    CTxOut out_a = ctx.vout[0];
    CTxOut out_b = ctx.vout[0];
    Check(out_a == out_b, "identical CTxOut compare equal");
    out_b.vPaths = {};
    Check(out_a != out_b, "CTxOut::operator== detects vPaths difference");

    // Verify EncodeCoin / DecodeCoinBytes lossless roundtrip for UtxoSet persistence.
    lotus::v2::Coin v2_coin;
    v2_coin.outpoint = {header.prev_id, 3};
    v2_coin.output = v2_out;
    v2_coin.creation_height = 42;
    v2_coin.creation_parent_mtp = 1700000000ULL;
    v2_coin.coinbase = true;
    std::vector<uint8_t> coin_bytes;
    Check(EncodeCoin(v2_coin, coin_bytes), "EncodeCoin succeeds");
    lotus::v2::Coin decoded_coin;
    Check(DecodeCoinBytes(coin_bytes, decoded_coin), "DecodeCoinBytes succeeds");
    Check(decoded_coin.outpoint == v2_coin.outpoint &&
              decoded_coin.output.flags == v2_coin.output.flags &&
              decoded_coin.output.value == v2_coin.output.value &&
              decoded_coin.output.branches == v2_coin.output.branches &&
              decoded_coin.output.paths == v2_coin.output.paths &&
              decoded_coin.creation_height == v2_coin.creation_height &&
              decoded_coin.creation_parent_mtp == v2_coin.creation_parent_mtp &&
              decoded_coin.coinbase == v2_coin.coinbase,
          "DecodeCoinBytes round-trips all Coin fields");

    SetActiveV2ChainId(ChainId{});

    std::cout << "V2 header boundary: serialized " << encoded.size()
              << " bytes; CBlockHeader consumed " << consumed
              << " and matched V2 header id; CTransaction v7 round-trip passed\n";
    return 0;
}
