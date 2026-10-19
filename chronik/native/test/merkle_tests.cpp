// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the Rust tests in chronik-indexer merkle.rs, plus hook/error tests.

#include <chronik/native/merkle.h>

#include <test/test_sha256.h>

#include <boost/test/unit_test.hpp>

#include <climits>
#include <stdexcept>
#include <string>
#include <vector>

using namespace chronik::native;

namespace {

Sha256dFn TestSha256d() {
    return Sha256dFromSha256(
        [](ByteView data, uint8_t out[32]) { test::TestSha256(data, out); });
}

Hash32 HexToSha256d(const std::string &hex) {
    BOOST_REQUIRE_EQUAL(hex.size(), 64u);
    Bytes be;
    for (size_t i = 0; i < 64; i += 2) {
        be.push_back(uint8_t(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    // Sha256d::from_be_hex
    return Hash32::FromReversed(be);
}

std::vector<Hash32> GetBlockchainHashes() {
    // First block hashes in the bitcoin blockchain
    const char *hexes[] = {
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
        "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd",
        "0000000082b5015589a3fdf2d4baff403e6f0be035a5d9742c1cae6295464449",
        "000000004ebadb55ee9096c9a2f8880e09da59c0d68b1c228da88e48844a1485",
        "000000009b7262315dbf071787ad3656097b892abffd1f95a1a022f896f533fc",
        "000000003031a0e73735690c5a1ff2a4be82553b2a12b776fbd3a215dc8f778d",
        "0000000071966c2b1d065fd446b1e485b2c9d9594acd2007ccbd5441cfc89444",
        "00000000408c48f847aa786c2268fc3e6ec2af68e8468a34a28c61b7f1de0dc6",
        "000000008d9dc510f23c2657fc4f67bea30078cc05a90eb89e84cc475c080805",
        "000000002c05cc2e78923c34df87fd108b22221ac6076c18f3ade378a4d915e9",
        "0000000097be56d606cdd9c54b04d4747e957d3608abe69198c661f2add73073",
        "0000000027c2488e2510d1acf4369787784fa20ee084c258b58d9fbd43802b5e",
        "000000005c51de2031a895adc145ee2242e919a01c6d61fb222a54a54b4d3089",
        "0000000080f17a0c5a67f663a9bc9969eb37e81666d9321125f0e293656f8a37",
        "00000000b3322c8c3ef7d2cf6da009a776e6a99ee65ec5a32f3f345712238473",
        "00000000174a25bb399b009cc8deff1c4b3ea84df7e93affaaf60dc3416cc4f5",
    };
    std::vector<Hash32> out;
    for (const char *h : hexes) {
        out.push_back(HexToSha256d(h));
    }
    return out;
}

// These roots as well as the merkle branches tested below can be checked
// using Electrum ABC's console (see merkle.rs).
std::vector<Hash32> GetMerkleRoots() {
    const char *hexes[] = {
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        "abdc2227d02d114b77be15085c1257709252a7a103f9ac0ab3c85d67e12bc0b8",
        "6ce668e2ec49dae449c0d55de7b1c973696c7d4a47024dbcb26ee99411244ff6",
        "965ac94082cebbcffe458075651e9cc33ce703ab0115c72d9e8b1a9906b2b636",
        "a7b8e38ec91da1483864ecd86a19580a79c385c3871c1b74e4c9cca38a9a43a5",
        "8128c71269a41befbdbacb87e90cf246991cc305a357df36ddb4345f1e691f52",
        "1872dce49586510591bb2a2a10fba53300694c85995cdb64aa72f871bb688d88",
        "c809e7a698a4b4c474ff6f5f05e88af6d7cb80ddbbe302660dfe6bd1969224a2",
        "e347b1c43fd9b5415bf0d92708db8284b78daf4d0e24f9c3405f45feb85e25db",
        "8a5027e722a53eef05400679fe711bd5cea74ba0b604d9a98caabf8ac0986a7e",
        "8b8f513a34feeb1f2cdac70fcd97042be23ccd64de9d66d36f9407bbc1809f5f",
        "b05152646ed9384d234ae37e034db54e1ff65314200edd9617c53cd72a2e706d",
        "15288b27a233994b809901c91af1bd27992b20b26cf187b4eb72d6a2858ff5f0",
        "77f9bc6eae1e18f92f746fb2f6b8f66c11086833ae2177f60905f0b2397ef67a",
        "4ffb2fac9ecd33b1925bae9c8e2ae89b85078b90853b1feb5d7038a8fdbd1176",
        "3cdcb64f35c3fc45a2737c2c22c5b61ccb8b93d36af10d21ae953b7d91e094d7",
        "ad1bb2b84eeb782e3cc281cc801ae5da49a43b60b2a37c265c37737553709f21",
    };
    std::vector<Hash32> out;
    for (const char *h : hexes) {
        out.push_back(HexToSha256d(h));
    }
    return out;
}

MerkleHashGetter MakeGetter(const std::vector<Hash32> &hashes) {
    return [&hashes](size_t start, size_t count) {
        return std::vector<Hash32>(hashes.begin() + start,
                                   hashes.begin() + start + count);
    };
}

std::pair<Hash32, std::vector<Hash32>>
Uncached(const std::vector<Hash32> &hashes, size_t length, size_t index) {
    return MerkleRootAndBranch(
        TestSha256d(), std::span<const Hash32>(hashes.data(), length), index);
}

} // namespace

BOOST_AUTO_TEST_SUITE(merkle_tests)

BOOST_AUTO_TEST_CASE(test_roots) {
    const auto blockhashes = GetBlockchainHashes();
    const auto roots = GetMerkleRoots();
    BOOST_REQUIRE_EQUAL(blockhashes.size(), roots.size());
    for (size_t i = 0; i < blockhashes.size(); ++i) {
        const auto [root, branch] = Uncached(blockhashes, i + 1, 0);
        BOOST_CHECK(root == roots[i]);
    }
}

BOOST_AUTO_TEST_CASE(test_branches) {
    const auto bh = GetBlockchainHashes();

    auto branch = Uncached(bh, 1, 0).second;
    BOOST_CHECK(branch.empty());

    branch = Uncached(bh, 2, 0).second;
    BOOST_REQUIRE_EQUAL(branch.size(), 1u);
    BOOST_CHECK(branch[0] == bh[1]);

    branch = Uncached(bh, 2, 1).second;
    BOOST_REQUIRE_EQUAL(branch.size(), 1u);
    BOOST_CHECK(branch[0] == bh[0]);

    using V = std::vector<Hash32>;
    BOOST_CHECK(Uncached(bh, 3, 0).second ==
                (V{bh[1], HexToSha256d("66e512a6e02cea83ac65cbdd907a2731e778b9"
                                       "6b71839ff7b19836c433c5c92b")}));
    BOOST_CHECK(Uncached(bh, 3, 1).second ==
                (V{bh[0], HexToSha256d("66e512a6e02cea83ac65cbdd907a2731e778b9"
                                       "6b71839ff7b19836c433c5c92b")}));
    BOOST_CHECK(Uncached(bh, 3, 2).second ==
                (V{bh[2], HexToSha256d("abdc2227d02d114b77be15085c1257709252a7"
                                       "a103f9ac0ab3c85d67e12bc0b8")}));
    BOOST_CHECK(Uncached(bh, 16, 7).second ==
                (V{bh[6],
                   HexToSha256d("f9f17a3c6d02b0920eccb11156df370bf4117fae2233df"
                                "ee40817586ba981ca5"),
                   HexToSha256d("965ac94082cebbcffe458075651e9cc33ce703ab0115c7"
                                "2d9e8b1a9906b2b636"),
                   HexToSha256d("a0c4df031de8f1370f278ac9f3dcdca4f627f86ff6238f"
                                "09e40270bb9ecd3f62")}));
    BOOST_CHECK(Uncached(bh, 16, 10).second ==
                (V{bh[11],
                   HexToSha256d("cd5d21a5bc8ad65c8dc862bd9e6ec38f914ee6499d7e0a"
                                "d23d7ca9582770b6c2"),
                   HexToSha256d("d84ed7114670b8d129dd1d50970315995c0d6309e0935e"
                                "7bbc91477bfc717d3a"),
                   HexToSha256d("c809e7a698a4b4c474ff6f5f05e88af6d7cb80ddbbe302"
                                "660dfe6bd1969224a2")}));
    BOOST_CHECK(Uncached(bh, 16, 15).second ==
                (V{bh[14],
                   HexToSha256d("e55021736ef89c3787e2729058a76a3cf6decf561b856c"
                                "57eb88ed99899009d1"),
                   HexToSha256d("e9106987dc15c9ea710feeed3c2b3252cbfe2192580369"
                                "6ea52aa7b50a0f1085"),
                   HexToSha256d("c809e7a698a4b4c474ff6f5f05e88af6d7cb80ddbbe302"
                                "660dfe6bd1969224a2")}));
}

BOOST_AUTO_TEST_CASE(test_cached_matches_uncached) {
    const auto bh = GetBlockchainHashes();
    const auto roots = GetMerkleRoots();
    MerkleTree cache(TestSha256d());
    for (size_t i = 0; i < bh.size(); ++i) {
        const size_t length = i + 1;
        for (size_t index = 0; index < length; ++index) {
            const auto got = cache.MerkleRootAndBranch(length, index, MakeGetter(bh));
            const auto expected = Uncached(bh, length, index);
            BOOST_CHECK(got == expected);
            if (index == 0) {
                BOOST_CHECK(got.first == roots[i]);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(test_cache_fetches_only_segment_when_warm) {
    const auto bh = GetBlockchainHashes();
    MerkleTree cache(TestSha256d());
    // Warm the cache for all hashes.
    cache.MerkleRootAndBranch(bh.size(), 0, MakeGetter(bh));

    size_t max_count = 0, total_fetched = 0;
    cache.MerkleRootAndBranch(bh.size(), 7, [&](size_t start, size_t count) {
        BOOST_CHECK(start + count <= bh.size());
        max_count = std::max(max_count, count);
        total_fetched += count;
        return std::vector<Hash32>(bh.begin() + start,
                                   bh.begin() + start + count);
    });
    // After warm-up, a proof should only pull one mid-level segment.
    BOOST_CHECK(max_count < bh.size());
    BOOST_CHECK(total_fetched < bh.size());
}

BOOST_AUTO_TEST_CASE(test_truncate) {
    const auto bh = GetBlockchainHashes();
    MerkleTree cache(TestSha256d());
    cache.MerkleRootAndBranch(bh.size(), 0, MakeGetter(bh));
    BOOST_CHECK(cache.IsInitialized());
    BOOST_CHECK_EQUAL(cache.Length(), bh.size());

    cache.Truncate(8);
    BOOST_CHECK(cache.IsInitialized());
    BOOST_CHECK_EQUAL(cache.Length(), 8u);

    const auto got = cache.MerkleRootAndBranch(8, 3, MakeGetter(bh));
    BOOST_CHECK(got == Uncached(bh, 8, 3));

    cache.Truncate(0);
    BOOST_CHECK(!cache.IsInitialized());
    BOOST_CHECK_EQUAL(cache.Length(), 0u);
}

BOOST_AUTO_TEST_CASE(test_functional_sequence) {
    // Mirrors chronik_block_header.py: grow cache tip-first, then query
    // shorter checkpoints (including lengths aligned to the segment size).
    const auto bh = GetBlockchainHashes();
    MerkleTree cache(TestSha256d());
    for (size_t i = 1; i < 11; ++i) {
        const size_t length = i + 1;
        BOOST_CHECK_MESSAGE(cache.MerkleRootAndBranch(length, i, MakeGetter(bh)) ==
                                Uncached(bh, length, i),
                            "grow i=" << i);
    }
    for (size_t cp = 1; cp < 11; ++cp) {
        const size_t length = cp + 1;
        for (size_t h = 0; h < length; ++h) {
            BOOST_CHECK_MESSAGE(
                cache.MerkleRootAndBranch(length, h, MakeGetter(bh)) ==
                    Uncached(bh, length, h),
                "cp=" << cp << " h=" << h);
        }
    }
}

BOOST_AUTO_TEST_CASE(test_truncate_then_extend_after_reorg) {
    auto bh = GetBlockchainHashes();
    MerkleTree cache(TestSha256d());
    cache.MerkleRootAndBranch(bh.size(), 0, MakeGetter(bh));

    // Invalidate from height 5 upward (same idea as chronik_block_header.py).
    cache.Truncate(5);
    // Replace the tip and grow a new fork.
    bh.resize(5);
    bh.push_back(HexToSha256d(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    for (int k = 0; k < 10; ++k) {
        Hash32 h;
        h.b.fill(uint8_t(bh.size()));
        bh.push_back(h);
    }
    for (size_t cp = 1; cp < bh.size(); ++cp) {
        const size_t length = cp + 1;
        for (size_t h = 0; h < length; ++h) {
            BOOST_CHECK_MESSAGE(
                cache.MerkleRootAndBranch(length, h, MakeGetter(bh)) ==
                    Uncached(bh, length, h),
                "cp=" << cp << " h=" << h);
        }
    }
}

BOOST_AUTO_TEST_CASE(test_bad_args) {
    MerkleTree cache(TestSha256d());
    const auto hashes = GetBlockchainHashes();
    try {
        cache.MerkleRootAndBranch(0, 0, MakeGetter(hashes));
        BOOST_FAIL("expected MerkleTreeError");
    } catch (const MerkleTreeError &e) {
        BOOST_CHECK(e.kind() == MerkleTreeError::Kind::BadArgs);
        BOOST_CHECK_EQUAL(std::string(e.what()), "Invalid merkle tree arguments");
    }
}

BOOST_AUTO_TEST_CASE(test_calc_branch_len_0_panics) {
    BOOST_CHECK_THROW(CalcBranchLen(0), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_calc_branch_len) {
    BOOST_CHECK_EQUAL(CalcBranchLen(1), 0u);
    BOOST_CHECK_EQUAL(CalcBranchLen(2), 1u);
    // for i in 2..usize::MAX.ilog2()
    for (size_t i = 2; i < 63; ++i) {
        const size_t p = size_t(1) << i;
        BOOST_CHECK_EQUAL(CalcBranchLen(p - 1), i);
        BOOST_CHECK_EQUAL(CalcBranchLen(p), i);
        BOOST_CHECK_EQUAL(CalcBranchLen(p + 1), i + 1);
    }
}

// ---- native-only tests ----

BOOST_AUTO_TEST_CASE(native_hash_count_mismatch) {
    const auto bh = GetBlockchainHashes();
    MerkleTree cache(TestSha256d());
    try {
        cache.MerkleRootAndBranch(4, 0, [&](size_t start, size_t count) {
            return std::vector<Hash32>(bh.begin() + start,
                                       bh.begin() + start + count - 1);
        });
        BOOST_FAIL("expected MerkleTreeError");
    } catch (const MerkleTreeError &e) {
        BOOST_CHECK(e.kind() == MerkleTreeError::Kind::HashCountMismatch);
        BOOST_CHECK_EQUAL(std::string(e.what()),
                          "Expected 4 hashes from provider, got 3");
    }
    BOOST_CHECK(!cache.IsInitialized());
}

BOOST_AUTO_TEST_CASE(native_getter_error_propagates) {
    MerkleTree cache(TestSha256d());
    BOOST_CHECK_EXCEPTION(
        cache.MerkleRootAndBranch(3, 1,
                                  [](size_t, size_t) -> std::vector<Hash32> {
                                      throw ChronikError("404: nope");
                                  }),
        ChronikError,
        [](const ChronikError &e) { return std::string(e.what()) == "404: nope"; });
}

BOOST_AUTO_TEST_CASE(native_index_out_of_range) {
    const auto bh = GetBlockchainHashes();
    MerkleTree cache(TestSha256d());
    BOOST_CHECK_THROW(cache.MerkleRootAndBranch(3, 3, MakeGetter(bh)),
                      MerkleTreeError);
    BOOST_CHECK_THROW(MerkleRootAndBranch(TestSha256d(), {}, 0), std::logic_error);
    BOOST_CHECK_THROW(
        MerkleRootAndBranch(TestSha256d(), std::span<const Hash32>(bh.data(), 2), 2),
        std::logic_error);
}

BOOST_AUTO_TEST_CASE(native_sha256d_hook) {
    // sha256d("") = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
    const Hash32 h = TestSha256d()(ByteView());
    BOOST_CHECK(h == Hash32::FromBytes(
                         std::vector<uint8_t>{
                             0x5d, 0xf6, 0xe0, 0xe2, 0x76, 0x13, 0x59, 0xd3,
                             0x0a, 0x82, 0x75, 0x05, 0x8e, 0x29, 0x9f, 0xcc,
                             0x03, 0x81, 0x53, 0x45, 0x45, 0xf5, 0x5c, 0xf4,
                             0x3e, 0x41, 0x98, 0x3f, 0x5d, 0x4c, 0x94, 0x56}));
}

BOOST_AUTO_TEST_CASE(native_large_chain_cached_matches_uncached) {
    // Exercise several depth_higher changes and segment boundaries.
    std::vector<Hash32> hashes;
    for (int i = 0; i < 300; ++i) {
        Hash32 h;
        h.b[0] = uint8_t(i);
        h.b[1] = uint8_t(i >> 8);
        h.b[31] = 0x77;
        hashes.push_back(h);
    }
    MerkleTree cache(TestSha256d());
    const size_t lengths[] = {1, 2, 3, 5, 16, 17, 64, 65, 100, 255, 256, 257, 300,
                              120, 33, 299};
    for (size_t length : lengths) {
        for (size_t index : {size_t(0), length / 3, length / 2, length - 1}) {
            BOOST_CHECK_MESSAGE(
                cache.MerkleRootAndBranch(length, index, MakeGetter(hashes)) ==
                    Uncached(hashes, length, index),
                "len=" << length << " idx=" << index);
        }
        if (length == 257) {
            cache.Truncate(70);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
