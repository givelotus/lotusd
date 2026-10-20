// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Port of the chronik-db/src/mdbx.rs tests.

#include <ext/lotus_v2/db/env.h>
#include <ext/lotus_v2/db/test/v2_test_util.h>

#include <boost/test/unit_test.hpp>

using namespace chronik::native::lotus_v2;
using namespace chronik::native::lotus_v2::test;

namespace {
using Op36 = std::array<uint8_t, 36>;

Op36 Fill36(uint8_t b) {
    Op36 a;
    a.fill(b);
    return a;
}

Bytes PostingKey(const Bytes32 &root, uint8_t pos, const Op36 &op) {
    Bytes k{'p'};
    k.insert(k.end(), root.begin(), root.end());
    k.push_back(pos);
    k.insert(k.end(), op.begin(), op.end());
    return k;
}

Bytes B(std::string_view s) { return Bytes(s.begin(), s.end()); }
} // namespace

BOOST_AUTO_TEST_SUITE(lotus_v2_env_tests)

BOOST_AUTO_TEST_CASE(named_subdatabases_dupfixed_postings_and_flat_files) {
    V2TempDir dir("mdbx-v2-unit");
    V2Env env(dir.path);
    BOOST_CHECK(env.IsEmpty());
    BOOST_CHECK(std::filesystem::is_regular_file(dir.path / "mdbx.dat"));

    const Bytes32 root = B32(7);
    const uint8_t pos = 3;
    const Op36 op1 = Fill36(1), op2 = Fill36(2), op3 = Fill36(3);
    V2WriteBatch batch;
    batch.Put(PostingKey(root, pos, op2), {});
    batch.Put(PostingKey(root, pos, op1), {});
    batch.Put(PostingKey(root, pos, op3), {});
    batch.Put(B("tip"), B("anchor-bytes"));
    env.Write(batch);

    std::optional<V2EnvSnapshot> snap(env.Snapshot());
    BOOST_CHECK(snap->Get(Str("tip")) == B("anchor-bytes"));
    BOOST_CHECK(snap->NextPostingDupfixed(root, pos, std::nullopt) == op1);
    BOOST_CHECK(snap->NextPostingDupfixed(root, pos, op1) == op2);
    Op36 between = op2;
    between[35] = 99;
    BOOST_CHECK(snap->NextPostingDupfixed(root, pos, between) == op3);
    BOOST_CHECK(!snap->NextPostingDupfixed(root, pos, op3));

    // Delete the middle duplicate value without affecting op1 and op3.
    V2WriteBatch del_batch;
    del_batch.Delete(PostingKey(root, pos, op2));
    env.Write(del_batch);

    std::optional<V2EnvSnapshot> snap2(env.Snapshot());
    BOOST_CHECK(snap2->NextPostingDupfixed(root, pos, op1) == op3);
    // The old MVCC snapshot still sees op2.
    BOOST_CHECK(snap->NextPostingDupfixed(root, pos, op1) == op2);
    snap.reset();
    snap2.reset();

    // Multi-page dups (300 x 36B > 4096B page size).
    const Bytes32 root_multi = B32(9);
    V2WriteBatch multi_batch;
    std::vector<Op36> expected_ops;
    for (uint32_t i = 0; i < 300; ++i) {
        Op36 op{};
        for (int b = 0; b < 4; ++b) {
            op[b] = uint8_t(i >> (24 - 8 * b));
        }
        expected_ops.push_back(op);
        multi_batch.Put(PostingKey(root_multi, pos, op), {});
    }
    env.Write(multi_batch);

    const V2EnvSnapshot snap3 = env.Snapshot();
    BOOST_CHECK(snap3.PostingsDupfixedAfter(root_multi, pos, std::nullopt) ==
                expected_ops);
    BOOST_CHECK(snap3.PostingsDupfixedAfter(root_multi, pos,
                                            expected_ops[150]) ==
                std::vector<Op36>(expected_ops.begin() + 151,
                                  expected_ops.end()));
    std::vector<Op36> iter_ops;
    std::optional<Op36> cursor_op;
    while (auto next_op =
               snap3.NextPostingDupfixed(root_multi, pos, cursor_op)) {
        iter_ops.push_back(*next_op);
        cursor_op = next_op;
    }
    BOOST_CHECK(iter_ops == expected_ops);
}

BOOST_AUTO_TEST_SUITE_END()
