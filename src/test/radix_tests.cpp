// Copyright (c) 2019 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <radix.h>
#include <radix_map.h>

#include <arith_uint256.h>
#include <uint256.h>
#include <uint256radixkey.h>
#include <util/strencodings.h>

#include <test/lcg.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <chrono>
#include <future>
#include <thread>
#include <type_traits>

BOOST_FIXTURE_TEST_SUITE(radix_tests, BasicTestingSetup)

template <typename K> struct TestElement {
    K key;

    TestElement(K keyIn) : key(keyIn) {}
    const K &getId() const { return key; }

    IMPLEMENT_RCU_REFCOUNT(uint32_t);
};

template <typename K> struct TestElementInt : TestElement<K> {
    TestElementInt(K keyIn) : TestElement<K>(std::move(keyIn)) {}

    static auto SignedMin() {
        return std::numeric_limits<typename std::make_signed<K>::type>::min();
    }
    static auto SignedMax() {
        return std::numeric_limits<typename std::make_signed<K>::type>::max();
    }
    static auto MinusOne() {
        return std::numeric_limits<typename std::make_unsigned<K>::type>::max();
    }
    static auto MinusTwo() {
        return std::numeric_limits<
                   typename std::make_unsigned<K>::type>::max() -
               1;
    }
};

struct TestElementUint256 : TestElement<Uint256RadixKey> {
    TestElementUint256(const uint256 &keyIn)
        : TestElement<Uint256RadixKey>(Uint256RadixKey(keyIn)) {}
    TestElementUint256(uint64_t keyIn)
        : TestElement<Uint256RadixKey>(Uint256RadixKey(keyIn)) {}

    static inline arith_uint256 signedMin = arith_uint256(1) << 255;
    static inline arith_uint256 signedMax = ~signedMin;
    static inline arith_uint256 minusOne = arith_uint256(0) - 1;
    static inline arith_uint256 minusTwo = minusOne - 1;

    static uint256 SignedMin() { return ArithToUint256(signedMin); }
    static uint256 SignedMax() { return ArithToUint256(signedMax); }
    static uint256 MinusOne() { return ArithToUint256(minusOne); }
    static uint256 MinusTwo() { return ArithToUint256(minusTwo); }
};

template <typename E> void testInsert() {
    RadixTree<E> mytree;

    auto zero = RCUPtr<E>::make(0);
    auto one = RCUPtr<E>::make(1);
    auto two = RCUPtr<E>::make(2);
    auto three = RCUPtr<E>::make(3);

    // Inserting a new element into the tree returns true.
    BOOST_CHECK(mytree.insert(one));

    // Inserting an element already in the tree returns false.
    BOOST_CHECK(!mytree.insert(one));

    // Let's insert more elements and check behavior stays consistent.
    BOOST_CHECK(mytree.insert(zero));
    BOOST_CHECK(!mytree.insert(one));
    BOOST_CHECK(mytree.insert(two));
    BOOST_CHECK(mytree.insert(three));
    BOOST_CHECK(!mytree.insert(zero));
    BOOST_CHECK(!mytree.insert(one));
    BOOST_CHECK(!mytree.insert(two));
    BOOST_CHECK(!mytree.insert(three));

    // Check extreme values.
    auto maxsigned = RCUPtr<E>::make(E::SignedMax());
    auto minsigned = RCUPtr<E>::make(E::SignedMin());
    auto minusone = RCUPtr<E>::make(E::MinusOne());
    auto minustwo = RCUPtr<E>::make(E::MinusTwo());

    // Insert them into the tree.
    BOOST_CHECK(mytree.insert(maxsigned));
    BOOST_CHECK(mytree.insert(minsigned));
    BOOST_CHECK(mytree.insert(minusone));
    BOOST_CHECK(mytree.insert(minustwo));

    // All elements are now in the tree.
    BOOST_CHECK(!mytree.insert(zero));
    BOOST_CHECK(!mytree.insert(one));
    BOOST_CHECK(!mytree.insert(two));
    BOOST_CHECK(!mytree.insert(three));
    BOOST_CHECK(!mytree.insert(maxsigned));
    BOOST_CHECK(!mytree.insert(minsigned));
    BOOST_CHECK(!mytree.insert(minusone));
    BOOST_CHECK(!mytree.insert(minustwo));
}

BOOST_AUTO_TEST_CASE(insert_test) {
    testInsert<TestElementInt<int32_t>>();
    testInsert<TestElementInt<uint32_t>>();
    testInsert<TestElementInt<int64_t>>();
    testInsert<TestElementInt<uint64_t>>();

    testInsert<TestElementUint256>();
}

template <typename E> void testGet() {
    RadixTree<E> mytree;

    auto zero = RCUPtr<E>::make(0);
    auto one = RCUPtr<E>::make(1);
    auto two = RCUPtr<E>::make(2);
    auto three = RCUPtr<E>::make(3);

    auto keyZero = zero->getId();
    auto keyOne = one->getId();
    auto keyTwo = two->getId();
    auto keyThree = three->getId();

    // There are no elements in the tree so far.
    BOOST_CHECK_EQUAL(mytree.get(keyOne), nullptr);

    // Insert an element into the tree and check it is there.
    BOOST_CHECK(mytree.insert(one));
    BOOST_CHECK_EQUAL(mytree.get(keyOne), one);

    // Let's insert more elements and check they are recovered properly.
    BOOST_CHECK_EQUAL(mytree.get(keyZero), nullptr);
    BOOST_CHECK(mytree.insert(zero));
    BOOST_CHECK_EQUAL(mytree.get(keyZero), zero);
    BOOST_CHECK_EQUAL(mytree.get(keyOne), one);

    // More elements.
    BOOST_CHECK_EQUAL(mytree.get(keyTwo), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(keyThree), nullptr);
    BOOST_CHECK(mytree.insert(two));
    BOOST_CHECK(mytree.insert(three));

    BOOST_CHECK_EQUAL(mytree.get(keyZero), zero);
    BOOST_CHECK_EQUAL(mytree.get(keyOne), one);
    BOOST_CHECK_EQUAL(mytree.get(keyTwo), two);
    BOOST_CHECK_EQUAL(mytree.get(keyThree), three);

    auto maxsigned = RCUPtr<E>::make(E::SignedMax());
    auto minsigned = RCUPtr<E>::make(E::SignedMin());
    auto minusone = RCUPtr<E>::make(E::MinusOne());
    auto minustwo = RCUPtr<E>::make(E::MinusTwo());

    // Check that they are not in the tree.
    BOOST_CHECK_EQUAL(mytree.get(E::SignedMax()), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(E::SignedMin()), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(E::MinusOne()), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(E::MinusTwo()), nullptr);

    // Insert into the tree.
    BOOST_CHECK(mytree.insert(maxsigned));
    BOOST_CHECK(mytree.insert(minsigned));
    BOOST_CHECK(mytree.insert(minusone));
    BOOST_CHECK(mytree.insert(minustwo));

    // And now they all are in the tree.
    BOOST_CHECK_EQUAL(mytree.get(keyZero), zero);
    BOOST_CHECK_EQUAL(mytree.get(keyOne), one);
    BOOST_CHECK_EQUAL(mytree.get(keyTwo), two);
    BOOST_CHECK_EQUAL(mytree.get(keyThree), three);
    BOOST_CHECK_EQUAL(mytree.get(E::SignedMax()), maxsigned);
    BOOST_CHECK_EQUAL(mytree.get(E::SignedMin()), minsigned);
    BOOST_CHECK_EQUAL(mytree.get(E::MinusOne()), minusone);
    BOOST_CHECK_EQUAL(mytree.get(E::MinusTwo()), minustwo);
}

BOOST_AUTO_TEST_CASE(get_test) {
    testGet<TestElementInt<int32_t>>();
    testGet<TestElementInt<uint32_t>>();
    testGet<TestElementInt<int64_t>>();
    testGet<TestElementInt<uint64_t>>();

    testGet<TestElementUint256>();
}

template <typename E> void testRemove() {
    RadixTree<E> mytree;

    auto zero = RCUPtr<E>::make(0);
    auto one = RCUPtr<E>::make(1);
    auto two = RCUPtr<E>::make(2);
    auto three = RCUPtr<E>::make(3);

    auto keyZero = zero->getId();
    auto keyOne = one->getId();
    auto keyTwo = two->getId();
    auto keyThree = three->getId();

    // Removing an element that isn't in the tree returns false.
    BOOST_CHECK(!mytree.remove(keyOne));

    // Insert an element into the tree and check you can remove it.
    BOOST_CHECK(mytree.insert(one));
    BOOST_CHECK(mytree.remove(keyOne));
    BOOST_CHECK_EQUAL(mytree.get(keyOne), nullptr);

    // Insert several elements and remove them.
    BOOST_CHECK(mytree.insert(zero));
    BOOST_CHECK(mytree.insert(one));
    BOOST_CHECK(mytree.insert(two));
    BOOST_CHECK(mytree.insert(three));

    BOOST_CHECK(mytree.remove(keyZero));
    BOOST_CHECK(mytree.remove(keyOne));
    BOOST_CHECK(mytree.remove(keyTwo));
    BOOST_CHECK(mytree.remove(keyThree));

    BOOST_CHECK_EQUAL(mytree.get(keyZero), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(keyOne), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(keyTwo), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(keyThree), nullptr);

    // Once the elements are removed, removing them again returns false.
    BOOST_CHECK(!mytree.remove(keyZero));
    BOOST_CHECK(!mytree.remove(keyOne));
    BOOST_CHECK(!mytree.remove(keyTwo));
    BOOST_CHECK(!mytree.remove(keyThree));

    // Check extreme values.
    auto maxsigned = RCUPtr<E>::make(E::SignedMax());
    auto minsigned = RCUPtr<E>::make(E::SignedMin());
    auto minusone = RCUPtr<E>::make(E::MinusOne());
    auto minustwo = RCUPtr<E>::make(E::MinusTwo());

    // Insert them all.
    BOOST_CHECK(mytree.insert(zero));
    BOOST_CHECK(mytree.insert(one));
    BOOST_CHECK(mytree.insert(two));
    BOOST_CHECK(mytree.insert(three));
    BOOST_CHECK(mytree.insert(maxsigned));
    BOOST_CHECK(mytree.insert(minsigned));
    BOOST_CHECK(mytree.insert(minusone));
    BOOST_CHECK(mytree.insert(minustwo));

    // Delete them all
    BOOST_CHECK(mytree.remove(keyZero));
    BOOST_CHECK(mytree.remove(keyOne));
    BOOST_CHECK(mytree.remove(keyTwo));
    BOOST_CHECK(mytree.remove(keyThree));
    BOOST_CHECK(mytree.remove(E::SignedMax()));
    BOOST_CHECK(mytree.remove(E::SignedMin()));
    BOOST_CHECK(mytree.remove(E::MinusOne()));
    BOOST_CHECK(mytree.remove(E::MinusTwo()));

    BOOST_CHECK_EQUAL(mytree.get(keyZero), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(keyOne), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(keyTwo), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(keyThree), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(E::SignedMax()), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(E::SignedMin()), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(E::MinusOne()), nullptr);
    BOOST_CHECK_EQUAL(mytree.get(E::MinusTwo()), nullptr);
}

BOOST_AUTO_TEST_CASE(remove_test) {
    testRemove<TestElementInt<int32_t>>();
    testRemove<TestElementInt<uint32_t>>();
    testRemove<TestElementInt<int64_t>>();
    testRemove<TestElementInt<uint64_t>>();

    testRemove<TestElementUint256>();
}

BOOST_AUTO_TEST_CASE(const_element_test) {
    using C = const TestElementInt<uint64_t>;
    RadixTree<C> mytree;

    BOOST_CHECK(mytree.insert(RCUPtr<C>::make(0)));
    BOOST_CHECK(mytree.insert(RCUPtr<C>::make(1)));
    BOOST_CHECK(mytree.insert(RCUPtr<C>::make(2)));
    BOOST_CHECK(mytree.insert(RCUPtr<C>::make(3)));

    BOOST_CHECK(!mytree.insert(RCUPtr<C>::make(0)));
    BOOST_CHECK(!mytree.insert(RCUPtr<C>::make(1)));
    BOOST_CHECK(!mytree.insert(RCUPtr<C>::make(2)));
    BOOST_CHECK(!mytree.insert(RCUPtr<C>::make(3)));

    BOOST_CHECK(mytree.get(0));
    BOOST_CHECK(mytree.get(1));
    BOOST_CHECK(mytree.get(2));
    BOOST_CHECK(mytree.get(3));

    BOOST_CHECK(mytree.remove(0));
    BOOST_CHECK(mytree.remove(1));
    BOOST_CHECK(mytree.remove(2));
    BOOST_CHECK(mytree.remove(3));

    BOOST_CHECK(!mytree.get(0));
    BOOST_CHECK(!mytree.get(1));
    BOOST_CHECK(!mytree.get(2));
    BOOST_CHECK(!mytree.get(3));

    BOOST_CHECK(!mytree.remove(0));
    BOOST_CHECK(!mytree.remove(1));
    BOOST_CHECK(!mytree.remove(2));
    BOOST_CHECK(!mytree.remove(3));
}

void CheckConstTree(const RadixTree<TestElementInt<uint64_t>> &mytree,
                    bool expected) {
    BOOST_CHECK_EQUAL(!!mytree.get(0), expected);
    BOOST_CHECK_EQUAL(!!mytree.get(1), expected);
    BOOST_CHECK_EQUAL(!!mytree.get(2), expected);
    BOOST_CHECK_EQUAL(!!mytree.get(3), expected);
}

BOOST_AUTO_TEST_CASE(const_tree_test) {
    using E = TestElementInt<uint64_t>;
    RadixTree<E> mytree;

    CheckConstTree(mytree, false);

    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(0)));
    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(1)));
    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(2)));
    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(3)));

    CheckConstTree(mytree, true);

    BOOST_CHECK(mytree.remove(0));
    BOOST_CHECK(mytree.remove(1));
    BOOST_CHECK(mytree.remove(2));
    BOOST_CHECK(mytree.remove(3));

    CheckConstTree(mytree, false);
}

BOOST_AUTO_TEST_CASE(test_cow) {
    using E = TestElementInt<uint32_t>;

    RadixTree<E> mytree;

    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(0)));
    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(1)));
    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(2)));
    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(3)));

    RadixTree<E> copyTree = mytree;

    // The copy tree is identical.
    BOOST_CHECK(copyTree.get(0));
    BOOST_CHECK(copyTree.get(1));
    BOOST_CHECK(copyTree.get(2));
    BOOST_CHECK(copyTree.get(3));

    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(90)));
    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(91)));
    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(92)));
    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(93)));

    // The copy was unaffected.
    BOOST_CHECK(copyTree.get(0));
    BOOST_CHECK(copyTree.get(1));
    BOOST_CHECK(copyTree.get(2));
    BOOST_CHECK(copyTree.get(3));
    BOOST_CHECK(!copyTree.get(90));
    BOOST_CHECK(!copyTree.get(91));
    BOOST_CHECK(!copyTree.get(92));
    BOOST_CHECK(!copyTree.get(93));

    copyTree = mytree;

    BOOST_CHECK(mytree.remove(0));
    BOOST_CHECK(mytree.remove(1));
    BOOST_CHECK(mytree.remove(2));
    BOOST_CHECK(mytree.remove(3));

    // The copy was unaffected by the removals.
    BOOST_CHECK(copyTree.get(0));
    BOOST_CHECK(copyTree.get(1));
    BOOST_CHECK(copyTree.get(2));
    BOOST_CHECK(copyTree.get(3));
    BOOST_CHECK(copyTree.get(90));
    BOOST_CHECK(copyTree.get(91));
    BOOST_CHECK(copyTree.get(92));
    BOOST_CHECK(copyTree.get(93));
}

BOOST_AUTO_TEST_CASE(immutable_clone_keeps_generic_writer_barrier) {
    using E = TestElementInt<uint64_t>;
    using Tree = RadixTree<E>;
    Tree builder;
    BOOST_REQUIRE(builder.insert(RCUPtr<E>::make(42)));
    auto published = std::make_unique<const Tree>(std::move(builder));
    std::promise<void> generic_started, tagged_started;
    std::promise<void> generic_complete, tagged_complete;
    auto generic_ready = generic_complete.get_future();
    auto tagged_ready = tagged_complete.get_future();
    std::thread generic_worker, tagged_worker;
    std::future_status generic_status, tagged_status;
    {
        RCULock held_reader;
        generic_worker = std::thread([&] {
            generic_started.set_value();
            Tree copy(*published);
            generic_complete.set_value();
        });
        tagged_worker = std::thread([&] {
            tagged_started.set_value();
            Tree copy(*published, Tree::ImmutableSnapshotTag{});
            // Signal before copy destruction or RCU thread-local teardown:
            // thread exit may itself need the held reader's grace period.
            tagged_complete.set_value();
        });
        generic_started.get_future().wait();
        tagged_started.get_future().wait();
        generic_status = generic_ready.wait_for(std::chrono::milliseconds(100));
        tagged_status = tagged_ready.wait_for(std::chrono::seconds(1));
    }
    // Release the reader unconditionally before joining or any fatal assertion.
    generic_worker.join();
    tagged_worker.join();
    BOOST_CHECK(generic_status == std::future_status::timeout);
    BOOST_CHECK(tagged_status == std::future_status::ready);
    BOOST_CHECK(published->get(42));
}

BOOST_AUTO_TEST_CASE(immutable_snapshot_cow) {
    using E = TestElementInt<uint64_t>;
    using Tree = RadixTree<E>;
    Tree builder;
    for (uint64_t key = 0; key < 256; ++key) {
        BOOST_REQUIRE(builder.insert(RCUPtr<E>::make(key)));
    }
    // Transfer the only mutable builder into an immutable published owner.
    auto published = std::make_unique<const Tree>(std::move(builder));
    Tree first(*published, Tree::ImmutableSnapshotTag{});
    Tree second(*published, Tree::ImmutableSnapshotTag{});
    for (uint64_t key = 0; key < 128; ++key) {
        BOOST_REQUIRE(first.remove(key));
        BOOST_REQUIRE(second.insert(RCUPtr<E>::make(key + 256)));
    }
    for (uint64_t key = 0; key < 256; ++key) {
        BOOST_CHECK(published->get(key));
        BOOST_CHECK_EQUAL(bool(first.get(key)), key >= 128);
        BOOST_CHECK(second.get(key));
        BOOST_CHECK(!published->get(key + 256));
    }
    // A join traverses one pinned view and looks up a second view using the
    // existing read guard, without nesting RCU read sections.
    const Tree &second_view = second;
    size_t joined{0};
    first.forEachLeaf([&](const auto &entry) {
        BOOST_CHECK(second_view.getWithinReadSection(entry->getId()));
        ++joined;
        return true;
    });
    BOOST_CHECK_EQUAL(joined, 128U);
    // Descendant snapshots independently retain shared nodes after the
    // original publication is released.
    published.reset();
    for (uint64_t key = 0; key < 128; ++key) {
        BOOST_CHECK(second.get(key + 256));
        BOOST_CHECK(!first.get(key + 256));
    }
}

BOOST_AUTO_TEST_CASE(test_move) {
    using E = TestElementInt<uint32_t>;

    RadixTree<E> mytree;

    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(0)));
    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(1)));
    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(2)));
    BOOST_CHECK(mytree.insert(RCUPtr<E>::make(3)));

    RadixTree<E> movedTree = std::move(mytree);

    BOOST_CHECK(!mytree.remove(0));
    BOOST_CHECK(!mytree.remove(1));
    BOOST_CHECK(!mytree.remove(2));
    BOOST_CHECK(!mytree.remove(3));

    BOOST_CHECK(movedTree.remove(0));
    BOOST_CHECK(movedTree.remove(1));
    BOOST_CHECK(movedTree.remove(2));
    BOOST_CHECK(movedTree.remove(3));
}

#define THREADS 128
#define ELEMENTS 65536

BOOST_AUTO_TEST_CASE(insert_stress_test) {
    using E = TestElementInt<uint32_t>;

    RadixTree<E> mytree;
    std::atomic<uint32_t> success{0};
    std::vector<std::thread> threads;
    threads.reserve(THREADS);

    for (int i = 0; i < THREADS; i++) {
        threads.push_back(std::thread([&] {
            MMIXLinearCongruentialGenerator lcg;
            for (int j = 0; j < ELEMENTS; j++) {
                uint32_t v = lcg.next();

                if (mytree.remove(v)) {
                    success--;
                    std::this_thread::yield();
                }

                auto ptr = RCUPtr<E>::make(v);
                if (mytree.insert(ptr)) {
                    success++;
                    std::this_thread::yield();
                }

                if (mytree.remove(v)) {
                    success--;
                    std::this_thread::yield();
                }

                if (mytree.insert(ptr)) {
                    success++;
                    std::this_thread::yield();
                }
            }
        }));
    }

    // Wait for all the threads to finish.
    for (std::thread &t : threads) {
        t.join();
    }

    BOOST_CHECK_EQUAL(success.load(), ELEMENTS);

    // All the elements have been inserted into the tree.
    MMIXLinearCongruentialGenerator lcg;
    for (int i = 0; i < ELEMENTS; i++) {
        uint32_t v = lcg.next();
        BOOST_CHECK_EQUAL(mytree.get(v)->getId(), v);
        auto ptr = RCUPtr<E>::make(v);
        BOOST_CHECK(!mytree.insert(ptr));
        BOOST_CHECK(mytree.get(v) != ptr);
    }

    // Cleanup after ourselves.
    RCULock::synchronize();
}

BOOST_AUTO_TEST_CASE(tree_traversal) {
    using E = TestElement<uint32_t>;

    RadixTree<E> mytree;

    // Build a vector of elements in ascending key order
    std::vector<RCUPtr<E>> elements;
    elements.reserve(ELEMENTS);
    for (uint32_t i = 0; i < ELEMENTS; i++) {
        auto ptr = RCUPtr<E>::make(i);
        elements.push_back(std::move(ptr));
    }

    // Insert in random order
    auto randomizedElements = elements;
    Shuffle(randomizedElements.begin(), randomizedElements.end(),
            FastRandomContext());
    for (auto &element : randomizedElements) {
        BOOST_CHECK(mytree.insert(element));
    }

    // Check the tree is traversed in ascending key order
    size_t count = 0;
    bool ret = mytree.forEachLeaf([&](RCUPtr<E> ptr) {
        // This test assumes the key is equal to the value
        BOOST_CHECK_EQUAL(ptr->getId(), count);
        BOOST_CHECK_EQUAL(ptr, elements[count++]);

        return true;
    });

    // All the elements are parsed
    BOOST_CHECK_EQUAL(count, ELEMENTS);
    BOOST_CHECK(ret);

    // Check we can stop the traversal when needed
    const size_t stopCount = ELEMENTS / 2;
    count = 0;
    ret = mytree.forEachLeaf([&](RCUPtr<E> ptr) {
        // This test assumes the key is equal to the value
        BOOST_CHECK_EQUAL(ptr->getId(), count);
        BOOST_CHECK_EQUAL(ptr, elements[count++]);

        return count < stopCount;
    });

    BOOST_CHECK_EQUAL(count, stopCount);
    BOOST_CHECK(!ret);
}

BOOST_AUTO_TEST_CASE(uint256_nibbles_match_full_width_shift) {
    auto check = [](const arith_uint256 &value) {
        const Uint256RadixKey key{value};
        for (uint32_t level = 0; level < 64; ++level) {
            BOOST_TEST_CONTEXT("value=" << value.GetHex() << " level=" << level) {
                const uint32_t expected =
                    static_cast<uint32_t>((value >> (level * 4)).GetLow64() & 15);
                BOOST_CHECK_EQUAL(value.GetNibble(level), expected);
                BOOST_CHECK_EQUAL(key.GetNibble(level), expected);
            }
        }
        BOOST_CHECK_EQUAL(value.GetNibble(64), 0U);
        BOOST_CHECK_EQUAL(key.GetNibble(std::numeric_limits<uint32_t>::max()), 0U);
    };
    check(arith_uint256(0));
    check(~arith_uint256(0));
    check(UintToArith256(uint256S(
        "0123456789abcdeffedcba98765432100f1e2d3c4b5a69788796a5b4c3d2e1f0")));
    check(UintToArith256(uint256S(
        "aaaaaaaa55555555aaaaaaaa55555555aaaaaaaa55555555aaaaaaaa55555555")));
    for (unsigned bit = 0; bit < 256; ++bit) {
        check(arith_uint256(1) << bit);
    }
    FastRandomContext rng{true};
    for (unsigned i = 0; i < 128; ++i) check(UintToArith256(rng.rand256()));
}

BOOST_AUTO_TEST_CASE(uint256_tree_splits_at_every_nibble) {
    using E = TestElementUint256;
    for (unsigned level = 0; level < 64; ++level) {
        BOOST_TEST_CONTEXT("split level=" << level) {
            RadixTree<E> tree;
            const arith_uint256 shared = UintToArith256(uint256S(
                "c86420fedba9753113579bdf02468acefedcba98765432100123456789abcdef"));
            const arith_uint256 mask = arith_uint256(15) << (level * 4);
            std::vector<RCUPtr<E>> entries;
            // Each trial starts with one leaf, then diverges only at the
            // selected nibble. Include every possible child slot.
            for (unsigned nibble = 0; nibble < 16; ++nibble) {
                const auto key = (shared & ~mask) |
                    (arith_uint256(nibble) << (level * 4));
                entries.push_back(RCUPtr<E>::make(ArithToUint256(key)));
                BOOST_REQUIRE(tree.insert(entries.back()));
            }
            for (const auto &entry : entries) {
                BOOST_CHECK(tree.get(entry->getId()) == entry);
                BOOST_CHECK(!tree.insert(entry));
            }
            for (const auto &entry : entries) {
                BOOST_REQUIRE(tree.remove(entry->getId()));
                BOOST_CHECK(!tree.get(entry->getId()));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(uint256_key_equality_compares_high_bits) {
    for (uint64_t low : {uint64_t{0}, uint64_t{0x0123456789abcdef}}) {
        const Uint256RadixKey original{arith_uint256(low)};
        const Uint256RadixKey copy{original.base};
        BOOST_CHECK(original == copy);
        BOOST_CHECK(!(original != copy));
        for (unsigned bit = 64; bit < 256; ++bit) {
            BOOST_TEST_CONTEXT("low=" << low << " high bit=" << bit) {
                const Uint256RadixKey other{
                    arith_uint256(low) | (arith_uint256(1) << bit)};
                BOOST_CHECK_EQUAL(size_t(original), size_t(other));
                BOOST_CHECK(!(original == other));
                BOOST_CHECK(!(other == original));
                BOOST_CHECK(original != other);
                BOOST_CHECK(other != original);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(uint256_tree_same_low64_distinct_high_bits) {
    using E = TestElementUint256;
    using Tree = RadixTree<E>;
    for (uint64_t low : {uint64_t{0}, uint64_t{0x0123456789abcdef}}) {
        Tree live;
        std::vector<RCUPtr<E>> entries;
        entries.push_back(RCUPtr<E>::make(low));
        for (unsigned bit : {64U, 95U, 127U, 128U, 159U, 191U, 192U, 223U, 255U}) {
            entries.push_back(RCUPtr<E>::make(ArithToUint256(
                arith_uint256(low) | (arith_uint256(1) << bit))));
        }
        // A multi-high-bit key shares the low64 and a path with live keys,
        // but is absent. Neither lookup nor removal may match a nearby leaf.
        const Uint256RadixKey missing{arith_uint256(low) |
            (arith_uint256(1) << 255) | (arith_uint256(1) << 64)};
        for (const auto &entry : entries) {
            BOOST_CHECK(!live.get(entry->getId()));
            BOOST_REQUIRE(live.insert(entry));
            BOOST_CHECK(!live.insert(RCUPtr<E>::make(
                ArithToUint256(entry->getId().base))));
            BOOST_CHECK(live.get(entry->getId()) == entry);
            BOOST_CHECK(!live.get(missing));
            BOOST_CHECK(!live.remove(missing));
        }
        // No writer is active while sharing the immutable snapshot root.
        const Tree snapshot(live, Tree::ImmutableSnapshotTag{});
        for (const auto &entry : entries) {
            BOOST_CHECK(live.get(entry->getId()) == entry);
            BOOST_CHECK(snapshot.get(entry->getId()).get() == entry.get());
        }
        for (const auto &entry : entries) {
            BOOST_REQUIRE(live.remove(entry->getId()));
            BOOST_CHECK(!live.get(entry->getId()));
            BOOST_CHECK(!live.remove(entry->getId()));
            BOOST_CHECK(snapshot.get(entry->getId()).get() == entry.get());
        }
        BOOST_CHECK(!live.get(missing));
        BOOST_CHECK(!snapshot.get(missing));
        auto newly_inserted = RCUPtr<E>::make(ArithToUint256(missing.base));
        BOOST_REQUIRE(live.insert(newly_inserted));
        BOOST_CHECK(live.get(missing) == newly_inserted);
        BOOST_CHECK(!snapshot.get(missing));
        for (const auto &entry : entries) {
            BOOST_CHECK(!live.get(entry->getId()));
            BOOST_CHECK(snapshot.get(entry->getId()).get() == entry.get());
        }
    }
}

BOOST_AUTO_TEST_CASE(uint256_key_wrapper) {
    Uint256RadixKey key = uint256S(
        "AA00000000000000000000000000000000000000000000000000000000000000");

    auto checkEqual = [&](const Uint256RadixKey &val, const uint256 &expected) {
        BOOST_CHECK_EQUAL(ArithToUint256(val.base), expected);
    };

    auto checkOperands = [&](const Uint256RadixKey &val,
                             const uint256 &expected_uint256,
                             const size_t expected_size_t) {
        checkEqual(val, expected_uint256);

        checkEqual(val & Uint256RadixKey(uint256::ZERO), uint256::ZERO);
        checkEqual(val & val, expected_uint256);
        checkEqual(val & TestElementUint256::MinusOne(), expected_uint256);

        BOOST_CHECK_EQUAL(size_t(val), expected_size_t);
    };

    // clang-format off
    checkOperands(key >> 0u,   uint256S("AA00000000000000000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 1u,   uint256S("5500000000000000000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 2u,   uint256S("2A80000000000000000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 3u,   uint256S("1540000000000000000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 4u,   uint256S("0AA0000000000000000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 8u,   uint256S("00AA000000000000000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 16u,  uint256S("0000AA0000000000000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 24u,  uint256S("000000AA00000000000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 32u,  uint256S("00000000AA000000000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 40u,  uint256S("0000000000AA0000000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 48u,  uint256S("000000000000AA00000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 56u,  uint256S("00000000000000AA000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 64u,  uint256S("0000000000000000AA0000000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 72u,  uint256S("000000000000000000AA00000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 80u,  uint256S("00000000000000000000AA000000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 88u,  uint256S("0000000000000000000000AA0000000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 96u,  uint256S("000000000000000000000000AA00000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 104u, uint256S("00000000000000000000000000AA000000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 112u, uint256S("0000000000000000000000000000AA0000000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 120u, uint256S("000000000000000000000000000000AA00000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 128u, uint256S("00000000000000000000000000000000AA000000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 136u, uint256S("0000000000000000000000000000000000AA0000000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 144u, uint256S("000000000000000000000000000000000000AA00000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 152u, uint256S("00000000000000000000000000000000000000AA000000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 160u, uint256S("0000000000000000000000000000000000000000AA0000000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 168u, uint256S("000000000000000000000000000000000000000000AA00000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 176u, uint256S("00000000000000000000000000000000000000000000AA000000000000000000"), 0x0000000000000000);
    checkOperands(key >> 184u, uint256S("0000000000000000000000000000000000000000000000AA0000000000000000"), 0x0000000000000000);
    checkOperands(key >> 185u, uint256S("0000000000000000000000000000000000000000000000550000000000000000"), 0x0000000000000000);
    checkOperands(key >> 186u, uint256S("00000000000000000000000000000000000000000000002A8000000000000000"), 0x8000000000000000);
    checkOperands(key >> 192u, uint256S("000000000000000000000000000000000000000000000000AA00000000000000"), 0xAA00000000000000);
    checkOperands(key >> 200u, uint256S("00000000000000000000000000000000000000000000000000AA000000000000"), 0x00AA000000000000);
    checkOperands(key >> 208u, uint256S("0000000000000000000000000000000000000000000000000000AA0000000000"), 0x0000AA0000000000);
    checkOperands(key >> 216u, uint256S("000000000000000000000000000000000000000000000000000000AA00000000"), 0x000000AA00000000);
    checkOperands(key >> 224u, uint256S("00000000000000000000000000000000000000000000000000000000AA000000"), 0x00000000AA000000);
    checkOperands(key >> 232u, uint256S("0000000000000000000000000000000000000000000000000000000000AA0000"), 0x0000000000AA0000);
    checkOperands(key >> 240u, uint256S("000000000000000000000000000000000000000000000000000000000000AA00"), 0x000000000000AA00);
    checkOperands(key >> 248u, uint256S("00000000000000000000000000000000000000000000000000000000000000AA"), 0x00000000000000AA);
    checkOperands(key >> 252u, uint256S("000000000000000000000000000000000000000000000000000000000000000A"), 0x000000000000000A);
    checkOperands(key >> 253u, uint256S("0000000000000000000000000000000000000000000000000000000000000005"), 0x0000000000000005);
    checkOperands(key >> 254u, uint256S("0000000000000000000000000000000000000000000000000000000000000002"), 0x0000000000000002);
    checkOperands(key >> 255u, uint256S("0000000000000000000000000000000000000000000000000000000000000001"), 0x0000000000000001);
    checkOperands(key >> 256u, uint256S("0000000000000000000000000000000000000000000000000000000000000000"), 0x0000000000000000);
    // clang-format on
}

BOOST_AUTO_TEST_CASE(radix_adapter) {
    using E = TestElement<std::string>;

    struct StringKeyAdapter {
        uint64_t getId(const E &e) const {
            uint64_t key;
            BOOST_REQUIRE(ParseUInt64(e.getId(), &key));
            return key;
        }
    };

    RadixTree<E, StringKeyAdapter> mytree;

    auto zero = RCUPtr<E>::make("0");
    auto one = RCUPtr<E>::make("1");
    auto two = RCUPtr<E>::make("2");
    auto three = RCUPtr<E>::make("3");

    // Let's insert some elements
    BOOST_CHECK(mytree.insert(zero));
    BOOST_CHECK(mytree.insert(one));
    BOOST_CHECK(mytree.insert(two));
    BOOST_CHECK(mytree.insert(three));
    BOOST_CHECK(!mytree.insert(zero));
    BOOST_CHECK(!mytree.insert(one));
    BOOST_CHECK(!mytree.insert(two));
    BOOST_CHECK(!mytree.insert(three));

    // Retrieval is done using the converted key
    BOOST_CHECK_EQUAL(mytree.get(0), zero);
    BOOST_CHECK_EQUAL(mytree.get(1), one);
    BOOST_CHECK_EQUAL(mytree.get(2), two);
    BOOST_CHECK_EQUAL(mytree.get(3), three);

    // And so does removal
    BOOST_CHECK(mytree.remove(0));
    BOOST_CHECK(mytree.remove(1));
    BOOST_CHECK(mytree.remove(2));
    BOOST_CHECK(mytree.remove(3));

    BOOST_CHECK(!mytree.get(0));
    BOOST_CHECK(!mytree.get(1));
    BOOST_CHECK(!mytree.get(2));
    BOOST_CHECK(!mytree.get(3));
}

BOOST_AUTO_TEST_CASE(radix_tree_map_sorted_order_lower_bound_and_prefix) {
    // 1. uint64_t map: insertOrAssign, sorted order, forEachFrom
    RadixTreeMap<uint64_t, std::string> u64_map;
    BOOST_CHECK(u64_map.empty());
    BOOST_CHECK(u64_map.insertOrAssign(40, "forty"));
    BOOST_CHECK(u64_map.insertOrAssign(10, "ten_old"));
    BOOST_CHECK(u64_map.insertOrAssign(30, "thirty"));
    BOOST_CHECK(u64_map.insertOrAssign(20, "twenty"));
    BOOST_CHECK_EQUAL(u64_map.size(), 4U);

    // Replace existing key 10 while a pinned snapshot holds the old value
    const auto snap_before_assign = u64_map.pinSnapshot();
    BOOST_CHECK(!u64_map.insertOrAssign(10, "ten_new"));
    BOOST_CHECK_EQUAL(u64_map.size(), 4U);
    BOOST_CHECK_EQUAL(u64_map.get(10).value_or(""), "ten_new");
    BOOST_CHECK_EQUAL(snap_before_assign.get(10).value_or(""), "ten_old");

    std::vector<uint64_t> all_keys;
    u64_map.forEach([&](uint64_t k, const std::string &) {
        all_keys.push_back(k);
    });
    BOOST_CHECK((all_keys == std::vector<uint64_t>{10, 20, 30, 40}));

    std::vector<uint64_t> from_25;
    u64_map.forEachFrom(25, [&](uint64_t k, const std::string &) {
        from_25.push_back(k);
    });
    BOOST_CHECK((from_25 == std::vector<uint64_t>{30, 40}));

    std::vector<uint64_t> from_20_stop_1;
    u64_map.forEachFrom(20, [&](uint64_t k, const std::string &) {
        from_20_stop_1.push_back(k);
        return false; // stop after first
    });
    BOOST_CHECK((from_20_stop_1 == std::vector<uint64_t>{20}));

    // 2. 128-bit composite pair<uint64_t, uint64_t> map
    RadixTreeMap<std::pair<uint64_t, uint64_t>, uint64_t> pair_map;
    pair_map.insertOrAssign({2, 5}, 25);
    pair_map.insertOrAssign({1, 9}, 19);
    pair_map.insertOrAssign({2, 1}, 21);
    pair_map.insertOrAssign({1, 2}, 12);

    std::vector<uint64_t> pair_vals;
    pair_map.forEach([&](const auto &, uint64_t v) { pair_vals.push_back(v); });
    BOOST_CHECK((pair_vals == std::vector<uint64_t>{12, 19, 21, 25}));

    std::vector<uint64_t> pair_from;
    pair_map.forEachFrom({1, 5}, [&](const auto &, uint64_t v) {
        pair_from.push_back(v);
    });
    BOOST_CHECK((pair_from == std::vector<uint64_t>{19, 21, 25}));

    std::vector<uint64_t> pair_prefix2;
    pair_map.forEachPrefix({2, 0}, 16, [&](const auto &, uint64_t v) {
        pair_prefix2.push_back(v);
    });
    BOOST_CHECK((pair_prefix2 == std::vector<uint64_t>{21, 25}));

    // 3. COutPoint (288-bit key): prefix_nibbles = 64 scans all spent outputs of a TxId
    RadixTreeMap<COutPoint, uint32_t> outpoint_map;
    const TxId txid_a{uint256S(
        "1111111111111111111111111111111111111111111111111111111111111111")};
    const TxId txid_b{uint256S(
        "2222222222222222222222222222222222222222222222222222222222222222")};
    const TxId txid_c{uint256S(
        "1111111111111111111111111111111111111111111111111111111111111112")};

    // Single path-compressed leaf test for forEachPrefix
    outpoint_map.insertOrAssign(COutPoint(txid_a, 7), 107);
    {
        std::vector<uint32_t> single_a;
        outpoint_map.forEachPrefix(
            COutPoint(txid_a, 0), OutpointRadixKey::TXID_PREFIX_NIBBLES,
            [&](const COutPoint &op, uint32_t v) {
                BOOST_CHECK(op.GetTxId() == txid_a);
                single_a.push_back(v);
            });
        BOOST_CHECK((single_a == std::vector<uint32_t>{107}));

        std::vector<uint32_t> single_b;
        outpoint_map.forEachPrefix(
            COutPoint(txid_b, 0), OutpointRadixKey::TXID_PREFIX_NIBBLES,
            [&](const COutPoint &, uint32_t v) { single_b.push_back(v); });
        BOOST_CHECK(single_b.empty());
    }

    // Multiple outputs for txid_a, plus outputs for txid_b and near-neighbor txid_c
    outpoint_map.insertOrAssign(COutPoint(txid_a, 0), 100);
    outpoint_map.insertOrAssign(COutPoint(txid_a, 256), 356);
    outpoint_map.insertOrAssign(COutPoint(txid_a, 2), 102);
    outpoint_map.insertOrAssign(COutPoint(txid_b, 0), 200);
    outpoint_map.insertOrAssign(COutPoint(txid_c, 0), 300);

    std::vector<uint32_t> outputs_a;
    outpoint_map.forEachPrefix(
        COutPoint(txid_a, 0), OutpointRadixKey::TXID_PREFIX_NIBBLES,
        [&](const COutPoint &op, uint32_t v) {
            BOOST_CHECK(op.GetTxId() == txid_a);
            outputs_a.push_back(v);
        });
    BOOST_CHECK((outputs_a == std::vector<uint32_t>{100, 102, 107, 356}));

    // Verify full map order matches COutPoint::operator<
    std::vector<COutPoint> ordered_outpoints;
    outpoint_map.forEach([&](const COutPoint &op, uint32_t) {
        ordered_outpoints.push_back(op);
    });
    BOOST_CHECK(std::is_sorted(ordered_outpoints.begin(),
                               ordered_outpoints.end()));
}

BOOST_AUTO_TEST_CASE(radix_tree_map_concurrent_snapshots_and_slab_reclamation) {
    RadixTreeMap<uint64_t, uint64_t> map;
    for (uint64_t i = 0; i < 512; ++i) {
        BOOST_REQUIRE(map.insertOrAssign(i, i * 10));
    }
    const auto pinned = map.pinSnapshot();
    BOOST_CHECK_EQUAL(pinned.size(), 512U);

    // Mutate and erase in the live map across multiple threads while readers
    // concurrently verify the immutable pinned snapshot.
    std::atomic<bool> stop{false};
    std::atomic<size_t> reader_failures{0};
    std::vector<std::thread> readers;
    for (int t = 0; t < 4; ++t) {
        readers.emplace_back([&]() {
            while (!stop.load(std::memory_order_relaxed)) {
                size_t count = 0;
                uint64_t expected_k = 0;
                pinned.forEach([&](uint64_t k, uint64_t v) {
                    if (k != expected_k || v != k * 10) {
                        reader_failures.fetch_add(1, std::memory_order_relaxed);
                    }
                    ++expected_k;
                    ++count;
                });
                if (count != 512U) {
                    reader_failures.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    for (uint64_t round = 1; round <= 4; ++round) {
        for (uint64_t i = 0; i < 256; ++i) {
            BOOST_CHECK(map.erase(i));
        }
        for (uint64_t i = 256; i < 512; ++i) {
            BOOST_CHECK(!map.insertOrAssign(i, i * 10 + round));
        }
        for (uint64_t i = 0; i < 256; ++i) {
            BOOST_CHECK(map.insertOrAssign(i, i * 10 + round));
        }
    }

    stop.store(true, std::memory_order_relaxed);
    for (auto &th : readers) {
        th.join();
    }
    BOOST_CHECK_EQUAL(reader_failures.load(), 0U);

    BOOST_CHECK_EQUAL(map.size(), 512U);
    for (uint64_t i = 0; i < 512; ++i) {
        BOOST_CHECK_EQUAL(map.get(i).value_or(0), i * 10 + 4);
        BOOST_CHECK_EQUAL(pinned.get(i).value_or(0), i * 10);
    }
    map.clear();
    BOOST_CHECK(map.empty());
    RCULock::synchronize();
}

BOOST_AUTO_TEST_SUITE_END()
