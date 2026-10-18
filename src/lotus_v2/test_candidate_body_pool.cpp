// Copyright (c) 2026 The Lotus developers
#include "candidate_body_pool.h"
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <new>
#include <stdexcept>
using namespace lotus::v2;
// Executable-local allocation fault seam, absent from the pool API. Fail once
// then disarm so diagnostics and exception cleanup can run normally.
namespace {
long allocation_countdown = -1;
}
void *operator new(std::size_t size) {
    if (allocation_countdown == 0) {
        allocation_countdown = -1;
        throw std::bad_alloc();
    }
    if (allocation_countdown > 0) --allocation_countdown;
    if (auto *p = std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc();
}
void *operator new[](std::size_t n) {
    return ::operator new(n);
}
void operator delete(void *p) noexcept {
    std::free(p);
}
void operator delete[](void *p) noexcept {
    std::free(p);
}
void operator delete(void *p, std::size_t) noexcept {
    std::free(p);
}
void operator delete[](void *p, std::size_t) noexcept {
    std::free(p);
}
#define CHECK(c)                                                               \
    do {                                                                       \
        if (!(c))                                                              \
            throw std::runtime_error("line " + std::to_string(__LINE__) +      \
                                     ": " #c);                                 \
    } while (false)
namespace {
const TxProfile PROFILE{32, 32, 8, 512, 8, 8192, 64};
ChainId Chain() {
    ChainId c{};
    c[0] = 77;
    return c;
}
struct Fixture {
    Header header;
    std::vector<uint8_t> wire;
    Hash id;
    explicit Fixture(uint32_t tag = 1, unsigned count = 1) {
        std::vector<Transaction> transactions;
        for (unsigned n = 0; n < count; ++n) {
            Transaction tx;
            Input input;
            input.flags = n ? 1 : 2;
            input.prev_txid[0] = static_cast<uint8_t>(tag + n);
            input.prev_index = 42;
            input.sequence = UINT32_MAX;
            if (n) input.witnesses = {BranchWitness{{0x4e}, {}, {}}};
            tx.inputs = {input};
            Output output;
            output.value = 100 + n;
            output.branches = {BranchLeaf(std::vector<uint8_t>{0x4e})};
            output.paths = {{0}};
            tx.outputs = {output};
            transactions.push_back(std::move(tx));
        }
        header.version = 2;
        header.height = 5;
        header.prev_id[0] = 99;
        header.time = 1000 + tag;
        header.bits = 0x207fffff;
        header.state_root[0] = static_cast<uint8_t>(tag);
        header.size = HEADER_SIZE + 4;
        std::string error;
        for (const auto &tx : transactions) {
            std::vector<uint8_t> bytes;
            CHECK(EncodeTransaction(tx, PROFILE, bytes, error));
            header.size += bytes.size() + CompactSizeWidth(bytes.size());
        }
        CHECK(CompleteTransactionRoot(transactions, PROFILE, Chain(),
                                      header.tx_root, error));
        CHECK(EncodeBlockWire(header, transactions, PROFILE, wire, error));
        CHECK(BlockId(Chain(), header, id));
    }
};
CandidateBodyLimits Limits(uint64_t bytes = 65536) {
    return {8, bytes, bytes * 4, 8, bytes * 4, 32};
}
void BindingAndContext() {
    Fixture f;
    CandidateBodyPool pool(Chain(), PROFILE, Limits(), 10);
    CHECK(pool.PutAuthenticated(f.id, f.header, f.wire) ==
          CandidateBodyStatus::RetainedAuthenticated);
    CHECK(pool.Stats().epoch == 11 && pool.Stats().bodies == 1 &&
          pool.Stats().resident_wire_bytes == f.wire.size());
    CHECK(pool.Probe(f.id, f.header, f.wire.size()) ==
          CandidateBodyStatus::Available);
    CHECK(pool.Probe(f.id, f.header, f.wire.size() - 1) ==
          CandidateBodyStatus::CapacityRefused);
    CHECK(pool.PutAuthenticated(f.id, f.header, f.wire) ==
              CandidateBodyStatus::Duplicate &&
          pool.Stats().epoch == 11);
    FramedBlock decoded;
    std::string error;
    CHECK(DecodeBlockWire(f.wire, PROFILE, Chain(), decoded, error));
    CHECK(!CheckCoinbaseContext(decoded.transactions.front(), f.header.prev_id,
                                f.header.height, error));
    // Retention authenticates these exact bytes despite a known contextual
    // coinbase failure; it is never reported as a block acceptance result.
    CandidateBodyPin pin;
    CHECK(pool.Pin(f.id, f.header, f.wire.size(), pin) ==
          CandidateBodyStatus::Available);
    CHECK(pin && std::equal(pin.Wire().begin(), pin.Wire().end(),
                            f.wire.begin(), f.wire.end()));
    CHECK(pin.BoundHeader() && pin.BoundHeader()->height == f.header.height);
    std::vector<uint8_t> copy{9};
    CHECK(pin.CopyTo(f.wire.size() - 1, copy) ==
              CandidateBodyStatus::CapacityRefused &&
          copy == std::vector<uint8_t>{9});
    CHECK(pin.CopyTo(f.wire.size(), copy) == CandidateBodyStatus::Available &&
          copy == f.wire);
    auto altered = f.header;
    ++altered.time;
    CHECK(pool.Probe(f.id, altered, f.wire.size()) ==
          CandidateBodyStatus::Malformed);
    CHECK(pool.Pin(f.id, altered, f.wire.size(), pin) ==
              CandidateBodyStatus::Malformed &&
          pin);
    CHECK(pool.Evict(f.id) == CandidateBodyStatus::Pinned);
    pin = {};
    CHECK(pool.Stats().pins == 0 && pool.Stats().pinned_wire_bytes == 0);
    CHECK(pool.Evict(f.id) == CandidateBodyStatus::Evicted &&
          pool.Stats().epoch == 12);
    CHECK(pool.Stats().resident_wire_bytes == 0 &&
          pool.Probe(f.id, f.header, UINT64_MAX) ==
              CandidateBodyStatus::Missing);
    CHECK(pool.PutAuthenticated(f.id, f.header, f.wire) ==
              CandidateBodyStatus::RetainedAuthenticated &&
          pool.Stats().epoch == 13);
}
void Corruption() {
    Fixture f;
    CandidateBodyPool pool(Chain(), PROFILE, Limits(), 0);
    auto bad = f.wire;
    bad.back() ^= 1;
    CHECK(pool.PutAuthenticated(f.id, f.header, bad) ==
          CandidateBodyStatus::Malformed);
    bad = f.wire;
    bad.push_back(0);
    CHECK(pool.PutAuthenticated(f.id, f.header, bad) ==
          CandidateBodyStatus::Malformed);
    auto wrong = f.id;
    wrong[0] ^= 1;
    CHECK(pool.PutAuthenticated(wrong, f.header, f.wire) ==
          CandidateBodyStatus::Malformed);
    auto h = f.header;
    ++h.time;
    CHECK(pool.PutAuthenticated(f.id, h, f.wire) ==
          CandidateBodyStatus::Malformed);
    // Well-framed bytes with a wrong root fail before publication.
    h = f.header;
    h.tx_root[0] ^= 1;
    std::array<uint8_t, HEADER_SIZE> header;
    CHECK(SerializeHeader(h, header));
    bad = f.wire;
    std::copy(header.begin(), header.end(), bad.begin());
    Hash id;
    CHECK(BlockId(Chain(), h, id));
    CHECK(pool.PutAuthenticated(id, h, bad) == CandidateBodyStatus::Malformed);
    CandidateBodyPool wrong_chain(ChainId{}, PROFILE, Limits(), 0);
    CHECK(wrong_chain.PutAuthenticated(f.id, f.header, f.wire) ==
          CandidateBodyStatus::Malformed);
    CHECK(pool.Stats().bodies == 0 && pool.Stats().epoch == 0 &&
          pool.Stats().resident_wire_bytes == 0);
    // Truncations cannot publish partial entries or change the epoch.
    for (size_t n = 0; n < f.wire.size(); ++n) {
        bad.assign(f.wire.begin(), f.wire.begin() + n);
        CHECK(pool.PutAuthenticated(f.id, f.header, bad) ==
              CandidateBodyStatus::Malformed);
    }
}
void CapsAndEpoch() {
    auto invalid_profile = PROFILE;
    invalid_profile.max_inputs = 0;
    bool rejected = false;
    try {
        CandidateBodyPool bad(Chain(), invalid_profile, Limits(), 0);
    } catch (const std::invalid_argument &) {
        rejected = true;
    }
    CHECK(rejected);
    Fixture a, b(2), multiple(3, 2);
    auto limits = Limits(a.wire.size());
    limits.max_resident_wire_bytes = a.wire.size();
    limits.max_bodies = 1;
    limits.max_pins = 1;
    limits.max_pinned_wire_bytes = a.wire.size();
    CandidateBodyPool pool(Chain(), PROFILE, limits, 0);
    CHECK(pool.PutAuthenticated(a.id, a.header, a.wire) ==
          CandidateBodyStatus::RetainedAuthenticated);
    CHECK(pool.PutAuthenticated(b.id, b.header, b.wire) ==
          CandidateBodyStatus::CapacityRefused);
    CandidateBodyPin one, two;
    CHECK(pool.Pin(a.id, a.header, a.wire.size(), one) ==
          CandidateBodyStatus::Available);
    CHECK(pool.Pin(a.id, a.header, a.wire.size(), two) ==
              CandidateBodyStatus::CapacityRefused &&
          !two);
    CHECK(pool.Stats().pins == 1 &&
          pool.Stats().pinned_wire_bytes == a.wire.size() &&
          pool.Stats().epoch == 1);
    one = {};
    CHECK(pool.Evict(a.id) == CandidateBodyStatus::Evicted);
    CHECK(pool.PutAuthenticated(b.id, b.header, b.wire) ==
          CandidateBodyStatus::RetainedAuthenticated);
    auto l = Limits();
    l.max_decode_transactions = 1;
    CandidateBodyPool count(Chain(), PROFILE, l, 0);
    CHECK(count.PutAuthenticated(multiple.id, multiple.header, multiple.wire) ==
              CandidateBodyStatus::CapacityRefused &&
          count.Stats().epoch == 0);
    l = Limits(a.wire.size() - 1);
    CandidateBodyPool bytes(Chain(), PROFILE, l, 0);
    CHECK(bytes.PutAuthenticated(a.id, a.header, a.wire) ==
          CandidateBodyStatus::CapacityRefused);
    l = Limits();
    l.max_pinned_wire_bytes = a.wire.size() - 1;
    CandidateBodyPool pinbytes(Chain(), PROFILE, l, 0);
    CHECK(pinbytes.PutAuthenticated(a.id, a.header, a.wire) ==
          CandidateBodyStatus::RetainedAuthenticated);
    CHECK(pinbytes.Pin(a.id, a.header, UINT64_MAX, two) ==
          CandidateBodyStatus::CapacityRefused);
    CandidateBodyPool epoch(Chain(), PROFILE, Limits(), UINT64_MAX - 1);
    CHECK(epoch.PutAuthenticated(a.id, a.header, a.wire) ==
              CandidateBodyStatus::RetainedAuthenticated &&
          epoch.Stats().epoch == UINT64_MAX);
    CHECK(epoch.PutAuthenticated(a.id, a.header, a.wire) ==
          CandidateBodyStatus::Duplicate);
    CHECK(epoch.Evict(a.id) == CandidateBodyStatus::EpochExhausted);
    CHECK(epoch.PutAuthenticated(b.id, b.header, b.wire) ==
              CandidateBodyStatus::EpochExhausted &&
          epoch.Stats().bodies == 1);
    CHECK(epoch.Pin(a.id, a.header, UINT64_MAX, two) ==
          CandidateBodyStatus::Available);
    CandidateBodyPool exhausted(Chain(), PROFILE, Limits(), UINT64_MAX);
    CHECK(exhausted.PutAuthenticated(a.id, a.header, a.wire) ==
              CandidateBodyStatus::EpochExhausted &&
          exhausted.Stats().bodies == 0);
}
void PinLifetime() {
    {
        Fixture repeated;
        auto l = Limits();
        l.max_pins = 2;
        l.max_pinned_wire_bytes = repeated.wire.size() * 2;
        CandidateBodyPool pool(Chain(), PROFILE, l, 0);
        CHECK(pool.PutAuthenticated(repeated.id, repeated.header,
                                    repeated.wire) ==
              CandidateBodyStatus::RetainedAuthenticated);
        CandidateBodyPin a, b, c;
        CHECK(pool.Pin(repeated.id, repeated.header, UINT64_MAX, a) ==
              CandidateBodyStatus::Available);
        CHECK(pool.Pin(repeated.id, repeated.header, UINT64_MAX, b) ==
              CandidateBodyStatus::Available);
        CHECK(pool.Stats().pins == 2 &&
              pool.Stats().pinned_wire_bytes == repeated.wire.size() * 2);
        CHECK(pool.Pin(repeated.id, repeated.header, UINT64_MAX, c) ==
              CandidateBodyStatus::CapacityRefused);
        a = {};
        CHECK(pool.Stats().pins == 1 &&
              pool.Stats().pinned_wire_bytes == repeated.wire.size());
    }
    Fixture f, other(2);
    CandidateBodyPin pin;
    {
        CandidateBodyPool pool(Chain(), PROFILE, Limits(), 0);
        CHECK(pool.PutAuthenticated(f.id, f.header, f.wire) ==
              CandidateBodyStatus::RetainedAuthenticated);
        CHECK(pool.PutAuthenticated(other.id, other.header, other.wire) ==
              CandidateBodyStatus::RetainedAuthenticated);
        CHECK(pool.Pin(f.id, f.header, UINT64_MAX, pin) ==
              CandidateBodyStatus::Available);
        CandidateBodyPin moved = std::move(pin);
        CHECK(!pin && moved);
        pin = std::move(moved);
        CHECK(pin && !moved && pool.Stats().pins == 1);
        CHECK(pool.Evict(other.id) == CandidateBodyStatus::Evicted);
    }
    std::vector<uint8_t> copy;
    CHECK(pin.CopyTo(UINT64_MAX, copy) == CandidateBodyStatus::Available &&
          copy == f.wire);
    pin = {};
    CHECK(!pin && pin.Wire().empty() && !pin.BoundHeader());
    CHECK(pin.CopyTo(UINT64_MAX, copy) == CandidateBodyStatus::Missing);
}
void AllocationFailures() {
    Fixture f;
    bool success = false;
    unsigned failures = 0;
    for (long n = 0; n < 1000; ++n) {
        CandidateBodyPool pool(Chain(), PROFILE, Limits(), 0);
        allocation_countdown = n;
        const auto result = pool.PutAuthenticated(f.id, f.header, f.wire);
        allocation_countdown = -1;
        if (result == CandidateBodyStatus::RetainedAuthenticated) {
            success = true;
            break;
        }
        CHECK(result == CandidateBodyStatus::CapacityRefused);
        CHECK(pool.Stats().bodies == 0 &&
              pool.Stats().resident_wire_bytes == 0 && pool.Stats().epoch == 0);
        CHECK(pool.Probe(f.id, f.header, UINT64_MAX) ==
              CandidateBodyStatus::Missing);
        ++failures;
    }
    CHECK(success && failures > 10);
    CandidateBodyPool pool(Chain(), PROFILE, Limits(), 0);
    CHECK(pool.PutAuthenticated(f.id, f.header, f.wire) ==
          CandidateBodyStatus::RetainedAuthenticated);
    CandidateBodyPin pin;
    allocation_countdown = 0;
    auto result = pool.Pin(f.id, f.header, UINT64_MAX, pin);
    allocation_countdown = -1;
    CHECK(result == CandidateBodyStatus::CapacityRefused && !pin &&
          pool.Stats().pins == 0 && pool.Stats().epoch == 1);
    CHECK(pool.Pin(f.id, f.header, UINT64_MAX, pin) ==
          CandidateBodyStatus::Available);
    std::vector<uint8_t> copy{9};
    allocation_countdown = 0;
    result = pin.CopyTo(UINT64_MAX, copy);
    allocation_countdown = -1;
    CHECK(result == CandidateBodyStatus::CapacityRefused &&
          copy == std::vector<uint8_t>{9} && pin && pool.Stats().pins == 1);
    // Preflight capacity refusals allocate nothing, even with the next
    // allocation armed to fail; no decode/copy happens under an exhausted cap.
    auto l = Limits(f.wire.size() - 1);
    CandidateBodyPool capped(Chain(), PROFILE, l, 0);
    allocation_countdown = 0;
    result = capped.PutAuthenticated(f.id, f.header, f.wire);
    const bool untouched = allocation_countdown == 0;
    allocation_countdown = -1;
    CHECK(result == CandidateBodyStatus::CapacityRefused && untouched);
    std::cout << "allocation failure points checked: " << failures << '\n';
}
} // namespace
int main() {
    try {
        BindingAndContext();
        Corruption();
        CapsAndEpoch();
        PinLifetime();
        AllocationFailures();
        std::cout << "candidate body pool checks passed\n";
        return 0;
    } catch (const std::exception &e) {
        allocation_countdown = -1;
        std::cerr << e.what() << '\n';
        return 1;
    }
}
