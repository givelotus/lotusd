// Copyright (c) 2026 The Lotus developers
#include "dev_genesis.h"

#include "commitment.h"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace lotus::v2;

namespace {
void Check(bool ok, const char *message) {
    if (!ok) throw std::runtime_error(message);
}

std::string Hex(const Hash &hash) {
    constexpr char chars[] = "0123456789abcdef";
    std::string result;
    for (uint8_t byte : hash) {
        result.push_back(chars[byte >> 4]);
        result.push_back(chars[byte & 15]);
    }
    return result;
}

bool SameHeader(const Header &a, const Header &b) {
    return a.prev_id == b.prev_id && a.bits == b.bits && a.time == b.time &&
           a.nonce == b.nonce && a.version == b.version && a.size == b.size &&
           a.height == b.height && a.tx_root == b.tx_root &&
           a.state_root == b.state_root;
}

bool ZeroHash(const Hash &hash) {
    for (uint8_t byte : hash) {
        if (byte != 0) return false;
    }
    return true;
}

void RejectUnchanged(const Hash &prev_id, uint64_t height) {
    DevelopmentGenesisFixture rejected;
    rejected.header.version = 0xdeadbeef;
    rejected.header.nonce = 7;
    rejected.header.height = 99;
    rejected.state.bootstrap_reserve = 123;
    Check(!MakeDevelopmentGenesis(prev_id, height, rejected),
          "nonzero previous id or height must be rejected");
    Check(rejected.header.version == 0xdeadbeef && rejected.header.nonce == 7 &&
              rejected.header.height == 99 &&
              rejected.state.bootstrap_reserve == 123,
          "rejected construction leaves the fixture unchanged");
}
} // namespace

int main() {
    try {
        Check(HEADER_SIZE == 134, "header encoding is 134 bytes");
        DevelopmentGenesisFixture fixture;
        fixture.header.version = 1;
        Check(MakeDevelopmentGenesis({}, 0, fixture), "construct height 0");
        Check(fixture.chain_id == kDevelopmentChainId &&
                  ZeroHash(fixture.chain_id),
              "development chain id is all zeros");
        const Header &header = fixture.header;
        Check(ZeroHash(header.prev_id) && header.nonce == 0 &&
                  header.version == 2 && header.height == 0 &&
                  header.time <= MAX_TIME && header.bits == 0x1d00ffff &&
                  header.size == HEADER_SIZE,
              "height-0 header fields");
        Hash pow_limit{};
        pow_limit[31] = 0xff;
        Hash target{};
        Check(DecodeTarget(header.bits, pow_limit, target),
              "bits stay the header test canonical target");

        // Empty transaction root already pinned by test_commitment.cpp.
        Hash tx_root{};
        Check(TransactionRoot({}, tx_root) && header.tx_root == tx_root &&
                  Hex(header.tx_root) ==
                      "24518f458e1e543b742619b81b0f24839a1753a447ff5322ca80fcfa705b0856",
              "tx root is the existing empty commitment");

        Check(fixture.state.bootstrap_reserve == 9 &&
                  fixture.state.tail_subsidy == 200 &&
                  fixture.state.prev_work[0] == 9 &&
                  fixture.state.ema_block_cost == 4,
              "genesis state is the existing monetary test state");
        const Hash utxo = EmptyUtxoRoot();
        const Hash state_root =
            StateRoot(fixture.chain_id, 0, utxo, fixture.state);
        const Hash state_root_again =
            StateRoot(fixture.chain_id, 0, utxo, fixture.state);
        Check(header.state_root == state_root && state_root == state_root_again,
              "state root matches two StateRoot calls");
        Check(Hex(state_root) ==
                  "3ecef0a5a8524cde7fa2921c52256c5a4306783c6d24e8604ec2b6288ec39acf",
              "development genesis state root matches the Python fixture");

        std::array<uint8_t, HEADER_SIZE> bytes{};
        Check(SerializeHeader(header, bytes), "serialize development header");
        Check(bytes.size() == 134, "serialized header is exactly 134 bytes");
        Header parsed;
        parsed.version = 0x11111111;
        Check(ParseHeader(bytes.data(), bytes.size(), parsed), "parse header");
        Check(SameHeader(parsed, header), "parse restores the same fields");
        std::array<uint8_t, HEADER_SIZE> repeated{};
        Check(SerializeHeader(parsed, repeated) && repeated == bytes,
              "serialize parsed header");

        DevelopmentGenesisFixture again;
        Check(MakeDevelopmentGenesis({}, 0, again) &&
                  SameHeader(again.header, header) &&
                  again.state.bootstrap_reserve ==
                      fixture.state.bootstrap_reserve &&
                  again.state.tail_subsidy == fixture.state.tail_subsidy &&
                  again.state.prev_work == fixture.state.prev_work &&
                  again.state.ema_block_cost == fixture.state.ema_block_cost,
              "fixture construction is deterministic");

        Hash nonzero{};
        nonzero[0] = 1;
        RejectUnchanged(nonzero, 0);
        nonzero[0] = 0;
        nonzero[31] = 1;
        RejectUnchanged(nonzero, 0);
        RejectUnchanged({}, 1);
        RejectUnchanged({}, UINT64_MAX);
        nonzero[0] = 1;
        RejectUnchanged(nonzero, 1);

        // Same AdvanceMonetary arguments as test_monetary.cpp Step(state).
        // Subsidy 202 is that test's expected integer. The monetary tests do
        // not pin a state-root integer, so only two calls are compared.
        // No new economic vector was added.
        const MonetaryTransition first = AdvanceMonetary(
            DevelopmentGenesis, fixture.state, 9, {}, 0, 0, 1, 1, 4, 4);
        const MonetaryTransition second = AdvanceMonetary(
            DevelopmentGenesis, fixture.state, 9, {}, 0, 0, 1, 1, 4, 4);
        Check(first.subsidy == 202 && second.subsidy == 202 &&
                  first.bootstrap_issued == 2 && second.bootstrap_issued == 2 &&
                  first.state.bootstrap_reserve == 7 &&
                  second.state.bootstrap_reserve == 7 &&
                  first.state.tail_subsidy == 200 &&
                  second.state.tail_subsidy == 200,
              "existing height-one subsidy");
        const Hash transition_root =
            StateRoot(fixture.chain_id, 1, utxo, first.state);
        const Hash transition_root_again =
            StateRoot(fixture.chain_id, 1, utxo, second.state);
        Check(transition_root == transition_root_again,
              "transition state root is deterministic");
        Check(transition_root != header.state_root,
              "issuance step is not the recorded genesis root");
        std::cout << "development genesis fixture checks passed\n"
                  << "subsidy 202 matches the existing monetary test; "
                  << "genesis state root matches the recorded Python digest; "
                  << "no new economic vector\n";
    } catch (const std::exception &error) {
        std::cerr << "development genesis: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
