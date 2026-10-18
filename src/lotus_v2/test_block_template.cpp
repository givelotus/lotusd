#include "block_template.h"

#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>

using namespace lotus::v2;

namespace {
void Check(bool condition, const char *message) {
    if (!condition) {
        std::cerr << "V2 block template: " << message << '\n';
        std::exit(1);
    }
}

std::string Hex(const uint8_t *data, size_t size) {
    constexpr char chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        result.push_back(chars[data[i] >> 4]);
        result.push_back(chars[data[i] & 15]);
    }
    return result;
}

std::string Hex(const Hash &hash) { return Hex(hash.data(), hash.size()); }

Header Parent() {
    Header parent;
    for (size_t i = 0; i < parent.prev_id.size(); ++i) {
        parent.prev_id[i] = static_cast<uint8_t>(0x40 + i);
        parent.tx_root[i] = 0x11;
        parent.state_root[i] = 0x22;
    }
    parent.bits = 0x2100ffff;
    parent.time = 1700000000;
    parent.nonce = 0;
    parent.version = 2;
    parent.size = 200;
    parent.height = 4;
    return parent;
}

Hash Ceiling() {
    Hash ceiling{};
    ceiling.fill(0xff);
    return ceiling;
}

bool SameHeader(const Header &left, const Header &right) {
    return left.prev_id == right.prev_id && left.bits == right.bits && left.time == right.time &&
           left.nonce == right.nonce && left.version == right.version && left.size == right.size &&
           left.height == right.height && left.tx_root == right.tx_root &&
           left.state_root == right.state_root;
}

bool SubtractOne(Hash &value) {
    for (uint8_t &byte : value) {
        if (byte == 0) {
            byte = 0xff;
            continue;
        }
        --byte;
        return true;
    }
    return false;
}
} // namespace

int main() {
    const ChainId chain_id = [] {
        ChainId id{};
        for (size_t i = 0; i < id.size(); ++i) id[i] = static_cast<uint8_t>(i);
        return id;
    }();
    const Header parent = Parent();
    Hash tx_root{};
    Hash state_root{};
    tx_root.fill(0x33);
    state_root.fill(0x44);
    constexpr uint64_t time = 1700000120;
    constexpr uint64_t size = 400;
    constexpr uint32_t bits = 0x2100ffff;

    const std::optional<Header> child =
        BuildChildHeader(parent, chain_id, tx_root, state_root, time, size, bits);
    Check(child.has_value(), "build child header");
    Hash parent_id{};
    Check(BlockId(chain_id, parent, parent_id), "parent block id");
    Check(child->prev_id == parent_id, "prev_id is the parent block id");
    Check(child->height == parent.height + 1, "height is parent plus one");
    Check(child->nonce == 0, "nonce starts at zero");
    Check(child->version == parent.version, "version is copied from the parent");
    Check(child->tx_root == tx_root && child->state_root == state_root, "supplied roots");
    Check(child->tx_root != parent.tx_root && child->state_root != parent.state_root,
          "roots are not copied from the parent");
    Check(child->time == time && child->size == size && child->bits == bits,
          "supplied time, size, and bits");

    std::array<uint8_t, HEADER_SIZE> bytes{};
    Check(SerializeHeader(*child, bytes), "serialize child");
    Check(bytes.size() == 134, "serialized header is 134 bytes");
    Header parsed;
    parsed.nonce = 99;
    Check(ParseHeader(bytes.data(), bytes.size(), parsed) && parsed.nonce == 0,
          "serialized header round-trips");

    Check(!BuildChildHeader(parent, chain_id, tx_root, state_root, MAX_TIME + 1, size, bits),
          "reject timestamp above MAX_TIME");
    const uint32_t rejected_bits[] = {0x1d80ffff, 0x1d000000, 0x22010000, 0x03000001, 0};
    for (uint32_t bad : rejected_bits) {
        Check(!BuildChildHeader(parent, chain_id, tx_root, state_root, time, size, bad),
              "reject bits DecodeTarget rejects");
    }
    Header overflow = parent;
    overflow.height = std::numeric_limits<uint64_t>::max();
    Check(!BuildChildHeader(overflow, chain_id, tx_root, state_root, time, size, bits),
          "reject height overflow");
    Header unhashable = parent;
    unhashable.time = MAX_TIME + 1;
    Check(!BuildChildHeader(unhashable, chain_id, tx_root, state_root, time, size, bits),
          "reject a parent whose block id cannot be computed");
    Check(BuildChildHeader(parent, chain_id, tx_root, state_root, MAX_TIME, size, bits).has_value(),
          "maximum u48 timestamp is accepted");

    Hash target{};
    Check(DecodeTarget(bits, Ceiling(), target), "decode the easy target");
    // Local searches only. No call below tries more than 256 nonces.
    Header easy = *child;
    Check(SearchNonce(easy, chain_id, target, 0, 8), "easy target found within 8 attempts");
    Hash found_id{};
    Check(BlockId(chain_id, easy, found_id) && MeetsTarget(found_id, target),
          "found header meets target");
    Check(easy.nonce < 8, "winning nonce is inside the attempt window");
    Check(easy.prev_id == child->prev_id && easy.bits == child->bits && easy.time == child->time &&
              easy.version == child->version && easy.size == child->size &&
              easy.height == child->height && easy.tx_root == child->tx_root &&
              easy.state_root == child->state_root,
          "search changes only the nonce");
    Check(child->nonce == 0, "the template nonce stays zero");

    Header at_cap = *child;
    Check(SearchNonce(at_cap, chain_id, target, easy.nonce, MAX_NONCE_ATTEMPTS),
          "256 attempts are allowed");
    Check(at_cap.nonce == easy.nonce, "known nonce is accepted at the attempt cap");

    Header refused = *child;
    refused.nonce = 77;
    const Header refused_before = refused;
    Check(!SearchNonce(refused, chain_id, target, 3, 257), "257 attempts are refused");
    Check(SameHeader(refused, refused_before), "refused search leaves the header unchanged");

    Hash lowest{};
    lowest.fill(0xff);
    for (uint64_t nonce = 0; nonce < 4; ++nonce) {
        Header candidate = *child;
        candidate.nonce = nonce;
        Hash block_id{};
        Check(BlockId(chain_id, candidate, block_id), "hard-target candidate id");
        if (MeetsTarget(block_id, lowest)) lowest = block_id;
    }
    Check(SubtractOne(lowest), "candidate block ids are not zero");
    Header missed = *child;
    missed.nonce = 55;
    const Header missed_before = missed;
    Check(!SearchNonce(missed, chain_id, lowest, 0, 4), "hard target misses within 4 attempts");
    Check(SameHeader(missed, missed_before), "a miss leaves the header unchanged");

    const Hash body = BodyHash(chain_id, *child);
    Hash work{};
    Hash block_id{};
    Check(WorkHash(chain_id, *child, work), "child work hash");
    Check(BlockId(chain_id, *child, block_id), "child template block id");

    const std::string json =
        std::string("{\"protocol\":\"v2\",\"job_id\":\"native-037-template\",\"chain_id\":\"") +
        Hex(chain_id) + "\",\"header\":\"" + Hex(bytes.data(), bytes.size()) +
        "\",\"target\":\"" + Hex(target) + "\"}";
    const std::filesystem::path path = "/tmp/lotus-v2-native-037-packet/job.json";
    std::filesystem::create_directories(path.parent_path());
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    Check(static_cast<bool>(file), "open job json");
    file << json << '\n';
    Check(static_cast<bool>(file), "write job json");

    std::cout << "V2 block template passed\n";
    std::cout << "body " << Hex(body) << '\n';
    std::cout << "work " << Hex(work) << '\n';
    std::cout << "block_id " << Hex(block_id) << '\n';
    std::cout << "job " << json << '\n';
}
