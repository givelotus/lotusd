#include "header.h"
#include "arith_uint256.h"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <string>

using namespace lotus::v2;

namespace {
void Check(bool condition, const char *message) {
    if (!condition) {
        std::cerr << "V2 header: " << message << '\n';
        std::exit(1);
    }
}

std::string Hex(const uint8_t *data, size_t size) {
    constexpr char chars[] = "0123456789abcdef";
    std::string result;
    for (size_t i = 0; i < size; ++i) {
        result.push_back(chars[data[i] >> 4]);
        result.push_back(chars[data[i] & 15]);
    }
    return result;
}

std::string Hex(const Hash &hash) { return Hex(hash.data(), hash.size()); }
} // namespace

int main() {
    // These constants were computed independently with Python blake3 1.0.11,
    // not by the vendored C implementation under test.
    ChainId chain_id;
    Header header;
    for (unsigned i = 0; i < 32; ++i) {
        chain_id[i] = i;
        header.prev_id[i] = i + 32;
        header.tx_root[i] = i + 64;
        header.state_root[i] = i + 96;
    }
    header.bits = 0x1d00ffff;
    header.time = 0x010203040506;
    header.nonce = 0x08090a0b0c0d0e0f;
    header.version = 2;
    header.size = 0x1122334455667788;
    header.height = 0x99aabbccddeeff00;
    std::array<uint8_t, HEADER_SIZE> bytes;
    Check(SerializeHeader(header, bytes), "serialize normal header");
    Check(Hex(bytes.data(), bytes.size()) ==
              "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
              "ffff001d0605040302010f0e0d0c0b0a0908020000008877665544332211"
              "00ffeeddccbbaa99404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
              "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
          "exact 134-byte encoding and offsets");
    Header parsed;
    parsed.version = 0xdeadbeef;
    Check(!ParseHeader(bytes.data(), bytes.size() - 1, parsed), "reject short header");
    Check(parsed.version == 0xdeadbeef, "short parse leaves output unchanged");
    Check(!ParseHeader(bytes.data(), bytes.size() + 1, parsed), "reject trailing bytes");
    Check(!ParseHeader(nullptr, bytes.size(), parsed), "reject null data");
    Check(ParseHeader(bytes.data(), bytes.size(), parsed), "parse header");
    std::array<uint8_t, HEADER_SIZE> repeated;
    Check(SerializeHeader(parsed, repeated) && bytes == repeated, "round trip");
    Check(Hex(BodyHash(chain_id, header)) ==
              "1704e11edcbc47eb829d210ac1affb606dd4021c82305e07a028962456efec3d",
          "independent BodyHash vector");
    Hash work;
    Hash id;
    Check(WorkHash(chain_id, header, work) && Hex(work) ==
              "56c49269bcb4709b42d48312a382badc0906162e5bd6e49aac48a7096288ffd1",
          "independent WorkHash vector");
    Check(BlockId(chain_id, header, id) && Hex(id) ==
              "fbe9243579627fc3a41043c80395d33a8a01b91a9b86b6c6e629530595c83370",
          "independent BlockID vector");
    header.nonce++;
    Check(WorkHash(chain_id, header, work) && Hex(work) ==
              "3df1f29ca207e25132c7b3fdddfae0163b16d0c6bf7488e2810858e84f0673e5",
          "nonce mutation WorkHash");
    Check(BlockId(chain_id, header, id) && Hex(id) ==
              "8a967f4522d06f683830cf003b9f456001e045f617bf4d4336754a91c75f5824",
          "nonce mutation BlockID");
    header.nonce = UINT64_MAX;
    Check(BlockId(chain_id, header, id) && Hex(id) ==
              "ce606e015b769cf60502917d0bac3597048e25668c7df323f817b53969aab371",
          "maximum nonce BlockID");
    const Hash old_body = BodyHash(chain_id, header);
    chain_id[0]++;
    Check(BodyHash(chain_id, header) != old_body, "ChainID enters BodyHash");
    chain_id[0]--;
    header.time = MAX_TIME;
    Check(SerializeHeader(header, bytes) && bytes[41] == 0xff, "maximum u48 time");
    header.time++;
    bytes[0] = 0xa5;
    Check(!SerializeHeader(header, bytes), "reject u48 overflow in encoding");
    Check(bytes[0] == 0xa5, "failed encoding leaves output unchanged");
    work.fill(0xa5);
    Check(!WorkHash(chain_id, header, work), "reject u48 overflow in work hash");
    Check(work[0] == 0xa5 && work[31] == 0xa5, "failed work hash leaves output unchanged");
    id.fill(0xa5);
    Check(!BlockId(chain_id, header, id), "reject u48 overflow in block ID");
    Check(id[0] == 0xa5 && id[31] == 0xa5, "failed block hash leaves output unchanged");

    Hash pow_limit{};
    pow_limit[31] = 0xff;
    Hash target{};
    Check(DecodeTarget(0x1d00ffff, pow_limit, target), "Bitcoin-style canonical target");
    Check(target[26] == 0xff && target[27] == 0xff && target[28] == 0,
          "compact target byte placement");
    Check(!DecodeTarget(0x1d80ffff, pow_limit, target), "reject sign bit");
    Check(!DecodeTarget(0x1d000000, pow_limit, target), "reject zero");
    Check(!DecodeTarget(0x22010000, pow_limit, target), "reject 257-bit overflow");
    Check(!DecodeTarget(0x03000001, pow_limit, target), "reject noncanonical compact");
    Hash low_limit{};
    low_limit[0] = 1;
    Check(!DecodeTarget(0x1d00ffff, low_limit, target), "enforce supplied POW_LIMIT");
    Hash equal = target;
    Check(MeetsTarget(equal, target), "target equality accepted");
    equal[0]++;
    Check(!MeetsTarget(equal, target), "target plus one rejected");
    equal = target;
    for (size_t i = 0; i < equal.size(); ++i) {
        if (equal[i]-- != 0) break;
    }
    Check(MeetsTarget(equal, target), "target minus one accepted");

    // Differential compact parsing against ABC's arithmetic representation.
    // Cover every exponent and representative mantissa/sign/rounding classes.
    const uint32_t mantissas[] = {0, 1, 0x7f, 0x80, 0xff, 0x100,
                                  0xffff, 0x10000, 0x7fffff,
                                  0x800001, 0xffffff};
    const Hash limits[] = {pow_limit, low_limit};
    for (const Hash &limit : limits) {
        for (uint32_t exponent = 0; exponent < 256; ++exponent) {
            for (uint32_t mantissa : mantissas) {
                const uint32_t compact = (exponent << 24) | mantissa;
                arith_uint256 reference;
                bool negative = false;
                bool overflow = false;
                reference.SetCompact(compact, &negative, &overflow);
                Hash reference_bytes{};
                for (unsigned i = 0; i < 32; ++i) {
                    reference_bytes[i] = static_cast<uint8_t>((reference >> (8 * i)).GetLow64());
                }
                const bool expected = (compact & 0x00800000U) == 0 &&
                                      !negative && !overflow && reference != 0 &&
                                      reference.GetCompact() == compact &&
                                      MeetsTarget(reference_bytes, limit);
                Hash actual;
                actual.fill(0xa5);
                const bool accepted = DecodeTarget(compact, limit, actual);
                Check(accepted == expected, "ABC compact differential acceptance");
                if (accepted) {
                    Check(actual == reference_bytes, "ABC compact differential value");
                } else {
                    Check(std::all_of(actual.begin(), actual.end(),
                                      [](uint8_t byte) { return byte == 0xa5; }),
                          "failed target decoding leaves output unchanged");
                }
            }
        }
    }
    std::cout << "V2 header primitive vectors and boundaries passed\n";
}
