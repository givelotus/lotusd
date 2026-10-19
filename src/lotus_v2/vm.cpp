#include "vm.h"

#include "commitment.h"
#include "field_size.h"
#include "tagged_hash.h"
#include "vendor/blake3/blake3.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>
#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#elif defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#include <emmintrin.h>
#endif

namespace lotus::v2 {
namespace {
    using Int = __int128_t;
    using UInt = __uint128_t;
#ifdef LOTUS_V2_VM_TEST_INSTRUMENTATION
    VmCryptoFault vm_crypto_fault = VmCryptoFault::None;
#define VM_TEST_CRYPTO_FAIL(name) (vm_crypto_fault == VmCryptoFault::name)
#else
#define VM_TEST_CRYPTO_FAIL(name) false
#endif
    struct VmFailure : std::runtime_error {
        VmStatus status;
        VmFailure(const char *message, bool unsupported = false)
            : std::runtime_error(message),
              status(unsupported ? VmStatus::Unsupported : VmStatus::Invalid) {}
        VmFailure(const char *message, VmStatus kind)
            : std::runtime_error(message), status(kind) {}
    };
    struct Instruction {
        VmOpcode op;
        VmBytes data;
        size_t peer = 0; // IF: ELSE or ENDIF; ELSE/loop: closing marker
        size_t end = 0;  // IF: ENDIF
    };

    // Genesis allocation for C_account, byte for byte the P03 registry
    // (docs/lotus-v2/tools/opcodes.json, sha256 recorded in
    // vm_test/opcode_coverage.json): 225 assigned bytes, 31 OP_SUCCESS_N.
    // This is a pre-genesis reallocation (67/68 retired, new bytes added);
    // after genesis, only unassigned bytes may become assigned (soft fork).
    // 0x6c (EMITLOG) counts as assigned but the scan rejects it on-chain, and
    // 0xff (EXT2) is the two-byte prefix handled by the scan.
    bool GenesisAssigned(uint8_t op) {
        return op <= 0x5d || (op >= 0x60 && op <= 0x66) ||
               (op >= 0x69 && op <= 0x6c) || (op >= 0x70 && op <= 0x81) ||
               (op >= 0x88 && op <= 0x94) || (op >= 0x98 && op <= 0xb4) ||
               (op >= 0xb8 && op <= 0xc3) || (op >= 0xc8 && op <= 0xdf) ||
               (op >= 0xe0 && op <= 0xef) || (op >= 0xf0 && op <= 0xf6) ||
               op == 0xff;
    }
    constexpr uint8_t OP_EMITLOG = 0x6c;
    // Current enforcement allocation. A future activated view may add bytes.
    bool Assigned(uint8_t op) {
        return GenesisAssigned(op);
    }
    // Two-byte `ff xx` opcodes. None is assigned at genesis, so every pair is
    // OP_SUCCESS_EXT_xx. Assigning one is a soft fork under P03's contract.
    bool GenesisAssignedExt(uint8_t) { return false; }
    bool AssignedExt(uint8_t selector) { return GenesisAssignedExt(selector); }

    size_t PushLength(std::span<const uint8_t> script, size_t &pos,
                      const VmProfile &profile) {
        if (pos >= script.size()) throw VmFailure("truncated PUSHDATA length");
        const uint8_t first = script[pos++];
        uint64_t length = first;
        if (first >= 253) {
            const unsigned width = first == 253 ? 2 : first == 254 ? 4 : 8;
            if (script.size() - pos < width)
                throw VmFailure("truncated CompactSize");
            length = 0;
            for (unsigned i = 0; i < width; ++i)
                length |= uint64_t(script[pos++]) << (8 * i);
            if ((first == 253 && length < 253) ||
                (first == 254 && length <= 65535) ||
                (first == 255 && length <= UINT32_MAX))
                throw VmFailure("nonminimal CompactSize");
        }
        if (length > profile.max_element_bytes ||
            length > std::numeric_limits<size_t>::max() ||
            (length > 0 && length <= 75))
            throw VmFailure("invalid PUSHDATA length");
        return size_t(length);
    }

    // Scan never interprets control flow and stops before inspecting the suffix
    // of a success byte. When no success is present, it also gives full
    // instruction boundaries to the structural decoder.
    bool Scan(std::span<const uint8_t> script, const VmProfile &profile,
              std::vector<Instruction> &instructions, bool genesis = false) {
        size_t pos = 0;
        while (pos < script.size()) {
            uint8_t op = script[pos++];
            if (op == VM_EXT2_PREFIX) {
                // The selector is never parsed as a push or a one-byte opcode.
                if (pos == script.size()) throw VmFailure("truncated EXT2");
                const uint8_t selector = script[pos++];
                if (!(genesis ? GenesisAssignedExt(selector)
                              : AssignedExt(selector)))
                    return true;
                instructions.push_back(Instruction{VmExt2(selector), {}, 0, 0});
                continue;
            }
            // EMITLOG is simulation-only and permanently invalid on-chain. It
            // rejects as soon as the scan reaches it, so a later success byte,
            // a skipped arm or an earlier RETURN cannot hide it.
            if (op == OP_EMITLOG)
                throw VmFailure("EMITLOG is invalid on-chain");
            if (!(genesis ? GenesisAssigned(op) : Assigned(op))) return true;
            size_t len = 0;
            if (op >= 1 && op <= 75) {
                len = op;
                if (len > profile.max_element_bytes)
                    throw VmFailure("fixed push exceeds element cap");
            } else if (op == 0x4c) {
                len = PushLength(script, pos, profile);
            }
            if (len > script.size() - pos) throw VmFailure("truncated push");
            Instruction ins{op, {}, 0, 0};
            if (len || op == 0x4c)
                ins.data.assign(script.begin() + pos,
                                script.begin() + pos + len);
            pos += len;
            instructions.push_back(std::move(ins));
        }
        return false;
    }

    void Structure(std::vector<Instruction> &code, const VmProfile &profile) {
        struct Frame {
            VmOpcode op;
            size_t start;
            bool has_else;
        };
        std::vector<Frame> frames;
        size_t loop_depth = 0;
        for (size_t i = 0; i < code.size(); ++i) {
            const VmOpcode op = code[i].op;
            if (op == 0x61 || op == 0x62 || op == 0x69) {
                if (op == 0x69 && ++loop_depth > 2)
                    throw VmFailure("loop nesting exceeds two");
                if (frames.size() >= profile.max_ast_depth)
                    throw VmFailure("AST depth exceeded");
                frames.push_back({op, i, false});
            } else if (op == 0x63) {
                if (frames.empty() || frames.back().op > 0x62 ||
                    frames.back().has_else)
                    throw VmFailure("unmatched ELSE");
                code[frames.back().start].peer = i;
                frames.back().has_else = true;
            } else if (op == 0x64) {
                if (frames.empty() || frames.back().op > 0x62)
                    throw VmFailure("unmatched ENDIF");
                Frame frame = frames.back();
                frames.pop_back();
                code[frame.start].end = i;
                if (frame.has_else)
                    code[code[frame.start].peer].peer = i;
                else
                    code[frame.start].peer = i;
            } else if (op == 0x6a) {
                if (frames.empty() || frames.back().op != 0x69)
                    throw VmFailure("unmatched ENDENUMERATE");
                code[frames.back().start].peer = i;
                frames.pop_back();
                --loop_depth;
            }
        }
        if (!frames.empty()) throw VmFailure("unclosed structure");
    }

    void SimdInvertInPlace(uint8_t *dst, size_t len) {
        size_t i = 0;
#if defined(__aarch64__) || defined(_M_ARM64)
        for (; i + 16 <= len; i += 16)
            vst1q_u8(dst + i, vmvnq_u8(vld1q_u8(dst + i)));
#elif defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
        const __m128i ones = _mm_set1_epi8(-1);
        for (; i + 16 <= len; i += 16) {
            __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i *>(dst + i));
            _mm_storeu_si128(reinterpret_cast<__m128i *>(dst + i), _mm_xor_si128(v, ones));
        }
#endif
        for (; i < len; ++i) dst[i] ^= 0xff;
    }

    VmBytes SimdBitwiseBinOp(uint8_t op, const VmBytes &a, const VmBytes &b) {
        const size_t min_len = std::min(a.size(), b.size());
        const size_t max_len = std::max(a.size(), b.size());
        if (op == 0x8e) {
            // AND with zero-padding: high bytes min_len..max_len-1 remain 0.
            VmBytes out(max_len, 0);
            size_t i = 0;
#if defined(__aarch64__) || defined(_M_ARM64)
            for (; i + 16 <= min_len; i += 16)
                vst1q_u8(out.data() + i,
                         vandq_u8(vld1q_u8(a.data() + i), vld1q_u8(b.data() + i)));
#elif defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
            for (; i + 16 <= min_len; i += 16) {
                __m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i *>(a.data() + i));
                __m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i *>(b.data() + i));
                _mm_storeu_si128(reinterpret_cast<__m128i *>(out.data() + i),
                                 _mm_and_si128(va, vb));
            }
#endif
            for (; i < min_len; ++i) out[i] = a[i] & b[i];
            return out;
        }
        // OR (0x8f) and XOR (0x90) with zero-padding: copy longer, combine prefix.
        VmBytes out = (a.size() >= b.size()) ? a : b;
        const uint8_t *shorter = (a.size() >= b.size()) ? b.data() : a.data();
        size_t i = 0;
        if (op == 0x8f) {
#if defined(__aarch64__) || defined(_M_ARM64)
            for (; i + 16 <= min_len; i += 16)
                vst1q_u8(out.data() + i,
                         vorrq_u8(vld1q_u8(out.data() + i), vld1q_u8(shorter + i)));
#elif defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
            for (; i + 16 <= min_len; i += 16) {
                __m128i vo = _mm_loadu_si128(reinterpret_cast<const __m128i *>(out.data() + i));
                __m128i vs = _mm_loadu_si128(reinterpret_cast<const __m128i *>(shorter + i));
                _mm_storeu_si128(reinterpret_cast<__m128i *>(out.data() + i),
                                 _mm_or_si128(vo, vs));
            }
#endif
            for (; i < min_len; ++i) out[i] |= shorter[i];
        } else {
#if defined(__aarch64__) || defined(_M_ARM64)
            for (; i + 16 <= min_len; i += 16)
                vst1q_u8(out.data() + i,
                         veorq_u8(vld1q_u8(out.data() + i), vld1q_u8(shorter + i)));
#elif defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
            for (; i + 16 <= min_len; i += 16) {
                __m128i vo = _mm_loadu_si128(reinterpret_cast<const __m128i *>(out.data() + i));
                __m128i vs = _mm_loadu_si128(reinterpret_cast<const __m128i *>(shorter + i));
                _mm_storeu_si128(reinterpret_cast<__m128i *>(out.data() + i),
                                 _mm_xor_si128(vo, vs));
            }
#endif
            for (; i < min_len; ++i) out[i] ^= shorter[i];
        }
        return out;
    }

    using Mag = std::vector<uint64_t>;

    void TrimMag(Mag &m) {
        while (!m.empty() && m.back() == 0) m.pop_back();
    }

    size_t BitLengthMag(const Mag &m) {
        if (m.empty()) return 0;
        return (m.size() - 1) * 64 + (64 - unsigned(__builtin_clzll(m.back())));
    }

    int CompareMag(const Mag &a, const Mag &b) {
        if (a.size() != b.size()) return a.size() < b.size() ? -1 : 1;
        for (size_t i = a.size(); i > 0; --i)
            if (a[i - 1] != b[i - 1]) return a[i - 1] < b[i - 1] ? -1 : 1;
        return 0;
    }

    Mag AddMag(const Mag &a, const Mag &b) {
        const size_t n = std::max(a.size(), b.size());
        Mag out(n, 0);
        UInt carry = 0;
        for (size_t i = 0; i < n; ++i) {
            const UInt sum = (i < a.size() ? UInt(a[i]) : 0) +
                             (i < b.size() ? UInt(b[i]) : 0) + carry;
            out[i] = uint64_t(sum);
            carry = sum >> 64;
        }
        if (carry) out.push_back(uint64_t(carry));
        TrimMag(out);
        return out;
    }

    Mag SubMag(const Mag &a, const Mag &b) {
        Mag out(a.size(), 0);
        UInt borrow = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            const UInt sub = (i < b.size() ? UInt(b[i]) : 0) + borrow;
            out[i] = a[i] - uint64_t(sub);
            borrow = (UInt(a[i]) < sub) ? 1 : 0;
        }
        TrimMag(out);
        return out;
    }

    Mag MulMag(const Mag &a, const Mag &b) {
        if (a.empty() || b.empty()) return {};
        Mag out(a.size() + b.size(), 0);
        for (size_t i = 0; i < a.size(); ++i) {
            UInt carry = 0;
            const UInt ai = a[i];
            for (size_t j = 0; j < b.size(); ++j) {
                const UInt cur = UInt(out[i + j]) + ai * UInt(b[j]) + carry;
                out[i + j] = uint64_t(cur);
                carry = cur >> 64;
            }
            out[i + b.size()] = uint64_t(UInt(out[i + b.size()]) + carry);
        }
        TrimMag(out);
        return out;
    }

    Mag ShlMag(const Mag &a, size_t bits) {
        if (a.empty() || bits == 0) return a;
        const size_t word_shift = bits / 64;
        const unsigned bit_shift = unsigned(bits % 64);
        Mag out(a.size() + word_shift + 1, 0);
        if (bit_shift == 0) {
            for (size_t i = 0; i < a.size(); ++i) out[i + word_shift] = a[i];
        } else {
            uint64_t carry = 0;
            for (size_t i = 0; i < a.size(); ++i) {
                out[i + word_shift] = (a[i] << bit_shift) | carry;
                carry = a[i] >> (64 - bit_shift);
            }
            out[a.size() + word_shift] = carry;
        }
        TrimMag(out);
        return out;
    }

    Mag ShrMag(const Mag &a, size_t bits) {
        if (a.empty()) return {};
        const size_t word_shift = bits / 64;
        if (word_shift >= a.size()) return {};
        const unsigned bit_shift = unsigned(bits % 64);
        Mag out(a.size() - word_shift, 0);
        if (bit_shift == 0) {
            for (size_t i = 0; i < out.size(); ++i) out[i] = a[i + word_shift];
        } else {
            for (size_t i = 0; i < out.size(); ++i) {
                out[i] = a[i + word_shift] >> bit_shift;
                if (i + word_shift + 1 < a.size())
                    out[i] |= a[i + word_shift + 1] << (64 - bit_shift);
            }
        }
        TrimMag(out);
        return out;
    }

    // Knuth Algorithm D in base 2^64 using __uint128_t.
    std::pair<Mag, Mag> DivModMag(const Mag &u, const Mag &v) {
        if (v.empty()) throw VmFailure("invalid division");
        const int cmp = CompareMag(u, v);
        if (cmp < 0) return {{}, u};
        if (cmp == 0) return {{1}, {}};
        if (u.size() <= 2 && v.size() <= 2) {
            const UInt u128 = UInt(u[0]) | (u.size() > 1 ? (UInt(u[1]) << 64) : 0);
            const UInt v128 = UInt(v[0]) | (v.size() > 1 ? (UInt(v[1]) << 64) : 0);
            const UInt q128 = u128 / v128, r128 = u128 % v128;
            Mag q{uint64_t(q128), uint64_t(q128 >> 64)};
            Mag r{uint64_t(r128), uint64_t(r128 >> 64)};
            TrimMag(q);
            TrimMag(r);
            return {std::move(q), std::move(r)};
        }
        if (v.size() == 1) {
            const uint64_t d = v[0];
            Mag q(u.size(), 0);
            UInt rem = 0;
            for (size_t i = u.size(); i > 0; --i) {
                const UInt cur = (rem << 64) | u[i - 1];
                q[i - 1] = uint64_t(cur / d);
                rem = cur % d;
            }
            TrimMag(q);
            Mag r;
            if (rem) r.push_back(uint64_t(rem));
            return {std::move(q), std::move(r)};
        }
        const size_t n = v.size();
        const size_t m = u.size() - n;
        const unsigned shift = unsigned(__builtin_clzll(v.back()));
        Mag vn = ShlMag(v, shift);
        Mag un = ShlMag(u, shift);
        un.resize(u.size() + 1, 0);
        Mag q(m + 1, 0);
        const UInt base = UInt(1) << 64;
        for (size_t jj = m + 1; jj > 0; --jj) {
            const size_t j = jj - 1;
            const UInt num = (UInt(un[j + n]) << 64) | un[j + n - 1];
            UInt qhat = num / vn[n - 1];
            UInt rhat = num % vn[n - 1];
            if (qhat >= base) {
                qhat = base - 1;
                rhat = num - qhat * vn[n - 1];
            }
            while (rhat < base &&
                   qhat * UInt(vn[n - 2]) > ((rhat << 64) | un[j + n - 2])) {
                --qhat;
                rhat += vn[n - 1];
            }
            UInt borrow = 0;
            for (size_t i = 0; i < n; ++i) {
                const UInt p = qhat * UInt(vn[i]) + borrow;
                borrow = p >> 64;
                const uint64_t p_lo = uint64_t(p);
                if (un[j + i] < p_lo) ++borrow;
                un[j + i] -= p_lo;
            }
            const bool negative = UInt(un[j + n]) < borrow;
            un[j + n] -= uint64_t(borrow);
            if (negative) {
                --qhat;
                UInt carry = 0;
                for (size_t i = 0; i < n; ++i) {
                    const UInt sum = UInt(un[j + i]) + vn[i] + carry;
                    un[j + i] = uint64_t(sum);
                    carry = sum >> 64;
                }
                un[j + n] += uint64_t(carry);
            }
            q[j] = uint64_t(qhat);
        }
        un.resize(n);
        Mag r = ShrMag(un, shift);
        TrimMag(q);
        TrimMag(r);
        return {std::move(q), std::move(r)};
    }

    Mag MagFromUnsignedBytes(std::span<const uint8_t> bytes) {
        Mag out((bytes.size() + 7) / 8, 0);
        for (size_t i = 0; i < bytes.size(); ++i)
            out[i / 8] |= uint64_t(bytes[i]) << (8 * (i % 8));
        TrimMag(out);
        return out;
    }

    VmBytes MagToUnsignedBytes(const Mag &m, size_t width) {
        VmBytes out(width, 0);
        for (size_t i = 0; i < width; ++i) {
            const size_t limb = i / 8;
            if (limb < m.size())
                out[i] = uint8_t((m[limb] >> (8 * (i % 8))) & 0xff);
        }
        return out;
    }

    struct BigInt {
        bool neg = false;
        Mag limbs;

        bool IsZero() const { return limbs.empty(); }

        void Normalize() {
            TrimMag(limbs);
            if (limbs.empty()) neg = false;
        }

        static BigInt FromInt(Int v) {
            BigInt out;
            if (v == 0) return out;
            out.neg = v < 0;
            const UInt mag = v < 0 ? UInt(-(v + 1)) + 1 : UInt(v);
            out.limbs.push_back(uint64_t(mag));
            if (mag >> 64) out.limbs.push_back(uint64_t(mag >> 64));
            out.Normalize();
            return out;
        }

        static BigInt FromSignedBytes(std::span<const uint8_t> bytes) {
            BigInt out;
            if (bytes.empty()) return out;
            const bool negative = (bytes.back() & 0x80) != 0;
            if (!negative) {
                out.limbs = MagFromUnsignedBytes(bytes);
                return out;
            }
            out.neg = true;
            out.limbs.assign((bytes.size() + 7) / 8, 0);
            uint16_t carry = 1;
            for (size_t i = 0; i < bytes.size(); ++i) {
                const uint16_t inv = uint16_t(uint8_t(~bytes[i])) + carry;
                out.limbs[i / 8] |= uint64_t(uint8_t(inv)) << (8 * (i % 8));
                carry = inv >> 8;
            }
            if (carry) {
                const size_t top_byte = bytes.size();
                if (top_byte / 8 >= out.limbs.size()) out.limbs.push_back(0);
                out.limbs[top_byte / 8] |= uint64_t(1) << (8 * (top_byte % 8));
            }
            out.Normalize();
            return out;
        }

        size_t MinimalSignedWidth() const {
            if (IsZero()) return 1;
            if (!neg) return BitLengthMag(limbs) / 8 + 1;
            const Mag minus_one = SubMag(limbs, {1});
            return BitLengthMag(minus_one) / 8 + 1;
        }

        VmBytes ToSignedBytes(size_t width, const char *overflow_msg = "int128 overflow") const {
            if (width == 0) {
                if (!IsZero()) throw VmFailure(overflow_msg);
                return {};
            }
            if (MinimalSignedWidth() > width) throw VmFailure(overflow_msg);
            if (!neg) return MagToUnsignedBytes(limbs, width);
            VmBytes out(width, 0xff);
            uint16_t carry = 1;
            for (size_t i = 0; i < width; ++i) {
                const size_t limb = i / 8;
                const uint8_t mag_byte =
                    limb < limbs.size() ? uint8_t((limbs[limb] >> (8 * (i % 8))) & 0xff) : 0;
                const uint16_t tc = uint16_t(uint8_t(~mag_byte)) + carry;
                out[i] = uint8_t(tc & 0xff);
                carry = tc >> 8;
            }
            return out;
        }

        Int ToClampedInt128() const {
            const UInt sign = UInt(1) << 127;
            const Int min_val = -Int(sign - 1) - 1;
            const Int max_val = Int(sign - 1);
            if (IsZero()) return 0;
            if (limbs.size() > 2) return neg ? min_val : max_val;
            const UInt mag = UInt(limbs[0]) | (limbs.size() > 1 ? (UInt(limbs[1]) << 64) : 0);
            if (!neg) return mag >= sign ? max_val : Int(mag);
            if (mag > sign) return min_val;
            if (mag == sign) return min_val;
            return -Int(mag);
        }
    };

    int CompareBig(const BigInt &a, const BigInt &b) {
        if (a.neg != b.neg) return a.neg ? -1 : 1;
        const int cmp = CompareMag(a.limbs, b.limbs);
        return a.neg ? -cmp : cmp;
    }

    BigInt AddBig(const BigInt &a, const BigInt &b) {
        if (a.IsZero()) return b;
        if (b.IsZero()) return a;
        BigInt out;
        if (a.neg == b.neg) {
            out.neg = a.neg;
            out.limbs = AddMag(a.limbs, b.limbs);
        } else {
            const int cmp = CompareMag(a.limbs, b.limbs);
            if (cmp == 0) return out;
            if (cmp > 0) {
                out.neg = a.neg;
                out.limbs = SubMag(a.limbs, b.limbs);
            } else {
                out.neg = b.neg;
                out.limbs = SubMag(b.limbs, a.limbs);
            }
        }
        out.Normalize();
        return out;
    }

    BigInt NegBig(BigInt a) {
        if (!a.IsZero()) a.neg = !a.neg;
        return a;
    }

    BigInt SubBig(const BigInt &a, const BigInt &b) {
        return AddBig(a, NegBig(b));
    }

    BigInt MulBig(const BigInt &a, const BigInt &b) {
        BigInt out;
        if (a.IsZero() || b.IsZero()) return out;
        out.neg = a.neg != b.neg;
        out.limbs = MulMag(a.limbs, b.limbs);
        out.Normalize();
        return out;
    }

    std::pair<BigInt, BigInt> DivModBig(const BigInt &a, const BigInt &b) {
        if (b.IsZero()) throw VmFailure("invalid division");
        auto [q_mag, r_mag] = DivModMag(a.limbs, b.limbs);
        BigInt q{a.neg != b.neg, std::move(q_mag)};
        BigInt r{a.neg, std::move(r_mag)};
        q.Normalize();
        r.Normalize();
        return {std::move(q), std::move(r)};
    }

    BigInt NumericBig(const VmBytes &bytes) {
        if (bytes.size() < VM_MIN_NUMERIC_BYTES || bytes.size() > VM_MAX_NUMERIC_BYTES)
            throw VmFailure("operand is not N");
        return BigInt::FromSignedBytes(bytes);
    }

    Int Numeric(const VmBytes &bytes) {
        return NumericBig(bytes).ToClampedInt128();
    }
    constexpr size_t VM_STATEHASH_MAX_ITEMS = 64;
    size_t CompactSizeBytes(uint64_t value) {
        return value < 253 ? 1 : value <= 0xffff ? 3 : value <= 0xffffffff ? 5 : 9;
    }
    // CS(k) plus CS(len) for every item: the STATEHASH preimage bytes that
    // are not item payload.
    size_t StateHashFramingBytes(const std::vector<VmBytes> &items) {
        size_t total = CompactSizeBytes(items.size());
        for (const auto &item : items) total += CompactSizeBytes(item.size());
        return total;
    }
    VmBytes Number(Int number) {
        UInt value = UInt(number);
        VmBytes bytes(16);
        for (size_t i = 0; i < 16; ++i) {
            bytes[i] = uint8_t(value & 255);
            value >>= 8;
        }
        return bytes;
    }
    bool Boolean(const VmBytes &value) {
        const Int n = Numeric(value);
        if (value.size() != 16 || (n != 0 && n != 1))
            throw VmFailure("noncanonical Boolean");
        return n == 1;
    }
    VmBytes Sha256(std::span<const uint8_t> value) {
        VmBytes out(32);
        unsigned int len = 0;
        if (VM_TEST_CRYPTO_FAIL(Digest) ||
            !EVP_Digest(value.data(), value.size(), out.data(), &len,
                        EVP_sha256(), nullptr) ||
            len != 32)
            throw VmFailure("SHA256 failure", VmStatus::OperationalError);
        return out;
    }
    VmBytes Blake3(std::span<const uint8_t> value) {
        VmBytes out(32);
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, value.data(), value.size());
        blake3_hasher_finalize(&hasher, out.data(), out.size());
        return out;
    }
    bool LessHashLittleEndian(const Hash &a, const Hash &b) {
        for (size_t i = 32; i > 0; --i)
            if (a[i - 1] != b[i - 1]) return a[i - 1] < b[i - 1];
        return false;
    }
    Hash MerkleStep(uint8_t algorithm, bool indexed, uint16_t layer,
                    const Hash &left, const Hash &right) {
        if (algorithm == 0)
            return indexed ? IndexedNode(layer, left, right)
                           : BranchNode(left, right);
        std::array<uint8_t, 64> pair{};
        std::copy(left.begin(), left.end(), pair.begin());
        std::copy(right.begin(), right.end(), pair.begin() + 32);
        VmBytes digest = algorithm == 1 ? Blake3(pair) : Sha256(pair);
        if (algorithm == 3) digest = Sha256(digest);
        Hash result{};
        std::copy(digest.begin(), digest.end(), result.begin());
        return result;
    }

    // Carry input of ADDCARRY/SUBCARRY must be canonical N(0) or N(1).
    UInt CarryInput(const VmBytes &bytes) {
        const Int value = Numeric(bytes);
        if (bytes.size() != 16 || (value != 0 && value != 1))
            throw VmFailure("carry is not N(0)/N(1)");
        return UInt(value);
    }
    // Exact 256-bit product from 64-bit limbs; no host integer wider than
    // 128 bits and no reliance on wrapping signed arithmetic.
    void WideMultiply(UInt a, UInt b, UInt &high, UInt &low) {
        const UInt mask = (UInt(1) << 64) - 1;
        const UInt a0 = a & mask, a1 = a >> 64, b0 = b & mask, b1 = b >> 64;
        const UInt p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
        const UInt middle = (p00 >> 64) + (p01 & mask) + (p10 & mask);
        low = (p00 & mask) | (middle << 64);
        high = p11 + (p01 >> 64) + (p10 >> 64) + (middle >> 64);
    }
    // P03 LOG2_Q64: e=bit_length(x)-1, k=max(127, e), z=x<<(k-e) normalized into
    // [2^k, 2^(k+1)), then 64 rounds of squaring recurrence.
    Int Log2Q64(const BigInt &x) {
        if (x.neg || x.IsZero()) throw VmFailure("LOG requires x>0");
        const size_t bits = BitLengthMag(x.limbs);
        const size_t e = bits - 1;
        UInt f = 0;
        if (e <= 127) {
            Mag z_mag = ShlMag(x.limbs, 127 - e);
            UInt z = (z_mag.empty() ? UInt(0) : UInt(z_mag[0])) |
                     (z_mag.size() > 1 ? (UInt(z_mag[1]) << 64) : UInt(0));
            for (unsigned round = 0; round < 64; ++round) {
                UInt high, low;
                WideMultiply(z, z, high, low);
                const bool bit = (high >> 127) != 0; // t >= 2^128
                z = bit ? high                        // floor(t/2) = floor(z*z/2^128)
                        : (high << 1) | (low >> 127); // t, fits since high < 2^127
                f = (f << 1) | UInt(bit);
            }
        } else {
            const size_t k = e;
            Mag z = x.limbs;
            for (unsigned round = 0; round < 64; ++round) {
                Mag t = ShrMag(MulMag(z, z), k);
                const bool bit = BitLengthMag(t) >= k + 2;
                z = bit ? ShrMag(t, 1) : std::move(t);
                f = (f << 1) | UInt(bit);
            }
        }
        return Int((UInt(e) << 64) | f);
    }
    BigInt IntegerSqrt(const BigInt &x) {
        if (x.neg) throw VmFailure("SQRT requires x>=0");
        if (x.IsZero()) return {};
        const size_t bits = BitLengthMag(x.limbs);
        BigInt g;
        g.limbs = ShlMag({1}, (bits + 1) / 2);
        for (;;) {
            auto [q, rem] = DivModMag(x.limbs, g.limbs);
            (void)rem;
            Mag sum = AddMag(g.limbs, q);
            Mag next = ShrMag(sum, 1);
            if (CompareMag(next, g.limbs) >= 0) break;
            g.limbs = std::move(next);
        }
        g.Normalize();
        return g;
    }

    // Big-endian 32-byte scalar comparison helpers for ECDSA r||s ranges.
    using Scalar32 = std::array<uint8_t, 32>;
    constexpr Scalar32 SECP256K1_ORDER{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
        0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
    constexpr Scalar32 SECP256K1_HALF_ORDER{
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4,
        0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0};
    constexpr Scalar32 P256_ORDER{
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17,
        0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51};
    constexpr Scalar32 P256_HALF_ORDER{
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b,
        0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8};
    // 1 <= r < n and 1 <= s <= floor(n/2), both 32-byte big-endian.
    bool StrictLowSRange(std::span<const uint8_t> signature,
                         const Scalar32 &order, const Scalar32 &half) {
        const uint8_t *r = signature.data(), *s = signature.data() + 32;
        const Scalar32 zero{};
        return std::memcmp(r, zero.data(), 32) != 0 &&
               std::memcmp(r, order.data(), 32) < 0 &&
               std::memcmp(s, zero.data(), 32) != 0 &&
               std::memcmp(s, half.data(), 32) <= 0;
    }
    void DerInteger(VmBytes &out, const uint8_t *value) {
        size_t start = 0;
        while (start < 31 && value[start] == 0) ++start;
        const bool pad = (value[start] & 0x80) != 0;
        out.push_back(0x02);
        out.push_back(uint8_t(32 - start + (pad ? 1 : 0)));
        if (pad) out.push_back(0);
        out.insert(out.end(), value + start, value + 32);
    }

    struct PkeyDeleter {
        void operator()(EVP_PKEY *key) const { EVP_PKEY_free(key); }
    };
    struct PkeyCtxDeleter {
        void operator()(EVP_PKEY_CTX *ctx) const { EVP_PKEY_CTX_free(ctx); }
    };
    using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
    using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter>;

    // Profile 1: SEC1-compressed P-256 key; malformed keys are script errors.
    // The message is the already-computed digest and is not hashed again.
    bool VerifyP256Ecdsa(std::span<const uint8_t> key,
                         std::span<const uint8_t> signature,
                         std::span<const uint8_t> message) {
        if (key.size() != 33 || (key[0] != 0x02 && key[0] != 0x03))
            throw VmFailure("CHECKDATASIG P-256 key encoding");
        if (!signature.empty() && signature.size() != 64)
            throw VmFailure("CHECKDATASIG signature width");
        char group[] = "prime256v1";
        VmBytes point(key.begin(), key.end());
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, group,
                                             0),
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                              point.data(), point.size()),
            OSSL_PARAM_construct_end()};
        PkeyCtxPtr import(
            VM_TEST_CRYPTO_FAIL(P256Context)
                ? nullptr
                : EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
        EVP_PKEY *raw = nullptr;
        if (!import || EVP_PKEY_fromdata_init(import.get()) != 1)
            throw VmFailure("CHECKDATASIG P-256 provider unavailable",
                            VmStatus::OperationalError);
        // Import failure does not prove malformed key: providers may fail for
        // local reasons. Keep rejection conservative until independently known.
        if (EVP_PKEY_fromdata(import.get(), &raw, EVP_PKEY_PUBLIC_KEY,
                              params) != 1)
            throw VmFailure("CHECKDATASIG P-256 key import failed",
                            VmStatus::OperationalError);
        PkeyPtr pkey(raw);
        PkeyCtxPtr check(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(),
                                                    nullptr));
        if (!check)
            throw VmFailure("CHECKDATASIG P-256 check unavailable",
                            VmStatus::OperationalError);
        const int key_check = EVP_PKEY_public_check(check.get());
        if (key_check < 0)
            throw VmFailure("CHECKDATASIG P-256 check failed",
                            VmStatus::OperationalError);
        if (key_check == 0) throw VmFailure("CHECKDATASIG P-256 key encoding");
        if (signature.empty()) return false;
        if (!StrictLowSRange(signature, P256_ORDER, P256_HALF_ORDER))
            return false;
        VmBytes der{0x30, 0};
        DerInteger(der, signature.data());
        DerInteger(der, signature.data() + 32);
        der[1] = uint8_t(der.size() - 2);
        PkeyCtxPtr verify(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(),
                                                     nullptr));
        if (!verify || EVP_PKEY_verify_init(verify.get()) != 1)
            throw VmFailure("CHECKDATASIG P-256 verifier unavailable",
                            VmStatus::OperationalError);
        const int verified =
            VM_TEST_CRYPTO_FAIL(P256Verify)
                ? -1
                : EVP_PKEY_verify(verify.get(), der.data(), der.size(),
                                  message.data(), message.size());
        if (verified < 0)
            throw VmFailure("CHECKDATASIG P-256 verification failed",
                            VmStatus::OperationalError);
        return verified == 1;
    }
    // Profile 3: SEC1-compressed secp256k1 key, strict low-S r||s.
    bool VerifySecp256k1Ecdsa(std::span<const uint8_t> key,
                              std::span<const uint8_t> signature,
                              std::span<const uint8_t> message) {
        secp256k1_pubkey parsed;
        if (key.size() != 33 || (key[0] != 0x02 && key[0] != 0x03) ||
            !secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed,
                                       key.data(), key.size()))
            throw VmFailure("CHECKDATASIG secp256k1 key encoding");
        if (signature.empty()) return false;
        if (signature.size() != 64)
            throw VmFailure("CHECKDATASIG signature width");
        if (!StrictLowSRange(signature, SECP256K1_ORDER, SECP256K1_HALF_ORDER))
            return false;
        secp256k1_ecdsa_signature sig;
        if (!secp256k1_ecdsa_signature_parse_compact(secp256k1_context_static,
                                                     &sig, signature.data()))
            return false;
        return secp256k1_ecdsa_verify(secp256k1_context_static, &sig,
                                      message.data(), &parsed) == 1;
    }
    // Profile 0: BIP340 over the exact 32 message bytes.
    bool VerifyDataBip340(std::span<const uint8_t> key,
                          std::span<const uint8_t> signature,
                          std::span<const uint8_t> message,
                          BatchSigCollector *batch_sigs) {
        secp256k1_xonly_pubkey parsed;
        if (key.size() != 32 ||
            !secp256k1_xonly_pubkey_parse(secp256k1_context_static, &parsed,
                                          key.data()))
            throw VmFailure("CHECKDATASIG x-only key encoding");
        if (signature.empty()) return false;
        if (signature.size() != 64)
            throw VmFailure("CHECKDATASIG signature width");
        if (batch_sigs) {
            Hash msg_hash{};
            std::copy_n(message.begin(), 32, msg_hash.begin());
            if (!batch_sigs->Add(key, signature, msg_hash))
                throw VmFailure("CHECKDATASIG x-only key encoding");
            return true;
        }
        return secp256k1_schnorrsig_verify(secp256k1_context_static,
                                           signature.data(), message.data(),
                                           message.size(), &parsed) == 1;
    }

    // Profile 2: strict prime-subgroup Ed25519. This is not a library's
    // default (cofactored) verifier. Points use RFC 8032 canonical decoding;
    // S must be < L; A and R must be non-identity and satisfy [L]P = identity;
    // the accepted equation is the uncofactored [S]B = R + [h]A with
    // h = SHA512(R || A || message).
    struct EdBn {
        BIGNUM *n;
        EdBn() : n(VM_TEST_CRYPTO_FAIL(EdAllocation) ? nullptr : BN_new()) {
            if (!n)
                throw VmFailure("CHECKDATASIG Ed25519 arithmetic",
                                VmStatus::OperationalError);
        }
        explicit EdBn(BIGNUM *owned) : n(owned) {
            if (!n)
                throw VmFailure("CHECKDATASIG Ed25519 arithmetic",
                                VmStatus::OperationalError);
        }
        ~EdBn() { BN_free(n); }
        EdBn(const EdBn &) = delete;
        EdBn &operator=(const EdBn &) = delete;
        EdBn(EdBn &&other) noexcept : n(other.n) { other.n = nullptr; }
        EdBn &operator=(EdBn &&other) noexcept {
            if (this != &other) {
                BN_free(n);
                n = other.n;
                other.n = nullptr;
            }
            return *this;
        }
    };
    struct EdPoint {
        EdBn x, y, z, t;
    };
    struct Ed25519 {
        BN_CTX *ctx;
        EdBn p, l, d, d2, i, exp, bx, by;
        explicit Ed25519()
            : ctx(BN_CTX_new()), p(Hex("7fffffffffffffffffffffffffffffff"
                                       "ffffffffffffffffffffffffffffffed")),
              l(Hex("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")),
              d(Hex("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3")),
              d2(),
              i(Hex("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0")),
              exp(Hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe")),
              bx(Hex("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a")),
              by(Hex("6666666666666666666666666666666666666666666666666666666666666658")) {
            if (!ctx)
                throw VmFailure("CHECKDATASIG Ed25519 arithmetic",
                                VmStatus::OperationalError);
            Require(BN_mod_add(d2.n, d.n, d.n, p.n, ctx) == 1);
        }
        ~Ed25519() { BN_CTX_free(ctx); }
        Ed25519(const Ed25519 &) = delete;
        Ed25519 &operator=(const Ed25519 &) = delete;
        static EdBn Hex(const char *digits) {
            BIGNUM *value = nullptr;
            if (BN_hex2bn(&value, digits) <= 0)
                throw VmFailure("CHECKDATASIG Ed25519 arithmetic",
                                VmStatus::OperationalError);
            return EdBn(value);
        }
        void Require(bool ok) const {
            if (!ok)
                throw VmFailure("CHECKDATASIG Ed25519 arithmetic",
                                VmStatus::OperationalError);
        }
        EdBn Mod(const BIGNUM *a, const BIGNUM *b) {
            EdBn out;
            Require(BN_mod_mul(out.n, a, b, p.n, ctx) == 1);
            return out;
        }
        EdBn Add(const BIGNUM *a, const BIGNUM *b) {
            EdBn out;
            Require(BN_mod_add(out.n, a, b, p.n, ctx) == 1);
            return out;
        }
        EdBn Sub(const BIGNUM *a, const BIGNUM *b) {
            EdBn out;
            Require(BN_mod_sub(out.n, a, b, p.n, ctx) == 1);
            return out;
        }
        EdBn Inv(const BIGNUM *a) {
            EdBn out;
            if (!BN_mod_inverse(out.n, a, p.n, ctx))
                throw VmFailure("CHECKDATASIG Ed25519 arithmetic",
                                VmStatus::OperationalError);
            return out;
        }
        // RFC 8032 square root of u/v for p ≡ 5 (mod 8); nullopt-as-false.
        bool SqrtRatio(const BIGNUM *u, const BIGNUM *v, EdBn &root) {
            EdBn ratio = Mod(u, Inv(v).n);
            Require(BN_mod_exp(root.n, ratio.n, exp.n, p.n, ctx) == 1);
            EdBn vx2 = Mod(v, Mod(root.n, root.n).n);
            if (BN_cmp(vx2.n, u) == 0) return true;
            EdBn neg;
            Require(BN_mod_sub(neg.n, p.n, u, p.n, ctx) == 1);
            if (BN_cmp(vx2.n, neg.n) != 0) return false;
            EdBn adjusted = Mod(root.n, i.n);
            Require(BN_copy(root.n, adjusted.n) != nullptr);
            return true;
        }
        bool Decode(std::span<const uint8_t> bytes, EdPoint &out) {
            if (!BN_lebin2bn(bytes.data(), int(bytes.size()), out.y.n))
                throw VmFailure("CHECKDATASIG Ed25519 arithmetic",
                                VmStatus::OperationalError);
            const int sign = BN_is_bit_set(out.y.n, 255);
            if (sign) BN_clear_bit(out.y.n, 255);
            if (BN_cmp(out.y.n, p.n) >= 0) return false;
            EdBn y2 = Mod(out.y.n, out.y.n);
            EdBn one;
            Require(BN_one(one.n) == 1);
            EdBn u = Sub(y2.n, one.n);
            EdBn v = Add(Mod(d.n, y2.n).n, one.n);
            if (!SqrtRatio(u.n, v.n, out.x)) return false;
            if (BN_is_zero(out.x.n) && sign) return false;
            if (BN_is_odd(out.x.n) != sign) {
                Require(BN_mod_sub(out.x.n, p.n, out.x.n, p.n, ctx) == 1);
            }
            Require(BN_one(out.z.n) == 1);
            out.t = Mod(out.x.n, out.y.n);
            return true;
        }
        EdPoint Identity() {
            EdPoint id;
            BN_zero(id.x.n);
            Require(BN_one(id.y.n) == 1 && BN_one(id.z.n) == 1);
            BN_zero(id.t.n);
            return id;
        }
        bool IsIdentity(const EdPoint &point) {
            return BN_is_zero(point.x.n) && BN_cmp(point.y.n, point.z.n) == 0;
        }
        bool Equal(const EdPoint &a, const EdPoint &b) {
            EdBn ax_bz = Mod(a.x.n, b.z.n);
            EdBn bx_az = Mod(b.x.n, a.z.n);
            if (BN_cmp(ax_bz.n, bx_az.n) != 0) return false;
            EdBn ay_bz = Mod(a.y.n, b.z.n);
            EdBn by_az = Mod(b.y.n, a.z.n);
            return BN_cmp(ay_bz.n, by_az.n) == 0;
        }
        // RFC 8032 §5.1.4 complete extended twisted Edwards addition.
        EdPoint Combine(const EdPoint &p1, const EdPoint &p2) {
            EdBn a = Mod(Sub(p1.y.n, p1.x.n).n, Sub(p2.y.n, p2.x.n).n);
            EdBn b = Mod(Add(p1.y.n, p1.x.n).n, Add(p2.y.n, p2.x.n).n);
            EdBn c = Mod(Mod(p1.t.n, d2.n).n, p2.t.n);
            EdBn z1z2 = Mod(p1.z.n, p2.z.n);
            EdBn d_val = Add(z1z2.n, z1z2.n);
            EdBn e = Sub(b.n, a.n);
            EdBn f = Sub(d_val.n, c.n);
            EdBn g = Add(d_val.n, c.n);
            EdBn h = Add(b.n, a.n);
            EdPoint out;
            out.x = Mod(e.n, f.n);
            out.y = Mod(g.n, h.n);
            out.t = Mod(e.n, h.n);
            out.z = Mod(f.n, g.n);
            return out;
        }
        EdPoint Scale(const BIGNUM *scalar, const EdPoint &base) {
            EdPoint result = Identity();
            EdPoint acc;
            Require(BN_copy(acc.x.n, base.x.n) && BN_copy(acc.y.n, base.y.n) &&
                    BN_copy(acc.z.n, base.z.n) && BN_copy(acc.t.n, base.t.n));
            for (int bit = 0, nbits = BN_num_bits(scalar); bit < nbits; ++bit) {
                if (BN_is_bit_set(scalar, bit)) result = Combine(result, acc);
                acc = Combine(acc, acc);
            }
            return result;
        }
        bool InPrimeSubgroup(const EdPoint &point) {
            if (IsIdentity(point)) return false;
            return IsIdentity(Scale(l.n, point));
        }
    };
    bool VerifyEd25519(std::span<const uint8_t> key,
                       std::span<const uint8_t> signature,
                       std::span<const uint8_t> message) {
        if (key.size() != 32)
            throw VmFailure("CHECKDATASIG Ed25519 key encoding");
        if (!signature.empty() && signature.size() != 64)
            throw VmFailure("CHECKDATASIG signature width");
        Ed25519 curve;
        EdPoint public_key, commitment;
        if (!curve.Decode(key, public_key))
            throw VmFailure("CHECKDATASIG Ed25519 key encoding");
        if (signature.empty()) return false;
        // A canonical signature whose point, scalar, subgroup or equation
        // check fails triggers NULLFAIL in caller.
        if (!curve.Decode(std::span(signature.data(), 32), commitment))
            return false;
        EdBn scalar;
        if (!BN_lebin2bn(signature.data() + 32, 32, scalar.n))
            throw VmFailure("CHECKDATASIG Ed25519 arithmetic",
                            VmStatus::OperationalError);
        if (BN_cmp(scalar.n, curve.l.n) >= 0 ||
            !curve.InPrimeSubgroup(public_key) ||
            !curve.InPrimeSubgroup(commitment))
            return false;
        std::array<uint8_t, 64> digest{};
        unsigned int len = 0;
        std::array<uint8_t, 96> preimage{};
        std::copy_n(signature.begin(), 32, preimage.begin());
        std::copy_n(key.begin(), 32, preimage.begin() + 32);
        std::copy(message.begin(), message.end(), preimage.begin() + 64);
        if (VM_TEST_CRYPTO_FAIL(Digest) ||
            !EVP_Digest(preimage.data(), preimage.size(), digest.data(), &len,
                        EVP_sha512(), nullptr) ||
            len != 64)
            throw VmFailure("CHECKDATASIG Ed25519 arithmetic",
                            VmStatus::OperationalError);
        EdBn challenge;
        if (!BN_lebin2bn(digest.data(), 64, challenge.n) ||
            BN_mod(challenge.n, challenge.n, curve.l.n, curve.ctx) != 1)
            throw VmFailure("CHECKDATASIG Ed25519 arithmetic",
                            VmStatus::OperationalError);
        EdPoint base;
        if (!BN_copy(base.x.n, curve.bx.n) || !BN_copy(base.y.n, curve.by.n) ||
            BN_one(base.z.n) != 1)
            throw VmFailure("CHECKDATASIG Ed25519 arithmetic",
                            VmStatus::OperationalError);
        base.t = curve.Mod(base.x.n, base.y.n);
        EdPoint left = curve.Scale(scalar.n, base);
        EdPoint right =
            curve.Combine(commitment, curve.Scale(challenge.n, public_key));
        return curve.Equal(left, right);
    }

#include "vm_cost.inc"

    class Machine {
        const std::vector<Instruction> &code;
        const VmProfile &profile;
        const VmCostProfile &cost_profile;
        uint16_t input_count;
        uint16_t output_count;
        const VmExecutionContext *context;
        const PreparedSigningContext *prepared_signing;
        BatchSigCollector *batch_sigs;
        std::span<const uint8_t> active_script;
        std::optional<Hash> cached_txid;
        std::optional<VmAssetTotalsMap> local_asset_totals;
        size_t mint_count;
        std::vector<VmBytes> stack;
        std::vector<VmBytes> alternate;
        size_t bytes = 0;
        size_t steps = 0;
        VmCostUnits executed_cost = 0;
        bool tracking_step = false;
        std::vector<size_t> step_operands;
        std::vector<size_t> step_results;

        void Charge(VmCostUnits delta) {
            executed_cost = RawAdd(executed_cost, delta);
        }
        VmCostUnits MerkleStepCost(Int selector) const {
            const std::array<size_t, 1> tagged{96}, pair{64};
            const std::array<size_t, 1> digest{32};
            const std::array<VmCostUnits, 4> cost{
                OpCost(0xba, tagged, digest, cost_profile, false),
                OpCost(0xba, pair, digest, cost_profile, false),
                OpCost(0xb8, pair, digest, cost_profile, false),
                OpCost(0xb9, pair, digest, cost_profile, false)};
            if (selector >= 0 && selector <= 3) return cost[size_t(selector)];
            return *std::max_element(cost.begin(), cost.end());
        }

        VmBytes Pop() {
            if (stack.empty()) throw VmFailure("stack underflow");
            VmBytes value = std::move(stack.back());
            bytes -= value.size();
            stack.pop_back();
            if (tracking_step) step_operands.push_back(value.size());
            return value;
        }
        void Push(VmBytes value, bool to_alt = false) {
            auto &target = to_alt ? alternate : stack;
            const size_t cap =
                to_alt ? profile.max_altstack_items : profile.max_stack_items;
            if (value.size() > profile.max_element_bytes ||
                target.size() >= cap ||
                value.size() > profile.max_vm_bytes - bytes)
                throw VmFailure("stack bound exceeded");
            if (tracking_step && !to_alt) step_results.push_back(value.size());
            bytes += value.size();
            target.push_back(std::move(value));
        }
        void Require(size_t n) const {
            if (stack.size() < n) throw VmFailure("stack underflow");
        }
        void Tick() {
            if (++steps > profile.max_steps)
                throw VmFailure("step bound exceeded",
                                VmStatus::OperationalError);
        }
        size_t Index(Int value, size_t bound) const {
            if (value < 0 || value >= Int(bound))
                throw VmFailure("introspection index out of range");
            return size_t(value);
        }
        const VmExecutionContext &Context() const {
            if (!context)
                throw VmFailure("introspection needs authenticated context",
                                true);
            return *context;
        }
        const Output &CoinAt(Int index) const {
            const auto &ctx = Context();
            const size_t i = Index(index, ctx.tx.inputs.size());
            if (ctx.tx.inputs[i].flags != 1 || !ctx.resolved[i])
                throw VmFailure("UTXO read at nonspend input");
            return *ctx.resolved[i];
        }
        const Input &InputAt(Int index) const {
            const auto &tx = Context().tx;
            return tx.inputs[Index(index, tx.inputs.size())];
        }
        const Output &OutputAt(Int index) const {
            const auto &ctx = Context();
            return ctx.tx.outputs[Index(index, ctx.tx.outputs.size())];
        }
        VmBytes PathBytes(const std::vector<uint8_t> &path) const {
            if (path.size() > MAX_OUTPUT_BRANCHES)
                throw VmFailure("path width");
            VmBytes encoded{uint8_t(path.size())};
            encoded.insert(encoded.end(), path.begin(), path.end());
            return encoded;
        }
        VmBytes OutputBytes(const Output &output) const {
            VmBytes encoded;
            std::string error;
            if (!EncodeOutput(output, encoded, error))
                throw VmFailure("output encoding unavailable",
                                VmStatus::OperationalError);
            return encoded;
        }
        bool ExclusiveBranch(const Output &output, const VmBytes &root) const {
            if (!RequiresBranch(output, root)) return false;
            for (const auto &path : output.paths)
                if (path.size() == 1 &&
                    std::equal(root.begin(), root.end(),
                               output.branches[path.front()].begin()))
                    return true;
            return false;
        }
        bool ContinuesBranch(const Output &output, const VmBytes &new_root) const {
            const auto &ctx = Context();
            if (ctx.tx.inputs[ctx.input_index].flags != 1)
                throw VmFailure("continuation requires spend");
            if (new_root.size() != 32)
                throw VmFailure("continuation root width");
            if (output.IsBurn()) return false;
            const auto &coin = *ctx.resolved[ctx.input_index];
            const auto &input = ctx.tx.inputs[ctx.input_index];
            const size_t branch_index =
                coin.paths[input.path_index][ctx.witness_index];
            if (output.paths != coin.paths ||
                output.branches.size() != coin.branches.size())
                return false;
            for (size_t i = 0; i < coin.branches.size(); ++i) {
                if (i == branch_index) {
                    if (!std::equal(new_root.begin(), new_root.end(),
                                    output.branches[i].begin()))
                        return false;
                } else if (output.branches[i] != coin.branches[i]) {
                    return false;
                }
            }
            return true;
        }
        bool RequiresBranch(const Output &output, const VmBytes &root) const {
            if (root.size() != 32 || output.IsBurn() || output.paths.empty())
                return false;
            for (const auto &path : output.paths) {
                bool found = false;
                for (const auto branch_index : path) {
                    if (branch_index < output.branches.size() &&
                        std::equal(root.begin(), root.end(),
                                   output.branches[branch_index].begin()))
                        found = true;
                }
                if (!found) return false;
            }
            return true;
        }
        // 0=continue; positive value exits that many active loops.
        unsigned Execute(size_t begin, size_t end, unsigned active_loops) {
            for (size_t i = begin; i < end; ++i) {
                Tick();
                const auto &ins = code[i];
                const VmOpcode op = ins.op;
                if (op == 0x61 || op == 0x62) {
                    VmBytes cond_bytes = Pop();
                    const std::array<size_t, 1> cond_op{cond_bytes.size()};
                    Charge(OpCost(op, cond_op, {}, cost_profile, false));
                    if (ins.peer != ins.end) {
                        Charge(OpCost(0x63, {}, {}, cost_profile, false));
                    }
                    Charge(OpCost(0x64, {}, {}, cost_profile, false));
                    bool condition = Boolean(cond_bytes);
                    if (op == 0x62) condition = !condition;
                    size_t branch_begin = condition ? i + 1 : ins.peer + 1;
                    size_t branch_end = condition ? ins.peer : ins.end;
                    unsigned signal =
                        Execute(branch_begin, branch_end, active_loops);
                    if (signal) return signal;
                    i = ins.end;
                    continue;
                }
                if (op == 0x69) {
                    VmBytes bound_bytes = Pop();
                    const Int bound = Numeric(bound_bytes);
                    if (bound < 0 || bound > 256)
                        throw VmFailure("loop bound");
                    const std::array<size_t, 1> loop_op{bound_bytes.size()};
                    Charge(OpCost(op, loop_op, {}, cost_profile, false));
                    for (size_t index = 0; index < size_t(bound); ++index) {
                        Tick();
                        Push(Number(index));
                        Charge(OpCost(0x6a, {}, {}, cost_profile, false));
                        unsigned signal =
                            Execute(i + 1, ins.peer, active_loops + 1);
                        if (signal) {
                            if (signal > 1) return signal - 1;
                            break;
                        }
                    }
                    i = ins.peer;
                    continue;
                }
                step_operands.clear();
                step_results.clear();
                tracking_step = true;
                if (op >= 1 && op <= 0x4c) {
                    Push(ins.data);
                    tracking_step = false;
                    Charge(OpCost(op, step_operands, step_results, cost_profile,
                                  false));
                    continue;
                }
                if (op == 0) {
                    Push(Number(0));
                    tracking_step = false;
                    Charge(OpCost(op, step_operands, step_results, cost_profile,
                                  false));
                    continue;
                }
                if (op >= 0x4d && op <= 0x5d) {
                    Push(Number(op == 0x4d ? -1 : op - 0x4d));
                    tracking_step = false;
                    Charge(OpCost(op, step_operands, step_results, cost_profile,
                                  false));
                    continue;
                }
                switch (op) {
                    case 0x60:
                        break;
                    case 0x65:
                        if (!Boolean(Pop())) throw VmFailure("VERIFY false");
                        break;
                    case 0x66:
                        throw VmFailure("RETURN");
                    case 0x6b: {
                        // Boolean(cond) N(depth) BREAK: both operands are
                        // always popped and the depth is validated before
                        // the condition is acted on. N(1) exits `depth`
                        // loops; N(0) continues.
                        const Int depth = Numeric(Pop());
                        const VmBytes cond_bytes = Pop();
                        if (depth < 1 || depth > active_loops)
                            throw VmFailure("BREAK depth");
                        if (!Boolean(cond_bytes)) break;
                        tracking_step = false;
                        Charge(OpCost(op, step_operands, step_results,
                                      cost_profile, false));
                        return unsigned(depth);
                    }
                    case 0x70:
                        Push(Pop(), true);
                        break;
                    case 0x71: {
                        if (alternate.empty())
                            throw VmFailure("alternate underflow");
                        VmBytes value = std::move(alternate.back());
                        bytes -= value.size();
                        alternate.pop_back();
                        step_operands.push_back(value.size());
                        Push(std::move(value));
                        break;
                    }
                    case 0x72:
                        Require(2);
                        Pop();
                        Pop();
                        break;
                    case 0x73: {
                        Require(2);
                        auto a = stack[stack.size() - 2];
                        auto b = stack.back();
                        Push(std::move(a));
                        Push(std::move(b));
                        break;
                    }
                    case 0x74: {
                        Require(3);
                        auto a = stack[stack.size() - 3];
                        auto b = stack[stack.size() - 2];
                        auto c = stack.back();
                        Push(std::move(a));
                        Push(std::move(b));
                        Push(std::move(c));
                        break;
                    }
                    case 0x75: {
                        Require(4);
                        auto a = stack[stack.size() - 4];
                        auto b = stack[stack.size() - 3];
                        Push(std::move(a));
                        Push(std::move(b));
                        break;
                    }
                    case 0x76:
                        Require(6);
                        for (auto it = stack.end() - 6; it != stack.end(); ++it)
                            step_operands.push_back(it->size());
                        std::rotate(stack.end() - 6, stack.end() - 4,
                                    stack.end());
                        break;
                    case 0x77:
                        Require(4);
                        for (auto it = stack.end() - 4; it != stack.end(); ++it)
                            step_operands.push_back(it->size());
                        std::rotate(stack.end() - 4, stack.end() - 2,
                                    stack.end());
                        break;
                    case 0x78:
                        Push(Number(stack.size()));
                        break;
                    case 0x79:
                        Pop();
                        break;
                    case 0x7a:
                        Require(1);
                        step_operands.push_back(stack.back().size());
                        Push(stack.back());
                        break;
                    case 0x7b: {
                        Require(2);
                        auto top = Pop();
                        Pop();
                        Push(std::move(top));
                        step_operands.erase(step_operands.begin());
                        step_results.pop_back();
                        break;
                    }
                    case 0x7c:
                        Require(2);
                        step_operands.push_back(stack[stack.size() - 2].size());
                        Push(stack[stack.size() - 2]);
                        break;
                    case 0x7d: {
                        const Int index = Numeric(Pop());
                        if (index < 0 || index >= Int(stack.size()))
                            throw VmFailure("PICK index");
                        const auto &picked =
                            stack[stack.size() - 1 - size_t(index)];
                        step_operands.push_back(picked.size());
                        Push(picked);
                        break;
                    }
                    case 0x7e: {
                        const Int index = Numeric(Pop());
                        if (index < 0 || index >= Int(stack.size()))
                            throw VmFailure("ROLL index");
                        auto item = stack.end() - 1 - size_t(index);
                        step_operands.push_back(item->size());
                        if (i > begin && LiteralValue(&code[i - 1])) {
                            step_results.push_back(item->size());
                        }
                        std::rotate(item, item + 1, stack.end());
                        break;
                    }
                    case 0x7f:
                        Require(3);
                        for (auto it = stack.end() - 3; it != stack.end(); ++it)
                            step_operands.push_back(it->size());
                        std::rotate(stack.end() - 3, stack.end() - 2,
                                    stack.end());
                        break;
                    case 0x80:
                        Require(2);
                        step_operands.push_back(stack[stack.size() - 2].size());
                        step_operands.push_back(stack[stack.size() - 1].size());
                        std::swap(stack[stack.size() - 1],
                                  stack[stack.size() - 2]);
                        break;
                    case 0x81: {
                        Require(2);
                        step_operands.push_back(stack[stack.size() - 2].size());
                        step_operands.push_back(stack[stack.size() - 1].size());
                        auto top = stack.back();
                        std::swap(stack[stack.size() - 1],
                                  stack[stack.size() - 2]);
                        Push(std::move(top));
                        break;
                    }
                    case 0x88: {
                        auto b = Pop(), a = Pop();
                        if (a.size() > profile.max_element_bytes - b.size())
                            throw VmFailure("CAT element bound");
                        a.insert(a.end(), b.begin(), b.end());
                        Push(std::move(a));
                        break;
                    }
                    case 0x89: {
                        const Int offset = Numeric(Pop());
                        auto value = Pop();
                        if (offset < 0 || offset > Int(value.size()))
                            throw VmFailure("SPLIT index");
                        const size_t position = size_t(offset);
                        VmBytes right(value.begin() + position, value.end());
                        value.resize(position);
                        Push(std::move(value));
                        Push(std::move(right));
                        break;
                    }
                    case 0x8a: {
                        const Int width = Numeric(Pop());
                        const BigInt value = NumericBig(Pop());
                        if (width < 0 || width > Int(profile.max_element_bytes))
                            throw VmFailure("NUM2BIN width");
                        Push(value.ToSignedBytes(size_t(width), "NUM2BIN overflow"));
                        break;
                    }
                    case 0x8b: {
                        auto encoded = Pop();
                        if (encoded.size() > VM_MAX_NUMERIC_BYTES)
                            throw VmFailure("BIN2NUM width");
                        const BigInt value = BigInt::FromSignedBytes(encoded);
                        const size_t out_width =
                            std::max<size_t>(VM_MIN_NUMERIC_BYTES, value.MinimalSignedWidth());
                        Push(value.ToSignedBytes(out_width));
                        break;
                    }
                    case 0x8c:
                        Require(1);
                        step_operands.push_back(stack.back().size());
                        Push(Number(stack.back().size()));
                        break;
                    case 0x8d: {
                        auto value = Pop();
                        SimdInvertInPlace(value.data(), value.size());
                        Push(std::move(value));
                        break;
                    }
                    case 0x8e:
                    case 0x8f:
                    case 0x90: {
                        auto b = Pop(), a = Pop();
                        Push(SimdBitwiseBinOp(uint8_t(op), a, b));
                        break;
                    }
                    case 0x91:
                    case 0x92: {
                        auto b = Pop(), a = Pop();
                        Push(Number(a == b));
                        if (op == 0x92) {
                            if (!Boolean(Pop()))
                                throw VmFailure("EQUALVERIFY false");
                            step_operands.pop_back();
                            step_results.pop_back();
                        }
                        break;
                    }
                    case 0x93: {
                        auto b = Pop(), a = Pop();
                        bool a_smaller = a.size() < b.size();
                        for (size_t j = std::max(a.size(), b.size()); j > 0; --j) {
                            const uint8_t ab = j <= a.size() ? a[j - 1] : 0;
                            const uint8_t bb = j <= b.size() ? b[j - 1] : 0;
                            if (ab != bb) {
                                a_smaller = ab < bb;
                                break;
                            }
                        }
                        if (a_smaller) {
                            Push(std::move(a));
                            Push(std::move(b));
                        } else {
                            Push(std::move(b));
                            Push(std::move(a));
                        }
                        break;
                    }
                    case 0x94: {
                        const Int shift = Numeric(Pop());
                        auto value = Pop();
                        const Int bits = Int(value.size()) * 8;
                        VmBytes result(value.size());
                        if (shift > -bits && shift < bits) {
                            const size_t distance = size_t(shift < 0 ? -shift : shift);
                            const size_t whole = distance / 8;
                            const unsigned remain = unsigned(distance % 8);
                            for (size_t j = 0; j < value.size(); ++j) {
                                if (shift >= 0) {
                                    if (j < whole) continue;
                                    const size_t source = j - whole;
                                    result[j] = uint8_t(value[source] << remain);
                                    if (remain && source)
                                        result[j] |= uint8_t(value[source - 1] >>
                                                             (8 - remain));
                                } else {
                                    if (whole > value.size() - j - 1) continue;
                                    const size_t source = j + whole;
                                    result[j] = uint8_t(value[source] >> remain);
                                    if (remain && source + 1 < value.size())
                                        result[j] |= uint8_t(value[source + 1] <<
                                                             (8 - remain));
                                }
                            }
                        }
                        Push(std::move(result));
                        break;
                    }
                    case 0x98:
                    case 0x99:
                    case 0x9a:
                    case 0x9b:
                    case 0x9c:
                    case 0x9d: {
                        const auto raw_a = Pop();
                        if (op == 0x9c) {
                            const bool b = Boolean(raw_a);
                            Push(Number(!b));
                            break;
                        }
                        const BigInt a = NumericBig(raw_a);
                        if (op == 0x9d) {
                            Push(Number(!a.IsZero()));
                            break;
                        }
                        const size_t width = raw_a.size();
                        BigInt out;
                        if (op == 0x98) out = AddBig(a, BigInt::FromInt(1));
                        if (op == 0x99) out = SubBig(a, BigInt::FromInt(1));
                        if (op == 0x9a) out = NegBig(a);
                        if (op == 0x9b) out = a.neg ? NegBig(a) : a;
                        Push(out.ToSignedBytes(width));
                        break;
                    }
                    case 0x9e:
                    case 0x9f:
                    case 0xa0:
                    case 0xa1:
                    case 0xa2:
                    case 0xa3:
                    case 0xa4:
                    case 0xa5:
                    case 0xa6:
                    case 0xa7:
                    case 0xa8:
                    case 0xa9:
                    case 0xaa:
                    case 0xab:
                    case 0xac:
                    case 0xad:
                    case 0xae: {
                        const auto raw_b = Pop(), raw_a = Pop();
                        if (op == 0xa0 || op == 0xa1 || op == 0xa2) {
                            const size_t limbs_a = std::max<size_t>(
                                1, (std::min<size_t>(raw_a.size(),
                                                     VM_MAX_NUMERIC_BYTES) +
                                    15) /
                                       16);
                            const size_t limbs_b = std::max<size_t>(
                                1, (std::min<size_t>(raw_b.size(),
                                                     VM_MAX_NUMERIC_BYTES) +
                                    15) /
                                       16);
                            const size_t quad = limbs_a * limbs_b;
                            if (quad > 1)
                                step_operands.push_back((quad - 1) * 16);
                        }
                        if (op == 0xa4 || op == 0xa5) {
                            const bool b = Boolean(raw_b), a = Boolean(raw_a);
                            Push(Number(op == 0xa4 ? (a && b) : (a || b)));
                            break;
                        }
                        const BigInt b = NumericBig(raw_b), a = NumericBig(raw_a);
                        if (op >= 0xa6 && op <= 0xac) {
                            const int cmp = CompareBig(a, b);
                            bool flag = false;
                            if (op == 0xa6 || op == 0xa7) flag = (cmp == 0);
                            if (op == 0xa8) flag = (cmp != 0);
                            if (op == 0xa9) flag = (cmp < 0);
                            if (op == 0xaa) flag = (cmp > 0);
                            if (op == 0xab) flag = (cmp <= 0);
                            if (op == 0xac) flag = (cmp >= 0);
                            Push(Number(flag));
                            if (op == 0xa7) {
                                if (!Boolean(Pop()))
                                    throw VmFailure("NUMEQUALVERIFY false");
                                step_operands.pop_back();
                                step_results.pop_back();
                            }
                            break;
                        }
                        const size_t width = std::max(raw_a.size(), raw_b.size());
                        if (op == 0x9e) {
                            Push(AddBig(a, b).ToSignedBytes(width));
                            break;
                        }
                        if (op == 0x9f) {
                            Push(SubBig(a, b).ToSignedBytes(width));
                            break;
                        }
                        if (op == 0xa0) {
                            const BigInt prod = MulBig(a, b);
                            const size_t out_width = std::max(width, prod.MinimalSignedWidth());
                            if (out_width > VM_MAX_MUL_BYTES)
                                throw VmFailure("int128 overflow");
                            Push(prod.ToSignedBytes(out_width));
                            break;
                        }
                        if (op == 0xa1 || op == 0xa2) {
                            auto [q, r] = DivModBig(a, b);
                            (void)q.ToSignedBytes(width, "invalid division");
                            Push((op == 0xa1 ? q : r).ToSignedBytes(width, "invalid division"));
                            break;
                        }
                        if (op == 0xa3) {
                            const size_t a_width = raw_a.size();
                            const Int shift = b.ToClampedInt128();
                            const Int max_bits = Int(a_width) * 8;
                            BigInt out;
                            if (shift >= max_bits) {
                                if (!a.IsZero()) throw VmFailure("MULPOW2 overflow");
                            } else if (shift >= 0) {
                                out.neg = a.neg;
                                out.limbs = ShlMag(a.limbs, size_t(shift));
                                out.Normalize();
                            } else if (shift > -max_bits) {
                                out.neg = a.neg;
                                out.limbs = ShrMag(a.limbs, size_t(-shift));
                                out.Normalize();
                            }
                            Push(out.ToSignedBytes(a_width, "MULPOW2 overflow"));
                            break;
                        }
                        if (op == 0xad) {
                            Push((CompareBig(a, b) <= 0 ? a : b).ToSignedBytes(width));
                            break;
                        }
                        if (op == 0xae) {
                            Push((CompareBig(a, b) >= 0 ? a : b).ToSignedBytes(width));
                            break;
                        }
                        break;
                    }
                    case 0xaf: {
                        const BigInt high = NumericBig(Pop());
                        const BigInt low = NumericBig(Pop());
                        const BigInt value = NumericBig(Pop());
                        Push(Number(CompareBig(low, value) <= 0 && CompareBig(value, high) < 0));
                        break;
                    }
                    case 0xb0:
                    case 0xb1: {
                        const UInt carry = CarryInput(Pop());
                        const auto raw_b = Pop(), raw_a = Pop();
                        if (raw_a.size() > VM_MAX_NUMERIC_BYTES ||
                            raw_b.size() > VM_MAX_NUMERIC_BYTES)
                            throw VmFailure("operand is not U");
                        const size_t width = std::max<size_t>(
                            VM_MIN_NUMERIC_BYTES, std::max(raw_a.size(), raw_b.size()));
                        VmBytes out(width, 0);
                        bool flag = false;
                        if (op == 0xb0) {
                            uint16_t c = uint16_t(carry);
                            for (size_t j = 0; j < width; ++j) {
                                const uint16_t aj = j < raw_a.size() ? raw_a[j] : 0;
                                const uint16_t bj = j < raw_b.size() ? raw_b[j] : 0;
                                const uint16_t s = aj + bj + c;
                                out[j] = uint8_t(s & 0xff);
                                c = s >> 8;
                            }
                            flag = (c != 0);
                        } else {
                            int16_t b_in = int16_t(carry);
                            for (size_t j = 0; j < width; ++j) {
                                const int16_t aj = j < raw_a.size() ? raw_a[j] : 0;
                                const int16_t bj = j < raw_b.size() ? raw_b[j] : 0;
                                const int16_t d = aj - bj - b_in;
                                out[j] = uint8_t(d & 0xff);
                                b_in = d < 0 ? 1 : 0;
                            }
                            flag = (b_in != 0);
                        }
                        Push(std::move(out));
                        Push(Number(flag));
                        break;
                    }
                    case 0xb2: {
                        const auto raw_b = Pop(), raw_a = Pop();
                        if (raw_a.size() > VM_MAX_NUMERIC_BYTES ||
                            raw_b.size() > VM_MAX_NUMERIC_BYTES)
                            throw VmFailure("operand is not U");
                        const size_t limbs_a = std::max<size_t>(
                            1, (raw_a.size() + 15) / 16);
                        const size_t limbs_b = std::max<size_t>(
                            1, (raw_b.size() + 15) / 16);
                        const size_t quad = limbs_a * limbs_b;
                        if (quad > 1) step_operands.push_back((quad - 1) * 16);
                        const size_t width = std::max<size_t>(
                            VM_MIN_NUMERIC_BYTES, std::max(raw_a.size(), raw_b.size()));
                        const Mag prod =
                            MulMag(MagFromUnsignedBytes(raw_a), MagFromUnsignedBytes(raw_b));
                        const VmBytes full = MagToUnsignedBytes(prod, 2 * width);
                        VmBytes low(full.begin(), full.begin() + width);
                        VmBytes high(full.begin() + width, full.end());
                        Push(std::move(high));
                        Push(std::move(low));
                        break;
                    }
                    case 0xb3: {
                        const auto raw_a = Pop();
                        const size_t limbs = std::max<size_t>(
                            1, (std::min<size_t>(raw_a.size(),
                                                 VM_MAX_NUMERIC_BYTES) +
                                15) /
                                   16);
                        if (limbs > 1)
                            step_operands.push_back((limbs * limbs - 1) * 16);
                        Push(Number(Log2Q64(NumericBig(raw_a))));
                        break;
                    }
                    case 0xb4: {
                        const auto raw_a = Pop();
                        const size_t limbs = std::max<size_t>(
                            1, (std::min<size_t>(raw_a.size(),
                                                 VM_MAX_NUMERIC_BYTES) +
                                15) /
                                   16);
                        if (limbs > 1)
                            step_operands.push_back((limbs * limbs - 1) * 16);
                        const BigInt root = IntegerSqrt(NumericBig(raw_a));
                        Push(root.ToSignedBytes(raw_a.size()));
                        break;
                    }
                    case 0xbd: {
                        const Int algorithm = Numeric(Pop());
                        const auto key = Pop();
                        const auto message = Pop();
                        const auto signature = Pop();
                        if (algorithm < 0 || algorithm > 3)
                            throw VmFailure("CHECKDATASIG algorithm");
                        if (message.size() != 32)
                            throw VmFailure("CHECKDATASIG message width");
                        const bool valid =
                            algorithm == 0
                                ? VerifyDataBip340(key, signature, message,
                                                   batch_sigs)
                            : algorithm == 1
                                ? VerifyP256Ecdsa(key, signature, message)
                            : algorithm == 2
                                ? VerifyEd25519(key, signature, message)
                                : VerifySecp256k1Ecdsa(key, signature, message);
                        if (!signature.empty() && !valid)
                            throw VmFailure("CHECKDATASIG NULLFAIL");
                        Push(Number(valid));
                        break;
                    }
                    case 0xb8:
                    case 0xb9: {
                        VmBytes digest = Sha256(Pop());
                        if (op == 0xb9) digest = Sha256(digest);
                        Push(std::move(digest));
                        break;
                    }
                    case 0xba:
                        Push(Blake3(Pop()));
                        break;
                    case 0xbe: {
                        VmBytes script = Pop();
                        Hash leaf = BranchLeaf(script);
                        Push(VmBytes(leaf.begin(), leaf.end()));
                        break;
                    }
                    case 0xbf: {
                        auto b = Pop(), a = Pop();
                        if (a.size() != 32 || b.size() != 32)
                            throw VmFailure("NODEHASH width");
                        Hash ah{}, bh{};
                        std::copy(a.begin(), a.end(), ah.begin());
                        std::copy(b.begin(), b.end(), bh.begin());
                        Hash node = BranchNode(ah, bh);
                        Push(VmBytes(node.begin(), node.end()));
                        break;
                    }
                    case 0xc0:
                    case 0xc1: {
                        const Int selected = Numeric(Pop());
                        if (selected < 0 || selected > 3)
                            throw VmFailure("Merkle hash selector");
                        const auto proof = Pop();
                        const bool indexed = op == 0xc1;
                        VmBytes key;
                        if (indexed) key = Pop();
                        const auto leaf = Pop();
                        if (leaf.size() != 32 || proof.size() % 32 ||
                            (!indexed && proof.size() / 32 > 64) ||
                            (indexed && (key.empty() || key.size() > 32 ||
                                         proof.size() / 32 > 8 * key.size())))
                            throw VmFailure("Merkle proof framing");
                        Hash acc{};
                        std::copy(leaf.begin(), leaf.end(), acc.begin());
                        for (size_t layer = 0; layer < proof.size() / 32;
                             ++layer) {
                            Hash sibling{};
                            std::copy_n(proof.begin() + 32 * layer, 32,
                                        sibling.begin());
                            const bool right = indexed
                                ? ((key[layer / 8] >> (layer % 8)) & 1)
                                : LessHashLittleEndian(sibling, acc);
                            const Hash &left = right ? sibling : acc;
                            const Hash &other = right ? acc : sibling;
                            acc = MerkleStep(uint8_t(selected), indexed,
                                             uint16_t(layer), left, other);
                        }
                        Push(VmBytes(acc.begin(), acc.end()));
                        Charge(RawMul(MerkleStepCost(selected),
                                      proof.size() / 32));
                        break;
                    }
                    case 0xc2: {
                        const Int selected = Numeric(Pop());
                        if (selected < 0 || selected > 2)
                            throw VmFailure("SIGHASH mode");
                        const auto &ctx = Context();
                        if ((selected &&
                             ctx.tx.inputs[ctx.input_index].flags == 3) ||
                            (selected == 2 &&
                             ctx.input_index >= ctx.tx.outputs.size()))
                            throw VmFailure("SIGHASH invocation mode");
                        Hash message;
                        std::string error;
                        if (!SigningMessage(*prepared_signing, ctx.input_index,
                                            ctx.witness_index, uint8_t(selected),
                                            ctx.positive_delta, message, error))
                            throw VmFailure("SIGHASH message unavailable",
                                            VmStatus::OperationalError);
                        Push(VmBytes(message.begin(), message.end()));
                        break;
                    }
                    case 0xbb:
                    case 0xbc: {
                        auto key = Pop(), signature = Pop();
                        if (!context)
                            throw VmFailure(
                                "CHECKSIG needs authenticated context", true);
                        if (signature.empty()) {
                            secp256k1_xonly_pubkey parsed;
                            if (key.size() != 32 ||
                                !secp256k1_xonly_pubkey_parse(
                                    secp256k1_context_static, &parsed,
                                    key.data()))
                                throw VmFailure("CHECKSIG wire encoding");
                            if (op == 0xbc)
                                throw VmFailure("CHECKSIGVERIFY false");
                            Push(Number(0));
                            break;
                        }
                        const uint8_t mode =
                            signature.size() == 65 ? signature.back() : 0;
                        const bool mint =
                            context->tx.inputs[context->input_index].flags == 3;
                        if ((signature.size() != 64 &&
                             signature.size() != 65) ||
                            (signature.size() == 65 &&
                             (mode == 0 || mode > 2)) ||
                            (mode && mint) ||
                            (mode == 2 && context->input_index >=
                                              context->tx.outputs.size()))
                            throw VmFailure("CHECKSIG wire encoding");
                        Hash message;
                        std::string error;
                        if (!SigningMessage(*prepared_signing,
                                            context->input_index,
                                            context->witness_index, mode,
                                            context->positive_delta, message,
                                            error))
                            throw VmFailure("CHECKSIG message unavailable",
                                            VmStatus::OperationalError);
                        if (batch_sigs) {
                            if (!batch_sigs->Add(key, signature, message))
                                throw VmFailure("CHECKSIG wire encoding");
                            if (op == 0xbb) Push(Number(1));
                            break;
                        }
                        const auto verified = VerifyBip340Signature(
                            key, signature, message, mint);
                        if (verified == SignatureStatus::InvalidEncoding ||
                            verified == SignatureStatus::InvalidPublicKey)
                            throw VmFailure("CHECKSIG wire encoding");
                        if (verified != SignatureStatus::Valid)
                            throw VmFailure("CHECKSIG NULLFAIL");
                        if (op == 0xbb) Push(Number(1));
                        break;
                    }
                    case 0xc3: { // STATEHASH: item_1..item_k N(k) -> Hash32
                        const Int k = Numeric(Pop());
                        if (k < 0 || k > Int(VM_STATEHASH_MAX_ITEMS))
                            throw VmFailure("STATEHASH item count");
                        Require(size_t(k));
                        std::vector<VmBytes> items(static_cast<size_t>(k));
                        for (size_t i = size_t(k); i-- > 0;) items[i] = Pop();
                        // Charge the CompactSize framing on top of the items.
                        if (tracking_step)
                            step_operands.push_back(
                                StateHashFramingBytes(items));
                        const Hash digest = ContractStateHash(items);
                        Push(VmBytes(digest.begin(), digest.end()));
                        break;
                    }
                    case 0xc8:
                        Context();
                        Push(Number(7));
                        break;
                    case 0xc9:
                        Push(Number(input_count));
                        break;
                    case 0xca:
                        Push(Number(output_count));
                        break;
                    case 0xcb: {
                        Context();
                        Push(Number(mint_count));
                        break;
                    }
                    case 0xcc:
                        Push(Number(Context().tx.lock >> 8));
                        break;
                    case 0xcd:
                        Push(Number(Context().tx.lock & 255));
                        break;
                    case 0xce: {
                        const auto &ctx = Context();
                        (void)ctx;
                        if (!cached_txid)
                            cached_txid = prepared_signing->Identities().txid;
                        Push(VmBytes(cached_txid->begin(), cached_txid->end()));
                        break;
                    }
                    case 0xcf: {
                        const auto &chain = Context().chain_id;
                        Push(VmBytes(chain.begin(), chain.end()));
                        break;
                    }
                    case 0xd0:
                        Push(Number(Context().input_index));
                        break;
                    case 0xd1: {
                        const auto &tx = Context().tx;
                        const size_t i =
                            Index(Numeric(Pop()), tx.inputs.size());
                        Push(Number(tx.inputs[i].flags));
                        break;
                    }
                    case 0xd2: {
                        const auto &input = InputAt(Numeric(Pop()));
                        Push(VmBytes(input.prev_txid.begin(),
                                     input.prev_txid.end()));
                        break;
                    }
                    case 0xd3:
                        Push(Number(InputAt(Numeric(Pop())).prev_index));
                        break;
                    case 0xd4:
                        Push(Number(InputAt(Numeric(Pop())).sequence));
                        break;
                    case 0xd5: {
                        const auto &input = InputAt(Numeric(Pop()));
                        if (input.flags != 1)
                            throw VmFailure("path index at nonspend input");
                        Push(Number(input.path_index));
                        break;
                    }
                    case 0xd6:
                        Push(Number(CoinAt(Numeric(Pop())).value));
                        break;
                    case 0xd7: {
                        const auto &coin = CoinAt(Numeric(Pop()));
                        Push(coin.HasToken() ? VmBytes(coin.token_id.begin(),
                                                       coin.token_id.end())
                                             : VmBytes(32));
                        break;
                    }
                    case 0xd8:
                        Push(Number(CoinAt(Numeric(Pop())).branches.size()));
                        break;
                    case 0xd9: {
                        const Int branch = Numeric(Pop());
                        const auto &coin = CoinAt(Numeric(Pop()));
                        const auto &root =
                            coin.branches[Index(branch, coin.branches.size())];
                        Push(VmBytes(root.begin(), root.end()));
                        break;
                    }
                    case 0xda:
                        Push(Number(CoinAt(Numeric(Pop())).paths.size()));
                        break;
                    case 0xdb: {
                        const Int path = Numeric(Pop());
                        const auto &coin = CoinAt(Numeric(Pop()));
                        Push(PathBytes(
                            coin.paths[Index(path, coin.paths.size())]));
                        break;
                    }
                    case 0xdc:
                        Push(OutputBytes(CoinAt(Numeric(Pop()))));
                        break;
                    case 0xdd: {
                        auto root = Pop();
                        const auto &coin = CoinAt(Numeric(Pop()));
                        Push(Number(RequiresBranch(coin, root)));
                        break;
                    }
                    case 0xdf: { // INPUTWITNESSARG: i w a -> bytes
                        const Int a = Numeric(Pop());
                        const Int w = Numeric(Pop());
                        const auto &input = InputAt(Numeric(Pop()));
                        // Any input's arguments are readable (plan I-12).
                        // A spend has one witness per path slot; a mint has
                        // exactly witness 0; a coinbase has none.
                        if (input.flags == 2)
                            throw VmFailure("witness argument at coinbase input");
                        if (input.flags == 3 && w != 0)
                            throw VmFailure("introspection index out of range");
                        const auto &witness =
                            input.witnesses[Index(w, input.witnesses.size())];
                        Push(witness.arguments[Index(
                            a, witness.arguments.size())]);
                        break;
                    }
                    case 0xde: // UTXOFLAGS
                        Push(Number(CoinAt(Numeric(Pop())).flags));
                        break;
                    case 0xe0:
                        Push(Number(OutputAt(Numeric(Pop())).flags));
                        break;
                    case 0xe1:
                        Push(Number(OutputAt(Numeric(Pop())).value));
                        break;
                    case 0xe2: {
                        const auto &output = OutputAt(Numeric(Pop()));
                        Push(output.HasToken()
                                 ? VmBytes(output.token_id.begin(),
                                           output.token_id.end())
                                 : VmBytes(32));
                        break;
                    }
                    case 0xe3:
                        Push(Number(OutputAt(Numeric(Pop())).branches.size()));
                        break;
                    case 0xe4: {
                        const Int branch = Numeric(Pop());
                        const auto &output = OutputAt(Numeric(Pop()));
                        const auto &root = output.branches[
                            Index(branch, output.branches.size())];
                        Push(VmBytes(root.begin(), root.end()));
                        break;
                    }
                    case 0xe5:
                        Push(Number(OutputAt(Numeric(Pop())).paths.size()));
                        break;
                    case 0xe6: {
                        const Int path = Numeric(Pop());
                        const auto &output = OutputAt(Numeric(Pop()));
                        Push(PathBytes(output.paths[
                            Index(path, output.paths.size())]));
                        break;
                    }
                    case 0xe7:
                        Push(OutputBytes(OutputAt(Numeric(Pop()))));
                        break;
                    case 0xe8: {
                        auto root = Pop();
                        const auto &output = OutputAt(Numeric(Pop()));
                        Push(Number(RequiresBranch(output, root)));
                        break;
                    }
                    case 0xe9: {
                        auto root = Pop();
                        const auto &output = OutputAt(Numeric(Pop()));
                        if (root.size() != 32)
                            throw VmFailure("exclusive root width");
                        Push(Number(ExclusiveBranch(output, root)));
                        break;
                    }
                    case 0xea: {
                        auto root = Pop();
                        const auto &output = OutputAt(Numeric(Pop()));
                        Push(Number(ContinuesBranch(output, root)));
                        break;
                    }
                    case 0xec: { // TXTOKENBALANCE: asset -> N(in) N(out)
                        const VmBytes asset = Pop();
                        const auto &ctx = Context();
                        if (asset.size() != 32)
                            throw VmFailure("token balance asset width");
                        const VmAssetTotalsMap *totals = nullptr;
                        if (ctx.prepared) {
                            totals = &ctx.prepared->AssetTotals();
                        } else {
                            if (!local_asset_totals) {
                                std::string error;
                                local_asset_totals.emplace();
                                if (!ComputeVmAssetTotals(ctx.tx, ctx.resolved,
                                                          *local_asset_totals,
                                                          error))
                                    throw VmFailure("asset sum overflow");
                            }
                            totals = &*local_asset_totals;
                        }
                        Hash32 key;
                        std::copy(asset.begin(), asset.end(), key.begin());
                        const auto found = totals->find(key);
                        const VmAssetTotals value =
                            found == totals->end() ? VmAssetTotals{}
                                                   : found->second;
                        Push(Number(Int(value.inputs)));
                        Push(Number(Int(value.outputs)));
                        break;
                    }
                    case 0xed: { // STATEVERIFY: Hash32 ->
                        const VmBytes root = Pop();
                        const auto &ctx = Context();
                        if (ctx.tx.inputs[ctx.input_index].flags != 1)
                            throw VmFailure("STATEVERIFY requires spend");
                        if (root.size() != 32)
                            throw VmFailure("STATEVERIFY root width");
                        const auto &coin = CoinAt(Int(ctx.input_index));
                        if (!coin.HasState())
                            throw VmFailure("STATEVERIFY coin lacks state");
                        if (!std::equal(root.begin(), root.end(),
                                        coin.state_root.begin()))
                            throw VmFailure("STATEVERIFY mismatch");
                        break;
                    }
                    case 0xee: { // UTXOSTATEROOT: zeros without HAS_STATE
                        const auto &coin = CoinAt(Numeric(Pop()));
                        Push(coin.HasState() ? VmBytes(coin.state_root.begin(),
                                                       coin.state_root.end())
                                             : VmBytes(32));
                        break;
                    }
                    case 0xef: { // OUTPUTSTATEROOT: zeros without HAS_STATE
                        const auto &output = OutputAt(Numeric(Pop()));
                        Push(output.HasState()
                                 ? VmBytes(output.state_root.begin(),
                                           output.state_root.end())
                                 : VmBytes(32));
                        break;
                    }
                    case 0xf0:
                        Context();
                        Push(VmBytes(active_script.begin(), active_script.end()));
                        break;
                    case 0xf1:
                        Push(Number(
                            Context().tx.inputs[Context().input_index].flags));
                        break;
                    case 0xf2: {
                        const auto &ctx = Context();
                        const auto &input = ctx.tx.inputs[ctx.input_index];
                        const Hash &root =
                            input.flags == 3
                                ? input.prev_txid
                                : ctx.resolved[ctx.input_index]->branches
                                      [ctx.resolved[ctx.input_index]
                                           ->paths[input.path_index]
                                                  [ctx.witness_index]];
                        Push(VmBytes(root.begin(), root.end()));
                        break;
                    }
                    case 0xf3: {
                        const Int bound = Numeric(Pop());
                        const Int kind = Numeric(Pop());
                        const uint64_t lock = Context().tx.lock;
                        if ((kind != 1 && kind != 2) || bound < 0 ||
                            bound > Int((uint64_t(1) << 56) - 1) ||
                            uint8_t(lock) != uint8_t(kind) ||
                            (lock >> 8) < uint64_t(bound))
                            throw VmFailure("absolute lock unsatisfied");
                        break;
                    }
                    case 0xf4: {
                        const Int bound = Numeric(Pop());
                        const Int kind = Numeric(Pop());
                        const auto &ctx = Context();
                        const auto &input = ctx.tx.inputs[ctx.input_index];
                        const uint32_t sequence = input.sequence;
                        const bool time_kind = (sequence & (uint32_t(1) << 22)) != 0;
                        if (input.flags != 1 || (kind != 1 && kind != 2) ||
                            bound < 0 || bound > 65535 ||
                            sequence == UINT32_MAX ||
                            time_kind != (kind == 2) ||
                            (sequence & 65535) < uint32_t(bound))
                            throw VmFailure("relative lock unsatisfied");
                        break;
                    }
                    case 0xf5: { // ACTIVEBRANCHINDEX: -1 for a mint
                        const auto &ctx = Context();
                        const auto &input = ctx.tx.inputs[ctx.input_index];
                        if (input.flags == 3) {
                            Push(Number(-1));
                            break;
                        }
                        const auto &coin = CoinAt(Int(ctx.input_index));
                        Push(Number(
                            coin.paths[input.path_index][ctx.witness_index]));
                        break;
                    }
                    case 0xf6: { // ACTIVEWITNESSINDEX: 0 for a mint
                        const auto &ctx = Context();
                        Push(Number(ctx.tx.inputs[ctx.input_index].flags == 3
                                        ? 0
                                        : ctx.witness_index));
                        break;
                    }
                    default:
                        throw VmFailure("assigned opcode not implemented",
                                        true);
                }
                tracking_step = false;
                Charge(OpCost(op, step_operands, step_results, cost_profile,
                              false));
            }
            return 0;
        }

    public:
        Machine(const std::vector<Instruction> &code,
                std::span<const uint8_t> script, const VmProfile &profile,
                const VmCostProfile &cost_profile,
                uint16_t input_count, uint16_t output_count,
                const std::vector<VmBytes> &arguments,
                const VmExecutionContext *context,
                const PreparedSigningContext *prepared_signing,
                BatchSigCollector *batch_sigs)
            : code(code), profile(profile), cost_profile(cost_profile),
              input_count(input_count), output_count(output_count),
              context(context), prepared_signing(prepared_signing),
              batch_sigs(batch_sigs), active_script(script),
              mint_count(context && context->prepared ? context->prepared->MintCount() :
                         context ? std::count_if(
                                       context->tx.inputs.begin(),
                                       context->tx.inputs.end(),
                                       [](const Input &input) {
                                           return input.flags == 3;
                                       })
                                 : 0) {
            for (const auto &arg : arguments)
                Push(arg);
            if (context &&
                context->tx.inputs[context->input_index].flags == 3) {
                UInt delta = 0;
                for (size_t i = 0; i < 16; ++i)
                    delta |= UInt((*context->positive_delta)[i]) << (8 * i);
                if (delta > (UInt(1) << 127) - 1)
                    throw VmFailure("mint delta exceeds N");
                Push(Number(Int(delta)));
            }
        }
        std::vector<VmBytes> Run() {
            if (Execute(0, code.size(), 0))
                throw VmFailure("BREAK escaped top level");
            if (!alternate.empty() || stack.size() != 1 ||
                !Boolean(stack.front()))
                throw VmFailure("unclean final stack");
            return stack;
        }
        VmCostUnits ExecutedCost() const { return executed_cost; }
    };
} // namespace
bool ValidateVmCostProfile(const VmProfile &vm, const VmCostProfile &cost, std::string &error) {
    try {
        if (!vm.max_script_bytes || !vm.max_element_bytes ||
            vm.max_element_bytes > VM_HARD_ELEMENT_BYTES ||
            !vm.max_stack_items || !vm.max_altstack_items || !vm.max_vm_bytes ||
            !vm.max_ast_depth || !vm.max_steps)
            throw VmFailure("invalid explicit VM profile",
                            VmStatus::OperationalError);
        CheckCostProfile(cost, vm);
        error.clear();
        return true;
    } catch (const std::exception &e) {
        error = e.what();
        return false;
    }
}


#ifdef LOTUS_V2_VM_TEST_INSTRUMENTATION
namespace { VmPreparationCounts preparation_counts; }
VmPreparationCounts VmPreparationWorkCounts() { return preparation_counts; }
void SetVmCryptoFault(VmCryptoFault fault) {
    vm_crypto_fault = fault;
}
#define VM_COUNT_PREPARATION(field) (++preparation_counts.field)
#else
#define VM_COUNT_PREPARATION(field) ((void)0)
#endif

bool PreparedVmTransaction::TryGetFieldSizeAt(uint8_t op, size_t idx,
                                              size_t &out_size) const {
    std::string err;
    if (op == 0xe7) {
        if (idx >= tx_.outputs.size()) return false;
        return OutputSerializedSize(tx_.outputs[idx], out_size, err);
    }
    if (op == 0xdc) {
        if (idx >= tx_.inputs.size()) return false;
        if (idx >= coins_.size() || !coins_[idx]) {
            out_size = 0;
            return true;
        }
        return OutputSerializedSize(*coins_[idx], out_size, err);
    }
    if (op == 0xe6) {
        bool found = false;
        size_t best = 0;
        for (const auto &output : tx_.outputs) {
            if (idx < output.paths.size()) {
                found = true;
                best = std::max(best, PathSerializedSize(output.paths[idx]));
            }
        }
        if (!found) return false;
        out_size = best;
        return true;
    }
    if (op == 0xdb) {
        bool found = false;
        size_t best = 0;
        for (size_t i = 0; i < tx_.inputs.size(); ++i) {
            if (i < coins_.size() && coins_[i] &&
                idx < coins_[i]->paths.size()) {
                found = true;
                best =
                    std::max(best, PathSerializedSize(coins_[i]->paths[idx]));
            }
        }
        if (!found) return false;
        out_size = best;
        return true;
    }
    return false;
}

bool AddVmAssetTotal(VmAssetTotalsMap &totals, const Output &output,
                     bool input, std::string &error) {
    auto &entry = totals[output.HasToken() ? output.token_id : Hash32{}];
    __uint128_t &sum = input ? entry.inputs : entry.outputs;
    if (sum > ~__uint128_t{0} - output.value) {
        error = "asset sum overflow";
        return false;
    }
    sum += output.value;
    return true;
}

bool ComputeVmAssetTotals(const Transaction &tx, const ResolvedCoins &resolved,
                          VmAssetTotalsMap &totals, std::string &error) {
    totals.clear();
    for (size_t i = 0; i < tx.inputs.size() && i < resolved.size(); ++i) {
        if (tx.inputs[i].flags != 1 || !resolved[i]) continue;
        if (!AddVmAssetTotal(totals, *resolved[i], true, error)) return false;
    }
    for (const Output &output : tx.outputs)
        if (!AddVmAssetTotal(totals, output, false, error)) return false;
    return true;
}

SigningPreparationStatus PreparedVmTransaction::PrepareChecked(
    const Transaction &tx, const TxProfile &profile, const ChainId &chain,
    const ResolvedCoins &coins, const VmCostProfile &cost, std::string &error,
    const IdentityDigests *precomputed_identities) {
    try {
        ready_ = false;
        tx_ = tx;
        profile_ = profile;
        chain_ = chain;
        coins_ = coins;
        cost_ = cost;
        mint_count_ =
            std::count_if(tx_.inputs.begin(), tx_.inputs.end(),
                          [](const Input &input) { return input.flags == 3; });
        VM_COUNT_PREPARATION(signing);
        const auto signing_status = PrepareSigningContextChecked(
            tx_, profile_, chain_, coins_, signing_, error,
            precomputed_identities);
        if (signing_status != SigningPreparationStatus::Ready)
            return signing_status;
        if (!ComputeVmAssetTotals(tx_, coins_, asset_totals_, error))
            return SigningPreparationStatus::InvalidWitness;
        const auto context = Invocation(0, 0);
        try {
            VM_COUNT_PREPARATION(field_sizes);
            max_field_bound_ = 0;
            field_maxima_.fill(0);
            const VmProfile hard_profile{1, 1, VM_HARD_ELEMENT_BYTES, 1, 1, 1,
                                         1, 1};
            CheckCostProfile(cost_, hard_profile);
            if (cost_.field_sizes.empty()) {
                size_t max_db = 0, max_dc = 0, max_e6 = 0, max_e7 = 0;
                std::string sz_err;
                for (const Output &output : tx_.outputs) {
                    size_t sz = 0;
                    if (!OutputSerializedSize(output, sz, sz_err)) {
                        throw VmFailure("field-size output encoding",
                                        VmStatus::OperationalError);
                    }
                    max_e7 = std::max(max_e7, sz);
                    for (const auto &path : output.paths) {
                        max_e6 = std::max(max_e6, PathSerializedSize(path));
                    }
                }
                for (size_t i = 0; i < tx_.inputs.size(); ++i) {
                    if (i >= coins_.size() || !coins_[i]) continue;
                    const Output &coin = *coins_[i];
                    size_t sz = 0;
                    if (!OutputSerializedSize(coin, sz, sz_err)) {
                        throw VmFailure("field-size output encoding",
                                        VmStatus::OperationalError);
                    }
                    max_dc = std::max(max_dc, sz);
                    for (const auto &path : coin.paths) {
                        max_db = std::max(max_db, PathSerializedSize(path));
                    }
                }
                field_maxima_[0xdb] = max_db;
                field_maxima_[0xdc] = max_dc;
                field_maxima_[0xe6] = max_e6;
                field_maxima_[0xe7] = max_e7;
            } else {
                for (const auto &[op, sizes] : cost_.field_sizes) {
                    (void)op;
                    for (auto size : sizes)
                        max_field_bound_ = std::max(max_field_bound_, size);
                }
                ApplyDerivedFieldSizes(cost_, context);
                for (const auto &[op, sizes] : cost_.field_sizes) {
                    size_t maximum = 0;
                    for (auto size : sizes)
                        maximum = std::max(maximum, size);
                    field_maxima_[op] = maximum;
                }
            }
            // INPUTWITNESSARG (df) can return any witness argument.
            size_t max_argument = 0;
            for (const Input &input : tx_.inputs)
                for (const BranchWitness &witness : input.witnesses)
                    for (const VmBytes &argument : witness.arguments)
                        max_argument = std::max(max_argument, argument.size());
            field_maxima_[0xdf] = max_argument;
        } catch (const VmFailure &failure) {
            error = failure.what();
            return failure.status == VmStatus::Unsupported
                       ? SigningPreparationStatus::Unsupported
                       : SigningPreparationStatus::OperationalError;
        }
        ready_ = true;
        error.clear();
        return SigningPreparationStatus::Ready;
    } catch (const std::exception &exception) {
        error = exception.what();
        return SigningPreparationStatus::OperationalError;
    }
}

bool PreparedVmTransaction::Prepare(
    const Transaction &tx, const TxProfile &profile, const ChainId &chain,
    const ResolvedCoins &coins, const VmCostProfile &cost, std::string &error) {
    return PrepareChecked(tx, profile, chain, coins, cost, error) ==
           SigningPreparationStatus::Ready;
}

VmResult EvaluateVmImpl(std::span<const uint8_t> script,
                        const std::vector<VmBytes> &arguments,
                        const VmProfile &profile, uint16_t input_count,
                        uint16_t output_count,
                        const VmExecutionContext *context,
                        const VmCostProfile *cost_profile,
                        VmCostUnits *charged_cost,
                        BatchSigCollector *batch_sigs) {
    try {
        if (!profile.max_script_bytes || !profile.max_element_bytes ||
            profile.max_element_bytes > VM_HARD_ELEMENT_BYTES ||
            !profile.max_stack_items || !profile.max_altstack_items ||
            !profile.max_vm_bytes || !profile.max_ast_depth ||
            !profile.max_steps)
            throw VmFailure("invalid explicit VM profile",
                            VmStatus::OperationalError);
        if (script.size() > profile.max_script_bytes ||
            arguments.size() > profile.max_arguments)
            throw VmFailure("invocation framing limit");
        size_t bytes = 0;
        for (const auto &arg : arguments) {
            if (arg.size() > profile.max_element_bytes ||
                arg.size() > profile.max_vm_bytes - bytes)
                throw VmFailure("argument byte limit");
            bytes += arg.size();
        }
        if (arguments.size() > profile.max_stack_items)
            throw VmFailure("argument count exceeds stack cap");

        // Copy so a derived size cannot shrink a caller hint, and so the
        // caller's profile is left unchanged. Charging below reads this copy.
        std::optional<VmCostProfile> authenticated_cost;
        if (context && context->prepared && !context->prepared->Owns(*context))
            throw VmFailure("prepared transaction ownership mismatch",
                            VmStatus::OperationalError);
        const bool cached_cost = context && context->prepared &&
            cost_profile == &context->prepared->Cost();
        if (cached_cost) {
            if (context->prepared->MaxFieldBound() > profile.max_element_bytes)
                throw VmFailure("invalid field-size bound",
                                VmStatus::OperationalError);
        } else if (cost_profile) {
            CheckCostProfile(*cost_profile, profile);
        }
        if (cost_profile && context &&
            (!context->prepared || cost_profile != &context->prepared->Cost())) {
            authenticated_cost = *cost_profile;
            VM_COUNT_PREPARATION(field_sizes);
            ApplyDerivedFieldSizes(*authenticated_cost, *context);
            cost_profile = &*authenticated_cost;
        }
        VmCostProfile default_unit_cost;
        if (!cost_profile) {
            default_unit_cost.max_invocation_cost = ~VmCostUnits(0);
            default_unit_cost.structural_byte_cost = 1;
            for (auto &f : default_unit_cost.opcode) {
                f = {1, 1, 1};
            }
        }
        const VmCostProfile &exec_cost_profile =
            cost_profile ? *cost_profile : default_unit_cost;
        std::optional<PreparedSigningContext> local_signing;
        const PreparedSigningContext *prepared_signing = nullptr;
        if (context) {
            if (context->input_index >= context->tx.inputs.size())
                throw VmFailure("invocation input index",
                                VmStatus::OperationalError);
            const auto &input = context->tx.inputs[context->input_index];
            if (input.flags == 3) {
                if (!context->positive_delta ||
                    arguments.size() >= profile.max_stack_items ||
                    profile.max_element_bytes < 16 ||
                    profile.max_vm_bytes - bytes < 16)
                    throw VmFailure("mint initial stack bound");
                UInt delta = 0;
                for (size_t i = 0; i < 16; ++i)
                    delta |= UInt((*context->positive_delta)[i]) << (8 * i);
                if (delta == 0 || delta > (UInt(1) << 127) - 1)
                    throw VmFailure("mint delta is not positive N");
            }
            if (context->witness_index >= input.witnesses.size())
                throw VmFailure("invocation witness index",
                                VmStatus::OperationalError);
            const auto &witness = input.witnesses[context->witness_index];
            if (!std::equal(script.begin(), script.end(),
                            witness.script.begin(), witness.script.end()) ||
                arguments != witness.arguments)
                throw VmFailure("invocation bytes disagree with witness",
                                VmStatus::OperationalError);
            std::string error;
            if (context->prepared) {
                prepared_signing = &context->prepared->Signing();
            } else {
                local_signing.emplace();
                VM_COUNT_PREPARATION(signing);
                const auto preparation = PrepareSigningContextChecked(
                    context->tx, context->tx_profile, context->chain_id,
                    context->resolved, *local_signing, error);
                if (preparation != SigningPreparationStatus::Ready)
                    throw VmFailure(
                        "invocation membership/context invalid",
                        preparation == SigningPreparationStatus::InvalidWitness
                            ? VmStatus::Invalid
                            : VmStatus::OperationalError);
                prepared_signing = &*local_signing;
            }
            if (!ValidateSigningInvocation(
                    *prepared_signing, context->input_index,
                    context->witness_index, context->positive_delta, error))
                throw VmFailure("invocation membership/context invalid",
                                VmStatus::OperationalError);
        }
        std::vector<Instruction> code;
        code.reserve(8);
        const VmCostUnits exec_structural =
            RawMul(script.size(), exec_cost_profile.structural_byte_cost);
        if (Scan(script, profile, code)) {
            if (cost_profile) {
                const auto cost =
                    CostMul(script.size(), cost_profile->structural_byte_cost,
                            *cost_profile);
                if (cost > cost_profile->max_invocation_cost)
                    throw VmFailure("static cost cap exceeded");
                *charged_cost = cost;
            }
            return {VmStatus::AutomaticSuccess, {}, {}, exec_structural};
        }
        Structure(code, profile);
        if (cost_profile) {
            const auto structural =
                CostMul(script.size(), cost_profile->structural_byte_cost,
                        *cost_profile);
            const auto instructions =
                SizePass(code, profile, *cost_profile, script.size(),
                         input_count, output_count,
                         cached_cost ? context->prepared : nullptr)
                    .Charge(
                        arguments,
                        context &&
                            context->tx.inputs[context->input_index].flags ==
                                3);
            const auto cost = CostAdd(structural, instructions, *cost_profile);
            if (cost > cost_profile->max_invocation_cost)
                throw VmFailure("static cost cap exceeded");
            *charged_cost = cost;
        }
        BatchSigCollector *target_sigs =
            batch_sigs ? batch_sigs : (context ? context->batch_sigs : nullptr);
        BatchSigCollector staged_sigs;
        Machine machine(code, script, profile, exec_cost_profile, input_count,
                        output_count, arguments, context, prepared_signing,
                        target_sigs ? &staged_sigs : nullptr);
        try {
            auto final_stack = machine.Run();
            if (target_sigs) {
                target_sigs->Merge(std::move(staged_sigs));
            }
            const VmCostUnits executed =
                RawAdd(exec_structural, machine.ExecutedCost());
            return {VmStatus::Success, {}, std::move(final_stack), executed};
        } catch (const VmFailure &failure) {
            const VmCostUnits executed =
                RawAdd(exec_structural, machine.ExecutedCost());
            return {failure.status, failure.what(), {}, executed};
        }
    } catch (const VmFailure &failure) {
        return {failure.status, failure.what(), {}};
    } catch (const std::exception &failure) {
        return {VmStatus::OperationalError, failure.what(), {}};
    }
}
VmResult EvaluateVm(std::span<const uint8_t> script,
                    const std::vector<VmBytes> &arguments,
                    const VmProfile &profile, uint16_t input_count,
                    uint16_t output_count, BatchSigCollector *batch_sigs) {
    return EvaluateVmImpl(script, arguments, profile, input_count, output_count,
                          nullptr, nullptr, nullptr, batch_sigs);
}
VmResult EvaluateVmWithContext(std::span<const uint8_t> script,
                               const std::vector<VmBytes> &arguments,
                               const VmProfile &profile,
                               const VmExecutionContext &context,
                               BatchSigCollector *batch_sigs) {
    if (context.tx.inputs.size() > UINT16_MAX ||
        context.tx.outputs.size() > UINT16_MAX)
        return {VmStatus::Invalid, "transaction count width", {}};
    return EvaluateVmImpl(
        script, arguments, profile, uint16_t(context.tx.inputs.size()),
        uint16_t(context.tx.outputs.size()), &context, nullptr, nullptr,
        batch_sigs);
}
VmChargedResult EvaluateVmCharged(std::span<const uint8_t> script,
                                  const std::vector<VmBytes> &arguments,
                                  const VmProfile &profile,
                                  const VmCostProfile &cost_profile,
                                  uint16_t input_count, uint16_t output_count,
                                  const VmExecutionContext *context,
                                  BatchSigCollector *batch_sigs) {
    if (context) {
        if (context->tx.inputs.size() > UINT16_MAX ||
            context->tx.outputs.size() > UINT16_MAX)
            return {{VmStatus::Invalid, "transaction count width", {}},
                    0,
                    0,
                    false};
        input_count = uint16_t(context->tx.inputs.size());
        output_count = uint16_t(context->tx.outputs.size());
    }
    VmCostUnits cost = 0;
    auto invocation =
        EvaluateVmImpl(script, arguments, profile, input_count, output_count,
                       context, &cost_profile, &cost, batch_sigs);
    return {std::move(invocation), cost, cost, cost != 0};
}
} // namespace lotus::v2

