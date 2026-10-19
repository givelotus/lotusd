// Copyright (c) 2026 The Lotus developers
// ENFORCEOUTPUT (eb) OutputTemplate binary format. Header-only so every
// target that compiles the VM gets it without build-file changes.
//
//   flags:u8          value bits 0-1, token bits 2-3, paths bits 4-5,
//                     burn bit 6, wildcard bit 7
//   [value:u64]       iff value mode is EXACT (01) or MIN (10)
//   [token_id:h32]    iff token mode is EXACT (10)
//   branch_count:u8   0..16 (0 = any count)
//   branch_mask:u16   slots pinned to roots carried in the template
//   branch_stack_mask:u16  slots pinned to roots popped from the stack
//   state_mode:u8     0 none, 1 root in template, 2 root from the stack
//   output_mode:u8    0 any output, 1 index in template, 2 index from stack
//                     (restricts the match mask to one output)
//   [state_root:h32]  iff state_mode == 1 (nonzero)
//   [output_index:u16] iff output_mode == 1
//   popcount(branch_mask) x h32, in ascending slot order
//   [paths: Vec(Vec(CS))]  iff paths mode is EXPLICIT (01)
//
// All integers are little-endian; CompactSize is shortest-form. Malformed
// templates, including trailing bytes, are script errors.
#ifndef LOTUS_V2_OUTPUT_TEMPLATE_H
#define LOTUS_V2_OUTPUT_TEMPLATE_H

#include "output.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace lotus::v2 {

struct OutputTemplate {
    enum : uint8_t { OMIT = 0 };
    // Value: OMIT, EXACT, MIN, FROM_STACK.
    enum : uint8_t { VALUE_EXACT = 1, VALUE_MIN = 2, VALUE_FROM_STACK = 3 };
    // Token: OMIT, NATIVE, EXACT, SELF (the active branch root).
    enum : uint8_t { TOKEN_NATIVE = 1, TOKEN_EXACT = 2, TOKEN_SELF = 3 };
    // Paths: OMIT, EXPLICIT, INHERIT (the spent coin's paths).
    enum : uint8_t { PATHS_EXPLICIT = 1, PATHS_INHERIT = 2 };
    enum : uint8_t { STATE_NONE = 0, STATE_TEMPLATE = 1, STATE_STACK = 2 };
    enum : uint8_t { OUTPUT_ANY = 0, OUTPUT_TEMPLATE = 1, OUTPUT_STACK = 2 };

    uint8_t value_mode = 0;
    uint8_t token_mode = 0;
    uint8_t paths_mode = 0;
    bool burn = false;
    bool wildcard = false;
    uint64_t value = 0;
    Hash32 token_id{};
    uint8_t branch_count = 0;
    uint16_t branch_mask = 0;
    uint16_t branch_stack_mask = 0;
    uint8_t state_mode = 0;
    uint8_t output_mode = 0;
    Hash32 state_root{};
    uint16_t output_index = 0;
    // Static pinned roots, ascending slot order (one per branch_mask bit).
    std::vector<Hash32> branches;
    std::vector<std::vector<uint8_t>> paths;
};

namespace output_template_detail {
    inline unsigned PopCount16(uint16_t v) {
        unsigned n = 0;
        for (; v; v &= uint16_t(v - 1)) ++n;
        return n;
    }
    class Reader {
    public:
        explicit Reader(std::span<const uint8_t> bytes) : bytes_(bytes) {}
        bool Done() const { return at_ == bytes_.size(); }
        bool Le(size_t width, uint64_t &out) {
            if (bytes_.size() - at_ < width) return false;
            out = 0;
            for (size_t i = 0; i < width; ++i)
                out |= uint64_t(bytes_[at_ + i]) << (8 * i);
            at_ += width;
            return true;
        }
        bool H32(Hash32 &out) {
            if (bytes_.size() - at_ < 32) return false;
            for (size_t i = 0; i < 32; ++i) out[i] = bytes_[at_ + i];
            at_ += 32;
            return true;
        }
        // Shortest-form CompactSize bounded by `cap`.
        bool Compact(uint64_t cap, uint64_t &out) {
            uint64_t lead;
            if (!Le(1, lead)) return false;
            if (lead < 253) {
                out = lead;
            } else {
                const size_t width = lead == 253 ? 2 : lead == 254 ? 4 : 8;
                if (!Le(width, out)) return false;
                const uint64_t min = width == 2   ? 253
                                     : width == 4 ? 0x10000
                                                  : 0x100000000ULL;
                if (out < min) return false;
            }
            return out <= cap;
        }

    private:
        std::span<const uint8_t> bytes_;
        size_t at_ = 0;
    };
} // namespace output_template_detail

// Parses and validates the template-level rules that do not depend on the
// invocation (a mint check for INHERIT is the caller's). On failure `out` is
// unspecified and `error` names the rule.
inline bool ParseOutputTemplate(std::span<const uint8_t> bytes,
                                OutputTemplate &out, std::string &error) {
    using namespace output_template_detail;
    out = OutputTemplate{};
    Reader r(bytes);
    uint64_t v;
    auto fail = [&](const char *message) {
        error = message;
        return false;
    };
    if (!r.Le(1, v)) return fail("template truncated");
    const uint8_t flags = uint8_t(v);
    out.value_mode = flags & 3;
    out.token_mode = (flags >> 2) & 3;
    out.paths_mode = (flags >> 4) & 3;
    out.burn = (flags >> 6) & 1;
    out.wildcard = (flags >> 7) & 1;
    if (out.paths_mode == 3) return fail("template paths mode");
    if (out.value_mode == OutputTemplate::VALUE_EXACT ||
        out.value_mode == OutputTemplate::VALUE_MIN) {
        if (!r.Le(8, out.value)) return fail("template truncated");
    }
    if (out.token_mode == OutputTemplate::TOKEN_EXACT &&
        !r.H32(out.token_id))
        return fail("template truncated");
    uint64_t count, mask, stack_mask, state_mode, output_mode;
    if (!r.Le(1, count) || !r.Le(2, mask) || !r.Le(2, stack_mask) ||
        !r.Le(1, state_mode) || !r.Le(1, output_mode))
        return fail("template truncated");
    if (count > MAX_OUTPUT_BRANCHES) return fail("template branch count");
    if (state_mode > 2) return fail("template state mode");
    if (output_mode > 2) return fail("template output mode");
    out.branch_count = uint8_t(count);
    out.branch_mask = uint16_t(mask);
    out.branch_stack_mask = uint16_t(stack_mask);
    out.state_mode = uint8_t(state_mode);
    out.output_mode = uint8_t(output_mode);
    if (out.branch_mask & out.branch_stack_mask)
        return fail("template mask overlap");
    if (out.branch_count &&
        ((out.branch_mask | out.branch_stack_mask) >> out.branch_count))
        return fail("template mask beyond branch count");
    if (out.state_mode == OutputTemplate::STATE_TEMPLATE) {
        if (!r.H32(out.state_root)) return fail("template truncated");
        if (out.state_root == Hash32{}) return fail("template zero state root");
    }
    if (out.output_mode == OutputTemplate::OUTPUT_TEMPLATE) {
        if (!r.Le(2, v)) return fail("template truncated");
        out.output_index = uint16_t(v);
    }
    out.branches.resize(PopCount16(out.branch_mask));
    for (auto &root : out.branches)
        if (!r.H32(root)) return fail("template truncated");
    if (out.paths_mode == OutputTemplate::PATHS_EXPLICIT) {
        uint64_t path_count;
        if (!r.Compact(MAX_OUTPUT_PATHS, path_count))
            return fail("template paths");
        out.paths.resize(size_t(path_count));
        for (auto &path : out.paths) {
            uint64_t length;
            if (!r.Compact(MAX_OUTPUT_BRANCHES, length))
                return fail("template paths");
            path.resize(size_t(length));
            for (auto &index : path) {
                uint64_t value;
                if (!r.Compact(MAX_OUTPUT_BRANCHES - 1, value))
                    return fail("template paths");
                index = uint8_t(value);
            }
        }
    }
    if (!r.Done()) return fail("template trailing bytes");
    if (out.burn) {
        if (out.paths_mode == OutputTemplate::PATHS_INHERIT)
            return fail("template burn inherits paths");
        if (out.paths_mode == OutputTemplate::PATHS_EXPLICIT &&
            !out.paths.empty())
            return fail("template burn with paths");
    }
    error.clear();
    return true;
}

} // namespace lotus::v2

#endif
