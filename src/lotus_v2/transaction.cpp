#include "transaction.h"
#include "commitment.h"

#include <algorithm>
#include <set>
#include <utility>

namespace lotus::v2 {
namespace {

    constexpr size_t MAX_WITNESS_ARGUMENT_BYTES = 8192;

    class Reader {
    public:
        explicit Reader(const std::vector<uint8_t> &frame) : frame_(frame) {}
        size_t Offset() const { return offset_; }
        size_t Remaining() const { return frame_.size() - offset_; }
        bool Finished() const { return Remaining() == 0; }
        bool Take(size_t count, const uint8_t *&ptr) {
            if (count > Remaining()) return false;
            ptr = frame_.data() + offset_;
            offset_ += count;
            return true;
        }
        bool Integer(size_t width, uint64_t &value) {
            const uint8_t *ptr;
            if (width == 0 || width > 8 || !Take(width, ptr)) return false;
            value = 0;
            for (size_t i = 0; i < width; ++i)
                value |= uint64_t(ptr[i]) << (8 * i);
            return true;
        }
        bool CompactSize(uint64_t cap, uint64_t &value) {
            uint64_t lead;
            if (!Integer(1, lead)) return false;
            if (lead < 253)
                value = lead;
            else {
                const size_t width = lead == 253 ? 2 : lead == 254 ? 4 : 8;
                if (!Integer(width, value)) return false;
                if (value < (width == 2   ? 253ULL
                             : width == 4 ? 65536ULL
                                          : 4294967296ULL))
                    return false;
            }
            return value <= cap;
        }
        bool Bytes(size_t cap, std::vector<uint8_t> &out) {
            uint64_t count;
            if (!CompactSize(cap, count) || count > Remaining()) return false;
            const uint8_t *ptr;
            if (!Take(size_t(count), ptr)) return false;
            out.assign(ptr, ptr + count);
            return true;
        }

    private:
        const std::vector<uint8_t> &frame_;
        size_t offset_ = 0;
    };

    void Integer(uint64_t value, size_t width, std::vector<uint8_t> &out) {
        for (size_t i = 0; i < width; ++i)
            out.push_back(uint8_t(value >> (8 * i)));
    }
    void CS(uint64_t value, std::vector<uint8_t> &out) {
        if (value < 253)
            Integer(value, 1, out);
        else if (value <= 65535) {
            out.push_back(253);
            Integer(value, 2, out);
        } else if (value <= 4294967295ULL) {
            out.push_back(254);
            Integer(value, 4, out);
        } else {
            out.push_back(255);
            Integer(value, 8, out);
        }
    }
    void Bytes(const std::vector<uint8_t> &value, std::vector<uint8_t> &out) {
        CS(value.size(), out);
        out.insert(out.end(), value.begin(), value.end());
    }

    bool ValidProfile(const TxProfile &p, std::string &error) {
        if (p.max_inputs == 0 || p.max_inputs > MAX_TX_INPUTS ||
            p.max_outputs > MAX_TX_OUTPUTS || p.max_mints > p.max_inputs ||
            p.max_arguments > 65535 ||
            p.max_argument_bytes > MAX_WITNESS_ARGUMENT_BYTES ||
            p.max_branch_proof_depth > 64) {
            error = "profile";
            return false;
        }
        return true;
    }

    bool WitnessWire(const BranchWitness &w, const TxProfile &p, bool core,
                     std::vector<uint8_t> &out, std::string &error) {
        if (w.script.size() > p.max_script_bytes ||
            w.siblings.size() > p.max_branch_proof_depth ||
            w.arguments.size() > p.max_arguments) {
            error = "witness cap";
            return false;
        }
        Bytes(w.script, out);
        CS(w.siblings.size(), out);
        for (const auto &hash : w.siblings)
            out.insert(out.end(), hash.begin(), hash.end());
        if (!core) {
            CS(w.arguments.size(), out);
            for (const auto &arg : w.arguments) {
                if (arg.size() > p.max_argument_bytes) {
                    error = "argument cap";
                    return false;
                }
                Bytes(arg, out);
            }
        }
        return true;
    }

    bool InputWire(const Input &input, const TxProfile &p, bool core,
                   std::vector<uint8_t> &out, std::string &error) {
        if (input.flags < 1 || input.flags > 3) {
            error = "input flags";
            return false;
        }
        out.insert(out.end(), input.prev_txid.begin(), input.prev_txid.end());
        Integer(input.prev_index, 4, out);
        Integer(input.sequence, 4, out);
        out.push_back(input.flags);
        if (input.flags == 1) {
            if (input.has_coinbase_data || !input.coinbase_data.empty() ||
                input.path_index >= MAX_OUTPUT_PATHS ||
                input.witnesses.empty() ||
                input.witnesses.size() > MAX_OUTPUT_BRANCHES ||
                (input.sequence != UINT32_MAX &&
                 (input.sequence & ~0x40ffffU))) {
                error = "spend authorization";
                return false;
            }
            CS(input.path_index, out);
            CS(input.witnesses.size(), out);
            for (const auto &w : input.witnesses)
                if (!WitnessWire(w, p, core, out, error)) return false;
        } else if (input.flags == 2) {
            if (input.sequence != UINT32_MAX || input.path_index != 0 ||
                !input.witnesses.empty() ||
                (input.has_coinbase_data &&
                 (input.coinbase_data.empty() ||
                  input.coinbase_data.size() > 8192)) ||
                (!input.has_coinbase_data && !input.coinbase_data.empty())) {
                error = "coinbase data";
                return false;
            }
            CS(input.has_coinbase_data ? 1 : 0, out);
            if (input.has_coinbase_data) Bytes(input.coinbase_data, out);
        } else {
            if (input.has_coinbase_data || !input.coinbase_data.empty()) {
                error = "mint coinbase data";
                return false;
            }
            if (input.prev_txid == Hash32{} || input.prev_index != 0 ||
                input.sequence != UINT32_MAX || input.path_index != 0 ||
                input.witnesses.size() != 1) {
                error = "mint pseudo-outpoint";
                return false;
            }
            if (!WitnessWire(input.witnesses[0], p, core, out, error))
                return false;
        }
        return true;
    }

    bool ReadWitness(Reader &r, const TxProfile &p, BranchWitness &w,
                     std::string &error) {
        if (!r.Bytes(p.max_script_bytes, w.script)) {
            error = "script bytes";
            return false;
        }
        uint64_t count;
        if (!r.CompactSize(p.max_branch_proof_depth, count) ||
            count > r.Remaining() / 32) {
            error = "sibling count";
            return false;
        }
        w.siblings.reserve(size_t(count));
        for (uint64_t i = 0; i < count; ++i) {
            const uint8_t *ptr;
            if (!r.Take(32, ptr)) {
                error = "siblings";
                return false;
            }
            Hash32 hash;
            std::copy_n(ptr, 32, hash.begin());
            w.siblings.push_back(hash);
        }
        if (!r.CompactSize(p.max_arguments, count) || count > r.Remaining()) {
            error = "argument count";
            return false;
        }
        w.arguments.reserve(size_t(count));
        for (uint64_t i = 0; i < count; ++i) {
            std::vector<uint8_t> arg;
            if (!r.Bytes(p.max_argument_bytes, arg)) {
                error = "argument bytes";
                return false;
            }
            w.arguments.push_back(std::move(arg));
        }
        return true;
    }

    bool ReadInput(Reader &r, const TxProfile &p, Input &input,
                   std::string &error) {
        const uint8_t *ptr;
        uint64_t value;
        if (!r.Take(32, ptr)) {
            error = "prev txid";
            return false;
        }
        std::copy_n(ptr, 32, input.prev_txid.begin());
        if (!r.Integer(4, value)) {
            error = "prev index";
            return false;
        }
        input.prev_index = uint32_t(value);
        if (!r.Integer(4, value)) {
            error = "sequence";
            return false;
        }
        input.sequence = uint32_t(value);
        if (!r.Integer(1, value)) {
            error = "input flags";
            return false;
        }
        input.flags = uint8_t(value);
        if (input.flags == 1) {
            if (!r.CompactSize(MAX_OUTPUT_PATHS - 1, value)) {
                error = "path index";
                return false;
            }
            input.path_index = uint8_t(value);
            if (!r.CompactSize(MAX_OUTPUT_BRANCHES, value) ||
                value > r.Remaining() / 3) {
                error = "witness count";
                return false;
            }
            input.witnesses.reserve(size_t(value));
            for (uint64_t i = 0; i < value; ++i) {
                BranchWitness w;
                if (!ReadWitness(r, p, w, error)) return false;
                input.witnesses.push_back(std::move(w));
            }
        } else if (input.flags == 2) {
            if (!r.CompactSize(1, value)) {
                error = "coinbase count";
                return false;
            }
            if (value == 1) {
                input.has_coinbase_data = true;
                if (!r.Bytes(8192, input.coinbase_data)) {
                    error = "coinbase bytes";
                    return false;
                }
            }
        } else if (input.flags == 3) {
            BranchWitness w;
            if (!ReadWitness(r, p, w, error)) return false;
            input.witnesses.push_back(std::move(w));
        } else {
            error = "input flags";
            return false;
        }
        std::vector<uint8_t> check;
        return InputWire(input, p, false, check, error);
    }

    bool ReadOutput(Reader &r, const std::vector<uint8_t> &frame,
                    Output &output, std::string &error) {
        const size_t begin = r.Offset();
        uint64_t flags, count, length;
        const uint8_t *unused;
        if (!r.Integer(1, flags) || (flags & 0xf8) ||
            !r.Take(8 + ((flags & OUTPUT_FLAG_HAS_TOKEN) ? 32 : 0) +
                        ((flags & OUTPUT_FLAG_HAS_STATE) ? 32 : 0),
                    unused)) {
            error = "output prefix";
            return false;
        }
        if (!r.CompactSize(MAX_OUTPUT_BRANCHES, count) ||
            count > r.Remaining() / 32 || !r.Take(size_t(count) * 32, unused)) {
            error = "output branches";
            return false;
        }
        if (!r.CompactSize(MAX_OUTPUT_PATHS, count) || count > r.Remaining()) {
            error = "output paths";
            return false;
        }
        for (uint64_t p = 0; p < count; ++p) {
            if (!r.CompactSize(MAX_OUTPUT_BRANCHES, length) ||
                length > r.Remaining()) {
                error = "output path length";
                return false;
            }
            for (uint64_t i = 0; i < length; ++i) {
                uint64_t index;
                if (!r.CompactSize(MAX_OUTPUT_BRANCHES - 1, index)) {
                    error = "output path index";
                    return false;
                }
            }
        }
        if (r.Offset() - begin > MAX_OUTPUT_BYTES) {
            error = "output bytes";
            return false;
        }
        return DecodeOutput({frame.begin() + begin, frame.begin() + r.Offset()},
                            output, error);
    }

} // namespace

bool EncodeInputCore(const Input &input, const TxProfile &profile,
                     std::vector<uint8_t> &result, std::string &error) {
    if (!ValidProfile(profile, error)) return false;
    std::vector<uint8_t> encoded;
    if (!InputWire(input, profile, true, encoded, error)) return false;
    result = std::move(encoded);
    error.clear();
    return true;
}

bool EncodeInputFull(const Input &input, const TxProfile &profile,
                     std::vector<uint8_t> &result, std::string &error) {
    if (!ValidProfile(profile, error)) return false;
    std::vector<uint8_t> encoded;
    if (!InputWire(input, profile, false, encoded, error)) return false;
    result = std::move(encoded);
    error.clear();
    return true;
}

bool EncodeTransaction(const Transaction &tx, const TxProfile &profile,
                       std::vector<uint8_t> &result, std::string &error) {
    if (!ValidProfile(profile, error)) return false;
    if (tx.inputs.empty() || tx.inputs.size() > profile.max_inputs ||
        tx.outputs.size() > profile.max_outputs || ((tx.lock & 255) > 2) ||
        ((tx.lock & 255) == 0 && tx.lock != 0)) {
        error = "transaction header";
        return false;
    }
    size_t mint_count = 0;
    bool has_spend = false;
    bool has_coinbase = false;
    std::set<std::pair<Hash32, uint32_t>> outpoints;
    for (const auto &input : tx.inputs) {
        has_spend |= input.flags == 1;
        has_coinbase |= input.flags == 2;
        mint_count += input.flags == 3;
        if (!outpoints.emplace(input.prev_txid, input.prev_index).second) {
            error = "repeated outpoint";
            return false;
        }
    }
    if (has_coinbase) {
        if (tx.inputs.size() != 1 || tx.inputs[0].flags != 2 || tx.lock != 0 ||
            tx.outputs.empty() ||
            std::any_of(tx.outputs.begin(), tx.outputs.end(),
                        [](const Output &o) {
                            // Coinbase runs no script: it can neither
                            // mint tokens nor authorize state.
                            return o.HasToken() || o.HasState();
                        })) {
            error = "coinbase shape";
            return false;
        }
    } else if (!has_spend || mint_count > profile.max_mints) {
        error = "ordinary input mix";
        return false;
    }
    std::vector<uint8_t> encoded;
    Integer(7, 4, encoded);
    Integer(tx.lock, 8, encoded);
    Integer(tx.inputs.size(), 2, encoded);
    Integer(tx.outputs.size(), 2, encoded);
    for (const auto &input : tx.inputs) {
        if (!InputWire(input, profile, false, encoded, error)) return false;
    }
    for (const auto &output : tx.outputs) {
        std::vector<uint8_t> wire;
        if (!EncodeOutput(output, wire, error)) return false;
        encoded.insert(encoded.end(), wire.begin(), wire.end());
    }
    result = std::move(encoded);
    error.clear();
    return true;
}

bool DecodeTransaction(const std::vector<uint8_t> &frame,
                       const TxProfile &profile, Transaction &result,
                       std::string &error) {
    if (!ValidProfile(profile, error)) return false;
    Reader r(frame);
    uint64_t value, input_count, output_count;
    if (!r.Integer(4, value) || value != 7 || !r.Integer(8, value)) {
        error = "version/lock";
        return false;
    }
    Transaction parsed;
    parsed.lock = value;
    if (!r.Integer(2, input_count) || !r.Integer(2, output_count) ||
        input_count == 0 || input_count > profile.max_inputs ||
        output_count > profile.max_outputs ||
        input_count > r.Remaining() / 42) {
        error = "transaction count";
        return false;
    }
    parsed.inputs.reserve(size_t(input_count));
    for (uint64_t i = 0; i < input_count; ++i) {
        Input input;
        if (!ReadInput(r, profile, input, error)) return false;
        parsed.inputs.push_back(std::move(input));
    }
    if (output_count > r.Remaining() / 43) {
        error = "output count";
        return false;
    }
    parsed.outputs.reserve(size_t(output_count));
    for (uint64_t i = 0; i < output_count; ++i) {
        Output output;
        if (!ReadOutput(r, frame, output, error)) return false;
        parsed.outputs.push_back(std::move(output));
    }
    if (!r.Finished()) {
        error = "trailing bytes";
        return false;
    }
    std::vector<uint8_t> check;
    if (!EncodeTransaction(parsed, profile, check, error)) return false;
    result = std::move(parsed);
    error.clear();
    return true;
}

bool CheckCoinbaseContext(const Transaction &tx, const Hash32 &parent_block_id,
                          uint64_t height, std::string &error) {
    if (tx.inputs.size() != 1 || tx.inputs[0].flags != 2 ||
        height > UINT32_MAX || tx.inputs[0].prev_index != height ||
        tx.inputs[0].prev_txid != parent_block_id) {
        error = "coinbase parent/height";
        return false;
    }
    error.clear();
    return true;
}

bool ComputeTransactionIdentities(const Transaction &tx,
                                  const TxProfile &profile,
                                  const Hash32 &chain_id, Hash32 &txid,
                                  Hash32 &txhash, std::string &error,
                                  Hash32 *outputs_root_out) {
    if (!ValidProfile(profile, error)) return false;
    // Counts are bounded by the u16 wire format only, never by the profile's
    // (consensus) caps: identity is a function of the transaction's content.
    if (tx.inputs.empty() || tx.inputs.size() > MAX_WIRE_TX_INPUTS ||
        tx.outputs.size() > MAX_WIRE_TX_OUTPUTS || ((tx.lock & 255) > 2) ||
        ((tx.lock & 255) == 0 && tx.lock != 0)) {
        error = "transaction header";
        return false;
    }
    bool has_spend = false;
    bool has_coinbase = false;
    const size_t n_in = tx.inputs.size();
    if (n_in <= 16) {
        for (size_t i = 0; i < n_in; ++i) {
            const auto &input = tx.inputs[i];
            has_spend |= input.flags == 1;
            has_coinbase |= input.flags == 2;
            for (size_t j = 0; j < i; ++j) {
                if (tx.inputs[j].prev_index == input.prev_index &&
                    tx.inputs[j].prev_txid == input.prev_txid) {
                    error = "repeated outpoint";
                    return false;
                }
            }
        }
    } else {
        std::set<std::pair<Hash32, uint32_t>> outpoints;
        for (const auto &input : tx.inputs) {
            has_spend |= input.flags == 1;
            has_coinbase |= input.flags == 2;
            if (!outpoints.emplace(input.prev_txid, input.prev_index).second) {
                error = "repeated outpoint";
                return false;
            }
        }
    }
    if (has_coinbase) {
        if (n_in != 1 || tx.inputs[0].flags != 2 || tx.lock != 0 ||
            tx.outputs.empty() ||
            std::any_of(tx.outputs.begin(), tx.outputs.end(),
                        [](const Output &o) { return o.HasToken(); })) {
            error = "coinbase shape";
            return false;
        }
    } else if (!has_spend) {
        // The mint count is bounded by the input count; profile.max_mints is
        // a validation cap and does not affect identity.
        error = "ordinary input mix";
        return false;
    }

    std::vector<Hash> core_leaves, full_leaves;
    core_leaves.reserve(n_in);
    full_leaves.reserve(n_in);
    std::vector<uint8_t> core, full;
    core.reserve(128);
    full.reserve(256);
    for (const auto &input : tx.inputs) {
        core.clear();
        full.clear();
        if (!InputWire(input, profile, true, core, error) ||
            !InputWire(input, profile, false, full, error))
            return false;
        core_leaves.push_back(InputCoreLeaf(core));
        full_leaves.push_back(InputFullLeaf(full));
    }
    const Hash inputs_root = IndexedTreeRoot(core_leaves);
    const Hash full_inputs_root = IndexedTreeRoot(full_leaves);
    std::vector<Hash> output_leaves;
    output_leaves.reserve(tx.outputs.size());
    std::vector<uint8_t> wire;
    wire.reserve(64);
    for (const auto &output : tx.outputs) {
        if (!EncodeOutput(output, wire, error)) return false;
        output_leaves.push_back(OutputLeaf(wire));
    }
    const Hash outputs_root = IndexedTreeRoot(output_leaves);
    if (outputs_root_out) {
        *outputs_root_out = outputs_root;
    }
    TxHeaderCore header{};
    header[0] = 7;
    for (size_t i = 0; i < 8; ++i)
        header[4 + i] = uint8_t(tx.lock >> (8 * i));
    header[12] = uint8_t(n_in);
    header[13] = uint8_t(n_in >> 8);
    header[14] = uint8_t(tx.outputs.size());
    header[15] = uint8_t(tx.outputs.size() >> 8);
    txid = TransactionId(chain_id, header, inputs_root, outputs_root);
    txhash = TransactionHash(chain_id, header, full_inputs_root, outputs_root);
    error.clear();
    return true;
}

} // namespace lotus::v2
