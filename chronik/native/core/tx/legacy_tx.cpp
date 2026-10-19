// Copyright (c) 2026 The Lotus developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chronik/native/tx/legacy_tx.h>

#include <algorithm>
#include <cstring>

namespace chronik::native {

namespace {

struct DataError {
    std::string msg;
};

class Reader {
public:
    explicit Reader(ByteView data) : m_data(data) {}

    ByteView ReadBytes(size_t num_bytes) {
        if (Remaining() < num_bytes) {
            throw DataError{"Invalid length, expected " +
                            std::to_string(num_bytes) + " bytes but got " +
                            std::to_string(Remaining()) + " bytes"};
        }
        ByteView v = m_data.subspan(m_pos, num_bytes);
        m_pos += num_bytes;
        return v;
    }

    template <typename T> T ReadLe() {
        ByteView v = ReadBytes(sizeof(T));
        T value{};
        for (size_t i = 0; i < sizeof(T); ++i) {
            value |= T(uint64_t(v[i]) << (8 * i));
        }
        return value;
    }

    uint64_t ReadCompactSize() {
        const uint8_t first = ReadLe<uint8_t>();
        switch (first) {
            case 0xfd:
                return ReadLe<uint16_t>();
            case 0xfe:
                return ReadLe<uint32_t>();
            case 0xff:
                return ReadLe<uint64_t>();
            default:
                return first;
        }
    }

    Bytes ReadVarBytes() {
        const uint64_t size = ReadCompactSize();
        ByteView v = ReadBytes(size_t(size));
        return Bytes(v.begin(), v.end());
    }

    size_t Remaining() const { return m_data.size() - m_pos; }
    size_t Pos() const { return m_pos; }

private:
    ByteView m_data;
    size_t m_pos = 0;
};

template <typename T> void WriteLe(Bytes &out, T value) {
    for (size_t i = 0; i < sizeof(T); ++i) {
        out.push_back(uint8_t(uint64_t(value) >> (8 * i)));
    }
}

void WriteVarBytes(Bytes &out, const Bytes &bytes) {
    WriteCompactSize(out, bytes.size());
    out.insert(out.end(), bytes.begin(), bytes.end());
}

} // namespace

void WriteCompactSize(Bytes &out, uint64_t size) {
    if (size <= 0xfc) {
        out.push_back(uint8_t(size));
    } else if (size <= 0xffff) {
        out.push_back(0xfd);
        WriteLe<uint16_t>(out, uint16_t(size));
    } else if (size <= 0xffff'ffff) {
        out.push_back(0xfe);
        WriteLe<uint32_t>(out, uint32_t(size));
    } else {
        out.push_back(0xff);
        WriteLe<uint64_t>(out, size);
    }
}

size_t CompactSizeLen(uint64_t size) {
    if (size <= 0xfc) {
        return 1;
    }
    if (size <= 0xffff) {
        return 3;
    }
    if (size <= 0xffff'ffff) {
        return 5;
    }
    return 9;
}

LegacyTxDecodeResult DecodeLegacyTx(ByteView raw) {
    LegacyTxDecodeResult result;
    Reader r(raw);
    try {
        Tx &tx = result.tx;
        tx.version = int32_t(r.ReadLe<uint32_t>());
        const uint64_t num_inputs = r.ReadCompactSize();
        tx.inputs.reserve(size_t(std::min<uint64_t>(num_inputs, 0x10000)));
        for (uint64_t i = 0; i < num_inputs; ++i) {
            TxInput input;
            ByteView txid = r.ReadBytes(32);
            std::memcpy(input.prev_out.txid.b.data(), txid.data(), 32);
            input.prev_out.out_idx = r.ReadLe<uint32_t>();
            input.script = r.ReadVarBytes();
            input.sequence = r.ReadLe<uint32_t>();
            tx.inputs.push_back(std::move(input));
        }
        const uint64_t num_outputs = r.ReadCompactSize();
        tx.outputs.reserve(size_t(std::min<uint64_t>(num_outputs, 0x10000)));
        for (uint64_t i = 0; i < num_outputs; ++i) {
            TxOutput output;
            output.sats = int64_t(r.ReadLe<uint64_t>());
            output.script = r.ReadVarBytes();
            tx.outputs.push_back(std::move(output));
        }
        tx.locktime = r.ReadLe<uint32_t>();
        result.consumed = r.Pos();
        tx.wire_size = uint32_t(result.consumed);
    } catch (const DataError &err) {
        result.error = err.msg;
        result.tx = Tx{};
    }
    return result;
}

Bytes SerializeLegacyTx(const Tx &tx) {
    Bytes out;
    WriteLe<uint32_t>(out, uint32_t(tx.version));
    WriteCompactSize(out, tx.inputs.size());
    for (const TxInput &input : tx.inputs) {
        out.insert(out.end(), input.prev_out.txid.b.begin(),
                   input.prev_out.txid.b.end());
        WriteLe<uint32_t>(out, input.prev_out.out_idx);
        WriteVarBytes(out, input.script);
        WriteLe<uint32_t>(out, input.sequence);
    }
    WriteCompactSize(out, tx.outputs.size());
    for (const TxOutput &output : tx.outputs) {
        WriteLe<uint64_t>(out, uint64_t(output.sats));
        WriteVarBytes(out, output.script);
    }
    WriteLe<uint32_t>(out, tx.locktime);
    return out;
}

} // namespace chronik::native
