// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COMPRESSOR_H
#define BITCOIN_COMPRESSOR_H

#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <span.h>

bool CompressScript(const CScript &script, std::vector<uint8_t> &out);
unsigned int GetSpecialScriptSize(unsigned int nSize);
bool DecompressScript(CScript &script, unsigned int nSize,
                      const std::vector<uint8_t> &out);

/**
 * Compress amount.
 *
 * @pre Function defined only for 0 <= nAmount <= MAX_MONEY.
 */
uint64_t CompressAmount(Amount nAmount);

Amount DecompressAmount(uint64_t nAmount);

/**
 * Compact serializer for scripts.
 *
 * It detects common cases and encodes them much more efficiently.
 * 3 special cases are defined:
 *  * Pay to pubkey hash (encoded as 21 bytes)
 *  * Pay to script hash (encoded as 21 bytes)
 *  * Pay to pubkey starting with 0x02, 0x03 or 0x04 (encoded as 33 bytes)
 *
 * Other scripts up to 121 bytes require 1 byte + script length. Above that,
 * scripts up to 16505 bytes require 2 bytes + script length.
 */
struct ScriptCompression {
    /**
     * make this static for now (there are only 6 special scripts defined) this
     * can potentially be extended together with a new nVersion for
     * transactions, in which case this value becomes dependent on nVersion and
     * nHeight of the enclosing transaction.
     */
    static const unsigned int nSpecialScripts = 6;

    template <typename Stream>
    void Ser(Stream &s, const CScript &script) const {
        std::vector<uint8_t> compr;
        if (CompressScript(script, compr)) {
            s << Span{compr};
            return;
        }
        unsigned int nSize = script.size() + nSpecialScripts;
        s << VARINT(nSize);
        s << Span{script};
    }

    template <typename Stream> void Unser(Stream &s, CScript &script) {
        unsigned int nSize = 0;
        s >> VARINT(nSize);
        if (nSize < nSpecialScripts) {
            std::vector<uint8_t> vch(GetSpecialScriptSize(nSize), 0x00);
            s >> Span{vch};
            DecompressScript(script, nSize, vch);
            return;
        }
        nSize -= nSpecialScripts;
        if (nSize > MAX_SCRIPT_SIZE) {
            // Overly long script, replace with a short invalid one
            script << OP_RETURN;
            s.ignore(nSize);
        } else {
            script.resize(nSize);
            s >> Span{script};
        }
    }
};

struct AmountCompression {
    template <typename Stream, typename I> void Ser(Stream &s, I val) {
        s << VARINT(CompressAmount(val));
    }
    template <typename Stream, typename I> void Unser(Stream &s, I &val) {
        uint64_t v;
        s >> VARINT(v);
        val = DecompressAmount(v);
    }
};

/**
 * wrapper for CTxOut that provides a more compact serialization
 */
struct TxOutCompression {
    template <typename Stream>
    void Ser(Stream &s, const CTxOut &obj) const {
        AmountCompression{}.Ser(s, obj.nValue);
        // A V2 output (it has branches) is stored by its fields, a legacy
        // output by its script, so the representation survives the round
        // trip whatever its scriptPubKey holds.
        if (!obj.IsLegacy()) {
            const unsigned int v2_tag =
                ScriptCompression::nSpecialScripts + MAX_SCRIPT_SIZE + 1U +
                static_cast<unsigned int>(obj.nFlags & 0x07U);
            s << VARINT(v2_tag);
            if (obj.nFlags & 0x01U) {
                s << obj.tokenId;
            }
            if (obj.nFlags & 0x04U) {
                s << obj.stateRoot;
            }
            WriteCompactSize(s, obj.vBranches.size());
            for (const auto &b : obj.vBranches) {
                s.write(AsBytes(Span{b.data(), 32}));
            }
            WriteCompactSize(s, obj.vPaths.size());
            for (const auto &p : obj.vPaths) {
                s << p;
            }
            return;
        }
        ScriptCompression{}.Ser(s, obj.scriptPubKey);
    }

    template <typename Stream>
    void Unser(Stream &s, CTxOut &obj) {
        obj.SetNull();
        AmountCompression{}.Unser(s, obj.nValue);
        unsigned int nSize = 0;
        s >> VARINT(nSize);
        constexpr unsigned int kV2TagBase =
            ScriptCompression::nSpecialScripts + MAX_SCRIPT_SIZE + 1U;
        // Tags kV2TagBase..+7 carry the three V2 flag bits (token, burn,
        // state); burn+state is never valid.
        if (nSize >= kV2TagBase && nSize < kV2TagBase + 8U) {
            obj.nFlags = static_cast<uint8_t>(nSize - kV2TagBase);
            if ((obj.nFlags & 0x06U) == 0x06U) {
                throw std::ios_base::failure("invalid V2 compressed flags");
            }
            if (obj.nFlags & 0x01U) {
                s >> obj.tokenId;
            }
            if (obj.nFlags & 0x04U) {
                s >> obj.stateRoot;
            }
            const uint64_t branch_count = ReadCompactSize(s);
            if (branch_count == 0 ||
                branch_count > lotus::v2::MAX_OUTPUT_BRANCHES) {
                throw std::ios_base::failure(
                    "invalid V2 compressed branch count");
            }
            obj.vBranches.resize(branch_count);
            for (auto &b : obj.vBranches) {
                s.read(AsWritableBytes(Span{b.data(), 32}));
            }
            const uint64_t path_count = ReadCompactSize(s);
            if (path_count > lotus::v2::MAX_OUTPUT_PATHS) {
                throw std::ios_base::failure(
                    "invalid V2 compressed path count");
            }
            obj.vPaths.resize(path_count);
            for (auto &p : obj.vPaths) {
                s >> p;
            }
            // The scriptPubKey of a V2 output is its V2 wire encoding.
            obj.scriptPubKey = CTxOut::V2ScriptPubKey(obj.ToV2Output());
            return;
        }
        if (nSize < ScriptCompression::nSpecialScripts) {
            std::vector<uint8_t> vch(GetSpecialScriptSize(nSize), 0x00);
            s >> Span{vch};
            DecompressScript(obj.scriptPubKey, nSize, vch);
            return;
        }
        nSize -= ScriptCompression::nSpecialScripts;
        if (nSize > MAX_SCRIPT_SIZE) {
            obj.scriptPubKey << OP_RETURN;
            s.ignore(nSize);
        } else {
            obj.scriptPubKey.resize(nSize);
            s >> Span{obj.scriptPubKey};
        }
    }
};

#endif // BITCOIN_COMPRESSOR_H
