// Copyright (c) 2020 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <avalanche/delegation.h>

#include <avalanche/proof.h>
#include <avalanche/validation.h>
#include <hash.h>
#include <lotus_v2/signing.h>
#include <streams.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <span>

namespace avalanche {

bool Delegation::FromHex(Delegation &dg, const std::string &dgHex,
                         bilingual_str &errorOut) {
    if (!IsHex(dgHex)) {
        errorOut = _("Delegation must be an hexadecimal string.");
        return false;
    }

    DataStream ss{ParseHex(dgHex)};

    try {
        ss >> dg;
    } catch (std::exception &e) {
        errorOut = strprintf(_("Delegation has invalid format: %s"), e.what());
        return false;
    }

    return true;
}

template <typename L, typename F>
static bool reduceLevels(uint256 &hash, const std::vector<L> &levels, F f) {
    for (const auto &l : levels) {
        HashWriter ss{};
        ss << hash;
        ss << l.pubkey;
        hash = ss.GetHash();

        if (!f(l)) {
            return false;
        }
    }

    return true;
}

template <typename L>
static bool reduceLevels(uint256 &hash, const std::vector<L> &levels) {
    return reduceLevels(hash, levels, [](const L &) { return true; });
}

ProofId Delegation::getProofId() const {
    return limitedProofid.computeProofId(proofMaster);
}

const CPubKey &Delegation::getDelegatedPubkey() const {
    if (!levels.empty()) {
        return levels.back().pubkey;
    }
    return proofMaster;
}

DelegationId Delegation::computeDelegationId() const {
    uint256 hash = getProofId();
    reduceLevels(hash, levels);
    return DelegationId(hash);
}

bool Delegation::verify(DelegationState &state, CPubKey &auth) const {
    uint256 hash = getProofId();
    const CPubKey *pauth = &proofMaster;

    if (levels.size() > MAX_DELEGATION_LEVELS) {
        return state.Invalid(DelegationResult::TOO_MANY_LEVELS,
                             "too-many-levels");
    }

    if (levels.size() >= 2) {
        lotus::v2::BatchSigCollector collector;
        collector.Reserve(levels.size());
        for (size_t i = 0; i < levels.size(); ++i) {
            const Level &l = levels[i];
            HashWriter ss{};
            ss << hash;
            ss << l.pubkey;
            hash = ss.GetHash();

            if (!collector.AddLegacySchnorr(
                    std::span<const uint8_t>{pauth->data(), pauth->size()},
                    std::span<const uint8_t>{l.sig.data(), l.sig.size()},
                    hash.begin())) {
                if (!collector.Empty() && !collector.VerifyAll()) {
                    const size_t idx = collector.FirstFailingIndex().value_or(0);
                    auth = (idx == 0) ? proofMaster : levels[idx - 1].pubkey;
                } else {
                    auth = *pauth;
                }
                return state.Invalid(DelegationResult::INVALID_SIGNATURE,
                                     "invalid-signature");
            }
            pauth = &l.pubkey;
        }

        if (collector.VerifyAll()) {
            auth = *pauth;
            return true;
        }

        const size_t idx = collector.FirstFailingIndex().value_or(0);
        auth = (idx == 0) ? proofMaster : levels[idx - 1].pubkey;
        return state.Invalid(DelegationResult::INVALID_SIGNATURE,
                             "invalid-signature");
    }

    bool ret = reduceLevels(hash, levels, [&](const Level &l) {
        if (!pauth->VerifySchnorr(hash, l.sig)) {
            return state.Invalid(DelegationResult::INVALID_SIGNATURE,
                                 "invalid-signature");
        }

        // This key is valid, now up to the next delegation level.
        pauth = &l.pubkey;
        return true;
    });

    auth = *pauth;
    return ret;
}

} // namespace avalanche
