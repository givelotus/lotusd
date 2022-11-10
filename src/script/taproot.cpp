// Copyright (c) 2021 Logos Foundation
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <hash.h>
#include <pubkey.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/taproot.h>

static const CHashWriter HASHER_TAPLEAF = TaggedHash("TapLeaf");
static const CHashWriter HASHER_TAPBRANCH = TaggedHash("TapBranch");
static const CHashWriter HASHER_TAPTWEAK = TaggedHash("TapTweak");

bool VerifyTaprootCommitment(uint256 &tapleaf_hash,
                             const valtype &control_block,
                             const valtype &commitment,
                             const CScript &exec_script) {
    const int path_len = (control_block.size() - TAPROOT_CONTROL_BASE_SIZE) /
                         TAPROOT_CONTROL_NODE_SIZE;

    // Calculate merkle root
    CHashWriter tapleaf_hasher = HASHER_TAPLEAF;
    tapleaf_hasher << uint8_t(control_block[0] & TAPROOT_LEAF_MASK)
                   << exec_script;
    tapleaf_hash = tapleaf_hasher.GetSHA256();
    uint256 merkle_hash = tapleaf_hash;
    const uint8_t *control_nodes =
        control_block.data() + TAPROOT_CONTROL_BASE_SIZE;
    for (int i = 0; i < path_len; ++i) {
        CHashWriter ss_branch = HASHER_TAPBRANCH;
        Span<const uint8_t> node(control_nodes + TAPROOT_CONTROL_NODE_SIZE * i,
                                 TAPROOT_CONTROL_NODE_SIZE);
        if (std::lexicographical_compare(merkle_hash.begin(), merkle_hash.end(),
                                         node.begin(), node.end())) {
            ss_branch << merkle_hash << node;
        } else {
            ss_branch << node << merkle_hash;
        }
        merkle_hash = ss_branch.GetSHA256();
    }

    // Extract internal pubkey from the control block
    // Note: We're not using the X-only pubkeys, unlike as in Bitcoin Core.
    // There, commitment is 32 bytes, not 33 and the parity of the commitment is
    // then encoded in the first bit of the first byte of the control block.
    // We don't need to do that as we're using 33 byte pubkeys. Instead, we just
    // encode the parity of the internal pubkey in that first bit of the first
    // byte of the control block.
    valtype vch_p(control_block.begin(),
                  control_block.begin() + TAPROOT_CONTROL_BASE_SIZE);
    // Parity of internal pubkey is encoded in the first bit
    vch_p[0] = vch_p[0] & 1 ? 0x03 : 0x02;
    const CPubKey p{vch_p};
    const uint256 tweak_hash =
        (CHashWriter(HASHER_TAPTWEAK) << MakeSpan(p) << merkle_hash)
            .GetSHA256();

    // Verify commitment matches
    const CPubKey q{commitment};
    CPubKey q_expected;
    if (!p.AddScalar(q_expected, tweak_hash)) {
        return false;
    }
    return q == q_expected;
}

bool IsPayToTaproot(const CScript &script) {
    if (script.size() < TAPROOT_SIZE_WITHOUT_STATE) {
        return false;
    }
    // Taproot must start with OP_SCRIPTTYPE OP_1
    if (script[0] != OP_SCRIPTTYPE || script[1] != TAPROOT_SCRIPTTYPE) {
        return false;
    }
    // First push (commitment) must be 33 bytes long
    if (script[2] != CPubKey::COMPRESSED_SIZE) {
        return false;
    }
    // If there's only a commitment but no state, we're valid
    if (script.size() == TAPROOT_SIZE_WITHOUT_STATE) {
        return true;
    }
    // Otherwise, we need a state with 32 bytes.
    return script.size() == TAPROOT_SIZE_WITH_STATE &&
           script[TAPROOT_SIZE_WITHOUT_STATE] == CSHA256::OUTPUT_SIZE;
}

bool TxHasPayToTaproot(const CTransaction &tx) {
    for (CTxOut output : tx.vout) {
        if (IsPayToTaproot(output.scriptPubKey)) {
            return true;
        }
    }
    return false;
}
