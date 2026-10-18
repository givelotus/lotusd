// Copyright (c) 2026 The Lotus developers
#include "candidate_store.h"
#include "block_transition.h"
namespace lotus::v2 {
bool CandidateFailureFact::FromValidation(const DeterministicBlockFailure &proof,
                                         CandidateFailureFact &out) {
    if (!proof.Valid()) return false;
    out = CandidateFailureFact(proof.BlockId(), proof.ParentId(), proof.ProfileDigest(), proof.ParentRoot());
    return true;
}
} // namespace lotus::v2
