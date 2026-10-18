// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_HEADER_ADMISSION_H
#define LOTUS_V2_HEADER_ADMISSION_H
#include "disk_block.h"
namespace lotus::v2 {
enum class HeaderAdmission { Stored, Known, MissingParent, Invalid, StorageError };
// Deterministic header-only admission. Roots and size are commitments, not body
// validation results. Caller serializes store access and bounds announced headers.
// Clock eligibility and peer resource policy remain separate; no wall-clock read.
// Requires an initialized indexed development store and exact validator profile.
HeaderAdmission AdmitDevelopmentHeader(
    const Header &, const HeaderChainProfile &, const OrdinaryCandidateProfile &,
    const MonetaryProfile &, const BlockCostProfile &, DiskStateStore &,
    std::string &error);
} // namespace lotus::v2
#endif
