// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_REORG_RECOVERY_H
#define LOTUS_V2_REORG_RECOVERY_H
#include "disk_body.h"
#include <functional>
namespace lotus::v2 {
struct ReorgProfiles {
    HeaderChainProfile header;
    OrdinaryCandidateProfile ordinary;
    MonetaryProfile monetary;
    BlockCostProfile cost;
};
struct ReorgLimits {
    ForkLimits fork; // Count limits and total preparation/index-check Gets.
    uint64_t max_body_bytes{};
    uint64_t max_total_body_bytes{};
    uint64_t max_journal_bytes{};
    uint64_t max_undo_bytes{};
    uint64_t max_total_undo_bytes{};
};
enum class ReorgBodyResult { Found, Missing, CapacityRefused, Error };
// Must return only the named body's bytes within the authorized cap. The source
// cannot mutate the chainstate. Full contextual validation occurs at connect.
using ReorgBodySource = std::function<ReorgBodyResult(
    const Hash &, uint64_t, std::vector<uint8_t> &, std::string &)>;
enum class ReorgPhase : uint8_t {
    DisconnectSource = 0,
    ConnectTarget = 1,
    RollbackTarget = 2,
    RestoreSource = 3
};
struct ReorgProgress {
    Hash attempt{}, source{}, target{}, fork{}, current{}, failed_block{},
        source_failure_block{};
    // Bounded diagnostic prefix; fixed space is reserved at preparation.
    std::string operational_error;
    uint64_t revision{}, detached{}, connected{}, restored{};
    ReorgPhase phase{ReorgPhase::DisconnectSource};
    bool replacement_invalid{};
};
enum class ReorgResult {
    Idle,
    Prepared,
    Progress,
    CompleteTarget,
    RestoredSource,
    MissingBody,
    InvalidBody,
    Deferred,
    NotHeavier,
    CapacityRefused,
    StaleTip,
    StorageError,
    Inconclusive,
    ExcludedTarget
};
// Requires a fresh indexed home with explicitly configured recovery creation
// caps. J embeds all pinned bodies; its total cap bounds repeated
// serialization, not just one body. Single writer; no global candidate
// selection or wall clock.
ReorgResult PrepareDevelopmentSwitch(const Hash &expected_source,
                                     const Hash &target, uint64_t now,
                                     uint64_t future_window,
                                     const ReorgLimits &, const ReorgProfiles &,
                                     const ReorgBodySource &, DiskStateStore &,
                                     ReorgProgress &, std::string &,
                                     bool allow_parked_source = false);
// At most one full block connect/disconnect per call. Journal-only phase
// changes and completion also consume a call. Forward steps gate all target
// ancestors; rollback/restoration use deterministic validation without a new
// clock gate. On storage failure reopen and reread J before deciding which
// batch committed. Inconclusive leaves the durable checkpoint and output
// unchanged; address the local execution limitation before retrying. It never
// publishes a replacement-invalid classification.
ReorgResult StepDevelopmentSwitch(uint64_t now, uint64_t future_window,
                                  const ReorgLimits &, const ReorgProfiles &,
                                  DiskStateStore &, ReorgProgress &,
                                  std::string &);
// No mutation. Idle means no pending J. Other failures leave out unchanged.
ReorgResult ReadDevelopmentSwitch(const ReorgLimits &, const ReorgProfiles &,
                                  const DiskStateStore &, ReorgProgress &,
                                  std::string &);
} // namespace lotus::v2
#endif
