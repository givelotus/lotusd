// Copyright (c) 2026 The Lotus developers
#ifndef LOTUS_V2_CHRONIK_SYNC_H
#define LOTUS_V2_CHRONIK_SYNC_H
#include "development_runtime.h"
#include "chronik_explorer.h"
namespace lotus::v2 {
struct ChronikAnchor {
    Hash block_id{};
    uint64_t height{};
    bool operator==(const ChronikAnchor &) const = default;
};
struct ChronikInput {
    Hash txid{};
    uint32_t out_idx{}, input_index{};
};
struct ChronikTransaction {
    Hash txid{}, txhash{};
    uint32_t index{};
    std::vector<uint8_t> wire;
    uint64_t lock{};
    std::vector<ChronikFullInput> full_inputs;
    std::vector<ChronikInput> inputs;
    std::vector<std::vector<uint8_t>> outputs;
};
struct ChronikBlock {
    ChronikAnchor anchor, parent;
    std::array<uint8_t, HEADER_SIZE> header_wire{};
    std::vector<ChronikTransaction> transactions;
};
// Checkpoint must come from durable index state, including after restart.
// Implementations throw on errors. Successful operations are durable/atomic.
class ChronikSink {
public:
    virtual ~ChronikSink() = default;
    virtual std::optional<ChronikAnchor> Checkpoint() = 0;
    virtual void Initialize(const ChronikBlock &) = 0;
    virtual void Connect(const ChronikBlock &) = 0;
    virtual void Disconnect(const ChronikAnchor &) = 0;
};
enum class ChronikSyncResult { Progress, Ready, Unavailable, Error };
// Single owner; caller serializes runtime, sync and sink. Invalidate HTTP
// BEFORE any runtime transition, and publish AFTER Step returns Ready, tied to
// the runtime context generation and stable tip. Never retain readiness across
// a runtime mutation. Index errors only affect query availability. Each Step
// performs <=2 active header queries (each returns <=1 header), or one
// active query plus one genesis header read; one creation-capped runtime
// snapshot, at most one
// max_body_bytes body, and performs <=1 durable index operation. Active-height
// lookups retain at most one returned header per query, never a full path.
// Catchup and divergent-suffix removal use linear step counts. Runtime/sink
// lifetimes exceed this object. Genesis bytes are served through
// ReadConnectedBody, never from an unauthenticated caller buffer.
class ChronikSync {
public:
    ChronikSync(DevelopmentRuntime &, ChronikSink &, ChainId, TxProfile,
                uint64_t max_body_bytes);
    ChronikSyncResult Step(std::string &error);

private:
    DevelopmentRuntime &runtime_;
    ChronikSink &sink_;
    ChainId chain_;
    TxProfile profile_;
    uint64_t max_bytes_;
};
// Structural conversion additionally authenticates the exact native block id
// and ordered transaction root. Exports the exact header and complete frames,
// all input selectors/witness locations, and every output including burns.
// The compatibility inputs subset contains spends with native input ordinals.
// Historical spend coins are resolved exclusively by the durable DB owner.
bool MakeChronikBlock(const std::vector<uint8_t> &, const ChainId &,
                      const TxProfile &, const ChronikAnchor &, ChronikBlock &,
                      std::string &);
} // namespace lotus::v2
#ifdef LOTUS_V2_CHRONIK_CXX
#include "chronik_lib/src/v2_ffi.rs.h"
namespace lotus::v2 {
class CxxChronikSink final : public ChronikSink {
public:
    explicit CxxChronikSink(const chronik_v2::V2Service &service)
        : service_(service) {}
    std::optional<ChronikAnchor> Checkpoint() override;
    void Initialize(const ChronikBlock &) override;
    void Connect(const ChronikBlock &) override;
    void Disconnect(const ChronikAnchor &) override;

private:
    const chronik_v2::V2Service &service_;
};
} // namespace lotus::v2
#endif
#endif
