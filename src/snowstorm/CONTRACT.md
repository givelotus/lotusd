# Snowstorm executable contract

This directory contains the public contract, independent test oracles, deterministic host and acceptance suite for the new reconciliation core. Contract authoring does not implement the library. The implementation must be written by a different agent after the complete artifact review and freeze gate.

The authoritative specification is the uniquely marked section of the parent repository's `docs/lotus-v2/snowstorm.md`. Its marker-inclusive SHA256 for this separately reviewed correction is `71294dfcac0fad07ecc9fd0177ab9ad7b77e9c50d144333d75bd2e7bd947192c`. The original frozen marker hash `1adfb6b9859ac6cd580aa968a98aae0773654023e0456ccbbc44e387fabc4927` is retained as historical provenance. The intermediate artifact-review clarification hash `1a503dc8f606e97c82ee1a70d2a59c45ec382983a575f6caa5b0ea7407073cd6` remains preserved in the review history; the subsequent reviewed delta qualifies mandatory full acceptance auditing versus explicit simulator observation and defines transport-hook scope. The earlier preauthoring proposal hash `7ff645de6a46d3ffb0246c56c161da83315ab35aa0af0f4e1625faeb216d1cd6` remains historical approval provenance; the independent artifact review approved the precise prefreeze clarification delta before this replacement. Do not copy that specification into this submodule. Historical miniblock, geometric-decimation, SnapBlock and previous simulator results are not evidence for this core.

The original frozen source commit `becda82213b59cf11527bcd4a2f38c871fb2cc05` and manifest `f4c5b1786d968320a44d70e00006e28797c02994b0bb7f510f48fcea84751e24` remain immutable historical evidence. A concrete suspension/awaiting-admission overlap defect required this explicitly authorized separate correction: an already host-admitted body awaiting its notification must retain its token/hash/generation, reserved capacity and existing eligible Pending/Lambda when speculative work is suspended. The independent host now preserves that state, and an added six-subcase T12 regression covers callback and tip endings under three failure outcomes. All 102 original cases, counts and limits remain; no production implementation or public signature is changed by the correction. Revision validation and the new manifest/commit trust anchor are recorded separately; this does not retroactively validate the original contradiction or permit silently changing frozen files to fit an implementation.

## Ownership and implementation boundary

- `include/snowstorm/`: declarations and plain data types. No library function bodies beyond trivial plain-struct accessors. Every declaration cites the normative section it serves.
- `test/oracle/`: slow independent arithmetic, schedule, cell and operation-log models. These files must not include production public headers or implementation files. Their self-tests have hand-derived vectors and run before a library exists.
- `test/harness/`: reusable deterministic host owning real `SnowstormNode` instances. It supplies bytes, validated host outcomes, explicit time and public values. Ground truth stays here and in acceptance assertions, never inside a node.
- `test/acceptance/`: the `snowstorm_acceptance` Boost suite. It exercises the public contract, independent oracles and actual host model; it is not another protocol implementation.
- `test/CMakeLists.txt` and check scripts: protected registration, inventory, separation and cross-process checks.
- Future `src/`, `fuzz/`, `bench/` and `sim/`: implementation-stage work. No stub library may be introduced to make a preimplementation link succeed.

The core has one serialized owner. It cannot call IO, infer real time, inspect harness ground truth or identify adversaries through test labels. The caller-supplied RootFn is a pure canonical calculation only. Hot field/decode/peel/sketch-update methods must be implementable with preallocated workspace/output and no fresh heap allocation; allocating a value copy from `stats()` is outside those hot paths.

## Freeze trust boundary

`ACCEPTANCE.sha256` records hashes of the normative marker span; every API, oracle, oracle self-test, harness and acceptance source; the check scripts; complete acceptance build registration; and the marked registration spans in `src/CMakeLists.txt` and this directory's `CMakeLists.txt`. The exact manifest is generated only after the full file set and source compilation are stable.

The manifest cannot authenticate itself. Its independent trust anchor is the reviewed source commit and manifest digest recorded by the root coordinator and independent reviewer outside this manifest. A matching checker plus mutually edited manifest is not a trustworthy freeze. Review must invoke the recorded checker path directly and confirm the registered CTest tests still exist, rather than trusting discovery alone.

The checker requires exactly one standalone begin marker and one standalone end marker in the parent specification, in that order, both LF-terminated. The hash includes both marker lines and the final LF. Missing, duplicated, reversed or changed marker lines fail. Frozen directory inventory is exact: missing, changed and extra files fail. Registration spans are similarly unique and marker-inclusive. Unfrozen implementation insertion areas must not redirect or bypass frozen acceptance registration.

Use explicit `SNOWSTORM_SPEC_ROOT` for portable builds; Git-derived superproject/root discovery is a fallback, and absence of the parent specification is an error. Checker extraction scratch output belongs only under the parent worktree's ignored `.scratch/` directory. It must work while lotusd is a registered submodule and in the specified plain-files layout.

After freeze nobody, including the contract author, may change a frozen file to make an implementation pass. A demonstrated contract defect stops dependent work and is reported with evidence. Do not update hashes, weaken a test, lower a trial count or modify the marker span as an implementation workaround.

## Acceptance obligations

All tests retain their complete prescribed counts. Smoke runs are useful diagnostics but never acceptance evidence. Each randomized trial records a reproducible seed; fresh trials use distinct derived seeds. Failure output identifies the relevant trial, peer/session and observation.

| Test | Normative coverage | Required workload |
|---|---|---|
| T1 | §2 | Million multiply pairs, million inverses, million distinct pair solves, million trace-one rejections and million trace-zero roots; random batch inverse including size one; zero solve. |
| T2 | §4.1 | Exhaustive small 0/1/2-item sign/reference combinations; 100,000 each of 3/4/5-item random cells; million uniform random-cell postcondition checks. |
| T3 | §4.2 | 10,000 items over symbol positions 0–255; million items for frequencies at 1,2,4,8,16,64,256 within four standard deviations; independent exact integer schedule. |
| T4 | §4.3 | 10,000 random update sequences and random-range direct encodings. |
| T5 | §4.4 | Signed differences 0,1,2,3,10,100,1000,2000; 10,000 arbitrary residuals; grouped source-cell proof; operation bound 64*(difference+1)*symbols; constructive contradiction cycle. |
| T6 | §3/§5 | Interleaved logs, many pinned snapshots, release/expiry, rekey/reset, exact body-versus-ID collision semantics and every local boundary. |
| T7 | §5/§6 | 1,000 fresh trials each for differences 0,1,2,3,10,100,1000; 7,000 total; initial differences at most two require exactly one exchange. |
| T8 | §5/§6 | Ten consecutive changing-pool sessions with 0–5 changes per side before/during/between sessions; all eight removal reasons; callback-gap and no-double-update regressions. |
| T9 | §6/§7 | 5/20/100 nodes, 100 fully connected with rare repolls; invariant after every call; no-redecode and negative-assumption three-node cases. |
| T10 | §1/§3/§6/§7 | Real wire fake/real mixture; multiple failed donors, probation, wrong binding, local policy refusal, honest fallback after more than eight failures, stale callbacks and conservative rejection collision. |
| T11 | §4/§6 | 100,000 malformed/oversized/truncated inputs per wire message type; garbage/inconsistent cells, duplicates/reordering/unknown sessions, concurrent honest progress and exact terminal statuses. |
| T12 | §5/§6/§10 | Every allocation/cap boundary; honest headroom below 50%; 50-height 20-node soak with last-ten mean at most 1.1 times first-ten; 100-peer fixed-floor/complete-global-accounting check. |
| T13 | §8 | Exact 19/26/35/12 constants; six independently hand-computed finite values within 1e-9; full evidence/abstention/root-change/freeze semantics; support tails, small-population exhaustive checks and extreme valid epsilon. |
| T14 | §1/§9 | No core/API includes from tests, simulator, fuzz, benchmarks or archives; harness only passes public values and bytes. |
| T15 | §1/§9 | Complete byte-identical message/action transcripts twice in one process and across two independently launched processes. |
| T16 | §6/§8 | Two- and five-node 10%-loss runs; every captured wave deadline; underestimated RTT 1→3ms and larger jumps under zero/10% loss; late data without false vote freshness; expiry/resource recovery. |

Every actual Done is checked against its captured responder raw snapshot. Every honest RootMatched is checked against captured candidate ground truth and has no decode/continuation. The latter must never be called a raw-set proof. Honest excluded-extra and malicious root-echo fixtures enforce that distinction. Quiescent agreement and body validity are checked externally; the core never receives a ground-truth stopping condition.

The separately labelled same-session negative-to-positive adversarial trace establishes reachability and required malformed-session termination. It does not distinguish a correct peeler with a stale internal session minus entry when that model is immediately released. The implementation gate must independently inspect the postcommit Node reference transition and demonstrate that omitting minus erasure is caught by the postcommit reference invariant before cleanup. Passing the public trace alone is not that mutation proof.

A Two decode's audit preserves the original pair cell and membership bits. It is not checked as two fictitious singleton decodes. Per-call diagnostics include transient sessions closed before `stats()` and are bounded without silent truncation. Memory observations include retained capacities, padding, pins, Pending, donors, probation, unavailable/local-refused records, Actions and diagnostics; moving a peer-keyed map to a global owner does not exclude it from the node total.

## Build and evidence gates

`ENABLE_SNOWSTORM` defaults OFF. OFF configuration/build must add no Snowstorm targets, sources, dependencies or flags; compare with the saved prechange baseline. An identical binary is not claimed without reproducible-build evidence.

The registered ON targets are `snowstorm-oracle-self-tests`, `snowstorm-acceptance-objects`, `test-snowstorm` and `check-snowstorm`. The last includes acceptance, oracle and guard/process checks. Direct freeze verification is independent of CTest discovery:

```sh
cmake -DSNOWSTORM_SOURCE_ROOT=/absolute/path/to/daemon/lotusd \
  -DSNOWSTORM_SPEC_ROOT=/absolute/path/to/parent \
  -P /absolute/path/to/daemon/lotusd/src/snowstorm/test/check_frozen.cmake
```

Manifest rows use a 64-character lowercase SHA256, two spaces, and one of `file:<source-relative-path>`, `normative:docs/lotus-v2/snowstorm.md`, or `span:<source-relative-CMake-path>#<marker-id>`. Protected span IDs are `option`, `registration` and `test-registration`. Paths are relative to the indicated source or parent root; they never point into the permanent main checkout.

With ON, build the oracle-only executable and the acceptance object target explicitly. All acceptance translation units must compile against the declarations. Before implementation, attempting to link `test-snowstorm` must fail for absent Snowstorm library definitions; a compiler error, missing third-party dependency or stub-produced success is not the expected proof. After implementation, real linking and the complete suite must pass.

Independent artifact review precedes freeze and implementation. It recomputes hashes, runs oracle self-tests, compiles acceptance sources, checks the expected link failure, tests freeze tampering/extra-file detection with exact restoration, verifies OFF preservation and inspects every normative statement against a meaningful test. Passing the earlier proposal review alone does not pass this artifact gate.

The independent OFF proof configured and built lotusd, lotus-cli and test_bitcoin successfully. Its 663 target source/dependency/compile/link projections and 961 compile-command entries matched the prechange baseline. The check-bitcoin dependency ordering changed but its multiset did not; that canonicalization is recorded rather than mistaken for new graph edges. Evidence is under the parent `.scratch/orchestration/baseline-off/contract-off-*`. This establishes OFF graph/build preservation, not identical binaries.

The ON configuration and oracle-only CMake build passed. The resulting independent oracle executable passed 66,493 checks; the direct include-boundary guard passed. All fifteen acceptance/harness translation units compiled through the configured CMake/Ninja target graph. After the targeted artifact-review repairs, linking failed for exactly 83 absent `snowstorm::` symbols, with no unrelated undefined dependency; no stub implementation was supplied. These are preimplementation compilation checks, not acceptance behavioral results. Evidence is under the parent `.scratch/orchestration/contract-on/`. The repaired aggregate build and repeated oracle check passed; `repair-r1-*` retains the intermediate proof and `final-r2-*` records the transport/source-provenance repair checkpoint, and `body-r3-*` records the bounded body-service/physical-outcome extension and `body-r4-*` records the final exactly-once admission-notification repair. Final independent review and freeze checks remain required.

Root coordinates build commands, logs, exit status, source dirty state and binary/config hashes. Do not compile while another owner is editing its source. Long runs require bounded timeout, heartbeat and a recorded PID; empty successful output is not evidence. Exact commands and resulting source/parent hashes are recorded in the parent `.scratch/orchestration/` handoff, not invented here before execution.

## Scientific and integration limits

The finite T=25 threshold calibration is not an unlimited-height error guarantee, and completion-selected/reused evidence is not an unconditional fresh hypergeometric sample. Root votes do not authenticate transaction bodies. A finite sketch is not an injective proof for arbitrary sets. Short-ID collision buckets do not ensure complete body dissemination. Conservative rejection may suppress a later valid colliding body, which must produce an explicit diagnostic. Host-local policy refusal is not peer fraud and must not bypass normal admission.

These limitations must remain visible in simulator and paper results. Main evaluation uses 600 nodes/500 peers, with the full 200/32 small-network check, 50 trials and ten heights for every required scenario. R11/R12 are explicitly fresh-seed replication cohorts under mandatory Pending, not pooling ablations; R14 has both adversary variants. No old simulator measurement establishes new behavior.

The reusable host defaults to full per-call acceptance observation. Its explicit simulation observation mode omits automatic diagnostic copies and deep invariant replay, while retaining the same actual core calls, returned Actions and independent host truth; it is not continuous correctness evidence. Supplemental same-seed fixtures compare complete actual transcripts and truth across both modes.

Transport policy callbacks receive endpoint identities, bytes and explicit delivery-ready time. Policy-enabled scripted replies wait for their service-ready event before reserving link serialization, then apply the returned network delay or drop. The absent-policy path retains its existing seeded draw order. `Traffic.sent` and `Traffic.bytes` count actual Node Send actions; reverse scripted WireReply deliveries also affect delivered/dropped counters but are not included in those sent/byte counters. These counters alone are not total bidirectional wire accounting. A simulator requiring full link totals must instrument both directions through the transport policy and separately define transaction-body traffic and BodyRule service-delay costs.

The optional body-service policy models bounded request and service-ready response packets through the same directed transport queues, jitter and loss as reconciliation. It looks up donor availability only after request arrival, charges the declared modeled framing/body bytes, and delivers exactly one terminal token result: a response strictly before its captured deadline, or timeout at the deadline. Late, disconnected and stale packets retain physical arrival accounting without creating a second result or admission. The host operational payload cap is 16MiB per phase; this is not a native transaction limit or native codec claim. The legacy reliable BodyRule path is preserved for default acceptance fixtures and cannot substitute for the main campaign network costs.

Delivery observers report actual event time, separate scheduled arrival, endpoint generations, traffic class, token identity, physical bytes and application disposition. They retain no unlimited history and cannot mutate or reenter the host. Policy callbacks own service decisions; read-only observers never install BodyRules. Body operations retain only finite scheduled phase references, release them after draining, and do not accumulate completed-token tombstones. Replacing either policy while body phases remain active is rejected. Supplemental fixtures cover phase loss, deadline ties, late arrivals, ownership cancellation, shared queues, physical accounting, boundary validation, observer noninterference and full/light equivalence; these additions do not reduce any prescribed workload.

Later integration must use the new core, actual peer messages, actual host admission/removal, tip/reorg hooks and isolated real nodes. Compilation, this in-memory host or legacy Snowstorm paths cannot substitute for that proof. Runtime/build defaults remain OFF and ordinary validation/block fallback remain intact.
