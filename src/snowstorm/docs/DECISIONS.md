# Snowstorm implementation decisions

## Finite syndrome fingerprints do not prove arbitrary-set truth

The cell's count and GF(2^64) moments x, x^3, x^5 are finite fingerprints.
Passing a singleton/pair decode's algebraic, schedule and membership checks
is not a deterministic proof that it is an element of an arbitrary larger
underlying difference. Host body validation remains a separate requirement.
No probability bound or protocol safety theorem is established here.

During Session development, a supplemental fixture used consecutive explicit
IDs12001 through12010, alternating positive/negative signs. Independent direct
field arithmetic, a Gaussian solver and an exact binary-search schedule
reproduced the failing trace: +12009; −12008,−12010; +12000; −12002,−12006;
then attempted repeated +12002,+12006. The positive12000 was an algebraically
valid singleton alias from a seven-item source residual. The engine correctly
returned recoverable inconsistent_symbols on the repeated claim; raw/reference
reconstruction did not drift. An aligned affine octet such as12000..12007 has
zero XOR of these moments and can have zero signed count.

The exact consecutive-ID fixture is retained as a negative structural-alias
regression, expecting bounded recoverable inconsistency rather than universal
convergence. The separate600 supplemental convergence trials retain all six
difference sizes and100 trials each, but derive IDs with the real short_id
function from canonical fixture transaction hashes and a deterministic fresh
per-trial key. This corrects an unsupported fixture expectation, not the
production algorithm. Frozen acceptance tests were not altered. Full frozen
Node tests remain required and are not replaced by these supplemental tests.

Independent diagnostic provenance: scratch DIAG-session-model-20261026.md and
its independent code/JSON, plus session-model and session-model-diagnosis logs.
The pre-correction scratch fixture SHA256 is
fdbe0dc6c3d9b6b5cfd959c15074a7bd2fd6796551879ffea89cdae5b623755d.
The Session handoff records the corrected and negative fixture hashes and runs.
This limitation must remain explicit in evaluation and paper review.

## Session ownership and hot callbacks

SessionRequest owns exactly one logical request and checked RTT/deadline state.
SessionResponder owns one Store pin and its immutable raw-body, candidate-body,
root and exclusion metadata; expiry releases all dynamic metadata. Node must
sweep responder owners immediately when Store expires pins.

SessionModel captures Pending at open without constructing a peeler. Before a
root-mismatch path uses the model, explicit preparation constructs/reserves the
engine from the current own/plus/minus reference. Own removals while waiting
are retained in plus. RootMatched can therefore close without constructing a
peeler. Done releases engine storage and compacts membership while preserving
its reference. Node owns wave evidence lifetimes and clears the model after
its last permitted scoring wave; it must discover donors before compaction.

Private Peeler observers are borrowed for one run, execute only after a whole
One/Two has committed, and cannot allocate, invoke host code or reenter engine
mutation. SessionModel updates plus/minus and asserts the actual reference
before forwarding the committed audit. Rejecting/resource checks stay in the
precommit policy. The later Node omitted-minus-erasure mutation remains a
separate mandatory proof; an observer-only test cannot replace it.
