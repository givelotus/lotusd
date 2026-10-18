# Explicit offline development command

`lotusd -lotusv2development MANIFEST DATADIR status`
initializes or reopens the exact caller-supplied development chain.
`submit BLOCK_FILE` validates and atomically connects a complete block;
`disconnect EXPECTED_TIP_HEX` validates and applies its undo, refusing genesis.
These positional commands start no socket, RPC server, Chronik, or inherited
chainstate. The flag must be the first argument. No network profile is selected
by default. This is not peer synchronization or a usable public testnet.

The required datadir is a dedicated namespace containing only
`lotus-v2-development.identity` and `chainstate-v2`. Existing unrelated or inherited
data directories and symlink entries are refused. The marker binds ChainID,
exact genesis and the validator profile. An interrupted `.initializing` directory
or missing/incomplete marker fails closed for explicit recovery; marker file
creation is not fsynced and no automatic namespace recovery is claimed. LevelDB
state transitions retain their separate synchronous-batch durability contract.

Exit status: 0 success, 1 command/configuration/local file failure, 2 invalid
submitted block, 3 time-deferred block, 4 storage or disconnect refusal. JSON
records distinguish these outcomes. A poisoned store reports `tip_known=false`
and `reopen_required=true` without claiming a durable cached tip. Ordinary status
and success report native byte-order BlockID/roots and height. Local clock UTC
seconds drives eligibility; the window is supplied in the manifest.

## Manifest schema 2

Every listed key is required; extra, missing and duplicate object keys reject.
Unsigned integers may be decimal JSON numbers or decimal strings; fractions,
signs, leading zeros and overflow reject. Hex strings are lowercase byte order
as serialized, not display-reversed Bitcoin hashes.

- `schema`: 2.
- `tail_formula_version`: 1 (absolute genesis-anchored tail).
- `header`: exact `chain_id`, `genesis_id`, `version`, `time`, `bits`, `pow_limit`,
  `half_life`, `spacing`. Hashes/limit are 32-byte hex; timing arguments are
  positive signed-64-compatible integers. No ASERT constants are selected here.
- `transaction_limits`: seven values, in TxProfile order: inputs, outputs, mints,
  script bytes, arguments, argument bytes, branch proof depth.
- `vm_limits`: eight values: script bytes, arguments, element bytes, main stack
  items, alt stack items, total VM bytes, AST depth, host step guard.
- `invocation_limits`: invocation cost cap (u128), aggregate cap (u128), structural
  byte cost (u64). All 256 `opcode_costs` entries are `[base, operand_byte,
  result_byte]`; assigned opcode bases must be positive.
- `field_sizes`: array of `[opcode, [sizes...]]` entries, without duplicate
  opcodes; the execution engine validates allowed hints and bounds.
- `monetary`: twelve values in MonetaryProfile order: boot shift, transaction knee
  shift, EMA shift, EMA minimum, linear shift, quadratic shift, tail minimum,
  tail maximum, dust, minimum fee per kB, genesis tail, genesis work (32-byte little-endian hex).
- `outer_costs`: hash base, hash byte, resolved byte, asset comparison.
- `initial_monetary`: canonical 56-byte hex. `genesis`: full block hex.
- `coinbase_maturity`, `dust_limit`: explicit ordinary profile inputs; dust must
  agree with the monetary profile.
- `future_window`: external clock eligibility window in seconds.
- `block_read_limit`: positive local file capacity. Refusal is an operational
  command error, not a consensus block-size ceiling. Config files have a local
  8 MiB read cap. Native host-work guards remain an explicit operational profile
  limitation and need care before public deployment.

## Reproduce against the documented proposal

First explicitly generate the reference parameter/manifest artifacts using the
monorepo development-profile document's reproduction program. Conversion checks
their recorded parameter SHA256. It never changes the reference expected result.
Pass the native host-step guard and local read capacity explicitly:

```
python3 convert_profile.py --parameters PARAMETERS --reference REFERENCE_JSON \
  --output-dir NEW_ARTIFACT_DIR --max-steps HOST_GUARD --block-read-limit LOCAL_CAP
python3 verify.py --daemon /absolute/path/lotusd \
  --manifest NEW_ARTIFACT_DIR/manifest.json --reference REFERENCE_JSON \
  --first-block NEW_ARTIFACT_DIR/first.block --work-dir NEW_EVIDENCE_DIR
```

The verifier uses separate processes for genesis, submit, reopen, disconnect,
reconnect and rejection. It checks reference identities/state roots, refuses
legacy-looking disposable directories without changing their contents, and
checks malformed manifests. Both generation and test directories must be new;
failures and exact command output remain available for review. A proposal tested
this way is not an adopted network profile or publication authorization.

Absolute tail migration (2026-10-15): manifests now require `schema:2` and `tail_formula_version:1`. The monetary array has twelve entries: the original ten, followed by explicit `genesis_tail` (u64 JSON number) and `genesis_work` (32-byte little-endian hex). The initial state must match these anchors. Schema 1 and incompatible existing home identities fail without reset. The conversion tool requires `tail_formula_version:1`, `genesis_tail` and `genesis_work` in the source parameters and checks their equality to explicit initial values; it never infers an anchor from an arbitrary parent state.
