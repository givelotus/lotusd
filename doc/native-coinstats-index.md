# Native CoinStatsIndex accounting

This index/RPC extension is introduced only in the Lotus V2 layer. It does not
change shared eCash behavior, consensus, or the canonical native Coin hash.
Created Coins hash their accepted paid fee share and effective expiration;
expired Coins are removed using the complete durable `CBlockUndo::vexpired`
record and restored with that same metadata on disconnect. Same-block-created
and-spent outputs do not enter the final-set hash. Reindex and historical sync
use block/undo records rather than the mutable current UTXO view.

`gettxoutsetinfo` indexed `block_info` adds:

- `unspendables.expired`: value of previously spendable outputs destroyed by the
  native deterministic expiry sweep. This is included in `unspendable` and
  `total_unspendable_amount`; it is not an ordinary transaction input or an
  unclaimed miner reward.
- `cleaning_bounty`: the additional cleaning reward allowed by the daemon's
  accepted `Chainstate::ConnectBlock` path, computed with the same existing
  `ComputeCleaningCrewBounty` helper and accepted transaction fees.

Writing I for ordinary transaction prevouts, S for subsidy, E for expired value,
B for cleaning bounty, O for new spendable non-coinbase outputs, C for spendable
coinbase outputs, and U for all unspendables (including E), the per-block ledger
is `I + S + E + B = O + C + U`. Existing `prevout_spent` and subsidy meanings are
unchanged. Unclaimed rewards exclude the explicit expired subset. Bounty is a
separate category; it is not silently counted as subsidy. The native standalone
monetary engine funds its bounty from fee burn instead of adding it to the daemon
reward allowance. This document describes the existing daemon path only and does
not reconcile that separate consensus-integration question.

The index database has an explicit native format version of 2. An unversioned
nonempty index, an unreadable version, or another version is rejected with an
actionable `-reindex` message. Earlier indexes can contain incorrect paid-Coin
roots and lack authenticated expiry/bounty counters; zero defaults are therefore
not safe. `-reindex` clears/rebuilds the index from accepted block and undo data.
This changes only the experimental native index format, not chainstate, blocks,
undo encoding, consensus commitments, or published data.

Focused component tests may synthesize a valid paid expiration height and durable
undo without mining the entire 131,400-block minimum lifetime. Such tests cover
the index component and are not natural-chain expiry consensus validation.
