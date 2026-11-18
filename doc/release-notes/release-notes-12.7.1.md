# Lotus 12.7.1 Release Notes

Lotus 12.7.1 is a required upgrade for the Winter Solstice 2026 network
upgrade, the **2nd Kings** epoch. It follows the consensus rules of
LotusiaStewardship/lotusd 12.0.0 exactly, so nodes running either release stay
on the same chain. Nodes that do not upgrade split from the network when 2nd
Kings activates.

Lotus version numbers are major.RPC.security. The major number changes when
nodes that do not upgrade would split from the network. The second number
changes with the RPC interface, and the third with security fixes. This
release changes the consensus rules and adds NNG RPC endpoints, so both the
major and the second number change: it follows 11.6.1 as 12.7.1.

## Upgrade before 2026-12-21 20:50 UTC

| Network | 2nd Kings activates     | Value        |
| ------- | ----------------------- | ------------ |
| Mainnet | 2026-12-21 20:50 UTC    | `1797886200` |
| Testnet | 2026-11-30 20:50 UTC    | mainnet − 21 days |
| Regtest | same as mainnet         |              |

Activation happens when the median time of the last 11 blocks reaches that
time, so it can arrive about an hour after the clock time. 12.7.1 nodes and
11.6.x nodes agree on every block before then, with one exception: 12.7.1
rejects a coinbase that does not commit the block height, as described below.
Nodes can be upgraded in any order before activation.

## Coinbase height commitment restored (security fix)

The first output of every coinbase must again start with `OP_RETURN "logos"
<height>`. Lotus 8.3.4 loosened this rule: from height 1,018,000 a coinbase
whose first output did not carry the `logos` prefix was accepted without any
height check. Because the coinbase input script is not part of a Lotus
transaction ID and there is no BIP30 check, the height commitment is what
keeps coinbase transaction IDs unique. Without it, a miner could create a
coinbase with the same ID as an earlier one and overwrite its unspent
outputs (the class of bug fixed in Bitcoin by BIP30, CVE-2012-1909).

The check takes effect when a node runs 12.7.1; it does not wait for 2nd
Kings. It rejects nothing historical: every block on the chain from height 1
to the tip commits its height (heights 1..16 as `OP_1`..`OP_16`, which is
what the miner emits for those values), so no block mined under the loose
rule exists. From 12.7.1, a block whose first coinbase output does not begin
with `OP_RETURN "logos" <height>` is rejected with `bad-cb-height`. Data
after the height is still allowed.

Until 2nd Kings activates this is the one rule where 12.7.1 and 11.6.x
disagree: 11.6.x still accepts a coinbase without the commitment, and
LotusiaStewardship/lotusd 12.0.0 accepts one until 2nd Kings. After
activation all of them reject it.

## Consensus changes at 2nd Kings

### New miner fund address

From activation, every block's coinbase must pay half of the block reward to a
single address:

    lotus_16PSJPVHNWEF4t1nSFefhth6HAtqn6oripT4k9iNv

It replaces the 1st Kings address (`lotus_16PSJQXrnTrUbhnxPpPgf1jd16JFkWk8TdbpALVME`).
Blocks that pay any earlier address set are rejected with `bad-cb-minerfund`.
Mining software that builds its own coinbase must be updated; `getblocktemplate`
and the built-in miner already include the new output.

### Replay protection moves to 1st Chronicles

Lotus 11.6.1 and older switch to the replay-protected signature fork value at
2nd Kings; after that they treat every signature made by ordinary wallets as
invalid. 12.7.1 does not switch at 2nd Kings: replay protection now activates
at the next scheduled upgrade, **1st Chronicles**, 2027-06-21 14:10 UTC
(`firstChroniclesActivationTime` = `1813587000`; testnet 2027-05-31 14:10 UTC).

A node left on 11.6.1 therefore stops following the network at 2nd Kings in
two ways: it rejects blocks with ordinary wallet transactions, and it does not
require the new miner fund output. If such a node has already rejected a
block, run `lotus-cli reconsiderblock <hash>` with the hash of the first
rejected block after upgrading.

1st Chronicles has no rules of its own yet. 12.7.1 nodes will make the
replay-protection switch at that time, so the network needs another release
before 2027-06-21.

## NNG interface

- The `-nngrpc`, `-nngpub` and `-nngpubmsg` options work again. Lotus 11.6.0
  and 11.6.1 lost their registration, so a node started with any of them
  stopped at startup with "Invalid parameter".
- Lotus now builds against NNG 1.x and NNG 2.x. The bundled `depends` build
  uses NNG 2.1.0 (previously 1.5.2).
- New stratum mining endpoints for external pool coordinators, compatible
  with LotusiaStewardship/lotusd: the `GetMiningTemplateRequest` RPC returns
  a block template with the coinbase split around reserved extranonce space,
  the coinbase merkle branches and Stratum-ordered header fields, and the
  `miningwrkchg` pub topic (`-nngpubmsg=miningwrkchg`) signals new tips,
  reorgs and mempool changes. See `doc/nng.md`.

## Network

- The mainnet DNS seed is now `seed.lotusia.org`, the Lotus network's seeder.
  Earlier releases listed eCash seeders, so a fresh node found Lotus peers
  only through the fixed seeds.
- `-version` and the license text now point to
  https://github.com/LotusiaStewardship/lotusd and https://www.lotusia.org.

## Historical rules aligned with the network

Three rules for old blocks now match the values the network runs. They only
matter for a reorganisation back past 2024 or 2022; no block on the current
chain is affected.

- The Judges upgrade time is 2024-06-20 20:51 UTC (`1718916660`), not
  20:50.
- Taproot and `SIGHASH_LOTUS` spends are invalid in all blocks before 2nd
  Samuel, including those before Numbers.
- Blocks with Taproot outputs are invalid before 2nd Samuel, including those
  before Numbers. Mainnet's first Taproot output is at height 1,189,230,
  after 2nd Samuel.

## Other notes

- Hidden options for testing: `-secondkingsactivationtime` overrides the 2nd
  Kings time and `-replayprotectionactivationtime` the replay-protection time.
  `-firstchroniclesactivationtime` is accepted but has no effect yet. Do not
  set them on mainnet.
- The consensus changes are ported from LotusiaStewardship/lotusd 12.0.0
  (commit 9706858859, by Matthew (maff1989)).
