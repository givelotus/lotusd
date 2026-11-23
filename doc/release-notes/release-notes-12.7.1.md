# Lotus 12.7.1 Release Notes

Lotus 12.7.1 is a required upgrade for the Winter Solstice 2026 network
upgrade, the **2nd Kings** epoch. It follows the consensus rules of
LotusiaStewardship/lotusd 12.0.0, plus the chain fork id replay protection
described below. Nodes that do not upgrade split from the network when 2nd
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
11.6.x nodes agree on every block before then, so nodes can be upgraded in
any order before activation.

## Consensus changes at 2nd Kings

### New miner fund address

From activation, every block's coinbase must pay half of the block reward to a
single address:

    lotus_16PSJPVHNWEF4t1nSFefhth6HAtqn6oripT4k9iNv

It replaces the 1st Kings address (`lotus_16PSJQXrnTrUbhnxPpPgf1jd16JFkWk8TdbpALVME`).
Blocks that pay any earlier address set are rejected with `bad-cb-minerfund`.
Mining software that builds its own coinbase must be updated; `getblocktemplate`
and the built-in miner already include the new output.

### Coinbase height commitment restored (security fix)

The first output of every coinbase must again start with
`OP_RETURN "logos" <height>`. Lotus 8.3.4 loosened this rule: from height
1,018,000 a coinbase whose first output did not carry the `logos` prefix was
accepted without any height check. Because the coinbase input script is not
part of a Lotus transaction ID and there is no BIP30 check, the height
commitment is what keeps coinbase transaction IDs unique. Without it, a
miner could create a coinbase with the same ID as an earlier one and
overwrite its unspent outputs (the class of bug fixed in Bitcoin by BIP30,
CVE-2012-1909).

From activation, a block whose first coinbase output does not begin with
`OP_RETURN "logos" <height>` is rejected with `bad-cb-height`. Data after the
height is still allowed. Blocks mined before activation under the loosened
rule remain valid.

### Replay protection at 2nd Kings uses the Lotus chain fork id

From activation, every signature commits to the Lotus chain fork id
`CHAIN_FORK_ID = 0x4c4f54` ("LOT"), defined in `src/script/sighashtype.h`.
`SignatureHash` uses it whenever `SCRIPT_ENABLE_REPLAY_PROTECTION` is set, in
place of the stock `forkValue ^ 0xdead | 0xff0000` transform. It applies
before the signature algorithm is chosen, so it covers legacy, BIP143 and
`SIGHASH_LOTUS` signatures.

The separation is two-way. A signature made for Lotus is invalid on any chain
that uses another fork id, including one that activates the stock `0xffdead`
value, and a signature made for such a chain is invalid on Lotus.

`lotus-tx` is offline and has no median time past, so it takes the fork id
explicitly: `-forkid=0x4c4f54` commits the chain id, and the default
`-forkid=0` keeps pre-activation signatures.

The default activation is `secondKingsActivationTime` (`1797886200`).
`-replayprotectionactivationtime` still overrides it for testnet and regtest.
`firstChroniclesActivationTime` (`1813587000`) now only marks the next
scheduled epoch, **1st Chronicles**, 2027-06-21 14:10 UTC, which has no rules
of its own.

After activation, signatures with fork value 0 are invalid. Lotus 11.6.1 and
older, and any node without the chain fork id, therefore stop following the
network at 2nd Kings. A node left on 11.6.1 also does not require the new
miner fund output. If such a node has already rejected a block, run
`lotus-cli reconsiderblock <hash>` with the hash of the first rejected block
after upgrading.

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
- The chain fork id replay protection is ported from LotusiaStewardship/lotusd
  (commits 5463ed8ce, 54739e491, ff7ae63fb and 17cbfbf9f, by Matthew
  (maff1989)).
