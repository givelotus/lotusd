# Chain configuration and mining capabilities

`getchainconfig` is the authoritative one-call discovery RPC. Schema version 1
returns these objects together, using the selected node parameters:

- `chain`: `family` (`bitcoin`), `kind` (`ecash` or `lotus-v2`), `network`,
  `genesis` (normal RPC hash hex), and stable `identifier` (`kind-network:genesis`).
  Lotus V2 also has its raw 32-byte `chainid`.
- `currency`: `ticker`, decimal-string `atomsperunit`, `rpcdecimals`, and
  `displaydecimals` (2). The RPC denomination comes from the same builder as
  `getcurrencyinfo`; amounts on the wire and consensus integer units do not change.
  Display policy must preserve nonzero atoms rather than rounding them away.
- `address`: current output `format` (`cashaddr` or `base58check`), CashAddr `hrp`,
  supported CashAddr `types` (0 pubkeyhash, 1 scripthash), `acceptedformats`, and
  raw hex `base58prefixes` (`pubkeyhash`, `scripthash`). These describe implemented
  codecs, not planned native MAST-address templates.
- `mining`: `pow` (below) and `testgeneration` (test-chain generation support).
- `features`: implemented `legacytransactions`, `nativetransactions`, and
  `message_signing` (`legacy-p2pkh`). Message signing does not imply native MAST
  message verification support.
- `node`: compiled `client` and numeric `version`, for diagnostics, not chain selection.

A client chooses its compiled ChainAdaptor using this explicit identity and
capability object, freezes one connection-scoped ChainConfig, and discards it
when changing node or network. It must reject unknown versions, unsupported
algorithms, inconsistent identity, and unknown required capabilities. No ticker
or header-length guessing, repeated polling, or remote executable code is needed.
Capabilities do not grant RPC authorization. `getmininginfo.pow` uses exactly the
same proof-of-work builder for clients that separately query mining statistics.

`getmininginfo.pow` is schema version 1, a read-only description of the
selected chain's mining format. Clients must implement and whitelist the named
algorithm; no field contains executable code. Unknown versions or algorithms
must be rejected. RPC authorization and normal consensus validation still apply.

For `sha256d`, hash exactly the first 80 header bytes twice with SHA-256.
The four-byte nonce starts at byte 76 and is little endian. Interpret the raw
32-byte digest as a little-endian integer when comparing it with the target.
RPC block hash strings use the reverse of those raw digest bytes.

`template_rpc` names `getrawunsolvedblock(address)`: obtain the complete block
from the node, preserve its transactions, coinbase and commitments, and change
only its nonce. `submit_rpc` names `submitblock(blockhex)`; the node validates
the result. The descriptor reports `targetbyteorder: "big"` because the template's
64-character `target` string is a big-endian hexadecimal integer. It is distinct
from `hashbyteorder: "little"`. Clients should check that the target agrees with
the compact target in the supplied header before starting work.

The descriptor is separate from `getcurrencyinfo`: currency symbols and display
precision do not identify a proof-of-work algorithm. Network identity remains
`getmininginfo.chain`. This interface changes no chain parameters or consensus.
