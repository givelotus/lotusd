# Lotus V2 application message signing

## Scope and status

Candidate selected by the maintainer on 2026-10-20; provisional through
pre-launch testnet. This is an application proof of control of a recognized
single-key address, not a transaction signature, authorization to transfer
funds, or proof of control of arbitrary MAST policies. It changes no consensus
rules. Native transactions continue to use BIP340 Schnorr.

The eCash tier keeps exactly its existing Qt/daemon `signmessage`,
`verifymessage`, message magic and compact signature behavior. Lotus V2
uses the same RPC names and familiar three-field verification workflow,
with a distinct chain-bound message digest and native type-1 address check.
The PWA calls these existing RPCs through its ChainAdapter/wallet provider;
private keys remain in the node. Adapter identity comes from the node's
chain configuration, never an address-prefix rename or ticker heuristic.

## Exact signed digest

Let `message` be the exact UTF-8 bytes of the RPC message string, including
all spaces, newlines, tabs and embedded NULs. No trimming, Unicode
normalization, case conversion or line-ending conversion is permitted.

```
preimage = CompactSize(22) || UTF8("Lotus Signed Message:\n")
           || 0x01 || ChainID[32]
           || CompactSize(len(message)) || message
digest = SHA256(SHA256(preimage))
```

CompactSize uses shortest-form Bitcoin length encoding. ChainID bytes are
in the chain's defined raw digest order, not a displayed/reversed hex string.
The application version byte is 1; another interpretation requires another
version. The distinct prefix prevents transaction-signature reuse, and the
chain ID prevents cross-network/replay between chains with distinct IDs.
Regtest uses its explicitly defined all-zero chain ID. Nothing here silently
changes an actual chain ID or genesis.

## Signature envelope

The display value is canonical padded RFC 4648 Base64 of exactly 65 bytes:

```
header[1] || r[32 unsigned big-endian] || s[32 unsigned big-endian]
header = 27 + recovery_id + 4
```

`recovery_id` is 0–3; native type-1 proofs accept headers 31–34 only. This
is Bitcoin's compact recoverable ECDSA container, not DER/ASN.1. ECDSA is
secp256k1; require valid nonzero scalars r,s and `s <= n/2`. Signing uses the
existing low-S compact signing implementation. ABC's recoverable ECDSA
nonce generator uses RFC6979 with its exact 16-byte `ECDSA+Recovery  `
algorithm-personalization suffix (two trailing spaces). Independent signature
vectors must include it; it is nonce derivation, not message preimage bytes. High-S equivalents, invalid
headers/scalars, truncated/oversized encodings, whitespace in Base64 and
noncanonical Base64 spellings are rejected. No separate public-key field is
required: recovery supplies it.

## Address binding

For a type-1 address defined in [addresses.md](xpiaddr.md):

1. Validate address checksum, canonical type/payload/padding and current network.
2. Recover the secp256k1 public key using the exact digest and compact proof.
3. Serialize **only its 32-byte big-endian x coordinate**, exactly as used by
   the address template. The compressed-header flag cannot select another
   address key encoding.
4. Check `BLAKE3(xonly_public_key) == address.payload`.

P and -P intentionally have the same x-only keyhash. This matches native
BIP340 spending authority. ECDSA recovery parity affects recovery, not the
address preimage. The verifier need not execute a VM or possess a wallet.
Explicit root/type-0 addresses and unsupported templates are not accepted
by this single-key message API.

Legacy P2PKH addresses on the V2 daemon use the Lotus digest above and the
legacy address's actual public-key hash/SEC encoding. Their existing compact
compression headers 27–34 remain meaningful. Legacy P2SH is not a single-key
message target. The eCash daemon retains its original eCash digest unchanged;
the native address format is not enabled in that tier.

## RPC/provider behavior

`signmessage(address, message)` must use a key owned by the selected wallet,
require unlocking when encrypted, and reject watch-only or missing keys.
Both legacy and descriptor providers must resolve the native x-only keyhash.
`verifymessage(address, signature, message)` is public and requires no loaded
wallet. `signmessagewithprivkey` uses the same Lotus digest, preserving its
private key's SEC compression flag; native type-1 use requires a compressed
WIF so the returned envelope has the native header. Do not add another RPC
just to select the format. Do not mix eCash and Lotus signature domains based
on the address's text.

## Discovery integration

After both this feature and `getchainconfig` are integrated, the V2 discovery
adapter reports `features.message_signing` as
`lotus-chain-bound-compact-ecdsa-v1`, and
`features.native_keyhash_message_signing` as true. Its `message_address`
object identifies `format: xpiaddr`, the current network HRP, `types: [1]`,
and `keyhash: blake3-xonly32`. This describes message RPC support only. It
must not change the separate global receive/send address capabilities until
native wallet destination and spending support is actually integrated.
The PWA's strict ChainConfig validator must adopt this scheme at the same
integration point, so it never mislabels a Lotus proof as eCash-compatible.

## Independent digest vector and validation gates

```
network = regtest; ChainID = 32 zero bytes
message (escaped) = "  Lotus message\nwith whitespace\t"
digest (raw order) = 7564181309ced3fbd11303d70a957bb62984da700bfd4c6078e16303f66503f7
secret scalar = 1 (public test vector only)
compact signature = IP7/Qe4Hwq9jlGfz3Gm0ADQN7fPip/HUDoSvozREAZ4bP2qZWMaD8HPLXthcQS5SPn9j59HTAEBdSsFTX3186ZM=
```

This digest is independently generated with Python `hashlib.sha256` over the
specified bytes. The matching keyhash/address vector is in addresses.md.
Candidate tests must include independent ECDSA verification of the compact
r,s against this digest, both key-manager types, encrypted/watch-only cases,
restart, wrong message/key/network/type, malformed Base64/header/scalars,
high-S malleation and whitespace preservation. Existing eCash vectors are a
byte-for-byte compatibility control, not evidence of native wallet spend
support. Record actual build/runtime results separately; documentation or a
round-trip alone is insufficient validation.
