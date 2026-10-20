# Native wallet receiving

`getnewaddress "label" "native"` explicitly creates a Lotus V2 type1
receiving address from a compressed public key in the selected wallet. Its
payload is BLAKE3 of the x-only public key, and its committed program is the
canonical native keyhash template. This is a separate address policy; it
does not translate a legacy cashaddr or reinterpret an existing commitment.

The default `getnewaddress` behavior and explicit `"legacy"` selection keep
the existing legacy policy. Native addresses have separate addressbook
entries, labels and purposes. Their ownership survives restart and rescan
without changing transaction bytes, IDs or native output encodings.

For a recognized native keyhash policy, `getaddressinfo` reports `native`,
numeric `type`, `root`, `known_policy`, the public key, and ownership facts.
`ismine` denotes private-key ownership even while the wallet is locked;
`iswatchonly` denotes recognized public-only ownership. Both `spendable`
and `solvable` remain false for the ordinary CWallet funding/signing route.
Native PSBT or another explicit native signer may still use an owned key;
this receiving feature does not implement ordinary `sendtoaddress` funding.

`listunspent`, receiving totals, transaction listings and address labels use
the native destination. A native address passed to an unsupported legacy
script construction path is rejected instead of being converted to legacy
script bytes. Legacy transaction signing and legacy address encodings are
unchanged.

The optional discovery field `wallet.native_receiving` advertises this
provider only in a binary that includes the receiving feature. It does not
advertise ordinary native funding or native message-signing support.
