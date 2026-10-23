# Optional mempool consistency checking

`-checkmempool=0` is the default on every network, including regtest.
`-checkmempool=1` runs the whole-pool diagnostic after every checked mutation;
`-checkmempool=N` samples about one mutation in N. This controls a diagnostic,
not transaction input/script validation, admission policy or consensus.
The independent `-checkblockindex` defaults are unchanged.

The checker traverses entries in parent-before-child entry-ID order. It proves
all ancestor ordering from direct-parent edges, retaining graph links, input
coins, pointer ownership, fees, serialized sizes and cached-memory assertions.
One check scales with pool entries and edges; checking after every insertion
still has aggregate quadratic cost as the pool grows.

Native test fixtures explicitly use `check_ratio=1`. Functional test nodes
explicitly pass `-checkmempool=1`; an individual diagnostic-policy test may
remove that framework default to test actual node defaults. Performance
harnesses must record their effective option: old regtest measurements without
an override used the former default of 1. Preserve those historical results
and distinguish profile changes from code speedups.
