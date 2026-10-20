# Transaction relay simulator

The design study behind Nucleation relay (fixed relay tick, fan-out,
8-byte short-id announcements, continuous reconciliation). It is a model,
not a measurement: one transaction at a time through a random peer graph,
no queueing, contention or batching, and silent nodes as the only
adversary besides passive spies.

- `relay_sim.py`: the simulator (`Cfg`, `simulate`). A node that gets a
  transaction announces it on its next tick to K peers not known to have
  it (all peers for the originator); a peer that lacks it requests the
  body from one announcer at a time. Nodes reconcile with one random peer
  every `recon` seconds. `k` is a fixed number, a fraction of the node's
  peers, `None` (flood), or `(min, pct, max)`, the node's rule
  (`-txrelayfanoutmin/pct/max`). `NODE_DEFAULTS` holds the node's defaults.
- `relay_experiments.py`: the tables of the design study
  (`python3 relay_experiments.py [processes] [1-7|all]`).
- `relay_final.py`: the final candidates.
- `relay_node_defaults.py`: the node's defaults against a flood on the same
  tick (`python3 relay_node_defaults.py [processes]`).

The runners use `multiprocessing`; each has an `if __name__ == "__main__":`
guard, which macOS needs (it starts workers by re-importing the script).
Keep the process count low on a shared machine.

## Results (2,000 nodes, one-way link latency 10-80 ms, 40 transactions)

From the plan (2026-10-19):

| Design | 100% reached (median / worst) | Bytes per node per tx | Duplicate bodies |
|---|---|---|---|
| Flood, Poisson 2 s / 5 s (before) | 4.7 s / 6.1 s | ~870 (16 peers), grows with peers | 0 |
| Flood, 25 ms tick, 36-byte ids | 0.60 s / 0.68 s | 678 (1,568 with 48 peers) | 0 |
| Fan-out max(8, p x peers) capped, 10 ms tick, reconcile 0.25 s, 8-byte ids | 0.71 s / 0.76 s | 349 | 0 |
| Same, with 30% silent nodes | 0.88 s / 1.63 s | 331 | 0 |
| Pushing bodies to 2 peers instead of announcing | faster by ~0.1 s | +360 | 1.8 per node |

`relay_node_defaults.py` with the node's defaults (rerun 2026-10-19):

| Config | peers | t50 | t90 | t99 | t100 | worst | bytes/node/tx |
|---|---|---|---|---|---|---|---|
| Flood, 10 ms tick, 36-byte ids | 16 | 0.30 | 0.38 | 0.44 | 0.48 | 0.53 | 685 |
| Node defaults | 16 | 0.38 | 0.49 | 0.59 | 0.71 | 0.76 | 349 |
| Node defaults, 32 peers | 32 | 0.34 | 0.45 | 0.54 | 0.67 | 0.77 | 356 |
| Node defaults, 30% silent | 16 | 0.46 | 0.58 | 0.70 | 0.88 | 1.63 | 331 |
| Same without reconciliation | 16 | 0.46 | 0.57 | 0.67 | never | never | 330 |

Bytes count announcements, requests (36 bytes), bodies (250 bytes) and
reconciliation (16 bytes per difference); message headers and the epoch
field of `invshort` are not modelled. The floor (one body and one request
per node) is 286 bytes. Measurements on real regtest clusters are in the
Nucleation relay measurement commit.
