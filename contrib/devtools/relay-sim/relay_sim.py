"""Transaction relay simulator (Nucleation relay design study): time to sync vs bytes, redundancy and privacy.

One transaction at a time through a random peer graph (no queueing or load).
A node that gets a tx announces it on its next tick to K random peers not
known to have it (all peers if K is None). Announcing = INV (peer requests the
body if it lacks it and has not requested it); the first P of the chosen peers
get the body pushed instead. Nodes reconcile with one random peer every
`recon` seconds; a missing tx found that way is fetched. A fraction of nodes
may be "dead": they receive but never announce, answer or reconcile.
"""

import dataclasses
import heapq
import math
import random
import statistics

BODY, GETDATA, SKETCH_PER_DIFF = 250, 36, 16


@dataclasses.dataclass(frozen=True)
class Cfg:
    n: int = 2000
    outbound: int = 8
    k: object = 8  # None = all peers; float = fraction; (min, pct, max) = node rule
    tick: float = 0.025  # 0 = immediate
    recon: object = 1.0  # None = off
    push: int = 0  # bodies pushed per announce
    entries: int = 0  # 0 = node-originated; m = wallet sends body to m random nodes
    dead: float = 0.0
    id_bytes: int = 36
    known: bool = True  # known-inventory suppression
    txs: int = 40
    seed: int = 1
    hubs: float = 0.0  # fraction of nodes that receive half of all inbound connections


def fanout(n, kmin, pct, kmax):
    """The node's fan-out (TxRelayFanout): clamp(max(min, ceil(pct x n)), min, max)"""
    kmax = max(kmax, kmin)
    return min(max(kmin, math.ceil(pct * n - 1e-9)), kmax)


# The node's defaults: -txrelayfanoutmin/pct/max, -txrelaytick,
# -txreconinterval, 8-byte invshort ids
NODE_DEFAULTS = {"k": (8, 0.25, 32), "tick": 0.010, "recon": 0.25, "id_bytes": 8}


class Net:
    def __init__(self, c):
        rng = random.Random(c.seed)
        self.rng = rng
        n = c.n
        adj = [set() for _ in range(n)]
        self.outb = [set() for _ in range(n)]
        hubset = list(range(int(n * c.hubs)))
        for a in range(n):
            while len(self.outb[a]) < c.outbound:
                b = (
                    rng.choice(hubset)
                    if hubset and rng.random() < 0.5
                    else rng.randrange(n)
                )
                if b != a and b not in adj[a]:
                    self.outb[a].add(b)
                    adj[a].add(b)
                    adj[b].add(a)
        self.peers = [sorted(s) for s in adj]
        self.lat = {}
        for a in range(n):
            for b in self.peers[a]:
                if (b, a) not in self.lat:
                    self.lat[(a, b)] = self.lat[(b, a)] = rng.uniform(0.010, 0.080)
        self.dead = set(rng.sample(range(n), int(n * c.dead)))
        self.spies = set(rng.sample(range(n), n // 10))


def run_tx(c, net, rng):
    n, peers, lat, dead = c.n, net.peers, net.lat, net.dead
    INF = math.inf
    have = [INF] * n
    known = [set() for _ in range(n)]  # peers known to have it
    requested = [False] * n
    announcers = [[] for _ in range(n)]
    tried = [set() for _ in range(n)]
    st = {
        "inv": 0,
        "dup_inv": 0,
        "getdata": 0,
        "body": 0,
        "dup_body": 0,
        "recon_hit": 0,
    }
    spy_first = {}
    ev = []
    seq = [0]

    def push(t, kind, node, frm):
        seq[0] += 1
        heapq.heappush(ev, (t, seq[0], kind, node, frm))

    def tick_after(t):
        return t if c.tick == 0 else math.ceil((t + 1e-9) / c.tick) * c.tick

    def observe(node, t, frm):
        if node in net.spies and node not in spy_first:
            spy_first[node] = (t, frm)

    def receive(node, t, frm, originate=False):
        """node now has the tx; an originator announces to all its peers."""
        have[node] = t
        if frm is not None:
            known[node].add(frm)
        if node not in dead:
            push(
                tick_after(t + 0.001), "announce", node, "origin" if originate else None
            )

    def request(node, t):
        for frm in announcers[node]:
            if frm not in tried[node]:
                tried[node].add(frm)
                requested[node] = True
                st["getdata"] += 1
                if frm in dead:
                    push(t + 1.0, "timeout", node, frm)  # request timeout
                else:
                    push(t + 2 * lat[(node, frm)], "body", node, frm)
                return
        requested[node] = False

    origin = None
    if c.entries:
        for e in rng.sample(range(n), c.entries):
            receive(e, rng.uniform(0.010, 0.080), None, originate=True)
            st["body"] += 1  # the wallet's upload to this entry node
        origin_is_wallet = True
    else:
        origin = rng.choice(
            [x for x in range(n) if x not in net.spies and x not in dead]
        )
        have[origin] = 0.0
        push(tick_after(0.0), "announce", origin, "origin")
        origin_is_wallet = False
    if c.recon:
        for a in range(n):
            push(rng.uniform(0, c.recon), "recon", a, None)

    while ev:
        t, _, kind, node, frm = heapq.heappop(ev)
        if t > 60:
            break
        if kind == "announce":
            cands = [b for b in peers[node] if not (c.known and b in known[node])]
            kk = c.k
            if isinstance(kk, float):  # a fraction of this node's peers
                kk = max(1, round(kk * len(peers[node])))
            elif isinstance(kk, tuple):  # the node's rule: (min, pct, max)
                kk = fanout(len(peers[node]), *kk)
            if kk is not None and frm != "origin" and len(cands) > kk:
                cands = rng.sample(cands, kk)
            else:
                rng.shuffle(cands)
            for i, b in enumerate(cands):
                known[node].add(b)
                if i < c.push:
                    st["body"] += 1
                    push(t + lat[(node, b)], "pushbody", b, node)
                else:
                    st["inv"] += 1
                    push(t + lat[(node, b)], "inv", b, node)
        elif kind == "inv":
            observe(node, t, frm)
            known[node].add(frm)
            if have[node] != INF or requested[node]:
                st["dup_inv"] += 1
                announcers[node].append(frm)
                continue
            announcers[node].append(frm)
            request(node, t)
        elif kind in ("body", "pushbody"):
            if kind == "body":
                st["body"] += 1
            else:
                observe(node, t, frm)
            known[node].add(frm)
            if have[node] != INF:
                st["dup_body"] += 1
                continue
            receive(node, t, frm)
        elif kind == "timeout":
            if have[node] == INF:
                request(node, t)
        elif kind == "recon":
            if have[node] != INF or node in dead:
                continue
            if requested[node]:
                # Already being fetched: reconciliation would not fetch it again
                push(t + c.recon, "recon", node, None)
                continue
            p = rng.choice(peers[node])
            if p not in dead and have[p] <= t:
                st["recon_hit"] += 1
                st["getdata"] += 1
                observe(node, t, p)
                push(t + 4 * lat[(node, p)], "body", node, p)
                requested[node] = True
            else:
                push(t + c.recon, "recon", node, None)
    # Coverage over nodes that relay (non-relaying nodes are the adversary)
    times = sorted(have[x] for x in range(n) if x not in dead)
    live = len(times)

    def pct(f):
        return times[min(live - 1, max(0, math.ceil(f * live) - 1))]

    found = None
    if not origin_is_wallet and spy_first:
        found = min(spy_first.values())[1] == origin
    by = (
        st["inv"] * c.id_bytes
        + st["getdata"] * GETDATA
        + st["body"] * BODY
        + st["recon_hit"] * SKETCH_PER_DIFF
    ) / n
    return {
        "t50": pct(0.5),
        "t90": pct(0.9),
        "t99": pct(0.99),
        "t100": times[-1],
        "inv": st["inv"] / n,
        "dup_inv": st["dup_inv"] / n,
        "body": st["body"] / n,
        "dup_body": st["dup_body"] / n,
        "recon": st["recon_hit"] / n,
        "bytes": by,
        "found": found,
    }


def simulate(c):
    net = Net(c)
    rng = random.Random(c.seed * 7919 + 1)
    res = [run_tx(c, net, rng) for _ in range(c.txs)]
    med = {k: statistics.median(r[k] for r in res) for k in res[0] if k != "found"}
    med["t100_max"] = max(r["t100"] for r in res)
    f = [r["found"] for r in res if r["found"] is not None]
    med["found"] = sum(f) / len(f) if f else None
    med["peers"] = statistics.mean(len(p) for p in net.peers)
    return c, med
