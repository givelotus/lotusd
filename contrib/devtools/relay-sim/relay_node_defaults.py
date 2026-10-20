"""Compare the node's relay before and after Nucleation relay, in simulation.

Usage: python3 relay_node_defaults.py [processes]
"""

import dataclasses
import sys

from relay_experiments import table
from relay_sim import NODE_DEFAULTS, Cfg


def main():
    procs = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    base = Cfg()
    nucleation = dataclasses.replace(base, **NODE_DEFAULTS)
    cfgs = [
        # Flood every peer with 36-byte INVs on the fixed 10 ms tick (R1 only;
        # the Poisson-timer baseline is not modelled by this simulator)
        dataclasses.replace(base, k=None, tick=0.010, recon=None, id_bytes=36),
        nucleation,
        dataclasses.replace(nucleation, outbound=16),
        dataclasses.replace(nucleation, dead=0.3),
        dataclasses.replace(nucleation, recon=None, dead=0.3),
    ]
    table(
        "Node defaults: fan-out (8, 0.25, 32), tick 10 ms, recon 0.25 s, 8-byte ids",
        cfgs,
        ["k", "tick", "recon", "id_bytes", "outbound", "dead"],
        procs,
    )


if __name__ == "__main__":
    main()
