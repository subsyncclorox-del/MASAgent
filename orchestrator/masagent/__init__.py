"""MASAgent orchestrator.

The brain layer: reads the attack-surface map produced by the Go recon core,
plans tests, directs an agent swarm, validates every finding with a reproducible
PoC in a sandbox, and reports. Every network action is mediated by the Go
scopeguard; nothing here is given a raw network handle.
"""

__version__ = "0.1.0"
