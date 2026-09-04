"""External scanner integrations, normalized to MASAgent findings.

Every scanner: (1) refuses to run against an out-of-scope target, (2) egresses
only through the scope guard proxy, (3) returns normalized ScanFinding objects.
If a tool binary is absent, the wrapper returns an 'unavailable' result rather
than failing the run — MASAgent degrades gracefully.
"""
from .base import Scanner, ScanFinding, ScannerUnavailable
from .nuclei import Nuclei
from .sqlmap import SQLMap
from .dalfox import Dalfox

ALL: dict[str, type[Scanner]] = {"nuclei": Nuclei, "sqlmap": SQLMap, "dalfox": Dalfox}

__all__ = ["Scanner", "ScanFinding", "ScannerUnavailable", "Nuclei", "SQLMap", "Dalfox", "ALL"]
