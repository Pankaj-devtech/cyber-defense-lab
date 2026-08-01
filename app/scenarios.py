"""Attack scenario identifiers for the simulation sandbox."""

from enum import StrEnum


class Scenario(StrEnum):
    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    MALWARE_BEACON = "malware_beacon"
    SQL_INJECTION = "sql_injection"
    MIXED = "mixed"
    BENIGN = "benign"
