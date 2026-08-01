"""Rule-based detection engine for simulated events."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Protocol

from app.models import SimulatedEvent


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    rule_name: str
    severity: str
    message: str
    mitre_technique: str | None
    event_id: int


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    name: str
    description: str
    severity: str
    mitre_technique: str | None


class DetectionRule(Protocol):
    info: RuleInfo

    def evaluate(self, events: list[SimulatedEvent]) -> list[RuleHit]: ...


class BruteForceRule:
    info = RuleInfo(
        rule_id="R001",
        name="SSH Brute Force",
        description="Many failed auth attempts from one source to one host.",
        severity="high",
        mitre_technique="T1110",
    )

    def evaluate(self, events: list[SimulatedEvent]) -> list[RuleHit]:
        buckets: dict[tuple[str, str], list[SimulatedEvent]] = defaultdict(list)
        for event in events:
            if event.event_type == "auth.failure" and event.dest_port == 22:
                buckets[(event.source_ip, event.dest_ip)].append(event)

        hits: list[RuleHit] = []
        for (src, dst), group in buckets.items():
            if len(group) < 5:
                continue
            for event in group:
                hits.append(
                    RuleHit(
                        rule_id=self.info.rule_id,
                        rule_name=self.info.name,
                        severity=self.info.severity,
                        message=f"{len(group)} failed SSH logins from {src} to {dst}",
                        mitre_technique=self.info.mitre_technique,
                        event_id=event.id,
                    )
                )
        return hits


class PortScanRule:
    info = RuleInfo(
        rule_id="R002",
        name="Port Scan",
        description="One source probes many distinct ports on a single host.",
        severity="medium",
        mitre_technique="T1046",
    )

    def evaluate(self, events: list[SimulatedEvent]) -> list[RuleHit]:
        buckets: dict[tuple[str, str], set[int]] = defaultdict(set)
        by_key: dict[tuple[str, str], list[SimulatedEvent]] = defaultdict(list)
        for event in events:
            if event.event_type == "network.scan":
                key = (event.source_ip, event.dest_ip)
                buckets[key].add(event.dest_port)
                by_key[key].append(event)

        hits: list[RuleHit] = []
        for key, ports in buckets.items():
            if len(ports) < 5:
                continue
            src, dst = key
            for event in by_key[key]:
                hits.append(
                    RuleHit(
                        rule_id=self.info.rule_id,
                        rule_name=self.info.name,
                        severity=self.info.severity,
                        message=f"Port scan: {src} probed {len(ports)} ports on {dst}",
                        mitre_technique=self.info.mitre_technique,
                        event_id=event.id,
                    )
                )
        return hits


class MalwareBeaconRule:
    info = RuleInfo(
        rule_id="R003",
        name="Malware Beaconing",
        description="Repeated outbound beacons from an internal host to one external IP.",
        severity="critical",
        mitre_technique="T1071",
    )

    def evaluate(self, events: list[SimulatedEvent]) -> list[RuleHit]:
        buckets: dict[tuple[str, str], list[SimulatedEvent]] = defaultdict(list)
        for event in events:
            if event.event_type == "network.beacon":
                buckets[(event.source_ip, event.dest_ip)].append(event)

        hits: list[RuleHit] = []
        for (src, dst), group in buckets.items():
            if len(group) < 3:
                continue
            for event in group:
                hits.append(
                    RuleHit(
                        rule_id=self.info.rule_id,
                        rule_name=self.info.name,
                        severity=self.info.severity,
                        message=f"Beacon pattern: {src} → {dst} ({len(group)} hits)",
                        mitre_technique=self.info.mitre_technique,
                        event_id=event.id,
                    )
                )
        return hits


class SqlInjectionRule:
    info = RuleInfo(
        rule_id="R004",
        name="SQL Injection Attempt",
        description="HTTP request summary contains common SQLi patterns.",
        severity="high",
        mitre_technique="T1190",
    )

    _NEEDLES = ("' OR ", "DROP TABLE", "UNION SELECT", "admin'--", "1=1")

    def evaluate(self, events: list[SimulatedEvent]) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for event in events:
            if event.event_type != "http.request":
                continue
            upper = event.summary.upper()
            if not any(needle.upper() in upper for needle in self._NEEDLES):
                continue
            hits.append(
                RuleHit(
                    rule_id=self.info.rule_id,
                    rule_name=self.info.name,
                    severity=self.info.severity,
                    message=f"SQLi pattern in request from {event.source_ip}",
                    mitre_technique=self.info.mitre_technique,
                    event_id=event.id,
                )
            )
        return hits


RULES: list[DetectionRule] = [
    BruteForceRule(),
    PortScanRule(),
    MalwareBeaconRule(),
    SqlInjectionRule(),
]


def list_rules() -> list[RuleInfo]:
    return [rule.info for rule in RULES]


def run_detection(events: list[SimulatedEvent]) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for rule in RULES:
        hits.extend(rule.evaluate(events))
    return hits
