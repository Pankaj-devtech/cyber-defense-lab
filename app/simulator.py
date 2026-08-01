"""Synthetic event generator for the simulation sandbox."""

from __future__ import annotations

import random
from dataclasses import dataclass

from app.scenarios import Scenario

# Fixed pools keep demos reproducible-ish while still looking realistic.
_SRC_POOL = ["10.0.1.20", "10.0.1.55", "192.168.50.12", "172.16.8.4", "203.0.113.77"]
_DST_INTERNAL = ["10.0.0.10", "10.0.0.20", "10.0.0.30"]
_DST_EXTERNAL = ["198.51.100.44", "203.0.113.90", "192.0.2.66"]
_USER_POOL = ["alice", "bob", "carol", "dave", "svc_backup"]


@dataclass(frozen=True)
class GeneratedEvent:
    scenario: str
    event_type: str
    source_ip: str
    dest_ip: str
    dest_port: int
    protocol: str
    summary: str
    is_malicious: bool


def _brute_force(rng: random.Random, count: int) -> list[GeneratedEvent]:
    attacker = rng.choice(_SRC_POOL)
    target = rng.choice(_DST_INTERNAL)
    events: list[GeneratedEvent] = []
    for i in range(count):
        user = rng.choice(_USER_POOL)
        success = i == count - 1 and count >= 5
        events.append(
            GeneratedEvent(
                scenario=Scenario.BRUTE_FORCE.value,
                event_type="auth.failure" if not success else "auth.success",
                source_ip=attacker,
                dest_ip=target,
                dest_port=22,
                protocol="tcp",
                summary=(
                    f"SSH login {'succeeded' if success else 'failed'} for user={user}"
                ),
                is_malicious=True,
            )
        )
    return events


def _port_scan(rng: random.Random, count: int) -> list[GeneratedEvent]:
    scanner = rng.choice(_SRC_POOL)
    target = rng.choice(_DST_INTERNAL)
    ports = list(range(20, 20 + count))
    rng.shuffle(ports)
    return [
        GeneratedEvent(
            scenario=Scenario.PORT_SCAN.value,
            event_type="network.scan",
            source_ip=scanner,
            dest_ip=target,
            dest_port=port,
            protocol="tcp",
            summary=f"TCP SYN probe to port {port}",
            is_malicious=True,
        )
        for port in ports
    ]


def _malware_beacon(rng: random.Random, count: int) -> list[GeneratedEvent]:
    infected = rng.choice(_DST_INTERNAL)
    c2 = rng.choice(_DST_EXTERNAL)
    events: list[GeneratedEvent] = []
    for i in range(count):
        events.append(
            GeneratedEvent(
                scenario=Scenario.MALWARE_BEACON.value,
                event_type="network.beacon",
                source_ip=infected,
                dest_ip=c2,
                dest_port=443,
                protocol="tcp",
                summary=f"Periodic HTTPS beacon #{i + 1} to C2 host",
                is_malicious=True,
            )
        )
    return events


def _sql_injection(rng: random.Random, count: int) -> list[GeneratedEvent]:
    attacker = rng.choice(_SRC_POOL)
    app = rng.choice(_DST_INTERNAL)
    payloads = [
        "' OR 1=1 --",
        "1; DROP TABLE users;--",
        "admin'--",
        "UNION SELECT null, password FROM users",
    ]
    return [
        GeneratedEvent(
            scenario=Scenario.SQL_INJECTION.value,
            event_type="http.request",
            source_ip=attacker,
            dest_ip=app,
            dest_port=80,
            protocol="http",
            summary=f"HTTP GET /login?q={rng.choice(payloads)}",
            is_malicious=True,
        )
        for _ in range(count)
    ]


def _benign(rng: random.Random, count: int) -> list[GeneratedEvent]:
    events: list[GeneratedEvent] = []
    for _ in range(count):
        src = rng.choice(_DST_INTERNAL)
        dst = rng.choice(_DST_EXTERNAL)
        port = rng.choice([80, 443, 53, 123])
        proto = "udp" if port in {53, 123} else "tcp"
        events.append(
            GeneratedEvent(
                scenario=Scenario.BENIGN.value,
                event_type="network.flow",
                source_ip=src,
                dest_ip=dst,
                dest_port=port,
                protocol=proto,
                summary=f"Normal {proto.upper()} traffic to port {port}",
                is_malicious=False,
            )
        )
    return events


_SCENARIO_BUILDERS = {
    Scenario.BRUTE_FORCE: _brute_force,
    Scenario.PORT_SCAN: _port_scan,
    Scenario.MALWARE_BEACON: _malware_beacon,
    Scenario.SQL_INJECTION: _sql_injection,
    Scenario.BENIGN: _benign,
}


def generate_events(
    scenario: Scenario,
    *,
    count: int = 10,
    seed: int | None = None,
) -> list[GeneratedEvent]:
    rng = random.Random(seed)
    if scenario == Scenario.MIXED:
        per = max(1, count // 4)
        leftover = count - per * 4
        batch = (
            _brute_force(rng, per)
            + _port_scan(rng, per)
            + _malware_beacon(rng, per)
            + _sql_injection(rng, per)
            + _benign(rng, max(leftover, 1))
        )
        rng.shuffle(batch)
        return batch[:count] if count < len(batch) else batch

    return _SCENARIO_BUILDERS[scenario](rng, count)
