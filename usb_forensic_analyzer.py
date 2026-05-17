#!/usr/bin/env python3
"""
USB Forensic Analyzer
=====================
Author : Samy Laalioui
Case   : IR-2024-0047  |  Operation Silent Drive
Purpose: Analyze USB device connection history for IOC-based threat detection,
         supporting incident response and insider threat investigations.
"""

from __future__ import annotations

import csv
import json
import random
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

# ─────────────────────────── constants ───────────────────────────

CASE_ID      = "IR-2024-0047"
OPERATION    = "Operation Silent Drive"
ANALYST      = "Samy Laalioui"
ORGANIZATION = "NWMSU Cyber Defense Lab"
OUTPUT_DIR   = Path(".")

# Known-bad VID/PID pairs (simulated threat-intel feed)
KNOWN_BAD_VID_PID = {
    ("AAAA", "BBBB"): "RubberDucky payload device",
    ("0000", "0000"): "Null-identifier evasion tool",
    ("1234", "5678"): "Known exfil device — APT-41 TTP",
}

# IOC weights — tuned for Classic Physique, I mean Classic IR :)
IOC_WEIGHTS = {
    "known_bad_vid_pid":      40,   # CRITICAL
    "unknown_vendor":         25,   # HIGH
    "missing_serial":         20,   # HIGH
    "high_frequency":         15,   # MEDIUM
    "off_hours_connection":   15,   # MEDIUM
    "rapid_reconnect":        10,   # LOW
    "no_driver_signature":    10,   # LOW
}

SEVERITY_MAP = {
    (75, 999): "CRITICAL",
    (45,  74): "HIGH",
    (20,  44): "MEDIUM",
    (1,   19): "LOW",
    (0,    0): "CLEAN",
}

NORMAL_VENDORS = ["SanDisk", "Kingston", "Samsung", "PNY", "Lexar", "Verbatim"]


# ─────────────────────────── data models ─────────────────────────

@dataclass
class USBEvent:
    """A single USB connection event."""
    timestamp:        datetime
    device_id:        str          # USB\VID_xxxx&PID_xxxx
    vid:              str
    pid:              str
    vendor:           str
    serial:           Optional[str]
    driver_signed:    bool
    connections:      int          # connection count in 24-hr window
    last_seen:        Optional[datetime] = None  # for rapid-reconnect check

    @property
    def vid_pid(self) -> tuple[str, str]:
        return (self.vid, self.pid)

    @property
    def hour(self) -> int:
        return self.timestamp.hour


@dataclass
class IOCResult:
    """Scored IOC result for a single USB event."""
    device_id:     str
    vendor:        str
    serial:        Optional[str]
    timestamp:     datetime
    iocs_triggered: List[str]     = field(default_factory=list)
    score:          int           = 0
    severity:       str           = "CLEAN"
    notes:          List[str]     = field(default_factory=list)

    def compute_severity(self) -> None:
        for (lo, hi), label in SEVERITY_MAP.items():
            if lo <= self.score <= hi:
                self.severity = label
                return

    def to_dict(self) -> dict:
        return {
            "device_id":      self.device_id,
            "vendor":         self.vendor,
            "serial":         self.serial or "MISSING",
            "timestamp":      self.timestamp.isoformat(),
            "score":          self.score,
            "severity":       self.severity,
            "iocs_triggered": self.iocs_triggered,
            "notes":          self.notes,
        }


# ─────────────────────────── data generation ─────────────────────

def generate_usb_events(n: int = 40, seed: int = 42) -> List[USBEvent]:
    """
    Simulate realistic USB connection logs over a 30-day window.
    Injects known-bad devices, off-hours anomalies, and missing-serial
    patterns to replicate real IR evidence conditions.
    """
    random.seed(seed)
    base_time = datetime.now() - timedelta(days=30)
    events: List[USBEvent] = []

    # ── inject known-bad devices ──────────────────────────────────
    bad_entries = [
        ("AAAA", "BBBB", "Unknown",  "",                False, 18, 2),
        ("0000", "0000", "Unknown",  "",                False,  3, 1),
        ("1234", "5678", "Generic",  "SN000000",        False, 22, 5),
    ]
    for vid, pid, vendor, serial, signed, hour_offset, conns in bad_entries:
        ts = base_time + timedelta(hours=hour_offset + random.randint(0, 2))
        events.append(USBEvent(
            timestamp=ts,
            device_id=f"USB\\VID_{vid}&PID_{pid}",
            vid=vid, pid=pid,
            vendor=vendor,
            serial=serial or None,
            driver_signed=signed,
            connections=conns,
            last_seen=ts - timedelta(minutes=random.randint(2, 8)),
        ))

    # ── generate normal + noisy events ───────────────────────────
    while len(events) < n:
        vid = f"{random.randint(0x1000, 0x9FFF):04X}"
        pid = f"{random.randint(0x1000, 0x9FFF):04X}"
        vendor = random.choice(NORMAL_VENDORS)
        hour_offset = random.randint(0, 720)
        ts = base_time + timedelta(hours=hour_offset)

        # 8% chance of missing serial (real-world noise)
        serial = None if random.random() < 0.08 else f"SN{random.randint(100000, 999999)}"
        # 5% chance of unsigned driver
        signed = random.random() > 0.05
        conns  = random.randint(1, 8)
        # 10% chance of rapid reconnect (suspicious)
        last_seen = (ts - timedelta(minutes=random.randint(1, 5))
                     if random.random() < 0.10 else None)

        events.append(USBEvent(
            timestamp=ts,
            device_id=f"USB\\VID_{vid}&PID_{pid}",
            vid=vid, pid=pid,
            vendor=vendor,
            serial=serial,
            driver_signed=signed,
            connections=conns,
            last_seen=last_seen,
        ))

    events.sort(key=lambda e: e.timestamp)
    return events


# ─────────────────────────── IOC engine ──────────────────────────

def score_event(event: USBEvent) -> IOCResult:
    """
    Apply 7-rule weighted IOC scoring engine to a single USB event.
    Returns a fully-scored IOCResult.
    """
    result = IOCResult(
        device_id=event.device_id,
        vendor=event.vendor,
        serial=event.serial,
        timestamp=event.timestamp,
    )

    # Rule 1 — Known-bad VID/PID (CRITICAL)
    if event.vid_pid in KNOWN_BAD_VID_PID:
        result.score += IOC_WEIGHTS["known_bad_vid_pid"]
        result.iocs_triggered.append("KNOWN_BAD_VID_PID")
        result.notes.append(f"Matched threat-intel: {KNOWN_BAD_VID_PID[event.vid_pid]}")

    # Rule 2 — Unknown / unrecognized vendor (HIGH)
    if event.vendor.lower() in ("unknown", "generic", ""):
        result.score += IOC_WEIGHTS["unknown_vendor"]
        result.iocs_triggered.append("UNKNOWN_VENDOR")
        result.notes.append("Vendor string absent or unrecognized — common in spoofed/DIY devices")

    # Rule 3 — Missing serial number (HIGH)
    if not event.serial:
        result.score += IOC_WEIGHTS["missing_serial"]
        result.iocs_triggered.append("MISSING_SERIAL")
        result.notes.append("No serial number — device may be evading host-based logging")

    # Rule 4 — High connection frequency (MEDIUM)
    if event.connections > 10:
        result.score += IOC_WEIGHTS["high_frequency"]
        result.iocs_triggered.append("HIGH_FREQUENCY")
        result.notes.append(f"{event.connections} connections in 24 hr window — abnormal usage pattern")

    # Rule 5 — Off-hours connection (MEDIUM): before 06:00 or after 20:00
    if event.hour < 6 or event.hour >= 20:
        result.score += IOC_WEIGHTS["off_hours_connection"]
        result.iocs_triggered.append("OFF_HOURS_CONNECTION")
        result.notes.append(f"Connected at {event.hour:02d}:xx — outside normal business hours")

    # Rule 6 — Rapid reconnect within 5 minutes (LOW)
    if event.last_seen:
        delta_minutes = (event.timestamp - event.last_seen).seconds // 60
        if delta_minutes <= 5:
            result.score += IOC_WEIGHTS["rapid_reconnect"]
            result.iocs_triggered.append("RAPID_RECONNECT")
            result.notes.append(f"Re-connected {delta_minutes} min after last disconnect — scripted behavior possible")

    # Rule 7 — Unsigned driver (LOW)
    if not event.driver_signed:
        result.score += IOC_WEIGHTS["no_driver_signature"]
        result.iocs_triggered.append("NO_DRIVER_SIGNATURE")
        result.notes.append("Driver signature absent — could indicate custom/malicious firmware")

    result.compute_severity()
    return result


def analyze(events: List[USBEvent]) -> List[IOCResult]:
    return [score_event(e) for e in events]


# ─────────────────────────── output artifacts ────────────────────

def write_csv(results: List[IOCResult], path: Path) -> None:
    fieldnames = ["device_id", "vendor", "serial", "timestamp",
                  "score", "severity", "iocs_triggered", "notes"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            row = r.to_dict()
            row["iocs_triggered"] = " | ".join(row["iocs_triggered"])
            row["notes"]          = " | ".join(row["notes"])
            writer.writerow(row)
    print(f"  [+] CSV  → {path}")


def write_json(results: List[IOCResult], path: Path) -> None:
    payload = {
        "case_id":    CASE_ID,
        "operation":  OPERATION,
        "generated":  datetime.now().isoformat(),
        "total":      len(results),
        "findings":   [r.to_dict() for r in results],
    }
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    print(f"  [+] JSON → {path}")


def write_report(events: List[USBEvent], results: List[IOCResult], path: Path) -> None:
    flagged   = [r for r in results if r.severity != "CLEAN"]
    critical  = [r for r in flagged if r.severity == "CRITICAL"]
    high      = [r for r in flagged if r.severity == "HIGH"]
    medium    = [r for r in flagged if r.severity == "MEDIUM"]
    low       = [r for r in flagged if r.severity == "LOW"]

    timestamps = [e.timestamp for e in events]
    date_range = f"{min(timestamps).date()} → {max(timestamps).date()}"

    lines = [
        "=" * 70,
        "         USB DEVICE FORENSIC INVESTIGATION REPORT",
        "=" * 70,
        f"  Case ID    : {CASE_ID}",
        f"  Operation  : {OPERATION}",
        f"  Analyst    : {ANALYST}",
        f"  Org        : {ORGANIZATION}",
        f"  Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Evidence   : Windows USB connection logs (simulated)",
        f"  Date Range : {date_range}",
        "=" * 70,
        "",
        "CHAIN OF CUSTODY",
        "-" * 70,
        "  Evidence acquired from simulated Windows Registry:",
        "  HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
        "  No modifications made to source data during analysis.",
        "",
        "EXECUTIVE SUMMARY",
        "-" * 70,
        f"  Total USB events analyzed : {len(results)}",
        f"  Flagged events            : {len(flagged)}",
        f"    CRITICAL                : {len(critical)}",
        f"    HIGH                    : {len(high)}",
        f"    MEDIUM                  : {len(medium)}",
        f"    LOW                     : {len(low)}",
        "",
    ]

    if critical:
        lines += ["CRITICAL FINDINGS — IMMEDIATE ACTION REQUIRED", "-" * 70]
        for r in critical:
            lines += [
                f"  Device  : {r.device_id}",
                f"  Vendor  : {r.vendor}",
                f"  Serial  : {r.serial or 'MISSING'}",
                f"  Score   : {r.score}  |  Severity: {r.severity}",
                f"  IOCs    : {', '.join(r.iocs_triggered)}",
            ]
            for note in r.notes:
                lines.append(f"            • {note}")
            lines.append("")

    if high:
        lines += ["HIGH SEVERITY FINDINGS", "-" * 70]
        for r in high:
            lines += [
                f"  Device  : {r.device_id}",
                f"  Score   : {r.score}  |  IOCs: {', '.join(r.iocs_triggered)}",
            ]
            for note in r.notes:
                lines.append(f"            • {note}")
            lines.append("")

    if medium or low:
        lines += ["MEDIUM / LOW FINDINGS", "-" * 70]
        for r in medium + low:
            lines.append(
                f"  [{r.severity:<8}] {r.device_id}  score={r.score}"
                f"  iocs={','.join(r.iocs_triggered)}"
            )
        lines.append("")

    lines += [
        "RECOMMENDATIONS",
        "-" * 70,
        "  1. Isolate and image any CRITICAL-flagged device immediately.",
        "  2. Cross-reference UNKNOWN_VENDOR + MISSING_SERIAL devices against",
        "     known-bad VID/PID threat-intel feeds (e.g., USB Guardian).",
        "  3. Review off-hours connections against badge/swipe access logs.",
        "  4. Enforce USB device allowlisting via Group Policy or EDR.",
        "  5. Escalate APT-41-linked device (VID 1234 / PID 5678) to IR team.",
        "",
        "ANALYST NOTES",
        "-" * 70,
        "  Scoring engine applies 7 weighted IOC rules. Thresholds:",
        "  CRITICAL ≥ 75  |  HIGH 45–74  |  MEDIUM 20–44  |  LOW 1–19",
        "  Simulated data includes intentional noise (missing serials,",
        "  unsigned drivers) to reflect real-world forensic evidence quality.",
        "",
        "=" * 70,
        "  END OF REPORT — IR-2024-0047",
        "=" * 70,
    ]

    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"  [+] RPT  → {path}")


# ─────────────────────────── main ────────────────────────────────

def main() -> None:
    print("=" * 70)
    print(f"  USB FORENSIC ANALYZER  |  {CASE_ID}  |  {OPERATION}")
    print("=" * 70)

    print("\n[1/4] Generating USB connection evidence...")
    events = generate_usb_events(n=40)
    print(f"      {len(events)} events spanning 30 days")

    print("\n[2/4] Running IOC scoring engine (7 rules)...")
    results = analyze(events)
    flagged = [r for r in results if r.severity != "CLEAN"]
    print(f"      {len(flagged)} / {len(results)} events flagged")

    severity_counts = {}
    for r in flagged:
        severity_counts[r.severity] = severity_counts.get(r.severity, 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        if count:
            print(f"      {sev:<10}: {count}")

    print("\n[3/4] Writing output artifacts...")
    write_csv(results,         OUTPUT_DIR / "usb_ioc_results.csv")
    write_json(results,        OUTPUT_DIR / "usb_ioc_results.json")
    write_report(events, results, OUTPUT_DIR / "forensic_report.txt")

    print("\n[4/4] Top critical findings:")
    critical = [r for r in results if r.severity == "CRITICAL"]
    for r in critical[:3]:
        print(f"  ⚠  {r.device_id}  score={r.score}  iocs={r.iocs_triggered}")

    print("\n✅ Analysis complete. Artifacts ready for case file.\n")


if __name__ == "__main__":
    main()
