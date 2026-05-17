# USB Connection Forensic Analyzer

**Case:** IR-2024-0047 | **Operation:** Silent Drive  
**Author:** Samy Laalioui | NWMSU Cyber Defense Lab

A Python-based forensic analysis tool that simulates and analyzes USB device connection history to support incident response and insider threat investigations. Built to demonstrate IOC-based detection logic used by security analysts during real IR engagements.

---

## Overview

USB devices are a persistent vector for insider threats and data exfiltration. This tool models realistic Windows USB connection logs and applies a **weighted, multi-rule IOC scoring engine** to flag suspicious activity — the same analytical approach used during endpoint forensic investigations.

---

## Features

| Feature | Description |
|---|---|
| **7-Rule IOC Engine** | Weighted scoring across CRITICAL / HIGH / MEDIUM / LOW tiers |
| **Known-Bad VID/PID Detection** | Matches against simulated threat-intel feed (APT-41 TTPs, RubberDucky) |
| **Missing Serial Detection** | Identifies devices evading host-based logging |
| **Off-Hours Analysis** | Flags connections outside business hours (before 06:00, after 20:00) |
| **Rapid Reconnect Detection** | Detects scripted/automated USB behavior (≤5 min reconnect) |
| **Driver Signature Check** | Flags unsigned drivers indicating custom/malicious firmware |
| **High-Frequency Detection** | Abnormal connection count within 24-hr window |
| **3 Output Artifacts** | Structured CSV + JSON + formal forensic report with chain of custody |

---

## IOC Scoring Engine

```
Rule                     Weight    Severity Tier
───────────────────────────────────────────────
Known-bad VID/PID          40      CRITICAL (≥75)
Unknown vendor             25      HIGH     (45–74)
Missing serial             20      HIGH
High connection frequency  15      MEDIUM   (20–44)
Off-hours connection       15      MEDIUM
Rapid reconnect            10      LOW      (1–19)
Unsigned driver            10      LOW
```

Scores stack across rules — a device missing a serial number, connecting at 2am with an unknown vendor hits 60 (HIGH) before any other checks.

---

## Output Artifacts

```
usb_ioc_results.csv      — all events with score, severity, triggered IOCs
usb_ioc_results.json     — structured case payload with metadata
forensic_report.txt      — formal IR report with chain of custody block,
                           executive summary, and analyst recommendations
```

### Sample forensic report header
```
======================================================================
         USB DEVICE FORENSIC INVESTIGATION REPORT
======================================================================
  Case ID    : IR-2024-0047
  Operation  : Operation Silent Drive
  Analyst    : Samy Laalioui
  Generated  : 2024-11-15 14:32:07

CHAIN OF CUSTODY
----------------------------------------------------------------------
  Evidence acquired from simulated Windows Registry:
  HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
  No modifications made to source data during analysis.
```

---

## Tech Stack

| Tool | Purpose |
|---|---|
| Python 3 | Core language |
| `dataclasses` | Typed data models for events and IOC results |
| `json` / `csv` | Structured artifact output |
| `datetime` | Timestamp handling and timeline reconstruction |
| `pathlib` | Cross-platform file I/O |

No external dependencies — runs on any machine with Python 3.7+.

---

## Installation & Usage

```bash
git clone https://github.com/samylaalioui/usb-forensic-analyzer
cd usb-forensic-analyzer
python usb_forensic_analyzer.py
```

Output artifacts are written to the working directory.

---

## Why Simulated Data?

Real USB logs contain sensitive system information tied to specific machines. Simulating realistic evidence — including intentional noise like missing serials, unsigned drivers, and off-hours timestamps — allowed me to:

- Model the data quality issues analysts actually face in IR engagements
- Inject known-bad device patterns (RubberDucky, APT-41-linked VID/PIDs) without privacy concerns
- Tune the scoring engine against predictable ground-truth cases

---

## What This Demonstrates

- **IOC-based detection logic** — scoring engines are how SIEMs and EDR tools triage alerts
- **Forensic evidence standards** — chain of custody, case IDs, structured reporting
- **Insider threat TTPs** — how missing serials and off-hours behavior indicate intent
- **False positive management** — weighted scoring reduces noise vs. binary flag/no-flag logic

---

## Planned Improvements

- [ ] Parse actual Windows Registry `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` entries
- [ ] YARA rule integration for device signature matching
- [ ] VirusTotal / USB threat-intel API lookup for VID/PID cross-reference
- [ ] Timeline visualization (matplotlib or Rich terminal output)
- [ ] SIEM export format (CEF / JSON-LD)

---

## Related Projects

- [SIEM Detection Lab](../siem-detection-lab) — Splunk + Metasploitable (in progress)
- [Network Traffic Analyzer](../network-traffic-analyzer) — Python + Scapy (in progress)
- [HackTheBox Labs](../htb-labs)
