# FinSOC Agent — AI-Powered Incident Response with Confidence Scoring

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![MCP](https://img.shields.io/badge/Protocol-MCP-green)
![OpenClaw](https://img.shields.io/badge/Runtime-OpenClaw-orange)
![SANS SIFT](https://img.shields.io/badge/Toolkit-SANS%20SIFT-red)

**FIND EVIL! Hackathon** — SANS Institute | Prize Pool: $22,000 | Deadline: June 15, 2026

> AI attackers can compromise a domain in 8 minutes. FinSOC Agent gives defenders the same speed — with every finding scored for confidence and backed by a full evidence chain.

---

## What Makes This Different

Most AI forensic tools have a hallucination problem: the model confidently reports findings that aren't supported by the underlying tool output. In security, that's dangerous.

**FinSOC Agent's Confidence Scoring Layer** solves this. Every finding must pass through a deterministic scoring engine before it reaches the analyst. No score, no report. The analyst always knows exactly which tool commands produced which evidence.

```
Finding: DNS Tunneling Detected
Confidence: 72/100 (HIGH)
Evidence: tshark dns_extract → 15 long subdomain queries
MITRE: T1071.004
IOCs: a3f2b1c9d8e7.evil-c2.com, ...
```

---

## Quick Start

```bash
# Install dependencies
pip install mcp anthropic

# Run the MCP server (for OpenClaw integration)
python src/mcp_server.py

# Run standalone analysis on a case directory
python src/agent.py --case samples/demo_case/ --verbose

# Run with JSON output
python src/agent.py --case samples/demo_case/ --json
```

**Demo (single PCAP file):**
```bash
python src/agent.py --case samples/demo_case/demo_traffic.pcap
```

---

## Architecture

```
OpenClaw Agent Runtime
        ↓
   FinSOC SKILL.md  (natural language interface)
        ↓
   MCP Server — src/mcp_server.py
        ↓
   SIFT Tools: vol | tshark | fls | yara | strings | binwalk
        ↓
   Confidence Scoring Engine — src/confidence.py
        ↓
   Structured IR Report (findings + evidence chain)
```

---

## MCP Tools (10 total)

| Tool | Category | Description |
|------|----------|-------------|
| `memory_pslist` | Memory | List processes from Windows memory dump (Volatility3) |
| `memory_netscan` | Memory | Scan network connections from memory dump |
| `memory_malfind` | Memory | Detect injected code / hollowed processes |
| `network_dns_extract` | Network | Extract DNS queries from PCAP (tshark) |
| `network_http_extract` | Network | Extract HTTP sessions and user agents |
| `network_connections` | Network | Build connection graph from PCAP |
| `filesystem_list` | Filesystem | List files from disk image (Sleuthkit fls) |
| `yara_scan` | Malware | Scan artifacts with YARA rules |
| `binary_strings` | Malware | Extract strings from suspicious binaries |
| `score_finding` | Scoring | Score a finding based on evidence quality |

---

## Confidence Scoring

Scores are calculated on four axes:

| Axis | Max Points | How |
|------|-----------|-----|
| Tool reliability | 60 | Volatility3=0.95, tshark=0.90, YARA=0.85, strings=0.60 |
| Corroboration | 20 | +8 pts per unique tool (capped at 20) |
| IOC specificity | 15 | MD5/SHA256=5pts, URLs=3pts, strings=1pt |
| MITRE mapping | 5 | +5 if mapped to ATT&CK technique |

**Labels:**
- 90–100: CONFIRMED
- 70–89: HIGH
- 50–69: MEDIUM
- 30–49: LOW
- 0–29: SPECULATIVE (suppressed by default)

---

## Project Structure

```
find-evil-agent/
├── src/
│   ├── agent.py          # Main IR agent — orchestrates tools + scoring
│   ├── confidence.py     # Confidence Scoring Engine
│   ├── tools.py          # SIFT tool wrappers (tshark, vol, fls, yara)
│   └── mcp_server.py     # MCP Server — 10 tools over stdio
├── samples/
│   └── demo_case/
│       ├── demo_traffic.pcap       # Sample network capture
│       ├── financial_malware.yar   # YARA rules for financial malware
│       └── suspicious_script.ps1   # Sample malicious PowerShell
├── docs/
│   ├── devpost-writeup.md          # Hackathon submission writeup
│   ├── demo-video-script.md        # 3-minute demo video script
│   └── submission-checklist.md     # Submission steps for Leon
├── skills/
│   └── SKILL.md                    # OpenClaw skill definition
└── tests/
    └── test_confidence.py          # Unit tests (6/6 passing)
```

---

## Demo Results

Running against `samples/demo_case/demo_traffic.pcap`:

```
============================================================
INCIDENT RESPONSE FINDINGS REPORT
Generated: 2026-05-17T00:00:00Z
Total Findings: 2
============================================================

[1] HIGH — exfiltration
    Description: Possible DNS tunneling: 15 long subdomain queries detected
    Confidence: 72/100 (HIGH)
    MITRE: T1071.004
    IOCs: a3f2b1c9d8e7.evil-c2.com, ...

[2] HIGH — c2_communication
    Description: Suspicious HTTP user agents detected: python-requests/2.28
    Confidence: 70/100 (HIGH)
    MITRE: T1071.001
    IOCs: python-requests/2.28, PowerShell/5.1
```

---

## Requirements

- Python 3.10+
- SANS SIFT Workstation (or individual tools: tshark, volatility3, sleuthkit, yara, strings, binwalk)
- `pip install mcp anthropic`

---

## Hackathon

**Competition:** [FIND EVIL! by SANS Institute](https://findevil.devpost.com/)  
**Scoring criteria:** Autonomous Execution Quality · IR Accuracy · Audit Trail Quality · Breadth & Depth · Constraint Implementation · Usability & Documentation
