# FinSOC Agent Skill

## Purpose
AI-powered incident response using SIFT forensic tools with confidence scoring.
Detects malware, C2 communication, lateral movement, and data exfiltration.

## When to Use
- Analyzing memory dumps, disk images, or network captures
- Investigating security incidents
- Hunting for IOCs (Indicators of Compromise)
- FIND EVIL! Hackathon submissions

## Available MCP Tools

| Tool | Input | Use Case |
|------|-------|----------|
| `memory_pslist` | memory_image path | List processes from memory dump |
| `memory_netscan` | memory_image path | Network connections from memory |
| `memory_malfind` | memory_image path | Injected code / shellcode detection |
| `network_dns_extract` | pcap_path | DNS queries → detect tunneling |
| `network_http_extract` | pcap_path | HTTP requests → detect C2 |
| `network_connections` | pcap_path | TCP connections → detect exfiltration |
| `filesystem_list` | image_path | Files in disk image |
| `yara_scan` | rules_file, target | Malware signature matching |
| `binary_strings` | binary_path | Extract strings from binary |
| `score_finding` | description, tool, output, iocs | Score a finding (0-100) |

## Confidence Score Guide
- 90-100: CONFIRMED — report immediately
- 70-89: HIGH — high priority investigation
- 50-69: MEDIUM — investigate further
- 30-49: LOW — note and monitor
- <30: SPECULATIVE — do not report without more evidence

## Quick Start
```bash
# Run full analysis on a case directory
cd /home/taomi/projects/find-evil-agent
python3 -m src.agent --case samples/demo_case/ --verbose

# Start MCP server
python3 -m src.mcp_server
```

## MITRE ATT&CK Coverage
- T1003.001 — Credential Dumping (LSASS)
- T1059.001 — PowerShell execution
- T1071.001 — Web-based C2
- T1071.004 — DNS tunneling
- T1055 — Process injection
- T1041 — Exfiltration over C2
