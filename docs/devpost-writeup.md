# FinSOC Agent — AI-Powered Incident Response with Confidence Scoring

## Inspiration

In 2024, red team researchers demonstrated that an AI-powered attacker could achieve full domain compromise in under **8 minutes** — from initial foothold to domain controller. Human SOC analysts, working through alert queues and manual tool chains, simply cannot match that pace.

Financial institutions face a compounded version of this problem. A breach at a bank isn't just a data loss event — it's a regulatory incident, a customer trust crisis, and potentially a systemic risk. The window between "attacker in the network" and "irreversible damage" is measured in minutes, not hours.

We built FinSOC Agent to answer a simple question: **what if the defender had an AI too?**

The existing tooling — SANS SIFT Workstation, Volatility3, Sleuthkit, tshark, YARA — is excellent. But it requires a skilled analyst to orchestrate it, interpret results, and write findings. That's the bottleneck. We wanted to automate the orchestration layer while keeping the human analyst in control of decisions.

## What It Does

FinSOC Agent is an AI-powered incident response agent built on the **Model Context Protocol (MCP)** architecture. It wraps the SANS SIFT forensic toolkit into 10 structured tools and adds a **Confidence Scoring Layer** that every finding must pass through before being reported.

**Core capabilities:**

- **Network traffic analysis** — extracts DNS queries, HTTP sessions, and connection graphs from PCAP files using tshark; detects DNS tunneling (T1071.004) and C2 communication patterns (T1071.001)
- **Memory forensics** — runs Volatility3 against Windows memory dumps to list processes, scan network connections, and detect injected code via malfind
- **File system forensics** — uses Sleuthkit (fls/mmls/icat) to enumerate files and recover deleted artifacts
- **Malware detection** — scans artifacts with YARA rules tuned for financial malware (banking trojans, credential stealers, ransomware precursors)
- **Binary analysis** — extracts strings from suspicious binaries to surface embedded C2 URLs, registry keys, and encoded payloads
- **Confidence scoring** — every finding gets a score from 0–100 based on tool reliability, evidence corroboration, IOC specificity, and MITRE ATT&CK mapping

The agent produces a structured report where each finding includes: confidence score, confidence label (CONFIRMED / HIGH / MEDIUM / LOW / SPECULATIVE), MITRE technique, IOC list, and a full evidence chain traceable to specific tool executions.

## How We Built It

**Architecture:** OpenClaw agent runtime + Python MCP Server + SIFT tools

The MCP Server (`src/mcp_server.py`) exposes 10 tools over stdio transport:

| Category | Tools |
|----------|-------|
| Memory | `memory_pslist`, `memory_netscan`, `memory_malfind` |
| Network | `network_dns_extract`, `network_http_extract`, `network_connections` |
| Filesystem | `filesystem_list` |
| Malware | `yara_scan`, `binary_strings` |
| Scoring | `score_finding` |

The **Confidence Scoring Engine** (`src/confidence.py`) is the core differentiator. It scores findings on four axes:
1. **Tool reliability** (up to 60 pts) — Volatility3 scores 0.95, tshark 0.90, YARA 0.85, strings 0.60; failed tool executions are penalized 70%
2. **Corroboration** (up to 20 pts) — findings supported by multiple independent tools score higher
3. **IOC specificity** (up to 15 pts) — MD5/SHA256 hashes score 5 pts each, URLs 3 pts, generic strings 1 pt
4. **MITRE ATT&CK mapping** (5 pts) — findings mapped to specific techniques get a bonus

The `FinSOCAgent` class (`src/agent.py`) orchestrates the full workflow: discover artifacts in a case directory, run appropriate tools, score findings, filter out low-confidence noise (threshold: 30/100), and produce a structured report.

**SKILL.md** defines the OpenClaw skill interface, allowing the agent to be invoked directly from the OpenClaw chat interface with natural language commands like "analyze this PCAP for C2 traffic."

## Challenges

**The hallucination problem** was our primary engineering challenge. Large language models, when asked to perform forensic analysis, will sometimes confidently report findings that aren't supported by the underlying tool output. In a security context, a false positive can trigger an unnecessary incident response, and a false negative can let an attacker persist.

Our solution: **no finding enters the report without passing through the Confidence Scoring Engine.** The agent cannot assert a finding — it can only call tools, collect Evidence objects, and submit them to the scorer. The scorer is deterministic and auditable. If the score is below 30, the finding is suppressed. If it's above 70, it's labeled HIGH. The analyst always knows exactly which tool commands produced which evidence.

**Tool output parsing** was the second challenge. SIFT tools produce human-readable text output, not structured JSON. We built lightweight parsers for each tool that extract the signal (suspicious process names, long DNS subdomains, unusual HTTP user agents) while discarding noise.

## Accomplishments

- **End-to-end demo working**: `python src/agent.py --case samples/demo_case/` produces a full IR report from a real PCAP file
- **DNS tunneling detection**: confidence score 72/100 (HIGH) — tshark identifies 15+ long subdomain queries, mapped to MITRE T1071.004
- **C2 communication detection**: confidence score 70/100 (HIGH) — suspicious HTTP user agents (Python requests, PowerShell) detected, mapped to T1071.001
- **10 MCP tools** fully implemented and tested
- **Confidence scoring** validated against 6 unit test cases (all passing)
- **YARA rules** for financial malware patterns included in `samples/demo_case/financial_malware.yar`

## What We Learned

Building on the **SIFT + MCP** architecture taught us that the hardest part of AI-assisted forensics isn't the AI — it's the evidence chain. The MCP protocol forces a clean separation between "what the AI thinks" and "what the tools actually found." That separation is what makes the system trustworthy.

We also learned that **confidence scoring is a forcing function for better tool design**. When every finding needs a score, you're forced to think carefully about what evidence actually supports a conclusion. It made us write better parsers, use more specific IOCs, and map findings to MITRE techniques rather than vague descriptions.

The SIFT toolchain itself is remarkably powerful. Volatility3's plugin architecture, tshark's display filters, and YARA's rule language give you everything you need for deep forensic analysis — the gap was always the orchestration layer, not the tools themselves.

## What's Next

- **Memory forensics integration**: the current demo focuses on network traffic; the next phase adds full Volatility3 memory analysis with process injection detection and credential extraction alerts
- **Real-time alerting**: stream findings to a SIEM or Slack channel as they're discovered, rather than waiting for the full report
- **Expanded YARA ruleset**: partner with threat intelligence feeds to keep financial malware signatures current
- **Enterprise deployment**: package as a Docker container with a REST API so SOC teams can integrate FinSOC Agent into existing IR workflows without touching the underlying SIFT installation
- **Analyst feedback loop**: let analysts mark findings as true/false positive to tune the confidence scoring weights over time
