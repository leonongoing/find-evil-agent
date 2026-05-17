# FinSOC Agent — 3-Minute Demo Video Script

**Total Duration:** 3:00  
**Format:** Screen recording with voiceover  
**Setup:** Terminal + code editor side by side, dark theme

---

## [0:00 – 0:30] Problem Statement

**[SCREEN: Title card — "FinSOC Agent: AI-Powered Incident Response"]**

**VOICEOVER:**
> "In 2024, researchers showed that an AI-powered attacker can achieve full domain compromise in under 8 minutes. From initial foothold to domain controller — 8 minutes.
>
> A human SOC analyst, working through alert queues and running forensic tools manually, cannot match that speed. By the time they've opened Volatility and run pslist, the attacker has already moved laterally.
>
> FinSOC Agent is our answer: an AI defender that runs the same SIFT forensic toolkit — but at machine speed, with every finding scored for confidence and backed by a full evidence chain."

**[SCREEN: Split — left: attacker timeline (8 min), right: FinSOC Agent analysis starting]**

---

## [0:30 – 1:30] Live Analysis Demo

**[SCREEN: Terminal, project root]**

**VOICEOVER:**
> "Let's run a real analysis. We have a PCAP file captured from a simulated financial institution network. We'll point FinSOC Agent at it."

**[TYPE IN TERMINAL:]**
```bash
python src/agent.py --case samples/demo_case/ --verbose
```

**[SCREEN: Agent output scrolling — show verbose logs]**

**VOICEOVER (as output appears):**
> "The agent discovers the PCAP file automatically. It calls tshark to extract DNS queries first..."

**[SCREEN: Show DNS extraction output — long subdomain queries appearing]**

> "...and immediately flags something suspicious. These DNS queries have subdomains over 50 characters long. That's a classic DNS tunneling signature — attackers use it to exfiltrate data through DNS, which most firewalls don't block."

**[SCREEN: HTTP extraction output appearing]**

> "Next, HTTP traffic. The agent spots a Python requests user agent making POST requests to an unusual external host. That's a C2 beacon — command and control communication."

**[SCREEN: Final report printing]**

> "In under 10 seconds, we have two high-confidence findings. Let's look at what the scoring engine produced."

---

## [1:30 – 2:30] Confidence Scoring Deep Dive

**[SCREEN: Report output, zoom in on Finding F001]**

**VOICEOVER:**
> "This is the key differentiator. Every finding has a confidence score."

**[SCREEN: Highlight the confidence score line]**

```
[1] HIGH — exfiltration
    Description: Possible DNS tunneling: 15 long subdomain queries detected
    Confidence: 72/100 (HIGH)
    MITRE: T1071.004
    IOCs: a3f2b1c9d8e7.evil-c2.com, ...
```

> "72 out of 100. Labeled HIGH. Here's how that score was calculated:"

**[SCREEN: Switch to confidence.py, show the scoring logic]**

> "tshark has a reliability score of 0.90 — it's a mature, deterministic tool. That gives us a base of 54 points. The finding is corroborated by a single tool, so no corroboration bonus. But we have 5 specific IOC domains, adding 5 points. And we've mapped it to MITRE T1071.004, adding 5 more. Total: 72."

**[SCREEN: Back to terminal, show Finding F002]**

```
[2] MEDIUM — c2_communication
    Description: Suspicious HTTP user agents detected: python-requests/2.28
    Confidence: 70/100 (HIGH)
    MITRE: T1071.001
    IOCs: python-requests/2.28, PowerShell/5.1
```

> "The C2 finding scores 70. Same tshark base, but the IOCs here are user agent strings — less specific than domain names, so slightly lower score."

**[SCREEN: Show what happens with a LOW confidence finding — score below 30 gets suppressed]**

> "Findings below 30 are suppressed entirely. The analyst only sees what the evidence actually supports. No hallucinations, no noise."

---

## [2:30 – 3:00] Architecture Summary & What's Next

**[SCREEN: Architecture diagram]**

```
OpenClaw Agent Runtime
        ↓
   FinSOC SKILL.md
        ↓
   MCP Server (10 tools)
   ┌─────────────────────────────────┐
   │ memory_pslist  memory_netscan   │
   │ memory_malfind                  │
   │ network_dns_extract             │
   │ network_http_extract            │
   │ network_connections             │
   │ filesystem_list                 │
   │ yara_scan  binary_strings       │
   │ score_finding                   │
   └─────────────────────────────────┘
        ↓
   Confidence Scoring Engine
        ↓
   Structured IR Report
```

**VOICEOVER:**
> "The architecture is clean: OpenClaw orchestrates the agent, the MCP server wraps 10 SIFT tools, and every finding passes through the Confidence Scoring Engine before it reaches the analyst.

> What's next: memory forensics integration for live incident response, real-time alerting via SIEM connectors, and enterprise deployment packaging.

> FinSOC Agent — because when the attacker has AI, the defender needs AI too."

**[SCREEN: GitHub repo URL + Devpost link]**

---

## Recording Notes

- Use a dark terminal theme (Dracula or One Dark)
- Font size: 18pt minimum for readability
- Run the demo command live — don't fake the output
- Pause 1 second after each finding appears before continuing voiceover
- Total runtime target: 2:50–3:00
- Export at 1080p minimum
