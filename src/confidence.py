"""
Confidence Scoring Engine for FinSOC Agent
==========================================
Every forensic finding gets a confidence score (0-100) and evidence chain.
Core differentiator vs Protocol SIFT hallucination problem.
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class Evidence:
    tool: str
    command: str
    raw_output: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    exit_code: int = 0


@dataclass
class Finding:
    finding_id: str
    category: str
    description: str
    confidence: int        # 0-100
    severity: str          # critical/high/medium/low/info
    evidence: list = field(default_factory=list)
    iocs: list = field(default_factory=list)
    mitre_technique: Optional[str] = None
    analyst_note: str = ""

    def confidence_label(self) -> str:
        if self.confidence >= 90: return "CONFIRMED"
        elif self.confidence >= 70: return "HIGH"
        elif self.confidence >= 50: return "MEDIUM"
        elif self.confidence >= 30: return "LOW"
        else: return "SPECULATIVE"

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "description": self.description,
            "confidence": self.confidence,
            "confidence_label": self.confidence_label(),
            "severity": self.severity,
            "mitre_technique": self.mitre_technique,
            "iocs": self.iocs,
            "evidence_count": len(self.evidence),
            "analyst_note": self.analyst_note
        }


class ConfidenceScorer:
    """Score forensic findings based on evidence quality and corroboration."""

    TOOL_RELIABILITY = {
        "volatility3": 0.95, "vol": 0.95,
        "sleuthkit": 0.90, "fls": 0.90, "mmls": 0.90, "icat": 0.90,
        "tshark": 0.90,
        "yara": 0.85,
        "strings": 0.60,
        "binwalk": 0.70,
    }

    def score(self, evidence_list: list, iocs: list = None,
              mitre_technique: str = None) -> int:
        if not evidence_list:
            return 0

        # Base: avg tool reliability (max 60 pts)
        tool_scores = []
        for e in evidence_list:
            tool_name = e.tool.lower().split()[0]
            reliability = self.TOOL_RELIABILITY.get(tool_name, 0.5)
            if e.exit_code != 0:
                reliability *= 0.3
            tool_scores.append(reliability)
        base_score = (sum(tool_scores) / len(tool_scores)) * 60

        # Corroboration: unique tools (max 20 pts)
        unique_tools = len(set(e.tool for e in evidence_list))
        corroboration_bonus = min(unique_tools * 8, 20)

        # IOC specificity (max 15 pts)
        ioc_bonus = 0
        for ioc in (iocs or []):
            if len(ioc) in (32, 64):  # MD5/SHA256
                ioc_bonus += 5
            elif ioc.startswith(("http://", "https://")):
                ioc_bonus += 3
            else:
                ioc_bonus += 1
        ioc_bonus = min(ioc_bonus, 15)

        # MITRE match (5 pts)
        mitre_bonus = 5 if mitre_technique else 0

        return min(int(base_score + corroboration_bonus + ioc_bonus + mitre_bonus), 100)

    def format_report(self, findings: list) -> str:
        if not findings:
            return "No findings above confidence threshold."
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 5), -f.confidence)
        )
        lines = [
            "=" * 60,
            "INCIDENT RESPONSE FINDINGS REPORT",
            f"Generated: {datetime.utcnow().isoformat()}Z",
            f"Total Findings: {len(findings)}",
            "=" * 60, ""
        ]
        for i, f in enumerate(sorted_findings, 1):
            lines += [
                f"[{i}] {f.severity.upper()} — {f.category}",
                f"    Description: {f.description}",
                f"    Confidence: {f.confidence}/100 ({f.confidence_label()})",
                f"    MITRE: {f.mitre_technique or 'N/A'}",
                f"    IOCs: {', '.join(f.iocs) if f.iocs else 'none'}",
                ""
            ]
        return "\n".join(lines)

    def should_report(self, score: int, threshold: int = 30) -> bool:
        """Only report findings above threshold to reduce noise."""
        return score >= threshold
