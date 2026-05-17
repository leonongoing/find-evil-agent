"""
FinSOC Agent — Main IR Agent
=============================
Orchestrates SIFT tools, scores findings, and produces audit-trail reports.
"""

import argparse
import json
import sys
from pathlib import Path
from .confidence import ConfidenceScorer, Finding, Evidence
from . import tools


class FinSOCAgent:
    """
    Financial Security Operations Center AI Agent.
    
    Runs forensic tools, scores findings with confidence, and produces
    a structured IR report with full evidence chain.
    """

    def __init__(self, case_dir: str, verbose: bool = False):
        self.case_dir = Path(case_dir)
        self.verbose = verbose
        self.scorer = ConfidenceScorer()
        self.findings: list[Finding] = []
        self._finding_counter = 0

    def _next_id(self) -> str:
        self._finding_counter += 1
        return f"F{self._finding_counter:03d}"

    def _log(self, msg: str):
        if self.verbose:
            print(f"[FinSOC] {msg}", file=sys.stderr)

    def analyze_pcap(self, pcap_path: str) -> list[Finding]:
        """Analyze a network capture file."""
        self._log(f"Analyzing pcap: {pcap_path}")
        findings = []

        # Collect evidence
        dns_ev = tools.tshark_dns(pcap_path)
        http_ev = tools.tshark_http(pcap_path)
        conn_ev = tools.tshark_connections(pcap_path)

        # Look for suspicious DNS (long subdomains = DNS tunneling)
        if dns_ev.exit_code == 0:
            suspicious_domains = [
                line for line in dns_ev.raw_output.splitlines()
                if len(line) > 50 and "." in line
            ]
            if suspicious_domains:
                iocs = suspicious_domains[:5]
                score = self.scorer.score(
                    [dns_ev], iocs=iocs, mitre_technique="T1071.004"
                )
                findings.append(Finding(
                    finding_id=self._next_id(),
                    category="exfiltration",
                    description=f"Possible DNS tunneling: {len(suspicious_domains)} long subdomain queries detected",
                    confidence=score,
                    severity="high",
                    evidence=[dns_ev],
                    iocs=iocs,
                    mitre_technique="T1071.004"
                ))

        # Look for suspicious HTTP (unusual user agents, POST to rare hosts)
        if http_ev.exit_code == 0:
            lines = http_ev.raw_output.splitlines()
            suspicious_ua = [l for l in lines if any(
                ua in l.lower() for ua in ["python", "curl", "wget", "powershell", "go-http"]
            )]
            if suspicious_ua:
                score = self.scorer.score(
                    [http_ev], iocs=suspicious_ua[:3], mitre_technique="T1071.001"
                )
                findings.append(Finding(
                    finding_id=self._next_id(),
                    category="c2_communication",
                    description=f"Suspicious HTTP user agents detected: {suspicious_ua[0][:80]}",
                    confidence=score,
                    severity="medium",
                    evidence=[http_ev],
                    iocs=suspicious_ua[:3],
                    mitre_technique="T1071.001"
                ))

        return findings

    def analyze_memory(self, memory_image: str) -> list[Finding]:
        """Analyze a memory dump."""
        self._log(f"Analyzing memory image: {memory_image}")
        findings = []

        pslist_ev = tools.vol_pslist(memory_image)
        cmdline_ev = tools.vol_cmdline(memory_image)

        # Look for suspicious processes
        if pslist_ev.exit_code == 0:
            suspicious_procs = [
                line for line in pslist_ev.raw_output.splitlines()
                if any(p in line.lower() for p in [
                    "mimikatz", "meterpreter", "cobalt", "beacon",
                    "powershell", "wscript", "cscript", "regsvr32"
                ])
            ]
            if suspicious_procs:
                score = self.scorer.score(
                    [pslist_ev, cmdline_ev],
                    iocs=suspicious_procs[:3],
                    mitre_technique="T1059.001"
                )
                findings.append(Finding(
                    finding_id=self._next_id(),
                    category="execution",
                    description=f"Suspicious process(es) detected in memory: {suspicious_procs[0][:80]}",
                    confidence=score,
                    severity="critical",
                    evidence=[pslist_ev, cmdline_ev],
                    iocs=suspicious_procs[:3],
                    mitre_technique="T1059.001"
                ))

        return findings

    def run(self) -> dict:
        """Run full IR analysis on case directory."""
        self._log(f"Starting analysis of case: {self.case_dir}")

        # Find artifacts
        pcaps = list(self.case_dir.glob("**/*.pcap")) + list(self.case_dir.glob("**/*.pcapng"))
        memory_images = list(self.case_dir.glob("**/*.mem")) + list(self.case_dir.glob("**/*.raw"))

        for pcap in pcaps:
            self._log(f"Found pcap: {pcap}")
            self.findings.extend(self.analyze_pcap(str(pcap)))

        for mem in memory_images:
            self._log(f"Found memory image: {mem}")
            self.findings.extend(self.analyze_memory(str(mem)))

        # Filter low-confidence findings
        reportable = [f for f in self.findings if self.scorer.should_report(f.confidence)]

        report = {
            "case_dir": str(self.case_dir),
            "total_findings": len(self.findings),
            "reportable_findings": len(reportable),
            "findings": [f.to_dict() for f in reportable]
        }

        return report


def main():
    parser = argparse.ArgumentParser(description="FinSOC Agent — IR Analysis")
    parser.add_argument("--case", required=True, help="Case directory with forensic artifacts")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    agent = FinSOCAgent(args.case, verbose=args.verbose)
    report = agent.run()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        scorer = ConfidenceScorer()
        findings = [
            Finding(
                finding_id=f["finding_id"],
                category=f["category"],
                description=f["description"],
                confidence=f["confidence"],
                severity=f["severity"],
                iocs=f.get("iocs", []),
                mitre_technique=f.get("mitre_technique")
            )
            for f in report["findings"]
        ]
        print(scorer.format_report(findings))


if __name__ == "__main__":
    main()
