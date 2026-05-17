"""
SIFT Tool Wrappers for FinSOC Agent
====================================
Each wrapper runs a SIFT tool, captures output, and returns Evidence objects.
All commands are parameterized to prevent injection.
"""

import subprocess
import shlex
from pathlib import Path
from .confidence import Evidence


def _run(tool: str, args: list[str], timeout: int = 60) -> Evidence:
    """Run a tool safely with parameterized args."""
    cmd = [tool] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout + result.stderr
        return Evidence(
            tool=tool,
            command=" ".join(shlex.quote(a) for a in cmd),
            raw_output=output[:10000],  # cap at 10KB
            exit_code=result.returncode
        )
    except subprocess.TimeoutExpired:
        return Evidence(
            tool=tool,
            command=" ".join(shlex.quote(a) for a in cmd),
            raw_output=f"TIMEOUT after {timeout}s",
            exit_code=-1
        )
    except FileNotFoundError:
        return Evidence(
            tool=tool,
            command=" ".join(shlex.quote(a) for a in cmd),
            raw_output=f"Tool not found: {tool}",
            exit_code=-2
        )


# ── Memory Forensics (Volatility3) ──────────────────────────────────────────

def vol_pslist(memory_image: str) -> Evidence:
    """List running processes from memory dump."""
    return _run("vol", ["-f", memory_image, "windows.pslist.PsList"])


def vol_netscan(memory_image: str) -> Evidence:
    """Scan network connections from memory dump."""
    return _run("vol", ["-f", memory_image, "windows.netstat.NetStat"])


def vol_cmdline(memory_image: str) -> Evidence:
    """Extract command line arguments from processes."""
    return _run("vol", ["-f", memory_image, "windows.cmdline.CmdLine"])


def vol_malfind(memory_image: str) -> Evidence:
    """Find injected code / suspicious memory regions."""
    return _run("vol", ["-f", memory_image, "windows.malfind.Malfind"], timeout=120)


# ── File System Forensics (Sleuth Kit) ──────────────────────────────────────

def fls_list(image: str, inode: str = "") -> Evidence:
    """List files in a disk image."""
    args = [image]
    if inode:
        args = ["-r", "-p", image, inode]
    return _run("fls", args)


def mmls_partitions(image: str) -> Evidence:
    """List partition table of a disk image."""
    return _run("mmls", [image])


def icat_extract(image: str, inode: str, output_path: str) -> Evidence:
    """Extract a file by inode from disk image."""
    return _run("icat", [image, inode])


# ── Network Analysis (TShark) ────────────────────────────────────────────────

def tshark_summary(pcap: str) -> Evidence:
    """Summarize network capture."""
    return _run("tshark", ["-r", pcap, "-q", "-z", "io,stat,0"])


def tshark_dns(pcap: str) -> Evidence:
    """Extract DNS queries from pcap."""
    return _run("tshark", ["-r", pcap, "-Y", "dns", "-T", "fields",
                            "-e", "dns.qry.name", "-e", "dns.a"])


def tshark_http(pcap: str) -> Evidence:
    """Extract HTTP requests from pcap."""
    return _run("tshark", ["-r", pcap, "-Y", "http.request", "-T", "fields",
                            "-e", "http.host", "-e", "http.request.uri",
                            "-e", "http.user_agent"])


def tshark_connections(pcap: str) -> Evidence:
    """List all TCP connections."""
    return _run("tshark", ["-r", pcap, "-q", "-z", "conv,tcp"])


# ── Malware Detection (YARA) ─────────────────────────────────────────────────

def yara_scan(rules_file: str, target: str) -> Evidence:
    """Scan a file or directory with YARA rules."""
    return _run("yara", ["-r", rules_file, target])


# ── Binary Analysis ──────────────────────────────────────────────────────────

def extract_strings(binary: str, min_length: int = 8) -> Evidence:
    """Extract printable strings from binary."""
    return _run("strings", [f"-n{min_length}", binary])


def binwalk_analyze(binary: str) -> Evidence:
    """Analyze binary for embedded files/signatures."""
    return _run("binwalk", [binary])
