"""
FinSOC Agent — MCP Server
==========================
Exposes SIFT forensic tools as MCP tools for OpenClaw/Claude integration.
Each tool returns structured output with confidence scoring.

Usage:
    python3 -m src.mcp_server
"""

import asyncio
import json
import logging
import subprocess
import shlex
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .confidence import ConfidenceScorer, Evidence, Finding
from . import tools as sift

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Server("finsoc-ir-agent")
scorer = ConfidenceScorer()


def _evidence_to_dict(ev: Evidence) -> dict:
    return {
        "tool": ev.tool,
        "command": ev.command,
        "exit_code": ev.exit_code,
        "timestamp": ev.timestamp,
        "output": ev.raw_output[:2000]  # cap for MCP response size
    }


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="memory_pslist",
            description=(
                "List running processes from a Windows memory dump using Volatility3. "
                "Returns process names, PIDs, PPIDs, and timestamps. "
                "Use to detect suspicious processes (mimikatz, meterpreter, etc.)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_image": {
                        "type": "string",
                        "description": "Absolute path to the memory dump file (.mem, .raw, .vmem)"
                    }
                },
                "required": ["memory_image"]
            }
        ),
        Tool(
            name="memory_netscan",
            description=(
                "Scan network connections from a Windows memory dump. "
                "Returns active/closed TCP/UDP connections with remote IPs and ports. "
                "Use to detect C2 connections, lateral movement, or data exfiltration."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_image": {"type": "string", "description": "Path to memory dump"}
                },
                "required": ["memory_image"]
            }
        ),
        Tool(
            name="memory_malfind",
            description=(
                "Find injected code and suspicious memory regions in a Windows memory dump. "
                "Detects process injection, shellcode, and reflective DLL loading. "
                "High-confidence indicator of malware presence."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "memory_image": {"type": "string", "description": "Path to memory dump"}
                },
                "required": ["memory_image"]
            }
        ),
        Tool(
            name="network_dns_extract",
            description=(
                "Extract all DNS queries from a PCAP network capture. "
                "Returns queried domains and resolved IPs. "
                "Use to detect DNS tunneling, C2 beaconing, or data exfiltration via DNS."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_path": {"type": "string", "description": "Path to .pcap or .pcapng file"}
                },
                "required": ["pcap_path"]
            }
        ),
        Tool(
            name="network_http_extract",
            description=(
                "Extract HTTP requests from a PCAP file. "
                "Returns hosts, URIs, and user agents. "
                "Use to detect web-based C2, malware downloads, or credential theft."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_path": {"type": "string", "description": "Path to .pcap or .pcapng file"}
                },
                "required": ["pcap_path"]
            }
        ),
        Tool(
            name="network_connections",
            description=(
                "List all TCP connections from a PCAP file with byte counts. "
                "Use to identify high-volume data transfers (exfiltration) or "
                "unusual connection patterns."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pcap_path": {"type": "string", "description": "Path to .pcap or .pcapng file"}
                },
                "required": ["pcap_path"]
            }
        ),
        Tool(
            name="filesystem_list",
            description=(
                "List files in a disk image using Sleuth Kit. "
                "Returns file names, inodes, and metadata. "
                "Use to find deleted files, hidden directories, or suspicious artifacts."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "image_path": {"type": "string", "description": "Path to disk image"},
                    "inode": {"type": "string", "description": "Optional: specific inode to list", "default": ""}
                },
                "required": ["image_path"]
            }
        ),
        Tool(
            name="yara_scan",
            description=(
                "Scan a file or directory with YARA rules for malware signatures. "
                "Returns matching rule names and file locations. "
                "Use to detect known malware families, exploit kits, or custom IOCs."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "rules_file": {"type": "string", "description": "Path to .yar YARA rules file"},
                    "target": {"type": "string", "description": "Path to file or directory to scan"}
                },
                "required": ["rules_file", "target"]
            }
        ),
        Tool(
            name="binary_strings",
            description=(
                "Extract printable strings from a binary file. "
                "Use to find hardcoded C2 addresses, credentials, registry keys, "
                "or other IOCs embedded in malware."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "Path to binary file"},
                    "min_length": {"type": "integer", "description": "Minimum string length (default: 8)", "default": 8}
                },
                "required": ["binary_path"]
            }
        ),
        Tool(
            name="score_finding",
            description=(
                "Calculate a confidence score (0-100) for a forensic finding. "
                "Input: list of tool names used, list of IOCs found, optional MITRE technique. "
                "Output: score + label (CONFIRMED/HIGH/MEDIUM/LOW/SPECULATIVE). "
                "Use before reporting any finding to avoid hallucinations."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tools_used": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of tool names that produced evidence (e.g. ['volatility3', 'tshark'])"
                    },
                    "iocs": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of IOCs found (hashes, IPs, domains, etc.)"
                    },
                    "mitre_technique": {
                        "type": "string",
                        "description": "Optional MITRE ATT&CK technique ID (e.g. 'T1059.001')"
                    },
                    "all_tools_succeeded": {
                        "type": "boolean",
                        "description": "Whether all tool calls returned exit code 0",
                        "default": True
                    }
                },
                "required": ["tools_used"]
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        result = await _dispatch(name, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        logger.exception("Tool %s failed", name)
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]


async def _dispatch(name: str, args: dict) -> dict:
    loop = asyncio.get_event_loop()

    if name == "memory_pslist":
        ev = await loop.run_in_executor(None, sift.vol_pslist, args["memory_image"])
        return {"tool": "memory_pslist", "evidence": _evidence_to_dict(ev)}

    elif name == "memory_netscan":
        ev = await loop.run_in_executor(None, sift.vol_netscan, args["memory_image"])
        return {"tool": "memory_netscan", "evidence": _evidence_to_dict(ev)}

    elif name == "memory_malfind":
        ev = await loop.run_in_executor(None, sift.vol_malfind, args["memory_image"])
        return {"tool": "memory_malfind", "evidence": _evidence_to_dict(ev)}

    elif name == "network_dns_extract":
        ev = await loop.run_in_executor(None, sift.tshark_dns, args["pcap_path"])
        return {"tool": "network_dns_extract", "evidence": _evidence_to_dict(ev)}

    elif name == "network_http_extract":
        ev = await loop.run_in_executor(None, sift.tshark_http, args["pcap_path"])
        return {"tool": "network_http_extract", "evidence": _evidence_to_dict(ev)}

    elif name == "network_connections":
        ev = await loop.run_in_executor(None, sift.tshark_connections, args["pcap_path"])
        return {"tool": "network_connections", "evidence": _evidence_to_dict(ev)}

    elif name == "filesystem_list":
        ev = await loop.run_in_executor(
            None, sift.fls_list, args["image_path"], args.get("inode", "")
        )
        return {"tool": "filesystem_list", "evidence": _evidence_to_dict(ev)}

    elif name == "yara_scan":
        ev = await loop.run_in_executor(
            None, sift.yara_scan, args["rules_file"], args["target"]
        )
        return {"tool": "yara_scan", "evidence": _evidence_to_dict(ev)}

    elif name == "binary_strings":
        ev = await loop.run_in_executor(
            None, sift.extract_strings, args["binary_path"], args.get("min_length", 8)
        )
        return {"tool": "binary_strings", "evidence": _evidence_to_dict(ev)}

    elif name == "score_finding":
        # Build synthetic Evidence objects for scoring
        evidence_list = []
        for tool_name in args.get("tools_used", []):
            exit_code = 0 if args.get("all_tools_succeeded", True) else 1
            evidence_list.append(Evidence(
                tool=tool_name,
                command=f"{tool_name} [invoked]",
                raw_output="[evidence captured separately]",
                exit_code=exit_code
            ))
        score = scorer.score(
            evidence_list,
            iocs=args.get("iocs", []),
            mitre_technique=args.get("mitre_technique")
        )
        # Build a temporary Finding to get the label
        f = Finding("tmp", "tmp", "tmp", score, "info")
        return {
            "confidence_score": score,
            "confidence_label": f.confidence_label(),
            "should_report": scorer.should_report(score),
            "guidance": (
                "Report this finding." if scorer.should_report(score)
                else "Score too low — gather more evidence before reporting."
            )
        }

    else:
        raise ValueError(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
