#!/usr/bin/env python3
"""
MacMCP - MCP server for macOS malware analysis and security research.

Provides tools to remotely analyze macOS systems via SSH, equivalent to
the FlareVM MCP for Windows analysis.
"""

import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# Add parent dir to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from mac_connection import MacConnection, get_connection

# ---------------------------------------------------------------------------
# Server init
# ---------------------------------------------------------------------------

server = Server("macmcp")
CONFIG_PATH = os.environ.get("MACMCP_CONFIG", os.path.join(os.path.dirname(__file__), "config.json"))


def conn() -> MacConnection:
    return get_connection(CONFIG_PATH)


def _ok(text: str) -> list[TextContent]:
    return [TextContent(type="text", text=text)]


def _run(cmd: str, timeout: int = 60) -> str:
    """Run command and return formatted output."""
    code, out, err = conn().run(cmd, timeout=timeout)
    parts = []
    if out.strip():
        parts.append(out.strip())
    if err.strip():
        parts.append(f"[stderr]\n{err.strip()}")
    parts.append(f"[exit: {code}]")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

TOOLS = [
    # ── Connection & File Transfer ──────────────────────────────────────────
    Tool(
        name="check_connection",
        description="Verify SSH connection to the macOS machine. Always call this first.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="upload_file",
        description="Upload a file from the local machine to the macOS target.",
        inputSchema={
            "type": "object",
            "properties": {
                "local_path": {"type": "string", "description": "Path on this machine"},
                "remote_path": {"type": "string", "description": "Destination path on macOS"},
            },
            "required": ["local_path", "remote_path"],
        },
    ),
    Tool(
        name="download_file",
        description="Download a file from the macOS target to the local machine.",
        inputSchema={
            "type": "object",
            "properties": {
                "remote_path": {"type": "string", "description": "Path on macOS"},
                "local_path": {"type": "string", "description": "Destination path on this machine"},
            },
            "required": ["remote_path", "local_path"],
        },
    ),
    # ── Basic System Operations ─────────────────────────────────────────────
    Tool(
        name="execute_bash",
        description="Execute a bash command on the macOS machine. Returns stdout, stderr, and exit code.",
        inputSchema={
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Bash command to run"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 60)", "default": 60},
                "use_sudo": {"type": "boolean", "description": "Run with sudo (default false)", "default": False},
            },
            "required": ["command"],
        },
    ),
    Tool(
        name="read_file",
        description="Read the contents of a file on the macOS machine.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to file on macOS"},
                "max_bytes": {"type": "integer", "description": "Max bytes to read (default 100000)", "default": 100000},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="get_file_hash",
        description="Calculate MD5, SHA1, and SHA256 hashes of a file on macOS.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to file on macOS"},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="list_processes",
        description="List running processes on macOS, with optional name filter.",
        inputSchema={
            "type": "object",
            "properties": {
                "filter": {"type": "string", "description": "Optional process name filter"},
            },
            "required": [],
        },
    ),
    Tool(
        name="get_system_info",
        description="Get macOS system information: version, hardware, SIP status, SecureBootStatus.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    # ── Static Analysis ─────────────────────────────────────────────────────
    Tool(
        name="analyze_macho",
        description="Analyze a Mach-O binary: file type, architecture, headers, load commands, linked libraries.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to Mach-O binary on macOS"},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="extract_strings",
        description="Extract printable strings from a binary file on macOS.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to file on macOS"},
                "min_length": {"type": "integer", "description": "Minimum string length (default 6)", "default": 6},
                "filter_pattern": {"type": "string", "description": "Optional regex to filter strings (e.g. 'http|flag|key')"},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="analyze_code_signing",
        description="Analyze code signature of a binary: certificate, entitlements, team ID, notarization status.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to binary or app bundle on macOS"},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="get_entitlements",
        description="Extract entitlements from a signed binary or app bundle.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to binary or .app on macOS"},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="analyze_dylibs",
        description="List dynamic libraries linked by a Mach-O binary (otool -L).",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to binary on macOS"},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="get_quarantine_info",
        description="Get quarantine extended attributes and origin info for a file (xattr, quarantine DB).",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to file on macOS"},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="check_gatekeeper",
        description="Check Gatekeeper/Notarization assessment for a file or app bundle.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to file or .app on macOS"},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="disassemble_function",
        description="Disassemble a function in a Mach-O binary using otool.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to binary on macOS"},
                "arch": {"type": "string", "description": "Architecture: arm64 or x86_64 (default: auto-detect)"},
            },
            "required": ["file_path"],
        },
    ),
    # ── Network Analysis ────────────────────────────────────────────────────
    Tool(
        name="monitor_network_realtime",
        description="Capture real-time network connections on macOS using lsof and netstat.",
        inputSchema={
            "type": "object",
            "properties": {
                "duration": {"type": "integer", "description": "Capture duration in seconds (default 10)", "default": 10},
                "process_filter": {"type": "string", "description": "Optional process name filter"},
            },
            "required": [],
        },
    ),
    Tool(
        name="tcpdump_start",
        description="Start tcpdump packet capture on macOS in background. Returns capture file path.",
        inputSchema={
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Network interface (default: en0)", "default": "en0"},
                "output_file": {"type": "string", "description": "Output pcap file path (default: /tmp/macmcp/capture.pcap)"},
                "filter": {"type": "string", "description": "BPF filter string (e.g. 'tcp port 443')"},
            },
            "required": [],
        },
    ),
    Tool(
        name="tcpdump_stop",
        description="Stop tcpdump capture and return summary of captured packets.",
        inputSchema={
            "type": "object",
            "properties": {
                "output_file": {"type": "string", "description": "Pcap file path to analyze (default: /tmp/macmcp/capture.pcap)"},
                "download_to": {"type": "string", "description": "Optional local path to download the pcap file to"},
            },
            "required": [],
        },
    ),
    # ── Process & File System Monitoring ───────────────────────────────────
    Tool(
        name="fs_usage_monitor",
        description="Monitor filesystem and system calls for a process using fs_usage (requires sudo).",
        inputSchema={
            "type": "object",
            "properties": {
                "process_name": {"type": "string", "description": "Process name to filter (optional)"},
                "duration": {"type": "integer", "description": "Duration in seconds (default 15)", "default": 15},
                "output_file": {"type": "string", "description": "Optional file to save output to on macOS"},
            },
            "required": [],
        },
    ),
    Tool(
        name="dtrace_trace",
        description="Run a DTrace one-liner or script on macOS for syscall/API tracing.",
        inputSchema={
            "type": "object",
            "properties": {
                "script": {"type": "string", "description": "DTrace script content or one-liner"},
                "pid": {"type": "integer", "description": "Target PID (optional)"},
                "process_name": {"type": "string", "description": "Target process name (optional)"},
                "duration": {"type": "integer", "description": "Duration in seconds (default 10)", "default": 10},
            },
            "required": ["script"],
        },
    ),
    Tool(
        name="execute_with_monitoring",
        description=(
            "Execute a program on macOS with comprehensive monitoring: "
            "file system activity (fs_usage), network connections, and process tree. "
            "Returns a full behavioral report."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "executable": {"type": "string", "description": "Path to executable or app on macOS"},
                "arguments": {"type": "string", "description": "Optional command-line arguments"},
                "duration": {"type": "integer", "description": "Monitoring duration in seconds (default 30)", "default": 30},
            },
            "required": ["executable"],
        },
    ),
    # ── Persistence Analysis ────────────────────────────────────────────────
    Tool(
        name="list_launch_agents",
        description=(
            "List all LaunchAgents and LaunchDaemons (persistence locations). "
            "Covers user, system, and third-party locations."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "filter": {"type": "string", "description": "Optional filter string for plist names"},
            },
            "required": [],
        },
    ),
    Tool(
        name="analyze_plist",
        description="Parse and display a plist file in human-readable format.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to .plist file on macOS"},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="check_persistence",
        description=(
            "Comprehensive persistence check: LaunchAgents/Daemons, login items, "
            "cron jobs, kernel extensions, login/logout hooks, emond rules, "
            "periodic scripts, at jobs."
        ),
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="list_login_items",
        description="List user login items (apps/scripts that run at login) on macOS.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    # ── macOS Security Features ─────────────────────────────────────────────
    Tool(
        name="check_sip_status",
        description="Check System Integrity Protection (SIP) status and configuration.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="check_tcc_permissions",
        description="Check TCC (Transparency, Consent and Control) database for app permissions.",
        inputSchema={
            "type": "object",
            "properties": {
                "app_identifier": {"type": "string", "description": "Optional bundle ID or app name to filter"},
            },
            "required": [],
        },
    ),
    Tool(
        name="list_kernel_extensions",
        description="List loaded and installed kernel extensions (kexts/system extensions).",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="check_network_filters",
        description="List Network Extension and content filter providers (NEFilterDataProvider etc.).",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    # ── Frida Dynamic Instrumentation ──────────────────────────────────────
    Tool(
        name="frida_list_processes",
        description="List processes available for Frida instrumentation on macOS.",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="frida_run_script",
        description="Run a Frida JavaScript instrumentation script on a macOS process.",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Process name or PID to instrument"},
                "script_content": {"type": "string", "description": "Frida JavaScript script"},
                "timeout": {"type": "integer", "description": "Script run timeout in seconds (default 10)", "default": 10},
            },
            "required": ["target", "script_content"],
        },
    ),
    Tool(
        name="frida_spawn_and_attach",
        description="Spawn a process and immediately attach Frida for instrumentation from launch.",
        inputSchema={
            "type": "object",
            "properties": {
                "executable": {"type": "string", "description": "Path to executable to spawn"},
                "script_content": {"type": "string", "description": "Frida JavaScript script"},
                "timeout": {"type": "integer", "description": "Script run timeout in seconds (default 15)", "default": 15},
            },
            "required": ["executable", "script_content"],
        },
    ),
    # ── Memory & Process Inspection ─────────────────────────────────────────
    Tool(
        name="inspect_process",
        description="Detailed inspection of a running process: open files, network connections, memory maps, loaded dylibs.",
        inputSchema={
            "type": "object",
            "properties": {
                "process_name_or_pid": {"type": "string", "description": "Process name or PID"},
            },
            "required": ["process_name_or_pid"],
        },
    ),
    Tool(
        name="dump_process_memory",
        description="Dump memory regions of a running process for analysis.",
        inputSchema={
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Target process PID"},
                "output_dir": {"type": "string", "description": "Directory to save memory dumps (default /tmp/macmcp/memdump)"},
            },
            "required": ["pid"],
        },
    ),
    # ── LLDB Debugging ──────────────────────────────────────────────────────
    Tool(
        name="lldb_run_commands",
        description="Run LLDB debugger commands on a macOS process or binary. Useful for patching anti-debug.",
        inputSchema={
            "type": "object",
            "properties": {
                "executable": {"type": "string", "description": "Path to executable (for launching) or PID (for attaching)"},
                "commands": {"type": "string", "description": "LLDB commands, one per line"},
                "timeout": {"type": "integer", "description": "Timeout in seconds (default 30)", "default": 30},
            },
            "required": ["executable", "commands"],
        },
    ),
    # ── App Bundle Analysis ─────────────────────────────────────────────────
    Tool(
        name="analyze_app_bundle",
        description=(
            "Comprehensive analysis of a macOS .app bundle: "
            "Info.plist, entitlements, frameworks, plugins, code signature, main binary."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "app_path": {"type": "string", "description": "Path to .app bundle on macOS"},
            },
            "required": ["app_path"],
        },
    ),
    Tool(
        name="analyze_pkg_installer",
        description="Analyze a macOS .pkg installer: contents, scripts, distribution XML, certificates.",
        inputSchema={
            "type": "object",
            "properties": {
                "pkg_path": {"type": "string", "description": "Path to .pkg file on macOS"},
                "extract_dir": {"type": "string", "description": "Directory to extract contents (default /tmp/macmcp/pkg_extract)"},
            },
            "required": ["pkg_path"],
        },
    ),
    # ── Screenshot ─────────────────────────────────────────────────────────
    Tool(
        name="take_screenshot",
        description="Take a screenshot on the macOS machine and download it locally.",
        inputSchema={
            "type": "object",
            "properties": {
                "local_save_path": {"type": "string", "description": "Local path to save screenshot (default /tmp/mac_screenshot.png)"},
            },
            "required": [],
        },
    ),
]


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------

@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    c = conn()

    # ── check_connection ─────────────────────────────────────────────────
    if name == "check_connection":
        try:
            code, out, err = c.run("sw_vers && uname -m && uptime", timeout=15)
            if code == 0:
                return _ok(f"[connected]\n{out.strip()}")
            return _ok(f"[connected but command failed]\n{err.strip()}")
        except Exception as e:
            return _ok(f"[connection failed] {e}")

    # ── upload_file ──────────────────────────────────────────────────────
    elif name == "upload_file":
        local = arguments["local_path"]
        remote = arguments["remote_path"]
        c.upload_file(local, remote)
        return _ok(f"Uploaded {local} -> {remote}")

    # ── download_file ─────────────────────────────────────────────────────
    elif name == "download_file":
        remote = arguments["remote_path"]
        local = arguments["local_path"]
        c.download_file(remote, local)
        return _ok(f"Downloaded {remote} -> {local}")

    # ── execute_bash ──────────────────────────────────────────────────────
    elif name == "execute_bash":
        cmd = arguments["command"]
        timeout = arguments.get("timeout", 60)
        use_sudo = arguments.get("use_sudo", False)
        if use_sudo:
            result = c.run_sudo(cmd, timeout=timeout)
            code, out, err = result
        else:
            code, out, err = c.run(cmd, timeout=timeout)
        parts = []
        if out.strip():
            parts.append(out.strip())
        if err.strip():
            parts.append(f"[stderr]\n{err.strip()}")
        parts.append(f"[exit: {code}]")
        return _ok("\n".join(parts))

    # ── read_file ─────────────────────────────────────────────────────────
    elif name == "read_file":
        path = arguments["file_path"]
        max_bytes = arguments.get("max_bytes", 100_000)
        content = c.read_remote_file(path, max_bytes)
        return _ok(content)

    # ── get_file_hash ─────────────────────────────────────────────────────
    elif name == "get_file_hash":
        path = arguments["file_path"]
        cmd = f'md5 "{path}"; shasum -a 1 "{path}"; shasum -a 256 "{path}"'
        return _ok(_run(cmd))

    # ── list_processes ────────────────────────────────────────────────────
    elif name == "list_processes":
        filt = arguments.get("filter", "")
        cmd = "ps aux"
        if filt:
            cmd += f" | grep -i '{filt}' | grep -v grep"
        return _ok(_run(cmd))

    # ── get_system_info ───────────────────────────────────────────────────
    elif name == "get_system_info":
        cmds = [
            "sw_vers",
            "uname -srm",
            "system_profiler SPHardwareDataType | grep -E 'Model|CPU|Memory|Serial'",
            "csrutil status",
            "nvram -p 2>/dev/null | grep -E 'boot-args|security' | head -10",
            "sysctl kern.boottime",
        ]
        results = []
        for cmd in cmds:
            code, out, err = c.run(cmd, timeout=15)
            results.append(out.strip() if code == 0 else f"[{cmd}: failed]")
        return _ok("\n\n".join(r for r in results if r))

    # ── analyze_macho ─────────────────────────────────────────────────────
    elif name == "analyze_macho":
        path = arguments["file_path"]
        cmds = [
            f'file "{path}"',
            f'otool -f "{path}" 2>/dev/null || otool -h "{path}"',  # fat/thin headers
            f'otool -l "{path}" | head -120',
            f'otool -L "{path}"',
            f'nm -m "{path}" 2>/dev/null | head -60 || echo "(nm not available)"',
        ]
        results = []
        for cmd in cmds:
            results.append(_run(cmd, timeout=20))
        return _ok("\n\n---\n\n".join(results))

    # ── extract_strings ───────────────────────────────────────────────────
    elif name == "extract_strings":
        path = arguments["file_path"]
        min_len = arguments.get("min_length", 6)
        pattern = arguments.get("filter_pattern", "")
        cmd = f'strings -n {min_len} "{path}"'
        if pattern:
            cmd += f" | grep -E '{pattern}'"
        return _ok(_run(cmd, timeout=30))

    # ── analyze_code_signing ──────────────────────────────────────────────
    elif name == "analyze_code_signing":
        path = arguments["file_path"]
        cmd = (
            f'codesign -dvvv "{path}" 2>&1; '
            f'echo "---"; '
            f'codesign --verify --deep --strict "{path}" 2>&1; '
            f'echo "---"; '
            f'spctl --assess --verbose "{path}" 2>&1'
        )
        return _ok(_run(cmd, timeout=30))

    # ── get_entitlements ──────────────────────────────────────────────────
    elif name == "get_entitlements":
        path = arguments["file_path"]
        cmd = f'codesign -d --entitlements :- "{path}" 2>&1'
        return _ok(_run(cmd, timeout=15))

    # ── analyze_dylibs ────────────────────────────────────────────────────
    elif name == "analyze_dylibs":
        path = arguments["file_path"]
        cmd = f'otool -L "{path}"'
        return _ok(_run(cmd, timeout=15))

    # ── get_quarantine_info ───────────────────────────────────────────────
    elif name == "get_quarantine_info":
        path = arguments["file_path"]
        cmd = (
            f'xattr -l "{path}"; '
            f'echo "---"; '
            f'xattr -p com.apple.quarantine "{path}" 2>/dev/null || echo "(no quarantine xattr)"'
        )
        return _ok(_run(cmd, timeout=10))

    # ── check_gatekeeper ─────────────────────────────────────────────────
    elif name == "check_gatekeeper":
        path = arguments["file_path"]
        cmd = f'spctl --assess --verbose=4 "{path}" 2>&1; codesign --verify --deep --strict "{path}" 2>&1'
        return _ok(_run(cmd, timeout=20))

    # ── disassemble_function ──────────────────────────────────────────────
    elif name == "disassemble_function":
        path = arguments["file_path"]
        arch = arguments.get("arch", "")
        arch_flag = f"-arch {arch}" if arch else ""
        cmd = f'otool {arch_flag} -tV "{path}" | head -200'
        return _ok(_run(cmd, timeout=30))

    # ── monitor_network_realtime ──────────────────────────────────────────
    elif name == "monitor_network_realtime":
        duration = arguments.get("duration", 10)
        proc_filter = arguments.get("process_filter", "")
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {workdir}")
        out_file = f"{workdir}/netmon_{int(time.time())}.txt"
        if proc_filter:
            cmd = (
                f'(for i in $(seq 1 {duration}); do '
                f'lsof -nP -i -a -c "{proc_filter}" 2>/dev/null; '
                f'sleep 1; done) | sort -u > "{out_file}" 2>&1 &'
            )
        else:
            cmd = (
                f'(for i in $(seq 1 {duration}); do '
                f'lsof -nP -i 2>/dev/null; '
                f'sleep 1; done) | sort -u > "{out_file}" 2>&1 &'
            )
        c.run(cmd)
        time.sleep(duration + 1)
        result = _run(f'cat "{out_file}" 2>/dev/null | head -500')
        c.run(f'rm -f "{out_file}"')
        return _ok(result)

    # ── tcpdump_start ─────────────────────────────────────────────────────
    elif name == "tcpdump_start":
        iface = arguments.get("interface", "en0")
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {workdir}")
        out_file = arguments.get("output_file", f"{workdir}/capture.pcap")
        bpf = arguments.get("filter", "")
        filter_arg = f'"{bpf}"' if bpf else ""
        cmd = f'sudo tcpdump -i {iface} -w "{out_file}" {filter_arg} > /dev/null 2>&1 &'
        c.run_sudo(f'tcpdump -i {iface} -w "{out_file}" {filter_arg} -U > /dev/null 2>&1 & echo $!')
        return _ok(f"tcpdump capture started -> {out_file}")

    # ── tcpdump_stop ──────────────────────────────────────────────────────
    elif name == "tcpdump_stop":
        workdir = c.remote_work_dir
        out_file = arguments.get("output_file", f"{workdir}/capture.pcap")
        download_to = arguments.get("download_to", "")
        # Kill tcpdump
        c.run("sudo pkill tcpdump 2>/dev/null; sleep 1")
        # Summarize with tcpdump -r
        summary = _run(f'tcpdump -r "{out_file}" -nn 2>/dev/null | head -200')
        if download_to:
            c.download_file(out_file, download_to)
            summary += f"\n[pcap downloaded to {download_to}]"
        return _ok(summary)

    # ── fs_usage_monitor ──────────────────────────────────────────────────
    elif name == "fs_usage_monitor":
        proc = arguments.get("process_name", "")
        duration = arguments.get("duration", 15)
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {workdir}")
        out_file = arguments.get("output_file", f"{workdir}/fs_usage_{int(time.time())}.txt")
        proc_flag = f"-f filesystem {proc}" if proc else "-f filesystem"
        cmd = f'sudo timeout {duration} fs_usage {proc_flag} > "{out_file}" 2>&1; echo done'
        code, out, err = c.run_sudo(
            f'timeout {duration} fs_usage {proc_flag} > "{out_file}" 2>&1; echo done',
            timeout=duration + 10,
        )
        result = _run(f'cat "{out_file}" | head -300')
        return _ok(result)

    # ── dtrace_trace ──────────────────────────────────────────────────────
    elif name == "dtrace_trace":
        script = arguments["script"]
        pid = arguments.get("pid")
        proc = arguments.get("process_name", "")
        duration = arguments.get("duration", 10)
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {workdir}")
        script_file = f"{workdir}/dtrace_{int(time.time())}.d"
        # Write script to remote
        escaped = script.replace("'", "'\\''")
        c.run(f"echo '{escaped}' > '{script_file}'")
        pid_flag = f"-p {pid}" if pid else ""
        cmd = f'sudo timeout {duration} dtrace {pid_flag} -s "{script_file}" 2>&1 | head -300'
        code, out, err = c.run(cmd, timeout=duration + 15)
        c.run(f'rm -f "{script_file}"')
        return _ok(out + err)

    # ── execute_with_monitoring ───────────────────────────────────────────
    elif name == "execute_with_monitoring":
        executable = arguments["executable"]
        args = arguments.get("arguments", "")
        duration = arguments.get("duration", 30)
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {workdir}")
        ts = int(time.time())
        net_file = f"{workdir}/net_{ts}.txt"
        fs_file = f"{workdir}/fs_{ts}.txt"
        proc_file = f"{workdir}/proc_{ts}.txt"

        report = [f"=== MacMCP Behavioral Analysis: {executable} ===\n"]

        # Baseline: network connections before
        _, net_before, _ = c.run("lsof -nP -i 2>/dev/null | head -50")

        # Start fs_usage in background
        c.run(
            f'sudo timeout {duration + 5} fs_usage -f filesystem > "{fs_file}" 2>&1 &',
            timeout=5,
        )

        # Start network monitor
        c.run(
            f'(for i in $(seq 1 {duration}); do lsof -nP -i 2>/dev/null; sleep 1; done)'
            f' | sort -u > "{net_file}" 2>&1 &',
            timeout=5,
        )

        # Launch the target
        launch_cmd = f'"{executable}" {args}' if args else f'"{executable}"'
        c.run(f'{launch_cmd} &', timeout=5)

        # Record child processes
        time.sleep(2)
        _, proc_out, _ = c.run(f'pgrep -l -f "{executable}" 2>/dev/null')
        report.append(f"[Processes after launch]\n{proc_out.strip()}")

        # Wait for duration
        time.sleep(duration)

        # Collect results
        _, fs_out, _ = c.run(f'cat "{fs_file}" | head -300')
        _, net_out, _ = c.run(f'cat "{net_file}" | head -100')
        _, ps_out, _ = c.run(f'ps aux | grep -i "{executable}" | grep -v grep')

        report.append(f"\n[File System Activity (fs_usage)]\n{fs_out.strip()}")
        report.append(f"\n[Network Connections]\n{net_out.strip()}")
        report.append(f"\n[Processes]\n{ps_out.strip()}")

        # Cleanup
        c.run(f'sudo pkill -f fs_usage 2>/dev/null; rm -f "{fs_file}" "{net_file}"')

        return _ok("\n".join(report))

    # ── list_launch_agents ────────────────────────────────────────────────
    elif name == "list_launch_agents":
        filt = arguments.get("filter", "")
        dirs = [
            "~/Library/LaunchAgents",
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            "/System/Library/LaunchAgents",
            "/System/Library/LaunchDaemons",
        ]
        results = []
        for d in dirs:
            cmd = f'ls "{d}" 2>/dev/null'
            if filt:
                cmd += f" | grep -i '{filt}'"
            code, out, _ = c.run(cmd, timeout=10)
            if out.strip():
                results.append(f"=== {d} ===\n{out.strip()}")
        return _ok("\n\n".join(results) if results else "No launch agents/daemons found.")

    # ── analyze_plist ─────────────────────────────────────────────────────
    elif name == "analyze_plist":
        path = arguments["file_path"]
        cmd = f'plutil -p "{path}" 2>&1 || cat "{path}"'
        return _ok(_run(cmd, timeout=10))

    # ── check_persistence ─────────────────────────────────────────────────
    elif name == "check_persistence":
        checks = [
            # LaunchAgents/Daemons
            ("LaunchAgents (user)", 'ls ~/Library/LaunchAgents 2>/dev/null'),
            ("LaunchAgents (system)", 'ls /Library/LaunchAgents 2>/dev/null'),
            ("LaunchDaemons", 'ls /Library/LaunchDaemons 2>/dev/null'),
            # Cron
            ("Cron jobs", 'crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null'),
            # Login/Logout hooks
            ("Login hooks", 'sudo defaults read com.apple.loginwindow LoginHook 2>/dev/null'),
            ("Logout hooks", 'sudo defaults read com.apple.loginwindow LogoutHook 2>/dev/null'),
            # At jobs
            ("At jobs", 'sudo atq 2>/dev/null'),
            # Periodic scripts
            ("Periodic scripts", 'ls /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly 2>/dev/null | head -30'),
            # Kernel extensions
            ("Kernel/System Extensions", 'kextstat 2>/dev/null | grep -v apple | head -20; systemextensionsctl list 2>/dev/null | head -30'),
            # Login items (via defaults)
            ("Login items (loginwindow)", 'sudo defaults read com.apple.loginwindow AutoLaunchedApplicationDictionary 2>/dev/null'),
            # Emond
            ("Emond rules", 'ls /etc/emond.d/rules/ 2>/dev/null'),
            # Profiles
            ("Configuration profiles", 'sudo profiles list 2>/dev/null | head -30'),
        ]
        results = []
        for label, cmd in checks:
            code, out, err = c.run(cmd, timeout=10)
            output = out.strip() or err.strip() or "(empty)"
            results.append(f"=== {label} ===\n{output}")
        return _ok("\n\n".join(results))

    # ── list_login_items ──────────────────────────────────────────────────
    elif name == "list_login_items":
        cmd = (
            'osascript -e \'tell application "System Events" to get the name of every login item\' 2>/dev/null; '
            'sfltool dumpbtm 2>/dev/null | head -100'
        )
        return _ok(_run(cmd, timeout=15))

    # ── check_sip_status ─────────────────────────────────────────────────
    elif name == "check_sip_status":
        cmd = "csrutil status; echo '---'; csrutil authenticated-root status 2>/dev/null"
        return _ok(_run(cmd, timeout=10))

    # ── check_tcc_permissions ─────────────────────────────────────────────
    elif name == "check_tcc_permissions":
        app_id = arguments.get("app_identifier", "")
        # TCC databases
        user_tcc = "~/Library/Application Support/com.apple.TCC/TCC.db"
        sys_tcc = "/Library/Application Support/com.apple.TCC/TCC.db"
        query = "SELECT service, client, auth_value, auth_reason FROM access"
        if app_id:
            query += f" WHERE client LIKE '%{app_id}%'"
        cmd = (
            f'sqlite3 "{user_tcc}" "{query}" 2>/dev/null | head -50; '
            f'echo "--- System TCC ---"; '
            f'sudo sqlite3 "{sys_tcc}" "{query}" 2>/dev/null | head -50'
        )
        return _ok(_run(cmd, timeout=15))

    # ── list_kernel_extensions ────────────────────────────────────────────
    elif name == "list_kernel_extensions":
        cmd = (
            "kextstat | grep -v com.apple | head -40; "
            "echo '--- System Extensions ---'; "
            "systemextensionsctl list 2>/dev/null"
        )
        return _ok(_run(cmd, timeout=15))

    # ── check_network_filters ─────────────────────────────────────────────
    elif name == "check_network_filters":
        cmd = (
            "sudo pkgutil --pkgs 2>/dev/null | grep -i 'filter\\|vpn\\|proxy\\|network' | head -20; "
            "echo '---'; "
            "systemextensionsctl list 2>/dev/null | grep -i 'network\\|filter\\|vpn' | head -20"
        )
        return _ok(_run(cmd, timeout=15))

    # ── frida_list_processes ──────────────────────────────────────────────
    elif name == "frida_list_processes":
        cmd = "frida-ps -U 2>/dev/null || frida-ps 2>/dev/null || echo 'frida not found - install with: pip3 install frida-tools'"
        return _ok(_run(cmd, timeout=15))

    # ── frida_run_script ──────────────────────────────────────────────────
    elif name == "frida_run_script":
        target = arguments["target"]
        script = arguments["script_content"]
        timeout = arguments.get("timeout", 10)
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {workdir}")
        ts = int(time.time())
        script_file = f"{workdir}/frida_{ts}.js"
        escaped = script.replace("'", "'\\''")
        c.run(f"cat > '{script_file}' << 'FRIDAEOF'\n{script}\nFRIDAEOF")
        cmd = f'timeout {timeout} frida -n "{target}" -l "{script_file}" 2>&1 | head -200'
        result = _run(cmd, timeout=timeout + 10)
        c.run(f'rm -f "{script_file}"')
        return _ok(result)

    # ── frida_spawn_and_attach ────────────────────────────────────────────
    elif name == "frida_spawn_and_attach":
        executable = arguments["executable"]
        script = arguments["script_content"]
        timeout = arguments.get("timeout", 15)
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {workdir}")
        ts = int(time.time())
        script_file = f"{workdir}/frida_spawn_{ts}.js"
        c.run(f"cat > '{script_file}' << 'FRIDAEOF'\n{script}\nFRIDAEOF")
        cmd = f'timeout {timeout} frida -f "{executable}" --no-pause -l "{script_file}" 2>&1 | head -200'
        result = _run(cmd, timeout=timeout + 10)
        c.run(f'rm -f "{script_file}"')
        return _ok(result)

    # ── inspect_process ───────────────────────────────────────────────────
    elif name == "inspect_process":
        target = arguments["process_name_or_pid"]
        # Determine if PID or name
        is_pid = target.isdigit()
        pid_flag = f"-p {target}" if is_pid else f"-c {target}"
        name_flag = target if not is_pid else ""
        cmds = [
            (f"lsof {pid_flag} -nP 2>/dev/null | head -100", "Open Files & Connections"),
            (f"vmmap {target} 2>/dev/null | head -80" if is_pid else f"vmmap $(pgrep '{target}' | head -1) 2>/dev/null | head -80", "Memory Map"),
            (f"ps -p {target} -o pid,ppid,user,command" if is_pid else f"ps aux | grep -i '{target}' | grep -v grep", "Process Info"),
        ]
        results = []
        for cmd, label in cmds:
            code, out, err = c.run(cmd, timeout=20)
            results.append(f"=== {label} ===\n{(out + err).strip()}")
        return _ok("\n\n".join(results))

    # ── dump_process_memory ───────────────────────────────────────────────
    elif name == "dump_process_memory":
        pid = arguments["pid"]
        out_dir = arguments.get("output_dir", f"{c.remote_work_dir}/memdump")
        c.run(f"mkdir -p {out_dir}")
        cmd = f'sudo gcore -o "{out_dir}/core_{pid}" {pid} 2>&1'
        return _ok(_run(cmd, timeout=60))

    # ── lldb_run_commands ─────────────────────────────────────────────────
    elif name == "lldb_run_commands":
        executable = arguments["executable"]
        commands = arguments["commands"]
        timeout = arguments.get("timeout", 30)
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {workdir}")
        ts = int(time.time())
        cmd_file = f"{workdir}/lldb_{ts}.cmd"
        # Write commands to file
        c.run(f"cat > '{cmd_file}' << 'LLDBEOF'\n{commands}\nquit\nLLDBEOF")
        if executable.isdigit():
            lldb_cmd = f'timeout {timeout} lldb -p {executable} -s "{cmd_file}" 2>&1 | head -300'
        else:
            lldb_cmd = f'timeout {timeout} lldb "{executable}" -s "{cmd_file}" 2>&1 | head -300'
        result = _run(lldb_cmd, timeout=timeout + 10)
        c.run(f'rm -f "{cmd_file}"')
        return _ok(result)

    # ── analyze_app_bundle ────────────────────────────────────────────────
    elif name == "analyze_app_bundle":
        app = arguments["app_path"]
        cmds = [
            (f'plutil -p "{app}/Contents/Info.plist" 2>/dev/null | head -80', "Info.plist"),
            (f'codesign -dvvv "{app}" 2>&1', "Code Signature"),
            (f'codesign -d --entitlements :- "{app}" 2>&1', "Entitlements"),
            (f'ls "{app}/Contents/MacOS/" 2>/dev/null', "Executables"),
            (f'ls "{app}/Contents/Frameworks/" 2>/dev/null | head -30', "Frameworks"),
            (f'ls "{app}/Contents/PlugIns/" 2>/dev/null | head -20', "Plugins"),
            (f'otool -L "{app}/Contents/MacOS/"$(ls "{app}/Contents/MacOS/" | head -1) 2>/dev/null', "Linked Libraries"),
        ]
        results = []
        for cmd, label in cmds:
            code, out, err = c.run(cmd, timeout=15)
            output = (out + err).strip()
            if output:
                results.append(f"=== {label} ===\n{output}")
        return _ok("\n\n".join(results))

    # ── analyze_pkg_installer ─────────────────────────────────────────────
    elif name == "analyze_pkg_installer":
        pkg = arguments["pkg_path"]
        extract_dir = arguments.get("extract_dir", f"{c.remote_work_dir}/pkg_extract")
        c.run(f"mkdir -p {extract_dir}")
        cmds = [
            (f'pkgutil --check-signature "{pkg}" 2>&1', "Signature"),
            (f'pkgutil --payload-files "{pkg}" 2>/dev/null | head -60', "Payload Files"),
            (f'xar -tf "{pkg}" 2>/dev/null | head -40', "Archive Contents"),
            (f'cd "{extract_dir}" && xar -xf "{pkg}" 2>&1 && ls "{extract_dir}"', "Extraction"),
        ]
        results = []
        for cmd, label in cmds:
            code, out, err = c.run(cmd, timeout=30)
            output = (out + err).strip()
            results.append(f"=== {label} ===\n{output}")
        # Check for scripts
        _, scripts, _ = c.run(f'find "{extract_dir}" -name "preinstall" -o -name "postinstall" 2>/dev/null')
        if scripts.strip():
            results.append(f"=== Scripts Found ===\n{scripts.strip()}")
            for script_path in scripts.strip().split("\n")[:3]:
                _, content, _ = c.run(f'cat "{script_path}" 2>/dev/null')
                results.append(f"--- {script_path} ---\n{content.strip()}")
        return _ok("\n\n".join(results))

    # ── take_screenshot ───────────────────────────────────────────────────
    elif name == "take_screenshot":
        local_path = arguments.get("local_save_path", "/tmp/mac_screenshot.png")
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {workdir}")
        remote_path = f"{workdir}/screenshot_{int(time.time())}.png"
        c.run(f'screencapture -x "{remote_path}" 2>&1')
        c.download_file(remote_path, local_path)
        c.run(f'rm -f "{remote_path}"')
        return _ok(f"Screenshot saved to {local_path}")

    else:
        return _ok(f"Unknown tool: {name}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
