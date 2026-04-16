#!/usr/bin/env python3
"""
MacMCP - MCP server for macOS malware analysis and security research.

Provides tools to remotely analyze macOS systems via SSH, equivalent to
the FlareVM MCP for Windows analysis.

Security:
- All user-provided strings interpolated into shell commands are escaped via
  ``_sh()`` (shlex.quote). Never use raw f-string interpolation for user input.
- Sudo passwords are sent over stdin via ``mac_connection.run_sudo``.
- SSH host keys are verified against ~/.ssh/known_hosts by default.
"""

import asyncio
import json
import os
import shlex
import sys
import time
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    GetPromptResult,
    Prompt,
    PromptArgument,
    PromptMessage,
    Resource,
    TextContent,
    Tool,
)

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


def _sh(arg: Any) -> str:
    """Shell-quote a single argument for safe interpolation in bash commands.

    Always use this for any user-supplied path/filter/pattern that ends up in
    a command string. Without it, an attacker controlling the argument can
    break out and execute arbitrary commands on the macOS target.
    """
    return shlex.quote(str(arg))


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
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    ),
    Tool(
        name="extract_strings",
        description="Extract printable strings from a binary file on macOS.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "min_length": {"type": "integer", "default": 6},
                "filter_pattern": {"type": "string", "description": "Optional regex filter"},
            },
            "required": ["file_path"],
        },
    ),
    Tool(
        name="analyze_code_signing",
        description="Analyze code signature of a binary: certificate, entitlements, team ID, notarization status.",
        inputSchema={
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    ),
    Tool(
        name="get_entitlements",
        description="Extract entitlements from a signed binary or app bundle.",
        inputSchema={
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    ),
    Tool(
        name="analyze_dylibs",
        description="List dynamic libraries linked by a Mach-O binary (otool -L).",
        inputSchema={
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    ),
    Tool(
        name="get_quarantine_info",
        description="Get quarantine extended attributes and origin info for a file.",
        inputSchema={
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    ),
    Tool(
        name="check_gatekeeper",
        description="Check Gatekeeper/Notarization assessment for a file or app bundle.",
        inputSchema={
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    ),
    Tool(
        name="disassemble_function",
        description="Disassemble a function in a Mach-O binary using otool.",
        inputSchema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "arch": {"type": "string", "description": "arm64 or x86_64"},
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
                "duration": {"type": "integer", "default": 10},
                "process_filter": {"type": "string"},
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
                "interface": {"type": "string", "default": "en0"},
                "output_file": {"type": "string"},
                "filter": {"type": "string", "description": "BPF filter"},
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
                "output_file": {"type": "string"},
                "download_to": {"type": "string"},
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
                "process_name": {"type": "string"},
                "duration": {"type": "integer", "default": 15},
                "output_file": {"type": "string"},
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
                "script": {"type": "string"},
                "pid": {"type": "integer"},
                "process_name": {"type": "string"},
                "duration": {"type": "integer", "default": 10},
            },
            "required": ["script"],
        },
    ),
    Tool(
        name="execute_with_monitoring",
        description=(
            "Execute a program on macOS with comprehensive monitoring: "
            "file system activity (fs_usage), network connections, and process tree."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "executable": {"type": "string"},
                "arguments": {"type": "string"},
                "duration": {"type": "integer", "default": 30},
            },
            "required": ["executable"],
        },
    ),
    # ── Persistence Analysis ────────────────────────────────────────────────
    Tool(
        name="list_launch_agents",
        description="List all LaunchAgents and LaunchDaemons (persistence locations).",
        inputSchema={
            "type": "object",
            "properties": {"filter": {"type": "string"}},
            "required": [],
        },
    ),
    Tool(
        name="analyze_plist",
        description="Parse and display a plist file in human-readable format.",
        inputSchema={
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    ),
    Tool(
        name="check_persistence",
        description="Comprehensive persistence check across LaunchAgents/Daemons, login items, cron, hooks, kexts.",
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
            "properties": {"app_identifier": {"type": "string"}},
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
        description="List Network Extension and content filter providers.",
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
                "target": {"type": "string"},
                "script_content": {"type": "string"},
                "timeout": {"type": "integer", "default": 10},
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
                "executable": {"type": "string"},
                "script_content": {"type": "string"},
                "timeout": {"type": "integer", "default": 15},
            },
            "required": ["executable", "script_content"],
        },
    ),
    # ── Memory & Process Inspection ─────────────────────────────────────────
    Tool(
        name="inspect_process",
        description="Detailed inspection of a running process: open files, network, memory maps, dylibs.",
        inputSchema={
            "type": "object",
            "properties": {"process_name_or_pid": {"type": "string"}},
            "required": ["process_name_or_pid"],
        },
    ),
    Tool(
        name="dump_process_memory",
        description="Dump memory regions of a running process for analysis.",
        inputSchema={
            "type": "object",
            "properties": {
                "pid": {"type": "integer"},
                "output_dir": {"type": "string"},
            },
            "required": ["pid"],
        },
    ),
    # ── LLDB Debugging ──────────────────────────────────────────────────────
    Tool(
        name="lldb_run_commands",
        description="Run LLDB debugger commands on a macOS process or binary.",
        inputSchema={
            "type": "object",
            "properties": {
                "executable": {"type": "string"},
                "commands": {"type": "string"},
                "timeout": {"type": "integer", "default": 30},
            },
            "required": ["executable", "commands"],
        },
    ),
    # ── App Bundle Analysis ─────────────────────────────────────────────────
    Tool(
        name="analyze_app_bundle",
        description="Comprehensive analysis of a macOS .app bundle.",
        inputSchema={
            "type": "object",
            "properties": {"app_path": {"type": "string"}},
            "required": ["app_path"],
        },
    ),
    Tool(
        name="analyze_pkg_installer",
        description="Analyze a macOS .pkg installer: contents, scripts, distribution XML, certificates.",
        inputSchema={
            "type": "object",
            "properties": {
                "pkg_path": {"type": "string"},
                "extract_dir": {"type": "string"},
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
            "properties": {"local_save_path": {"type": "string"}},
            "required": [],
        },
    ),
    # ── Composite Playbooks (Automated Malware Analysis) ───────────────────
    Tool(
        name="triage_full",
        description=(
            "Composite playbook: complete static triage of a macOS sample. "
            "Runs hashes, Mach-O analysis, security-relevant strings, code signing, "
            "entitlements, quarantine xattr, and Gatekeeper assessment. "
            "Returns a structured markdown report."
        ),
        inputSchema={
            "type": "object",
            "properties": {"file_path": {"type": "string"}},
            "required": ["file_path"],
        },
    ),
    Tool(
        name="behavioral_full",
        description=(
            "Composite playbook: full behavioral analysis. Captures persistence "
            "baseline, starts tcpdump + fs_usage, executes the sample for $duration "
            "seconds, then diffs persistence and reports network/file/process activity."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "executable": {"type": "string"},
                "arguments": {"type": "string"},
                "duration": {"type": "integer", "default": 30},
            },
            "required": ["executable"],
        },
    ),
    Tool(
        name="app_bundle_full_audit",
        description=(
            "Composite playbook: full .app bundle audit. Walks Info.plist, signing, "
            "entitlements, frameworks, plugins, helper tools, dylibs, hashes every "
            "binary, and checks Gatekeeper."
        ),
        inputSchema={
            "type": "object",
            "properties": {"app_path": {"type": "string"}},
            "required": ["app_path"],
        },
    ),
    Tool(
        name="incident_response_scan",
        description=(
            "Composite playbook: macOS incident response triage. Persistence, kexts, "
            "TCC, SIP, live network, suspicious processes, network filters, and "
            "quarantine info on a sample of /Applications."
        ),
        inputSchema={"type": "object", "properties": {}, "required": []},
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

    elif name == "upload_file":
        local = arguments["local_path"]
        remote = arguments["remote_path"]
        c.upload_file(local, remote)
        return _ok(f"Uploaded {local} -> {remote}")

    elif name == "download_file":
        remote = arguments["remote_path"]
        local = arguments["local_path"]
        c.download_file(remote, local)
        return _ok(f"Downloaded {remote} -> {local}")

    elif name == "execute_bash":
        cmd = arguments["command"]
        timeout = arguments.get("timeout", 60)
        use_sudo = arguments.get("use_sudo", False)
        if use_sudo:
            code, out, err = c.run_sudo(cmd, timeout=timeout)
        else:
            code, out, err = c.run(cmd, timeout=timeout)
        parts = []
        if out.strip():
            parts.append(out.strip())
        if err.strip():
            parts.append(f"[stderr]\n{err.strip()}")
        parts.append(f"[exit: {code}]")
        return _ok("\n".join(parts))

    elif name == "read_file":
        path = arguments["file_path"]
        max_bytes = arguments.get("max_bytes", 100_000)
        content = c.read_remote_file(path, max_bytes)
        return _ok(content)

    elif name == "get_file_hash":
        path = _sh(arguments["file_path"])
        cmd = f"md5 {path}; shasum -a 1 {path}; shasum -a 256 {path}"
        return _ok(_run(cmd))

    elif name == "list_processes":
        filt = arguments.get("filter", "")
        cmd = "ps aux"
        if filt:
            cmd += f" | grep -i {_sh(filt)} | grep -v grep"
        return _ok(_run(cmd))

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

    elif name == "analyze_macho":
        path = _sh(arguments["file_path"])
        cmds = [
            f"file {path}",
            f"otool -f {path} 2>/dev/null || otool -h {path}",
            f"otool -l {path} | head -120",
            f"otool -L {path}",
            f"nm -m {path} 2>/dev/null | head -60 || echo '(nm not available)'",
        ]
        results = [_run(cmd, timeout=20) for cmd in cmds]
        return _ok("\n\n---\n\n".join(results))

    elif name == "extract_strings":
        path = _sh(arguments["file_path"])
        min_len = int(arguments.get("min_length", 6))
        pattern = arguments.get("filter_pattern", "")
        cmd = f"strings -n {min_len} {path}"
        if pattern:
            cmd += f" | grep -E {_sh(pattern)}"
        return _ok(_run(cmd, timeout=30))

    elif name == "analyze_code_signing":
        path = _sh(arguments["file_path"])
        cmd = (
            f"codesign -dvvv {path} 2>&1; "
            f"echo '---'; "
            f"codesign --verify --deep --strict {path} 2>&1; "
            f"echo '---'; "
            f"spctl --assess --verbose {path} 2>&1"
        )
        return _ok(_run(cmd, timeout=30))

    elif name == "get_entitlements":
        path = _sh(arguments["file_path"])
        cmd = f"codesign -d --entitlements :- {path} 2>&1"
        return _ok(_run(cmd, timeout=15))

    elif name == "analyze_dylibs":
        path = _sh(arguments["file_path"])
        return _ok(_run(f"otool -L {path}", timeout=15))

    elif name == "get_quarantine_info":
        path = _sh(arguments["file_path"])
        cmd = (
            f"xattr -l {path}; "
            f"echo '---'; "
            f"xattr -p com.apple.quarantine {path} 2>/dev/null || echo '(no quarantine xattr)'"
        )
        return _ok(_run(cmd, timeout=10))

    elif name == "check_gatekeeper":
        path = _sh(arguments["file_path"])
        cmd = f"spctl --assess --verbose=4 {path} 2>&1; codesign --verify --deep --strict {path} 2>&1"
        return _ok(_run(cmd, timeout=20))

    elif name == "disassemble_function":
        path = _sh(arguments["file_path"])
        arch = arguments.get("arch", "")
        # Whitelist arch values to avoid injection
        if arch and arch not in ("arm64", "x86_64", "arm64e", "i386"):
            return _ok(f"[error] invalid arch: {arch}")
        arch_flag = f"-arch {arch}" if arch else ""
        cmd = f"otool {arch_flag} -tV {path} | head -200"
        return _ok(_run(cmd, timeout=30))

    elif name == "monitor_network_realtime":
        duration = int(arguments.get("duration", 10))
        proc_filter = arguments.get("process_filter", "")
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {_sh(workdir)}")
        out_file = f"{workdir}/netmon_{int(time.time())}.txt"
        out_file_q = _sh(out_file)
        if proc_filter:
            cmd = (
                f"(for i in $(seq 1 {duration}); do "
                f"lsof -nP -i -a -c {_sh(proc_filter)} 2>/dev/null; "
                f"sleep 1; done) | sort -u > {out_file_q} 2>&1 &"
            )
        else:
            cmd = (
                f"(for i in $(seq 1 {duration}); do "
                f"lsof -nP -i 2>/dev/null; "
                f"sleep 1; done) | sort -u > {out_file_q} 2>&1 &"
            )
        c.run(cmd)
        time.sleep(duration + 1)
        result = _run(f"cat {out_file_q} 2>/dev/null | head -500")
        c.run(f"rm -f {out_file_q}")
        return _ok(result)

    elif name == "tcpdump_start":
        iface = arguments.get("interface", "en0")
        if not iface.replace("_", "").replace("-", "").isalnum():
            return _ok(f"[error] invalid interface name: {iface}")
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {_sh(workdir)}")
        out_file = arguments.get("output_file", f"{workdir}/capture.pcap")
        bpf = arguments.get("filter", "")
        out_q = _sh(out_file)
        bpf_q = _sh(bpf) if bpf else ""
        c.run_sudo(f"tcpdump -i {iface} -w {out_q} {bpf_q} -U > /dev/null 2>&1 & echo $!")
        return _ok(f"tcpdump capture started -> {out_file}")

    elif name == "tcpdump_stop":
        workdir = c.remote_work_dir
        out_file = arguments.get("output_file", f"{workdir}/capture.pcap")
        download_to = arguments.get("download_to", "")
        c.run_sudo("pkill tcpdump 2>/dev/null; sleep 1")
        summary = _run(f"tcpdump -r {_sh(out_file)} -nn 2>/dev/null | head -200")
        if download_to:
            c.download_file(out_file, download_to)
            summary += f"\n[pcap downloaded to {download_to}]"
        return _ok(summary)

    elif name == "fs_usage_monitor":
        proc = arguments.get("process_name", "")
        duration = int(arguments.get("duration", 15))
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {_sh(workdir)}")
        out_file = arguments.get("output_file", f"{workdir}/fs_usage_{int(time.time())}.txt")
        out_q = _sh(out_file)
        proc_flag = f"-f filesystem {_sh(proc)}" if proc else "-f filesystem"
        c.run_sudo(
            f"timeout {duration} fs_usage {proc_flag} > {out_q} 2>&1; echo done",
            timeout=duration + 10,
        )
        result = _run(f"cat {out_q} | head -300")
        return _ok(result)

    elif name == "dtrace_trace":
        script = arguments["script"]
        pid = arguments.get("pid")
        duration = int(arguments.get("duration", 10))
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {_sh(workdir)}")
        script_file = f"{workdir}/dtrace_{int(time.time())}.d"
        # Upload script via SFTP-style write to avoid shell escaping issues
        # Use base64 round-trip — robust against any payload bytes.
        import base64
        b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
        c.run(f"echo {_sh(b64)} | base64 -D > {_sh(script_file)}")
        pid_flag = f"-p {int(pid)}" if pid else ""
        cmd = f"timeout {duration} dtrace {pid_flag} -s {_sh(script_file)} 2>&1 | head -300"
        code, out, err = c.run_sudo(cmd, timeout=duration + 15)
        c.run(f"rm -f {_sh(script_file)}")
        return _ok(out + err)

    elif name == "execute_with_monitoring":
        executable = arguments["executable"]
        args = arguments.get("arguments", "")
        duration = int(arguments.get("duration", 30))
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {_sh(workdir)}")
        ts = int(time.time())
        net_file = f"{workdir}/net_{ts}.txt"
        fs_file = f"{workdir}/fs_{ts}.txt"
        exe_q = _sh(executable)
        net_q = _sh(net_file)
        fs_q = _sh(fs_file)

        report = [f"=== MacMCP Behavioral Analysis: {executable} ===\n"]

        c.run_sudo(
            f"timeout {duration + 5} fs_usage -f filesystem > {fs_q} 2>&1 &",
            timeout=5,
        )
        c.run(
            f"(for i in $(seq 1 {duration}); do lsof -nP -i 2>/dev/null; sleep 1; done)"
            f" | sort -u > {net_q} 2>&1 &",
            timeout=5,
        )

        # Launch the target. args is intentionally not quoted (user may pass
        # multiple args); document this in the schema.
        launch_cmd = f"{exe_q} {args}" if args else exe_q
        c.run(f"{launch_cmd} &", timeout=5)

        time.sleep(2)
        _, proc_out, _ = c.run(f"pgrep -l -f {exe_q} 2>/dev/null")
        report.append(f"[Processes after launch]\n{proc_out.strip()}")

        time.sleep(duration)

        _, fs_out, _ = c.run(f"cat {fs_q} | head -300")
        _, net_out, _ = c.run(f"cat {net_q} | head -100")
        _, ps_out, _ = c.run(f"ps aux | grep -i {exe_q} | grep -v grep")

        report.append(f"\n[File System Activity (fs_usage)]\n{fs_out.strip()}")
        report.append(f"\n[Network Connections]\n{net_out.strip()}")
        report.append(f"\n[Processes]\n{ps_out.strip()}")

        c.run_sudo(f"pkill -f fs_usage 2>/dev/null; rm -f {fs_q} {net_q}")
        return _ok("\n".join(report))

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
            cmd = f"ls {_sh(d)} 2>/dev/null"
            if filt:
                cmd += f" | grep -i {_sh(filt)}"
            code, out, _ = c.run(cmd, timeout=10)
            if out.strip():
                results.append(f"=== {d} ===\n{out.strip()}")
        return _ok("\n\n".join(results) if results else "No launch agents/daemons found.")

    elif name == "analyze_plist":
        path = _sh(arguments["file_path"])
        cmd = f"plutil -p {path} 2>&1 || cat {path}"
        return _ok(_run(cmd, timeout=10))

    elif name == "check_persistence":
        checks = [
            ("LaunchAgents (user)", "ls ~/Library/LaunchAgents 2>/dev/null"),
            ("LaunchAgents (system)", "ls /Library/LaunchAgents 2>/dev/null"),
            ("LaunchDaemons", "ls /Library/LaunchDaemons 2>/dev/null"),
            ("Cron jobs", "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null"),
            ("Login hooks", "defaults read com.apple.loginwindow LoginHook 2>/dev/null"),
            ("Logout hooks", "defaults read com.apple.loginwindow LogoutHook 2>/dev/null"),
            ("At jobs", "atq 2>/dev/null"),
            ("Periodic scripts", "ls /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly 2>/dev/null | head -30"),
            ("Kernel/System Extensions", "kextstat 2>/dev/null | grep -v apple | head -20; systemextensionsctl list 2>/dev/null | head -30"),
            ("Login items (loginwindow)", "defaults read com.apple.loginwindow AutoLaunchedApplicationDictionary 2>/dev/null"),
            ("Emond rules", "ls /etc/emond.d/rules/ 2>/dev/null"),
            ("Configuration profiles", "profiles list 2>/dev/null | head -30"),
        ]
        results = []
        for label, cmd in checks:
            code, out, err = c.run(cmd, timeout=10)
            output = out.strip() or err.strip() or "(empty)"
            results.append(f"=== {label} ===\n{output}")
        return _ok("\n\n".join(results))

    elif name == "list_login_items":
        cmd = (
            "osascript -e 'tell application \"System Events\" to get the name of every login item' 2>/dev/null; "
            "sfltool dumpbtm 2>/dev/null | head -100"
        )
        return _ok(_run(cmd, timeout=15))

    elif name == "check_sip_status":
        cmd = "csrutil status; echo '---'; csrutil authenticated-root status 2>/dev/null"
        return _ok(_run(cmd, timeout=10))

    elif name == "check_tcc_permissions":
        app_id = arguments.get("app_identifier", "")
        user_tcc = "~/Library/Application Support/com.apple.TCC/TCC.db"
        sys_tcc = "/Library/Application Support/com.apple.TCC/TCC.db"
        if app_id:
            # SQL parameter substitution unavailable via sqlite3 CLI; sanitize aggressively.
            safe_id = "".join(ch for ch in app_id if ch.isalnum() or ch in ".-_")
            where = f" WHERE client LIKE '%{safe_id}%'"
        else:
            where = ""
        query = f"SELECT service, client, auth_value, auth_reason FROM access{where}"
        cmd = (
            f"sqlite3 {_sh(user_tcc)} {_sh(query)} 2>/dev/null | head -50; "
            f"echo '--- System TCC ---'; "
            f"sqlite3 {_sh(sys_tcc)} {_sh(query)} 2>/dev/null | head -50"
        )
        # System TCC needs sudo
        out1 = _run(cmd, timeout=15)
        return _ok(out1)

    elif name == "list_kernel_extensions":
        cmd = (
            "kextstat | grep -v com.apple | head -40; "
            "echo '--- System Extensions ---'; "
            "systemextensionsctl list 2>/dev/null"
        )
        return _ok(_run(cmd, timeout=15))

    elif name == "check_network_filters":
        cmd = (
            "pkgutil --pkgs 2>/dev/null | grep -i 'filter\\|vpn\\|proxy\\|network' | head -20; "
            "echo '---'; "
            "systemextensionsctl list 2>/dev/null | grep -i 'network\\|filter\\|vpn' | head -20"
        )
        return _ok(_run(cmd, timeout=15))

    elif name == "frida_list_processes":
        cmd = "frida-ps -U 2>/dev/null || frida-ps 2>/dev/null || echo 'frida not found - install with: pip3 install frida-tools'"
        return _ok(_run(cmd, timeout=15))

    elif name == "frida_run_script":
        target = arguments["target"]
        script = arguments["script_content"]
        timeout = int(arguments.get("timeout", 10))
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {_sh(workdir)}")
        ts = int(time.time())
        script_file = f"{workdir}/frida_{ts}.js"
        # Upload via base64 to avoid any shell metachar escapes.
        import base64
        b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
        c.run(f"echo {_sh(b64)} | base64 -D > {_sh(script_file)}")
        cmd = f"timeout {timeout} frida -n {_sh(target)} -l {_sh(script_file)} 2>&1 | head -200"
        result = _run(cmd, timeout=timeout + 10)
        c.run(f"rm -f {_sh(script_file)}")
        return _ok(result)

    elif name == "frida_spawn_and_attach":
        executable = arguments["executable"]
        script = arguments["script_content"]
        timeout = int(arguments.get("timeout", 15))
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {_sh(workdir)}")
        ts = int(time.time())
        script_file = f"{workdir}/frida_spawn_{ts}.js"
        import base64
        b64 = base64.b64encode(script.encode("utf-8")).decode("ascii")
        c.run(f"echo {_sh(b64)} | base64 -D > {_sh(script_file)}")
        cmd = f"timeout {timeout} frida -f {_sh(executable)} --no-pause -l {_sh(script_file)} 2>&1 | head -200"
        result = _run(cmd, timeout=timeout + 10)
        c.run(f"rm -f {_sh(script_file)}")
        return _ok(result)

    elif name == "inspect_process":
        target = str(arguments["process_name_or_pid"])
        is_pid = target.isdigit()
        target_q = _sh(target)
        if is_pid:
            cmds = [
                (f"lsof -p {target} -nP 2>/dev/null | head -100", "Open Files & Connections"),
                (f"vmmap {target} 2>/dev/null | head -80", "Memory Map"),
                (f"ps -p {target} -o pid,ppid,user,command", "Process Info"),
            ]
        else:
            cmds = [
                (f"lsof -c {target_q} -nP 2>/dev/null | head -100", "Open Files & Connections"),
                (f"vmmap $(pgrep {target_q} | head -1) 2>/dev/null | head -80", "Memory Map"),
                (f"ps aux | grep -i {target_q} | grep -v grep", "Process Info"),
            ]
        results = []
        for cmd, label in cmds:
            code, out, err = c.run(cmd, timeout=20)
            results.append(f"=== {label} ===\n{(out + err).strip()}")
        return _ok("\n\n".join(results))

    elif name == "dump_process_memory":
        pid = int(arguments["pid"])
        out_dir = arguments.get("output_dir", f"{c.remote_work_dir}/memdump")
        c.run(f"mkdir -p {_sh(out_dir)}")
        cmd = f"gcore -o {_sh(out_dir + '/core_' + str(pid))} {pid} 2>&1"
        code, out, err = c.run_sudo(cmd, timeout=60)
        return _ok((out + err).strip() + f"\n[exit: {code}]")

    elif name == "lldb_run_commands":
        executable = arguments["executable"]
        commands = arguments["commands"]
        timeout = int(arguments.get("timeout", 30))
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {_sh(workdir)}")
        ts = int(time.time())
        cmd_file = f"{workdir}/lldb_{ts}.cmd"
        import base64
        body = commands.rstrip() + "\nquit\n"
        b64 = base64.b64encode(body.encode("utf-8")).decode("ascii")
        c.run(f"echo {_sh(b64)} | base64 -D > {_sh(cmd_file)}")
        if executable.isdigit():
            lldb_cmd = f"timeout {timeout} lldb -p {int(executable)} -s {_sh(cmd_file)} 2>&1 | head -300"
        else:
            lldb_cmd = f"timeout {timeout} lldb {_sh(executable)} -s {_sh(cmd_file)} 2>&1 | head -300"
        result = _run(lldb_cmd, timeout=timeout + 10)
        c.run(f"rm -f {_sh(cmd_file)}")
        return _ok(result)

    elif name == "analyze_app_bundle":
        app = arguments["app_path"]
        app_q = _sh(app)
        cmds = [
            (f"plutil -p {_sh(app + '/Contents/Info.plist')} 2>/dev/null | head -80", "Info.plist"),
            (f"codesign -dvvv {app_q} 2>&1", "Code Signature"),
            (f"codesign -d --entitlements :- {app_q} 2>&1", "Entitlements"),
            (f"ls {_sh(app + '/Contents/MacOS/')} 2>/dev/null", "Executables"),
            (f"ls {_sh(app + '/Contents/Frameworks/')} 2>/dev/null | head -30", "Frameworks"),
            (f"ls {_sh(app + '/Contents/PlugIns/')} 2>/dev/null | head -20", "Plugins"),
            (
                f"main=$(ls {_sh(app + '/Contents/MacOS/')} | head -1); "
                f"otool -L {_sh(app + '/Contents/MacOS/')}\"$main\" 2>/dev/null",
                "Linked Libraries",
            ),
        ]
        results = []
        for cmd, label in cmds:
            code, out, err = c.run(cmd, timeout=15)
            output = (out + err).strip()
            if output:
                results.append(f"=== {label} ===\n{output}")
        return _ok("\n\n".join(results))

    elif name == "analyze_pkg_installer":
        pkg = arguments["pkg_path"]
        extract_dir = arguments.get("extract_dir", f"{c.remote_work_dir}/pkg_extract")
        pkg_q = _sh(pkg)
        ext_q = _sh(extract_dir)
        c.run(f"mkdir -p {ext_q}")
        cmds = [
            (f"pkgutil --check-signature {pkg_q} 2>&1", "Signature"),
            (f"pkgutil --payload-files {pkg_q} 2>/dev/null | head -60", "Payload Files"),
            (f"xar -tf {pkg_q} 2>/dev/null | head -40", "Archive Contents"),
            (f"cd {ext_q} && xar -xf {pkg_q} 2>&1 && ls {ext_q}", "Extraction"),
        ]
        results = []
        for cmd, label in cmds:
            code, out, err = c.run(cmd, timeout=30)
            output = (out + err).strip()
            results.append(f"=== {label} ===\n{output}")
        _, scripts, _ = c.run(f"find {ext_q} -name preinstall -o -name postinstall 2>/dev/null")
        if scripts.strip():
            results.append(f"=== Scripts Found ===\n{scripts.strip()}")
            for script_path in scripts.strip().split("\n")[:3]:
                _, content, _ = c.run(f"cat {_sh(script_path)} 2>/dev/null")
                results.append(f"--- {script_path} ---\n{content.strip()}")
        return _ok("\n\n".join(results))

    elif name == "take_screenshot":
        local_path = arguments.get("local_save_path", "/tmp/mac_screenshot.png")
        workdir = c.remote_work_dir
        c.run(f"mkdir -p {_sh(workdir)}")
        remote_path = f"{workdir}/screenshot_{int(time.time())}.png"
        c.run(f"screencapture -x {_sh(remote_path)} 2>&1")
        c.download_file(remote_path, local_path)
        c.run(f"rm -f {_sh(remote_path)}")
        return _ok(f"Screenshot saved to {local_path}")

    # ── Composite Playbooks ─────────────────────────────────────────────
    elif name == "triage_full":
        return _ok(_playbook_triage_full(c, arguments["file_path"]))

    elif name == "behavioral_full":
        return _ok(_playbook_behavioral_full(
            c,
            arguments["executable"],
            arguments.get("arguments", ""),
            int(arguments.get("duration", 30)),
        ))

    elif name == "app_bundle_full_audit":
        return _ok(_playbook_app_bundle_full_audit(c, arguments["app_path"]))

    elif name == "incident_response_scan":
        return _ok(_playbook_incident_response_scan(c))

    else:
        return _ok(f"Unknown tool: {name}")


# ---------------------------------------------------------------------------
# Composite playbooks
# ---------------------------------------------------------------------------

def _section(title: str, body: str) -> str:
    return f"## {title}\n\n```\n{body.strip()}\n```\n"


def _playbook_triage_full(c: MacConnection, file_path: str) -> str:
    p = _sh(file_path)
    out = [f"# MacMCP Static Triage: `{file_path}`\n"]

    code, hashes, _ = c.run(f"md5 {p}; shasum -a 1 {p}; shasum -a 256 {p}", timeout=20)
    out.append(_section("File Hashes", hashes))

    code, macho, _ = c.run(f"file {p}; otool -h {p} 2>/dev/null; otool -L {p} 2>/dev/null | head -40", timeout=20)
    out.append(_section("Mach-O Analysis", macho))

    pattern = "http|https|flag|key|password|crypto|exec|spawn|/tmp|/Library|com.apple|launchctl"
    code, strs, _ = c.run(f"strings -n 6 {p} | grep -E {_sh(pattern)} | head -100", timeout=30)
    out.append(_section("Security-Relevant Strings", strs or "(none matched)"))

    code, sig, _ = c.run(f"codesign -dvvv {p} 2>&1; echo '---'; spctl --assess --verbose {p} 2>&1", timeout=20)
    out.append(_section("Code Signing", sig))

    code, ent, _ = c.run(f"codesign -d --entitlements :- {p} 2>&1", timeout=15)
    out.append(_section("Entitlements", ent))

    code, q, _ = c.run(f"xattr -l {p}; xattr -p com.apple.quarantine {p} 2>/dev/null", timeout=10)
    out.append(_section("Quarantine / xattr", q or "(none)"))

    code, gk, _ = c.run(f"spctl --assess --verbose=4 {p} 2>&1", timeout=20)
    out.append(_section("Gatekeeper Assessment", gk))

    return "\n".join(out)


def _playbook_behavioral_full(c: MacConnection, executable: str, args: str, duration: int) -> str:
    exe_q = _sh(executable)
    workdir = c.remote_work_dir
    c.run(f"mkdir -p {_sh(workdir)}")
    ts = int(time.time())
    pcap = f"{workdir}/behav_{ts}.pcap"
    fs_file = f"{workdir}/behav_fs_{ts}.txt"
    pcap_q, fs_q = _sh(pcap), _sh(fs_file)

    out = [f"# MacMCP Behavioral Analysis: `{executable}`\n"]

    # Persistence baseline
    _, before, _ = c.run("ls ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null | sort", timeout=10)
    out.append(_section("Persistence Baseline", before))

    # Start tcpdump + fs_usage
    c.run_sudo(f"tcpdump -i en0 -w {pcap_q} -U > /dev/null 2>&1 &", timeout=5)
    c.run_sudo(f"timeout {duration + 5} fs_usage -f filesystem > {fs_q} 2>&1 &", timeout=5)

    # Launch
    launch = f"{exe_q} {args}" if args else exe_q
    c.run(f"{launch} > /dev/null 2>&1 &", timeout=5)

    time.sleep(duration)

    # Stop tcpdump
    c.run_sudo("pkill tcpdump 2>/dev/null; sleep 1")
    _, pcap_summary, _ = c.run(f"tcpdump -r {pcap_q} -nn 2>/dev/null | head -100", timeout=20)
    out.append(_section("Network Traffic Summary (tcpdump)", pcap_summary or "(no traffic captured)"))

    # IOC extraction from pcap
    _, iocs, _ = c.run(
        f"tcpdump -r {pcap_q} -nn 2>/dev/null | "
        "awk '{for(i=1;i<=NF;i++) if($i~/[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+/) print $i}' "
        "| sort -u | head -30",
        timeout=20,
    )
    out.append(_section("Network IOCs (unique IPs)", iocs or "(none)"))

    # fs_usage
    _, fs_out, _ = c.run(f"cat {fs_q} | head -200", timeout=15)
    out.append(_section("File System Activity (fs_usage)", fs_out or "(none captured)"))

    # Persistence diff
    _, after, _ = c.run("ls ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null | sort", timeout=10)
    _, diff, _ = c.run(
        f"diff <(echo {_sh(before)}) <(echo {_sh(after)}) 2>/dev/null || echo '(no change detected)'",
        timeout=10,
    )
    out.append(_section("Persistence Diff (after vs before)", diff or "(no change)"))

    # Child processes
    _, kids, _ = c.run(f"pgrep -l -f {exe_q} 2>/dev/null; ps aux | grep -i {exe_q} | grep -v grep", timeout=10)
    out.append(_section("Spawned Processes", kids or "(none)"))

    # Cleanup
    c.run_sudo(f"pkill -f fs_usage 2>/dev/null; rm -f {fs_q}")

    return "\n".join(out)


def _playbook_app_bundle_full_audit(c: MacConnection, app_path: str) -> str:
    app = app_path.rstrip("/")
    out = [f"# MacMCP App Bundle Audit: `{app}`\n"]

    _, plist, _ = c.run(f"plutil -p {_sh(app + '/Contents/Info.plist')} 2>/dev/null | head -100", timeout=15)
    out.append(_section("Info.plist", plist or "(no Info.plist)"))

    _, sig, _ = c.run(f"codesign -dvvv {_sh(app)} 2>&1", timeout=15)
    out.append(_section("Code Signature", sig))

    _, ent, _ = c.run(f"codesign -d --entitlements :- {_sh(app)} 2>&1", timeout=15)
    out.append(_section("Entitlements", ent))

    _, macho, _ = c.run(
        f"main=$(ls {_sh(app + '/Contents/MacOS/')} 2>/dev/null | head -1); "
        f"file {_sh(app + '/Contents/MacOS/')}\"$main\"; "
        f"otool -h {_sh(app + '/Contents/MacOS/')}\"$main\"",
        timeout=20,
    )
    out.append(_section("Main Binary (Mach-O)", macho))

    _, strs, _ = c.run(
        f"main=$(ls {_sh(app + '/Contents/MacOS/')} 2>/dev/null | head -1); "
        f"strings -n 6 {_sh(app + '/Contents/MacOS/')}\"$main\" 2>/dev/null | "
        f"grep -E {_sh('http|https|/tmp|/Library|com.apple|launchctl|sudo|exec|spawn')} | head -60",
        timeout=30,
    )
    out.append(_section("Suspicious Strings (main binary)", strs or "(none matched)"))

    _, helpers, _ = c.run(
        f"ls {_sh(app + '/Contents/Library/LoginItems/')} 2>/dev/null; "
        f"ls {_sh(app + '/Contents/XPCServices/')} 2>/dev/null; "
        f"ls {_sh(app + '/Contents/PlugIns/')} 2>/dev/null",
        timeout=10,
    )
    out.append(_section("Helper Tools / XPC / Plugins", helpers or "(none)"))

    _, dylibs, _ = c.run(
        f"main=$(ls {_sh(app + '/Contents/MacOS/')} 2>/dev/null | head -1); "
        f"otool -L {_sh(app + '/Contents/MacOS/')}\"$main\" 2>/dev/null",
        timeout=15,
    )
    out.append(_section("Linked Dylibs", dylibs))

    _, gk, _ = c.run(f"spctl --assess --verbose=4 {_sh(app)} 2>&1", timeout=20)
    out.append(_section("Gatekeeper Assessment", gk))

    _, allbin, _ = c.run(
        f"find {_sh(app)} -type f \\( -perm +111 -o -name '*.dylib' \\) 2>/dev/null | "
        "head -20 | while read f; do echo \"$f\"; shasum -a 256 \"$f\" 2>/dev/null; done",
        timeout=30,
    )
    out.append(_section("Hashes of Bundled Binaries", allbin or "(none)"))

    return "\n".join(out)


def _playbook_incident_response_scan(c: MacConnection) -> str:
    out = ["# MacMCP Incident Response Scan\n"]

    # Persistence
    persist_blocks = []
    for label, cmd in [
        ("LaunchAgents (user)", "ls ~/Library/LaunchAgents 2>/dev/null"),
        ("LaunchAgents (system)", "ls /Library/LaunchAgents 2>/dev/null"),
        ("LaunchDaemons", "ls /Library/LaunchDaemons 2>/dev/null"),
        ("Cron", "crontab -l 2>/dev/null; ls /etc/cron* 2>/dev/null"),
    ]:
        _, o, _ = c.run(cmd, timeout=10)
        persist_blocks.append(f"--- {label} ---\n{o.strip() or '(empty)'}")
    out.append(_section("Persistence", "\n".join(persist_blocks)))

    _, kexts, _ = c.run("kextstat 2>/dev/null | grep -v com.apple | head -30; systemextensionsctl list 2>/dev/null | head -30", timeout=15)
    out.append(_section("Kernel & System Extensions (non-Apple)", kexts or "(none)"))

    _, tcc, _ = c.run(
        "sqlite3 ~/Library/Application\\ Support/com.apple.TCC/TCC.db "
        "'SELECT service, client, auth_value FROM access' 2>/dev/null | head -40",
        timeout=15,
    )
    out.append(_section("TCC Permissions (user DB)", tcc or "(none accessible)"))

    _, sip, _ = c.run("csrutil status", timeout=10)
    out.append(_section("SIP Status", sip))

    _, net, _ = c.run("(for i in $(seq 1 10); do lsof -nP -i 2>/dev/null; sleep 1; done) | sort -u | head -100", timeout=20)
    out.append(_section("Live Network Connections (10s)", net or "(none)"))

    _, procs, _ = c.run(
        "ps -axo pid,user,comm | tail -n +2 | "
        "awk '$3 !~ /^\\/(System|usr\\/(libexec|sbin|bin)|sbin|bin|Library\\/Apple)/ {print}' | head -50",
        timeout=15,
    )
    out.append(_section("Non-Apple-Path Processes", procs or "(none)"))

    _, nf, _ = c.run("systemextensionsctl list 2>/dev/null | grep -iE 'network|filter|vpn' | head -20", timeout=10)
    out.append(_section("Network Filters / VPN Extensions", nf or "(none)"))

    _, qapps, _ = c.run(
        "ls /Applications 2>/dev/null | head -10 | while read app; do "
        "echo \"--- $app ---\"; "
        "xattr -p com.apple.quarantine \"/Applications/$app\" 2>/dev/null || echo '(no quarantine)'; "
        "done",
        timeout=20,
    )
    out.append(_section("Quarantine Status (sample of /Applications)", qapps))

    return "\n".join(out)


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

PROMPTS = [
    Prompt(
        name="triage_macos_sample",
        description="Walk through full static triage of a suspected macOS malware sample.",
        arguments=[PromptArgument(name="sample_path", description="Path to sample on the macOS target", required=True)],
    ),
    Prompt(
        name="analyze_app_bundle",
        description="Step-by-step audit workflow for a macOS .app bundle.",
        arguments=[PromptArgument(name="app_path", description="Path to .app on macOS target", required=True)],
    ),
    Prompt(
        name="mac_persistence_check",
        description="Comprehensive persistence enumeration workflow for macOS.",
        arguments=[],
    ),
    Prompt(
        name="mac_incident_response",
        description="Incident response playbook for a suspected macOS compromise.",
        arguments=[],
    ),
    Prompt(
        name="pkg_installer_audit",
        description="Security audit workflow for a macOS .pkg installer.",
        arguments=[PromptArgument(name="pkg_path", description="Path to .pkg on macOS target", required=True)],
    ),
]


PROMPT_BODIES = {
    "triage_macos_sample": (
        "Perform a full static triage of the macOS sample at `{sample_path}`.\n\n"
        "Steps:\n"
        "1. Call `check_connection` to verify the SSH session is live.\n"
        "2. Call `triage_full` with file_path=`{sample_path}` for the one-shot report, OR run individually:\n"
        "   - `get_file_hash` (MD5/SHA1/SHA256)\n"
        "   - `analyze_macho` (architecture, load commands, linked libs)\n"
        "   - `extract_strings` with filter_pattern='http|flag|key|password|crypto|exec'\n"
        "   - `analyze_code_signing` and `get_entitlements`\n"
        "   - `get_quarantine_info` and `check_gatekeeper`\n"
        "3. Cross-reference hashes against VirusTotal or known-bad lists.\n"
        "4. Summarise: signing identity, capabilities (entitlements), notable strings, IOC candidates.\n"
        "5. Recommend whether dynamic analysis (`behavioral_full`) is warranted."
    ),
    "analyze_app_bundle": (
        "Audit the macOS application bundle at `{app_path}`.\n\n"
        "Steps:\n"
        "1. Call `app_bundle_full_audit` with app_path=`{app_path}` for the consolidated report.\n"
        "2. Pay special attention to:\n"
        "   - Entitlements granting privacy access (Camera, Microphone, AddressBook, FullDiskAccess)\n"
        "   - Helper tools / LoginItems / XPC services that survive uninstall\n"
        "   - Non-Apple-signed dylibs and `@rpath` / `@loader_path` references\n"
        "   - Bundled binaries with hashes that don't match the publisher's notarization\n"
        "3. If suspicious: run `behavioral_full` against the main executable.\n"
        "4. Report: trust verdict, capability summary, persistence footprint, IOCs."
    ),
    "mac_persistence_check": (
        "Enumerate every persistence mechanism on the target macOS machine.\n\n"
        "Steps:\n"
        "1. Call `check_persistence` for the full sweep.\n"
        "2. For any non-Apple plist found, call `analyze_plist` on it.\n"
        "3. Call `list_login_items` and `list_kernel_extensions`.\n"
        "4. Call `check_network_filters` to find Network/Content/VPN extensions.\n"
        "5. Flag any of: unsigned LaunchAgents, third-party kexts, sfltool entries lacking a known publisher.\n"
        "6. Output: table of (location, name, signer, last-modified)."
    ),
    "mac_incident_response": (
        "Triage a suspected macOS compromise.\n\n"
        "Steps:\n"
        "1. Call `incident_response_scan` for the consolidated IR report.\n"
        "2. Drill down where indicators emerge:\n"
        "   - Unknown LaunchAgent → `analyze_plist` then `analyze_macho` on the referenced binary\n"
        "   - Unfamiliar process → `inspect_process`\n"
        "   - Unexpected network endpoint → `monitor_network_realtime` then `tcpdump_start` for capture\n"
        "3. Capture evidence: `take_screenshot`, `download_file` for any suspicious binaries.\n"
        "4. Produce: timeline, IOC list (hashes/IPs/domains/paths), MITRE ATT&CK mapping, recommended remediation."
    ),
    "pkg_installer_audit": (
        "Audit the installer package at `{pkg_path}`.\n\n"
        "Steps:\n"
        "1. `get_file_hash` the .pkg.\n"
        "2. `analyze_pkg_installer` to extract payload and surface preinstall/postinstall scripts.\n"
        "3. Read each script with `read_file` — look for: `curl|wget`, `chmod +s`, sudoers edits, "
        "writes to /Library/LaunchDaemons or /Library/PrivilegedHelperTools.\n"
        "4. For each binary in the payload: `analyze_code_signing`, `get_entitlements`, `analyze_macho`.\n"
        "5. Verdict: trustworthy installer, suspicious behavior, or outright malicious."
    ),
}


@server.list_prompts()
async def list_prompts() -> list[Prompt]:
    return PROMPTS


@server.get_prompt()
async def get_prompt(name: str, arguments: dict[str, str] | None = None) -> GetPromptResult:
    arguments = arguments or {}
    body_template = PROMPT_BODIES.get(name)
    if body_template is None:
        raise ValueError(f"Unknown prompt: {name}")
    try:
        body = body_template.format(**arguments)
    except KeyError as e:
        raise ValueError(f"Missing required prompt argument: {e}") from e
    return GetPromptResult(
        description=next((p.description for p in PROMPTS if p.name == name), ""),
        messages=[
            PromptMessage(role="user", content=TextContent(type="text", text=body)),
        ],
    )


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

RESOURCES = [
    Resource(
        uri="mac://system/info",
        name="macOS System Info",
        description="Live snapshot of the target macOS system (sw_vers, hardware, SIP).",
        mimeType="text/markdown",
    ),
    Resource(
        uri="mac://persistence/locations",
        name="macOS Persistence Locations",
        description="Reference list of every macOS persistence mechanism MacMCP checks.",
        mimeType="text/markdown",
    ),
    Resource(
        uri="mac://docs/cheatsheet",
        name="macOS Analysis Cheatsheet",
        description="Common macOS reverse-engineering and analysis commands.",
        mimeType="text/markdown",
    ),
    Resource(
        uri="mac://docs/frida-snippets",
        name="Frida Snippets for macOS",
        description="Common Frida JavaScript hooks for NSURLSession, NSFileManager, NSTask, etc.",
        mimeType="text/markdown",
    ),
    Resource(
        uri="mac://status/connection",
        name="SSH Connection Status",
        description="Current state of the SSH connection to the macOS target.",
        mimeType="text/plain",
    ),
]


def _read_pkg_resource(filename: str) -> str:
    path = os.path.join(os.path.dirname(__file__), "resources", filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    return f"(resource file missing: {filename})"


@server.list_resources()
async def list_resources() -> list[Resource]:
    return RESOURCES


@server.read_resource()
async def read_resource(uri: str) -> str:
    uri = str(uri)
    if uri == "mac://system/info":
        try:
            c = conn()
            _, sw, _ = c.run("sw_vers", timeout=10)
            _, hw, _ = c.run("system_profiler SPHardwareDataType | grep -E 'Model|CPU|Memory|Serial'", timeout=10)
            _, sip, _ = c.run("csrutil status", timeout=10)
            return (
                f"# macOS System Info\n\n"
                f"## sw_vers\n```\n{sw.strip()}\n```\n\n"
                f"## Hardware\n```\n{hw.strip()}\n```\n\n"
                f"## SIP\n```\n{sip.strip()}\n```\n"
            )
        except Exception as e:
            return f"# macOS System Info\n\n[error: {e}]"
    if uri == "mac://persistence/locations":
        return _read_pkg_resource("persistence-locations.md")
    if uri == "mac://docs/cheatsheet":
        return _read_pkg_resource("cheatsheet.md")
    if uri == "mac://docs/frida-snippets":
        return _read_pkg_resource("frida-snippets.md")
    if uri == "mac://status/connection":
        try:
            c = conn()
            connected = c._is_connected()  # noqa: SLF001
            host = c.config["ssh"].get("host", "(unset)")
            user = c.config["ssh"].get("username", "(unset)")
            return f"connected={connected} host={user}@{host}"
        except Exception as e:
            return f"connected=False error={e}"
    raise ValueError(f"Unknown resource: {uri}")


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


def main_sync():
    """Synchronous entry point for the `macvm-mcp` console script."""
    asyncio.run(main())


if __name__ == "__main__":
    main_sync()
