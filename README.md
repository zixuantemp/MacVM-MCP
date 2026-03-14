# MacMCP — macOS Analysis MCP Server

A Model Context Protocol (MCP) server for macOS security research and malware analysis.
Connects to a macOS machine via SSH and exposes 39 tools equivalent to FlareVM MCP but for macOS.

## Architecture

```
Kali Linux (Claude Code)
      │
      │  SSH (paramiko)
      ▼
macOS 14/15/26 target
  ├── Static analysis (otool, codesign, strings)
  ├── Behavioral analysis (fs_usage, dtrace)
  ├── Network monitoring (tcpdump, lsof)
  ├── Persistence (launchctl, plist)
  ├── Security (SIP, TCC, Gatekeeper)
  └── Dynamic (Frida, LLDB)
```

## Setup

### 1. Configure SSH access

Copy and edit the config:
```bash
cp config.json.example config.json
```

Edit `config.json`:
```json
{
  "ssh": {
    "host": "192.168.1.100",
    "port": 22,
    "username": "analyst",
    "password": "yourpassword",
    "key_file": "~/.ssh/id_rsa"
  },
  "remote_work_dir": "/tmp/macmcp",
  "local_work_dir": "/home/kali/Desktop/analysis"
}
```

Or use environment variables:
```bash
export MAC_SSH_HOST=192.168.1.100
export MAC_SSH_USER=analyst
export MAC_SSH_PASSWORD=yourpassword
export MAC_SSH_KEY=~/.ssh/id_rsa
```

### 2. macOS target requirements

- SSH enabled: `System Settings → General → Sharing → Remote Login`
- Optional for full capability (some tools need sudo):
  ```bash
  # On the macOS target, allow passwordless sudo for analysis user:
  echo "analyst ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/analyst
  ```
- Optional: Install Frida for dynamic instrumentation:
  ```bash
  pip3 install frida-tools
  ```

### 3. Register with Claude Code

Add to `~/.claude/claude_desktop_config.json` (or the active MCP config):

```json
{
  "mcpServers": {
    "macmcp": {
      "command": "/home/kali/Desktop/venv/bin/python3",
      "args": ["/home/kali/Desktop/MacMCP/server.py"],
      "env": {
        "MACMCP_CONFIG": "/home/kali/Desktop/MacMCP/config.json"
      }
    }
  }
}
```

## Tool Reference

### Connection & File Transfer
| Tool | Description |
|------|-------------|
| `check_connection` | Verify SSH + show OS version. **Always call first.** |
| `upload_file` | Copy file from Kali → macOS |
| `download_file` | Copy file from macOS → Kali |

### Basic System
| Tool | Description |
|------|-------------|
| `execute_bash` | Run any bash command (optional sudo) |
| `read_file` | Read remote file contents |
| `get_file_hash` | MD5 + SHA1 + SHA256 |
| `list_processes` | `ps aux` with optional filter |
| `get_system_info` | SW version, hardware, SIP, boot-args |

### Static Analysis
| Tool | Description |
|------|-------------|
| `analyze_macho` | Mach-O headers, load commands, symbols |
| `extract_strings` | Strings with optional regex filter |
| `analyze_code_signing` | Certificate, team ID, notarization |
| `get_entitlements` | Entitlements plist |
| `analyze_dylibs` | Linked dylibs (`otool -L`) |
| `get_quarantine_info` | com.apple.quarantine xattr |
| `check_gatekeeper` | `spctl` assessment |
| `disassemble_function` | `otool -tV` disassembly |

### Behavioral Analysis
| Tool | Description |
|------|-------------|
| `execute_with_monitoring` | **All-in-one**: run binary + fs_usage + network capture |
| `fs_usage_monitor` | File system activity via `fs_usage` |
| `dtrace_trace` | DTrace one-liner or script |

### Network Analysis
| Tool | Description |
|------|-------------|
| `monitor_network_realtime` | Live connections via `lsof -i` |
| `tcpdump_start` | Start packet capture (background) |
| `tcpdump_stop` | Stop capture + summarize + optional download |

### Persistence
| Tool | Description |
|------|-------------|
| `check_persistence` | **Comprehensive**: all persistence locations |
| `list_launch_agents` | LaunchAgents + LaunchDaemons |
| `analyze_plist` | Parse any plist in human-readable form |
| `list_login_items` | Login items via osascript |

### macOS Security Features
| Tool | Description |
|------|-------------|
| `check_sip_status` | SIP + authenticated root status |
| `check_tcc_permissions` | TCC DB: app permission grants |
| `list_kernel_extensions` | kexts + System Extensions |
| `check_network_filters` | Network Extension providers |

### Dynamic Analysis
| Tool | Description |
|------|-------------|
| `frida_list_processes` | List Frida-injectable processes |
| `frida_run_script` | Instrument running process with JS |
| `frida_spawn_and_attach` | Spawn + instrument from launch |
| `inspect_process` | lsof + vmmap + ps for a process |
| `dump_process_memory` | `gcore` memory dump |
| `lldb_run_commands` | LLDB commands on binary/process |

### App Analysis
| Tool | Description |
|------|-------------|
| `analyze_app_bundle` | Full .app bundle analysis |
| `analyze_pkg_installer` | .pkg contents + scripts + signature |
| `take_screenshot` | Screenshot → download to Kali |

## Workflow Examples

### Quick triage
```
1. check_connection
2. upload_file (sample)
3. get_file_hash (sample)
4. analyze_macho (sample)
5. extract_strings (sample, filter_pattern="http|flag|key|password")
6. analyze_code_signing (sample)
```

### Behavioral analysis
```
1. upload_file (sample)
2. check_persistence  ← baseline
3. execute_with_monitoring (sample, duration=30)
4. check_persistence  ← diff for new entries
```

### .app bundle analysis
```
1. upload_file (MyApp.app → /tmp/macmcp/MyApp.app)
2. analyze_app_bundle (/tmp/macmcp/MyApp.app)
3. extract_strings (main binary)
4. check_gatekeeper (/tmp/macmcp/MyApp.app)
```

### Network IOC extraction
```
1. tcpdump_start (interface=en0)
2. execute_bash (run the sample)
3. sleep 30
4. tcpdump_stop (download_to=/home/kali/Desktop/analysis/capture.pcap)
```

### Frida API hooking
```javascript
// Hook NSURLSession to capture network requests
Interceptor.attach(
  ObjC.classes.NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
  onEnter(args) {
    const request = new ObjC.Object(args[2]);
    console.log('[NSURLSession]', request.URL().absoluteString());
  }
});
```

## macOS vs FlareVM Comparison

| FlareVM Tool | MacMCP Equivalent |
|---|---|
| `check_connection` (WinRM) | `check_connection` (SSH) |
| `execute_powershell` | `execute_bash` |
| `get_file_hash` | `get_file_hash` |
| `die_analyze` | `analyze_macho` + `extract_strings` |
| `capa_analyze` | `analyze_code_signing` + `analyze_macho` |
| `floss_extract_strings` | `extract_strings` |
| `procmon_start/stop` | `fs_usage_monitor` + `dtrace_trace` |
| `fakenet_start/stop` | `tcpdump_start/stop` |
| `regshot_snapshot` | `check_persistence` (before/after) |
| `autoruns_analyze` | `list_launch_agents` + `check_persistence` |
| `execute_with_monitoring` | `execute_with_monitoring` |
| `frida_run_script` | `frida_run_script` |
| `x64dbg_load` | `lldb_run_commands` |
| `process_hacker_info` | `inspect_process` |
| `take_screenshot` | `take_screenshot` |
