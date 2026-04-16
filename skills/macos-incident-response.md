---
name: macos-incident-response
description: Use when the user is responding to a suspected macOS compromise, hunt, or breach investigation. Triggers include "my mac is hacked", "investigate this mac", "IR on macOS", "find malware on this mac", "what's running on this machine", or any forensic / live-response scenario where the goal is to enumerate persistence, current activity, and IOCs on a (possibly compromised) macOS host.
---

# macOS Incident Response

You are operating against a real macOS host via the MacVM MCP server.

## Workflow

1. **Verify connectivity** — `check_connection`.
2. **One-shot IR** — call `incident_response_scan`. Returns persistence, kexts/system extensions, TCC, SIP, live network, suspicious processes, network filters, sample-of-/Applications quarantine status.
3. **Persistence deep-dive** — for any non-Apple plist returned: `analyze_plist` then `analyze_macho` on the `ProgramArguments[0]` binary. Hash it, check signature.
4. **Process deep-dive** — for any process not under `/System|/usr/(libexec|sbin|bin)|/Library/Apple`: `inspect_process` for open files, dylibs, network. Hash the binary on disk.
5. **Network deep-dive** — `monitor_network_realtime` (longer duration), then `tcpdump_start` → wait → `tcpdump_stop` + `download_to=<local pcap>` for offline analysis. Pull unique IPs/domains.
6. **Privacy / TCC** — review the TCC dump from the IR report against `mac://docs/cheatsheet`. Any non-Apple client with Accessibility, Input Monitoring, Full Disk Access, or Screen Recording is high-priority.
7. **Evidence preservation** — `take_screenshot`. `download_file` any suspicious binary. Record output of every step (the report itself is evidence).
8. **Output**: timeline (sorted by `last_modified` of artefacts), IOC list (hashes/IPs/domains/paths/bundle-IDs), MITRE ATT&CK for macOS mapping, prioritized remediation (kill PID, disable LaunchAgent, revoke TCC, image disk).

## Safety
- Read-only by default. Do not call `tccutil reset`, `launchctl remove`, `kill`, or any destructive op without explicit user confirmation.
- If SIP is disabled (`csrutil status` shows "disabled"), treat the entire system as untrusted — kernel-level evasion is in scope.
