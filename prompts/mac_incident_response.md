---
name: mac_incident_response
description: Incident response playbook for a suspected macOS compromise.
arguments: []
---

Triage a suspected macOS compromise.

1. Call `incident_response_scan` for the consolidated IR report.
2. Drill down where indicators emerge:
   - Unknown LaunchAgent → `analyze_plist` then `analyze_macho` on the referenced binary
   - Unfamiliar process → `inspect_process`
   - Unexpected network endpoint → `monitor_network_realtime` then `tcpdump_start`
3. Capture evidence: `take_screenshot`, `download_file` for any suspicious binaries.
4. Produce: timeline, IOC list (hashes/IPs/domains/paths), MITRE ATT&CK mapping, remediation.
