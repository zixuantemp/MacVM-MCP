---
name: triage_macos_sample
description: Walk through full static triage of a suspected macOS malware sample.
arguments:
  - name: sample_path
    description: Path to sample on the macOS target
    required: true
---

Perform a full static triage of the macOS sample at `{sample_path}`.

1. Call `check_connection` first.
2. Call `triage_full` with `file_path={sample_path}` for the consolidated report, or run individually:
   - `get_file_hash`
   - `analyze_macho`
   - `extract_strings` with `filter_pattern='http|flag|key|password|crypto|exec'`
   - `analyze_code_signing` and `get_entitlements`
   - `get_quarantine_info`, `check_gatekeeper`
3. Look up hashes against VirusTotal / known-bad lists.
4. Summarise: signing identity, capabilities (entitlements), notable strings, IOC candidates.
5. Decide whether to escalate to dynamic analysis (`behavioral_full`).
