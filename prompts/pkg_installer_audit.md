---
name: pkg_installer_audit
description: Security audit workflow for a macOS .pkg installer.
arguments:
  - name: pkg_path
    description: Path to .pkg on macOS target
    required: true
---

Audit the installer package at `{pkg_path}`.

1. `get_file_hash` the .pkg.
2. `analyze_pkg_installer` to extract payload and surface preinstall/postinstall scripts.
3. Read each script with `read_file` — look for: `curl|wget`, `chmod +s`, sudoers edits,
   writes to `/Library/LaunchDaemons` or `/Library/PrivilegedHelperTools`.
4. For each binary in payload: `analyze_code_signing`, `get_entitlements`, `analyze_macho`.
5. Verdict: trustworthy installer, suspicious behavior, or outright malicious.
