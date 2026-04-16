---
name: analyze_app_bundle
description: Step-by-step audit workflow for a macOS .app bundle.
arguments:
  - name: app_path
    description: Path to .app on macOS target
    required: true
---

Audit the macOS application bundle at `{app_path}`.

1. Call `app_bundle_full_audit` with `app_path={app_path}` for the full report.
2. Pay attention to:
   - Privacy entitlements (Camera, Microphone, AddressBook, FullDiskAccess)
   - LoginItems / XPC services that survive uninstall
   - Non-Apple-signed dylibs and `@rpath` / `@loader_path` references
   - Bundled binaries with hashes that don't match the publisher's notarization
3. If suspicious, run `behavioral_full` against the main executable.
4. Report: trust verdict, capability summary, persistence footprint, IOCs.
