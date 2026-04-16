---
name: audit-app-bundle
description: Use when the user wants to audit, vet, or analyse an installed macOS .app bundle for trustworthiness, capabilities, or supply-chain integrity. Triggers include "audit this app", "what does this .app do", "is this Mac application safe", "check entitlements of X.app", or requests to evaluate any application in /Applications or ~/Applications.
---

# Audit a macOS .app bundle

You are working with the MacVM MCP server. The target is a real macOS machine reachable over SSH.

## Workflow

1. **Verify connectivity** — `check_connection`.
2. **Locate the bundle** — typical paths are `/Applications/<Name>.app` or `~/Applications/<Name>.app`. Confirm it exists with `execute_bash` (`ls -la <app>`).
3. **Full audit** — call `app_bundle_full_audit` with `app_path=<path>`. Reads Info.plist, signing, entitlements, frameworks, plugins, helpers, dylibs, dropper hashes, Gatekeeper.
4. **Risk-score the entitlements** — cross-reference the signing report against `mac://docs/cheatsheet` and the TCC reference at `mac://docs/cheatsheet`. Highlight any of: `com.apple.security.cs.allow-unsigned-executable-memory`, `com.apple.security.device.audio-input`, `kTCCServiceAccessibility`, Full Disk Access.
5. **Inspect helper persistence** — for any LoginItem / XPC / PrivilegedHelperTool found, run `analyze_macho` and `analyze_code_signing` on it. Cross-reference the signer team ID against the parent app.
6. **Optional dynamic check** — `behavioral_full` against `Contents/MacOS/<MainExecutable>` if the audit reveals high-risk entitlements and the user wants behaviour.
7. **Output**: trust verdict (signed-and-notarized / signed-only / ad-hoc / unsigned), capability summary, persistence footprint installed, recommended action (allow / sandbox / remove).

## Pitfalls
- A signed bundle with `com.apple.security.get-task-allow=true` is debug-signed — never deploy it.
- Sparkle.framework <2.0 has CVE-2016-4148 — flag any bundle still shipping the old version.
