# Security Model

MacVM-MCP gives an LLM remote-code-execution on a macOS analysis VM. The threat model below is what we defend against and what we don't.

## In scope
- Shell injection from LLM-supplied tool arguments → all user-controlled strings interpolated into bash commands are escaped via `shlex.quote` (`_sh()` helper in `server.py`). Adding new tools requires the same discipline.
- Sudo password disclosure on the macOS target → password is delivered via stdin (`sudo -S -p ''`), never via `echo … | sudo -S` (which leaks via `ps`).
- MITM on SSH transport → `paramiko.RejectPolicy` is the default; host keys must already be in `~/.ssh/known_hosts`. Set `MAC_SSH_AUTO_ADD_HOSTKEY=1` only for first-time setup.
- Credential storage → SSH agent and key files are preferred. Passwords in `config.json` are supported but discouraged.

## Out of scope
- The macOS analysis VM itself. By design we *want* an LLM to execute (potentially malicious) binaries on it. Use a dedicated VM, snapshot before each session, revert after.
- Side channels through the MCP transport (stdio).
- Trust in the operator. Anyone with `MACMCP_CONFIG` access can reach the macOS VM.

## Recommended deployment
1. Generate a dedicated SSH key pair for the analysis VM. Don't reuse personal keys.
2. Restrict the analyst account in `/etc/sudoers` to the specific commands MacMCP uses (`tcpdump`, `fs_usage`, `dtrace`, `gcore`, `pkill`).
3. Network-isolate the VM (host-only adapter or dedicated VLAN). The whole point is malware can phone home — you want to control where.
4. Snapshot the VM before each engagement; revert after.
5. Never store the macOS user's iCloud / Apple ID password in `config.json`.

## Reporting

Open a GitHub security advisory or email the maintainer. Please don't file public issues for unpatched vulnerabilities.

## What changed in 1.0

- Added `_sh()` shell-quoting helper; audited every f-string in `server.py` (~30 sites).
- Replaced `echo '<pwd>' | sudo -S` with stdin-fed sudo.
- Replaced `paramiko.AutoAddPolicy` (TOFU) with `RejectPolicy` + opt-in env var.
- Whitelisted `arch` parameter in `disassemble_function`.
- Sanitised `app_identifier` in `check_tcc_permissions` (alnum + `.-_` only).
- Frida/dtrace/lldb scripts now uploaded via base64 (immune to quote-escape bugs).
