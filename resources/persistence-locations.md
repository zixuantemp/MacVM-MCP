# macOS Persistence Locations

Reference list of every persistence mechanism MacMCP enumerates via `check_persistence`.

## launchd jobs (the big one)
| Path | Scope | Runs as |
|------|-------|---------|
| `~/Library/LaunchAgents/` | Per-user | User, on login |
| `/Library/LaunchAgents/` | All users | User, on login |
| `/Library/LaunchDaemons/` | System | root, on boot |
| `/System/Library/LaunchAgents/` | Apple-only | User |
| `/System/Library/LaunchDaemons/` | Apple-only | root |

Inspect with `launchctl list` / `launchctl print`. Each plist references a `ProgramArguments` binary — always run `analyze_macho` + `analyze_code_signing` on it.

## Login Items
- `~/Library/Preferences/com.apple.loginitems.plist` (legacy)
- Modern (Ventura+): SMAppService — surfaced via `sfltool dumpbtm`
- `osascript -e 'tell application "System Events" to get the name of every login item'`

## Login / Logout Hooks (deprecated but still functional)
```
defaults read com.apple.loginwindow LoginHook
defaults read com.apple.loginwindow LogoutHook
```

## Cron / At
- `crontab -l` (per-user)
- `/etc/crontab`, `/etc/cron.d/`, `/etc/periodic/{daily,weekly,monthly}/`
- `atq` — pending at(1) jobs

## Kernel & System Extensions
- Kexts (legacy): `/Library/Extensions/`, `/System/Library/Extensions/` — `kextstat`
- System Extensions (modern): `/Library/SystemExtensions/` — `systemextensionsctl list`
- DriverKit, EndpointSecurity, NetworkExtension, ContentFilter

## Configuration Profiles
- `profiles list` (MDM-installed)
- `/Library/Managed Preferences/`

## Spotlight / QuickLook plug-ins
- `/Library/Spotlight/`, `~/Library/Spotlight/`
- `/Library/QuickLook/`, `~/Library/QuickLook/`

## Authorization Plugins
- `/Library/Security/SecurityAgentPlugins/`

## Dock / Finder Tiles
- `~/Library/Preferences/com.apple.dock.plist`

## Emond (Event Monitor — deprecated, removed in Ventura)
- `/etc/emond.d/rules/`

## Screen Savers (run as user)
- `/Library/Screen Savers/`, `~/Library/Screen Savers/`

## Sandboxed app re-open list
- `~/Library/Preferences/ByHost/com.apple.loginwindow.*.plist`

## PrivilegedHelperTools (SMJobBless)
- `/Library/PrivilegedHelperTools/` — root daemons installed by signed apps
- `/Library/LaunchDaemons/<bundle_id>.plist` matching helper

## Safari / Browser Extensions
- `~/Library/Safari/Extensions/`
- `~/Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions/`

## Periodic Apple-supplied jobs (legitimate but abusable)
- `/etc/periodic/daily/*`, `weekly/*`, `monthly/*`
- `/etc/defaults/periodic.conf`, `/etc/periodic.conf`

## ssh persistence
- `~/.ssh/authorized_keys`, `~/.ssh/config`
- `/etc/ssh/sshd_config`

## Shell rc files
- `~/.bash_profile`, `~/.bashrc`, `~/.zshrc`, `~/.zprofile`, `~/.profile`
- `/etc/zshenv`, `/etc/profile`
