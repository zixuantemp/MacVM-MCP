---
name: mac_persistence_check
description: Comprehensive persistence enumeration workflow for macOS.
arguments: []
---

Enumerate every persistence mechanism on the target macOS machine.

1. Call `check_persistence` for the full sweep.
2. For any non-Apple plist found, call `analyze_plist` on it.
3. Call `list_login_items` and `list_kernel_extensions`.
4. Call `check_network_filters` for Network/Content/VPN extensions.
5. Flag: unsigned LaunchAgents, third-party kexts, sfltool entries with unknown publishers.
6. Output: table of (location, name, signer, last-modified).
