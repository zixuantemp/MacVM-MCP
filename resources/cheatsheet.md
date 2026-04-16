# macOS Analysis Cheatsheet

## File Identification
```bash
file sample                           # File type, architecture
otool -h sample                       # Mach-O header
otool -f sample                       # Fat header (universal binary)
lipo -info sample                     # Architectures in fat binary
lipo -thin arm64 sample -output thin  # Extract single arch
```

## Strings & Symbols
```bash
strings -n 6 sample                   # ASCII strings, min 6 chars
strings -a -n 6 sample                # Search whole file
nm -m sample                          # Symbols with library origin
nm -gU sample                         # Globals + undefined
otool -IV sample                      # Indirect symbol table
```

## Linked Libraries
```bash
otool -L sample                       # Linked dylibs
otool -D sample                       # Install name
otool -l sample | grep -A2 RPATH      # Runtime search paths
```

## Disassembly
```bash
otool -tV sample                      # Disassemble text segment
otool -arch arm64 -tV sample          # Specific architecture
lldb sample                           # Interactive debugger
  (lldb) disassemble -n main
  (lldb) image lookup -rn ".*"
```

## Code Signing & Notarization
```bash
codesign -dvvv sample                 # Verbose signature info
codesign -d --entitlements :- sample  # Entitlements (XML to stdout)
codesign --verify --deep --strict sample
spctl --assess --verbose=4 sample     # Gatekeeper assessment
spctl --status                        # Gatekeeper enabled?
stapler validate sample.app           # Notarization ticket
```

## Quarantine & Provenance
```bash
xattr -l sample                       # All extended attributes
xattr -p com.apple.quarantine sample  # Quarantine flags
xattr -d com.apple.quarantine sample  # Strip quarantine
mdls sample                           # Spotlight metadata
```

## Persistence Enumeration
```bash
ls ~/Library/LaunchAgents
ls /Library/LaunchAgents /Library/LaunchDaemons
launchctl list                        # Running launchd jobs
sfltool dumpbtm                       # Background Task Management (Ventura+)
profiles list                         # Configuration profiles
kextstat | grep -v com.apple          # Loaded kernel extensions
systemextensionsctl list              # System extensions
```

## TCC (Privacy)
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service,client,auth_value FROM access"
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service,client,auth_value FROM access"
tccutil reset All <bundle_id>         # Reset permissions
```

## Live Monitoring
```bash
sudo fs_usage -f filesystem            # Real-time file syscalls
sudo fs_usage -f network               # Network syscalls
sudo dtrace -n 'syscall:::entry { @[execname] = count(); }'
sudo tcpdump -i en0 -w cap.pcap        # Packet capture
lsof -nP -i                            # Network connections
sudo lsof -p <pid>                     # Files held open by pid
vmmap <pid>                            # Process memory map
sample <pid> 5                         # 5-second CPU sample
```

## App Bundle Layout
```
MyApp.app/
└── Contents/
    ├── Info.plist                    ← Bundle metadata
    ├── _CodeSignature/               ← Detached signature
    ├── MacOS/MyApp                   ← Main executable
    ├── Frameworks/                   ← Bundled frameworks
    ├── PlugIns/                      ← Loadable plug-ins
    ├── XPCServices/                  ← XPC helpers
    ├── Library/LoginItems/           ← Auto-launch helpers
    └── Resources/                    ← Assets, .nib, .lproj/
```

## .pkg Installer Inspection
```bash
pkgutil --check-signature pkg.pkg
pkgutil --payload-files pkg.pkg
xar -tf pkg.pkg                       # Show contents
xar -xf pkg.pkg                       # Extract
# Then inspect: Distribution (XML), preinstall, postinstall, *.pkg/Payload
```

## Frida (Dynamic Instrumentation)
```bash
frida-ps -U                           # List processes
frida -n Safari -l hook.js            # Attach by name
frida -f /path/to/binary -l hook.js   # Spawn + attach
```
