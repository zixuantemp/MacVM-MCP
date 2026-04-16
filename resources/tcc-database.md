# TCC Database Reference

The TCC (Transparency, Consent and Control) database tracks per-app consent for privacy-protected resources.

## Locations
| DB | Scope |
|----|-------|
| `~/Library/Application Support/com.apple.TCC/TCC.db` | Per-user |
| `/Library/Application Support/com.apple.TCC/TCC.db` | System (needs sudo) |

## Schema (relevant table: `access`)
| Column | Meaning |
|--------|---------|
| `service` | Permission category (see below) |
| `client` | Bundle ID or absolute path of the requesting app |
| `client_type` | 0 = bundle ID, 1 = path |
| `auth_value` | 0 = denied, 2 = allowed, 3 = limited (e.g. partial Photos) |
| `auth_reason` | Why the value is what it is (user, MDM, system) |
| `last_modified` | Unix epoch |

## Common service identifiers
| Service | Resource |
|---------|----------|
| `kTCCServiceCamera` | Camera |
| `kTCCServiceMicrophone` | Microphone |
| `kTCCServiceAddressBook` | Contacts |
| `kTCCServiceCalendar` | Calendar |
| `kTCCServiceReminders` | Reminders |
| `kTCCServicePhotos` | Photos library |
| `kTCCServicePhotosAdd` | Add-only Photos |
| `kTCCServiceMediaLibrary` | Music library |
| `kTCCServiceLocation` | Core Location |
| `kTCCServiceAccessibility` | Accessibility / UI scripting (HIGH RISK) |
| `kTCCServicePostEvent` | Synthetic key/mouse events (HIGH RISK) |
| `kTCCServiceListenEvent` | Input monitoring / keylogging (HIGH RISK) |
| `kTCCServiceScreenCapture` | Screen recording |
| `kTCCServiceSystemPolicyAllFiles` | Full Disk Access (HIGH RISK) |
| `kTCCServiceSystemPolicyDocumentsFolder` | Documents folder |
| `kTCCServiceSystemPolicyDownloadsFolder` | Downloads folder |
| `kTCCServiceSystemPolicyDesktopFolder` | Desktop folder |
| `kTCCServiceSystemPolicyRemovableVolumes` | External drives |
| `kTCCServiceSystemPolicyNetworkVolumes` | Network shares |
| `kTCCServiceAppleEvents` | AppleScript automation of other apps |
| `kTCCServiceDeveloperTool` | Run unsigned binaries from Terminal |
| `kTCCServiceFileProviderDomain` | iCloud / file provider |

## Red flags for malware analysis
A non-Apple, non-MDM client with any of these is worth investigating:
- `kTCCServiceAccessibility`
- `kTCCServiceListenEvent`
- `kTCCServiceSystemPolicyAllFiles`
- `kTCCServiceScreenCapture`
- `kTCCServiceMicrophone` / `kTCCServiceCamera` (background apps)

## Sample query
```sql
SELECT service, client, auth_value, datetime(last_modified, 'unixepoch')
FROM access
WHERE auth_value = 2
  AND client NOT LIKE 'com.apple.%'
ORDER BY last_modified DESC;
```

## Resetting permissions
```bash
tccutil reset Camera                    # All apps, one service
tccutil reset Camera com.example.app    # One app, one service
tccutil reset All com.example.app       # One app, every service
```
