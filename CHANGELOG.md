# Changelog

All notable changes to the RDP Forensics Toolkit will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.8] - 2025-12-17

### Added
- Event 4648 (Explicit Credential Usage) support with time-based correlation
- PowerShell Parameter Sets for LogonID/SessionID mutual exclusivity
- Event table display in GroupBySession output
- Enhanced lifecycle warning messages (specific, contextual)
- Comprehensive documentation for LogonID vs SessionID filtering best practices

### Fixed
- SessionID filtering bug (moved to pre-correlation stage for accuracy)
- Event 4648 correlation (now uses time-based correlation instead of direct LogonID)
- Lifecycle completion logic (no false warnings for active sessions)
- Double output in GroupBySession mode (removed duplicate table)

### Changed
- Lifecycle completion definition (more realistic: Authentication + (Logon OR Active) OR Logoff)
- SessionID filter execution order (now pre-correlation)
- Warning messages (more specific and helpful)

### Removed
- Get-CurrentRDPSessions `-SessionID` parameter (use standard PowerShell filtering instead)

### Improved
- Help documentation (RECOMMENDED/NOTE annotations for LogonID vs SessionID)
- README.md (forensic best practices section with comparison tables)
- Parameter guidance (when to use LogonID vs SessionID)
- Get-CurrentRDPSessions simplicity (standard PowerShell filtering patterns)

**[Full Release Notes](docs/releases/v1.0.8.md)**

---

## [1.0.7] - 2025-12-16

### Fixed
- **Critical:** Improved correlation engine for better Domain Controller compatibility
- Event 4624 parsing with enhanced username extraction (domain\username format)
- Username format standardization across all events
- Secondary correlation now properly merges SessionID events into LogonID sessions
- Synchronized event detection prevents duplicate event correlation

### Changed
- LogonID-first correlation strategy (Security log priority over TerminalServices)
- Enhanced matching criteria: Username + Time (±10s) + RDP LogonType verification

### Added
- `-LogonID` parameter for filtering specific Security log sessions
- `-SessionID` parameter for filtering specific TerminalServices sessions
- Intelligent session merging (LogonID + SessionID correlation)

**[Full Release Notes](docs/releases/v1.0.7.md)**

---

## [1.0.6] - 2025-12-15

### Added
- Event 4776 (NTLM Credential Validation) tracking via `-IncludeCredentialValidation` parameter
- Comprehensive Kerberos authentication tracking (EventIDs 4768-4772)
- Time-based correlation for pre-authentication events (Domain Controller events)
- Automatic filtering of non-RDP authentication attempts
- Detection of Kerberos-to-NTLM fallback scenarios

### Improved
- Authentication flow visibility (Kerberos → NTLM fallback)
- Brute force detection (includes failed credential validations)
- Forensic timeline completeness

**[Full Release Notes](docs/releases/v1.0.6.md)**

---

## [1.0.5] - 2025-12-14

### Added
- ActivityID-based event correlation for precise cross-log matching
- Windows Event Correlation infrastructure integration
- Lifecycle completeness indicators

### Changed
- Correlation priority: ActivityID > LogonID > SessionID
- Improved session tracking accuracy

**[Full Release Notes](docs/releases/v1.0.5.md)**

---

## [1.0.4] - 2025-12-13

### Added
- Session grouping with `-GroupBySession` parameter
- Event correlation across all log sources
- Session lifecycle tracking (6 stages)
- Session duration analysis
- Lifecycle completeness warnings
- Separate CSV export for sessions

### Changed
- Export generates two files: events + session summary

**[Full Release Notes](docs/releases/v1.0.4.md)**

---

## [1.0.0] - 2025-12-09

### Added
- Initial release
- Comprehensive RDP connection lifecycle tracking
- Multi-source event log correlation (5 log sources)
- 15+ Event IDs monitoring
- Real-time session monitoring with `Get-CurrentRDPSessions`
- Brute force attack detection
- CSV export with summary reports
- Advanced filtering (username, IP, date range)
- Outbound connection tracking
- 10 ready-to-use example scenarios
- Complete test suite with Pester
- PowerShell 5.1 and 7.x compatibility

---

## Version History Quick Reference

| Version | Date | Key Features |
|---------|------|--------------|
| 1.0.8 | 2025-12-17 | Event 4648, Parameter Sets, SessionID fix |
| 1.0.7 | 2025-12-16 | Correlation engine fixes, LogonID/SessionID filters |
| 1.0.6 | 2025-12-15 | Kerberos/NTLM tracking, Event 4776 |
| 1.0.5 | 2025-12-14 | ActivityID correlation |
| 1.0.4 | 2025-12-13 | Session grouping, lifecycle tracking |
| 1.0.0 | 2025-12-09 | Initial release |

---

## Documentation

- [README.md](README.md) - Complete toolkit documentation
- [Getting Started Guide](docs/GETTING_STARTED.md) - Quick start tutorial
- [Quick Reference](docs/QUICK_REFERENCE.md) - Event IDs and command reference
- [Kerberos/NTLM Authentication](docs/KERBEROS_NTLM_AUTHENTICATION.md) - Deep dive into authentication tracking
- [Release Notes](docs/releases/) - Detailed version release notes

## Links

- **Repository:** https://github.com/BetaHydri/RDP-Forensic
- **Issues:** https://github.com/BetaHydri/RDP-Forensic/issues
- **License:** MIT
