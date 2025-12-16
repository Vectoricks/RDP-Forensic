# Release Notes - RDP-Forensic v1.0.6

**Release Date:** December 16, 2025

## 🎯 Overview

Version 1.0.6 adds **EventID 4776 (Credential Validation)** to authentication tracking, providing earlier detection of RDP connection attempts and enhanced brute force attack detection capabilities.

---

## ✨ New Features

### EventID 4776 - Credential Validation Tracking

**What is EventID 4776?**
- **"The computer attempted to validate the credentials for an account"**
- Logs NTLM credential validation attempts
- Occurs **before** EventID 4624 (Logon)
- Shows authentication package used (NTLM vs Kerberos)
- Provides Error Code: 0x0 = success, other = failure reason

**Benefits:**
- ✅ **Earlier Detection** - Captures authentication phase before logon
- ✅ **Brute Force Detection** - Shows repeated failed credential validation attempts
- ✅ **Authentication Protocol Visibility** - Identifies NTLM vs Kerberos usage
- ✅ **Source Tracking** - Shows workstation initiating authentication
- ✅ **Enhanced Forensics** - Completes the authentication timeline

**Event Details Captured:**
```
Account Name: <username>
Source Workstation: <source_computer>
Error Code: 0x0 (success) or error code
Authentication Package: NTLM
```

---

## 🔧 Improvements

### Enhanced Authentication Collection

**Updated Function:**
- `Get-RDPAuthenticationEvents` now collects EventID 4624, 4625, **and 4776**
- Parses both logon events and credential validation events
- Maintains ActivityID correlation for all event types
- Provides detailed error code information for failed validations

**Event Types Added:**
- `Credential Validation Success` - EventID 4776 with Error Code 0x0
- `Credential Validation Failed` - EventID 4776 with non-zero error code

### Lifecycle Tracking

- EventID 4776 now marks the **Authentication** lifecycle stage
- Improves session completeness detection
- Provides earlier authentication timestamp

---

## 📊 Usage Examples

### Detect Brute Force Attempts

```powershell
# Collect all authentication events including credential validation
$events = Get-RDPForensics -StartDate (Get-Date).AddHours(-24)

# Filter for failed credential validation
$events | Where-Object { 
    $_.EventID -eq 4776 -and $_.EventType -like '*Failed*' 
} | Group-Object User | Select-Object Count, Name | Sort-Object Count -Descending
```

### Authentication Timeline Analysis

```powershell
# View complete authentication sequence
Get-RDPForensics -Username "administrator" -GroupBySession | 
    ForEach-Object { 
        $_.Events | Where-Object { $_.EventID -in 4776, 4624, 4625 } | 
        Sort-Object TimeCreated 
    }
```

**Expected Sequence:**
1. **EventID 4776** - Credential Validation (NTLM check)
2. **EventID 4624** - Successful Logon (after validation passes)
3. **EventID 21** - Session Logon Succeeded

### Identify Authentication Protocol

```powershell
# Check which authentication method was used
Get-RDPForensics -StartDate (Get-Date).AddDays(-1) | 
    Where-Object { $_.EventID -eq 4776 } | 
    Select-Object TimeCreated, User, Details
```

---

## 🔍 Technical Details

### EventID 4776 Message Structure

```
Event ID: 4776
Source: Microsoft-Windows-Security-Auditing
Description: The computer attempted to validate the credentials for an account

Authentication Package: NTLM
Logon Account: <domain>\<user>
Source Workstation: <computer_name>
Error Code: 0x0
```

**Error Codes:**
- `0x0` - Success
- `0xC0000064` - User name does not exist
- `0xC000006A` - Incorrect password
- `0xC0000234` - Account locked out
- `0xC0000072` - Account disabled
- `0xC000006F` - Logon outside allowed time
- `0xC0000193` - Account expired
- `0xC0000071` - Password expired

### Lifecycle Stage Updates

```
Old: ConnectionAttempt → Authentication (4624) → Logon (21)
New: ConnectionAttempt → Authentication (4776/4624) → Logon (21)
```

---

## 📝 Breaking Changes

**None** - This release is fully backward compatible.

---

## ⚙️ Configuration

### Enable EventID 4776 Logging

EventID 4776 requires the **"Audit Credential Validation"** policy:

**Via PowerShell:**
```powershell
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Credential Validation"
```

**Via Group Policy:**
```
Computer Configuration → Policies → Windows Settings → 
Security Settings → Advanced Audit Policy Configuration → 
Account Logon → Audit Credential Validation

Enable: Success and Failure
```

**Via Local Security Policy:**
1. Run `secpol.msc`
2. Navigate to: Advanced Audit Policy Configuration → Account Logon
3. Enable "Audit Credential Validation" (Success, Failure)

---

## 🚀 Upgrade Instructions

### From v1.0.5

1. **Update Module:**
   ```powershell
   Remove-Module RDP-Forensic -ErrorAction SilentlyContinue
   Import-Module .\RDP-Forensic.psd1 -Force
   ```

2. **Verify Version:**
   ```powershell
   Get-Module RDP-Forensic | Select-Object Version
   # Should show 1.0.6
   ```

3. **Enable Credential Validation Auditing:**
   ```powershell
   auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
   ```

4. **Test Collection:**
   ```powershell
   Get-RDPForensics -StartDate (Get-Date).AddHours(-1) | 
       Where-Object { $_.EventID -eq 4776 }
   ```

---

## 🛡️ Security Benefits

### Brute Force Detection

EventID 4776 is critical for detecting password spray and brute force attacks:

```powershell
# Detect multiple failed validations from same source
Get-RDPForensics -StartDate (Get-Date).AddDays(-1) | 
    Where-Object { $_.EventID -eq 4776 -and $_.Details -notmatch '0x0' } |
    Group-Object User, Details |
    Where-Object { $_.Count -gt 5 } |
    Select-Object @{N='Account';E={$_.Group[0].User}}, 
                  @{N='ErrorCode';E={$_.Group[0].Details}}, 
                  @{N='Attempts';E={$_.Count}}
```

### Account Lockout Correlation

```powershell
# Find locked accounts from credential validation failures
Get-RDPForensics -StartDate (Get-Date).AddHours(-1) |
    Where-Object { $_.EventID -eq 4776 -and $_.Details -match '0xC0000234' }
```

---

## 📋 Compatibility

- **PowerShell:** 5.1, 7.x, 8.0+
- **Windows:** Server 2012 R2+, Windows 8.1+
- **Requires:** Administrator privileges + Credential Validation audit policy enabled
- **Dependencies:** None

---

## 📜 Changelog

### v1.0.6 (2025-12-16)
- **Added:** EventID 4776 (Credential Validation) to authentication tracking
- **Enhanced:** Authentication timeline with pre-logon credential validation
- **Improved:** Brute force attack detection capabilities
- **Updated:** Lifecycle tracking to include 4776 in Authentication stage
- **Added:** Error code parsing for credential validation failures
- **Added:** Authentication package identification (NTLM/Kerberos)

### Previous Versions
- **v1.0.5:** ActivityID-based event correlation
- **v1.0.4:** Event correlation engine with session lifecycle tracking
- **v1.0.3:** PowerShell 5.1 Unicode compatibility fixes
- **v1.0.2:** Real-time monitoring with Watch mode
- **v1.0.1:** Initial event collection and forensics
- **v1.0.0:** Initial release

---

## 📞 Feedback & Support

- **Issues:** [GitHub Issues](https://github.com/BetaHydri/RDP-Forensic/issues)
- **Discussions:** [GitHub Discussions](https://github.com/BetaHydri/RDP-Forensic/discussions)
- **Author:** Jan Tiedemann

---

**Thank you for using RDP-Forensic!** 🎉

EventID 4776 adds crucial pre-authentication visibility for enhanced security monitoring and forensic analysis.
