# Credential Detection Feature Design

**Date:** 2025-12-01
**Status:** Approved

## Overview

Add passive credential detection to identify cleartext authentication in captured network traffic. Credentials are displayed as critical threats in the existing Threats tab.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Use case | General-purpose (audit, IR, hunting) | Maximum utility |
| UI location | Threats tab as threat category | Credentials in cleartext ARE threats |
| Protocols | Comprehensive (13 protocols) | Full forensic capability |
| Credential storage | Full extraction | Maximum forensic value |
| Severity | All Critical | Any cleartext credential is a security failure |
| Extraction method | TShark fields, single-pass | ~10-15% overhead, acceptable |

## Supported Protocols

### Tier 1: Core Cleartext
- HTTP Basic Auth (`http.authorization`, `http.authbasic`)
- FTP (`ftp.request.command`, `ftp.request.arg`)
- Telnet (pattern matching in `telnet.data`)
- POP3 (`pop.request.command`, `pop.request.parameter`)
- IMAP (`imap.request`)

### Tier 2: Enterprise
- SMTP AUTH (`smtp.req.command`, `smtp.req.parameter`)
- LDAP Simple Bind (`ldap.simple`, `ldap.bindRequest.name`)
- SNMP Community Strings (`snmp.community`)

### Tier 3: Windows/Advanced
- Kerberos (`kerberos.CNameString`, `kerberos.realm`)
- NTLM (`ntlmssp.auth.username`, `ntlmssp.auth.domain`)

### Tier 4: Database
- MySQL (`mysql.user`, `mysql.passwd`)
- PostgreSQL (`pgsql.user`, `pgsql.password`)

## Architecture

### Data Flow

```
TShark (with credential fields)
         │
         ▼
TSharkParserOptimized.ParseLine()
         │
         ▼
ICredentialDetectionService.ExtractCredential()
         │
         ├──► CredentialFinding (stored in memory)
         │
         ▼
PacketInfo.HasCredentials = true
         │
         ▼ (post-analysis)
ThreatsViewModel receives credential findings as ThreatInfo
         │
         ▼
Threats tab displays with [Details] button
```

### New TShark Fields

Added to `BuildStreamingArguments()`:

```
-e http.authorization -e http.authbasic
-e ftp.request.command -e ftp.request.arg
-e telnet.data
-e smtp.req.command -e smtp.req.parameter
-e imap.request
-e pop.request.command -e pop.request.parameter
-e ldap.simple -e ldap.bindRequest.name
-e snmp.community
-e kerberos.CNameString -e kerberos.realm
-e ntlmssp.auth.username -e ntlmssp.auth.domain
-e mysql.user -e mysql.passwd
-e pgsql.user -e pgsql.password
```

### Data Model

```csharp
public record CredentialFinding
{
    public required uint FrameNumber { get; init; }
    public required DateTime Timestamp { get; init; }
    public required string SourceIP { get; init; }
    public required string DestinationIP { get; init; }
    public required ushort DestinationPort { get; init; }
    public required CredentialProtocol Protocol { get; init; }
    public required string? Username { get; init; }
    public required string? Password { get; init; }
    public string? Domain { get; init; }
    public string? AdditionalContext { get; init; }
}

public enum CredentialProtocol
{
    HttpBasic, HttpDigest, Ftp, Telnet, Pop3, Imap,
    Smtp, Ldap, Snmp, Kerberos, Ntlm, MySql, PostgreSql
}
```

### Service Interface

```csharp
public interface ICredentialDetectionService
{
    CredentialFinding? ExtractCredential(
        ReadOnlySpan<char> fields,
        uint frameNumber,
        DateTime timestamp,
        string sourceIP,
        string destIP,
        ushort destPort);

    IReadOnlyList<CredentialFinding> GetFindings();
    void Clear();
}
```

### Protocol Extractors (Strategy Pattern)

```csharp
internal interface IProtocolCredentialExtractor
{
    CredentialProtocol Protocol { get; }
    CredentialFinding? TryExtract(CredentialFieldData fields);
}
```

One implementation per protocol for clean separation.

## UI Design

### Threats Tab Integration

Credential findings appear as rows in the existing threat grid:

| Time | Severity | Category | Source | Destination | Protocol | Description | Actions |
|------|----------|----------|--------|-------------|----------|-------------|---------|
| 14:32:01 | Critical | Cleartext Credentials | 10.0.0.5 | 192.168.1.100:21 | FTP | FTP credentials detected | [Details] |

### Credential Details Flyout

Triggered by [Details] button:

```
┌─────────────────────────────────┐
│ Credential Details              │
├─────────────────────────────────┤
│ Protocol:  FTP                  │
│ Username:  admin                │
│ Password:  ●●●●●●●● [Show] [Copy]│
│ Target:    192.168.1.100:21     │
│ Timestamp: 2024-01-15 14:32:01  │
│ Frame:     #45231               │
└─────────────────────────────────┘
```

Password masked by default, revealed on explicit [Show] action.

### Packet List Integration

Packets with `HasCredentials = true` display 🔑 icon in packet grid.

## File Changes

### Modified Files
- `src/PCAPAnalyzer.TShark/TSharkService.cs` - Add credential fields
- `src/PCAPAnalyzer.TShark/TSharkParserOptimized.cs` - Parse and detect
- `src/PCAPAnalyzer.Core/Models/PacketInfo.cs` - Add HasCredentials flag
- `src/PCAPAnalyzer.UI/ServiceConfiguration.cs` - Register services
- `src/PCAPAnalyzer.UI/ViewModels/ThreatsViewModel.cs` - Display credentials
- `src/PCAPAnalyzer.UI/Views/ThreatsView.axaml` - Details flyout

### New Files
- `src/PCAPAnalyzer.Core/Models/CredentialFinding.cs`
- `src/PCAPAnalyzer.Core/Models/CredentialProtocol.cs`
- `src/PCAPAnalyzer.Core/Services/Credentials/ICredentialDetectionService.cs`
- `src/PCAPAnalyzer.Core/Services/Credentials/CredentialDetectionService.cs`
- `src/PCAPAnalyzer.Core/Services/Credentials/Extractors/IProtocolCredentialExtractor.cs`
- `src/PCAPAnalyzer.Core/Services/Credentials/Extractors/*.cs` (per-protocol)

## Performance Impact

- TShark extraction: ~2-5% overhead
- Parser: ~5-10% overhead
- Total: ~10-15% acceptable for forensic value

## Security Considerations

- Credentials stored in memory during analysis session only
- Not persisted to disk unless user exports
- UI requires explicit action to reveal passwords
- Tool intended for authorized security analysis
