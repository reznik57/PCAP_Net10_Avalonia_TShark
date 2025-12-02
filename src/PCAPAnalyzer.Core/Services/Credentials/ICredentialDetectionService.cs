using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Credentials;

/// <summary>
/// Service for detecting credentials in network traffic.
/// Thread-safe for concurrent packet processing.
/// </summary>
public interface ICredentialDetectionService
{
    /// <summary>
    /// Processes credential-related fields from a parsed TShark line.
    /// Called per-packet during parsing. Must be fast and thread-safe.
    /// </summary>
    /// <param name="fields">Credential field strings extracted from TShark output</param>
    /// <param name="frameNumber">Packet frame number</param>
    /// <param name="timestamp">Packet timestamp</param>
    /// <param name="sourceIP">Source IP address</param>
    /// <param name="destIP">Destination IP address</param>
    /// <param name="destPort">Destination port</param>
    /// <returns>CredentialFinding if credentials detected, null otherwise</returns>
    CredentialFinding? ProcessPacket(
        CredentialRawFields fields,
        uint frameNumber,
        DateTime timestamp,
        string sourceIP,
        string destIP,
        ushort destPort);

    /// <summary>
    /// Returns all credential findings collected during analysis.
    /// </summary>
    IReadOnlyList<CredentialFinding> GetFindings();

    /// <summary>
    /// Returns findings as ThreatInfo for display in Threats tab.
    /// </summary>
    IReadOnlyList<ThreatInfo> GetFindingsAsThreats();

    /// <summary>
    /// Clears all collected findings. Called when starting new analysis.
    /// </summary>
    void Clear();

    /// <summary>
    /// Gets the count of detected credentials.
    /// </summary>
    int Count { get; }
}

/// <summary>
/// Contains raw credential field strings extracted from TShark output.
/// Used for credential detection processing.
/// </summary>
public record struct CredentialRawFields
{
    // HTTP (fields 19-20)
    public string? HttpAuthorization { get; init; }
    public string? HttpAuthBasic { get; init; }

    // FTP (fields 21-22)
    public string? FtpCommand { get; init; }
    public string? FtpArg { get; init; }

    // SMTP (fields 23-24)
    public string? SmtpCommand { get; init; }
    public string? SmtpParameter { get; init; }

    // IMAP (field 25)
    public string? ImapRequest { get; init; }

    // POP3 (fields 26-27)
    public string? Pop3Command { get; init; }
    public string? Pop3Parameter { get; init; }

    // LDAP (fields 28-29)
    public string? LdapSimple { get; init; }
    public string? LdapBindName { get; init; }

    // SNMP (field 30)
    public string? SnmpCommunity { get; init; }

    // Kerberos (fields 31-32)
    public string? KerberosCName { get; init; }
    public string? KerberosRealm { get; init; }

    // NTLM (fields 33-34)
    public string? NtlmUsername { get; init; }
    public string? NtlmDomain { get; init; }

    // MySQL (fields 35-36)
    public string? MySqlUser { get; init; }
    public string? MySqlPassword { get; init; }

    // PostgreSQL (fields 37-38)
    public string? PgSqlUser { get; init; }
    public string? PgSqlPassword { get; init; }

    /// <summary>
    /// Returns true if any credential field has data.
    /// </summary>
    public readonly bool HasAnyCredentialData =>
        !string.IsNullOrEmpty(HttpAuthorization) || !string.IsNullOrEmpty(HttpAuthBasic) ||
        !string.IsNullOrEmpty(FtpCommand) ||
        !string.IsNullOrEmpty(SmtpCommand) ||
        !string.IsNullOrEmpty(ImapRequest) ||
        !string.IsNullOrEmpty(Pop3Command) ||
        !string.IsNullOrEmpty(LdapSimple) || !string.IsNullOrEmpty(LdapBindName) ||
        !string.IsNullOrEmpty(SnmpCommunity) ||
        !string.IsNullOrEmpty(KerberosCName) ||
        !string.IsNullOrEmpty(NtlmUsername) ||
        !string.IsNullOrEmpty(MySqlUser) || !string.IsNullOrEmpty(MySqlPassword) ||
        !string.IsNullOrEmpty(PgSqlUser) || !string.IsNullOrEmpty(PgSqlPassword);
}
