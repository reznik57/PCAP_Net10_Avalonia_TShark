using System;

namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// Represents a detected credential in network traffic.
/// All cleartext credentials are considered Critical severity.
/// </summary>
public record CredentialFinding
{
    /// <summary>
    /// Frame number of the packet containing credentials.
    /// </summary>
    public required uint FrameNumber { get; init; }

    /// <summary>
    /// Timestamp when the credential was transmitted.
    /// </summary>
    public required DateTime Timestamp { get; init; }

    /// <summary>
    /// Source IP address (sender of credentials).
    /// </summary>
    public required string SourceIP { get; init; }

    /// <summary>
    /// Destination IP address (recipient of credentials).
    /// </summary>
    public required string DestinationIP { get; init; }

    /// <summary>
    /// Destination port (service receiving credentials).
    /// </summary>
    public required ushort DestinationPort { get; init; }

    /// <summary>
    /// Protocol used to transmit the credential.
    /// </summary>
    public required CredentialProtocol Protocol { get; init; }

    /// <summary>
    /// Extracted username (may be null for some protocols).
    /// </summary>
    public string? Username { get; init; }

    /// <summary>
    /// Extracted password or credential value.
    /// For security, display masked in UI unless explicitly revealed.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Domain for NTLM/Kerberos authentication.
    /// </summary>
    public string? Domain { get; init; }

    /// <summary>
    /// Additional context (realm, community string, etc.).
    /// </summary>
    public string? AdditionalContext { get; init; }

    /// <summary>
    /// Gets a display-friendly protocol name.
    /// </summary>
    public string ProtocolDisplayName => Protocol switch
    {
        CredentialProtocol.HttpBasic => "HTTP Basic Auth",
        CredentialProtocol.HttpDigest => "HTTP Digest Auth",
        CredentialProtocol.Ftp => "FTP",
        CredentialProtocol.Telnet => "Telnet",
        CredentialProtocol.Pop3 => "POP3",
        CredentialProtocol.Imap => "IMAP",
        CredentialProtocol.Smtp => "SMTP",
        CredentialProtocol.Ldap => "LDAP",
        CredentialProtocol.Snmp => "SNMP",
        CredentialProtocol.Kerberos => "Kerberos",
        CredentialProtocol.Ntlm => "NTLM",
        CredentialProtocol.MySql => "MySQL",
        CredentialProtocol.PostgreSql => "PostgreSQL",
        _ => Protocol.ToString()
    };

    /// <summary>
    /// Gets a masked password for safe display.
    /// </summary>
    public string MaskedPassword => string.IsNullOrEmpty(Password)
        ? "[empty]"
        : new string('*', Math.Min(Password.Length, 8));

    /// <summary>
    /// Gets a description suitable for threat display.
    /// </summary>
    public string ThreatDescription => string.IsNullOrEmpty(Username)
        ? $"{ProtocolDisplayName} credentials detected"
        : $"{ProtocolDisplayName} credentials for user '{Username}'";

    /// <summary>
    /// Converts this finding to a ThreatInfo for display in the threats tab.
    /// </summary>
    public ThreatInfo ToThreatInfo() => new()
    {
        Type = "Cleartext Credentials",
        Severity = ThreatSeverity.Critical,
        Description = ThreatDescription,
        SourceIP = SourceIP,
        DestinationIP = DestinationIP,
        Timestamp = Timestamp,
        PacketNumbers = new System.Collections.Generic.List<int> { (int)FrameNumber },
        Confidence = 1.0,
        MitigationSteps = new System.Collections.Generic.List<string>
        {
            "Use encrypted protocols (HTTPS, SFTP, LDAPS, etc.)",
            "Rotate compromised credentials immediately",
            "Review network traffic for additional exposure",
            "Implement network segmentation to limit credential exposure"
        },
        AdditionalData = new System.Collections.Generic.Dictionary<string, object>
        {
            ["CredentialProtocol"] = Protocol.ToString(),
            ["Username"] = Username ?? string.Empty,
            ["HasPassword"] = !string.IsNullOrEmpty(Password),
            ["Domain"] = Domain ?? string.Empty,
            ["DestinationPort"] = DestinationPort
        }
    };
}

/// <summary>
/// Protocol types that can expose credentials in cleartext.
/// </summary>
public enum CredentialProtocol
{
    /// <summary>HTTP Basic Authentication (base64-encoded, easily decoded)</summary>
    HttpBasic,

    /// <summary>HTTP Digest Authentication (hashed, but crackable)</summary>
    HttpDigest,

    /// <summary>FTP USER/PASS commands (cleartext)</summary>
    Ftp,

    /// <summary>Telnet login (cleartext)</summary>
    Telnet,

    /// <summary>POP3 USER/PASS commands (cleartext)</summary>
    Pop3,

    /// <summary>IMAP LOGIN command (cleartext)</summary>
    Imap,

    /// <summary>SMTP AUTH command (base64 or cleartext)</summary>
    Smtp,

    /// <summary>LDAP Simple Bind (cleartext password)</summary>
    Ldap,

    /// <summary>SNMP Community String (effectively a password)</summary>
    Snmp,

    /// <summary>Kerberos (tickets can be cracked offline)</summary>
    Kerberos,

    /// <summary>NTLM authentication (hashes can be cracked/relayed)</summary>
    Ntlm,

    /// <summary>MySQL authentication</summary>
    MySql,

    /// <summary>PostgreSQL authentication</summary>
    PostgreSql
}
