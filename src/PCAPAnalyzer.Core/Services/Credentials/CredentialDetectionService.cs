using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Credentials;

/// <summary>
/// Detects credentials in network traffic from TShark field data.
/// Thread-safe implementation using ConcurrentBag for findings.
/// </summary>
public sealed class CredentialDetectionService : ICredentialDetectionService
{
    private readonly ConcurrentBag<CredentialFinding> _findings = new();

    public int Count => _findings.Count;

    public CredentialFinding? ProcessPacket(
        CredentialRawFields fields,
        uint frameNumber,
        DateTime timestamp,
        string sourceIP,
        string destIP,
        ushort destPort)
    {
        // Fast path: skip if no credential data
        if (!fields.HasAnyCredentialData)
            return null;

        // Try each protocol extractor in order of likelihood
        var finding = TryExtractHttpCredentials(fields, frameNumber, timestamp, sourceIP, destIP, destPort)
                   ?? TryExtractFtpCredentials(fields, frameNumber, timestamp, sourceIP, destIP, destPort)
                   ?? TryExtractSmtpCredentials(fields, frameNumber, timestamp, sourceIP, destIP, destPort)
                   ?? TryExtractImapCredentials(fields, frameNumber, timestamp, sourceIP, destIP, destPort)
                   ?? TryExtractPop3Credentials(fields, frameNumber, timestamp, sourceIP, destIP, destPort)
                   ?? TryExtractLdapCredentials(fields, frameNumber, timestamp, sourceIP, destIP, destPort)
                   ?? TryExtractSnmpCredentials(fields, frameNumber, timestamp, sourceIP, destIP, destPort)
                   ?? TryExtractKerberosCredentials(fields, frameNumber, timestamp, sourceIP, destIP, destPort)
                   ?? TryExtractNtlmCredentials(fields, frameNumber, timestamp, sourceIP, destIP, destPort)
                   ?? TryExtractMySqlCredentials(fields, frameNumber, timestamp, sourceIP, destIP, destPort)
                   ?? TryExtractPostgreSqlCredentials(fields, frameNumber, timestamp, sourceIP, destIP, destPort);

        if (finding != null)
        {
            _findings.Add(finding);
        }

        return finding;
    }

    public IReadOnlyList<CredentialFinding> GetFindings() =>
        _findings.OrderBy(f => f.Timestamp).ToList();

    public IReadOnlyList<ThreatInfo> GetFindingsAsThreats() =>
        _findings.Select(f => f.ToThreatInfo()).OrderBy(t => t.Timestamp).ToList();

    public void Clear() => _findings.Clear();

    #region Protocol Extractors

    private static CredentialFinding? TryExtractHttpCredentials(
        CredentialRawFields fields,
        uint frameNumber, DateTime timestamp, string sourceIP, string destIP, ushort destPort)
    {
        // Check http.authorization first (raw header)
        if (!string.IsNullOrEmpty(fields.HttpAuthorization))
        {
            var authHeader = fields.HttpAuthorization;

            if (authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                var (username, password) = DecodeBasicAuth(authHeader[6..]);
                return new CredentialFinding
                {
                    FrameNumber = frameNumber,
                    Timestamp = timestamp,
                    SourceIP = sourceIP,
                    DestinationIP = destIP,
                    DestinationPort = destPort,
                    Protocol = CredentialProtocol.HttpBasic,
                    Username = username,
                    Password = password
                };
            }

            if (authHeader.StartsWith("Digest ", StringComparison.OrdinalIgnoreCase))
            {
                var username = ExtractDigestUsername(authHeader);
                return new CredentialFinding
                {
                    FrameNumber = frameNumber,
                    Timestamp = timestamp,
                    SourceIP = sourceIP,
                    DestinationIP = destIP,
                    DestinationPort = destPort,
                    Protocol = CredentialProtocol.HttpDigest,
                    Username = username,
                    AdditionalContext = "Digest auth (hash, crackable)"
                };
            }
        }

        // Check http.authbasic (pre-decoded by Wireshark)
        if (!string.IsNullOrEmpty(fields.HttpAuthBasic))
        {
            var decoded = fields.HttpAuthBasic;
            var colonIdx = decoded.IndexOf(':', StringComparison.Ordinal);
            var username = colonIdx > 0 ? decoded[..colonIdx] : decoded;
            var password = colonIdx > 0 && colonIdx < decoded.Length - 1 ? decoded[(colonIdx + 1)..] : null;

            return new CredentialFinding
            {
                FrameNumber = frameNumber,
                Timestamp = timestamp,
                SourceIP = sourceIP,
                DestinationIP = destIP,
                DestinationPort = destPort,
                Protocol = CredentialProtocol.HttpBasic,
                Username = username,
                Password = password
            };
        }

        return null;
    }

    private static CredentialFinding? TryExtractFtpCredentials(
        CredentialRawFields fields,
        uint frameNumber, DateTime timestamp, string sourceIP, string destIP, ushort destPort)
    {
        if (string.IsNullOrEmpty(fields.FtpCommand))
            return null;

        var command = fields.FtpCommand.ToUpperInvariant();
        var arg = fields.FtpArg;

        // FTP uses separate USER and PASS commands
        // We capture PASS commands which contain the actual password
        if (command == "PASS" && !string.IsNullOrEmpty(arg))
        {
            return new CredentialFinding
            {
                FrameNumber = frameNumber,
                Timestamp = timestamp,
                SourceIP = sourceIP,
                DestinationIP = destIP,
                DestinationPort = destPort,
                Protocol = CredentialProtocol.Ftp,
                Password = arg,
                AdditionalContext = "FTP PASS command"
            };
        }

        if (command == "USER" && !string.IsNullOrEmpty(arg))
        {
            return new CredentialFinding
            {
                FrameNumber = frameNumber,
                Timestamp = timestamp,
                SourceIP = sourceIP,
                DestinationIP = destIP,
                DestinationPort = destPort,
                Protocol = CredentialProtocol.Ftp,
                Username = arg,
                AdditionalContext = "FTP USER command"
            };
        }

        return null;
    }

    private static CredentialFinding? TryExtractSmtpCredentials(
        CredentialRawFields fields,
        uint frameNumber, DateTime timestamp, string sourceIP, string destIP, ushort destPort)
    {
        if (string.IsNullOrEmpty(fields.SmtpCommand))
            return null;

        var command = fields.SmtpCommand.ToUpperInvariant();

        if (command == "AUTH" && !string.IsNullOrEmpty(fields.SmtpParameter))
        {
            var param = fields.SmtpParameter;

            // AUTH PLAIN base64
            if (param.StartsWith("PLAIN ", StringComparison.OrdinalIgnoreCase))
            {
                var (username, password) = DecodePlainAuth(param[6..]);
                return new CredentialFinding
                {
                    FrameNumber = frameNumber,
                    Timestamp = timestamp,
                    SourceIP = sourceIP,
                    DestinationIP = destIP,
                    DestinationPort = destPort,
                    Protocol = CredentialProtocol.Smtp,
                    Username = username,
                    Password = password
                };
            }

            // AUTH LOGIN (base64 username, then base64 password in subsequent packets)
            if (param.StartsWith("LOGIN", StringComparison.OrdinalIgnoreCase))
            {
                return new CredentialFinding
                {
                    FrameNumber = frameNumber,
                    Timestamp = timestamp,
                    SourceIP = sourceIP,
                    DestinationIP = destIP,
                    DestinationPort = destPort,
                    Protocol = CredentialProtocol.Smtp,
                    AdditionalContext = "SMTP AUTH LOGIN initiated"
                };
            }
        }

        return null;
    }

    private static CredentialFinding? TryExtractImapCredentials(
        CredentialRawFields fields,
        uint frameNumber, DateTime timestamp, string sourceIP, string destIP, ushort destPort)
    {
        if (string.IsNullOrEmpty(fields.ImapRequest))
            return null;

        var request = fields.ImapRequest;

        // IMAP LOGIN command: tag LOGIN username password
        if (request.Contains(" LOGIN ", StringComparison.OrdinalIgnoreCase))
        {
            var parts = request.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var loginIdx = Array.FindIndex(parts, p => p.Equals("LOGIN", StringComparison.OrdinalIgnoreCase));

            if (loginIdx >= 0 && loginIdx + 2 < parts.Length)
            {
                var username = parts[loginIdx + 1].Trim('"');
                var password = parts[loginIdx + 2].Trim('"');

                return new CredentialFinding
                {
                    FrameNumber = frameNumber,
                    Timestamp = timestamp,
                    SourceIP = sourceIP,
                    DestinationIP = destIP,
                    DestinationPort = destPort,
                    Protocol = CredentialProtocol.Imap,
                    Username = username,
                    Password = password
                };
            }
        }

        return null;
    }

    private static CredentialFinding? TryExtractPop3Credentials(
        CredentialRawFields fields,
        uint frameNumber, DateTime timestamp, string sourceIP, string destIP, ushort destPort)
    {
        if (string.IsNullOrEmpty(fields.Pop3Command))
            return null;

        var command = fields.Pop3Command.ToUpperInvariant();
        var param = fields.Pop3Parameter;

        if (command == "PASS" && !string.IsNullOrEmpty(param))
        {
            return new CredentialFinding
            {
                FrameNumber = frameNumber,
                Timestamp = timestamp,
                SourceIP = sourceIP,
                DestinationIP = destIP,
                DestinationPort = destPort,
                Protocol = CredentialProtocol.Pop3,
                Password = param
            };
        }

        if (command == "USER" && !string.IsNullOrEmpty(param))
        {
            return new CredentialFinding
            {
                FrameNumber = frameNumber,
                Timestamp = timestamp,
                SourceIP = sourceIP,
                DestinationIP = destIP,
                DestinationPort = destPort,
                Protocol = CredentialProtocol.Pop3,
                Username = param
            };
        }

        return null;
    }

    private static CredentialFinding? TryExtractLdapCredentials(
        CredentialRawFields fields,
        uint frameNumber, DateTime timestamp, string sourceIP, string destIP, ushort destPort)
    {
        // LDAP Simple Bind - password sent in cleartext
        if (!string.IsNullOrEmpty(fields.LdapSimple))
        {
            var bindName = fields.LdapBindName;
            var password = fields.LdapSimple;

            return new CredentialFinding
            {
                FrameNumber = frameNumber,
                Timestamp = timestamp,
                SourceIP = sourceIP,
                DestinationIP = destIP,
                DestinationPort = destPort,
                Protocol = CredentialProtocol.Ldap,
                Username = bindName,
                Password = password
            };
        }

        return null;
    }

    private static CredentialFinding? TryExtractSnmpCredentials(
        CredentialRawFields fields,
        uint frameNumber, DateTime timestamp, string sourceIP, string destIP, ushort destPort)
    {
        if (string.IsNullOrEmpty(fields.SnmpCommunity))
            return null;

        var community = fields.SnmpCommunity;

        // Skip common default/test community strings for noise reduction? No - user wanted all
        return new CredentialFinding
        {
            FrameNumber = frameNumber,
            Timestamp = timestamp,
            SourceIP = sourceIP,
            DestinationIP = destIP,
            DestinationPort = destPort,
            Protocol = CredentialProtocol.Snmp,
            Password = community,
            AdditionalContext = "SNMP Community String"
        };
    }

    private static CredentialFinding? TryExtractKerberosCredentials(
        CredentialRawFields fields,
        uint frameNumber, DateTime timestamp, string sourceIP, string destIP, ushort destPort)
    {
        if (string.IsNullOrEmpty(fields.KerberosCName))
            return null;

        var cname = fields.KerberosCName;
        var realm = fields.KerberosRealm;

        return new CredentialFinding
        {
            FrameNumber = frameNumber,
            Timestamp = timestamp,
            SourceIP = sourceIP,
            DestinationIP = destIP,
            DestinationPort = destPort,
            Protocol = CredentialProtocol.Kerberos,
            Username = cname,
            Domain = realm,
            AdditionalContext = "Kerberos ticket (can be cracked offline)"
        };
    }

    private static CredentialFinding? TryExtractNtlmCredentials(
        CredentialRawFields fields,
        uint frameNumber, DateTime timestamp, string sourceIP, string destIP, ushort destPort)
    {
        if (string.IsNullOrEmpty(fields.NtlmUsername))
            return null;

        var username = fields.NtlmUsername;
        var domain = fields.NtlmDomain;

        return new CredentialFinding
        {
            FrameNumber = frameNumber,
            Timestamp = timestamp,
            SourceIP = sourceIP,
            DestinationIP = destIP,
            DestinationPort = destPort,
            Protocol = CredentialProtocol.Ntlm,
            Username = username,
            Domain = domain,
            AdditionalContext = "NTLM auth (hash can be cracked/relayed)"
        };
    }

    private static CredentialFinding? TryExtractMySqlCredentials(
        CredentialRawFields fields,
        uint frameNumber, DateTime timestamp, string sourceIP, string destIP, ushort destPort)
    {
        if (string.IsNullOrEmpty(fields.MySqlUser) && string.IsNullOrEmpty(fields.MySqlPassword))
            return null;

        return new CredentialFinding
        {
            FrameNumber = frameNumber,
            Timestamp = timestamp,
            SourceIP = sourceIP,
            DestinationIP = destIP,
            DestinationPort = destPort,
            Protocol = CredentialProtocol.MySql,
            Username = fields.MySqlUser,
            Password = fields.MySqlPassword
        };
    }

    private static CredentialFinding? TryExtractPostgreSqlCredentials(
        CredentialRawFields fields,
        uint frameNumber, DateTime timestamp, string sourceIP, string destIP, ushort destPort)
    {
        if (string.IsNullOrEmpty(fields.PgSqlUser) && string.IsNullOrEmpty(fields.PgSqlPassword))
            return null;

        return new CredentialFinding
        {
            FrameNumber = frameNumber,
            Timestamp = timestamp,
            SourceIP = sourceIP,
            DestinationIP = destIP,
            DestinationPort = destPort,
            Protocol = CredentialProtocol.PostgreSql,
            Username = fields.PgSqlUser,
            Password = fields.PgSqlPassword
        };
    }

    #endregion

    #region Decoding Helpers

    /// <summary>
    /// Decodes HTTP Basic Auth base64 credentials.
    /// Format: base64(username:password)
    /// </summary>
    private static (string? username, string? password) DecodeBasicAuth(string base64)
    {
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(base64.Trim()));
            var colonIdx = decoded.IndexOf(':', StringComparison.Ordinal);

            if (colonIdx > 0)
            {
                return (decoded[..colonIdx], decoded[(colonIdx + 1)..]);
            }

            return (decoded, null);
        }
        catch
        {
            return (null, null);
        }
    }

    /// <summary>
    /// Decodes SMTP AUTH PLAIN credentials.
    /// Format: base64(\0username\0password) or base64(authzid\0username\0password)
    /// </summary>
    private static (string? username, string? password) DecodePlainAuth(string base64)
    {
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(base64.Trim()));
            var parts = decoded.Split('\0', StringSplitOptions.None);

            // Format is: authzid\0authcid\0password (authzid often empty)
            if (parts.Length >= 3)
            {
                return (parts[1], parts[2]);
            }

            if (parts.Length == 2)
            {
                return (parts[0], parts[1]);
            }

            return (null, null);
        }
        catch
        {
            return (null, null);
        }
    }

    /// <summary>
    /// Extracts username from HTTP Digest auth header.
    /// </summary>
    private static string? ExtractDigestUsername(string authHeader)
    {
        const string usernameKey = "username=\"";
        var startIdx = authHeader.IndexOf(usernameKey, StringComparison.OrdinalIgnoreCase);

        if (startIdx < 0)
            return null;

        startIdx += usernameKey.Length;
        var endIdx = authHeader.IndexOf('"', startIdx);

        if (endIdx < 0)
            return null;

        return authHeader[startIdx..endIdx];
    }

    #endregion
}
