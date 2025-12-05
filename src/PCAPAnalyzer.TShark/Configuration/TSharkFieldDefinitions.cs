using System;

namespace PCAPAnalyzer.TShark.Configuration;

/// <summary>
/// Centralized TShark field definitions for packet analysis.
/// Optimized for Wireshark 4.6.1+ with lean, security-focused field selection.
///
/// Design principles:
/// 1. Every field MUST be parsed and used by the application
/// 2. Favor native TShark fields over manual computation (JA3, SNI)
/// 3. Remove duplicates and low-value fields
/// 4. Balance security value vs. parsing overhead
///
/// Field layout (58 fields total):
/// - Core (0-17): Frame metadata, IPs, ports, protocols, TCP details
/// - Credentials (18-37): Cleartext auth detection
/// - OS Fingerprint (38-55): TCP stack, TLS handshake, DHCP, SSH
/// - Security (56-57): Native JA3 + SNI (high value, low cost)
/// </summary>
public static class TSharkFieldDefinitions
{
    /// <summary>
    /// Core packet analysis fields (0-17).
    /// Essential frame metadata, IP addresses, ports, protocols, and TCP details.
    /// Note: frame.time removed (duplicate of frame.time_epoch).
    /// </summary>
    public static readonly string CoreFields =
        "-e frame.number -e frame.time_epoch -e frame.len " +              // 0-2: Frame number, epoch timestamp, length
        "-e ip.src -e ip.dst -e ipv6.src -e ipv6.dst " +                   // 3-6: IP addresses
        "-e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport " +   // 7-10: Ports
        "-e _ws.col.Protocol -e frame.protocols -e _ws.col.Info " +        // 11-13: Protocol info
        "-e tcp.flags -e tcp.seq -e tcp.ack -e tcp.window_size";           // 14-17: TCP details

    /// <summary>
    /// Credential detection fields (18-37).
    /// Captures cleartext credentials for HTTP, FTP, SMTP, IMAP, POP3, LDAP, SNMP, Kerberos, NTLM, MySQL, PostgreSQL.
    /// Field names updated for Wireshark 4.6.1+ compatibility.
    /// </summary>
    public static readonly string CredentialFields =
        "-e http.authorization -e http.authbasic " +                    // 18-19: HTTP Basic Auth
        "-e ftp.request.command -e ftp.request.arg " +                  // 20-21: FTP USER/PASS
        "-e smtp.req.command -e smtp.req.parameter " +                  // 22-23: SMTP AUTH
        "-e imap.request " +                                            // 24: IMAP LOGIN
        "-e pop.request.command -e pop.request.parameter " +            // 25-26: POP3 USER/PASS
        "-e ldap.simple -e ldap.name " +                                // 27-28: LDAP Simple Bind
        "-e snmp.community " +                                          // 29: SNMP Community
        "-e kerberos.CNameString -e kerberos.realm " +                  // 30-31: Kerberos
        "-e ntlmssp.auth.username -e ntlmssp.auth.domain " +            // 32-33: NTLM
        "-e mysql.user -e mysql.passwd " +                              // 34-35: MySQL
        "-e pgsql.parameter_name -e pgsql.password";                    // 36-37: PostgreSQL

    /// <summary>
    /// OS fingerprinting fields (38-54).
    /// Essential TCP/IP stack characteristics for host identification.
    /// Removed low-value fields: tcp.options (raw hex), tcp.options.sack_perm, tcp.options.timestamp.tsval.
    /// Field names updated for Wireshark 4.6.1+ compatibility.
    /// </summary>
    public static readonly string OsFingerprintFields =
        "-e ip.ttl -e ip.flags.df " +                                   // 38-39: TTL, DF flag
        "-e eth.src " +                                                 // 40: MAC address
        "-e tcp.options.mss_val -e tcp.options.wscale " +               // 41-42: MSS, Window scale (key fingerprint values)
        "-e tcp.window_size_value " +                                   // 43: Initial window size
        "-e tls.handshake.type -e tls.handshake.version " +             // 44-45: TLS handshake info
        "-e tls.handshake.ciphersuite " +                               // 46: Cipher suites
        "-e tls.handshake.extension.type " +                            // 47: Extensions
        "-e tls.handshake.extensions_supported_groups " +               // 48: Supported groups (was elliptic_curves)
        "-e tls.handshake.extensions_ec_point_formats " +               // 49: EC point formats
        "-e dhcp.option.dhcp -e dhcp.option.request_list_item " +       // 50-51: DHCP message type, options
        "-e dhcp.option.vendor_class_id -e dhcp.option.hostname " +     // 52-53: DHCP vendor/hostname
        "-e ssh.protocol -e http.server";                               // 54-55: SSH banner, HTTP server

    /// <summary>
    /// Security analysis fields (56-57).
    /// High-value native TShark fields that eliminate manual computation.
    /// JA3 hash: Identifies client/malware by TLS fingerprint.
    /// SNI: Target domain even for encrypted traffic.
    /// </summary>
    public static readonly string SecurityFields =
        "-e tls.handshake.ja3 " +                                       // 56: Native JA3 hash (replaces manual computation)
        "-e tls.handshake.extensions_server_name";                      // 57: SNI - target domain for encrypted traffic

    /// <summary>
    /// Builds complete TShark arguments for streaming packet analysis.
    /// Includes all field categories: core, credentials, OS fingerprinting, and security.
    /// </summary>
    /// <param name="pcapPath">Path to PCAP file (will be quoted)</param>
    /// <returns>Complete TShark command arguments</returns>
    public static string BuildStreamingArguments(string pcapPath)
    {
        return $"-r \"{pcapPath}\" -T fields " +
               $"{CoreFields} " +
               $"{CredentialFields} " +
               $"{OsFingerprintFields} " +
               $"{SecurityFields} " +
               "-E occurrence=f";
    }

    /// <summary>
    /// Builds TShark arguments for fast packet counting.
    /// Only extracts frame.number for minimal processing overhead.
    /// </summary>
    /// <param name="pcapPath">Path to PCAP file (will be quoted)</param>
    /// <returns>TShark command arguments for counting</returns>
    public static string BuildCountArguments(string pcapPath)
    {
        return $"-r \"{pcapPath}\" -T fields -e frame.number";
    }

    /// <summary>
    /// Builds TShark arguments for extracting first packet timestamp.
    /// Used for capture time range detection.
    /// </summary>
    /// <param name="pcapPath">Path to PCAP file (will be quoted)</param>
    /// <returns>TShark command arguments for first timestamp</returns>
    public static string BuildFirstTimestampArguments(string pcapPath)
    {
        return $"-r \"{pcapPath}\" -T fields -e frame.time_epoch -c 1";
    }

    /// <summary>
    /// Builds TShark arguments for extracting all packet timestamps.
    /// Used for finding last packet timestamp (expensive for large files).
    /// </summary>
    /// <param name="pcapPath">Path to PCAP file (will be quoted)</param>
    /// <returns>TShark command arguments for all timestamps</returns>
    public static string BuildAllTimestampsArguments(string pcapPath)
    {
        return $"-r \"{pcapPath}\" -T fields -e frame.time_epoch";
    }

    /// <summary>
    /// Total number of fields in streaming output.
    /// Must match MAX_TSHARK_FIELDS in TSharkParserOptimized.
    /// Core (18) + Credentials (20) + OS Fingerprint (18) + Security (2) = 58 fields
    /// </summary>
    public const int TotalFieldCount = 58;
}
