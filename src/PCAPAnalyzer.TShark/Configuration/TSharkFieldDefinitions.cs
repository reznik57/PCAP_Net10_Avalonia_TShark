using System;

namespace PCAPAnalyzer.TShark.Configuration;

/// <summary>
/// Centralized TShark field definitions for packet analysis.
/// Defines field layouts for streaming analysis, credential detection, and OS fingerprinting.
/// </summary>
public static class TSharkFieldDefinitions
{
    /// <summary>
    /// Core packet analysis fields (0-18).
    /// Includes frame metadata, IP addresses, ports, protocols, and TCP details.
    /// </summary>
    public static readonly string CoreFields =
        "-e frame.number -e frame.time -e frame.time_epoch -e frame.len " +
        "-e ip.src -e ip.dst -e ipv6.src -e ipv6.dst " +
        "-e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport " +
        "-e _ws.col.Protocol -e frame.protocols -e _ws.col.Info " +
        "-e tcp.flags -e tcp.seq -e tcp.ack -e tcp.window_size";

    /// <summary>
    /// Credential detection fields (19-38).
    /// Captures cleartext credentials for HTTP, FTP, SMTP, IMAP, POP3, LDAP, SNMP, Kerberos, NTLM, MySQL, PostgreSQL.
    /// </summary>
    public static readonly string CredentialFields =
        "-e http.authorization -e http.authbasic " +                    // 19-20: HTTP Basic Auth
        "-e ftp.request.command -e ftp.request.arg " +                  // 21-22: FTP USER/PASS
        "-e smtp.req.command -e smtp.req.parameter " +                  // 23-24: SMTP AUTH
        "-e imap.request " +                                            // 25: IMAP LOGIN
        "-e pop.request.command -e pop.request.parameter " +            // 26-27: POP3 USER/PASS
        "-e ldap.simple -e ldap.bindRequest.name " +                    // 28-29: LDAP Simple Bind
        "-e snmp.community " +                                          // 30: SNMP Community
        "-e kerberos.CNameString -e kerberos.realm " +                  // 31-32: Kerberos
        "-e ntlmssp.auth.username -e ntlmssp.auth.domain " +            // 33-34: NTLM
        "-e mysql.user -e mysql.passwd " +                              // 35-36: MySQL
        "-e pgsql.user -e pgsql.password";                              // 37-38: PostgreSQL

    /// <summary>
    /// OS fingerprinting fields (39-59).
    /// Captures TCP/IP stack characteristics, TLS JA3 data, DHCP options, SSH banners, HTTP server headers.
    /// </summary>
    public static readonly string OsFingerprintFields =
        "-e ip.ttl -e ip.flags.df " +                                   // 39-40: TTL, DF flag
        "-e eth.src " +                                                 // 41: MAC address
        "-e tcp.options -e tcp.options.mss_val " +                      // 42-43: TCP options, MSS
        "-e tcp.options.wscale -e tcp.options.sack_perm " +             // 44-45: Window scale, SACK
        "-e tcp.options.timestamp.tsval " +                             // 46: TCP timestamp
        "-e tcp.window_size_value " +                                   // 47: Initial window size
        "-e tls.handshake.type -e tls.handshake.version " +             // 48-49: TLS handshake info
        "-e tls.handshake.ciphersuite " +                               // 50: Cipher suites (JA3)
        "-e tls.handshake.extension.type " +                            // 51: Extensions (JA3)
        "-e tls.handshake.extensions_elliptic_curves " +                // 52: Elliptic curves (JA3)
        "-e tls.handshake.extensions_ec_point_formats " +               // 53: EC point formats (JA3)
        "-e dhcp.option.dhcp -e dhcp.option.request_list " +            // 54-55: DHCP options
        "-e dhcp.option.vendor_class_id -e dhcp.option.hostname " +     // 56-57: DHCP vendor/hostname
        "-e ssh.protocol -e http.server";                               // 58-59: SSH banner, HTTP server

    /// <summary>
    /// Builds complete TShark arguments for streaming packet analysis.
    /// Includes all field categories: core, credentials, and OS fingerprinting.
    /// </summary>
    /// <param name="pcapPath">Path to PCAP file (will be quoted)</param>
    /// <returns>Complete TShark command arguments</returns>
    public static string BuildStreamingArguments(string pcapPath)
    {
        return $"-r \"{pcapPath}\" -T fields " +
               $"{CoreFields} " +
               $"{CredentialFields} " +
               $"{OsFingerprintFields} " +
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
    /// </summary>
    public const int TotalFieldCount = 60;
}
