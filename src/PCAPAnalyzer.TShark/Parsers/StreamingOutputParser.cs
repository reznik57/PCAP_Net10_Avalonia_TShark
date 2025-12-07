using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Globalization;
using System.Runtime.CompilerServices;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.TShark.Parsers;

/// <summary>
/// High-performance streaming parser for TShark tab-delimited output.
/// Optimized for memory efficiency and throughput.
/// Uses string interning for IPs and protocol pooling to reduce allocations.
/// </summary>
public sealed class StreamingOutputParser
{
    private const int ExpectedFieldCount = 15;
    private int _parseFailureCount;
    private string? _firstParseFailure;

    // String interning for IP addresses - most PCAPs have <1000 unique IPs but millions of packets
    // This reduces millions of string allocations to thousands
    private readonly ConcurrentDictionary<string, string> _ipCache = new(StringComparer.Ordinal);
    private const int MaxCachedIPs = 10_000; // Limit cache size to prevent unbounded growth

    // Protocol string pool - only ~50 unique protocols, use frozen dictionary for O(1) lookup
    private static readonly FrozenDictionary<string, string> ProtocolPool = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["TCP"] = "TCP",
        ["UDP"] = "UDP",
        ["ICMP"] = "ICMP",
        ["ICMPv6"] = "ICMPv6",
        ["HTTP"] = "HTTP",
        ["HTTP/2"] = "HTTP/2",
        ["HTTP/3"] = "HTTP/3",
        ["HTTPS"] = "HTTPS",
        ["TLS"] = "TLS",
        ["TLSv1"] = "TLSv1",
        ["TLSv1.1"] = "TLSv1.1",
        ["TLSv1.2"] = "TLSv1.2",
        ["TLSv1.3"] = "TLSv1.3",
        ["SSL"] = "SSL",
        ["SSLv3"] = "SSLv3",
        ["DNS"] = "DNS",
        ["DHCP"] = "DHCP",
        ["DHCPv6"] = "DHCPv6",
        ["ARP"] = "ARP",
        ["SSH"] = "SSH",
        ["FTP"] = "FTP",
        ["SFTP"] = "SFTP",
        ["SMTP"] = "SMTP",
        ["POP3"] = "POP3",
        ["IMAP"] = "IMAP",
        ["SNMP"] = "SNMP",
        ["SNMPv1"] = "SNMPv1",
        ["SNMPv2c"] = "SNMPv2c",
        ["SNMPv3"] = "SNMPv3",
        ["RTP"] = "RTP",
        ["RTCP"] = "RTCP",
        ["SIP"] = "SIP",
        ["QUIC"] = "QUIC",
        ["SMB"] = "SMB",
        ["SMB2"] = "SMB2",
        ["SMB3"] = "SMB3",
        ["NTP"] = "NTP",
        ["LDAP"] = "LDAP",
        ["LDAPS"] = "LDAPS",
        ["Kerberos"] = "Kerberos",
        ["RADIUS"] = "RADIUS",
        ["MQTT"] = "MQTT",
        ["AMQP"] = "AMQP",
        ["Redis"] = "Redis",
        ["MySQL"] = "MySQL",
        ["PostgreSQL"] = "PostgreSQL",
        ["MongoDB"] = "MongoDB",
        ["Modbus"] = "Modbus",
        ["DNP3"] = "DNP3",
        ["COAP"] = "CoAP",
        ["STUN"] = "STUN",
        ["TURN"] = "TURN",
        ["WebSocket"] = "WebSocket",
        ["gRPC"] = "gRPC",
    }.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

    // Common IP addresses that appear frequently
    private static readonly FrozenDictionary<string, string> CommonIPs = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["0.0.0.0"] = "0.0.0.0",
        ["127.0.0.1"] = "127.0.0.1",
        ["255.255.255.255"] = "255.255.255.255",
        ["::"] = "::",
        ["::1"] = "::1",
    }.ToFrozenDictionary(StringComparer.Ordinal);

    public int ParseFailureCount => _parseFailureCount;
    public string? FirstParseFailure => _firstParseFailure;
    public int CachedIPCount => _ipCache.Count;

    /// <summary>
    /// Parses a single line of TShark tab-delimited output into a PacketInfo struct.
    /// Returns null if the line cannot be parsed.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public PacketInfo? ParseLine(ReadOnlySpan<char> line)
    {
        if (line.IsEmpty || line.IsWhiteSpace())
            return null;

        // Use span-based splitting for zero-allocation parsing
        Span<Range> fieldRanges = stackalloc Range[ExpectedFieldCount];
        var fieldCount = line.Split(fieldRanges, '\t', StringSplitOptions.None);

        if (fieldCount < ExpectedFieldCount)
        {
            RecordParseFailure(line);
            return null;
        }

        // Parse frame number (field 0)
        var frameNumberSpan = line[fieldRanges[0]];
        if (!uint.TryParse(frameNumberSpan, NumberStyles.Integer, CultureInfo.InvariantCulture, out var frameNumber))
        {
            RecordParseFailure(line);
            return null;
        }

        // Parse timestamp (prefer epoch - field 2)
        var timestamp = ParseTimestamp(line, fieldRanges);
        if (!timestamp.HasValue)
        {
            RecordParseFailure(line);
            return null;
        }

        // Parse length (field 3)
        var lengthSpan = line[fieldRanges[3]];
        if (!ushort.TryParse(lengthSpan, NumberStyles.Integer, CultureInfo.InvariantCulture, out var length))
        {
            RecordParseFailure(line);
            return null;
        }

        // Parse IPs - Check IPv4 (fields 4,5) first, then IPv6 (fields 6,7)
        // Use interning to reduce string allocations
        var sourceIPSpan = ExtractIP(line, fieldRanges[4], fieldRanges[6]);
        var destIPSpan = ExtractIP(line, fieldRanges[5], fieldRanges[7]);
        var sourceIP = InternIP(sourceIPSpan);
        var destIP = InternIP(destIPSpan);

        // Parse ports - TCP (fields 8,9) or UDP (fields 10,11)
        var sourcePort = ExtractPort(line, fieldRanges[8], fieldRanges[10]);
        var destPort = ExtractPort(line, fieldRanges[9], fieldRanges[11]);

        // Extract protocol information (fields 12, 13, 14)
        var protocolStr = line[fieldRanges[12]];
        var protocolStack = line[fieldRanges[13]];
        var info = line[fieldRanges[14]].ToString(); // Allocate for Info string (required - unique per packet)

        // Extract L4 protocol (TCP/UDP) from protocol stack
        var l4Protocol = ExtractL4Protocol(protocolStack);

        // Extract L7 protocol (application layer) - uses protocol pooling
        var l7Protocol = ExtractL7Protocol(protocolStr, protocolStack, info);

        return new PacketInfo
        {
            FrameNumber = frameNumber,
            Timestamp = timestamp.Value,
            Length = length,
            SourceIP = sourceIP,
            DestinationIP = destIP,
            SourcePort = sourcePort,
            DestinationPort = destPort,
            Protocol = l4Protocol,
            L7Protocol = l7Protocol,
            Info = info
        };
    }

    /// <summary>
    /// Interns an IP address string to reduce allocations.
    /// Uses a static pool for common IPs and a bounded cache for others.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private string InternIP(ReadOnlySpan<char> ipSpan)
    {
        // Fast path: check common IPs first (static, no allocation needed for lookup)
        Span<char> buffer = stackalloc char[64]; // Max IPv6 length
        if (ipSpan.Length <= buffer.Length)
        {
            ipSpan.CopyTo(buffer);
            var key = buffer[..ipSpan.Length].ToString();

            if (CommonIPs.TryGetValue(key, out var commonIP))
                return commonIP;

            // Check cache
            if (_ipCache.TryGetValue(key, out var cachedIP))
                return cachedIP;

            // Add to cache if not full
            if (_ipCache.Count < MaxCachedIPs)
            {
                _ipCache.TryAdd(key, key);
                return key;
            }

            // Cache full, return new string (rare case)
            return key;
        }

        // Fallback for very long strings (shouldn't happen with valid IPs)
        return ipSpan.ToString();
    }

    /// <summary>
    /// Parses timestamp from either epoch or formatted time fields
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static DateTime? ParseTimestamp(ReadOnlySpan<char> line, Span<Range> fieldRanges)
    {
        // Try epoch format first (field 2) - most reliable
        var epochSpan = line[fieldRanges[2]];
        if (!epochSpan.IsEmpty &&
            double.TryParse(epochSpan, NumberStyles.Float, CultureInfo.InvariantCulture, out var epochSeconds))
        {
            var epochMicroseconds = (long)Math.Round(epochSeconds * 1_000_000.0, MidpointRounding.AwayFromZero);
            var epochOffset = DateTimeOffset.FromUnixTimeMilliseconds(epochMicroseconds / 1000);
            return epochOffset.AddTicks((epochMicroseconds % 1000) * 10).LocalDateTime;
        }

        // Fall back to formatted time (field 1)
        var timeSpan = line[fieldRanges[1]];
        if (!timeSpan.IsEmpty && TryParseFormattedTime(timeSpan, out var timestamp))
        {
            return timestamp;
        }

        return null;
    }

    /// <summary>
    /// Tries to parse a formatted timestamp string
    /// </summary>
    private static bool TryParseFormattedTime(ReadOnlySpan<char> input, out DateTime timestamp)
    {
        timestamp = default;

        if (input.IsEmpty || input.IsWhiteSpace())
            return false;

        const DateTimeStyles styles = DateTimeStyles.AssumeLocal | DateTimeStyles.AllowWhiteSpaces;

        // Try parsing as-is
        if (DateTime.TryParse(input, CultureInfo.CurrentCulture, styles, out timestamp))
            return true;

        if (DateTime.TryParse(input, CultureInfo.InvariantCulture, styles, out timestamp))
            return true;

        // Try removing trailing timezone info
        var lastSpace = input.LastIndexOf(' ');
        if (lastSpace > 0)
        {
            var truncated = input[..lastSpace];
            if (DateTime.TryParse(truncated, CultureInfo.CurrentCulture, styles, out timestamp))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Extracts IP address, preferring IPv4 over IPv6
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ReadOnlySpan<char> ExtractIP(ReadOnlySpan<char> line, Range ipv4Range, Range ipv6Range)
    {
        var ipv4 = line[ipv4Range];
        if (!ipv4.IsEmpty && !ipv4.IsWhiteSpace())
            return ipv4;

        var ipv6 = line[ipv6Range];
        if (!ipv6.IsEmpty && !ipv6.IsWhiteSpace())
            return ipv6;

        return "0.0.0.0";
    }

    /// <summary>
    /// Extracts port number, preferring TCP over UDP
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ushort ExtractPort(ReadOnlySpan<char> line, Range tcpRange, Range udpRange)
    {
        var tcpPort = line[tcpRange];
        if (!tcpPort.IsEmpty &&
            ushort.TryParse(tcpPort, NumberStyles.Integer, CultureInfo.InvariantCulture, out var tcpPortValue))
        {
            return tcpPortValue;
        }

        var udpPort = line[udpRange];
        if (!udpPort.IsEmpty &&
            ushort.TryParse(udpPort, NumberStyles.Integer, CultureInfo.InvariantCulture, out var udpPortValue))
        {
            return udpPortValue;
        }

        return 0;
    }

    /// <summary>
    /// Extract Layer 4 protocol (TCP/UDP/ICMP) from protocol stack
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Protocol ExtractL4Protocol(ReadOnlySpan<char> protocolStack)
    {
        if (protocolStack.IsEmpty)
            return Protocol.Unknown;

        // Scan for TCP, UDP, or ICMP in the protocol stack
        // Protocol stack format: "eth:ethertype:ip:tcp" or similar

        // Look for "tcp" (case-insensitive)
        if (ContainsProtocol(protocolStack, "tcp"))
            return Protocol.TCP;

        // Look for "udp"
        if (ContainsProtocol(protocolStack, "udp"))
            return Protocol.UDP;

        // Look for "icmp" or "icmpv6"
        if (ContainsProtocol(protocolStack, "icmp"))
            return Protocol.ICMP;

        return Protocol.Unknown;
    }

    /// <summary>
    /// Extract Layer 7 application protocol
    /// </summary>
    private static string ExtractL7Protocol(ReadOnlySpan<char> protocolStr, ReadOnlySpan<char> protocolStack, string? info)
    {
        // If Wireshark shows TCP/UDP, check if there's an application protocol
        if (protocolStr.Equals("TCP", StringComparison.OrdinalIgnoreCase) ||
            protocolStr.Equals("UDP", StringComparison.OrdinalIgnoreCase) ||
            protocolStr.Equals("ICMP", StringComparison.OrdinalIgnoreCase))
        {
            // Check protocol stack for application layer
            if (!protocolStack.IsEmpty)
            {
                var lastProto = GetLastProtocol(protocolStack);

                // If last protocol is transport layer, no app layer detected
                if (lastProto.Equals("tcp", StringComparison.OrdinalIgnoreCase) ||
                    lastProto.Equals("udp", StringComparison.OrdinalIgnoreCase) ||
                    lastProto.Equals("icmp", StringComparison.OrdinalIgnoreCase) ||
                    lastProto.Equals("data", StringComparison.OrdinalIgnoreCase))
                {
                    return string.Empty; // No L7 protocol
                }

                // Return mapped protocol name
                return MapProtocolName(lastProto, protocolStr.ToString(), info);
            }
            return string.Empty;
        }

        // Wireshark has identified an application protocol
        return EnhanceProtocolWithVersion(protocolStr.ToString(), info);
    }

    /// <summary>
    /// Gets the last protocol from a colon-separated protocol stack
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ReadOnlySpan<char> GetLastProtocol(ReadOnlySpan<char> protocolStack)
    {
        var lastColon = protocolStack.LastIndexOf(':');
        return lastColon >= 0 ? protocolStack[(lastColon + 1)..] : protocolStack;
    }

    /// <summary>
    /// Checks if protocol stack contains a specific protocol (case-insensitive)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool ContainsProtocol(ReadOnlySpan<char> protocolStack, ReadOnlySpan<char> protocol)
    {
        // Split by colon and check each segment
        int start = 0;
        while (start < protocolStack.Length)
        {
            var colonIndex = protocolStack[start..].IndexOf(':');
            var segment = colonIndex >= 0
                ? protocolStack.Slice(start, colonIndex)
                : protocolStack[start..];

            if (segment.Equals(protocol, StringComparison.OrdinalIgnoreCase))
                return true;

            if (colonIndex < 0)
                break;

            start += colonIndex + 1;
        }

        return false;
    }

    /// <summary>
    /// Map protocol names to standard display format.
    /// Uses protocol pooling to return interned strings.
    /// </summary>
    private static string MapProtocolName(ReadOnlySpan<char> protocol, string displayProtocol, string? info)
    {
        // Use span comparison for efficiency
        if (protocol.Equals("tls", StringComparison.OrdinalIgnoreCase))
            return EnhanceProtocolWithVersion(displayProtocol, info);

        if (protocol.Equals("ssl", StringComparison.OrdinalIgnoreCase))
            return GetPooledProtocol(displayProtocol);

        if (protocol.Equals("http", StringComparison.OrdinalIgnoreCase))
            return ProtocolPool["HTTP"];

        if (protocol.Equals("http2", StringComparison.OrdinalIgnoreCase))
            return ProtocolPool["HTTP/2"];

        if (protocol.Equals("http3", StringComparison.OrdinalIgnoreCase))
            return ProtocolPool["HTTP/3"];

        if (protocol.Equals("dns", StringComparison.OrdinalIgnoreCase))
            return ProtocolPool["DNS"];

        if (protocol.Equals("snmp", StringComparison.OrdinalIgnoreCase))
            return EnhanceSnmpVersion(displayProtocol, info);

        if (protocol.Equals("ssh", StringComparison.OrdinalIgnoreCase))
            return ProtocolPool["SSH"];

        if (protocol.Equals("ftp", StringComparison.OrdinalIgnoreCase))
            return ProtocolPool["FTP"];

        if (protocol.Equals("smtp", StringComparison.OrdinalIgnoreCase))
            return ProtocolPool["SMTP"];

        if (protocol.Equals("pop", StringComparison.OrdinalIgnoreCase))
            return ProtocolPool["POP3"];

        if (protocol.Equals("imap", StringComparison.OrdinalIgnoreCase))
            return ProtocolPool["IMAP"];

        return GetPooledProtocol(displayProtocol);
    }

    /// <summary>
    /// Gets a pooled protocol string if available, otherwise returns the input.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string GetPooledProtocol(string protocol)
    {
        return ProtocolPool.TryGetValue(protocol, out var pooled) ? pooled : protocol;
    }

    /// <summary>
    /// Enhance protocol with version information where available.
    /// Uses protocol pooling for common versions.
    /// </summary>
    private static string EnhanceProtocolWithVersion(string protocol, string? info)
    {
        if (string.IsNullOrWhiteSpace(info))
            return GetPooledProtocol(protocol);

        // For SNMP, extract version from info
        if (protocol.Equals("SNMP", StringComparison.OrdinalIgnoreCase))
        {
            return EnhanceSnmpVersion(protocol, info);
        }

        // For SMB, check version
        if (protocol.StartsWith("SMB", StringComparison.OrdinalIgnoreCase))
        {
            if (info.Contains("SMB2", StringComparison.OrdinalIgnoreCase))
                return ProtocolPool["SMB2"];
            if (info.Contains("SMB3", StringComparison.OrdinalIgnoreCase))
                return ProtocolPool["SMB3"];
        }

        // Return pooled version for protocols that already include version (TLSv1.2, etc.)
        return GetPooledProtocol(protocol);
    }

    /// <summary>
    /// Extract SNMP version from packet info.
    /// Returns pooled strings to reduce allocations.
    /// </summary>
    private static string EnhanceSnmpVersion(string protocol, string? info)
    {
        if (string.IsNullOrWhiteSpace(info))
            return GetPooledProtocol(protocol);

        // Check for SNMPv3 indicators
        if (info.Contains("msgVersion=3", StringComparison.OrdinalIgnoreCase) ||
            info.Contains("SNMPv3", StringComparison.OrdinalIgnoreCase) ||
            info.Contains("msgAuthoritativeEngineID", StringComparison.OrdinalIgnoreCase))
        {
            return ProtocolPool["SNMPv3"];
        }

        // Check for SNMPv2c
        if (info.Contains("version-2c", StringComparison.OrdinalIgnoreCase) ||
            info.Contains("SNMPv2c", StringComparison.OrdinalIgnoreCase) ||
            info.Contains("version: v2c", StringComparison.OrdinalIgnoreCase))
        {
            return ProtocolPool["SNMPv2c"];
        }

        // Check for SNMPv1
        if (info.Contains("version-1", StringComparison.OrdinalIgnoreCase) ||
            info.Contains("SNMPv1", StringComparison.OrdinalIgnoreCase) ||
            info.Contains("version: 1", StringComparison.OrdinalIgnoreCase))
        {
            return ProtocolPool["SNMPv1"];
        }

        // Default to SNMPv1 if no version specified
        return ProtocolPool["SNMPv1"];
    }

    /// <summary>
    /// Records a parse failure for diagnostics
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void RecordParseFailure(ReadOnlySpan<char> line)
    {
        _parseFailureCount++;
        if (_firstParseFailure is null)
        {
            _firstParseFailure = line.ToString();
        }
    }

    /// <summary>
    /// Resets parse failure statistics and clears the IP cache.
    /// Call this when starting to parse a new PCAP file.
    /// </summary>
    public void ResetStatistics()
    {
        _parseFailureCount = 0;
        _firstParseFailure = null;
        _ipCache.Clear();
    }

    /// <summary>
    /// Clears only the IP cache without resetting statistics.
    /// Useful for memory management during long-running sessions.
    /// </summary>
    public void ClearIPCache()
    {
        _ipCache.Clear();
    }
}
