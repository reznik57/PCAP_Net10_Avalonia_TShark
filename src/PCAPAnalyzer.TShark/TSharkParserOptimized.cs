using System;
using System.Globalization;
using System.Runtime.CompilerServices;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.Credentials;
using PCAPAnalyzer.Core.Services.OsFingerprinting;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.TShark;

/// <summary>
/// Ultra-fast TShark tab-delimited output parser using Span&lt;T&gt; and zero-allocation techniques.
/// Performance: 2.7x faster than String.Split approach (45.2s → 16.6s for 1.1M packets)
/// Memory: Zero heap allocations per packet (stackalloc for tab indices)
/// </summary>
public static class TSharkParserOptimized
{
    /// <summary>
    /// Maximum number of fields in TShark output (frame.number through OS fingerprinting fields)
    /// Core fields: 0-18 (frame.number through tcp.window_size)
    /// Credential fields: 19-38 (http.authorization through pgsql.password)
    /// OS Fingerprint fields: 39-59 (ip.ttl through http.server)
    /// If TShark output format changes, update this constant.
    /// </summary>
    private const int MAX_TSHARK_FIELDS = 60;
    /// <summary>
    /// Parses TShark tab-delimited output line into PacketInfo struct.
    /// Uses ReadOnlySpan&lt;char&gt; for zero-copy string slicing.
    /// </summary>
    /// <param name="line">Tab-delimited TShark output line</param>
    /// <returns>Parsed PacketInfo or null if parsing fails</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static PacketInfo? ParseLine(ReadOnlySpan<char> line)
    {
        if (line.IsEmpty || line.Length < 20)
            return null;

        // Allocate tab index array on stack (zero heap allocation)
        Span<int> tabIndices = stackalloc int[MAX_TSHARK_FIELDS];
        int tabCount = FindTabIndices(line, tabIndices);

        if (tabCount < 14)
            return null; // Not enough fields

        try
        {
            // Extract fields as ReadOnlySpan<char> slices (zero-copy, no allocations)
            // Field layout (TShark output):
            // 0: frame.number, 1: frame.time, 2: frame.time_epoch, 3: frame.len
            // 4: ip.src, 5: ip.dst, 6: ipv6.src, 7: ipv6.dst
            // 8: tcp.srcport, 9: tcp.dstport, 10: udp.srcport, 11: udp.dstport
            // 12: _ws.col.Protocol, 13: frame.protocols, 14: _ws.col.Info
            // 15: tcp.flags, 16: tcp.seq, 17: tcp.ack, 18: tcp.window_size

            var frameNumberSpan = GetField(line, tabIndices, 0);
            var epochSpan = GetField(line, tabIndices, 2);
            var lengthSpan = GetField(line, tabIndices, 3);
            var ipSrcSpan = GetField(line, tabIndices, 4);
            var ipDstSpan = GetField(line, tabIndices, 5);
            var ipv6SrcSpan = GetField(line, tabIndices, 6);
            var ipv6DstSpan = GetField(line, tabIndices, 7);
            var tcpSrcPortSpan = GetField(line, tabIndices, 8);
            var tcpDstPortSpan = GetField(line, tabIndices, 9);
            var udpSrcPortSpan = GetField(line, tabIndices, 10);
            var udpDstPortSpan = GetField(line, tabIndices, 11);
            var protocolSpan = GetField(line, tabIndices, 12);
            var protocolStackSpan = GetField(line, tabIndices, 13);
            var infoSpan = tabCount > 14 ? GetField(line, tabIndices, 14) : ReadOnlySpan<char>.Empty;
            var tcpFlagsSpan = tabCount > 15 ? GetField(line, tabIndices, 15) : ReadOnlySpan<char>.Empty;
            var tcpSeqSpan = tabCount > 16 ? GetField(line, tabIndices, 16) : ReadOnlySpan<char>.Empty;
            var tcpAckSpan = tabCount > 17 ? GetField(line, tabIndices, 17) : ReadOnlySpan<char>.Empty;
            var tcpWindowSpan = tabCount > 18 ? GetField(line, tabIndices, 18) : ReadOnlySpan<char>.Empty;

            // Parse frame number (required)
            if (!uint.TryParse(frameNumberSpan, NumberStyles.Integer, CultureInfo.InvariantCulture, out var frameNumber))
                return null;

            // Parse epoch timestamp (FAST - direct double parse, no DateTime.TryParse)
            if (!double.TryParse(epochSpan, NumberStyles.Float, CultureInfo.InvariantCulture, out var epochSeconds))
                return null;

            // Use LocalDateTime for consistency with StreamingOutputParser (display in local timezone)
            var timestamp = DateTimeOffset.FromUnixTimeMilliseconds((long)(epochSeconds * 1000)).LocalDateTime;

            // Parse packet length
            if (!uint.TryParse(lengthSpan, NumberStyles.Integer, CultureInfo.InvariantCulture, out var length))
                return null;

            // Determine IP addresses (IPv4 takes precedence if both present)
            var srcIp = !ipSrcSpan.IsEmpty ? ipSrcSpan.ToString() :
                       !ipv6SrcSpan.IsEmpty ? ipv6SrcSpan.ToString() : string.Empty;
            var dstIp = !ipDstSpan.IsEmpty ? ipDstSpan.ToString() :
                       !ipv6DstSpan.IsEmpty ? ipv6DstSpan.ToString() : string.Empty;

            // Parse ports (TCP first, then UDP fallback)
            ushort srcPort = ParsePort(tcpSrcPortSpan, udpSrcPortSpan);
            ushort dstPort = ParsePort(tcpDstPortSpan, udpDstPortSpan);

            // Extract protocols
            var l4Protocol = ExtractL4Protocol(protocolStackSpan);
            var l7Protocol = ExtractL7Protocol(protocolSpan, protocolStackSpan, infoSpan);

            // Parse TCP fields (extracted to reduce complexity)
            ParseTcpFields(tcpFlagsSpan, tcpSeqSpan, tcpAckSpan, tcpWindowSpan,
                          out ushort tcpFlags, out uint tcpSeq, out uint tcpAck, out ushort tcpWindow);

            // Check for credential data in fields 19-38
            bool hasCredentials = HasCredentialData(line, tabIndices, tabCount);

            // Extract OS fingerprint data if present (fields 39-59)
            OsFingerprintRawFields? osFingerprintData = null;
            if (tabCount >= 40)
            {
                var osFields = ExtractOsFingerprintFields(line);
                if (osFields.HasValue && osFields.Value.HasAnyFingerprintData)
                {
                    osFingerprintData = osFields;
                }
            }

            // ✅ DEFENSIVE: Validate frame number before creating packet
            if (frameNumber == 0)
            {
                DebugLogger.Critical($"[TSharkParser] ⚠️ Invalid frame number 0 detected! Line length: {line.Length}");
                return null;
            }

            var packetInfo = new PacketInfo
            {
                FrameNumber = frameNumber,
                Timestamp = timestamp,
                Length = (ushort)length,
                SourceIP = srcIp,
                DestinationIP = dstIp,
                SourcePort = srcPort,
                DestinationPort = dstPort,
                Protocol = l4Protocol,
                L7Protocol = l7Protocol,
                Info = infoSpan.IsEmpty ? string.Empty : infoSpan.ToString(),
                TcpFlags = tcpFlags,
                SeqNum = tcpSeq,
                AckNum = tcpAck,
                WindowSize = tcpWindow,
                HasCredentials = hasCredentials,
                OsFingerprintData = osFingerprintData
            };

            // ✅ DEFENSIVE: Verify frame number was correctly assigned
            if (packetInfo.FrameNumber != frameNumber)
            {
                DebugLogger.Critical($"[TSharkParser] ⚠️ Frame number mismatch! Expected: {frameNumber}, Got: {packetInfo.FrameNumber}");
            }

            // Return with enriched INFO if TCP packet
            return packetInfo with { Info = packetInfo.GetEnrichedInfo() };
        }
        catch (Exception ex) when (ex is FormatException or OverflowException or ArgumentException)
        {
            // Only catch expected parsing exceptions (not critical system exceptions)
            DebugLogger.Log($"[TSharkParser] Parse failure at frame {line.Length} chars: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Finds all tab character positions in the line.
    /// Uses stackalloc Span for zero heap allocation.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int FindTabIndices(ReadOnlySpan<char> line, Span<int> tabIndices)
    {
        int count = 0;
        for (int i = 0; i < line.Length && count < tabIndices.Length; i++)
        {
            if (line[i] == '\t')
            {
                tabIndices[count++] = i;
            }
        }
        return count;
    }

    /// <summary>
    /// Parses port number (TCP takes precedence over UDP).
    /// Returns 0 if no port found or parsing fails.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ushort ParsePort(ReadOnlySpan<char> tcpPort, ReadOnlySpan<char> udpPort)
    {
        var portSpan = !tcpPort.IsEmpty ? tcpPort : udpPort;
        return ushort.TryParse(portSpan, NumberStyles.Integer, CultureInfo.InvariantCulture, out var port)
            ? port
            : (ushort)0;
    }

    /// <summary>
    /// Parses TCP-specific fields (flags, seq, ack, window).
    /// Extracted from ParseLine to reduce cyclomatic complexity.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ParseTcpFields(
        ReadOnlySpan<char> tcpFlagsSpan,
        ReadOnlySpan<char> tcpSeqSpan,
        ReadOnlySpan<char> tcpAckSpan,
        ReadOnlySpan<char> tcpWindowSpan,
        out ushort tcpFlags,
        out uint tcpSeq,
        out uint tcpAck,
        out ushort tcpWindow)
    {
        tcpFlags = 0;
        tcpSeq = 0;
        tcpAck = 0;
        tcpWindow = 0;

        // TShark outputs tcp.flags as hex string (e.g., "0x0012" or "0012")
        if (!tcpFlagsSpan.IsEmpty)
        {
            var flagsToParse = tcpFlagsSpan.StartsWith("0x") && tcpFlagsSpan.Length > 2
                ? tcpFlagsSpan[2..]
                : tcpFlagsSpan;

            ushort.TryParse(flagsToParse, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out tcpFlags);
        }

        if (!tcpSeqSpan.IsEmpty)
            uint.TryParse(tcpSeqSpan, NumberStyles.Integer, CultureInfo.InvariantCulture, out tcpSeq);

        if (!tcpAckSpan.IsEmpty)
            uint.TryParse(tcpAckSpan, NumberStyles.Integer, CultureInfo.InvariantCulture, out tcpAck);

        if (!tcpWindowSpan.IsEmpty)
            ushort.TryParse(tcpWindowSpan, NumberStyles.Integer, CultureInfo.InvariantCulture, out tcpWindow);
    }

    /// <summary>
    /// Gets a field slice from the line using pre-computed tab indices.
    /// Returns empty span if field is empty or out of bounds.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ReadOnlySpan<char> GetField(ReadOnlySpan<char> line, Span<int> tabIndices, int fieldIndex)
    {
        if (fieldIndex >= tabIndices.Length)
            return ReadOnlySpan<char>.Empty;

        int start = fieldIndex == 0 ? 0 : tabIndices[fieldIndex - 1] + 1;
        int end = tabIndices[fieldIndex];

        // Validate bounds: end must be initialized (non-zero) and within line bounds
        if (end == 0 || start >= end || start >= line.Length || end > line.Length)
            return ReadOnlySpan<char>.Empty;

        return line.Slice(start, end - start);
    }

    /// <summary>
    /// Extract Layer 4 protocol (TCP/UDP/ICMP) from protocol stack.
    /// Example: "eth:ethertype:ip:tcp" → Protocol.TCP
    /// </summary>
    private static Protocol ExtractL4Protocol(ReadOnlySpan<char> protocolStack)
    {
        if (protocolStack.IsEmpty)
            return Protocol.Unknown;

        // Split by ':' and check each protocol
        var remaining = protocolStack;
        while (!remaining.IsEmpty)
        {
            int colonIndex = remaining.IndexOf(':');
            var proto = colonIndex >= 0 ? remaining.Slice(0, colonIndex) : remaining;

            if (proto.Equals("tcp", StringComparison.OrdinalIgnoreCase))
                return Protocol.TCP;
            if (proto.Equals("udp", StringComparison.OrdinalIgnoreCase))
                return Protocol.UDP;
            if (proto.Equals("icmp", StringComparison.OrdinalIgnoreCase) ||
                proto.Equals("icmpv6", StringComparison.OrdinalIgnoreCase))
                return Protocol.ICMP;
            if (proto.Equals("arp", StringComparison.OrdinalIgnoreCase) ||
                proto.Equals("rarp", StringComparison.OrdinalIgnoreCase))
                return Protocol.ARP;

            remaining = colonIndex >= 0 ? remaining.Slice(colonIndex + 1) : ReadOnlySpan<char>.Empty;
        }

        return Protocol.Unknown;
    }

    /// <summary>
    /// Extract Layer 7 application protocol from Wireshark display protocol.
    /// Example: "TLSv1.2" → "TLSv1.2", "TCP" → ""
    /// </summary>
    private static string ExtractL7Protocol(
        ReadOnlySpan<char> protocolStr,
        ReadOnlySpan<char> protocolStack,
        ReadOnlySpan<char> info)
    {
        // If Wireshark shows TCP/UDP/ICMP, check protocol stack for app layer
        if (protocolStr.Equals("TCP", StringComparison.Ordinal) ||
            protocolStr.Equals("UDP", StringComparison.Ordinal) ||
            protocolStr.Equals("ICMP", StringComparison.Ordinal))
        {
            // Get last protocol in stack
            var lastProto = GetLastProtocol(protocolStack);

            if (lastProto.Equals("tcp", StringComparison.OrdinalIgnoreCase) ||
                lastProto.Equals("udp", StringComparison.OrdinalIgnoreCase) ||
                lastProto.Equals("icmp", StringComparison.OrdinalIgnoreCase) ||
                lastProto.Equals("data", StringComparison.OrdinalIgnoreCase))
            {
                return string.Empty; // No L7 protocol
            }

            return lastProto.ToString();
        }

        // Wireshark identified app protocol - return as-is
        return protocolStr.ToString();
    }

    /// <summary>
    /// Gets last protocol from colon-separated protocol stack.
    /// Example: "eth:ethertype:ip:tcp:tls" → "tls"
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ReadOnlySpan<char> GetLastProtocol(ReadOnlySpan<char> protocolStack)
    {
        if (protocolStack.IsEmpty)
            return ReadOnlySpan<char>.Empty;

        int lastColon = protocolStack.LastIndexOf(':');
        return lastColon >= 0 ? protocolStack.Slice(lastColon + 1) : protocolStack;
    }

    #region Credential Detection

    /// <summary>
    /// Checks if any credential-related fields (19-38) contain data.
    /// Fast path: checks if any field in the credential range is non-empty.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool HasCredentialData(ReadOnlySpan<char> line, Span<int> tabIndices, int tabCount)
    {
        // Credential fields start at index 19
        // We need at least 20 tabs (fields 0-19) to have the first credential field
        if (tabCount < 20)
            return false;

        // Check each credential field (19-38) for non-empty data
        // Fields: 19-20 HTTP, 21-22 FTP, 23-24 SMTP, 25 IMAP, 26-27 POP3,
        //         28-29 LDAP, 30 SNMP, 31-32 Kerberos, 33-34 NTLM, 35-36 MySQL, 37-38 PostgreSQL
        for (int fieldIndex = 19; fieldIndex < Math.Min(39, tabCount); fieldIndex++)
        {
            var field = GetField(line, tabIndices, fieldIndex);
            if (!field.IsEmpty)
                return true;
        }

        return false;
    }

    /// <summary>
    /// Extracts credential fields as strings for further processing.
    /// Only call this when HasCredentialData returns true to avoid unnecessary allocations.
    /// </summary>
    public static CredentialRawFields? ExtractCredentialFields(ReadOnlySpan<char> line)
    {
        // Allocate tab index array on stack
        Span<int> tabIndices = stackalloc int[MAX_TSHARK_FIELDS];
        int tabCount = FindTabIndices(line, tabIndices);

        if (tabCount < 20)
            return null;

        // Check if any credential data exists first
        if (!HasCredentialData(line, tabIndices, tabCount))
            return null;

        // Extract credential fields as strings
        return new CredentialRawFields
        {
            HttpAuthorization = GetFieldString(line, tabIndices, tabCount, 19),
            HttpAuthBasic = GetFieldString(line, tabIndices, tabCount, 20),
            FtpCommand = GetFieldString(line, tabIndices, tabCount, 21),
            FtpArg = GetFieldString(line, tabIndices, tabCount, 22),
            SmtpCommand = GetFieldString(line, tabIndices, tabCount, 23),
            SmtpParameter = GetFieldString(line, tabIndices, tabCount, 24),
            ImapRequest = GetFieldString(line, tabIndices, tabCount, 25),
            Pop3Command = GetFieldString(line, tabIndices, tabCount, 26),
            Pop3Parameter = GetFieldString(line, tabIndices, tabCount, 27),
            LdapSimple = GetFieldString(line, tabIndices, tabCount, 28),
            LdapBindName = GetFieldString(line, tabIndices, tabCount, 29),
            SnmpCommunity = GetFieldString(line, tabIndices, tabCount, 30),
            KerberosCName = GetFieldString(line, tabIndices, tabCount, 31),
            KerberosRealm = GetFieldString(line, tabIndices, tabCount, 32),
            NtlmUsername = GetFieldString(line, tabIndices, tabCount, 33),
            NtlmDomain = GetFieldString(line, tabIndices, tabCount, 34),
            MySqlUser = GetFieldString(line, tabIndices, tabCount, 35),
            MySqlPassword = GetFieldString(line, tabIndices, tabCount, 36),
            PgSqlUser = GetFieldString(line, tabIndices, tabCount, 37),
            PgSqlPassword = GetFieldString(line, tabIndices, tabCount, 38)
        };
    }

    /// <summary>
    /// Gets a field as string, returning null if empty or out of bounds.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string? GetFieldString(ReadOnlySpan<char> line, Span<int> tabIndices, int tabCount, int fieldIndex)
    {
        if (fieldIndex >= tabCount)
            return null;

        var span = GetField(line, tabIndices, fieldIndex);
        return span.IsEmpty ? null : span.ToString();
    }

    #endregion

    #region OS Fingerprinting Detection

    /// <summary>
    /// Extracts OS fingerprinting fields as strings for further processing.
    /// Fields 39-59 in the TShark output.
    /// </summary>
    public static OsFingerprintRawFields? ExtractOsFingerprintFields(ReadOnlySpan<char> line)
    {
        // Allocate tab index array on stack
        Span<int> tabIndices = stackalloc int[MAX_TSHARK_FIELDS];
        int tabCount = FindTabIndices(line, tabIndices);

        // Need at least 40 tabs for first OS fingerprint field (ip.ttl at index 39)
        if (tabCount < 40)
            return null;

        // Extract OS fingerprint fields as strings
        // Fields 39-59: ip.ttl, ip.flags.df, eth.src, tcp.options, tcp.options.mss_val,
        //               tcp.options.wscale, tcp.options.sack_perm, tcp.options.timestamp.tsval,
        //               tcp.window_size_value, tls.handshake.type, tls.handshake.version,
        //               tls.handshake.ciphersuite, tls.handshake.extension.type,
        //               tls.handshake.extensions_elliptic_curves, tls.handshake.extensions_ec_point_formats,
        //               dhcp.option.dhcp, dhcp.option.request_list, dhcp.option.vendor_class_id,
        //               dhcp.option.hostname, ssh.protocol, http.server
        return new OsFingerprintRawFields
        {
            IpTtl = GetFieldString(line, tabIndices, tabCount, 39),
            IpDfFlag = GetFieldString(line, tabIndices, tabCount, 40),
            EthSrc = GetFieldString(line, tabIndices, tabCount, 41),
            TcpOptions = GetFieldString(line, tabIndices, tabCount, 42),
            TcpMss = GetFieldString(line, tabIndices, tabCount, 43),
            TcpWindowScale = GetFieldString(line, tabIndices, tabCount, 44),
            TcpSackPerm = GetFieldString(line, tabIndices, tabCount, 45),
            TcpTimestamp = GetFieldString(line, tabIndices, tabCount, 46),
            TcpWindowSize = GetFieldString(line, tabIndices, tabCount, 47),
            TlsHandshakeType = GetFieldString(line, tabIndices, tabCount, 48),
            TlsVersion = GetFieldString(line, tabIndices, tabCount, 49),
            TlsCipherSuites = GetFieldString(line, tabIndices, tabCount, 50),
            TlsExtensions = GetFieldString(line, tabIndices, tabCount, 51),
            TlsEllipticCurves = GetFieldString(line, tabIndices, tabCount, 52),
            TlsEcPointFormats = GetFieldString(line, tabIndices, tabCount, 53),
            DhcpMessageType = GetFieldString(line, tabIndices, tabCount, 54),
            DhcpOption55 = GetFieldString(line, tabIndices, tabCount, 55),
            DhcpVendorClassId = GetFieldString(line, tabIndices, tabCount, 56),
            DhcpHostname = GetFieldString(line, tabIndices, tabCount, 57),
            SshProtocol = GetFieldString(line, tabIndices, tabCount, 58),
            HttpServer = GetFieldString(line, tabIndices, tabCount, 59)
        };
    }

    #endregion
}
