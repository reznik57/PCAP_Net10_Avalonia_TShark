using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using System;
using System.Collections.Frozen;
using System.Collections.Generic;

namespace PCAPAnalyzer.UI.Services.Filters;

/// <summary>
/// Static registry of quick filter predicates organized by category.
/// Extracted from SmartFilterBuilderService to improve maintainability.
///
/// CA1502 suppressions: High cyclomatic complexity is intentional in predicate registration methods.
/// Each method adds predicates using simple dictionary operations - the complexity comes from
/// the comprehensive set of filters supported, not from control flow complexity.
///
/// SINGLE SOURCE OF TRUTH for all quick filter predicates used across:
/// - SmartFilterBuilderService (filter chip creation)
/// - SmartFilterableTab (quick filter toggles)
/// - MainWindowViewModel (global filter state)
///
/// Categories:
/// - IP Address Classification (IPv4, IPv6, RFC1918, Public, etc.)
/// - Traffic Direction (PrivateToPublic, PublicToPrivate, etc.)
/// - L4 Transport Protocols (TCP, UDP, ICMP, ARP, etc.)
/// - TCP Flags (SYN, RST, FIN, ACK-only, etc.)
/// - L7 Application Protocols (HTTP, HTTPS, DNS, SSH, etc.)
/// - VoIP Protocols (SIP, RTP, RTCP, H.323, etc.)
/// - Security & Compliance (TLSv1.0, CleartextAuth, etc.)
/// - TCP Performance (Retransmissions, ZeroWindow, etc.)
/// - Frame Characteristics (SmallFrame, Fragmented, etc.)
/// </summary>
public static class QuickFilterPredicateRegistry
{
    /// <summary>
    /// Frozen dictionary of all quick filter predicates for O(1) lookup.
    /// Using FrozenDictionary for optimal read performance (immutable after creation).
    /// </summary>
    private static readonly FrozenDictionary<string, Func<PacketInfo, bool>> Predicates = BuildPredicateDictionary();

    /// <summary>
    /// Gets a predicate for a quick filter by code name.
    /// Returns null if the filter name is not recognized.
    /// </summary>
    /// <param name="quickFilterCodeName">The code name of the quick filter (e.g., "SYN", "TCP", "IPv4")</param>
    /// <returns>A predicate function, or null if the filter name is not recognized</returns>
    public static Func<PacketInfo, bool>? GetPredicate(string? quickFilterCodeName)
    {
        if (string.IsNullOrWhiteSpace(quickFilterCodeName))
            return null;

        return Predicates.GetValueOrDefault(quickFilterCodeName);
    }

    /// <summary>
    /// Checks if a quick filter code name is registered.
    /// </summary>
    public static bool IsRegistered(string? quickFilterCodeName)
        => !string.IsNullOrWhiteSpace(quickFilterCodeName) && Predicates.ContainsKey(quickFilterCodeName);

    /// <summary>
    /// Gets all registered quick filter code names.
    /// </summary>
    public static IEnumerable<string> GetAllCodeNames() => Predicates.Keys;

    /// <summary>
    /// Builds the complete predicate dictionary organized by category.
    /// </summary>
    private static FrozenDictionary<string, Func<PacketInfo, bool>> BuildPredicateDictionary()
    {
        var dict = new Dictionary<string, Func<PacketInfo, bool>>(StringComparer.Ordinal);

        // Add all categories
        AddIpAddressPredicates(dict);
        AddTrafficDirectionPredicates(dict);
        AddTransportProtocolPredicates(dict);
        AddTcpFlagPredicates(dict);
        AddFrameCharacteristicPredicates(dict);
        AddApplicationProtocolPredicates(dict);
        AddVoipProtocolPredicates(dict);
        AddSecurityPredicates(dict);
        AddTcpPerformancePredicates(dict);
        AddVpnProtocolPredicates(dict);
        AddProtocolErrorPredicates(dict);
        AddIcmpTypePredicates(dict);
        AddDnsTypePredicates(dict);
        AddPortRangePredicates(dict);

        return dict.ToFrozenDictionary(StringComparer.Ordinal);
    }

    #region IP Address Classification

    private static void AddIpAddressPredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        // IP Version
        dict["IPv4"] = p => NetworkFilterHelper.IsIPv4(p.SourceIP) ||
                            NetworkFilterHelper.IsIPv4(p.DestinationIP);
        dict["IPv6"] = p => NetworkFilterHelper.IsIPv6(p.SourceIP) ||
                            NetworkFilterHelper.IsIPv6(p.DestinationIP);

        // Address Scope
        dict["RFC1918"] = p => NetworkFilterHelper.IsRFC1918(p.SourceIP) ||
                               NetworkFilterHelper.IsRFC1918(p.DestinationIP);
        dict["PublicIP"] = p => !NetworkFilterHelper.IsRFC1918(p.SourceIP) &&
                                !NetworkFilterHelper.IsLoopback(p.SourceIP) &&
                                !NetworkFilterHelper.IsLinkLocal(p.SourceIP);
        dict["Public"] = dict["PublicIP"]; // Alias
        dict["APIPA"] = p => NetworkFilterHelper.IsLinkLocal(p.SourceIP) ||
                             NetworkFilterHelper.IsLinkLocal(p.DestinationIP);

        // Special Addresses
        dict["Loopback"] = p => NetworkFilterHelper.IsLoopback(p.SourceIP) ||
                                NetworkFilterHelper.IsLoopback(p.DestinationIP);
        dict["LinkLocal"] = p => NetworkFilterHelper.IsLinkLocal(p.SourceIP) ||
                                 NetworkFilterHelper.IsLinkLocal(p.DestinationIP);
        dict["Anycast"] = p => NetworkFilterHelper.IsAnycast(p.SourceIP) ||
                               NetworkFilterHelper.IsAnycast(p.DestinationIP);

        // Delivery Method
        dict["Unicast"] = p => !NetworkFilterHelper.IsBroadcastPacket(
                                   p.DestinationIP, p.L7Protocol, p.Info, p.DestinationMAC) &&
                               !NetworkFilterHelper.IsMulticast(p.DestinationIP);
        dict["Multicast"] = p => NetworkFilterHelper.IsMulticast(p.SourceIP) ||
                                 NetworkFilterHelper.IsMulticast(p.DestinationIP);
        dict["Broadcast"] = p => NetworkFilterHelper.IsBroadcastPacket(
                                     p.DestinationIP, p.L7Protocol, p.Info, p.DestinationMAC);
    }

    #endregion

    #region Traffic Direction

    private static void AddTrafficDirectionPredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        // PrivateToPublic: RFC1918 source → non-RFC1918 destination
        dict["PrivateToPublic"] = p => NetworkFilterHelper.IsRFC1918(p.SourceIP) &&
                                       !NetworkFilterHelper.IsRFC1918(p.DestinationIP) &&
                                       !NetworkFilterHelper.IsLoopback(p.DestinationIP) &&
                                       !NetworkFilterHelper.IsMulticast(p.DestinationIP) &&
                                       !NetworkFilterHelper.IsBroadcastPacket(
                                           p.DestinationIP, p.L7Protocol, p.Info, p.DestinationMAC);

        // PublicToPrivate: Non-RFC1918 source → RFC1918 destination
        dict["PublicToPrivate"] = p => !NetworkFilterHelper.IsRFC1918(p.SourceIP) &&
                                       !NetworkFilterHelper.IsLoopback(p.SourceIP) &&
                                       NetworkFilterHelper.IsRFC1918(p.DestinationIP);
    }

    #endregion

    #region L4 Transport Protocols

    private static void AddTransportProtocolPredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        dict["TCP"] = p => p.Protocol == Protocol.TCP;
        dict["UDP"] = p => p.Protocol == Protocol.UDP;
        dict["ICMP"] = p => p.Protocol == Protocol.ICMP;
        dict["ARP"] = p => p.L7Protocol?.Equals("ARP", StringComparison.OrdinalIgnoreCase) == true;
        dict["IGMP"] = p => p.L7Protocol?.Contains("IGMP", StringComparison.OrdinalIgnoreCase) == true ||
                           p.Protocol.ToString().Contains("IGMP", StringComparison.OrdinalIgnoreCase);
        dict["GRE"] = p => p.L7Protocol?.Contains("GRE", StringComparison.OrdinalIgnoreCase) == true ||
                          p.Protocol.ToString().Contains("GRE", StringComparison.OrdinalIgnoreCase);
    }

    #endregion

    #region TCP Flags

    private static void AddTcpFlagPredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        // TCP flag bits: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20

        // SYN without ACK (connection initiation)
        dict["SYN"] = p => p.Protocol == Protocol.TCP &&
                          (p.TcpFlags & 0x02) != 0 && (p.TcpFlags & 0x10) == 0;
        dict["TcpSyn"] = dict["SYN"]; // Alias

        // SYN-ACK (connection response)
        dict["SYN-ACK"] = p => p.Protocol == Protocol.TCP &&
                              (p.TcpFlags & 0x12) == 0x12;
        dict["TcpSynAck"] = dict["SYN-ACK"]; // Alias

        // RST (connection reset)
        dict["RST"] = p => p.Protocol == Protocol.TCP && (p.TcpFlags & 0x04) != 0;
        dict["TcpRst"] = dict["RST"]; // Alias

        // FIN (connection termination)
        dict["FIN"] = p => p.Protocol == Protocol.TCP && (p.TcpFlags & 0x01) != 0;
        dict["TcpFin"] = dict["FIN"]; // Alias

        // PSH (push flag - immediate delivery)
        dict["PSH"] = p => p.Protocol == Protocol.TCP && (p.TcpFlags & 0x08) != 0;
        dict["TcpPsh"] = dict["PSH"]; // Alias

        // ACK-only (has ACK, but no SYN, FIN, or RST)
        dict["ACK-only"] = p => p.Protocol == Protocol.TCP &&
                               (p.TcpFlags & 0x10) != 0 &&  // Has ACK
                               (p.TcpFlags & 0x07) == 0;    // No SYN, FIN, RST
        dict["TcpAckOnly"] = dict["ACK-only"]; // Alias

        // URG (urgent pointer - rarely used)
        dict["URG"] = p => p.Protocol == Protocol.TCP && (p.TcpFlags & 0x20) != 0;
        dict["TcpUrg"] = dict["URG"]; // Alias
    }

    #endregion

    #region Frame Characteristics

    private static void AddFrameCharacteristicPredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        // SmallFrame: < 60 bytes (Ethernet minimum is 64, but frame.len excludes 4-byte CRC)
        dict["SmallFrame"] = p => p.Length < 60;

        // Fragmented packets
        dict["Fragmented"] = p => MatchesAnyInfoPattern(p.Info, ["fragment", "frag offset"]);

        // Jumbo frames: > standard Ethernet MTU
        dict["JumboFrames"] = p => p.Length > 1514;
    }

    #endregion

    #region L7 Application Protocols

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "High complexity from comprehensive protocol coverage, not control flow")]
    private static void AddApplicationProtocolPredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        // HTTP: Plaintext HTTP including HTTP/2 (h2c), excluding HTTPS/TLS
        dict["HTTP"] = p => (p.L7Protocol?.Contains("HTTP", StringComparison.OrdinalIgnoreCase) == true ||
                            p.L7Protocol?.Equals("HTTP2", StringComparison.OrdinalIgnoreCase) == true ||
                            p.L7Protocol?.Equals("h2c", StringComparison.OrdinalIgnoreCase) == true) &&
                           p.L7Protocol?.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) != true &&
                           p.L7Protocol?.Contains("TLS", StringComparison.OrdinalIgnoreCase) != true;

        dict["HTTPS"] = p => p.L7Protocol?.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) == true ||
                            p.L7Protocol?.Contains("TLS", StringComparison.OrdinalIgnoreCase) == true;

        dict["DNS"] = p => p.L7Protocol?.Contains("DNS", StringComparison.OrdinalIgnoreCase) == true ||
                          p.SourcePort == 53 || p.DestinationPort == 53;

        dict["SSH"] = p => p.SourcePort == 22 || p.DestinationPort == 22;

        dict["FTP"] = p => p.SourcePort == 21 || p.DestinationPort == 21 ||
                          p.SourcePort == 20 || p.DestinationPort == 20;

        dict["SMTP"] = p => p.SourcePort == 25 || p.DestinationPort == 25 ||
                           p.SourcePort == 587 || p.DestinationPort == 587;

        dict["SNMP"] = p => p.SourcePort == 161 || p.DestinationPort == 161 ||
                           p.SourcePort == 162 || p.DestinationPort == 162;

        dict["DHCP"] = p => p.SourcePort == 67 || p.DestinationPort == 67 ||
                           p.SourcePort == 68 || p.DestinationPort == 68;

        dict["STUN"] = p => p.SourcePort == 3478 || p.DestinationPort == 3478 ||
                           p.SourcePort == 5349 || p.DestinationPort == 5349;

        dict["Telnet"] = p => p.L7Protocol?.Contains("TELNET", StringComparison.OrdinalIgnoreCase) == true ||
                             p.DestinationPort == 23 || p.SourcePort == 23;
    }

    #endregion

    #region VoIP Protocols

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "High complexity from comprehensive VoIP protocol coverage, not control flow")]
    private static void AddVoipProtocolPredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        // SIP: Session Initiation Protocol (signaling for VoIP calls)
        dict["SIP"] = p => p.L7Protocol?.Contains("SIP", StringComparison.OrdinalIgnoreCase) == true ||
                          p.SourcePort == 5060 || p.DestinationPort == 5060 ||
                          p.SourcePort == 5061 || p.DestinationPort == 5061;

        // RTP: Real-time Transport Protocol (audio/video payload)
        dict["RTP"] = p => p.L7Protocol?.Contains("RTP", StringComparison.OrdinalIgnoreCase) == true &&
                          p.L7Protocol?.Contains("RTCP", StringComparison.OrdinalIgnoreCase) != true;

        // RTCP: RTP Control Protocol (QoS feedback)
        dict["RTCP"] = p => p.L7Protocol?.Contains("RTCP", StringComparison.OrdinalIgnoreCase) == true;

        // H.323: Legacy VoIP signaling protocol
        dict["H323"] = p => p.L7Protocol?.Contains("H.323", StringComparison.OrdinalIgnoreCase) == true ||
                           p.L7Protocol?.Contains("H323", StringComparison.OrdinalIgnoreCase) == true ||
                           p.SourcePort == 1720 || p.DestinationPort == 1720;
        dict["H.323"] = dict["H323"]; // Alias

        // MGCP: Media Gateway Control Protocol
        dict["MGCP"] = p => p.L7Protocol?.Contains("MGCP", StringComparison.OrdinalIgnoreCase) == true ||
                           p.SourcePort == 2427 || p.DestinationPort == 2427 ||
                           p.SourcePort == 2727 || p.DestinationPort == 2727;

        // SCCP/Skinny: Cisco VoIP
        dict["SCCP"] = p => p.L7Protocol?.Contains("SCCP", StringComparison.OrdinalIgnoreCase) == true ||
                           p.L7Protocol?.Contains("Skinny", StringComparison.OrdinalIgnoreCase) == true ||
                           p.SourcePort == 2000 || p.DestinationPort == 2000;
        dict["Skinny"] = dict["SCCP"]; // Alias

        // WebRTC ICE candidates
        dict["WebRTC"] = p => p.L7Protocol?.Contains("WebRTC", StringComparison.OrdinalIgnoreCase) == true ||
                             p.L7Protocol?.Contains("DTLS", StringComparison.OrdinalIgnoreCase) == true ||
                             p.Info?.Contains("ICE", StringComparison.OrdinalIgnoreCase) == true;
    }

    #endregion

    #region Security & Compliance

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "High complexity from comprehensive security filter coverage, not control flow")]
    private static void AddSecurityPredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        // Deprecated TLS versions (RFC 8996)
        dict["TlsV10"] = p => p.L7Protocol?.Contains("TLS 1.0", StringComparison.OrdinalIgnoreCase) == true ||
                             p.L7Protocol?.Contains("TLSv1.0", StringComparison.OrdinalIgnoreCase) == true;
        dict["TlsV11"] = p => p.L7Protocol?.Contains("TLS 1.1", StringComparison.OrdinalIgnoreCase) == true ||
                             p.L7Protocol?.Contains("TLSv1.1", StringComparison.OrdinalIgnoreCase) == true;

        // Modern TLS versions
        dict["TlsV12"] = p => p.L7Protocol?.Contains("TLS 1.2", StringComparison.OrdinalIgnoreCase) == true ||
                             p.L7Protocol?.Contains("TLSv1.2", StringComparison.OrdinalIgnoreCase) == true;
        dict["TlsV13"] = p => p.L7Protocol?.Contains("TLS 1.3", StringComparison.OrdinalIgnoreCase) == true ||
                             p.L7Protocol?.Contains("TLSv1.3", StringComparison.OrdinalIgnoreCase) == true;

        // Obsolete crypto (combined)
        dict["ObsoleteCrypto"] = p => p.L7Protocol?.Contains("SSL", StringComparison.OrdinalIgnoreCase) == true ||
                                     p.L7Protocol?.Contains("TLS 1.0", StringComparison.OrdinalIgnoreCase) == true ||
                                     p.L7Protocol?.Contains("TLSv1.0", StringComparison.OrdinalIgnoreCase) == true ||
                                     p.L7Protocol?.Contains("TLS 1.1", StringComparison.OrdinalIgnoreCase) == true ||
                                     p.L7Protocol?.Contains("TLSv1.1", StringComparison.OrdinalIgnoreCase) == true;

        // Deprecated protocols
        dict["SSHv1"] = p => p.L7Protocol?.Contains("SSH-1", StringComparison.OrdinalIgnoreCase) == true ||
                            p.L7Protocol?.Contains("SSHv1", StringComparison.OrdinalIgnoreCase) == true ||
                            p.Info?.Contains("SSH-1.", StringComparison.OrdinalIgnoreCase) == true;
        dict["SmbV1"] = p => p.L7Protocol?.Contains("SMBv1", StringComparison.OrdinalIgnoreCase) == true ||
                            p.L7Protocol?.Contains("SMB1", StringComparison.OrdinalIgnoreCase) == true;

        // Insecure protocols
        dict["Insecure"] = p => NetworkFilterHelper.IsInsecureProtocol(p.L7Protocol ?? p.Protocol.ToString());
        dict["INSECURE"] = dict["Insecure"]; // Alias

        // Cleartext authentication
        dict["CleartextAuth"] = p => IsCleartextAuth(p);

        // Encrypted traffic (positive security)
        dict["Encrypted"] = p => p.L7Protocol?.Contains("TLS", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("SSL", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("SSH", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("ESP", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("IKE", StringComparison.OrdinalIgnoreCase) == true ||
                                p.DestinationPort == 443 || p.DestinationPort == 22 ||
                                p.SourcePort == 443 || p.SourcePort == 22;

        // Attack indicators
        dict["SYNFlood"] = p => p.Protocol == Protocol.TCP &&
                               (p.TcpFlags & 0x02) != 0 &&  // SYN flag
                               (p.TcpFlags & 0x10) == 0;    // No ACK
        dict["SynFlood"] = dict["SYNFlood"]; // Alias

        dict["PortScan"] = p => p.Protocol == Protocol.TCP &&
                               (p.TcpFlags & 0x02) != 0 &&  // SYN flag
                               (p.TcpFlags & 0x10) == 0 &&  // No ACK
                               p.DestinationPort < 1024;    // Well-known ports

        dict["InvalidTTL"] = p => p.Info?.Contains("TTL=1 ", StringComparison.Ordinal) == true ||
                                 p.Info?.Contains("TTL=0 ", StringComparison.Ordinal) == true ||
                                 p.Info?.Contains("ttl=1 ", StringComparison.OrdinalIgnoreCase) == true ||
                                 p.Info?.Contains("ttl=0 ", StringComparison.OrdinalIgnoreCase) == true;
        dict["LowTTL"] = dict["InvalidTTL"]; // Alias

        // Certificate issues
        dict["TLSCertError"] = p => p.Info?.Contains("Certificate", StringComparison.OrdinalIgnoreCase) == true &&
                                   (p.Info?.Contains("error", StringComparison.OrdinalIgnoreCase) == true ||
                                    p.Info?.Contains("expired", StringComparison.OrdinalIgnoreCase) == true ||
                                    p.Info?.Contains("invalid", StringComparison.OrdinalIgnoreCase) == true ||
                                    p.Info?.Contains("untrusted", StringComparison.OrdinalIgnoreCase) == true ||
                                    p.Info?.Contains("self-signed", StringComparison.OrdinalIgnoreCase) == true);
        dict["CertError"] = dict["TLSCertError"]; // Alias
    }

    /// <summary>
    /// Checks if packet contains cleartext authentication credentials.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "High complexity from comprehensive auth pattern checking, not control flow")]
    private static bool IsCleartextAuth(PacketInfo p)
    {
        // FTP/SMTP/POP3/IMAP/Telnet - check for USER/PASS commands
        if ((p.L7Protocol?.Contains("FTP", StringComparison.OrdinalIgnoreCase) == true ||
             p.L7Protocol?.Contains("SMTP", StringComparison.OrdinalIgnoreCase) == true ||
             p.L7Protocol?.Contains("POP", StringComparison.OrdinalIgnoreCase) == true ||
             p.L7Protocol?.Contains("IMAP", StringComparison.OrdinalIgnoreCase) == true ||
             p.L7Protocol?.Contains("TELNET", StringComparison.OrdinalIgnoreCase) == true ||
             p.DestinationPort == 21 || p.DestinationPort == 23 || p.DestinationPort == 25 ||
             p.DestinationPort == 110 || p.DestinationPort == 143 || p.DestinationPort == 587) &&
            (p.Info?.Contains("USER ", StringComparison.Ordinal) == true ||
             p.Info?.Contains("PASS ", StringComparison.Ordinal) == true ||
             p.Info?.Contains("AUTH ", StringComparison.Ordinal) == true ||
             p.Info?.Contains("LOGIN ", StringComparison.Ordinal) == true))
        {
            return true;
        }

        // HTTP Basic Auth header
        if (p.L7Protocol?.Contains("HTTP", StringComparison.OrdinalIgnoreCase) == true &&
            p.Info?.Contains("Authorization: Basic", StringComparison.OrdinalIgnoreCase) == true)
        {
            return true;
        }

        return false;
    }

    #endregion

    #region TCP Performance

    private static void AddTcpPerformancePredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        dict["Retransmissions"] = p => p.Info?.Contains("Retransmission", StringComparison.OrdinalIgnoreCase) == true;
        dict["Retransmission"] = dict["Retransmissions"]; // Alias

        dict["DuplicateAck"] = p => MatchesAnyInfoPattern(p.Info, ["Dup ACK", "DupACK", "Duplicate ACK"]);
        dict["DupAck"] = dict["DuplicateAck"]; // Alias

        dict["ZeroWindow"] = p => MatchesAnyInfoPattern(p.Info, ["Zero window", "ZeroWindow"]);

        dict["OutOfOrder"] = p => MatchesAnyInfoPattern(p.Info, ["Out-of-Order", "OutOfOrder", "out of order"]);

        dict["KeepAlive"] = p => p.Info?.Contains("Keep-Alive", StringComparison.OrdinalIgnoreCase) == true;

        dict["ConnectionRefused"] = p =>
            (p.Protocol == Protocol.TCP && (p.TcpFlags & 0x04) != 0 && (p.TcpFlags & 0x10) == 0) ||
            MatchesAnyInfoPattern(p.Info, ["refused", "Connection reset"]);

        dict["WindowFull"] = p => p.Info?.Contains("Window full", StringComparison.OrdinalIgnoreCase) == true;
    }

    #endregion

    #region VPN Protocols

    private static void AddVpnProtocolPredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        dict["WireGuard"] = p => p.SourcePort == 51820 || p.DestinationPort == 51820;
        dict["OpenVPN"] = p => p.SourcePort == 1194 || p.DestinationPort == 1194;
        dict["IKEv2"] = p => p.SourcePort == 500 || p.DestinationPort == 500 ||
                           p.SourcePort == 4500 || p.DestinationPort == 4500;
        dict["IPSec"] = p => p.L7Protocol?.Contains("ESP", StringComparison.OrdinalIgnoreCase) == true ||
                           p.L7Protocol?.Contains("AH", StringComparison.OrdinalIgnoreCase) == true ||
                           p.L7Protocol?.Contains("ISAKMP", StringComparison.OrdinalIgnoreCase) == true ||
                           p.L7Protocol?.Contains("IKE", StringComparison.OrdinalIgnoreCase) == true;
        dict["L2TP"] = p => p.SourcePort == 1701 || p.DestinationPort == 1701;
        dict["PPTP"] = p => p.SourcePort == 1723 || p.DestinationPort == 1723;
    }

    #endregion

    #region Protocol Errors

    private static void AddProtocolErrorPredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        // HTTP 4xx/5xx errors
        dict["HTTPErrors"] = p => p.L7Protocol?.Contains("HTTP", StringComparison.OrdinalIgnoreCase) == true &&
                                 MatchesHttpErrorCode(p.Info);

        dict["DNSFailures"] = p => p.Info?.Contains("NXDOMAIN", StringComparison.OrdinalIgnoreCase) == true ||
                                  p.Info?.Contains("SERVFAIL", StringComparison.OrdinalIgnoreCase) == true;

        dict["ICMPUnreachable"] = p => p.Info?.Contains("unreachable", StringComparison.OrdinalIgnoreCase) == true;
    }

    /// <summary>
    /// Matches HTTP 4xx/5xx error status codes in packet info.
    /// </summary>
    private static bool MatchesHttpErrorCode(string? info)
    {
        if (string.IsNullOrEmpty(info))
            return false;

        ReadOnlySpan<string> errorCodes =
        [
            "400", "401", "402", "403", "404", "405", "406", "407", "408", "409",
            "410", "411", "412", "413", "414", "415", "416", "417", "418", "421",
            "422", "423", "424", "425", "426", "428", "429", "431", "451",
            "500", "501", "502", "503", "504", "505", "506", "507", "508", "510", "511"
        ];

        foreach (var code in errorCodes)
        {
            if (info.Contains($" {code} ", StringComparison.Ordinal) ||
                info.Contains($" {code}\r", StringComparison.Ordinal) ||
                info.Contains($" {code}\n", StringComparison.Ordinal) ||
                info.EndsWith($" {code}", StringComparison.Ordinal) ||
                info.StartsWith($"{code} ", StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    #endregion

    #region ICMP Types

    private static void AddIcmpTypePredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        dict["ICMPEchoRequest"] = p => p.Protocol == Protocol.ICMP &&
                                      MatchesAnyInfoPattern(p.Info, ["Echo (ping) request", "Echo request"]);
        dict["PingRequest"] = dict["ICMPEchoRequest"]; // Alias

        dict["ICMPEchoReply"] = p => p.Protocol == Protocol.ICMP &&
                                    MatchesAnyInfoPattern(p.Info, ["Echo (ping) reply", "Echo reply"]);
        dict["PingReply"] = dict["ICMPEchoReply"]; // Alias

        dict["ICMPTimeExceeded"] = p => p.Protocol == Protocol.ICMP &&
                                       p.Info?.Contains("Time-to-live exceeded", StringComparison.OrdinalIgnoreCase) == true;

        dict["ICMPRedirect"] = p => p.Protocol == Protocol.ICMP &&
                                   p.Info?.Contains("Redirect", StringComparison.OrdinalIgnoreCase) == true;
    }

    #endregion

    #region DNS Types

    private static void AddDnsTypePredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        dict["DNSQuery"] = p => (p.L7Protocol?.Contains("DNS", StringComparison.OrdinalIgnoreCase) == true ||
                               p.SourcePort == 53 || p.DestinationPort == 53) &&
                              p.Info?.Contains("Standard query", StringComparison.OrdinalIgnoreCase) == true &&
                              p.Info?.Contains("response", StringComparison.OrdinalIgnoreCase) != true;

        dict["DNSResponse"] = p => (p.L7Protocol?.Contains("DNS", StringComparison.OrdinalIgnoreCase) == true ||
                                   p.SourcePort == 53 || p.DestinationPort == 53) &&
                                  p.Info?.Contains("Standard query response", StringComparison.OrdinalIgnoreCase) == true;
    }

    #endregion

    #region Port Ranges

    private static void AddPortRangePredicates(Dictionary<string, Func<PacketInfo, bool>> dict)
    {
        // Well-known ports: 0-1023 (privileged)
        dict["WellKnownPorts"] = p => (p.SourcePort >= 0 && p.SourcePort <= 1023) ||
                                     (p.DestinationPort >= 0 && p.DestinationPort <= 1023);

        // Registered ports: 1024-49151
        dict["RegisteredPorts"] = p => (p.SourcePort >= 1024 && p.SourcePort <= 49151) ||
                                      (p.DestinationPort >= 1024 && p.DestinationPort <= 49151);

        // Ephemeral ports: 49152-65535
        dict["EphemeralPorts"] = p => (p.SourcePort >= 49152 && p.SourcePort <= 65535) ||
                                     (p.DestinationPort >= 49152 && p.DestinationPort <= 65535);
        dict["HighPorts"] = dict["EphemeralPorts"]; // Alias
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Matches if the Info field contains any of the specified patterns.
    /// </summary>
    private static bool MatchesAnyInfoPattern(string? info, ReadOnlySpan<string> patterns,
        StringComparison comparisonType = StringComparison.OrdinalIgnoreCase)
    {
        if (string.IsNullOrEmpty(info))
            return false;

        foreach (var pattern in patterns)
        {
            if (info.Contains(pattern, comparisonType))
                return true;
        }

        return false;
    }

    #endregion
}
