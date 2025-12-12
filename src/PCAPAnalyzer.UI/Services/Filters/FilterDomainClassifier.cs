using System;
using System.Collections.Frozen;
using System.Collections.Generic;

namespace PCAPAnalyzer.UI.Services.Filters;

/// <summary>
/// Classifies quick filters into logical domains for proper OR/AND combination.
///
/// Domain-based Logic:
/// - Filters within the SAME domain use OR logic (e.g., "Germany OR USA")
/// - Filters across DIFFERENT domains use AND logic (e.g., "Germany AND Port 443")
///
/// This allows intuitive filter combinations that match analyst expectations.
/// </summary>
public static class FilterDomainClassifier
{
    /// <summary>
    /// Filter domains for logical grouping.
    /// </summary>
    public enum FilterDomain
    {
        /// <summary>Source-specific IP address filters: SourceIP only (requires AND with dest)</summary>
        SourceIpSpecific,

        /// <summary>Dest-specific IP address filters: DestIP only (requires AND with source)</summary>
        DestIpSpecific,

        /// <summary>General IP address filters: Countries, Regions, IPv4, IPv6, etc. (check either endpoint)</summary>
        IpAddress,

        /// <summary>Traffic direction: Inbound, Outbound, Internal, PrivateToPublic, PublicToPrivate</summary>
        Direction,

        /// <summary>Port filters: specific ports or port ranges (for constraints)</summary>
        Port,

        /// <summary>L4 transport protocol: TCP, UDP, ICMP, ARP</summary>
        Transport,

        /// <summary>TCP flag filters: SYN, RST, FIN, PSH, ACK, URG</summary>
        TcpFlags,

        /// <summary>Application service identification: L7 protocols (HTTP, DNS) + VoIP (SIP, RTP)</summary>
        Service,

        /// <summary>Security indicators: deprecated crypto, cleartext auth, attack patterns</summary>
        Security,

        /// <summary>Frame characteristics: size, fragmentation, retransmissions</summary>
        Frame,

        /// <summary>Fallback for unclassified filters</summary>
        Other
    }

    /// <summary>
    /// Frozen lookup table for quick filter classification.
    /// </summary>
    private static readonly FrozenDictionary<string, FilterDomain> DomainLookup = BuildDomainLookup();

    /// <summary>
    /// Gets the domain for a quick filter code name.
    /// </summary>
    /// <param name="quickFilterCodeName">The code name of the quick filter</param>
    /// <returns>The filter domain, or Other if not recognized</returns>
    public static FilterDomain GetDomain(string? quickFilterCodeName)
    {
        if (string.IsNullOrWhiteSpace(quickFilterCodeName))
            return FilterDomain.Other;

        return DomainLookup.GetValueOrDefault(quickFilterCodeName, FilterDomain.Other);
    }

    /// <summary>
    /// Checks if two quick filters belong to the same domain (should use OR logic).
    /// </summary>
    public static bool AreSameDomain(string? filter1, string? filter2)
    {
        if (string.IsNullOrWhiteSpace(filter1) || string.IsNullOrWhiteSpace(filter2))
            return false;

        return GetDomain(filter1) == GetDomain(filter2);
    }

    /// <summary>
    /// Groups filters by their domain for proper combination logic.
    /// </summary>
    public static Dictionary<FilterDomain, List<string>> GroupByDomain(IEnumerable<string> filterNames)
    {
        var result = new Dictionary<FilterDomain, List<string>>();

        foreach (var name in filterNames)
        {
            var domain = GetDomain(name);
            if (!result.TryGetValue(domain, out var list))
            {
                list = [];
                result[domain] = list;
            }
            list.Add(name);
        }

        return result;
    }

    private static FrozenDictionary<string, FilterDomain> BuildDomainLookup()
    {
        var dict = new Dictionary<string, FilterDomain>(StringComparer.Ordinal);

        // IP Address domain - all IP-based filters
        AddToDomain(dict, FilterDomain.IpAddress,
            "IPv4", "IPv6", "RFC1918", "PublicIP", "Public", "APIPA",
            "Loopback", "LinkLocal", "Anycast", "Unicast", "Multicast", "Broadcast");

        // Direction domain
        AddToDomain(dict, FilterDomain.Direction,
            "PrivateToPublic", "PublicToPrivate", "Inbound", "Outbound", "Internal");

        // Transport (L4) domain
        AddToDomain(dict, FilterDomain.Transport,
            "TCP", "UDP", "ICMP", "ARP", "IGMP", "GRE");

        // TCP Flags domain
        AddToDomain(dict, FilterDomain.TcpFlags,
            "SYN", "TcpSyn", "SYN-ACK", "TcpSynAck", "RST", "TcpRst",
            "FIN", "TcpFin", "PSH", "TcpPsh", "ACK-only", "TcpAckOnly", "URG", "TcpUrg");

        // Service domain - L7 protocols + VoIP
        AddToDomain(dict, FilterDomain.Service,
            "HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMTP", "SNMP", "DHCP", "STUN",
            "SIP", "RTP", "RTCP", "H323", "H.323", "MGCP", "SCCP", "Skinny", "WebRTC", "Telnet");

        // Security domain
        AddToDomain(dict, FilterDomain.Security,
            "TlsV10", "TlsV11", "ObsoleteCrypto", "SSHv1", "SmbV1", "Insecure", "INSECURE",
            "CleartextAuth", "Encrypted", "SYNFlood", "SynFlood", "PortScan", "InvalidTTL", "LowTTL",
            "TLSCertError", "CertError", "TlsV12", "TlsV13",
            // VPN protocols are security-related
            "WireGuard", "OpenVPN", "IKEv2", "IPSec", "L2TP", "PPTP");

        // Frame domain
        AddToDomain(dict, FilterDomain.Frame,
            "SmallFrame", "Fragmented", "Retransmission", "Retransmissions",
            "OutOfOrder", "DuplicateAck", "DupAck", "ZeroWindow", "WindowFull",
            "JumboFrames", "KeepAlive", "ConnectionRefused");

        return dict.ToFrozenDictionary(StringComparer.Ordinal);
    }

    private static void AddToDomain(Dictionary<string, FilterDomain> dict, FilterDomain domain, params string[] filters)
    {
        foreach (var filter in filters)
        {
            dict[filter] = domain;
        }
    }
}
