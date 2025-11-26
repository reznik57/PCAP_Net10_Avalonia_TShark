using System.Diagnostics.CodeAnalysis;
using System.Net;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Implementation of dashboard smart filter logic.
/// Extracted from DashboardViewModel.UpdateFilteredStatistics() (lines 568-899).
/// </summary>
public class DashboardFilterService : IDashboardFilterService
{
    public IEnumerable<PacketInfo> ApplySmartFilters(
        IEnumerable<PacketInfo> packets,
        DashboardSmartFilters filters,
        bool useAndMode = true,
        bool useNotMode = false)
    {
        if (packets == null || !filters.HasActiveFilters)
            return packets ?? Enumerable.Empty<PacketInfo>();

        var predicates = GetActivePredicates(filters);
        if (!predicates.Any())
            return packets;

        IEnumerable<PacketInfo> result;
        if (useAndMode)
        {
            // AND: all filters must match
            result = packets.Where(p => predicates.All(pred => pred(p)));
        }
        else
        {
            // OR: any filter can match
            result = packets.Where(p => predicates.Any(pred => pred(p)));
        }

        // NOT mode: invert results
        if (useNotMode)
        {
            var matching = result.ToHashSet();
            return packets.Where(p => !matching.Contains(p));
        }

        return result;
    }

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive class coupling", Justification = "Switch expression maps 38 filter types to predicates - complexity is inherent to exhaustive matching")]
    public Func<PacketInfo, bool> GetFilterPredicate(DashboardFilterType filterType)
    {
        return filterType switch
        {
            // Network Types
            DashboardFilterType.RFC1918 => p => IsRFC1918(p.SourceIP) || IsRFC1918(p.DestinationIP),
            DashboardFilterType.PublicIP => p => !IsPrivateIP(p.SourceIP) || !IsPrivateIP(p.DestinationIP),
            DashboardFilterType.APIPA => p => IsAPIPA(p.SourceIP) || IsAPIPA(p.DestinationIP),
            DashboardFilterType.IPv4 => p => IsIPv4(p.SourceIP) || IsIPv4(p.DestinationIP),
            DashboardFilterType.IPv6 => p => IsIPv6(p.SourceIP) || IsIPv6(p.DestinationIP),
            DashboardFilterType.Multicast => p => IsMulticast(p.SourceIP) || IsMulticast(p.DestinationIP),
            DashboardFilterType.Broadcast => p => IsBroadcast(p.DestinationIP),
            DashboardFilterType.Anycast => p => IsAnycast(p.SourceIP) || IsAnycast(p.DestinationIP),

            // Security
            DashboardFilterType.Insecure => p => IsInsecureProtocol(p),
            DashboardFilterType.Anomalies => p => !p.IsSecureProtocol(),

            // L7 Protocols
            DashboardFilterType.TlsV10 => p => p.L7Protocol == "TLS v1.0",
            DashboardFilterType.TlsV11 => p => p.L7Protocol == "TLS v1.1",
            DashboardFilterType.TlsV12 => p => p.L7Protocol == "TLS v1.2",
            DashboardFilterType.TlsV13 => p => p.L7Protocol == "TLS v1.3",
            DashboardFilterType.HTTP => p => p.L7Protocol == "HTTP",
            DashboardFilterType.HTTPS => p => p.L7Protocol == "HTTPS" || p.DestinationPort == 443,
            DashboardFilterType.DNS => p => p.L7Protocol == "DNS" || p.DestinationPort == 53,
            DashboardFilterType.SNMP => p => p.L7Protocol == "SNMP" || p.DestinationPort == 161 || p.DestinationPort == 162,
            DashboardFilterType.SSH => p => p.L7Protocol == "SSH" || p.DestinationPort == 22,
            DashboardFilterType.FTP => p => p.L7Protocol == "FTP" || p.DestinationPort == 21,
            DashboardFilterType.SMTP => p => p.L7Protocol == "SMTP" || p.DestinationPort == 25,
            DashboardFilterType.STUN => p => p.L7Protocol == "STUN" || p.DestinationPort == 3478,
            DashboardFilterType.DHCP => p => p.L7Protocol == "DHCP" || p.DestinationPort == 67 || p.DestinationPort == 68,

            // VPN Protocols
            DashboardFilterType.WireGuard => p => p.DestinationPort == 51820,
            DashboardFilterType.OpenVPN => p => p.DestinationPort == 1194,
            DashboardFilterType.IKEv2 => p => p.DestinationPort == 500 || p.DestinationPort == 4500,
            DashboardFilterType.IPSec => p => p.L7Protocol == "IPSec",
            DashboardFilterType.L2TP => p => p.DestinationPort == 1701,
            DashboardFilterType.PPTP => p => p.DestinationPort == 1723,

            // Traffic Patterns
            DashboardFilterType.JumboFrames => p => p.Length > 1500,
            DashboardFilterType.PrivateToPublic => p => IsPrivateIP(p.SourceIP) && !IsPrivateIP(p.DestinationIP),
            DashboardFilterType.PublicToPrivate => p => !IsPrivateIP(p.SourceIP) && IsPrivateIP(p.DestinationIP),
            DashboardFilterType.LinkLocal => p => IsLinkLocal(p.SourceIP) || IsLinkLocal(p.DestinationIP),
            DashboardFilterType.Loopback => p => IsLoopback(p.SourceIP) || IsLoopback(p.DestinationIP),
            DashboardFilterType.Suspicious => p => !p.IsSecureProtocol() && (p.SourcePort > 49152 || p.DestinationPort > 49152),
            DashboardFilterType.TcpIssues => p => p.Protocol == Protocol.TCP && p.Length < 60,
            DashboardFilterType.DnsAnomalies => p => (p.L7Protocol == "DNS" || p.DestinationPort == 53) && p.Length > 512,
            DashboardFilterType.PortScans => p => p.Protocol == Protocol.TCP && p.Length < 100,

            _ => _ => true
        };
    }

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive class coupling", Justification = "Generates descriptions for 38 filter flags - complexity is inherent to the filter count")]
    public IReadOnlyList<string> GetActiveFilterDescriptions(DashboardSmartFilters filters)
    {
        var descriptions = new List<string>();

        if (filters.Rfc1918) descriptions.Add("RFC1918");
        if (filters.PublicIP) descriptions.Add("Public IP");
        if (filters.Apipa) descriptions.Add("APIPA");
        if (filters.Ipv4) descriptions.Add("IPv4");
        if (filters.Ipv6) descriptions.Add("IPv6");
        if (filters.Multicast) descriptions.Add("Multicast");
        if (filters.Broadcast) descriptions.Add("Broadcast");
        if (filters.Anycast) descriptions.Add("Anycast");
        if (filters.Insecure) descriptions.Add("Insecure");
        if (filters.Anomalies) descriptions.Add("Anomalies");
        if (filters.TlsV10) descriptions.Add("TLS 1.0");
        if (filters.TlsV11) descriptions.Add("TLS 1.1");
        if (filters.TlsV12) descriptions.Add("TLS 1.2");
        if (filters.TlsV13) descriptions.Add("TLS 1.3");
        if (filters.Http) descriptions.Add("HTTP");
        if (filters.Https) descriptions.Add("HTTPS");
        if (filters.Dns) descriptions.Add("DNS");
        if (filters.Snmp) descriptions.Add("SNMP");
        if (filters.Ssh) descriptions.Add("SSH");
        if (filters.Ftp) descriptions.Add("FTP");
        if (filters.Smtp) descriptions.Add("SMTP");
        if (filters.Stun) descriptions.Add("STUN");
        if (filters.Dhcp) descriptions.Add("DHCP");
        if (filters.WireGuard) descriptions.Add("WireGuard");
        if (filters.OpenVPN) descriptions.Add("OpenVPN");
        if (filters.IkeV2) descriptions.Add("IKEv2");
        if (filters.Ipsec) descriptions.Add("IPSec");
        if (filters.L2tp) descriptions.Add("L2TP");
        if (filters.Pptp) descriptions.Add("PPTP");
        if (filters.JumboFrames) descriptions.Add("Jumbo Frames");
        if (filters.PrivateToPublic) descriptions.Add("Private->Public");
        if (filters.PublicToPrivate) descriptions.Add("Public->Private");
        if (filters.LinkLocal) descriptions.Add("Link-Local");
        if (filters.Loopback) descriptions.Add("Loopback");
        if (filters.Suspicious) descriptions.Add("Suspicious");
        if (filters.TcpIssues) descriptions.Add("TCP Issues");
        if (filters.DnsAnomalies) descriptions.Add("DNS Anomalies");
        if (filters.PortScans) descriptions.Add("Port Scans");

        return descriptions.AsReadOnly();
    }

    // ==================== PRIVATE HELPER METHODS ====================

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive class coupling", Justification = "Collects predicates for 38 active filters - complexity is inherent to the filter count")]
    private List<Func<PacketInfo, bool>> GetActivePredicates(DashboardSmartFilters filters)
    {
        var predicates = new List<Func<PacketInfo, bool>>();

        if (filters.Rfc1918) predicates.Add(GetFilterPredicate(DashboardFilterType.RFC1918));
        if (filters.PublicIP) predicates.Add(GetFilterPredicate(DashboardFilterType.PublicIP));
        if (filters.Apipa) predicates.Add(GetFilterPredicate(DashboardFilterType.APIPA));
        if (filters.Ipv4) predicates.Add(GetFilterPredicate(DashboardFilterType.IPv4));
        if (filters.Ipv6) predicates.Add(GetFilterPredicate(DashboardFilterType.IPv6));
        if (filters.Multicast) predicates.Add(GetFilterPredicate(DashboardFilterType.Multicast));
        if (filters.Broadcast) predicates.Add(GetFilterPredicate(DashboardFilterType.Broadcast));
        if (filters.Anycast) predicates.Add(GetFilterPredicate(DashboardFilterType.Anycast));
        if (filters.Insecure) predicates.Add(GetFilterPredicate(DashboardFilterType.Insecure));
        if (filters.Anomalies) predicates.Add(GetFilterPredicate(DashboardFilterType.Anomalies));
        if (filters.TlsV10) predicates.Add(GetFilterPredicate(DashboardFilterType.TlsV10));
        if (filters.TlsV11) predicates.Add(GetFilterPredicate(DashboardFilterType.TlsV11));
        if (filters.TlsV12) predicates.Add(GetFilterPredicate(DashboardFilterType.TlsV12));
        if (filters.TlsV13) predicates.Add(GetFilterPredicate(DashboardFilterType.TlsV13));
        if (filters.Http) predicates.Add(GetFilterPredicate(DashboardFilterType.HTTP));
        if (filters.Https) predicates.Add(GetFilterPredicate(DashboardFilterType.HTTPS));
        if (filters.Dns) predicates.Add(GetFilterPredicate(DashboardFilterType.DNS));
        if (filters.Snmp) predicates.Add(GetFilterPredicate(DashboardFilterType.SNMP));
        if (filters.Ssh) predicates.Add(GetFilterPredicate(DashboardFilterType.SSH));
        if (filters.Ftp) predicates.Add(GetFilterPredicate(DashboardFilterType.FTP));
        if (filters.Smtp) predicates.Add(GetFilterPredicate(DashboardFilterType.SMTP));
        if (filters.Stun) predicates.Add(GetFilterPredicate(DashboardFilterType.STUN));
        if (filters.Dhcp) predicates.Add(GetFilterPredicate(DashboardFilterType.DHCP));
        if (filters.WireGuard) predicates.Add(GetFilterPredicate(DashboardFilterType.WireGuard));
        if (filters.OpenVPN) predicates.Add(GetFilterPredicate(DashboardFilterType.OpenVPN));
        if (filters.IkeV2) predicates.Add(GetFilterPredicate(DashboardFilterType.IKEv2));
        if (filters.Ipsec) predicates.Add(GetFilterPredicate(DashboardFilterType.IPSec));
        if (filters.L2tp) predicates.Add(GetFilterPredicate(DashboardFilterType.L2TP));
        if (filters.Pptp) predicates.Add(GetFilterPredicate(DashboardFilterType.PPTP));
        if (filters.JumboFrames) predicates.Add(GetFilterPredicate(DashboardFilterType.JumboFrames));
        if (filters.PrivateToPublic) predicates.Add(GetFilterPredicate(DashboardFilterType.PrivateToPublic));
        if (filters.PublicToPrivate) predicates.Add(GetFilterPredicate(DashboardFilterType.PublicToPrivate));
        if (filters.LinkLocal) predicates.Add(GetFilterPredicate(DashboardFilterType.LinkLocal));
        if (filters.Loopback) predicates.Add(GetFilterPredicate(DashboardFilterType.Loopback));
        if (filters.Suspicious) predicates.Add(GetFilterPredicate(DashboardFilterType.Suspicious));
        if (filters.TcpIssues) predicates.Add(GetFilterPredicate(DashboardFilterType.TcpIssues));
        if (filters.DnsAnomalies) predicates.Add(GetFilterPredicate(DashboardFilterType.DnsAnomalies));
        if (filters.PortScans) predicates.Add(GetFilterPredicate(DashboardFilterType.PortScans));

        return predicates;
    }

    // ==================== IP CLASSIFICATION HELPERS ====================
    // Delegate to centralized NetworkFilterHelper for consistency

    private static bool IsRFC1918(string ip) => NetworkFilterHelper.IsRFC1918(ip);
    private static bool IsPrivateIP(string ip) =>
        NetworkFilterHelper.IsRFC1918(ip) || NetworkFilterHelper.IsLoopback(ip) || NetworkFilterHelper.IsLinkLocal(ip);
    private static bool IsAPIPA(string ip) => NetworkFilterHelper.IsLinkLocal(ip);
    private static bool IsIPv4(string ip) => NetworkFilterHelper.IsIPv4(ip);
    private static bool IsIPv6(string ip) => NetworkFilterHelper.IsIPv6(ip);
    private static bool IsMulticast(string ip) => NetworkFilterHelper.IsMulticast(ip);
    private static bool IsBroadcast(string ip) => NetworkFilterHelper.IsBroadcast(ip);
    private static bool IsAnycast(string ip) => NetworkFilterHelper.IsAnycast(ip);
    private static bool IsLinkLocal(string ip) => NetworkFilterHelper.IsLinkLocal(ip);
    private static bool IsLoopback(string ip) => NetworkFilterHelper.IsLoopback(ip);
    private static bool IsInsecureProtocol(PacketInfo p) =>
        NetworkFilterHelper.IsInsecurePort(p.SourcePort) ||
        NetworkFilterHelper.IsInsecurePort(p.DestinationPort) ||
        NetworkFilterHelper.IsInsecureProtocol(p.L7Protocol ?? p.Protocol.ToString());
}
