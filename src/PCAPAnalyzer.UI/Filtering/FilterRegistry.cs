using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;

namespace PCAPAnalyzer.UI.Filtering;

/// <summary>
/// Filter definition with predicate and metadata.
/// </summary>
public sealed record FilterDefinition(
    string Name,
    string Description,
    string Category,
    Func<PacketInfo, bool> Predicate,
    bool IsPlaceholder = false
);

/// <summary>
/// Data-driven filter registry. Replaces 100+ lines of switch statements and 30+ RelayCommands
/// with a single dictionary lookup. Filters are categorized for UI grouping.
/// </summary>
public static class FilterRegistry
{

    /// <summary>
    /// All registered filters, keyed by name.
    /// </summary>
    public static IReadOnlyDictionary<string, FilterDefinition> Filters { get; } = BuildRegistry();

    /// <summary>
    /// Gets filter by name, returns null if not found.
    /// </summary>
    public static FilterDefinition? Get(string name) =>
        Filters.TryGetValue(name, out var def) ? def : null;

    /// <summary>
    /// Creates a PacketFilter from a named filter definition.
    /// </summary>
    public static PacketFilter? CreateFilter(string name)
    {
        if (!Filters.TryGetValue(name, out var def))
            return null;

        return new PacketFilter
        {
            CustomPredicate = def.Predicate,
            Description = def.Description
        };
    }

    /// <summary>
    /// Gets all filters in a category.
    /// </summary>
    public static IEnumerable<FilterDefinition> GetByCategory(string category)
    {
        foreach (var kvp in Filters)
        {
            if (kvp.Value.Category == category)
                yield return kvp.Value;
        }
    }

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Data-driven registry initialization - complexity is inherent to number of filters")]
    private static Dictionary<string, FilterDefinition> BuildRegistry()
    {
        var registry = new Dictionary<string, FilterDefinition>(StringComparer.OrdinalIgnoreCase);

        // ==================== NETWORK ADDRESS FILTERS ====================
        AddFilter(registry, "RFC1918", "RFC1918 Private IP", "Network",
            p => NetworkFilterHelper.IsRFC1918(p.SourceIP) || NetworkFilterHelper.IsRFC1918(p.DestinationIP));

        AddFilter(registry, "PublicIP", "Public IP", "Network",
            p => !(NetworkFilterHelper.IsRFC1918(p.SourceIP) || NetworkFilterHelper.IsLoopback(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.SourceIP)) ||
                 !(NetworkFilterHelper.IsRFC1918(p.DestinationIP) || NetworkFilterHelper.IsLoopback(p.DestinationIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP)));

        AddFilter(registry, "APIPA", "APIPA (169.254.x.x)", "Network",
            p => NetworkFilterHelper.IsLinkLocal(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP));

        AddFilter(registry, "IPv4", "IPv4 Only", "Network",
            p => NetworkFilterHelper.IsIPv4(p.SourceIP) || NetworkFilterHelper.IsIPv4(p.DestinationIP));

        AddFilter(registry, "IPv6", "IPv6 Only", "Network",
            p => NetworkFilterHelper.IsIPv6(p.SourceIP) || NetworkFilterHelper.IsIPv6(p.DestinationIP));

        AddFilter(registry, "Loopback", "Loopback", "Network",
            p => NetworkFilterHelper.IsLoopback(p.SourceIP) || NetworkFilterHelper.IsLoopback(p.DestinationIP));

        AddFilter(registry, "LinkLocal", "Link-local", "Network",
            p => NetworkFilterHelper.IsLinkLocal(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP));

        AddFilter(registry, "Multicast", "Multicast", "Network",
            p => NetworkFilterHelper.IsMulticast(p.DestinationIP));

        AddFilter(registry, "Broadcast", "Broadcast", "Network",
            p => NetworkFilterHelper.IsBroadcast(p.DestinationIP));

        AddFilter(registry, "Anycast", "Anycast", "Network",
            p => NetworkFilterHelper.IsAnycast(p.DestinationIP));

        // ==================== TRAFFIC DIRECTION FILTERS ====================
        AddFilter(registry, "PrivateToPublic", "Private → Public", "Direction",
            p => (NetworkFilterHelper.IsRFC1918(p.SourceIP) || NetworkFilterHelper.IsLoopback(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.SourceIP)) &&
                 !(NetworkFilterHelper.IsRFC1918(p.DestinationIP) || NetworkFilterHelper.IsLoopback(p.DestinationIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP)));

        AddFilter(registry, "PublicToPrivate", "Public → Private", "Direction",
            p => !(NetworkFilterHelper.IsRFC1918(p.SourceIP) || NetworkFilterHelper.IsLoopback(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.SourceIP)) &&
                 (NetworkFilterHelper.IsRFC1918(p.DestinationIP) || NetworkFilterHelper.IsLoopback(p.DestinationIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP)));

        // ==================== L7 PROTOCOL FILTERS ====================
        AddFilter(registry, "HTTP", "L7 Protocol: HTTP", "Protocol",
            p => p.L7Protocol == "HTTP" || p.L7Protocol == "HTTP/2" || p.L7Protocol == "HTTP/3");

        AddFilter(registry, "HTTPS", "L7 Protocol: HTTPS/TLS", "Protocol",
            p => !string.IsNullOrWhiteSpace(p.L7Protocol) &&
                 (p.L7Protocol.StartsWith("TLS", StringComparison.Ordinal) || p.L7Protocol == "SSL" || p.L7Protocol == "HTTPS"));

        AddFilter(registry, "DNS", "L7 Protocol: DNS", "Protocol",
            p => p.L7Protocol == "DNS");

        AddFilter(registry, "SNMP", "L7 Protocol: SNMP", "Protocol",
            p => !string.IsNullOrWhiteSpace(p.L7Protocol) && p.L7Protocol.StartsWith("SNMP", StringComparison.Ordinal));

        AddFilter(registry, "SSH", "L7 Protocol: SSH", "Protocol",
            p => p.L7Protocol == "SSH" || p.L7Protocol == "SSHv2");

        AddFilter(registry, "FTP", "L7 Protocol: FTP", "Protocol",
            p => p.L7Protocol == "FTP" || p.L7Protocol == "FTPS" || p.L7Protocol == "SFTP");

        AddFilter(registry, "SMTP", "L7 Protocol: SMTP", "Protocol",
            p => p.L7Protocol == "SMTP" || p.L7Protocol == "SMTPS");

        AddFilter(registry, "STUN", "L7 Protocol: STUN/TURN", "Protocol",
            p => p.L7Protocol == "STUN" || p.L7Protocol == "TURN");

        AddFilter(registry, "DHCP", "DHCP Server (UDP dst:68)", "Protocol",
            p => p.Protocol == Protocol.UDP && p.DestinationPort == 68);

        AddFilter(registry, "ICMP", "ICMP Traffic", "Protocol",
            p => p.Protocol == Protocol.ICMP);

        // ==================== VPN PROTOCOL FILTERS ====================
        AddFilter(registry, "WireGuard", "VPN: WireGuard", "VPN",
            p => p.L7Protocol == "WireGuard" || (p.Protocol == Protocol.UDP && p.DestinationPort == 51820));

        AddFilter(registry, "OpenVPN", "VPN: OpenVPN", "VPN",
            p => p.L7Protocol == "OpenVPN" ||
                 (p.Protocol == Protocol.UDP && p.DestinationPort == 1194) ||
                 (p.Protocol == Protocol.TCP && p.DestinationPort == 1194));

        AddFilter(registry, "IKEv2", "VPN: IKEv2/IKE", "VPN",
            p => p.L7Protocol == "IKEv2" || p.L7Protocol == "IKE" || p.L7Protocol == "ISAKMP");

        AddFilter(registry, "IPSec", "VPN: IPSec", "VPN",
            p => p.L7Protocol == "ESP" || p.L7Protocol == "AH" || p.L7Protocol == "IPSec" || p.L7Protocol == "ISAKMP");

        AddFilter(registry, "L2TP", "VPN: L2TP", "VPN",
            p => p.L7Protocol == "L2TP");

        AddFilter(registry, "PPTP", "VPN: PPTP", "VPN",
            p => p.L7Protocol == "PPTP" || (p.Protocol == Protocol.TCP && p.DestinationPort == 1723));

        // ==================== TLS VERSION FILTERS ====================
        AddFilter(registry, "TLSv1.0", "L7 Protocol: TLSv1.0", "TLS",
            p => p.L7Protocol == "TLSv1.0" || p.L7Protocol == "TLSv1");

        AddFilter(registry, "TLSv1.1", "L7 Protocol: TLSv1.1", "TLS",
            p => p.L7Protocol == "TLSv1.1");

        AddFilter(registry, "TLSv1.2", "L7 Protocol: TLSv1.2", "TLS",
            p => p.L7Protocol == "TLSv1.2");

        AddFilter(registry, "TLSv1.3", "L7 Protocol: TLSv1.3", "TLS",
            p => p.L7Protocol == "TLSv1.3");

        // ==================== SECURITY/ANALYSIS FILTERS ====================
        AddFilter(registry, "InsecureProtocols", "Insecure Protocols", "Security",
            p => NetworkFilterHelper.IsInsecureProtocol(p.L7Protocol ?? p.Protocol.ToString()));

        AddFilter(registry, "JumboFrames", "Jumbo Frames (>1500 bytes)", "Security",
            p => p.Length > 1500);

        AddFilter(registry, "WebTraffic", "Web Traffic (HTTP/HTTPS)", "Security",
            p => p.SourcePort == 80 || p.DestinationPort == 80 ||
                 p.SourcePort == 443 || p.DestinationPort == 443 ||
                 p.L7Protocol == "HTTP" || (!string.IsNullOrWhiteSpace(p.L7Protocol) && p.L7Protocol.StartsWith("TLS", StringComparison.Ordinal)));

        AddFilter(registry, "SecureWeb", "Secure Web (HTTPS)", "Security",
            p => p.SourcePort == 443 || p.DestinationPort == 443 ||
                 (!string.IsNullOrWhiteSpace(p.L7Protocol) && (p.L7Protocol.StartsWith("TLS", StringComparison.Ordinal) || p.L7Protocol == "HTTPS")));

        // ==================== PLACEHOLDER FILTERS (require external services) ====================
        AddPlaceholder(registry, "Anomalies", "Anomalies", "Analysis");
        AddPlaceholder(registry, "Suspicious", "Suspicious Traffic", "Analysis");
        AddPlaceholder(registry, "TCPIssues", "TCP Issues", "Analysis");
        AddPlaceholder(registry, "DNSAnomalies", "DNS Anomalies", "Analysis");
        AddPlaceholder(registry, "PortScans", "Port Scans", "Analysis");

        return registry;
    }

    private static void AddFilter(
        Dictionary<string, FilterDefinition> registry,
        string name,
        string description,
        string category,
        Func<PacketInfo, bool> predicate)
    {
        registry[name] = new FilterDefinition(name, description, category, predicate);
    }

    private static void AddPlaceholder(
        Dictionary<string, FilterDefinition> registry,
        string name,
        string description,
        string category)
    {
        registry[name] = new FilterDefinition(name, description, category, _ => false, IsPlaceholder: true);
    }
}
