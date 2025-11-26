using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.Interfaces;

/// <summary>
/// Service for applying Dashboard smart filters to packet collections.
/// Extracted from DashboardViewModel to enable testability and reuse.
/// </summary>
public interface IDashboardFilterService
{
    /// <summary>
    /// Apply all active smart filters to packet collection.
    /// </summary>
    /// <param name="packets">Source packets to filter</param>
    /// <param name="filters">Active filter configuration</param>
    /// <param name="useAndMode">True for AND logic, false for OR logic</param>
    /// <param name="useNotMode">True to invert results</param>
    /// <returns>Filtered packets matching criteria</returns>
    IEnumerable<PacketInfo> ApplySmartFilters(
        IEnumerable<PacketInfo> packets,
        DashboardSmartFilters filters,
        bool useAndMode = true,
        bool useNotMode = false);

    /// <summary>
    /// Get predicate for a specific smart filter type.
    /// </summary>
    Func<PacketInfo, bool> GetFilterPredicate(DashboardFilterType filterType);

    /// <summary>
    /// Get descriptions of all active filters for UI display.
    /// </summary>
    IReadOnlyList<string> GetActiveFilterDescriptions(DashboardSmartFilters filters);
}

/// <summary>
/// Dashboard-specific smart filter types.
/// </summary>
public enum DashboardFilterType
{
    // Network Types
    RFC1918, PublicIP, APIPA, IPv4, IPv6, Multicast, Broadcast, Anycast,

    // Security
    Insecure, Anomalies,

    // L7 Protocols
    TlsV10, TlsV11, TlsV12, TlsV13, HTTP, HTTPS, DNS, SNMP, SSH, FTP, SMTP, STUN, DHCP,

    // VPN Protocols
    WireGuard, OpenVPN, IKEv2, IPSec, L2TP, PPTP,

    // Traffic Patterns
    JumboFrames, PrivateToPublic, PublicToPrivate, LinkLocal, Loopback,
    Suspicious, TcpIssues, DnsAnomalies, PortScans
}
