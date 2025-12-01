using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.Interfaces;

/// <summary>
/// Immutable anomaly frame data for thread-safe filtering.
/// Each ViewModel instance maintains its own copy.
/// </summary>
public sealed class AnomalyFrameSet
{
    public HashSet<long> AllFrames { get; init; } = new();
    public HashSet<long> HighSeverityFrames { get; init; } = new();
    public HashSet<long> TcpAnomalyFrames { get; init; } = new();
    public HashSet<long> NetworkAnomalyFrames { get; init; } = new();

    public static AnomalyFrameSet Empty { get; } = new();
}

/// <summary>
/// Service for applying Dashboard smart filters to packet collections.
/// THREAD-SAFE: All methods are stateless - anomaly data passed as parameter.
/// </summary>
public interface IDashboardFilterService
{
    /// <summary>
    /// Apply all active smart filters to packet collection.
    /// </summary>
    IEnumerable<PacketInfo> ApplySmartFilters(
        IEnumerable<PacketInfo> packets,
        DashboardSmartFilters filters,
        AnomalyFrameSet anomalyFrames,
        bool useAndMode = true,
        bool useNotMode = false);

    /// <summary>
    /// Async version with progress reporting and cancellation.
    /// Processes packets on background thread.
    /// </summary>
    Task<List<PacketInfo>> ApplySmartFiltersAsync(
        List<PacketInfo> packets,
        DashboardSmartFilters filters,
        AnomalyFrameSet anomalyFrames,
        bool useAndMode = true,
        bool useNotMode = false,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Get predicate for a specific smart filter type.
    /// </summary>
    Func<PacketInfo, bool> GetFilterPredicate(DashboardFilterType filterType, AnomalyFrameSet anomalyFrames);

    /// <summary>
    /// Get descriptions of all active filters for UI display.
    /// </summary>
    IReadOnlyList<string> GetActiveFilterDescriptions(DashboardSmartFilters filters);

    /// <summary>
    /// Build a compiled predicate for efficient single-pass filtering.
    /// </summary>
    Func<PacketInfo, bool> BuildCompiledPredicate(DashboardSmartFilters filters, AnomalyFrameSet anomalyFrames, bool useAndMode);
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
    Suspicious, TcpIssues, DnsAnomalies, PortScans,

    // TCP Performance (new)
    Retransmissions, ZeroWindow, KeepAlive, ConnectionRefused, WindowFull,

    // Security Audit (new)
    CleartextAuth, ObsoleteCrypto, DnsTunneling, ScanTraffic, NonStandardPorts, SmbV1,

    // Clean View - noise reduction (new)
    HideBroadcast, ApplicationDataOnly, HideTunnelOverhead,

    // Protocol Errors (new)
    HttpErrors, DnsFailures, IcmpUnreachable
}
