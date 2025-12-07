using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// THREAD-SAFE implementation of dashboard smart filter logic.
/// All methods are stateless - anomaly data passed as parameter to avoid race conditions.
/// </summary>
public class DashboardFilterService : IDashboardFilterService
{
    // Pre-computed insecure protocol set for O(1) lookup
    private static readonly FrozenSet<string> InsecureProtocols = new[]
    {
        "HTTP", "FTP", "TELNET", "POP", "POP3", "IMAP", "SMTP", "SMB", "SMB2",
        "NFS", "TFTP", "SNMPv1", "SNMPv2c", "RDP", "TLS v1.0", "TLS v1.1"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    public IEnumerable<PacketInfo> ApplySmartFilters(
        IEnumerable<PacketInfo> packets,
        DashboardSmartFilters filters,
        AnomalyFrameSet anomalyFrames,
        bool useAndMode = true,
        bool useNotMode = false)
    {
        if (packets is null || !filters.HasActiveFilters)
            return packets ?? Enumerable.Empty<PacketInfo>();

        var predicate = BuildCompiledPredicate(filters, anomalyFrames, useAndMode);

        IEnumerable<PacketInfo> result = packets.Where(predicate);

        // NOT mode: invert results
        if (useNotMode)
        {
            var matching = result.ToHashSet();
            return packets.Where(p => !matching.Contains(p));
        }

        return result;
    }

    /// <summary>
    /// Async filter with progress reporting. Runs on background thread.
    /// Single-pass evaluation - O(n) not O(n × filters).
    /// </summary>
    public async Task<List<PacketInfo>> ApplySmartFiltersAsync(
        List<PacketInfo> packets,
        DashboardSmartFilters filters,
        AnomalyFrameSet anomalyFrames,
        bool useAndMode = true,
        bool useNotMode = false,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (packets is null || packets.Count == 0)
            return new List<PacketInfo>();

        if (!filters.HasActiveFilters)
        {
            progress?.Report(1.0);
            return new List<PacketInfo>(packets);
        }

        var predicate = BuildCompiledPredicate(filters, anomalyFrames, useAndMode);

        return await Task.Run(() =>
        {
            var count = packets.Count;
            var reportInterval = Math.Max(1, count / 100);
            var result = new List<PacketInfo>(count / 4);

            for (int i = 0; i < count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (predicate(packets[i]))
                    result.Add(packets[i]);

                if (i % reportInterval == 0)
                    progress?.Report((double)i / count);
            }

            // Handle NOT mode - invert the results
            if (useNotMode)
            {
                var matchingSet = result.ToHashSet();
                result = packets.Where(p => !matchingSet.Contains(p)).ToList();
            }

            progress?.Report(1.0);
            DebugLogger.Log($"[DashboardFilterService] Async filter complete: {result.Count:N0}/{count:N0} packets pass");
            return result;
        }, cancellationToken);
    }

    /// <summary>
    /// Build a compiled predicate for efficient single-pass filtering.
    /// </summary>
    public Func<PacketInfo, bool> BuildCompiledPredicate(DashboardSmartFilters filters, AnomalyFrameSet anomalyFrames, bool useAndMode)
    {
        var activePredicates = GetActivePredicates(filters, anomalyFrames);

        if (activePredicates.Count == 0)
            return _ => true;

        if (activePredicates.Count == 1)
            return activePredicates[0];

        // Compile into single combined predicate
        if (useAndMode)
        {
            return p =>
            {
                foreach (var pred in activePredicates)
                {
                    if (!pred(p)) return false;
                }
                return true;
            };
        }
        else
        {
            return p =>
            {
                foreach (var pred in activePredicates)
                {
                    if (pred(p)) return true;
                }
                return false;
            };
        }
    }

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive class coupling", Justification = "Switch expression maps 38 filter types to predicates - complexity is inherent to exhaustive matching")]
    public Func<PacketInfo, bool> GetFilterPredicate(DashboardFilterType filterType, AnomalyFrameSet anomalyFrames)
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

            // Security - Use actual anomaly detection results (thread-safe via parameter)
            DashboardFilterType.Insecure => p => IsInsecureProtocolFast(p),
            DashboardFilterType.Anomalies => p => anomalyFrames.AllFrames.Contains((long)p.FrameNumber),

            // L7 Protocols
            DashboardFilterType.TlsV10 => p => p.L7Protocol == "TLS v1.0",
            DashboardFilterType.TlsV11 => p => p.L7Protocol == "TLS v1.1",
            DashboardFilterType.TlsV12 => p => p.L7Protocol == "TLS v1.2",
            DashboardFilterType.TlsV13 => p => p.L7Protocol == "TLS v1.3",
            DashboardFilterType.HTTP => p => p.L7Protocol == "HTTP",
            DashboardFilterType.HTTPS => p => p.L7Protocol == "HTTPS" || p.DestinationPort == 443,
            DashboardFilterType.DNS => p => p.L7Protocol == "DNS" || p.DestinationPort == 53 || p.SourcePort == 53,
            DashboardFilterType.SNMP => p => p.L7Protocol == "SNMP" || p.DestinationPort == 161 || p.DestinationPort == 162,
            DashboardFilterType.SSH => p => p.L7Protocol == "SSH" || p.DestinationPort == 22,
            DashboardFilterType.FTP => p => p.L7Protocol == "FTP" || p.DestinationPort == 21 || p.DestinationPort == 20,
            DashboardFilterType.SMTP => p => p.L7Protocol == "SMTP" || p.DestinationPort == 25 || p.DestinationPort == 587,
            DashboardFilterType.STUN => p => p.L7Protocol == "STUN" || p.DestinationPort == 3478,
            DashboardFilterType.DHCP => p => p.L7Protocol == "DHCP" || p.DestinationPort == 67 || p.DestinationPort == 68,

            // VPN Protocols (check both source and destination)
            DashboardFilterType.WireGuard => p => p.DestinationPort == 51820 || p.SourcePort == 51820,
            DashboardFilterType.OpenVPN => p => p.DestinationPort == 1194 || p.SourcePort == 1194,
            DashboardFilterType.IKEv2 => p => p.DestinationPort == 500 || p.DestinationPort == 4500 || p.SourcePort == 500 || p.SourcePort == 4500,
            DashboardFilterType.IPSec => p => p.L7Protocol == "IPSec" || p.L7Protocol == "ESP" || p.L7Protocol == "AH",
            DashboardFilterType.L2TP => p => p.DestinationPort == 1701 || p.SourcePort == 1701,
            DashboardFilterType.PPTP => p => p.DestinationPort == 1723 || p.SourcePort == 1723,

            // Traffic Patterns
            DashboardFilterType.JumboFrames => p => p.Length >= 1501,
            DashboardFilterType.PrivateToPublic => p => IsPrivateIP(p.SourceIP) && !IsPrivateIP(p.DestinationIP),
            DashboardFilterType.PublicToPrivate => p => !IsPrivateIP(p.SourceIP) && IsPrivateIP(p.DestinationIP),
            DashboardFilterType.LinkLocal => p => IsLinkLocal(p.SourceIP) || IsLinkLocal(p.DestinationIP),
            DashboardFilterType.Loopback => p => IsLoopback(p.SourceIP) || IsLoopback(p.DestinationIP),

            // Anomaly-based filters (thread-safe via parameter)
            DashboardFilterType.Suspicious => p => anomalyFrames.HighSeverityFrames.Contains((long)p.FrameNumber),
            DashboardFilterType.TcpIssues => p => anomalyFrames.TcpAnomalyFrames.Contains((long)p.FrameNumber),
            DashboardFilterType.DnsAnomalies => p =>
                (p.L7Protocol == "DNS" || p.DestinationPort == 53 || p.SourcePort == 53) &&
                (anomalyFrames.NetworkAnomalyFrames.Contains((long)p.FrameNumber) || p.Length > 1000),
            DashboardFilterType.PortScans => p =>
                anomalyFrames.NetworkAnomalyFrames.Contains((long)p.FrameNumber) &&
                p.Protocol == Protocol.TCP &&
                (p.TcpFlags & 0x02) != 0 && (p.TcpFlags & 0x10) == 0,

            // TCP Performance (check Info field for TShark analysis markers)
            DashboardFilterType.Retransmissions => p => ContainsInfoMarker(p, "[TCP Retransmission]", "[TCP Fast Retransmission]"),
            DashboardFilterType.ZeroWindow => p => ContainsInfoMarker(p, "[TCP ZeroWindow]", "[TCP Zero Window]"),
            DashboardFilterType.KeepAlive => p => ContainsInfoMarker(p, "[TCP Keep-Alive]"),
            DashboardFilterType.ConnectionRefused => p => p.Protocol == Protocol.TCP && (p.TcpFlags & 0x04) != 0, // RST flag
            DashboardFilterType.WindowFull => p => ContainsInfoMarker(p, "[TCP Window Full]"),

            // Security Audit
            DashboardFilterType.CleartextAuth => p => IsCleartextAuth(p),
            DashboardFilterType.ObsoleteCrypto => p => p.L7Protocol == "TLS v1.0" || p.L7Protocol == "TLS v1.1" || p.L7Protocol == "SSLv3",
            DashboardFilterType.DnsTunneling => p => IsPotentialDnsTunneling(p),
            DashboardFilterType.ScanTraffic => p => IsScanTraffic(p, anomalyFrames),
            DashboardFilterType.NonStandardPorts => p => IsHttpOnNonStandardPort(p),
            DashboardFilterType.SmbV1 => p => p.DestinationPort == 445 && (p.L7Protocol == "SMB" || p.L7Protocol == "SMB2") && ContainsInfoMarker(p, "SMB1", "NT LM"),

            // Clean View (exclusion filters - return TRUE for packets to HIDE)
            DashboardFilterType.HideBroadcast => p => IsBroadcastDiscovery(p),
            DashboardFilterType.ApplicationDataOnly => p => p.Length <= 66, // Only headers, no payload
            DashboardFilterType.HideTunnelOverhead => p => p.L7Protocol == "ESP" || p.L7Protocol == "GRE" || p.L7Protocol == "IPIP",

            // Protocol Errors
            DashboardFilterType.HttpErrors => p => IsHttpError(p),
            DashboardFilterType.DnsFailures => p => IsDnsFailure(p),
            DashboardFilterType.IcmpUnreachable => p => p.Protocol == Protocol.ICMP && ContainsInfoMarker(p, "Destination unreachable", "unreachable"),

            _ => _ => true
        };
    }

    /// <summary>
    /// Fast insecure protocol check using pre-computed HashSet.
    /// </summary>
    private static bool IsInsecureProtocolFast(PacketInfo p)
    {
        var protocol = p.L7Protocol ?? p.Protocol.ToString();
        if (InsecureProtocols.Contains(protocol))
            return true;

        // Also check common insecure ports
        return NetworkFilterHelper.IsInsecurePort(p.SourcePort) ||
               NetworkFilterHelper.IsInsecurePort(p.DestinationPort);
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
        // TCP Performance
        if (filters.Retransmissions) descriptions.Add("Retransmissions");
        if (filters.ZeroWindow) descriptions.Add("Zero Window");
        if (filters.KeepAlive) descriptions.Add("Keep-Alive");
        if (filters.ConnectionRefused) descriptions.Add("Conn Refused");
        if (filters.WindowFull) descriptions.Add("Window Full");
        // Security Audit
        if (filters.CleartextAuth) descriptions.Add("Cleartext Auth");
        if (filters.ObsoleteCrypto) descriptions.Add("Old Crypto");
        if (filters.DnsTunneling) descriptions.Add("DNS Tunnel");
        if (filters.ScanTraffic) descriptions.Add("Scan Traffic");
        if (filters.NonStandardPorts) descriptions.Add("Non-Std Ports");
        if (filters.SmbV1) descriptions.Add("SMBv1");
        // Clean View
        if (filters.HideBroadcast) descriptions.Add("Hide Bcast");
        if (filters.ApplicationDataOnly) descriptions.Add("App Data");
        if (filters.HideTunnelOverhead) descriptions.Add("Hide Tunnels");
        // Protocol Errors
        if (filters.HttpErrors) descriptions.Add("HTTP Errors");
        if (filters.DnsFailures) descriptions.Add("DNS Failures");
        if (filters.IcmpUnreachable) descriptions.Add("ICMP Unreach");

        return descriptions.AsReadOnly();
    }

    // ==================== PRIVATE HELPER METHODS ====================

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive class coupling", Justification = "Collects predicates for 38 active filters - complexity is inherent to the filter count")]
    private List<Func<PacketInfo, bool>> GetActivePredicates(DashboardSmartFilters filters, AnomalyFrameSet anomalyFrames)
    {
        var predicates = new List<Func<PacketInfo, bool>>();

        if (filters.Rfc1918) predicates.Add(GetFilterPredicate(DashboardFilterType.RFC1918, anomalyFrames));
        if (filters.PublicIP) predicates.Add(GetFilterPredicate(DashboardFilterType.PublicIP, anomalyFrames));
        if (filters.Apipa) predicates.Add(GetFilterPredicate(DashboardFilterType.APIPA, anomalyFrames));
        if (filters.Ipv4) predicates.Add(GetFilterPredicate(DashboardFilterType.IPv4, anomalyFrames));
        if (filters.Ipv6) predicates.Add(GetFilterPredicate(DashboardFilterType.IPv6, anomalyFrames));
        if (filters.Multicast) predicates.Add(GetFilterPredicate(DashboardFilterType.Multicast, anomalyFrames));
        if (filters.Broadcast) predicates.Add(GetFilterPredicate(DashboardFilterType.Broadcast, anomalyFrames));
        if (filters.Anycast) predicates.Add(GetFilterPredicate(DashboardFilterType.Anycast, anomalyFrames));
        if (filters.Insecure) predicates.Add(GetFilterPredicate(DashboardFilterType.Insecure, anomalyFrames));
        if (filters.Anomalies) predicates.Add(GetFilterPredicate(DashboardFilterType.Anomalies, anomalyFrames));
        if (filters.TlsV10) predicates.Add(GetFilterPredicate(DashboardFilterType.TlsV10, anomalyFrames));
        if (filters.TlsV11) predicates.Add(GetFilterPredicate(DashboardFilterType.TlsV11, anomalyFrames));
        if (filters.TlsV12) predicates.Add(GetFilterPredicate(DashboardFilterType.TlsV12, anomalyFrames));
        if (filters.TlsV13) predicates.Add(GetFilterPredicate(DashboardFilterType.TlsV13, anomalyFrames));
        if (filters.Http) predicates.Add(GetFilterPredicate(DashboardFilterType.HTTP, anomalyFrames));
        if (filters.Https) predicates.Add(GetFilterPredicate(DashboardFilterType.HTTPS, anomalyFrames));
        if (filters.Dns) predicates.Add(GetFilterPredicate(DashboardFilterType.DNS, anomalyFrames));
        if (filters.Snmp) predicates.Add(GetFilterPredicate(DashboardFilterType.SNMP, anomalyFrames));
        if (filters.Ssh) predicates.Add(GetFilterPredicate(DashboardFilterType.SSH, anomalyFrames));
        if (filters.Ftp) predicates.Add(GetFilterPredicate(DashboardFilterType.FTP, anomalyFrames));
        if (filters.Smtp) predicates.Add(GetFilterPredicate(DashboardFilterType.SMTP, anomalyFrames));
        if (filters.Stun) predicates.Add(GetFilterPredicate(DashboardFilterType.STUN, anomalyFrames));
        if (filters.Dhcp) predicates.Add(GetFilterPredicate(DashboardFilterType.DHCP, anomalyFrames));
        if (filters.WireGuard) predicates.Add(GetFilterPredicate(DashboardFilterType.WireGuard, anomalyFrames));
        if (filters.OpenVPN) predicates.Add(GetFilterPredicate(DashboardFilterType.OpenVPN, anomalyFrames));
        if (filters.IkeV2) predicates.Add(GetFilterPredicate(DashboardFilterType.IKEv2, anomalyFrames));
        if (filters.Ipsec) predicates.Add(GetFilterPredicate(DashboardFilterType.IPSec, anomalyFrames));
        if (filters.L2tp) predicates.Add(GetFilterPredicate(DashboardFilterType.L2TP, anomalyFrames));
        if (filters.Pptp) predicates.Add(GetFilterPredicate(DashboardFilterType.PPTP, anomalyFrames));
        if (filters.JumboFrames) predicates.Add(GetFilterPredicate(DashboardFilterType.JumboFrames, anomalyFrames));
        if (filters.PrivateToPublic) predicates.Add(GetFilterPredicate(DashboardFilterType.PrivateToPublic, anomalyFrames));
        if (filters.PublicToPrivate) predicates.Add(GetFilterPredicate(DashboardFilterType.PublicToPrivate, anomalyFrames));
        if (filters.LinkLocal) predicates.Add(GetFilterPredicate(DashboardFilterType.LinkLocal, anomalyFrames));
        if (filters.Loopback) predicates.Add(GetFilterPredicate(DashboardFilterType.Loopback, anomalyFrames));
        if (filters.Suspicious) predicates.Add(GetFilterPredicate(DashboardFilterType.Suspicious, anomalyFrames));
        if (filters.TcpIssues) predicates.Add(GetFilterPredicate(DashboardFilterType.TcpIssues, anomalyFrames));
        if (filters.DnsAnomalies) predicates.Add(GetFilterPredicate(DashboardFilterType.DnsAnomalies, anomalyFrames));
        if (filters.PortScans) predicates.Add(GetFilterPredicate(DashboardFilterType.PortScans, anomalyFrames));
        // TCP Performance
        if (filters.Retransmissions) predicates.Add(GetFilterPredicate(DashboardFilterType.Retransmissions, anomalyFrames));
        if (filters.ZeroWindow) predicates.Add(GetFilterPredicate(DashboardFilterType.ZeroWindow, anomalyFrames));
        if (filters.KeepAlive) predicates.Add(GetFilterPredicate(DashboardFilterType.KeepAlive, anomalyFrames));
        if (filters.ConnectionRefused) predicates.Add(GetFilterPredicate(DashboardFilterType.ConnectionRefused, anomalyFrames));
        if (filters.WindowFull) predicates.Add(GetFilterPredicate(DashboardFilterType.WindowFull, anomalyFrames));
        // Security Audit
        if (filters.CleartextAuth) predicates.Add(GetFilterPredicate(DashboardFilterType.CleartextAuth, anomalyFrames));
        if (filters.ObsoleteCrypto) predicates.Add(GetFilterPredicate(DashboardFilterType.ObsoleteCrypto, anomalyFrames));
        if (filters.DnsTunneling) predicates.Add(GetFilterPredicate(DashboardFilterType.DnsTunneling, anomalyFrames));
        if (filters.ScanTraffic) predicates.Add(GetFilterPredicate(DashboardFilterType.ScanTraffic, anomalyFrames));
        if (filters.NonStandardPorts) predicates.Add(GetFilterPredicate(DashboardFilterType.NonStandardPorts, anomalyFrames));
        if (filters.SmbV1) predicates.Add(GetFilterPredicate(DashboardFilterType.SmbV1, anomalyFrames));
        // Clean View (these are exclusion filters - need special handling)
        if (filters.HideBroadcast) predicates.Add(p => !GetFilterPredicate(DashboardFilterType.HideBroadcast, anomalyFrames)(p));
        if (filters.ApplicationDataOnly) predicates.Add(p => !GetFilterPredicate(DashboardFilterType.ApplicationDataOnly, anomalyFrames)(p));
        if (filters.HideTunnelOverhead) predicates.Add(p => !GetFilterPredicate(DashboardFilterType.HideTunnelOverhead, anomalyFrames)(p));
        // Protocol Errors
        if (filters.HttpErrors) predicates.Add(GetFilterPredicate(DashboardFilterType.HttpErrors, anomalyFrames));
        if (filters.DnsFailures) predicates.Add(GetFilterPredicate(DashboardFilterType.DnsFailures, anomalyFrames));
        if (filters.IcmpUnreachable) predicates.Add(GetFilterPredicate(DashboardFilterType.IcmpUnreachable, anomalyFrames));

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

    // ==================== ADVANCED FILTER HELPERS ====================

    /// <summary>Check if Info field contains any of the specified markers (case-insensitive)</summary>
    private static bool ContainsInfoMarker(PacketInfo p, params string[] markers)
    {
        if (string.IsNullOrEmpty(p.Info)) return false;
        foreach (var marker in markers)
        {
            if (p.Info.Contains(marker, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>Detect cleartext authentication (HTTP Basic, FTP USER/PASS, Telnet login)</summary>
    private static bool IsCleartextAuth(PacketInfo p)
    {
        // HTTP Basic Auth
        if (p.L7Protocol == "HTTP" && ContainsInfoMarker(p, "Authorization: Basic", "WWW-Authenticate"))
            return true;
        // FTP credentials
        if (p.L7Protocol == "FTP" && ContainsInfoMarker(p, "USER ", "PASS "))
            return true;
        // Telnet (any traffic on port 23 is cleartext)
        if (p.DestinationPort == 23 || p.SourcePort == 23)
            return true;
        // POP3 credentials
        if ((p.DestinationPort == 110 || p.SourcePort == 110) && ContainsInfoMarker(p, "USER ", "PASS "))
            return true;
        return false;
    }

    /// <summary>Detect potential DNS tunneling (long query names, high query frequency)</summary>
    private static bool IsPotentialDnsTunneling(PacketInfo p)
    {
        if (p.L7Protocol != "DNS" && p.DestinationPort != 53 && p.SourcePort != 53)
            return false;
        // Long DNS queries often indicate tunneling (base64 encoded data)
        if (p.Length > 200)
            return true;
        // Check for suspicious TXT queries
        if (ContainsInfoMarker(p, "TXT", "NULL"))
            return true;
        return false;
    }

    /// <summary>Detect scan traffic patterns (SYN without ACK, unusual flag combinations)</summary>
    private static bool IsScanTraffic(PacketInfo p, AnomalyFrameSet anomalyFrames)
    {
        if (p.Protocol != Protocol.TCP) return false;
        // SYN scan: SYN flag set, ACK not set
        bool isSynOnly = (p.TcpFlags & 0x02) != 0 && (p.TcpFlags & 0x10) == 0;
        // NULL scan: no flags
        bool isNullScan = p.TcpFlags == 0;
        // FIN scan: FIN only
        bool isFinScan = p.TcpFlags == 0x01;
        // XMAS scan: FIN, PSH, URG
        bool isXmasScan = p.TcpFlags == 0x29;
        return isSynOnly || isNullScan || isFinScan || isXmasScan ||
               anomalyFrames.NetworkAnomalyFrames.Contains((long)p.FrameNumber);
    }

    /// <summary>Detect HTTP on non-standard ports</summary>
    private static bool IsHttpOnNonStandardPort(PacketInfo p)
    {
        if (p.L7Protocol != "HTTP") return false;
        // Standard HTTP ports: 80, 8080, 8000, 8888
        var standardPorts = new[] { 80, 8080, 8000, 8888, 3128 };
        return !standardPorts.Contains(p.DestinationPort) && !standardPorts.Contains(p.SourcePort);
    }

    /// <summary>Detect broadcast/discovery protocols (ARP, SSDP, mDNS, LLMNR, NetBIOS)</summary>
    private static bool IsBroadcastDiscovery(PacketInfo p)
    {
        // ARP
        if (p.Protocol == Protocol.ARP) return true;
        // SSDP (port 1900)
        if (p.DestinationPort == 1900 || p.SourcePort == 1900) return true;
        // mDNS (port 5353)
        if (p.DestinationPort == 5353 || p.SourcePort == 5353) return true;
        // LLMNR (port 5355)
        if (p.DestinationPort == 5355 || p.SourcePort == 5355) return true;
        // NetBIOS Name Service (port 137)
        if (p.DestinationPort == 137 || p.SourcePort == 137) return true;
        // Broadcast destination
        if (IsBroadcast(p.DestinationIP)) return true;
        return false;
    }

    /// <summary>Detect HTTP 4xx/5xx errors</summary>
    private static bool IsHttpError(PacketInfo p)
    {
        if (p.L7Protocol != "HTTP") return false;
        // Look for HTTP response codes in Info
        return ContainsInfoMarker(p, " 4", " 5") && ContainsInfoMarker(p, "HTTP/1", "HTTP/2");
    }

    /// <summary>Detect DNS failures (NXDOMAIN, SERVFAIL, REFUSED)</summary>
    private static bool IsDnsFailure(PacketInfo p)
    {
        if (p.L7Protocol != "DNS" && p.DestinationPort != 53 && p.SourcePort != 53)
            return false;
        return ContainsInfoMarker(p, "NXDOMAIN", "SERVFAIL", "REFUSED", "No such name", "Server failure");
    }
}
