using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component responsible for quick filter toggles.
/// Handles IP type filters, network filters, security filters, and traffic direction filters.
/// </summary>
public partial class QuickFilterViewModel : ObservableObject
{
    // IP type filters
    [ObservableProperty] private bool _rfc1918Toggle;
    [ObservableProperty] private bool _publicIpToggle;
    [ObservableProperty] private bool _apipaToggle;
    [ObservableProperty] private bool _iPv4Toggle;
    [ObservableProperty] private bool _iPv6Toggle;
    [ObservableProperty] private bool _loopbackToggle;
    [ObservableProperty] private bool _linkLocalToggle;

    // Network filters
    [ObservableProperty] private bool _multicastToggle;
    [ObservableProperty] private bool _broadcastToggle;
    [ObservableProperty] private bool _anycastToggle;

    // Security filters
    [ObservableProperty] private bool _insecureToggle;
    [ObservableProperty] private bool _anomaliesToggle;
    [ObservableProperty] private bool _suspiciousToggle;
    [ObservableProperty] private bool _tcpIssuesToggle;
    [ObservableProperty] private bool _dnsAnomaliesToggle;
    [ObservableProperty] private bool _portScansToggle;

    // Traffic direction filters
    [ObservableProperty] private bool _privateToPublicToggle;
    [ObservableProperty] private bool _publicToPrivateToggle;

    // Special filters
    [ObservableProperty] private bool _jumboFramesToggle;

    // ==================== TCP PERFORMANCE FILTERS ====================
    /// <summary>TCP retransmissions - packet loss indicator</summary>
    [ObservableProperty] private bool _retransmissionsToggle;
    /// <summary>TCP zero window - receiver congestion</summary>
    [ObservableProperty] private bool _zeroWindowToggle;
    /// <summary>TCP keep-alive packets - idle connections</summary>
    [ObservableProperty] private bool _keepAliveToggle;
    /// <summary>Connection refused (RST) - failed connections</summary>
    [ObservableProperty] private bool _connectionRefusedToggle;
    /// <summary>Window full - sender capped by receiver</summary>
    [ObservableProperty] private bool _windowFullToggle;

    // ==================== SECURITY AUDIT FILTERS ====================
    /// <summary>Cleartext authentication (HTTP Basic, FTP USER, Telnet)</summary>
    [ObservableProperty] private bool _cleartextAuthToggle;
    /// <summary>Obsolete crypto (TLS 1.0/1.1, SSLv3)</summary>
    [ObservableProperty] private bool _obsoleteCryptoToggle;
    /// <summary>Potential DNS tunneling (long query names)</summary>
    [ObservableProperty] private bool _dnsTunnelingToggle;
    /// <summary>Nmap/scan traffic patterns</summary>
    [ObservableProperty] private bool _scanTrafficToggle;
    /// <summary>HTTP on non-standard ports</summary>
    [ObservableProperty] private bool _nonStandardPortsToggle;
    /// <summary>SMBv1 traffic (vulnerable to EternalBlue)</summary>
    [ObservableProperty] private bool _smbV1Toggle;

    // ==================== CLEAN VIEW (NOISE REDUCTION) ====================
    /// <summary>Hide broadcast/discovery chatter (ARP, SSDP, mDNS, LLMNR)</summary>
    [ObservableProperty] private bool _hideBroadcastToggle;
    /// <summary>Show only application data (packets with payload)</summary>
    [ObservableProperty] private bool _applicationDataOnlyToggle;
    /// <summary>Hide tunnel overhead (ESP, GRE, IPIP)</summary>
    [ObservableProperty] private bool _hideTunnelOverheadToggle;

    // ==================== PROTOCOL ERROR FILTERS ====================
    /// <summary>HTTP 4xx/5xx error responses</summary>
    [ObservableProperty] private bool _httpErrorsToggle;
    /// <summary>DNS failures (NXDOMAIN, SERVFAIL, REFUSED)</summary>
    [ObservableProperty] private bool _dnsFailuresToggle;
    /// <summary>ICMP unreachable messages</summary>
    [ObservableProperty] private bool _icmpUnreachableToggle;

    // ==================== MODE SELECTOR ====================
    /// <summary>
    /// True = Include mode (show matching packets), False = Exclude mode (hide matching packets)
    /// </summary>
    [ObservableProperty] private bool _isIncludeMode = true;

    /// <summary>
    /// Event raised when any quick filter changes
    /// </summary>
    public event EventHandler? FilterChanged;

    /// <summary>
    /// Gets all toggle values as an array for iteration
    /// </summary>
    private bool[] AllToggles => new[]
    {
        Rfc1918Toggle, PublicIpToggle, ApipaToggle, IPv4Toggle, IPv6Toggle,
        LoopbackToggle, LinkLocalToggle, MulticastToggle, BroadcastToggle,
        AnycastToggle, InsecureToggle, AnomaliesToggle, SuspiciousToggle,
        TcpIssuesToggle, DnsAnomaliesToggle, PortScansToggle,
        PrivateToPublicToggle, PublicToPrivateToggle, JumboFramesToggle,
        RetransmissionsToggle, ZeroWindowToggle, KeepAliveToggle,
        ConnectionRefusedToggle, WindowFullToggle,
        CleartextAuthToggle, ObsoleteCryptoToggle, DnsTunnelingToggle,
        ScanTrafficToggle, NonStandardPortsToggle, SmbV1Toggle,
        HideBroadcastToggle, ApplicationDataOnlyToggle, HideTunnelOverheadToggle,
        HttpErrorsToggle, DnsFailuresToggle, IcmpUnreachableToggle
    };

    /// <summary>
    /// Gets whether any quick filter is active
    /// </summary>
    public bool HasActiveFilters => AllToggles.Any(t => t);

    /// <summary>
    /// Gets count of active quick filters
    /// </summary>
    public int ActiveFilterCount => AllToggles.Count(t => t);

    /// <summary>
    /// Clears all quick filters
    /// </summary>
    public void ClearAll()
    {
        // Network filters
        Rfc1918Toggle = false;
        PublicIpToggle = false;
        ApipaToggle = false;
        IPv4Toggle = false;
        IPv6Toggle = false;
        LoopbackToggle = false;
        LinkLocalToggle = false;
        MulticastToggle = false;
        BroadcastToggle = false;
        AnycastToggle = false;
        // Security filters
        InsecureToggle = false;
        AnomaliesToggle = false;
        SuspiciousToggle = false;
        TcpIssuesToggle = false;
        DnsAnomaliesToggle = false;
        PortScansToggle = false;
        // Traffic direction
        PrivateToPublicToggle = false;
        PublicToPrivateToggle = false;
        JumboFramesToggle = false;
        // TCP Performance
        RetransmissionsToggle = false;
        ZeroWindowToggle = false;
        KeepAliveToggle = false;
        ConnectionRefusedToggle = false;
        WindowFullToggle = false;
        // Security Audit
        CleartextAuthToggle = false;
        ObsoleteCryptoToggle = false;
        DnsTunnelingToggle = false;
        ScanTrafficToggle = false;
        NonStandardPortsToggle = false;
        SmbV1Toggle = false;
        // Clean View
        HideBroadcastToggle = false;
        ApplicationDataOnlyToggle = false;
        HideTunnelOverheadToggle = false;
        // Protocol Errors
        HttpErrorsToggle = false;
        DnsFailuresToggle = false;
        IcmpUnreachableToggle = false;

        DebugLogger.Log("[QuickFilterViewModel] Cleared all quick filters");
        FilterChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Filter toggle metadata for description and name generation
    /// </summary>
    private IEnumerable<(Func<bool> Toggle, string DisplayName, string CodeName)> FilterMappings => new (Func<bool>, string, string)[]
    {
        (() => Rfc1918Toggle, "RFC1918", "RFC1918"),
        (() => PublicIpToggle, "Public IP", "PublicIP"),
        (() => ApipaToggle, "APIPA", "APIPA"),
        (() => IPv4Toggle, "IPv4", "IPv4"),
        (() => IPv6Toggle, "IPv6", "IPv6"),
        (() => LoopbackToggle, "Loopback", "Loopback"),
        (() => LinkLocalToggle, "Link-local", "LinkLocal"),
        (() => MulticastToggle, "Multicast", "Multicast"),
        (() => BroadcastToggle, "Broadcast", "Broadcast"),
        (() => AnycastToggle, "Anycast", "Anycast"),
        (() => InsecureToggle, "Insecure", "Insecure"),
        (() => AnomaliesToggle, "Anomalies", "Anomalies"),
        (() => SuspiciousToggle, "Suspicious", "Suspicious"),
        (() => TcpIssuesToggle, "TCP Issues", "TCPIssues"),
        (() => DnsAnomaliesToggle, "DNS Anomalies", "DNSAnomalies"),
        (() => PortScansToggle, "Port Scans", "PortScans"),
        (() => PrivateToPublicToggle, "Private→Public", "PrivateToPublic"),
        (() => PublicToPrivateToggle, "Public→Private", "PublicToPrivate"),
        (() => JumboFramesToggle, "Jumbo Frames", "JumboFrames"),
        (() => RetransmissionsToggle, "Retransmissions", "Retransmissions"),
        (() => ZeroWindowToggle, "Zero Window", "ZeroWindow"),
        (() => KeepAliveToggle, "Keep-Alive", "KeepAlive"),
        (() => ConnectionRefusedToggle, "Conn Refused", "ConnectionRefused"),
        (() => WindowFullToggle, "Window Full", "WindowFull"),
        (() => CleartextAuthToggle, "Cleartext Auth", "CleartextAuth"),
        (() => ObsoleteCryptoToggle, "Obsolete Crypto", "ObsoleteCrypto"),
        (() => DnsTunnelingToggle, "DNS Tunneling", "DNSTunneling"),
        (() => ScanTrafficToggle, "Scan Traffic", "ScanTraffic"),
        (() => NonStandardPortsToggle, "Non-Std Ports", "NonStandardPorts"),
        (() => SmbV1Toggle, "SMBv1", "SMBv1"),
        (() => HideBroadcastToggle, "Hide Broadcast", "HideBroadcast"),
        (() => ApplicationDataOnlyToggle, "App Data Only", "AppDataOnly"),
        (() => HideTunnelOverheadToggle, "Hide Tunnels", "HideTunnels"),
        (() => HttpErrorsToggle, "HTTP Errors", "HTTPErrors"),
        (() => DnsFailuresToggle, "DNS Failures", "DNSFailures"),
        (() => IcmpUnreachableToggle, "ICMP Unreachable", "ICMPUnreachable")
    };

    /// <summary>
    /// Gets a description of active quick filters
    /// </summary>
    public string GetFilterDescription()
    {
        var active = FilterMappings.Where(m => m.Toggle()).Select(m => m.DisplayName).ToList();
        return active.Count > 0 ? string.Join(", ", active) : "";
    }

    /// <summary>
    /// Gets list of active filter names
    /// </summary>
    public List<string> GetActiveFilterNames()
    {
        return FilterMappings.Where(m => m.Toggle()).Select(m => m.CodeName).ToList();
    }

    // Property change handlers to raise FilterChanged event
    partial void OnRfc1918ToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnPublicIpToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnApipaToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnIPv4ToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnIPv6ToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnLoopbackToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnLinkLocalToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnMulticastToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnBroadcastToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnAnycastToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnInsecureToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnAnomaliesToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnSuspiciousToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnTcpIssuesToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnDnsAnomaliesToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnPortScansToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnPrivateToPublicToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnPublicToPrivateToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnJumboFramesToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);

    // TCP Performance handlers
    partial void OnRetransmissionsToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnZeroWindowToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnKeepAliveToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnConnectionRefusedToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnWindowFullToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);

    // Security Audit handlers
    partial void OnCleartextAuthToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnObsoleteCryptoToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnDnsTunnelingToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnScanTrafficToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnNonStandardPortsToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnSmbV1ToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);

    // Clean View handlers
    partial void OnHideBroadcastToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnApplicationDataOnlyToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnHideTunnelOverheadToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);

    // Protocol Error handlers
    partial void OnHttpErrorsToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnDnsFailuresToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnIcmpUnreachableToggleChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
}
