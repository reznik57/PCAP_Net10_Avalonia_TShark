using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Smart Filters configuration model for FileAnalysisView.
/// Provides sophisticated filtering options including network types, traffic patterns, security filters, and custom criteria.
/// </summary>
public partial class SmartFiltersModel : ObservableObject
{
    // ==================== NETWORK TYPE FILTERS ====================

    [ObservableProperty] private bool _privateNetworks;
    [ObservableProperty] private bool _publicIPs;
    [ObservableProperty] private bool _ipv4Only;
    [ObservableProperty] private bool _ipv6Only;
    [ObservableProperty] private bool _multicast;
    [ObservableProperty] private bool _broadcast;
    [ObservableProperty] private bool _anycast;

    // ==================== TRAFFIC TYPE FILTERS ====================

    [ObservableProperty] private bool _insecure;
    [ObservableProperty] private bool _anomalies;

    // ==================== SECURITY FILTERS ====================

    [ObservableProperty] private bool _tlsV10;
    [ObservableProperty] private bool _tlsV11;
    [ObservableProperty] private bool _insecureProtocols;

    // ==================== L7 PROTOCOL FILTERS ====================

    [ObservableProperty] private bool _http;
    [ObservableProperty] private bool _https;
    [ObservableProperty] private bool _dns;
    [ObservableProperty] private bool _dhcpServer;
    [ObservableProperty] private bool _stun;

    // ==================== VPN PROTOCOL FILTERS ====================

    [ObservableProperty] private bool _wireGuard;
    [ObservableProperty] private bool _pptp;
    [ObservableProperty] private bool _smtp;

    // ==================== CUSTOM FILTERS ====================

    /// <summary>
    /// Source IP address or CIDR notation (e.g., "192.168.1.0/24")
    /// </summary>
    [ObservableProperty] private string? _sourceIPCIDR;

    /// <summary>
    /// Destination IP address or CIDR notation
    /// </summary>
    [ObservableProperty] private string? _destIPCIDR;

    /// <summary>
    /// Source port number
    /// </summary>
    [ObservableProperty] private string? _sourcePort;

    /// <summary>
    /// Destination port number
    /// </summary>
    [ObservableProperty] private string? _destPort;

    /// <summary>
    /// Protocol filter (TCP, UDP, ICMP, etc.)
    /// </summary>
    [ObservableProperty] private string? _protocol;

    // ==================== FILTER LOGIC MODE ====================

    /// <summary>
    /// Filter logic: AND (all criteria must match) vs OR (any criteria matches)
    /// </summary>
    [ObservableProperty] private FilterLogic _logic = FilterLogic.AND;

    /// <summary>
    /// Clear all filter selections
    /// </summary>
    public void Clear()
    {
        // Network Type
        PrivateNetworks = false;
        PublicIPs = false;
        Ipv4Only = false;
        Ipv6Only = false;
        Multicast = false;
        Broadcast = false;
        Anycast = false;

        // Traffic Type
        Insecure = false;
        Anomalies = false;

        // Security
        TlsV10 = false;
        TlsV11 = false;
        InsecureProtocols = false;

        // L7 Protocols
        Http = false;
        Https = false;
        Dns = false;
        DhcpServer = false;
        Stun = false;

        // VPN Protocols
        WireGuard = false;
        Pptp = false;
        Smtp = false;

        // Custom
        SourceIPCIDR = null;
        DestIPCIDR = null;
        SourcePort = null;
        DestPort = null;
        Protocol = null;

        Logic = FilterLogic.AND;
    }

    /// <summary>
    /// Check if any filters are currently active
    /// </summary>
    public bool HasActiveFilters()
    {
        return PrivateNetworks || PublicIPs || Ipv4Only || Ipv6Only || Multicast || Broadcast || Anycast ||
               Insecure || Anomalies ||
               TlsV10 || TlsV11 || InsecureProtocols ||
               Http || Https || Dns || DhcpServer || Stun ||
               WireGuard || Pptp || Smtp ||
               !string.IsNullOrWhiteSpace(SourceIPCIDR) ||
               !string.IsNullOrWhiteSpace(DestIPCIDR) ||
               !string.IsNullOrWhiteSpace(SourcePort) ||
               !string.IsNullOrWhiteSpace(DestPort) ||
               !string.IsNullOrWhiteSpace(Protocol);
    }
}

/// <summary>
/// Filter combination logic
/// </summary>
public enum FilterLogic
{
    /// <summary>
    /// All selected filters must match (AND logic)
    /// </summary>
    AND,

    /// <summary>
    /// Any selected filter can match (OR logic)
    /// </summary>
    OR,

    /// <summary>
    /// Exclude packets matching filters (NOT logic)
    /// </summary>
    NOT
}
