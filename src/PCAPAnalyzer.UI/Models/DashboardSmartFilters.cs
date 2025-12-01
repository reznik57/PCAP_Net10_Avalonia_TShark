using System.Diagnostics.CodeAnalysis;
using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Model for Dashboard-specific smart filter toggle states.
/// Mirrors the 30+ filter toggles in DashboardViewModel.
/// </summary>
public partial class DashboardSmartFilters : ObservableObject
{
    // ==================== NETWORK TYPE FILTERS ====================
    [ObservableProperty] private bool _rfc1918;
    [ObservableProperty] private bool _publicIP;
    [ObservableProperty] private bool _apipa;
    [ObservableProperty] private bool _ipv4;
    [ObservableProperty] private bool _ipv6;
    [ObservableProperty] private bool _multicast;
    [ObservableProperty] private bool _broadcast;
    [ObservableProperty] private bool _anycast;

    // ==================== SECURITY FILTERS ====================
    [ObservableProperty] private bool _insecure;
    [ObservableProperty] private bool _anomalies;

    // ==================== L7 PROTOCOL FILTERS ====================
    [ObservableProperty] private bool _tlsV10;
    [ObservableProperty] private bool _tlsV11;
    [ObservableProperty] private bool _tlsV12;
    [ObservableProperty] private bool _tlsV13;
    [ObservableProperty] private bool _http;
    [ObservableProperty] private bool _https;
    [ObservableProperty] private bool _dns;
    [ObservableProperty] private bool _snmp;
    [ObservableProperty] private bool _ssh;
    [ObservableProperty] private bool _ftp;
    [ObservableProperty] private bool _smtp;
    [ObservableProperty] private bool _stun;
    [ObservableProperty] private bool _dhcp;

    // ==================== VPN PROTOCOL FILTERS ====================
    [ObservableProperty] private bool _wireGuard;
    [ObservableProperty] private bool _openVPN;
    [ObservableProperty] private bool _ikeV2;
    [ObservableProperty] private bool _ipsec;
    [ObservableProperty] private bool _l2tp;
    [ObservableProperty] private bool _pptp;

    // ==================== TRAFFIC PATTERN FILTERS ====================
    [ObservableProperty] private bool _jumboFrames;
    [ObservableProperty] private bool _privateToPublic;
    [ObservableProperty] private bool _publicToPrivate;
    [ObservableProperty] private bool _linkLocal;
    [ObservableProperty] private bool _loopback;
    [ObservableProperty] private bool _suspicious;
    [ObservableProperty] private bool _tcpIssues;
    [ObservableProperty] private bool _dnsAnomalies;
    [ObservableProperty] private bool _portScans;

    // ==================== TCP PERFORMANCE FILTERS ====================
    [ObservableProperty] private bool _retransmissions;
    [ObservableProperty] private bool _zeroWindow;
    [ObservableProperty] private bool _keepAlive;
    [ObservableProperty] private bool _connectionRefused;
    [ObservableProperty] private bool _windowFull;

    // ==================== SECURITY AUDIT FILTERS ====================
    [ObservableProperty] private bool _cleartextAuth;
    [ObservableProperty] private bool _obsoleteCrypto;
    [ObservableProperty] private bool _dnsTunneling;
    [ObservableProperty] private bool _scanTraffic;
    [ObservableProperty] private bool _nonStandardPorts;
    [ObservableProperty] private bool _smbV1;

    // ==================== CLEAN VIEW (NOISE REDUCTION) ====================
    [ObservableProperty] private bool _hideBroadcast;
    [ObservableProperty] private bool _applicationDataOnly;
    [ObservableProperty] private bool _hideTunnelOverhead;

    // ==================== PROTOCOL ERROR FILTERS ====================
    [ObservableProperty] private bool _httpErrors;
    [ObservableProperty] private bool _dnsFailures;
    [ObservableProperty] private bool _icmpUnreachable;

    /// <summary>
    /// Check if any filters are active.
    /// </summary>
    [SuppressMessage("Maintainability", "CA1502:Avoid excessive class coupling", Justification = "Filter aggregation requires checking all filter flags - complexity is inherent to the domain")]
    public bool HasActiveFilters =>
        Rfc1918 || PublicIP || Apipa || Ipv4 || Ipv6 || Multicast || Broadcast || Anycast ||
        Insecure || Anomalies ||
        TlsV10 || TlsV11 || TlsV12 || TlsV13 || Http || Https || Dns || Snmp || Ssh || Ftp || Smtp || Stun || Dhcp ||
        WireGuard || OpenVPN || IkeV2 || Ipsec || L2tp || Pptp ||
        JumboFrames || PrivateToPublic || PublicToPrivate || LinkLocal || Loopback ||
        Suspicious || TcpIssues || DnsAnomalies || PortScans ||
        // TCP Performance
        Retransmissions || ZeroWindow || KeepAlive || ConnectionRefused || WindowFull ||
        // Security Audit
        CleartextAuth || ObsoleteCrypto || DnsTunneling || ScanTraffic || NonStandardPorts || SmbV1 ||
        // Clean View
        HideBroadcast || ApplicationDataOnly || HideTunnelOverhead ||
        // Protocol Errors
        HttpErrors || DnsFailures || IcmpUnreachable;

    /// <summary>
    /// Clear all filter selections.
    /// </summary>
    public void Clear()
    {
        Rfc1918 = PublicIP = Apipa = Ipv4 = Ipv6 = Multicast = Broadcast = Anycast = false;
        Insecure = Anomalies = false;
        TlsV10 = TlsV11 = TlsV12 = TlsV13 = Http = Https = Dns = Snmp = Ssh = Ftp = Smtp = Stun = Dhcp = false;
        WireGuard = OpenVPN = IkeV2 = Ipsec = L2tp = Pptp = false;
        JumboFrames = PrivateToPublic = PublicToPrivate = LinkLocal = Loopback = false;
        Suspicious = TcpIssues = DnsAnomalies = PortScans = false;
        // TCP Performance
        Retransmissions = ZeroWindow = KeepAlive = ConnectionRefused = WindowFull = false;
        // Security Audit
        CleartextAuth = ObsoleteCrypto = DnsTunneling = ScanTraffic = NonStandardPorts = SmbV1 = false;
        // Clean View
        HideBroadcast = ApplicationDataOnly = HideTunnelOverhead = false;
        // Protocol Errors
        HttpErrors = DnsFailures = IcmpUnreachable = false;
    }
}
