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

    /// <summary>
    /// Event raised when any quick filter changes
    /// </summary>
    public event EventHandler? FilterChanged;

    /// <summary>
    /// Gets whether any quick filter is active
    /// </summary>
    public bool HasActiveFilters =>
        Rfc1918Toggle || PublicIpToggle || ApipaToggle || IPv4Toggle || IPv6Toggle ||
        LoopbackToggle || LinkLocalToggle || MulticastToggle || BroadcastToggle ||
        AnycastToggle || InsecureToggle || AnomaliesToggle || SuspiciousToggle ||
        TcpIssuesToggle || DnsAnomaliesToggle || PortScansToggle ||
        PrivateToPublicToggle || PublicToPrivateToggle || JumboFramesToggle;

    /// <summary>
    /// Gets count of active quick filters
    /// </summary>
    public int ActiveFilterCount
    {
        get
        {
            int count = 0;
            if (Rfc1918Toggle) count++;
            if (PublicIpToggle) count++;
            if (ApipaToggle) count++;
            if (IPv4Toggle) count++;
            if (IPv6Toggle) count++;
            if (LoopbackToggle) count++;
            if (LinkLocalToggle) count++;
            if (MulticastToggle) count++;
            if (BroadcastToggle) count++;
            if (AnycastToggle) count++;
            if (InsecureToggle) count++;
            if (AnomaliesToggle) count++;
            if (SuspiciousToggle) count++;
            if (TcpIssuesToggle) count++;
            if (DnsAnomaliesToggle) count++;
            if (PortScansToggle) count++;
            if (PrivateToPublicToggle) count++;
            if (PublicToPrivateToggle) count++;
            if (JumboFramesToggle) count++;
            return count;
        }
    }

    /// <summary>
    /// Clears all quick filters
    /// </summary>
    public void ClearAll()
    {
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
        InsecureToggle = false;
        AnomaliesToggle = false;
        SuspiciousToggle = false;
        TcpIssuesToggle = false;
        DnsAnomaliesToggle = false;
        PortScansToggle = false;
        PrivateToPublicToggle = false;
        PublicToPrivateToggle = false;
        JumboFramesToggle = false;

        DebugLogger.Log("[QuickFilterViewModel] Cleared all quick filters");
        FilterChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Gets a description of active quick filters
    /// </summary>
    public string GetFilterDescription()
    {
        var active = new List<string>();

        if (Rfc1918Toggle) active.Add("RFC1918");
        if (PublicIpToggle) active.Add("Public IP");
        if (ApipaToggle) active.Add("APIPA");
        if (IPv4Toggle) active.Add("IPv4");
        if (IPv6Toggle) active.Add("IPv6");
        if (LoopbackToggle) active.Add("Loopback");
        if (LinkLocalToggle) active.Add("Link-local");
        if (MulticastToggle) active.Add("Multicast");
        if (BroadcastToggle) active.Add("Broadcast");
        if (AnycastToggle) active.Add("Anycast");
        if (InsecureToggle) active.Add("Insecure");
        if (AnomaliesToggle) active.Add("Anomalies");
        if (SuspiciousToggle) active.Add("Suspicious");
        if (TcpIssuesToggle) active.Add("TCP Issues");
        if (DnsAnomaliesToggle) active.Add("DNS Anomalies");
        if (PortScansToggle) active.Add("Port Scans");
        if (PrivateToPublicToggle) active.Add("Private→Public");
        if (PublicToPrivateToggle) active.Add("Public→Private");
        if (JumboFramesToggle) active.Add("Jumbo Frames");

        return active.Count > 0 ? string.Join(", ", active) : "";
    }

    /// <summary>
    /// Gets list of active filter names
    /// </summary>
    public List<string> GetActiveFilterNames()
    {
        var active = new List<string>();

        if (Rfc1918Toggle) active.Add("RFC1918");
        if (PublicIpToggle) active.Add("PublicIP");
        if (ApipaToggle) active.Add("APIPA");
        if (IPv4Toggle) active.Add("IPv4");
        if (IPv6Toggle) active.Add("IPv6");
        if (LoopbackToggle) active.Add("Loopback");
        if (LinkLocalToggle) active.Add("LinkLocal");
        if (MulticastToggle) active.Add("Multicast");
        if (BroadcastToggle) active.Add("Broadcast");
        if (AnycastToggle) active.Add("Anycast");
        if (InsecureToggle) active.Add("Insecure");
        if (AnomaliesToggle) active.Add("Anomalies");
        if (SuspiciousToggle) active.Add("Suspicious");
        if (TcpIssuesToggle) active.Add("TCPIssues");
        if (DnsAnomaliesToggle) active.Add("DNSAnomalies");
        if (PortScansToggle) active.Add("PortScans");
        if (PrivateToPublicToggle) active.Add("PrivateToPublic");
        if (PublicToPrivateToggle) active.Add("PublicToPrivate");
        if (JumboFramesToggle) active.Add("JumboFrames");

        return active;
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
}
