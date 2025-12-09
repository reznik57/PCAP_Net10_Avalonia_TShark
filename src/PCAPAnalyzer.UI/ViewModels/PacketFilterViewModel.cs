using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.Filtering;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Orchestrator ViewModel for enhanced packet filtering.
/// Coordinates 4 specialized component ViewModels using composition pattern.
/// Uses data-driven FilterRegistry for all filter definitions.
/// </summary>
public partial class PacketFilterViewModel : ObservableObject
{
    private readonly ITabFilterService _filterService;
    private readonly Action<PacketFilter> _onFilterApplied;
    private readonly List<string> _activePredefinedFilters = [];

    // Component ViewModels (Composition)
    public BasicFilterViewModel BasicFilters { get; }
    public QuickFilterViewModel QuickFilters { get; }
    public ProtocolFilterViewModel ProtocolFilters { get; }
    public FilterStatisticsViewModel Statistics { get; }

    public PacketFilterViewModel(ITabFilterService filterService, Action<PacketFilter> onFilterApplied)
    {
        ArgumentNullException.ThrowIfNull(filterService);
        ArgumentNullException.ThrowIfNull(onFilterApplied);
        _filterService = filterService;
        _onFilterApplied = onFilterApplied;

        // Initialize component ViewModels
        BasicFilters = new();
        QuickFilters = new();
        ProtocolFilters = new();
        Statistics = new();

        // Subscribe to component events
        BasicFilters.FilterChanged += OnComponentFilterChanged;
        QuickFilters.FilterChanged += OnComponentFilterChanged;
        ProtocolFilters.FilterChanged += OnComponentFilterChanged;

        // Subscribe to filter service changes
        _filterService.FilterChanged += OnFilterChanged;
        _filterService.PropertyChanged += OnFilterServicePropertyChanged;

        UpdateFilterStatus();
        DebugLogger.Log("[PacketFilterViewModel] Initialized with FilterRegistry-based architecture");
    }

    private void OnFilterChanged(object? sender, FilterChangedEventArgs e)
    {
        UpdateFilterStatus();
        _onFilterApplied?.Invoke(e.Filter);
    }

    private void OnFilterServicePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ITabFilterService.IsFilterActive) ||
            e.PropertyName == nameof(ITabFilterService.FilterDescription))
        {
            UpdateFilterStatus();
        }
    }

    private void OnComponentFilterChanged(object? sender, EventArgs e)
    {
        UpdateCombinedFilterDescription();
        DebugLogger.Log("[PacketFilterViewModel] Component filter changed");
    }

    private void UpdateFilterStatus()
    {
        Statistics.IsFilterActive = _filterService.IsFilterActive;
        Statistics.FilterDescription = _filterService.FilterDescription;
    }

    private void UpdateCombinedFilterDescription()
    {
        var basicDesc = BasicFilters.GetFilterDescription();
        var quickDesc = QuickFilters.GetFilterDescription();
        var protocolDesc = ProtocolFilters.GetFilterDescription();
        Statistics.UpdateFilterDescription(basicDesc, quickDesc, protocolDesc, BasicFilters.UseAndMode);
    }

    public void UpdateStatistics(long totalPackets, long filteredPackets)
    {
        Statistics.UpdatePacketCounts(totalPackets, filteredPackets);
    }

    // ==================== CORE FILTER COMMANDS ====================

    /// <summary>
    /// Applies a named filter from the FilterRegistry.
    /// This single command replaces 30+ individual Apply*Filter commands.
    /// </summary>
    [RelayCommand]
    private void ApplyNamedFilter(string filterName)
    {
        var filter = FilterRegistry.CreateFilter(filterName);
        if (filter is not null)
        {
            _filterService.ApplyFilter(filter);
            DebugLogger.Log($"[PacketFilterViewModel] Applied filter: {filterName}");
        }
        else
        {
            DebugLogger.Log($"[PacketFilterViewModel] Unknown filter: {filterName}");
        }
    }

    /// <summary>
    /// Applies all active filters from all components
    /// </summary>
    [RelayCommand]
    private void ApplyFilters()
    {
        var filters = new List<PacketFilter>();

        // Collect filters from QuickFilters
        foreach (var filterName in QuickFilters.GetActiveFilterNames())
        {
            var filter = FilterRegistry.CreateFilter(filterName);
            if (filter is not null)
                filters.Add(filter);
        }

        // Collect filters from ProtocolFilters
        foreach (var protocol in ProtocolFilters.GetActiveProtocolNames())
        {
            var filter = FilterRegistry.CreateFilter(protocol);
            if (filter is not null)
                filters.Add(filter);
        }

        // Add basic filters (IP/Port/Protocol)
        if (BasicFilters.HasActiveFilters)
        {
            var basicFilter = CreateBasicFilter();
            if (basicFilter is not null)
                filters.Add(basicFilter);
        }

        // Apply combined filters
        if (filters.Count > 0)
        {
            var combinedFilter = CombineFilters(filters, BasicFilters.UseAndMode);
            _filterService.ApplyFilter(combinedFilter);
            DebugLogger.Log($"[PacketFilterViewModel] Applied {filters.Count} combined filters");
        }
    }

    [RelayCommand]
    private void ClearAllFilters()
    {
        _filterService.ClearFilter();
        BasicFilters.ClearAll();
        QuickFilters.ClearAll();
        ProtocolFilters.ClearAll();
        Statistics.Reset();
        _activePredefinedFilters.Clear();
        DebugLogger.Log("[PacketFilterViewModel] Cleared all filters");
    }

    [RelayCommand]
    private void ClearFilter()
    {
        _filterService.ClearFilter();
        BasicFilters.IpFilterText = "";
        BasicFilters.PortFilterText = "";
        BasicFilters.ProtocolFilterText = "";
        _activePredefinedFilters.Clear();
        Statistics.CombinedFiltersDescription = "";
        Statistics.HasCombinedFilters = false;
    }

    [RelayCommand]
    private void AddPredefinedFilter(string filterName)
    {
        if (!_activePredefinedFilters.Contains(filterName))
        {
            _activePredefinedFilters.Add(filterName);
            DebugLogger.Log($"[PacketFilterViewModel] Added predefined filter: {filterName}");
        }
    }

    [RelayCommand]
    private void RemovePredefinedFilter(string filterName)
    {
        if (_activePredefinedFilters.Remove(filterName))
        {
            DebugLogger.Log($"[PacketFilterViewModel] Removed predefined filter: {filterName}");
        }
    }

    // ==================== COMPATIBILITY LAYER (Legacy Commands) ====================
    // These commands delegate to ApplyNamedFilter for backwards compatibility.
    // They will be removed once all XAML bindings are updated.

    [RelayCommand] private void ApplyRFC1918Filter() => ApplyNamedFilter("RFC1918");
    [RelayCommand] private void ApplyPublicIPFilter() => ApplyNamedFilter("PublicIP");
    [RelayCommand] private void ApplyMulticastFilter() => ApplyNamedFilter("Multicast");
    [RelayCommand] private void ApplyBroadcastFilter() => ApplyNamedFilter("Broadcast");
    [RelayCommand] private void ApplyAnycastFilter() => ApplyNamedFilter("Anycast");
    [RelayCommand] private void ApplyInsecureProtocolsFilter() => ApplyNamedFilter("InsecureProtocols");
    [RelayCommand] private void ApplyAnomaliesFilter() => ApplyNamedFilter("Anomalies");
    [RelayCommand] private void ApplyHttpFilter() => ApplyNamedFilter("HTTP");
    [RelayCommand] private void ApplyHttpsFilter() => ApplyNamedFilter("HTTPS");
    [RelayCommand] private void ApplyDnsFilter() => ApplyNamedFilter("DNS");
    [RelayCommand] private void ApplySnmpFilter() => ApplyNamedFilter("SNMP");
    [RelayCommand] private void ApplySshFilter() => ApplyNamedFilter("SSH");
    [RelayCommand] private void ApplyFtpFilter() => ApplyNamedFilter("FTP");
    [RelayCommand] private void ApplySmtpFilter() => ApplyNamedFilter("SMTP");
    [RelayCommand] private void ApplyStunFilter() => ApplyNamedFilter("STUN");
    [RelayCommand] private void ApplyDhcpServerFilter() => ApplyNamedFilter("DHCP");
    [RelayCommand] private void ApplyWireGuardFilter() => ApplyNamedFilter("WireGuard");
    [RelayCommand] private void ApplyOpenVpnFilter() => ApplyNamedFilter("OpenVPN");
    [RelayCommand] private void ApplyIkeV2Filter() => ApplyNamedFilter("IKEv2");
    [RelayCommand] private void ApplyIpsecFilter() => ApplyNamedFilter("IPSec");
    [RelayCommand] private void ApplyL2tpFilter() => ApplyNamedFilter("L2TP");
    [RelayCommand] private void ApplyPptpFilter() => ApplyNamedFilter("PPTP");
    [RelayCommand] private void ApplyTcpIssuesFilter() => ApplyNamedFilter("TCPIssues");
    [RelayCommand] private void ApplyDnsAnomaliesFilter() => ApplyNamedFilter("DNSAnomalies");
    [RelayCommand] private void ApplyPortScanFilter() => ApplyNamedFilter("PortScans");
    [RelayCommand] private void ApplyJumboFramesFilter() => ApplyNamedFilter("JumboFrames");
    [RelayCommand] private void ApplyIcmpFilter() => ApplyNamedFilter("ICMP");
    [RelayCommand] private void ApplyWebTrafficFilter() => ApplyNamedFilter("WebTraffic");
    [RelayCommand] private void ApplySecureWebFilter() => ApplyNamedFilter("SecureWeb");
    [RelayCommand] private void ApplyLinkLocalFilter() => ApplyNamedFilter("LinkLocal");
    [RelayCommand] private void ApplyLoopbackFilter() => ApplyNamedFilter("Loopback");
    [RelayCommand] private void ApplySuspiciousTrafficFilter() => ApplyNamedFilter("Suspicious");
    [RelayCommand] private void ApplyPrivateToPublicFilter() => ApplyNamedFilter("PrivateToPublic");
    [RelayCommand] private void ApplyPublicToPrivateFilter() => ApplyNamedFilter("PublicToPrivate");
    [RelayCommand] private void ApplyIPv4Filter() => ApplyNamedFilter("IPv4");
    [RelayCommand] private void ApplyIPv6Filter() => ApplyNamedFilter("IPv6");

    // ==================== HELPER METHODS ====================

    private PacketFilter? CreateBasicFilter()
    {
        // Placeholder - full implementation would handle CIDR, port ranges, etc.
        return null;
    }

    private static PacketFilter CombineFilters(List<PacketFilter> filters, bool useAndMode)
    {
        if (filters.Count == 1)
            return filters[0];

        var descriptions = filters.Select(f => f.Description).Where(d => !string.IsNullOrWhiteSpace(d));
        var combinedDescription = string.Join(useAndMode ? " AND " : " OR ", descriptions);

        return new PacketFilter
        {
            CustomPredicate = p =>
            {
                if (useAndMode)
                    return filters.All(f => f.CustomPredicate?.Invoke(p) ?? true);
                else
                    return filters.Any(f => f.CustomPredicate?.Invoke(p) ?? false);
            },
            Description = combinedDescription
        };
    }

    // ==================== COMPATIBILITY PROPERTIES ====================
    // These delegate to component ViewModels for backwards compatibility.

    public string IpFilterText { get => BasicFilters.IpFilterText; set => BasicFilters.IpFilterText = value; }
    public string PortFilterText { get => BasicFilters.PortFilterText; set => BasicFilters.PortFilterText = value; }
    public string ProtocolFilterText { get => BasicFilters.ProtocolFilterText; set => BasicFilters.ProtocolFilterText = value; }
    public string SourceIpCidrFilter { get => BasicFilters.SourceIpCidrFilter; set => BasicFilters.SourceIpCidrFilter = value; }
    public string DestIpCidrFilter { get => BasicFilters.DestIpCidrFilter; set => BasicFilters.DestIpCidrFilter = value; }
    public string SourcePortRangeFilter { get => BasicFilters.SourcePortRangeFilter; set => BasicFilters.SourcePortRangeFilter = value; }
    public string DestPortRangeFilter { get => BasicFilters.DestPortRangeFilter; set => BasicFilters.DestPortRangeFilter = value; }
    public bool NotSourceIp { get => BasicFilters.NotSourceIp; set => BasicFilters.NotSourceIp = value; }
    public bool NotDestIp { get => BasicFilters.NotDestIp; set => BasicFilters.NotDestIp = value; }
    public bool NotSourcePort { get => BasicFilters.NotSourcePort; set => BasicFilters.NotSourcePort = value; }
    public bool NotDestPort { get => BasicFilters.NotDestPort; set => BasicFilters.NotDestPort = value; }
    public bool NotProtocol { get => BasicFilters.NotProtocol; set => BasicFilters.NotProtocol = value; }
    public bool UseNotFilter { get => BasicFilters.UseNotFilter; set => BasicFilters.UseNotFilter = value; }
    public bool UseNotForAllFilters { get => BasicFilters.UseNotForAllFilters; set => BasicFilters.UseNotForAllFilters = value; }
    public bool UseAndMode { get => BasicFilters.UseAndMode; set => BasicFilters.UseAndMode = value; }
    public bool UseOrMode { get => BasicFilters.UseOrMode; set => BasicFilters.UseOrMode = value; }

    public bool Rfc1918Toggle { get => QuickFilters.Rfc1918Toggle; set => QuickFilters.Rfc1918Toggle = value; }
    public bool PublicIpToggle { get => QuickFilters.PublicIpToggle; set => QuickFilters.PublicIpToggle = value; }
    public bool ApipaToggle { get => QuickFilters.ApipaToggle; set => QuickFilters.ApipaToggle = value; }
    public bool IPv4Toggle { get => QuickFilters.IPv4Toggle; set => QuickFilters.IPv4Toggle = value; }
    public bool IPv6Toggle { get => QuickFilters.IPv6Toggle; set => QuickFilters.IPv6Toggle = value; }
    public bool LoopbackToggle { get => QuickFilters.LoopbackToggle; set => QuickFilters.LoopbackToggle = value; }
    public bool LinkLocalToggle { get => QuickFilters.LinkLocalToggle; set => QuickFilters.LinkLocalToggle = value; }
    public bool MulticastToggle { get => QuickFilters.MulticastToggle; set => QuickFilters.MulticastToggle = value; }
    public bool BroadcastToggle { get => QuickFilters.BroadcastToggle; set => QuickFilters.BroadcastToggle = value; }
    public bool AnycastToggle { get => QuickFilters.AnycastToggle; set => QuickFilters.AnycastToggle = value; }
    public bool InsecureToggle { get => QuickFilters.InsecureToggle; set => QuickFilters.InsecureToggle = value; }
    public bool AnomaliesToggle { get => QuickFilters.AnomaliesToggle; set => QuickFilters.AnomaliesToggle = value; }
    public bool SuspiciousToggle { get => QuickFilters.SuspiciousToggle; set => QuickFilters.SuspiciousToggle = value; }
    public bool TcpIssuesToggle { get => QuickFilters.TcpIssuesToggle; set => QuickFilters.TcpIssuesToggle = value; }
    public bool DnsAnomaliesToggle { get => QuickFilters.DnsAnomaliesToggle; set => QuickFilters.DnsAnomaliesToggle = value; }
    public bool PortScansToggle { get => QuickFilters.PortScansToggle; set => QuickFilters.PortScansToggle = value; }
    public bool PrivateToPublicToggle { get => QuickFilters.PrivateToPublicToggle; set => QuickFilters.PrivateToPublicToggle = value; }
    public bool PublicToPrivateToggle { get => QuickFilters.PublicToPrivateToggle; set => QuickFilters.PublicToPrivateToggle = value; }
    public bool JumboFramesToggle { get => QuickFilters.JumboFramesToggle; set => QuickFilters.JumboFramesToggle = value; }

    public bool HttpToggle { get => ProtocolFilters.HttpToggle; set => ProtocolFilters.HttpToggle = value; }
    public bool HttpsToggle { get => ProtocolFilters.HttpsToggle; set => ProtocolFilters.HttpsToggle = value; }
    public bool DnsToggle { get => ProtocolFilters.DnsToggle; set => ProtocolFilters.DnsToggle = value; }
    public bool SnmpToggle { get => ProtocolFilters.SnmpToggle; set => ProtocolFilters.SnmpToggle = value; }
    public bool SshToggle { get => ProtocolFilters.SshToggle; set => ProtocolFilters.SshToggle = value; }
    public bool FtpToggle { get => ProtocolFilters.FtpToggle; set => ProtocolFilters.FtpToggle = value; }
    public bool SmtpToggle { get => ProtocolFilters.SmtpToggle; set => ProtocolFilters.SmtpToggle = value; }
    public bool StunToggle { get => ProtocolFilters.StunToggle; set => ProtocolFilters.StunToggle = value; }
    public bool DhcpServerToggle { get => ProtocolFilters.DhcpServerToggle; set => ProtocolFilters.DhcpServerToggle = value; }
    public bool WireGuardToggle { get => ProtocolFilters.WireGuardToggle; set => ProtocolFilters.WireGuardToggle = value; }
    public bool OpenVpnToggle { get => ProtocolFilters.OpenVpnToggle; set => ProtocolFilters.OpenVpnToggle = value; }
    public bool IkeV2Toggle { get => ProtocolFilters.IkeV2Toggle; set => ProtocolFilters.IkeV2Toggle = value; }
    public bool IpsecToggle { get => ProtocolFilters.IpsecToggle; set => ProtocolFilters.IpsecToggle = value; }
    public bool L2tpToggle { get => ProtocolFilters.L2tpToggle; set => ProtocolFilters.L2tpToggle = value; }
    public bool PptpToggle { get => ProtocolFilters.PptpToggle; set => ProtocolFilters.PptpToggle = value; }
    public bool TlsV10Toggle { get => ProtocolFilters.TlsV10Toggle; set => ProtocolFilters.TlsV10Toggle = value; }
    public bool TlsV11Toggle { get => ProtocolFilters.TlsV11Toggle; set => ProtocolFilters.TlsV11Toggle = value; }
    public bool TlsV12Toggle { get => ProtocolFilters.TlsV12Toggle; set => ProtocolFilters.TlsV12Toggle = value; }
    public bool TlsV13Toggle { get => ProtocolFilters.TlsV13Toggle; set => ProtocolFilters.TlsV13Toggle = value; }
    public List<string> AvailableProtocols { get => ProtocolFilters.AvailableProtocols; set => ProtocolFilters.AvailableProtocols = value; }

    public bool IsFilterActive { get => Statistics.IsFilterActive; set => Statistics.IsFilterActive = value; }
    public string FilterDescription { get => Statistics.FilterDescription; set => Statistics.FilterDescription = value; }
    public long TotalPackets { get => Statistics.TotalPackets; set => Statistics.TotalPackets = value; }
    public long FilteredPackets { get => Statistics.FilteredPackets; set => Statistics.FilteredPackets = value; }
    public string FilterEfficiency { get => Statistics.FilterEfficiency; set => Statistics.FilterEfficiency = value; }
    public string CombinedFiltersDescription { get => Statistics.CombinedFiltersDescription; set => Statistics.CombinedFiltersDescription = value; }
    public bool HasCombinedFilters { get => Statistics.HasCombinedFilters; set => Statistics.HasCombinedFilters = value; }
    public bool IsAnalyzing { get => Statistics.IsAnalyzing; set => Statistics.IsAnalyzing = value; }
    public bool CanApplyFilters { get => Statistics.CanApplyFilters; set => Statistics.CanApplyFilters = value; }
}
