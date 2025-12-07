using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Orchestrator ViewModel for enhanced packet filtering.
/// Coordinates 4 specialized component ViewModels using composition pattern.
/// Reduced from 1,398 lines to ~400 lines through component-based architecture.
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
        _filterService = filterService ?? throw new ArgumentNullException(nameof(filterService));
        _onFilterApplied = onFilterApplied ?? throw new ArgumentNullException(nameof(onFilterApplied));

        // Initialize component ViewModels
        BasicFilters = new BasicFilterViewModel();
        QuickFilters = new QuickFilterViewModel();
        ProtocolFilters = new ProtocolFilterViewModel();
        Statistics = new FilterStatisticsViewModel();

        // Subscribe to component events
        BasicFilters.FilterChanged += OnComponentFilterChanged;
        QuickFilters.FilterChanged += OnComponentFilterChanged;
        ProtocolFilters.FilterChanged += OnComponentFilterChanged;

        // Subscribe to filter service changes
        _filterService.FilterChanged += OnFilterChanged;
        _filterService.PropertyChanged += OnFilterServicePropertyChanged;

        UpdateFilterStatus();
        DebugLogger.Log("[EnhancedFilterViewModel] Initialized with component-based architecture");
    }

    /// <summary>
    /// Handles filter changes from the global filter service
    /// </summary>
    private void OnFilterChanged(object? sender, FilterChangedEventArgs e)
    {
        UpdateFilterStatus();
        _onFilterApplied?.Invoke(e.Filter);
    }

    /// <summary>
    /// Handles property changes from the filter service
    /// </summary>
    private void OnFilterServicePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ITabFilterService.IsFilterActive) ||
            e.PropertyName == nameof(ITabFilterService.FilterDescription))
        {
            UpdateFilterStatus();
        }
    }

    /// <summary>
    /// Handles filter changes from component ViewModels
    /// </summary>
    private void OnComponentFilterChanged(object? sender, EventArgs e)
    {
        UpdateCombinedFilterDescription();
        DebugLogger.Log("[EnhancedFilterViewModel] Component filter changed");
    }

    /// <summary>
    /// Updates filter status from the global filter service
    /// </summary>
    private void UpdateFilterStatus()
    {
        Statistics.IsFilterActive = _filterService.IsFilterActive;
        Statistics.FilterDescription = _filterService.FilterDescription;
    }

    /// <summary>
    /// Updates the combined filter description from all components
    /// </summary>
    private void UpdateCombinedFilterDescription()
    {
        var basicDesc = BasicFilters.GetFilterDescription();
        var quickDesc = QuickFilters.GetFilterDescription();
        var protocolDesc = ProtocolFilters.GetFilterDescription();

        Statistics.UpdateFilterDescription(basicDesc, quickDesc, protocolDesc, BasicFilters.UseAndMode);
    }

    /// <summary>
    /// Updates packet statistics
    /// </summary>
    public void UpdateStatistics(long totalPackets, long filteredPackets)
    {
        Statistics.UpdatePacketCounts(totalPackets, filteredPackets);
    }

    // ==================== FILTER APPLICATION COMMANDS ====================

    /// <summary>
    /// Applies all active filters from all components
    /// </summary>
    [RelayCommand]
    private void ApplyFilters()
    {
        var filters = new List<PacketFilter>();

        // Collect filters from QuickFilters
        var quickFilterNames = QuickFilters.GetActiveFilterNames();
        foreach (var filterName in quickFilterNames)
        {
            var filter = GetPredefinedFilterByName(filterName);
            if (filter != null)
                filters.Add(filter);
        }

        // Collect filters from ProtocolFilters
        var protocolNames = ProtocolFilters.GetActiveProtocolNames();
        foreach (var protocol in protocolNames)
        {
            var filter = GetProtocolFilter(protocol);
            if (filter != null)
                filters.Add(filter);
        }

        // Add basic filters (IP/Port/Protocol)
        if (BasicFilters.HasActiveFilters)
        {
            var basicFilter = CreateBasicFilter();
            if (basicFilter != null)
                filters.Add(basicFilter);
        }

        // Apply combined filters
        if (filters.Count > 0)
        {
            var combinedFilter = CombineFilters(filters, BasicFilters.UseAndMode);
            _filterService.ApplyFilter(combinedFilter);
            DebugLogger.Log($"[EnhancedFilterViewModel] Applied {filters.Count} combined filters");
        }
        else
        {
            DebugLogger.Log("[EnhancedFilterViewModel] No active filters to apply");
        }
    }

    /// <summary>
    /// Clears all filters across all components
    /// </summary>
    [RelayCommand]
    private void ClearAllFilters()
    {
        _filterService.ClearFilter();
        BasicFilters.ClearAll();
        QuickFilters.ClearAll();
        ProtocolFilters.ClearAll();
        Statistics.Reset();
        _activePredefinedFilters.Clear();

        DebugLogger.Log("[EnhancedFilterViewModel] Cleared all filters");
    }

    /// <summary>
    /// Clears only the custom filter inputs
    /// </summary>
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

    // ==================== QUICK FILTER COMMANDS ====================

    [RelayCommand]
    private void ApplyRFC1918Filter()
    {
        _filterService.ApplyRFC1918Filter();
    }

    [RelayCommand]
    private void ApplyPublicIPFilter()
    {
        _filterService.ApplyPublicIPFilter();
    }

    [RelayCommand]
    private void ApplyMulticastFilter()
    {
        _filterService.ApplyMulticastFilter();
    }

    [RelayCommand]
    private void ApplyBroadcastFilter()
    {
        _filterService.ApplyBroadcastFilter();
    }

    [RelayCommand]
    private void ApplyAnycastFilter()
    {
        _filterService.ApplyAnycastFilter();
    }

    [RelayCommand]
    private void ApplyInsecureProtocolsFilter()
    {
        _filterService.ApplyInsecureProtocolsFilter();
    }

    [RelayCommand]
    private void ApplyAnomaliesFilter()
    {
        _filterService.ApplyAnomalyFilter();
    }

    // ==================== L7 PROTOCOL FILTER COMMANDS ====================

    [RelayCommand]
    private void ApplyHttpFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.L7Protocol == "HTTP" || p.L7Protocol == "HTTP/2" || p.L7Protocol == "HTTP/3",
            "L7 Protocol: HTTP"
        );
    }

    [RelayCommand]
    private void ApplyHttpsFilter()
    {
        _filterService.ApplyCustomFilter(
            p => !string.IsNullOrWhiteSpace(p.L7Protocol) &&
                 (p.L7Protocol.StartsWith("TLS", StringComparison.Ordinal) || p.L7Protocol == "SSL" || p.L7Protocol == "HTTPS"),
            "L7 Protocol: HTTPS/TLS"
        );
    }

    [RelayCommand]
    private void ApplyDnsFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.L7Protocol == "DNS",
            "L7 Protocol: DNS"
        );
    }

    [RelayCommand]
    private void ApplySnmpFilter()
    {
        _filterService.ApplyCustomFilter(
            p => !string.IsNullOrWhiteSpace(p.L7Protocol) && p.L7Protocol.StartsWith("SNMP", StringComparison.Ordinal),
            "L7 Protocol: SNMP"
        );
    }

    [RelayCommand]
    private void ApplySshFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.L7Protocol == "SSH" || p.L7Protocol == "SSHv2",
            "L7 Protocol: SSH"
        );
    }

    [RelayCommand]
    private void ApplyFtpFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.L7Protocol == "FTP" || p.L7Protocol == "FTPS" || p.L7Protocol == "SFTP",
            "L7 Protocol: FTP"
        );
    }

    [RelayCommand]
    private void ApplySmtpFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.L7Protocol == "SMTP" || p.L7Protocol == "SMTPS",
            "L7 Protocol: SMTP"
        );
    }

    [RelayCommand]
    private void ApplyStunFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.L7Protocol == "STUN" || p.L7Protocol == "TURN",
            "L7 Protocol: STUN/TURN"
        );
    }

    [RelayCommand]
    private void ApplyDhcpServerFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.Protocol == Protocol.UDP && p.DestinationPort == 68,
            "DHCP Server (UDP dst:68)"
        );
    }

    // ==================== VPN PROTOCOL FILTER COMMANDS ====================

    [RelayCommand]
    private void ApplyWireGuardFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.L7Protocol == "WireGuard" ||
                 (p.Protocol == Protocol.UDP && p.DestinationPort == 51820),
            "VPN: WireGuard"
        );
    }

    [RelayCommand]
    private void ApplyOpenVpnFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.L7Protocol == "OpenVPN" ||
                 (p.Protocol == Protocol.UDP && p.DestinationPort == 1194) ||
                 (p.Protocol == Protocol.TCP && p.DestinationPort == 1194),
            "VPN: OpenVPN"
        );
    }

    [RelayCommand]
    private void ApplyIkeV2Filter()
    {
        _filterService.ApplyCustomFilter(
            p => p.L7Protocol == "IKEv2" || p.L7Protocol == "IKE" || p.L7Protocol == "ISAKMP",
            "VPN: IKEv2/IKE"
        );
    }

    [RelayCommand]
    private void ApplyIpsecFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.L7Protocol == "ESP" || p.L7Protocol == "AH" ||
                 p.L7Protocol == "IPSec" || p.L7Protocol == "ISAKMP",
            "VPN: IPSec"
        );
    }

    [RelayCommand]
    private void ApplyL2tpFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.L7Protocol == "L2TP",
            "VPN: L2TP"
        );
    }

    [RelayCommand]
    private void ApplyPptpFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.L7Protocol == "PPTP" || (p.Protocol == Protocol.TCP && p.DestinationPort == 1723),
            "VPN: PPTP"
        );
    }

    // ==================== HELPER METHODS ====================

    /// <summary>
    /// Gets a predefined filter by name
    /// </summary>
    private PacketFilter? GetPredefinedFilterByName(string filterName)
    {
        return filterName switch
        {
            "RFC1918" => new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsRFC1918(p.SourceIP) || NetworkFilterHelper.IsRFC1918(p.DestinationIP),
                Description = "RFC1918 Private IP"
            },
            "PublicIP" => new PacketFilter
            {
                CustomPredicate = p => !(NetworkFilterHelper.IsRFC1918(p.SourceIP) || NetworkFilterHelper.IsLoopback(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.SourceIP)) ||
                                      !(NetworkFilterHelper.IsRFC1918(p.DestinationIP) || NetworkFilterHelper.IsLoopback(p.DestinationIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP)),
                Description = "Public IP"
            },
            "APIPA" => new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsLinkLocal(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP),
                Description = "APIPA (169.254.x.x)"
            },
            "IPv4" => new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsIPv4(p.SourceIP) || NetworkFilterHelper.IsIPv4(p.DestinationIP),
                Description = "IPv4 Only"
            },
            "IPv6" => new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsIPv6(p.SourceIP) || NetworkFilterHelper.IsIPv6(p.DestinationIP),
                Description = "IPv6 Only"
            },
            "Loopback" => new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsLoopback(p.SourceIP) || NetworkFilterHelper.IsLoopback(p.DestinationIP),
                Description = "Loopback"
            },
            "LinkLocal" => new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsLinkLocal(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP),
                Description = "Link-local"
            },
            "Multicast" => new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsMulticast(p.DestinationIP),
                Description = "Multicast"
            },
            "Broadcast" => new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsBroadcast(p.DestinationIP),
                Description = "Broadcast"
            },
            "Anycast" => new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsAnycast(p.DestinationIP),
                Description = "Anycast"
            },
            "InsecureProtocols" => new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsInsecureProtocol(p.L7Protocol ?? p.Protocol.ToString()),
                Description = "Insecure Protocols"
            },
            "Anomalies" => new PacketFilter
            {
                CustomPredicate = p => false, // Placeholder - anomaly detection done by AnomalyService
                Description = "Anomalies"
            },
            "Suspicious" => new PacketFilter
            {
                CustomPredicate = p => false, // Placeholder - suspicious traffic detection done by ThreatService
                Description = "Suspicious Traffic"
            },
            "TCPIssues" => new PacketFilter
            {
                CustomPredicate = p => false, // Placeholder - TCP issues detected by NetworkAnalyzer
                Description = "TCP Issues"
            },
            "DNSAnomalies" => new PacketFilter
            {
                CustomPredicate = p => false, // Placeholder - DNS anomalies detected by DNSAnalyzer
                Description = "DNS Anomalies"
            },
            "PortScans" => new PacketFilter
            {
                CustomPredicate = p => false, // Placeholder - port scans detected by PortScanDetector
                Description = "Port Scans"
            },
            "PrivateToPublic" => new PacketFilter
            {
                CustomPredicate = p => (NetworkFilterHelper.IsRFC1918(p.SourceIP) || NetworkFilterHelper.IsLoopback(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.SourceIP)) &&
                                      !(NetworkFilterHelper.IsRFC1918(p.DestinationIP) || NetworkFilterHelper.IsLoopback(p.DestinationIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP)),
                Description = "Private → Public"
            },
            "PublicToPrivate" => new PacketFilter
            {
                CustomPredicate = p => !(NetworkFilterHelper.IsRFC1918(p.SourceIP) || NetworkFilterHelper.IsLoopback(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.SourceIP)) &&
                                      (NetworkFilterHelper.IsRFC1918(p.DestinationIP) || NetworkFilterHelper.IsLoopback(p.DestinationIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP)),
                Description = "Public → Private"
            },
            "JumboFrames" => new PacketFilter
            {
                CustomPredicate = p => p.Length > 1500,
                Description = "Jumbo Frames (>1500 bytes)"
            },
            _ => null
        };
    }

    /// <summary>
    /// Gets a protocol-specific filter
    /// </summary>
    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Protocol filter generation requires comprehensive mapping for HTTP/HTTPS, DNS, SNMP, SMB, FTP, SSH, RDP, Telnet, DHCP, NTP, and security-related protocols")]
    private PacketFilter? GetProtocolFilter(string protocol)
    {
        return protocol switch
        {
            "HTTP" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "HTTP" || p.L7Protocol == "HTTP/2" || p.L7Protocol == "HTTP/3",
                Description = "L7 Protocol: HTTP"
            },
            "HTTPS" => new PacketFilter
            {
                CustomPredicate = p => !string.IsNullOrWhiteSpace(p.L7Protocol) &&
                                      (p.L7Protocol.StartsWith("TLS", StringComparison.Ordinal) || p.L7Protocol == "SSL" || p.L7Protocol == "HTTPS"),
                Description = "L7 Protocol: HTTPS/TLS"
            },
            "DNS" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "DNS",
                Description = "L7 Protocol: DNS"
            },
            "SNMP" => new PacketFilter
            {
                CustomPredicate = p => !string.IsNullOrWhiteSpace(p.L7Protocol) && p.L7Protocol.StartsWith("SNMP", StringComparison.Ordinal),
                Description = "L7 Protocol: SNMP"
            },
            "SSH" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "SSH" || p.L7Protocol == "SSHv2",
                Description = "L7 Protocol: SSH"
            },
            "FTP" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "FTP" || p.L7Protocol == "FTPS" || p.L7Protocol == "SFTP",
                Description = "L7 Protocol: FTP"
            },
            "SMTP" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "SMTP" || p.L7Protocol == "SMTPS",
                Description = "L7 Protocol: SMTP"
            },
            "STUN" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "STUN" || p.L7Protocol == "TURN",
                Description = "L7 Protocol: STUN/TURN"
            },
            "DHCP" => new PacketFilter
            {
                CustomPredicate = p => p.Protocol == Protocol.UDP && p.DestinationPort == 68,
                Description = "DHCP Server"
            },
            "WireGuard" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "WireGuard" ||
                                      (p.Protocol == Protocol.UDP && p.DestinationPort == 51820),
                Description = "VPN: WireGuard"
            },
            "OpenVPN" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "OpenVPN" ||
                                      (p.Protocol == Protocol.UDP && p.DestinationPort == 1194) ||
                                      (p.Protocol == Protocol.TCP && p.DestinationPort == 1194),
                Description = "VPN: OpenVPN"
            },
            "IKEv2" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "IKEv2" || p.L7Protocol == "IKE" || p.L7Protocol == "ISAKMP",
                Description = "VPN: IKEv2"
            },
            "IPSec" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "ESP" || p.L7Protocol == "AH" ||
                                      p.L7Protocol == "IPSec" || p.L7Protocol == "ISAKMP",
                Description = "VPN: IPSec"
            },
            "L2TP" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "L2TP",
                Description = "VPN: L2TP"
            },
            "PPTP" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "PPTP" || (p.Protocol == Protocol.TCP && p.DestinationPort == 1723),
                Description = "VPN: PPTP"
            },
            "TLSv1.0" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "TLSv1.0" || p.L7Protocol == "TLSv1",
                Description = "L7 Protocol: TLSv1.0"
            },
            "TLSv1.1" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "TLSv1.1",
                Description = "L7 Protocol: TLSv1.1"
            },
            "TLSv1.2" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "TLSv1.2",
                Description = "L7 Protocol: TLSv1.2"
            },
            "TLSv1.3" => new PacketFilter
            {
                CustomPredicate = p => p.L7Protocol == "TLSv1.3",
                Description = "L7 Protocol: TLSv1.3"
            },
            _ => null
        };
    }

    /// <summary>
    /// Creates a basic filter from IP/Port/Protocol inputs
    /// </summary>
    private PacketFilter? CreateBasicFilter()
    {
        // Implementation would combine IP/Port/Protocol filters from BasicFilters component
        // This is a simplified version - full implementation would handle CIDR, port ranges, etc.
        return null; // Placeholder
    }

    /// <summary>
    /// Combines multiple filters with AND or OR logic
    /// </summary>
    private PacketFilter CombineFilters(List<PacketFilter> filters, bool useAndMode)
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

    // ==================== IP ADDRESS HELPER METHODS ====================
    // All IP/protocol helpers inline NetworkFilterHelper calls to reduce indirection

    // ==================== ADDITIONAL FILTER COMMANDS ====================

    [RelayCommand]
    private void AddPredefinedFilter(string filterName)
    {
        if (!_activePredefinedFilters.Contains(filterName))
        {
            _activePredefinedFilters.Add(filterName);
            DebugLogger.Log($"[EnhancedFilterViewModel] Added predefined filter: {filterName}");
        }
    }

    [RelayCommand]
    private void RemovePredefinedFilter(string filterName)
    {
        if (_activePredefinedFilters.Contains(filterName))
        {
            _activePredefinedFilters.Remove(filterName);
            DebugLogger.Log($"[EnhancedFilterViewModel] Removed predefined filter: {filterName}");
        }
    }

    [RelayCommand]
    private void ApplyTcpIssuesFilter()
    {
        _filterService.ApplyCustomFilter(
            p => false, // Placeholder - TCP issues detected by NetworkAnalyzer
            "TCP Issues"
        );
    }

    [RelayCommand]
    private void ApplyDnsAnomaliesFilter()
    {
        _filterService.ApplyCustomFilter(
            p => false, // Placeholder - DNS anomalies detected by DNSAnalyzer
            "DNS Anomalies"
        );
    }

    [RelayCommand]
    private void ApplyPortScanFilter()
    {
        _filterService.ApplyCustomFilter(
            p => false, // Placeholder - port scans detected by PortScanDetector
            "Port Scans"
        );
    }

    [RelayCommand]
    private void ApplyJumboFramesFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.Length > 1500,
            "Jumbo Frames (>1500 bytes)"
        );
    }

    [RelayCommand]
    private void ApplyIcmpFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.Protocol == Protocol.ICMP,
            "ICMP Traffic"
        );
    }

    [RelayCommand]
    private void ApplyWebTrafficFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.SourcePort == 80 || p.DestinationPort == 80 ||
                 p.SourcePort == 443 || p.DestinationPort == 443 ||
                 p.L7Protocol == "HTTP" || (!string.IsNullOrWhiteSpace(p.L7Protocol) && p.L7Protocol.StartsWith("TLS", StringComparison.Ordinal)),
            "Web Traffic (HTTP/HTTPS)"
        );
    }

    [RelayCommand]
    private void ApplySecureWebFilter()
    {
        _filterService.ApplyCustomFilter(
            p => p.SourcePort == 443 || p.DestinationPort == 443 ||
                 (!string.IsNullOrWhiteSpace(p.L7Protocol) && (p.L7Protocol.StartsWith("TLS", StringComparison.Ordinal) || p.L7Protocol == "HTTPS")),
            "Secure Web (HTTPS)"
        );
    }

    [RelayCommand]
    private void ApplyLinkLocalFilter()
    {
        _filterService.ApplyCustomFilter(
            p => NetworkFilterHelper.IsLinkLocal(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP),
            "Link-local"
        );
    }

    [RelayCommand]
    private void ApplyLoopbackFilter()
    {
        _filterService.ApplyCustomFilter(
            p => NetworkFilterHelper.IsLoopback(p.SourceIP) || NetworkFilterHelper.IsLoopback(p.DestinationIP),
            "Loopback"
        );
    }

    [RelayCommand]
    private void ApplySuspiciousTrafficFilter()
    {
        _filterService.ApplyCustomFilter(
            p => false, // Placeholder - suspicious traffic detection done by ThreatService
            "Suspicious Traffic"
        );
    }

    [RelayCommand]
    private void ApplyPrivateToPublicFilter()
    {
        _filterService.ApplyCustomFilter(
            p => (NetworkFilterHelper.IsRFC1918(p.SourceIP) || NetworkFilterHelper.IsLoopback(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.SourceIP)) &&
                 !(NetworkFilterHelper.IsRFC1918(p.DestinationIP) || NetworkFilterHelper.IsLoopback(p.DestinationIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP)),
            "Private → Public"
        );
    }

    [RelayCommand]
    private void ApplyPublicToPrivateFilter()
    {
        _filterService.ApplyCustomFilter(
            p => !(NetworkFilterHelper.IsRFC1918(p.SourceIP) || NetworkFilterHelper.IsLoopback(p.SourceIP) || NetworkFilterHelper.IsLinkLocal(p.SourceIP)) &&
                 (NetworkFilterHelper.IsRFC1918(p.DestinationIP) || NetworkFilterHelper.IsLoopback(p.DestinationIP) || NetworkFilterHelper.IsLinkLocal(p.DestinationIP)),
            "Public → Private"
        );
    }

    [RelayCommand]
    private void ApplyIPv4Filter()
    {
        _filterService.ApplyIPv4Filter();
    }

    [RelayCommand]
    private void ApplyIPv6Filter()
    {
        _filterService.ApplyIPv6Filter();
    }

    // ==================== COMPATIBILITY LAYER ====================
    // Merged from EnhancedFilterViewModel.Compatibility.cs for cleaner project structure.
    // All properties delegate to the appropriate component ViewModel.

    // ==================== BASIC FILTER PROPERTIES ====================

    public string IpFilterText
    {
        get => BasicFilters.IpFilterText;
        set => BasicFilters.IpFilterText = value;
    }

    public string PortFilterText
    {
        get => BasicFilters.PortFilterText;
        set => BasicFilters.PortFilterText = value;
    }

    public string ProtocolFilterText
    {
        get => BasicFilters.ProtocolFilterText;
        set => BasicFilters.ProtocolFilterText = value;
    }

    public string SourceIpCidrFilter
    {
        get => BasicFilters.SourceIpCidrFilter;
        set => BasicFilters.SourceIpCidrFilter = value;
    }

    public string DestIpCidrFilter
    {
        get => BasicFilters.DestIpCidrFilter;
        set => BasicFilters.DestIpCidrFilter = value;
    }

    public string SourcePortRangeFilter
    {
        get => BasicFilters.SourcePortRangeFilter;
        set => BasicFilters.SourcePortRangeFilter = value;
    }

    public string DestPortRangeFilter
    {
        get => BasicFilters.DestPortRangeFilter;
        set => BasicFilters.DestPortRangeFilter = value;
    }

    public bool NotSourceIp
    {
        get => BasicFilters.NotSourceIp;
        set => BasicFilters.NotSourceIp = value;
    }

    public bool NotDestIp
    {
        get => BasicFilters.NotDestIp;
        set => BasicFilters.NotDestIp = value;
    }

    public bool NotSourcePort
    {
        get => BasicFilters.NotSourcePort;
        set => BasicFilters.NotSourcePort = value;
    }

    public bool NotDestPort
    {
        get => BasicFilters.NotDestPort;
        set => BasicFilters.NotDestPort = value;
    }

    public bool NotProtocol
    {
        get => BasicFilters.NotProtocol;
        set => BasicFilters.NotProtocol = value;
    }

    public bool UseNotFilter
    {
        get => BasicFilters.UseNotFilter;
        set => BasicFilters.UseNotFilter = value;
    }

    public bool UseNotForAllFilters
    {
        get => BasicFilters.UseNotForAllFilters;
        set => BasicFilters.UseNotForAllFilters = value;
    }

    public bool UseAndMode
    {
        get => BasicFilters.UseAndMode;
        set => BasicFilters.UseAndMode = value;
    }

    public bool UseOrMode
    {
        get => BasicFilters.UseOrMode;
        set => BasicFilters.UseOrMode = value;
    }

    // ==================== QUICK FILTER PROPERTIES ====================

    public bool Rfc1918Toggle
    {
        get => QuickFilters.Rfc1918Toggle;
        set => QuickFilters.Rfc1918Toggle = value;
    }

    public bool PublicIpToggle
    {
        get => QuickFilters.PublicIpToggle;
        set => QuickFilters.PublicIpToggle = value;
    }

    public bool ApipaToggle
    {
        get => QuickFilters.ApipaToggle;
        set => QuickFilters.ApipaToggle = value;
    }

    public bool IPv4Toggle
    {
        get => QuickFilters.IPv4Toggle;
        set => QuickFilters.IPv4Toggle = value;
    }

    public bool IPv6Toggle
    {
        get => QuickFilters.IPv6Toggle;
        set => QuickFilters.IPv6Toggle = value;
    }

    public bool LoopbackToggle
    {
        get => QuickFilters.LoopbackToggle;
        set => QuickFilters.LoopbackToggle = value;
    }

    public bool LinkLocalToggle
    {
        get => QuickFilters.LinkLocalToggle;
        set => QuickFilters.LinkLocalToggle = value;
    }

    public bool MulticastToggle
    {
        get => QuickFilters.MulticastToggle;
        set => QuickFilters.MulticastToggle = value;
    }

    public bool BroadcastToggle
    {
        get => QuickFilters.BroadcastToggle;
        set => QuickFilters.BroadcastToggle = value;
    }

    public bool AnycastToggle
    {
        get => QuickFilters.AnycastToggle;
        set => QuickFilters.AnycastToggle = value;
    }

    public bool InsecureToggle
    {
        get => QuickFilters.InsecureToggle;
        set => QuickFilters.InsecureToggle = value;
    }

    public bool AnomaliesToggle
    {
        get => QuickFilters.AnomaliesToggle;
        set => QuickFilters.AnomaliesToggle = value;
    }

    public bool SuspiciousToggle
    {
        get => QuickFilters.SuspiciousToggle;
        set => QuickFilters.SuspiciousToggle = value;
    }

    public bool TcpIssuesToggle
    {
        get => QuickFilters.TcpIssuesToggle;
        set => QuickFilters.TcpIssuesToggle = value;
    }

    public bool DnsAnomaliesToggle
    {
        get => QuickFilters.DnsAnomaliesToggle;
        set => QuickFilters.DnsAnomaliesToggle = value;
    }

    public bool PortScansToggle
    {
        get => QuickFilters.PortScansToggle;
        set => QuickFilters.PortScansToggle = value;
    }

    public bool PrivateToPublicToggle
    {
        get => QuickFilters.PrivateToPublicToggle;
        set => QuickFilters.PrivateToPublicToggle = value;
    }

    public bool PublicToPrivateToggle
    {
        get => QuickFilters.PublicToPrivateToggle;
        set => QuickFilters.PublicToPrivateToggle = value;
    }

    public bool JumboFramesToggle
    {
        get => QuickFilters.JumboFramesToggle;
        set => QuickFilters.JumboFramesToggle = value;
    }

    // ==================== PROTOCOL FILTER PROPERTIES ====================

    public bool HttpToggle
    {
        get => ProtocolFilters.HttpToggle;
        set => ProtocolFilters.HttpToggle = value;
    }

    public bool HttpsToggle
    {
        get => ProtocolFilters.HttpsToggle;
        set => ProtocolFilters.HttpsToggle = value;
    }

    public bool DnsToggle
    {
        get => ProtocolFilters.DnsToggle;
        set => ProtocolFilters.DnsToggle = value;
    }

    public bool SnmpToggle
    {
        get => ProtocolFilters.SnmpToggle;
        set => ProtocolFilters.SnmpToggle = value;
    }

    public bool SshToggle
    {
        get => ProtocolFilters.SshToggle;
        set => ProtocolFilters.SshToggle = value;
    }

    public bool FtpToggle
    {
        get => ProtocolFilters.FtpToggle;
        set => ProtocolFilters.FtpToggle = value;
    }

    public bool SmtpToggle
    {
        get => ProtocolFilters.SmtpToggle;
        set => ProtocolFilters.SmtpToggle = value;
    }

    public bool StunToggle
    {
        get => ProtocolFilters.StunToggle;
        set => ProtocolFilters.StunToggle = value;
    }

    public bool DhcpServerToggle
    {
        get => ProtocolFilters.DhcpServerToggle;
        set => ProtocolFilters.DhcpServerToggle = value;
    }

    public bool WireGuardToggle
    {
        get => ProtocolFilters.WireGuardToggle;
        set => ProtocolFilters.WireGuardToggle = value;
    }

    public bool OpenVpnToggle
    {
        get => ProtocolFilters.OpenVpnToggle;
        set => ProtocolFilters.OpenVpnToggle = value;
    }

    public bool IkeV2Toggle
    {
        get => ProtocolFilters.IkeV2Toggle;
        set => ProtocolFilters.IkeV2Toggle = value;
    }

    public bool IpsecToggle
    {
        get => ProtocolFilters.IpsecToggle;
        set => ProtocolFilters.IpsecToggle = value;
    }

    public bool L2tpToggle
    {
        get => ProtocolFilters.L2tpToggle;
        set => ProtocolFilters.L2tpToggle = value;
    }

    public bool PptpToggle
    {
        get => ProtocolFilters.PptpToggle;
        set => ProtocolFilters.PptpToggle = value;
    }

    public bool TlsV10Toggle
    {
        get => ProtocolFilters.TlsV10Toggle;
        set => ProtocolFilters.TlsV10Toggle = value;
    }

    public bool TlsV11Toggle
    {
        get => ProtocolFilters.TlsV11Toggle;
        set => ProtocolFilters.TlsV11Toggle = value;
    }

    public bool TlsV12Toggle
    {
        get => ProtocolFilters.TlsV12Toggle;
        set => ProtocolFilters.TlsV12Toggle = value;
    }

    public bool TlsV13Toggle
    {
        get => ProtocolFilters.TlsV13Toggle;
        set => ProtocolFilters.TlsV13Toggle = value;
    }

    public List<string> AvailableProtocols
    {
        get => ProtocolFilters.AvailableProtocols;
        set => ProtocolFilters.AvailableProtocols = value;
    }

    // ==================== STATISTICS PROPERTIES ====================

    public bool IsFilterActive
    {
        get => Statistics.IsFilterActive;
        set => Statistics.IsFilterActive = value;
    }

    public string FilterDescription
    {
        get => Statistics.FilterDescription;
        set => Statistics.FilterDescription = value;
    }

    public long TotalPackets
    {
        get => Statistics.TotalPackets;
        set => Statistics.TotalPackets = value;
    }

    public long FilteredPackets
    {
        get => Statistics.FilteredPackets;
        set => Statistics.FilteredPackets = value;
    }

    public string FilterEfficiency
    {
        get => Statistics.FilterEfficiency;
        set => Statistics.FilterEfficiency = value;
    }

    public string CombinedFiltersDescription
    {
        get => Statistics.CombinedFiltersDescription;
        set => Statistics.CombinedFiltersDescription = value;
    }

    public bool HasCombinedFilters
    {
        get => Statistics.HasCombinedFilters;
        set => Statistics.HasCombinedFilters = value;
    }

    public bool IsAnalyzing
    {
        get => Statistics.IsAnalyzing;
        set => Statistics.IsAnalyzing = value;
    }

    public bool CanApplyFilters
    {
        get => Statistics.CanApplyFilters;
        set => Statistics.CanApplyFilters = value;
    }
}
