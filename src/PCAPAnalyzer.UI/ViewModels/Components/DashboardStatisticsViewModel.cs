using System;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages all statistics display and table data for the Dashboard.
/// Extracted from DashboardViewModel to follow Single Responsibility Principle.
/// </summary>
public partial class DashboardStatisticsViewModel : ObservableObject
{
    // ==================== SUMMARY STATISTICS ====================

    [ObservableProperty] private string _analysisSummary = "No data loaded";
    [ObservableProperty] private long _totalPackets;
    [ObservableProperty] private string _totalBytesFormatted = "0 B";
    [ObservableProperty] private int _uniqueIPs;
    [ObservableProperty] private int _uniqueProtocols;
    [ObservableProperty] private int _differentPorts;
    [ObservableProperty] private int _activeConversations;
    [ObservableProperty] private int _threatCount;
    [ObservableProperty] private int _criticalThreats;
    [ObservableProperty] private bool _hasThreats;
    [ObservableProperty] private bool _isLoadingStats = false;

    /// <summary>
    /// Indicates if filter application is allowed (for FilterPanelControl binding).
    /// Returns true when not loading stats.
    /// </summary>
    [ObservableProperty] private bool _canApplyFilters = true;

    /// <summary>
    /// Syncs CanApplyFilters with IsLoadingStats - disable filters during loading.
    /// </summary>
    partial void OnIsLoadingStatsChanged(bool value)
    {
        CanApplyFilters = !value;
    }

    // ==================== QUICK STATS ====================

    [ObservableProperty] private DateTime _lastUpdateTime = DateTime.Now;
    [ObservableProperty] private string _currentThroughput = "0 KB/s";
    [ObservableProperty] private int _lowAnomalies = 0;
    [ObservableProperty] private int _mediumAnomalies = 0;

    // ==================== PACKET SIZE STATISTICS ====================

    [ObservableProperty] private double _averagePacketSize = 0;
    [ObservableProperty] private int _medianPacketSize = 0;
    [ObservableProperty] private int _minPacketSize = 0;
    [ObservableProperty] private int _maxPacketSize = 0;
    [ObservableProperty] private double _standardDeviation = 0;

    // ==================== FILTERED STATISTICS ====================

    [ObservableProperty] private bool _showFilteredStats = false;
    [ObservableProperty] private long _filteredTotalPackets;
    [ObservableProperty] private string _filteredTotalBytesFormatted = "0 B";
    [ObservableProperty] private int _filteredUniqueIPs;
    [ObservableProperty] private int _filteredProtocolCount;
    [ObservableProperty] private int _filteredDifferentPorts;
    [ObservableProperty] private int _filteredConversationCount;
    [ObservableProperty] private int _filteredSecurityThreats;
    [ObservableProperty] private int _filteredAnomalies;

    // ==================== TABLE DATA - ENDPOINTS ====================

    [ObservableProperty] private ObservableCollection<EndpointViewModel> _topSources = new();
    [ObservableProperty] private ObservableCollection<EndpointViewModel> _topDestinations = new();
    [ObservableProperty] private ObservableCollection<EndpointViewModel> _topSourcesByBytes = new();
    [ObservableProperty] private ObservableCollection<EndpointViewModel> _topDestinationsByBytes = new();

    [ObservableProperty] private ObservableCollection<EndpointViewModel> _topSourcesDisplay = new();
    [ObservableProperty] private ObservableCollection<EndpointViewModel> _topDestinationsDisplay = new();
    [ObservableProperty] private ObservableCollection<EndpointViewModel> _topSourcesByBytesDisplay = new();
    [ObservableProperty] private ObservableCollection<EndpointViewModel> _topDestinationsByBytesDisplay = new();

    // Total IPs (combined source + destination traffic)
    [ObservableProperty] private ObservableCollection<EndpointViewModel> _topTotalIPsByPacketsExtended = new();
    [ObservableProperty] private ObservableCollection<EndpointViewModel> _topTotalIPsByBytesExtended = new();

    // ==================== TABLE DATA - CONVERSATIONS & SERVICES ====================

    [ObservableProperty] private ObservableCollection<ConversationViewModel> _topConversations = new();
    [ObservableProperty] private ObservableCollection<ConversationViewModel> _topConversationsByBytes = new();
    [ObservableProperty] private ObservableCollection<ServiceViewModel> _topServices = new();
    [ObservableProperty] private ObservableCollection<ServiceViewModel> _topServicesByBytes = new();

    // ==================== TABLE DATA - PORTS & THREATS ====================

    [ObservableProperty] private ObservableCollection<TopPortViewModel> _topPorts = new();
    [ObservableProperty] private ObservableCollection<TopPortViewModel> _topPortsByPacketsDisplay = new();
    [ObservableProperty] private ObservableCollection<TopPortViewModel> _topPortsByBytesDisplay = new();
    [ObservableProperty] private ObservableCollection<ThreatViewModel> _topThreats = new();

    // ==================== VIEW TOGGLE STATES ====================

    [ObservableProperty] private bool _showSourcesByPackets = true;
    [ObservableProperty] private bool _showDestinationsByPackets = true;
    [ObservableProperty] private bool _showConversationsByPackets = true;
    [ObservableProperty] private bool _showServicesByPackets = true;

    // Computed properties for display
    public ObservableCollection<EndpointViewModel> DisplayedSources =>
        ShowSourcesByPackets ? TopSources : TopSourcesByBytes;

    public ObservableCollection<EndpointViewModel> DisplayedDestinations =>
        ShowDestinationsByPackets ? TopDestinations : TopDestinationsByBytes;

    public ObservableCollection<ConversationViewModel> DisplayedConversations =>
        ShowConversationsByPackets ? TopConversations : TopConversationsByBytes;

    public ObservableCollection<ServiceViewModel> DisplayedServices =>
        ShowServicesByPackets ? TopServices : TopServicesByBytes;

    // ==================== CONSTRUCTOR ====================

    public DashboardStatisticsViewModel()
    {
        InitializeEmptyTables();
    }

    // ==================== INITIALIZATION ====================

    private void InitializeEmptyTables()
    {
        try
        {
            TopSources?.Clear();
            TopDestinations?.Clear();
            TopConversations?.Clear();
            TopServices?.Clear();
            TopSourcesByBytes?.Clear();
            TopDestinationsByBytes?.Clear();
            TopConversationsByBytes?.Clear();
            TopServicesByBytes?.Clear();
            TopSourcesDisplay?.Clear();
            TopDestinationsDisplay?.Clear();
            TopSourcesByBytesDisplay?.Clear();
            TopDestinationsByBytesDisplay?.Clear();
            TopPorts?.Clear();
            TopThreats?.Clear();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardStatisticsViewModel] Error initializing empty tables: {ex.Message}");
        }
    }

    // ==================== VIEW TOGGLE COMMANDS ====================

    [RelayCommand]
    private void ToggleSourcesView()
    {
        ShowSourcesByPackets = !ShowSourcesByPackets;
        OnPropertyChanged(nameof(DisplayedSources));
    }

    [RelayCommand]
    private void ToggleDestinationsView()
    {
        ShowDestinationsByPackets = !ShowDestinationsByPackets;
        OnPropertyChanged(nameof(DisplayedDestinations));
    }

    [RelayCommand]
    private void ToggleConversationsView()
    {
        ShowConversationsByPackets = !ShowConversationsByPackets;
        OnPropertyChanged(nameof(DisplayedConversations));
    }

    [RelayCommand]
    private void ToggleServicesView()
    {
        ShowServicesByPackets = !ShowServicesByPackets;
        OnPropertyChanged(nameof(DisplayedServices));
    }

    // ==================== PUBLIC UPDATE METHODS ====================

    /// <summary>
    /// Updates all statistics with new network data.
    /// Called by parent DashboardViewModel when data changes.
    /// </summary>
    public void UpdateAllStatistics(NetworkStatistics statistics, bool isFiltered = false)
    {
        var startTime = DateTime.Now;
        try
        {
            DebugLogger.Log($"[DashboardStatisticsViewModel] UpdateAllStatistics called - isFiltered: {isFiltered}, statistics null: {statistics == null}");

            if (statistics == null)
            {
                DebugLogger.Log("[DashboardStatisticsViewModel] No statistics provided");
                InitializeEmptyTables();
                return;
            }

            DebugLogger.Log($"[DashboardStatisticsViewModel] Statistics: {statistics.TotalPackets:N0} packets, {statistics.TotalBytes:N0} bytes, UniquePortCount: {statistics.UniquePortCount}");

            if (isFiltered)
            {
                UpdateFilteredStatistics(statistics);
            }
            else
            {
                var t1 = DateTime.Now;
                UpdateMainStatistics(statistics);
                var e1 = (DateTime.Now - t1).TotalSeconds;

                var t2 = DateTime.Now;
                UpdateTables(statistics);
                var e2 = (DateTime.Now - t2).TotalSeconds;

                DebugLogger.Log($"[DashboardStatisticsViewModel] Main updates: MainStats: {e1:F3}s, Tables: {e2:F3}s");
            }

            DebugLogger.Log($"[DashboardStatisticsViewModel] After update - TotalPackets: {TotalPackets:N0}, DifferentPorts: {DifferentPorts}");

            LastUpdateTime = DateTime.Now;

            var totalElapsed = (DateTime.Now - startTime).TotalSeconds;
            DebugLogger.Log($"[DashboardStatisticsViewModel] UpdateAllStatistics completed in {totalElapsed:F3}s");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardStatisticsViewModel] Error updating statistics: {ex.Message}");
            DebugLogger.Log($"[DashboardStatisticsViewModel] Stack trace: {ex.StackTrace}");
        }
    }

    /// <summary>
    /// Updates main (unfiltered) statistics.
    /// </summary>
    private void UpdateMainStatistics(NetworkStatistics statistics)
    {
        try
        {
            // Basic counts
            TotalPackets = statistics.TotalPackets;
            TotalBytesFormatted = NumberFormatter.FormatBytes(statistics.TotalBytes);
            UniqueIPs = statistics.AllUniqueIPs?.Count ?? 0;
            UniqueProtocols = statistics.ProtocolStats.Count;

            // Derived counts
            DifferentPorts = statistics.UniquePortCount;  // Use total unique port count, not just top N
            ActiveConversations = statistics.TotalConversationCount;  // Use total conversation count, not just top 30
            ThreatCount = statistics.DetectedThreats?.Count ?? statistics.Threats?.Count ?? 0;
            CriticalThreats = statistics.DetectedThreats?.Count(t => t.Severity == ThreatSeverity.Critical)
                             ?? statistics.Threats?.Count(t => t.Severity == ThreatSeverity.Critical) ?? 0;
            HasThreats = ThreatCount > 0;

            DebugLogger.Log($"[DashboardStatisticsViewModel] ThreatCount: {ThreatCount}, DetectedThreats: {statistics.DetectedThreats?.Count ?? 0}, Threats: {statistics.Threats?.Count ?? 0}");

            // Analysis summary
            AnalysisSummary = GenerateAnalysisSummary(statistics);

            // Anomaly breakdown
            if (statistics.DetectedThreats != null && statistics.DetectedThreats.Any())
            {
                LowAnomalies = statistics.DetectedThreats.Count(t => t.Severity == ThreatSeverity.Low);
                MediumAnomalies = statistics.DetectedThreats.Count(t => t.Severity == ThreatSeverity.Medium);
            }
            else if (statistics.Threats != null && statistics.Threats.Any())
            {
                LowAnomalies = statistics.Threats.Count(t => t.Severity == ThreatSeverity.Low);
                MediumAnomalies = statistics.Threats.Count(t => t.Severity == ThreatSeverity.Medium);
            }

            // Packet Size Distribution statistics
            if (statistics.PacketSizeDistribution != null)
            {
                AveragePacketSize = statistics.PacketSizeDistribution.AveragePacketSize;
                MedianPacketSize = statistics.PacketSizeDistribution.MedianPacketSize;
                MinPacketSize = statistics.PacketSizeDistribution.MinPacketSize;
                MaxPacketSize = statistics.PacketSizeDistribution.MaxPacketSize;
                StandardDeviation = statistics.PacketSizeDistribution.StandardDeviation;
            }
            else
            {
                AveragePacketSize = 0;
                MedianPacketSize = 0;
                MinPacketSize = 0;
                MaxPacketSize = 0;
                StandardDeviation = 0;
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardStatisticsViewModel] Error updating main statistics: {ex.Message}");
        }
    }

    /// <summary>
    /// Updates filtered statistics when filter is active.
    /// </summary>
    private void UpdateFilteredStatistics(NetworkStatistics statistics)
    {
        try
        {
            ShowFilteredStats = true;
            FilteredTotalPackets = statistics.TotalPackets;
            FilteredTotalBytesFormatted = NumberFormatter.FormatBytes(statistics.TotalBytes);
            FilteredUniqueIPs = statistics.AllUniqueIPs?.Count ?? 0;
            FilteredProtocolCount = statistics.ProtocolStats.Count;
            FilteredDifferentPorts = statistics.UniquePortCount;  // Use total unique port count, not just top N
            FilteredConversationCount = statistics.TotalConversationCount;  // Use total conversation count, not just top 30
            FilteredSecurityThreats = statistics.DetectedThreats?.Count ?? 0;
            FilteredAnomalies = statistics.DetectedThreats?.Count ?? 0;
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardStatisticsViewModel] Error updating filtered statistics: {ex.Message}");
        }
    }

    /// <summary>
    /// Clears filtered statistics.
    /// </summary>
    public void ClearFilteredStatistics()
    {
        ShowFilteredStats = false;
        FilteredTotalPackets = 0;
        FilteredTotalBytesFormatted = "0 B";
        FilteredUniqueIPs = 0;
        FilteredProtocolCount = 0;
        FilteredDifferentPorts = 0;
        FilteredConversationCount = 0;
        FilteredSecurityThreats = 0;
        FilteredAnomalies = 0;
    }

    /// <summary>
    /// Updates all data tables with new statistics.
    /// </summary>
    private void UpdateTables(NetworkStatistics statistics)
    {
        var startTime = DateTime.Now;
        try
        {
            if (statistics == null)
            {
                DebugLogger.Log("[DashboardStatisticsViewModel] No statistics for tables");
                InitializeEmptyTables();
                return;
            }

            DebugLogger.Log($"[DashboardStatisticsViewModel] UpdateTables - TopSources: {statistics.TopSources?.Count ?? 0}, TopDestinations: {statistics.TopDestinations?.Count ?? 0}, TopPorts: {statistics.TopPorts?.Count ?? 0}, TopConversations: {statistics.TopConversations?.Count ?? 0}");

            var t1 = DateTime.Now;
            UpdateEndpointTables(statistics);
            var e1 = (DateTime.Now - t1).TotalSeconds;

            var t2 = DateTime.Now;
            UpdateConversationTables(statistics);
            var e2 = (DateTime.Now - t2).TotalSeconds;

            var t3 = DateTime.Now;
            UpdateServiceTables(statistics);
            var e3 = (DateTime.Now - t3).TotalSeconds;

            var t4 = DateTime.Now;
            UpdatePortTables(statistics);
            var e4 = (DateTime.Now - t4).TotalSeconds;

            var t5 = DateTime.Now;
            UpdateThreatTables(statistics);
            var e5 = (DateTime.Now - t5).TotalSeconds;

            var totalElapsed = (DateTime.Now - startTime).TotalSeconds;
            DebugLogger.Log($"[DashboardStatisticsViewModel] UpdateTables completed in {totalElapsed:F3}s (Endpoints: {e1:F3}s, Conversations: {e2:F3}s, Services: {e3:F3}s, Ports: {e4:F3}s, Threats: {e5:F3}s)");
            DebugLogger.Log($"[DashboardStatisticsViewModel] Tables updated - TopSources: {TopSources.Count}, TopDestinations: {TopDestinations.Count}, TopPorts: {TopPorts.Count}, TopConversations: {TopConversations.Count}");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardStatisticsViewModel] Error updating tables: {ex.Message}");
            DebugLogger.Log($"[DashboardStatisticsViewModel] Stack trace: {ex.StackTrace}");
        }
    }

    private void UpdateEndpointTables(NetworkStatistics statistics)
    {
        PopulateSourcesByPackets(statistics);
        PopulateSourcesByBytes(statistics);
        PopulateDestinationsByPackets(statistics);
        PopulateDestinationsByBytes(statistics);
        PopulateTotalIPs(statistics);

        OnPropertyChanged(nameof(DisplayedSources));
        OnPropertyChanged(nameof(DisplayedDestinations));
    }

    private void PopulateSourcesByPackets(NetworkStatistics statistics)
    {
        TopSources.Clear();
        TopSourcesDisplay.Clear();
        if (statistics.TopSources == null) return;

        foreach (var source in statistics.TopSources)
        {
            var vm = CreateEndpointViewModel(source.Address, source.PacketCount, source.ByteCount,
                source.Percentage, source.Country, source.CountryCode);
            TopSources.Add(vm);
            TopSourcesDisplay.Add(vm);
        }
    }

    private void PopulateSourcesByBytes(NetworkStatistics statistics)
    {
        TopSourcesByBytes.Clear();
        TopSourcesByBytesDisplay.Clear();
        if (statistics.TopSources == null) return;

        var totalBytes = statistics.TotalBytes > 0 ? statistics.TotalBytes : 1;
        foreach (var source in statistics.TopSources.OrderByDescending(s => s.ByteCount))
        {
            var percentage = (source.ByteCount * 100.0) / totalBytes;
            var vm = CreateEndpointViewModel(source.Address, source.PacketCount, source.ByteCount,
                percentage, source.Country, source.CountryCode);
            TopSourcesByBytes.Add(vm);
            TopSourcesByBytesDisplay.Add(vm);
        }
    }

    private void PopulateDestinationsByPackets(NetworkStatistics statistics)
    {
        TopDestinations.Clear();
        TopDestinationsDisplay.Clear();
        if (statistics.TopDestinations == null) return;

        foreach (var dest in statistics.TopDestinations)
        {
            var vm = CreateEndpointViewModel(dest.Address, dest.PacketCount, dest.ByteCount,
                dest.Percentage, dest.Country, dest.CountryCode);
            TopDestinations.Add(vm);
            TopDestinationsDisplay.Add(vm);
        }
    }

    private void PopulateDestinationsByBytes(NetworkStatistics statistics)
    {
        TopDestinationsByBytes.Clear();
        TopDestinationsByBytesDisplay.Clear();
        if (statistics.TopDestinations == null) return;

        var totalBytes = statistics.TotalBytes > 0 ? statistics.TotalBytes : 1;
        foreach (var dest in statistics.TopDestinations.OrderByDescending(d => d.ByteCount))
        {
            var percentage = (dest.ByteCount * 100.0) / totalBytes;
            var vm = CreateEndpointViewModel(dest.Address, dest.PacketCount, dest.ByteCount,
                percentage, dest.Country, dest.CountryCode);
            TopDestinationsByBytes.Add(vm);
            TopDestinationsByBytesDisplay.Add(vm);
        }
    }

    private void PopulateTotalIPs(NetworkStatistics statistics)
    {
        TopTotalIPsByPacketsExtended.Clear();
        TopTotalIPsByBytesExtended.Clear();

        if (statistics.TopSources == null || statistics.TopDestinations == null)
        {
            DebugLogger.Log("[DashboardStatisticsViewModel] PopulateTotalIPs: TopSources or TopDestinations is null");
            return;
        }

        var ipTotals = CombineSourceAndDestinationTraffic(statistics.TopSources, statistics.TopDestinations);
        var totalPackets = statistics.TotalPackets > 0 ? statistics.TotalPackets : 1;
        var totalBytes = statistics.TotalBytes > 0 ? statistics.TotalBytes : 1;

        DebugLogger.Log($"[DashboardStatisticsViewModel] PopulateTotalIPs: Combined {ipTotals.Count} unique IPs");

        AddTotalIPsByPackets(ipTotals, totalPackets, totalBytes);
        AddTotalIPsByBytes(ipTotals, totalPackets, totalBytes);

        DebugLogger.Log($"[DashboardStatisticsViewModel] PopulateTotalIPs: Populated TopTotalIPsByPacketsExtended={TopTotalIPsByPacketsExtended.Count}, TopTotalIPsByBytesExtended={TopTotalIPsByBytesExtended.Count}");
    }

    private Dictionary<string, (long packets, long bytes, string country, string countryCode)> CombineSourceAndDestinationTraffic(
        IEnumerable<EndpointStatistics> sources, IEnumerable<EndpointStatistics> destinations)
    {
        var ipTotals = new Dictionary<string, (long packets, long bytes, string country, string countryCode)>();

        foreach (var source in sources)
        {
            if (!ipTotals.ContainsKey(source.Address))
            {
                ipTotals[source.Address] = (source.PacketCount, source.ByteCount, source.Country, source.CountryCode);
            }
            else
            {
                var current = ipTotals[source.Address];
                ipTotals[source.Address] = (current.packets + source.PacketCount, current.bytes + source.ByteCount, source.Country, source.CountryCode);
            }
        }

        foreach (var dest in destinations)
        {
            if (!ipTotals.ContainsKey(dest.Address))
            {
                ipTotals[dest.Address] = (dest.PacketCount, dest.ByteCount, dest.Country, dest.CountryCode);
            }
            else
            {
                var current = ipTotals[dest.Address];
                ipTotals[dest.Address] = (current.packets + dest.PacketCount, current.bytes + dest.ByteCount, dest.Country, dest.CountryCode);
            }
        }

        return ipTotals;
    }

    private void AddTotalIPsByPackets(Dictionary<string, (long packets, long bytes, string country, string countryCode)> ipTotals,
        long totalPackets, long totalBytes)
    {
        var rank = 1;
        foreach (var ip in ipTotals.OrderByDescending(kvp => kvp.Value.packets).Take(30))
        {
            var percentage = (ip.Value.packets * 100.0) / totalPackets;
            var vm = CreateEndpointViewModel(ip.Key, ip.Value.packets, ip.Value.bytes,
                percentage, ip.Value.country, ip.Value.countryCode);
            vm.Rank = rank++;
            TopTotalIPsByPacketsExtended.Add(vm);
        }
    }

    private void AddTotalIPsByBytes(Dictionary<string, (long packets, long bytes, string country, string countryCode)> ipTotals,
        long totalPackets, long totalBytes)
    {
        var rank = 1;
        foreach (var ip in ipTotals.OrderByDescending(kvp => kvp.Value.bytes).Take(30))
        {
            var percentage = (ip.Value.bytes * 100.0) / totalBytes;
            var vm = CreateEndpointViewModel(ip.Key, ip.Value.packets, ip.Value.bytes,
                percentage, ip.Value.country, ip.Value.countryCode);
            vm.Rank = rank++;
            TopTotalIPsByBytesExtended.Add(vm);
        }
    }

    private EndpointViewModel CreateEndpointViewModel(string address, long packetCount, long byteCount,
        double percentage, string country, string countryCode)
    {
        return new EndpointViewModel
        {
            Address = address,
            PacketCount = packetCount,
            ByteCount = byteCount,
            BytesFormatted = NumberFormatter.FormatBytes(byteCount),
            Percentage = percentage,
            Type = PCAPAnalyzer.Core.Services.NetworkFilterHelper.IsIPv4(address) ? "IPv4" :
                   PCAPAnalyzer.Core.Services.NetworkFilterHelper.IsIPv6(address) ? "IPv6" : "Unknown",
            Country = country,
            CountryCode = countryCode
        };
    }

    private void UpdateConversationTables(NetworkStatistics statistics)
    {
        // By packets
        TopConversations.Clear();
        if (statistics.TopConversations != null)
        {
            foreach (var conv in statistics.TopConversations)
            {
                TopConversations.Add(new ConversationViewModel
                {
                    SourceAddress = conv.SourceAddress,
                    SourcePort = conv.SourcePort,
                    DestinationAddress = conv.DestinationAddress,
                    DestinationPort = conv.DestinationPort,
                    Protocol = conv.Protocol,
                    PacketCount = conv.PacketCount,
                    ByteCount = conv.ByteCount,
                    Duration = conv.Duration,
                    SourceDisplay = $"{conv.SourceAddress}:{conv.SourcePort}",
                    DestinationDisplay = $"{conv.DestinationAddress}:{conv.DestinationPort}",
                    DurationFormatted = FormatDuration(conv.Duration),
                    Percentage = statistics.TotalPackets > 0 ? (double)conv.PacketCount / statistics.TotalPackets * 100 : 0,
                    BytesFormatted = NumberFormatter.FormatBytes(conv.ByteCount)
                });
            }
        }

        // By bytes
        TopConversationsByBytes.Clear();
        if (statistics.TopConversations != null)
        {
            foreach (var conv in statistics.TopConversations.OrderByDescending(c => c.ByteCount))
            {
                TopConversationsByBytes.Add(new ConversationViewModel
                {
                    SourceAddress = conv.SourceAddress,
                    SourcePort = conv.SourcePort,
                    DestinationAddress = conv.DestinationAddress,
                    DestinationPort = conv.DestinationPort,
                    Protocol = conv.Protocol,
                    PacketCount = conv.PacketCount,
                    ByteCount = conv.ByteCount,
                    Duration = conv.Duration,
                    SourceDisplay = $"{conv.SourceAddress}:{conv.SourcePort}",
                    DestinationDisplay = $"{conv.DestinationAddress}:{conv.DestinationPort}",
                    DurationFormatted = FormatDuration(conv.Duration),
                    Percentage = (double)conv.ByteCount / statistics.TotalBytes * 100,
                    BytesFormatted = NumberFormatter.FormatBytes(conv.ByteCount)
                });
            }
        }

        OnPropertyChanged(nameof(DisplayedConversations));
    }

    private void UpdateServiceTables(NetworkStatistics statistics)
    {
        // By packets
        TopServices.Clear();
        if (statistics.ServiceStats != null)
        {
            foreach (var service in statistics.ServiceStats.Values.OrderByDescending(s => s.PacketCount))
            {
                TopServices.Add(new ServiceViewModel
                {
                    ServiceName = service.ServiceName,
                    Port = service.Port,
                    Protocol = service.Protocol,
                    PacketCount = service.PacketCount,
                    ByteCount = service.ByteCount,
                    UniqueHostCount = service.UniqueHosts?.Count ?? 0,
                    IsEncrypted = service.IsEncrypted
                });
            }
        }

        // By bytes
        TopServicesByBytes.Clear();
        if (statistics.ServiceStats != null)
        {
            foreach (var service in statistics.ServiceStats.Values.OrderByDescending(s => s.ByteCount))
            {
                TopServicesByBytes.Add(new ServiceViewModel
                {
                    ServiceName = service.ServiceName,
                    Port = service.Port,
                    Protocol = service.Protocol,
                    PacketCount = service.PacketCount,
                    ByteCount = service.ByteCount,
                    UniqueHostCount = service.UniqueHosts?.Count ?? 0,
                    IsEncrypted = service.IsEncrypted
                });
            }
        }

        OnPropertyChanged(nameof(DisplayedServices));
    }

    private void UpdatePortTables(NetworkStatistics statistics)
    {
        TopPorts.Clear();
        TopPortsByPacketsDisplay.Clear();
        TopPortsByBytesDisplay.Clear();

        if (statistics.TopPorts != null)
        {
            foreach (var port in statistics.TopPorts)
            {
                var portVM = new TopPortViewModel
                {
                    Port = port.Port,
                    Protocol = port.Protocol ?? "Unknown",
                    Service = port.Service ?? "Unknown",
                    PacketCount = port.PacketCount,
                    ByteCount = port.ByteCount,
                    DisplayName = $"{port.Port}/{(port.Protocol ?? "Unknown")}",
                    ServiceName = port.Service ?? "Unknown",
                    Percentage = port.Percentage,
                    PacketCountFormatted = port.PacketCount.ToString("N0"),
                    ByteCountFormatted = NumberFormatter.FormatBytes(port.ByteCount)
                };
                TopPorts.Add(portVM);
                TopPortsByPacketsDisplay.Add(portVM);
            }

            // Also populate TopPortsByBytesDisplay sorted by bytes with BYTE-based percentages
            var totalBytes = statistics.TotalBytes > 0 ? statistics.TotalBytes : 1;
            var portsByBytes = statistics.TopPorts.OrderByDescending(p => p.ByteCount).ToList();
            foreach (var port in portsByBytes)
            {
                var portVM = new TopPortViewModel
                {
                    Port = port.Port,
                    Protocol = port.Protocol ?? "Unknown",
                    Service = port.Service ?? "Unknown",
                    PacketCount = port.PacketCount,
                    ByteCount = port.ByteCount,
                    DisplayName = $"{port.Port}/{(port.Protocol ?? "Unknown")}",
                    ServiceName = port.Service ?? "Unknown",
                    Percentage = (port.ByteCount * 100.0) / totalBytes,  // % of TOTAL bytes
                    PacketCountFormatted = port.PacketCount.ToString("N0"),
                    ByteCountFormatted = NumberFormatter.FormatBytes(port.ByteCount)
                };
                TopPortsByBytesDisplay.Add(portVM);
            }
        }
    }

    private void UpdateThreatTables(NetworkStatistics statistics)
    {
        TopThreats.Clear();
        if (statistics.DetectedThreats != null)
        {
            foreach (var threat in statistics.DetectedThreats)
            {
                TopThreats.Add(new ThreatViewModel
                {
                    Type = threat.Type,
                    Description = threat.Description,
                    Severity = threat.Severity.ToString(),
                    SeverityColor = GetSeverityColor(threat.Severity),
                    DetectedAt = threat.DetectedAt,
                    SourceAddress = threat.SourceAddress ?? "N/A",
                    DestinationAddress = threat.DestinationAddress ?? "N/A"
                });
            }
        }
    }

    // ==================== HELPER METHODS ====================

    private string FormatDuration(TimeSpan duration)
    {
        return Helpers.TimeFormatter.FormatAsSeconds(duration);
    }

    private string GenerateAnalysisSummary(NetworkStatistics statistics)
    {
        return $"Analyzed {statistics.TotalPackets:N0} packets ({NumberFormatter.FormatBytes(statistics.TotalBytes)}) across {statistics.ProtocolStats.Count} protocols";
    }

    private string GetSeverityColor(ThreatSeverity severity)
    {
        return severity switch
        {
            ThreatSeverity.Critical => "#DC2626",
            ThreatSeverity.High => "#F59E0B",
            ThreatSeverity.Medium => "#FCD34D",
            ThreatSeverity.Low => "#10B981",
            _ => "#6B7280"
        };
    }
}

// Note: ViewModel classes moved to TableViewModels.cs in main ViewModels namespace
// to maintain backward compatibility with existing code
