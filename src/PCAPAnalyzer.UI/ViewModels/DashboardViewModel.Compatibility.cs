using System.Collections.ObjectModel;
using LiveChartsCore;
using LiveChartsCore.SkiaSharpView;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Compatibility layer for DashboardViewModel.
/// Forwards properties from child ViewModels to parent for XAML binding compatibility.
/// </summary>
public partial class DashboardViewModel
{
    // ==================== STATISTICS PROPERTY FORWARDING ====================

    public bool IsLoadingStats => Statistics.IsLoadingStats;
    public bool IsLoadingFilteredStats => Statistics.ShowFilteredStats;
    public bool ShowFilteredStats => Statistics.ShowFilteredStats;

    // Basic statistics
    public long TotalPackets => Statistics.TotalPackets;
    public string TotalBytesFormatted => Statistics.TotalBytesFormatted;
    public int UniqueIPs => Statistics.UniqueIPs;
    public int UniqueDestinationPorts => Statistics.DifferentPorts;
    public int ActiveConversations => Statistics.ActiveConversations;
    public int ThreatCount => Statistics.ThreatCount;
    public int TotalAnomalies => Statistics.ThreatCount;

    // Filtered statistics
    public long FilteredTotalPackets => Statistics.FilteredTotalPackets;
    public double FilteredPacketsPercentage => Statistics.TotalPackets > 0 ? (Statistics.FilteredTotalPackets * 100.0 / Statistics.TotalPackets) : 0;
    public string FilteredTotalBytesFormatted => Statistics.FilteredTotalBytesFormatted;
    public double FilteredTrafficPercentage => (_unfilteredStatistics is not null && _filteredStatistics is not null && _unfilteredStatistics.TotalBytes > 0)
        ? (_filteredStatistics.TotalBytes * 100.0 / _unfilteredStatistics.TotalBytes) : 0;
    public int FilteredUniqueIPs => Statistics.FilteredUniqueIPs;
    public double FilteredIPsPercentage => Statistics.UniqueIPs > 0 ? (Statistics.FilteredUniqueIPs * 100.0 / Statistics.UniqueIPs) : 0;
    public int FilteredDifferentPorts => Statistics.FilteredDifferentPorts;
    public double FilteredDifferentPortsPercentage => Statistics.DifferentPorts > 0 ? (Statistics.FilteredDifferentPorts * 100.0 / Statistics.DifferentPorts) : 0;
    public int FilteredConversationCount => Statistics.FilteredConversationCount;
    public double FilteredConversationsPercentage => Statistics.ActiveConversations > 0 ? (Statistics.FilteredConversationCount * 100.0 / Statistics.ActiveConversations) : 0;
    public int FilteredSecurityThreats => Statistics.FilteredSecurityThreats;
    public double FilteredThreatsPercentage => Statistics.ThreatCount > 0 ? (Statistics.FilteredSecurityThreats * 100.0 / Statistics.ThreatCount) : 0;
    public int FilteredAnomalies => Statistics.FilteredAnomalies;
    public double FilteredAnomaliesPercentage => Statistics.ThreatCount > 0 ? (Statistics.FilteredAnomalies * 100.0 / Statistics.ThreatCount) : 0;
    public int FilteredProtocolCount => Statistics.FilteredProtocolCount;
    public double FilteredProtocolsPercentage => Statistics.UniqueProtocols > 0 ? (Statistics.FilteredProtocolCount * 100.0 / Statistics.UniqueProtocols) : 0;

    // ==================== COLLECTION PROPERTY FORWARDING ====================

    // Endpoint collections
    public ObservableCollection<EndpointViewModel> TopSources => Statistics.TopSources;
    public ObservableCollection<EndpointViewModel> TopSourcesByBytes => Statistics.TopSourcesByBytes;
    public ObservableCollection<EndpointViewModel> TopSourcesDisplay => Statistics.TopSourcesDisplay;
    public ObservableCollection<EndpointViewModel> TopSourcesByBytesDisplay => Statistics.TopSourcesByBytesDisplay;
    public ObservableCollection<EndpointViewModel> TopDestinations => Statistics.TopDestinations;
    public ObservableCollection<EndpointViewModel> TopDestinationsByBytes => Statistics.TopDestinationsByBytes;
    public ObservableCollection<EndpointViewModel> TopDestinationsDisplay => Statistics.TopDestinationsDisplay;
    public ObservableCollection<EndpointViewModel> TopDestinationsByBytesDisplay => Statistics.TopDestinationsByBytesDisplay;

    // Port collections
    public ObservableCollection<TopPortViewModel> TopPorts => Statistics.TopPorts;
    public ObservableCollection<TopPortViewModel> TopPortsByPacketsDisplay => Statistics.TopPortsByPacketsDisplay;
    public ObservableCollection<TopPortViewModel> TopPortsByBytesDisplay => Statistics.TopPortsByBytesDisplay;

    // Conversation collections
    public ObservableCollection<ConversationViewModel> TopConversations => Statistics.TopConversations;
    public ObservableCollection<ConversationViewModel> TopConversationsByBytes => Statistics.TopConversationsByBytes;

    // ==================== CHARTS PROPERTY FORWARDING ====================

    public ObservableCollection<ISeries> TimelineSeries => Charts.TimelineSeries;
    public Axis[] XAxes => Charts.XAxes;
    public Axis[] YAxes => Charts.YAxes;
    public ObservableCollection<ISeries> ThroughputSeries => Charts.ThroughputSeries;
    public ObservableCollection<ISeries> ProtocolSeries => Charts.ProtocolSeries;
    public ObservableCollection<ISeries> PortSeries => Charts.PortSeries;
    public ObservableCollection<ISeries> PortByBytesSeries => Charts.PortByBytesSeries;
    public ObservableCollection<ISeries> PortByPacketsSeries => Charts.PortByPacketsSeries;

    // ==================== COMPATIBILITY METHODS ====================

    public void UpdateThroughputChart(NetworkStatistics statistics)
    {
        Charts.UpdateThroughputChart(statistics);
    }

    public void UpdateThroughputChart()
    {
        if (_currentStatistics is not null)
        {
            Charts.UpdateThroughputChart(_currentStatistics);
        }
    }

    public void UpdateStatistics(NetworkStatistics statistics)
    {
        _nextStatisticsOverride = statistics;
    }

    public void ResetStatistics()
    {
        _currentStatistics = null;
        _unfilteredStatistics = null;
        _filteredStatistics = null;
        _allPackets = null;
        _filteredPackets = null;

        Statistics.TopSources.Clear();
        Statistics.TopDestinations.Clear();
        Statistics.TopPorts.Clear();
        Statistics.TopConversations.Clear();
        Charts.TimelineSeries.Clear();
        Charts.ThroughputSeries.Clear();
        Charts.ProtocolSeries.Clear();
        NetworkStatsBar.ClearStats();
    }

    // ==================== NETWORK STATS BAR (Total/Filtered Pattern) ====================

    /// <summary>
    /// Updates NetworkStatsBar with unified Total/Filtered display pattern.
    /// Call after filtering or when statistics change.
    /// </summary>
    public void UpdateNetworkStatsBar()
    {
        NetworkStatsBar.ClearStats();

        // Get totals from unfiltered statistics, filtered from current
        var totalPackets = _unfilteredStatistics?.TotalPackets ?? Statistics.TotalPackets;
        var totalBytes = _unfilteredStatistics?.TotalBytes ?? 0L;
        var totalIPs = _unfilteredStatistics?.AllUniqueIPs.Count ?? Statistics.UniqueIPs;
        var totalPorts = _unfilteredStatistics?.UniquePortCount ?? Statistics.DifferentPorts;
        var totalStreams = _unfilteredStatistics?.TotalStreamCount ?? Statistics.ActiveConversations;

        var filteredPackets = _filteredStatistics?.TotalPackets ?? Statistics.FilteredTotalPackets;
        var filteredBytes = _filteredStatistics?.TotalBytes ?? 0L;
        var filteredIPs = _filteredStatistics?.AllUniqueIPs.Count ?? Statistics.FilteredUniqueIPs;
        var filteredPorts = _filteredStatistics?.UniquePortCount ?? Statistics.FilteredDifferentPorts;
        var filteredStreams = _filteredStatistics?.TotalStreamCount ?? Statistics.FilteredConversationCount;

        // If no filter active, show unfiltered totals only
        if (!IsFilterActive)
        {
            filteredPackets = totalPackets;
            filteredBytes = totalBytes;
            filteredIPs = totalIPs;
            filteredPorts = totalPorts;
            filteredStreams = totalStreams;
        }

        // Packets
        TabStatsHelper.AddNumericStat(NetworkStatsBar, "PACKETS", "📦",
            totalPackets, filteredPackets, IsFilterActive,
            ThemeColorHelper.GetColorHex("StatPackets", "#58A6FF"));

        // Traffic
        TabStatsHelper.AddBytesStat(NetworkStatsBar, "TRAFFIC", "💾",
            totalBytes, filteredBytes, IsFilterActive,
            ThemeColorHelper.GetColorHex("StatBytes", "#A371F7"));

        // Unique IPs
        TabStatsHelper.AddNumericStat(NetworkStatsBar, "UNIQUE IPs", "🌐",
            totalIPs, filteredIPs, IsFilterActive,
            ThemeColorHelper.GetColorHex("StatIPs", "#7EE787"));

        // Streams
        TabStatsHelper.AddNumericStat(NetworkStatsBar, "STREAMS", "💬",
            totalStreams, filteredStreams, IsFilterActive,
            ThemeColorHelper.GetColorHex("StatConversations", "#F0883E"));

        // Destination Ports
        TabStatsHelper.AddNumericStat(NetworkStatsBar, "DEST PORTS", "🔌",
            totalPorts, filteredPorts, IsFilterActive,
            ThemeColorHelper.GetColorHex("StatPorts", "#79C0FF"));
    }
}
