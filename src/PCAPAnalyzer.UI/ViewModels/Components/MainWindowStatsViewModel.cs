using System;
using System.Linq;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Handles PacketAnalysisStats bar calculations and updates.
/// Extracted from MainWindowViewModel to reduce file size.
/// </summary>
public class MainWindowStatsViewModel
{
    private readonly IPacketStatisticsCalculator _packetStatsCalculator;

    public MainWindowStatsViewModel(IPacketStatisticsCalculator packetStatsCalculator)
    {
        _packetStatsCalculator = packetStatsCalculator ?? throw new ArgumentNullException(nameof(packetStatsCalculator));
    }

    /// <summary>
    /// Initialize stats bar with default configuration.
    /// </summary>
    public void InitializePacketAnalysisStats(StatsBarControlViewModel statsBar)
    {
        statsBar.SectionTitle = "PACKET ANALYSIS OVERVIEW";
        statsBar.AccentColor = "#3B82F6";
        statsBar.ColumnCount = 5;
        UpdatePacketAnalysisStats(statsBar, null);
    }

    /// <summary>
    /// Update PacketAnalysisStats with current values (German formatting).
    /// </summary>
    public void UpdatePacketAnalysisStats(StatsBarControlViewModel statsBar, MainWindowPacketViewModel? packetManager)
    {
        statsBar.ClearStats();

        var data = GatherStatsData(packetManager);
        var germanCulture = new System.Globalization.CultureInfo("de-DE");

        // Stat 1: Packets
        if (data.FilterActive)
        {
            var totalPackets = $"Total: {data.TotalPackets.ToString("N0", germanCulture)}";
            var filtered = $"Filtered: {data.FilteredCount.ToString("N0", germanCulture)} ({data.FilteredPct:F1}%)";
            statsBar.AddStat("PACKETS", totalPackets, "📦", "#58A6FF", filtered, "#3FB950");
        }
        else
        {
            statsBar.AddStat("PACKETS", data.TotalPackets.ToString("N0", germanCulture), "📦", "#58A6FF");
        }

        // Stat 2: Traffic
        if (data.FilterActive)
        {
            var totalTraffic = $"Total: {FormatBytesGerman(data.TotalBytes)}";
            var filtered = $"Filtered: {FormatBytesGerman(data.FilteredBytes)} ({data.TrafficPct:F1}%)";
            statsBar.AddStat("TRAFFIC", totalTraffic, "💾", "#58A6FF", filtered, "#3FB950");
        }
        else
        {
            statsBar.AddStat("TRAFFIC", FormatBytesGerman(data.TotalBytes), "💾", "#58A6FF");
        }

        // Stat 3: Unique IPs
        if (data.FilterActive)
        {
            var totalIPs = $"Total: {data.TotalUniqueIPs.ToString("N0", germanCulture)}";
            var ipPct = data.TotalUniqueIPs > 0 ? (data.FilteredUniqueIPs * 100.0 / data.TotalUniqueIPs) : 0.0;
            var filtered = $"Filtered: {data.FilteredUniqueIPs.ToString("N0", germanCulture)} ({ipPct:F1}%)";
            statsBar.AddStat("UNIQUE IPs", totalIPs, "🌐", "#58A6FF", filtered, "#3FB950");
        }
        else
        {
            statsBar.AddStat("UNIQUE IPs", data.TotalUniqueIPs.ToString("N0", germanCulture), "🌐", "#58A6FF");
        }

        // Stat 4: Destination Ports
        if (data.FilterActive)
        {
            var totalPorts = $"Total: {data.TotalDestPorts.ToString("N0", germanCulture)}";
            var portPct = data.TotalDestPorts > 0 ? (data.FilteredDestPorts * 100.0 / data.TotalDestPorts) : 0.0;
            var filtered = $"Filtered: {data.FilteredDestPorts.ToString("N0", germanCulture)} ({portPct:F1}%)";
            statsBar.AddStat("DEST PORTS", totalPorts, "🔌", "#58A6FF", filtered, "#3FB950");
        }
        else
        {
            statsBar.AddStat("DEST PORTS", data.TotalDestPorts.ToString("N0", germanCulture), "🔌", "#58A6FF");
        }

        // Stat 5: Streams
        if (data.FilterActive)
        {
            var totalConvs = $"Total: {data.TotalConversations.ToString("N0", germanCulture)}";
            var convPct = data.TotalConversations > 0 ? (data.FilteredConversations * 100.0 / data.TotalConversations) : 0.0;
            var filtered = $"Filtered: {data.FilteredConversations.ToString("N0", germanCulture)} ({convPct:F1}%)";
            statsBar.AddStat("STREAMS", totalConvs, "💬", "#58A6FF", filtered, "#3FB950");
        }
        else
        {
            statsBar.AddStat("STREAMS", data.TotalConversations.ToString("N0", germanCulture), "💬", "#58A6FF");
        }
    }

    /// <summary>
    /// Gather stats data from PacketManager with defensive fallbacks.
    /// </summary>
    private (long TotalPackets, long FilteredCount, long TotalBytes, long FilteredBytes,
             bool FilterActive, double FilteredPct, double TrafficPct,
             int TotalUniqueIPs, int FilteredUniqueIPs,
             int TotalDestPorts, int FilteredDestPorts,
             int TotalConversations, int FilteredConversations) GatherStatsData(MainWindowPacketViewModel? packetManager)
    {
        long totalPackets = 0;
        long totalBytes = 0;

        if (packetManager?.CachedDashboardPackets != null)
        {
            var allPackets = packetManager.CachedDashboardPackets;
            totalPackets = allPackets.Count;
            totalBytes = allPackets.Sum(p => (long)p.Length);
        }

        var filteredCount = packetManager?.FilteredPacketCount ?? 0;
        var filteredBytes = packetManager?.FilteredBytes ?? 0;
        var filterActive = packetManager?.IsFilterActive ?? false;

        var filteredPct = totalPackets > 0 ? (filteredCount * 100.0 / totalPackets) : 0.0;
        var trafficPct = totalBytes > 0 ? (filteredBytes * 100.0 / totalBytes) : 0.0;

        var (totalIPs, filteredIPs) = CalculateUniqueIPs(packetManager);
        var (totalPorts, filteredPorts) = CalculateDestinationPorts(packetManager);
        var (totalConvs, filteredConvs) = CalculateTCPConversations(packetManager);

        return (totalPackets, filteredCount, totalBytes, filteredBytes, filterActive,
                filteredPct, trafficPct, totalIPs, filteredIPs, totalPorts, filteredPorts,
                totalConvs, filteredConvs);
    }

    /// <summary>
    /// Calculate unique IP addresses (total + filtered).
    /// </summary>
    private (int Total, int Filtered) CalculateUniqueIPs(MainWindowPacketViewModel? packetManager)
    {
        if (packetManager?.CachedDashboardPackets == null || packetManager.CachedDashboardPackets.Count == 0)
            return (0, 0);

        var totalIPs = _packetStatsCalculator.CalculateUniqueIPs(packetManager.CachedDashboardPackets);

        if (!packetManager.IsFilterActive)
            return (totalIPs, 0);

        var filteredPackets = packetManager.GetFilteredPackets().ToList();
        var filteredIPs = _packetStatsCalculator.CalculateUniqueIPs(filteredPackets);
        return (totalIPs, filteredIPs);
    }

    /// <summary>
    /// Calculate unique destination ports (total + filtered).
    /// </summary>
    private (int Total, int Filtered) CalculateDestinationPorts(MainWindowPacketViewModel? packetManager)
    {
        if (packetManager?.CachedDashboardPackets == null || packetManager.CachedDashboardPackets.Count == 0)
            return (0, 0);

        var totalPorts = _packetStatsCalculator.CalculateUniqueDestinationPorts(packetManager.CachedDashboardPackets);

        if (!packetManager.IsFilterActive)
            return (totalPorts, 0);

        var filteredPackets = packetManager.GetFilteredPackets().ToList();
        var filteredPorts = _packetStatsCalculator.CalculateUniqueDestinationPorts(filteredPackets);
        return (totalPorts, filteredPorts);
    }

    /// <summary>
    /// Calculate TCP conversations (total + filtered).
    /// </summary>
    private (int Total, int Filtered) CalculateTCPConversations(MainWindowPacketViewModel? packetManager)
    {
        if (packetManager?.CachedDashboardPackets == null || packetManager.CachedDashboardPackets.Count == 0)
            return (0, 0);

        var totalConversations = _packetStatsCalculator.CalculateTCPConversations(packetManager.CachedDashboardPackets);

        if (!packetManager.IsFilterActive)
            return (totalConversations, 0);

        var filteredPackets = packetManager.GetFilteredPackets().ToList();
        var filteredConversations = _packetStatsCalculator.CalculateTCPConversations(filteredPackets);
        return (totalConversations, filteredConversations);
    }

    /// <summary>
    /// Format bytes with German number formatting.
    /// </summary>
    private string FormatBytesGerman(long bytes)
    {
        if (bytes == 0) return "0 B";

        var germanCulture = new System.Globalization.CultureInfo("de-DE");
        string[] sizes = { "B", "KB", "MB", "GB", "TB" };
        int order = 0;
        double size = bytes;

        while (size >= 1024 && order < sizes.Length - 1)
        {
            order++;
            size /= 1024;
        }

        return $"{size.ToString("F2", germanCulture)} {sizes[order]}";
    }
}
