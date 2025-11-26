using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.VoiceQoS;

/// <summary>
/// Manages top endpoint statistics and extended collections for VoiceQoS tab.
/// Calculates top talkers/listeners for QoS, Latency, and Jitter categories.
/// </summary>
public partial class VoiceQoSStatisticsViewModel : ObservableObject
{
    private readonly object _collectionLock = new();

    // Top sources/destinations (Top 30 each)
    [ObservableProperty] private ObservableCollection<TopEndpointItem> _topQoSSources = new();
    [ObservableProperty] private ObservableCollection<TopEndpointItem> _topQoSDestinations = new();
    [ObservableProperty] private ObservableCollection<TopEndpointItem> _topLatencySources = new();
    [ObservableProperty] private ObservableCollection<TopEndpointItem> _topLatencyDestinations = new();
    [ObservableProperty] private ObservableCollection<TopEndpointItem> _topJitterSources = new();
    [ObservableProperty] private ObservableCollection<TopEndpointItem> _topJitterDestinations = new();

    // Extended collections for Dashboard-style tables (with Rank and Percentage)
    [ObservableProperty] private ObservableCollection<TopEndpointItemExtended> _topQoSSourcesExtended = new();
    [ObservableProperty] private ObservableCollection<TopEndpointItemExtended> _topQoSDestinationsExtended = new();
    [ObservableProperty] private ObservableCollection<TopEndpointItemExtended> _topLatencySourcesExtended = new();
    [ObservableProperty] private ObservableCollection<TopEndpointItemExtended> _topLatencyDestinationsExtended = new();
    [ObservableProperty] private ObservableCollection<TopEndpointItemExtended> _topJitterSourcesExtended = new();
    [ObservableProperty] private ObservableCollection<TopEndpointItemExtended> _topJitterDestinationsExtended = new();

    /// <summary>
    /// Updates top endpoints from the provided filtered collections.
    /// Call this after applying filters to refresh the top talkers/listeners.
    /// </summary>
    public void UpdateTopEndpoints(
        IEnumerable<QoSTrafficItem> qosTraffic,
        IEnumerable<LatencyConnectionItem> latencyConnections,
        IEnumerable<JitterConnectionItem> jitterConnections)
    {
        // Top QoS Sources (Top 30)
        var qosSources = qosTraffic
            .GroupBy(q => q.SourceIP)
            .Select(g => new TopEndpointItem
            {
                IPAddress = g.Key,
                FlowCount = g.Count(),
                PacketCount = g.Sum(x => x.PacketCount),
                TotalBytes = g.Sum(x => x.TotalBytes),
                MetricType = "QoS Flows"
            })
            .OrderByDescending(x => x.PacketCount)
            .Take(30)
            .ToList();

        // Top QoS Destinations (Top 30)
        var qosDests = qosTraffic
            .GroupBy(q => q.DestinationIP)
            .Select(g => new TopEndpointItem
            {
                IPAddress = g.Key,
                FlowCount = g.Count(),
                PacketCount = g.Sum(x => x.PacketCount),
                TotalBytes = g.Sum(x => x.TotalBytes),
                MetricType = "QoS Flows"
            })
            .OrderByDescending(x => x.PacketCount)
            .Take(30)
            .ToList();

        // Top Latency Sources (Top 30)
        var latencySources = latencyConnections
            .GroupBy(l => l.SourceIP)
            .Select(g => new TopEndpointItem
            {
                IPAddress = g.Key,
                FlowCount = g.Count(),
                PacketCount = g.Sum(x => x.PacketCount),
                AverageMetric = g.Average(x => x.AverageLatency),
                MetricType = "Latency"
            })
            .OrderByDescending(x => x.PacketCount)
            .Take(30)
            .ToList();

        // Top Latency Destinations (Top 30)
        var latencyDests = latencyConnections
            .GroupBy(l => l.DestinationIP)
            .Select(g => new TopEndpointItem
            {
                IPAddress = g.Key,
                FlowCount = g.Count(),
                PacketCount = g.Sum(x => x.PacketCount),
                AverageMetric = g.Average(x => x.AverageLatency),
                MetricType = "Latency"
            })
            .OrderByDescending(x => x.PacketCount)
            .Take(30)
            .ToList();

        // Top Jitter Sources (Top 30)
        var jitterSources = jitterConnections
            .GroupBy(j => j.SourceIP)
            .Select(g => new TopEndpointItem
            {
                IPAddress = g.Key,
                FlowCount = g.Count(),
                PacketCount = g.Sum(x => x.PacketCount),
                AverageMetric = g.Average(x => x.AverageJitter),
                MetricType = "Jitter"
            })
            .OrderByDescending(x => x.PacketCount)
            .Take(30)
            .ToList();

        // Top Jitter Destinations (Top 30)
        var jitterDests = jitterConnections
            .GroupBy(j => j.DestinationIP)
            .Select(g => new TopEndpointItem
            {
                IPAddress = g.Key,
                FlowCount = g.Count(),
                PacketCount = g.Sum(x => x.PacketCount),
                AverageMetric = g.Average(x => x.AverageJitter),
                MetricType = "Jitter"
            })
            .OrderByDescending(x => x.PacketCount)
            .Take(30)
            .ToList();

        // Update UI collections (with thread-safety)
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            lock (_collectionLock)
            {
                UpdateCollection(TopQoSSources, qosSources);
                UpdateCollection(TopQoSDestinations, qosDests);
                UpdateCollection(TopLatencySources, latencySources);
                UpdateCollection(TopLatencyDestinations, latencyDests);
                UpdateCollection(TopJitterSources, jitterSources);
                UpdateCollection(TopJitterDestinations, jitterDests);
            }

            // Populate Extended collections for Dashboard-style tables
            PopulateExtendedCollections();

            DebugLogger.Log($"[VoiceQoSStatisticsViewModel] Top endpoints updated: QoS Sources={TopQoSSources.Count}, Latency Sources={TopLatencySources.Count}, Jitter Sources={TopJitterSources.Count}");
        });
    }

    /// <summary>
    /// Populates Extended collections with Rank and Percentage for Dashboard-style tables
    /// </summary>
    private void PopulateExtendedCollections()
    {
        // QoS Sources
        TopQoSSourcesExtended.Clear();
        PopulateExtendedFromSource(TopQoSSources, TopQoSSourcesExtended, "QoS");

        // QoS Destinations
        TopQoSDestinationsExtended.Clear();
        PopulateExtendedFromSource(TopQoSDestinations, TopQoSDestinationsExtended, "QoS");

        // Latency Sources
        TopLatencySourcesExtended.Clear();
        PopulateExtendedFromSource(TopLatencySources, TopLatencySourcesExtended, "Latency");

        // Latency Destinations
        TopLatencyDestinationsExtended.Clear();
        PopulateExtendedFromSource(TopLatencyDestinations, TopLatencyDestinationsExtended, "Latency");

        // Jitter Sources
        TopJitterSourcesExtended.Clear();
        PopulateExtendedFromSource(TopJitterSources, TopJitterSourcesExtended, "Jitter");

        // Jitter Destinations
        TopJitterDestinationsExtended.Clear();
        PopulateExtendedFromSource(TopJitterDestinations, TopJitterDestinationsExtended, "Jitter");
    }

    /// <summary>
    /// Populates an extended collection from a source collection with ranking and percentage
    /// </summary>
    private static void PopulateExtendedFromSource(
        ObservableCollection<TopEndpointItem> source,
        ObservableCollection<TopEndpointItemExtended> target,
        string metricType)
    {
        var items = source.Take(30).ToList();
        var totalPackets = items.Sum(x => x.PacketCount);

        for (int i = 0; i < items.Count; i++)
        {
            var item = items[i];
            target.Add(new TopEndpointItemExtended
            {
                Rank = $"{i + 1}",
                IPAddress = item.IPAddress,
                FlowCount = item.FlowCount,
                PacketCount = item.PacketCount,
                TotalBytes = item.TotalBytes,
                Percentage = totalPackets > 0 ? (item.PacketCount * 100.0 / totalPackets) : 0,
                AverageMetric = item.AverageMetric,
                MetricType = metricType,
                Badge = $"{item.FlowCount} flows"
            });
        }
    }

    /// <summary>
    /// Helper to update an ObservableCollection with minimal UI churn
    /// </summary>
    private static void UpdateCollection<T>(ObservableCollection<T> collection, List<T> newItems)
    {
        collection.Clear();
        foreach (var item in newItems)
        {
            collection.Add(item);
        }
    }
}
