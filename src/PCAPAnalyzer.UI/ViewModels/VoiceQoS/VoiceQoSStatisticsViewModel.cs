using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.ViewModels.VoiceQoS;

/// <summary>
/// Manages top endpoint statistics and extended collections for VoiceQoS tab.
/// Calculates top talkers/listeners for QoS, Latency, and Jitter categories.
/// </summary>
public partial class VoiceQoSStatisticsViewModel : ObservableObject
{
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    private readonly Lock _collectionLock = new();

    // Fingerprint for early-exit optimization
    private string? _lastEndpointsFingerprint;

    // Top sources/destinations (Top 30 each)
    [ObservableProperty] private ObservableCollection<TopEndpointItem> _topQoSSources = [];
    [ObservableProperty] private ObservableCollection<TopEndpointItem> _topQoSDestinations = [];
    [ObservableProperty] private ObservableCollection<TopEndpointItem> _topLatencySources = [];
    [ObservableProperty] private ObservableCollection<TopEndpointItem> _topLatencyDestinations = [];
    [ObservableProperty] private ObservableCollection<TopEndpointItem> _topJitterSources = [];
    [ObservableProperty] private ObservableCollection<TopEndpointItem> _topJitterDestinations = [];

    // Extended collections for Dashboard-style tables (with Rank and Percentage)
    [ObservableProperty] private ObservableCollection<TopEndpointItemExtended> _topQoSSourcesExtended = [];
    [ObservableProperty] private ObservableCollection<TopEndpointItemExtended> _topQoSDestinationsExtended = [];
    [ObservableProperty] private ObservableCollection<TopEndpointItemExtended> _topLatencySourcesExtended = [];
    [ObservableProperty] private ObservableCollection<TopEndpointItemExtended> _topLatencyDestinationsExtended = [];
    [ObservableProperty] private ObservableCollection<TopEndpointItemExtended> _topJitterSourcesExtended = [];
    [ObservableProperty] private ObservableCollection<TopEndpointItemExtended> _topJitterDestinationsExtended = [];

    /// <summary>
    /// Updates top endpoints from the provided filtered collections.
    /// Call this after applying filters to refresh the top talkers/listeners.
    /// Uses fingerprinting for early-exit and single-pass aggregation for each category.
    /// </summary>
    public void UpdateTopEndpoints(
        IEnumerable<QoSTrafficItem> qosTraffic,
        IEnumerable<LatencyConnectionItem> latencyConnections,
        IEnumerable<JitterConnectionItem> jitterConnections)
    {
        // Materialize once to avoid multiple enumeration
        var qosList = qosTraffic as IList<QoSTrafficItem> ?? qosTraffic.ToList();
        var latencyList = latencyConnections as IList<LatencyConnectionItem> ?? latencyConnections.ToList();
        var jitterList = jitterConnections as IList<JitterConnectionItem> ?? jitterConnections.ToList();

        // Fingerprint check for early-exit
        var fingerprint = $"{qosList.Count}|{latencyList.Count}|{jitterList.Count}";
        if (fingerprint == _lastEndpointsFingerprint)
        {
            DebugLogger.Log("[VoiceQoSStatisticsViewModel] SKIPPING UpdateTopEndpoints - data unchanged");
            return;
        }
        _lastEndpointsFingerprint = fingerprint;

        // Single-pass QoS aggregation: build both source and destination maps in one iteration
        var qosSrcMap = new Dictionary<string, (int flowCount, int packetCount, long totalBytes)>();
        var qosDstMap = new Dictionary<string, (int flowCount, int packetCount, long totalBytes)>();
        foreach (var q in qosList)
        {
            if (!qosSrcMap.TryGetValue(q.SourceIP, out var srcVal))
                srcVal = (0, 0, 0);
            qosSrcMap[q.SourceIP] = (srcVal.flowCount + 1, srcVal.packetCount + q.PacketCount, srcVal.totalBytes + q.TotalBytes);

            if (!qosDstMap.TryGetValue(q.DestinationIP, out var dstVal))
                dstVal = (0, 0, 0);
            qosDstMap[q.DestinationIP] = (dstVal.flowCount + 1, dstVal.packetCount + q.PacketCount, dstVal.totalBytes + q.TotalBytes);
        }

        var qosSources = qosSrcMap
            .Select(kvp => new TopEndpointItem { IPAddress = kvp.Key, FlowCount = kvp.Value.flowCount, PacketCount = kvp.Value.packetCount, TotalBytes = kvp.Value.totalBytes, MetricType = "QoS Flows" })
            .OrderByDescending(x => x.PacketCount).Take(30).ToList();
        var qosDests = qosDstMap
            .Select(kvp => new TopEndpointItem { IPAddress = kvp.Key, FlowCount = kvp.Value.flowCount, PacketCount = kvp.Value.packetCount, TotalBytes = kvp.Value.totalBytes, MetricType = "QoS Flows" })
            .OrderByDescending(x => x.PacketCount).Take(30).ToList();

        // Single-pass Latency aggregation
        var latSrcMap = new Dictionary<string, (int flowCount, int packetCount, double latencySum)>();
        var latDstMap = new Dictionary<string, (int flowCount, int packetCount, double latencySum)>();
        foreach (var l in latencyList)
        {
            if (!latSrcMap.TryGetValue(l.SourceIP, out var srcVal))
                srcVal = (0, 0, 0);
            latSrcMap[l.SourceIP] = (srcVal.flowCount + 1, srcVal.packetCount + l.PacketCount, srcVal.latencySum + l.AverageLatency);

            if (!latDstMap.TryGetValue(l.DestinationIP, out var dstVal))
                dstVal = (0, 0, 0);
            latDstMap[l.DestinationIP] = (dstVal.flowCount + 1, dstVal.packetCount + l.PacketCount, dstVal.latencySum + l.AverageLatency);
        }

        var latencySources = latSrcMap
            .Select(kvp => new TopEndpointItem { IPAddress = kvp.Key, FlowCount = kvp.Value.flowCount, PacketCount = kvp.Value.packetCount, AverageMetric = kvp.Value.flowCount > 0 ? kvp.Value.latencySum / kvp.Value.flowCount : 0, MetricType = "Latency" })
            .OrderByDescending(x => x.PacketCount).Take(30).ToList();
        var latencyDests = latDstMap
            .Select(kvp => new TopEndpointItem { IPAddress = kvp.Key, FlowCount = kvp.Value.flowCount, PacketCount = kvp.Value.packetCount, AverageMetric = kvp.Value.flowCount > 0 ? kvp.Value.latencySum / kvp.Value.flowCount : 0, MetricType = "Latency" })
            .OrderByDescending(x => x.PacketCount).Take(30).ToList();

        // Single-pass Jitter aggregation
        var jitSrcMap = new Dictionary<string, (int flowCount, int packetCount, double jitterSum)>();
        var jitDstMap = new Dictionary<string, (int flowCount, int packetCount, double jitterSum)>();
        foreach (var j in jitterList)
        {
            if (!jitSrcMap.TryGetValue(j.SourceIP, out var srcVal))
                srcVal = (0, 0, 0);
            jitSrcMap[j.SourceIP] = (srcVal.flowCount + 1, srcVal.packetCount + j.PacketCount, srcVal.jitterSum + j.AverageJitter);

            if (!jitDstMap.TryGetValue(j.DestinationIP, out var dstVal))
                dstVal = (0, 0, 0);
            jitDstMap[j.DestinationIP] = (dstVal.flowCount + 1, dstVal.packetCount + j.PacketCount, dstVal.jitterSum + j.AverageJitter);
        }

        var jitterSources = jitSrcMap
            .Select(kvp => new TopEndpointItem { IPAddress = kvp.Key, FlowCount = kvp.Value.flowCount, PacketCount = kvp.Value.packetCount, AverageMetric = kvp.Value.flowCount > 0 ? kvp.Value.jitterSum / kvp.Value.flowCount : 0, MetricType = "Jitter" })
            .OrderByDescending(x => x.PacketCount).Take(30).ToList();
        var jitterDests = jitDstMap
            .Select(kvp => new TopEndpointItem { IPAddress = kvp.Key, FlowCount = kvp.Value.flowCount, PacketCount = kvp.Value.packetCount, AverageMetric = kvp.Value.flowCount > 0 ? kvp.Value.jitterSum / kvp.Value.flowCount : 0, MetricType = "Jitter" })
            .OrderByDescending(x => x.PacketCount).Take(30).ToList();

        // Update UI collections (with thread-safety)
        Dispatcher.InvokeAsync(() =>
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
