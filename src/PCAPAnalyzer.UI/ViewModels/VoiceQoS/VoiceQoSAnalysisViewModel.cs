using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.Cache;
using PCAPAnalyzer.Core.Services.VoiceQoS;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.VoiceQoS;

/// <summary>
/// Manages VoiceQoS packet analysis including QoS traffic, latency, and jitter detection.
/// Handles cache loading/saving and provides analysis results to the main ViewModel.
/// </summary>
public partial class VoiceQoSAnalysisViewModel : ObservableObject
{
    private readonly IAnalysisCacheService? _cacheService;
    private string? _currentFilePath;
    private string? _currentCacheKey;

    // Protocol-specific minimum packet thresholds (industry best practices)
    private const int MinPacketsRTP = 50;    // RFC 3550: Need 50+ for reliable RTCP stats
    private const int MinPacketsTCP = 10;    // Need handshake + data + ACKs
    private const int MinPacketsUDP = 20;    // No reliability, need more samples
    private const int MinPacketsOther = 10;  // Default for other protocols

    // Analysis results (unfiltered "all" collections)
    public List<QoSTrafficItem> AllQoSTraffic { get; private set; } = [];
    public List<LatencyConnectionItem> AllLatencyConnections { get; private set; } = [];
    public List<JitterConnectionItem> AllJitterConnections { get; private set; } = [];
    public List<PacketInfo> AllPackets { get; private set; } = [];

    // Pre-aggregated chart data (generated ONCE during analysis)
    public VoiceQoSTimeSeriesData? CachedTimeSeriesData { get; private set; }

    // Event fired when analysis completes
    public event Action<VoiceQoSAnalysisCompletedEventArgs>? AnalysisCompleted;

    public VoiceQoSAnalysisViewModel(IAnalysisCacheService? cacheService = null)
    {
        _cacheService = cacheService;
    }

    /// <summary>
    /// Sets the current file path for cache key generation.
    /// </summary>
    public void SetCurrentFile(string filePath)
    {
        _currentFilePath = filePath;
        _currentCacheKey = null;
        DebugLogger.Log($"[VoiceQoSAnalysisViewModel] Current file set: {filePath}");
    }

    /// <summary>
    /// Analyzes packets for QoS, latency, and jitter metrics.
    /// </summary>
    /// <param name="packets">Packets to analyze</param>
    /// <param name="latencyThreshold">Latency threshold in ms</param>
    /// <param name="jitterThreshold">Jitter threshold in ms</param>
    /// <param name="minimumPacketThreshold">Minimum packets for statistical reliability</param>
    public async Task AnalyzePacketsAsync(
        IReadOnlyList<PacketInfo> packets,
        double latencyThreshold,
        double jitterThreshold,
        int minimumPacketThreshold)
    {
        var startTime = DateTime.Now;
        var packetList = packets as List<PacketInfo> ?? packets.ToList();
        AllPackets = packetList;

        DebugLogger.Log($"[VoiceQoSAnalysisViewModel] Starting analysis of {packetList.Count:N0} packets");

        // TRY CACHE FIRST
        var cachedResult = await TryLoadFromCacheAsync(startTime);
        if (cachedResult is not null)
        {
            RestoreFromCache(cachedResult, latencyThreshold, jitterThreshold);
            GenerateChartData();

            NotifyAnalysisCompleted(true, startTime);
            return;
        }

        // CACHE MISS - Perform full analysis
        DebugLogger.Log($"[VoiceQoSAnalysisViewModel] Cache miss - performing fresh analysis");

        await Task.Run(() =>
        {
            AnalyzeQoSTraffic(packetList);
            AnalyzeLatency(packetList, latencyThreshold, minimumPacketThreshold);
            AnalyzeJitter(packetList, jitterThreshold, minimumPacketThreshold);
        });

        // Generate chart data
        GenerateChartData();

        // Save to cache
        SaveToCache();

        NotifyAnalysisCompleted(false, startTime);
    }

    /// <summary>
    /// Sets analysis data from pre-computed cache (used by ITabPopulationTarget).
    /// </summary>
    public void SetFromCache(VoiceQoSAnalysisResult analysisResult, VoiceQoSTimeSeriesData? timeSeriesData, IReadOnlyList<PacketInfo> packets)
    {
        AllPackets = packets.ToList();
        CachedTimeSeriesData = timeSeriesData;

        // Convert Core models to UI models
        AllQoSTraffic = analysisResult.QoSTraffic.Select(q => new QoSTrafficItem
        {
            SourceIP = q.SourceIP,
            DestinationIP = q.DestinationIP,
            Protocol = q.Protocol,
            PacketCount = q.PacketCount,
            TotalBytes = q.TotalBytes,
            FirstSeen = q.FirstSeen,
            LastSeen = q.LastSeen,
            QoSType = q.QoSType,
            PortRange = q.PortRange,
            DscpMarking = q.DscpMarking,
            DscpValue = q.DscpValue,
            Packets = new List<PacketInfo>()
        }).ToList();

        AllLatencyConnections = analysisResult.HighLatencyConnections.Select(l => new LatencyConnectionItem
        {
            SourceIP = l.SourceIP,
            DestinationIP = l.DestinationIP,
            Protocol = l.Protocol,
            AverageLatency = l.AverageLatency,
            MaxLatency = l.MaxLatency,
            MinLatency = l.MinLatency,
            PacketCount = l.PacketCount,
            FirstSeen = l.FirstSeen,
            LastSeen = l.LastSeen,
            PortRange = l.PortRange,
            Packets = new List<PacketInfo>()
        }).ToList();

        AllJitterConnections = analysisResult.HighJitterConnections.Select(j => new JitterConnectionItem
        {
            SourceIP = j.SourceIP,
            DestinationIP = j.DestinationIP,
            Protocol = j.Protocol,
            AverageJitter = j.AverageJitter,
            MaxJitter = j.MaxJitter,
            MinJitter = j.MinJitter,
            PacketCount = j.PacketCount,
            FirstSeen = j.FirstSeen,
            LastSeen = j.LastSeen,
            PortRange = j.PortRange,
            Packets = new List<PacketInfo>()
        }).ToList();

        DebugLogger.Log($"[VoiceQoSAnalysisViewModel] SetFromCache - QoS: {AllQoSTraffic.Count}, Latency: {AllLatencyConnections.Count}, Jitter: {AllJitterConnections.Count}");
    }

    #region Analysis Methods

    private void AnalyzeQoSTraffic(List<PacketInfo> packets)
    {
        var qosPackets = new List<QoSTrafficItem>();

        var flows = packets
            .Where(p => !string.IsNullOrEmpty(p.SourceIP) && !string.IsNullOrEmpty(p.DestinationIP))
            .GroupBy(p => new { p.SourceIP, p.DestinationIP, p.Protocol })
            .ToList();

        foreach (var flow in flows)
        {
            var isQoS = flow.Any(p =>
                (p.SourcePort >= 16384 && p.SourcePort <= 32767) ||
                (p.DestinationPort >= 16384 && p.DestinationPort <= 32767) ||
                p.SourcePort == 5060 || p.DestinationPort == 5060 ||
                p.SourcePort == 5061 || p.DestinationPort == 5061 ||
                (p.L7Protocol?.Contains("RTP", StringComparison.OrdinalIgnoreCase) ?? false) ||
                (p.L7Protocol?.Contains("SIP", StringComparison.OrdinalIgnoreCase) ?? false) ||
                (p.Info?.Contains("SIP", StringComparison.OrdinalIgnoreCase) ?? false) ||
                (p.Info?.Contains("RTP", StringComparison.OrdinalIgnoreCase) ?? false)
            );

            if (isQoS)
            {
                var flowPackets = flow.ToList();
                var totalBytes = flowPackets.Sum(p => p.Length);
                var qosType = DetermineQoSType(flowPackets);
                var (dscpMarking, dscpValue) = DetermineDscpMarking(qosType);
                var portRange = DeterminePortRange(flowPackets);

                qosPackets.Add(new QoSTrafficItem
                {
                    SourceIP = flow.Key.SourceIP,
                    DestinationIP = flow.Key.DestinationIP,
                    Protocol = flow.Key.Protocol.ToString(),
                    PacketCount = flowPackets.Count,
                    TotalBytes = totalBytes,
                    FirstSeen = flowPackets.Min(p => p.Timestamp),
                    LastSeen = flowPackets.Max(p => p.Timestamp),
                    QoSType = qosType,
                    PortRange = portRange,
                    DscpMarking = dscpMarking,
                    DscpValue = dscpValue,
                    Packets = flowPackets
                });
            }
        }

        AllQoSTraffic = qosPackets;
        DebugLogger.Log($"[VoiceQoSAnalysisViewModel] QoS analysis complete: {qosPackets.Count} flows, {qosPackets.Sum(q => q.PacketCount)} packets");
    }

    private void AnalyzeLatency(List<PacketInfo> packets, double latencyThreshold, int minimumPacketThreshold)
    {
        var latencyConnections = new List<LatencyConnectionItem>();

        var flows = packets
            .Where(p => !string.IsNullOrEmpty(p.SourceIP) && !string.IsNullOrEmpty(p.DestinationIP))
            .GroupBy(p => new
            {
                IP1 = string.Compare(p.SourceIP, p.DestinationIP, StringComparison.Ordinal) < 0 ? p.SourceIP : p.DestinationIP,
                IP2 = string.Compare(p.SourceIP, p.DestinationIP, StringComparison.Ordinal) < 0 ? p.DestinationIP : p.SourceIP,
                p.Protocol
            })
            .ToList();

        foreach (var flow in flows)
        {
            var flowPackets = flow.OrderBy(p => p.Timestamp).ToList();

            int minPackets = GetMinimumPacketThreshold(flow.Key.Protocol.ToString(), flowPackets, minimumPacketThreshold);
            if (flowPackets.Count < minPackets) continue;

            var intervals = new List<double>();
            for (int i = 1; i < flowPackets.Count; i++)
            {
                var interval = (flowPackets[i].Timestamp - flowPackets[i - 1].Timestamp).TotalMilliseconds;
                if (interval > 0 && interval < 10000)
                    intervals.Add(interval);
            }

            if (intervals.Any())
            {
                var avgLatency = intervals.Average();
                var maxLat = intervals.Max();
                var minLat = intervals.Min();
                var sortedIntervals = intervals.OrderBy(x => x).ToList();
                var p5Latency = CalculatePercentile(sortedIntervals, 5);
                var p95Latency = CalculatePercentile(sortedIntervals, 95);
                var portRange = DeterminePortRange(flowPackets);

                if (avgLatency >= latencyThreshold / 10)
                {
                    latencyConnections.Add(new LatencyConnectionItem
                    {
                        SourceIP = flow.Key.IP1,
                        DestinationIP = flow.Key.IP2,
                        Protocol = flow.Key.Protocol.ToString(),
                        AverageLatency = avgLatency,
                        MaxLatency = maxLat,
                        MinLatency = minLat,
                        P5Latency = p5Latency,
                        P95Latency = p95Latency,
                        PacketCount = flowPackets.Count,
                        FirstSeen = flowPackets.First().Timestamp,
                        LastSeen = flowPackets.Last().Timestamp,
                        PortRange = portRange,
                        Packets = flowPackets
                    });
                }
            }
        }

        AllLatencyConnections = latencyConnections;
        DebugLogger.Log($"[VoiceQoSAnalysisViewModel] Latency analysis complete: {latencyConnections.Count} high-latency connections");
    }

    private void AnalyzeJitter(List<PacketInfo> packets, double jitterThreshold, int minimumPacketThreshold)
    {
        var jitterConnections = new List<JitterConnectionItem>();

        var flows = packets
            .Where(p => !string.IsNullOrEmpty(p.SourceIP) && !string.IsNullOrEmpty(p.DestinationIP))
            .GroupBy(p => new
            {
                IP1 = string.Compare(p.SourceIP, p.DestinationIP, StringComparison.Ordinal) < 0 ? p.SourceIP : p.DestinationIP,
                IP2 = string.Compare(p.SourceIP, p.DestinationIP, StringComparison.Ordinal) < 0 ? p.DestinationIP : p.SourceIP,
                p.Protocol
            })
            .ToList();

        foreach (var flow in flows)
        {
            var flowPackets = flow.OrderBy(p => p.Timestamp).ToList();

            int minPackets = GetMinimumPacketThreshold(flow.Key.Protocol.ToString(), flowPackets, minimumPacketThreshold);
            if (flowPackets.Count < minPackets) continue;

            var intervals = new List<double>();
            for (int i = 1; i < flowPackets.Count; i++)
            {
                var interval = (flowPackets[i].Timestamp - flowPackets[i - 1].Timestamp).TotalMilliseconds;
                if (interval > 0 && interval < 10000)
                    intervals.Add(interval);
            }

            if (intervals.Count >= 2)
            {
                var mean = intervals.Average();
                var variance = intervals.Sum(x => Math.Pow(x - mean, 2)) / intervals.Count;
                var jitter = Math.Sqrt(variance);
                var maxJitter = intervals.Max() - intervals.Min();
                var sortedIntervals = intervals.OrderBy(x => x).ToList();
                var p5Jitter = CalculatePercentile(sortedIntervals, 5);
                var p95Jitter = CalculatePercentile(sortedIntervals, 95);
                var portRange = DeterminePortRange(flowPackets);

                if (jitter >= jitterThreshold / 10)
                {
                    jitterConnections.Add(new JitterConnectionItem
                    {
                        SourceIP = flow.Key.IP1,
                        DestinationIP = flow.Key.IP2,
                        Protocol = flow.Key.Protocol.ToString(),
                        AverageJitter = jitter,
                        MaxJitter = maxJitter,
                        MinJitter = 0.0,
                        P5Jitter = p5Jitter,
                        P95Jitter = p95Jitter,
                        PacketCount = flowPackets.Count,
                        FirstSeen = flowPackets.First().Timestamp,
                        LastSeen = flowPackets.Last().Timestamp,
                        PortRange = portRange,
                        Packets = flowPackets
                    });
                }
            }
        }

        AllJitterConnections = jitterConnections;
        DebugLogger.Log($"[VoiceQoSAnalysisViewModel] Jitter analysis complete: {jitterConnections.Count} high-jitter connections");
    }

    #endregion

    #region Helper Methods

    private int GetMinimumPacketThreshold(string protocol, List<PacketInfo> packets, int baselineThreshold)
    {
        if (protocol.Equals("UDP", StringComparison.OrdinalIgnoreCase))
        {
            var ports = packets.Select(p => p.SourcePort).Concat(packets.Select(p => p.DestinationPort))
                              .Where(p => p > 0).Distinct().ToList();

            bool isLikelyRTP = ports.Any(p => (p >= 16384 && p <= 32767) || (p >= 5004 && p <= 5100));

            if (isLikelyRTP)
                return Math.Max(baselineThreshold, MinPacketsRTP);

            return Math.Max(baselineThreshold, MinPacketsUDP);
        }

        if (protocol.Equals("TCP", StringComparison.OrdinalIgnoreCase))
            return Math.Max(baselineThreshold, MinPacketsTCP);

        return Math.Max(baselineThreshold, MinPacketsOther);
    }

    private static double CalculatePercentile(List<double> sortedValues, double percentile)
    {
        if (sortedValues is null || sortedValues.Count == 0) return 0;
        if (sortedValues.Count == 1) return sortedValues[0];

        double index = (percentile / 100.0) * (sortedValues.Count - 1);
        int lowerIndex = (int)Math.Floor(index);
        int upperIndex = (int)Math.Ceiling(index);

        if (lowerIndex == upperIndex) return sortedValues[lowerIndex];

        double weight = index - lowerIndex;
        return sortedValues[lowerIndex] * (1 - weight) + sortedValues[upperIndex] * weight;
    }

    private static string DetermineQoSType(List<PacketInfo> packets)
    {
        if (packets.Any(p => p.L7Protocol?.Contains("RTP", StringComparison.OrdinalIgnoreCase) ?? false))
            return "RTP (Voice/Video)";
        if (packets.Any(p => p.L7Protocol?.Contains("SIP", StringComparison.OrdinalIgnoreCase) ?? false))
            return "SIP (Signaling)";
        if (packets.Any(p => p.SourcePort == 5060 || p.DestinationPort == 5060))
            return "SIP";
        if (packets.Any(p => (p.SourcePort >= 16384 && p.SourcePort <= 32767) ||
                             (p.DestinationPort >= 16384 && p.DestinationPort <= 32767)))
            return "RTP/Media";

        return "QoS Marked";
    }

    private static (string marking, int value) DetermineDscpMarking(string qosType)
    {
        return qosType switch
        {
            "RTP (Voice/Video)" => ("EF", 46),
            "SIP (Signaling)" => ("CS3", 24),
            "RTP/Media" => ("AF41", 34),
            "SIP" => ("CS3", 24),
            _ => ("BE", 0)
        };
    }

    private static string DeterminePortRange(List<PacketInfo> packets)
    {
        var ports = new HashSet<ushort>();
        foreach (var p in packets)
        {
            if (p.SourcePort > 0) ports.Add(p.SourcePort);
            if (p.DestinationPort > 0) ports.Add(p.DestinationPort);
        }

        if (ports.Count == 0) return "N/A";
        if (ports.Count == 1) return ports.First().ToString();
        if (ports.Count == 2) return $"{ports.Min()}, {ports.Max()}";

        return $"{ports.Min()}-{ports.Max()} ({ports.Count} ports)";
    }

    #endregion

    #region Cache Methods

    private async Task<VoiceQoSAnalysisResult?> TryLoadFromCacheAsync(DateTime startTime)
    {
        if (_cacheService is null || string.IsNullOrEmpty(_currentFilePath))
            return null;

        try
        {
            if (string.IsNullOrEmpty(_currentCacheKey))
            {
                _currentCacheKey = await _cacheService.ComputeCacheKeyAsync(_currentFilePath);
                DebugLogger.Log($"[VoiceQoSAnalysisViewModel] Cache key computed: {_currentCacheKey}");
            }

            var isCached = await _cacheService.IsCachedAsync(_currentCacheKey, "VoiceQoS");
            if (!isCached) return null;

            var cachedData = await _cacheService.LoadVoiceQoSAsync(_currentCacheKey);

            if (cachedData is not null && (cachedData.QoSTraffic.Count > 0 || cachedData.HighLatencyConnections.Count > 0 || cachedData.HighJitterConnections.Count > 0))
            {
                var elapsed = (DateTime.Now - startTime).TotalSeconds;
                DebugLogger.Log($"[VoiceQoSAnalysisViewModel] LOADED FROM CACHE in {elapsed:F2}s");
                return cachedData;
            }

            return null;
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[VoiceQoSAnalysisViewModel] Cache error: {ex.Message}");
            return null;
        }
    }

    private void RestoreFromCache(VoiceQoSAnalysisResult cached, double latencyThreshold, double jitterThreshold)
    {
        var (qos, latency, jitter) = ConvertFromCacheModel(cached);
        AllQoSTraffic = qos;
        AllLatencyConnections = latency;
        AllJitterConnections = jitter;

        DebugLogger.Log($"[VoiceQoSAnalysisViewModel] Restored from cache - QoS: {qos.Count}, Latency: {latency.Count}, Jitter: {jitter.Count}");
    }

    private void SaveToCache()
    {
        if (_cacheService is null || string.IsNullOrEmpty(_currentCacheKey))
            return;

        var cacheData = ConvertToCacheModel(AllQoSTraffic, AllLatencyConnections, AllJitterConnections);

        _ = Task.Run(async () =>
        {
            try
            {
                await _cacheService.SaveVoiceQoSAsync(_currentCacheKey, cacheData);
                DebugLogger.Log($"[VoiceQoSAnalysisViewModel] Saved to cache: QoS={cacheData.QoSTraffic.Count}");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[VoiceQoSAnalysisViewModel] Error saving to cache: {ex.Message}");
            }
        });
    }

    private void GenerateChartData()
    {
        var chartStartTime = DateTime.Now;
        var generator = new VoiceQoSTimeSeriesGenerator();

        CachedTimeSeriesData = generator.GenerateTimeSeriesFromFlows(
            AllQoSTraffic.Select(q => q.Packets),
            AllLatencyConnections.Select(l => l.Packets),
            AllJitterConnections.Select(j => j.Packets),
            TimeSpan.FromSeconds(1));

        var elapsed = (DateTime.Now - chartStartTime).TotalMilliseconds;
        DebugLogger.Log($"[VoiceQoSAnalysisViewModel] Chart data generated in {elapsed:F0}ms - {CachedTimeSeriesData.DataPoints.Count} time buckets");
    }

    private static VoiceQoSAnalysisResult ConvertToCacheModel(List<QoSTrafficItem> qos, List<LatencyConnectionItem> latency, List<JitterConnectionItem> jitter)
    {
        return new VoiceQoSAnalysisResult
        {
            QoSTraffic = qos.Select(q => new VoiceQoSTrafficItem
            {
                SourceIP = q.SourceIP, DestinationIP = q.DestinationIP, Protocol = q.Protocol,
                PacketCount = q.PacketCount, TotalBytes = q.TotalBytes, FirstSeen = q.FirstSeen,
                LastSeen = q.LastSeen, QoSType = q.QoSType, PortRange = q.PortRange,
                DscpMarking = q.DscpMarking, DscpValue = q.DscpValue
            }).ToList(),
            HighLatencyConnections = latency.Select(l => new VoiceQoSLatencyItem
            {
                SourceIP = l.SourceIP, DestinationIP = l.DestinationIP, Protocol = l.Protocol,
                AverageLatency = l.AverageLatency, MaxLatency = l.MaxLatency, MinLatency = l.MinLatency,
                PacketCount = l.PacketCount, FirstSeen = l.FirstSeen, LastSeen = l.LastSeen, PortRange = l.PortRange
            }).ToList(),
            HighJitterConnections = jitter.Select(j => new VoiceQoSJitterItem
            {
                SourceIP = j.SourceIP, DestinationIP = j.DestinationIP, Protocol = j.Protocol,
                AverageJitter = j.AverageJitter, MaxJitter = j.MaxJitter, MinJitter = j.MinJitter,
                PacketCount = j.PacketCount, FirstSeen = j.FirstSeen, LastSeen = j.LastSeen, PortRange = j.PortRange
            }).ToList(),
            AnalysisTimestamp = DateTime.UtcNow
        };
    }

    private static (List<QoSTrafficItem>, List<LatencyConnectionItem>, List<JitterConnectionItem>) ConvertFromCacheModel(VoiceQoSAnalysisResult cached)
    {
        var qos = cached.QoSTraffic.Select(q => new QoSTrafficItem
        {
            SourceIP = q.SourceIP, DestinationIP = q.DestinationIP, Protocol = q.Protocol,
            PacketCount = q.PacketCount, TotalBytes = q.TotalBytes, FirstSeen = q.FirstSeen,
            LastSeen = q.LastSeen, QoSType = q.QoSType, PortRange = q.PortRange,
            DscpMarking = q.DscpMarking, DscpValue = q.DscpValue, Packets = new List<PacketInfo>()
        }).ToList();

        var latency = cached.HighLatencyConnections.Select(l => new LatencyConnectionItem
        {
            SourceIP = l.SourceIP, DestinationIP = l.DestinationIP, Protocol = l.Protocol,
            AverageLatency = l.AverageLatency, MaxLatency = l.MaxLatency, MinLatency = l.MinLatency,
            PacketCount = l.PacketCount, FirstSeen = l.FirstSeen, LastSeen = l.LastSeen,
            PortRange = l.PortRange, Packets = new List<PacketInfo>()
        }).ToList();

        var jitter = cached.HighJitterConnections.Select(j => new JitterConnectionItem
        {
            SourceIP = j.SourceIP, DestinationIP = j.DestinationIP, Protocol = j.Protocol,
            AverageJitter = j.AverageJitter, MaxJitter = j.MaxJitter, MinJitter = j.MinJitter,
            PacketCount = j.PacketCount, FirstSeen = j.FirstSeen, LastSeen = j.LastSeen,
            PortRange = j.PortRange, Packets = new List<PacketInfo>()
        }).ToList();

        return (qos, latency, jitter);
    }

    private void NotifyAnalysisCompleted(bool fromCache, DateTime startTime)
    {
        var elapsed = (DateTime.Now - startTime).TotalSeconds;
        DebugLogger.Log($"[VoiceQoSAnalysisViewModel] Analysis completed (fromCache={fromCache}) in {elapsed:F2}s");

        AnalysisCompleted?.Invoke(new VoiceQoSAnalysisCompletedEventArgs
        {
            FromCache = fromCache,
            QoSCount = AllQoSTraffic.Count,
            LatencyCount = AllLatencyConnections.Count,
            JitterCount = AllJitterConnections.Count,
            TotalQoSPackets = AllQoSTraffic.Sum(q => q.PacketCount),
            ElapsedSeconds = elapsed
        });
    }

    #endregion
}

/// <summary>
/// Event args for analysis completion notification.
/// </summary>
public class VoiceQoSAnalysisCompletedEventArgs
{
    public bool FromCache { get; init; }
    public int QoSCount { get; init; }
    public int LatencyCount { get; init; }
    public int JitterCount { get; init; }
    public int TotalQoSPackets { get; init; }
    public double ElapsedSeconds { get; init; }
}
