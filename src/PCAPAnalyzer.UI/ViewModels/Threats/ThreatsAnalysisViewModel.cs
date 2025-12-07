using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.ViewModels.Threats;

/// <summary>
/// Manages threat analysis, detection, and cache operations.
/// Extracted from ThreatsViewModel to isolate detection logic from UI state.
/// </summary>
public partial class ThreatsAnalysisViewModel : ObservableObject
{
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    private readonly IInsecurePortDetector _insecurePortDetector;
    private readonly IUnifiedAnomalyDetectionService _anomalyService;
    private readonly PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService? _cacheService;

    // Analysis state
    private bool _isAnalyzing;
    private string? _currentFilePath;
    private string? _currentCacheKey;
    private int _lastAnalyzedPacketCount;
    private bool _lastFilterState;

    // Analysis results
    public List<EnhancedSecurityThreat> AllThreats { get; private set; } = [];
    public List<SuricataAlert> SuricataAlerts { get; private set; } = [];
    public List<YaraMatch> YaraMatches { get; private set; } = [];
    public SecurityMetrics? Metrics { get; private set; }

    /// <summary>
    /// Event fired when analysis completes with results
    /// </summary>
    public event Action<List<EnhancedSecurityThreat>, SecurityMetrics?>? AnalysisCompleted;

    public ThreatsAnalysisViewModel(
        IInsecurePortDetector insecurePortDetector,
        IUnifiedAnomalyDetectionService anomalyService,
        PCAPAnalyzer.Core.Services.Cache.IAnalysisCacheService? cacheService = null)
    {
        _insecurePortDetector = insecurePortDetector;
        _anomalyService = anomalyService;
        _cacheService = cacheService;
    }

    /// <summary>
    /// Sets the current file path for cache key computation
    /// </summary>
    public void SetCurrentFile(string filePath)
    {
        _currentFilePath = filePath;
        _currentCacheKey = null;
    }

    /// <summary>
    /// Check if analysis should be skipped (already analyzed same data)
    /// </summary>
    public bool ShouldSkipAnalysis(int packetCount, bool isFilterActive)
    {
        return _lastAnalyzedPacketCount == packetCount &&
               _lastFilterState == isFilterActive &&
               AllThreats.Count > 0;
    }

    /// <summary>
    /// Sets threats from pre-analyzed cache (bypasses detection).
    /// </summary>
    public async Task SetFromCacheAsync(List<SecurityThreat> threats, IReadOnlyList<PacketInfo> packets)
    {
        DebugLogger.Log($"[ThreatsAnalysisViewModel] SetFromCache - {threats.Count:N0} threats");

        AllThreats = threats.Select(t => new EnhancedSecurityThreat
        {
            Category = ThreatCategory.InsecureProtocol,
            Severity = t.Severity,
            ThreatName = t.Type,
            Description = t.Description,
            FirstSeen = t.DetectedAt,
            LastSeen = t.DetectedAt,
            OccurrenceCount = t.AffectedPackets?.Count ?? 1,
            RiskScore = (int)t.Severity * 2,
            Service = t.Type,
            AffectedIPs = new List<string> { t.SourceAddress, t.DestinationAddress }
        }).ToList();

        _lastAnalyzedPacketCount = packets.Count;
        _lastFilterState = false;

        Metrics = _insecurePortDetector.CalculateSecurityMetrics(AllThreats);

        await Dispatcher.InvokeAsync(() =>
            AnalysisCompleted?.Invoke(AllThreats, Metrics));

        DebugLogger.Log($"[ThreatsAnalysisViewModel] SetFromCache complete - {AllThreats.Count:N0} threats");
    }

    /// <summary>
    /// Attempts to load threats from cache.
    /// </summary>
    public async Task<bool> TryLoadFromCacheAsync(int currentPacketCount, bool isFilterActive)
    {
        if (_cacheService is null || string.IsNullOrEmpty(_currentFilePath))
            return false;

        try
        {
            if (string.IsNullOrEmpty(_currentCacheKey))
            {
                _currentCacheKey = await _cacheService.ComputeCacheKeyAsync(_currentFilePath);
                DebugLogger.Log($"[ThreatsAnalysisViewModel] Cache key: {_currentCacheKey}");
            }

            if (!await _cacheService.IsCachedAsync(_currentCacheKey, "Threats"))
                return false;

            var cachedThreats = await _cacheService.LoadThreatsAsync(_currentCacheKey);
            if (cachedThreats is null || cachedThreats.Count == 0)
                return false;

            AllThreats = cachedThreats;
            Metrics = _insecurePortDetector.CalculateSecurityMetrics(AllThreats);
            _lastAnalyzedPacketCount = currentPacketCount;
            _lastFilterState = isFilterActive;
            _isAnalyzing = false;

            await Dispatcher.InvokeAsync(() =>
                AnalysisCompleted?.Invoke(AllThreats, Metrics));

            DebugLogger.Log($"[ThreatsAnalysisViewModel] LOADED FROM CACHE - {AllThreats.Count:N0} threats");
            return true;
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[ThreatsAnalysisViewModel] Cache error: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Saves threats to cache asynchronously.
    /// </summary>
    public void TrySaveToCache()
    {
        if (_cacheService is null || string.IsNullOrEmpty(_currentCacheKey))
            return;

        _ = Task.Run(async () =>
        {
            try
            {
                await _cacheService.SaveThreatsAsync(_currentCacheKey, AllThreats);
                DebugLogger.Log($"[ThreatsAnalysisViewModel] Saved {AllThreats.Count:N0} threats to cache");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[ThreatsAnalysisViewModel] Cache save error: {ex.Message}");
            }
        });
    }

    /// <summary>
    /// Performs threat detection on packets.
    /// </summary>
    public async Task AnalyzeAsync(List<PacketInfo> packets, int currentPacketCount, bool isFilterActive)
    {
        if (_isAnalyzing) return;
        _isAnalyzing = true;

        var startTime = DateTime.Now;

        await Task.Run(async () =>
        {
            DebugLogger.Log($"[ThreatsAnalysisViewModel] Starting threat detection on {packets.Count:N0} packets...");
            const int BATCH_SIZE = 100_000;
            var allThreatsCollection = new ConcurrentBag<EnhancedSecurityThreat>();

            if (packets.Count > 500_000)
            {
                // Large dataset - parallel batch processing
                DebugLogger.Log($"[ThreatsAnalysisViewModel] Using parallel batch processing");

                var monitoredPorts = new HashSet<int> { 21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443 };
                var versionCheckPackets = packets.Where(p =>
                    monitoredPorts.Contains(p.DestinationPort) || monitoredPorts.Contains(p.SourcePort)).ToList();

                var batches = CreateBatches(packets, BATCH_SIZE);
                var versionBatches = CreateBatches(versionCheckPackets, BATCH_SIZE);

                await Parallel.ForEachAsync(batches, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                    async (batch, ct) =>
                    {
                        var batchThreats = _insecurePortDetector.DetectInsecurePorts(batch);
                        var batchAnomalies = await _anomalyService.DetectAllAnomaliesAsync(batch);

                        foreach (var threat in batchThreats)
                            allThreatsCollection.Add(threat);

                        foreach (var anomaly in batchAnomalies.Where(a => a.Severity >= AnomalySeverity.Medium))
                            allThreatsCollection.Add(ConvertAnomalyToThreat(anomaly));
                    });

                if (versionCheckPackets.Count > 0)
                {
                    await Parallel.ForEachAsync(versionBatches, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                        async (batch, ct) =>
                        {
                            var versionThreats = _insecurePortDetector.DetectInsecureVersions(batch);
                            foreach (var threat in versionThreats)
                                allThreatsCollection.Add(threat);
                            await Task.CompletedTask;
                        });
                }

                AllThreats = allThreatsCollection.ToList();
            }
            else
            {
                // Sequential for smaller datasets
                AllThreats = _insecurePortDetector.DetectInsecurePorts(packets);
                var versionThreats = _insecurePortDetector.DetectInsecureVersions(packets);
                AllThreats.AddRange(versionThreats);

                var anomalies = await _anomalyService.DetectAllAnomaliesAsync(packets);
                foreach (var anomaly in anomalies.Where(a => a.Severity >= AnomalySeverity.Medium))
                    AllThreats.Add(ConvertAnomalyToThreat(anomaly));
            }

            // Ensure valid risk scores
            foreach (var threat in AllThreats.Where(t => t.RiskScore == 0))
            {
                threat.RiskScore = threat.Severity switch
                {
                    ThreatSeverity.Critical => 9.0,
                    ThreatSeverity.High => 7.0,
                    ThreatSeverity.Medium => 5.0,
                    ThreatSeverity.Low => 3.0,
                    _ => 1.0
                };
            }

            Metrics = _insecurePortDetector.CalculateSecurityMetrics(AllThreats);

            var elapsed = (DateTime.Now - startTime).TotalSeconds;
            DebugLogger.Log($"[ThreatsAnalysisViewModel] Detection complete in {elapsed:F2}s - {AllThreats.Count:N0} threats");
        });

        _lastAnalyzedPacketCount = currentPacketCount;
        _lastFilterState = isFilterActive;
        _isAnalyzing = false;

        await Dispatcher.InvokeAsync(() =>
            AnalysisCompleted?.Invoke(AllThreats, Metrics));

        TrySaveToCache();
    }

    /// <summary>
    /// Add Suricata alerts to threat list
    /// </summary>
    public void AddSuricataAlerts(List<SuricataAlert> alerts)
    {
        SuricataAlerts = alerts;
        if (alerts is null || alerts.Count == 0) return;

        foreach (var alert in alerts)
        {
            AllThreats.Add(new EnhancedSecurityThreat
            {
                Category = ThreatCategory.MaliciousActivity,
                Severity = alert.Severity >= 4 ? ThreatSeverity.Critical :
                          alert.Severity == 3 ? ThreatSeverity.High :
                          alert.Severity == 2 ? ThreatSeverity.Medium : ThreatSeverity.Low,
                ThreatName = alert.AlertSignature ?? "Suricata Alert",
                Description = alert.AlertCategory ?? "Suricata detection",
                FirstSeen = alert.Timestamp,
                LastSeen = alert.Timestamp,
                OccurrenceCount = 1,
                RiskScore = alert.Severity >= 4 ? 9 : alert.Severity == 3 ? 7 : alert.Severity == 2 ? 5 : 3,
                Service = "Suricata",
                AffectedIPs = new List<string> { alert.SourceIP, alert.DestinationIP },
                Metadata = new Dictionary<string, object>
                {
                    ["SuricataJson"] = alert.RawJson,
                    ["SuricataSeverity"] = alert.Severity
                }
            });
        }

        Metrics = _insecurePortDetector.CalculateSecurityMetrics(AllThreats);
        AnalysisCompleted?.Invoke(AllThreats, Metrics);
    }

    /// <summary>
    /// Add YARA matches to threat list
    /// </summary>
    public void AddYaraMatches(List<YaraMatch> matches)
    {
        YaraMatches = matches;
        if (matches is null || matches.Count == 0) return;

        foreach (var match in matches)
        {
            AllThreats.Add(new EnhancedSecurityThreat
            {
                Category = ThreatCategory.KnownVulnerability,
                Severity = ThreatSeverity.Medium,
                ThreatName = $"YARA: {match.RuleName}",
                Description = $"YARA rule matched on {match.Target}",
                FirstSeen = DateTime.Now,
                LastSeen = DateTime.Now,
                OccurrenceCount = 1,
                RiskScore = 5,
                Service = match.Namespace,
                Metadata = new Dictionary<string, object>
                {
                    ["YaraRule"] = match.RuleName,
                    ["YaraNamespace"] = match.Namespace,
                    ["RawLine"] = match.RawLine
                }
            });
        }

        Metrics = _insecurePortDetector.CalculateSecurityMetrics(AllThreats);
        AnalysisCompleted?.Invoke(AllThreats, Metrics);
    }

    private static List<List<T>> CreateBatches<T>(List<T> source, int batchSize)
    {
        var batches = new List<List<T>>();
        for (int i = 0; i < source.Count; i += batchSize)
        {
            var size = Math.Min(batchSize, source.Count - i);
            batches.Add(source.GetRange(i, size));
        }
        return batches;
    }

    private static EnhancedSecurityThreat ConvertAnomalyToThreat(NetworkAnomaly anomaly)
    {
        return new EnhancedSecurityThreat
        {
            Category = anomaly.Category switch
            {
                AnomalyCategory.Security => ThreatCategory.KnownVulnerability,
                _ => ThreatCategory.MaliciousActivity
            },
            Severity = anomaly.Severity switch
            {
                AnomalySeverity.Critical => ThreatSeverity.Critical,
                AnomalySeverity.High => ThreatSeverity.High,
                AnomalySeverity.Medium => ThreatSeverity.Medium,
                AnomalySeverity.Low => ThreatSeverity.Low,
                _ => ThreatSeverity.Info
            },
            ThreatName = anomaly.Type,
            Description = anomaly.Description,
            FirstSeen = anomaly.DetectedAt,
            LastSeen = anomaly.DetectedAt,
            OccurrenceCount = 1,
            RiskScore = anomaly.Severity == AnomalySeverity.Critical ? 9 :
                       anomaly.Severity == AnomalySeverity.High ? 7 : 5,
            AffectedIPs = new List<string> { anomaly.SourceIP, anomaly.DestinationIP }
                .Where(ip => !string.IsNullOrEmpty(ip))
                .Distinct()
                .ToList()
        };
    }
}
