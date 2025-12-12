using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Threat detection logic for ThreatsViewModel.
/// Contains UpdateThreatsAsync and parallel batch processing.
/// </summary>
public partial class ThreatsViewModel
{
    /// <summary>
    /// Sets the filtered packet set and re-analyzes threats from filtered packets only.
    /// Called by MainWindowViewModel when global filters are applied.
    /// This bypasses the cache to ensure threats are recalculated from the filtered packet set.
    /// </summary>
    /// <param name="filteredPackets">The filtered packet list from PacketManager</param>
    public async Task SetFilteredPacketsAsync(IReadOnlyList<PacketInfo> filteredPackets)
    {
        DebugLogger.Log($"[ThreatsViewModel] SetFilteredPacketsAsync called with {filteredPackets.Count:N0} filtered packets");

        // Set filter active flag for Total/Filtered display
        IsGlobalFilterActive = true;

        // Update Statistics component with filtered packet count for Total/Filtered header display
        Statistics.SetFilteredState(filteredPackets.Count, isFiltered: true);

        // Reset cache tracking to force re-analysis
        _lastAnalyzedPacketCount = -1;
        _lastFilterState = false;

        // Clear existing threats to force fresh analysis
        _allThreats.Clear();
        _metrics = null;

        // Re-analyze with filtered packets
        await UpdateThreatsAsync(filteredPackets);

        // Notify percentage property changes
        NotifyThreatPercentageChanges();

        // Update stats bar for filtered state
        UpdateThreatsStatsBar();

        DebugLogger.Log($"[ThreatsViewModel] SetFilteredPacketsAsync complete - {_allThreats.Count:N0} threats from {filteredPackets.Count:N0} packets");
    }

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity", Justification = "Complex threat detection requires filtering, caching, parallel batching, anomaly detection, and UI updates - justified for performance optimization")]
    public async Task UpdateThreatsAsync(IReadOnlyList<PacketInfo> packets)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
        DebugLogger.Log($"[{timestamp}] [ThreatsViewModel] UpdateThreatsAsync starting with {packets.Count:N0} packets");

        // Prevent concurrent analysis
        if (_isAnalyzing)
        {
            DebugLogger.Log($"[{timestamp}] [ThreatsViewModel] Analysis already in progress, skipping redundant call");
            return;
        }

        var startTime = DateTime.Now;

        // Store reference to unfiltered packets (no copy)
        _unfilteredPackets = packets;

        // Apply filter if filter service is available and active
        var isFilterActive = _filterService?.IsFilterActive == true;
        _currentPackets = isFilterActive
            ? _filterService!.GetFilteredPackets(packets).ToList()
            : packets;

        // OPTIMIZATION: Skip analysis if packets and filter state unchanged
        var currentPacketCount = _currentPackets.Count;
        if (_lastAnalyzedPacketCount == currentPacketCount &&
            _lastFilterState == isFilterActive &&
            _allThreats.Count > 0)
        {
            DebugLogger.Log($"[{timestamp}] [ThreatsViewModel] Skipping analysis - already analyzed {currentPacketCount:N0} packets with filter={isFilterActive}");
            return;
        }

        _isAnalyzing = true;

        // Show initial UI with loading state (dispatch to UI thread)
        await _dispatcher.InvokeAsync(() =>
        {
            TotalThreats = 0;
            OverallRiskScore = 0;
            RiskLevel = "Analyzing...";
            RiskLevelColor = ThemeColorHelper.GetColorHex("TextMuted", "#6B7280");
        });

        // TRY CACHE FIRST - delegate to Analysis component
        if (await Analysis.TryLoadFromCacheAsync(currentPacketCount, isFilterActive))
        {
            _isAnalyzing = false;
            return; // OnAnalysisCompleted will update UI
        }

        // PERFORMANCE OPTIMIZATION: Parallel batch processing for large packet sets
        await Task.Run(async () =>
        {
            DebugLogger.Log($"[ThreatsViewModel] Starting PARALLEL threat detection on background thread...");
            var workingSet = _currentPackets ?? _unfilteredPackets;
            DebugLogger.Log($"[ThreatsViewModel] Analyzing {workingSet.Count:N0} packets for threats...");

            const int BATCH_SIZE = 100_000;
            var allThreatsCollection = new System.Collections.Concurrent.ConcurrentBag<EnhancedSecurityThreat>();

            if (workingSet.Count > 500_000)
            {
                await ProcessLargeDatasetAsync(workingSet, allThreatsCollection, BATCH_SIZE);
            }
            else
            {
                await ProcessSmallDatasetAsync(workingSet, allThreatsCollection);
            }

            // Credential threat detection
            DetectCredentialThreats(workingSet, allThreatsCollection);

            // Ensure all threats have valid risk scores
            foreach (var threat in allThreatsCollection.Where(t => t.RiskScore == 0))
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

            _allThreats = allThreatsCollection.ToList();
            _metrics = _insecurePortDetector.CalculateSecurityMetrics(_allThreats);

            var analysisElapsed = (DateTime.Now - startTime).TotalSeconds;
            DebugLogger.Log($"[ThreatsViewModel] Threat analysis complete in {analysisElapsed:F2}s - {_allThreats.Count:N0} total threats");
        });

        // Update UI on UI thread
        await _dispatcher.InvokeAsync(() => UpdateUI());

        // SAVE TO CACHE
        Analysis.TrySaveToCache();

        // Update cache tracking
        _lastAnalyzedPacketCount = currentPacketCount;
        _lastFilterState = isFilterActive;
        _isAnalyzing = false;

        var totalElapsed = (DateTime.Now - startTime).TotalSeconds;
        var endTimestamp = DateTime.Now.ToString("HH:mm:ss.fff");
        DebugLogger.Log($"[{endTimestamp}] [ThreatsViewModel] UpdateThreatsAsync complete in {totalElapsed:F2}s");
    }

    private async Task ProcessLargeDatasetAsync(IReadOnlyList<PacketInfo> workingSet,
        System.Collections.Concurrent.ConcurrentBag<EnhancedSecurityThreat> allThreatsCollection, int batchSize)
    {
        DebugLogger.Log($"[ThreatsViewModel] Large dataset detected - using parallel batch processing (batch size: {batchSize:N0})");

        // Pre-filter for version detection ONCE before batching
        var monitoredPorts = new HashSet<int> { 21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443 };
        var versionCheckPackets = workingSet.Where(p => monitoredPorts.Contains(p.DestinationPort) || monitoredPorts.Contains(p.SourcePort)).ToList();
        DebugLogger.Log($"[ThreatsViewModel] Pre-filtered {versionCheckPackets.Count:N0} packets for version detection");

        // Split into batches
        var batches = CreateBatches(workingSet, batchSize);
        var versionBatches = CreateBatchesFromList(versionCheckPackets, batchSize);

        DebugLogger.Log($"[ThreatsViewModel] Created {batches.Count} full batches + {versionBatches.Count} version check batches");

        // Process insecure ports batches in parallel
        var processedBatches = 0;
        await Parallel.ForEachAsync(batches, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            async (batch, cancellationToken) =>
            {
                var batchPortThreats = _insecurePortDetector.DetectInsecurePorts(batch);
                var batchAnomalies = await _anomalyService.DetectAllAnomaliesAsync(batch);

                foreach (var threat in batchPortThreats)
                    allThreatsCollection.Add(threat);

                AddAnomaliesAsThreats(batchAnomalies, allThreatsCollection);

                var completed = System.Threading.Interlocked.Increment(ref processedBatches);
                var progress = (completed * 100.0) / batches.Count;
                if (ShouldLogProgress(progress, completed, batches.Count))
                {
                    DebugLogger.Log($"[Threats] {progress:F0}% ({completed}/{batches.Count} batches) - {allThreatsCollection.Count:N0} threats");
                }

                await Task.CompletedTask;
            });

        // Process version detection batches
        if (versionCheckPackets.Count > 0)
        {
            DebugLogger.Log($"[ThreatsViewModel] Starting parallel version detection on {versionBatches.Count} batches...");
            await Parallel.ForEachAsync(versionBatches, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
                async (batch, cancellationToken) =>
                {
                    var versionThreats = _insecurePortDetector.DetectInsecureVersions(batch);
                    foreach (var threat in versionThreats)
                        allThreatsCollection.Add(threat);
                    await Task.CompletedTask;
                });
            DebugLogger.Log($"[ThreatsViewModel] Version detection complete");
        }

        DebugLogger.Log($"[ThreatsViewModel] Parallel processing complete - {allThreatsCollection.Count:N0} total threats");
    }

    private async Task ProcessSmallDatasetAsync(IReadOnlyList<PacketInfo> workingSet,
        System.Collections.Concurrent.ConcurrentBag<EnhancedSecurityThreat> allThreatsCollection)
    {
        DebugLogger.Log($"[ThreatsViewModel] Small dataset - using sequential processing");

        DebugLogger.Log($"[ThreatsViewModel] Detecting insecure ports...");
        var portThreats = _insecurePortDetector.DetectInsecurePorts(workingSet);
        foreach (var threat in portThreats)
            allThreatsCollection.Add(threat);
        DebugLogger.Log($"[ThreatsViewModel] Found {portThreats.Count} insecure port threats");

        DebugLogger.Log($"[ThreatsViewModel] Detecting insecure versions...");
        var versionThreats = _insecurePortDetector.DetectInsecureVersions(workingSet);
        foreach (var threat in versionThreats)
            allThreatsCollection.Add(threat);
        DebugLogger.Log($"[ThreatsViewModel] Total threats after version check: {allThreatsCollection.Count}");

        DebugLogger.Log($"[ThreatsViewModel] Detecting anomalies...");
        var anomalies = await _anomalyService.DetectAllAnomaliesAsync(workingSet);
        DebugLogger.Log($"[ThreatsViewModel] Found {anomalies.Count} anomalies");

        AddAnomaliesAsThreats(anomalies, allThreatsCollection);
    }

    private void AddAnomaliesAsThreats(IReadOnlyList<NetworkAnomaly> anomalies,
        System.Collections.Concurrent.ConcurrentBag<EnhancedSecurityThreat> allThreatsCollection)
    {
        foreach (var anomaly in anomalies.Where(a => a.Severity >= AnomalySeverity.Medium))
        {
            allThreatsCollection.Add(new EnhancedSecurityThreat
            {
                Category = ThreatDisplayHelpers.MapAnomalyCategory(anomaly.Category),
                Severity = ThreatDisplayHelpers.MapAnomalySeverity(anomaly.Severity),
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
            });
        }
    }

    private void DetectCredentialThreats(IReadOnlyList<PacketInfo> workingSet,
        System.Collections.Concurrent.ConcurrentBag<EnhancedSecurityThreat> allThreatsCollection)
    {
        var credentialPackets = workingSet.Where(p => p.HasCredentials).ToList();
        if (!credentialPackets.Any()) return;

        DebugLogger.Log($"[ThreatsViewModel] Detected {credentialPackets.Count:N0} packets with credentials");

        var credentialsByPort = credentialPackets
            .GroupBy(p => new { p.DestinationPort, Service = ThreatDisplayHelpers.GetServiceName(p.DestinationPort) })
            .ToList();

        foreach (var group in credentialsByPort)
        {
            var first = group.First();
            var last = group.Last();

            allThreatsCollection.Add(new EnhancedSecurityThreat
            {
                Category = ThreatCategory.CleartextCredentials,
                Severity = ThreatSeverity.Critical,
                ThreatName = $"Cleartext Credentials ({group.Key.Service})",
                Description = $"Detected {group.Count()} packet(s) containing cleartext credentials on port {group.Key.DestinationPort} ({group.Key.Service}). Credentials transmitted in cleartext can be intercepted and compromised.",
                FirstSeen = first.Timestamp,
                LastSeen = last.Timestamp,
                OccurrenceCount = group.Count(),
                RiskScore = 9.5,
                Port = group.Key.DestinationPort,
                Service = group.Key.Service,
                Protocol = first.Protocol.ToString(),
                AffectedIPs = group
                    .SelectMany(p => new[] { p.SourceIP, p.DestinationIP })
                    .Where(ip => !string.IsNullOrEmpty(ip))
                    .Distinct()
                    .ToList(),
                Vulnerabilities = new List<string>
                {
                    "CWE-319: Cleartext Transmission of Sensitive Information",
                    "CWE-523: Unprotected Transport of Credentials"
                },
                Mitigations = new List<string>
                {
                    $"Migrate from {group.Key.Service} to encrypted alternative (e.g., SFTP, HTTPS, LDAPS)",
                    "Enable TLS/SSL encryption for this service",
                    "Rotate any credentials that may have been exposed",
                    "Implement network segmentation to limit credential exposure"
                },
                Metadata = new Dictionary<string, object>
                {
                    ["CredentialPacketCount"] = group.Count(),
                    ["Protocol"] = first.L7Protocol ?? first.Protocol.ToString(),
                    ["FrameNumbers"] = group.Select(p => (int)p.FrameNumber).Take(100).ToList()
                }
            });
        }

        DebugLogger.Log($"[ThreatsViewModel] Added {credentialsByPort.Count} credential threat entries");
    }

    private static List<List<PacketInfo>> CreateBatches(IReadOnlyList<PacketInfo> source, int batchSize)
    {
        var batches = new List<List<PacketInfo>>();
        for (int i = 0; i < source.Count; i += batchSize)
        {
            var size = Math.Min(batchSize, source.Count - i);
            batches.Add(source.Skip(i).Take(size).ToList());
        }
        return batches;
    }

    private static List<List<PacketInfo>> CreateBatchesFromList(List<PacketInfo> source, int batchSize)
    {
        var batches = new List<List<PacketInfo>>();
        for (int i = 0; i < source.Count; i += batchSize)
        {
            var size = Math.Min(batchSize, source.Count - i);
            batches.Add(source.GetRange(i, size));
        }
        return batches;
    }

    private static bool ShouldLogProgress(double progress, int completed, int total)
    {
        return (progress >= 24.5 && progress < 26) ||
               (progress >= 49.5 && progress < 51) ||
               (progress >= 74.5 && progress < 76) ||
               completed == total;
    }
}
