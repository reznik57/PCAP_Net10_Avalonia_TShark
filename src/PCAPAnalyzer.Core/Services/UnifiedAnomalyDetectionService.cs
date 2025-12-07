using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;
using PCAPAnalyzer.Core.Services.AnomalyDetectors;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Unified anomaly detection service using Composite pattern.
/// Aggregates multiple specialized detectors to provide comprehensive anomaly detection.
/// </summary>
public interface IUnifiedAnomalyDetectionService
{
    /// <summary>
    /// Detect all anomalies across all registered detectors
    /// </summary>
    /// <param name="packets">Packets to analyze for anomalies</param>
    /// <param name="progress">Optional progress callback for real-time updates</param>
    Task<List<NetworkAnomaly>> DetectAllAnomaliesAsync(
        IEnumerable<PacketInfo> packets,
        IProgress<AnalysisProgress>? progress = null);

    /// <summary>
    /// Detect anomalies by specific category
    /// </summary>
    Task<List<NetworkAnomaly>> DetectByCategoryAsync(IEnumerable<PacketInfo> packets, AnomalyCategory category);

    /// <summary>
    /// Register a new detector
    /// </summary>
    void RegisterDetector(IAnomalyDetector detector);

    /// <summary>
    /// Unregister a detector by name
    /// </summary>
    void UnregisterDetector(string detectorName);

    /// <summary>
    /// Get list of registered detectors
    /// </summary>
    IReadOnlyList<IAnomalyDetector> GetRegisteredDetectors();
}

/// <summary>
/// Implementation of unified anomaly detection service
/// </summary>
public class UnifiedAnomalyDetectionService : IUnifiedAnomalyDetectionService
{
    private readonly List<IAnomalyDetector> _detectors = [];
    private readonly Lock _lock = new();

    public UnifiedAnomalyDetectionService(IGeoIPService? geoIPService = null)
    {
        // Register default detectors in priority order
        RegisterDetector(new NetworkAnomalyDetector());
        RegisterDetector(new TCPAnomalyDetector());
        RegisterDetector(new ApplicationAnomalyDetector());

        // Register specialized detectors
        RegisterDetector(new VoipAnomalyDetector());
        RegisterDetector(new IoTAnomalyDetector());
        RegisterDetector(new CryptoMiningDetector());
        RegisterDetector(new DataExfiltrationDetector());

        // Register geo-aware detectors (require GeoIP service for full functionality)
        RegisterDetector(new GeoThreatDetector(geoIPService));
    }

    public async Task<List<NetworkAnomaly>> DetectAllAnomaliesAsync(
        IEnumerable<PacketInfo> packets,
        IProgress<AnalysisProgress>? progress = null)
    {
        var packetList = packets.ToList();
        var totalPackets = packetList.Count;

        if (!packetList.Any())
            return new List<NetworkAnomaly>();

        var sw = Stopwatch.StartNew();
        DebugLogger.Log($"[Threat Detection] Starting threat analysis on {totalPackets:N0} packets...");

        // Report start
        progress?.Report(new AnalysisProgress
        {
            Phase = "Analyzing Data",
            SubPhase = "Threat Detection",
            Detail = $"Starting threat analysis on {totalPackets:N0} packets...",
            PacketsAnalyzed = 0,
            TotalPackets = totalPackets,
            ThreatsDetected = 0
        });

        // OPTIMIZATION: Parallelize detector execution instead of sequential foreach
        // Previous: 7 detectors × 433ms sequential = 5.2s (per batch, × 12 batches)
        // Optimized: All detectors run in parallel = ~433ms (single batch time)
        // Expected savings: 4.8s per batch, ~57.6s total across all batches

        List<IAnomalyDetector> activeDetectors;
        using (_lock.EnterScope())
        {
            activeDetectors = _detectors.ToList();
        }

        // Thread-safe counters for progress reporting
        long packetsAnalyzed = 0;
        int threatsDetected = 0;
        int completedDetectors = 0;
        var progressLock = new object();

        // Run all detectors in parallel using Task-based parallelism
        var detectionTasks = activeDetectors.Select(detector => Task.Run(() =>
        {
            // For specialized detectors, check if they should run
            if (detector is ISpecializedDetector specializedDetector)
            {
                if (!specializedDetector.CanDetect(packetList))
                {
                    Interlocked.Increment(ref completedDetectors);
                    return new List<NetworkAnomaly>();
                }
            }

            var detectorAnomalies = detector.Detect(packetList);

            // Update progress after each detector completes
            lock (progressLock)
            {
                packetsAnalyzed += totalPackets; // Each detector analyzes all packets
                threatsDetected += detectorAnomalies.Count;
                completedDetectors++;

                var percentComplete = (completedDetectors * 100) / activeDetectors.Count;

                DebugLogger.Log($"[Threat Detection] {detector.Name}: {detectorAnomalies.Count} threats found " +
                                  $"({completedDetectors}/{activeDetectors.Count} detectors complete)");

                progress?.Report(new AnalysisProgress
                {
                    Phase = "Analyzing Data",
                    SubPhase = "Threat Detection",
                    Detail = $"Analyzing packets ({completedDetectors}/{activeDetectors.Count} detectors), {threatsDetected} threats detected",
                    PacketsAnalyzed = packetsAnalyzed,
                    TotalPackets = totalPackets * activeDetectors.Count,
                    ThreatsDetected = threatsDetected,
                    ElapsedTime = sw.Elapsed
                });
            }

            return detectorAnomalies;
        })).ToArray();

        // Wait for all detectors to complete (async pattern - no thread blocking)
        var results = await Task.WhenAll(detectionTasks);

        // Aggregate results from all detectors using LINQ
        var allAnomalies = results.SelectMany(r => r).ToList();

        sw.Stop();
        DebugLogger.Log($"[Threat Detection] Complete: {totalPackets:N0} packets analyzed, " +
                          $"{allAnomalies.Count} threats detected in {sw.Elapsed.TotalSeconds:F1}s");

        // Report completion
        progress?.Report(new AnalysisProgress
        {
            Phase = "Analyzing Data",
            SubPhase = "Threat Detection",
            Detail = $"Threat detection complete: {allAnomalies.Count} threats found",
            PacketsAnalyzed = totalPackets * activeDetectors.Count,
            TotalPackets = totalPackets * activeDetectors.Count,
            ThreatsDetected = allAnomalies.Count,
            ElapsedTime = sw.Elapsed
        });

        // Sort by severity (Critical -> High -> Medium -> Low) then by detection time
        return allAnomalies
            .OrderByDescending(a => a.Severity)
            .ThenBy(a => a.DetectedAt)
            .ToList();
    }

    public async Task<List<NetworkAnomaly>> DetectByCategoryAsync(IEnumerable<PacketInfo> packets, AnomalyCategory category)
    {
        var packetList = packets.ToList();

        if (!packetList.Any())
            return new List<NetworkAnomaly>();

        List<IAnomalyDetector> categoryDetectors;
        using (_lock.EnterScope())
        {
            categoryDetectors = _detectors.Where(d => d.Category == category).ToList();
        }

        // OPTIMIZATION: Parallelize category-specific detectors
        var detectionTasks = categoryDetectors.Select(detector => Task.Run(() =>
        {
            // For specialized detectors, check if they should run
            if (detector is ISpecializedDetector specializedDetector)
            {
                if (!specializedDetector.CanDetect(packetList))
                    return new List<NetworkAnomaly>();
            }

            return detector.Detect(packetList);
        })).ToArray();

        // Wait for all detectors to complete (async pattern - no thread blocking)
        var results = await Task.WhenAll(detectionTasks);

        // Aggregate results from all category-specific detectors
        var anomalies = results.SelectMany(r => r).ToList();

        return anomalies
            .OrderByDescending(a => a.Severity)
            .ThenBy(a => a.DetectedAt)
            .ToList();
    }

    public void RegisterDetector(IAnomalyDetector detector)
    {
        if (detector == null)
            return;

        using (_lock.EnterScope())
        {
            if (!_detectors.Any(d => d.Name == detector.Name))
            {
                _detectors.Add(detector);
            }
        }
    }

    public void UnregisterDetector(string detectorName)
    {
        if (string.IsNullOrEmpty(detectorName))
            return;

        using (_lock.EnterScope())
        {
            _detectors.RemoveAll(d => d.Name == detectorName);
        }
    }

    public IReadOnlyList<IAnomalyDetector> GetRegisteredDetectors()
    {
        using (_lock.EnterScope())
        {
            return _detectors.ToList().AsReadOnly();
        }
    }
}
