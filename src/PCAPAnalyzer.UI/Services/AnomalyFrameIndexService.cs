using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Singleton service that indexes anomalies by frame number for efficient cross-tab filtering.
/// </summary>
public class AnomalyFrameIndexService : IAnomalyFrameIndexService
{
    private readonly ILogger<AnomalyFrameIndexService> _logger;
    private readonly Lock _lock = new();

    private List<NetworkAnomaly> _allAnomalies = new();
    private Dictionary<long, List<NetworkAnomaly>> _frameToAnomalies = new();
    private List<string> _detectorNames = new();

    public AnomalyFrameIndexService(ILogger<AnomalyFrameIndexService> logger)
    {
        _logger = logger;
    }

    public bool HasIndex { get; private set; }
    public int TotalAnomalyCount => _allAnomalies.Count;

    public void BuildIndex(IReadOnlyList<NetworkAnomaly> anomalies)
    {
        lock (_lock)
        {
            _logger.LogInformation("Building anomaly frame index for {Count} anomalies", anomalies.Count);
            var sw = System.Diagnostics.Stopwatch.StartNew();

            _allAnomalies = anomalies.ToList();

            // Build frame-to-anomaly mapping
            _frameToAnomalies = _allAnomalies
                .Where(a => a.AffectedFrames?.Any() == true)
                .SelectMany(a => a.AffectedFrames!.Select(f => (Frame: f, Anomaly: a)))
                .GroupBy(x => x.Frame)
                .ToDictionary(g => g.Key, g => g.Select(x => x.Anomaly).Distinct().ToList());

            // Extract unique detector names
            _detectorNames = _allAnomalies
                .Select(a => a.DetectorName)
                .Where(n => !string.IsNullOrEmpty(n))
                .Distinct()
                .OrderBy(n => n)
                .ToList();

            HasIndex = true;

            sw.Stop();
            _logger.LogInformation(
                "Anomaly frame index built in {Elapsed}ms. {FrameCount} frames mapped, {DetectorCount} detectors",
                sw.ElapsedMilliseconds, _frameToAnomalies.Count, _detectorNames.Count);
        }
    }

    public void ClearIndex()
    {
        lock (_lock)
        {
            _allAnomalies.Clear();
            _frameToAnomalies.Clear();
            _detectorNames.Clear();
            HasIndex = false;
            _logger.LogDebug("Anomaly frame index cleared");
        }
    }

    public HashSet<long> GetFramesMatchingFilters(
        IReadOnlyList<AnomalySeverity>? severities,
        IReadOnlyList<AnomalyCategory>? categories,
        IReadOnlyList<string>? detectors)
    {
        lock (_lock)
        {
            if (!HasIndex) return new HashSet<long>();

            // If no filters, return empty (meaning "no anomaly filter active")
            bool hasFilters = (severities?.Any() == true) ||
                              (categories?.Any() == true) ||
                              (detectors?.Any() == true);
            if (!hasFilters) return new HashSet<long>();

            var matching = _allAnomalies.AsEnumerable();

            if (severities?.Any() == true)
                matching = matching.Where(a => severities.Contains(a.Severity));

            if (categories?.Any() == true)
                matching = matching.Where(a => categories.Contains(a.Category));

            if (detectors?.Any() == true)
                matching = matching.Where(a => detectors.Contains(a.DetectorName));

            return matching
                .Where(a => a.AffectedFrames?.Any() == true)
                .SelectMany(a => a.AffectedFrames!)
                .ToHashSet();
        }
    }

    public IReadOnlyList<NetworkAnomaly> GetAnomaliesForFrame(long frameNumber)
    {
        lock (_lock)
        {
            if (_frameToAnomalies.TryGetValue(frameNumber, out var anomalies))
                return anomalies;
            return Array.Empty<NetworkAnomaly>();
        }
    }

    public IReadOnlyList<NetworkAnomaly> GetFilteredAnomalies(
        IReadOnlyList<AnomalySeverity>? severities,
        IReadOnlyList<AnomalyCategory>? categories,
        IReadOnlyList<string>? detectors)
    {
        lock (_lock)
        {
            if (!HasIndex) return Array.Empty<NetworkAnomaly>();

            var matching = _allAnomalies.AsEnumerable();

            if (severities?.Any() == true)
                matching = matching.Where(a => severities.Contains(a.Severity));

            if (categories?.Any() == true)
                matching = matching.Where(a => categories.Contains(a.Category));

            if (detectors?.Any() == true)
                matching = matching.Where(a => detectors.Contains(a.DetectorName));

            return matching.ToList();
        }
    }

    public IReadOnlyList<string> GetDetectorNames()
    {
        lock (_lock)
        {
            return _detectorNames.ToList();
        }
    }
}
