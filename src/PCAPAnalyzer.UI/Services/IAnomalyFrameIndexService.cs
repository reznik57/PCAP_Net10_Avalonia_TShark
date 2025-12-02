using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Provides indexed access to anomalies by frame number for cross-tab filtering.
/// Singleton service populated once per analysis, used by all tabs.
/// </summary>
public interface IAnomalyFrameIndexService
{
    /// <summary>
    /// Build the frame-to-anomaly index from analysis results.
    /// Called once after analysis completes.
    /// </summary>
    void BuildIndex(IReadOnlyList<NetworkAnomaly> anomalies);

    /// <summary>
    /// Clear the index when loading a new file.
    /// </summary>
    void ClearIndex();

    /// <summary>
    /// Check if the index has been populated.
    /// </summary>
    bool HasIndex { get; }

    /// <summary>
    /// Get all frame numbers that have anomalies matching the specified filters.
    /// Returns empty set if no filters active (meaning "show all").
    /// </summary>
    HashSet<long> GetFramesMatchingFilters(
        IReadOnlyList<AnomalySeverity>? severities,
        IReadOnlyList<AnomalyCategory>? categories,
        IReadOnlyList<string>? detectors);

    /// <summary>
    /// Get all anomalies associated with a specific frame number.
    /// </summary>
    IReadOnlyList<NetworkAnomaly> GetAnomaliesForFrame(long frameNumber);

    /// <summary>
    /// Get all anomalies matching the specified filters.
    /// </summary>
    IReadOnlyList<NetworkAnomaly> GetFilteredAnomalies(
        IReadOnlyList<AnomalySeverity>? severities,
        IReadOnlyList<AnomalyCategory>? categories,
        IReadOnlyList<string>? detectors);

    /// <summary>
    /// Get all unique detector names from the current anomaly set.
    /// </summary>
    IReadOnlyList<string> GetDetectorNames();

    /// <summary>
    /// Get total anomaly count (unfiltered).
    /// </summary>
    int TotalAnomalyCount { get; }
}
