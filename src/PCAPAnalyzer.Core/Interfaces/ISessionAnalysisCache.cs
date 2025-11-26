using System;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Interfaces;

/// <summary>
/// Interface for session analysis cache service.
/// Thread-safe in-memory cache for current analysis session.
/// Cleared when file closes or new file loads.
/// NO persistence to disk (session-only requirement).
/// </summary>
public interface ISessionAnalysisCache
{
    /// <summary>
    /// Sets the current analysis result in cache.
    /// Thread-safe. Replaces existing cache.
    /// </summary>
    /// <param name="result">Complete analysis result to cache</param>
    void Set(AnalysisResult result);

    /// <summary>
    /// Gets the current cached analysis result.
    /// Thread-safe. Returns null if no cache exists.
    /// </summary>
    /// <returns>Cached result or null</returns>
    AnalysisResult? Get();

    /// <summary>
    /// Checks if cache is valid for a given file hash.
    /// Thread-safe. Returns false if no cache or hash mismatch.
    /// </summary>
    /// <param name="fileHash">SHA256 hash of PCAP file to validate</param>
    /// <returns>True if cache exists and hash matches</returns>
    bool IsValid(string fileHash);

    /// <summary>
    /// Clears the cache and triggers aggressive GC to reclaim memory.
    /// Thread-safe. Safe to call multiple times.
    ///
    /// GC Strategy:
    /// - Gen2 collection to reclaim large objects (LOH)
    /// - WaitForPendingFinalizers to ensure cleanup completes
    /// - Second Gen2 collection to finalize any resurrections
    ///
    /// Expected behavior: 10-20GB memory freed within 1-2 seconds.
    /// </summary>
    void Clear();

    /// <summary>
    /// Gets statistics about the current cache state.
    /// Thread-safe. Useful for diagnostics and UI display.
    /// </summary>
    /// <returns>Cache statistics snapshot</returns>
    CacheStatistics GetStatistics();
}

/// <summary>
/// Snapshot of cache statistics for diagnostics.
/// </summary>
public class CacheStatistics
{
    /// <summary>
    /// True if cache contains data.
    /// </summary>
    public bool HasData { get; set; }

    /// <summary>
    /// Total number of packets cached.
    /// </summary>
    public long TotalPackets { get; set; }

    /// <summary>
    /// Estimated memory usage in GB.
    /// </summary>
    public double MemoryGB { get; set; }

    /// <summary>
    /// Timestamp when cache was populated.
    /// </summary>
    public DateTime? CachedAt { get; set; }

    /// <summary>
    /// Path to cached file.
    /// </summary>
    public string FilePath { get; set; } = "";

    /// <summary>
    /// Number of threats cached.
    /// </summary>
    public int ThreatCount { get; set; }

    /// <summary>
    /// Number of countries cached.
    /// </summary>
    public int CountryCount { get; set; }

    /// <summary>
    /// Human-readable summary.
    /// </summary>
    public override string ToString()
    {
        return HasData
            ? $"CacheStats[{System.IO.Path.GetFileName(FilePath)}, {TotalPackets:N0} packets, " +
              $"{MemoryGB:F2}GB, {ThreatCount} threats, {CountryCount} countries, cached at {CachedAt:HH:mm:ss}]"
            : "CacheStats[Empty]";
    }
}
