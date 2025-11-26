using System;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Service implementation of session analysis cache.
/// Thread-safe in-memory cache for current analysis session.
/// Cleared when file closes or new file loads.
/// NO persistence to disk (session-only requirement).
///
/// Design:
/// - Singleton pattern via DI for global access across ViewModels
/// - Lock-based thread safety (simple, low overhead)
/// - Aggressive GC on Clear() to reclaim 10-20GB memory
/// - Cache validation via file hash
/// </summary>
public class SessionAnalysisCacheService : ISessionAnalysisCache
{
    private AnalysisResult? _current;
    private readonly object _lock = new();

    /// <summary>
    /// Sets the current analysis result in cache.
    /// Thread-safe. Replaces existing cache.
    /// </summary>
    /// <param name="result">Complete analysis result to cache</param>
    public void Set(AnalysisResult result)
    {
        if (result == null)
            throw new ArgumentNullException(nameof(result));

        lock (_lock)
        {
            _current = result;
            DebugLogger.Log($"[SessionAnalysisCache] Cached {result.TotalPackets:N0} packets, " +
                              $"{result.EstimatedMemoryGB:F2}GB, {result.Threats.Count} threats, " +
                              $"{result.CountryTraffic.Count} countries");
        }
    }

    /// <summary>
    /// Gets the current cached analysis result.
    /// Thread-safe. Returns null if no cache exists.
    /// </summary>
    /// <returns>Cached result or null</returns>
    public AnalysisResult? Get()
    {
        lock (_lock)
        {
            return _current;
        }
    }

    /// <summary>
    /// Checks if cache is valid for a given file hash.
    /// Thread-safe. Returns false if no cache or hash mismatch.
    /// </summary>
    /// <param name="fileHash">SHA256 hash of PCAP file to validate</param>
    /// <returns>True if cache exists and hash matches</returns>
    public bool IsValid(string fileHash)
    {
        if (string.IsNullOrEmpty(fileHash))
            return false;

        lock (_lock)
        {
            return _current != null && _current.FileHash == fileHash;
        }
    }

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
    public void Clear()
    {
        lock (_lock)
        {
            if (_current != null)
            {
                var packets = _current.TotalPackets;
                var memoryGB = _current.EstimatedMemoryGB;
                var filePath = _current.FilePath;

                _current = null;

                // Aggressive GC to reclaim large memory (10-20GB)
                // Gen2 collection targets Large Object Heap (LOH) where packets reside
                GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
                GC.WaitForPendingFinalizers();
                GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);

                DebugLogger.Log($"[SessionAnalysisCache] Cleared cache for '{System.IO.Path.GetFileName(filePath)}' " +
                                  $"({packets:N0} packets, {memoryGB:F2}GB freed), triggered aggressive GC");
            }
        }
    }

    /// <summary>
    /// Gets statistics about the current cache state.
    /// Thread-safe. Useful for diagnostics and UI display.
    /// </summary>
    /// <returns>Cache statistics snapshot</returns>
    public CacheStatistics GetStatistics()
    {
        lock (_lock)
        {
            return new CacheStatistics
            {
                HasData = _current != null,
                TotalPackets = _current?.TotalPackets ?? 0,
                MemoryGB = _current?.EstimatedMemoryGB ?? 0,
                CachedAt = _current?.AnalyzedAt,
                FilePath = _current?.FilePath ?? "",
                ThreatCount = _current?.Threats.Count ?? 0,
                CountryCount = _current?.CountryTraffic.Count ?? 0
            };
        }
    }
}
