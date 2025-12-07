using System;
using System.Threading;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Caching
{
    /// <summary>
    /// Thread-safe in-memory cache for current analysis session.
    /// Cleared when file closes or new file loads.
    /// NO persistence to disk (session-only requirement).
    ///
    /// Design:
    /// - Static singleton pattern for global access across ViewModels
    /// - Lock-based thread safety (simple, low overhead)
    /// - Aggressive GC on Clear() to reclaim 10-20GB memory
    /// - Cache validation via file hash
    /// </summary>
    public static class SessionAnalysisCache
    {
        private static AnalysisResult? _current;
        private static readonly Lock _lock = new();

        /// <summary>
        /// Sets the current analysis result in cache.
        /// Thread-safe. Replaces existing cache.
        /// </summary>
        /// <param name="result">Complete analysis result to cache</param>
        public static void Set(AnalysisResult result)
        {
            if (result == null)
                throw new ArgumentNullException(nameof(result));

            using (_lock.EnterScope())
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
        public static AnalysisResult? Get()
        {
            using (_lock.EnterScope())
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
        public static bool IsValid(string fileHash)
        {
            if (string.IsNullOrEmpty(fileHash))
                return false;

            using (_lock.EnterScope())
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
        public static void Clear()
        {
            using (_lock.EnterScope())
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
        public static CacheStatistics GetStatistics()
        {
            using (_lock.EnterScope())
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
}
