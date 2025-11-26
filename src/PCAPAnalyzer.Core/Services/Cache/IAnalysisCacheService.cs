using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Cache
{
    /// <summary>
    /// Cache service for storing PCAP analysis results in SQLite database.
    /// Enables instant loading of previously analyzed files.
    /// </summary>
    public interface IAnalysisCacheService : IDisposable
    {
        /// <summary>
        /// Computes a unique cache key for a PCAP file based on file path, size, and modification time.
        /// Cache key is stable and immutable - does NOT include packet count to prevent key mutation during analysis.
        /// </summary>
        /// <param name="filePath">Path to the PCAP file</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Unique cache key string (format: {FileHash}_{AnalysisVersion})</returns>
        Task<string> ComputeCacheKeyAsync(string filePath, CancellationToken cancellationToken = default);

        /// <summary>
        /// Checks if analysis results are cached for the given key.
        /// </summary>
        /// <param name="cacheKey">Cache key to check</param>
        /// <param name="analysisType">Type of analysis (Threats or VoiceQoS)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if cached results exist</returns>
        Task<bool> IsCachedAsync(string cacheKey, string analysisType, CancellationToken cancellationToken = default);

        /// <summary>
        /// Saves threat analysis results to cache.
        /// </summary>
        /// <param name="cacheKey">Cache key</param>
        /// <param name="threats">List of detected threats</param>
        /// <param name="cancellationToken">Cancellation token</param>
        Task SaveThreatsAsync(string cacheKey, List<EnhancedSecurityThreat> threats, CancellationToken cancellationToken = default);

        /// <summary>
        /// Loads threat analysis results from cache.
        /// </summary>
        /// <param name="cacheKey">Cache key</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of threats if found, null otherwise</returns>
        Task<List<EnhancedSecurityThreat>?> LoadThreatsAsync(string cacheKey, CancellationToken cancellationToken = default);

        /// <summary>
        /// Saves VoiceQoS analysis results to cache.
        /// </summary>
        /// <param name="cacheKey">Cache key</param>
        /// <param name="qosData">VoiceQoS analysis result</param>
        /// <param name="cancellationToken">Cancellation token</param>
        Task SaveVoiceQoSAsync(string cacheKey, VoiceQoSAnalysisResult qosData, CancellationToken cancellationToken = default);

        /// <summary>
        /// Loads VoiceQoS analysis results from cache.
        /// </summary>
        /// <param name="cacheKey">Cache key</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>VoiceQoS data if found, null otherwise</returns>
        Task<VoiceQoSAnalysisResult?> LoadVoiceQoSAsync(string cacheKey, CancellationToken cancellationToken = default);

        /// <summary>
        /// Clears old cache entries that haven't been accessed in the specified number of days.
        /// </summary>
        /// <param name="maxAgeDays">Maximum age in days (default: 30)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Number of entries deleted</returns>
        Task<int> ClearOldCacheAsync(int maxAgeDays = 30, CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets the total size of the cache database in megabytes.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Total cache size in MB</returns>
        Task<long> GetCacheSizeMBAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Gets cache statistics (total entries, hits, misses, etc.).
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Cache statistics dictionary</returns>
        Task<Dictionary<string, object>> GetCacheStatisticsAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Deletes all cache entries for a specific file.
        /// </summary>
        /// <param name="fileHash">File hash to delete</param>
        /// <param name="cancellationToken">Cancellation token</param>
        Task DeleteCacheForFileAsync(string fileHash, CancellationToken cancellationToken = default);

        /// <summary>
        /// Optimizes the database (VACUUM) to reclaim space.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        Task OptimizeDatabaseAsync(CancellationToken cancellationToken = default);
    }
}
