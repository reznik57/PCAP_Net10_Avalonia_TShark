using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using PCAPAnalyzer.Core.Configuration;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;

namespace PCAPAnalyzer.Core.Services.Statistics
{
    /// <summary>
    /// Enhanced decorator that adds enterprise-grade caching to any IStatisticsService implementation.
    /// Uses Microsoft.Extensions.Caching.Memory with configurable size limits, metrics, and eviction policies.
    /// </summary>
    public class CachedStatisticsService : IStatisticsService, IDisposable
    {
        private readonly IStatisticsService _inner;
        private readonly IMemoryCache _cache;
        private readonly StatisticsCacheConfiguration _config;
        private readonly CacheMetrics _metrics;
        private readonly SemaphoreSlim _calculationSemaphore = new(1, 1);
        private bool _disposed;

        public CachedStatisticsService(
            IStatisticsService inner,
            StatisticsCacheConfiguration? config = null)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _config = config ?? StatisticsCacheConfiguration.Default;
            _config.Validate();

            _cache = new MemoryCache(_config.ToMemoryCacheOptions());
            _metrics = new CacheMetrics();
        }

        public CachedStatisticsService(
            IStatisticsService inner,
            IMemoryCache cache,
            StatisticsCacheConfiguration? config = null)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
            _config = config ?? StatisticsCacheConfiguration.Default;
            _config.Validate();
            _metrics = new CacheMetrics();
        }

        /// <summary>
        /// Gets the current cache performance metrics.
        /// </summary>
        public CacheMetricsSnapshot Metrics => _metrics.GetSnapshot();

        /// <summary>
        /// Synchronous wrapper for CalculateStatisticsAsync. This method uses Task.Run to avoid blocking
        /// the calling thread while waiting for async operations.
        ///
        /// WARNING: Prefer using CalculateStatisticsAsync directly when possible to avoid thread pool overhead.
        /// This method exists solely for IStatisticsService interface compatibility.
        /// </summary>
        public NetworkStatistics CalculateStatistics(IEnumerable<PacketInfo> packets)
        {
            // Uses Task.Run to avoid sync-over-async blocking. The inner async method needs to:
            // 1. Acquire semaphore asynchronously
            // 2. Call async inner service methods
            // This pattern prevents deadlocks by running the async code on the thread pool.
            return Task.Run(() => CalculateStatisticsAsync(packets)).GetAwaiter().GetResult();
        }

        public async Task<NetworkStatistics> CalculateStatisticsAsync(IEnumerable<PacketInfo> packets, object? geoIPStage = null, object? flowStage = null)
        {
            if (!_config.Enabled || !_config.CacheStatistics)
                return await _inner.CalculateStatisticsAsync(packets, geoIPStage, flowStage);

            var packetList = packets?.ToList();
            if (packetList is null || !packetList.Any())
                return new NetworkStatistics();

            var cacheKey = GenerateCacheKey("statistics", packetList);
            var estimatedSize = EstimateNetworkStatisticsSize(packetList.Count);

            // Try to get from cache
            if (_cache.TryGetValue<NetworkStatistics>(cacheKey, out var cached) && cached is not null)
            {
                if (_config.EnableMetrics)
                    _metrics.RecordHit();
                PCAPAnalyzer.Core.Utilities.DebugLogger.Log($"[CachedStats] CACHE HIT for {packetList.Count:N0} packets, returning cached stats with {cached.TotalPackets:N0} total, TopSources: {cached.TopSources?.Count ?? 0}");
                return cached!;
            }

            PCAPAnalyzer.Core.Utilities.DebugLogger.Log($"[CachedStats] CACHE MISS for {packetList.Count:N0} packets - will calculate fresh");

            if (_config.EnableMetrics)
                _metrics.RecordMiss();

            // Acquire semaphore to prevent duplicate calculations
            await _calculationSemaphore.WaitAsync();
            try
            {
                // Double-check after acquiring lock
                if (_cache.TryGetValue<NetworkStatistics>(cacheKey, out cached) && cached is not null)
                {
                    if (_config.EnableMetrics)
                        _metrics.RecordHit();
                    return cached!;
                }

                // ✅ TIMING FIX: Pass stage references through to inner service
                // Calculate and cache
                var result = await _inner.CalculateStatisticsAsync(packetList, geoIPStage, flowStage);

                // Log what we calculated
                var topSrc = result.TopSources?.FirstOrDefault();
                PCAPAnalyzer.Core.Utilities.DebugLogger.Log($"[CachedStats] CALCULATED fresh stats: TotalPackets={result.TotalPackets:N0}, TopSources={result.TopSources?.Count ?? 0}, FirstTopSource={topSrc?.Address ?? "none"}({topSrc?.PacketCount ?? 0:N0} packets)");

                SetCache(cacheKey, result, estimatedSize);
                return result;
            }
            finally
            {
                _calculationSemaphore.Release();
            }
        }

        public async Task<NetworkStatistics> EnrichWithGeoAsync(NetworkStatistics statistics, IEnumerable<PacketInfo> packets, IProgress<AnalysisProgress>? progress = null)
        {
            if (statistics is null)
                throw new ArgumentNullException(nameof(statistics));

            if (!_config.Enabled || !_config.CacheGeoEnrichment)
                return await _inner.EnrichWithGeoAsync(statistics, packets, progress);

            var packetList = packets as List<PacketInfo> ?? packets?.ToList() ?? new List<PacketInfo>();
            if (packetList.Count == 0)
                return statistics;

            var cacheKey = GenerateCacheKey("geo_enrichment",
                statistics.TotalPackets,
                statistics.TotalBytes,
                statistics.FirstPacketTime.Ticks);
            var estimatedSize = EstimateNetworkStatisticsSize(packetList.Count);

            if (_cache.TryGetValue<NetworkStatistics>(cacheKey, out var cached) && cached is not null)
            {
                if (_config.EnableMetrics)
                    _metrics.RecordHit();
                return cached!;
            }

            if (_config.EnableMetrics)
                _metrics.RecordMiss();

            await _calculationSemaphore.WaitAsync();
            try
            {
                if (_cache.TryGetValue<NetworkStatistics>(cacheKey, out cached) && cached is not null)
                {
                    if (_config.EnableMetrics)
                        _metrics.RecordHit();
                    return cached!;
                }

                var result = await _inner.EnrichWithGeoAsync(statistics, packetList, progress);
                SetCache(cacheKey, result, estimatedSize);
                return result;
            }
            finally
            {
                _calculationSemaphore.Release();
            }
        }

        public List<TimeSeriesDataPoint> GenerateTimeSeries(IEnumerable<PacketInfo> packets, TimeSpan interval)
        {
            if (!_config.Enabled || !_config.CacheTimeSeries)
                return _inner.GenerateTimeSeries(packets, interval);

            var packetList = packets?.ToList();
            if (packetList is null || !packetList.Any())
                return new List<TimeSeriesDataPoint>();

            var cacheKey = GenerateCacheKey("timeseries", packetList, interval.TotalSeconds);
            var estimatedSize = EstimateTimeSeriesSize(packetList.Count, interval);

            if (_cache.TryGetValue<List<TimeSeriesDataPoint>>(cacheKey, out var cached) && cached is not null)
            {
                if (_config.EnableMetrics)
                    _metrics.RecordHit();
                return cached!;
            }

            if (_config.EnableMetrics)
                _metrics.RecordMiss();

            var result = _inner.GenerateTimeSeries(packetList, interval);
            SetCache(cacheKey, result, estimatedSize);
            return result;
        }

        public List<SecurityThreat> DetectThreats(IEnumerable<PacketInfo> packets)
        {
            if (!_config.Enabled || !_config.CacheThreats)
                return _inner.DetectThreats(packets);

            var packetList = packets?.ToList();
            if (packetList is null || !packetList.Any())
                return new List<SecurityThreat>();

            var cacheKey = GenerateCacheKey("threats", packetList);
            var estimatedSize = EstimateThreatListSize(packetList.Count);

            if (_cache.TryGetValue<List<SecurityThreat>>(cacheKey, out var cached) && cached is not null)
            {
                if (_config.EnableMetrics)
                    _metrics.RecordHit();
                return cached!;
            }

            if (_config.EnableMetrics)
                _metrics.RecordMiss();

            var result = _inner.DetectThreats(packetList);
            SetCache(cacheKey, result, estimatedSize);
            return result;
        }

        public List<ExpertInsight> GenerateInsights(NetworkStatistics stats)
        {
            // Insights are lightweight and based on already-calculated stats
            // No need to cache - they're fast to compute
            return _inner.GenerateInsights(stats);
        }

        /// <summary>
        /// Clears all cached entries and resets metrics.
        /// </summary>
        public void ClearCache()
        {
            if (_cache is MemoryCache mc)
            {
                mc.Compact(1.0); // Remove all entries
            }
            _metrics.Reset();
        }

        private void SetCache<T>(string key, T value, long estimatedSize)
        {
            var options = new MemoryCacheEntryOptions()
                .SetSize(estimatedSize)
                .SetPriority(_config.CacheItemPriority)
                .SetAbsoluteExpiration(_config.ExpirationTime);

            if (_config.SlidingExpiration.HasValue)
            {
                options.SetSlidingExpiration(_config.SlidingExpiration.Value);
            }

            // Register eviction callback for metrics
            if (_config.EnableMetrics)
            {
                options.RegisterPostEvictionCallback((k, v, reason, state) =>
                {
                    _metrics.RecordEviction();
                    _metrics.RecordMemoryChange(-estimatedSize);
                });
            }

            _cache.Set(key, value, options);

            if (_config.EnableMetrics)
            {
                _metrics.RecordMemoryChange(estimatedSize);
            }
        }

        private string GenerateCacheKey(string prefix, List<PacketInfo> packets, params object[] additionalComponents)
        {
            // Use packet characteristics for cache key instead of full packet content
            var packetCount = packets.Count;
            var totalBytes = packets.Sum(p => (long)p.Length);
            var timeRange = packets.Any()
                ? (packets.Max(p => p.Timestamp) - packets.Min(p => p.Timestamp)).Ticks
                : 0;

            // Create hash of key characteristics for compact cache key
            using var sha256 = SHA256.Create();
            var sb = new StringBuilder();
            sb.Append(prefix);
            sb.Append('|');
            sb.Append(packetCount);
            sb.Append('|');
            sb.Append(totalBytes);
            sb.Append('|');
            sb.Append(timeRange);

            foreach (var component in additionalComponents)
            {
                sb.Append('|');
                sb.Append(component);
            }

            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
            return $"{prefix}_{Convert.ToHexString(hashBytes)[..16]}"; // Use first 16 chars of hash
        }

        private string GenerateCacheKey(string prefix, params object[] components)
        {
            using var sha256 = SHA256.Create();
            var sb = new StringBuilder();
            sb.Append(prefix);

            foreach (var component in components)
            {
                sb.Append('|');
                sb.Append(component);
            }

            var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
            return $"{prefix}_{Convert.ToHexString(hashBytes)[..16]}";
        }

        // Estimation methods for memory size tracking
        private long EstimateNetworkStatisticsSize(int packetCount)
        {
            // Rough estimation based on typical NetworkStatistics object size
            // Base object + collections overhead
            const long baseSize = 1024; // Base object
            const long perPacketOverhead = 50; // Estimate per packet metadata
            const long collectionOverhead = 10240; // Protocol stats, endpoints, etc.

            return baseSize + (packetCount * perPacketOverhead) + collectionOverhead;
        }

        private long EstimateTimeSeriesSize(int packetCount, TimeSpan interval)
        {
            // Estimate based on number of time series points
            var estimatedPoints = Math.Max(1, packetCount / 100); // Rough estimate
            const long perPointSize = 128; // TimeSeriesDataPoint size
            return estimatedPoints * perPointSize;
        }

        private long EstimateThreatListSize(int packetCount)
        {
            // Most packets don't generate threats, but threats can be large
            var estimatedThreats = Math.Max(1, packetCount / 1000);
            const long perThreatSize = 512; // SecurityThreat with metadata
            return estimatedThreats * perThreatSize;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                // Dispose managed resources
                _calculationSemaphore?.Dispose();

                // Only dispose cache if we created it ourselves
                if (_cache is MemoryCache mc)
                {
                    mc.Dispose();
                }
            }
            // Dispose unmanaged resources (if any) here

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
