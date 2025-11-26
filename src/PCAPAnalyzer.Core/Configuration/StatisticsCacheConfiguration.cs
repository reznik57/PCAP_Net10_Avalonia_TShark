using System;
using Microsoft.Extensions.Caching.Memory;

namespace PCAPAnalyzer.Core.Configuration
{
    /// <summary>
    /// Configuration options for statistics caching.
    /// Controls cache behavior, expiration, and memory limits.
    /// </summary>
    public class StatisticsCacheConfiguration
    {
        /// <summary>
        /// Gets or sets whether caching is enabled.
        /// Default: true
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Gets or sets the cache entry expiration time.
        /// Default: 30 seconds
        /// </summary>
        public TimeSpan ExpirationTime { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Gets or sets the sliding expiration time (entry expires if not accessed within this time).
        /// Default: 15 seconds
        /// </summary>
        public TimeSpan? SlidingExpiration { get; set; } = TimeSpan.FromSeconds(15);

        /// <summary>
        /// Gets or sets the maximum cache size in megabytes.
        /// Default: 100 MB
        /// </summary>
        public long MaxCacheSizeMB { get; set; } = 100;

        /// <summary>
        /// Gets or sets the priority for cache entries.
        /// Default: Normal
        /// </summary>
        public CacheItemPriority CacheItemPriority { get; set; } = CacheItemPriority.Normal;

        /// <summary>
        /// Gets or sets whether to enable cache metrics tracking.
        /// Default: true
        /// </summary>
        public bool EnableMetrics { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to cache statistics calculations.
        /// Default: true
        /// </summary>
        public bool CacheStatistics { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to cache geo enrichment results.
        /// Default: true
        /// </summary>
        public bool CacheGeoEnrichment { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to cache time series data.
        /// Default: true
        /// </summary>
        public bool CacheTimeSeries { get; set; } = true;

        /// <summary>
        /// Gets or sets whether to cache threat detection results.
        /// Default: true
        /// </summary>
        public bool CacheThreats { get; set; } = true;

        /// <summary>
        /// Gets or sets the compaction percentage (0.0 to 1.0) when size limit is exceeded.
        /// Default: 0.25 (remove 25% of entries)
        /// </summary>
        public double CompactionPercentage { get; set; } = 0.25;

        /// <summary>
        /// Creates a default configuration optimized for typical usage.
        /// </summary>
        public static StatisticsCacheConfiguration Default => new();

        /// <summary>
        /// Creates a configuration optimized for large PCAP files (>100MB).
        /// </summary>
        public static StatisticsCacheConfiguration LargeFile => new()
        {
            ExpirationTime = TimeSpan.FromMinutes(2),
            SlidingExpiration = TimeSpan.FromMinutes(1),
            MaxCacheSizeMB = 250,
            CacheItemPriority = CacheItemPriority.High
        };

        /// <summary>
        /// Creates a configuration optimized for memory-constrained environments.
        /// </summary>
        public static StatisticsCacheConfiguration LowMemory => new()
        {
            ExpirationTime = TimeSpan.FromSeconds(15),
            SlidingExpiration = TimeSpan.FromSeconds(10),
            MaxCacheSizeMB = 50,
            CompactionPercentage = 0.40
        };

        /// <summary>
        /// Creates a configuration with caching disabled.
        /// </summary>
        public static StatisticsCacheConfiguration Disabled => new()
        {
            Enabled = false
        };

        /// <summary>
        /// Validates the configuration and throws if invalid.
        /// </summary>
        public void Validate()
        {
            if (ExpirationTime <= TimeSpan.Zero)
                throw new ArgumentException("ExpirationTime must be positive", nameof(ExpirationTime));

            if (SlidingExpiration.HasValue && SlidingExpiration.Value <= TimeSpan.Zero)
                throw new ArgumentException("SlidingExpiration must be positive when set", nameof(SlidingExpiration));

            if (MaxCacheSizeMB <= 0)
                throw new ArgumentException("MaxCacheSizeMB must be positive", nameof(MaxCacheSizeMB));

            if (CompactionPercentage < 0 || CompactionPercentage > 1)
                throw new ArgumentException("CompactionPercentage must be between 0 and 1", nameof(CompactionPercentage));
        }

        /// <summary>
        /// Creates MemoryCacheOptions from this configuration.
        /// </summary>
        public MemoryCacheOptions ToMemoryCacheOptions()
        {
            return new MemoryCacheOptions
            {
                SizeLimit = MaxCacheSizeMB * 1024 * 1024, // Convert MB to bytes
                CompactionPercentage = CompactionPercentage
            };
        }
    }
}
