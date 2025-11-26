using System;
using Microsoft.Extensions.Caching.Memory;

namespace PCAPAnalyzer.Core.Configuration
{
    /// <summary>
    /// Configuration options for reporting service caching.
    /// Controls cache behavior, expiration policies, and memory limits for report generation.
    /// </summary>
    public class CacheConfiguration
    {
        /// <summary>
        /// Gets or sets whether caching is enabled globally.
        /// Default: true
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Gets or sets the default cache entry expiration time.
        /// Default: 10 minutes
        /// </summary>
        public TimeSpan DefaultExpiration { get; set; } = TimeSpan.FromMinutes(10);

        /// <summary>
        /// Gets or sets the default sliding expiration time.
        /// Entry expires if not accessed within this time.
        /// Default: null (no sliding expiration)
        /// </summary>
        public TimeSpan? DefaultSlidingExpiration { get; set; }

        /// <summary>
        /// Gets or sets the maximum cache size in megabytes.
        /// Default: 100 MB
        /// </summary>
        public long MaxCacheSizeMB { get; set; } = 100;

        /// <summary>
        /// Gets or sets the default priority for cache entries.
        /// Default: Normal
        /// </summary>
        public CacheItemPriority DefaultPriority { get; set; } = CacheItemPriority.Normal;

        /// <summary>
        /// Gets or sets whether to enable cache metrics tracking.
        /// Default: true
        /// </summary>
        public bool EnableMetrics { get; set; } = true;

        /// <summary>
        /// Gets or sets the compaction percentage (0.0 to 1.0) when size limit is exceeded.
        /// Default: 0.25 (remove 25% of entries)
        /// </summary>
        public double CompactionPercentage { get; set; } = 0.25;

        /// <summary>
        /// Creates a default configuration optimized for typical usage.
        /// </summary>
        public static CacheConfiguration Default => new();

        /// <summary>
        /// Creates a configuration optimized for large file analysis (>100MB PCAP files).
        /// </summary>
        public static CacheConfiguration LargeFile => new()
        {
            DefaultExpiration = TimeSpan.FromMinutes(15),
            DefaultSlidingExpiration = TimeSpan.FromMinutes(10),
            MaxCacheSizeMB = 250,
            DefaultPriority = CacheItemPriority.High
        };

        /// <summary>
        /// Creates a configuration optimized for memory-constrained environments.
        /// </summary>
        public static CacheConfiguration LowMemory => new()
        {
            DefaultExpiration = TimeSpan.FromMinutes(5),
            DefaultSlidingExpiration = TimeSpan.FromMinutes(3),
            MaxCacheSizeMB = 50,
            CompactionPercentage = 0.40,
            DefaultPriority = CacheItemPriority.Low
        };

        /// <summary>
        /// Creates a configuration with caching disabled.
        /// All cache operations will pass through to underlying services.
        /// </summary>
        public static CacheConfiguration Disabled => new()
        {
            Enabled = false
        };

        /// <summary>
        /// Validates the configuration and throws if invalid.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when configuration values are invalid.</exception>
        public void Validate()
        {
            if (DefaultExpiration <= TimeSpan.Zero)
                throw new ArgumentException("DefaultExpiration must be positive", nameof(DefaultExpiration));

            if (DefaultSlidingExpiration.HasValue && DefaultSlidingExpiration.Value <= TimeSpan.Zero)
                throw new ArgumentException("DefaultSlidingExpiration must be positive when set", nameof(DefaultSlidingExpiration));

            if (DefaultSlidingExpiration.HasValue && DefaultSlidingExpiration.Value >= DefaultExpiration)
                throw new ArgumentException("DefaultSlidingExpiration must be less than DefaultExpiration", nameof(DefaultSlidingExpiration));

            if (MaxCacheSizeMB <= 0)
                throw new ArgumentException("MaxCacheSizeMB must be positive", nameof(MaxCacheSizeMB));

            if (CompactionPercentage < 0 || CompactionPercentage > 1)
                throw new ArgumentException("CompactionPercentage must be between 0 and 1", nameof(CompactionPercentage));
        }

        /// <summary>
        /// Creates MemoryCacheOptions from this configuration.
        /// </summary>
        /// <returns>MemoryCacheOptions configured with this instance's settings.</returns>
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
