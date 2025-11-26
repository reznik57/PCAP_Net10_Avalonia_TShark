using System.Threading;
using System.Threading.Tasks;

namespace PCAPAnalyzer.Core.Services.Caching
{
    /// <summary>
    /// Defines caching operations for application-wide caching functionality.
    /// Provides async-first API for storing and retrieving cached data.
    /// </summary>
    public interface ICacheService
    {
        /// <summary>
        /// Retrieves a cached value by key.
        /// </summary>
        /// <typeparam name="T">The type of the cached value.</typeparam>
        /// <param name="key">The cache key.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>The cached value if found; otherwise, null.</returns>
        Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default) where T : class;

        /// <summary>
        /// Stores a value in the cache with specified options.
        /// </summary>
        /// <typeparam name="T">The type of the value to cache.</typeparam>
        /// <param name="key">The cache key.</param>
        /// <param name="value">The value to cache.</param>
        /// <param name="options">Cache entry options.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A task representing the async operation.</returns>
        Task SetAsync<T>(string key, T value, CacheOptions options, CancellationToken cancellationToken = default) where T : class;

        /// <summary>
        /// Removes a cached entry by key.
        /// </summary>
        /// <param name="key">The cache key to remove.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>True if the entry was removed; otherwise, false.</returns>
        Task<bool> RemoveAsync(string key, CancellationToken cancellationToken = default);

        /// <summary>
        /// Clears all entries from the cache.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>A task representing the async operation.</returns>
        Task ClearAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Retrieves current cache statistics for monitoring and diagnostics.
        /// </summary>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Cache statistics including hit ratio, entry count, and memory usage.</returns>
        Task<CacheStatistics> GetStatisticsAsync(CancellationToken cancellationToken = default);
    }

    /// <summary>
    /// Options for cache entry configuration.
    /// Controls expiration, priority, and size tracking.
    /// </summary>
    public class CacheOptions
    {
        /// <summary>
        /// Gets or sets the absolute expiration time from now.
        /// Entry will be removed after this duration regardless of access.
        /// </summary>
        public TimeSpan? AbsoluteExpiration { get; set; }

        /// <summary>
        /// Gets or sets the sliding expiration time.
        /// Entry expiration resets on each access if not accessed within this duration.
        /// </summary>
        public TimeSpan? SlidingExpiration { get; set; }

        /// <summary>
        /// Gets or sets the cache entry priority.
        /// Higher priority entries are less likely to be evicted.
        /// </summary>
        public Microsoft.Extensions.Caching.Memory.CacheItemPriority Priority { get; set; } =
            Microsoft.Extensions.Caching.Memory.CacheItemPriority.Normal;

        /// <summary>
        /// Gets or sets the estimated size of the cache entry.
        /// Used for size-bounded cache eviction policies.
        /// </summary>
        public long? Size { get; set; }
    }

    /// <summary>
    /// Statistics for cache monitoring and diagnostics.
    /// </summary>
    public class CacheStatistics
    {
        /// <summary>
        /// Gets or sets the total number of cache Get requests.
        /// </summary>
        public long TotalRequests { get; set; }

        /// <summary>
        /// Gets or sets the number of successful cache hits.
        /// </summary>
        public long CacheHits { get; set; }

        /// <summary>
        /// Gets or sets the number of cache misses.
        /// </summary>
        public long CacheMisses { get; set; }

        /// <summary>
        /// Gets or sets the number of entries evicted from the cache.
        /// </summary>
        public long Evictions { get; set; }

        /// <summary>
        /// Gets or sets the approximate number of entries currently in the cache.
        /// This is an estimate and may not be exact due to concurrent operations.
        /// </summary>
        public int ApproximateEntryCount { get; set; }

        /// <summary>
        /// Gets the cache hit ratio as a percentage (0-100).
        /// </summary>
        public double HitRatio => TotalRequests > 0 ? (double)CacheHits / TotalRequests * 100 : 0;

        /// <summary>
        /// Gets or sets the total estimated memory usage in bytes.
        /// </summary>
        public long TotalMemoryBytes { get; set; }
    }
}
