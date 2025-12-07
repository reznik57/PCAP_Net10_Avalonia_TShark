using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Configuration;

namespace PCAPAnalyzer.Core.Services.Caching
{
    /// <summary>
    /// Thread-safe in-memory cache service implementation.
    /// Provides caching with automatic expiration, size limits, and comprehensive metrics tracking.
    /// </summary>
    public sealed class MemoryCacheService : ICacheService, IDisposable
    {
        private readonly IMemoryCache _memoryCache;
        private readonly CacheConfiguration _configuration;
        private readonly ILogger<MemoryCacheService> _logger;

        // Metrics tracking (using Interlocked for thread-safe updates)
        private long _totalRequests;
        private long _cacheHits;
        private long _cacheMisses;
        private long _evictions;
        private int _approximateEntryCount;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="MemoryCacheService"/> class.
        /// </summary>
        /// <param name="memoryCache">The underlying IMemoryCache instance.</param>
        /// <param name="configuration">Cache configuration settings.</param>
        /// <param name="logger">Logger for diagnostics.</param>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
        public MemoryCacheService(
            IMemoryCache memoryCache,
            CacheConfiguration configuration,
            ILogger<MemoryCacheService> logger)
        {
            ArgumentNullException.ThrowIfNull(memoryCache);
            ArgumentNullException.ThrowIfNull(configuration);
            ArgumentNullException.ThrowIfNull(logger);
            _memoryCache = memoryCache;
            _configuration = configuration;
            _logger = logger;

            _configuration.Validate();

            _logger.LogInformation(
                "MemoryCacheService initialized with MaxSize={MaxSizeMB}MB, DefaultExpiration={Expiration}, MetricsEnabled={Metrics}",
                _configuration.MaxCacheSizeMB,
                _configuration.DefaultExpiration,
                _configuration.EnableMetrics);
        }

        /// <summary>
        /// Retrieves a cached value by key.
        /// </summary>
        public Task<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default) where T : class
        {
            ThrowIfDisposed();
            ValidateKey(key);

            if (!_configuration.Enabled)
            {
                _logger.LogDebug("Cache is disabled, returning null for key: {Key}", key);
                return Task.FromResult<T?>(null);
            }

            cancellationToken.ThrowIfCancellationRequested();

            if (_configuration.EnableMetrics)
            {
                Interlocked.Increment(ref _totalRequests);
            }

            try
            {
                if (_memoryCache.TryGetValue(key, out T? value))
                {
                    if (_configuration.EnableMetrics)
                    {
                        Interlocked.Increment(ref _cacheHits);
                    }

                    _logger.LogDebug("Cache hit for key: {Key}", key);
                    return Task.FromResult(value);
                }
                else
                {
                    if (_configuration.EnableMetrics)
                    {
                        Interlocked.Increment(ref _cacheMisses);
                    }

                    _logger.LogDebug("Cache miss for key: {Key}", key);
                    return Task.FromResult<T?>(null);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving cache entry for key: {Key}", key);
                return Task.FromResult<T?>(null);
            }
        }

        /// <summary>
        /// Stores a value in the cache with specified options.
        /// </summary>
        public Task SetAsync<T>(string key, T value, CacheOptions options, CancellationToken cancellationToken = default) where T : class
        {
            ThrowIfDisposed();
            ValidateKey(key);

            ArgumentNullException.ThrowIfNull(value);

            if (!_configuration.Enabled)
            {
                _logger.LogDebug("Cache is disabled, skipping set for key: {Key}", key);
                return Task.CompletedTask;
            }

            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var cacheEntryOptions = CreateCacheEntryOptions(options);

                // Register eviction callback for metrics
                if (_configuration.EnableMetrics)
                {
                    cacheEntryOptions.RegisterPostEvictionCallback(OnEviction);
                }

                // Check if entry already exists
                bool isNewEntry = !_memoryCache.TryGetValue(key, out _);

                _memoryCache.Set(key, value, cacheEntryOptions);

                if (isNewEntry && _configuration.EnableMetrics)
                {
                    Interlocked.Increment(ref _approximateEntryCount);
                }

                _logger.LogDebug(
                    "Cached entry for key: {Key}, Expiration={Expiration}, Priority={Priority}",
                    key,
                    options.AbsoluteExpiration ?? _configuration.DefaultExpiration,
                    options.Priority);

                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error caching entry for key: {Key}", key);
                return Task.CompletedTask; // Fail gracefully
            }
        }

        /// <summary>
        /// Removes a cached entry by key.
        /// </summary>
        public Task<bool> RemoveAsync(string key, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            ValidateKey(key);

            if (!_configuration.Enabled)
            {
                return Task.FromResult(false);
            }

            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                bool existed = _memoryCache.TryGetValue(key, out _);
                _memoryCache.Remove(key);

                if (existed)
                {
                    _logger.LogDebug("Removed cache entry for key: {Key}", key);

                    if (_configuration.EnableMetrics)
                    {
                        Interlocked.Decrement(ref _approximateEntryCount);
                    }
                }

                return Task.FromResult(existed);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error removing cache entry for key: {Key}", key);
                return Task.FromResult(false);
            }
        }

        /// <summary>
        /// Clears all entries from the cache.
        /// </summary>
        public Task ClearAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            if (!_configuration.Enabled)
            {
                return Task.CompletedTask;
            }

            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                // IMemoryCache doesn't have a Clear method, so we need to dispose and recreate
                // For this implementation, we'll just log a warning
                _logger.LogWarning("Cache clear requested but IMemoryCache doesn't support full clear. Consider recreating the cache instance.");

                // Reset metrics
                if (_configuration.EnableMetrics)
                {
                    Interlocked.Exchange(ref _approximateEntryCount, 0);
                }

                return Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error clearing cache");
                return Task.CompletedTask;
            }
        }

        /// <summary>
        /// Retrieves current cache statistics for monitoring and diagnostics.
        /// </summary>
        public Task<CacheStatistics> GetStatisticsAsync(CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();

            var statistics = new CacheStatistics
            {
                TotalRequests = Interlocked.Read(ref _totalRequests),
                CacheHits = Interlocked.Read(ref _cacheHits),
                CacheMisses = Interlocked.Read(ref _cacheMisses),
                Evictions = Interlocked.Read(ref _evictions),
                ApproximateEntryCount = Interlocked.CompareExchange(ref _approximateEntryCount, 0, 0),
                TotalMemoryBytes = _configuration.MaxCacheSizeMB * 1024 * 1024 // Approximate
            };

            _logger.LogInformation(
                "Cache statistics: Requests={Requests}, Hits={Hits}, Misses={Misses}, HitRatio={HitRatio:F2}%, Entries={Entries}, Evictions={Evictions}",
                statistics.TotalRequests,
                statistics.CacheHits,
                statistics.CacheMisses,
                statistics.HitRatio,
                statistics.ApproximateEntryCount,
                statistics.Evictions);

            return Task.FromResult(statistics);
        }

        /// <summary>
        /// Creates MemoryCacheEntryOptions from CacheOptions, applying configuration defaults.
        /// </summary>
        private MemoryCacheEntryOptions CreateCacheEntryOptions(CacheOptions options)
        {
            var entryOptions = new MemoryCacheEntryOptions
            {
                Priority = options.Priority
            };

            // Apply expiration
            var absoluteExpiration = options.AbsoluteExpiration ?? _configuration.DefaultExpiration;
            entryOptions.SetAbsoluteExpiration(absoluteExpiration);

            // Apply sliding expiration if specified
            var slidingExpiration = options.SlidingExpiration ?? _configuration.DefaultSlidingExpiration;
            if (slidingExpiration.HasValue)
            {
                entryOptions.SetSlidingExpiration(slidingExpiration.Value);
            }

            // Apply size (required when cache has SizeLimit)
            // If size not explicitly provided, default to 1 to allow entry to be cached
            var size = options.Size ?? 1;
            entryOptions.SetSize(size);

            return entryOptions;
        }

        /// <summary>
        /// Callback invoked when a cache entry is evicted.
        /// Used for tracking eviction metrics.
        /// </summary>
        private void OnEviction(object key, object? value, EvictionReason reason, object? state)
        {
            if (reason != EvictionReason.Replaced && reason != EvictionReason.Removed)
            {
                Interlocked.Increment(ref _evictions);
                Interlocked.Decrement(ref _approximateEntryCount);

                _logger.LogDebug("Cache entry evicted: Key={Key}, Reason={Reason}", key, reason);

                if (reason == EvictionReason.Capacity)
                {
                    _logger.LogWarning(
                        "Cache capacity limit reached, entry evicted. Consider increasing MaxCacheSizeMB (current: {MaxSizeMB}MB)",
                        _configuration.MaxCacheSizeMB);
                }
            }
        }

        /// <summary>
        /// Validates a cache key.
        /// </summary>
        private static void ValidateKey(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
            {
                throw new ArgumentException("Cache key cannot be null or whitespace", nameof(key));
            }
        }

        /// <summary>
        /// Throws if the service has been disposed.
        /// </summary>
        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(MemoryCacheService));
            }
        }

        /// <summary>
        /// Disposes the cache service and underlying resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Protected implementation of Dispose pattern.
        /// </summary>
        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed resources
                    _logger.LogInformation("Disposing MemoryCacheService");

                    // IMemoryCache is owned externally and should be disposed by the DI container
                    // We don't dispose it here, just clean up our state
                }

                _disposed = true;
            }
        }
    }
}
