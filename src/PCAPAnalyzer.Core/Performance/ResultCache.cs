using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

namespace PCAPAnalyzer.Core.Performance
{
    /// <summary>
    /// Thread-safe LRU (Least Recently Used) cache for PCAP analysis results
    /// Improves performance by caching frequently accessed analysis results
    /// </summary>
    /// <typeparam name="TKey">Type of cache key</typeparam>
    /// <typeparam name="TValue">Type of cached value</typeparam>
    public sealed class ResultCache<TKey, TValue> : IDisposable where TKey : notnull
    {
        private readonly int _maxCapacity;
        private readonly TimeSpan? _expirationTime;
        private readonly ConcurrentDictionary<TKey, CacheEntry> _cache;
        private readonly LinkedList<TKey> _accessOrder;
        private readonly ReaderWriterLockSlim _lock;
        private readonly Timer? _cleanupTimer;
        private readonly TimeProvider _timeProvider;
        private bool _disposed;

        // Statistics
        private long _hits;
        private long _misses;
        private long _evictions;

        /// <summary>
        /// Gets the current number of items in the cache
        /// </summary>
        public int Count => _cache.Count;

        /// <summary>
        /// Gets the cache hit rate (percentage)
        /// </summary>
        public double HitRate
        {
            get
            {
                long total = _hits + _misses;
                return total == 0 ? 0 : (_hits * 100.0) / total;
            }
        }

        /// <summary>
        /// Gets cache statistics
        /// </summary>
        public CacheStatistics Statistics => new()
        {
            Hits = Interlocked.Read(ref _hits),
            Misses = Interlocked.Read(ref _misses),
            Evictions = Interlocked.Read(ref _evictions),
            CurrentSize = _cache.Count,
            MaxCapacity = _maxCapacity,
            HitRate = HitRate
        };

        /// <summary>
        /// Initializes a new instance of the ResultCache
        /// </summary>
        /// <param name="maxCapacity">Maximum number of items to cache</param>
        /// <param name="expirationTime">Optional time after which entries expire</param>
        /// <param name="timeProvider">Optional TimeProvider for testability</param>
        public ResultCache(int maxCapacity = 1000, TimeSpan? expirationTime = null, TimeProvider? timeProvider = null)
        {
            if (maxCapacity <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxCapacity), "Capacity must be positive");

            _maxCapacity = maxCapacity;
            _expirationTime = expirationTime;
            _timeProvider = timeProvider ?? TimeProvider.System;
            _cache = new ConcurrentDictionary<TKey, CacheEntry>();
            _accessOrder = new LinkedList<TKey>();
            _lock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);

            // Start cleanup timer if expiration is enabled
            if (_expirationTime.HasValue)
            {
                _cleanupTimer = new Timer(
                    CleanupExpiredEntries,
                    null,
                    _expirationTime.Value,
                    _expirationTime.Value
                );
            }
        }

        /// <summary>
        /// Gets a value from the cache
        /// </summary>
        /// <param name="key">Cache key</param>
        /// <param name="value">Retrieved value if found</param>
        /// <returns>True if value was found, false otherwise</returns>
        public bool TryGetValue(TKey key, out TValue? value)
        {
            if (_cache.TryGetValue(key, out var entry))
            {
                var utcNow = _timeProvider.GetUtcNow().UtcDateTime;

                // Check expiration
                if (_expirationTime.HasValue &&
                    utcNow - entry.CreatedAt > _expirationTime.Value)
                {
                    // Expired - remove it
                    TryRemove(key);
                    Interlocked.Increment(ref _misses);
                    value = default;
                    return false;
                }

                // Update access time and order
                entry.LastAccessedAt = utcNow;
                UpdateAccessOrder(key);

                Interlocked.Increment(ref _hits);
                value = entry.Value;
                return true;
            }

            Interlocked.Increment(ref _misses);
            value = default;
            return false;
        }

        /// <summary>
        /// Adds or updates a value in the cache
        /// </summary>
        /// <param name="key">Cache key</param>
        /// <param name="value">Value to cache</param>
        public void AddOrUpdate(TKey key, TValue value)
        {
            var utcNow = _timeProvider.GetUtcNow().UtcDateTime;
            var entry = new CacheEntry
            {
                Value = value,
                CreatedAt = utcNow,
                LastAccessedAt = utcNow
            };

            // Add or update the entry
            _cache.AddOrUpdate(key, entry, (_, _) => entry);

            // Update access order
            UpdateAccessOrder(key);

            // Evict if over capacity
            if (_cache.Count > _maxCapacity)
            {
                EvictLeastRecentlyUsed();
            }
        }

        /// <summary>
        /// Gets or adds a value using a factory function
        /// </summary>
        /// <param name="key">Cache key</param>
        /// <param name="valueFactory">Function to create value if not in cache</param>
        /// <returns>Cached or newly created value</returns>
        public TValue GetOrAdd(TKey key, Func<TKey, TValue> valueFactory)
        {
            if (TryGetValue(key, out var value) && value is not null)
            {
                return value;
            }

            var newValue = valueFactory(key);
            AddOrUpdate(key, newValue);
            return newValue;
        }

        /// <summary>
        /// Removes a specific key from the cache
        /// </summary>
        /// <param name="key">Key to remove</param>
        /// <returns>True if key was removed, false if not found</returns>
        public bool TryRemove(TKey key)
        {
            if (_cache.TryRemove(key, out _))
            {
                RemoveFromAccessOrder(key);
                return true;
            }
            return false;
        }

        /// <summary>
        /// Clears all entries from the cache
        /// </summary>
        public void Clear()
        {
            _lock.EnterWriteLock();
            try
            {
                _cache.Clear();
                _accessOrder.Clear();
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        /// <summary>
        /// Updates the access order for LRU tracking
        /// </summary>
        private void UpdateAccessOrder(TKey key)
        {
            _lock.EnterWriteLock();
            try
            {
                // Remove if exists
                _accessOrder.Remove(key);

                // Add to end (most recently used)
                _accessOrder.AddLast(key);
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        /// <summary>
        /// Removes a key from the access order tracking
        /// </summary>
        private void RemoveFromAccessOrder(TKey key)
        {
            _lock.EnterWriteLock();
            try
            {
                _accessOrder.Remove(key);
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        /// <summary>
        /// Evicts the least recently used entry
        /// </summary>
        private void EvictLeastRecentlyUsed()
        {
            _lock.EnterWriteLock();
            try
            {
                if (_accessOrder.First is LinkedListNode<TKey> node)
                {
                    var keyToEvict = node.Value;
                    _accessOrder.RemoveFirst();

                    if (_cache.TryRemove(keyToEvict, out _))
                    {
                        Interlocked.Increment(ref _evictions);
                    }
                }
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        /// <summary>
        /// Cleanup timer callback to remove expired entries
        /// </summary>
        private void CleanupExpiredEntries(object? state)
        {
            if (_disposed) return;

            var now = _timeProvider.GetUtcNow().UtcDateTime;
            var keysToRemove = new List<TKey>();

            // Find expired keys
            foreach (var kvp in _cache)
            {
                if (_expirationTime.HasValue &&
                    now - kvp.Value.CreatedAt > _expirationTime.Value)
                {
                    keysToRemove.Add(kvp.Key);
                }
            }

            // Remove expired keys
            foreach (var key in keysToRemove)
            {
                TryRemove(key);
            }
        }

        /// <summary>
        /// Gets all keys currently in the cache
        /// </summary>
        public IEnumerable<TKey> GetKeys()
        {
            return _cache.Keys.ToList();
        }

        /// <summary>
        /// Resets cache statistics
        /// </summary>
        public void ResetStatistics()
        {
            Interlocked.Exchange(ref _hits, 0);
            Interlocked.Exchange(ref _misses, 0);
            Interlocked.Exchange(ref _evictions, 0);
        }

        public void Dispose()
        {
            if (_disposed) return;

            _cleanupTimer?.Dispose();
            _lock.Dispose();
            _cache.Clear();
            _accessOrder.Clear();

            _disposed = true;
        }

        /// <summary>
        /// Cache entry wrapper
        /// </summary>
        private sealed class CacheEntry
        {
            public TValue Value { get; init; } = default!;
            public DateTime CreatedAt { get; init; }
            public DateTime LastAccessedAt { get; set; }
        }
    }

    /// <summary>
    /// Cache statistics
    /// </summary>
    public sealed class CacheStatistics
    {
        public long Hits { get; init; }
        public long Misses { get; init; }
        public long Evictions { get; init; }
        public int CurrentSize { get; init; }
        public int MaxCapacity { get; init; }
        public double HitRate { get; init; }

        public override string ToString()
        {
            return $"Hits: {Hits}, Misses: {Misses}, Hit Rate: {HitRate:F2}%, " +
                   $"Evictions: {Evictions}, Size: {CurrentSize}/{MaxCapacity}";
        }
    }
}
