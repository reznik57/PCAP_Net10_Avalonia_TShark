using System;
using System.Threading;

namespace PCAPAnalyzer.Core.Services.Statistics
{
    /// <summary>
    /// Tracks cache performance metrics for statistics service.
    /// Thread-safe implementation using Interlocked operations.
    /// </summary>
    public class CacheMetrics
    {
        private long _hits;
        private long _misses;
        private long _evictions;
        private long _totalMemoryBytes;
        private readonly DateTime _startTime;

        public CacheMetrics()
        {
            _startTime = DateTime.UtcNow;
        }

        /// <summary>
        /// Total number of cache hits (successful cache retrievals).
        /// </summary>
        public long Hits => Interlocked.Read(ref _hits);

        /// <summary>
        /// Total number of cache misses (cache lookups that required computation).
        /// </summary>
        public long Misses => Interlocked.Read(ref _misses);

        /// <summary>
        /// Total number of cache evictions (entries removed due to size/expiration).
        /// </summary>
        public long Evictions => Interlocked.Read(ref _evictions);

        /// <summary>
        /// Estimated total memory used by cached entries in bytes.
        /// </summary>
        public long TotalMemoryBytes => Interlocked.Read(ref _totalMemoryBytes);

        /// <summary>
        /// Total number of cache operations (hits + misses).
        /// </summary>
        public long TotalOperations => Hits + Misses;

        /// <summary>
        /// Cache hit rate as a percentage (0-100).
        /// </summary>
        public double HitRate
        {
            get
            {
                var total = TotalOperations;
                return total > 0 ? (Hits / (double)total) * 100 : 0;
            }
        }

        /// <summary>
        /// Average memory per cached entry in bytes.
        /// </summary>
        public double AverageEntrySize
        {
            get
            {
                var entries = Hits + Misses;
                return entries > 0 ? TotalMemoryBytes / (double)entries : 0;
            }
        }

        /// <summary>
        /// Time elapsed since metrics tracking started.
        /// </summary>
        public TimeSpan Uptime => DateTime.UtcNow - _startTime;

        /// <summary>
        /// Records a cache hit.
        /// </summary>
        public void RecordHit()
        {
            Interlocked.Increment(ref _hits);
        }

        /// <summary>
        /// Records a cache miss.
        /// </summary>
        public void RecordMiss()
        {
            Interlocked.Increment(ref _misses);
        }

        /// <summary>
        /// Records a cache eviction.
        /// </summary>
        public void RecordEviction()
        {
            Interlocked.Increment(ref _evictions);
        }

        /// <summary>
        /// Records memory usage change.
        /// </summary>
        /// <param name="bytes">Number of bytes (positive for add, negative for remove)</param>
        public void RecordMemoryChange(long bytes)
        {
            Interlocked.Add(ref _totalMemoryBytes, bytes);
        }

        /// <summary>
        /// Resets all metrics to zero.
        /// </summary>
        public void Reset()
        {
            Interlocked.Exchange(ref _hits, 0);
            Interlocked.Exchange(ref _misses, 0);
            Interlocked.Exchange(ref _evictions, 0);
            Interlocked.Exchange(ref _totalMemoryBytes, 0);
        }

        /// <summary>
        /// Returns a snapshot of current metrics.
        /// </summary>
        public CacheMetricsSnapshot GetSnapshot()
        {
            return new CacheMetricsSnapshot
            {
                Hits = Hits,
                Misses = Misses,
                Evictions = Evictions,
                TotalMemoryBytes = TotalMemoryBytes,
                HitRate = HitRate,
                TotalOperations = TotalOperations,
                Uptime = Uptime
            };
        }

        public override string ToString()
        {
            return $"Cache Metrics: Hits={Hits}, Misses={Misses}, HitRate={HitRate:F2}%, " +
                   $"Memory={TotalMemoryBytes / 1024.0 / 1024.0:F2}MB, Evictions={Evictions}";
        }
    }

    /// <summary>
    /// Immutable snapshot of cache metrics at a point in time.
    /// </summary>
    public class CacheMetricsSnapshot
    {
        public long Hits { get; init; }
        public long Misses { get; init; }
        public long Evictions { get; init; }
        public long TotalMemoryBytes { get; init; }
        public double HitRate { get; init; }
        public long TotalOperations { get; init; }
        public TimeSpan Uptime { get; init; }

        public double TotalMemoryMB => TotalMemoryBytes / 1024.0 / 1024.0;

        public override string ToString()
        {
            return $"Hits: {Hits}, Misses: {Misses}, Hit Rate: {HitRate:F2}%, " +
                   $"Memory: {TotalMemoryMB:F2}MB, Evictions: {Evictions}, Uptime: {Uptime:g}";
        }
    }
}
