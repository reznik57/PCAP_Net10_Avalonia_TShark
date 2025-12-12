using System;
using System.Collections.Generic;
using System.Threading;

namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// Statistics for a single DNS base domain, used for tunnel detection.
/// Tracks query volume, entropy scores, and sample queries.
/// </summary>
public sealed class DnsDomainStats
{
    private int _queryCount;
    private double _maxEntropy;
    private double _totalEntropy;
    private DateTime _firstSeen;
    private DateTime _lastSeen;
    private readonly List<string> _sampleQueries = new(5);
    private readonly List<long> _frameNumbers = new(100);
    private readonly Lock _lock = new();

    /// <summary>
    /// Base domain (e.g., "evil.com" from "encoded.evil.com")
    /// </summary>
    public string BaseDomain { get; }

    /// <summary>
    /// Total query count for this domain
    /// </summary>
    public int QueryCount => Volatile.Read(ref _queryCount);

    /// <summary>
    /// Maximum subdomain entropy observed
    /// </summary>
    public double MaxEntropy
    {
        get { using (_lock.EnterScope()) return _maxEntropy; }
    }

    /// <summary>
    /// Average subdomain entropy across all queries
    /// </summary>
    public double AverageEntropy
    {
        get
        {
            using (_lock.EnterScope())
            {
                return _queryCount > 0 ? _totalEntropy / _queryCount : 0.0;
            }
        }
    }

    /// <summary>
    /// First time this domain was queried
    /// </summary>
    public DateTime FirstSeen
    {
        get { using (_lock.EnterScope()) return _firstSeen; }
    }

    /// <summary>
    /// Last time this domain was queried
    /// </summary>
    public DateTime LastSeen
    {
        get { using (_lock.EnterScope()) return _lastSeen; }
    }

    /// <summary>
    /// Query rate (queries per minute)
    /// </summary>
    public double QueriesPerMinute
    {
        get
        {
            using (_lock.EnterScope())
            {
                var duration = _lastSeen - _firstSeen;
                if (duration.TotalMinutes < 0.1)
                    return _queryCount; // Short window, return total
                return _queryCount / duration.TotalMinutes;
            }
        }
    }

    /// <summary>
    /// Sample queries for manual inspection (first 5)
    /// </summary>
    public IReadOnlyList<string> SampleQueries
    {
        get { using (_lock.EnterScope()) return _sampleQueries.ToArray(); }
    }

    /// <summary>
    /// Frame numbers of packets querying this domain (up to 100)
    /// </summary>
    public IReadOnlyList<long> FrameNumbers
    {
        get { using (_lock.EnterScope()) return _frameNumbers.ToArray(); }
    }

    public DnsDomainStats(string baseDomain)
    {
        BaseDomain = baseDomain ?? throw new ArgumentNullException(nameof(baseDomain));
        _firstSeen = DateTime.MaxValue;
        _lastSeen = DateTime.MinValue;
    }

    /// <summary>
    /// Record a DNS query for this domain (thread-safe)
    /// </summary>
    /// <param name="fullQueryName">Full DNS query name (e.g., "abc123.data.evil.com")</param>
    /// <param name="entropy">Pre-calculated subdomain entropy</param>
    /// <param name="timestamp">Query timestamp</param>
    /// <param name="frameNumber">Packet frame number</param>
    public void RecordQuery(string fullQueryName, double entropy, DateTime timestamp, long frameNumber)
    {
        Interlocked.Increment(ref _queryCount);

        using (_lock.EnterScope())
        {
            // Update entropy stats
            _totalEntropy += entropy;
            if (entropy > _maxEntropy)
                _maxEntropy = entropy;

            // Update timestamps
            if (timestamp < _firstSeen)
                _firstSeen = timestamp;
            if (timestamp > _lastSeen)
                _lastSeen = timestamp;

            // Store sample queries (first 5)
            if (_sampleQueries.Count < 5)
                _sampleQueries.Add(fullQueryName);

            // Store frame numbers (up to 100)
            if (_frameNumbers.Count < 100)
                _frameNumbers.Add(frameNumber);
        }
    }
}
