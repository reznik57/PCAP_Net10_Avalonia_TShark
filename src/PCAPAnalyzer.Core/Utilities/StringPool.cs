using System;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace PCAPAnalyzer.Core.Utilities;

/// <summary>
/// High-performance thread-safe string pool for deduplicating frequently repeated strings.
/// Designed for PCAP parsing where IP addresses and protocol names repeat millions of times.
///
/// Performance characteristics:
/// - O(1) lookup for existing strings (hash-based)
/// - Zero allocation for cache hits
/// - Thread-safe for parallel parsing (ConcurrentDictionary)
///
/// Memory savings example (1M packets, 5000 unique IPs):
/// - Without pooling: 2M string allocations (~40MB)
/// - With pooling: 5000 string allocations (~100KB) = 99% reduction
/// </summary>
public sealed class StringPool
{
    private readonly ConcurrentDictionary<int, string> _pool = [];

    /// <summary>
    /// Returns an interned string for the given span.
    /// If the string already exists in the pool, returns the cached instance.
    /// Otherwise, allocates a new string and caches it.
    /// </summary>
    /// <param name="span">The character span to intern</param>
    /// <returns>Interned string instance (may be shared across multiple callers)</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public string Intern(ReadOnlySpan<char> span)
    {
        if (span.IsEmpty)
            return string.Empty;

        // Use built-in span hash with ordinal comparison for consistency and performance
        var hash = string.GetHashCode(span, StringComparison.Ordinal);

        // Fast path: check if already pooled
        if (_pool.TryGetValue(hash, out var existing))
        {
            // Verify it's actually the same string (hash collision check)
            if (existing.AsSpan().SequenceEqual(span))
                return existing;

            // Hash collision - rare but possible
            // Fall through to create new string with collision-resistant key
            hash = GetCollisionResistantHash(span, hash);
            if (_pool.TryGetValue(hash, out existing) && existing.AsSpan().SequenceEqual(span))
                return existing;
        }

        // Slow path: allocate new string and cache it
        var newString = span.ToString();
        _pool.TryAdd(hash, newString);
        return newString;
    }

    /// <summary>
    /// Interns a string that's already allocated.
    /// Useful when you have a string but want to deduplicate future occurrences.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public string Intern(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        return Intern(value.AsSpan());
    }

    /// <summary>
    /// Clears all cached strings from the pool.
    /// Call this when starting analysis of a new PCAP file to prevent unbounded growth.
    /// </summary>
    public void Clear()
    {
        var count = _pool.Count;
        _pool.Clear();
        DebugLogger.Log($"[StringPool] Cleared {count} interned strings");
    }

    /// <summary>
    /// Gets the number of unique strings currently in the pool.
    /// Useful for diagnostics and memory estimation.
    /// </summary>
    public int Count => _pool.Count;

    /// <summary>
    /// Estimates memory saved by the pool.
    /// Assumes average string length of 20 chars and 2M total references.
    /// </summary>
    /// <param name="totalReferences">Total number of times strings were requested</param>
    /// <returns>Estimated bytes saved</returns>
    public long EstimateMemorySaved(long totalReferences)
    {
        // Without pooling: totalReferences * (24 byte header + avg 20 chars * 2 bytes)
        // With pooling: Count * (24 byte header + avg 20 chars * 2 bytes)
        const int avgStringSize = 24 + 20 * 2; // 64 bytes average
        var withoutPooling = totalReferences * avgStringSize;
        var withPooling = Count * avgStringSize;
        return withoutPooling - withPooling;
    }

    /// <summary>
    /// Generates a collision-resistant hash by incorporating string length.
    /// Only called on hash collisions (rare).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int GetCollisionResistantHash(ReadOnlySpan<char> span, int originalHash)
    {
        // Combine original hash with length to reduce collision probability
        return HashCode.Combine(originalHash, span.Length);
    }
}
