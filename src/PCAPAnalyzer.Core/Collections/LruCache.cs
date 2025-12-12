using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace PCAPAnalyzer.Core.Collections;

/// <summary>
/// Thread-safe LRU (Least Recently Used) cache with configurable capacity.
/// Used to limit memory usage when tracking DNS domain statistics.
/// </summary>
/// <typeparam name="TKey">Key type</typeparam>
/// <typeparam name="TValue">Value type</typeparam>
public sealed class LruCache<TKey, TValue> where TKey : notnull
{
    private readonly int _capacity;
    private readonly Dictionary<TKey, LinkedListNode<CacheEntry>> _cache;
    private readonly LinkedList<CacheEntry> _lruList;
    private readonly Lock _lock = new();

    private readonly record struct CacheEntry(TKey Key, TValue Value);

    /// <summary>
    /// Creates a new LRU cache with the specified capacity.
    /// </summary>
    /// <param name="capacity">Maximum number of items to cache</param>
    public LruCache(int capacity)
    {
        if (capacity <= 0)
            throw new ArgumentOutOfRangeException(nameof(capacity), "Capacity must be positive");

        _capacity = capacity;
        _cache = new Dictionary<TKey, LinkedListNode<CacheEntry>>(capacity);
        _lruList = new LinkedList<CacheEntry>();
    }

    /// <summary>
    /// Current number of items in the cache
    /// </summary>
    public int Count
    {
        get { using (_lock.EnterScope()) return _cache.Count; }
    }

    /// <summary>
    /// Maximum capacity of the cache
    /// </summary>
    public int Capacity => _capacity;

    /// <summary>
    /// Gets or adds a value to the cache. If the key exists, returns existing value
    /// and moves it to most-recently-used position.
    /// </summary>
    /// <param name="key">Cache key</param>
    /// <param name="valueFactory">Factory to create value if not in cache</param>
    /// <returns>Existing or newly created value</returns>
    public TValue GetOrAdd(TKey key, Func<TKey, TValue> valueFactory)
    {
        using (_lock.EnterScope())
        {
            if (_cache.TryGetValue(key, out var node))
            {
                // Move to front (most recently used)
                _lruList.Remove(node);
                _lruList.AddFirst(node);
                return node.Value.Value;
            }

            // Create new value
            var value = valueFactory(key);
            AddInternal(key, value);
            return value;
        }
    }

    /// <summary>
    /// Tries to get a value from the cache without modifying LRU order.
    /// </summary>
    public bool TryGetValue(TKey key, [MaybeNullWhen(false)] out TValue value)
    {
        using (_lock.EnterScope())
        {
            if (_cache.TryGetValue(key, out var node))
            {
                value = node.Value.Value;
                return true;
            }

            value = default;
            return false;
        }
    }

    /// <summary>
    /// Adds or updates a value in the cache.
    /// </summary>
    public void AddOrUpdate(TKey key, TValue value)
    {
        using (_lock.EnterScope())
        {
            if (_cache.TryGetValue(key, out var existingNode))
            {
                // Remove existing
                _lruList.Remove(existingNode);
                _cache.Remove(key);
            }

            AddInternal(key, value);
        }
    }

    /// <summary>
    /// Gets all values currently in the cache (snapshot).
    /// </summary>
    public IReadOnlyList<TValue> GetAllValues()
    {
        using (_lock.EnterScope())
        {
            var result = new List<TValue>(_cache.Count);
            foreach (var node in _lruList)
            {
                result.Add(node.Value);
            }
            return result;
        }
    }

    /// <summary>
    /// Clears all items from the cache.
    /// </summary>
    public void Clear()
    {
        using (_lock.EnterScope())
        {
            _cache.Clear();
            _lruList.Clear();
        }
    }

    private void AddInternal(TKey key, TValue value)
    {
        // Evict LRU item if at capacity
        if (_cache.Count >= _capacity)
        {
            var lruNode = _lruList.Last;
            if (lruNode is not null)
            {
                _cache.Remove(lruNode.Value.Key);
                _lruList.RemoveLast();
            }
        }

        // Add new entry at front
        var entry = new CacheEntry(key, value);
        var newNode = _lruList.AddFirst(entry);
        _cache[key] = newNode;
    }
}
