using System;
using PCAPAnalyzer.Core.Collections;
using Xunit;

namespace PCAPAnalyzer.Tests.Collections;

public class LruCacheTests
{
    [Fact]
    public void Constructor_InvalidCapacity_Throws()
    {
        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() => new LruCache<string, int>(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new LruCache<string, int>(-1));
    }

    [Fact]
    public void GetOrAdd_NewKey_CreatesValue()
    {
        // Arrange
        var cache = new LruCache<string, int>(10);

        // Act
        var value = cache.GetOrAdd("key1", _ => 42);

        // Assert
        Assert.Equal(42, value);
        Assert.Equal(1, cache.Count);
    }

    [Fact]
    public void GetOrAdd_ExistingKey_ReturnsExistingValue()
    {
        // Arrange
        var cache = new LruCache<string, int>(10);
        cache.GetOrAdd("key1", _ => 42);

        // Act
        var callCount = 0;
        var value = cache.GetOrAdd("key1", _ =>
        {
            callCount++;
            return 100;
        });

        // Assert
        Assert.Equal(42, value); // Original value
        Assert.Equal(0, callCount); // Factory not called
    }

    [Fact]
    public void GetOrAdd_AtCapacity_EvictsLru()
    {
        // Arrange
        var cache = new LruCache<string, int>(3);
        cache.GetOrAdd("key1", _ => 1);
        cache.GetOrAdd("key2", _ => 2);
        cache.GetOrAdd("key3", _ => 3);

        // Act - Add 4th item, should evict key1 (LRU)
        cache.GetOrAdd("key4", _ => 4);

        // Assert
        Assert.Equal(3, cache.Count);
        Assert.False(cache.TryGetValue("key1", out _)); // Evicted
        Assert.True(cache.TryGetValue("key2", out _));
        Assert.True(cache.TryGetValue("key3", out _));
        Assert.True(cache.TryGetValue("key4", out _));
    }

    [Fact]
    public void GetOrAdd_AccessUpdatesLru()
    {
        // Arrange
        var cache = new LruCache<string, int>(3);
        cache.GetOrAdd("key1", _ => 1);
        cache.GetOrAdd("key2", _ => 2);
        cache.GetOrAdd("key3", _ => 3);

        // Access key1 to make it most recently used
        cache.GetOrAdd("key1", _ => 100);

        // Act - Add 4th item, should evict key2 (now LRU)
        cache.GetOrAdd("key4", _ => 4);

        // Assert
        Assert.True(cache.TryGetValue("key1", out _)); // Preserved (accessed recently)
        Assert.False(cache.TryGetValue("key2", out _)); // Evicted (LRU)
        Assert.True(cache.TryGetValue("key3", out _));
        Assert.True(cache.TryGetValue("key4", out _));
    }

    [Fact]
    public void TryGetValue_ExistingKey_ReturnsTrue()
    {
        // Arrange
        var cache = new LruCache<string, int>(10);
        cache.GetOrAdd("key1", _ => 42);

        // Act
        var found = cache.TryGetValue("key1", out var value);

        // Assert
        Assert.True(found);
        Assert.Equal(42, value);
    }

    [Fact]
    public void TryGetValue_MissingKey_ReturnsFalse()
    {
        // Arrange
        var cache = new LruCache<string, int>(10);

        // Act
        var found = cache.TryGetValue("missing", out var value);

        // Assert
        Assert.False(found);
        Assert.Equal(default, value);
    }

    [Fact]
    public void AddOrUpdate_NewKey_AddsValue()
    {
        // Arrange
        var cache = new LruCache<string, int>(10);

        // Act
        cache.AddOrUpdate("key1", 42);

        // Assert
        Assert.Equal(1, cache.Count);
        Assert.True(cache.TryGetValue("key1", out var value));
        Assert.Equal(42, value);
    }

    [Fact]
    public void AddOrUpdate_ExistingKey_UpdatesValue()
    {
        // Arrange
        var cache = new LruCache<string, int>(10);
        cache.GetOrAdd("key1", _ => 42);

        // Act
        cache.AddOrUpdate("key1", 100);

        // Assert
        Assert.Equal(1, cache.Count);
        Assert.True(cache.TryGetValue("key1", out var value));
        Assert.Equal(100, value);
    }

    [Fact]
    public void GetAllValues_ReturnsAllValues()
    {
        // Arrange
        var cache = new LruCache<string, int>(10);
        cache.GetOrAdd("key1", _ => 1);
        cache.GetOrAdd("key2", _ => 2);
        cache.GetOrAdd("key3", _ => 3);

        // Act
        var values = cache.GetAllValues();

        // Assert
        Assert.Equal(3, values.Count);
        Assert.Contains(1, values);
        Assert.Contains(2, values);
        Assert.Contains(3, values);
    }

    [Fact]
    public void Clear_RemovesAllItems()
    {
        // Arrange
        var cache = new LruCache<string, int>(10);
        cache.GetOrAdd("key1", _ => 1);
        cache.GetOrAdd("key2", _ => 2);

        // Act
        cache.Clear();

        // Assert
        Assert.Equal(0, cache.Count);
        Assert.False(cache.TryGetValue("key1", out _));
        Assert.False(cache.TryGetValue("key2", out _));
    }

    [Fact]
    public void Capacity_ReturnsConfiguredCapacity()
    {
        // Arrange
        var cache = new LruCache<string, int>(100);

        // Assert
        Assert.Equal(100, cache.Capacity);
    }

    [Fact]
    public void ThreadSafe_ConcurrentAccess_NoExceptions()
    {
        // Arrange
        var cache = new LruCache<int, string>(100);

        // Act & Assert - no exceptions
        Parallel.For(0, 1000, i =>
        {
            cache.GetOrAdd(i % 200, key => $"value_{key}");
            cache.TryGetValue(i % 200, out _);
        });

        Assert.True(cache.Count <= 100);
    }

    [Fact]
    public void LruEviction_CorrectOrder()
    {
        // Arrange
        var cache = new LruCache<int, int>(5);

        // Add 5 items
        for (int i = 1; i <= 5; i++)
            cache.GetOrAdd(i, k => k * 10);

        // Access items 1, 3, 5 (making 2, 4 the LRU)
        cache.GetOrAdd(1, _ => 0);
        cache.GetOrAdd(3, _ => 0);
        cache.GetOrAdd(5, _ => 0);

        // Add 2 more items - should evict 2 then 4
        cache.GetOrAdd(6, k => k * 10);
        cache.GetOrAdd(7, k => k * 10);

        // Assert
        Assert.False(cache.TryGetValue(2, out _)); // Evicted first
        Assert.False(cache.TryGetValue(4, out _)); // Evicted second
        Assert.True(cache.TryGetValue(1, out _));
        Assert.True(cache.TryGetValue(3, out _));
        Assert.True(cache.TryGetValue(5, out _));
        Assert.True(cache.TryGetValue(6, out _));
        Assert.True(cache.TryGetValue(7, out _));
    }
}
