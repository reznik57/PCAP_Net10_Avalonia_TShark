using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Moq;
using PCAPAnalyzer.Core.Configuration;
using PCAPAnalyzer.Core.Services.Caching;
using Xunit;

namespace PCAPAnalyzer.Tests.Services.Caching
{
    /// <summary>
    /// Comprehensive tests for MemoryCacheService covering all scenarios.
    /// Tests cache operations, expiration, metrics, and error handling.
    /// </summary>
    public class MemoryCacheServiceTests : IDisposable
    {
        private readonly IMemoryCache _memoryCache;
        private readonly CacheConfiguration _configuration;
        private readonly Mock<ILogger<MemoryCacheService>> _loggerMock;
        private readonly MemoryCacheService _cacheService;

        public MemoryCacheServiceTests()
        {
            _configuration = CacheConfiguration.Default;
            _memoryCache = new MemoryCache(_configuration.ToMemoryCacheOptions());
            _loggerMock = new Mock<ILogger<MemoryCacheService>>();
            _cacheService = new MemoryCacheService(_memoryCache, _configuration, _loggerMock.Object);
        }

        #region Constructor Tests

        [Fact]
        public void Constructor_WithNullMemoryCache_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                new MemoryCacheService(null!, _configuration, _loggerMock.Object));
        }

        [Fact]
        public void Constructor_WithNullConfiguration_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                new MemoryCacheService(_memoryCache, null!, _loggerMock.Object));
        }

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                new MemoryCacheService(_memoryCache, _configuration, null!));
        }

        [Fact]
        public void Constructor_WithInvalidConfiguration_ThrowsArgumentException()
        {
            // Arrange
            var invalidConfig = new CacheConfiguration { DefaultExpiration = TimeSpan.FromSeconds(-1) };

            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                new MemoryCacheService(_memoryCache, invalidConfig, _loggerMock.Object));
        }

        #endregion

        #region GetAsync Tests

        [Fact]
        public async Task GetAsync_WithValidKey_ReturnsCachedValue()
        {
            // Arrange
            const string key = "test-key";
            var value = new TestData { Value = "test-value" };
            var options = new CacheOptions { AbsoluteExpiration = TimeSpan.FromMinutes(5) };
            await _cacheService.SetAsync(key, value, options);

            // Act
            var result = await _cacheService.GetAsync<TestData>(key);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("test-value", result.Value);
        }

        [Fact]
        public async Task GetAsync_WithNonExistentKey_ReturnsNull()
        {
            // Arrange
            const string key = "non-existent-key";

            // Act
            var result = await _cacheService.GetAsync<TestData>(key);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task GetAsync_WithNullKey_ThrowsArgumentException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await _cacheService.GetAsync<TestData>(null!));
        }

        [Fact]
        public async Task GetAsync_WithEmptyKey_ThrowsArgumentException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await _cacheService.GetAsync<TestData>(string.Empty));
        }

        [Fact]
        public async Task GetAsync_WithWhitespaceKey_ThrowsArgumentException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await _cacheService.GetAsync<TestData>("   "));
        }

        [Fact]
        public async Task GetAsync_WithCacheDisabled_ReturnsNull()
        {
            // Arrange
            var disabledConfig = CacheConfiguration.Disabled;
            var disabledCache = new MemoryCacheService(_memoryCache, disabledConfig, _loggerMock.Object);
            const string key = "test-key";

            // Act
            var result = await disabledCache.GetAsync<TestData>(key);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task GetAsync_UpdatesMetrics_CorrectlyTracksHits()
        {
            // Arrange
            const string key = "test-key";
            var value = new TestData { Value = "test" };
            var options = new CacheOptions { AbsoluteExpiration = TimeSpan.FromMinutes(5) };
            await _cacheService.SetAsync(key, value, options);

            // Act
            await _cacheService.GetAsync<TestData>(key);
            await _cacheService.GetAsync<TestData>(key);
            var stats = await _cacheService.GetStatisticsAsync();

            // Assert
            Assert.Equal(2, stats.CacheHits);
            Assert.Equal(2, stats.TotalRequests);
            Assert.Equal(100.0, stats.HitRatio);
        }

        [Fact]
        public async Task GetAsync_UpdatesMetrics_CorrectlyTracksMisses()
        {
            // Arrange
            const string key = "non-existent";

            // Act
            await _cacheService.GetAsync<TestData>(key);
            await _cacheService.GetAsync<TestData>(key);
            var stats = await _cacheService.GetStatisticsAsync();

            // Assert
            Assert.Equal(0, stats.CacheHits);
            Assert.Equal(2, stats.CacheMisses);
            Assert.Equal(2, stats.TotalRequests);
            Assert.Equal(0.0, stats.HitRatio);
        }

        #endregion

        #region SetAsync Tests

        [Fact]
        public async Task SetAsync_WithValidParameters_StoresValue()
        {
            // Arrange
            const string key = "test-key";
            var value = new TestData { Value = "test-value" };
            var options = new CacheOptions { AbsoluteExpiration = TimeSpan.FromMinutes(5) };

            // Act
            await _cacheService.SetAsync(key, value, options);
            var result = await _cacheService.GetAsync<TestData>(key);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("test-value", result.Value);
        }

        [Fact]
        public async Task SetAsync_WithNullValue_ThrowsArgumentNullException()
        {
            // Arrange
            const string key = "test-key";
            var options = new CacheOptions();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await _cacheService.SetAsync<TestData>(key, null!, options));
        }

        [Fact]
        public async Task SetAsync_WithNullKey_ThrowsArgumentException()
        {
            // Arrange
            var value = new TestData { Value = "test" };
            var options = new CacheOptions();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await _cacheService.SetAsync(null!, value, options));
        }

        [Fact]
        public async Task SetAsync_WithCacheDisabled_DoesNotStore()
        {
            // Arrange
            var disabledConfig = CacheConfiguration.Disabled;
            var disabledCache = new MemoryCacheService(_memoryCache, disabledConfig, _loggerMock.Object);
            const string key = "test-key";
            var value = new TestData { Value = "test" };
            var options = new CacheOptions();

            // Act
            await disabledCache.SetAsync(key, value, options);
            var result = await disabledCache.GetAsync<TestData>(key);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task SetAsync_WithAbsoluteExpiration_ExpiresAfterDuration()
        {
            // Arrange
            const string key = "expiring-key";
            var value = new TestData { Value = "test" };
            var options = new CacheOptions { AbsoluteExpiration = TimeSpan.FromMilliseconds(100) };

            // Act
            await _cacheService.SetAsync(key, value, options);
            await Task.Delay(150); // Wait for expiration
            var result = await _cacheService.GetAsync<TestData>(key);

            // Assert
            Assert.Null(result);
        }

        [Fact]
        public async Task SetAsync_OverwritesExistingEntry_UpdatesValue()
        {
            // Arrange
            const string key = "test-key";
            var value1 = new TestData { Value = "original" };
            var value2 = new TestData { Value = "updated" };
            var options = new CacheOptions { AbsoluteExpiration = TimeSpan.FromMinutes(5) };

            // Act
            await _cacheService.SetAsync(key, value1, options);
            await _cacheService.SetAsync(key, value2, options);
            var result = await _cacheService.GetAsync<TestData>(key);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("updated", result.Value);
        }

        #endregion

        #region RemoveAsync Tests

        [Fact]
        public async Task RemoveAsync_WithExistingKey_ReturnsTrue()
        {
            // Arrange
            const string key = "test-key";
            var value = new TestData { Value = "test" };
            var options = new CacheOptions { AbsoluteExpiration = TimeSpan.FromMinutes(5) };
            await _cacheService.SetAsync(key, value, options);

            // Act
            var removed = await _cacheService.RemoveAsync(key);

            // Assert
            Assert.True(removed);
            var result = await _cacheService.GetAsync<TestData>(key);
            Assert.Null(result);
        }

        [Fact]
        public async Task RemoveAsync_WithNonExistentKey_ReturnsFalse()
        {
            // Arrange
            const string key = "non-existent";

            // Act
            var removed = await _cacheService.RemoveAsync(key);

            // Assert
            Assert.False(removed);
        }

        [Fact]
        public async Task RemoveAsync_WithNullKey_ThrowsArgumentException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(async () =>
                await _cacheService.RemoveAsync(null!));
        }

        #endregion

        #region ClearAsync Tests

        [Fact]
        public async Task ClearAsync_CompletesSuccessfully()
        {
            // Arrange
            const string key1 = "key1";
            const string key2 = "key2";
            var value = new TestData { Value = "test" };
            var options = new CacheOptions { AbsoluteExpiration = TimeSpan.FromMinutes(5) };
            await _cacheService.SetAsync(key1, value, options);
            await _cacheService.SetAsync(key2, value, options);

            // Act
            await _cacheService.ClearAsync();

            // Assert - Clear doesn't throw
            // Note: IMemoryCache doesn't support full clear, so we just verify it doesn't throw
        }

        #endregion

        #region GetStatisticsAsync Tests

        [Fact]
        public async Task GetStatisticsAsync_ReturnsAccurateStatistics()
        {
            // Arrange
            var key1 = "key1";
            var key2 = "key2";
            var value = new TestData { Value = "test" };
            var options = new CacheOptions { AbsoluteExpiration = TimeSpan.FromMinutes(5) };

            // Act
            await _cacheService.SetAsync(key1, value, options);
            await _cacheService.SetAsync(key2, value, options);
            await _cacheService.GetAsync<TestData>(key1); // Hit
            await _cacheService.GetAsync<TestData>(key1); // Hit
            await _cacheService.GetAsync<TestData>("non-existent"); // Miss
            var stats = await _cacheService.GetStatisticsAsync();

            // Assert
            Assert.Equal(3, stats.TotalRequests);
            Assert.Equal(2, stats.CacheHits);
            Assert.Equal(1, stats.CacheMisses);
            Assert.Equal(66.67, Math.Round(stats.HitRatio, 2));
            Assert.True(stats.ApproximateEntryCount >= 0);
        }

        [Fact]
        public async Task GetStatisticsAsync_WithZeroRequests_ReturnsZeroHitRatio()
        {
            // Act
            var stats = await _cacheService.GetStatisticsAsync();

            // Assert
            Assert.Equal(0, stats.TotalRequests);
            Assert.Equal(0.0, stats.HitRatio);
        }

        #endregion

        #region Thread Safety Tests

        [Fact]
        public async Task ConcurrentOperations_MaintainDataIntegrity()
        {
            // Arrange
            var tasks = new Task[10];
            var value = new TestData { Value = "test" };
            var options = new CacheOptions { AbsoluteExpiration = TimeSpan.FromMinutes(5) };

            // Act - Concurrent writes and reads
            for (int i = 0; i < tasks.Length; i++)
            {
                int index = i;
                tasks[i] = Task.Run(async () =>
                {
                    var key = $"key-{index}";
                    await _cacheService.SetAsync(key, value, options);
                    var result = await _cacheService.GetAsync<TestData>(key);
                    Assert.NotNull(result);
                });
            }

            await Task.WhenAll(tasks);

            // Assert - No exceptions thrown, operations completed
            Assert.All(tasks, t => Assert.True(t.IsCompletedSuccessfully));
        }

        #endregion

        #region Disposal Tests

        [Fact]
        public async Task Dispose_DisposesSuccessfully()
        {
            // Arrange
            var cache = new MemoryCacheService(_memoryCache, _configuration, _loggerMock.Object);

            // Act
            cache.Dispose();

            // Assert - Subsequent operations should throw ObjectDisposedException
            await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
                await cache.GetAsync<TestData>("test"));
        }

        [Fact]
        public void Dispose_CalledMultipleTimes_DoesNotThrow()
        {
            // Arrange
            var cache = new MemoryCacheService(_memoryCache, _configuration, _loggerMock.Object);

            // Act & Assert
            cache.Dispose();
            cache.Dispose(); // Should not throw
        }

        #endregion

        #region Cancellation Tests

        [Fact]
        public async Task GetAsync_WithCancelledToken_ThrowsOperationCanceledException()
        {
            // Arrange
            var cts = new CancellationTokenSource();
            cts.Cancel();

            // Act & Assert
            await Assert.ThrowsAsync<OperationCanceledException>(async () =>
                await _cacheService.GetAsync<TestData>("test", cts.Token));
        }

        [Fact]
        public async Task SetAsync_WithCancelledToken_ThrowsOperationCanceledException()
        {
            // Arrange
            var cts = new CancellationTokenSource();
            cts.Cancel();
            var value = new TestData { Value = "test" };
            var options = new CacheOptions();

            // Act & Assert
            await Assert.ThrowsAsync<OperationCanceledException>(async () =>
                await _cacheService.SetAsync("test", value, options, cts.Token));
        }

        #endregion

        public void Dispose()
        {
            _cacheService.Dispose();
            _memoryCache.Dispose();
        }

        /// <summary>
        /// Test data class for caching tests.
        /// </summary>
        private class TestData
        {
            public string Value { get; set; } = string.Empty;
        }
    }
}
