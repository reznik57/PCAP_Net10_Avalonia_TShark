using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Moq;
using PCAPAnalyzer.Core.Configuration;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Services.Statistics;
using Xunit;

namespace PCAPAnalyzer.Tests.Services
{
    /// <summary>
    /// Unit tests for EnhancedCachedStatisticsService.
    /// Validates caching behavior, metrics tracking, and thread safety.
    /// </summary>
    public class EnhancedCachedStatisticsServiceTests : IDisposable
    {
        private readonly Mock<IStatisticsService> _mockInnerService;
        private readonly IMemoryCache _cache;
        private readonly StatisticsCacheConfiguration _config;
        private readonly EnhancedCachedStatisticsService _cachedService;
        private readonly List<PacketInfo> _testPackets;

        public EnhancedCachedStatisticsServiceTests()
        {
            _mockInnerService = new Mock<IStatisticsService>();
            _config = StatisticsCacheConfiguration.Default;
            _cache = new MemoryCache(_config.ToMemoryCacheOptions());
            _cachedService = new EnhancedCachedStatisticsService(_mockInnerService.Object, _cache, _config);

            // Create test packets
            _testPackets = CreateTestPackets(100);
        }

        public void Dispose()
        {
            _cachedService?.Dispose();
            _cache?.Dispose();
        }

        #region Cache Hit/Miss Tests

        [Fact]
        public async Task CalculateStatisticsAsync_FirstCall_ShouldMiss()
        {
            // Arrange
            var expectedStats = CreateTestStatistics(100);
            _mockInnerService.Setup(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()))
                .ReturnsAsync(expectedStats);

            // Act
            var result = await _cachedService.CalculateStatisticsAsync(_testPackets);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(100, result.TotalPackets);
            _mockInnerService.Verify(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()), Times.Once);
        }

        [Fact]
        public async Task CalculateStatisticsAsync_SecondCall_ShouldHit()
        {
            // Arrange
            var expectedStats = CreateTestStatistics(100);
            _mockInnerService.Setup(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()))
                .ReturnsAsync(expectedStats);

            // Act
            var result1 = await _cachedService.CalculateStatisticsAsync(_testPackets);
            var result2 = await _cachedService.CalculateStatisticsAsync(_testPackets);

            // Assert
            Assert.NotNull(result1);
            Assert.NotNull(result2);
            Assert.Equal(result1.TotalPackets, result2.TotalPackets);

            // Inner service should only be called once (cached second time)
            _mockInnerService.Verify(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()), Times.Once);
        }

        [Fact]
        public async Task CalculateStatisticsAsync_DifferentPackets_ShouldMiss()
        {
            // Arrange
            var packets1 = CreateTestPackets(100);
            var packets2 = CreateTestPackets(50); // Different packet count
            var stats1 = CreateTestStatistics(100);
            var stats2 = CreateTestStatistics(50);

            _mockInnerService.SetupSequence(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()))
                .ReturnsAsync(stats1)
                .ReturnsAsync(stats2);

            // Act
            var result1 = await _cachedService.CalculateStatisticsAsync(packets1);
            var result2 = await _cachedService.CalculateStatisticsAsync(packets2);

            // Assert
            Assert.Equal(100, result1.TotalPackets);
            Assert.Equal(50, result2.TotalPackets);

            // Should be called twice (different cache keys)
            _mockInnerService.Verify(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()), Times.Exactly(2));
        }

        #endregion

        #region Metrics Tests

        [Fact]
        public async Task Metrics_AfterCacheHit_ShouldIncrementHits()
        {
            // Arrange
            var expectedStats = CreateTestStatistics(100);
            _mockInnerService.Setup(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()))
                .ReturnsAsync(expectedStats);

            // Act
            await _cachedService.CalculateStatisticsAsync(_testPackets); // Miss
            await _cachedService.CalculateStatisticsAsync(_testPackets); // Hit

            var metrics = _cachedService.Metrics;

            // Assert
            Assert.Equal(1, metrics.Hits);
            Assert.Equal(1, metrics.Misses);
            Assert.Equal(50.0, metrics.HitRate); // 1 hit out of 2 operations = 50%
        }

        [Fact]
        public async Task Metrics_MultipleCacheHits_ShouldTrackCorrectly()
        {
            // Arrange
            var expectedStats = CreateTestStatistics(100);
            _mockInnerService.Setup(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()))
                .ReturnsAsync(expectedStats);

            // Act
            await _cachedService.CalculateStatisticsAsync(_testPackets); // Miss
            await _cachedService.CalculateStatisticsAsync(_testPackets); // Hit
            await _cachedService.CalculateStatisticsAsync(_testPackets); // Hit
            await _cachedService.CalculateStatisticsAsync(_testPackets); // Hit

            var metrics = _cachedService.Metrics;

            // Assert
            Assert.Equal(3, metrics.Hits);
            Assert.Equal(1, metrics.Misses);
            Assert.Equal(75.0, metrics.HitRate); // 3 hits out of 4 operations = 75%
        }

        [Fact]
        public void Metrics_InitialState_ShouldBeZero()
        {
            // Act
            var metrics = _cachedService.Metrics;

            // Assert
            Assert.Equal(0, metrics.Hits);
            Assert.Equal(0, metrics.Misses);
            Assert.Equal(0, metrics.Evictions);
            Assert.Equal(0.0, metrics.HitRate);
        }

        #endregion

        #region Configuration Tests

        [Fact]
        public async Task DisabledCache_ShouldBypassCache()
        {
            // Arrange
            var disabledConfig = StatisticsCacheConfiguration.Disabled;
            using var disabledService = new EnhancedCachedStatisticsService(_mockInnerService.Object, _cache, disabledConfig);

            var expectedStats = CreateTestStatistics(100);
            _mockInnerService.Setup(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()))
                .ReturnsAsync(expectedStats);

            // Act
            await disabledService.CalculateStatisticsAsync(_testPackets);
            await disabledService.CalculateStatisticsAsync(_testPackets);

            // Assert - should call inner service twice (no caching)
            _mockInnerService.Verify(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()), Times.Exactly(2));
        }

        [Fact]
        public async Task CacheStatisticsDisabled_OtherOperationsStillCached()
        {
            // Arrange
            var config = new StatisticsCacheConfiguration
            {
                Enabled = true,
                CacheStatistics = false, // Disable statistics caching
                CacheTimeSeries = true   // Keep time series enabled
            };
            using var service = new EnhancedCachedStatisticsService(_mockInnerService.Object, _cache, config);

            var expectedStats = CreateTestStatistics(100);
            var expectedTimeSeries = CreateTestTimeSeries(10);

            _mockInnerService.Setup(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()))
                .ReturnsAsync(expectedStats);
            _mockInnerService.Setup(s => s.GenerateTimeSeries(It.IsAny<IEnumerable<PacketInfo>>(), It.IsAny<TimeSpan>()))
                .Returns(expectedTimeSeries);

            // Act
            await service.CalculateStatisticsAsync(_testPackets);
            await service.CalculateStatisticsAsync(_testPackets); // Should not cache

            service.GenerateTimeSeries(_testPackets, TimeSpan.FromSeconds(1));
            service.GenerateTimeSeries(_testPackets, TimeSpan.FromSeconds(1)); // Should cache

            // Assert
            _mockInnerService.Verify(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()), Times.Exactly(2)); // Not cached
            _mockInnerService.Verify(s => s.GenerateTimeSeries(It.IsAny<IEnumerable<PacketInfo>>(), It.IsAny<TimeSpan>()), Times.Once); // Cached
        }

        [Fact]
        public void Configuration_Validation_InvalidExpiration_ShouldThrow()
        {
            // Arrange
            var invalidConfig = new StatisticsCacheConfiguration
            {
                ExpirationTime = TimeSpan.FromSeconds(-1) // Invalid
            };

            // Act & Assert
            Assert.Throws<ArgumentException>(() => invalidConfig.Validate());
        }

        #endregion

        #region Other Operations Tests

        [Fact]
        public async Task EnrichWithGeoAsync_ShouldCache()
        {
            // Arrange
            var baseStats = CreateTestStatistics(100);
            var enrichedStats = CreateTestStatistics(100);
            enrichedStats.GeolocatedPackets = 80;

            _mockInnerService.Setup(s => s.EnrichWithGeoAsync(It.IsAny<NetworkStatistics>(), It.IsAny<IEnumerable<PacketInfo>>()))
                .ReturnsAsync(enrichedStats);

            // Act
            var result1 = await _cachedService.EnrichWithGeoAsync(baseStats, _testPackets);
            var result2 = await _cachedService.EnrichWithGeoAsync(baseStats, _testPackets);

            // Assert
            Assert.Equal(80, result1.GeolocatedPackets);
            _mockInnerService.Verify(s => s.EnrichWithGeoAsync(It.IsAny<NetworkStatistics>(), It.IsAny<IEnumerable<PacketInfo>>()), Times.Once);
        }

        [Fact]
        public void GenerateTimeSeries_ShouldCache()
        {
            // Arrange
            var expectedSeries = CreateTestTimeSeries(10);
            _mockInnerService.Setup(s => s.GenerateTimeSeries(It.IsAny<IEnumerable<PacketInfo>>(), It.IsAny<TimeSpan>()))
                .Returns(expectedSeries);

            // Act
            var result1 = _cachedService.GenerateTimeSeries(_testPackets, TimeSpan.FromSeconds(1));
            var result2 = _cachedService.GenerateTimeSeries(_testPackets, TimeSpan.FromSeconds(1));

            // Assert
            Assert.NotNull(result1);
            Assert.Equal(10, result1.Count);
            _mockInnerService.Verify(s => s.GenerateTimeSeries(It.IsAny<IEnumerable<PacketInfo>>(), It.IsAny<TimeSpan>()), Times.Once);
        }

        [Fact]
        public void DetectThreats_ShouldCache()
        {
            // Arrange
            var expectedThreats = CreateTestThreats(5);
            _mockInnerService.Setup(s => s.DetectThreats(It.IsAny<IEnumerable<PacketInfo>>()))
                .Returns(expectedThreats);

            // Act
            var result1 = _cachedService.DetectThreats(_testPackets);
            var result2 = _cachedService.DetectThreats(_testPackets);

            // Assert
            Assert.NotNull(result1);
            Assert.Equal(5, result1.Count);
            _mockInnerService.Verify(s => s.DetectThreats(It.IsAny<IEnumerable<PacketInfo>>()), Times.Once);
        }

        [Fact]
        public void GenerateInsights_ShouldNotCache()
        {
            // Arrange
            var stats = CreateTestStatistics(100);
            var expectedInsights = CreateTestInsights(3);
            _mockInnerService.Setup(s => s.GenerateInsights(It.IsAny<NetworkStatistics>()))
                .Returns(expectedInsights);

            // Act
            var result1 = _cachedService.GenerateInsights(stats);
            var result2 = _cachedService.GenerateInsights(stats);

            // Assert
            Assert.NotNull(result1);
            Assert.Equal(3, result1.Count);
            // Insights are not cached (lightweight computation)
            _mockInnerService.Verify(s => s.GenerateInsights(It.IsAny<NetworkStatistics>()), Times.Exactly(2));
        }

        #endregion

        #region Clear Cache Tests

        [Fact]
        public async Task ClearCache_ShouldInvalidateCache()
        {
            // Arrange
            var expectedStats = CreateTestStatistics(100);
            _mockInnerService.Setup(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()))
                .ReturnsAsync(expectedStats);

            // Act
            await _cachedService.CalculateStatisticsAsync(_testPackets); // Miss
            await _cachedService.CalculateStatisticsAsync(_testPackets); // Hit

            _cachedService.ClearCache();

            await _cachedService.CalculateStatisticsAsync(_testPackets); // Should miss again

            // Assert
            _mockInnerService.Verify(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()), Times.Exactly(2));
        }

        [Fact]
        public void ClearCache_ShouldResetMetrics()
        {
            // Arrange
            var expectedStats = CreateTestStatistics(100);
            _mockInnerService.Setup(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()))
                .ReturnsAsync(expectedStats);

            // Act
            _cachedService.CalculateStatisticsAsync(_testPackets).Wait();
            _cachedService.CalculateStatisticsAsync(_testPackets).Wait();

            var metricsBefore = _cachedService.Metrics;
            Assert.True(metricsBefore.Hits > 0);

            _cachedService.ClearCache();

            var metricsAfter = _cachedService.Metrics;

            // Assert
            Assert.Equal(0, metricsAfter.Hits);
            Assert.Equal(0, metricsAfter.Misses);
        }

        #endregion

        #region Thread Safety Tests

        [Fact]
        public async Task ConcurrentAccess_ShouldBeSafe()
        {
            // Arrange
            var expectedStats = CreateTestStatistics(100);
            _mockInnerService.Setup(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()))
                .ReturnsAsync(expectedStats)
                .Callback(() => Task.Delay(10).Wait()); // Simulate computation time

            // Act - Multiple concurrent calls
            var tasks = Enumerable.Range(0, 10)
                .Select(_ => _cachedService.CalculateStatisticsAsync(_testPackets))
                .ToArray();

            var results = await Task.WhenAll(tasks);

            // Assert
            Assert.All(results, r => Assert.NotNull(r));
            Assert.All(results, r => Assert.Equal(100, r.TotalPackets));

            // Should only compute once despite concurrent access (deduplication)
            _mockInnerService.Verify(s => s.CalculateStatisticsAsync(It.IsAny<IEnumerable<PacketInfo>>()), Times.Once);
        }

        #endregion

        #region Helper Methods

        private List<PacketInfo> CreateTestPackets(int count)
        {
            var packets = new List<PacketInfo>();
            var baseTime = DateTime.UtcNow;

            for (int i = 0; i < count; i++)
            {
                packets.Add(new PacketInfo
                {
                    FrameNumber = (uint)i + 1,
                    Timestamp = baseTime.AddSeconds(i),
                    SourceIP = $"192.168.1.{i % 256}",
                    DestinationIP = $"10.0.0.{i % 256}",
                    Protocol = i % 2 == 0 ? ProtocolType.TCP : ProtocolType.UDP,
                    Length = 1500,
                    SourcePort = 443,
                    DestinationPort = 80
                });
            }

            return packets;
        }

        private NetworkStatistics CreateTestStatistics(int packetCount)
        {
            return new NetworkStatistics
            {
                TotalPackets = packetCount,
                TotalBytes = packetCount * 1500L,
                FirstPacketTime = DateTime.UtcNow,
                LastPacketTime = DateTime.UtcNow.AddSeconds(packetCount),
                ProtocolStats = new Dictionary<string, ProtocolStatistics>(),
                TopSources = new List<EndpointStatistics>(),
                TopDestinations = new List<EndpointStatistics>(),
                TopConversations = new List<ConversationStatistics>(),
                TopPorts = new List<PortStatistics>()
            };
        }

        private List<TimeSeriesDataPoint> CreateTestTimeSeries(int count)
        {
            var series = new List<TimeSeriesDataPoint>();
            var baseTime = DateTime.UtcNow;

            for (int i = 0; i < count; i++)
            {
                series.Add(new TimeSeriesDataPoint
                {
                    Timestamp = baseTime.AddSeconds(i),
                    Value = 100.0 + i,
                    Series = "Test"
                });
            }

            return series;
        }

        private List<SecurityThreat> CreateTestThreats(int count)
        {
            var threats = new List<SecurityThreat>();

            for (int i = 0; i < count; i++)
            {
                threats.Add(new SecurityThreat
                {
                    ThreatId = Guid.NewGuid().ToString(),
                    DetectedAt = DateTime.UtcNow,
                    Severity = ThreatSeverity.Medium,
                    Type = "Test Threat",
                    Description = $"Test threat {i}"
                });
            }

            return threats;
        }

        private List<ExpertInsight> CreateTestInsights(int count)
        {
            var insights = new List<ExpertInsight>();

            for (int i = 0; i < count; i++)
            {
                insights.Add(new ExpertInsight
                {
                    GeneratedAt = DateTime.UtcNow,
                    Category = "Test",
                    Title = $"Insight {i}",
                    Description = "Test insight",
                    Severity = InsightSeverity.Info
                });
            }

            return insights;
        }

        #endregion
    }
}
