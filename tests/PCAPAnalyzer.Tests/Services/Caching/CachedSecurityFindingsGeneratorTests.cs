using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using PCAPAnalyzer.Core.Configuration;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.Caching;
using PCAPAnalyzer.Core.Services.Reporting;
using Xunit;

namespace PCAPAnalyzer.Tests.Services.Caching
{
    /// <summary>
    /// Tests for CachedSecurityFindingsGenerator covering caching integration and fallback behavior.
    /// Uses real SecurityFindingsGenerator instance (not mocked) to test actual caching behavior.
    /// </summary>
    public class CachedSecurityFindingsGeneratorTests
    {
        private readonly SecurityFindingsGenerator _innerGenerator;
        private readonly Mock<ICacheService> _cacheServiceMock;
        private readonly CacheKeyGenerator _keyGenerator;
        private readonly CacheConfiguration _configuration;
        private readonly Mock<ILogger<CachedSecurityFindingsGenerator>> _loggerMock;
        private readonly CachedSecurityFindingsGenerator _cachedGenerator;

        public CachedSecurityFindingsGeneratorTests()
        {
            // Use REAL SecurityFindingsGenerator since methods are not virtual
            var innerLoggerMock = new Mock<ILogger<SecurityFindingsGenerator>>();
            _innerGenerator = new SecurityFindingsGenerator(innerLoggerMock.Object);

            _cacheServiceMock = new Mock<ICacheService>();
            _keyGenerator = new CacheKeyGenerator();
            _configuration = CacheConfiguration.Default;
            _loggerMock = new Mock<ILogger<CachedSecurityFindingsGenerator>>();

            _cachedGenerator = new CachedSecurityFindingsGenerator(
                _innerGenerator,
                _cacheServiceMock.Object,
                _keyGenerator,
                _configuration,
                _loggerMock.Object);
        }

        #region GenerateAsync Tests

        [Fact]
        public async Task GenerateAsync_WithCacheHit_ReturnsCachedResult()
        {
            // Arrange
            var stats = CreateTestStatistics();
            var threats = CreateTestThreats();
            var cachedFindings = new List<SecurityFinding>
            {
                new SecurityFinding { Title = "Cached Finding", FindingId = "CACHED-001" }
            };

            _cacheServiceMock
                .Setup(x => x.GetAsync<List<SecurityFinding>>(It.IsAny<string>(), default))
                .ReturnsAsync(cachedFindings);

            // Act
            var result = await _cachedGenerator.GenerateAsync(stats, threats);

            // Assert
            Assert.Same(cachedFindings, result);
            Assert.Single(result);
            Assert.Equal("Cached Finding", result[0].Title);

            // Verify cache was checked
            _cacheServiceMock.Verify(x => x.GetAsync<List<SecurityFinding>>(It.IsAny<string>(), default), Times.Once);
        }

        [Fact]
        public async Task GenerateAsync_WithCacheMiss_GeneratesAndCaches()
        {
            // Arrange
            var stats = CreateTestStatistics();
            var threats = CreateTestThreats();

            _cacheServiceMock
                .Setup(x => x.GetAsync<List<SecurityFinding>>(It.IsAny<string>(), default))
                .ReturnsAsync((List<SecurityFinding>?)null);

            // Act
            var result = await _cachedGenerator.GenerateAsync(stats, threats);

            // Assert - Real generator creates findings from threats
            Assert.NotNull(result);
            Assert.NotEmpty(result); // Should have at least one finding from the threat

            // Verify cache operations
            _cacheServiceMock.Verify(x => x.GetAsync<List<SecurityFinding>>(It.IsAny<string>(), default), Times.Once);
            _cacheServiceMock.Verify(x => x.SetAsync(
                It.IsAny<string>(),
                It.IsAny<List<SecurityFinding>>(),
                It.IsAny<CacheOptions>(),
                default), Times.Once);
        }

        [Fact]
        public async Task GenerateAsync_WithNullStatistics_ThrowsArgumentNullException()
        {
            // Arrange
            var threats = CreateTestThreats();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await _cachedGenerator.GenerateAsync(null!, threats));
        }

        [Fact]
        public async Task GenerateAsync_WithNullThreats_ThrowsArgumentNullException()
        {
            // Arrange
            var stats = CreateTestStatistics();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await _cachedGenerator.GenerateAsync(stats, null!));
        }

        [Fact]
        public async Task GenerateAsync_WithCacheDisabled_BypassesCache()
        {
            // Arrange
            var disabledConfig = CacheConfiguration.Disabled;
            var cachedGen = new CachedSecurityFindingsGenerator(
                _innerGenerator,
                _cacheServiceMock.Object,
                _keyGenerator,
                disabledConfig,
                _loggerMock.Object);

            var stats = CreateTestStatistics();
            var threats = CreateTestThreats();

            // Act
            var result = await cachedGen.GenerateAsync(stats, threats);

            // Assert - Should generate without cache
            Assert.NotNull(result);
            _cacheServiceMock.Verify(x => x.GetAsync<List<SecurityFinding>>(It.IsAny<string>(), default), Times.Never);
            _cacheServiceMock.Verify(x => x.SetAsync(It.IsAny<string>(), It.IsAny<List<SecurityFinding>>(), It.IsAny<CacheOptions>(), default), Times.Never);
        }

        [Fact]
        public async Task GenerateAsync_WhenCacheFails_FallsBackToDirectGeneration()
        {
            // Arrange
            var stats = CreateTestStatistics();
            var threats = CreateTestThreats();

            _cacheServiceMock
                .Setup(x => x.GetAsync<List<SecurityFinding>>(It.IsAny<string>(), default))
                .ThrowsAsync(new Exception("Cache error"));

            // Act
            var result = await _cachedGenerator.GenerateAsync(stats, threats);

            // Assert - Should still generate results despite cache failure
            Assert.NotNull(result);
            Assert.NotEmpty(result);
        }

        #endregion

        #region AnalyzeInsecureServicesAsync Tests

        [Fact]
        public async Task AnalyzeInsecureServicesAsync_WithCacheHit_ReturnsCachedResult()
        {
            // Arrange
            var stats = CreateTestStatisticsWithInsecurePort();
            var cachedFindings = new List<SecurityFinding>
            {
                new SecurityFinding { Title = "Cached Insecure Service", FindingId = "CACHE-SVC-001" }
            };

            _cacheServiceMock
                .Setup(x => x.GetAsync<List<SecurityFinding>>(It.IsAny<string>(), default))
                .ReturnsAsync(cachedFindings);

            // Act
            var result = await _cachedGenerator.AnalyzeInsecureServicesAsync(stats);

            // Assert
            Assert.Same(cachedFindings, result);
            Assert.Single(result);
            Assert.Equal("Cached Insecure Service", result[0].Title);
        }

        [Fact]
        public async Task AnalyzeInsecureServicesAsync_WithCacheMiss_GeneratesAndCaches()
        {
            // Arrange
            var stats = CreateTestStatisticsWithInsecurePort();

            _cacheServiceMock
                .Setup(x => x.GetAsync<List<SecurityFinding>>(It.IsAny<string>(), default))
                .ReturnsAsync((List<SecurityFinding>?)null);

            // Act
            var result = await _cachedGenerator.AnalyzeInsecureServicesAsync(stats);

            // Assert - Real generator creates findings for insecure ports
            Assert.NotNull(result);

            // Verify cache operations
            _cacheServiceMock.Verify(x => x.SetAsync(
                It.IsAny<string>(),
                It.IsAny<List<SecurityFinding>>(),
                It.IsAny<CacheOptions>(),
                default), Times.Once);
        }

        #endregion

        #region AnalyzeSuspiciousPatternsAsync Tests

        [Fact]
        public async Task AnalyzeSuspiciousPatternsAsync_WithCacheHit_ReturnsCachedResult()
        {
            // Arrange
            var stats = CreateTestStatistics();
            var cachedFindings = new List<SecurityFinding>
            {
                new SecurityFinding { Title = "Cached Suspicious Pattern", FindingId = "CACHE-PAT-001" }
            };

            _cacheServiceMock
                .Setup(x => x.GetAsync<List<SecurityFinding>>(It.IsAny<string>(), default))
                .ReturnsAsync(cachedFindings);

            // Act
            var result = await _cachedGenerator.AnalyzeSuspiciousPatternsAsync(stats);

            // Assert
            Assert.Same(cachedFindings, result);
            Assert.Single(result);
            Assert.Equal("Cached Suspicious Pattern", result[0].Title);
        }

        [Fact]
        public async Task AnalyzeSuspiciousPatternsAsync_WithCacheMiss_GeneratesAndCaches()
        {
            // Arrange
            var stats = CreateTestStatistics();

            _cacheServiceMock
                .Setup(x => x.GetAsync<List<SecurityFinding>>(It.IsAny<string>(), default))
                .ReturnsAsync((List<SecurityFinding>?)null);

            // Act
            var result = await _cachedGenerator.AnalyzeSuspiciousPatternsAsync(stats);

            // Assert - Real generator analyzes patterns
            Assert.NotNull(result);

            // Verify cache operations
            _cacheServiceMock.Verify(x => x.SetAsync(
                It.IsAny<string>(),
                It.IsAny<List<SecurityFinding>>(),
                It.IsAny<CacheOptions>(),
                default), Times.Once);
        }

        #endregion

        #region Helper Methods

        private NetworkStatistics CreateTestStatistics()
        {
            return new NetworkStatistics
            {
                TotalPackets = 10000,
                TotalBytes = 5000000,
                FirstPacketTime = DateTime.UtcNow.AddHours(-1),
                LastPacketTime = DateTime.UtcNow,
                TopPorts = new List<PortStatistics>
                {
                    new PortStatistics { Port = 80, PacketCount = 1000 },
                    new PortStatistics { Port = 443, PacketCount = 2000 }
                },
                TopConversations = new List<ConversationStatistics>
                {
                    new ConversationStatistics
                    {
                        SourceAddress = "192.168.1.1",
                        DestinationAddress = "10.0.0.1",
                        SourcePort = 50000,
                        DestinationPort = 80,
                        PacketCount = 500,
                        ByteCount = 250000,
                        StartTime = DateTime.UtcNow.AddMinutes(-5),
                        EndTime = DateTime.UtcNow
                    }
                }
            };
        }

        private NetworkStatistics CreateTestStatisticsWithInsecurePort()
        {
            return new NetworkStatistics
            {
                TotalPackets = 10000,
                TotalBytes = 5000000,
                FirstPacketTime = DateTime.UtcNow.AddHours(-1),
                LastPacketTime = DateTime.UtcNow,
                TopPorts = new List<PortStatistics>
                {
                    new PortStatistics { Port = 23, PacketCount = 500 }, // Telnet - insecure
                    new PortStatistics { Port = 443, PacketCount = 2000 }
                },
                TopConversations = new List<ConversationStatistics>
                {
                    new ConversationStatistics
                    {
                        SourceAddress = "192.168.1.1",
                        DestinationAddress = "10.0.0.1",
                        SourcePort = 50000,
                        DestinationPort = 23,
                        PacketCount = 500,
                        ByteCount = 25000,
                        StartTime = DateTime.UtcNow.AddMinutes(-2),
                        EndTime = DateTime.UtcNow
                    }
                }
            };
        }

        private List<SecurityThreat> CreateTestThreats()
        {
            return new List<SecurityThreat>
            {
                new SecurityThreat
                {
                    Type = "Port Scan",
                    Severity = ThreatSeverity.High,
                    SourceAddress = "192.168.1.100",
                    DestinationAddress = "10.0.0.1",
                    DetectedAt = DateTime.UtcNow
                }
            };
        }

        #endregion
    }
}
