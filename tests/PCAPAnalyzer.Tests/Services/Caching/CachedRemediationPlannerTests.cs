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
    /// Tests for CachedRemediationPlanner covering caching integration and fallback behavior.
    /// Uses real RemediationPlanner instance (not mocked) to test actual caching behavior.
    /// </summary>
    public class CachedRemediationPlannerTests
    {
        private readonly RemediationPlanner _innerPlanner;
        private readonly Mock<ICacheService> _cacheServiceMock;
        private readonly CacheKeyGenerator _keyGenerator;
        private readonly CacheConfiguration _configuration;
        private readonly Mock<ILogger<CachedRemediationPlanner>> _loggerMock;
        private readonly CachedRemediationPlanner _cachedPlanner;

        public CachedRemediationPlannerTests()
        {
            // Use REAL RemediationPlanner since methods are not virtual
            var innerLoggerMock = new Mock<ILogger<RemediationPlanner>>();
            _innerPlanner = new RemediationPlanner(innerLoggerMock.Object);

            _cacheServiceMock = new Mock<ICacheService>();
            _keyGenerator = new CacheKeyGenerator();
            _configuration = CacheConfiguration.Default;
            _loggerMock = new Mock<ILogger<CachedRemediationPlanner>>();

            _cachedPlanner = new CachedRemediationPlanner(
                _innerPlanner,
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
            var findings = CreateTestFindings();
            var recommendations = CreateTestRecommendations();
            var cachedPlan = new RemediationPlan
            {
                TotalEstimatedTime = "Cached Plan Time",
                Phases = new List<RemediationPhase>
                {
                    new RemediationPhase { Name = "Cached Phase 1", PhaseNumber = 1 }
                }
            };

            _cacheServiceMock
                .Setup(x => x.GetAsync<RemediationPlan>(It.IsAny<string>(), default))
                .ReturnsAsync(cachedPlan);

            // Act
            var result = await _cachedPlanner.GenerateAsync(findings, recommendations);

            // Assert
            Assert.Same(cachedPlan, result);
            Assert.Equal("Cached Plan Time", result.TotalEstimatedTime);
            Assert.Single(result.Phases);

            // Verify cache was checked
            _cacheServiceMock.Verify(x => x.GetAsync<RemediationPlan>(It.IsAny<string>(), default), Times.Once);
        }

        [Fact]
        public async Task GenerateAsync_WithCacheMiss_GeneratesAndCaches()
        {
            // Arrange
            var findings = CreateTestFindings();
            var recommendations = CreateTestRecommendations();

            _cacheServiceMock
                .Setup(x => x.GetAsync<RemediationPlan>(It.IsAny<string>(), default))
                .ReturnsAsync((RemediationPlan?)null);

            // Act
            var result = await _cachedPlanner.GenerateAsync(findings, recommendations);

            // Assert - Real planner generates actual plan
            Assert.NotNull(result);
            Assert.NotNull(result.Phases);
            Assert.NotEmpty(result.Phases); // Should have phases from real generator
            Assert.NotNull(result.TotalEstimatedTime);

            // Verify cache operations
            _cacheServiceMock.Verify(x => x.GetAsync<RemediationPlan>(It.IsAny<string>(), default), Times.Once);
            _cacheServiceMock.Verify(x => x.SetAsync(
                It.IsAny<string>(),
                It.IsAny<RemediationPlan>(),
                It.IsAny<CacheOptions>(),
                default), Times.Once);
        }

        [Fact]
        public async Task GenerateAsync_WithNullFindings_ThrowsArgumentNullException()
        {
            // Arrange
            var recommendations = CreateTestRecommendations();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await _cachedPlanner.GenerateAsync(null!, recommendations));
        }

        [Fact]
        public async Task GenerateAsync_WithNullRecommendations_ThrowsArgumentNullException()
        {
            // Arrange
            var findings = CreateTestFindings();

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await _cachedPlanner.GenerateAsync(findings, null!));
        }

        [Fact]
        public async Task GenerateAsync_WithCacheDisabled_BypassesCache()
        {
            // Arrange
            var disabledConfig = CacheConfiguration.Disabled;
            var cachedPlanner = new CachedRemediationPlanner(
                _innerPlanner,
                _cacheServiceMock.Object,
                _keyGenerator,
                disabledConfig,
                _loggerMock.Object);

            var findings = CreateTestFindings();
            var recommendations = CreateTestRecommendations();

            // Act
            var result = await cachedPlanner.GenerateAsync(findings, recommendations);

            // Assert - Should generate without cache
            Assert.NotNull(result);
            Assert.NotEmpty(result.Phases);
            _cacheServiceMock.Verify(x => x.GetAsync<RemediationPlan>(It.IsAny<string>(), default), Times.Never);
            _cacheServiceMock.Verify(x => x.SetAsync(It.IsAny<string>(), It.IsAny<RemediationPlan>(), It.IsAny<CacheOptions>(), default), Times.Never);
        }

        [Fact]
        public async Task GenerateAsync_WhenCacheFails_FallsBackToDirectGeneration()
        {
            // Arrange
            var findings = CreateTestFindings();
            var recommendations = CreateTestRecommendations();

            _cacheServiceMock
                .Setup(x => x.GetAsync<RemediationPlan>(It.IsAny<string>(), default))
                .ThrowsAsync(new Exception("Cache error"));

            // Act
            var result = await _cachedPlanner.GenerateAsync(findings, recommendations);

            // Assert - Should still generate results despite cache failure
            Assert.NotNull(result);
            Assert.NotEmpty(result.Phases);
        }

        #endregion

        #region GenerateServiceRemediationStep Tests

        [Fact]
        public void GenerateServiceRemediationStep_CallsRealService()
        {
            // Act - Calling real planner method
            var result = _cachedPlanner.GenerateServiceRemediationStep(21, "FTP");

            // Assert - Real planner generates actual step
            Assert.NotNull(result);
            Assert.Equal("Replace FTP with secure alternative", result.Summary);
            Assert.NotEmpty(result.DetailedSteps);
        }

        #endregion

        #region GenerateRecommendationsAsync Tests

        [Fact]
        public async Task GenerateRecommendationsAsync_WithCacheHit_ReturnsCachedResult()
        {
            // Arrange
            var findings = CreateTestFindings();
            var perfIssues = new List<PerformanceIssue>();
            var cachedRecs = new List<Recommendation>
            {
                new Recommendation { Title = "Cached Recommendation", Priority = RemediationPriority.High }
            };

            _cacheServiceMock
                .Setup(x => x.GetAsync<List<Recommendation>>(It.IsAny<string>(), default))
                .ReturnsAsync(cachedRecs);

            // Act
            var result = await _cachedPlanner.GenerateRecommendationsAsync(findings, perfIssues);

            // Assert
            Assert.Same(cachedRecs, result);
            Assert.Single(result);
            Assert.Equal("Cached Recommendation", result[0].Title);
        }

        [Fact]
        public async Task GenerateRecommendationsAsync_WithCacheMiss_GeneratesAndCaches()
        {
            // Arrange
            var findings = CreateTestFindings();
            var perfIssues = new List<PerformanceIssue>
            {
                new PerformanceIssue { Category = "Bandwidth", Severity = SeverityLevel.High }
            };

            _cacheServiceMock
                .Setup(x => x.GetAsync<List<Recommendation>>(It.IsAny<string>(), default))
                .ReturnsAsync((List<Recommendation>?)null);

            // Act
            var result = await _cachedPlanner.GenerateRecommendationsAsync(findings, perfIssues);

            // Assert - Real planner generates recommendations
            Assert.NotNull(result);
            Assert.NotEmpty(result); // Should have recommendations from real generator

            // Verify cache operations
            _cacheServiceMock.Verify(x => x.SetAsync(
                It.IsAny<string>(),
                It.IsAny<List<Recommendation>>(),
                It.IsAny<CacheOptions>(),
                default), Times.Once);
        }

        [Fact]
        public async Task GenerateRecommendationsAsync_WithNullFindings_ThrowsArgumentNullException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await _cachedPlanner.GenerateRecommendationsAsync(null!, new List<PerformanceIssue>()));
        }

        [Fact]
        public async Task GenerateRecommendationsAsync_WithNullPerformanceIssues_ThrowsArgumentNullException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(async () =>
                await _cachedPlanner.GenerateRecommendationsAsync(CreateTestFindings(), null!));
        }

        [Fact]
        public async Task GenerateRecommendationsAsync_WhenCacheFails_FallsBackToDirectGeneration()
        {
            // Arrange
            var findings = CreateTestFindings();
            var perfIssues = new List<PerformanceIssue>();

            _cacheServiceMock
                .Setup(x => x.GetAsync<List<Recommendation>>(It.IsAny<string>(), default))
                .ThrowsAsync(new Exception("Cache error"));

            // Act
            var result = await _cachedPlanner.GenerateRecommendationsAsync(findings, perfIssues);

            // Assert - Should still generate results despite cache failure
            Assert.NotNull(result);
        }

        #endregion

        #region Helper Methods

        private List<SecurityFinding> CreateTestFindings()
        {
            return new List<SecurityFinding>
            {
                new SecurityFinding
                {
                    FindingId = "F001",
                    Title = "Test Finding - Insecure Service",
                    Severity = SeverityLevel.High,
                    Category = "Insecure Services",
                    RiskScore = 75.0,
                    Remediation = new RemediationStep
                    {
                        Priority = RemediationPriority.High,
                        Summary = "Fix insecure service",
                        EstimatedEffort = "4 hours"
                    }
                }
            };
        }

        private List<Recommendation> CreateTestRecommendations()
        {
            return new List<Recommendation>
            {
                new Recommendation
                {
                    Title = "Test Recommendation - Deploy SIEM",
                    Priority = RemediationPriority.High,
                    Category = "Monitoring",
                    EstimatedTimeframe = "2-4 weeks"
                }
            };
        }

        #endregion
    }
}
