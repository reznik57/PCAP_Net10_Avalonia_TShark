using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.Caching;
using Xunit;

namespace PCAPAnalyzer.Tests.Services.Caching
{
    /// <summary>
    /// Tests for CacheKeyGenerator ensuring deterministic key generation and collision resistance.
    /// </summary>
    public class CacheKeyGeneratorTests
    {
        private readonly CacheKeyGenerator _generator;

        public CacheKeyGeneratorTests()
        {
            _generator = new CacheKeyGenerator();
        }

        #region GenerateForSecurityFindings Tests

        [Fact]
        public void GenerateForSecurityFindings_WithSameInputs_GeneratesSameKey()
        {
            // Arrange
            var stats = CreateTestStatistics();
            var threats = CreateTestThreats();

            // Act
            var key1 = _generator.GenerateForSecurityFindings(stats, threats);
            var key2 = _generator.GenerateForSecurityFindings(stats, threats);

            // Assert
            Assert.Equal(key1, key2);
        }

        [Fact]
        public void GenerateForSecurityFindings_WithDifferentInputs_GeneratesDifferentKeys()
        {
            // Arrange
            var stats1 = CreateTestStatistics();
            var stats2 = CreateTestStatistics();
            stats2.TotalPackets = 999999; // Different value
            var threats = CreateTestThreats();

            // Act
            var key1 = _generator.GenerateForSecurityFindings(stats1, threats);
            var key2 = _generator.GenerateForSecurityFindings(stats2, threats);

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void GenerateForSecurityFindings_WithNullStatistics_ThrowsArgumentNullException()
        {
            // Arrange
            var threats = CreateTestThreats();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                _generator.GenerateForSecurityFindings(null!, threats));
        }

        [Fact]
        public void GenerateForSecurityFindings_WithNullThreats_ThrowsArgumentNullException()
        {
            // Arrange
            var stats = CreateTestStatistics();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                _generator.GenerateForSecurityFindings(stats, null!));
        }

        [Fact]
        public void GenerateForSecurityFindings_GeneratesValidFormat()
        {
            // Arrange
            var stats = CreateTestStatistics();
            var threats = CreateTestThreats();

            // Act
            var key = _generator.GenerateForSecurityFindings(stats, threats);

            // Assert
            Assert.Contains("ReportCache:SecurityFindings:", key);
            Assert.True(CacheKeyGenerator.ValidateKeyFormat(key));
        }

        #endregion

        #region GenerateForRemediationPlan Tests

        [Fact]
        public void GenerateForRemediationPlan_WithSameInputs_GeneratesSameKey()
        {
            // Arrange
            var findings = CreateTestFindings();
            var recommendations = CreateTestRecommendations();

            // Act
            var key1 = _generator.GenerateForRemediationPlan(findings, recommendations);
            var key2 = _generator.GenerateForRemediationPlan(findings, recommendations);

            // Assert
            Assert.Equal(key1, key2);
        }

        [Fact]
        public void GenerateForRemediationPlan_WithDifferentInputs_GeneratesDifferentKeys()
        {
            // Arrange
            var findings1 = CreateTestFindings();
            var findings2 = CreateTestFindings();
            findings2.Add(new SecurityFinding { Title = "Additional Finding" });
            var recommendations = CreateTestRecommendations();

            // Act
            var key1 = _generator.GenerateForRemediationPlan(findings1, recommendations);
            var key2 = _generator.GenerateForRemediationPlan(findings2, recommendations);

            // Assert
            Assert.NotEqual(key1, key2);
        }

        [Fact]
        public void GenerateForRemediationPlan_WithNullFindings_ThrowsArgumentNullException()
        {
            // Arrange
            var recommendations = CreateTestRecommendations();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                _generator.GenerateForRemediationPlan(null!, recommendations));
        }

        [Fact]
        public void GenerateForRemediationPlan_WithNullRecommendations_ThrowsArgumentNullException()
        {
            // Arrange
            var findings = CreateTestFindings();

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() =>
                _generator.GenerateForRemediationPlan(findings, null!));
        }

        #endregion

        #region GenerateGeneric Tests

        [Fact]
        public void GenerateGeneric_WithValidParameters_GeneratesKey()
        {
            // Act
            var key = _generator.GenerateGeneric("TestService", "TestOperation", "param1", 123);

            // Assert
            Assert.NotNull(key);
            Assert.Contains("ReportCache:TestService:TestOperation:", key);
        }

        [Fact]
        public void GenerateGeneric_WithNullServiceName_ThrowsArgumentException()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                _generator.GenerateGeneric(null!, "Operation"));
        }

        [Fact]
        public void GenerateGeneric_WithNullOperation_ThrowsArgumentException()
        {
            // Act & Assert
            Assert.Throws<ArgumentException>(() =>
                _generator.GenerateGeneric("Service", null!));
        }

        [Fact]
        public void GenerateGeneric_WithSameParameters_GeneratesSameKey()
        {
            // Act
            var key1 = _generator.GenerateGeneric("Service", "Op", "p1", "p2");
            var key2 = _generator.GenerateGeneric("Service", "Op", "p1", "p2");

            // Assert
            Assert.Equal(key1, key2);
        }

        #endregion

        #region Key Validation Tests

        [Fact]
        public void ValidateKeyFormat_WithValidKey_ReturnsTrue()
        {
            // Arrange
            var stats = CreateTestStatistics();
            var threats = CreateTestThreats();
            var key = _generator.GenerateForSecurityFindings(stats, threats);

            // Act
            var isValid = CacheKeyGenerator.ValidateKeyFormat(key);

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void ValidateKeyFormat_WithInvalidKey_ReturnsFalse()
        {
            // Act
            var isValid = CacheKeyGenerator.ValidateKeyFormat("invalid-key-format");

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void ValidateKeyFormat_WithNullKey_ReturnsFalse()
        {
            // Act
            var isValid = CacheKeyGenerator.ValidateKeyFormat(null!);

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void ExtractOperation_WithValidKey_ReturnsOperation()
        {
            // Arrange
            var stats = CreateTestStatistics();
            var threats = CreateTestThreats();
            var key = _generator.GenerateForSecurityFindings(stats, threats);

            // Act
            var operation = CacheKeyGenerator.ExtractOperation(key);

            // Assert
            Assert.Equal("SecurityFindings", operation);
        }

        [Fact]
        public void ExtractOperation_WithInvalidKey_ReturnsNull()
        {
            // Act
            var operation = CacheKeyGenerator.ExtractOperation("invalid-key");

            // Assert
            Assert.Null(operation);
        }

        #endregion

        #region Collision Resistance Tests

        [Fact]
        public void KeyGeneration_WithManyDifferentInputs_GeneratesUniqueKeys()
        {
            // Arrange
            var keys = new HashSet<string>();
            var stats = CreateTestStatistics();

            // Act - Generate keys with varying threat counts
            for (int i = 0; i < 100; i++)
            {
                var threats = new List<SecurityThreat>();
                for (int j = 0; j < i; j++)
                {
                    threats.Add(new SecurityThreat
                    {
                        Type = $"Threat-{j}",
                        Severity = (ThreatSeverity)(j % 5 + 1)
                    });
                }

                var key = _generator.GenerateForSecurityFindings(stats, threats);
                keys.Add(key);
            }

            // Assert - All keys should be unique
            Assert.Equal(100, keys.Count);
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
                ProtocolStats = new Dictionary<string, ProtocolStatistics>
                {
                    ["TCP"] = new ProtocolStatistics { Protocol = "TCP", PacketCount = 5000 },
                    ["UDP"] = new ProtocolStatistics { Protocol = "UDP", PacketCount = 3000 }
                },
                TopPorts = new List<PortStatistics>
                {
                    new PortStatistics { Port = 80, PacketCount = 1000 },
                    new PortStatistics { Port = 443, PacketCount = 2000 }
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
                    DestinationAddress = "10.0.0.50"
                },
                new SecurityThreat
                {
                    Type = "Malware",
                    Severity = ThreatSeverity.Critical,
                    SourceAddress = "192.168.1.200",
                    DestinationAddress = "10.0.0.100"
                }
            };
        }

        private List<SecurityFinding> CreateTestFindings()
        {
            return new List<SecurityFinding>
            {
                new SecurityFinding
                {
                    Title = "Test Finding 1",
                    Severity = SeverityLevel.High,
                    Category = "Security",
                    RiskScore = 75.0
                },
                new SecurityFinding
                {
                    Title = "Test Finding 2",
                    Severity = SeverityLevel.Medium,
                    Category = "Configuration",
                    RiskScore = 50.0
                }
            };
        }

        private List<Recommendation> CreateTestRecommendations()
        {
            return new List<Recommendation>
            {
                new Recommendation
                {
                    Title = "Test Recommendation",
                    Priority = RemediationPriority.High,
                    Category = "Security"
                }
            };
        }

        #endregion
    }
}
