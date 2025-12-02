using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using Moq;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Services;
using Xunit;

namespace PCAPAnalyzer.Tests.Services;

public class AnomalyFrameIndexServiceTests
{
    private readonly Mock<ILogger<AnomalyFrameIndexService>> _loggerMock;
    private readonly AnomalyFrameIndexService _service;

    public AnomalyFrameIndexServiceTests()
    {
        _loggerMock = new Mock<ILogger<AnomalyFrameIndexService>>();
        _service = new AnomalyFrameIndexService(_loggerMock.Object);
    }

    [Fact]
    public void BuildIndex_SetsHasIndex()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("TCP", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2, 3 }),
            CreateAnomaly("Network", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 4, 5 })
        };

        // Act
        _service.BuildIndex(anomalies);

        // Assert
        Assert.True(_service.HasIndex);
        Assert.Equal(2, _service.TotalAnomalyCount);
    }

    [Fact]
    public void ClearIndex_ResetsState()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("TCP", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2, 3 })
        };
        _service.BuildIndex(anomalies);

        // Act
        _service.ClearIndex();

        // Assert
        Assert.False(_service.HasIndex);
        Assert.Equal(0, _service.TotalAnomalyCount);
        Assert.Empty(_service.GetDetectorNames());
    }

    [Fact]
    public void GetFramesMatchingFilters_NoFilters_ReturnsEmpty()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("TCP", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2, 3 }),
            CreateAnomaly("Network", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 4, 5 })
        };
        _service.BuildIndex(anomalies);

        // Act - No filters provided
        var result = _service.GetFramesMatchingFilters(null, null, null);

        // Assert - Should return empty set (no anomaly filter active)
        Assert.Empty(result);
    }

    [Fact]
    public void GetFramesMatchingFilters_SeverityFilter_ReturnsMatchingFrames()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("TCP-High", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2, 3 }),
            CreateAnomaly("Network-Medium", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 4, 5 }),
            CreateAnomaly("TCP-Critical", AnomalySeverity.Critical, AnomalyCategory.TCP, new List<long> { 6, 7 })
        };
        _service.BuildIndex(anomalies);

        // Act - Filter by High severity only
        var result = _service.GetFramesMatchingFilters(
            new List<AnomalySeverity> { AnomalySeverity.High },
            null,
            null);

        // Assert - Should return frames from High severity anomaly
        Assert.Equal(3, result.Count);
        Assert.Contains(1L, result);
        Assert.Contains(2L, result);
        Assert.Contains(3L, result);
        Assert.DoesNotContain(4L, result);
        Assert.DoesNotContain(5L, result);
    }

    [Fact]
    public void GetFramesMatchingFilters_CategoryFilter_ReturnsMatchingFrames()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("TCP-Detector", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2, 3 }),
            CreateAnomaly("Network-Detector", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 4, 5 }),
            CreateAnomaly("Security-Detector", AnomalySeverity.Critical, AnomalyCategory.Security, new List<long> { 6, 7 })
        };
        _service.BuildIndex(anomalies);

        // Act - Filter by TCP category only
        var result = _service.GetFramesMatchingFilters(
            null,
            new List<AnomalyCategory> { AnomalyCategory.TCP },
            null);

        // Assert - Should return frames from TCP category anomaly
        Assert.Equal(3, result.Count);
        Assert.Contains(1L, result);
        Assert.Contains(2L, result);
        Assert.Contains(3L, result);
        Assert.DoesNotContain(4L, result);
    }

    [Fact]
    public void GetFramesMatchingFilters_CombinedFilters_AppliesAnd()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("TCP-Detector", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2, 3 }),
            CreateAnomaly("Network-Detector", AnomalySeverity.High, AnomalyCategory.Network, new List<long> { 4, 5 }),
            CreateAnomaly("TCP-Detector-2", AnomalySeverity.Medium, AnomalyCategory.TCP, new List<long> { 6, 7 })
        };
        _service.BuildIndex(anomalies);

        // Act - Filter by High severity AND TCP category
        var result = _service.GetFramesMatchingFilters(
            new List<AnomalySeverity> { AnomalySeverity.High },
            new List<AnomalyCategory> { AnomalyCategory.TCP },
            null);

        // Assert - Should return frames from High + TCP anomaly only
        Assert.Equal(3, result.Count);
        Assert.Contains(1L, result);
        Assert.Contains(2L, result);
        Assert.Contains(3L, result);
        Assert.DoesNotContain(4L, result); // High but Network
        Assert.DoesNotContain(6L, result); // TCP but Medium
    }

    [Fact]
    public void GetFramesMatchingFilters_DetectorFilter_ReturnsMatchingFrames()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("TCPDetector", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2, 3 }),
            CreateAnomaly("NetworkDetector", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 4, 5 }),
            CreateAnomaly("SecurityDetector", AnomalySeverity.Critical, AnomalyCategory.Security, new List<long> { 6, 7 })
        };
        _service.BuildIndex(anomalies);

        // Act - Filter by specific detector
        var result = _service.GetFramesMatchingFilters(
            null,
            null,
            new List<string> { "TCPDetector" });

        // Assert
        Assert.Equal(3, result.Count);
        Assert.Contains(1L, result);
        Assert.Contains(2L, result);
        Assert.Contains(3L, result);
        Assert.DoesNotContain(4L, result);
    }

    [Fact]
    public void GetFramesMatchingFilters_MultipleDetectors_ReturnsMatchingFrames()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("DetectorA", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2 }),
            CreateAnomaly("DetectorB", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 3, 4 }),
            CreateAnomaly("DetectorC", AnomalySeverity.Critical, AnomalyCategory.Security, new List<long> { 5, 6 })
        };
        _service.BuildIndex(anomalies);

        // Act - Filter by two detectors (OR within detector filter)
        var result = _service.GetFramesMatchingFilters(
            null,
            null,
            new List<string> { "DetectorA", "DetectorB" });

        // Assert
        Assert.Equal(4, result.Count);
        Assert.Contains(1L, result);
        Assert.Contains(2L, result);
        Assert.Contains(3L, result);
        Assert.Contains(4L, result);
        Assert.DoesNotContain(5L, result);
    }

    [Fact]
    public void GetFramesMatchingFilters_NoIndex_ReturnsEmpty()
    {
        // Act - No index built
        var result = _service.GetFramesMatchingFilters(
            new List<AnomalySeverity> { AnomalySeverity.High },
            null,
            null);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void GetAnomaliesForFrame_OverlappingFrame_ReturnsBoth()
    {
        // Arrange - Two anomalies affecting the same frame
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("Detector1", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2, 3 }),
            CreateAnomaly("Detector2", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 2, 3, 4 })
        };
        _service.BuildIndex(anomalies);

        // Act - Get anomalies for frame 2 (affected by both)
        var result = _service.GetAnomaliesForFrame(2);

        // Assert - Should return both anomalies
        Assert.Equal(2, result.Count);
        Assert.Contains(result, a => a.DetectorName == "Detector1");
        Assert.Contains(result, a => a.DetectorName == "Detector2");
    }

    [Fact]
    public void GetAnomaliesForFrame_SingleAnomaly_ReturnsOne()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("Detector1", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2, 3 }),
            CreateAnomaly("Detector2", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 4, 5, 6 })
        };
        _service.BuildIndex(anomalies);

        // Act
        var result = _service.GetAnomaliesForFrame(1);

        // Assert
        Assert.Single(result);
        Assert.Equal("Detector1", result[0].DetectorName);
    }

    [Fact]
    public void GetAnomaliesForFrame_UnknownFrame_ReturnsEmpty()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("Detector1", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2, 3 })
        };
        _service.BuildIndex(anomalies);

        // Act - Frame 999 doesn't exist
        var result = _service.GetAnomaliesForFrame(999);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void GetAnomaliesForFrame_NoIndex_ReturnsEmpty()
    {
        // Act - No index built
        var result = _service.GetAnomaliesForFrame(1);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void GetDetectorNames_ReturnsDistinctSorted()
    {
        // Arrange - Multiple anomalies from different detectors
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("ZebraDetector", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1 }),
            CreateAnomaly("AlphaDetector", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 2 }),
            CreateAnomaly("BetaDetector", AnomalySeverity.Critical, AnomalyCategory.Security, new List<long> { 3 }),
            CreateAnomaly("AlphaDetector", AnomalySeverity.Low, AnomalyCategory.TCP, new List<long> { 4 }) // Duplicate
        };
        _service.BuildIndex(anomalies);

        // Act
        var result = _service.GetDetectorNames();

        // Assert - Should be distinct and sorted alphabetically
        Assert.Equal(3, result.Count);
        Assert.Equal("AlphaDetector", result[0]);
        Assert.Equal("BetaDetector", result[1]);
        Assert.Equal("ZebraDetector", result[2]);
    }

    [Fact]
    public void GetDetectorNames_NoIndex_ReturnsEmpty()
    {
        // Act
        var result = _service.GetDetectorNames();

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void GetFilteredAnomalies_NoFilters_ReturnsAll()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("Detector1", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2 }),
            CreateAnomaly("Detector2", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 3, 4 })
        };
        _service.BuildIndex(anomalies);

        // Act
        var result = _service.GetFilteredAnomalies(null, null, null);

        // Assert
        Assert.Equal(2, result.Count);
    }

    [Fact]
    public void GetFilteredAnomalies_MultipleFilters_AppliesAnd()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("DetectorA", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2 }),
            CreateAnomaly("DetectorB", AnomalySeverity.High, AnomalyCategory.Network, new List<long> { 3, 4 }),
            CreateAnomaly("DetectorA", AnomalySeverity.Medium, AnomalyCategory.TCP, new List<long> { 5, 6 })
        };
        _service.BuildIndex(anomalies);

        // Act - Filter by High severity AND TCP category AND DetectorA
        var result = _service.GetFilteredAnomalies(
            new List<AnomalySeverity> { AnomalySeverity.High },
            new List<AnomalyCategory> { AnomalyCategory.TCP },
            new List<string> { "DetectorA" });

        // Assert - Should return only the anomaly matching all criteria
        Assert.Single(result);
        Assert.Equal("DetectorA", result[0].DetectorName);
        Assert.Equal(AnomalySeverity.High, result[0].Severity);
        Assert.Equal(AnomalyCategory.TCP, result[0].Category);
    }

    [Fact]
    public void GetFilteredAnomalies_SeverityFilter_ReturnsMatching()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("Detector1", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1 }),
            CreateAnomaly("Detector2", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 2 }),
            CreateAnomaly("Detector3", AnomalySeverity.High, AnomalyCategory.Security, new List<long> { 3 })
        };
        _service.BuildIndex(anomalies);

        // Act
        var result = _service.GetFilteredAnomalies(
            new List<AnomalySeverity> { AnomalySeverity.High },
            null,
            null);

        // Assert
        Assert.Equal(2, result.Count);
        Assert.All(result, a => Assert.Equal(AnomalySeverity.High, a.Severity));
    }

    [Fact]
    public void GetFilteredAnomalies_NoIndex_ReturnsEmpty()
    {
        // Act
        var result = _service.GetFilteredAnomalies(
            new List<AnomalySeverity> { AnomalySeverity.High },
            null,
            null);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void BuildIndex_WithAnomaliesWithoutFrames_HandlesCorrectly()
    {
        // Arrange - Some anomalies have no AffectedFrames
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("Detector1", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2 }),
            CreateAnomaly("Detector2", AnomalySeverity.Medium, AnomalyCategory.Network, null), // No frames
            CreateAnomaly("Detector3", AnomalySeverity.Critical, AnomalyCategory.Security, new List<long>()) // Empty frames
        };

        // Act
        _service.BuildIndex(anomalies);

        // Assert
        Assert.True(_service.HasIndex);
        Assert.Equal(3, _service.TotalAnomalyCount);

        // GetFramesMatchingFilters should only return frames from anomalies that have them
        var frames = _service.GetFramesMatchingFilters(
            null,
            new List<AnomalyCategory> { AnomalyCategory.Network, AnomalyCategory.Security },
            null);
        Assert.Empty(frames); // Neither Network nor Security have frames

        var tcpFrames = _service.GetFramesMatchingFilters(
            null,
            new List<AnomalyCategory> { AnomalyCategory.TCP },
            null);
        Assert.Equal(2, tcpFrames.Count);
    }

    [Fact]
    public void BuildIndex_WithEmptyList_SetsIndexButNoData()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>();

        // Act
        _service.BuildIndex(anomalies);

        // Assert
        Assert.True(_service.HasIndex);
        Assert.Equal(0, _service.TotalAnomalyCount);
        Assert.Empty(_service.GetDetectorNames());
    }

    [Fact]
    public void GetFramesMatchingFilters_MultipleSeverities_AppliesOr()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("Detector1", AnomalySeverity.Low, AnomalyCategory.TCP, new List<long> { 1, 2 }),
            CreateAnomaly("Detector2", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 3, 4 }),
            CreateAnomaly("Detector3", AnomalySeverity.High, AnomalyCategory.Security, new List<long> { 5, 6 })
        };
        _service.BuildIndex(anomalies);

        // Act - Filter by Low OR High severity
        var result = _service.GetFramesMatchingFilters(
            new List<AnomalySeverity> { AnomalySeverity.Low, AnomalySeverity.High },
            null,
            null);

        // Assert
        Assert.Equal(4, result.Count);
        Assert.Contains(1L, result);
        Assert.Contains(2L, result);
        Assert.Contains(5L, result);
        Assert.Contains(6L, result);
        Assert.DoesNotContain(3L, result);
        Assert.DoesNotContain(4L, result);
    }

    [Fact]
    public void GetFramesMatchingFilters_MultipleCategories_AppliesOr()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("Detector1", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2 }),
            CreateAnomaly("Detector2", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 3, 4 }),
            CreateAnomaly("Detector3", AnomalySeverity.Critical, AnomalyCategory.Security, new List<long> { 5, 6 })
        };
        _service.BuildIndex(anomalies);

        // Act - Filter by TCP OR Security category
        var result = _service.GetFramesMatchingFilters(
            null,
            new List<AnomalyCategory> { AnomalyCategory.TCP, AnomalyCategory.Security },
            null);

        // Assert
        Assert.Equal(4, result.Count);
        Assert.Contains(1L, result);
        Assert.Contains(2L, result);
        Assert.Contains(5L, result);
        Assert.Contains(6L, result);
        Assert.DoesNotContain(3L, result);
        Assert.DoesNotContain(4L, result);
    }

    [Fact]
    public void ThreadSafety_ConcurrentReads_DoNotThrow()
    {
        // Arrange
        var anomalies = new List<NetworkAnomaly>
        {
            CreateAnomaly("Detector1", AnomalySeverity.High, AnomalyCategory.TCP, new List<long> { 1, 2, 3 }),
            CreateAnomaly("Detector2", AnomalySeverity.Medium, AnomalyCategory.Network, new List<long> { 4, 5, 6 })
        };
        _service.BuildIndex(anomalies);

        // Act - Concurrent reads should not throw
        var tasks = Enumerable.Range(0, 10).Select(_ => System.Threading.Tasks.Task.Run(() =>
        {
            _service.GetFramesMatchingFilters(new List<AnomalySeverity> { AnomalySeverity.High }, null, null);
            _service.GetAnomaliesForFrame(1);
            _service.GetDetectorNames();
            _service.GetFilteredAnomalies(null, null, null);
        })).ToArray();

        // Assert - Should complete without exceptions
        System.Threading.Tasks.Task.WaitAll(tasks);
    }

    /// <summary>
    /// Helper method to create a NetworkAnomaly for testing
    /// </summary>
    private NetworkAnomaly CreateAnomaly(
        string detectorName,
        AnomalySeverity severity,
        AnomalyCategory category,
        List<long>? frames)
    {
        return new NetworkAnomaly
        {
            DetectorName = detectorName,
            Severity = severity,
            Category = category,
            Type = $"{category} Test",
            Description = $"Test anomaly from {detectorName}",
            DetectedAt = DateTime.UtcNow,
            AffectedFrames = frames ?? new List<long>(),
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.200",
            Protocol = "TCP"
        };
    }
}
