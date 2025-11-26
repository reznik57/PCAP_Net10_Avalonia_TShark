using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.AnomalyDetectors;
using Xunit;

namespace PCAPAnalyzer.Tests.Services.AnomalyDetectors;

public class DataExfiltrationDetectorTests
{
    private readonly DataExfiltrationDetector _detector;

    public DataExfiltrationDetectorTests()
    {
        _detector = new DataExfiltrationDetector();
    }

    [Fact]
    public void Detect_EmptyPackets_ReturnsEmpty()
    {
        // Arrange
        var packets = new List<PacketInfo>();

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.Empty(anomalies);
    }

    [Fact]
    public void CanDetect_WithSufficientPackets_ReturnsTrue()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        for (int i = 0; i < 60; i++)
        {
            packets.Add(new PacketInfo { FrameNumber = i });
        }

        // Act
        var result = _detector.CanDetect(packets);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void CanDetect_WithInsufficientPackets_ReturnsFalse()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        for (int i = 0; i < 30; i++)
        {
            packets.Add(new PacketInfo { FrameNumber = i });
        }

        // Act
        var result = _detector.CanDetect(packets);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Detect_LargeUpload_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 15MB upload
        for (int i = 0; i < 10000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 8080, // Non-standard port
                Info = "TCP",
                Timestamp = timestamp.AddSeconds(i * 0.1),
                Length = 1536 // ~15MB total
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var exfiltration = anomalies.Find(a => a.Type == "Data Exfiltration");
        Assert.NotNull(exfiltration);
        Assert.True((long)exfiltration.Metrics["TotalBytes"] >= 10 * 1024 * 1024);
        Assert.True((bool)exfiltration.Metrics["IsNonStandardPort"]);
    }

    [Fact]
    public void Detect_SlowExfiltration_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate slow transfer: 2MB over 2 hours
        for (int i = 0; i < 1000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 443,
                Info = "TCP",
                Timestamp = timestamp.AddSeconds(i * 7.2), // 2 hours total
                Length = 2048 // 2MB total
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var slowExfil = anomalies.Find(a => a.Type == "Slow Data Exfiltration");
        Assert.NotNull(slowExfil);
        Assert.Equal(AnomalySeverity.High, slowExfil.Severity);
        Assert.True((double)slowExfil.Metrics["DurationHours"] >= 1.0);
    }

    [Fact]
    public void Detect_EncodedTransfer_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate packets with base64-like patterns
        for (int i = 0; i < 10; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 443,
                Info = "data: SGVsbG8gV29ybGQhVGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIG1lc3NhZ2U=", // base64 pattern
                Timestamp = timestamp.AddSeconds(i),
                Length = 500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var encoded = anomalies.Find(a => a.Type == "Encoded Data Transfer");
        Assert.NotNull(encoded);
        Assert.True((int)encoded.Metrics["EncodedPackets"] >= 5);
    }

    [Fact]
    public void Detect_UnusualUploadRatio_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate high upload traffic (10MB)
        for (int i = 0; i < 5000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i * 2,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 443,
                Info = "TCP upload",
                Timestamp = timestamp.AddSeconds(i * 0.1),
                Length = 2048 // Upload packet
            });
        }

        // Generate small download traffic (1MB)
        for (int i = 0; i < 500; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i * 2 + 1,
                Protocol = Protocol.TCP,
                SourceIP = "10.0.0.1",
                DestinationIP = "192.168.1.100",
                SourcePort = 443,
                Info = "TCP download",
                Timestamp = timestamp.AddSeconds(i * 0.1),
                Length = 2048 // Download packet
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        // Should detect unusual outbound traffic (10:1 ratio)
        var unusual = anomalies.Find(a => a.Type == "Unusual Outbound Traffic" || a.Type == "Data Exfiltration");
        Assert.NotNull(unusual);
    }

    [Fact]
    public void Detect_SmallUpload_DoesNotDetect()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate small upload (5MB, below 10MB threshold)
        for (int i = 0; i < 100; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 443,
                Info = "TCP",
                Timestamp = timestamp.AddSeconds(i),
                Length = 51200 // 5MB total
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        // Should not detect large upload (below threshold)
        var exfiltration = anomalies.Find(a => a.Type == "Data Exfiltration");
        Assert.Null(exfiltration);
    }

    [Fact]
    public void Properties_ReturnsCorrectValues()
    {
        // Assert
        Assert.Equal("Data Exfiltration Detector", _detector.Name);
        Assert.Equal(AnomalyCategory.Security, _detector.Category);
        Assert.Equal(7, _detector.Priority);
    }

    [Fact]
    public void Detect_LargeUpload_StandardPort_DetectsWithMediumSeverity()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 15MB upload to standard HTTPS port
        for (int i = 0; i < 10000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 443, // Standard port
                Timestamp = timestamp.AddSeconds(i * 0.1),
                Length = 1536
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var exfiltration = anomalies.Find(a => a.Type == "Data Exfiltration");
        Assert.NotNull(exfiltration);
        Assert.False((bool)exfiltration.Metrics["IsNonStandardPort"]);
    }

    [Fact]
    public void Detect_VeryLargeUpload_100MB_DetectsCritical()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 150MB upload
        for (int i = 0; i < 100000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 8443,
                Timestamp = timestamp.AddSeconds(i * 0.01),
                Length = 1536
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var exfiltration = anomalies.Find(a => a.Type == "Data Exfiltration");
        Assert.NotNull(exfiltration);
        Assert.Equal(AnomalySeverity.Critical, exfiltration.Severity);
    }

    [Fact]
    public void Detect_SlowExfiltration_WithRegularPattern_Detected()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate regular pattern (every 30 seconds for 2 hours)
        for (int i = 0; i < 240; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 443,
                Timestamp = timestamp.AddSeconds(i * 30), // Regular 30s intervals
                Length = 10000 // 2.4MB total
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var slowExfil = anomalies.Find(a => a.Type == "Slow Data Exfiltration");
        Assert.NotNull(slowExfil);
        Assert.True((bool)slowExfil.Metrics["RegularPattern"]);
    }

    [Fact]
    public void Detect_EncodedTransfer_WithBase64Keyword_Detected()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 6; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 443,
                Info = "Content-Type: base64 encoded data",
                Timestamp = timestamp.AddSeconds(i),
                Length = 1000000 // 1MB per packet, 6MB total
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var encoded = anomalies.Find(a => a.Type == "Encoded Data Transfer");
        Assert.NotNull(encoded);
        Assert.Equal(AnomalySeverity.High, encoded.Severity);
    }

    [Fact]
    public void Detect_MultipleDestinations_EncodedTransfer_TracksCount()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 10; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.{i % 3}.1", // 3 different destinations
                DestinationPort = 443,
                Info = "base64: SGVsbG8gV29ybGQhVGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIG1lc3NhZ2U=",
                Timestamp = timestamp.AddSeconds(i),
                Length = 500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var encoded = anomalies.Find(a => a.Type == "Encoded Data Transfer");
        Assert.NotNull(encoded);
        Assert.Equal(3, encoded.Metrics["UniqueDestinations"]);
    }

    [Fact]
    public void Detect_HighUploadRatio_10to1_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // 10MB upload
        for (int i = 0; i < 5000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i * 2,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 443,
                Timestamp = timestamp.AddSeconds(i * 0.1),
                Length = 2048
            });
        }

        // 1MB download
        for (int i = 0; i < 500; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i * 2 + 1,
                Protocol = Protocol.TCP,
                SourceIP = "10.0.0.1",
                DestinationIP = "192.168.1.100",
                SourcePort = 443,
                Timestamp = timestamp.AddSeconds(i * 0.1),
                Length = 2048
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var unusual = anomalies.Find(a => a.Type == "Unusual Outbound Traffic");
        Assert.NotNull(unusual);
        var ratio = (double)unusual.Metrics["UploadDownloadRatio"];
        Assert.True(ratio >= 3.0);
    }

    [Fact]
    public void Detect_UploadRatio_TracksMultipleMetrics()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 3000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.{i % 5}.1",
                DestinationPort = 443 + (i % 3),
                Timestamp = timestamp.AddSeconds(i * 0.1),
                Length = 2048
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        if (anomalies.Any(a => a.Type == "Unusual Outbound Traffic" || a.Type == "Data Exfiltration"))
        {
            var anomaly = anomalies.First(a => a.Type == "Unusual Outbound Traffic" || a.Type == "Data Exfiltration");
            Assert.Contains("UniqueDestinations", anomaly.Metrics.Keys);
            Assert.Contains("PacketCount", anomaly.Metrics.Keys);
        }
    }

    [Fact]
    public void Detect_NormalWebBrowsing_NoFalsePositive()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Simulate normal web browsing (balanced upload/download)
        for (int i = 0; i < 100; i++)
        {
            // Request
            packets.Add(new PacketInfo
            {
                FrameNumber = i * 2,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "93.184.216.34",
                DestinationPort = 443,
                Timestamp = timestamp.AddSeconds(i),
                Length = 500
            });

            // Response (larger)
            packets.Add(new PacketInfo
            {
                FrameNumber = i * 2 + 1,
                Protocol = Protocol.TCP,
                SourceIP = "93.184.216.34",
                DestinationIP = "192.168.1.100",
                SourcePort = 443,
                Timestamp = timestamp.AddSeconds(i + 0.1),
                Length = 1500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.Empty(anomalies);
    }

    [Fact]
    public void Detect_ShortDurationTransfer_NoSlowExfiltration()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // 2MB in 30 minutes (below 1 hour threshold)
        for (int i = 0; i < 1000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 443,
                Timestamp = timestamp.AddSeconds(i * 1.8), // 30 minutes
                Length = 2048
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var slowExfil = anomalies.Find(a => a.Type == "Slow Data Exfiltration");
        Assert.Null(slowExfil);
    }

    [Fact]
    public void Detect_IncludesDetectorName()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 10000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 8080,
                Timestamp = timestamp.AddSeconds(i * 0.1),
                Length = 1536
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var exfiltration = anomalies.Find(a => a.Type == "Data Exfiltration");
        Assert.NotNull(exfiltration);
        Assert.Equal("Data Exfiltration Detector", exfiltration.DetectorName);
    }

    [Fact]
    public void Detect_Recommendation_ContainsInvestigation()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 10000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 8080,
                Timestamp = timestamp.AddSeconds(i * 0.1),
                Length = 1536
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var exfiltration = anomalies.Find(a => a.Type == "Data Exfiltration");
        Assert.NotNull(exfiltration);
        Assert.Contains("investigate", exfiltration.Recommendation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Detect_MultipleConcurrentAnomalies_AllDetected()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Large upload (triggers Data Exfiltration)
        for (int i = 0; i < 10000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 8080,
                Timestamp = timestamp.AddSeconds(i * 0.1),
                Length = 1536
            });
        }

        // Encoded packets (triggers Encoded Transfer)
        for (int i = 0; i < 10; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = 10000 + i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.2",
                DestinationPort = 443,
                Info = "base64: VGhpcyBpcyBhbiBleGFtcGxlIG9mIGJhc2U2NCBlbmNvZGVkIGRhdGE=",
                Timestamp = timestamp.AddSeconds(1000 + i),
                Length = 500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.True(anomalies.Count >= 2);
        Assert.Contains(anomalies, a => a.Type == "Data Exfiltration");
        Assert.Contains(anomalies, a => a.Type == "Encoded Data Transfer");
    }
}
