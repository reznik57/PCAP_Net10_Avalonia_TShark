using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.AnomalyDetectors;
using Xunit;

namespace PCAPAnalyzer.Tests.Services.AnomalyDetectors;

public class IoTAnomalyDetectorTests
{
    private readonly IoTAnomalyDetector _detector;

    public IoTAnomalyDetectorTests()
    {
        _detector = new IoTAnomalyDetector();
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
    public void CanDetect_WithMQTTTraffic_ReturnsTrue()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { Protocol = Protocol.TCP, DestinationPort = 1883 }
        };

        // Act
        var result = _detector.CanDetect(packets);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void CanDetect_WithCoAPTraffic_ReturnsTrue()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { Protocol = Protocol.UDP, DestinationPort = 5683, Info = "CoAP" }
        };

        // Act
        var result = _detector.CanDetect(packets);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void CanDetect_WithoutIoTTraffic_ReturnsFalse()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { Protocol = Protocol.TCP, DestinationPort = 80 }
        };

        // Act
        var result = _detector.CanDetect(packets);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void Detect_MQTTFlooding_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 250 MQTT packets in 1 second (exceeds 100/sec threshold)
        for (int i = 0; i < 250; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = $"192.168.1.{i % 50}",
                DestinationIP = "192.168.1.100",
                DestinationPort = 1883,
                Info = "MQTT: Publish",
                Timestamp = timestamp.AddMilliseconds(i * 4),
                Length = 200
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var flooding = Assert.Single(anomalies);
        Assert.Equal("IoT MQTT Flooding", flooding.Type);
        Assert.Equal(AnomalySeverity.Critical, flooding.Severity);
    }

    [Fact]
    public void Detect_MultipleBrokers_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Single device connecting to 4 different brokers
        for (int i = 0; i < 4; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.50",
                DestinationIP = $"10.0.0.{i + 1}",
                DestinationPort = 1883,
                Info = "MQTT Connect",
                Timestamp = timestamp.AddSeconds(i),
                Length = 100
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var multipleBrokers = Assert.Single(anomalies);
        Assert.Equal("IoT Multiple Brokers", multipleBrokers.Type);
        Assert.Equal(AnomalySeverity.Medium, multipleBrokers.Severity);
        Assert.Equal(4, multipleBrokers.Metrics["BrokerCount"]);
    }

    [Fact]
    public void Detect_CoAPAmplification_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Small requests
        for (int i = 0; i < 10; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "192.168.1.200",
                DestinationPort = 5683,
                Info = "CoAP: GET",
                Timestamp = timestamp.AddMilliseconds(i * 100),
                Length = 50 // Small request
            });
        }

        // Large responses (15x amplification)
        for (int i = 0; i < 10; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = 100 + i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.200",
                DestinationIP = "192.168.1.100",
                SourcePort = 5683,
                Info = "CoAP: Response",
                Timestamp = timestamp.AddMilliseconds(i * 100 + 50),
                Length = 750 // Large response
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var amplification = Assert.Single(anomalies);
        Assert.Equal("IoT CoAP Amplification", amplification.Type);
        Assert.Equal(AnomalySeverity.High, amplification.Severity);
        Assert.True((double)amplification.Metrics["AmplificationRatio"] >= 10);
    }

    [Fact]
    public void Detect_UnauthorizedAccess_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // 15 rapid connection attempts in 3 minutes
        for (int i = 0; i < 15; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.150",
                DestinationIP = "192.168.1.100",
                DestinationPort = 1883,
                Info = "MQTT Connect",
                Timestamp = timestamp.AddSeconds(i * 12),
                Length = 100
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var unauthorized = Assert.Single(anomalies);
        Assert.Equal("IoT Unauthorized Access", unauthorized.Type);
        Assert.True(unauthorized.Metrics.ContainsKey("ConnectionAttempts"));
        Assert.Equal(15, unauthorized.Metrics["ConnectionAttempts"]);
    }

    [Fact]
    public void Properties_ReturnsCorrectValues()
    {
        // Assert
        Assert.Equal("IoT Anomaly Detector", _detector.Name);
        Assert.Equal(AnomalyCategory.IoT, _detector.Category);
        Assert.Equal(4, _detector.Priority);
    }

    [Fact]
    public void Detect_MQTTSecurePort_IsDetected()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { Protocol = Protocol.TCP, DestinationPort = 8883, Info = "MQTT" }
        };

        // Act
        var canDetect = _detector.CanDetect(packets);

        // Assert
        Assert.True(canDetect);
    }

    [Fact]
    public void Detect_CoAPSecurePort_IsDetected()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { Protocol = Protocol.UDP, DestinationPort = 5684, Info = "CoAP" }
        };

        // Act
        var canDetect = _detector.CanDetect(packets);

        // Assert
        Assert.True(canDetect);
    }

    [Fact]
    public void Detect_MQTTFlooding_HighRate_CriticalSeverity()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 300 MQTT packets in 1 second (>200/sec = critical)
        for (int i = 0; i < 300; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = $"192.168.1.{i % 50}",
                DestinationIP = "192.168.1.100",
                DestinationPort = 1883,
                Info = "MQTT: Publish",
                Timestamp = timestamp.AddMilliseconds(i * 3.33),
                Length = 200
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var flooding = anomalies.Find(a => a.Type == "IoT MQTT Flooding");
        Assert.NotNull(flooding);
        Assert.Equal(AnomalySeverity.Critical, flooding.Severity);
    }

    [Fact]
    public void Detect_MultipleBrokers_FiveBrokers_HighSeverity()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Single device connecting to 5 different brokers
        for (int i = 0; i < 5; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.50",
                DestinationIP = $"10.0.0.{i + 1}",
                DestinationPort = 1883,
                Info = "MQTT Connect",
                Timestamp = timestamp.AddSeconds(i),
                Length = 100
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var multipleBrokers = anomalies.Find(a => a.Type == "IoT Multiple Brokers");
        Assert.NotNull(multipleBrokers);
        Assert.Equal(AnomalySeverity.High, multipleBrokers.Severity);
    }

    [Fact]
    public void Detect_CoAPAmplification_HighRatio_CriticalSeverity()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Small requests
        for (int i = 0; i < 10; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "192.168.1.200",
                DestinationPort = 5683,
                Info = "CoAP: GET",
                Timestamp = timestamp.AddMilliseconds(i * 100),
                Length = 30 // Very small request
            });
        }

        // Large responses (100x amplification)
        for (int i = 0; i < 10; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = 100 + i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.200",
                DestinationIP = "192.168.1.100",
                SourcePort = 5683,
                Info = "CoAP: Response",
                Timestamp = timestamp.AddMilliseconds(i * 100 + 50),
                Length = 3000 // Large response (100x)
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var amplification = anomalies.Find(a => a.Type == "IoT CoAP Amplification");
        Assert.NotNull(amplification);
        Assert.Equal(AnomalySeverity.Critical, amplification.Severity);
    }

    [Fact]
    public void Detect_UnauthorizedAccess_HighRate_HighSeverity()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // 20 rapid connection attempts in 1 minute (>10/min = high severity)
        for (int i = 0; i < 20; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.150",
                DestinationIP = "192.168.1.100",
                DestinationPort = 1883,
                Info = "MQTT Connect",
                Timestamp = timestamp.AddSeconds(i * 3),
                Length = 100
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var unauthorized = anomalies.Find(a => a.Type == "IoT Unauthorized Access");
        Assert.NotNull(unauthorized);
        Assert.Equal(AnomalySeverity.High, unauthorized.Severity);
    }

    [Fact]
    public void Detect_MQTTFlooding_TracksUniqueSources()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // 250 packets from 50 different sources
        for (int i = 0; i < 250; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = $"192.168.1.{i % 50}",
                DestinationIP = "192.168.1.100",
                DestinationPort = 1883,
                Info = "MQTT: Publish",
                Timestamp = timestamp.AddMilliseconds(i * 4),
                Length = 200
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var flooding = anomalies.Find(a => a.Type == "IoT MQTT Flooding");
        Assert.NotNull(flooding);
        Assert.Equal(50, flooding.Metrics["UniqueSources"]);
    }

    [Fact]
    public void Detect_NormalMQTTTraffic_NoFalsePositive()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 50 packets in 1 second (below 100/sec threshold)
        for (int i = 0; i < 50; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.50",
                DestinationIP = "192.168.1.100",
                DestinationPort = 1883,
                Info = "MQTT: Publish",
                Timestamp = timestamp.AddMilliseconds(i * 20),
                Length = 200
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.Empty(anomalies);
    }

    [Fact]
    public void Detect_DetectorName_IsCorrect()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 250; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = $"192.168.1.{i % 50}",
                DestinationIP = "192.168.1.100",
                DestinationPort = 1883,
                Info = "MQTT: Publish",
                Timestamp = timestamp.AddMilliseconds(i * 4),
                Length = 200
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var flooding = anomalies.Find(a => a.Type == "IoT MQTT Flooding");
        Assert.NotNull(flooding);
        Assert.Equal("IoT Anomaly Detector", flooding.DetectorName);
    }

    [Fact]
    public void Detect_Recommendation_ContainsRateLimiting()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 250; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = $"192.168.1.{i % 50}",
                DestinationIP = "192.168.1.100",
                DestinationPort = 1883,
                Info = "MQTT: Publish",
                Timestamp = timestamp.AddMilliseconds(i * 4),
                Length = 200
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var flooding = anomalies.Find(a => a.Type == "IoT MQTT Flooding");
        Assert.NotNull(flooding);
        Assert.Contains("rate limiting", flooding.Recommendation, StringComparison.OrdinalIgnoreCase);
    }
}
