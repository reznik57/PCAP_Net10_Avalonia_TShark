using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.AnomalyDetectors;
using Xunit;

namespace PCAPAnalyzer.Tests.Services.AnomalyDetectors;

public class VoipAnomalyDetectorTests
{
    private readonly VoipAnomalyDetector _detector;

    public VoipAnomalyDetectorTests()
    {
        _detector = new VoipAnomalyDetector();
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
    public void CanDetect_WithSIPTraffic_ReturnsTrue()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { Protocol = Protocol.SIP, DestinationPort = 5060 }
        };

        // Act
        var result = _detector.CanDetect(packets);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void CanDetect_WithoutVoIPTraffic_ReturnsFalse()
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
    public void Detect_SIPFlooding_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 150 SIP packets in 1 second (exceeds 50/sec threshold)
        for (int i = 0; i < 150; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.SIP,
                SourceIP = $"192.168.1.{i % 100}",
                DestinationIP = "192.168.1.200",
                DestinationPort = 5060,
                Info = "SIP: INVITE",
                Timestamp = timestamp.AddMilliseconds(i * 6.67), // ~150/sec
                Length = 500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var flooding = Assert.Single(anomalies);
        Assert.Equal("VoIP SIP Flooding", flooding.Type);
        Assert.Equal(AnomalySeverity.Critical, flooding.Severity);
        Assert.Contains("flooding", flooding.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Detect_GhostCalls_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 15 INVITE messages without responses
        for (int i = 0; i < 15; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.SIP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"192.168.1.{i + 150}",
                DestinationPort = 5060,
                Info = "SIP: INVITE",
                Timestamp = timestamp.AddSeconds(i),
                Length = 500
            });
        }

        // Add only 2 responses (13% response rate, below 20% threshold)
        packets.Add(new PacketInfo
        {
            FrameNumber = 100,
            Protocol = Protocol.SIP,
            SourceIP = "192.168.1.151",
            DestinationIP = "192.168.1.100",
            Info = "SIP: 200 OK",
            Timestamp = timestamp.AddSeconds(1),
            Length = 300
        });
        packets.Add(new PacketInfo
        {
            FrameNumber = 101,
            Protocol = Protocol.SIP,
            SourceIP = "192.168.1.152",
            DestinationIP = "192.168.1.100",
            Info = "SIP: 200 OK",
            Timestamp = timestamp.AddSeconds(2),
            Length = 300
        });

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var ghostCall = anomalies.Find(a => a.Type == "VoIP Ghost Call");
        Assert.NotNull(ghostCall);
        Assert.Equal(AnomalySeverity.High, ghostCall.Severity);
    }

    [Fact]
    public void Detect_RTPQualityIssues_DetectsHighJitter()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate RTP stream with high jitter
        for (int i = 0; i < 100; i++)
        {
            // Variable intervals create jitter
            var interval = i % 2 == 0 ? 20 : 80; // Alternating 20ms and 80ms
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "192.168.1.200",
                SourcePort = 15000,
                DestinationPort = 15000,
                Info = "RTP",
                Timestamp = timestamp.AddMilliseconds(i * interval),
                Length = 200
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var rtpQuality = anomalies.Find(a => a.Type == "VoIP RTP Quality Issue");
        Assert.NotNull(rtpQuality);
        Assert.True(rtpQuality.Metrics.ContainsKey("Jitter"));
        Assert.True((double)rtpQuality.Metrics["Jitter"] > 30);
    }

    [Fact]
    public void Detect_TollFraud_DetectsHighCallVolume()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 25 calls to different destinations in 2 hours
        for (int i = 0; i < 25; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.SIP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.{i}.1",
                DestinationPort = 5060,
                Info = "SIP: INVITE",
                Timestamp = timestamp.AddMinutes(i * 5),
                Length = 500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var tollFraud = anomalies.Find(a => a.Type == "VoIP Toll Fraud");
        Assert.NotNull(tollFraud);
        Assert.Equal(AnomalySeverity.Critical, tollFraud.Severity);
        Assert.True(tollFraud.Metrics.ContainsKey("CallsPerHour"));
    }

    [Fact]
    public void Properties_ReturnsCorrectValues()
    {
        // Assert
        Assert.Equal("VoIP Anomaly Detector", _detector.Name);
        Assert.Equal(AnomalyCategory.VoIP, _detector.Category);
        Assert.Equal(5, _detector.Priority);
    }

    [Fact]
    public void CanDetect_WithRTPPortRange_ReturnsTrue()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { Protocol = Protocol.UDP, DestinationPort = 15000 }
        };

        // Act
        var result = _detector.CanDetect(packets);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void Detect_SIPFlooding_ModerateRate_DetectsHighSeverity()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 75 SIP packets in 1 second (50-100/sec = High)
        for (int i = 0; i < 75; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.SIP,
                SourceIP = $"192.168.1.{i % 50}",
                DestinationIP = "192.168.1.200",
                DestinationPort = 5060,
                Info = "SIP: INVITE",
                Timestamp = timestamp.AddMilliseconds(i * 13.33),
                Length = 500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var flooding = anomalies.Find(a => a.Type == "VoIP SIP Flooding");
        Assert.NotNull(flooding);
        Assert.Equal(AnomalySeverity.High, flooding.Severity);
    }

    [Fact]
    public void Detect_SIPFlooding_TracksREGISTERCount()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Mix of INVITE and REGISTER
        for (int i = 0; i < 150; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.SIP,
                SourceIP = $"192.168.1.{i % 100}",
                DestinationIP = "192.168.1.200",
                DestinationPort = 5060,
                Info = i % 2 == 0 ? "SIP: INVITE" : "SIP: REGISTER",
                Timestamp = timestamp.AddMilliseconds(i * 6.67),
                Length = 500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var flooding = anomalies.Find(a => a.Type == "VoIP SIP Flooding");
        Assert.NotNull(flooding);
        Assert.Contains("REGISTERCount", flooding.Metrics.Keys);
        Assert.Equal(75, flooding.Metrics["REGISTERCount"]);
    }

    [Fact]
    public void Detect_RTPQualityIssues_ModerateJitter_DetectsMediumSeverity()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate RTP stream with moderate jitter (30-50ms)
        for (int i = 0; i < 100; i++)
        {
            var interval = i % 2 == 0 ? 15 : 55; // 15ms and 55ms alternating = 40ms jitter
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "192.168.1.200",
                SourcePort = 15000,
                DestinationPort = 15000,
                Timestamp = timestamp.AddMilliseconds(i * interval),
                Length = 200
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var rtpQuality = anomalies.Find(a => a.Type == "VoIP RTP Quality Issue");
        Assert.NotNull(rtpQuality);
        Assert.Equal(AnomalySeverity.Medium, rtpQuality.Severity);
    }

    [Fact]
    public void Detect_RTPQualityIssues_HighPacketLoss_DetectsHighSeverity()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate RTP with large gaps (simulating packet loss >10%)
        for (int i = 0; i < 100; i++)
        {
            // Skip every 10th packet to simulate 10% loss
            if (i % 10 != 0)
            {
                packets.Add(new PacketInfo
                {
                    FrameNumber = i,
                    Protocol = Protocol.UDP,
                    SourceIP = "192.168.1.100",
                    DestinationIP = "192.168.1.200",
                    SourcePort = 15000,
                    DestinationPort = 15000,
                    Timestamp = timestamp.AddMilliseconds(i * 20),
                    Length = 200
                });
            }
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var rtpQuality = anomalies.Find(a => a.Type == "VoIP RTP Quality Issue");
        Assert.NotNull(rtpQuality);
        Assert.Equal(AnomalySeverity.High, rtpQuality.Severity);
    }

    [Fact]
    public void Detect_TollFraud_ManyDestinations_DetectsCritical()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 30 calls to 10 different destinations
        for (int i = 0; i < 30; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.SIP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.{i % 10}.1",
                DestinationPort = 5060,
                Info = "SIP: INVITE",
                Timestamp = timestamp.AddMinutes(i * 5),
                Length = 500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var tollFraud = anomalies.Find(a => a.Type == "VoIP Toll Fraud");
        Assert.NotNull(tollFraud);
        Assert.Equal(AnomalySeverity.Critical, tollFraud.Severity);
        Assert.Equal(10, tollFraud.Metrics["UniqueDestinations"]);
    }

    [Fact]
    public void Detect_GhostCalls_LowResponseRate_Detected()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // 20 INVITEs with only 1 response (5% response rate)
        for (int i = 0; i < 20; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.SIP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"192.168.1.{i + 150}",
                DestinationPort = 5060,
                Info = "SIP: INVITE",
                Timestamp = timestamp.AddSeconds(i),
                Length = 500
            });
        }

        // Only one response
        packets.Add(new PacketInfo
        {
            FrameNumber = 100,
            Protocol = Protocol.SIP,
            SourceIP = "192.168.1.151",
            DestinationIP = "192.168.1.100",
            Info = "SIP: 200 OK",
            Timestamp = timestamp.AddSeconds(1),
            Length = 300
        });

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var ghostCall = anomalies.Find(a => a.Type == "VoIP Ghost Call");
        Assert.NotNull(ghostCall);
        var responseRate = (double)ghostCall.Metrics["ResponseRate"];
        Assert.True(responseRate < 0.2);
    }

    [Fact]
    public void Detect_NormalVoIPCall_NoFalsePositive()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Normal SIP signaling
        packets.Add(new PacketInfo
        {
            FrameNumber = 1,
            Protocol = Protocol.SIP,
            SourceIP = "192.168.1.100",
            DestinationIP = "192.168.1.200",
            DestinationPort = 5060,
            Info = "SIP: INVITE",
            Timestamp = timestamp,
            Length = 500
        });

        packets.Add(new PacketInfo
        {
            FrameNumber = 2,
            Protocol = Protocol.SIP,
            SourceIP = "192.168.1.200",
            DestinationIP = "192.168.1.100",
            Info = "SIP: 200 OK",
            Timestamp = timestamp.AddSeconds(1),
            Length = 300
        });

        // Normal RTP stream (50 packets, good quality)
        for (int i = 0; i < 50; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = 3 + i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "192.168.1.200",
                SourcePort = 15000,
                DestinationPort = 15000,
                Timestamp = timestamp.AddSeconds(2 + i * 0.02),
                Length = 172
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

        for (int i = 0; i < 150; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.SIP,
                SourceIP = $"192.168.1.{i % 100}",
                DestinationIP = "192.168.1.200",
                DestinationPort = 5060,
                Info = "SIP: INVITE",
                Timestamp = timestamp.AddMilliseconds(i * 6.67),
                Length = 500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var flooding = anomalies.Find(a => a.Type == "VoIP SIP Flooding");
        Assert.NotNull(flooding);
        Assert.Equal("VoIP Anomaly Detector", flooding.DetectorName);
    }

    [Fact]
    public void Detect_Recommendation_ContainsQoS()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 100; i++)
        {
            var interval = i % 2 == 0 ? 20 : 80;
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "192.168.1.200",
                SourcePort = 15000,
                DestinationPort = 15000,
                Timestamp = timestamp.AddMilliseconds(i * interval),
                Length = 200
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var rtpQuality = anomalies.Find(a => a.Type == "VoIP RTP Quality Issue");
        Assert.NotNull(rtpQuality);
        Assert.Contains("QoS", rtpQuality.Recommendation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Detect_TollFraud_ImmediateAction_InRecommendation()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 25; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.SIP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.{i}.1",
                DestinationPort = 5060,
                Info = "SIP: INVITE",
                Timestamp = timestamp.AddMinutes(i * 5),
                Length = 500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var tollFraud = anomalies.Find(a => a.Type == "VoIP Toll Fraud");
        Assert.NotNull(tollFraud);
        Assert.Contains("Immediate", tollFraud.Recommendation, StringComparison.OrdinalIgnoreCase);
    }
}
