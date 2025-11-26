using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.AnomalyDetectors;
using Xunit;

namespace PCAPAnalyzer.Tests.Services.AnomalyDetectors;

public class CryptoMiningDetectorTests
{
    private readonly CryptoMiningDetector _detector;

    public CryptoMiningDetectorTests()
    {
        _detector = new CryptoMiningDetector();
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
    public void CanDetect_WithMiningPortTraffic_ReturnsTrue()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { Protocol = Protocol.TCP, DestinationPort = 3333 } // Stratum port
        };

        // Act
        var result = _detector.CanDetect(packets);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void CanDetect_WithoutMiningTraffic_ReturnsFalse()
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
    public void Detect_MiningPoolConnections_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Connect to 6 different mining pools
        for (int i = 0; i < 6; i++)
        {
            // Generate traffic to each pool
            for (int j = 0; j < 100; j++)
            {
                packets.Add(new PacketInfo
                {
                    FrameNumber = i * 100 + j,
                    Protocol = Protocol.TCP,
                    SourceIP = "192.168.1.100",
                    DestinationIP = $"10.0.{i}.1",
                    DestinationPort = 3333,
                    Info = "Stratum",
                    Timestamp = timestamp.AddSeconds(i * 10 + j * 0.1),
                    Length = 200
                });
            }
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var mining = anomalies.Find(a => a.Type == "Cryptomining");
        Assert.NotNull(mining);
        Assert.True((int)mining.Metrics["MiningPoolConnections"] >= 5);
    }

    [Fact]
    public void Detect_ExcessiveConnections_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Connect to 15 different IPs on mining port
        for (int i = 0; i < 15; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.0.{i + 1}",
                DestinationPort = 4444, // Monero port
                Info = "SYN",
                Timestamp = timestamp.AddSeconds(i),
                Length = 64
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var poolScanning = anomalies.Find(a => a.Type == "Cryptomining Pool Scanning");
        Assert.NotNull(poolScanning);
        Assert.Equal(AnomalySeverity.High, poolScanning.Severity);
        Assert.Equal(15, poolScanning.Metrics["UniqueConnections"]);
    }

    [Fact]
    public void Detect_StratumProtocol_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Stratum protocol messages
        packets.Add(new PacketInfo
        {
            FrameNumber = 1,
            Protocol = Protocol.TCP,
            SourceIP = "192.168.1.100",
            DestinationIP = "pool.example.com",
            DestinationPort = 3333,
            Info = "mining.subscribe",
            Timestamp = timestamp,
            Length = 200
        });

        packets.Add(new PacketInfo
        {
            FrameNumber = 2,
            Protocol = Protocol.TCP,
            SourceIP = "192.168.1.100",
            DestinationIP = "pool.example.com",
            DestinationPort = 3333,
            Info = "mining.authorize worker1 password",
            Timestamp = timestamp.AddSeconds(1),
            Length = 250
        });

        packets.Add(new PacketInfo
        {
            FrameNumber = 3,
            Protocol = Protocol.TCP,
            SourceIP = "192.168.1.100",
            DestinationIP = "pool.example.com",
            DestinationPort = 3333,
            Info = "mining.submit worker1 job1 nonce",
            Timestamp = timestamp.AddSeconds(2),
            Length = 300
        });

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var stratum = anomalies.Find(a => a.Type == "Stratum Mining Protocol");
        Assert.NotNull(stratum);
        Assert.Equal(AnomalySeverity.Critical, stratum.Severity);
        Assert.Equal(1, stratum.Metrics["StratumSubscribes"]);
        Assert.Equal(1, stratum.Metrics["StratumAuthorizes"]);
        Assert.Equal(1, stratum.Metrics["StratumSubmits"]);
    }

    [Fact]
    public void Detect_LargeTrafficToMiningPools_DetectsHighSeverity()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 15MB of traffic to mining pools
        for (int i = 0; i < 10000; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 3333,
                Info = "Stratum",
                Timestamp = timestamp.AddSeconds(i * 0.1),
                Length = 1536 // ~15MB total
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var mining = anomalies.Find(a => a.Type == "Cryptomining");
        Assert.NotNull(mining);
        Assert.Equal(AnomalySeverity.Critical, mining.Severity);
        Assert.True((long)mining.Metrics["TotalBytes"] > 10 * 1024 * 1024);
    }

    [Fact]
    public void Properties_ReturnsCorrectValues()
    {
        // Assert
        Assert.Equal("Cryptocurrency Mining Detector", _detector.Name);
        Assert.Equal(AnomalyCategory.Security, _detector.Category);
        Assert.Equal(6, _detector.Priority);
    }

    [Fact]
    public void Detect_MiningPort8333_Bitcoin_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 60; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.{i % 5}.1",
                DestinationPort = 8333, // Bitcoin port
                Timestamp = timestamp.AddSeconds(i),
                Length = 50000
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        Assert.Contains(anomalies, a => a.Type == "Cryptomining");
    }

    [Fact]
    public void Detect_MiningPort9332_Bitcoin_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 60; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.{i % 5}.1",
                DestinationPort = 9332,
                Timestamp = timestamp.AddSeconds(i),
                Length = 50000
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
    }

    [Fact]
    public void Detect_StratumWithMethodKeyword_DetectsPattern()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new()
            {
                FrameNumber = 1,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                DestinationPort = 3333,
                Info = "JSON-RPC: {\"method\": \"mining.subscribe\"}",
                Timestamp = DateTime.UtcNow,
                Length = 200
            }
        };

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
    }

    [Fact]
    public void Detect_MiningPoolDomainPattern_DetectsTraffic()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new()
            {
                FrameNumber = 1,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "nanopool.org",
                DestinationPort = 443,
                Info = "TLS",
                Timestamp = DateTime.UtcNow,
                Length = 1000
            }
        };

        // Act
        var canDetect = _detector.CanDetect(packets);

        // Assert
        Assert.True(canDetect);
    }

    [Fact]
    public void Detect_MultipleMiningPorts_DetectsAll()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;
        var ports = new[] { 3333, 4444, 5555, 8333, 9332 };

        for (int i = 0; i < 60; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.{i % 5}.1",
                DestinationPort = ports[i % ports.Length],
                Timestamp = timestamp.AddSeconds(i),
                Length = 50000
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var mining = anomalies.Find(a => a.Type == "Cryptomining");
        Assert.NotNull(mining);
    }

    [Fact]
    public void Detect_EvidenceField_ContainsDetectedPorts()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 60; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.{i % 5}.1",
                DestinationPort = 3333,
                Timestamp = timestamp.AddSeconds(i),
                Length = 50000
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var mining = anomalies.Find(a => a.Type == "Cryptomining");
        Assert.NotNull(mining);
        Assert.Contains("DetectedPorts", mining.Evidence.Keys);
    }

    [Fact]
    public void Detect_NormalHTTPTraffic_NoFalsePositive()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 100; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "93.184.216.34",
                DestinationPort = 80,
                Timestamp = timestamp.AddSeconds(i),
                Length = 1500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.Empty(anomalies);
    }

    [Fact]
    public void Detect_LowVolumeToMiningPort_BelowThreshold_NoDetection()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Only 4 connections, below 5 threshold
        for (int i = 0; i < 4; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.{i}.1",
                DestinationPort = 3333,
                Timestamp = timestamp.AddSeconds(i),
                Length = 1000
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.Empty(anomalies);
    }

    [Fact]
    public void Detect_RecommendationField_ContainsMalwareReference()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 60; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.{i % 5}.1",
                DestinationPort = 3333,
                Timestamp = timestamp.AddSeconds(i),
                Length = 50000
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var mining = anomalies.Find(a => a.Type == "Cryptomining");
        Assert.NotNull(mining);
        Assert.Contains("malware", mining.Recommendation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Detect_MiningWithDetectorName_IsCorrect()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 60; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = $"10.0.{i % 5}.1",
                DestinationPort = 3333,
                Timestamp = timestamp.AddSeconds(i),
                Length = 50000
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var mining = anomalies.Find(a => a.Type == "Cryptomining");
        Assert.NotNull(mining);
        Assert.Equal("Cryptocurrency Mining Detector", mining.DetectorName);
    }
}
