using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.AnomalyDetectors;
using Xunit;

namespace PCAPAnalyzer.Tests.Services.AnomalyDetectors;

public class DnsTunnelDetectorTests
{
    private readonly DnsTunnelDetector _detector;

    public DnsTunnelDetectorTests()
    {
        _detector = new DnsTunnelDetector();
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
    public void Properties_ReturnsCorrectValues()
    {
        // Assert
        Assert.Equal("DNS Tunnel Detector", _detector.Name);
        Assert.Equal(AnomalyCategory.Security, _detector.Category);
    }

    [Fact]
    public void Detect_HighEntropySubdomains_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Simulate DNS tunnel with base64-like encoded subdomains
        var encodedSubdomains = new[]
        {
            "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo",  // base64-like
            "MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ubw",
            "eHl6MTIzYWJjZGVmZ2hpamtsbW5vcHFycw",
            "cXdlcnR5dWlvcGFzZGZnaGprbHp4Y3Zibm0",
            "YXNkZmdoamtsenhjdmJubXF3ZXJ0eXVpbw",
            "cG9pdXl0cmV3cWFzZGZnaGprbHp4Y3Zibm0",
            "bW5iZXJ0eXVpb3Bhc2RmZ2hqa2x6eGN2Ym4",
            "eHhjdmJubW9pdXl0cmV3cWFzZGZnaGprbA",
            "YXplcnR5dWlvcHFzZGZnaGprbG14d3hjdmI",
            "cXNkZmdoamtsbXd4Y3Zibm5wb2l1eXRyZXc"
        };

        for (int i = 0; i < encodedSubdomains.Length; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} A {encodedSubdomains[i]}.tunnel.evil.com",
                Timestamp = timestamp.AddSeconds(i),
                Length = 100
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var tunnel = anomalies.Find(a => a.Type == "DNS Tunnel Suspected");
        Assert.NotNull(tunnel);
        Assert.True((double)tunnel.Metrics["MaxEntropy"] >= 3.5);
    }

    [Fact]
    public void Detect_HighVolumeQueries_DetectsAnomaly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate 200 queries in 1 minute = 200 qpm (above 100 threshold)
        for (int i = 0; i < 200; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} A query{i}.suspicious.net",
                Timestamp = timestamp.AddSeconds(i * 0.3), // ~60 seconds total
                Length = 80
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var tunnel = anomalies.Find(a => a.Type == "DNS Tunnel Suspected");
        Assert.NotNull(tunnel);
        Assert.True((double)tunnel.Metrics["QueriesPerMinute"] >= 100);
    }

    [Fact]
    public void Detect_BothIndicators_CriticalSeverity()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // High entropy + high volume = Critical
        for (int i = 0; i < 150; i++)
        {
            var encoded = Convert.ToBase64String(BitConverter.GetBytes(i * 12345 + 67890))
                .Replace("=", "")
                .Replace("+", "")
                .Replace("/", "");
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} A {encoded}data{i}.exfil.attacker.com",
                Timestamp = timestamp.AddSeconds(i * 0.4), // ~60 seconds
                Length = 100
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var tunnel = anomalies.Find(a => a.Type == "DNS Tunnel Suspected");
        Assert.NotNull(tunnel);
        Assert.Equal(AnomalySeverity.Critical, tunnel.Severity);
    }

    [Fact]
    public void Detect_WhitelistedDomain_NoFalsePositive()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // High volume to cloudflare (whitelisted)
        for (int i = 0; i < 200; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "1.1.1.1",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} A cdn{i}.cloudflare.com",
                Timestamp = timestamp.AddSeconds(i * 0.3),
                Length = 80
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        // Should not flag cloudflare.com even with high volume
        var cloudflareAnomaly = anomalies.Find(a =>
            a.Metrics.TryGetValue("BaseDomain", out var domain) &&
            domain?.ToString()?.Contains("cloudflare") == true);
        Assert.Null(cloudflareAnomaly);
    }

    [Fact]
    public void Detect_NormalDnsTraffic_NoFalsePositive()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Normal DNS queries
        var normalDomains = new[] { "google.com", "microsoft.com", "github.com", "example.com" };
        for (int i = 0; i < 20; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} A www.{normalDomains[i % 4]}",
                Timestamp = timestamp.AddSeconds(i * 5),
                Length = 60
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.Empty(anomalies);
    }

    [Fact]
    public void Detect_BelowMinQueries_NoDetection()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Only 5 queries (below 10 threshold)
        for (int i = 0; i < 5; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} A YWJjZGVmZ2hpamts{i}.evil.com",
                Timestamp = timestamp.AddSeconds(i),
                Length = 80
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.Empty(anomalies);
    }

    [Fact]
    public void Detect_TxtRecordQueries_HigherSuspicion()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // TXT record queries with encoded data
        for (int i = 0; i < 15; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} TXT YWJjZGVmZ2hpams{i}.data.tunnel.net",
                Timestamp = timestamp.AddSeconds(i),
                Length = 100
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
    }

    [Fact]
    public void AddToWhitelist_ExcludesDomain()
    {
        // Arrange
        var detector = new DnsTunnelDetector();
        detector.AddToWhitelist("internal.corp.com");

        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 200; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "10.0.0.1",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} A data{i}.internal.corp.com",
                Timestamp = timestamp.AddSeconds(i * 0.3),
                Length = 80
            });
        }

        // Act
        var anomalies = detector.Detect(packets);

        // Assert
        var corpAnomaly = anomalies.Find(a =>
            a.Metrics.TryGetValue("BaseDomain", out var domain) &&
            domain?.ToString()?.Contains("corp.com") == true);
        Assert.Null(corpAnomaly);
    }

    [Fact]
    public void Detect_MetricsContainSampleQueries()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 20; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} A YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd{i}.evil.net",
                Timestamp = timestamp.AddSeconds(i),
                Length = 100
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var tunnel = anomalies.Find(a => a.Type == "DNS Tunnel Suspected");
        Assert.NotNull(tunnel);
        Assert.True(tunnel.Metrics.ContainsKey("SampleQueries"));
        var samples = tunnel.Metrics["SampleQueries"] as List<string>;
        Assert.NotNull(samples);
        Assert.True(samples.Count <= 5); // First 5 samples only
    }

    [Fact]
    public void Detect_RecommendationContainsCriticalForDualIndicators()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        for (int i = 0; i < 150; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} A YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd{i % 100}.attacker.com",
                Timestamp = timestamp.AddSeconds(i * 0.4),
                Length = 100
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        var critical = anomalies.Find(a => a.Severity == AnomalySeverity.Critical);
        Assert.NotNull(critical);
        Assert.Contains("CRITICAL", critical.Recommendation);
    }

    [Fact]
    public void Detect_SourceIPTracking_IdentifiesInfectedHost()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // All queries from same source
        for (int i = 0; i < 20; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} A YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd{i}.malware.net",
                Timestamp = timestamp.AddSeconds(i),
                Length = 100
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var tunnel = anomalies.Find(a => a.Type == "DNS Tunnel Suspected");
        Assert.NotNull(tunnel);
        Assert.Equal("192.168.1.100", tunnel.SourceIP);
    }

    [Fact]
    public void Detect_ThresholdsAreConfigurable()
    {
        // Arrange
        var detector = new DnsTunnelDetector
        {
            EntropyThreshold = 4.0,    // Higher threshold
            VolumeThreshold = 200.0,   // Higher threshold
            MinSuspiciousQueries = 5   // Lower threshold
        };

        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // Generate traffic that would trigger default but not custom thresholds
        for (int i = 0; i < 100; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} A sub{i}.test.com",
                Timestamp = timestamp.AddSeconds(i * 0.6), // ~100 qpm
                Length = 60
            });
        }

        // Act
        var anomalies = detector.Detect(packets);

        // Assert
        // Should not trigger with higher thresholds
        Assert.Empty(anomalies);
    }

    [Fact]
    public void Detect_NonDnsTraffic_Ignored()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // HTTP traffic (not DNS)
        for (int i = 0; i < 100; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.TCP,
                SourceIP = "192.168.1.100",
                DestinationIP = "93.184.216.34",
                SourcePort = 54321,
                DestinationPort = 80,
                Info = "GET /index.html HTTP/1.1",
                Timestamp = timestamp.AddSeconds(i),
                Length = 500
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.Empty(anomalies);
    }

    [Fact]
    public void Detect_MultiPartTld_HandledCorrectly()
    {
        // Arrange
        var packets = new List<PacketInfo>();
        var timestamp = DateTime.UtcNow;

        // .co.uk domain
        for (int i = 0; i < 20; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)i,
                Protocol = Protocol.UDP,
                SourceIP = "192.168.1.100",
                DestinationIP = "8.8.8.8",
                SourcePort = 12345,
                DestinationPort = 53,
                Info = $"Standard query 0x{i:X4} A YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd{i}.malicious.co.uk",
                Timestamp = timestamp.AddSeconds(i),
                Length = 100
            });
        }

        // Act
        var anomalies = _detector.Detect(packets);

        // Assert
        Assert.NotEmpty(anomalies);
        var tunnel = anomalies.Find(a => a.Type == "DNS Tunnel Suspected");
        Assert.NotNull(tunnel);
        // Should extract "malicious.co.uk" not "co.uk"
        Assert.Equal("malicious.co.uk", tunnel.Metrics["BaseDomain"]);
    }
}
