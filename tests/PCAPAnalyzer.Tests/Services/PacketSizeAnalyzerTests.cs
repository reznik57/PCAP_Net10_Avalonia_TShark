using System;
using System.Collections.Generic;
using System.Linq;
using FluentAssertions;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using Xunit;

namespace PCAPAnalyzer.Tests.Services;

/// <summary>
/// Comprehensive unit tests for PacketSizeAnalyzer service.
/// Week 1 P1 Feature: Packet Size Distribution Chart
/// </summary>
public class PacketSizeAnalyzerTests
{
    private readonly IPacketSizeAnalyzer _analyzer;

    public PacketSizeAnalyzerTests()
    {
        _analyzer = new PacketSizeAnalyzer();
    }

    #region Basic Distribution Tests

    [Fact]
    public void CalculateDistribution_WithEmptyPackets_ReturnsEmptyDistribution()
    {
        // Arrange
        var packets = Enumerable.Empty<PacketInfo>();

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert
        result.Should().NotBeNull();
        result.TotalPackets.Should().Be(0);
        result.TotalBytes.Should().Be(0);
        result.Buckets.Should().NotBeEmpty("buckets should be initialized with zero counts");
        result.Buckets.Should().HaveCount(8, "standard buckets should have 8 ranges");
        result.Buckets.Should().OnlyContain(b => b.PacketCount == 0);
    }

    [Fact]
    public void CalculateDistribution_WithSinglePacket_CalculatesCorrectly()
    {
        // Arrange
        var packets = new[]
        {
            CreatePacket(1, 100) // Small packet (64-127 range)
        };

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert
        result.TotalPackets.Should().Be(1);
        result.TotalBytes.Should().Be(100);
        result.AveragePacketSize.Should().Be(100);
        result.MedianPacketSize.Should().Be(100);
        result.MinPacketSize.Should().Be(100);
        result.MaxPacketSize.Should().Be(100);
        result.ModePacketSize.Should().Be(100);

        var smallBucket = result.Buckets.First(b => b.MinSize == 64 && b.MaxSize == 127);
        smallBucket.PacketCount.Should().Be(1);
        smallBucket.PacketPercentage.Should().Be(100.0);
    }

    [Fact]
    public void CalculateDistribution_WithMultiplePackets_DistributesCorrectly()
    {
        // Arrange
        var packets = new[]
        {
            CreatePacket(1, 50),    // Tiny (0-63)
            CreatePacket(2, 100),   // Small (64-127)
            CreatePacket(3, 200),   // Medium (128-255)
            CreatePacket(4, 400),   // Medium (256-511)
            CreatePacket(5, 800),   // Standard (512-1023)
            CreatePacket(6, 1200),  // Large (1024-1499)
            CreatePacket(7, 1500)   // Jumbo (1500+)
        };

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert
        result.TotalPackets.Should().Be(7);
        result.TotalBytes.Should().Be(50 + 100 + 200 + 400 + 800 + 1200 + 1500);
        result.Buckets.Should().HaveCount(8);

        // 7 buckets should have exactly 1 packet each, 1 bucket (1515+) has 0
        result.Buckets.Where(b => b.PacketCount == 1).Should().HaveCount(7);
        result.Buckets.Where(b => b.PacketCount == 0).Should().HaveCount(1);
    }

    #endregion

    #region Statistical Calculations Tests

    [Fact]
    public void CalculateDistribution_CalculatesStatisticsCorrectly()
    {
        // Arrange
        var packets = new[]
        {
            CreatePacket(1, 100),
            CreatePacket(2, 200),
            CreatePacket(3, 300),
            CreatePacket(4, 400),
            CreatePacket(5, 500)
        };

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert
        result.AveragePacketSize.Should().Be(300); // (100+200+300+400+500)/5
        result.MedianPacketSize.Should().Be(300); // Middle value
        result.MinPacketSize.Should().Be(100);
        result.MaxPacketSize.Should().Be(500);
        result.Q1PacketSize.Should().Be(200); // 25th percentile
        result.Q3PacketSize.Should().Be(400); // 75th percentile
    }

    [Fact]
    public void CalculateDistribution_CalculatesPercentiles()
    {
        // Arrange: 100 packets from 1 to 100 bytes
        var packets = Enumerable.Range(1, 100)
            .Select(i => CreatePacket(i, (uint)i))
            .ToList();

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert
        result.MedianPacketSize.Should().BeInRange(49, 51); // ~50th percentile
        result.Q1PacketSize.Should().BeInRange(24, 26);     // ~25th percentile
        result.Q3PacketSize.Should().BeInRange(74, 76);     // ~75th percentile
        result.P95PacketSize.Should().BeInRange(94, 96);    // ~95th percentile
        result.P99PacketSize.Should().BeInRange(98, 100);   // ~99th percentile
    }

    [Fact]
    public void CalculateDistribution_CalculatesStandardDeviation()
    {
        // Arrange: Packets with known variance
        var packets = new[]
        {
            CreatePacket(1, 100),
            CreatePacket(2, 100),
            CreatePacket(3, 100),
            CreatePacket(4, 200),
            CreatePacket(5, 200)
        };

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert
        result.StandardDeviation.Should().BeGreaterThan(0);
        result.StandardDeviation.Should().BeLessThan(100); // Should be ~48.99
    }

    [Fact]
    public void CalculateDistribution_CalculatesModeCorrectly()
    {
        // Arrange: 100 is the most common size
        var packets = new[]
        {
            CreatePacket(1, 100),
            CreatePacket(2, 100),
            CreatePacket(3, 100), // 100 appears 3 times
            CreatePacket(4, 200),
            CreatePacket(5, 200), // 200 appears 2 times
            CreatePacket(6, 300)  // 300 appears 1 time
        };

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert
        result.ModePacketSize.Should().Be(100, "100 is the most common packet size");
    }

    #endregion

    #region Bucket Distribution Tests

    [Fact]
    public void CalculateDistribution_TinyPackets_CorrectBucket()
    {
        // Arrange: All tiny packets (0-63 bytes)
        var packets = new[]
        {
            CreatePacket(1, 10),
            CreatePacket(2, 30),
            CreatePacket(3, 60)
        };

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert
        var tinyBucket = result.Buckets.First(b => b.Category == PacketSizeCategory.Tiny);
        tinyBucket.PacketCount.Should().Be(3);
        tinyBucket.PacketPercentage.Should().Be(100.0);
        tinyBucket.Label.Should().Be("0-63");
    }

    [Fact]
    public void CalculateDistribution_SmallPackets_CorrectBucket()
    {
        // Arrange: All small packets (64-127 bytes)
        var packets = new[]
        {
            CreatePacket(1, 64),
            CreatePacket(2, 100),
            CreatePacket(3, 127)
        };

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert
        var smallBucket = result.Buckets.First(b => b.Category == PacketSizeCategory.Small);
        smallBucket.PacketCount.Should().Be(3);
        smallBucket.PacketPercentage.Should().Be(100.0);
    }

    [Fact]
    public void CalculateDistribution_JumboPackets_CorrectBucket()
    {
        // Arrange: Jumbo packets (1500+ bytes)
        // Now split between "1500-1514" and "1515+" buckets
        var packets = new[]
        {
            CreatePacket(1, 1500),  // Goes to 1500-1514 bucket
            CreatePacket(2, 9000),  // Jumbo frame - goes to 1515+ bucket
            CreatePacket(3, 1518)   // Standard Ethernet MTU - goes to 1515+ bucket
        };

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert - both Jumbo buckets together should have 3 packets
        var jumboBuckets = result.Buckets.Where(b => b.Category == PacketSizeCategory.Jumbo).ToList();
        jumboBuckets.Sum(b => b.PacketCount).Should().Be(3);

        // Verify bucket split: 1500-1514 has 1, 1515+ has 2
        result.Buckets.First(b => b.Label == "1500-1514").PacketCount.Should().Be(1);
        result.Buckets.First(b => b.Label == "1515+").PacketCount.Should().Be(2);
        result.Buckets.First(b => b.Label == "1515+").MaxSize.Should().Be(int.MaxValue);
    }

    [Fact]
    public void CalculateDistribution_CalculatesPercentagesCorrectly()
    {
        // Arrange: 10 packets, 3 tiny, 7 small
        var packets = new List<PacketInfo>();
        for (int i = 1; i <= 3; i++)
            packets.Add(CreatePacket(i, 50));  // Tiny
        for (int i = 4; i <= 10; i++)
            packets.Add(CreatePacket(i, 100)); // Small

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert
        var tinyBucket = result.Buckets.First(b => b.Category == PacketSizeCategory.Tiny);
        var smallBucket = result.Buckets.First(b => b.Category == PacketSizeCategory.Small);

        tinyBucket.PacketPercentage.Should().Be(30.0); // 3/10 = 30%
        smallBucket.PacketPercentage.Should().Be(70.0); // 7/10 = 70%
    }

    [Fact]
    public void CalculateDistribution_CalculatesBytePercentagesCorrectly()
    {
        // Arrange: 2 packets, one 100 bytes, one 900 bytes (total 1000)
        var packets = new[]
        {
            CreatePacket(1, 100),  // Small - 10% of bytes
            CreatePacket(2, 900)   // Standard - 90% of bytes
        };

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert
        var smallBucket = result.Buckets.First(b => b.Category == PacketSizeCategory.Small);
        var standardBucket = result.Buckets.First(b => b.Category == PacketSizeCategory.Standard);

        smallBucket.BytePercentage.Should().Be(10.0);
        standardBucket.BytePercentage.Should().Be(90.0);
    }

    #endregion

    #region Detailed Distribution Tests

    [Fact]
    public void CalculateDetailedDistribution_HasMoreBuckets()
    {
        // Arrange
        var packets = new[] { CreatePacket(1, 100) };

        // Act
        var result = _analyzer.CalculateDetailedDistribution(packets);

        // Assert
        result.Buckets.Should().HaveCount(12, "detailed buckets should have 12 ranges");
        result.Buckets.Should().Contain(b => b.Label == "128-191");
        result.Buckets.Should().Contain(b => b.Label == "9001+");
    }

    [Fact]
    public void CalculateDetailedDistribution_DistributesPacketsFinely()
    {
        // Arrange: Packets in detailed ranges
        var packets = new[]
        {
            CreatePacket(1, 150),  // 128-191
            CreatePacket(2, 200),  // 192-255
            CreatePacket(3, 300)   // 256-383
        };

        // Act
        var result = _analyzer.CalculateDetailedDistribution(packets);

        // Assert
        result.Buckets.First(b => b.Label == "128-191").PacketCount.Should().Be(1);
        result.Buckets.First(b => b.Label == "192-255").PacketCount.Should().Be(1);
        result.Buckets.First(b => b.Label == "256-383").PacketCount.Should().Be(1);
    }

    #endregion

    #region Custom Distribution Tests

    [Fact]
    public void CalculateCustomDistribution_WithCustomBuckets_Works()
    {
        // Arrange
        var packets = new[]
        {
            CreatePacket(1, 50),
            CreatePacket(2, 150),
            CreatePacket(3, 250)
        };

        var customBuckets = new List<(int MinSize, int MaxSize, string Label, PacketSizeCategory Category, string Description)>
        {
            (0, 100, "0-100", PacketSizeCategory.Tiny, "Very small"),
            (101, 200, "101-200", PacketSizeCategory.Small, "Small"),
            (201, 300, "201-300", PacketSizeCategory.Medium, "Medium")
        };

        // Act
        var result = _analyzer.CalculateCustomDistribution(packets, customBuckets);

        // Assert
        result.Buckets.Should().HaveCount(3);
        result.Buckets[0].PacketCount.Should().Be(1); // 50
        result.Buckets[1].PacketCount.Should().Be(1); // 150
        result.Buckets[2].PacketCount.Should().Be(1); // 250
    }

    [Fact]
    public void CalculateCustomDistribution_WithOpenEndedBucket_HandlesCorrectly()
    {
        // Arrange
        var packets = new[]
        {
            CreatePacket(1, 5000),
            CreatePacket(2, 10000),
            CreatePacket(3, 65000)
        };

        var customBuckets = new List<(int MinSize, int MaxSize, string Label, PacketSizeCategory Category, string Description)>
        {
            (0, 1000, "0-1000", PacketSizeCategory.Small, "Small"),
            (1001, int.MaxValue, "1000+", PacketSizeCategory.Jumbo, "Large and above")
        };

        // Act
        var result = _analyzer.CalculateCustomDistribution(packets, customBuckets);

        // Assert
        result.Buckets[0].PacketCount.Should().Be(0);
        result.Buckets[1].PacketCount.Should().Be(3); // All packets >= 1001
    }

    #endregion

    #region Bucket Property Tests

    [Fact]
    public void PacketSizeBucket_CalculatesAverageSizeCorrectly()
    {
        // Arrange
        var bucket = new PacketSizeBucket
        {
            PacketCount = 5,
            TotalBytes = 1000
        };

        // Act
        var averageSize = bucket.AverageSize;

        // Assert
        averageSize.Should().Be(200); // 1000/5 = 200
    }

    [Fact]
    public void PacketSizeBucket_WithZeroPackets_AverageSizeIsZero()
    {
        // Arrange
        var bucket = new PacketSizeBucket
        {
            PacketCount = 0,
            TotalBytes = 0
        };

        // Act
        var averageSize = bucket.AverageSize;

        // Assert
        averageSize.Should().Be(0);
    }

    [Fact]
    public void PacketSizeDistribution_MostCommonBucket_ReturnsCorrect()
    {
        // Arrange
        var distribution = new PacketSizeDistribution
        {
            Buckets = new List<PacketSizeBucket>
            {
                new() { Label = "A", PacketCount = 10 },
                new() { Label = "B", PacketCount = 50 }, // Most common
                new() { Label = "C", PacketCount = 20 }
            }
        };

        // Act
        var mostCommon = distribution.MostCommonBucket;

        // Assert
        mostCommon.Should().NotBeNull();
        mostCommon!.Label.Should().Be("B");
        mostCommon.PacketCount.Should().Be(50);
    }

    [Fact]
    public void PacketSizeDistribution_LargestBytesBucket_ReturnsCorrect()
    {
        // Arrange
        var distribution = new PacketSizeDistribution
        {
            Buckets = new List<PacketSizeBucket>
            {
                new() { Label = "A", TotalBytes = 1000 },
                new() { Label = "B", TotalBytes = 500 },
                new() { Label = "C", TotalBytes = 5000 } // Largest bytes
            }
        };

        // Act
        var largestBytes = distribution.LargestBytesBucket;

        // Assert
        largestBytes.Should().NotBeNull();
        largestBytes!.Label.Should().Be("C");
        largestBytes.TotalBytes.Should().Be(5000);
    }

    #endregion

    #region Extension Method Tests

    [Fact]
    public void GetSummary_WithValidDistribution_ReturnsFormattedString()
    {
        // Arrange
        var distribution = new PacketSizeDistribution
        {
            TotalPackets = 1000,
            AveragePacketSize = 512.5,
            MedianPacketSize = 500,
            MinPacketSize = 64,
            MaxPacketSize = 1500
        };

        // Act
        var summary = distribution.GetSummary();

        // Assert
        summary.Should().Contain("1,000");
        summary.Should().Contain("512.5");
        summary.Should().Contain("500");
        summary.Should().Contain("64-1500");
    }

    [Fact]
    public void GetSummary_WithEmptyDistribution_ReturnsNoDataMessage()
    {
        // Arrange
        var distribution = new PacketSizeDistribution
        {
            TotalPackets = 0
        };

        // Act
        var summary = distribution.GetSummary();

        // Assert
        summary.Should().Be("No packets analyzed");
    }

    [Fact]
    public void GetDetailedStats_WithValidDistribution_ReturnsMultilineStats()
    {
        // Arrange
        var distribution = new PacketSizeDistribution
        {
            TotalPackets = 1000,
            TotalBytes = 512000,
            AveragePacketSize = 512,
            MedianPacketSize = 500,
            StandardDeviation = 100,
            MinPacketSize = 64,
            MaxPacketSize = 1500,
            Q1PacketSize = 300,
            Q3PacketSize = 700,
            P95PacketSize = 1400,
            P99PacketSize = 1490,
            ModePacketSize = 1500
        };

        // Act
        var stats = distribution.GetDetailedStats();

        // Assert
        stats.Should().Contain("Total Packets: 1,000");
        stats.Should().Contain("Average Size:");
        stats.Should().Contain("Median Size:");
        stats.Should().Contain("Std Deviation:");
        stats.Should().Contain("Min/Max:");
        stats.Should().Contain("Q1/Q3:");
        stats.Should().Contain("95th/99th:");
        stats.Should().Contain("Mode:");
    }

    [Fact]
    public void GetTopBucketsByPackets_ReturnsTopN()
    {
        // Arrange
        var distribution = new PacketSizeDistribution
        {
            Buckets = new List<PacketSizeBucket>
            {
                new() { Label = "A", PacketCount = 10 },
                new() { Label = "B", PacketCount = 50 },
                new() { Label = "C", PacketCount = 30 },
                new() { Label = "D", PacketCount = 20 },
                new() { Label = "E", PacketCount = 40 }
            }
        };

        // Act
        var top3 = distribution.GetTopBucketsByPackets(3);

        // Assert
        top3.Should().HaveCount(3);
        top3[0].Label.Should().Be("B"); // 50
        top3[1].Label.Should().Be("E"); // 40
        top3[2].Label.Should().Be("C"); // 30
    }

    [Fact]
    public void GetTopBucketsByBytes_ReturnsTopN()
    {
        // Arrange
        var distribution = new PacketSizeDistribution
        {
            Buckets = new List<PacketSizeBucket>
            {
                new() { Label = "A", TotalBytes = 1000 },
                new() { Label = "B", TotalBytes = 5000 },
                new() { Label = "C", TotalBytes = 3000 }
            }
        };

        // Act
        var top2 = distribution.GetTopBucketsByBytes(2);

        // Assert
        top2.Should().HaveCount(2);
        top2[0].Label.Should().Be("B"); // 5000
        top2[1].Label.Should().Be("C"); // 3000
    }

    [Fact]
    public void ClassifyDistribution_WithHighTinyPackets_ReturnsControlHeavy()
    {
        // Arrange
        var distribution = new PacketSizeDistribution
        {
            TotalPackets = 100,
            Buckets = new List<PacketSizeBucket>
            {
                new() { Category = PacketSizeCategory.Tiny, PacketCount = 70, PacketPercentage = 70 },
                new() { Category = PacketSizeCategory.Jumbo, PacketCount = 30, PacketPercentage = 30 }
            }
        };

        // Act
        var classification = distribution.ClassifyDistribution();

        // Assert
        classification.Should().Be("Control-Heavy (High ACK traffic)");
    }

    [Fact]
    public void ClassifyDistribution_WithHighJumboPackets_ReturnsDataHeavy()
    {
        // Arrange
        var distribution = new PacketSizeDistribution
        {
            TotalPackets = 100,
            Buckets = new List<PacketSizeBucket>
            {
                new() { Category = PacketSizeCategory.Tiny, PacketCount = 30, PacketPercentage = 30 },
                new() { Category = PacketSizeCategory.Jumbo, PacketCount = 60, PacketPercentage = 60 }
            }
        };

        // Act
        var classification = distribution.ClassifyDistribution();

        // Assert
        classification.Should().Be("Data-Heavy (Large file transfers)");
    }

    [Fact]
    public void ClassifyDistribution_WithBalancedTraffic_ReturnsTypicalMixed()
    {
        // Arrange
        var distribution = new PacketSizeDistribution
        {
            TotalPackets = 100,
            Buckets = new List<PacketSizeBucket>
            {
                new() { Category = PacketSizeCategory.Tiny, PacketCount = 45, PacketPercentage = 45 },
                new() { Category = PacketSizeCategory.Jumbo, PacketCount = 25, PacketPercentage = 25 }
            }
        };

        // Act
        var classification = distribution.ClassifyDistribution();

        // Assert
        classification.Should().Be("Typical Mixed Traffic");
    }

    #endregion

    #region PacketSizeBucketDefinitions Tests

    [Fact]
    public void StandardBuckets_HasEightBuckets()
    {
        // Act
        var buckets = PacketSizeBucketDefinitions.StandardBuckets;

        // Assert
        buckets.Should().HaveCount(8);
        buckets.Should().Contain(b => b.Label == "0-63");
        buckets.Should().Contain(b => b.Label == "1500-1514");
        buckets.Should().Contain(b => b.Label == "1515+");
    }

    [Fact]
    public void DetailedBuckets_HasTwelveBuckets()
    {
        // Act
        var buckets = PacketSizeBucketDefinitions.DetailedBuckets;

        // Assert
        buckets.Should().HaveCount(12);
        buckets.Should().Contain(b => b.Label == "128-191");
        buckets.Should().Contain(b => b.Label == "9001+");
    }

    [Theory]
    [InlineData(50, PacketSizeCategory.Tiny)]
    [InlineData(100, PacketSizeCategory.Small)]
    [InlineData(300, PacketSizeCategory.Medium)]
    [InlineData(800, PacketSizeCategory.Standard)]
    [InlineData(1200, PacketSizeCategory.Large)]
    [InlineData(1500, PacketSizeCategory.Jumbo)]
    [InlineData(9000, PacketSizeCategory.Jumbo)]
    public void GetCategory_ReturnsCorrectCategory(int size, PacketSizeCategory expectedCategory)
    {
        // Act
        var category = PacketSizeBucketDefinitions.GetCategory(size);

        // Assert
        category.Should().Be(expectedCategory);
    }

    [Fact]
    public void GetCategoryDescription_ReturnsDescriptiveText()
    {
        // Act
        var tinyDesc = PacketSizeBucketDefinitions.GetCategoryDescription(PacketSizeCategory.Tiny);
        var jumboDesc = PacketSizeBucketDefinitions.GetCategoryDescription(PacketSizeCategory.Jumbo);

        // Assert
        tinyDesc.Should().Contain("Control packets");
        tinyDesc.Should().Contain("0-63");
        jumboDesc.Should().Contain("MTU");
        jumboDesc.Should().Contain("1500+");
    }

    #endregion

    #region Boundary Condition Tests

    [Fact]
    public void CalculateDistribution_BoundaryPacketSizes_CorrectBuckets()
    {
        // Arrange: Test boundary values
        var packets = new[]
        {
            CreatePacket(1, 63),   // Max tiny
            CreatePacket(2, 64),   // Min small
            CreatePacket(3, 127),  // Max small
            CreatePacket(4, 128),  // Min medium
            CreatePacket(5, 1499), // Max large
            CreatePacket(6, 1500)  // Min jumbo
        };

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert
        result.Buckets.First(b => b.Label == "0-63").PacketCount.Should().Be(1);
        result.Buckets.First(b => b.Label == "64-127").PacketCount.Should().Be(2); // 64 and 127
        result.Buckets.First(b => b.Label == "128-255").PacketCount.Should().Be(1);
        result.Buckets.First(b => b.Label == "1024-1499").PacketCount.Should().Be(1);
        result.Buckets.First(b => b.Label == "1500-1514").PacketCount.Should().Be(1); // 1500 goes to 1500-1514 bucket
    }

    [Fact]
    public void CalculateDistribution_ExtremelyLargePacket_HandledCorrectly()
    {
        // Arrange: Jumbo frames (all >1514 so they go to 1515+ bucket)
        var packets = new[]
        {
            CreatePacket(1, 65535), // Max IPv4 packet
            CreatePacket(2, 9000)   // Jumbo Ethernet frame
        };

        // Act
        var result = _analyzer.CalculateDistribution(packets);

        // Assert - both packets go to "1515+" bucket (both are >1514)
        var jumboFramesBucket = result.Buckets.First(b => b.Label == "1515+");
        jumboFramesBucket.PacketCount.Should().Be(2);
        jumboFramesBucket.TotalBytes.Should().Be(65535 + 9000);
    }

    #endregion

    #region Real-World Scenario Tests

    [Fact]
    public void CalculateDistribution_TypicalWebTraffic_ClassifiedCorrectly()
    {
        // Arrange: Simulate typical HTTP traffic
        var packets = new List<PacketInfo>();

        // TCP ACKs (tiny) - 40%
        for (int i = 0; i < 40; i++)
            packets.Add(CreatePacket(i, 52)); // TCP ACK size

        // HTTP responses (jumbo) - 30%
        for (int i = 40; i < 70; i++)
            packets.Add(CreatePacket(i, 1460)); // MTU - headers

        // Mixed small/medium - 30%
        for (int i = 70; i < 100; i++)
            packets.Add(CreatePacket(i, 200));

        // Act
        var result = _analyzer.CalculateDistribution(packets);
        var classification = result.ClassifyDistribution();

        // Assert
        classification.Should().NotBeNullOrEmpty();
        classification.Should().BeOneOf("Typical Mixed Traffic", "Varied Distribution", "Control-Heavy (High ACK traffic)");
        var tinyBucket = result.Buckets.First(b => b.Category == PacketSizeCategory.Tiny);
        tinyBucket.PacketPercentage.Should().Be(40.0);
    }

    #endregion

    #region Helper Methods

    private static PacketInfo CreatePacket(int number, uint length)
    {
        return new PacketInfo
        {
            FrameNumber = (uint)number,
            Length = (ushort)Math.Min(length, ushort.MaxValue),
            Timestamp = DateTime.Now,
            SourceIP = "192.168.1.1",
            DestinationIP = "192.168.1.2",
            SourcePort = 80,
            DestinationPort = 443,
            Protocol = Protocol.TCP
        };
    }

    #endregion
}
