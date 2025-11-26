using System;
using System.Collections.Generic;
using System.Linq;

namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// Represents the distribution of packet sizes across predefined buckets.
/// Used for histogram visualization and packet size analysis.
/// </summary>
public class PacketSizeDistribution
{
    /// <summary>
    /// Distribution buckets for packet sizes.
    /// Each bucket represents a range of packet sizes.
    /// </summary>
    public List<PacketSizeBucket> Buckets { get; set; } = new();

    /// <summary>
    /// Total number of packets analyzed.
    /// </summary>
    public long TotalPackets { get; set; }

    /// <summary>
    /// Total bytes across all packets.
    /// </summary>
    public long TotalBytes { get; set; }

    /// <summary>
    /// Average packet size in bytes.
    /// </summary>
    public double AveragePacketSize { get; set; }

    /// <summary>
    /// Median packet size in bytes.
    /// </summary>
    public int MedianPacketSize { get; set; }

    /// <summary>
    /// Minimum packet size in bytes.
    /// </summary>
    public int MinPacketSize { get; set; }

    /// <summary>
    /// Maximum packet size in bytes.
    /// </summary>
    public int MaxPacketSize { get; set; }

    /// <summary>
    /// Standard deviation of packet sizes.
    /// </summary>
    public double StandardDeviation { get; set; }

    /// <summary>
    /// Most common packet size (mode).
    /// </summary>
    public int ModePacketSize { get; set; }

    /// <summary>
    /// 25th percentile (Q1) packet size.
    /// </summary>
    public int Q1PacketSize { get; set; }

    /// <summary>
    /// 75th percentile (Q3) packet size.
    /// </summary>
    public int Q3PacketSize { get; set; }

    /// <summary>
    /// 95th percentile packet size.
    /// </summary>
    public int P95PacketSize { get; set; }

    /// <summary>
    /// 99th percentile packet size.
    /// </summary>
    public int P99PacketSize { get; set; }

    /// <summary>
    /// Gets the bucket with the highest packet count.
    /// </summary>
    public PacketSizeBucket? MostCommonBucket => Buckets?.OrderByDescending(b => b.PacketCount).FirstOrDefault();

    /// <summary>
    /// Gets the bucket with the highest byte count.
    /// </summary>
    public PacketSizeBucket? LargestBytesBucket => Buckets?.OrderByDescending(b => b.TotalBytes).FirstOrDefault();
}

/// <summary>
/// Represents a bucket/bin in the packet size histogram.
/// Each bucket covers a range of packet sizes.
/// </summary>
public class PacketSizeBucket
{
    /// <summary>
    /// Minimum packet size for this bucket (inclusive).
    /// </summary>
    public int MinSize { get; set; }

    /// <summary>
    /// Maximum packet size for this bucket (inclusive).
    /// </summary>
    public int MaxSize { get; set; }

    /// <summary>
    /// Number of packets in this bucket.
    /// </summary>
    public long PacketCount { get; set; }

    /// <summary>
    /// Total bytes from all packets in this bucket.
    /// </summary>
    public long TotalBytes { get; set; }

    /// <summary>
    /// Percentage of total packets in this bucket.
    /// </summary>
    public double PacketPercentage { get; set; }

    /// <summary>
    /// Percentage of total bytes in this bucket.
    /// </summary>
    public double BytePercentage { get; set; }

    /// <summary>
    /// Label for this bucket (e.g., "0-63", "64-127", "1500+").
    /// </summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>
    /// Category/classification for this bucket size.
    /// </summary>
    public PacketSizeCategory Category { get; set; }

    /// <summary>
    /// Description of what this packet size range typically represents.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Average packet size within this bucket.
    /// </summary>
    public double AverageSize => PacketCount > 0 ? (double)TotalBytes / PacketCount : 0;
}

/// <summary>
/// Categories for packet sizes based on typical network behavior.
/// </summary>
public enum PacketSizeCategory
{
    /// <summary>
    /// Tiny packets (0-63 bytes) - ACKs, control packets
    /// </summary>
    Tiny,

    /// <summary>
    /// Small packets (64-127 bytes) - Small data transfers, DNS queries
    /// </summary>
    Small,

    /// <summary>
    /// Medium packets (128-511 bytes) - Typical application data
    /// </summary>
    Medium,

    /// <summary>
    /// Standard packets (512-1023 bytes) - Moderate data transfers
    /// </summary>
    Standard,

    /// <summary>
    /// Large packets (1024-1499 bytes) - Near-MTU transfers
    /// </summary>
    Large,

    /// <summary>
    /// Jumbo packets (1500+ bytes) - Full MTU or larger
    /// </summary>
    Jumbo
}

/// <summary>
/// Provides standard packet size bucket definitions for analysis.
/// </summary>
public static class PacketSizeBucketDefinitions
{
    /// <summary>
    /// Standard packet size buckets based on common network patterns.
    /// </summary>
    public static readonly List<(int MinSize, int MaxSize, string Label, PacketSizeCategory Category, string Description)> StandardBuckets = new()
    {
        (0, 63, "0-63", PacketSizeCategory.Tiny, "TCP ACKs, control packets"),
        (64, 127, "64-127", PacketSizeCategory.Small, "Small data, DNS queries"),
        (128, 255, "128-255", PacketSizeCategory.Medium, "HTTP headers, small responses"),
        (256, 511, "256-511", PacketSizeCategory.Medium, "Typical application data"),
        (512, 1023, "512-1023", PacketSizeCategory.Standard, "Moderate data transfers"),
        (1024, 1499, "1024-1499", PacketSizeCategory.Large, "Near-MTU transfers"),
        (1500, 1514, "1500-1514", PacketSizeCategory.Jumbo, "Standard Ethernet MTU packets"),
        (1515, int.MaxValue, "1515+", PacketSizeCategory.Jumbo, "Jumbo frames")
    };

    /// <summary>
    /// Detailed packet size buckets for granular analysis.
    /// </summary>
    public static readonly List<(int MinSize, int MaxSize, string Label, PacketSizeCategory Category, string Description)> DetailedBuckets = new()
    {
        (0, 63, "0-63", PacketSizeCategory.Tiny, "TCP ACKs, control packets"),
        (64, 127, "64-127", PacketSizeCategory.Small, "Small data, DNS queries"),
        (128, 191, "128-191", PacketSizeCategory.Medium, "HTTP headers"),
        (192, 255, "192-255", PacketSizeCategory.Medium, "Small HTTP responses"),
        (256, 383, "256-383", PacketSizeCategory.Medium, "Typical app data"),
        (384, 511, "384-511", PacketSizeCategory.Medium, "Medium transfers"),
        (512, 767, "512-767", PacketSizeCategory.Standard, "Standard data"),
        (768, 1023, "768-1023", PacketSizeCategory.Standard, "Moderate transfers"),
        (1024, 1279, "1024-1279", PacketSizeCategory.Large, "Large transfers"),
        (1280, 1499, "1280-1499", PacketSizeCategory.Large, "Near-MTU"),
        (1500, 9000, "1500-9000", PacketSizeCategory.Jumbo, "MTU packets"),
        (9001, int.MaxValue, "9001+", PacketSizeCategory.Jumbo, "Jumbo frames")
    };

    /// <summary>
    /// Gets the category for a given packet size.
    /// </summary>
    public static PacketSizeCategory GetCategory(int packetSize)
    {
        return packetSize switch
        {
            <= 63 => PacketSizeCategory.Tiny,
            <= 127 => PacketSizeCategory.Small,
            <= 511 => PacketSizeCategory.Medium,
            <= 1023 => PacketSizeCategory.Standard,
            <= 1499 => PacketSizeCategory.Large,
            _ => PacketSizeCategory.Jumbo
        };
    }

    /// <summary>
    /// Gets a human-readable description for a packet size category.
    /// </summary>
    public static string GetCategoryDescription(PacketSizeCategory category)
    {
        return category switch
        {
            PacketSizeCategory.Tiny => "Control packets and ACKs (0-63 bytes)",
            PacketSizeCategory.Small => "Small data transfers (64-127 bytes)",
            PacketSizeCategory.Medium => "Medium application data (128-511 bytes)",
            PacketSizeCategory.Standard => "Standard data transfers (512-1023 bytes)",
            PacketSizeCategory.Large => "Large near-MTU transfers (1024-1499 bytes)",
            PacketSizeCategory.Jumbo => "Full MTU and jumbo frames (1500+ bytes)",
            _ => "Unknown"
        };
    }
}
