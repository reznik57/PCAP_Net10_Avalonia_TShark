using FluentAssertions;
using FluentAssertions.Execution;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Tests.Helpers;

/// <summary>
/// Custom assertion extensions for domain-specific objects.
/// Makes tests more readable and provides better error messages.
/// </summary>
public static class AssertionExtensions
{
    /// <summary>
    /// Asserts that a packet collection has the expected characteristics.
    /// </summary>
    public static void ShouldBeValidPacketCollection(
        this IEnumerable<PacketInfo> packets,
        int? expectedCount = null,
        Protocol? expectedProtocol = null)
    {
        using var _ = new AssertionScope();

        packets.Should().NotBeNull();
        packets.Should().AllSatisfy(p =>
        {
            p.FrameNumber.Should().BeGreaterThan(0u);
            p.Timestamp.Should().BeBefore(DateTime.Now.AddSeconds(1));
            p.SourceIP.Should().NotBeNullOrWhiteSpace();
            p.DestinationIP.Should().NotBeNullOrWhiteSpace();
        });

        if (expectedCount.HasValue)
        {
            packets.Should().HaveCount(expectedCount.Value);
        }

        if (expectedProtocol.HasValue)
        {
            packets.Should().AllSatisfy(p => p.Protocol.Should().Be(expectedProtocol.Value));
        }
    }

    /// <summary>
    /// Asserts that network statistics are valid and reasonable.
    /// </summary>
    public static void ShouldBeValidStatistics(this NetworkStatistics stats)
    {
        using var _ = new AssertionScope();

        stats.Should().NotBeNull();
        stats.TotalPackets.Should().BeGreaterThan(0);
        stats.TotalBytes.Should().BeGreaterThan(0);
        stats.LastPacketTime.Should().BeAfter(stats.FirstPacketTime);
        stats.ProtocolStats.Should().NotBeEmpty();
    }

    /// <summary>
    /// Asserts that an operation completed within a specified time.
    /// </summary>
    public static async Task ShouldCompleteWithinAsync(
        this Task task,
        TimeSpan maxDuration,
        string because = "")
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        await task;
        sw.Stop();

        sw.Elapsed.Should().BeLessThan(maxDuration, because);
    }

    /// <summary>
    /// Asserts that memory usage is within acceptable limits.
    /// </summary>
    public static void ShouldUseReasonableMemory(
        this Action action,
        long maxBytesAllocated)
    {
        var before = GC.GetTotalMemory(true);
        action();
        GC.Collect();
        GC.WaitForPendingFinalizers();
        var after = GC.GetTotalMemory(true);

        var allocated = after - before;
        allocated.Should().BeLessThan(maxBytesAllocated,
            $"because we expect less than {maxBytesAllocated / 1024 / 1024}MB allocation");
    }
}
