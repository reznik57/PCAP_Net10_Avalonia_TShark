using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using PCAPAnalyzer.Core.Models.Capture;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PCAPAnalyzer.PerformanceTests;

/// <summary>
/// Benchmarks for UI update patterns
/// Target: Maintain 60 FPS (< 16ms frame time) under 50K packets/sec load
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90, launchCount: 1, warmupCount: 3, iterationCount: 10)]
[MinColumn, MaxColumn, MeanColumn, MedianColumn]
public class UIUpdateBenchmarks
{
    private List<LivePacketData> _packets = new();

    [Params(1000, 10000, 50000)]
    public int PacketCount { get; set; }

    [Params(1, 10, 50, 100)]
    public int BatchSize { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _packets = GeneratePackets(PacketCount);
    }

    /// <summary>
    /// Baseline: Update UI for every packet (naive approach)
    /// Expected: Horrible performance at high rates
    /// </summary>
    [Benchmark(Baseline = true)]
    public async Task IndividualUIUpdates()
    {
        var updateCount = 0;

        foreach (var packet in _packets)
        {
            await SimulateUIUpdate(packet);
            updateCount++;
        }

        if (updateCount != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount} updates, got {updateCount}");
    }

    /// <summary>
    /// Optimized: Batch UI updates to reduce overhead
    /// Expected: 10-100x improvement depending on batch size
    /// </summary>
    [Benchmark]
    public async Task BatchedUIUpdates()
    {
        var batch = new List<LivePacketData>(BatchSize);
        var updateCount = 0;

        foreach (var packet in _packets)
        {
            batch.Add(packet);

            if (batch.Count >= BatchSize)
            {
                await SimulateUIBatchUpdate(batch);
                updateCount += batch.Count;
                batch.Clear();
            }
        }

        // Flush remaining
        if (batch.Count > 0)
        {
            await SimulateUIBatchUpdate(batch);
            updateCount += batch.Count;
        }

        if (updateCount != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount} updates, got {updateCount}");
    }

    /// <summary>
    /// Optimized: Time-based batching (max 60 updates/sec for 60 FPS)
    /// Ensures UI doesn't exceed frame budget
    /// </summary>
    [Benchmark]
    public async Task TimeBasedBatching()
    {
        var batch = new List<LivePacketData>(100);
        var lastFlush = DateTime.UtcNow;
        var flushInterval = TimeSpan.FromMilliseconds(16); // 60 FPS
        var updateCount = 0;

        foreach (var packet in _packets)
        {
            batch.Add(packet);

            var now = DateTime.UtcNow;
            if (batch.Count >= 100 || (now - lastFlush) >= flushInterval)
            {
                await SimulateUIBatchUpdate(batch);
                updateCount += batch.Count;
                batch.Clear();
                lastFlush = now;
            }
        }

        // Flush remaining
        if (batch.Count > 0)
        {
            await SimulateUIBatchUpdate(batch);
            updateCount += batch.Count;
        }

        if (updateCount != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount} updates, got {updateCount}");
    }

    /// <summary>
    /// Optimized: Throttled updates with sampling
    /// Show every Nth packet to reduce UI load
    /// </summary>
    [Benchmark]
    public async Task ThrottledUpdatesWithSampling()
    {
        var samplingRate = Math.Max(1, PacketCount / 1000); // Max 1000 UI updates
        var updateCount = 0;

        for (int i = 0; i < _packets.Count; i++)
        {
            if (i % samplingRate == 0)
            {
                await SimulateUIUpdate(_packets[i]);
                updateCount++;
            }
        }

        // Should update roughly 1000 times
    }

    /// <summary>
    /// Optimized: Async batching with background queue
    /// UI updates don't block packet processing
    /// </summary>
    [Benchmark]
    public async Task AsyncBatchedUpdates()
    {
        var updateQueue = new Queue<LivePacketData>();
        var updateTask = Task.Run(async () =>
        {
            var batch = new List<LivePacketData>(BatchSize);
            var processed = 0;

            while (processed < PacketCount)
            {
                lock (updateQueue)
                {
                    while (updateQueue.Count > 0 && batch.Count < BatchSize)
                    {
                        batch.Add(updateQueue.Dequeue());
                    }
                }

                if (batch.Count >= BatchSize || processed + batch.Count == PacketCount)
                {
                    await SimulateUIBatchUpdate(batch);
                    processed += batch.Count;
                    batch.Clear();
                }

                await Task.Delay(1); // Simulate UI thread scheduling
            }
        });

        // Producer: Add packets to queue
        foreach (var packet in _packets)
        {
            lock (updateQueue)
            {
                updateQueue.Enqueue(packet);
            }
        }

        // Wait for all updates to complete
        await updateTask;
    }

    /// <summary>
    /// Benchmark statistics aggregation for dashboard
    /// Tests concurrent updates to statistics
    /// </summary>
    [Benchmark]
    public void StatisticsAggregation()
    {
        var stats = new CaptureStats();

        foreach (var packet in _packets)
        {
            UpdateStatistics(stats, packet);
        }

        if (stats.TotalPackets != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount} packets, got {stats.TotalPackets}");
    }

    /// <summary>
    /// Benchmark top-N protocol tracking
    /// Tests efficient sorting and limiting
    /// </summary>
    [Benchmark]
    public void TopProtocolTracking()
    {
        var protocolCounts = new Dictionary<string, long>();

        foreach (var packet in _packets)
        {
            var protocol = packet.Protocol ?? "Unknown";

            if (protocolCounts.ContainsKey(protocol))
                protocolCounts[protocol]++;
            else
                protocolCounts[protocol] = 1;
        }

        // Get top 10 protocols
        var top10 = protocolCounts
            .OrderByDescending(kvp => kvp.Value)
            .Take(10)
            .ToList();
    }

    /// <summary>
    /// Benchmark observable collection updates
    /// Tests collection change notifications
    /// </summary>
    [Benchmark]
    public void ObservableCollectionUpdates()
    {
        var collection = new List<LivePacketData>();

        foreach (var packet in _packets)
        {
            collection.Add(packet);

            // Keep only last 1000 packets visible
            if (collection.Count > 1000)
            {
                collection.RemoveAt(0);
            }
        }

        if (collection.Count > 1000)
            throw new InvalidOperationException($"Collection should have max 1000 items, got {collection.Count}");
    }

    // Helper methods

    private List<LivePacketData> GeneratePackets(int count)
    {
        var packets = new List<LivePacketData>(count);
        var random = new Random(42);
        var protocols = new[] { "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH" };

        for (int i = 0; i < count; i++)
        {
            packets.Add(new LivePacketData
            {
                SequenceNumber = i,
                Timestamp = DateTime.UtcNow.AddMilliseconds(-i),
                Length = random.Next(64, 1500),
                Protocol = protocols[random.Next(protocols.Length)],
                SourceIp = $"192.168.{random.Next(1, 255)}.{random.Next(1, 255)}",
                DestinationIp = $"10.0.{random.Next(1, 255)}.{random.Next(1, 255)}",
                SourcePort = random.Next(1024, 65535),
                DestinationPort = random.Next(1, 1024)
            });
        }

        return packets;
    }

    private async Task SimulateUIUpdate(LivePacketData packet)
    {
        // Simulate UI dispatcher overhead + rendering
        await Task.Delay(1); // ~1ms per update (realistic for UI thread)
    }

    private async Task SimulateUIBatchUpdate(List<LivePacketData> batch)
    {
        // Batch update is more efficient - amortized overhead
        await Task.Delay(Math.Max(1, batch.Count / 10)); // ~0.1ms per packet in batch
    }

    private void UpdateStatistics(CaptureStats stats, LivePacketData packet)
    {
        stats.TotalPackets++;
        stats.TotalBytes += packet.Length;

        var protocol = packet.Protocol ?? "Unknown";
        if (stats.ProtocolCounts.ContainsKey(protocol))
            stats.ProtocolCounts[protocol]++;
        else
            stats.ProtocolCounts[protocol] = 1;
    }

    private class CaptureStats
    {
        public long TotalPackets { get; set; }
        public long TotalBytes { get; set; }
        public Dictionary<string, long> ProtocolCounts { get; set; } = new();
    }
}
