using System;
using System.Linq;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Running;
using PCAPAnalyzer.Core.Models.Capture;
using PCAPAnalyzer.UI.ViewModels.Capture;

namespace PCAPAnalyzer.PerformanceTests;

/// <summary>
/// Performance benchmarks for UI packet batching optimizations
/// Validates Phase 2B performance targets for 50K packets/sec throughput
///
/// Run with: dotnet run -c Release --project tests/PCAPAnalyzer.PerformanceTests
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput, warmupCount: 3, iterationCount: 5)]
[MinColumn, MaxColumn, MeanColumn, MedianColumn]
public class UIPacketBatchingBenchmarks
{
    private PacketListViewModel? _viewModel;
    private LivePacketData[]? _packets;

    [Params(1000, 10000, 50000)]
    public int PacketCount { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _viewModel = new PacketListViewModel();
        _packets = GeneratePackets(PacketCount);
    }

    [Benchmark(Description = "Batched packet additions with 50-packet buffer")]
    public async Task AddPackets_WithBatching()
    {
        // Reset for each iteration
        _viewModel!.Clear();
        await Task.Delay(50); // Allow clear to complete

        // Add packets (batching happens automatically)
        foreach (var packet in _packets!)
        {
            _viewModel.AddPacket(packet);
        }

        // Wait for final flush (100ms timer + safety margin)
        await Task.Delay(200);
    }

    [Benchmark(Description = "Packet additions under concurrent load")]
    public async Task AddPackets_ConcurrentLoad()
    {
        _viewModel!.Clear();
        await Task.Delay(50);

        // Simulate concurrent packet capture from multiple threads
        var tasks = Enumerable.Range(0, 4).Select(async threadId =>
        {
            var startIdx = threadId * (PacketCount / 4);
            var endIdx = startIdx + (PacketCount / 4);

            for (int i = startIdx; i < endIdx; i++)
            {
                _viewModel.AddPacket(_packets![i]);
            }
        });

        await Task.WhenAll(tasks);
        await Task.Delay(200);
    }

    [Benchmark(Description = "Sustained high-rate packet stream (simulates 50K pps)")]
    public async Task HighRatePacketStream()
    {
        _viewModel!.Clear();
        await Task.Delay(50);

        // Simulate 50K pps for 1 second by adding packets in bursts
        var batchSize = PacketCount / 10; // 10 bursts
        var delayBetweenBursts = 100; // ms

        for (int burst = 0; burst < 10; burst++)
        {
            for (int i = 0; i < batchSize && (burst * batchSize + i) < PacketCount; i++)
            {
                _viewModel.AddPacket(_packets![burst * batchSize + i]);
            }
            await Task.Delay(delayBetweenBursts);
        }
    }

    [Benchmark(Description = "Memory efficiency test - max packet limit")]
    public async Task MaxPacketLimit_MemoryManagement()
    {
        _viewModel!.Clear();
        await Task.Delay(50);

        // Add more than max limit (10K) to test FIFO behavior
        var extendedPackets = GeneratePackets(15_000);

        foreach (var packet in extendedPackets)
        {
            _viewModel.AddPacket(packet);
        }

        await Task.Delay(300);
    }

    [Benchmark(Description = "Batch flush overhead measurement")]
    public async Task BatchFlush_Overhead()
    {
        _viewModel!.Clear();
        await Task.Delay(50);

        // Add exactly batch size (50) to trigger immediate flush
        var batchPackets = GeneratePackets(50);

        foreach (var packet in batchPackets)
        {
            _viewModel.AddPacket(packet);
        }

        await Task.Delay(100); // Wait for flush
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _viewModel?.Dispose();
    }

    #region Helper Methods

    private static LivePacketData[] GeneratePackets(int count)
    {
        var packets = new LivePacketData[count];
        for (int i = 0; i < count; i++)
        {
            packets[i] = new LivePacketData
            {
                SequenceNumber = i,
                Timestamp = DateTime.UtcNow,
                SourceIp = $"192.168.{i / 256 % 256}.{i % 256}",
                DestinationIp = $"10.0.{i / 256 % 256}.{i % 256}",
                Protocol = i % 3 switch
                {
                    0 => "TCP",
                    1 => "UDP",
                    _ => "ICMP"
                },
                Length = 64 + (i % 1436), // Vary packet sizes
                CapturedLength = 64 + (i % 1436),
                SourcePort = 1024 + (i % 64511),
                DestinationPort = 1 + (i % 1023),
                ProtocolInfo = $"Seq={i} Ack={i + 1}",
                RawData = new byte[64 + (i % 100)], // Small payload for testing
                InterfaceId = "eth0"
            };
        }
        return packets;
    }

    #endregion
}

/// <summary>
/// Program entry point for running benchmarks
/// </summary>
public class Program
{
    public static void Main(string[] args)
    {
        var summary = BenchmarkRunner.Run<UIPacketBatchingBenchmarks>();

        Console.WriteLine("\n=== Benchmark Summary ===");
        Console.WriteLine("Performance targets:");
        Console.WriteLine("  - 50K packets/sec throughput: PASS if mean < 20ms per 1K packets");
        Console.WriteLine("  - Memory < 100MB for 10K packets: Check 'Allocated' column");
        Console.WriteLine("  - Batch flush latency < 5ms: Check 'BatchFlush_Overhead' result");
        Console.WriteLine("\nDetailed results saved to BenchmarkDotNet.Artifacts/");
    }
}
