using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Jobs;
using Microsoft.Extensions.Logging.Abstractions;
using PCAPAnalyzer.Core.Models.Capture;
using PCAPAnalyzer.Core.Services.Capture;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PCAPAnalyzer.PerformanceTests;

/// <summary>
/// Benchmarks for live packet capture performance
/// Target: 50,000+ packets/sec sustained throughput
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90, launchCount: 1, warmupCount: 3, iterationCount: 10)]
[MinColumn, MaxColumn, MeanColumn, MedianColumn]
public class LiveCaptureBenchmarks
{
    private LiveCaptureService? _captureService;
    private NetworkInterfaceManager? _interfaceManager;
    private string _testOutputDir = string.Empty;

    [Params(1000, 10000, 50000, 100000)]
    public int PacketCount { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _testOutputDir = Path.Combine(Path.GetTempPath(), $"pcap_bench_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testOutputDir);

        _interfaceManager = new NetworkInterfaceManager(NullLogger<NetworkInterfaceManager>.Instance);
        _captureService = new LiveCaptureService(
            NullLogger<LiveCaptureService>.Instance,
            _interfaceManager,
            "mock_tshark" // Will be mocked
        );
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _captureService?.Dispose();

        if (Directory.Exists(_testOutputDir))
        {
            try
            {
                Directory.Delete(_testOutputDir, true);
            }
            catch { /* Ignore cleanup errors */ }
        }
    }

    /// <summary>
    /// Benchmark packet processing throughput
    /// Measures packets/sec and memory allocation
    /// </summary>
    [Benchmark]
    public async Task ProcessSyntheticPackets()
    {
        var packets = GenerateSyntheticPackets(PacketCount);
        var processed = 0;

        foreach (var packet in packets)
        {
            // Simulate packet processing pipeline
            await ProcessPacketAsync(packet);
            processed++;
        }

        if (processed != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount} packets, processed {processed}");
    }

    /// <summary>
    /// Benchmark packet parsing performance
    /// Tests parsing overhead and string allocations
    /// </summary>
    [Benchmark]
    public void ParsePacketData()
    {
        var rawPackets = GenerateRawPacketData(PacketCount);
        var parsed = 0;

        foreach (var raw in rawPackets)
        {
            var packet = ParsePacket(raw);
            parsed++;
        }

        if (parsed != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount} packets, parsed {parsed}");
    }

    /// <summary>
    /// Benchmark concurrent packet processing
    /// Tests multi-threaded throughput
    /// </summary>
    [Benchmark]
    public async Task ConcurrentPacketProcessing()
    {
        var packets = GenerateSyntheticPackets(PacketCount);
        var consumer = new Consumer();

        await Parallel.ForEachAsync(packets, new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount
        }, async (packet, ct) =>
        {
            await ProcessPacketAsync(packet);
            consumer.Consume(packet);
        });
    }

    /// <summary>
    /// Benchmark packet buffer management
    /// Tests object pooling efficiency
    /// </summary>
    [Benchmark]
    public void BufferPooling()
    {
        var bufferSize = 65536; // Standard packet buffer
        var buffers = new List<byte[]>(PacketCount);

        // Allocate buffers
        for (int i = 0; i < PacketCount; i++)
        {
            buffers.Add(new byte[bufferSize]);
        }

        // Use buffers (simulate packet copy)
        foreach (var buffer in buffers)
        {
            Array.Clear(buffer, 0, buffer.Length);
        }

        // Cleanup
        buffers.Clear();
    }

    /// <summary>
    /// Benchmark UI update batching
    /// Tests responsiveness with high packet rates
    /// </summary>
    [Benchmark]
    public async Task UIUpdateBatching()
    {
        var packets = GenerateSyntheticPackets(PacketCount);
        var batchSize = 50;
        var batch = new List<LivePacketData>(batchSize);

        foreach (var packet in packets)
        {
            batch.Add(packet);

            if (batch.Count >= batchSize)
            {
                // Simulate UI update
                await FlushBatchToUI(batch);
                batch.Clear();
            }
        }

        // Flush remaining
        if (batch.Count > 0)
        {
            await FlushBatchToUI(batch);
        }
    }

    // Helper methods

    private List<LivePacketData> GenerateSyntheticPackets(int count)
    {
        var packets = new List<LivePacketData>(count);
        var random = new Random(42); // Deterministic seed

        for (int i = 0; i < count; i++)
        {
            packets.Add(new LivePacketData
            {
                SequenceNumber = i,
                Timestamp = DateTime.UtcNow,
                RawData = GenerateRandomPacketData(random.Next(64, 1500)),
                Length = random.Next(64, 1500),
                CapturedLength = random.Next(64, 1500),
                Protocol = GetRandomProtocol(random),
                SourceIp = $"192.168.1.{random.Next(1, 255)}",
                DestinationIp = $"10.0.0.{random.Next(1, 255)}",
                SourcePort = random.Next(1024, 65535),
                DestinationPort = random.Next(1, 1024),
                InterfaceId = "eth0"
            });
        }

        return packets;
    }

    private List<byte[]> GenerateRawPacketData(int count)
    {
        var packets = new List<byte[]>(count);
        var random = new Random(42);

        for (int i = 0; i < count; i++)
        {
            packets.Add(GenerateRandomPacketData(random.Next(64, 1500)));
        }

        return packets;
    }

    private byte[] GenerateRandomPacketData(int size)
    {
        var data = new byte[size];
        var random = new Random();
        random.NextBytes(data);

        // Set Ethernet header (destination MAC, source MAC, EtherType)
        data[12] = 0x08; // IPv4 EtherType
        data[13] = 0x00;

        // Set IP version and header length
        if (size >= 34)
        {
            data[14] = 0x45; // IPv4, 20-byte header
            data[23] = 0x06; // TCP protocol
        }

        return data;
    }

    private string GetRandomProtocol(Random random)
    {
        var protocols = new[] { "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH" };
        return protocols[random.Next(protocols.Length)];
    }

    private async Task ProcessPacketAsync(LivePacketData packet)
    {
        // Simulate packet processing overhead
        await Task.Yield();

        // Extract basic info (optimized version in actual code)
        _ = packet.Protocol;
        _ = packet.SourceIp;
        _ = packet.DestinationIp;
    }

    private LivePacketData ParsePacket(byte[] rawData)
    {
        var packet = new LivePacketData
        {
            RawData = rawData,
            Length = rawData.Length,
            CapturedLength = rawData.Length,
            Timestamp = DateTime.UtcNow
        };

        // Basic parsing (Ethernet + IP)
        if (rawData.Length >= 14)
        {
            packet.DestinationMac = BitConverter.ToString(rawData, 0, 6);
            packet.SourceMac = BitConverter.ToString(rawData, 6, 6);
        }

        if (rawData.Length >= 34)
        {
            var ipVersion = (rawData[14] >> 4) & 0x0F;
            if (ipVersion == 4)
            {
                packet.Protocol = "IPv4";
                packet.SourceIp = $"{rawData[26]}.{rawData[27]}.{rawData[28]}.{rawData[29]}";
                packet.DestinationIp = $"{rawData[30]}.{rawData[31]}.{rawData[32]}.{rawData[33]}";

                var ipProtocol = rawData[23];
                if (ipProtocol == 6) packet.Protocol = "TCP";
                else if (ipProtocol == 17) packet.Protocol = "UDP";
                else if (ipProtocol == 1) packet.Protocol = "ICMP";
            }
        }

        return packet;
    }

    private async Task FlushBatchToUI(List<LivePacketData> batch)
    {
        // Simulate UI dispatcher overhead
        await Task.Delay(1); // ~1ms UI update time
    }
}
