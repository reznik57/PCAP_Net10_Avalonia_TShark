using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using Microsoft.Extensions.Logging.Abstractions;
using PCAPAnalyzer.Core.Models.Capture;
using PCAPAnalyzer.Core.Services.Capture;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PCAPAnalyzer.PerformanceTests;

/// <summary>
/// Benchmarks for packet stream processing pipeline
/// Measures channel throughput, parsing efficiency, and anomaly detection
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90, launchCount: 1, warmupCount: 3, iterationCount: 10)]
[MinColumn, MaxColumn, MeanColumn, MedianColumn]
public class PacketProcessingBenchmarks
{
    private PacketStreamProcessor? _processor;
    private List<LivePacketData> _testPackets = [];

    [Params(1000, 10000, 50000)]
    public int PacketCount { get; set; }

    [Params(1, 4, 8)]
    public int Concurrency { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _processor = new PacketStreamProcessor(NullLogger<PacketStreamProcessor>.Instance, Concurrency);
        _testPackets = GenerateTestPackets(PacketCount);
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        if (_processor != null)
        {
            await _processor.StopAsync();
            _processor.Dispose();
        }
    }

    /// <summary>
    /// Benchmark packet stream processing throughput
    /// Tests end-to-end pipeline performance
    /// </summary>
    [Benchmark]
    public async Task StreamProcessing()
    {
        _processor!.Start();

        var processedCount = 0;
        var completionTcs = new TaskCompletionSource();

        _processor.PacketProcessed += (sender, packet) =>
        {
            if (Interlocked.Increment(ref processedCount) == PacketCount)
            {
                completionTcs.TrySetResult();
            }
        };

        // Enqueue all packets
        foreach (var packet in _testPackets)
        {
            await _processor.EnqueuePacketAsync(packet);
        }

        // Wait for all to process
        await completionTcs.Task.WaitAsync(TimeSpan.FromSeconds(30));

        await _processor.StopAsync();

        if (processedCount != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount}, processed {processedCount}");
    }

    /// <summary>
    /// Benchmark packet parsing without channel overhead
    /// Measures pure parsing performance
    /// </summary>
    [Benchmark]
    public void DirectPacketParsing()
    {
        var parsed = 0;

        foreach (var packet in _testPackets)
        {
            ParsePacketInfo(packet);
            parsed++;
        }

        if (parsed != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount}, parsed {parsed}");
    }

    /// <summary>
    /// Benchmark anomaly detection performance
    /// Tests pattern matching and heuristics
    /// </summary>
    [Benchmark]
    public void AnomalyDetection()
    {
        var detected = 0;

        foreach (var packet in _testPackets)
        {
            DetectAnomalies(packet);
            if (packet.HasAnomaly)
                detected++;
        }

        // ~10% of packets should have anomalies based on generation
    }

    /// <summary>
    /// Benchmark stream statistics aggregation
    /// Tests concurrent dictionary updates
    /// </summary>
    [Benchmark]
    public void StreamStatisticsAggregation()
    {
        var stats = new Dictionary<string, StreamStats>();

        foreach (var packet in _testPackets)
        {
            var key = $"{packet.SourceIp}:{packet.SourcePort}->{packet.DestinationIp}:{packet.DestinationPort}";

            if (!stats.ContainsKey(key))
            {
                stats[key] = new StreamStats();
            }

            stats[key].PacketCount++;
            stats[key].TotalBytes += packet.Length;
            stats[key].LastSeen = packet.Timestamp;
        }

        // Should have created multiple stream entries
        if (stats.Count == 0)
            throw new InvalidOperationException("No streams detected");
    }

    /// <summary>
    /// Benchmark zero-allocation parsing with Span<T>
    /// Tests optimized string-free parsing
    /// </summary>
    [Benchmark]
    public void ZeroAllocationParsing()
    {
        var parsed = 0;

        foreach (var packet in _testPackets)
        {
            ParseWithSpan(packet.RawData.AsSpan());
            parsed++;
        }

        if (parsed != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount}, parsed {parsed}");
    }

    /// <summary>
    /// Benchmark protocol identification performance
    /// Tests protocol matching and classification
    /// </summary>
    [Benchmark]
    public void ProtocolIdentification()
    {
        var identified = 0;

        foreach (var packet in _testPackets)
        {
            var protocol = IdentifyProtocol(packet.RawData);
            identified++;
        }

        if (identified != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount}, identified {identified}");
    }

    // Helper methods

    private List<LivePacketData> GenerateTestPackets(int count)
    {
        var packets = new List<LivePacketData>(count);
        var random = new Random(42);

        for (int i = 0; i < count; i++)
        {
            var rawData = GeneratePacketData(random.Next(64, 1500), random);

            packets.Add(new LivePacketData
            {
                SequenceNumber = i,
                Timestamp = DateTime.UtcNow.AddMilliseconds(-i),
                RawData = rawData,
                Length = rawData.Length,
                CapturedLength = rawData.Length,
                SourceIp = $"192.168.{random.Next(1, 255)}.{random.Next(1, 255)}",
                DestinationIp = $"10.0.{random.Next(1, 255)}.{random.Next(1, 255)}",
                SourcePort = random.Next(1024, 65535),
                DestinationPort = random.Next(1, 1024),
                Protocol = "Unknown",
                InterfaceId = "eth0"
            });
        }

        return packets;
    }

    private byte[] GeneratePacketData(int size, Random random)
    {
        var data = new byte[size];
        random.NextBytes(data);

        // Create realistic packet structure
        if (size >= 14)
        {
            // Ethernet header
            data[12] = 0x08; // IPv4
            data[13] = 0x00;
        }

        if (size >= 34)
        {
            // IP header
            data[14] = 0x45; // IPv4, 20-byte header
            data[23] = (byte)random.Next(1, 18); // Random protocol

            // Source and destination IPs
            for (int i = 26; i < 34; i++)
            {
                data[i] = (byte)random.Next(1, 255);
            }
        }

        return data;
    }

    private void ParsePacketInfo(LivePacketData packet)
    {
        if (packet.RawData.Length >= 14)
        {
            packet.DestinationMac = BitConverter.ToString(packet.RawData, 0, 6);
            packet.SourceMac = BitConverter.ToString(packet.RawData, 6, 6);
        }

        if (packet.RawData.Length >= 34)
        {
            var ipVersion = (packet.RawData[14] >> 4) & 0x0F;
            if (ipVersion == 4)
            {
                packet.Protocol = "IPv4";
                packet.SourceIp = $"{packet.RawData[26]}.{packet.RawData[27]}.{packet.RawData[28]}.{packet.RawData[29]}";
                packet.DestinationIp = $"{packet.RawData[30]}.{packet.RawData[31]}.{packet.RawData[32]}.{packet.RawData[33]}";
            }
        }
    }

    private void DetectAnomalies(LivePacketData packet)
    {
        var anomalies = new List<string>();

        // Large packet
        if (packet.Length > 9000)
            anomalies.Add("Jumbo frame");

        // Unknown protocol
        if (packet.Protocol == "Unknown" && packet.RawData.Length > 0)
            anomalies.Add("Unknown protocol");

        // Suspicious port
        if (packet.SourcePort is > 0 and < 1024 && packet.DestinationPort is > 0 and < 1024)
            anomalies.Add("Privileged port communication");

        packet.HasAnomaly = anomalies.Count > 0;
        packet.Anomalies = anomalies;
    }

    private void ParseWithSpan(ReadOnlySpan<byte> data)
    {
        if (data.Length < 14) return;

        // Zero-allocation MAC extraction
        ReadOnlySpan<byte> destMac = data.Slice(0, 6);
        ReadOnlySpan<byte> srcMac = data.Slice(6, 6);

        if (data.Length < 34) return;

        // Zero-allocation IP extraction
        var ipVersion = (data[14] >> 4) & 0x0F;
        if (ipVersion == 4)
        {
            ReadOnlySpan<byte> srcIp = data.Slice(26, 4);
            ReadOnlySpan<byte> destIp = data.Slice(30, 4);
        }
    }

    private string IdentifyProtocol(byte[] data)
    {
        if (data.Length < 34) return "Unknown";

        var ipVersion = (data[14] >> 4) & 0x0F;
        if (ipVersion != 4) return "Unknown";

        var ipProtocol = data[23];
        return ipProtocol switch
        {
            1 => "ICMP",
            6 => "TCP",
            17 => "UDP",
            _ => "Unknown"
        };
    }

    private class StreamStats
    {
        public long PacketCount { get; set; }
        public long TotalBytes { get; set; }
        public DateTime LastSeen { get; set; }
    }
}
