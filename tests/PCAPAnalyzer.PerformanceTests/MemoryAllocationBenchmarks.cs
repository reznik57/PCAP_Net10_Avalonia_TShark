using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using PCAPAnalyzer.Core.Models.Capture;
using PCAPAnalyzer.Core.Performance;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PCAPAnalyzer.PerformanceTests;

/// <summary>
/// Benchmarks for memory allocation patterns
/// Tests object pooling, string interning, and zero-allocation techniques
/// Target: < 10 MB/sec allocation rate at 50K packets/sec
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90, launchCount: 1, warmupCount: 3, iterationCount: 10)]
[MinColumn, MaxColumn, MeanColumn, MedianColumn]
public class MemoryAllocationBenchmarks
{
    private ObjectPool<byte[]>? _bufferPool;
    private ObjectPool<LivePacketData>? _packetPool;
    private List<byte[]> _testData = [];
    private Random _random = new(42);

    [Params(1000, 10000, 50000)]
    public int Operations { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        // Setup object pools
        _bufferPool = new ObjectPool<byte[]>(
            () => new byte[65536],
            arr => Array.Clear(arr, 0, arr.Length),
            maxPoolSize: 1000,
            preAllocate: 100
        );

        _packetPool = new ObjectPool<LivePacketData>(
            () => new LivePacketData(),
            p => ResetPacket(p),
            maxPoolSize: 1000,
            preAllocate: 100
        );

        // Generate test data
        _testData = Enumerable.Range(0, 1000)
            .Select(_ => GenerateRandomData(_random.Next(64, 1500)))
            .ToList();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _bufferPool?.Dispose();
        _packetPool?.Dispose();
    }

    /// <summary>
    /// Baseline: Direct byte array allocation without pooling
    /// </summary>
    [Benchmark(Baseline = true)]
    public void DirectAllocation()
    {
        var buffers = new List<byte[]>(Operations);

        for (int i = 0; i < Operations; i++)
        {
            var buffer = new byte[65536];
            Array.Clear(buffer, 0, buffer.Length);
            buffers.Add(buffer);
        }

        // Simulate usage
        foreach (var buffer in buffers)
        {
            _ = buffer[0];
        }
    }

    /// <summary>
    /// Optimized: Pooled byte array allocation
    /// Expected: 50-70% reduction in allocations
    /// </summary>
    [Benchmark]
    public void PooledAllocation()
    {
        var buffers = new List<byte[]>(Operations);

        for (int i = 0; i < Operations; i++)
        {
            var buffer = _bufferPool!.Rent();
            buffers.Add(buffer);
        }

        // Simulate usage
        foreach (var buffer in buffers)
        {
            _ = buffer[0];
        }

        // Return to pool
        foreach (var buffer in buffers)
        {
            _bufferPool!.Return(buffer);
        }
    }

    /// <summary>
    /// Optimized: ArrayPool<T> from System.Buffers
    /// Comparison with BCL implementation
    /// </summary>
    [Benchmark]
    public void ArrayPoolAllocation()
    {
        var pool = ArrayPool<byte>.Shared;
        var buffers = new List<byte[]>(Operations);

        for (int i = 0; i < Operations; i++)
        {
            var buffer = pool.Rent(65536);
            buffers.Add(buffer);
        }

        // Simulate usage
        foreach (var buffer in buffers)
        {
            _ = buffer[0];
        }

        // Return to pool
        foreach (var buffer in buffers)
        {
            pool.Return(buffer);
        }
    }

    /// <summary>
    /// Baseline: String concatenation for protocol names
    /// </summary>
    [Benchmark]
    public void StringConcatenation()
    {
        var protocols = new List<string>(Operations);

        for (int i = 0; i < Operations; i++)
        {
            var protocol = GetProtocolName(i % 7);
            protocols.Add(protocol);
        }

        // Simulate usage
        var uniqueCount = protocols.Distinct().Count();
    }

    /// <summary>
    /// Optimized: String interning for repeated protocol names
    /// Expected: Significant memory reduction for repeated strings
    /// </summary>
    [Benchmark]
    public void StringInterning()
    {
        var protocols = new List<string>(Operations);

        for (int i = 0; i < Operations; i++)
        {
            var protocol = string.Intern(GetProtocolName(i % 7));
            protocols.Add(protocol);
        }

        // Simulate usage
        var uniqueCount = protocols.Distinct().Count();
    }

    /// <summary>
    /// Baseline: LivePacketData allocation without pooling
    /// </summary>
    [Benchmark]
    public void PacketObjectAllocation()
    {
        var packets = new List<LivePacketData>(Operations);

        for (int i = 0; i < Operations; i++)
        {
            var packet = new LivePacketData
            {
                SequenceNumber = i,
                Timestamp = DateTime.UtcNow,
                RawData = _testData[i % _testData.Count],
                Length = 1000,
                Protocol = "TCP"
            };
            packets.Add(packet);
        }

        // Simulate usage
        var totalLength = packets.Sum(p => p.Length);
    }

    /// <summary>
    /// Optimized: LivePacketData pooling
    /// Expected: 30-50% reduction in allocations
    /// </summary>
    [Benchmark]
    public void PacketObjectPooling()
    {
        var packets = new List<LivePacketData>(Operations);

        for (int i = 0; i < Operations; i++)
        {
            var packet = _packetPool!.Rent();
            packet.SequenceNumber = i;
            packet.Timestamp = DateTime.UtcNow;
            packet.RawData = _testData[i % _testData.Count];
            packet.Length = 1000;
            packet.Protocol = string.Intern("TCP");
            packets.Add(packet);
        }

        // Simulate usage
        var totalLength = packets.Sum(p => p.Length);

        // Return to pool
        foreach (var packet in packets)
        {
            _packetPool!.Return(packet);
        }
    }

    /// <summary>
    /// Baseline: BitConverter.ToString for MAC addresses
    /// Creates new string on every call
    /// </summary>
    [Benchmark]
    public void MacAddressFormatting_BitConverter()
    {
        var macAddresses = new List<string>(Operations);

        for (int i = 0; i < Operations; i++)
        {
            var macBytes = _testData[i % _testData.Count].AsSpan(0, 6).ToArray();
            var mac = BitConverter.ToString(macBytes);
            macAddresses.Add(mac);
        }

        var uniqueCount = macAddresses.Distinct().Count();
    }

    /// <summary>
    /// Optimized: Span<T> based MAC formatting
    /// Reduces allocations with stackalloc
    /// </summary>
    [Benchmark]
    public void MacAddressFormatting_Span()
    {
        var macAddresses = new List<string>(Operations);

        for (int i = 0; i < Operations; i++)
        {
            var macBytes = _testData[i % _testData.Count].AsSpan(0, 6);
            var mac = FormatMacAddress(macBytes);
            macAddresses.Add(mac);
        }

        var uniqueCount = macAddresses.Distinct().Count();
    }

    /// <summary>
    /// Baseline: String.Format for IP addresses
    /// </summary>
    [Benchmark]
    public void IPAddressFormatting_StringFormat()
    {
        var ipAddresses = new List<string>(Operations);

        for (int i = 0; i < Operations; i++)
        {
            var data = _testData[i % _testData.Count];
            if (data.Length >= 30)
            {
                var ip = string.Format("{0}.{1}.{2}.{3}", data[26], data[27], data[28], data[29]);
                ipAddresses.Add(ip);
            }
        }

        var uniqueCount = ipAddresses.Distinct().Count();
    }

    /// <summary>
    /// Optimized: String interpolation with DefaultInterpolatedStringHandler
    /// .NET 6+ optimization
    /// </summary>
    [Benchmark]
    public void IPAddressFormatting_Interpolation()
    {
        var ipAddresses = new List<string>(Operations);

        for (int i = 0; i < Operations; i++)
        {
            var data = _testData[i % _testData.Count];
            if (data.Length >= 30)
            {
                var ip = $"{data[26]}.{data[27]}.{data[28]}.{data[29]}";
                ipAddresses.Add(ip);
            }
        }

        var uniqueCount = ipAddresses.Distinct().Count();
    }

    /// <summary>
    /// Baseline: LINQ for protocol counting
    /// </summary>
    [Benchmark]
    public void ProtocolCounting_LINQ()
    {
        var protocols = new List<string>(Operations);

        for (int i = 0; i < Operations; i++)
        {
            protocols.Add(GetProtocolName(i % 7));
        }

        var counts = protocols.GroupBy(p => p).ToDictionary(g => g.Key, g => g.Count());
    }

    /// <summary>
    /// Optimized: Dictionary for protocol counting
    /// Avoids LINQ allocations
    /// </summary>
    [Benchmark]
    public void ProtocolCounting_Dictionary()
    {
        var counts = new Dictionary<string, int>();

        for (int i = 0; i < Operations; i++)
        {
            var protocol = GetProtocolName(i % 7);

            if (counts.ContainsKey(protocol))
                counts[protocol]++;
            else
                counts[protocol] = 1;
        }
    }

    // Helper methods

    private byte[] GenerateRandomData(int size)
    {
        var data = new byte[size];
        _random.NextBytes(data);
        return data;
    }

    private string GetProtocolName(int index)
    {
        return index switch
        {
            0 => "TCP",
            1 => "UDP",
            2 => "ICMP",
            3 => "HTTP",
            4 => "HTTPS",
            5 => "DNS",
            6 => "SSH",
            _ => "Unknown"
        };
    }

    private void ResetPacket(LivePacketData packet)
    {
        packet.SequenceNumber = 0;
        packet.Timestamp = default;
        packet.RawData = Array.Empty<byte>();
        packet.Length = 0;
        packet.CapturedLength = 0;
        packet.SourceMac = null;
        packet.DestinationMac = null;
        packet.SourceIp = null;
        packet.DestinationIp = null;
        packet.SourcePort = null;
        packet.DestinationPort = null;
        packet.Protocol = string.Empty;
        packet.ProtocolInfo = null;
        packet.HasAnomaly = false;
        packet.Anomalies.Clear();
        packet.InterfaceId = string.Empty;
    }

    private string FormatMacAddress(ReadOnlySpan<byte> macBytes)
    {
        // Use stackalloc for small buffer (17 chars: XX-XX-XX-XX-XX-XX)
        Span<char> buffer = stackalloc char[17];

        for (int i = 0; i < 6; i++)
        {
            var b = macBytes[i];
            buffer[i * 3] = GetHexChar(b >> 4);
            buffer[i * 3 + 1] = GetHexChar(b & 0x0F);

            if (i < 5)
                buffer[i * 3 + 2] = '-';
        }

        return new string(buffer);
    }

    private static char GetHexChar(int value)
    {
        return value < 10 ? (char)('0' + value) : (char)('A' + value - 10);
    }
}
