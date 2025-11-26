using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PCAPAnalyzer.PerformanceTests;

/// <summary>
/// Benchmarks for TShark process communication and I/O
/// Tests process spawn overhead, pipe throughput, and output parsing
/// Target: < 50ms process spawn, < 10ms output parsing per 1000 packets
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net90, launchCount: 1, warmupCount: 3, iterationCount: 10)]
[MinColumn, MaxColumn, MeanColumn, MedianColumn]
public class TSharkIOBenchmarks
{
    private string _testDataDir = string.Empty;
    private string _smallPcapFile = string.Empty;
    private string _mediumPcapFile = string.Empty;

    [Params(100, 1000, 10000)]
    public int PacketCount { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        _testDataDir = Path.Combine(Path.GetTempPath(), $"tshark_bench_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDataDir);

        // Create synthetic PCAP files
        _smallPcapFile = Path.Combine(_testDataDir, "small.pcap");
        _mediumPcapFile = Path.Combine(_testDataDir, "medium.pcap");

        CreateSyntheticPcapFile(_smallPcapFile, 100);
        CreateSyntheticPcapFile(_mediumPcapFile, 1000);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        if (Directory.Exists(_testDataDir))
        {
            try
            {
                Directory.Delete(_testDataDir, true);
            }
            catch { /* Ignore cleanup errors */ }
        }
    }

    /// <summary>
    /// Benchmark process spawn overhead
    /// Measures time to start and stop TShark process
    /// </summary>
    [Benchmark]
    public async Task ProcessSpawnOverhead()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "echo", // Lightweight process for benchmarking
            Arguments = "test",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        for (int i = 0; i < 10; i++) // Spawn 10 processes
        {
            using var process = Process.Start(startInfo);
            if (process != null)
            {
                await process.WaitForExitAsync();
            }
        }
    }

    /// <summary>
    /// Benchmark pipe throughput (simulated TShark output)
    /// Tests reading from process StandardOutput
    /// </summary>
    [Benchmark]
    public async Task PipeThroughput()
    {
        var output = GenerateSyntheticTSharkOutput(PacketCount);

        var startInfo = new ProcessStartInfo
        {
            FileName = "echo",
            Arguments = output.Replace("\n", " "),
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(startInfo);
        if (process != null)
        {
            var result = await process.StandardOutput.ReadToEndAsync();
            await process.WaitForExitAsync();
        }
    }

    /// <summary>
    /// Benchmark JSON output parsing (tshark -T json)
    /// Tests deserialization performance
    /// </summary>
    [Benchmark]
    public void ParseJSONOutput()
    {
        var json = GenerateSyntheticJSONOutput(PacketCount);

        // Simulate parsing JSON packet data
        var lines = json.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var parsed = 0;

        foreach (var line in lines)
        {
            if (line.Contains("\"timestamp\""))
            {
                parsed++;
            }
        }

        if (parsed < PacketCount / 2) // Rough validation
            throw new InvalidOperationException($"Expected at least {PacketCount / 2} packets, parsed {parsed}");
    }

    /// <summary>
    /// Benchmark PDML (XML) output parsing (tshark -T pdml)
    /// Tests XML parsing performance
    /// </summary>
    [Benchmark]
    public void ParsePDMLOutput()
    {
        var pdml = GenerateSyntheticPDMLOutput(PacketCount);

        // Simulate parsing PDML packet data
        var lines = pdml.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var parsed = 0;

        foreach (var line in lines)
        {
            if (line.Contains("<packet>"))
            {
                parsed++;
            }
        }

        if (parsed != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount} packets, parsed {parsed}");
    }

    /// <summary>
    /// Benchmark line-by-line output reading
    /// Tests streaming vs. ReadToEnd
    /// </summary>
    [Benchmark]
    public async Task StreamingLineReading()
    {
        var output = GenerateSyntheticTSharkOutput(PacketCount);
        var lines = output.Split('\n');

        using var memoryStream = new MemoryStream(Encoding.UTF8.GetBytes(output));
        using var reader = new StreamReader(memoryStream);

        var lineCount = 0;
        string? line;

        while ((line = await reader.ReadLineAsync()) != null)
        {
            if (line.Contains("packet"))
            {
                lineCount++;
            }
        }
    }

    /// <summary>
    /// Benchmark buffered vs. unbuffered reading
    /// Tests buffer size impact on throughput
    /// </summary>
    [Benchmark]
    public async Task BufferedReading()
    {
        var output = GenerateSyntheticTSharkOutput(PacketCount);

        using var memoryStream = new MemoryStream(Encoding.UTF8.GetBytes(output));
        using var reader = new StreamReader(memoryStream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, bufferSize: 8192);

        var content = await reader.ReadToEndAsync();

        if (content.Length == 0)
            throw new InvalidOperationException("No content read");
    }

    /// <summary>
    /// Benchmark packet field extraction
    /// Tests parsing overhead for extracting specific fields
    /// </summary>
    [Benchmark]
    public void PacketFieldExtraction()
    {
        var packets = GenerateSyntheticPacketLines(PacketCount);
        var extracted = 0;

        foreach (var packet in packets)
        {
            // Extract fields using string operations
            var parts = packet.Split('\t');

            if (parts.Length >= 5)
            {
                var timestamp = parts[0];
                var source = parts[1];
                var dest = parts[2];
                var protocol = parts[3];
                var length = parts[4];
                extracted++;
            }
        }

        if (extracted != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount} extractions, got {extracted}");
    }

    /// <summary>
    /// Benchmark Span<T> based field extraction
    /// Tests zero-allocation parsing
    /// </summary>
    [Benchmark]
    public void SpanBasedFieldExtraction()
    {
        var packets = GenerateSyntheticPacketLines(PacketCount);
        var extracted = 0;

        foreach (var packet in packets)
        {
            var span = packet.AsSpan();
            var fieldCount = 0;

            // Count fields without allocation
            for (int i = 0; i < span.Length; i++)
            {
                if (span[i] == '\t')
                    fieldCount++;
            }

            if (fieldCount >= 4)
                extracted++;
        }

        if (extracted != PacketCount)
            throw new InvalidOperationException($"Expected {PacketCount} extractions, got {extracted}");
    }

    /// <summary>
    /// Benchmark concurrent packet processing
    /// Tests parallel processing of TShark output
    /// </summary>
    [Benchmark]
    public async Task ConcurrentPacketProcessing()
    {
        var packets = GenerateSyntheticPacketLines(PacketCount);

        await Parallel.ForEachAsync(packets, new ParallelOptions
        {
            MaxDegreeOfParallelism = Environment.ProcessorCount
        }, async (packet, ct) =>
        {
            // Simulate packet processing
            await Task.Yield();
            _ = packet.Length;
        });
    }

    // Helper methods

    private void CreateSyntheticPcapFile(string path, int packetCount)
    {
        // Create a minimal valid PCAP file
        using var writer = new BinaryWriter(File.Create(path));

        // PCAP global header
        writer.Write(0xa1b2c3d4u); // Magic number
        writer.Write((ushort)2); // Version major
        writer.Write((ushort)4); // Version minor
        writer.Write(0); // Timezone offset
        writer.Write(0u); // Timestamp accuracy
        writer.Write(65535u); // Snaplen
        writer.Write(1u); // Network (Ethernet)

        // Write synthetic packets
        var random = new Random(42);
        for (int i = 0; i < packetCount; i++)
        {
            var packetSize = random.Next(64, 1500);

            // Packet header
            writer.Write(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            writer.Write(0); // Microseconds
            writer.Write(packetSize); // Captured length
            writer.Write(packetSize); // Original length

            // Packet data
            var packetData = new byte[packetSize];
            random.NextBytes(packetData);
            writer.Write(packetData);
        }
    }

    private string GenerateSyntheticTSharkOutput(int packetCount)
    {
        var sb = new StringBuilder(packetCount * 100);

        for (int i = 0; i < packetCount; i++)
        {
            sb.AppendLine($"packet {i}: timestamp=1234567890.{i:D6}, src=192.168.1.{i % 255}, dst=10.0.0.{i % 255}, proto=TCP, len={64 + i % 1436}");
        }

        return sb.ToString();
    }

    private string GenerateSyntheticJSONOutput(int packetCount)
    {
        var sb = new StringBuilder(packetCount * 200);
        sb.AppendLine("[");

        for (int i = 0; i < packetCount; i++)
        {
            sb.AppendLine("  {");
            sb.AppendLine($"    \"timestamp\": \"1234567890.{i:D6}\",");
            sb.AppendLine($"    \"source\": \"192.168.1.{i % 255}\",");
            sb.AppendLine($"    \"destination\": \"10.0.0.{i % 255}\",");
            sb.AppendLine($"    \"protocol\": \"TCP\",");
            sb.AppendLine($"    \"length\": {64 + i % 1436}");
            sb.AppendLine(i < packetCount - 1 ? "  }," : "  }");
        }

        sb.AppendLine("]");
        return sb.ToString();
    }

    private string GenerateSyntheticPDMLOutput(int packetCount)
    {
        var sb = new StringBuilder(packetCount * 150);
        sb.AppendLine("<pdml>");

        for (int i = 0; i < packetCount; i++)
        {
            sb.AppendLine($"  <packet>");
            sb.AppendLine($"    <field name=\"timestamp\" value=\"1234567890.{i:D6}\" />");
            sb.AppendLine($"    <field name=\"ip.src\" value=\"192.168.1.{i % 255}\" />");
            sb.AppendLine($"    <field name=\"ip.dst\" value=\"10.0.0.{i % 255}\" />");
            sb.AppendLine($"    <field name=\"frame.len\" value=\"{64 + i % 1436}\" />");
            sb.AppendLine($"  </packet>");
        }

        sb.AppendLine("</pdml>");
        return sb.ToString();
    }

    private string[] GenerateSyntheticPacketLines(int packetCount)
    {
        var lines = new string[packetCount];

        for (int i = 0; i < packetCount; i++)
        {
            lines[i] = $"1234567890.{i:D6}\t192.168.1.{i % 255}\t10.0.0.{i % 255}\tTCP\t{64 + i % 1436}";
        }

        return lines;
    }
}
