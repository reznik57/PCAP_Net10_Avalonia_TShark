using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PCAPAnalyzer.TShark;

namespace PCAPAnalyzer.Benchmark;

/// <summary>
/// Performance comparison between Sequential and Parallel TShark services.
/// Run with: dotnet run --project tests/PCAPAnalyzer.Benchmark -- [pcap-file-path]
/// </summary>
public class Program
{
    public static async Task Main(string[] args)
    {
        Console.WriteLine("═══════════════════════════════════════════════════════════════════");
        Console.WriteLine("  TShark Performance Comparison: Sequential vs Parallel");
        Console.WriteLine("═══════════════════════════════════════════════════════════════════");
        Console.WriteLine();

        // Find PCAP file
        var pcapPath = args.Length > 0 ? args[0] : FindDefaultPcapFile();

        if (string.IsNullOrEmpty(pcapPath) || !File.Exists(pcapPath))
        {
            Console.WriteLine("❌ No PCAP file found. Usage:");
            Console.WriteLine("   dotnet run --project tests/PCAPAnalyzer.Benchmark -- <path-to-pcap>");
            Console.WriteLine();
            Console.WriteLine("   Or place a .pcap file in the current directory.");
            return;
        }

        var fileInfo = new FileInfo(pcapPath);
        Console.WriteLine($"📁 PCAP File: {fileInfo.Name}");
        Console.WriteLine($"📊 File Size: {fileInfo.Length / 1024.0 / 1024.0:F2} MB");
        Console.WriteLine();

        // Check tool availability
        var tsharkInfo = WiresharkToolDetector.DetectTShark();
        var editcapInfo = WiresharkToolDetector.DetectEditcap();

        Console.WriteLine($"🔧 TShark: {(tsharkInfo.IsAvailable ? "✅ " + tsharkInfo.Description : "❌ Not found")}");
        Console.WriteLine($"🔧 editcap: {(editcapInfo.IsAvailable ? "✅ " + editcapInfo.Description : "❌ Not found")}");
        Console.WriteLine();

        if (!tsharkInfo.IsAvailable)
        {
            Console.WriteLine("❌ TShark not available. Please install Wireshark.");
            return;
        }

        // Run Sequential Benchmark
        Console.WriteLine("───────────────────────────────────────────────────────────────────");
        Console.WriteLine("  📈 SEQUENTIAL TSharkService");
        Console.WriteLine("───────────────────────────────────────────────────────────────────");

        var sequentialResult = await BenchmarkSequentialAsync(pcapPath);

        Console.WriteLine();
        Console.WriteLine($"  ⏱️  Time: {sequentialResult.Elapsed.TotalSeconds:F2}s");
        Console.WriteLine($"  📦 Packets: {sequentialResult.PacketCount:N0}");
        Console.WriteLine($"  ⚡ Rate: {sequentialResult.PacketsPerSecond:N0} packets/sec");
        Console.WriteLine();

        // Run Parallel Benchmark (if editcap available)
        if (editcapInfo.IsAvailable)
        {
            Console.WriteLine("───────────────────────────────────────────────────────────────────");
            Console.WriteLine($"  📈 PARALLEL ParallelTSharkService ({Environment.ProcessorCount} cores)");
            Console.WriteLine("───────────────────────────────────────────────────────────────────");

            var parallelResult = await BenchmarkParallelAsync(pcapPath, editcapInfo);

            Console.WriteLine();
            Console.WriteLine($"  ⏱️  Time: {parallelResult.Elapsed.TotalSeconds:F2}s");
            Console.WriteLine($"  📦 Packets: {parallelResult.PacketCount:N0}");
            Console.WriteLine($"  ⚡ Rate: {parallelResult.PacketsPerSecond:N0} packets/sec");
            Console.WriteLine();

            // Comparison
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");
            Console.WriteLine("  📊 COMPARISON");
            Console.WriteLine("═══════════════════════════════════════════════════════════════════");

            var speedup = sequentialResult.Elapsed.TotalSeconds / parallelResult.Elapsed.TotalSeconds;
            Console.WriteLine($"  🚀 Speedup: {speedup:F2}× faster");
            Console.WriteLine($"  ⏱️  Time saved: {sequentialResult.Elapsed.TotalSeconds - parallelResult.Elapsed.TotalSeconds:F2}s");
            Console.WriteLine();
        }
        else
        {
            Console.WriteLine("⚠️  Skipping parallel benchmark (editcap not available)");
        }
    }

    private static async Task<BenchmarkResult> BenchmarkSequentialAsync(string pcapPath)
    {
        var logger = NullLogger<TSharkService>.Instance;
        using var service = new TSharkService(logger);

        var sw = Stopwatch.StartNew();
        var packetCount = 0L;

        var started = await service.StartAnalysisAsync(pcapPath, CancellationToken.None);
        if (!started)
        {
            Console.WriteLine("  ❌ Failed to start analysis");
            return new BenchmarkResult();
        }

        Console.Write("  Loading: ");
        var lastProgress = DateTime.Now;

        await foreach (var packet in service.PacketReader.ReadAllAsync())
        {
            packetCount++;

            // Progress indicator every 2 seconds
            if ((DateTime.Now - lastProgress).TotalSeconds >= 2)
            {
                Console.Write($"{packetCount:N0}... ");
                lastProgress = DateTime.Now;
            }
        }

        sw.Stop();
        Console.WriteLine($"{packetCount:N0} ✓");

        return new BenchmarkResult
        {
            Elapsed = sw.Elapsed,
            PacketCount = packetCount,
            PacketsPerSecond = packetCount / sw.Elapsed.TotalSeconds
        };
    }

    private static async Task<BenchmarkResult> BenchmarkParallelAsync(string pcapPath, WiresharkToolInfo editcapInfo)
    {
        var logger = NullLogger<ParallelTSharkService>.Instance;
        using var service = new ParallelTSharkService(logger, editcapInfo);

        var sw = Stopwatch.StartNew();
        var packetCount = 0L;

        var started = await service.StartAnalysisAsync(pcapPath, CancellationToken.None);
        if (!started)
        {
            Console.WriteLine("  ❌ Failed to start analysis");
            return new BenchmarkResult();
        }

        Console.Write("  Loading: ");
        var lastProgress = DateTime.Now;

        await foreach (var packet in service.PacketReader.ReadAllAsync())
        {
            packetCount++;

            // Progress indicator every 2 seconds
            if ((DateTime.Now - lastProgress).TotalSeconds >= 2)
            {
                Console.Write($"{packetCount:N0}... ");
                lastProgress = DateTime.Now;
            }
        }

        sw.Stop();
        Console.WriteLine($"{packetCount:N0} ✓");

        return new BenchmarkResult
        {
            Elapsed = sw.Elapsed,
            PacketCount = packetCount,
            PacketsPerSecond = packetCount / sw.Elapsed.TotalSeconds
        };
    }

    private static string? FindDefaultPcapFile()
    {
        // Look for common PCAP file locations
        var searchPaths = new[]
        {
            ".",
            "..",
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            "/mnt/c/Claude Code",
            "/mnt/d"
        };

        foreach (var path in searchPaths)
        {
            if (!Directory.Exists(path)) continue;

            var pcapFiles = Directory.GetFiles(path, "*.pcap", SearchOption.TopDirectoryOnly);
            if (pcapFiles.Length > 0)
            {
                // Return the largest one for a meaningful benchmark
                return pcapFiles.OrderByDescending(f => new FileInfo(f).Length).First();
            }

            var pcapngFiles = Directory.GetFiles(path, "*.pcapng", SearchOption.TopDirectoryOnly);
            if (pcapngFiles.Length > 0)
            {
                return pcapngFiles.OrderByDescending(f => new FileInfo(f).Length).First();
            }
        }

        return null;
    }

    private struct BenchmarkResult
    {
        public TimeSpan Elapsed;
        public long PacketCount;
        public double PacketsPerSecond;
    }
}
