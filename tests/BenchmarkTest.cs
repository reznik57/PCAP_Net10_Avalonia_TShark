using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using Microsoft.Extensions.ObjectPool;

namespace PCAPAnalyzer.Tests
{
    public class BenchmarkTest
    {
        public static async Task Main(string[] args)
        {
            Console.WriteLine("=== PCAP Analyzer Performance Benchmark ===");
            Console.WriteLine();
            
            var pcapFile = args.Length > 0 ? args[0] : "04.07.2025.pcap";
            
            if (!File.Exists(pcapFile))
            {
                Console.WriteLine($"Error: PCAP file '{pcapFile}' not found!");
                return;
            }
            
            var fileInfo = new FileInfo(pcapFile);
            Console.WriteLine($"PCAP File: {fileInfo.Name}");
            Console.WriteLine($"File Size: {fileInfo.Length / 1024.0 / 1024.0:F2} MB");
            Console.WriteLine($"Target: Process in 30-60 seconds");
            Console.WriteLine();
            
            // Create services
            var optimizer = new AutoOptimizationService();
            var perfTracker = new PerformanceTrackingService();
            var tsharkService = new OptimizedTSharkService(optimizer, perfTracker);
            
            // Create progress reporter
            var progress = new Progress<CalculationProgress>(p =>
            {
                Console.Write($"\r[{p.Stage}] {p.OverallProgress:F1}% - {p.CurrentOperation} | " +
                            $"{p.ItemsPerSecond:F0} items/sec | " +
                            $"ETA: {p.EstimatedRemaining.TotalSeconds:F0}s");
            });
            
            Console.WriteLine("Starting optimized analysis...");
            var stopwatch = Stopwatch.StartNew();
            
            try
            {
                // Run optimized processing
                var stats = await tsharkService.ProcessPcapFileAsync(pcapFile, progress);
                
                stopwatch.Stop();
                Console.WriteLine();
                Console.WriteLine();
                Console.WriteLine("=== Benchmark Results ===");
                Console.WriteLine($"Total Time: {stopwatch.Elapsed.TotalSeconds:F2} seconds");
                Console.WriteLine($"Packets Processed: {stats.TotalPackets:N0}");
                Console.WriteLine($"Bytes Processed: {stats.TotalBytes / 1024.0 / 1024.0:F2} MB");
                Console.WriteLine($"Throughput: {stats.TotalPackets / stopwatch.Elapsed.TotalSeconds:F0} packets/second");
                Console.WriteLine($"Speed Improvement: {stats.TotalPackets / stopwatch.Elapsed.TotalSeconds / 44:F1}x over baseline (44 pps)");
                
                if (stopwatch.Elapsed.TotalSeconds <= 60)
                {
                    Console.WriteLine();
                    Console.WriteLine("✅ SUCCESS: Achieved target of under 60 seconds!");
                    if (stopwatch.Elapsed.TotalSeconds <= 30)
                    {
                        Console.WriteLine("🚀 EXCELLENT: Achieved optimal target of under 30 seconds!");
                    }
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine("⚠️  Performance target not yet met. Optimization continuing...");
                }
                
                // Show optimization strategy used
                var strategy = optimizer.GetOptimalStrategy(pcapFile);
                Console.WriteLine();
                Console.WriteLine("=== Optimization Strategy ===");
                Console.WriteLine($"Mode: {strategy.Mode}");
                Console.WriteLine($"Threads: {strategy.ThreadCount}");
                Console.WriteLine($"Batch Size: {strategy.BatchSize}");
                Console.WriteLine($"Cache Size: {strategy.CacheSize}");
                Console.WriteLine($"Parallel Pipeline: {strategy.UseParallelPipeline}");
                Console.WriteLine($"Memory Pooling: {strategy.UseMemoryPooling}");
                Console.WriteLine($"Vectorization: {strategy.UseVectorization}");
                
                // Learn from this run
                Console.WriteLine();
                Console.WriteLine("Recording performance for future optimization...");
                var history = await optimizer.BenchmarkAsync(pcapFile, strategy);
                Console.WriteLine($"Recorded: {history.PacketsPerSecond:F0} packets/sec with {strategy.ThreadCount} threads");
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine($"Error during benchmark: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
            finally
            {
                tsharkService?.Dispose();
            }
        }
    }
}