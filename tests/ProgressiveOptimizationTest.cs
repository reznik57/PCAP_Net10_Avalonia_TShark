using System;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Services;

namespace PCAPAnalyzer.Tests
{
    /// <summary>
    /// Demonstrates progressive optimization to meet performance targets
    /// </summary>
    public class ProgressiveOptimizationTest
    {
        public static async Task Main(string[] args)
        {
            Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
            Console.WriteLine("║       PCAP Analyzer Progressive Optimization Demo           ║");
            Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
            Console.WriteLine();
            
            var pcapFile = args.Length > 0 ? args[0] : "../04.07.2025.pcap";
            
            if (!File.Exists(pcapFile))
            {
                Console.WriteLine($"❌ Error: PCAP file '{pcapFile}' not found!");
                return;
            }
            
            var fileInfo = new FileInfo(pcapFile);
            Console.WriteLine($"📁 PCAP File: {fileInfo.Name}");
            Console.WriteLine($"📊 File Size: {fileInfo.Length / 1024.0 / 1024.0:F2} MB");
            Console.WriteLine($"📦 Estimated Packets: ~1,106,728");
            Console.WriteLine();
            
            // Progressive targets
            int[] targets = { 60, 50, 40, 30 };
            
            var optimizer = new ProgressiveOptimizer();
            
            foreach (var targetSeconds in targets)
            {
                Console.WriteLine($"{'═'}{new string('═', 62)}{'═'}");
                Console.WriteLine($"🎯 Target: {targetSeconds} seconds");
                Console.WriteLine($"{'─'}{new string('─', 62)}{'─'}");
                
                var progress = new Progress<OptimizationProgress>(p =>
                {
                    Console.Write($"\r{p.Stage,-30} │ {p.CurrentTime.TotalSeconds,6:F2}s → " +
                                $"{p.TargetTime.TotalSeconds,3:F0}s │ " +
                                $"{p.PacketsPerSecond,7:F0} pps │ ");
                    
                    if (p.Improvement > 0)
                    {
                        Console.Write($"{p.Improvement:F1}x faster");
                    }
                    
                    // Progress bar
                    if (p.CurrentTime.TotalSeconds > 0)
                    {
                        var percentage = Math.Min(100, p.PercentageToTarget);
                        var barLength = 20;
                        var filled = (int)(percentage * barLength / 100);
                        var bar = new string('█', filled) + new string('░', barLength - filled);
                        Console.Write($" │ [{bar}] {percentage:F0}%");
                    }
                });
                
                var stopwatch = Stopwatch.StartNew();
                
                try
                {
                    var result = await optimizer.ProcessWithTargetAsync(
                        pcapFile, 
                        targetSeconds, 
                        progress);
                    
                    stopwatch.Stop();
                    
                    Console.WriteLine(); // New line after progress
                    Console.WriteLine();
                    
                    if (result.Success)
                    {
                        Console.WriteLine($"✅ SUCCESS: Achieved {targetSeconds}s target!");
                        Console.WriteLine($"   Final Time: {result.FinalTime.TotalSeconds:F2} seconds");
                        Console.WriteLine($"   Throughput: {result.PacketsProcessed / result.FinalTime.TotalSeconds:F0} packets/second");
                        Console.WriteLine($"   Level: {result.OptimizationLevel}");
                        
                        if (result.AppliedOptimizations?.Count > 0)
                        {
                            Console.WriteLine("   Applied Optimizations:");
                            foreach (var opt in result.AppliedOptimizations)
                            {
                                Console.WriteLine($"     • {opt}");
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine($"⚠️  Could not achieve {targetSeconds}s target");
                        Console.WriteLine($"   Best Time: {result.FinalTime.TotalSeconds:F2} seconds");
                        Console.WriteLine($"   Need {(result.FinalTime.TotalSeconds / targetSeconds - 1) * 100:F1}% more improvement");
                    }
                    
                    Console.WriteLine();
                    
                    // Show what would be needed for this target
                    ShowOptimizationStrategy(targetSeconds);
                }
                catch (Exception ex)
                {
                    Console.WriteLine();
                    Console.WriteLine($"❌ Error: {ex.Message}");
                }
            }
            
            Console.WriteLine($"{'═'}{new string('═', 62)}{'═'}");
            Console.WriteLine("📈 Optimization Journey Complete!");
            Console.WriteLine();
            ShowSummary();
        }
        
        private static void ShowOptimizationStrategy(int targetSeconds)
        {
            Console.WriteLine($"📋 Strategy for {targetSeconds}s target:");
            
            switch (targetSeconds)
            {
                case 60:
                    Console.WriteLine("   Stage 1: Basic Optimizations");
                    Console.WriteLine("   • Batch processing (1000 packets/batch)");
                    Console.WriteLine("   • Simple caching for GeoIP lookups");
                    Console.WriteLine("   • Throttle UI updates to 100ms intervals");
                    Console.WriteLine("   • Skip redundant calculations");
                    Console.WriteLine("   • Basic threading with Task.Run");
                    break;
                    
                case 50:
                    Console.WriteLine("   Stage 2: Parallel Pipeline");
                    Console.WriteLine("   • TPL Dataflow with 4 parser threads");
                    Console.WriteLine("   • Memory pooling with ArrayPool<byte>");
                    Console.WriteLine("   • Bounded channels for backpressure");
                    Console.WriteLine("   • Concurrent collections");
                    break;
                    
                case 40:
                    Console.WriteLine("   Stage 3: Vectorized Processing");
                    Console.WriteLine("   • SIMD operations (AVX2/SSE2)");
                    Console.WriteLine("   • Predictive prefetching");
                    Console.WriteLine("   • Branch prediction optimization");
                    Console.WriteLine("   • Struct-based packet data");
                    break;
                    
                case 30:
                    Console.WriteLine("   Stage 4: Native Integration");
                    Console.WriteLine("   • Direct TShark binary parsing");
                    Console.WriteLine("   • Zero-copy memory operations");
                    Console.WriteLine("   • Adaptive algorithm selection");
                    Console.WriteLine("   • JIT warm-up and PGO");
                    Console.WriteLine("   • Lock-free data structures");
                    break;
            }
            
            Console.WriteLine();
        }
        
        private static void ShowSummary()
        {
            Console.WriteLine("🏆 Key Optimization Techniques Summary:");
            Console.WriteLine();
            
            Console.WriteLine("1️⃣ BATCH PROCESSING");
            Console.WriteLine("   Process packets in groups rather than individually");
            Console.WriteLine("   Reduces overhead and improves cache locality");
            Console.WriteLine();
            
            Console.WriteLine("2️⃣ CACHING");
            Console.WriteLine("   Cache GeoIP lookups (80%+ hit rate expected)");
            Console.WriteLine("   Memoize expensive calculations");
            Console.WriteLine();
            
            Console.WriteLine("3️⃣ PARALLEL PROCESSING");
            Console.WriteLine("   Use all CPU cores effectively");
            Console.WriteLine("   Pipeline stages can run concurrently");
            Console.WriteLine();
            
            Console.WriteLine("4️⃣ MEMORY OPTIMIZATION");
            Console.WriteLine("   Object pooling reduces GC pressure");
            Console.WriteLine("   Span<T> for zero-allocation string operations");
            Console.WriteLine();
            
            Console.WriteLine("5️⃣ VECTORIZATION");
            Console.WriteLine("   Process multiple data points simultaneously");
            Console.WriteLine("   AVX2 can process 32 bytes at once");
            Console.WriteLine();
            
            Console.WriteLine("6️⃣ NATIVE INTEGRATION");
            Console.WriteLine("   Skip JSON parsing overhead");
            Console.WriteLine("   Direct binary data processing");
            Console.WriteLine();
            
            Console.WriteLine("💡 Remember: Measure → Optimize → Verify → Repeat");
        }
    }
}