using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using PCAPAnalyzer.Core.Performance;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace PCAPAnalyzer.PerformanceTests
{
    /// <summary>
    /// Performance benchmarks for PCAP processing components
    /// Run with: dotnet run -c Release --project tests/PCAPAnalyzer.PerformanceTests
    /// </summary>
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    [RankColumn]
    public class PerformanceBenchmarks
    {
        private byte[] _testData = Array.Empty<byte>();
        private ResultCache<string, byte[]>? _cache;
        private ObjectPool<byte[]>? _byteArrayPool;
        private string _testFilePath = string.Empty;

        [GlobalSetup]
        public void Setup()
        {
            // Create test data (1MB)
            _testData = new byte[1024 * 1024];
            new Random(42).NextBytes(_testData);

            // Create temporary test file
            _testFilePath = Path.GetTempFileName();
            File.WriteAllBytes(_testFilePath, _testData);

            // Initialize cache
            _cache = new ResultCache<string, byte[]>(maxCapacity: 1000);

            // Initialize object pool
            _byteArrayPool = new ObjectPool<byte[]>(
                () => new byte[4096],
                arr => Array.Clear(arr, 0, arr.Length),
                maxPoolSize: 100,
                preAllocate: 50
            );
        }

        [GlobalCleanup]
        public void Cleanup()
        {
            _cache?.Dispose();
            _byteArrayPool?.Dispose();

            if (File.Exists(_testFilePath))
            {
                File.Delete(_testFilePath);
            }
        }

        #region Result Cache Benchmarks

        [Benchmark(Description = "Cache: Write 1000 items")]
        public void CacheWrite()
        {
            for (int i = 0; i < 1000; i++)
            {
                _cache!.AddOrUpdate($"key_{i}", _testData);
            }
        }

        [Benchmark(Description = "Cache: Read 1000 items (100% hit rate)")]
        public void CacheRead()
        {
            // Pre-populate cache
            for (int i = 0; i < 1000; i++)
            {
                _cache!.AddOrUpdate($"key_{i}", _testData);
            }

            // Read all items
            for (int i = 0; i < 1000; i++)
            {
                _cache!.TryGetValue($"key_{i}", out _);
            }
        }

        [Benchmark(Description = "Cache: Mixed read/write")]
        public void CacheMixed()
        {
            for (int i = 0; i < 500; i++)
            {
                _cache!.AddOrUpdate($"key_{i}", _testData);
                _cache!.TryGetValue($"key_{i % 100}", out _);
            }
        }

        #endregion

        #region Memory-Mapped File Benchmarks

        [Benchmark(Description = "MemoryMapped: Read 1MB file")]
        public void MemoryMappedFileRead()
        {
            using var reader = new MemoryMappedFileReader(_testFilePath);
            var data = reader.ReadBlock(0, (int)reader.FileSize);
        }

        [Benchmark(Description = "MemoryMapped: Sequential chunks (64KB)")]
        public void MemoryMappedFileChunks()
        {
            using var reader = new MemoryMappedFileReader(_testFilePath);
            const int chunkSize = 64 * 1024;
            long offset = 0;

            while (offset < reader.FileSize)
            {
                int bytesToRead = (int)Math.Min(chunkSize, reader.FileSize - offset);
                var chunk = reader.ReadBlock(offset, bytesToRead);
                offset += bytesToRead;
            }
        }

        [Benchmark(Description = "Standard FileStream: Read 1MB")]
        public void StandardFileStreamRead()
        {
            var data = File.ReadAllBytes(_testFilePath);
        }

        #endregion

        #region Object Pool Benchmarks

        [Benchmark(Description = "ObjectPool: Rent/Return 10000 arrays")]
        public void ObjectPoolRentReturn()
        {
            for (int i = 0; i < 10000; i++)
            {
                var arr = _byteArrayPool!.Rent();
                // Simulate usage
                arr[0] = (byte)i;
                _byteArrayPool.Return(arr);
            }
        }

        [Benchmark(Description = "Direct allocation: 10000 arrays")]
        public void DirectAllocation()
        {
            for (int i = 0; i < 10000; i++)
            {
                var arr = new byte[4096];
                arr[0] = (byte)i;
                // Let GC collect
            }
        }

        [Benchmark(Description = "ObjectPool: Scoped usage")]
        public void ObjectPoolScoped()
        {
            for (int i = 0; i < 10000; i++)
            {
                using var pooled = _byteArrayPool!.RentScoped();
                pooled.Object[0] = (byte)i;
            }
        }

        #endregion

        #region Streaming Processor Benchmarks

        [Benchmark(Description = "StreamingProcessor: Process 10000 packets")]
        public async Task StreamingProcessorBenchmark()
        {
            using var processor = new StreamingPacketProcessor(maxConcurrency: 4, channelCapacity: 1000);

            processor.StartProcessing(async packet =>
            {
                // Simulate processing
                await Task.Delay(1);
                return new ProcessingResult { Success = true };
            });

            // Enqueue packets
            var tasks = Enumerable.Range(0, 10000).Select(i =>
                processor.EnqueuePacketAsync(new PacketData
                {
                    PacketNumber = i,
                    Timestamp = DateTime.UtcNow,
                    Data = _testData.AsMemory(0, 100)
                })
            );

            await Task.WhenAll(tasks);

            processor.CompleteAdding();
            await processor.WaitForCompletionAsync();
        }

        #endregion

        #region Performance Monitor Benchmarks

        [Benchmark(Description = "PerformanceMonitor: Record 10000 metrics")]
        public void PerformanceMonitorRecord()
        {
            var monitor = PerformanceMonitor.Instance;

            for (int i = 0; i < 10000; i++)
            {
                monitor.RecordMetric("test_metric", i * 0.1);
            }
        }

        [Benchmark(Description = "PerformanceMonitor: Time 1000 operations")]
        public void PerformanceMonitorTiming()
        {
            var monitor = PerformanceMonitor.Instance;

            for (int i = 0; i < 1000; i++)
            {
                using (monitor.Time("test_operation"))
                {
                    // Simulate work
                    var result = Math.Sqrt(i);
                }
            }
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
            var summary = BenchmarkDotNet.Running.BenchmarkRunner.Run<PerformanceBenchmarks>();

            Console.WriteLine("\n=== Benchmark Summary ===");
            Console.WriteLine($"Total benchmarks: {summary.Reports.Length}");
            Console.WriteLine($"Fastest: {summary.Reports.OrderBy(r => r.ResultStatistics?.Mean).First().BenchmarkCase.Descriptor.WorkloadMethodDisplayInfo}");
            Console.WriteLine($"Slowest: {summary.Reports.OrderByDescending(r => r.ResultStatistics?.Mean).First().BenchmarkCase.Descriptor.WorkloadMethodDisplayInfo}");
        }
    }
}
