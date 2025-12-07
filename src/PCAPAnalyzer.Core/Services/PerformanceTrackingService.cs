using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace PCAPAnalyzer.Core.Services
{
    public enum StatisticsCalculationStage
    {
        Initialization,      // 0-5%
        PacketParsing,       // 5-25%
        GeoIPLookup,         // 25-60%
        ProtocolAnalysis,    // 60-75%
        ThreatDetection,     // 75-85%
        Aggregation,         // 85-95%
        Finalization        // 95-100%
    }

    public class CalculationProgress
    {
        public string OperationId { get; set; } = Guid.NewGuid().ToString();
        public StatisticsCalculationStage Stage { get; set; }
        public double StageProgress { get; set; }  // 0-100 within current stage
        public double OverallProgress { get; set; } // 0-100 overall
        public long ProcessedItems { get; set; }
        public long TotalItems { get; set; }
        public TimeSpan Elapsed { get; set; }
        public TimeSpan EstimatedRemaining { get; set; }
        public double ItemsPerSecond { get; set; }
        public string CurrentOperation { get; set; } = "";
        public Dictionary<string, double> Metrics { get; set; } = [];
        
        // Convenience properties
        public string ProgressText => $"{OverallProgress:F1}% - {CurrentOperation}";
        public string ThroughputText => $"{ItemsPerSecond:F0} items/sec";
        public string TimeRemainingText => EstimatedRemaining.TotalSeconds > 0 
            ? $"{EstimatedRemaining:mm\\:ss} remaining" 
            : "Calculating...";
    }

    public class PerformanceSnapshot
    {
        public DateTime Timestamp { get; set; }
        public string OperationId { get; set; } = "";
        public double PacketsPerSecond { get; set; }
        public double LookupsPerSecond { get; set; }
        public double CacheHitRate { get; set; }
        public long MemoryUsageMB { get; set; }
        public double CpuUsagePercent { get; set; }
        public int ThreadCount { get; set; }
        public Dictionary<string, double> CustomMetrics { get; set; } = [];
    }

    public class BenchmarkResult
    {
        public string Operation { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public TimeSpan Duration { get; set; }
        public long ItemCount { get; set; }
        public double ItemsPerSecond { get; set; }
        public long MemoryUsedMB { get; set; }
        public int ThreadCount { get; set; }
        public double CpuUsage { get; set; }
        public Dictionary<StatisticsCalculationStage, TimeSpan> StageDurations { get; set; } = [];
        
        public string Summary => $"{Operation}: {ItemCount:N0} items in {Duration.TotalSeconds:F2}s " +
                                 $"({ItemsPerSecond:F0}/sec) using {MemoryUsedMB}MB";
    }

    public interface IPerformanceTrackingService
    {
        // Progress reporting
        IProgress<CalculationProgress> CreateProgressReporter(string operationId);
        void UpdateProgress(string operationId, CalculationProgress progress);
        
        // Performance metrics
        void RecordMetric(string operationId, string metric, double value, string unit = "");
        PerformanceSnapshot GetSnapshot(string operationId);
        IEnumerable<PerformanceSnapshot> GetHistory(string operationId, TimeSpan duration);
        
        // Benchmarking
        IDisposable StartBenchmark(string operation);
        void CompleteBenchmark(string operation, BenchmarkResult result);
        BenchmarkResult GetLatestBenchmark(string operation);
        IEnumerable<BenchmarkResult> GetBenchmarkHistory(string operation, int count = 10);
        
        // Analysis
        PerformanceRecommendations AnalyzePerformance(string operationId);
        string IdentifyBottleneck(string operationId);
    }

    public sealed class PerformanceTrackingService : IPerformanceTrackingService, IDisposable
    {
        private readonly ConcurrentDictionary<string, List<PerformanceSnapshot>> _snapshots = [];
        private readonly ConcurrentDictionary<string, List<BenchmarkResult>> _benchmarks = [];
        private readonly ConcurrentDictionary<string, CalculationProgress> _activeOperations = [];
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, double>> _metrics = [];
        private readonly Timer _metricsCollector;
        private Process _currentProcess;
        private bool _disposed;

        public PerformanceTrackingService()
        {
            _currentProcess = Process.GetCurrentProcess();
            
            // Start background metrics collection every second
            _metricsCollector = new Timer(CollectSystemMetrics, null, TimeSpan.Zero, TimeSpan.FromSeconds(1));
        }

        public IProgress<CalculationProgress> CreateProgressReporter(string operationId)
        {
            return new Progress<CalculationProgress>(progress =>
            {
                progress.OperationId = operationId;
                UpdateProgress(operationId, progress);
            });
        }

        public void UpdateProgress(string operationId, CalculationProgress progress)
        {
            _activeOperations[operationId] = progress;
            
            // Record snapshot
            var snapshot = new PerformanceSnapshot
            {
                Timestamp = DateTime.UtcNow,
                OperationId = operationId,
                PacketsPerSecond = progress.ItemsPerSecond,
                CacheHitRate = progress.Metrics.GetValueOrDefault("CacheHitRate", 0),
                MemoryUsageMB = GC.GetTotalMemory(false) / 1024 / 1024,
                ThreadCount = _currentProcess.Threads.Count,
                CustomMetrics = new Dictionary<string, double>(progress.Metrics)
            };
            
            _snapshots.AddOrUpdate(operationId, 
                new List<PerformanceSnapshot> { snapshot },
                (key, list) => 
                {
                    list.Add(snapshot);
                    // Keep only last 1000 snapshots per operation
                    if (list.Count > 1000)
                        list.RemoveAt(0);
                    return list;
                });
        }

        public void RecordMetric(string operationId, string metric, double value, string unit = "")
        {
            var metrics = _metrics.GetOrAdd(operationId, new ConcurrentDictionary<string, double>());
            
            // Update or accumulate metric
            metrics.AddOrUpdate(metric, value, (key, oldValue) =>
            {
                // For counters, accumulate; for gauges, replace
                if (metric.Contains("count", StringComparison.Ordinal) || metric.Contains("total", StringComparison.Ordinal))
                    return oldValue + value;
                return value;
            });
        }

        public PerformanceSnapshot GetSnapshot(string operationId)
        {
            if (_snapshots.TryGetValue(operationId, out var snapshots) && snapshots.Any())
            {
                return snapshots.Last();
            }
            
            return new PerformanceSnapshot { OperationId = operationId };
        }

        public IEnumerable<PerformanceSnapshot> GetHistory(string operationId, TimeSpan duration)
        {
            if (_snapshots.TryGetValue(operationId, out var snapshots))
            {
                var cutoff = DateTime.UtcNow - duration;
                return snapshots.Where(s => s.Timestamp > cutoff);
            }
            
            return Enumerable.Empty<PerformanceSnapshot>();
        }

        public IDisposable StartBenchmark(string operation)
        {
            return new BenchmarkScope(this, operation);
        }

        public void CompleteBenchmark(string operation, BenchmarkResult result)
        {
            _benchmarks.AddOrUpdate(operation,
                new List<BenchmarkResult> { result },
                (key, list) =>
                {
                    list.Add(result);
                    // Keep only last 100 benchmarks per operation
                    if (list.Count > 100)
                        list.RemoveAt(0);
                    return list;
                });
        }

        public BenchmarkResult GetLatestBenchmark(string operation)
        {
            if (_benchmarks.TryGetValue(operation, out var benchmarks) && benchmarks.Any())
            {
                return benchmarks.Last();
            }
            
            return new BenchmarkResult { Operation = operation };
        }

        public IEnumerable<BenchmarkResult> GetBenchmarkHistory(string operation, int count = 10)
        {
            if (_benchmarks.TryGetValue(operation, out var benchmarks))
            {
                return benchmarks.TakeLast(count);
            }
            
            return Enumerable.Empty<BenchmarkResult>();
        }

        public PerformanceRecommendations AnalyzePerformance(string operationId)
        {
            var recommendations = new PerformanceRecommendations
            {
                OperationId = operationId,
                Timestamp = DateTime.UtcNow
            };
            
            if (_activeOperations.TryGetValue(operationId, out var progress))
            {
                // Analyze cache hit rate
                var cacheHitRate = progress.Metrics.GetValueOrDefault("CacheHitRate", 0);
                if (cacheHitRate < 50)
                {
                    recommendations.AddRecommendation(
                        "Low Cache Hit Rate",
                        $"Cache hit rate is {cacheHitRate:F1}%. Consider pre-warming the cache or increasing cache size.",
                        PerformanceImpact.High);
                }
                
                // Analyze throughput
                var expectedThroughput = Environment.ProcessorCount * 100; // Expected packets/sec per core
                if (progress.ItemsPerSecond < expectedThroughput)
                {
                    recommendations.AddRecommendation(
                        "Low Throughput",
                        $"Processing {progress.ItemsPerSecond:F0} items/sec, expected {expectedThroughput:F0}. " +
                        "Check for synchronization bottlenecks or I/O blocking.",
                        PerformanceImpact.Medium);
                }
                
                // Analyze memory usage
                var memoryMB = progress.Metrics.GetValueOrDefault("MemoryMB", 0);
                if (memoryMB > 500)
                {
                    recommendations.AddRecommendation(
                        "High Memory Usage",
                        $"Using {memoryMB:F0}MB of memory. Consider streaming processing or reducing batch size.",
                        PerformanceImpact.Medium);
                }
                
                // Identify bottleneck stage
                recommendations.Bottleneck = IdentifyBottleneck(operationId);
            }
            
            return recommendations;
        }

        public string IdentifyBottleneck(string operationId)
        {
            if (_activeOperations.TryGetValue(operationId, out var progress))
            {
                // Simple heuristic based on current stage and progress rate
                var stageTime = progress.Elapsed.TotalSeconds * (progress.StageProgress / 100.0);
                
                return progress.Stage switch
                {
                    StatisticsCalculationStage.GeoIPLookup when progress.Metrics.GetValueOrDefault("CacheHitRate", 0) < 30 
                        => "GeoIP lookups (low cache hit rate)",
                    StatisticsCalculationStage.ThreatDetection when stageTime > 5 
                        => "Threat detection (complex rules)",
                    StatisticsCalculationStage.Aggregation when progress.ProcessedItems > 10000 
                        => "Data aggregation (large dataset)",
                    _ => $"Current stage: {progress.Stage}"
                };
            }
            
            return "Unable to determine";
        }

        private void CollectSystemMetrics(object? state)
        {
            try
            {
                _currentProcess.Refresh();
                
                // Collect metrics for all active operations
                foreach (var operation in _activeOperations.Keys)
                {
                    RecordMetric(operation, "system.memory.mb", GC.GetTotalMemory(false) / 1024 / 1024);
                    RecordMetric(operation, "system.threads", _currentProcess.Threads.Count);
                    RecordMetric(operation, "system.handles", _currentProcess.HandleCount);
                }
            }
            catch
            {
                // Ignore collection errors
            }
        }

        private class BenchmarkScope : IDisposable
        {
            private readonly PerformanceTrackingService _service;
            private readonly string _operation;
            private readonly Stopwatch _stopwatch;
            private readonly long _startMemory;
            private readonly Dictionary<StatisticsCalculationStage, DateTime> _stageStarts;

            public BenchmarkScope(PerformanceTrackingService service, string operation)
            {
                _service = service;
                _operation = operation;
                _stopwatch = Stopwatch.StartNew();
                _startMemory = GC.GetTotalMemory(false);
                _stageStarts = new Dictionary<StatisticsCalculationStage, DateTime>();
            }

            public void Dispose()
            {
                _stopwatch.Stop();
                
                var result = new BenchmarkResult
                {
                    Operation = _operation,
                    Timestamp = DateTime.UtcNow,
                    Duration = _stopwatch.Elapsed,
                    MemoryUsedMB = (GC.GetTotalMemory(false) - _startMemory) / 1024 / 1024,
                    ThreadCount = Process.GetCurrentProcess().Threads.Count
                };
                
                _service.CompleteBenchmark(_operation, result);
            }
        }

        private void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // Dispose managed resources
                _metricsCollector?.Dispose();
                _currentProcess?.Dispose();
            }
            // Dispose unmanaged resources (if any) here

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }

    public class PerformanceRecommendations
    {
        public string OperationId { get; set; } = "";
        public DateTime Timestamp { get; set; }
        public string Bottleneck { get; set; } = "";
        public List<PerformanceRecommendation> Recommendations { get; set; } = [];
        
        public void AddRecommendation(string title, string description, PerformanceImpact impact)
        {
            Recommendations.Add(new PerformanceRecommendation
            {
                Title = title,
                Description = description,
                Impact = impact
            });
        }
    }

    public class PerformanceRecommendation
    {
        public string Title { get; set; } = "";
        public string Description { get; set; } = "";
        public PerformanceImpact Impact { get; set; }
    }

    public enum PerformanceImpact
    {
        Low,
        Medium,
        High,
        Critical
    }
}