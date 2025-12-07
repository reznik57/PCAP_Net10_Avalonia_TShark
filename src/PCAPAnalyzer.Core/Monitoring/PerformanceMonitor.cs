using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Monitoring
{
    /// <summary>
    /// Monitors application performance metrics without affecting data processing
    /// </summary>
    public class PerformanceMonitor : IDisposable
    {
        private static readonly Lazy<PerformanceMonitor> _instance = new(() => new PerformanceMonitor());
        public static PerformanceMonitor Instance => _instance.Value;

        private readonly ConcurrentDictionary<string, PerformanceMetric> _metrics = [];
        private readonly Timer _reportTimer;
        private readonly Process _currentProcess;
        private bool _isDisposed;

        // Performance thresholds
        public const double HighCpuThreshold = 80.0; // 80% CPU
        public const long HighMemoryThreshold = 500_000_000; // 500MB
        public const int SlowResponseThreshold = 1000; // 1 second

        public bool MonitoringEnabled { get; set; }

        private PerformanceMonitor()
        {
            _currentProcess = Process.GetCurrentProcess();
            _reportTimer = new Timer(GenerateReport, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30));
        }

        /// <summary>
        /// Start measuring a specific operation
        /// </summary>
        public IDisposable MeasureOperation(string operationName)
        {
            return new OperationTimer(this, operationName);
        }

        /// <summary>
        /// Record a metric value
        /// </summary>
        public void RecordMetric(string name, double value, string unit = "")
        {
            var metric = _metrics.GetOrAdd(name, _ => new PerformanceMetric(name, unit));
            metric.Record(value);
        }

        /// <summary>
        /// Get current CPU usage percentage
        /// </summary>
        public double GetCpuUsage()
        {
            try
            {
                // Note: This is a simplified CPU calculation
                return _currentProcess.TotalProcessorTime.TotalMilliseconds / Environment.TickCount * 100;
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Get current memory usage in bytes
        /// </summary>
        public long GetMemoryUsage()
        {
            try
            {
                _currentProcess.Refresh();
                return _currentProcess.WorkingSet64;
            }
            catch
            {
                return 0;
            }
        }

        /// <summary>
        /// Check if system is under pressure
        /// </summary>
        public bool IsUnderPressure()
        {
            if (!MonitoringEnabled)
                return false;

            return GetCpuUsage() > HighCpuThreshold || 
                   GetMemoryUsage() > HighMemoryThreshold;
        }

        /// <summary>
        /// Get summary of all metrics
        /// </summary>
        public PerformanceSummary GetSummary()
        {
            if (!MonitoringEnabled)
            {
                return new PerformanceSummary
                {
                    CpuUsage = 0,
                    MemoryUsage = GetMemoryUsage(),
                    Metrics = _metrics.Values.Select(m => m.GetSummary()).ToList(),
                    IsUnderPressure = false
                };
            }

            return new PerformanceSummary
            {
                CpuUsage = GetCpuUsage(),
                MemoryUsage = GetMemoryUsage(),
                Metrics = _metrics.Values.Select(m => m.GetSummary()).ToList(),
                IsUnderPressure = IsUnderPressure()
            };
        }

        private void GenerateReport(object? state)
        {
            if (_isDisposed) return;

            if (!MonitoringEnabled)
                return;

            var summary = GetSummary();

            // Log performance report
            DebugLogger.Log($"[PERF] CPU: {summary.CpuUsage:F1}%, Memory: {summary.MemoryUsage / 1_000_000}MB");
            
            if (summary.IsUnderPressure)
            {
                DebugLogger.Log("[PERF] ⚠️ System under pressure - consider optimization");
            }

            // Log slowest operations
            var slowOps = summary.Metrics
                .Where(m => m.Unit == "ms" && m.Average > SlowResponseThreshold)
                .OrderByDescending(m => m.Average)
                .Take(3);

            foreach (var op in slowOps)
            {
                DebugLogger.Log($"[PERF] Slow operation: {op.Name} - Avg: {op.Average:F0}ms, Max: {op.Max:F0}ms");
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_isDisposed) return;

            if (disposing)
            {
                // Dispose managed resources
                _reportTimer?.Dispose();
                _currentProcess?.Dispose();
            }

            _isDisposed = true;
        }

        private class OperationTimer : IDisposable
        {
            private readonly PerformanceMonitor _monitor;
            private readonly string _operationName;
            private readonly Stopwatch _stopwatch;

            public OperationTimer(PerformanceMonitor monitor, string operationName)
            {
                _monitor = monitor;
                _operationName = operationName;
                _stopwatch = Stopwatch.StartNew();
            }

            public void Dispose()
            {
                _stopwatch.Stop();
                _monitor.RecordMetric(_operationName, _stopwatch.ElapsedMilliseconds, "ms");
            }
        }
    }

    public class PerformanceMetric
    {
        private readonly Lock _lock = new();
        private readonly string _name;
        private readonly string _unit;
        private double _sum;
        private double _min = double.MaxValue;
        private double _max = double.MinValue;
        private int _count;

        public PerformanceMetric(string name, string unit)
        {
            _name = name;
            _unit = unit;
        }

        public void Record(double value)
        {
            using (_lock.EnterScope())
            {
                _sum += value;
                _count++;
                _min = Math.Min(_min, value);
                _max = Math.Max(_max, value);
            }
        }

        public MetricSummary GetSummary()
        {
            using (_lock.EnterScope())
            {
                return new MetricSummary
                {
                    Name = _name,
                    Unit = _unit,
                    Count = _count,
                    Average = _count > 0 ? _sum / _count : 0,
                    Min = _count > 0 ? _min : 0,
                    Max = _count > 0 ? _max : 0
                };
            }
        }
    }

    public class PerformanceSummary
    {
        public double CpuUsage { get; set; }
        public long MemoryUsage { get; set; }
        public List<MetricSummary> Metrics { get; set; } = [];
        public bool IsUnderPressure { get; set; }
    }

    public class MetricSummary
    {
        public string Name { get; set; } = "";
        public string Unit { get; set; } = "";
        public int Count { get; set; }
        public double Average { get; set; }
        public double Min { get; set; }
        public double Max { get; set; }
    }
}
