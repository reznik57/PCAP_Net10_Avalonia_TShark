using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;

namespace PCAPAnalyzer.Core.Performance
{
    /// <summary>
    /// Central performance monitoring system for tracking application metrics
    /// PerformanceCounter is only available on Windows platforms.
    /// </summary>
    public sealed class PerformanceMonitor : IDisposable
    {
        private static readonly Lazy<PerformanceMonitor> _instance = new(() => new PerformanceMonitor());

        // Suppress CA1416 for the entire field - it's conditionally used based on platform checks
        [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
            Justification = "PerformanceCounter is conditionally used with OperatingSystem.IsWindows() checks")]
        private readonly ConcurrentDictionary<string, PerformanceCounter?> _counters = new();

        private readonly ConcurrentDictionary<string, List<PerformanceMetric>> _metrics = new();
        private readonly Lock _lock = new();
        private readonly bool _isWindowsPlatform = OperatingSystem.IsWindows();
        private bool _disposed;

        /// <summary>
        /// Gets the singleton instance of the performance monitor
        /// </summary>
        public static PerformanceMonitor Instance => _instance.Value;

        private PerformanceMonitor()
        {
            InitializeCounters();
        }

        /// <summary>
        /// Initializes performance counters (Windows only)
        /// On non-Windows platforms, counters are not initialized but metrics tracking still works
        /// </summary>
        private void InitializeCounters()
        {
            if (!_isWindowsPlatform)
            {
                Debug.WriteLine("PerformanceCounter is Windows-only. Performance counters disabled on this platform.");
                return;
            }

            // CPU and Memory counters (Windows only)
            RegisterCounter("CPU_Usage", "Processor", "% Processor Time", "_Total");
            RegisterCounter("Memory_Available", "Memory", "Available MBytes");
            RegisterCounter("Memory_Committed", "Memory", "Committed Bytes");

            // Application-specific counters (Windows only)
            RegisterCounter("GC_Collections_Gen0", ".NET CLR Memory", "# Gen 0 Collections", Process.GetCurrentProcess().ProcessName);
            RegisterCounter("GC_Collections_Gen1", ".NET CLR Memory", "# Gen 1 Collections", Process.GetCurrentProcess().ProcessName);
            RegisterCounter("GC_Collections_Gen2", ".NET CLR Memory", "# Gen 2 Collections", Process.GetCurrentProcess().ProcessName);
        }

        /// <summary>
        /// Registers a performance counter (Windows only)
        /// </summary>
        private void RegisterCounter(string name, string category, string counter, string? instance = null)
        {
            if (!_isWindowsPlatform)
            {
                return;
            }

            try
            {
                // PerformanceCounter is Windows-only
                if (OperatingSystem.IsWindows())
                {
                    var perfCounter = instance != null
                        ? new PerformanceCounter(category, counter, instance, true)
                        : new PerformanceCounter(category, counter, true);

                    _counters.TryAdd(name, perfCounter);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to register counter {name}: {ex.Message}");
            }
        }

        /// <summary>
        /// Starts timing an operation
        /// </summary>
        /// <param name="operationName">Name of the operation to time</param>
        /// <returns>A disposable timing context that automatically records the duration</returns>
        public IDisposable Time(string operationName)
        {
            return new TimingContext(this, operationName);
        }

        /// <summary>
        /// Records a metric value
        /// </summary>
        /// <param name="name">Metric name</param>
        /// <param name="value">Metric value</param>
        /// <param name="unit">Unit of measurement</param>
        public void RecordMetric(string name, double value, string unit = "ms")
        {
            var metric = new PerformanceMetric
            {
                Name = name,
                Value = value,
                Unit = unit,
                Timestamp = DateTime.UtcNow
            };

            _metrics.AddOrUpdate(
                name,
                _ => new List<PerformanceMetric> { metric },
                (_, list) =>
                {
                    using (_lock.EnterScope())
                    {
                        list.Add(metric);
                        // Keep only last 1000 measurements per metric
                        if (list.Count > 1000)
                        {
                            list.RemoveRange(0, list.Count - 1000);
                        }
                    }
                    return list;
                });
        }

        /// <summary>
        /// Gets current counter values (Windows only)
        /// Returns empty dictionary on non-Windows platforms
        /// </summary>
        /// <returns>Dictionary of counter names and their current values</returns>
        [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
            Justification = "Method checks platform and only accesses counters on Windows")]
        public Dictionary<string, float> GetCurrentCounters()
        {
            var results = new Dictionary<string, float>();

            if (!_isWindowsPlatform)
            {
                return results;
            }

            foreach (var kvp in _counters)
            {
                try
                {
                    // PerformanceCounter.NextValue() is Windows-only
                    if (OperatingSystem.IsWindows() && kvp.Value != null)
                    {
                        results[kvp.Key] = kvp.Value.NextValue();
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Failed to read counter {kvp.Key}: {ex.Message}");
                    results[kvp.Key] = 0;
                }
            }

            return results;
        }

        /// <summary>
        /// Gets statistics for a specific metric
        /// </summary>
        /// <param name="metricName">Name of the metric</param>
        /// <returns>Metric statistics or null if metric not found</returns>
        public MetricStatistics? GetMetricStatistics(string metricName)
        {
            if (!_metrics.TryGetValue(metricName, out var metricsList) || metricsList.Count == 0)
            {
                return null;
            }

            using (_lock.EnterScope())
            {
                var values = metricsList.Select(m => m.Value).ToList();

                return new MetricStatistics
                {
                    Name = metricName,
                    Count = values.Count,
                    Min = values.Min(),
                    Max = values.Max(),
                    Average = values.Average(),
                    Median = CalculateMedian(values),
                    Percentile95 = CalculatePercentile(values, 95),
                    Percentile99 = CalculatePercentile(values, 99),
                    StandardDeviation = CalculateStandardDeviation(values),
                    Unit = metricsList.First().Unit
                };
            }
        }

        /// <summary>
        /// Gets all recorded metrics
        /// </summary>
        /// <returns>Dictionary of metric names and their measurements</returns>
        public Dictionary<string, List<PerformanceMetric>> GetAllMetrics()
        {
            using (_lock.EnterScope())
            {
                return _metrics.ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.ToList()
                );
            }
        }

        /// <summary>
        /// Clears all recorded metrics
        /// </summary>
        public void ClearMetrics()
        {
            using (_lock.EnterScope())
            {
                _metrics.Clear();
            }
        }

        /// <summary>
        /// Generates a performance report
        /// </summary>
        /// <returns>Formatted performance report</returns>
        public string GenerateReport()
        {
            var report = new System.Text.StringBuilder();
            report.AppendLine("=== Performance Report ===");
            report.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            report.AppendLine();

            // Current counters
            report.AppendLine("Current System Metrics:");
            var counters = GetCurrentCounters();
            foreach (var kvp in counters.OrderBy(k => k.Key))
            {
                report.AppendLine($"  {kvp.Key}: {kvp.Value:F2}");
            }
            report.AppendLine();

            // Recorded metrics statistics
            report.AppendLine("Operation Statistics:");
            foreach (var metricName in _metrics.Keys.OrderBy(k => k))
            {
                var stats = GetMetricStatistics(metricName);
                if (stats != null)
                {
                    report.AppendLine($"  {stats.Name}:");
                    report.AppendLine($"    Count: {stats.Count}");
                    report.AppendLine($"    Min: {stats.Min:F2} {stats.Unit}");
                    report.AppendLine($"    Max: {stats.Max:F2} {stats.Unit}");
                    report.AppendLine($"    Avg: {stats.Average:F2} {stats.Unit}");
                    report.AppendLine($"    Median: {stats.Median:F2} {stats.Unit}");
                    report.AppendLine($"    P95: {stats.Percentile95:F2} {stats.Unit}");
                    report.AppendLine($"    P99: {stats.Percentile99:F2} {stats.Unit}");
                    report.AppendLine($"    StdDev: {stats.StandardDeviation:F2} {stats.Unit}");
                }
            }

            return report.ToString();
        }

        #region Statistical Calculations

        private static double CalculateMedian(List<double> values)
        {
            var sorted = values.OrderBy(v => v).ToList();
            int count = sorted.Count;

            if (count == 0) return 0;
            if (count % 2 == 0)
            {
                return (sorted[count / 2 - 1] + sorted[count / 2]) / 2.0;
            }
            return sorted[count / 2];
        }

        private static double CalculatePercentile(List<double> values, double percentile)
        {
            if (values.Count == 0) return 0;

            var sorted = values.OrderBy(v => v).ToList();
            double index = (percentile / 100.0) * (sorted.Count - 1);
            int lowerIndex = (int)Math.Floor(index);
            int upperIndex = (int)Math.Ceiling(index);

            if (lowerIndex == upperIndex)
            {
                return sorted[lowerIndex];
            }

            double lowerValue = sorted[lowerIndex];
            double upperValue = sorted[upperIndex];
            return lowerValue + (upperValue - lowerValue) * (index - lowerIndex);
        }

        private static double CalculateStandardDeviation(List<double> values)
        {
            if (values.Count < 2) return 0;

            double avg = values.Average();
            double sumOfSquares = values.Sum(v => Math.Pow(v - avg, 2));
            return Math.Sqrt(sumOfSquares / (values.Count - 1));
        }

        #endregion

        [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility",
            Justification = "Dispose checks platform before accessing Windows-only PerformanceCounters")]
        public void Dispose()
        {
            if (_disposed) return;

            // PerformanceCounter disposal is Windows-only
            if (OperatingSystem.IsWindows())
            {
                foreach (var counter in _counters.Values)
                {
                    counter?.Dispose();
                }
            }
            _counters.Clear();
            _metrics.Clear();

            _disposed = true;
        }

        #region Nested Classes

        /// <summary>
        /// Timing context for automatic duration recording
        /// </summary>
        private sealed class TimingContext : IDisposable
        {
            private readonly PerformanceMonitor _monitor;
            private readonly string _operationName;
            private readonly Stopwatch _stopwatch;

            public TimingContext(PerformanceMonitor monitor, string operationName)
            {
                _monitor = monitor;
                _operationName = operationName;
                _stopwatch = Stopwatch.StartNew();
            }

            public void Dispose()
            {
                _stopwatch.Stop();
                _monitor.RecordMetric(_operationName, _stopwatch.Elapsed.TotalMilliseconds, "ms");
            }
        }

        #endregion
    }

    /// <summary>
    /// Represents a performance metric measurement
    /// </summary>
    public sealed class PerformanceMetric
    {
        public string Name { get; init; } = string.Empty;
        public double Value { get; init; }
        public string Unit { get; init; } = string.Empty;
        public DateTime Timestamp { get; init; }
    }

    /// <summary>
    /// Statistics for a performance metric
    /// </summary>
    public sealed class MetricStatistics
    {
        public string Name { get; init; } = string.Empty;
        public int Count { get; init; }
        public double Min { get; init; }
        public double Max { get; init; }
        public double Average { get; init; }
        public double Median { get; init; }
        public double Percentile95 { get; init; }
        public double Percentile99 { get; init; }
        public double StandardDeviation { get; init; }
        public string Unit { get; init; } = string.Empty;
    }
}
