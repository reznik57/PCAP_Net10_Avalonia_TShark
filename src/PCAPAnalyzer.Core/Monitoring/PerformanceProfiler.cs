using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PCAPAnalyzer.Core.Monitoring
{
    /// <summary>
    /// Profiles performance of different application components
    /// </summary>
    public class PerformanceProfiler : IDisposable
    {
        private static readonly Lazy<PerformanceProfiler> _instance = new(() => new PerformanceProfiler());
        public static PerformanceProfiler Instance => _instance.Value;

        private readonly ConcurrentDictionary<string, ProfileSection> _sections = [];
        private readonly Timer _reportTimer;
        private bool _isDisposed;

        // Configuration
        public bool EnableProfiling { get; set; } = true;
        public TimeSpan ReportInterval { get; set; } = TimeSpan.FromMinutes(1);
        public int MaxSectionsToTrack { get; set; } = 100;

        private PerformanceProfiler()
        {
            _reportTimer = new Timer(
                GenerateReport, 
                null, 
                ReportInterval, 
                ReportInterval
            );
        }

        /// <summary>
        /// Start profiling a section of code
        /// </summary>
        public IDisposable StartSection(string sectionName, Dictionary<string, object>? metadata = null)
        {
            if (!EnableProfiling)
                return new NoOpDisposable();

            return new SectionProfiler(this, sectionName, metadata);
        }

        /// <summary>
        /// Record a profiling measurement
        /// </summary>
        internal void RecordMeasurement(string sectionName, TimeSpan duration, Dictionary<string, object>? metadata)
        {
            var section = _sections.GetOrAdd(sectionName, _ => new ProfileSection(sectionName));
            section.RecordMeasurement(duration, metadata);

            // Limit number of sections tracked
            if (_sections.Count > MaxSectionsToTrack)
            {
                CleanupOldSections();
            }
        }

        /// <summary>
        /// Get profiling report for a specific section
        /// </summary>
        public ProfileReport? GetSectionReport(string sectionName)
        {
            if (_sections.TryGetValue(sectionName, out var section))
            {
                return section.GenerateReport();
            }
            return null;
        }

        /// <summary>
        /// Get overall profiling report
        /// </summary>
        public ProfilingReport GenerateFullReport()
        {
            var report = new ProfilingReport
            {
                GeneratedAt = DateTime.UtcNow,
                Sections = _sections.Values
                    .Select(s => s.GenerateReport())
                    .OrderByDescending(r => r.TotalTime)
                    .ToList()
            };

            return report;
        }

        private void GenerateReport(object? state)
        {
            if (_isDisposed || !EnableProfiling) return;

            var report = GenerateFullReport();
            
            // Log top sections
            DetailedLogger.Instance.Info("PROFILER", "=== Performance Profile Report ===");
            
            var topSections = report.Sections.Take(10);
            foreach (var section in topSections)
            {
                var message = $"{section.Name}: Calls={section.CallCount}, " +
                             $"Avg={section.AverageTime.TotalMilliseconds:F2}ms, " +
                             $"Max={section.MaxTime.TotalMilliseconds:F2}ms, " +
                             $"Total={section.TotalTime.TotalSeconds:F2}s";
                
                DetailedLogger.Instance.Info("PROFILER", message);
            }

            // Identify slow operations
            var slowOps = report.Sections
                .Where(s => s.MaxTime.TotalMilliseconds > 1000)
                .Take(5);

            if (slowOps.Any())
            {
                DetailedLogger.Instance.Warning("PROFILER", "Slow operations detected:");
                foreach (var op in slowOps)
                {
                    DetailedLogger.Instance.Warning("PROFILER", 
                        $"  {op.Name}: Max={op.MaxTime.TotalMilliseconds:F0}ms");
                }
            }
        }

        private void CleanupOldSections()
        {
            // Remove least used sections
            var sectionsToRemove = _sections
                .OrderBy(kvp => kvp.Value.LastAccessed)
                .Take(_sections.Count - MaxSectionsToTrack + 10)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var key in sectionsToRemove)
            {
                _sections.TryRemove(key, out _);
            }
        }

        public void Reset()
        {
            _sections.Clear();
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
            }

            _isDisposed = true;
        }

        private class ProfileSection
        {
            private readonly string _name;
            private readonly Lock _lock = new();
            private readonly List<ProfileMeasurement> _measurements = [];
            private DateTime _lastAccessed;

            public ProfileSection(string name)
            {
                _name = name;
                _lastAccessed = DateTime.UtcNow;
            }

            public DateTime LastAccessed => _lastAccessed;

            public void RecordMeasurement(TimeSpan duration, Dictionary<string, object>? metadata)
            {
                using (_lock.EnterScope())
                {
                    _lastAccessed = DateTime.UtcNow;

                    _measurements.Add(new ProfileMeasurement
                    {
                        Duration = duration,
                        Timestamp = DateTime.UtcNow,
                        Metadata = metadata
                    });

                    // Keep only recent measurements
                    if (_measurements.Count > 1000)
                    {
                        _measurements.RemoveRange(0, _measurements.Count - 1000);
                    }
                }
            }

            public ProfileReport GenerateReport()
            {
                using (_lock.EnterScope())
                {
                    if (_measurements.Count == 0)
                    {
                        return new ProfileReport { Name = _name };
                    }

                    var durations = _measurements.Select(m => m.Duration).ToList();

                    return new ProfileReport
                    {
                        Name = _name,
                        CallCount = _measurements.Count,
                        TotalTime = TimeSpan.FromTicks(durations.Sum(d => d.Ticks)),
                        AverageTime = TimeSpan.FromTicks((long)durations.Average(d => d.Ticks)),
                        MinTime = durations.Min(),
                        MaxTime = durations.Max(),
                        LastCall = _measurements.Last().Timestamp
                    };
                }
            }
        }

        private class ProfileMeasurement
        {
            public TimeSpan Duration { get; set; }
            public DateTime Timestamp { get; set; }
            public Dictionary<string, object>? Metadata { get; set; }
        }

        private class SectionProfiler : IDisposable
        {
            private readonly PerformanceProfiler _profiler;
            private readonly string _sectionName;
            private readonly Dictionary<string, object>? _metadata;
            private readonly Stopwatch _stopwatch;

            public SectionProfiler(PerformanceProfiler profiler, string sectionName, Dictionary<string, object>? metadata)
            {
                _profiler = profiler;
                _sectionName = sectionName;
                _metadata = metadata;
                _stopwatch = Stopwatch.StartNew();
            }

            public void Dispose()
            {
                _stopwatch.Stop();
                _profiler.RecordMeasurement(_sectionName, _stopwatch.Elapsed, _metadata);
            }
        }

        private class NoOpDisposable : IDisposable
        {
            public void Dispose() { }
        }
    }

    public class ProfileReport
    {
        public string Name { get; set; } = "";
        public int CallCount { get; set; }
        public TimeSpan TotalTime { get; set; }
        public TimeSpan AverageTime { get; set; }
        public TimeSpan MinTime { get; set; }
        public TimeSpan MaxTime { get; set; }
        public DateTime LastCall { get; set; }
    }

    public class ProfilingReport
    {
        public DateTime GeneratedAt { get; set; }
        public List<ProfileReport> Sections { get; set; } = [];

        public string GenerateTextReport()
        {
            var sb = new StringBuilder();
            sb.AppendLine("=== Performance Profiling Report ===");
            sb.AppendLine($"Generated: {GeneratedAt:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();
            sb.AppendLine("Top Sections by Total Time:");
            sb.AppendLine("Name                          | Calls  | Total (s) | Avg (ms) | Max (ms)");
            sb.AppendLine("------------------------------|--------|-----------|----------|----------");

            foreach (var section in Sections.Take(20))
            {
                sb.AppendLine($"{section.Name,-30}| {section.CallCount,6} | {section.TotalTime.TotalSeconds,9:F2} | {section.AverageTime.TotalMilliseconds,8:F2} | {section.MaxTime.TotalMilliseconds,8:F2}");
            }

            return sb.ToString();
        }
    }
}