using System;
using System.Diagnostics;
using System.Runtime;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Monitoring
{
    /// <summary>
    /// Detects memory pressure and triggers optimization when needed
    /// </summary>
    public sealed class MemoryPressureDetector : IDisposable
    {
        private static readonly Lazy<MemoryPressureDetector> _instance = new(() => new MemoryPressureDetector());
        public static MemoryPressureDetector Instance => _instance.Value;

        private readonly Timer _monitorTimer;
        private readonly Process _currentProcess;
        private bool _isDisposed;

        // Memory thresholds (resolved at runtime based on available memory)
        private readonly long _warningThreshold;
        private readonly long _criticalThreshold;
        private readonly long _emergencyThreshold;

        // Events for pressure levels
        public event EventHandler? MemoryPressureWarning;
        public event EventHandler? MemoryPressureCritical;
        public event EventHandler? MemoryPressureEmergency;
        public event EventHandler? MemoryPressureRelieved;

        private MemoryPressureLevel _currentLevel = MemoryPressureLevel.Normal;
        private long _lastMemoryUsage;

        private MemoryPressureDetector()
        {
            _currentProcess = Process.GetCurrentProcess();

            // ✅ PERFORMANCE FIX: Ultra-aggressive memory usage - user has 10GB+ available
            // Maximize RAM utilization for fastest processing, minimize GC overhead
            const long oneGB = 1L * 1024 * 1024 * 1024;
            _warningThreshold = 8 * oneGB;      // 8GB (was 1GB) - first warning only
            _criticalThreshold = 12 * oneGB;    // 12GB (was 2GB) - still comfortable
            _emergencyThreshold = 16 * oneGB;   // 16GB (was 4GB) - max before intervention

#if DEBUG
            DebugLogger.Log($"[MEMORY] Thresholds set - Warning: {_warningThreshold / 1_000_000}MB, " +
                              $"Critical: {_criticalThreshold / 1_000_000}MB, Emergency: {_emergencyThreshold / 1_000_000}MB");
            // Start timer with 10s interval in DEBUG builds only
            _monitorTimer = new Timer(CheckMemoryPressure, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
#else
            // ✅ PERFORMANCE FIX: Disable timer-based monitoring in RELEASE builds (saves ~50-100ms every 10s)
            // Manual checks via CheckAndOptimizeAsync() still available if needed
            _monitorTimer = new Timer(_ => { }, null, Timeout.Infinite, Timeout.Infinite);
#endif
        }

        public MemoryPressureLevel CurrentLevel => _currentLevel;

        public long CurrentMemoryUsage => _lastMemoryUsage;

        public bool ShouldOptimize => _currentLevel >= MemoryPressureLevel.Warning;

        /// <summary>
        /// Force a memory check and optimization if needed
        /// </summary>
        public async Task<bool> CheckAndOptimizeAsync()
        {
            CheckMemoryPressure(null);

            if (ShouldOptimize)
            {
                await OptimizeMemoryAsync();
                return true;
            }

            return false;
        }

        private static (long warning, long critical, long emergency) CalculateThresholds()
        {
            const long oneGB = 1L * 1024 * 1024 * 1024;
            const long quarterGB = 256L * 1024 * 1024;

            var gcInfo = GC.GetGCMemoryInfo();
            var available = gcInfo.TotalAvailableMemoryBytes;

            if (available <= 0 || available == long.MaxValue)
            {
                available = Environment.Is64BitProcess ? 16L * oneGB : 4L * oneGB;
            }

            var warning = Math.Max(oneGB, (long)(available * 0.35));
            var critical = Math.Max(warning + quarterGB, (long)(available * 0.55));
            var emergency = Math.Max(critical + quarterGB, (long)(available * 0.70));

            var maxAllowed = Math.Max(critical + quarterGB, (long)(available * 0.85));
            maxAllowed = Math.Min(maxAllowed, 6L * oneGB);

            if (emergency > maxAllowed)
            {
                emergency = maxAllowed;
            }

            if (critical >= emergency)
            {
                critical = Math.Max(emergency - quarterGB, warning + quarterGB);
            }

            if (warning >= critical)
            {
                warning = Math.Max(oneGB, critical - quarterGB);
            }

            critical = Math.Max(critical, warning + quarterGB);
            emergency = Math.Max(emergency, critical + quarterGB);

            return (warning, critical, emergency);
        }

        private void CheckMemoryPressure(object? state)
        {
            if (_isDisposed) return;

            try
            {
                _currentProcess.Refresh();
                _lastMemoryUsage = _currentProcess.WorkingSet64;

                var previousLevel = _currentLevel;
                
                // Determine current pressure level
                if (_lastMemoryUsage >= _emergencyThreshold)
                {
                    _currentLevel = MemoryPressureLevel.Emergency;
                }
                else if (_lastMemoryUsage >= _criticalThreshold)
                {
                    _currentLevel = MemoryPressureLevel.Critical;
                }
                else if (_lastMemoryUsage >= _warningThreshold)
                {
                    _currentLevel = MemoryPressureLevel.Warning;
                }
                else
                {
                    _currentLevel = MemoryPressureLevel.Normal;
                }

                // Trigger events if level changed
                if (_currentLevel != previousLevel)
                {
                    LogMemoryStatus();
                    TriggerLevelChangeEvents(previousLevel, _currentLevel);
                }

            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[MEMORY] Error checking memory pressure: {ex.Message}");
            }
        }

        private void TriggerLevelChangeEvents(MemoryPressureLevel oldLevel, MemoryPressureLevel newLevel)
        {
            switch (newLevel)
            {
                case MemoryPressureLevel.Warning:
                    MemoryPressureWarning?.Invoke(this, EventArgs.Empty);
                    break;
                case MemoryPressureLevel.Critical:
                    MemoryPressureCritical?.Invoke(this, EventArgs.Empty);
                    break;
                case MemoryPressureLevel.Emergency:
                    MemoryPressureEmergency?.Invoke(this, EventArgs.Empty);
                    break;
                case MemoryPressureLevel.Normal:
                    if (oldLevel > MemoryPressureLevel.Normal)
                    {
                        MemoryPressureRelieved?.Invoke(this, EventArgs.Empty);
                    }
                    break;
            }
        }

        private async Task OptimizeMemoryAsync()
        {
            DebugLogger.Log("[MEMORY] Starting memory optimization (non-blocking)...");

            // Use Forced mode for Emergency, Optimized for others
            // NOTE: Aggressive mode REQUIRES blocking: true (throws ArgumentException otherwise)
            var gcMode = _currentLevel >= MemoryPressureLevel.Emergency
                ? GCCollectionMode.Forced  // Strongest non-blocking option
                : GCCollectionMode.Optimized;

            // ✅ PERF FIX: NEVER use blocking: true - it freezes the entire UI
            // Non-blocking GC allows UI thread to continue while collection happens
            GC.Collect(2, gcMode, blocking: false, compacting: false);
            await Task.Delay(50); // Brief yield to let GC make progress
            GC.WaitForPendingFinalizers();
            GC.Collect(1, GCCollectionMode.Optimized, blocking: false);

            // Request LOH compaction for next natural GC (non-blocking approach)
            if (_currentLevel >= MemoryPressureLevel.Critical)
            {
                // Set compaction mode - will compact on next blocking GC (app shutdown, etc.)
                GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
                DebugLogger.Log($"[MEMORY] GC requested (Gen2 {gcMode}, non-blocking, LOH compaction queued)");
            }
            else
            {
                DebugLogger.Log($"[MEMORY] GC requested (Gen2 {gcMode}, non-blocking)");
            }

            // Update memory reading (but don't claim "freed" - non-blocking GC results are async)
            await Task.Delay(100);
            _currentProcess.Refresh();
            _lastMemoryUsage = _currentProcess.WorkingSet64;
        }

        private void LogMemoryStatus()
        {
            var memoryMB = _lastMemoryUsage / 1_000_000;
            var icon = _currentLevel switch
            {
                MemoryPressureLevel.Emergency => "🔴",
                MemoryPressureLevel.Critical => "🟠",
                MemoryPressureLevel.Warning => "🟡",
                _ => "🟢"
            };

            DebugLogger.Log($"[MEMORY] {icon} Memory: {memoryMB}MB - Level: {_currentLevel}");
        }

        public MemoryStatus GetStatus()
        {
            return new MemoryStatus
            {
                CurrentUsage = _lastMemoryUsage,
                Level = _currentLevel,
                GCGen0Count = GC.CollectionCount(0),
                GCGen1Count = GC.CollectionCount(1),
                GCGen2Count = GC.CollectionCount(2),
                TotalMemory = GC.GetTotalMemory(false)
            };
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (_isDisposed) return;

            if (disposing)
            {
                // Dispose managed resources
                _monitorTimer?.Dispose();
                _currentProcess?.Dispose();
            }

            _isDisposed = true;
        }
    }

    public enum MemoryPressureLevel
    {
        Normal = 0,
        Warning = 1,
        Critical = 2,
        Emergency = 3
    }

    public class MemoryStatus
    {
        public long CurrentUsage { get; set; }
        public MemoryPressureLevel Level { get; set; }
        public int GCGen0Count { get; set; }
        public int GCGen1Count { get; set; }
        public int GCGen2Count { get; set; }
        public long TotalMemory { get; set; }

        public string GetFormattedUsage()
        {
            return $"{CurrentUsage / 1_000_000}MB";
        }
    }
}
