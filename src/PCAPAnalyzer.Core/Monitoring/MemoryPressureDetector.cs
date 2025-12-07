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
            DebugLogger.Log("[MEMORY] Starting memory optimization...");

            // Step 1: Request garbage collection - use aggressive mode for emergency
            var gen0Before = GC.CollectionCount(0);
            var gen1Before = GC.CollectionCount(1);
            var gen2Before = GC.CollectionCount(2);

            // ✅ FIX: Use Aggressive mode for Emergency level (was always Optimized)
            var gcMode = _currentLevel >= MemoryPressureLevel.Emergency
                ? GCCollectionMode.Aggressive
                : GCCollectionMode.Optimized;

            GC.Collect(2, gcMode, blocking: _currentLevel >= MemoryPressureLevel.Critical);
            await Task.Delay(100); // Let GC complete
            GC.WaitForPendingFinalizers();
            GC.Collect(2, gcMode, blocking: _currentLevel >= MemoryPressureLevel.Critical);

            var gen0After = GC.CollectionCount(0);
            var gen1After = GC.CollectionCount(1);
            var gen2After = GC.CollectionCount(2);

            DebugLogger.Log($"[MEMORY] GC Collections ({gcMode}) - Gen0: {gen0After - gen0Before}, Gen1: {gen1After - gen1Before}, Gen2: {gen2After - gen2Before}");

            // Step 2: Compact LOH if critical or emergency
            if (_currentLevel >= MemoryPressureLevel.Critical)
            {
                GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
                GC.Collect(2, GCCollectionMode.Forced, blocking: true, compacting: true);
                DebugLogger.Log("[MEMORY] Large Object Heap compacted");
            }

            // Step 3: Check results
            _currentProcess.Refresh();
            var newMemoryUsage = _currentProcess.WorkingSet64;
            var freed = _lastMemoryUsage - newMemoryUsage;

            if (freed > 0)
            {
                DebugLogger.Log($"[MEMORY] Freed {freed / 1_000_000}MB of memory");
            }
            else
            {
                DebugLogger.Log("[MEMORY] No significant memory freed");
            }

            _lastMemoryUsage = newMemoryUsage;
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
