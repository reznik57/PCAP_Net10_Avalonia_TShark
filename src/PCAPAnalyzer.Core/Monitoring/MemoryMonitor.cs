using System;
using System.Diagnostics;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Monitoring
{
    /// <summary>
    /// Monitors memory usage and reports on optimization effectiveness
    /// </summary>
    public static class MemoryMonitor
    {
        private static readonly Process _process = Process.GetCurrentProcess();
        private static long _peakMemory;
        private static long _lastMemory;
        private static DateTime _lastGC = DateTime.Now;
        private static TimeProvider _timeProvider = TimeProvider.System;

        /// <summary>
        /// Sets the TimeProvider for testing purposes.
        /// </summary>
        internal static void SetTimeProvider(TimeProvider timeProvider)
        {
            _timeProvider = timeProvider ?? TimeProvider.System;
            _lastGC = _timeProvider.GetLocalNow().DateTime;
        }

        public static void CheckMemory(string context)
        {
            _process.Refresh();
            var currentMemory = _process.WorkingSet64 / (1024 * 1024);
            var privateMB = _process.PrivateMemorySize64 / (1024 * 1024);
            var gcMemory = GC.GetTotalMemory(false) / (1024 * 1024);

            if (currentMemory > _peakMemory)
            {
                _peakMemory = currentMemory;
            }

            var change = currentMemory - _lastMemory;
            var changeStr = change > 0 ? $"+{change}" : change.ToString();

            DebugLogger.Log($"[MEMORY] {context}");
            DebugLogger.Log($"  Working Set: {currentMemory}MB ({changeStr}MB) | Peak: {_peakMemory}MB");
            DebugLogger.Log($"  Private: {privateMB}MB | GC Heap: {gcMemory}MB");
            DebugLogger.Log($"  Gen0: {GC.CollectionCount(0)} | Gen1: {GC.CollectionCount(1)} | Gen2: {GC.CollectionCount(2)}");

            // Check if we should suggest GC
            var now = _timeProvider.GetLocalNow().DateTime;
            if (currentMemory > 1000 && (now - _lastGC).TotalSeconds > 30)
            {
                DebugLogger.Log("  ⚠️ High memory - forcing garbage collection");
                ForceGarbageCollection();
                _lastGC = now;
            }

            _lastMemory = currentMemory;
        }
        
        public static void ForceGarbageCollection()
        {
            // ✅ PERF FIX: Use non-blocking GC to prevent UI freeze
            // NOTE: Don't measure "freed" - non-blocking GC completes asynchronously
            // so immediate measurement is meaningless (often shows negative/zero values)
            GC.Collect(2, GCCollectionMode.Optimized, blocking: false);
            GC.WaitForPendingFinalizers();
            GC.Collect(1, GCCollectionMode.Optimized, blocking: false);

            DebugLogger.Log("  GC requested (Gen2 Optimized, non-blocking)");
        }
        
        public static long GetCurrentMemoryMB()
        {
            _process.Refresh();
            return _process.WorkingSet64 / (1024 * 1024);
        }
        
        public static long GetPeakMemoryMB() => _peakMemory;
    }
}