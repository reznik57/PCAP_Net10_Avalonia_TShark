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
            if (currentMemory > 1000 && (DateTime.Now - _lastGC).TotalSeconds > 30)
            {
                DebugLogger.Log("  ⚠️ High memory - forcing garbage collection");
                ForceGarbageCollection();
                _lastGC = DateTime.Now;
            }
            
            _lastMemory = currentMemory;
        }
        
        public static void ForceGarbageCollection()
        {
            var before = GC.GetTotalMemory(false) / (1024 * 1024);
            
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            
            var after = GC.GetTotalMemory(false) / (1024 * 1024);
            var freed = before - after;
            
            DebugLogger.Log($"  GC freed {freed}MB (Heap: {before}MB -> {after}MB)");
        }
        
        public static long GetCurrentMemoryMB()
        {
            _process.Refresh();
            return _process.WorkingSet64 / (1024 * 1024);
        }
        
        public static long GetPeakMemoryMB() => _peakMemory;
    }
}