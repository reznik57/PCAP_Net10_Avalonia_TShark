using System;
using System.Diagnostics;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Monitoring
{
    public static class HealthMonitor
    {
        private static readonly Process _process = Process.GetCurrentProcess();
        private static DateTime _startTime;
        private static long _packetsProcessed;
        private static TimeProvider _timeProvider = TimeProvider.System;

        /// <summary>
        /// Sets the TimeProvider for testing purposes. Call before Initialize().
        /// </summary>
        internal static void SetTimeProvider(TimeProvider timeProvider)
        {
            _timeProvider = timeProvider ?? TimeProvider.System;
        }

        public static void Initialize()
        {
            _startTime = _timeProvider.GetLocalNow().DateTime;
            DebugLogger.Log($"[HEALTH] Monitor initialized at {_startTime:HH:mm:ss}");
        }

        public static void LogPacketProcessed()
        {
            _packetsProcessed++;
            // ✅ PERFORMANCE FIX: Reduced from 1K to 100K to minimize log spam
            if (_packetsProcessed % 100000 == 0)
            {
                LogStatus($"Processed {_packetsProcessed} packets");
            }
        }

        public static void LogStatus(string operation)
        {
            _process.Refresh();
            var memoryMB = _process.WorkingSet64 / (1024 * 1024);
            var now = _timeProvider.GetLocalNow().DateTime;
            var runtime = now - _startTime;

            DebugLogger.Log($"[{now:HH:mm:ss}] {operation}");
            DebugLogger.Log($"  Memory: {memoryMB}MB | Runtime: {runtime:hh\\:mm\\:ss} | Packets: {_packetsProcessed}");
            
            // Warning only - no action taken
            if (memoryMB > 1000)
            {
                DebugLogger.Log($"  ⚠️ Warning: High memory usage detected ({memoryMB}MB)");
            }
        }
        
        public static long GetPacketCount() => _packetsProcessed;
        public static long GetMemoryMB() => _process.WorkingSet64 / (1024 * 1024);
    }
}