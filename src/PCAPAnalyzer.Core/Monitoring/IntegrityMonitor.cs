using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Monitoring
{
    public static class IntegrityMonitor
    {
        private static readonly Dictionary<string, long> _counters = new();
        private static readonly object _lock = new();
        
        public static void Increment(string counter)
        {
            lock (_lock)
            {
                if (!_counters.ContainsKey(counter))
                    _counters[counter] = 0;
                _counters[counter]++;
            }
        }
        
        public static void Report()
        {
            lock (_lock)
            {
                DebugLogger.Log("\n[INTEGRITY] Data Flow Report:");
                DebugLogger.Log("==============================");
                foreach (var kvp in _counters)
                {
                    DebugLogger.Log($"  {kvp.Key}: {kvp.Value}");
                }
                
                // Check for data loss
                if (_counters.ContainsKey("PacketsReceived") && 
                    _counters.ContainsKey("PacketsProcessed"))
                {
                    var lost = _counters["PacketsReceived"] - _counters["PacketsProcessed"];
                    if (lost > 0)
                    {
                        DebugLogger.Log($"  ⚠️ WARNING: {lost} packets lost!");
                    }
                    else
                    {
                        DebugLogger.Log($"  ✅ No data loss detected");
                    }
                }
            }
        }
        
        public static long GetCounter(string name)
        {
            lock (_lock)
            {
                return _counters.ContainsKey(name) ? _counters[name] : 0;
            }
        }
    }
}