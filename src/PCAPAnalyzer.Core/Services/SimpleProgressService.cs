using System;
using System.Diagnostics;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Simple progress reporting service that works with existing models
    /// </summary>
    public sealed class SimpleProgressService
    {
        private readonly Stopwatch _stopwatch = new();
        private long _totalItems;
        private long _processedItems;
        private DateTime _lastReportTime = DateTime.MinValue;
        private readonly TimeSpan _reportInterval = TimeSpan.FromMilliseconds(500);
        
        public event EventHandler<ProgressEventArgs>? ProgressChanged;
        
        public void StartOperation(string operationName, long totalItems)
        {
            _totalItems = totalItems;
            _processedItems = 0;
            _stopwatch.Restart();
            
            DebugLogger.Log($"[PROGRESS] Starting {operationName}: {totalItems:N0} items");
            ReportProgress(operationName, 0, "Starting...");
        }
        
        public void UpdateProgress(string operationName, long itemsProcessed, long bytesProcessed = 0)
        {
            _processedItems += itemsProcessed;
            
            // Throttle progress reports
            var now = DateTime.UtcNow;
            if (now - _lastReportTime < _reportInterval && _processedItems < _totalItems)
                return;
            
            _lastReportTime = now;
            
            var percentage = _totalItems > 0 ? (_processedItems * 100.0) / _totalItems : 0;
            var elapsed = _stopwatch.Elapsed;
            var itemsPerSecond = elapsed.TotalSeconds > 0 ? _processedItems / elapsed.TotalSeconds : 0;
            var bytesPerSecond = elapsed.TotalSeconds > 0 && bytesProcessed > 0 ? bytesProcessed / elapsed.TotalSeconds : 0;
            
            var details = $"{_processedItems:N0}/{_totalItems:N0} items";
            if (itemsPerSecond > 0)
            {
                details += $" @ {itemsPerSecond:N0} items/s";
            }
            if (bytesPerSecond > 0)
            {
                details += $" ({NumberFormatter.FormatBytes((long)bytesPerSecond)}/s)";
            }

            ReportProgress(operationName, percentage, details);
        }
        
        public void CompleteOperation(string operationName)
        {
            _stopwatch.Stop();
            var elapsed = _stopwatch.Elapsed;
            var itemsPerSecond = elapsed.TotalSeconds > 0 ? _processedItems / elapsed.TotalSeconds : 0;
            
            var details = $"Completed {_processedItems:N0} items in {elapsed.TotalSeconds:F2}s @ {itemsPerSecond:N0} items/s";
            
            DebugLogger.Log($"[PROGRESS] Completed {operationName}: {details}");
            ReportProgress(operationName, 100, details);
        }
        
        private void ReportProgress(string operationName, double percentage, string details)
        {
            // Use the existing ProgressEventArgs structure
            var args = new ProgressEventArgs
            {
                PacketsProcessed = _processedItems,
                BytesProcessed = 0, // We don't track bytes in this simple version
                EstimatedMemoryUsage = 0
            };
            
            ProgressChanged?.Invoke(this, args);
            
            if (percentage > 0 && percentage < 100)
            {
                DebugLogger.Log($"[PROGRESS] {operationName}: {percentage:F1}% - {details}");
            }
        }
    }
}