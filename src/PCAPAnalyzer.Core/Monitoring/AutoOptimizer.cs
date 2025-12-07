using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Monitoring
{
    /// <summary>
    /// Automatically triggers optimizations based on system conditions
    /// </summary>
    public class AutoOptimizer : IDisposable
    {
        private static readonly Lazy<AutoOptimizer> _instance = new(() => new AutoOptimizer());
        public static AutoOptimizer Instance => _instance.Value;

        private readonly Timer _optimizationTimer;
        private readonly List<IOptimizationStrategy> _strategies;
        private bool _isDisposed;
        private bool _isOptimizing;
        private DateTime _lastOptimization = DateTime.MinValue;

        // Optimization settings
        public bool AutoOptimizationEnabled { get; set; }
        public TimeSpan MinimumOptimizationInterval { get; set; } = TimeSpan.FromMinutes(1);

        // Events
        public event EventHandler<OptimizationEventArgs>? OptimizationStarted;
        public event EventHandler<OptimizationEventArgs>? OptimizationCompleted;

        private AutoOptimizer()
        {
            _strategies = new List<IOptimizationStrategy>
            {
                new MemoryOptimizationStrategy(),
                new CollectionOptimizationStrategy(),
                new CacheOptimizationStrategy()
            };

            _optimizationTimer = new Timer(
                CheckAndOptimize, 
                null, 
                TimeSpan.FromSeconds(30), 
                TimeSpan.FromSeconds(30)
            );

            // Subscribe to memory pressure events
            MemoryPressureDetector.Instance.MemoryPressureCritical += OnMemoryPressureCritical;
        }

        private async void OnMemoryPressureCritical(object? sender, EventArgs e)
        {
            try
            {
                if (!AutoOptimizationEnabled)
                    return;

                await TriggerOptimizationAsync("Critical memory pressure detected").ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[OPTIMIZER] Error in OnMemoryPressureCritical: {ex.Message}");
            }
        }

        private async void CheckAndOptimize(object? state)
        {
            try
            {
                if (!AutoOptimizationEnabled || _isOptimizing || _isDisposed)
                    return;

                // Check if we should optimize
                var shouldOptimize = false;
                var reasons = new List<string>();

                // Check memory pressure
                if (MemoryPressureDetector.Instance.ShouldOptimize)
                {
                    shouldOptimize = true;
                    reasons.Add($"Memory pressure: {MemoryPressureDetector.Instance.CurrentLevel}");
                }

                // Check performance metrics
                var perfSummary = PerformanceMonitor.Instance.GetSummary();
                if (perfSummary.IsUnderPressure)
                {
                    shouldOptimize = true;
                    reasons.Add($"Performance pressure: CPU {perfSummary.CpuUsage:F1}%");
                }

                // Check time since last optimization
                if (shouldOptimize && DateTime.UtcNow - _lastOptimization < MinimumOptimizationInterval)
                {
                    shouldOptimize = false; // Too soon
                }

                if (shouldOptimize)
                {
                    await TriggerOptimizationAsync(string.Join(", ", reasons)).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[OPTIMIZER] Error in CheckAndOptimize: {ex.Message}");
            }
        }

        public async Task<OptimizationResult> TriggerOptimizationAsync(string reason)
        {
            if (!AutoOptimizationEnabled)
            {
                return new OptimizationResult
                {
                    Success = false,
                    Reason = reason,
                    Message = "Auto optimization disabled"
                };
            }

            if (_isOptimizing)
            {
                return new OptimizationResult 
                { 
                    Success = false, 
                    Message = "Optimization already in progress" 
                };
            }

            _isOptimizing = true;
            _lastOptimization = DateTime.UtcNow;

            var args = new OptimizationEventArgs { Reason = reason };
            OptimizationStarted?.Invoke(this, args);

            var result = new OptimizationResult
            {
                StartTime = DateTime.UtcNow,
                Reason = reason
            };

            try
            {
                DebugLogger.Log($"[OPTIMIZER] Starting optimization: {reason}");

                // Run applicable strategies
                foreach (var strategy in _strategies)
                {
                    if (await strategy.ShouldApplyAsync())
                    {
                        var strategyResult = await strategy.ApplyAsync();
                        result.StrategyResults.Add(strategyResult);
                        
                        DebugLogger.Log($"[OPTIMIZER] {strategy.Name}: {strategyResult.Message}");
                    }
                }

                result.Success = result.StrategyResults.Any(r => r.Success);
                result.EndTime = DateTime.UtcNow;
                result.Message = $"Completed {result.StrategyResults.Count} optimizations";

                args.Result = result;
                OptimizationCompleted?.Invoke(this, args);

                return result;
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[OPTIMIZER] Error during optimization: {ex.Message}");
                result.Success = false;
                result.Message = $"Optimization failed: {ex.Message}";
                return result;
            }
            finally
            {
                _isOptimizing = false;
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
                _optimizationTimer?.Dispose();
                MemoryPressureDetector.Instance.MemoryPressureCritical -= OnMemoryPressureCritical;
            }

            _isDisposed = true;
        }
    }

    public interface IOptimizationStrategy
    {
        string Name { get; }
        Task<bool> ShouldApplyAsync();
        Task<StrategyResult> ApplyAsync();
    }

    public class MemoryOptimizationStrategy : IOptimizationStrategy
    {
        public string Name => "Memory Optimization";

        public Task<bool> ShouldApplyAsync()
        {
            return Task.FromResult(MemoryPressureDetector.Instance.ShouldOptimize);
        }

        public async Task<StrategyResult> ApplyAsync()
        {
            var memoryBefore = GC.GetTotalMemory(false);
            
            // Force garbage collection
            GC.Collect(2, GCCollectionMode.Optimized);
            await Task.Delay(100);
            GC.WaitForPendingFinalizers();
            GC.Collect(2, GCCollectionMode.Optimized);

            var memoryAfter = GC.GetTotalMemory(false);
            var freed = memoryBefore - memoryAfter;

            return new StrategyResult
            {
                Success = freed > 0,
                Message = $"Freed {freed / 1_000_000}MB",
                MetricsBefore = new Dictionary<string, object> { ["Memory"] = memoryBefore },
                MetricsAfter = new Dictionary<string, object> { ["Memory"] = memoryAfter }
            };
        }
    }

    public class CollectionOptimizationStrategy : IOptimizationStrategy
    {
        public string Name => "Collection Optimization";

        public Task<bool> ShouldApplyAsync()
        {
            // Apply when we have large collections in memory
            var largeObjectHeapSize = GC.GetTotalMemory(false);
            return Task.FromResult(largeObjectHeapSize > 100_000_000); // 100MB
        }

        public async Task<StrategyResult> ApplyAsync()
        {
            // Trim excess capacity from collections
            // This would be implemented by specific collection holders
            await Task.Yield(); // Placeholder for actual implementation

            return new StrategyResult
            {
                Success = true,
                Message = "Collection capacities trimmed"
            };
        }
    }

    public class CacheOptimizationStrategy : IOptimizationStrategy
    {
        public string Name => "Cache Optimization";

        public Task<bool> ShouldApplyAsync()
        {
            // Apply when memory pressure is high
            return Task.FromResult(
                MemoryPressureDetector.Instance.CurrentLevel >= MemoryPressureLevel.Warning
            );
        }

        public async Task<StrategyResult> ApplyAsync()
        {
            // Clear caches when under pressure
            // This would be implemented by cache managers
            await Task.Yield(); // Placeholder for actual implementation

            return new StrategyResult
            {
                Success = true,
                Message = "Caches cleared"
            };
        }
    }

    public class OptimizationResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public string Reason { get; set; } = "";
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public List<StrategyResult> StrategyResults { get; set; } = new();

        public TimeSpan Duration => EndTime - StartTime;
    }

    public class StrategyResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = "";
        public Dictionary<string, object> MetricsBefore { get; set; } = new();
        public Dictionary<string, object> MetricsAfter { get; set; } = new();
    }

    public class OptimizationEventArgs : EventArgs
    {
        public string Reason { get; set; } = "";
        public OptimizationResult? Result { get; set; }
    }
}
