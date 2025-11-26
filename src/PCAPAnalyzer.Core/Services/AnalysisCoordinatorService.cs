using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Caching;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;
using PCAPAnalyzer.Core.Services.Cache;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Coordinates analysis orchestration and tab population.
/// Extracts ~600 lines of orchestration logic from MainWindowViewModel.
///
/// Responsibilities:
/// - Run analysis via AnalysisOrchestrator
/// - Populate all registered tabs from cached results
/// - Notify completion/failure via events
/// </summary>
public class AnalysisCoordinatorService : IAnalysisCoordinator
{
    private readonly AnalysisOrchestrator _orchestrator;
    private readonly IAnalysisCacheService? _cacheService;
    private readonly List<ITabPopulationTarget> _tabs = new();

    public event EventHandler<CoordinatorCompletedEventArgs>? AnalysisCompleted;
    public event EventHandler<CoordinatorFailedEventArgs>? AnalysisFailed;

    public AnalysisCoordinatorService(
        AnalysisOrchestrator orchestrator,
        IAnalysisCacheService? cacheService = null)
    {
        _orchestrator = orchestrator ?? throw new ArgumentNullException(nameof(orchestrator));
        _cacheService = cacheService;
    }

    /// <inheritdoc />
    public async Task<AnalysisResult> RunAnalysisAsync(
        string pcapPath,
        IProgress<AnalysisProgress>? progress = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(pcapPath))
            throw new ArgumentException("PCAP path cannot be null or empty", nameof(pcapPath));

        var stopwatch = Stopwatch.StartNew();
        DebugLogger.Log($"[AnalysisCoordinator] ========== ANALYSIS STARTED ==========");
        DebugLogger.Log($"[AnalysisCoordinator] File: {pcapPath}");

        try
        {
            // Clear session cache for fresh analysis
            SessionAnalysisCache.Clear();
            DebugLogger.Log("[AnalysisCoordinator] Session cache cleared");

            // Run orchestrator analysis
            var result = await _orchestrator.AnalyzeFileAsync(pcapPath, progress, ct);

            stopwatch.Stop();
            DebugLogger.Log($"[AnalysisCoordinator] Orchestrator complete in {stopwatch.Elapsed.TotalSeconds:F2}s");
            DebugLogger.Log($"[AnalysisCoordinator] Packets: {result.TotalPackets:N0}, Memory: {result.EstimatedMemoryGB:F2}GB");

            // Populate all registered tabs
            var tabStart = Stopwatch.StartNew();
            await PopulateTabsAsync(result);
            tabStart.Stop();
            DebugLogger.Log($"[AnalysisCoordinator] All tabs populated in {tabStart.ElapsedMilliseconds}ms");

            // Notify completion
            var totalDuration = stopwatch.Elapsed + tabStart.Elapsed;
            AnalysisCompleted?.Invoke(this, new CoordinatorCompletedEventArgs(result, totalDuration));

            DebugLogger.Log($"[AnalysisCoordinator] ========== ANALYSIS COMPLETE ({totalDuration.TotalSeconds:F2}s) ==========");
            return result;
        }
        catch (OperationCanceledException)
        {
            DebugLogger.Log("[AnalysisCoordinator] Analysis cancelled by user");
            AnalysisFailed?.Invoke(this, new CoordinatorFailedEventArgs("Analysis cancelled", null));
            throw;
        }
        catch (Exception ex)
        {
            DebugLogger.Critical($"[AnalysisCoordinator] Analysis failed: {ex.Message}");
            AnalysisFailed?.Invoke(this, new CoordinatorFailedEventArgs(ex.Message, ex));
            throw;
        }
    }

    /// <inheritdoc />
    public async Task PopulateTabsAsync(AnalysisResult result)
    {
        if (_tabs.Count == 0)
        {
            DebugLogger.Log("[AnalysisCoordinator] No tabs registered for population");
            return;
        }

        DebugLogger.Log($"[AnalysisCoordinator] Populating {_tabs.Count} tabs in parallel...");

        // Populate tabs in parallel for maximum performance
        var tasks = _tabs.Select(async tab =>
        {
            var sw = Stopwatch.StartNew();
            try
            {
                await tab.PopulateFromCacheAsync(result);
                DebugLogger.Log($"[AnalysisCoordinator] ✓ {tab.TabName} populated in {sw.ElapsedMilliseconds}ms");
            }
            catch (Exception ex)
            {
                DebugLogger.Critical($"[AnalysisCoordinator] ✗ {tab.TabName} population failed: {ex.Message}");
                // Don't throw - continue populating other tabs
            }
        });

        await Task.WhenAll(tasks);
    }

    /// <inheritdoc />
    public void RegisterTabs(params ITabPopulationTarget[] tabs)
    {
        _tabs.Clear();
        _tabs.AddRange(tabs.Where(t => t != null));
        DebugLogger.Log($"[AnalysisCoordinator] Registered {_tabs.Count} tabs: {string.Join(", ", _tabs.Select(t => t.TabName))}");
    }
}
