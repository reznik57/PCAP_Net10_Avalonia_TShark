using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Services.GeoIP;
using PCAPAnalyzer.Core.Services.Statistics;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Handles Dashboard-specific update logic and statistics computation.
/// Extracted from MainWindowViewModel to reduce file size.
/// </summary>
public class MainWindowDashboardViewModel : IDisposable
{
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    private readonly IStatisticsService _statisticsService;
    private readonly IGeoIPService _geoIpService;
    private readonly SemaphoreSlim _dashboardUpdateGate = new(1, 1);

    public MainWindowDashboardViewModel(IStatisticsService statisticsService, IGeoIPService geoIpService)
    {
        _statisticsService = statisticsService ?? throw new ArgumentNullException(nameof(statisticsService));
        _geoIpService = geoIpService ?? throw new ArgumentNullException(nameof(geoIpService));
    }

    /// <summary>
    /// Updates the Dashboard tab with latest statistics.
    /// PERFORMANCE: Uses cached data to avoid redundant re-analysis.
    /// </summary>
    public async Task UpdateDashboardAsync(
        DashboardViewModel? dashboardViewModel,
        MainWindowAnalysisViewModel analysis,
        MainWindowPacketViewModel packetManager,
        ITabFilterService packetAnalysisFilterService,
        ITabFilterService dashboardFilterService,
        bool forceUpdate = false)
    {
        var methodStart = DateTime.Now;
        DebugLogger.Log($"[{methodStart:HH:mm:ss.fff}] [UpdateDashboardAsync] ========== METHOD START ==========");

        if (!analysis.IsAnalysisComplete && !forceUpdate)
        {
            DebugLogger.Log("[DEBUG] Skipping dashboard update - analysis not complete");
            return;
        }

        // Skip if already loaded (unless forced)
        if (dashboardViewModel?.CurrentStatistics?.TotalPackets > 0 && !forceUpdate)
        {
            DebugLogger.Log("[UpdateDashboardAsync] Dashboard already loaded, skipping");
            return;
        }

        if (!await _dashboardUpdateGate.WaitAsync(TimeSpan.FromSeconds(10)))
        {
            DebugLogger.Critical("[WARNING] Dashboard update gate timeout");
            return;
        }

        try
        {
            // STEP 1: Build preliminary statistics
            var step1Start = DateTime.Now;
            DebugLogger.Log($"[{step1Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 1: Building preliminary statistics...");
            analysis.ReportTabProgress(analysis.GetDashboardStageKey(), 10, "Building preliminary statistics...");
            var preliminaryStats = analysis.FinalStatistics ?? analysis.StatisticsAggregator.BuildStatistics();
            var step1Elapsed = (DateTime.Now - step1Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 1 Complete in {step1Elapsed:F3}s");

            // STEP 2: Reference existing packets (MEMORY FIX)
            var step2Start = DateTime.Now;
            DebugLogger.Log($"[{step2Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 2: Referencing existing packet collection...");
            analysis.ReportTabProgress(analysis.GetDashboardStageKey(), 30, "Loading packet data...");

            List<PacketInfo> allPackets;
            if (packetManager.CachedDashboardPackets is not null && packetManager.CachedDashboardPackets.Count > 0)
            {
                allPackets = packetManager.CachedDashboardPackets;
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 2: Using cached {allPackets.Count:N0} packets");
            }
            else
            {
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 2: Cache empty, loading from store...");
                allPackets = await packetManager.LoadAllPacketsForDashboardAsync(preliminaryStats, CancellationToken.None).ConfigureAwait(false);
            }
            var step2Elapsed = (DateTime.Now - step2Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 2 Complete in {step2Elapsed:F3}s - {allPackets.Count:N0} packets");

            // STEP 3: GeoIP initialization
            var step3Start = DateTime.Now;
            DebugLogger.Log($"[{step3Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 3: Initializing GeoIP...");
            analysis.ReportTabProgress(analysis.GetDashboardStageKey(), 50, "Initializing GeoIP service...");
            await _geoIpService.InitializeAsync().ConfigureAwait(false);
            var step3Elapsed = (DateTime.Now - step3Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 3 Complete in {step3Elapsed:F3}s");

            // STEP 4: Compute or reuse statistics
            analysis.ReportTabProgress(analysis.GetDashboardStageKey(), 60, "Calculating statistics...");
            var (statistics, step4Elapsed) = await ComputeOrReuseStatisticsAsync(preliminaryStats, allPackets).ConfigureAwait(false);

            // GC after large operations
            PerformGarbageCollection();

            // STEP 5: Update DashboardViewModel
            var step5Start = DateTime.Now;
            DebugLogger.Log($"[{step5Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 5: Updating DashboardViewModel...");
            analysis.ReportTabProgress(analysis.GetDashboardStageKey(), 75, "Updating dashboard...");
            await Dispatcher.InvokeAsync(async () =>
            {
                if (dashboardViewModel is not null)
                {
                    await dashboardViewModel.UpdateStatistics(statistics, allPackets);
                }
            });
            var step5Elapsed = (DateTime.Now - step5Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 5 Complete in {step5Elapsed:F3}s");

            var totalElapsed = (DateTime.Now - methodStart).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] ========== COMPLETE in {totalElapsed:F3}s ==========");
            DebugLogger.Log($"[UpdateDashboardAsync] BREAKDOWN: Step1={step1Elapsed:F3}s, Step2={step2Elapsed:F3}s, Step3={step3Elapsed:F3}s, Step4={step4Elapsed:F3}s, Step5={step5Elapsed:F3}s");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[UpdateDashboardAsync] ERROR: {ex.Message}");
        }
        finally
        {
            _dashboardUpdateGate.Release();
        }
    }

    /// <summary>
    /// Computes or reuses network statistics (avoids redundant re-analysis).
    /// </summary>
    private async Task<(NetworkStatistics statistics, double elapsedSeconds)> ComputeOrReuseStatisticsAsync(
        NetworkStatistics? preliminaryStats,
        List<PacketInfo> allPackets)
    {
        var step4Start = DateTime.Now;

        var hasCompleteStats = preliminaryStats is not null &&
                               preliminaryStats.TotalPackets > 0 &&
                               preliminaryStats.CountryStatistics?.Count > 0;

        NetworkStatistics statistics;

        if (hasCompleteStats && allPackets.Count > 0)
        {
            DebugLogger.Log($"[{step4Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4: Using pre-calculated statistics");
            statistics = preliminaryStats!;

            if (statistics.CountryStatistics?.Count == 0)
            {
                DebugLogger.Log($"[{step4Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4: Enriching with GeoIP...");
                var enrichStart = DateTime.Now;
                statistics = await Task.Run(() => _statisticsService.CalculateStatistics(allPackets)).ConfigureAwait(false);
                var enrichElapsed = (DateTime.Now - enrichStart).TotalSeconds;
                DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4: GeoIP enrichment in {enrichElapsed:F3}s");
            }

            var elapsed = (DateTime.Now - step4Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4 Complete in {elapsed:F3}s (reused)");
            return (statistics, elapsed);
        }
        else if (allPackets.Count > 0)
        {
            DebugLogger.Log($"[{step4Start:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4: Running full analysis...");
            statistics = await Task.Run(() => _statisticsService.CalculateStatistics(allPackets)).ConfigureAwait(false);

            var elapsed = (DateTime.Now - step4Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4 Complete in {elapsed:F3}s");
            return (statistics, elapsed);
        }
        else
        {
            statistics = preliminaryStats ?? new NetworkStatistics();
            var elapsed = (DateTime.Now - step4Start).TotalSeconds;
            DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] [UpdateDashboardAsync] STEP 4 Skipped - no packets");
            return (statistics, elapsed);
        }
    }

    /// <summary>
    /// Aggressive GC to free memory after large operations.
    /// </summary>
    private static void PerformGarbageCollection()
    {
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] Running garbage collection...");
        var gcStart = DateTime.Now;
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var gcElapsed = (DateTime.Now - gcStart).TotalMilliseconds;
        DebugLogger.Log($"[{DateTime.Now:HH:mm:ss.fff}] GC completed in {gcElapsed:F0}ms");
    }

    public void Dispose()
    {
        _dashboardUpdateGate?.Dispose();
    }
}
