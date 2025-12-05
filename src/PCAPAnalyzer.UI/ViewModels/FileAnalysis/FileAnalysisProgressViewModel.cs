using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels.FileAnalysis;

/// <summary>
/// Manages progress tracking, metrics updates, and stage status synchronization.
/// Extracted from FileAnalysisViewModel to handle:
/// - Real-time progress metrics (packets, bytes, PPS)
/// - Throttled stage notifications
/// - ProgressCoordinator integration
/// - QuickStats updates from analysis results
/// </summary>
public partial class FileAnalysisProgressViewModel : ObservableObject
{
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    // ==================== THROTTLING ====================
    private long _lastStagesNotifyTicks;
    private const int STAGES_NOTIFY_THROTTLE_MS = 100;
    private int _lastLoggedProgress = -1;

    // Reference to stages collection (owned by parent)
    private ObservableCollection<AnalysisProgressStage>? _stages;

    // ==================== REAL-TIME METRICS ====================

    [ObservableProperty] private long _packetsProcessed;
    [ObservableProperty] private long _totalPacketsInFile;
    [ObservableProperty] private long _packetsPerSecond;
    [ObservableProperty] private string _totalBytesFormatted = "0 B";
    [ObservableProperty] private string _totalFileSizeFormatted = "0 B";
    [ObservableProperty] private TimeSpan _elapsedTime;
    [ObservableProperty] private string _remainingTimeFormatted = "Calculating...";
    [ObservableProperty] private double _progressPercentage;

    // ==================== QUICK STATS ====================

    [ObservableProperty] private QuickStatsModel _quickStats = new();

    partial void OnQuickStatsChanged(QuickStatsModel value)
    {
        DebugLogger.Log($"[FileAnalysisProgressViewModel] QuickStats replaced - TotalPackets: {value.TotalPackets:N0}");
    }

    // ==================== STAGE TIMING ====================

    [ObservableProperty] private TimeSpan _readingDuration = TimeSpan.Zero;
    [ObservableProperty] private TimeSpan _parsingDuration = TimeSpan.Zero;
    [ObservableProperty] private TimeSpan _statisticsDuration = TimeSpan.Zero;
    [ObservableProperty] private TimeSpan _finalizingDuration = TimeSpan.Zero;

    /// <summary>
    /// Initialize with reference to stages collection from parent ViewModel.
    /// </summary>
    public void SetStagesCollection(ObservableCollection<AnalysisProgressStage> stages)
    {
        _stages = stages;
    }

    /// <summary>
    /// Notify UI of Stages collection changes with throttling.
    /// Uses Interlocked for thread-safe check-and-update.
    /// </summary>
    public void NotifyStagesChangedThrottled()
    {
        var nowTicks = DateTime.UtcNow.Ticks;
        var lastTicks = Interlocked.Read(ref _lastStagesNotifyTicks);
        var elapsedMs = (nowTicks - lastTicks) / TimeSpan.TicksPerMillisecond;

        if (elapsedMs >= STAGES_NOTIFY_THROTTLE_MS)
        {
            if (Interlocked.CompareExchange(ref _lastStagesNotifyTicks, nowTicks, lastTicks) == lastTicks)
            {
                OnPropertyChanged(nameof(Stages));
            }
        }
    }

    /// <summary>
    /// Notify UI of Stages collection changes immediately (for completion events).
    /// </summary>
    public void NotifyStagesChangedImmediate()
    {
        Interlocked.Exchange(ref _lastStagesNotifyTicks, DateTime.UtcNow.Ticks);
        OnPropertyChanged(nameof(Stages));
    }

    /// <summary>
    /// Expose stages for property change notification (references parent's collection)
    /// </summary>
    public ObservableCollection<AnalysisProgressStage>? Stages => _stages;

    /// <summary>
    /// Reset all progress metrics to initial state.
    /// </summary>
    public void ResetMetrics()
    {
        PacketsProcessed = 0;
        PacketsPerSecond = 0;
        TotalBytesFormatted = "0 B";
        ElapsedTime = TimeSpan.Zero;
        ProgressPercentage = 0;
        RemainingTimeFormatted = "Calculating...";
        _lastLoggedProgress = -1;
    }

    /// <summary>
    /// Handle progress updates from ProgressCoordinator.
    /// Updates UI with accurate 0-100% progress, stage names, real-time stats, and ETA.
    /// </summary>
    public void OnProgressUpdate(AnalysisProgress progress)
    {
        Dispatcher.Post(() =>
        {
            // Update accurate progress (0-100% from ProgressCoordinator)
            ProgressPercentage = progress.Percent;

            // Update real-time stats
            if (progress.PacketsAnalyzed > 0)
                PacketsProcessed = progress.PacketsAnalyzed;

            if (progress.TotalPackets > 0)
                TotalPacketsInFile = progress.TotalPackets;

            if (progress.PacketsPerSecond > 0)
                PacketsPerSecond = progress.PacketsPerSecond;

            // Update ETA
            if (progress.RemainingTime.TotalSeconds > 0)
            {
                RemainingTimeFormatted = progress.RemainingTime.TotalSeconds < 60
                    ? $"{progress.RemainingTime.TotalSeconds:F0}s remaining"
                    : $"{progress.RemainingTime.TotalMinutes:F1}m remaining";
            }
            else
            {
                RemainingTimeFormatted = "Calculating...";
            }

            OnPropertyChanged(nameof(RemainingTimeFormatted));

            // Update stage status based on ProgressCoordinator phase
            UpdateStageStatusFromProgress(progress);

            // Log only at major milestones (every 10%)
            var progressInt = (int)progress.Percent;
            if (progressInt % 10 == 0 && progressInt != _lastLoggedProgress)
            {
                _lastLoggedProgress = progressInt;
                DebugLogger.Log($"[Progress] {progress.Percent:F1}% | {progress.Phase}");
            }
        });
    }

    /// <summary>
    /// Map overall progress percentage to UI stages and update their state.
    /// </summary>
    private void UpdateStageStatusFromProgress(AnalysisProgress progress)
    {
        if (_stages == null) return;

        bool stagesMutated = false;

        var (activeStageKey, stageRelativePercent) = ProgressCoordinator.GetActiveStageFromOverall(progress.Percent);

        if (activeStageKey != null)
        {
            var stage = _stages.FirstOrDefault(s => s.Key == activeStageKey);
            if (stage != null)
            {
                var wasActive = stage.State == AnalysisStageState.Active;

                if (stage.State != AnalysisStageState.Completed)
                {
                    stage.State = AnalysisStageState.Active;
                    stagesMutated = true;

                    if (!wasActive)
                    {
                        stage.StartTiming();
                        DebugLogger.Log($"[FileAnalysisProgressViewModel] Stage '{stage.Name}' activated (overall: {progress.Percent:F1}%)");
                    }
                }

                stage.PercentComplete = stageRelativePercent;
                stage.Detail = progress.Detail;
                stagesMutated = true;
                stage.UpdateElapsedTime();
            }

            // Mark previous stages as completed
            var currentStageIndex = _stages.ToList().FindIndex(s => s.Key == activeStageKey);
            if (currentStageIndex >= 0)
            {
                for (int i = 0; i < currentStageIndex; i++)
                {
                    if (_stages[i].State != AnalysisStageState.Completed)
                    {
                        // ✅ FIX: Only StopTiming if stage was Active (had StartTiming called)
                        // Stages that were Pending (skipped) should not call StopTiming
                        if (_stages[i].State == AnalysisStageState.Active)
                        {
                            _stages[i].StopTiming();
                        }
                        _stages[i].State = AnalysisStageState.Completed;
                        _stages[i].PercentComplete = 100;
                        stagesMutated = true;
                    }
                }
            }
        }

        // Special handling for Complete phase
        // ✅ FIX: Skip "Building Views" stage - it's handled separately by ReportTabLoadingProgress/CompleteAnalysis
        if (progress.Phase == "Complete" || progress.Percent >= 100)
        {
            foreach (var stage in _stages)
            {
                // Skip "views" stage - Building Views is managed by ReportTabLoadingProgress and CompleteAnalysis
                if (stage.Key == "views") continue;

                if (stage.State != AnalysisStageState.Completed)
                {
                    // ✅ FIX: Only StopTiming if stage was Active (had StartTiming called)
                    if (stage.State == AnalysisStageState.Active)
                    {
                        stage.StopTiming();
                    }
                    stage.State = AnalysisStageState.Completed;
                    stage.PercentComplete = 100;
                    stagesMutated = true;
                }
            }
        }

        if (stagesMutated)
        {
            if (progress.Phase == "Complete" || progress.Percent >= 100)
                NotifyStagesChangedImmediate();
            else
                NotifyStagesChangedThrottled();
        }
    }

    /// <summary>
    /// Update QuickStats model from AnalysisResult after analysis completes.
    /// </summary>
    public void UpdateQuickStatsFromResult(AnalysisResult result)
    {
        DebugLogger.Log($"[FileAnalysisProgressViewModel] UpdateQuickStatsFromResult - TotalPackets: {result.TotalPackets:N0}");

        Dispatcher.Post(() =>
        {
            QuickStats.TotalPackets = result.TotalPackets;
            TotalPacketsInFile = result.TotalPackets;

            QuickStats.TotalTrafficMB = result.TotalBytes / (1024.0 * 1024.0);
            TotalBytesFormatted = NumberFormatter.FormatBytes(result.TotalBytes);

            QuickStats.UniqueIPs = result.Statistics.AllUniqueIPs?.Count ?? 0;
            QuickStats.UniquePorts = result.Statistics.UniquePortCount;
            QuickStats.Conversations = result.Statistics.TopConversations?.Count ?? 0;
            QuickStats.Threats = result.Threats.Count;
            QuickStats.UniqueProtocols = result.Statistics.ProtocolStats?.Count ?? 0;
            QuickStats.Countries = result.CountryTraffic?.Count ?? 0;

            if (result.AnalysisDuration.TotalSeconds > 0)
            {
                QuickStats.ProcessingRate = (long)(result.TotalPackets / result.AnalysisDuration.TotalSeconds);
                PacketsPerSecond = QuickStats.ProcessingRate;
            }

            ElapsedTime = result.AnalysisDuration;
            DebugLogger.Log($"[FileAnalysisProgressViewModel] QuickStats updated - Rate: {QuickStats.ProcessingRate:N0} pps");
        });
    }

    /// <summary>
    /// Update real-time packet processing progress during analysis.
    /// </summary>
    public void UpdatePacketProcessingProgress(int currentCount, long currentBytes, long totalPackets, TimeSpan elapsed)
    {
        var packetsProgress = (double)currentCount / totalPackets;
        var currentPps = (long)(currentCount / (elapsed.TotalSeconds + 0.01));

        Dispatcher.Post(() =>
        {
            PacketsProcessed = currentCount;
            PacketsPerSecond = currentPps;
            TotalBytesFormatted = NumberFormatter.FormatBytes(currentBytes);
        });
    }
}
