using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels.FileAnalysis;

/// <summary>
/// Manages analysis stage lifecycle: initialization, reset, progress updates, and completion.
/// Extracted from FileAnalysisViewModel to handle the 7-stage analysis pipeline UI state.
/// </summary>
public partial class FileAnalysisStagesViewModel : ObservableObject
{
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    private MainWindowAnalysisViewModel? _analysisVm;
    private bool _isComplete; // Prevent late stage syncs after completion

    /// <summary>
    /// 7-stage analysis progress indicators with individual percentages and states.
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<AnalysisProgressStage> _stages = new();

    /// <summary>
    /// Event raised when stages collection changes (for parent to forward notifications)
    /// </summary>
    public event Action? StagesChanged;

    /// <summary>
    /// Set the MainWindowAnalysisViewModel reference for global progress overlay integration.
    /// </summary>
    public void SetAnalysisViewModel(MainWindowAnalysisViewModel analysisVm)
    {
        _analysisVm = analysisVm;
        DebugLogger.Log("[FileAnalysisStagesViewModel] Wired to MainWindowAnalysisViewModel");
    }

    /// <summary>
    /// Initialize analysis stages with meaningful technical progress names.
    /// Streamlined 4-stage pipeline for clarity and accuracy.
    /// Overall % ranges based on ProgressCoordinator.StageRanges (updated for capinfos).
    /// </summary>
    public void InitializeStages()
    {
        Stages.Clear();

        // Stage 0: Reading Capture (0-5% overall) - INSTANT with capinfos
        Stages.Add(new AnalysisProgressStage("read",
            "Reading Capture",
            "Getting packet count from PCAP header...",
            true));

        // Stage 1: Parsing Packets (5-55% overall) - Now takes bulk of time
        Stages.Add(new AnalysisProgressStage("parse",
            "Parsing Packets",
            "Decoding packet data via TShark...",
            true));

        // Stage 2: Analyzing Traffic (55-75% overall) - Statistics, GeoIP, threats, finalization
        Stages.Add(new AnalysisProgressStage("analyze",
            "Analyzing Traffic",
            "Computing statistics, GeoIP enrichment, and threat detection...",
            true));

        // Stage 3: Building Views (75-100% overall)
        Stages.Add(new AnalysisProgressStage("views",
            "Building Views",
            "Populating Dashboard, Threats, and analysis tabs...",
            true));
    }

    /// <summary>
    /// Reset all stages to Pending state for a NEW analysis.
    /// CRITICAL: Must reset ALL timing including completed stages!
    /// </summary>
    public void ResetStages()
    {
        DebugLogger.Log($"[FileAnalysisStagesViewModel] Resetting all stages for new analysis");

        _isComplete = false; // Allow new progress updates

        foreach (var stage in Stages)
        {
            stage.State = AnalysisStageState.Pending;
            stage.PercentComplete = 0;
            stage.Detail = stage.Description; // Reset detail to original description
            // CRITICAL FIX: Always reset timing for ALL stages when starting new analysis
            stage.ResetTiming();
        }

        StagesChanged?.Invoke();
    }

    /// <summary>
    /// Fully clear all stages (used by Clear button).
    /// Reinitializes stages to pristine state.
    /// </summary>
    public void ClearAllStages()
    {
        DebugLogger.Log($"[FileAnalysisStagesViewModel] Clearing all stages completely");

        // Stop all timers first
        foreach (var stage in Stages)
        {
            stage.ResetTiming();
        }

        // Reinitialize stages to pristine state
        InitializeStages();
        StagesChanged?.Invoke();
    }

    /// <summary>
    /// Update stage progress and timing, forwarding to global overlay when applicable.
    /// </summary>
    public void UpdateStageProgress(int stageIndex, AnalysisStageState state, int percentComplete, double overallProgress)
    {
        if (stageIndex >= Stages.Count) return;

        Dispatcher.Post(() =>
        {
            var stage = Stages[stageIndex];
            var previousState = stage.State;
            stage.State = state;
            stage.PercentComplete = percentComplete;

            if (state == AnalysisStageState.Active)
                stage.StartTiming();
            else if (state == AnalysisStageState.Completed)
                stage.StopTiming();

            // Log only at completion or major milestones
            if (state == AnalysisStageState.Completed || percentComplete == 0 || percentComplete == 100)
            {
                DebugLogger.Log($"[Stage] {stage.Name}: {previousState} → {state}, Progress: {percentComplete}%");
            }

            // Forward progress to global overlay for stages 0-3
            ForwardToGlobalOverlay(stageIndex, stage, state, percentComplete);

            StagesChanged?.Invoke();
        });
    }

    /// <summary>
    /// Report view building progress (Stage 3: 95-100%).
    /// Called by MainWindowViewModel during tab population.
    /// </summary>
    public void ReportTabLoadingProgress(int percentWithinStage, string message, Action<double>? updateOverallProgress = null)
    {
        if (Stages.Count < 4) return;

        Dispatcher.Post(() =>
        {
            var stage = Stages[3];
            var wasActive = stage.State == AnalysisStageState.Active;

            stage.State = AnalysisStageState.Active;
            stage.PercentComplete = percentWithinStage;

            if (!wasActive)
            {
                // Mark all previous stages (0-2) as completed before starting Building Views
                for (int i = 0; i < 3; i++)
                {
                    if (i < Stages.Count && Stages[i].State != AnalysisStageState.Completed)
                    {
                        // ✅ FIX: Only StopTiming if stage was Active (had StartTiming called)
                        if (Stages[i].State == AnalysisStageState.Active)
                        {
                            Stages[i].StopTiming();
                        }
                        Stages[i].State = AnalysisStageState.Completed;
                        Stages[i].PercentComplete = 100;
                    }
                }

                stage.StartTiming();
                DebugLogger.Log($"[FileAnalysisStagesViewModel] Stage 3 'Building Views' activated");
            }

            stage.UpdateElapsedTime();

            // Map 0-100% within stage to 95-100% overall
            updateOverallProgress?.Invoke(95 + (percentWithinStage * 0.05));

            StagesChanged?.Invoke();
            DebugLogger.Log($"[FileAnalysisStagesViewModel] Stage 3: {percentWithinStage}% - {message}");
        });
    }

    /// <summary>
    /// Complete entire analysis after all views built (Stage 3 done).
    /// </summary>
    public void CompleteAnalysis(Action? onComplete = null)
    {
        if (Stages.Count < 4) return;

        Dispatcher.Post(() =>
        {
            var stage = Stages[3];

            if (stage.State == AnalysisStageState.Active && !string.IsNullOrEmpty(stage.ElapsedTime))
            {
                stage.StopTiming();
            }

            stage.State = AnalysisStageState.Completed;
            stage.PercentComplete = 100;

            // ✅ FIX: Mark as complete to prevent late stage syncs
            _isComplete = true;

            StagesChanged?.Invoke();
            onComplete?.Invoke();

            DebugLogger.Log($"[FileAnalysisStagesViewModel] Analysis COMPLETE: All 4 stages finished");
        });
    }

    /// <summary>
    /// Synchronize stages from orchestrator/external source.
    /// Converts overall progress % to stage-relative % (0-100% within each stage).
    /// </summary>
    public void SyncStageFromOrchestrator(string phaseName, int percentComplete, string detail)
    {
        // ✅ FIX: Ignore late syncs after analysis is complete
        if (_isComplete) return;

        // Map orchestrator phases to 4-stage UI pipeline
        var phaseToStageKey = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Counting Packets", "read" },
            { "Reading Capture", "read" },
            { "Loading Packets", "parse" },
            { "Parsing Packets", "parse" },
            { "Analyzing Data", "analyze" },
            { "Analyzing Traffic", "analyze" },
            { "GeoIP Enrichment", "analyze" },
            { "Traffic Flow Analysis", "analyze" },
            { "Threat Detection", "analyze" },
            { "VoiceQoS Analysis", "analyze" },
            { "Finalizing", "analyze" },  // Merged into analyze
            { "Building Views", "views" },
            { "Loading Tabs", "views" },
            { "Complete", "views" }
        };

        // UI stage ranges (overall % → stage-relative %)
        // Based on ProgressCoordinator.StageRanges (updated for capinfos instant counting)
        var stageRanges = new Dictionary<string, (int Start, int End)>
        {
            { "read",    (0, 5) },     // Counting: 0-5% (instant with capinfos)
            { "parse",   (5, 55) },    // Loading: 5-55% (now bulk of time)
            { "analyze", (55, 75) },   // Stats+GeoIP+Flows+Finalize: 55-75%
            { "views",   (75, 100) }   // Tab loading: 75-100%
        };

        if (phaseToStageKey.TryGetValue(phaseName, out var stageKey))
        {
            var stage = Stages.FirstOrDefault(s => s.Key == stageKey);
            if (stage != null)
            {
                Dispatcher.Post(() =>
                {
                    if (stage.State != AnalysisStageState.Completed)
                    {
                        stage.State = AnalysisStageState.Active;
                        stage.StartTiming();
                    }

                    // ✅ FIX: Convert overall % to stage-relative % (0-100% within stage)
                    int stageRelativePercent = percentComplete;
                    if (stageRanges.TryGetValue(stageKey, out var range))
                    {
                        if (percentComplete < range.Start)
                            stageRelativePercent = 0;
                        else if (percentComplete >= range.End)
                            stageRelativePercent = 100;
                        else
                        {
                            var progress = (double)(percentComplete - range.Start) / (range.End - range.Start);
                            stageRelativePercent = Math.Min(100, Math.Max(0, (int)(progress * 100)));
                        }
                    }

                    stage.PercentComplete = stageRelativePercent;
                    stage.Detail = detail;
                    stage.UpdateElapsedTime();

                    // Mark previous stages as completed
                    var currentIndex = Stages.ToList().FindIndex(s => s.Key == stageKey);
                    if (currentIndex > 0)
                    {
                        for (int i = 0; i < currentIndex; i++)
                        {
                            if (Stages[i].State != AnalysisStageState.Completed)
                            {
                                Stages[i].State = AnalysisStageState.Completed;
                                Stages[i].PercentComplete = 100;
                                Stages[i].StopTiming();
                            }
                        }
                    }

                    StagesChanged?.Invoke();
                    DebugLogger.Log($"[FileAnalysisStagesViewModel] Stage synced: {stage.Name} overall={percentComplete}% → stage={stageRelativePercent}%");
                });
            }
        }
    }

    /// <summary>
    /// Get GeoIP stage reference for statistics service timing.
    /// Returns null - GeoIP is now consolidated into "Analyzing Data" stage.
    /// </summary>
    public AnalysisProgressStage? GetGeoIPStage() => null;

    /// <summary>
    /// Get Flow stage reference for statistics service timing.
    /// Returns null - Flow analysis is now consolidated into "Analyzing Data" stage.
    /// </summary>
    public AnalysisProgressStage? GetFlowStage() => null;

    /// <summary>
    /// Forward progress to global overlay for specific stages.
    /// Maps 4-stage pipeline to global overlay stages (which have more detail).
    /// </summary>
    private void ForwardToGlobalOverlay(int stageIndex, AnalysisProgressStage stage, AnalysisStageState state, int percentComplete)
    {
        if (_analysisVm == null || stageIndex > 2) return;  // Only forward stages 0-2 (views handled separately)

        // Map 4-stage pipeline to global overlay keys (overlay has finer granularity)
        var stageKey = stageIndex switch
        {
            0 => "stage-count",     // Reading Capture → Inspecting Capture
            1 => "stage-process",   // Parsing Packets → Processing Packets
            2 => "stage-stats",     // Analyzing Traffic → Calculating Statistics
            _ => null
        };

        if (stageKey == null) return;

        if (state == AnalysisStageState.Completed)
        {
            var elapsed = !string.IsNullOrEmpty(stage.ElapsedTime) ? stage.ElapsedTime : "";
            _analysisVm.CompleteTabStage(stageKey, $"{stage.Name} complete ({elapsed})");
        }
        else
        {
            _analysisVm.ReportTabProgress(stageKey, percentComplete, stage.Description);
        }
    }
}
