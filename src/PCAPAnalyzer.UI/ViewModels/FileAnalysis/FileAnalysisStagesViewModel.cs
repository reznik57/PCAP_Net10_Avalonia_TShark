using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels.FileAnalysis;

/// <summary>
/// Manages analysis stage lifecycle: initialization, reset, progress updates, and completion.
/// Extracted from FileAnalysisViewModel to handle the 7-stage analysis pipeline UI state.
/// </summary>
public partial class FileAnalysisStagesViewModel : ObservableObject
{
    private MainWindowAnalysisViewModel? _analysisVm;

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
    /// </summary>
    public void InitializeStages()
    {
        Stages.Clear();

        // Stage 0: Counting Packets (0-35%)
        Stages.Add(new AnalysisProgressStage("count",
            "Counting Packets",
            "Scanning PCAP file to determine total packet count...",
            true));

        // Stage 1: Loading Packets (35-70%)
        Stages.Add(new AnalysisProgressStage("load",
            "Loading Packets",
            "Streaming and decoding packets from TShark...",
            true));

        // Stage 2: Analyzing Data (70-80%)
        Stages.Add(new AnalysisProgressStage("stats",
            "Analyzing Data",
            "Building protocol, conversation, and endpoint statistics...",
            true));

        // Stage 3: GeoIP Enrichment (80-88%)
        Stages.Add(new AnalysisProgressStage("geoip",
            "GeoIP Enrichment",
            "Enriching IP addresses with geographic location data...",
            true));

        // Stage 4: Traffic Flow Analysis (88-95%)
        Stages.Add(new AnalysisProgressStage("flows",
            "Traffic Flow Analysis",
            "Analyzing network traffic patterns and flows...",
            true));

        // Stage 5: Finalizing (95-97%)
        Stages.Add(new AnalysisProgressStage("finalize",
            "Finalizing",
            "Preparing analysis results for display...",
            true));

        // Stage 6: Loading Tabs (97-100%)
        Stages.Add(new AnalysisProgressStage("tabs",
            "Loading Tabs",
            "Populating Dashboard, Threats, and analysis tabs...",
            true));
    }

    /// <summary>
    /// Reset all stages to Pending state while preserving timing from completed stages.
    /// </summary>
    public void ResetStages()
    {
        DebugLogger.Log($"[FileAnalysisStagesViewModel] Resetting all stages");

        foreach (var stage in Stages)
        {
            var wasCompleted = stage.State == AnalysisStageState.Completed;

            stage.State = AnalysisStageState.Pending;
            stage.PercentComplete = 0;

            // Preserve timing for previously completed stages
            if (!wasCompleted)
            {
                stage.ResetTiming();
            }
        }

        StagesChanged?.Invoke();
    }

    /// <summary>
    /// Update stage progress and timing, forwarding to global overlay when applicable.
    /// </summary>
    public void UpdateStageProgress(int stageIndex, AnalysisStageState state, int percentComplete, double overallProgress)
    {
        if (stageIndex >= Stages.Count) return;

        Dispatcher.UIThread.Post(() =>
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
    /// Report tab loading progress (Stage 6: 97-100%).
    /// Called by MainWindowViewModel during tab population.
    /// </summary>
    public void ReportTabLoadingProgress(int percentWithinStage, string message, Action<double>? updateOverallProgress = null)
    {
        if (Stages.Count < 7) return;

        Dispatcher.UIThread.Post(() =>
        {
            var stage = Stages[6];
            var wasActive = stage.State == AnalysisStageState.Active;

            stage.State = AnalysisStageState.Active;
            stage.PercentComplete = percentWithinStage;

            if (!wasActive)
            {
                stage.StartTiming();
                DebugLogger.Log($"[FileAnalysisStagesViewModel] Stage 6 'Loading Tabs' activated");
            }

            stage.UpdateElapsedTime();

            // Map 0-100% within stage to 97-100% overall
            updateOverallProgress?.Invoke(97 + (percentWithinStage * 0.03));

            StagesChanged?.Invoke();
            DebugLogger.Log($"[FileAnalysisStagesViewModel] Stage 6: {percentWithinStage}% - {message}");
        });
    }

    /// <summary>
    /// Complete entire analysis after all tabs loaded (Stage 6 done).
    /// </summary>
    public void CompleteAnalysis(Action? onComplete = null)
    {
        if (Stages.Count < 7) return;

        Dispatcher.UIThread.Post(() =>
        {
            var stage = Stages[6];

            if (stage.State == AnalysisStageState.Active && !string.IsNullOrEmpty(stage.ElapsedTime))
            {
                stage.StopTiming();
            }

            stage.State = AnalysisStageState.Completed;
            stage.PercentComplete = 100;

            StagesChanged?.Invoke();
            onComplete?.Invoke();

            DebugLogger.Log($"[FileAnalysisStagesViewModel] Analysis COMPLETE: All stages finished");
        });
    }

    /// <summary>
    /// Synchronize stages from orchestrator/external source.
    /// </summary>
    public void SyncStageFromOrchestrator(string phaseName, int percentComplete, string detail)
    {
        var phaseToStageKey = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Counting Packets", "count" },
            { "Loading Packets", "load" },
            { "Analyzing Data", "stats" },
            { "GeoIP Enrichment", "geoip" },
            { "Traffic Flow Analysis", "flows" },
            { "Threat Detection", "threats" },
            { "VoiceQoS Analysis", "voiceqos" },
            { "Finalizing", "finalize" },
            { "Complete", "finalize" }
        };

        if (phaseToStageKey.TryGetValue(phaseName, out var stageKey))
        {
            var stage = Stages.FirstOrDefault(s => s.Key == stageKey);
            if (stage != null)
            {
                Dispatcher.UIThread.Post(() =>
                {
                    if (stage.State != AnalysisStageState.Completed)
                    {
                        stage.State = AnalysisStageState.Active;
                        stage.StartTiming();
                    }

                    stage.PercentComplete = percentComplete;
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
                    DebugLogger.Log($"[FileAnalysisStagesViewModel] Stage synced: {stage.Name} ({percentComplete}%)");
                });
            }
        }
    }

    /// <summary>
    /// Get GeoIP stage reference for statistics service timing.
    /// </summary>
    public AnalysisProgressStage? GetGeoIPStage() => Stages.Count > 3 ? Stages[3] : null;

    /// <summary>
    /// Get Flow stage reference for statistics service timing.
    /// </summary>
    public AnalysisProgressStage? GetFlowStage() => Stages.Count > 4 ? Stages[4] : null;

    /// <summary>
    /// Forward progress to global overlay for specific stages.
    /// </summary>
    private void ForwardToGlobalOverlay(int stageIndex, AnalysisProgressStage stage, AnalysisStageState state, int percentComplete)
    {
        if (_analysisVm == null || stageIndex > 3) return;

        var stageKey = stageIndex switch
        {
            0 => "stage-count",
            1 => "stage-init",
            2 => "stage-process",
            3 => "stage-stats",
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
