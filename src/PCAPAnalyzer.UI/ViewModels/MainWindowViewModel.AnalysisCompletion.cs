using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Analysis completion handling for MainWindowViewModel.
/// Contains OnFileAnalysisCompleted, OnAnalysisCompleted, and related methods.
/// </summary>
public partial class MainWindowViewModel
{
    private void OnFileAnalysisCompleted(AnalysisCompletedEventArgs args)
    {
        if (!args.IsSuccessful)
        {
            DebugLogger.Critical($"[MainWindowViewModel] Analysis failed: {args.ErrorMessage}");
            _dispatcher.Post(() =>
            {
                UIState.UpdateStatus($"Analysis failed: {args.ErrorMessage}", ThemeColorHelper.GetColorHex("ColorDanger", "#F85149"));
                UIState.CanAccessAnalysisTabs = false;
            });
            return;
        }

        _dispatcher.Post(async () =>
        {
            if (!string.IsNullOrEmpty(args.FilePath))
                FileManager.CurrentFile = args.FilePath;

            await PacketManager.InitializePacketStoreAsync(CancellationToken.None);

            if (!string.IsNullOrEmpty(args.FilePath))
            {
                PacketManager?.PacketDetails?.SetPcapPath(args.FilePath);
                PacketManager?.PacketDetails?.SetPacketStore(PacketManager.ActivePacketStore);
            }

            if (args.Packets is not null && args.Packets.Count > 0 && PacketManager is not null)
                await PacketManager.ActivePacketStore.InsertPacketsAsync(args.Packets, CancellationToken.None);

            var cachedResult = _sessionCache.Get();
            if (cachedResult is not null)
            {
                FileAnalysisViewModel?.ReportTabLoadingProgress(0, "Populating tabs from cache...");
                await PopulateViewModelsFromCacheAsync(cachedResult);
                FileAnalysisViewModel?.ReportTabLoadingProgress(100, "Tabs populated");
                FileAnalysisViewModel?.CompleteAnalysis();
            }
            else
                OnAnalysisCompleted(this, args.Statistics);

            if (FileAnalysisViewModel is not null && args.Packets is not null)
                await CalculateFileAnalysisQuickStats(args.Statistics, args.Packets);

            UIState.CanAccessAnalysisTabs = true;
            UIState.HasResults = true;
            UIState.UpdateStatus($"Analysis complete: {args.Packets?.Count ?? 0:N0} packets analyzed", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
        });
    }

    private async Task CalculateFileAnalysisQuickStats(NetworkStatistics statistics, IReadOnlyList<PacketInfo> packets)
    {
        await Task.Run(() =>
        {
            if (FileAnalysisViewModel is null) return;
            var quickStats = FileAnalysisViewModel.QuickStats;
            quickStats.TotalPackets = packets.Count;
            quickStats.TotalTrafficMB = statistics.TotalBytes / 1024.0 / 1024.0;
            quickStats.UniqueIPs = statistics.AllUniqueIPs.Count;
            quickStats.UniquePorts = statistics.UniquePortCount;
            quickStats.Conversations = statistics.TotalConversationCount;
            quickStats.Threats = statistics.DetectedThreats?.Count ?? 0;
            quickStats.Anomalies = 0;
            quickStats.UniqueProtocols = statistics.ProtocolStats.Count;
            quickStats.ProcessingRate = FileAnalysisViewModel.ElapsedTime.TotalSeconds > 0
                ? (long)(packets.Count / FileAnalysisViewModel.ElapsedTime.TotalSeconds)
                : 0;
        });
    }

    private void OnAnalysisCompleted(object? sender, NetworkStatistics statistics)
    {
        _updateTimer.Stop();
        _dispatcher.Post(async () =>
        {
            UIState.UpdateStatus($"Analysis completed. Processing results...", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
            UIState.HasResults = true;
            UIState.CanAccessAnalysisTabs = false;
            PacketFilterViewModel.IsAnalyzing = false;
            PacketFilterViewModel.CanApplyFilters = true;

            try
            {
                await ProcessAnalysisCompletionAsync(statistics);
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[MainWindowViewModel] Tab loading error: {ex.Message}");
                FileAnalysisViewModel?.CompleteAnalysis();
                UIState.CanAccessAnalysisTabs = FileManager.HasFile;
                UIState.UpdateStatus($"Analysis complete with some errors: {ex.Message}", ThemeColorHelper.GetColorHex("ColorWarning", "#FFA500"));
            }
        });
    }

    private async Task ProcessAnalysisCompletionAsync(NetworkStatistics statistics)
    {
        FileAnalysisViewModel?.ReportTabLoadingProgress(0, "Loading Packet Analysis tab...");
        Analysis.ReportTabProgress(Analysis.GetPacketAnalysisStageKey(), 0, "Populating packet list...");
        await PacketManager.PopulateFullPacketListAsync(statistics);
        Analysis.ReportTabProgress(Analysis.GetPacketAnalysisStageKey(), 75, "Applying filters...");
        PacketManager.ApplyFilter(new PacketFilter());
        var filteredCount = PacketManager.GetFilteredPackets().Count;
        UIState.UpdatePaginationInfo(filteredCount);
        UIState.GoToPage(1);
        Analysis.CompleteTabStage(Analysis.GetPacketAnalysisStageKey(),
            $"Packet list ready ({filteredCount:N0} packets)");
        FileAnalysisViewModel?.ReportTabLoadingProgress(15, $"Packet Analysis loaded ({filteredCount:N0} packets)");
        UpdatePacketAnalysisStats();
        var filteredPacketsForChart = PacketManager.GetFilteredPackets();
        Charts.UpdatePacketsOverTimeChart(filteredPacketsForChart);

        FileAnalysisViewModel?.ReportTabLoadingProgress(15, "Loading tabs in parallel...");
        var packets = PacketManager.GetFilteredPackets().ToList();
        var stats = _tsharkService.GetStatistics();
        Charts.UpdateCharts(stats);

        var dashboardCountryTask = Task.Run(async () =>
        {
            await _dispatcher.InvokeAsync(async () => await UpdateDashboardAsync(forceUpdate: true));
            if (CountryTrafficViewModel is not null)
            {
                await _dispatcher.InvokeAsync(async () =>
                {
                    CountryTrafficViewModel.SetPackets(packets);
                    var enrichedStats = DashboardViewModel?.CurrentStatistics ?? statistics;
                    await CountryTrafficViewModel.UpdateStatistics(enrichedStats);
                });
            }
            return 0;
        });

        var threatsTask = Task.Run(async () =>
        {
            if (ThreatsViewModel is not null)
                await ThreatsViewModel.UpdateThreatsAsync(packets);
            return 0;
        });

        var anomalyTask = Task.Run(async () =>
        {
            var detectedAnomalies = await _anomalyService.DetectAllAnomaliesAsync(packets);
            await _dispatcher.InvokeAsync(async () =>
            {
                AnomalyViewModel?.UpdateAnomalies(detectedAnomalies);
                if (AnomaliesViewModel is not null)
                    await AnomaliesViewModel.LoadFromAnalysisResultAsync(detectedAnomalies);
                DashboardViewModel?.UpdateAnomalySummary(detectedAnomalies);
            });
            return 0;
        });

        var voiceQoSTask = Task.Run(async () =>
        {
            if (VoiceQoSViewModel is not null)
                await VoiceQoSViewModel.AnalyzePacketsAsync(packets);
            return 0;
        });

        FileAnalysisViewModel?.ReportTabLoadingProgress(50, "Analyzing Dashboard, Threats, VoiceQoS, Country...");
        await Task.WhenAll(dashboardCountryTask, threatsTask, anomalyTask, voiceQoSTask);

        Analysis.CompleteTabStage(Analysis.GetDashboardStageKey(), $"Dashboard ready");
        Analysis.CompleteTabStage(Analysis.GetThreatsStageKey(), $"Threats detected");
        Analysis.CompleteTabStage(Analysis.GetVoiceQoSStageKey(), $"VoIP analysis complete");
        Analysis.CompleteTabStage(Analysis.GetCountryTrafficStageKey(), $"Geographic analysis complete");
        FileAnalysisViewModel?.ReportTabLoadingProgress(95, "All tabs loaded");

        await FinalizeAnalysisAsync(statistics);
    }

    private async Task FinalizeAnalysisAsync(NetworkStatistics statistics)
    {
        Analysis.ReportTabProgress(Analysis.GetFinalizingStageKey(), 0, "Finalizing analysis...");
        try
        {
            Analysis.ReportTabProgress(Analysis.GetFinalizingStageKey(), 50, "Running background tools...");
            _ = Task.Run(async () =>
            {
                try { await RunExternalToolsAsync(statistics); }
                catch (Exception toolEx)
                {
                    DebugLogger.Log($"[MainWindowViewModel] External tools failed: {toolEx.Message}");
                }
            });
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowViewModel] Failed to start external tools: {ex.Message}");
        }

        Analysis.ReportTabProgress(Analysis.GetFinalizingStageKey(), 100, "Finalizing complete");
        Analysis.CompleteTabStage(Analysis.GetFinalizingStageKey(), "Analysis complete");
        FileAnalysisViewModel?.CompleteAnalysis();
        UIState.CanAccessAnalysisTabs = FileManager.HasFile;
        UIState.UpdateStatus($"Analysis complete. {Analysis.PacketCount:N0} packets analyzed.", ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80"));
    }

    private async Task RunExternalToolsAsync(NetworkStatistics statistics)
    {
        try
        {
            var currentFile = FileManager.CurrentFile;
            if (string.IsNullOrWhiteSpace(currentFile))
                return;

            if (_suricataService.IsAvailable)
            {
                var outputDir = System.IO.Path.Combine(Environment.CurrentDirectory, "analysis", "suricata",
                    System.IO.Path.GetFileNameWithoutExtension(currentFile) + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
                var alerts = await _suricataService.RunAsync(currentFile, outputDir, CancellationToken.None);
                DebugLogger.Log($"[Suricata] Parsed {alerts.Count} alerts");
                if (alerts.Count > 0 && ThreatsViewModel is not null)
                {
                    await _dispatcher.InvokeAsync(() => ThreatsViewModel.SetSuricataAlerts(alerts));
                }
            }

            if (_yaraService.IsAvailable)
            {
                var yaraOutput = System.IO.Path.Combine(Environment.CurrentDirectory, "analysis", "yara",
                    System.IO.Path.GetFileNameWithoutExtension(currentFile) + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".log");
                var matches = await _yaraService.RunAsync(currentFile, yaraOutput, CancellationToken.None);
                DebugLogger.Log($"[YARA] Matches: {matches.Count}");
                if (matches.Count > 0 && ThreatsViewModel is not null)
                {
                    await _dispatcher.InvokeAsync(() => ThreatsViewModel.SetYaraMatches(matches));
                }
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[PostAnalysis] Error: {ex.Message}");
        }
    }
}
