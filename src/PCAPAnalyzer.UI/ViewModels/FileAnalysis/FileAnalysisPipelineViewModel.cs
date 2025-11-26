using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels.FileAnalysis;

/// <summary>
/// Manages the 4-stage analysis pipeline execution:
/// Stage 0: Counting Packets (0-35%)
/// Stage 1: Loading Packets (35-70%)
/// Stage 2: Statistics (70-95%)
/// Stage 3: Finalization (95-97%)
///
/// Extracted from FileAnalysisViewModel to isolate pipeline logic from UI state.
/// </summary>
public partial class FileAnalysisPipelineViewModel : ObservableObject
{
    private readonly ITSharkService _tsharkService;
    private readonly IStatisticsService _statisticsService;
    private ProgressCoordinator? _analysisCoordinator;

    // Stage timing tracking
    private DateTime _stageStartTime;

    /// <summary>
    /// Event fired when analysis completes (success or failure).
    /// </summary>
    public event Action<AnalysisCompletedEventArgs>? AnalysisCompleted;

    /// <summary>
    /// Event for stage timing updates.
    /// </summary>
    public event Action<string, TimeSpan>? StageDurationUpdated;

    public FileAnalysisPipelineViewModel(ITSharkService tsharkService, IStatisticsService statisticsService)
    {
        _tsharkService = tsharkService;
        _statisticsService = statisticsService;
    }

    /// <summary>
    /// Initialize pipeline with ProgressCoordinator for accurate progress tracking.
    /// </summary>
    public void Initialize(ProgressCoordinator coordinator)
    {
        _analysisCoordinator = coordinator;
    }

    /// <summary>
    /// Stage 0: Count packets in PCAP file (0-35% progress).
    /// </summary>
    public async Task<(long totalPackets, List<PacketInfo> packets)> ExecuteCountingStageAsync(
        string filePath,
        CancellationToken cancellationToken)
    {
        _stageStartTime = DateTime.Now;
        _analysisCoordinator?.ReportCounting("Starting packet count...");

        var totalPackets = await _tsharkService.GetTotalPacketCountAsync(filePath, _analysisCoordinator!);

        if (totalPackets == 0)
        {
            var fileInfo = new FileInfo(filePath);
            totalPackets = Math.Max(1, fileInfo.Length / 1500);
        }

        // Pre-allocate list with exact capacity
        var packets = new List<PacketInfo>((int)totalPackets);
        DebugLogger.Log($"[Pipeline] Pre-allocated list for {totalPackets:N0} packets");

        _analysisCoordinator?.SetTotalPackets(totalPackets);
        _analysisCoordinator?.ReportCounting(100, $"Counted {totalPackets:N0} packets", totalPackets);

        var duration = DateTime.Now - _stageStartTime;
        StageDurationUpdated?.Invoke("Reading", duration);

        DebugLogger.Log($"[Pipeline] Stage 0 complete: {totalPackets:N0} packets counted");
        return (totalPackets, packets);
    }

    /// <summary>
    /// Stage 1: Load packets from TShark channel (35-70% progress).
    /// </summary>
    public async Task<long> ExecuteLoadingStageAsync(
        string filePath,
        List<PacketInfo> packets,
        long totalPackets,
        CancellationToken cancellationToken,
        Action<int, long>? onProgress = null)
    {
        _stageStartTime = DateTime.Now;

        var startSuccess = await _tsharkService.StartAnalysisAsync(filePath, cancellationToken);
        if (!startSuccess)
            throw new InvalidOperationException("Failed to start TShark analysis");

        _analysisCoordinator?.ReportLoading(0, "Starting packet loading...");

        long totalBytes = 0;
        var reader = _tsharkService.PacketReader;

        while (await reader.WaitToReadAsync(cancellationToken))
        {
            while (reader.TryRead(out var packet))
            {
                packets.Add(packet);
                totalBytes += packet.Length;

                // Throttle progress updates - every 5000 packets
                if (packets.Count % 5000 == 0)
                {
                    _analysisCoordinator?.ReportLoading(packets.Count, $"Loaded {packets.Count:N0}/{totalPackets:N0} packets...");
                    onProgress?.Invoke(packets.Count, totalBytes);
                }
            }
        }

        var duration = DateTime.Now - _stageStartTime;
        StageDurationUpdated?.Invoke("Parsing", duration);

        DebugLogger.Log($"[Pipeline] Stage 1 complete: {packets.Count:N0} packets loaded");
        return totalBytes;
    }

    /// <summary>
    /// Stage 2: Calculate statistics (70-95% progress).
    /// Includes GeoIP enrichment (80-88%) and flow analysis (88-95%).
    /// </summary>
    public async Task<NetworkStatistics> ExecuteStatisticsStageAsync(
        List<PacketInfo> packets,
        AnalysisProgressStage? geoIPStage = null,
        AnalysisProgressStage? flowStage = null)
    {
        _stageStartTime = DateTime.Now;
        _analysisCoordinator?.ReportStatistics(0, "Starting statistical analysis...");

        DebugLogger.Log($"[Pipeline] Starting statistics with stage refs - GeoIP: {geoIPStage?.Name ?? "(null)"}, Flow: {flowStage?.Name ?? "(null)"}");

        var statistics = await _statisticsService.CalculateStatisticsAsync(packets.AsReadOnly(), geoIPStage, flowStage);

        var duration = DateTime.Now - _stageStartTime;
        StageDurationUpdated?.Invoke("Statistics", duration);

        _analysisCoordinator?.ReportStatistics(100, "Statistics complete");
        DebugLogger.Log($"[Pipeline] Stage 2 complete: Statistics calculated");

        return statistics;
    }

    /// <summary>
    /// Stage 3: Finalization - prepare results for display (95-97% progress).
    /// </summary>
    public async Task ExecuteFinalizationStageAsync(
        List<PacketInfo> packets,
        long totalBytes,
        NetworkStatistics statistics,
        Action<long, string, TimeSpan, int, int, int, string>? onFinalized = null)
    {
        _analysisCoordinator?.ReportFinalizing(0, "Preparing results...");

        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var captureDuration = packets.Count > 1 && packets[^1].Timestamp > packets[0].Timestamp
                ? packets[^1].Timestamp - packets[0].Timestamp
                : TimeSpan.Zero;

            var avgPacketSize = packets.Count > 0
                ? NumberFormatter.FormatBytes(totalBytes / packets.Count)
                : "0 B";

            onFinalized?.Invoke(
                packets.Count,
                NumberFormatter.FormatBytes(totalBytes),
                captureDuration,
                statistics.ProtocolStats.Count,
                statistics.AllUniqueIPs.Count,
                statistics.UniquePortCount,
                avgPacketSize);
        });

        var duration = DateTime.Now - _stageStartTime;
        StageDurationUpdated?.Invoke("Finalizing", duration);

        _analysisCoordinator?.ReportFinalizing(100, "Results prepared, loading tabs...");
        DebugLogger.Log($"[Pipeline] Stage 3 complete: Results prepared");
    }

    /// <summary>
    /// Fire analysis completed event with full result data.
    /// </summary>
    public void FireAnalysisCompleted(
        DateTime startTime,
        string filePath,
        long totalBytes,
        List<PacketInfo> packets,
        NetworkStatistics statistics,
        TimeSpan readingDuration,
        TimeSpan parsingDuration,
        TimeSpan statisticsDuration,
        TimeSpan finalizingDuration,
        bool isSuccessful,
        string? errorMessage)
    {
        DebugLogger.Log($"[Pipeline] FireAnalysisCompleted - Success: {isSuccessful}, Packets: {packets.Count:N0}");

        var totalDuration = DateTime.Now - startTime;
        AnalysisCompleted?.Invoke(new AnalysisCompletedEventArgs
        {
            FilePath = filePath,
            Statistics = statistics,
            Packets = isSuccessful ? packets.AsReadOnly() : Array.Empty<PacketInfo>(),
            ReadingDuration = readingDuration,
            ParsingDuration = parsingDuration,
            StatisticsDuration = statisticsDuration,
            FinalizingDuration = finalizingDuration,
            TotalDuration = totalDuration,
            FileSize = totalBytes,
            IsSuccessful = isSuccessful,
            ErrorMessage = errorMessage
        });
    }

    /// <summary>
    /// Handle analysis cancellation by user.
    /// </summary>
    public void HandleCancellation()
    {
        DebugLogger.Log("[Pipeline] Analysis cancelled by user");
    }

    /// <summary>
    /// Handle analysis error and fire failed completion event.
    /// </summary>
    public void HandleError(Exception ex, DateTime startTime, string filePath)
    {
        DebugLogger.Log($"[Pipeline] Analysis error: {ex.Message}");
        FireAnalysisCompleted(
            startTime,
            filePath,
            0,
            new List<PacketInfo>(),
            new NetworkStatistics(),
            TimeSpan.Zero,
            TimeSpan.Zero,
            TimeSpan.Zero,
            TimeSpan.Zero,
            false,
            ex.Message);
    }
}
