using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading; // Required for DispatcherTimer only
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Monitoring;
using PCAPAnalyzer.Core.Collections;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.TShark;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages the analysis lifecycle including packet processing, progress tracking, and statistics aggregation.
/// Handles Start, Stop, Pause/Resume operations and coordinates with TShark service.
/// </summary>
public partial class MainWindowAnalysisViewModel : ObservableObject, IDisposable
{
    // Services
    private readonly IDispatcherService _dispatcher;
    private readonly ITSharkService _tsharkService;
    private readonly PcapInspectionService _pcapInspectionService = new();
    private readonly StreamingStatisticsAggregator _statisticsAggregator = new();
    private readonly ProcessingMetrics _processingMetrics = new();

    // State
    private CancellationTokenSource? _cts;
    private DateTime _startTime;
    private NetworkStatistics? _finalStatistics;
    private bool _analysisComplete;
    private DispatcherTimer? _elapsedTimer;
    private DispatcherTimer? _stageTimerUpdater;

    // Analysis stages - Phase 1: Data Acquisition
    private const string StageCountingKey = "stage-count";
    private const string StageInitializingKey = "stage-init";
    private const string StageProcessingKey = "stage-process";
    private const string StageStatsKey = "stage-stats";

    // Analysis stages - Phase 2: Tab Analysis (post-processing)
    private const string StageDashboardKey = "stage-dashboard";
    private const string StagePacketAnalysisKey = "stage-packet-analysis";
    private const string StageVoiceQoSKey = "stage-voiceqos";
    private const string StageCountryTrafficKey = "stage-country";
    private const string StageThreatsKey = "stage-threats";
    private const string StageChartsKey = "stage-charts";

    // Final stage
    private const string StageFinalizingKey = "stage-final";

    public ObservableCollection<AnalysisProgressStage> AnalysisStages { get; } = [];
    private readonly Dictionary<string, AnalysisProgressStage> _stageLookup = [];
    private readonly Lock _finalizingProgressLock = new();
    private double _lastFinalizingPercent;
    private string? _lastFinalizingDetail;

    // ============ DYNAMIC PROGRESS HANDOFF (Fix backwards jump) ============
    /// <summary>
    /// Captures the actual % when orchestrator completes (typically 95-100%).
    /// Tab population continues from this % to avoid backwards jumps.
    /// REPLACES hardcoded baseProgress = 62.0 assumption.
    /// </summary>
    private double _orchestratorCompletionPercent;

    /// <summary>
    /// Sets the orchestrator completion percentage for dynamic tab progress handoff.
    /// Called when orchestrator finishes to establish starting point for tab population.
    /// </summary>
    public void SetOrchestratorCompletionPercent(double percent)
    {
        _orchestratorCompletionPercent = Math.Clamp(percent, 0, 100);
        DebugLogger.Log($"[MainWindowAnalysisViewModel] Orchestrator completion captured: {_orchestratorCompletionPercent:F1}%");
        DebugLogger.Log($"[MainWindowAnalysisViewModel] Tab population will continue from {_orchestratorCompletionPercent:F1}% → 100%");
    }

    // Properties
    [ObservableProperty] private bool _isAnalyzing;
    [ObservableProperty] private long _packetCount;
    [ObservableProperty] private long _totalPacketsInFile;
    [ObservableProperty] private long _totalFileSize;
    [ObservableProperty] private double _processingRate;
    [ObservableProperty] private long _totalBytes;
    [ObservableProperty] private double _bytesPerSecond;
    [ObservableProperty] private double _analysisProgress;
    [ObservableProperty] private bool _isProgressIndeterminate = true;
    [ObservableProperty] private string _progressMessage = "Select or drop a PCAP file to analyze";
    [ObservableProperty] private double _progressPercentage;
    [ObservableProperty] private string _totalBytesFormatted = "0 B";
    [ObservableProperty] private int _threatsDetected;
    [ObservableProperty] private bool _isPaused;
    [ObservableProperty] private string _pauseResumeText = "Pause";
    [ObservableProperty] private string _pauseResumeIcon = "M 6 6 L 10 6 L 10 18 L 6 18 Z M 14 6 L 18 6 L 18 18 L 14 18 Z";
    [ObservableProperty] private string _elapsedTime = "00:00:00";
    [ObservableProperty] private double _finalizingProgressPercent;
    [ObservableProperty] private bool _isFinalizingStats;
    [ObservableProperty] private bool _isTabAnalysisActive;

    // ============ REAL-TIME METRICS (Enhanced Progress Visualization) ============
    [ObservableProperty] private long _realtimePacketsAnalyzed;
    [ObservableProperty] private long _realtimeTotalPackets;
    [ObservableProperty] private long _realtimePacketsPerSecond;
    [ObservableProperty] private double _realtimeMegabytesAnalyzed;
    [ObservableProperty] private double _realtimeTotalMegabytes;
    [ObservableProperty] private TimeSpan _realtimeElapsedTime;
    [ObservableProperty] private TimeSpan _realtimeRemainingTime;
    [ObservableProperty] private string _realtimeRemainingTimeFormatted = "";
    [ObservableProperty] private int _realtimeThreatsDetected;
    [ObservableProperty] private int _realtimeUniqueIPsProcessed;
    [ObservableProperty] private bool _hasRealtimeMetrics;

    // Events
    public event EventHandler<NetworkStatistics>? AnalysisCompleted;
    public event EventHandler<(NetworkStatistics Statistics, IPacketStore PacketStore)>? StatisticsBuilt; // EAGER PRELOADING: Fired after stats built, passes packetStore for preload queries
    public event EventHandler? AnalysisStopped;
    public event EventHandler<Exception>? AnalysisFailed;
    public event EventHandler<(long packets, long bytes, NetworkStatistics? stats)>? PacketBatchProcessed;
    public event EventHandler<string>? StatusChanged;

    public MainWindowAnalysisViewModel(IDispatcherService dispatcher, ITSharkService tsharkService)
    {
        ArgumentNullException.ThrowIfNull(dispatcher);
        ArgumentNullException.ThrowIfNull(tsharkService);
        _dispatcher = dispatcher;
        _tsharkService = tsharkService;

        InitializeAnalysisStages();
        ResetAnalysisStages();
    }

    // ============ PROGRESS OVERLAY REMOVED ============
    // Global progress overlay completely removed (see MainWindow.axaml).
    // Progress now handled exclusively by FileSelectionControl in File Manager tab.
    // This eliminates duplicate code paths and the "popup keeps reappearing" bug.

    /// <summary>
    /// Gets whether analysis has completed successfully
    /// </summary>
    public bool IsAnalysisComplete => _analysisComplete;

    /// <summary>
    /// Gets the final statistics from the completed analysis
    /// </summary>
    public NetworkStatistics? FinalStatistics => _finalStatistics;

    /// <summary>
    /// Gets the current statistics aggregator
    /// </summary>
    public StreamingStatisticsAggregator StatisticsAggregator => _statisticsAggregator;

    /// <summary>
    /// Gets the current cancellation token
    /// </summary>
    public CancellationToken CurrentCancellationToken => _cts?.Token ?? CancellationToken.None;

    /// <summary>
    /// Starts analysis of the specified PCAP file
    /// </summary>
    public async Task StartAnalysisAsync(string filePath, IPacketStore packetStore, CircularBuffer<PacketInfo> recentBuffer)
    {
        if (IsAnalyzing)
        {
            StatusChanged?.Invoke(this, "Analysis already in progress");
            return;
        }

        try
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = new();

            IsAnalyzing = true;
            IsPaused = false;
            StatusChanged?.Invoke(this, "Getting file information...");
            ProgressMessage = "Counting total packets...";
            IsProgressIndeterminate = true;
            AnalysisProgress = 0;
            ProgressPercentage = 0;
            ThreatsDetected = 0;
            PauseResumeText = "Pause";
            PauseResumeIcon = "M 6 6 L 10 6 L 10 18 L 6 18 Z M 14 6 L 18 6 L 18 18 L 14 18 Z";
            ResetAnalysisStages();

            SetStage(StageCountingKey, AnalysisStageState.Active, "Inspecting capture contents...", 0, ensureUiThread: false);

            // Inspect capture file
            var inspectionProgress = new Progress<PcapInspectionProgress>(p =>
            {
                var detail = $"Scanning capture: {p.PacketCount:N0} packets • {NumberFormatter.FormatBytes(p.BytesRead)} read • {NumberFormatter.FormatBytes((long)p.BytesPerSecond)} /s";
                SetStage(StageCountingKey, AnalysisStageState.Active, detail, p.PercentComplete, ensureUiThread: false);

                _dispatcher.Post(() =>
                {
                    ProgressMessage = detail;
                    IsProgressIndeterminate = false;
                    // Inspecting: 1% of total (0-1%)
                    var mappedPercent = Math.Clamp(p.PercentComplete, 0, 100) * 0.01;
                    UpdateOverallProgress(mappedPercent);
                });
            });

            PcapInspectionResult inspectionResult;
            try
            {
                inspectionResult = await Task.Run(() => _pcapInspectionService.Inspect(filePath, inspectionProgress, _cts.Token), _cts.Token);
            }
            catch (OperationCanceledException)
            {
                SetStage(StageCountingKey, AnalysisStageState.Error, "Capture inspection cancelled", 0, false);
                IsAnalyzing = false;
                return;
            }

            // Process inspection results
            if (inspectionResult.Success)
            {
                TotalPacketsInFile = inspectionResult.PacketCount;
                TotalFileSize = inspectionResult.BytesRead;

                if (TotalPacketsInFile > 0)
                {
                    var summary = $"Capture inspected: {inspectionResult.PacketCount:N0} packets ({NumberFormatter.FormatBytes(inspectionResult.BytesRead)})";
                    ProgressMessage = summary;
                    DebugLogger.Log($"[ANALYSIS] TotalPacketsInFile set to: {TotalPacketsInFile:N0} (from inspection)");
                    SetStage(StageCountingKey, AnalysisStageState.Completed, summary, 100, false);
                    UpdateOverallProgress(1);
                }
                else
                {
                    // Fallback to TShark count
                    DebugLogger.Log($"[ANALYSIS] Inspection returned 0 packets, falling back to TShark count...");
                    var verifiedCount = await _tsharkService.GetTotalPacketCountAsync(filePath);
                    TotalPacketsInFile = verifiedCount;
                    DebugLogger.Log($"[ANALYSIS] TotalPacketsInFile set to: {TotalPacketsInFile:N0} (from TShark)");

                    // Try to get file size
                    try
                    {
                        var fileInfo = new System.IO.FileInfo(filePath);
                        TotalFileSize = fileInfo.Length;
                    }
                    catch
                    {
                        TotalFileSize = 0;
                    }
                    var verifiedSummary = $"TShark count complete: {TotalPacketsInFile:N0} packets";
                    ProgressMessage = verifiedSummary;
                    SetStage(StageCountingKey, AnalysisStageState.Completed, verifiedSummary, 100, false);
                    UpdateOverallProgress(1);
                }

                UpdateInitializationStage("Preparing analysis engine...", 5);
            }
            else
            {
                // Fallback to TShark
                DebugLogger.Log($"[ANALYSIS] Inspection failed, using TShark count...");
                TotalPacketsInFile = await _tsharkService.GetTotalPacketCountAsync(filePath);
                DebugLogger.Log($"[ANALYSIS] TotalPacketsInFile set to: {TotalPacketsInFile:N0} (from TShark fallback)");
                // Try to get file size
                try
                {
                    var fileInfo = new System.IO.FileInfo(filePath);
                    TotalFileSize = fileInfo.Length;
                }
                catch
                {
                    TotalFileSize = 0;
                }
                var detail = $"TShark count complete: {TotalPacketsInFile:N0} packets";
                ProgressMessage = detail;
                SetStage(StageCountingKey, AnalysisStageState.Completed, detail, 100, false);
                UpdateOverallProgress(1);
                UpdateInitializationStage("Preparing analysis engine...", 5);
            }

            if (TotalPacketsInFile < 0)
            {
                TotalPacketsInFile = 0;
            }

            IsProgressIndeterminate = false;

            // Reset state
            _statisticsAggregator.Reset();
            _finalStatistics = null;
            _analysisComplete = false;

            PacketCount = 0;
            TotalBytes = 0;
            ProcessingRate = 0;
            BytesPerSecond = 0;
            _startTime = DateTime.Now;

            // Start elapsed time timer
            StartElapsedTimer();

            UpdateInitializationStage("Launching analysis engine...", 75);

            // Start TShark analysis
            var success = await _tsharkService.StartAnalysisAsync(filePath, _cts.Token);
            if (success)
            {
                StatusChanged?.Invoke(this, "Analyzing...");
                ProgressMessage = "Processing packets...";
                IsProgressIndeterminate = false;
                SetStage(StageInitializingKey, AnalysisStageState.Completed, "Analysis engine ready", 100, false);
                SetStage(StageProcessingKey, AnalysisStageState.Active, "Processing packets...", 0, false);

                // Start packet processing
                _ = Task.Run(() => ProcessPacketsAsync(packetStore, recentBuffer, _cts.Token), _cts.Token);
            }
            else
            {
                StatusChanged?.Invoke(this, "Failed to start analysis");
                ProgressMessage = "Analysis failed";
                SetStage(StageInitializingKey, AnalysisStageState.Error, "Failed to start analysis engine");
                IsAnalyzing = false;
                _processingMetrics.Fail(new InvalidOperationException("Failed to start capture"), PacketCount, TotalBytes);
            }
        }
        catch (Exception ex)
        {
            StopElapsedTimer();
            StatusChanged?.Invoke(this, $"Error: {ex.Message}");
            IsAnalyzing = false;
            _processingMetrics.Fail(ex, PacketCount, TotalBytes);
            SetStage(StageProcessingKey, AnalysisStageState.Error, $"Analysis error: {ex.Message}");
            AnalysisFailed?.Invoke(this, ex);
        }
    }

    /// <summary>
    /// Processes packets from TShark
    /// </summary>
    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Packet processing requires comprehensive analysis including protocol detection, threat detection, batching logic, statistics aggregation, anomaly detection, UI updates, and performance metrics tracking")]
    private async Task ProcessPacketsAsync(IPacketStore packetStore, CircularBuffer<PacketInfo> recentBuffer, CancellationToken cancellationToken)
    {
        var reader = _tsharkService.PacketReader;
        var packetBatch = new List<PacketInfo>(1000);
        var lastUIUpdate = DateTime.Now;
        var lastProgressUpdate = DateTime.Now;
        _analysisComplete = false;
        int processedCount = 0;
        int threatCount = 0;
        long totalBytesProcessed = 0;

        try
        {
            await foreach (var packet in reader.ReadAllAsync(cancellationToken))
            {
                if (IsPaused)
                {
                    await Task.Delay(100, cancellationToken);
                    continue;
                }

                packetBatch.Add(packet);
                processedCount++;
                totalBytesProcessed += packet.Length;

                // Detect threats
                if (packet.Protocol == Protocol.ICMP ||
                    (packet.SourcePort == 445 || packet.DestinationPort == 445) ||
                    (packet.SourcePort == 139 || packet.DestinationPort == 139))
                {
                    threatCount++;
                }

                // Process batch
                var shouldProcessBatch = packetBatch.Count >= 1000 ||
                                       (DateTime.Now - lastUIUpdate).TotalSeconds > 1;

                if (shouldProcessBatch && packetBatch.Count > 0)
                {
                    var storeBatch = packetBatch.ToArray();

                    // ✅ PERFORMANCE FIX: Only log every 100K packets (not every 1K batch)
                    if (processedCount % 100000 == 0)
                    {
                        var batchTimestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                        DebugLogger.Log($"[{batchTimestamp}] [ANALYSIS] Processing batch: {storeBatch.Length} packets (total: {processedCount:N0}, elapsed: {(DateTime.Now - _startTime).TotalSeconds:F1}s)");
                    }

                    await Task.Run(() => _statisticsAggregator.AddBatch(storeBatch), cancellationToken).ConfigureAwait(false);
                    recentBuffer.AddRange(storeBatch);
                    await packetStore.InsertPacketsAsync(storeBatch, cancellationToken);

                    packetBatch.Clear();
                    lastUIUpdate = DateTime.Now;

                    // Update progress every 250ms (4 updates/sec) for comfortable, smooth viewing experience
                    var now = DateTime.Now;
                    var shouldUpdateProgress = (now - lastProgressUpdate).TotalMilliseconds > 250;

                    if (shouldUpdateProgress)
                    {
                        lastProgressUpdate = now;

                        // Calculate progress metrics BEFORE UI dispatch (so they always execute)
                        var elapsed = (now - _startTime).TotalSeconds;
                        var rate = elapsed > 0 ? processedCount / elapsed : 0;
                        var bytesPerSecond = elapsed > 0 ? totalBytesProcessed / elapsed : 0;

                        // CRITICAL: Log progress SYNCHRONOUSLY so it always shows (not queued to UI thread)
                        var timestamp = now.ToString("HH:mm:ss.fff");
                        if (TotalPacketsInFile > 0)
                        {
                            var percent = Math.Min(100, (processedCount * 100.0) / TotalPacketsInFile);
                            DebugLogger.Log($"[{timestamp}] [PROGRESS] {percent:F1}% ({processedCount:N0}/{TotalPacketsInFile:N0}) @ {rate:F0} pkt/s, {NumberFormatter.FormatBytes((long)bytesPerSecond)}/s - Elapsed: {elapsed:F1}s");
                        }
                        else
                        {
                            DebugLogger.Log($"[{timestamp}] [PROGRESS] {processedCount:N0} packets @ {rate:F0} pkt/s - Elapsed: {elapsed:F1}s (Total unknown)");
                        }

                        // Update UI properties on UI thread (can be delayed if UI busy)
                        await _dispatcher.InvokeAsync(() =>
                        {
                            // Update all three statistics together every 0.5s
                            PacketCount = processedCount;
                            ProcessingRate = rate; // Update processing rate during processing (not just at end)
                            TotalBytes = totalBytesProcessed;
                            TotalBytesFormatted = NumberFormatter.FormatBytes(totalBytesProcessed);

                            // Additional metrics
                            ThreatsDetected = threatCount;
                            BytesPerSecond = bytesPerSecond;
                            var throughputMbps = bytesPerSecond > 0 ? (bytesPerSecond * 8.0 / 1_000_000.0) : 0;
                            _processingMetrics.Record(processedCount, totalBytesProcessed, rate, throughputMbps);

                            if (TotalPacketsInFile > 0)
                            {
                                var percent = Math.Min(100, (processedCount * 100.0) / TotalPacketsInFile);
                                UpdateProcessingStageProgress(processedCount, totalBytesProcessed, percent, bytesPerSecond);
                            }
                            else
                            {
                                UpdateProcessingStageProgress(processedCount, totalBytesProcessed, 0, bytesPerSecond);
                            }

                            // Format: "Processing... 47,000 packets (13,598 pkt/s, 3.72 MB/s) - Capture size 1,106,728 Packets, 305.2 MB"
                            var captureInfo = TotalPacketsInFile > 0 && TotalFileSize > 0
                                ? $" - Capture size {TotalPacketsInFile:N0} Packets, {NumberFormatter.FormatBytes(TotalFileSize)}"
                                : string.Empty;
                            ProgressMessage = $"Processing... {processedCount:N0} packets ({rate:N0} pkt/s, {NumberFormatter.FormatBytes((long)bytesPerSecond)}/s){captureInfo}";
                        });

                        // Notify subscribers
                        PacketBatchProcessed?.Invoke(this, (processedCount, totalBytesProcessed, null));
                    }
                }
            }

            // Process remaining packets
            if (packetBatch.Count > 0)
            {
                var storeBatch = packetBatch.ToArray();
                await Task.Run(() => _statisticsAggregator.AddBatch(storeBatch), cancellationToken).ConfigureAwait(false);
                recentBuffer.AddRange(storeBatch);
                await packetStore.InsertPacketsAsync(storeBatch, cancellationToken);
                packetBatch.Clear();
            }

            // Mark analysis as complete
            _analysisComplete = true;

            var endTimestamp = DateTime.Now.ToString("HH:mm:ss.fff");
            DebugLogger.Log($"[{endTimestamp}] [ANALYSIS] ========== PACKET PROCESSING COMPLETE ==========");
            DebugLogger.Log($"[{endTimestamp}] [ANALYSIS] Building final statistics from {processedCount:N0} packets...");
            var buildStatsStart = DateTime.Now;
            _finalStatistics = _statisticsAggregator.BuildStatistics();
            var buildStatsElapsed = (DateTime.Now - buildStatsStart).TotalSeconds;
            var statsTimestamp = DateTime.Now.ToString("HH:mm:ss.fff");
            DebugLogger.Log($"[{statsTimestamp}] [ANALYSIS] Statistics built in {buildStatsElapsed:F2}s");

            var finalThreats = (int)Math.Min(int.MaxValue, _statisticsAggregator.GetThreatCount());
            var finalPacketTotal = _finalStatistics?.TotalPackets ?? processedCount;
            var finalBytesTotal = _finalStatistics?.TotalBytes ?? totalBytesProcessed;

            SetStage(StageProcessingKey, AnalysisStageState.Completed, $"Processed {finalPacketTotal:N0} packets", 100);
            DebugLogger.Log($"[{statsTimestamp}] [ANALYSIS] Total processing time: {(DateTime.Now - _startTime).TotalSeconds:F2}s");
            DebugLogger.Log($"[{statsTimestamp}] [ANALYSIS] Threats detected: {finalThreats:N0}");

            // NOTE: DO NOT stop elapsed timer here - analysis continues through tab stages!
            // Timer will stop when Finalizing stage completes in CompleteTabStage()
            DebugLogger.Log($"[{statsTimestamp}] [ANALYSIS] ======== STARTING TAB ANALYSIS PHASE ========");

            // EAGER PRELOADING: Fire StatisticsBuilt event to trigger background tab analysis
            // This allows MainWindowViewModel to start preloading tabs in parallel BEFORE AnalysisCompleted
            // Pass packetStore so preload can query packets
            DebugLogger.Log($"[{statsTimestamp}] [ANALYSIS] *** TRIGGERING EAGER PRELOADING ***");
            if (_finalStatistics is not null)
            {
                StatisticsBuilt?.Invoke(this, (_finalStatistics, packetStore));
            }

            // Final update
            await _dispatcher.InvokeAsync(() =>
            {
                PacketCount = _finalStatistics?.TotalPackets ?? processedCount;
                ThreatsDetected = finalThreats;
                TotalBytes = _finalStatistics?.TotalBytes ?? totalBytesProcessed;
                var elapsedSeconds = (DateTime.Now - _startTime).TotalSeconds;
                ProcessingRate = elapsedSeconds > 0 ? PacketCount / elapsedSeconds : 0;
                BytesPerSecond = elapsedSeconds > 0 ? TotalBytes / elapsedSeconds : 0;
                TotalBytesFormatted = NumberFormatter.FormatBytes(TotalBytes);
                StatusChanged?.Invoke(this, "Analysis complete - processing results");
            });

            if (_finalStatistics is not null)
            {
                _processingMetrics.Complete(_finalStatistics.TotalPackets, _finalStatistics.TotalBytes, ThreatsDetected, _finalStatistics.PacketsPerSecond);
            }

            // Notify completion - tabs will handle finalization stage
            if (_finalStatistics is not null)
            {
                AnalysisCompleted?.Invoke(this, _finalStatistics);
            }
        }
        catch (OperationCanceledException)
        {
            // Expected when cancelling
            StopElapsedTimer();
        }
        catch (Exception ex)
        {
            StopElapsedTimer();
            await _dispatcher.InvokeAsync(() =>
            {
                StatusChanged?.Invoke(this, $"Error processing packets: {ex.Message}");
            });
            _processingMetrics.Fail(ex, processedCount, totalBytesProcessed);
            SetStage(StageProcessingKey, AnalysisStageState.Error, $"Processing error: {ex.Message}");
            SetStage(StageFinalizingKey, AnalysisStageState.Error, $"Finalization error: {ex.Message}");
            AnalysisFailed?.Invoke(this, ex);
        }
        finally
        {
            _analysisComplete = true;

            await _dispatcher.InvokeAsync(() =>
            {
                IsAnalyzing = false;
                // Note: Don't set progress to 100% here - let tab stages manage progress through ReportTabProgress
                // Premature 100% blocks tab stages from updating (UpdateOverallProgress has allowDecrease=false)
            });
        }
    }

    /// <summary>
    /// Stops the current analysis
    /// </summary>
    [RelayCommand]
    private async Task StopAsync()
    {
        try
        {
            _cts?.Cancel();
            await _tsharkService.StopAnalysisAsync();

            // Stop elapsed timer
            StopElapsedTimer();

            IsAnalyzing = false;
            StatusChanged?.Invoke(this, $"Analysis stopped. Processed {PacketCount:N0} packets");
            ProgressMessage = "Analysis stopped by user";
            SetStage(StageProcessingKey, AnalysisStageState.Error, "Processing stopped by user", 0, false);

            var finalizeDescription = GetStageDescription(StageFinalizingKey);
            if (string.IsNullOrWhiteSpace(finalizeDescription))
            {
                finalizeDescription = "Finalizing insights...";
            }
            SetStage(StageFinalizingKey, AnalysisStageState.Pending, finalizeDescription, 0, false);
            FinalizingProgressPercent = 0;
            IsFinalizingStats = false;
            IsTabAnalysisActive = false;

            _processingMetrics.Complete(PacketCount, TotalBytes, ThreatsDetected, ProcessingRate);

            AnalysisStopped?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex)
        {
            StatusChanged?.Invoke(this, $"Error stopping analysis: {ex.Message}");
            _processingMetrics.Fail(ex, PacketCount, TotalBytes);
        }
    }

    /// <summary>
    /// Pauses or resumes the current analysis
    /// </summary>
    [RelayCommand]
    private void PauseResume()
    {
        if (!IsAnalyzing) return;

        IsPaused = !IsPaused;
        if (IsPaused)
        {
            PauseResumeText = "Resume";
            PauseResumeIcon = "M 8 5 L 20 12 L 8 19 Z";
            ProgressMessage = "Analysis paused";
            StatusChanged?.Invoke(this, "Paused");
        }
        else
        {
            PauseResumeText = "Pause";
            PauseResumeIcon = "M 6 6 L 10 6 L 10 18 L 6 18 Z M 14 6 L 18 6 L 18 18 L 14 18 Z";
            ProgressMessage = "Resuming analysis...";
            StatusChanged?.Invoke(this, "Analyzing...");
        }
    }

    /// <summary>
    /// Resets analysis state
    /// </summary>
    public void ResetAnalysis()
    {
        _analysisComplete = false;
        _statisticsAggregator.Reset();
        _finalStatistics = null;
        PacketCount = 0;
        TotalBytes = 0;
        ProcessingRate = 0;
        BytesPerSecond = 0;
        ElapsedTime = "00:00:00";
        AnalysisProgress = 0;
        ProgressPercentage = 0;
        IsProgressIndeterminate = true;
        ThreatsDetected = 0;
        TotalBytesFormatted = "0 B";
        TotalPacketsInFile = 0;
        TotalFileSize = 0;
        ResetAnalysisStages();
        ResetOverallProgress();
    }

    private void InitializeAnalysisStages()
    {
        AnalysisStages.Clear();
        _stageLookup.Clear();

        // Phase 1: Data Acquisition (0-62%)
        AddStage(StageCountingKey, "Inspecting Capture", "Inspecting capture contents...", true);
        AddStage(StageInitializingKey, "Initializing Engine", "Initializing analysis engine...", true);
        AddStage(StageProcessingKey, "Processing Packets", "Processing packets...", true);
        AddStage(StageStatsKey, "Calculating Statistics", "Building network statistics...", true);

        // Phase 2: Tab Analysis (62-99%) - Order matches visual tabs: Packet Analysis → Dashboard → Security Threats → Voice/QoS → Country Traffic
        AddStage(StagePacketAnalysisKey, "Packet Analysis", "Preparing packet list...", true);
        AddStage(StageDashboardKey, "Dashboard", "Processing dashboard statistics...", true);
        AddStage(StageThreatsKey, "Security Threats", "Detecting security threats...", true);
        AddStage(StageVoiceQoSKey, "Voice/QoS", "Analyzing voice quality...", true);
        AddStage(StageCountryTrafficKey, "Country Traffic", "Mapping geographic traffic...", true);

        // Phase 3: Finalization (99-100%)
        AddStage(StageFinalizingKey, "Finalizing Results", "Finalizing analysis...", true);

        // Initialize continuous timer for updating active stage elapsed times
        InitializeStageTimerUpdater();
    }

    private void InitializeStageTimerUpdater()
    {
        _stageTimerUpdater?.Stop();
        _stageTimerUpdater = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(500) // Update every 500ms
        };
        _stageTimerUpdater.Tick += (s, e) => UpdateActiveStageTimers();
    }

    private void UpdateActiveStageTimers()
    {
        foreach (var stage in AnalysisStages)
        {
            // Update both Active and Completed stages to ensure timing persists
            if (stage.State == AnalysisStageState.Active || stage.State == AnalysisStageState.Completed)
            {
                stage.UpdateElapsedTime();
            }
        }
    }

    private void StartStageTimerUpdater()
    {
        _stageTimerUpdater?.Start();
    }

    private void StopStageTimerUpdater()
    {
        _stageTimerUpdater?.Stop();
    }

    private void AddStage(string key, string name, string description, bool showProgressBar)
    {
        var stage = new AnalysisProgressStage(key, name, description, showProgressBar);
        AnalysisStages.Add(stage);
        _stageLookup[key] = stage;
    }

    private void ResetAnalysisStages()
    {
        foreach (var stage in AnalysisStages)
        {
            // Preserve timing for completed stages so users can see previous run durations
            var wasCompleted = stage.State == AnalysisStageState.Completed;

            stage.State = AnalysisStageState.Pending;
            stage.PercentComplete = 0;
            stage.Detail = stage.Description;

            // Don't reset timing for previously completed stages
            // This preserves performance history across analysis runs
            if (!wasCompleted)
            {
                stage.ResetTiming();
            }
        }

        lock (_finalizingProgressLock)
        {
            _lastFinalizingPercent = 0;
            _lastFinalizingDetail = null;
        }

        FinalizingProgressPercent = 0;
        IsFinalizingStats = false;
        IsTabAnalysisActive = false;
    }

    private void ResetOverallProgress()
    {
        _dispatcher.Post(() =>
        {
            AnalysisProgress = 0;
            ProgressPercentage = 0;
            IsProgressIndeterminate = true;
            FinalizingProgressPercent = 0;
            IsFinalizingStats = false;
            IsTabAnalysisActive = false;
        });
    }

    /// <summary>
    /// Updates the overall analysis progress percentage
    /// </summary>
    public void UpdateOverallProgress(double percent, bool allowDecrease = false)
    {
        var clamped = Math.Clamp(percent, 0, 100);
        _dispatcher.Post(() =>
        {
            if (!allowDecrease && clamped <= AnalysisProgress)
            {
                return;
            }

            AnalysisProgress = clamped;
            ProgressPercentage = clamped;
            IsProgressIndeterminate = false;
        });
    }

    private void UpdateInitializationStage(string detail, double percent)
    {
        SetStage(StageInitializingKey, AnalysisStageState.Active, detail, percent, ensureUiThread: false);
        _dispatcher.Post(() => ProgressMessage = detail);
        // Initialization: 1% of total (1-2%)
        var mapped = 1 + Math.Clamp(percent, 0, 100) * 0.01;
        UpdateOverallProgress(mapped);
    }

    private void UpdateProcessingStageProgress(long packets, long bytes, double percent, double bytesPerSecond)
    {
        if (!_stageLookup.TryGetValue(StageProcessingKey, out var stage))
            return;

        if (stage.State == AnalysisStageState.Completed || stage.State == AnalysisStageState.Error)
            return;

        stage.State = AnalysisStageState.Active;
        stage.PercentComplete = Math.Clamp(percent, 0, 100);
        stage.Detail = $"{packets:N0} packets • {NumberFormatter.FormatBytes(bytes)} processed • {NumberFormatter.FormatBytes((long)bytesPerSecond)}/s";

        // Map packet processing to 2-62% range (60% total)
        var mapped = 2 + Math.Clamp(percent, 0, 100) * 0.60;
        UpdateOverallProgress(mapped);
    }

    private void ReportFinalizingProgress(double percent, string detail)
    {
        var clamped = Math.Clamp(percent, 0, 100);

        lock (_finalizingProgressLock)
        {
            if (clamped < _lastFinalizingPercent)
            {
                clamped = _lastFinalizingPercent;
            }

            _lastFinalizingPercent = clamped;
            _lastFinalizingDetail = detail;
        }

        SetStage(StageFinalizingKey, AnalysisStageState.Active, detail, clamped, ensureUiThread: false);

        _dispatcher.Post(() =>
        {
            ProgressMessage = detail;
            FinalizingProgressPercent = clamped;
            IsFinalizingStats = clamped < 100;
        });

        var mapped = 95 + clamped * 0.05 / 1.0;
        UpdateOverallProgress(mapped);
    }

    private void SetStage(string key, AnalysisStageState state, string detail, double percent = 0, bool ensureUiThread = true)
    {
        void Apply()
        {
            if (!_stageLookup.TryGetValue(key, out var stage))
            {
                return;
            }

            // Handle timing based on state changes
            var previousState = stage.State;
            stage.State = state;
            stage.Detail = detail;

            // Start timing when transitioning to Active
            if (state == AnalysisStageState.Active && previousState != AnalysisStageState.Active)
            {
                stage.StartTiming();
            }
            // Stop timing when completing or erroring
            else if (state == AnalysisStageState.Completed || state == AnalysisStageState.Error)
            {
                stage.StopTiming();
            }
            // Update elapsed time for active stages
            else if (state == AnalysisStageState.Active)
            {
                stage.UpdateElapsedTime();
            }

            if (stage.ShowProgressBar || state == AnalysisStageState.Completed)
            {
                stage.PercentComplete = Math.Clamp(percent, 0, 100);
            }
            else if (state == AnalysisStageState.Pending)
            {
                stage.PercentComplete = 0;
            }
            else if (state == AnalysisStageState.Completed)
            {
                stage.PercentComplete = 100;
            }
        }

        if (ensureUiThread && !_dispatcher.CheckAccess())
        {
            _dispatcher.Post(Apply);
        }
        else
        {
            Apply();
        }
    }

    private string GetStageDescription(string key)
    {
        return _stageLookup.TryGetValue(key, out var stage)
            ? stage.Description
            : string.Empty;
    }

    /// <summary>
    /// Reports progress for a specific tab analysis phase.
    /// FIXED: Uses dynamic orchestrator completion % instead of hardcoded 62%.
    /// </summary>
    /// <param name="stageKey">Stage key (use StageXxxKey constants)</param>
    /// <param name="percent">Progress within this stage (0-100)</param>
    /// <param name="message">Status message</param>
    public void ReportTabProgress(string stageKey, double percent, string message)
    {
        // Mark tab analysis as active
        IsTabAnalysisActive = true;

        SetStage(stageKey, AnalysisStageState.Active, message, percent, ensureUiThread: false);

        // ✅ FIX: Use captured orchestrator completion % (typically 95-100%) instead of hardcoded 62%
        // If orchestrator didn't set a value (legacy path), fall back to 62% for backwards compatibility
        var baseProgress = _orchestratorCompletionPercent > 0 ? _orchestratorCompletionPercent : 62.0;

        // Get stage weights dynamically based on remaining progress space
        var (stageStart, stageWeight) = GetStageProgressRange(stageKey, baseProgress);

        var overallProgress = baseProgress + stageStart + (percent / 100.0 * stageWeight);
        overallProgress = Math.Clamp(overallProgress, baseProgress, 100.0);

        // Validate monotonic increase
        if (overallProgress < AnalysisProgress && AnalysisProgress < 100)
        {
            DebugLogger.Log($"[WARNING] Progress backwards jump prevented: {AnalysisProgress:F1}% → {overallProgress:F1}% (stage: {stageKey}, percent: {percent:F1}%)");
            overallProgress = AnalysisProgress; // Clamp to prevent backwards movement
        }

        UpdateOverallProgress(overallProgress);

        _dispatcher.Post(() =>
        {
            ProgressMessage = message;
        });
    }

    /// <summary>
    /// Marks a tab analysis stage as completed
    /// </summary>
    public void CompleteTabStage(string stageKey, string message)
    {
        SetStage(stageKey, AnalysisStageState.Completed, message, 100, ensureUiThread: false);

        // If this is the final stage, mark tab analysis as complete and stop timers
        if (stageKey == StageFinalizingKey)
        {
            IsTabAnalysisActive = false;

            // Stop elapsed timer NOW - all analysis stages complete
            _dispatcher.Post(() => StopElapsedTimer());
        }
    }

    /// <summary>
    /// Gets the tab index for progress calculation (deprecated - use GetStageProgressRange)
    /// </summary>
    private static int GetTabIndex(string stageKey)
    {
        return stageKey switch
        {
            "stage-dashboard" => 0,
            "stage-packet-analysis" => 1,
            "stage-voiceqos" => 2,
            "stage-country" => 3,
            "stage-threats" => 4,
            _ => 0
        };
    }

    /// <summary>
    /// Gets the cumulative start position and weight for each stage.
    /// FIXED: Now calculates weights dynamically based on remaining progress space.
    /// Returns (cumulativeStart, stageWeight) relative to baseProgress.
    ///
    /// Order: Packet Analysis → Dashboard → Security Threats → Voice/QoS → Country Traffic → Finalizing
    ///
    /// Example:
    /// - If orchestrator completes at 95%, remaining space = 5%
    /// - Stages distributed proportionally: PacketAnalysis=2%, Dashboard=50%, Threats=18%, VoiceQoS=18%, Country=10%, Finalizing=2%
    /// - If orchestrator completes at 62% (legacy), remaining space = 38%
    /// - Stages get more room: PacketAnalysis=1%, Dashboard=20%, Threats=7%, VoiceQoS=7%, Country=2%, Finalizing=1%
    /// </summary>
    private static (double start, double weight) GetStageProgressRange(string stageKey, double baseProgress)
    {
        // Calculate remaining progress space (100% - baseProgress)
        var remainingSpace = 100.0 - baseProgress;

        // Define relative weights (these sum to 100 for proportional distribution)
        // Based on actual timing measurements from 1.1M packet PCAP
        var relativeWeights = new Dictionary<string, double>
        {
            ["stage-packet-analysis"] = 2.6,   // Fastest stage (packet list prep)
            ["stage-dashboard"] = 52.6,        // Heaviest stage (stats + GeoIP + charts)
            ["stage-threats"] = 18.4,          // Medium stage (threat detection)
            ["stage-voiceqos"] = 18.4,         // Medium stage (VoIP analysis)
            ["stage-country"] = 5.3,           // Light stage (geographic mapping)
            ["stage-final"] = 2.6              // Lightest stage (cleanup)
        };

        // Calculate absolute weights by scaling to remaining space
        var absoluteWeights = relativeWeights.ToDictionary(
            kvp => kvp.Key,
            kvp => (kvp.Value / 100.0) * remainingSpace
        );

        // Calculate cumulative starts
        var cumulativeStarts = new Dictionary<string, double>();
        double cumulative = 0.0;
        foreach (var stage in new[] { "stage-packet-analysis", "stage-dashboard", "stage-threats", "stage-voiceqos", "stage-country", "stage-final" })
        {
            cumulativeStarts[stage] = cumulative;
            cumulative += absoluteWeights[stage];
        }

        // Return (start, weight) for requested stage
        if (absoluteWeights.TryGetValue(stageKey, out var weight) &&
            cumulativeStarts.TryGetValue(stageKey, out var start))
        {
            return (start, weight);
        }

        return (0, 0); // Unknown stage
    }

    /// <summary>
    /// Public accessors for stage keys - used by MainWindowViewModel
    /// </summary>
    public string GetChartsStageKey() => StageChartsKey;
    public string GetDashboardStageKey() => StageDashboardKey;
    public string GetPacketAnalysisStageKey() => StagePacketAnalysisKey;
    public string GetVoiceQoSStageKey() => StageVoiceQoSKey;
    public string GetCountryTrafficStageKey() => StageCountryTrafficKey;
    public string GetThreatsStageKey() => StageThreatsKey;
    public string GetFinalizingStageKey() => StageFinalizingKey;

    /// <summary>
    /// Starts the elapsed time timer
    /// </summary>
    private void StartElapsedTimer()
    {
        StopElapsedTimer(); // Ensure no existing timer

        _elapsedTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(1)
        };
        _elapsedTimer.Tick += (s, e) =>
        {
            ElapsedTime = (DateTime.Now - _startTime).ToString(@"hh\:mm\:ss");
        };
        _elapsedTimer.Start();

        // Start stage timer updater for continuous elapsed time updates
        StartStageTimerUpdater();
    }

    /// <summary>
    /// Stops the elapsed time timer
    /// </summary>
    private void StopElapsedTimer()
    {
        if (_elapsedTimer is not null)
        {
            _elapsedTimer.Stop();
            _elapsedTimer = null;
        }

        // Also stop stage timer updater
        StopStageTimerUpdater();
    }

    /// <summary>
    /// Updates real-time metrics from AnalysisProgress object (Orchestrator-based analysis)
    /// </summary>
    public void UpdateRealtimeMetrics(PCAPAnalyzer.Core.Orchestration.AnalysisProgress? analysisProgress)
    {
        if (analysisProgress is null)
        {
            HasRealtimeMetrics = false;
            return;
        }

        _dispatcher.Post(() =>
        {
            RealtimePacketsAnalyzed = analysisProgress.PacketsAnalyzed;
            RealtimeTotalPackets = analysisProgress.TotalPackets;
            RealtimePacketsPerSecond = analysisProgress.PacketsPerSecond;
            RealtimeMegabytesAnalyzed = analysisProgress.MegabytesAnalyzed;
            RealtimeTotalMegabytes = analysisProgress.TotalMegabytes;
            RealtimeElapsedTime = analysisProgress.ElapsedTime;
            RealtimeRemainingTime = analysisProgress.RemainingTime;
            RealtimeThreatsDetected = analysisProgress.ThreatsDetected;
            RealtimeUniqueIPsProcessed = analysisProgress.UniqueIPsProcessed;

            // Format remaining time
            if (analysisProgress.RemainingTime > TimeSpan.Zero)
            {
                if (analysisProgress.RemainingTime.TotalHours >= 1)
                {
                    RealtimeRemainingTimeFormatted = $"{analysisProgress.RemainingTime:hh\\:mm\\:ss} remaining";
                }
                else if (analysisProgress.RemainingTime.TotalMinutes >= 1)
                {
                    RealtimeRemainingTimeFormatted = $"{analysisProgress.RemainingTime:mm\\:ss} remaining";
                }
                else
                {
                    RealtimeRemainingTimeFormatted = $"{analysisProgress.RemainingTime.TotalSeconds:F0}s remaining";
                }
            }
            else
            {
                RealtimeRemainingTimeFormatted = "";
            }

            HasRealtimeMetrics = true;
        });
    }

    public void Dispose()
    {
        StopElapsedTimer();
        StopStageTimerUpdater();
        _stageTimerUpdater = null;
        _cts?.Cancel();
        _cts?.Dispose();
    }
}
