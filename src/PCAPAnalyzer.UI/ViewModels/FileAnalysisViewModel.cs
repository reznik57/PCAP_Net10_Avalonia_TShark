using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading; // Required for DispatcherTimer only
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.UI.ViewModels.FileAnalysis;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Enhanced ViewModel for File Analysis tab - thin orchestrator pattern.
/// Delegates to component ViewModels:
/// - ProgressViewModel: Real-time metrics, throttling, QuickStats
/// - StagesViewModel: Stage initialization, reset, completion
/// - PipelineViewModel: 4-stage async analysis pipeline
/// </summary>
public partial class FileAnalysisViewModel : ObservableObject, IDisposable
{
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    private readonly Services.IFileDialogService? _fileDialogService;
    private readonly ITSharkService _tsharkService;
    private readonly ISessionAnalysisCache _sessionCache;
    private readonly AnalysisOrchestrator? _orchestrator;
    private CancellationTokenSource? _analysisCts;
    private readonly DispatcherTimer _progressTimer;
    private readonly Stopwatch _analysisStopwatch = new();

    // ==================== COMPONENT VIEWMODELS ====================

    /// <summary>Progress tracking, metrics, and QuickStats</summary>
    public FileAnalysisProgressViewModel ProgressViewModel { get; }

    /// <summary>Stage initialization, reset, and completion tracking</summary>
    public FileAnalysisStagesViewModel StagesViewModel { get; }

    /// <summary>4-stage analysis pipeline execution</summary>
    public FileAnalysisPipelineViewModel PipelineViewModel { get; }

    // ==================== FILE PROPERTIES ====================

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(AnalyzeCommand))]
    private string? _selectedFilePath;

    [ObservableProperty] private string? _selectedFileName;

    // ==================== ANALYSIS STATE ====================

    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(AnalyzeCommand))]
    [NotifyCanExecuteChangedFor(nameof(StopCommand))]
    private bool _isAnalyzing;

    [ObservableProperty] private bool _isAnalysisComplete;

    partial void OnIsAnalyzingChanged(bool value) =>
        DebugLogger.Log($"[FileAnalysisViewModel] IsAnalyzing: {value}");

    partial void OnIsAnalysisCompleteChanged(bool value) =>
        DebugLogger.Log($"[FileAnalysisViewModel] IsAnalysisComplete: {value}");

    // ==================== FORWARDED PROPERTIES ====================

    /// <summary>Progress percentage (forwarded from ProgressViewModel)</summary>
    public double ProgressPercentage
    {
        get => ProgressViewModel.ProgressPercentage;
        set => ProgressViewModel.ProgressPercentage = value;
    }

    /// <summary>Stages collection (forwarded from StagesViewModel)</summary>
    public ObservableCollection<AnalysisProgressStage> Stages => StagesViewModel.Stages;

    /// <summary>Real-time metrics</summary>
    public long PacketsProcessed => ProgressViewModel.PacketsProcessed;
    public long TotalPacketsInFile => ProgressViewModel.TotalPacketsInFile;
    public long PacketsPerSecond => ProgressViewModel.PacketsPerSecond;
    public string TotalBytesFormatted => ProgressViewModel.TotalBytesFormatted;
    public TimeSpan ElapsedTime => ProgressViewModel.ElapsedTime;
    public string RemainingTimeFormatted => ProgressViewModel.RemainingTimeFormatted;

    /// <summary>Quick stats model</summary>
    public QuickStatsModel QuickStats => ProgressViewModel.QuickStats;

    /// <summary>Stage durations</summary>
    public TimeSpan ReadingDuration => ProgressViewModel.ReadingDuration;
    public TimeSpan ParsingDuration => ProgressViewModel.ParsingDuration;
    public TimeSpan StatisticsDuration => ProgressViewModel.StatisticsDuration;
    public TimeSpan FinalizingDuration => ProgressViewModel.FinalizingDuration;

    // ==================== SMART FILTERS ====================

    [ObservableProperty] private SmartFiltersModel _smartFilters = new();
    [ObservableProperty] private bool _isFiltersExpanded;

    // ==================== PACKET PREVIEW ====================

    public ObservableCollection<PacketInfo> PreviewPackets { get; } = [];

    // ==================== SUMMARY STATS ====================

    [ObservableProperty] private long _totalPackets;
    [ObservableProperty] private string _totalTrafficVolume = "0 B";
    [ObservableProperty] private TimeSpan _captureDuration;
    [ObservableProperty] private DateTime? _captureStartTime;
    [ObservableProperty] private DateTime? _captureEndTime;
    [ObservableProperty] private int _uniqueProtocols;
    [ObservableProperty] private int _uniqueIPs;
    [ObservableProperty] private int _uniquePorts;
    [ObservableProperty] private string _averagePacketSize = "0 B";

    // ==================== NAVIGATION ====================

    public Action<int>? NavigateToTab { get; set; }

    // ==================== EVENTS ====================

    /// <summary>Event fired when analysis completes successfully.</summary>
    public Action<AnalysisCompletedEventArgs>? OnAnalysisCompleted { get; set; }

    /// <summary>Event fired during analysis for real-time progress updates.</summary>
    public Action<AnalysisProgressEventArgs>? OnProgressUpdated { get; set; }

    // ==================== CONSTRUCTOR ====================

    public FileAnalysisViewModel(
        ITSharkService tsharkService,
        IStatisticsService statisticsService,
        ISessionAnalysisCache sessionCache,
        MainWindowAnalysisViewModel? analysisVm = null,
        Services.IFileDialogService? fileDialogService = null,
        AnalysisOrchestrator? orchestrator = null)
    {
        _fileDialogService = fileDialogService;
        _tsharkService = tsharkService;
        _sessionCache = sessionCache ?? throw new ArgumentNullException(nameof(sessionCache));
        _orchestrator = orchestrator;

        // Initialize component ViewModels
        ProgressViewModel = new();
        StagesViewModel = new();
        PipelineViewModel = new FileAnalysisPipelineViewModel(tsharkService, statisticsService);

        // Wire up stages to progress for notifications
        ProgressViewModel.SetStagesCollection(StagesViewModel.Stages);

        // Forward property changes from ProgressViewModel for UI binding
        ProgressViewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(FileAnalysisProgressViewModel.ProgressPercentage))
                OnPropertyChanged(nameof(ProgressPercentage));
            else if (e.PropertyName == nameof(FileAnalysisProgressViewModel.PacketsProcessed))
                OnPropertyChanged(nameof(PacketsProcessed));
            else if (e.PropertyName == nameof(FileAnalysisProgressViewModel.PacketsPerSecond))
                OnPropertyChanged(nameof(PacketsPerSecond));
            else if (e.PropertyName == nameof(FileAnalysisProgressViewModel.ElapsedTime))
                OnPropertyChanged(nameof(ElapsedTime));
            else if (e.PropertyName == nameof(FileAnalysisProgressViewModel.RemainingTimeFormatted))
                OnPropertyChanged(nameof(RemainingTimeFormatted));
        };

        // Wire up analysis VM for global overlay
        if (analysisVm is not null)
            StagesViewModel.SetAnalysisViewModel(analysisVm);

        // Wire up stage change notifications
        StagesViewModel.StagesChanged += () => OnPropertyChanged(nameof(Stages));

        // Wire up pipeline events
        PipelineViewModel.AnalysisCompleted += args => OnAnalysisCompleted?.Invoke(args);
        PipelineViewModel.StageDurationUpdated += OnStageDurationUpdated;

        // Initialize timer
        _progressTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _progressTimer.Tick += (_, _) => ProgressViewModel.ElapsedTime = _analysisStopwatch.Elapsed;

        // Initialize stages
        StagesViewModel.InitializeStages();
    }

    private void OnStageDurationUpdated(string stageName, TimeSpan duration)
    {
        Dispatcher.Post(() =>
        {
            switch (stageName)
            {
                case "Reading":
                    ProgressViewModel.ReadingDuration = duration;
                    break;
                case "Parsing":
                    ProgressViewModel.ParsingDuration = duration;
                    break;
                case "Statistics":
                    ProgressViewModel.StatisticsDuration = duration;
                    break;
                case "Finalizing":
                    ProgressViewModel.FinalizingDuration = duration;
                    break;
            }
        });
    }

    /// <summary>
    /// Set the MainWindowAnalysisViewModel reference for global progress overlay integration.
    /// </summary>
    public void SetAnalysisViewModel(MainWindowAnalysisViewModel analysisVm)
    {
        StagesViewModel.SetAnalysisViewModel(analysisVm);
        DebugLogger.Log("[FileAnalysisViewModel] Wired to MainWindowAnalysisViewModel");
    }

    // ==================== COMMANDS ====================

    // Valid PCAP file extensions for drag & drop validation
    private static readonly string[] ValidPcapExtensions = { ".pcap", ".pcapng", ".cap" };

    [RelayCommand]
    private async Task BrowseAsync()
    {
        DebugLogger.Log("[FileAnalysisViewModel] Browse requested");

        if (_fileDialogService is null)
        {
            DebugLogger.Log("[FileAnalysisViewModel] FileDialogService not available");
            return;
        }

        var filter = new Services.FileDialogFilter("PCAP Files", "pcap", "pcapng", "cap");
        var filePath = await _fileDialogService.OpenFileAsync("Open PCAP File", filter);

        if (!string.IsNullOrEmpty(filePath))
        {
            SelectFile(filePath);
        }
    }

    /// <summary>
    /// Select a file from a given path (used by drag & drop).
    /// Validates file extension before accepting.
    /// </summary>
    /// <param name="filePath">Full path to the PCAP file</param>
    /// <returns>True if file was accepted, false if invalid extension</returns>
    public bool SelectFile(string filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            return false;

        var extension = Path.GetExtension(filePath).ToLowerInvariant();
        if (!Array.Exists(ValidPcapExtensions, ext => ext == extension))
        {
            DebugLogger.Log($"[FileAnalysisViewModel] Invalid file extension: {extension}");
            return false;
        }

        if (!File.Exists(filePath))
        {
            DebugLogger.Log($"[FileAnalysisViewModel] File does not exist: {filePath}");
            return false;
        }

        SelectedFilePath = filePath;
        SelectedFileName = Path.GetFileName(filePath);
        DebugLogger.Log($"[FileAnalysisViewModel] File selected: {filePath}");

        // Fetch capture time range in background (shown during countdown)
        _ = FetchCaptureTimeRangeAsync(filePath);

        return true;
    }

    /// <summary>
    /// Fetches capture time range from PCAP file in background.
    /// Called when a file is selected, before analysis starts.
    /// </summary>
    private async Task FetchCaptureTimeRangeAsync(string filePath)
    {
        try
        {
            var (firstTime, lastTime) = await _tsharkService.GetCaptureTimeRangeAsync(filePath);

            await Dispatcher.InvokeAsync(() =>
            {
                CaptureStartTime = firstTime;
                CaptureEndTime = lastTime;
                DebugLogger.Log($"[FileAnalysisViewModel] Capture time range: {firstTime:dd.MM.yyyy HH:mm} - {lastTime:dd.MM.yyyy HH:mm}");
            });
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[FileAnalysisViewModel] Failed to fetch capture time range: {ex.Message}");
        }
    }

    /// <summary>
    /// Check if a file has a valid PCAP extension.
    /// </summary>
    public static bool IsValidPcapFile(string filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            return false;

        var extension = Path.GetExtension(filePath).ToLowerInvariant();
        return Array.Exists(ValidPcapExtensions, ext => ext == extension);
    }

    [RelayCommand(CanExecute = nameof(CanAnalyze))]
    private async Task AnalyzeAsync()
    {
        if (string.IsNullOrEmpty(SelectedFilePath) || !File.Exists(SelectedFilePath))
            return;

        _analysisCts = new();
        IsAnalyzing = true;
        IsAnalysisComplete = false;
        ProgressViewModel.ResetMetrics();
        StagesViewModel.ResetStages();

        _analysisStopwatch.Restart();
        _progressTimer.Start();

        var overallStartTime = DateTime.Now;

        // ✅ PERFORMANCE FIX: Use orchestrator when available for complete analysis including VoiceQoS
        // This ensures VoiceQoS data is cached, preventing 25s re-analysis during tab population
        if (_orchestrator is not null)
        {
            await AnalyzeWithOrchestratorAsync(overallStartTime);
            return;
        }

        // Legacy pipeline path (fallback when orchestrator not available)
        // Create shared ProgressCoordinator
        var coordinator = new ProgressCoordinator(new Progress<AnalysisProgress>(ProgressViewModel.OnProgressUpdate));
        var fileInfo = new FileInfo(SelectedFilePath);
        coordinator.InitializeTimeEstimates(fileInfo.Length / 1024.0 / 1024.0);
        PipelineViewModel.Initialize(coordinator);

        try
        {
            // Stage 0: Count packets
            var (totalPackets, packets) = await PipelineViewModel.ExecuteCountingStageAsync(
                SelectedFilePath, _analysisCts.Token);
            _analysisCts.Token.ThrowIfCancellationRequested();

            await UpdateUIAfterCounting(totalPackets);

            // Stage 1: Load packets
            var totalBytes = await PipelineViewModel.ExecuteLoadingStageAsync(
                SelectedFilePath,
                packets,
                totalPackets,
                _analysisCts.Token,
                (count, bytes) => UpdateUIProgress(count, bytes));
            _analysisCts.Token.ThrowIfCancellationRequested();

            // Stage 2: Calculate statistics
            var statistics = await PipelineViewModel.ExecuteStatisticsStageAsync(
                packets,
                StagesViewModel.GetGeoIPStage(),
                StagesViewModel.GetFlowStage());
            _analysisCts.Token.ThrowIfCancellationRequested();

            // Stage 3: Finalization
            await PipelineViewModel.ExecuteFinalizationStageAsync(
                packets,
                totalBytes,
                statistics,
                OnFinalized);

            // Cache result (without VoiceQoS - legacy path)
            var analysisResult = BuildAnalysisResult(SelectedFilePath!, packets, statistics, totalBytes, overallStartTime);
            _sessionCache.Set(analysisResult);
            DebugLogger.Log($"[FileAnalysisViewModel] ⚡ Cached AnalysisResult (legacy): {packets.Count:N0} packets");

            // Set to 75% - tab loading phase starts here
            ProgressViewModel.ProgressPercentage = 75;

            // Fire completion event
            PipelineViewModel.FireAnalysisCompleted(
                overallStartTime,
                SelectedFilePath,
                totalBytes,
                packets,
                statistics,
                ProgressViewModel.ReadingDuration,
                ProgressViewModel.ParsingDuration,
                ProgressViewModel.StatisticsDuration,
                ProgressViewModel.FinalizingDuration,
                true,
                null);
        }
        catch (OperationCanceledException)
        {
            PipelineViewModel.HandleCancellation();
            await HandleAnalysisCancellation();
        }
        catch (Exception ex)
        {
            PipelineViewModel.HandleError(ex, overallStartTime, SelectedFilePath);
            await HandleAnalysisError();
        }
    }

    /// <summary>
    /// ✅ PERFORMANCE FIX: Use orchestrator for complete analysis with VoiceQoS included.
    /// This caches VoiceQoS data during main analysis, preventing 25s re-analysis during tab population.
    /// </summary>
    private async Task AnalyzeWithOrchestratorAsync(DateTime overallStartTime)
    {
        try
        {
            DebugLogger.Log("[FileAnalysisViewModel] Using orchestrator for complete analysis (includes VoiceQoS)");

            // Progress reporter forwards to UI
            var progress = new Progress<AnalysisProgress>(p =>
            {
                ProgressViewModel.OnProgressUpdate(p);
                StagesViewModel.SyncStageFromOrchestrator(p.Phase, (int)p.Percent, p.Detail);
            });

            // Run orchestrator analysis - includes VoiceQoS
            var result = await _orchestrator!.AnalyzeFileAsync(SelectedFilePath!, progress, _analysisCts!.Token);

            // Cache is already set by orchestrator, but ensure it's there
            if (_sessionCache.Get() is null)
            {
                _sessionCache.Set(result);
            }

            DebugLogger.Log($"[FileAnalysisViewModel] ⚡ Orchestrator complete: {result.TotalPackets:N0} packets, VoiceQoS={result.VoiceQoSData is not null}");

            // ✅ FIX: Set UI properties from orchestrator result (was missing - caused 00:00:00 duration)
            TotalPackets = result.TotalPackets;
            TotalTrafficVolume = NumberFormatter.FormatBytes(result.TotalBytes);
            CaptureDuration = result.Statistics.Duration;
            CaptureStartTime = result.Statistics.FirstPacketTime;
            CaptureEndTime = result.Statistics.LastPacketTime;
            UniqueProtocols = result.Statistics.ProtocolStats?.Count ?? 0;
            UniqueIPs = result.Statistics.AllUniqueIPs?.Count ?? 0;
            UniquePorts = result.Statistics.UniquePortCount;
            AveragePacketSize = result.TotalPackets > 0
                ? NumberFormatter.FormatBytes(result.TotalBytes / result.TotalPackets)
                : "0 B";

            // Set to 75% - tab loading starts
            ProgressViewModel.ProgressPercentage = 75;

            // Fire completion event with orchestrator results
            PipelineViewModel.FireAnalysisCompleted(
                overallStartTime,
                SelectedFilePath!,
                result.TotalBytes,
                result.AllPackets,
                result.Statistics,
                TimeSpan.Zero, // Orchestrator doesn't track per-stage durations
                TimeSpan.Zero,
                TimeSpan.Zero,
                TimeSpan.Zero,
                true,
                null);
        }
        catch (OperationCanceledException)
        {
            PipelineViewModel.HandleCancellation();
            await HandleAnalysisCancellation();
        }
        catch (Exception ex)
        {
            DebugLogger.Critical($"[FileAnalysisViewModel] Orchestrator analysis failed: {ex.Message}");
            PipelineViewModel.HandleError(ex, overallStartTime, SelectedFilePath ?? "unknown");
            await HandleAnalysisError();
        }
    }

    private async Task UpdateUIAfterCounting(long totalPackets)
    {
        await Dispatcher.InvokeAsync(() =>
        {
            ProgressViewModel.TotalPacketsInFile = totalPackets;
            ProgressViewModel.TotalBytesFormatted = "0 B";
        });
    }

    private void UpdateUIProgress(int count, long bytes)
    {
        Dispatcher.Post(() =>
        {
            ProgressViewModel.PacketsProcessed = count;
            ProgressViewModel.TotalBytesFormatted = NumberFormatter.FormatBytes(bytes);
        });
    }

    private void OnFinalized(long totalPackets, string trafficVolume, TimeSpan duration, int protocols, int ips, int ports, string avgSize, DateTime? captureStart, DateTime? captureEnd)
    {
        TotalPackets = totalPackets;
        TotalTrafficVolume = trafficVolume;
        CaptureDuration = duration;
        CaptureStartTime = captureStart;
        CaptureEndTime = captureEnd;
        UniqueProtocols = protocols;
        UniqueIPs = ips;
        UniquePorts = ports;
        AveragePacketSize = avgSize;
    }

    private async Task HandleAnalysisCancellation()
    {
        await Dispatcher.InvokeAsync(() =>
        {
            IsAnalyzing = false;
            _progressTimer.Stop();
        });
    }

    private async Task HandleAnalysisError()
    {
        await Dispatcher.InvokeAsync(() =>
        {
            IsAnalyzing = false;
            IsAnalysisComplete = false;
            _progressTimer.Stop();
        });
    }

    /// <summary>
    /// Builds a complete AnalysisResult for session caching.
    /// PERFORMANCE: Enables instant tab switching without redundant analysis.
    /// </summary>
    private static AnalysisResult BuildAnalysisResult(
        string filePath,
        List<PacketInfo> packets,
        NetworkStatistics statistics,
        long totalBytes,
        DateTime startTime)
    {
        var fileHash = ComputeFileHash(filePath);
        var duration = DateTime.Now - startTime;

        return new AnalysisResult
        {
            // Core data
            AllPackets = packets,
            Statistics = statistics,
            Threats = statistics.DetectedThreats?.ToList() ?? new List<SecurityThreat>(),

            // Tab-specific data (from statistics)
            CountryTraffic = statistics.CountryStatistics ?? new Dictionary<string, CountryTrafficStatistics>(),
            TrafficFlows = statistics.TrafficFlows ?? new List<TrafficFlowDirection>(),

            // Metadata
            FilePath = filePath,
            FileHash = fileHash,
            AnalyzedAt = DateTime.UtcNow,
            AnalysisDuration = duration,
            TotalPackets = packets.Count,
            TotalBytes = totalBytes
        };
    }

    /// <summary>
    /// Computes a fast hash of the file for cache validation.
    /// Uses first 64KB + file size for speed (not cryptographic security).
    /// </summary>
    private static string ComputeFileHash(string filePath)
    {
        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var sha = SHA256.Create();

            // Fast hash: first 64KB + file size
            var buffer = new byte[Math.Min(65536, stream.Length)];
            var bytesRead = stream.Read(buffer, 0, buffer.Length);

            // Include file size in hash for uniqueness
            var sizeBytes = BitConverter.GetBytes(stream.Length);
            sha.TransformBlock(buffer, 0, bytesRead, null, 0);
            sha.TransformFinalBlock(sizeBytes, 0, sizeBytes.Length);

            return Convert.ToHexString(sha.Hash!)[..16]; // Short 16-char hash
        }
        catch
        {
            // Fallback to file name + size
            var info = new FileInfo(filePath);
            return $"{info.Name}_{info.Length}";
        }
    }

    [RelayCommand(CanExecute = nameof(CanStop))]
    private void Stop()
    {
        _analysisCts?.Cancel();
        IsAnalyzing = false;
        _progressTimer.Stop();
    }

    [RelayCommand]
    private void Clear()
    {
        SelectedFilePath = null;
        SelectedFileName = null;
        IsAnalysisComplete = false;
        ProgressViewModel.ResetMetrics();
        ResetSummaryStats();
        // CRITICAL FIX: Reset all stages including their timers
        StagesViewModel.ClearAllStages();
        DebugLogger.Log("[FileAnalysisViewModel] Clear command executed - all stages and timers reset");
    }

    // ==================== NAVIGATION COMMANDS ====================
    // Tab order: FileManager(0), PacketAnalysis(1), Dashboard(2), CountryTraffic(3), VoiceQoS(4), Threats(5), Anomalies(6), HostInventory(7), Compare(8), Reports(9)

    [RelayCommand] private void NavigateToPacketAnalysis() => NavigateToTab?.Invoke(1);
    [RelayCommand] private void NavigateToDashboard() => NavigateToTab?.Invoke(2);
    [RelayCommand] private void NavigateToThreats() => NavigateToTab?.Invoke(5);
    [RelayCommand] private void NavigateToVoiceQoS() => NavigateToTab?.Invoke(4);

    // ==================== FILTER COMMANDS ====================

    [RelayCommand]
    private void ToggleFilters() => IsFiltersExpanded = !IsFiltersExpanded;

    [RelayCommand]
    private void ApplyFilters()
    {
        DebugLogger.Log("[FileAnalysisViewModel] Apply Filters requested");
        DebugLogger.Log($"[FileAnalysisViewModel] SourceIP: {SmartFilters.SourceIPCIDR}, DestIP: {SmartFilters.DestIPCIDR}");
    }

    [RelayCommand]
    private void ClearAnalysis()
    {
        SelectedFilePath = null;
        SelectedFileName = null;
        IsAnalysisComplete = false;
        ProgressViewModel.ResetMetrics();
        ProgressViewModel.QuickStats.Reset();
        StagesViewModel.Stages.Clear();
        PreviewPackets.Clear();
        DebugLogger.Log("[FileAnalysisViewModel] Analysis cleared");
    }

    [RelayCommand]
    private void ClearAllFilters()
    {
        SmartFilters.Clear();
        DebugLogger.Log("[FileAnalysisViewModel] All filters cleared");
    }

    // ==================== HELPER METHODS ====================

    private bool CanAnalyze() => !string.IsNullOrEmpty(SelectedFilePath) && !IsAnalyzing;
    private bool CanStop() => IsAnalyzing;

    private void ResetSummaryStats()
    {
        TotalPackets = 0;
        TotalTrafficVolume = "0 B";
        CaptureDuration = TimeSpan.Zero;
        CaptureStartTime = null;
        CaptureEndTime = null;
        UniqueProtocols = 0;
        UniqueIPs = 0;
        UniquePorts = 0;
        AveragePacketSize = "0 B";
    }

    // ==================== PUBLIC API (for MainWindowViewModel) ====================

    /// <summary>Report tab loading progress (Stage 6: 97-100%).</summary>
    public void ReportTabLoadingProgress(int percentWithinStage, string message)
    {
        StagesViewModel.ReportTabLoadingProgress(
            percentWithinStage,
            message,
            progress => ProgressViewModel.ProgressPercentage = progress);
    }

    /// <summary>Complete entire analysis after all tabs loaded.</summary>
    public void CompleteAnalysis()
    {
        StagesViewModel.CompleteAnalysis(() =>
        {
            ProgressViewModel.ProgressPercentage = 100;
            IsAnalyzing = false;
            IsAnalysisComplete = true;
            _progressTimer.Stop();
            DebugLogger.Log("[FileAnalysisViewModel] Analysis COMPLETE at 100%");
        });
    }

    /// <summary>Update QuickStats from analysis result.</summary>
    public void UpdateQuickStatsFromResult(AnalysisResult result) =>
        ProgressViewModel.UpdateQuickStatsFromResult(result);

    /// <summary>Sync stages from orchestrator.</summary>
    public void SyncStageFromOrchestrator(string phaseName, int percentComplete, string detail) =>
        StagesViewModel.SyncStageFromOrchestrator(phaseName, percentComplete, detail);

    /// <summary>Initialize progress reporter for ProgressCoordinator integration.</summary>
    public void InitializeProgressReporter()
    {
        DebugLogger.Log("[FileAnalysisViewModel] Progress reporter initialized");
    }

    /// <summary>Public accessor for progress reporter.</summary>
    public IProgress<AnalysisProgress>? ProgressReporter =>
        new Progress<AnalysisProgress>(ProgressViewModel.OnProgressUpdate);

    public void Dispose()
    {
        _analysisCts?.Cancel();
        _analysisCts?.Dispose();
        _progressTimer?.Stop();
        GC.SuppressFinalize(this);
    }
}
