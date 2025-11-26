using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// ViewModel for File Manager tab - provides file selection, information display, and quick statistics.
/// Delegates to FileAnalysisViewModel for actual file operations while maintaining tab-specific UI state.
/// </summary>
public partial class FileManagerViewModel : ObservableObject
{
    private readonly FileAnalysisViewModel _fileAnalysisViewModel;

    // ==================== THROTTLING ====================

    private DateTime _lastProgressUpdate = DateTime.MinValue;
    private DateTime _lastConsoleLog = DateTime.MinValue;
    private const int PROGRESS_UPDATE_THROTTLE_MS = 1000; // Max 1 update/second
    private const int CONSOLE_LOG_THROTTLE_MS = 1000;     // Max 1 log/second
    private int _lastLoggedProgressInt = -1; // Track last logged progress milestone

    // ==================== FILE PROPERTIES ====================

    [ObservableProperty] private string? _fileName;
    [ObservableProperty] private string? _filePath;
    [ObservableProperty] private string _fileSizeFormatted = "0 B";
    [ObservableProperty] private DateTime? _fileCreatedDate;
    [ObservableProperty] private DateTime? _fileModifiedDate;
    [ObservableProperty] private string _statusText = "No file selected";

    // ==================== ANALYSIS STATE ====================

    [ObservableProperty] private bool _isAnalysisComplete;
    [ObservableProperty] private bool _isAnalyzing;
    [ObservableProperty] private string _lastAnalysisText = "";

    // ==================== PROGRESS TRACKING ====================

    [ObservableProperty] private double _analysisProgress;
    [ObservableProperty] private string _currentPhase = "";
    [ObservableProperty] private string _elapsedTimeFormatted = "00:00:00";
    [ObservableProperty] private string _estimatedTimeRemaining = "Calculating...";
    [ObservableProperty] private string _processingRateFormatted = "0 pkt/s";
    [ObservableProperty] private long _currentPacketCount;
    [ObservableProperty] private System.Collections.ObjectModel.ObservableCollection<AnalysisProgressStage> _analysisStages = new();

    // ==================== ANALYSIS STATISTICS (File-specific, not network stats) ====================

    [ObservableProperty] private string _packetCount = "0";
    [ObservableProperty] private string _captureFileSize = "0 B";  // Actual PCAP file size
    [ObservableProperty] private string _duration = "00:00:00";
    [ObservableProperty] private string _processingRate = "0";
    [ObservableProperty] private string _analysisTime = "00:00:00";
    [ObservableProperty] private string _firstPacketTime = "--:--:--";
    [ObservableProperty] private string _lastPacketTime = "--:--:--";

    // ==================== DERIVED PROPERTIES ====================

    public bool HasFile
    {
        get
        {
            var hasFile = !string.IsNullOrEmpty(FilePath);
            // Reduced logging spam - only log on state changes
            return hasFile;
        }
    }

    public bool ShouldShowStages
    {
        get
        {
            return HasFile || IsAnalysisComplete;
        }
    }

    public bool CanAnalyze => HasFile && !_fileAnalysisViewModel.IsAnalyzing;

    // ==================== COMMANDS ====================

    public ICommand? BrowseCommand => _fileAnalysisViewModel.BrowseCommand;
    public ICommand? AnalyzeCommand => _fileAnalysisViewModel.AnalyzeCommand;

    [RelayCommand]
    private void Clear()
    {
        // Clear FileAnalysisViewModel via its public command instead of private method
        if (_fileAnalysisViewModel.ClearCommand?.CanExecute(null) == true)
        {
            _fileAnalysisViewModel.ClearCommand.Execute(null);
        }
    }

    [RelayCommand(CanExecute = nameof(CanExportReport))]
    private async Task ExportReport()
    {
        // FUTURE: Implement export report (PDF/HTML) via ReportGeneratorService
        await Task.CompletedTask;
    }

    private bool CanExportReport() => IsAnalysisComplete;

    // ==================== CONSTRUCTOR ====================

    /// <summary>
    /// Initializes FileManagerViewModel with reference to FileAnalysisViewModel.
    /// Subscribes to property changes to update File Manager tab UI in real-time.
    /// </summary>
    /// <param name="fileAnalysisViewModel">Shared FileAnalysisViewModel instance</param>
    /// <exception cref="ArgumentNullException">Thrown when fileAnalysisViewModel is null</exception>
    public FileManagerViewModel(FileAnalysisViewModel fileAnalysisViewModel)
    {
        _fileAnalysisViewModel = fileAnalysisViewModel ?? throw new ArgumentNullException(nameof(fileAnalysisViewModel));

        // Subscribe to FileAnalysisViewModel property changes
        _fileAnalysisViewModel.PropertyChanged += OnFileAnalysisViewModelPropertyChanged;

        // Initialize with current state
        UpdateFromFileAnalysisViewModel();
    }

    // ==================== EVENT HANDLERS ====================

    /// <summary>
    /// Handles property changes from FileAnalysisViewModel and updates File Manager UI accordingly.
    /// Provides real-time synchronization between analysis state and File Manager display.
    /// ✅ FIX: Added Stages subscription to detect stage mutations.
    /// </summary>
    private void OnFileAnalysisViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(FileAnalysisViewModel.SelectedFilePath):
                UpdateFileInfo();
                OnPropertyChanged(nameof(HasFile));
                OnPropertyChanged(nameof(ShouldShowStages)); // ✅ Notify UI that visibility should update
                OnPropertyChanged(nameof(CanAnalyze));
                break;

            case nameof(FileAnalysisViewModel.Stages):
                // ✅ FIX: Re-sync stages when collection changes (throttled to 1/sec)
                UpdateProgressInfo();
                break;

            case nameof(FileAnalysisViewModel.IsAnalyzing):
                IsAnalyzing = _fileAnalysisViewModel.IsAnalyzing;
                UpdateStatusText();
                OnPropertyChanged(nameof(CanAnalyze));
                break;

            case nameof(FileAnalysisViewModel.IsAnalysisComplete):
                IsAnalysisComplete = _fileAnalysisViewModel.IsAnalysisComplete;

                // ✅ CLEANUP: Reduced diagnostic logging (production-friendly)
                if (IsAnalysisComplete)
                {
                    DebugLogger.Log($"[FileManagerVM] 🏁 Analysis complete - {AnalysisStages.Count} stages finished");
                }

                OnPropertyChanged(nameof(ShouldShowStages)); // ✅ Notify UI that visibility should update
                UpdateStatusText();
                UpdateQuickStats();
                UpdateLastAnalysisText();
                ExportReportCommand.NotifyCanExecuteChanged();
                break;

            case nameof(FileAnalysisViewModel.ProgressPercentage):
                AnalysisProgress = _fileAnalysisViewModel.ProgressPercentage;
                break;

            case nameof(FileAnalysisViewModel.PacketsProcessed):
                CurrentPacketCount = _fileAnalysisViewModel.PacketsProcessed;
                break;

            case nameof(FileAnalysisViewModel.PacketsPerSecond):
                ProcessingRateFormatted = $"{NumberFormatter.FormatCount(_fileAnalysisViewModel.PacketsPerSecond)} pkt/s";
                break;

            case nameof(FileAnalysisViewModel.ElapsedTime):
                ElapsedTimeFormatted = _fileAnalysisViewModel.ElapsedTime.ToString(@"hh\:mm\:ss");
                break;

            case nameof(FileAnalysisViewModel.RemainingTimeFormatted):
                EstimatedTimeRemaining = _fileAnalysisViewModel.RemainingTimeFormatted;
                break;

            case nameof(FileAnalysisViewModel.TotalPackets):
            case nameof(FileAnalysisViewModel.TotalTrafficVolume):
            case nameof(FileAnalysisViewModel.CaptureDuration):
            case nameof(FileAnalysisViewModel.UniqueProtocols):
            case nameof(FileAnalysisViewModel.QuickStats):
                UpdateQuickStats();
                break;
        }
    }

    // ==================== UPDATE METHODS ====================

    /// <summary>
    /// Updates all File Manager properties from current FileAnalysisViewModel state.
    /// Called during initialization and when significant state changes occur.
    /// </summary>
    private void UpdateFromFileAnalysisViewModel()
    {
        UpdateFileInfo();
        UpdateStatusText();
        UpdateQuickStats();
        UpdateLastAnalysisText();
        UpdateProgressInfo();
    }

    /// <summary>
    /// Updates progress tracking properties from FileAnalysisViewModel.
    /// Syncs progress percentage, stages, current phase, and real-time metrics.
    /// ⚡ THROTTLED: Max 1 update/second to prevent UI spam.
    /// </summary>
    private void UpdateProgressInfo()
    {
        // ⚡ THROTTLE: Only update once per second max
        var now = DateTime.Now;
        var timeSinceLastUpdate = (now - _lastProgressUpdate).TotalMilliseconds;

        if (timeSinceLastUpdate < PROGRESS_UPDATE_THROTTLE_MS)
        {
            return; // Throttled - skip this update
        }

        _lastProgressUpdate = now;

        // Update all progress properties
        IsAnalyzing = _fileAnalysisViewModel.IsAnalyzing;
        AnalysisProgress = _fileAnalysisViewModel.ProgressPercentage;
        CurrentPacketCount = _fileAnalysisViewModel.PacketsProcessed;
        ElapsedTimeFormatted = _fileAnalysisViewModel.ElapsedTime.ToString(@"hh\:mm\:ss");
        EstimatedTimeRemaining = _fileAnalysisViewModel.RemainingTimeFormatted;
        ProcessingRateFormatted = $"{NumberFormatter.FormatCount(_fileAnalysisViewModel.PacketsPerSecond)} pkt/s";

        // Sync stages collection (keep same references, don't Clear+Add)
        // This is more efficient than Clear() + AddRange()
        if (AnalysisStages.Count == 0)
        {
            // First time: populate collection
            DebugLogger.Log($"[FileManagerVM] Syncing stages from FileAnalysisVM ({_fileAnalysisViewModel.Stages.Count} stages)");
            foreach (var stage in _fileAnalysisViewModel.Stages)
            {
                AnalysisStages.Add(stage);
                DebugLogger.Log($"[FileManagerVM]   Added stage: {stage.Name ?? "(null)"} [{stage.Key}]");
            }
            DebugLogger.Log($"[FileManagerVM] AnalysisStages.Count = {AnalysisStages.Count}");
            DebugLogger.Log($"[FileManagerVM] 🎨 UI BINDING CHECK: HasFile={HasFile}, FilePath={FilePath ?? "(null)"}");
            DebugLogger.Log($"[FileManagerVM] 🎨 Collection ready for ItemsControl binding");
        }
        // Else: stages already synced by reference (same objects)

        // Determine current phase from active stage
        var activeStage = _fileAnalysisViewModel.Stages.FirstOrDefault(s => s.State == AnalysisStageState.Active);
        CurrentPhase = activeStage?.Name ?? "Idle";

        // ⚡ THROTTLED LOGGING: Only log at major milestones (every 10%)
        var timeSinceLastLog = (now - _lastConsoleLog).TotalMilliseconds;
        var progressInt = (int)AnalysisProgress;
        if (progressInt % 10 == 0 && progressInt != _lastLoggedProgressInt && timeSinceLastLog >= CONSOLE_LOG_THROTTLE_MS)
        {
            _lastConsoleLog = now;
            _lastLoggedProgressInt = progressInt;
            DebugLogger.Log($"[Progress] {AnalysisProgress:F1}% | {CurrentPhase}");
        }
    }

    /// <summary>
    /// Updates file information display (name, path, size, modified date).
    /// Reads file metadata from disk if file exists.
    /// </summary>
    private void UpdateFileInfo()
    {
        var path = _fileAnalysisViewModel.SelectedFilePath;

        if (string.IsNullOrEmpty(path))
        {
            FileName = null;
            FilePath = null;
            FileSizeFormatted = "0 B";
            FileCreatedDate = null;
            FileModifiedDate = null;
        }
        else
        {
            FileName = Path.GetFileName(path);
            FilePath = path;

            try
            {
                if (File.Exists(path))
                {
                    var fileInfo = new FileInfo(path);
                    FileSizeFormatted = NumberFormatter.FormatBytes(fileInfo.Length);
                    FileCreatedDate = fileInfo.CreationTime;
                    FileModifiedDate = fileInfo.LastWriteTime;
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[FileManagerViewModel] Error reading file info: {ex.Message}");
                FileSizeFormatted = "Unknown";
                FileCreatedDate = null;
                FileModifiedDate = null;
            }
        }
    }

    /// <summary>
    /// Updates status text badge based on current analysis state.
    /// Shows "Ready", "Analyzing...", or "Complete" with visual indicators.
    /// </summary>
    private void UpdateStatusText()
    {
        if (!HasFile)
        {
            StatusText = "No file selected";
        }
        else if (_fileAnalysisViewModel.IsAnalyzing)
        {
            StatusText = "⚡ Analyzing...";
        }
        else if (_fileAnalysisViewModel.IsAnalysisComplete)
        {
            StatusText = "✅ Analysis Complete";
        }
        else
        {
            StatusText = "📂 Ready to analyze";
        }
    }

    /// <summary>
    /// Updates analysis statistics display from FileAnalysisViewModel results.
    /// Shows FILE-SPECIFIC stats: packet count, file size, timestamps, processing metrics.
    /// Does NOT show network stats (IPs, ports, protocols) - those belong in analysis tabs.
    /// </summary>
    private void UpdateQuickStats()
    {
        if (!_fileAnalysisViewModel.IsAnalysisComplete)
        {
            // Clear stats if not complete
            PacketCount = "0";
            CaptureFileSize = FileSizeFormatted;  // Show PCAP file size
            Duration = "00:00:00";
            ProcessingRate = "0";
            AnalysisTime = "00:00:00";
            FirstPacketTime = "--:--:--";
            LastPacketTime = "--:--:--";
            return;
        }

        // Use QuickStats model if available, otherwise fallback to individual properties
        var quickStats = _fileAnalysisViewModel.QuickStats;

        // Packet Count (use abbreviated format)
        PacketCount = quickStats.TotalPackets > 0
            ? NumberFormatter.FormatCount(quickStats.TotalPackets)
            : _fileAnalysisViewModel.TotalPackets > 0
                ? NumberFormatter.FormatCount(_fileAnalysisViewModel.TotalPackets)
                : "0";

        // Capture File Size (actual PCAP file size, not traffic volume)
        CaptureFileSize = FileSizeFormatted;

        // Capture Duration
        Duration = _fileAnalysisViewModel.CaptureDuration.TotalSeconds > 0
            ? NumberFormatter.FormatTimeSpan(_fileAnalysisViewModel.CaptureDuration)
            : "00:00:00";

        // Processing Rate (pkts/sec during analysis)
        ProcessingRate = quickStats.ProcessingRate > 0
            ? NumberFormatter.FormatCount(quickStats.ProcessingRate)
            : _fileAnalysisViewModel.ElapsedTime.TotalSeconds > 0 && _fileAnalysisViewModel.TotalPackets > 0
                ? NumberFormatter.FormatCount((long)(_fileAnalysisViewModel.TotalPackets / _fileAnalysisViewModel.ElapsedTime.TotalSeconds))
                : "0";

        // Analysis Time (how long the analysis took)
        AnalysisTime = _fileAnalysisViewModel.ElapsedTime.TotalSeconds > 0
            ? NumberFormatter.FormatTimeSpan(_fileAnalysisViewModel.ElapsedTime)
            : "00:00:00";

        // First/Last Packet Timestamps (from capture)
        // FUTURE: Add FirstPacketTime/LastPacketTime properties to FileAnalysisViewModel
        FirstPacketTime = "--:--:--";
        LastPacketTime = "--:--:--";
    }

    /// <summary>
    /// Updates "Last analyzed" timestamp display.
    /// Shows relative time (e.g., "Last analyzed: 2 minutes ago").
    /// </summary>
    private void UpdateLastAnalysisText()
    {
        if (!_fileAnalysisViewModel.IsAnalysisComplete)
        {
            LastAnalysisText = "";
            return;
        }

        // Simple implementation - could be enhanced with relative time formatting
        LastAnalysisText = $"Last analyzed: {DateTime.Now:HH:mm:ss}";
    }
}
