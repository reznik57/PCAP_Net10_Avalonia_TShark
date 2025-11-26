using System;
using System.Linq;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Constants;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Lightweight ViewModel for adaptive file selection control.
/// Manages UI state transitions (Empty, Analyzing, Complete, Collapsed) without duplicating business logic.
/// Business logic remains in FileAnalysisViewModel.
/// </summary>
public partial class FileSelectionControlViewModel : ObservableObject, IDisposable
{
    private readonly FileAnalysisViewModel _fileAnalysisViewModel;
    private System.Timers.Timer? _countdownTimer;

    // ==================== STATE MANAGEMENT ====================

    /// <summary>
    /// Current state of the file selection control
    /// </summary>
    [ObservableProperty]
    private FileControlState _currentState = FileControlState.Empty;

    /// <summary>
    /// Adaptive height based on current state (28-160px)
    /// Uses FileControlHeights constants for consistency
    /// </summary>
    [ObservableProperty]
    private double _fileControlHeight = FileControlHeights.Empty; // Start with Empty state height

    /// <summary>
    /// Whether control is in collapsed state (minimal indicator)
    /// </summary>
    [ObservableProperty]
    private bool _isCollapsed;

    // ==================== FILE INFORMATION ====================

    /// <summary>
    /// Currently selected file name (without path)
    /// </summary>
    [ObservableProperty]
    private string? _fileName;

    /// <summary>
    /// Quick statistics summary (e.g., "1.1M pkts • 274 MB • 01:18")
    /// </summary>
    [ObservableProperty]
    private string? _quickStats;

    /// <summary>
    /// Full file path
    /// </summary>
    [ObservableProperty]
    private string? _filePath;

    // ==================== FORMATTED METRIC PROPERTIES ====================

    /// <summary>
    /// Formatted packet count for display (e.g., "1.1M")
    /// </summary>
    [ObservableProperty]
    private string _packetCountFormatted = "0";

    /// <summary>
    /// FULL packet count with European formatting (e.g., "1.106.937")
    /// </summary>
    [ObservableProperty]
    private string _packetCountFullFormatted = "0";

    /// <summary>
    /// Processing rate with European formatting (e.g., "24.287 pkts/sec")
    /// </summary>
    [ObservableProperty]
    private string _processingRateFormatted = "0 pkts/sec";

    /// <summary>
    /// Formatted file size for display (e.g., "274 MB")
    /// </summary>
    [ObservableProperty]
    private string _fileSizeFormatted = "0 B";

    /// <summary>
    /// Formatted duration for display (e.g., "01:18")
    /// </summary>
    [ObservableProperty]
    private string _durationFormatted = "00:00";

    /// <summary>
    /// Stage breakdown summary (e.g., "Stage 0: 5.2s • Stage 1: 68.4s • Stage 2: 13.1s")
    /// </summary>
    [ObservableProperty]
    private string _stageBreakdownSummary = "";

    // ==================== PROGRESS PROPERTIES (PASSTHROUGH) ====================

    /// <summary>
    /// Current analysis progress (0-100%)
    /// </summary>
    [ObservableProperty]
    private double _progressPercentage;

    /// <summary>
    /// Elapsed time since analysis started (formatted)
    /// </summary>
    [ObservableProperty]
    private string _elapsedTimeFormatted = "00:00";

    /// <summary>
    /// Estimated time remaining (formatted)
    /// </summary>
    [ObservableProperty]
    private string _remainingTimeFormatted = "Calculating...";

    /// <summary>
    /// Current progress message (e.g., "Stage 1: Loading Packets - 45%")
    /// </summary>
    [ObservableProperty]
    private string _progressMessage = "Starting analysis...";

    /// <summary>
    /// Packets processed so far
    /// </summary>
    [ObservableProperty]
    private long _packetsProcessed;

    /// <summary>
    /// Total packets in file
    /// </summary>
    [ObservableProperty]
    private long _totalPacketsInFile;

    /// <summary>
    /// Processing speed (packets/second)
    /// </summary>
    [ObservableProperty]
    private long _packetsPerSecond;

    // ==================== COUNTDOWN PROPERTIES ====================

    /// <summary>
    /// Countdown seconds remaining before auto-start (2, 1, 0)
    /// </summary>
    [ObservableProperty]
    private int _countdownSeconds = 2;

    /// <summary>
    /// Countdown message for display
    /// </summary>
    [ObservableProperty]
    private string _countdownMessage = "Starting in 2...";

    // ==================== STATE VISIBILITY PROPERTIES ====================

    /// <summary>
    /// Show empty state (drop zone + browse button)
    /// </summary>
    public bool IsEmpty => CurrentState == FileControlState.Empty;

    /// <summary>
    /// Show file selected state (countdown + cancel)
    /// </summary>
    public bool IsFileSelected => CurrentState == FileControlState.FileSelected;

    /// <summary>
    /// Show analyzing state (compact bar with pause/stop)
    /// </summary>
    public bool IsAnalyzing => CurrentState == FileControlState.Analyzing;

    /// <summary>
    /// Show complete state (info bar with stats + actions)
    /// </summary>
    public bool IsComplete => CurrentState == FileControlState.Complete;

    // ==================== CONSTRUCTOR ====================

    public FileSelectionControlViewModel(FileAnalysisViewModel fileAnalysisViewModel)
    {
        _fileAnalysisViewModel = fileAnalysisViewModel ?? throw new ArgumentNullException(nameof(fileAnalysisViewModel));

        // Subscribe to FileAnalysisViewModel state changes
        _fileAnalysisViewModel.PropertyChanged += OnFileAnalysisViewModelPropertyChanged;

        // Initialize countdown timer (1 second interval)
        _countdownTimer = new System.Timers.Timer(1000);
        _countdownTimer.Elapsed += OnCountdownTick;
        _countdownTimer.AutoReset = true;
    }

    // ==================== EVENT HANDLERS ====================

    private void OnFileAnalysisViewModelPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(FileAnalysisViewModel.SelectedFilePath):
                OnFileSelected(_fileAnalysisViewModel.SelectedFilePath);
                break;

            case nameof(FileAnalysisViewModel.IsAnalyzing):
                if (_fileAnalysisViewModel.IsAnalyzing)
                    TransitionToAnalyzing();
                break;

            case nameof(FileAnalysisViewModel.IsAnalysisComplete):
                if (_fileAnalysisViewModel.IsAnalysisComplete)
                    TransitionToComplete();
                break;

            case nameof(FileAnalysisViewModel.TotalPackets):
            case nameof(FileAnalysisViewModel.TotalTrafficVolume):
            case nameof(FileAnalysisViewModel.CaptureDuration):
                UpdateQuickStats();
                break;

            // ==================== PROGRESS PROPERTY PASSTHROUGH ====================

            case nameof(FileAnalysisViewModel.ProgressPercentage):
                ProgressPercentage = _fileAnalysisViewModel.ProgressPercentage;
                UpdateProgressMessage(); // Generate user-friendly message
                break;

            case nameof(FileAnalysisViewModel.ElapsedTime):
                ElapsedTimeFormatted = NumberFormatter.FormatTimeSpan(_fileAnalysisViewModel.ElapsedTime);
                break;

            case nameof(FileAnalysisViewModel.RemainingTimeFormatted):
                RemainingTimeFormatted = _fileAnalysisViewModel.RemainingTimeFormatted;
                break;

            case nameof(FileAnalysisViewModel.PacketsProcessed):
                PacketsProcessed = _fileAnalysisViewModel.PacketsProcessed;
                UpdateProgressMessage(); // Update message with current packet count
                break;

            case nameof(FileAnalysisViewModel.TotalPacketsInFile):
                TotalPacketsInFile = _fileAnalysisViewModel.TotalPacketsInFile;
                break;

            case nameof(FileAnalysisViewModel.PacketsPerSecond):
                PacketsPerSecond = _fileAnalysisViewModel.PacketsPerSecond;
                break;

            case nameof(FileAnalysisViewModel.Stages):
                UpdateProgressMessage(); // Update based on current stage
                break;
        }
    }

    // ==================== PROGRESS HELPER METHODS ====================

    /// <summary>
    /// Generate user-friendly progress message from current stage and progress percentage
    /// </summary>
    private void UpdateProgressMessage()
    {
        // Find the current active stage (using State enum)
        var currentStage = _fileAnalysisViewModel.Stages
            .LastOrDefault(s => s.State == AnalysisStageState.Active || s.State == AnalysisStageState.Completed);

        if (currentStage != null)
        {
            var progressPercent = (int)Math.Round(ProgressPercentage);

            // Format: "Stage Name - XX% • X.XXK pkts/s"
            if (PacketsPerSecond > 0)
            {
                var speedFormatted = NumberFormatter.FormatCount(PacketsPerSecond);
                ProgressMessage = $"{currentStage.Name} - {progressPercent}%  •  {speedFormatted} pkts/s";
            }
            else
            {
                ProgressMessage = $"{currentStage.Name} - {progressPercent}%";
            }
        }
        else if (ProgressPercentage > 0)
        {
            // Fallback: just show percentage
            var progressPercent = (int)Math.Round(ProgressPercentage);
            ProgressMessage = $"Analyzing... {progressPercent}%";
        }
        else
        {
            ProgressMessage = "Starting analysis...";
        }
    }

    // ==================== COUNTDOWN TIMER ====================

    /// <summary>
    /// Countdown timer tick handler - decrements countdown and auto-starts when reaches 0
    /// </summary>
    private void OnCountdownTick(object? sender, System.Timers.ElapsedEventArgs e)
    {
        // Must update UI on UI thread
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            CountdownSeconds--;

            if (CountdownSeconds > 0)
            {
                CountdownMessage = $"Starting in {CountdownSeconds}...";
            }
            else
            {
                // Countdown reached 0 - auto-start analysis
                StopCountdown();
                CountdownMessage = "Starting now!";

                if (_fileAnalysisViewModel.AnalyzeCommand?.CanExecute(null) == true)
                {
                    DebugLogger.Log("[FileSelectionControl] Auto-starting analysis after countdown");
                    _ = ((CommunityToolkit.Mvvm.Input.IAsyncRelayCommand)_fileAnalysisViewModel.AnalyzeCommand).ExecuteAsync(null);
                }
            }
        });
    }

    /// <summary>
    /// Stop countdown timer
    /// </summary>
    private void StopCountdown()
    {
        _countdownTimer?.Stop();
    }

    /// <summary>
    /// Start countdown timer (2 seconds)
    /// </summary>
    private void StartCountdown()
    {
        CountdownSeconds = 2;
        CountdownMessage = "Starting in 2...";
        _countdownTimer?.Start();
    }

    // ==================== STATE TRANSITIONS ====================

    /// <summary>
    /// Called when user selects a file
    /// </summary>
    private void OnFileSelected(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            TransitionToEmpty();
            return;
        }

        FilePath = path;
        FileName = System.IO.Path.GetFileName(path);

        // File selected, but analysis hasn't started yet - show countdown state
        if (!_fileAnalysisViewModel.IsAnalyzing && !_fileAnalysisViewModel.IsAnalysisComplete)
        {
            TransitionToFileSelected();
        }
    }

    /// <summary>
    /// Transition to FileSelected state (show file info + countdown)
    /// </summary>
    private void TransitionToFileSelected()
    {
        CurrentState = FileControlState.FileSelected;
        FileControlHeight = FileControlHeights.FileSelected;
        IsCollapsed = false;
        StartCountdown(); // Start 2-second countdown
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(IsFileSelected));
        OnPropertyChanged(nameof(IsAnalyzing));
        OnPropertyChanged(nameof(IsComplete));
    }

    /// <summary>
    /// Transition to Empty state (no file selected)
    /// </summary>
    private void TransitionToEmpty()
    {
        StopCountdown(); // Ensure countdown stops
        CurrentState = FileControlState.Empty;
        FileControlHeight = FileControlHeights.Empty;
        IsCollapsed = false;
        FileName = null;
        QuickStats = null;
        FilePath = null;
        PacketCountFormatted = "0";
        FileSizeFormatted = "0 B";
        DurationFormatted = "00:00";

        // Reset progress properties
        ProgressPercentage = 0;
        ProgressMessage = "Starting analysis...";
        ElapsedTimeFormatted = "00:00";
        RemainingTimeFormatted = "Calculating...";
        PacketsProcessed = 0;
        TotalPacketsInFile = 0;
        PacketsPerSecond = 0;

        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(IsFileSelected)); // FIX: Notify FileSelected state change
        OnPropertyChanged(nameof(IsAnalyzing));
        OnPropertyChanged(nameof(IsComplete));
    }

    /// <summary>
    /// Transition to Analyzing state (progress bar with full metrics)
    /// </summary>
    private void TransitionToAnalyzing()
    {
        StopCountdown(); // Ensure countdown stops
        CurrentState = FileControlState.Analyzing;
        FileControlHeight = FileControlHeights.Analyzing;
        IsCollapsed = false;
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(IsFileSelected)); // FIX: Notify FileSelected state change
        OnPropertyChanged(nameof(IsAnalyzing));
        OnPropertyChanged(nameof(IsComplete));
    }

    /// <summary>
    /// Transition to Complete state (metric cards + stage breakdown + actions)
    /// </summary>
    private void TransitionToComplete()
    {
        StopCountdown(); // Ensure countdown stops
        CurrentState = FileControlState.Complete;
        FileControlHeight = FileControlHeights.Complete;
        IsCollapsed = false;
        UpdateQuickStats();
        UpdateFormattedMetrics();
        OnPropertyChanged(nameof(IsEmpty));
        OnPropertyChanged(nameof(IsFileSelected)); // FIX: Notify FileSelected state change
        OnPropertyChanged(nameof(IsAnalyzing));
        OnPropertyChanged(nameof(IsComplete));
    }

    /// <summary>
    /// Update quick statistics from FileAnalysisViewModel
    /// </summary>
    private void UpdateQuickStats()
    {
        if (_fileAnalysisViewModel.TotalPackets > 0)
        {
            var packets = NumberFormatter.FormatCount(_fileAnalysisViewModel.TotalPackets);
            var traffic = _fileAnalysisViewModel.TotalTrafficVolume ?? "0 B";
            var duration = NumberFormatter.FormatTimeSpan(_fileAnalysisViewModel.CaptureDuration);

            QuickStats = $"{packets} pkts  •  {traffic}  •  {duration}";
        }
        else
        {
            QuickStats = null;
        }
    }

    /// <summary>
    /// Update formatted metrics for Complete state metric cards
    /// </summary>
    private void UpdateFormattedMetrics()
    {
        // Packet count (abbreviated for backwards compatibility)
        PacketCountFormatted = _fileAnalysisViewModel.TotalPackets > 0
            ? NumberFormatter.FormatCount(_fileAnalysisViewModel.TotalPackets)
            : "0";

        // FULL packet count with European formatting
        PacketCountFullFormatted = _fileAnalysisViewModel.TotalPackets > 0
            ? NumberFormatter.FormatNumberEuropean(_fileAnalysisViewModel.TotalPackets)
            : "0";

        // Processing rate (packets per second) with European formatting
        var avgRate = _fileAnalysisViewModel.ElapsedTime.TotalSeconds > 0
            ? (long)(_fileAnalysisViewModel.TotalPackets / _fileAnalysisViewModel.ElapsedTime.TotalSeconds)
            : 0;
        ProcessingRateFormatted = avgRate > 0
            ? $"{NumberFormatter.FormatNumberEuropean(avgRate)} pkts/sec"
            : "0 pkts/sec";

        // File size
        FileSizeFormatted = _fileAnalysisViewModel.TotalTrafficVolume ?? "0 B";

        // Duration
        DurationFormatted = NumberFormatter.FormatTimeSpan(_fileAnalysisViewModel.CaptureDuration);

        // Stage breakdown summary
        UpdateStageBreakdown();
    }

    /// <summary>
    /// Update stage breakdown summary from completed stages
    /// Format: "Stage 0: 5.2s • Stage 1: 68.4s • Stage 2: 13.1s"
    /// </summary>
    private void UpdateStageBreakdown()
    {
        var completedStages = _fileAnalysisViewModel.Stages
            .Where(s => s.State == AnalysisStageState.Completed && !string.IsNullOrEmpty(s.ElapsedTime))
            .ToList();

        if (completedStages.Count == 0)
        {
            StageBreakdownSummary = "No stage data available";
            return;
        }

        var stageParts = completedStages
            .Select(s => $"{s.Name}: {s.ElapsedTime}")
            .ToArray();

        StageBreakdownSummary = string.Join(" • ", stageParts);
    }

    // ==================== COMMANDS ====================

    /// <summary>
    /// Browse command - delegates to FileAnalysisViewModel
    /// </summary>
    public ICommand? BrowseCommand => _fileAnalysisViewModel.BrowseCommand;

    /// <summary>
    /// Analyze command - delegates to FileAnalysisViewModel
    /// </summary>
    public ICommand? AnalyzeCommand => _fileAnalysisViewModel.AnalyzeCommand;

    /// <summary>
    /// Stop command - delegates to FileAnalysisViewModel
    /// </summary>
    public ICommand? StopCommand => _fileAnalysisViewModel.StopCommand;

    /// <summary>
    /// Collapse control to minimal indicator
    /// </summary>
    [RelayCommand]
    private void Collapse()
    {
        IsCollapsed = true;
        FileControlHeight = FileControlHeights.Collapsed;
    }

    /// <summary>
    /// Expand control from collapsed state
    /// </summary>
    [RelayCommand]
    private void Expand()
    {
        IsCollapsed = false;
        FileControlHeight = CurrentState switch
        {
            FileControlState.Empty => FileControlHeights.Empty,
            FileControlState.FileSelected => FileControlHeights.FileSelected,
            FileControlState.Analyzing => FileControlHeights.Analyzing,
            FileControlState.Complete => FileControlHeights.Complete,
            _ => FileControlHeights.Empty
        };
    }

    /// <summary>
    /// Clear current file and reset to empty state
    /// </summary>
    [RelayCommand]
    private void Clear()
    {
        _fileAnalysisViewModel.SelectedFilePath = null;
        TransitionToEmpty();
    }

    /// <summary>
    /// Cancel countdown and return to empty state
    /// </summary>
    [RelayCommand]
    private void CancelCountdown()
    {
        StopCountdown();
        _fileAnalysisViewModel.SelectedFilePath = null;
        TransitionToEmpty();
        DebugLogger.Log("[FileSelectionControl] Countdown cancelled by user");
    }

    /// <summary>
    /// Skip countdown and start analysis immediately
    /// </summary>
    [RelayCommand]
    private void AnalyzeNow()
    {
        StopCountdown();
        DebugLogger.Log("[FileSelectionControl] User skipped countdown - starting immediately");

        if (_fileAnalysisViewModel.AnalyzeCommand?.CanExecute(null) == true)
        {
            _ = ((CommunityToolkit.Mvvm.Input.IAsyncRelayCommand)_fileAnalysisViewModel.AnalyzeCommand).ExecuteAsync(null);
        }
    }

    /// <summary>
    /// Reanalyze current file
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanReanalyze))]
    private async Task Reanalyze(CancellationToken cancellationToken = default)
    {
        if (_fileAnalysisViewModel.AnalyzeCommand?.CanExecute(null) == true)
        {
            await ((IAsyncRelayCommand)_fileAnalysisViewModel.AnalyzeCommand).ExecuteAsync(cancellationToken);
        }
    }

    private bool CanReanalyze()
    {
        return !string.IsNullOrEmpty(FilePath) &&
               !_fileAnalysisViewModel.IsAnalyzing &&
               _fileAnalysisViewModel.AnalyzeCommand?.CanExecute(null) == true;
    }

    /// <summary>
    /// Dispose of managed resources (countdown timer).
    /// </summary>
    public void Dispose()
    {
        _countdownTimer?.Stop();
        _countdownTimer?.Dispose();
        _countdownTimer = null;
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// File control state enumeration
/// </summary>
public enum FileControlState
{
    /// <summary>
    /// No file selected - show drop zone + browse button
    /// </summary>
    Empty,

    /// <summary>
    /// File selected, countdown to auto-start - show file info + countdown + cancel button
    /// </summary>
    FileSelected,

    /// <summary>
    /// Analysis in progress - show compact bar with pause/stop
    /// </summary>
    Analyzing,

    /// <summary>
    /// Analysis complete - show info bar with stats + actions
    /// </summary>
    Complete
}
