using System;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public enum AnalysisStageState
{
    Pending,
    Active,
    Completed,
    Error
}

public partial class AnalysisProgressStage : ObservableObject
{
    private DateTime? _startTime;
    private DateTime? _endTime;
    private DispatcherTimer? _elapsedTimer;
    private int _lastLoggedSecond = -1; // Track last logged 5-second interval

    public AnalysisProgressStage(string key, string name, string description, bool showProgressBar = false)
    {
        Key = key;
        _name = name;
        _description = description;
        _detail = description;
        _showProgressBar = showProgressBar;
        _state = AnalysisStageState.Pending;
        _percentComplete = 0;
        _elapsedTime = string.Empty;
    }

    public string Key { get; }

    [ObservableProperty]
    private string _name;

    [ObservableProperty]
    private string _description;

    [ObservableProperty]
    private AnalysisStageState _state;

    [ObservableProperty]
    private double _percentComplete;

    [ObservableProperty]
    private string _detail;

    [ObservableProperty]
    private bool _showProgressBar;

    [ObservableProperty]
    private string _elapsedTime;

    /// <summary>
    /// Gets the icon for the current stage state (pending, active, completed, error)
    /// </summary>
    public string StateIcon => State switch
    {
        AnalysisStageState.Pending => "⏸️",
        AnalysisStageState.Active => "⏳",
        AnalysisStageState.Completed => "✅",
        AnalysisStageState.Error => "❌",
        _ => "❓"
    };

    /// <summary>
    /// Gets the color for the current stage state
    /// </summary>
    public string StateColor => State switch
    {
        AnalysisStageState.Pending => "#8B949E",     // Gray
        AnalysisStageState.Active => "#58A6FF",      // Blue
        AnalysisStageState.Completed => "#238636",   // Green
        AnalysisStageState.Error => "#DA3633",       // Red
        _ => "#8B949E"
    };

    partial void OnStateChanged(AnalysisStageState value)
    {
        // Notify that icon, color, and display detail properties changed when state changes
        OnPropertyChanged(nameof(StateIcon));
        OnPropertyChanged(nameof(StateColor));
        OnPropertyChanged(nameof(DisplayDetail));
    }

    /// <summary>
    /// Gets the display-friendly detail text. Shows "Waiting..." for pending stages.
    /// </summary>
    public string DisplayDetail => State == AnalysisStageState.Pending ? "Waiting..." : Detail;

    partial void OnDetailChanged(string value)
    {
        // Notify DisplayDetail when Detail changes
        OnPropertyChanged(nameof(DisplayDetail));
    }

    /// <summary>
    /// Starts timing this stage and begins real-time elapsed time updates.
    /// ✅ CRITICAL FIX: Only starts if not already running (prevents timer resets!)
    /// </summary>
    public void StartTiming()
    {
        // ✅ CRITICAL: Don't restart timer if already running!
        // Check ONLY _startTime - this is the definitive indicator that timing has started
        if (_startTime.HasValue)
        {
            // Already running - just update elapsed time display
            DebugLogger.Log($"[TIMING] [{Name}] ⏭️  Already timing (started at {_startTime:HH:mm:ss.fff}) - skipping restart");
            UpdateElapsedTime();
            return;
        }

        _startTime = DateTime.Now;
        _endTime = null;

        // ✅ FIX: Show initial "0.0s" immediately so timer doesn't appear stuck
        ElapsedTime = "0.0s";

        DebugLogger.Log($"[TIMING] [{Name}] ⏱️  START TIMING at {_startTime:HH:mm:ss.fff}");

        // Start timer for real-time elapsed time updates (every 100ms for responsiveness)
        _elapsedTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(100)
        };
        _elapsedTimer.Tick += (s, e) => UpdateElapsedTime();
        _elapsedTimer.Start();

        // ✅ FIX: Force immediate first update to show "0.0s" → "0.1s" quickly
        UpdateElapsedTime();
    }

    /// <summary>
    /// Stops timing and calculates final elapsed time
    /// </summary>
    public void StopTiming()
    {
        // Stop and dispose timer
        if (_elapsedTimer != null)
        {
            _elapsedTimer.Stop();
            _elapsedTimer = null;
        }

        if (_startTime.HasValue)
        {
            _endTime = DateTime.Now;
            UpdateElapsedTime();
            var duration = _endTime.Value - _startTime.Value;
            DebugLogger.Log($"[TIMING] [{Name}] ⏹️  STOP TIMING at {_endTime:HH:mm:ss.fff} - Duration: {duration.TotalSeconds:F1}s → ElapsedTime={ElapsedTime}");
        }
        else
        {
            DebugLogger.Log($"[TIMING] [{Name}] ⚠️  STOP TIMING called but _startTime is NULL!");
        }
    }

    /// <summary>
    /// Updates elapsed time display (for active stages)
    /// </summary>
    public void UpdateElapsedTime()
    {
        if (!_startTime.HasValue)
        {
            ElapsedTime = string.Empty;
            return;
        }

        var end = _endTime ?? DateTime.Now;
        var elapsed = end - _startTime.Value;

        var newElapsedTime = Helpers.TimeFormatter.FormatAsSeconds(elapsed);

        // Log only once per 5-second interval (e.g., at 0s, 5s, 10s, 15s...)
        var currentInterval = (int)(elapsed.TotalSeconds / 5);
        if (currentInterval != _lastLoggedSecond)
        {
            _lastLoggedSecond = currentInterval;
            DebugLogger.Log($"[TIMING] [{Name}] 🕐 Elapsed: {newElapsedTime}");
        }

        ElapsedTime = newElapsedTime;
    }

    /// <summary>
    /// Resets timing data and stops any active timer
    /// </summary>
    public void ResetTiming()
    {
        var previousElapsedTime = ElapsedTime;
        var hadStartTime = _startTime.HasValue;

        // Stop and dispose timer
        if (_elapsedTimer != null)
        {
            _elapsedTimer.Stop();
            _elapsedTimer = null;
        }

        _startTime = null;
        _endTime = null;
        _lastLoggedSecond = -1;
        ElapsedTime = string.Empty;

        DebugLogger.Log($"[TIMING] [{Name}] 🔄 RESET TIMING - Previous: {previousElapsedTime ?? "(none)"}, HadStartTime: {hadStartTime}");
    }
}
