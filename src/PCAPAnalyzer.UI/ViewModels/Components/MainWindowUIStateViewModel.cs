using System;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading; // Required for DispatcherTimer only
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Monitoring;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages UI state including status messages, colors, progress indicators, pagination, and monitoring metrics.
/// Handles screenshot commands and display-related properties.
/// </summary>
public partial class MainWindowUIStateViewModel : ObservableObject
{
    // Static color references for theme consistency
    private static readonly string ColorReady = ThemeColorHelper.GetColorHex("ColorSuccess", "#4ADE80");
    private static readonly string ColorAnalyzing = ThemeColorHelper.GetColorHex("AccentBlue", "#4A9FFF");
    private static readonly string ColorWarning = ThemeColorHelper.GetColorHex("ColorWarning", "#FFC107");
    private static readonly string ColorError = ThemeColorHelper.GetColorHex("ColorDanger", "#FF5252");
    private static readonly string ColorMuted = ThemeColorHelper.GetColorHex("TextMuted", "#8B949E");
    private static readonly string ColorSuccess = ThemeColorHelper.GetColorHex("ColorSuccess", "#22C55E");

    // Status and Display
    [ObservableProperty] private string _status = "Ready";
    [ObservableProperty] private string _statusColor = ColorReady;
    [ObservableProperty] private bool _hasResults;
    [ObservableProperty] private bool _canAccessAnalysisTabs = false;
    [ObservableProperty] private string _lastScreenshotInfo = "No screenshot taken yet";

    // Pagination
    [ObservableProperty] private int _currentPage = 1;
    [ObservableProperty] private int _totalPages = 1;
    private int _pageSize = 30;
    [ObservableProperty] private string _pageSizeText = "30";
    [ObservableProperty] private string _pageInfo = "Page 1 of 1 (0 total packets)";
    [ObservableProperty] private bool _canGoToPreviousPage;
    [ObservableProperty] private bool _canGoToNextPage;
    [ObservableProperty] private bool _canGoToFirstPage;
    [ObservableProperty] private bool _canGoToLastPage;
    [ObservableProperty] private string _goToPageText = "";
    [ObservableProperty] private string _goToPacketText = "";
    [ObservableProperty] private string _searchStreamText = "";
    [ObservableProperty] private string _streamSearchStatus = "";

    // Monitoring
    [ObservableProperty] private string _memoryUsage = "0 MB";
    [ObservableProperty] private string _cpuUsage = "N/A";
    [ObservableProperty] private string _memoryPressureLevel = "Normal";
    [ObservableProperty] private string _performanceStatus = string.Empty;

    // Screenshot state tracking (prevents double-click execution)
    private bool _isScreenshotInProgress;
    private DateTime _lastScreenshotTime = DateTime.MinValue;
    private const int SCREENSHOT_DEBOUNCE_MS = 1000; // 1 second debounce

    // Events
    public event EventHandler<int>? PageChanged;
    public event EventHandler<uint>? GoToPacketRequested;
    public event EventHandler<string>? SearchStreamRequested;

    public MainWindowUIStateViewModel()
    {
        // Initialize monitoring
        InitializeMonitoring();
    }

    public int PageSize
    {
        get => _pageSize;
        set
        {
            if (SetProperty(ref _pageSize, value))
            {
                PageSizeText = value.ToString();
                Status = $"Page size changed to {_pageSize} packets per page";
            }
        }
    }

    /// <summary>
    /// Updates status with color
    /// </summary>
    public void UpdateStatus(string message, string color)
    {
        Status = message;
        StatusColor = color;
    }

    /// <summary>
    /// Sets status for analysis state
    /// </summary>
    public void SetAnalysisStatus(bool isAnalyzing)
    {
        if (isAnalyzing)
        {
            StatusColor = ColorAnalyzing;
        }
        else
        {
            StatusColor = ColorReady;
        }
    }

    /// <summary>
    /// Updates pagination information
    /// </summary>
    public void UpdatePaginationInfo(int totalFilteredPackets)
    {
        TotalPages = Math.Max(1, (int)Math.Ceiling((double)totalFilteredPackets / PageSize));
        if (CurrentPage > TotalPages)
            CurrentPage = TotalPages;

        PageInfo = $"Page {CurrentPage} of {TotalPages} ({totalFilteredPackets:N0} total packets)";
        UpdateNavigationButtons();
    }

    /// <summary>
    /// Navigates to a specific page
    /// </summary>
    public void GoToPage(int pageNumber)
    {
        if (pageNumber < 1 || pageNumber > TotalPages)
            return;

        CurrentPage = pageNumber;
        UpdateNavigationButtons();
        PageChanged?.Invoke(this, pageNumber);
    }

    [RelayCommand]
    private void GoToFirstPage()
    {
        GoToPage(1);
    }

    [RelayCommand]
    private void GoToPreviousPage()
    {
        if (CurrentPage > 1)
            GoToPage(CurrentPage - 1);
    }

    [RelayCommand]
    private void GoToNextPage()
    {
        if (CurrentPage < TotalPages)
            GoToPage(CurrentPage + 1);
    }

    [RelayCommand]
    private void GoToLastPage()
    {
        GoToPage(TotalPages);
    }

    [RelayCommand]
    private void GoToPage()
    {
        if (int.TryParse(GoToPageText, out int pageNumber))
        {
            GoToPage(pageNumber);
            GoToPageText = ""; // Clear input after successful navigation
        }
    }

    [RelayCommand]
    private void GoToPacket()
    {
        if (uint.TryParse(GoToPacketText, out uint frameNumber) && frameNumber > 0)
        {
            GoToPacketRequested?.Invoke(this, frameNumber);
            GoToPacketText = ""; // Clear input after request
        }
    }

    [RelayCommand]
    private void SearchStream()
    {
        if (!string.IsNullOrWhiteSpace(SearchStreamText))
        {
            SearchStreamRequested?.Invoke(this, SearchStreamText.Trim());
        }
    }

    [RelayCommand]
    private void ClearStreamSearch()
    {
        SearchStreamText = "";
        StreamSearchStatus = "";
        // Trigger event with empty string to clear highlighting
        SearchStreamRequested?.Invoke(this, "");
    }

    private void UpdateNavigationButtons()
    {
        CanGoToFirstPage = CurrentPage > 1;
        CanGoToPreviousPage = CurrentPage > 1;
        CanGoToNextPage = CurrentPage < TotalPages;
        CanGoToLastPage = CurrentPage < TotalPages;
    }

    /// <summary>
    /// Resets pagination to initial state
    /// </summary>
    public void ResetPagination()
    {
        CurrentPage = 1;
        TotalPages = 1;
        PageInfo = "Page 1 of 1 (0 total packets)";
        UpdateNavigationButtons();
    }

    [RelayCommand]
    private async Task TakeScreenshotAsync()
    {
        // Debounce rapid clicks to prevent double-execution
        var now = DateTime.Now;
        var timeSinceLastClick = (now - _lastScreenshotTime).TotalMilliseconds;

        if (_isScreenshotInProgress)
        {
            DebugLogger.Log("[Screenshot] Already in progress, ignoring duplicate click");
            return;
        }

        if (timeSinceLastClick < SCREENSHOT_DEBOUNCE_MS)
        {
            DebugLogger.Log($"[Screenshot] Debouncing - {timeSinceLastClick:F0}ms since last click (minimum {SCREENSHOT_DEBOUNCE_MS}ms)");
            return;
        }

        _lastScreenshotTime = now;
        _isScreenshotInProgress = true;

        try
        {
            Status = "📸 Taking screenshot...";
            StatusColor = ColorWarning;
            DebugLogger.Log("[Screenshot] Starting screenshot capture...");

            var mainWindow = Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                ? desktop.MainWindow as Views.MainWindow
                : null;

            if (mainWindow is null)
            {
                Status = "Cannot access main window";
                StatusColor = ColorError;
                DebugLogger.Log("[Screenshot] ERROR: Cannot access main window");
                return;
            }

            var tabControl = mainWindow.FindControl<TabControl>("MainTabControl");
            var currentTabIndex = tabControl?.SelectedIndex ?? 0;

            // ✅ Enhanced logging for screenshot naming diagnosis
            // Tab order: FileManager(0), PacketAnalysis(1), Dashboard(2), CountryTraffic(3), VoiceQoS(4), Threats(5), Anomalies(6), HostInventory(7), Compare(8), Reports(9)
            var tabName = currentTabIndex switch
            {
                0 => "FileManager",
                1 => "PacketAnalysis",
                2 => "Dashboard",
                3 => "CountryTraffic",
                4 => "VoiceQoS",
                5 => "Threats",
                6 => "Anomalies",
                7 => "HostInventory",
                8 => "Compare",
                9 => "Reports",
                _ => "Unknown"
            };
            DebugLogger.Log($"[Screenshot] Current tab index: {currentTabIndex} → Tab name: {tabName}");

            var success = await mainWindow.TakeScreenshotForCurrentTabAsync(currentTabIndex);

            if (success)
            {
                Status = "✅ Screenshot saved successfully";
                StatusColor = ColorReady;
                LastScreenshotInfo = $"Screenshot saved at {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
                DebugLogger.Log("[Screenshot] Screenshot saved successfully");
            }
            else
            {
                Status = "Screenshot cancelled";
                StatusColor = ColorMuted;
                DebugLogger.Log("[Screenshot] Screenshot cancelled by user");
            }

            await Task.Delay(3000);
            Status = "Ready";
            StatusColor = ColorSuccess;
        }
        catch (Exception ex)
        {
            Status = $"Screenshot error: {ex.Message}";
            StatusColor = ColorError;
            DebugLogger.Log($"[Screenshot] ERROR: {ex.Message}");
            DebugLogger.Log($"[Screenshot] Stack trace: {ex.StackTrace}");
        }
        finally
        {
            _isScreenshotInProgress = false;
        }
    }

    [RelayCommand]
    private async Task TakeFullScreenshotAsync(object? parameter)
    {
        try
        {
            Status = "Taking full page screenshot...";
            StatusColor = ColorWarning;

            int? tabIndex = parameter as int?;

            var mainWindow = Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                ? desktop.MainWindow as Views.MainWindow
                : null;

            if (mainWindow is null)
            {
                Status = "Cannot access main window";
                StatusColor = ColorError;
                return;
            }

            var success = await mainWindow.TakeFullScreenshotAsync(tabIndex ?? -1);

            if (success)
            {
                Status = "Full page screenshot saved successfully";
                StatusColor = ColorReady;
                LastScreenshotInfo = $"Full page screenshot saved at {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
            }
            else
            {
                Status = "Screenshot cancelled or failed";
                StatusColor = ColorError;
            }

            await Task.Delay(3000);
            StatusColor = ColorReady;
        }
        catch (Exception ex)
        {
            Status = $"Screenshot failed: {ex.Message}";
            StatusColor = ColorError;
            DebugLogger.Log($"[MainWindowUIStateViewModel] Full screenshot error: {ex}");
        }
    }

    private void InitializeMonitoring()
    {
        try
        {
            // Subscribe to memory pressure events (including Emergency which was previously unhandled!)
            MemoryPressureDetector.Instance.MemoryPressureWarning += OnMemoryPressureWarning;
            MemoryPressureDetector.Instance.MemoryPressureCritical += OnMemoryPressureCritical;
            MemoryPressureDetector.Instance.MemoryPressureEmergency += OnMemoryPressureEmergency;
            MemoryPressureDetector.Instance.MemoryPressureRelieved += OnMemoryPressureRelieved;

            // Start monitoring timer
            var monitoringTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(2)
            };
            monitoringTimer.Tick += UpdateMonitoringMetrics;
            monitoringTimer.Start();

            CpuUsage = "N/A";
            PerformanceStatus = string.Empty;

            // ✅ PERFORMANCE: Removed verbose monitoring log - impacts startup time
            // DetailedLogger.Instance.Info("MONITORING", "Monitoring systems initialized");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[ERROR] Failed to initialize monitoring: {ex.Message}");
        }
    }

    private void UpdateMonitoringMetrics(object? sender, EventArgs e)
    {
        try
        {
            var memoryUsage = MemoryPressureDetector.Instance.CurrentMemoryUsage;
            MemoryUsage = $"{memoryUsage / 1_000_000} MB";

            var pressureLevel = MemoryPressureDetector.Instance.CurrentLevel;
            MemoryPressureLevel = pressureLevel.ToString();

            CpuUsage = "N/A";
            PerformanceStatus = string.Empty;
        }
        catch (Exception ex)
        {
            DetailedLogger.Instance.Error("MONITORING", "Failed to update metrics", ex);
        }
    }

    private void OnMemoryPressureWarning(object? sender, EventArgs e)
    {
        DetailedLogger.Instance.Warning("MEMORY", "Memory pressure warning triggered");
        Status = "⚠️ Memory usage is high";
    }

    private void OnMemoryPressureCritical(object? sender, EventArgs e)
    {
        DetailedLogger.Instance.Error("MEMORY", "Critical memory pressure detected");
        Status = "⚠️ Critical memory pressure - optimizing...";

        // ✅ FIX: Trigger GC on critical pressure (was just logging before)
        Task.Run(() =>
        {
            GC.Collect(2, GCCollectionMode.Optimized, blocking: false);
            GC.WaitForPendingFinalizers();
            DebugLogger.Log("[MEMORY] Critical: GC triggered (optimized mode)");
        });
    }

    private void OnMemoryPressureEmergency(object? sender, EventArgs e)
    {
        DetailedLogger.Instance.Error("MEMORY", "🚨 EMERGENCY memory pressure detected!");
        Status = "🚨 Emergency memory pressure - forced GC";

        // ✅ PERF FIX: Use NON-BLOCKING GC to prevent UI freeze
        // NOTE: Aggressive mode REQUIRES blocking: true (throws exception otherwise)
        // Use Forced mode instead - it's the strongest non-blocking option
        Task.Run(() =>
        {
            // Request LOH compaction on next blocking GC (won't block now)
            System.Runtime.GCSettings.LargeObjectHeapCompactionMode = System.Runtime.GCLargeObjectHeapCompactionMode.CompactOnce;

            // Forced mode: strongest GC that works with blocking: false
            // (Aggressive mode throws ArgumentException if blocking: false)
            GC.Collect(2, GCCollectionMode.Forced, blocking: false, compacting: false);
            GC.WaitForPendingFinalizers();

            // Second pass to collect finalizable objects (still non-blocking)
            GC.Collect(1, GCCollectionMode.Forced, blocking: false);

            // NOTE: Don't measure "freed" for non-blocking GC - collection happens asynchronously
            // so immediate measurement is meaningless (often shows negative values)
            DebugLogger.Log("[MEMORY] 🚨 Emergency GC requested (Gen2 Forced, non-blocking, LOH compaction queued)");
        });
    }

    private void OnMemoryPressureRelieved(object? sender, EventArgs e)
    {
        DetailedLogger.Instance.Info("MEMORY", "Memory pressure relieved");
        Status = "✅ Memory pressure relieved";
    }

    /// <summary>
    /// Resets all UI state
    /// </summary>
    public void ResetState()
    {
        Status = "Ready";
        StatusColor = ColorReady;
        HasResults = false;
        ResetPagination();
    }
}
