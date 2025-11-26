using System;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Monitoring;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages UI state including status messages, colors, progress indicators, pagination, and monitoring metrics.
/// Handles screenshot commands and display-related properties.
/// </summary>
public partial class MainWindowUIStateViewModel : ObservableObject
{
    // Status and Display
    [ObservableProperty] private string _status = "Ready";
    [ObservableProperty] private string _statusColor = "#4ADE80";
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
            StatusColor = "#4A9FFF";
        }
        else
        {
            StatusColor = "#4ADE80";
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
            StatusColor = "#FFC107";
            DebugLogger.Log("[Screenshot] Starting screenshot capture...");

            var mainWindow = Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                ? desktop.MainWindow as Views.MainWindow
                : null;

            if (mainWindow == null)
            {
                Status = "Cannot access main window";
                StatusColor = "#FF5252";
                DebugLogger.Log("[Screenshot] ERROR: Cannot access main window");
                return;
            }

            var tabControl = mainWindow.FindControl<TabControl>("MainTabControl");
            var currentTabIndex = tabControl?.SelectedIndex ?? 0;

            // ✅ Enhanced logging for screenshot naming diagnosis
            var tabName = currentTabIndex switch
            {
                0 => "FileManager",
                1 => "PacketAnalysis",
                2 => "Dashboard",
                3 => "SecurityThreats",
                4 => "VoiceQoS",
                5 => "CountryTraffic",
                6 => "Reports",
                _ => "Unknown"
            };
            DebugLogger.Log($"[Screenshot] Current tab index: {currentTabIndex} → Tab name: {tabName}");

            var success = await mainWindow.TakeScreenshotForCurrentTabAsync(currentTabIndex);

            if (success)
            {
                Status = "✅ Screenshot saved successfully";
                StatusColor = "#4ADE80";
                LastScreenshotInfo = $"Screenshot saved at {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
                DebugLogger.Log("[Screenshot] Screenshot saved successfully");
            }
            else
            {
                Status = "Screenshot cancelled";
                StatusColor = "#8B949E";
                DebugLogger.Log("[Screenshot] Screenshot cancelled by user");
            }

            await Task.Delay(3000);
            Status = "Ready";
            StatusColor = "#22C55E";
        }
        catch (Exception ex)
        {
            Status = $"Screenshot error: {ex.Message}";
            StatusColor = "#FF5252";
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
            StatusColor = "#FFC107";

            int? tabIndex = parameter as int?;

            var mainWindow = Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                ? desktop.MainWindow as Views.MainWindow
                : null;

            if (mainWindow == null)
            {
                Status = "Cannot access main window";
                StatusColor = "#FF5252";
                return;
            }

            var success = await mainWindow.TakeFullScreenshotAsync(tabIndex ?? -1);

            if (success)
            {
                Status = "Full page screenshot saved successfully";
                StatusColor = "#4ADE80";
                LastScreenshotInfo = $"Full page screenshot saved at {DateTime.Now:yyyy-MM-dd HH:mm:ss}";
            }
            else
            {
                Status = "Screenshot cancelled or failed";
                StatusColor = "#FF5252";
            }

            await Task.Delay(3000);
            StatusColor = "#4ADE80";
        }
        catch (Exception ex)
        {
            Status = $"Screenshot failed: {ex.Message}";
            StatusColor = "#FF5252";
            DebugLogger.Log($"[MainWindowUIStateViewModel] Full screenshot error: {ex}");
        }
    }

    private void InitializeMonitoring()
    {
        try
        {
            // Subscribe to memory pressure events
            MemoryPressureDetector.Instance.MemoryPressureWarning += OnMemoryPressureWarning;
            MemoryPressureDetector.Instance.MemoryPressureCritical += OnMemoryPressureCritical;
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
        Status = "⚠️ Critical memory pressure";
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
        StatusColor = "#4ADE80";
        HasResults = false;
        ResetPagination();
    }
}
