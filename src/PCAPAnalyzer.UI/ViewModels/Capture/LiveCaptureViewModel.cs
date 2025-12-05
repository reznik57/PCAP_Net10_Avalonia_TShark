using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models.Capture;
using PCAPAnalyzer.Core.Services.Capture;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Capture;

/// <summary>
/// Main ViewModel for live packet capture functionality
/// Orchestrates capture lifecycle, statistics updates, and packet display
/// Implements thread-safe UI updates and performance optimization patterns
/// </summary>
public partial class LiveCaptureViewModel : ViewModelBase, IDisposable
{
    private readonly ILiveCaptureService _captureService;
    private readonly INetworkInterfaceManager _interfaceManager;
    private CancellationTokenSource? _captureCts;
    private bool _disposed;

    /// <summary>
    /// Current capture configuration
    /// </summary>
    private CaptureConfiguration? _currentConfiguration;

    /// <summary>
    /// Packet list ViewModel
    /// </summary>
    [ObservableProperty]
    private PacketListViewModel _packetListViewModel;

    /// <summary>
    /// Statistics ViewModel
    /// </summary>
    [ObservableProperty]
    private LiveStatisticsViewModel _statisticsViewModel;

    /// <summary>
    /// Current capture status
    /// </summary>
    [ObservableProperty]
    private CaptureStatus _status = CaptureStatus.Stopped;

    /// <summary>
    /// Status message for display
    /// </summary>
    [ObservableProperty]
    private string _statusMessage = "Ready to capture";

    /// <summary>
    /// Status color - uses ThemeColorHelper for consistency
    /// </summary>
    [ObservableProperty]
    private string _statusColor = ThemeColorHelper.GetCaptureStatusColorHex("idle");

    /// <summary>
    /// Current session ID
    /// </summary>
    [ObservableProperty]
    private string _sessionId = string.Empty;

    /// <summary>
    /// Selected network interface name
    /// </summary>
    [ObservableProperty]
    private string _selectedInterfaceName = "No interface selected";

    /// <summary>
    /// Applied capture filter
    /// </summary>
    [ObservableProperty]
    private string _appliedFilter = "None";

    /// <summary>
    /// Whether capture is currently active
    /// </summary>
    [ObservableProperty]
    private bool _isCapturing;

    /// <summary>
    /// Whether capture is paused
    /// </summary>
    [ObservableProperty]
    private bool _isPaused;

    /// <summary>
    /// Error message
    /// </summary>
    [ObservableProperty]
    private string _errorMessage = string.Empty;

    /// <summary>
    /// Whether an error occurred
    /// </summary>
    [ObservableProperty]
    private bool _hasError;

    /// <summary>
    /// Whether configuration dialog is open
    /// </summary>
    [ObservableProperty]
    private bool _isConfigDialogOpen;

    /// <summary>
    /// Configuration dialog ViewModel
    /// </summary>
    [ObservableProperty]
    private CaptureConfigurationViewModel? _configurationViewModel;

    /// <summary>
    /// Start Capture Command
    /// </summary>
    public IAsyncRelayCommand StartCaptureCommand { get; }

    /// <summary>
    /// Stop Capture Command
    /// </summary>
    public IAsyncRelayCommand StopCaptureCommand { get; }

    /// <summary>
    /// Pause Capture Command
    /// </summary>
    public IAsyncRelayCommand PauseCaptureCommand { get; }

    /// <summary>
    /// Resume Capture Command
    /// </summary>
    public IAsyncRelayCommand ResumeCaptureCommand { get; }

    /// <summary>
    /// Configure Capture Command
    /// </summary>
    public IRelayCommand ConfigureCaptureCommand { get; }

    /// <summary>
    /// Clear Packets Command
    /// </summary>
    public IRelayCommand ClearPacketsCommand { get; }

    /// <summary>
    /// Export Capture Command
    /// </summary>
    public IAsyncRelayCommand ExportCaptureCommand { get; }

    public LiveCaptureViewModel(
        ILiveCaptureService captureService,
        INetworkInterfaceManager interfaceManager)
    {
        _captureService = captureService;
        _interfaceManager = interfaceManager;

        // Initialize child ViewModels
        PacketListViewModel = new PacketListViewModel();
        StatisticsViewModel = new LiveStatisticsViewModel();

        // Initialize commands
        StartCaptureCommand = new AsyncRelayCommand(StartCaptureAsync, () => !IsCapturing);
        StopCaptureCommand = new AsyncRelayCommand(StopCaptureAsync, () => IsCapturing);
        PauseCaptureCommand = new AsyncRelayCommand(PauseCaptureAsync, () => IsCapturing && !IsPaused);
        ResumeCaptureCommand = new AsyncRelayCommand(ResumeCaptureAsync, () => IsPaused);
        ConfigureCaptureCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(OpenConfigurationDialog, () => !IsCapturing);
        ClearPacketsCommand = new CommunityToolkit.Mvvm.Input.RelayCommand(ClearPackets);
        ExportCaptureCommand = new AsyncRelayCommand(ExportCaptureAsync, () => IsCapturing || _captureService.CurrentSession != null);

        // Subscribe to capture service events
        _captureService.PacketCaptured += OnPacketCaptured;
        _captureService.StatisticsUpdated += OnStatisticsUpdated;
        _captureService.StatusChanged += OnStatusChanged;
    }

    /// <summary>
    /// Opens the configuration dialog
    /// </summary>
    private void OpenConfigurationDialog()
    {
        ConfigurationViewModel = new CaptureConfigurationViewModel(_interfaceManager);
        _ = ConfigurationViewModel.InitializeAsync();
        IsConfigDialogOpen = true;
    }

    /// <summary>
    /// Closes the configuration dialog and starts capture if confirmed
    /// </summary>
    public async Task CloseConfigurationDialogAsync(bool confirmed)
    {
        IsConfigDialogOpen = false;

        if (confirmed && ConfigurationViewModel != null)
        {
            var (isValid, errorMsg) = ConfigurationViewModel.ValidateConfiguration();
            if (!isValid)
            {
                ShowError(errorMsg);
                return;
            }

            _currentConfiguration = ConfigurationViewModel.BuildConfiguration();
            SelectedInterfaceName = ConfigurationViewModel.SelectedInterface?.Name ?? "Unknown";
            AppliedFilter = string.IsNullOrWhiteSpace(_currentConfiguration.CaptureFilter)
                ? "None (capture all)"
                : _currentConfiguration.CaptureFilter;

            await StartCaptureAsync();
        }

        ConfigurationViewModel = null;
    }

    /// <summary>
    /// Starts packet capture
    /// </summary>
    private async Task StartCaptureAsync()
    {
        if (_currentConfiguration == null)
        {
            OpenConfigurationDialog();
            return;
        }

        try
        {
            ClearError();
            _captureCts = new CancellationTokenSource();

            // Reset statistics and packet list
            StatisticsViewModel.Reset();
            PacketListViewModel.Clear();

            // Start capture
            var session = await _captureService.StartCaptureAsync(_currentConfiguration, _captureCts.Token);
            SessionId = session.SessionId;

            IsCapturing = true;
            IsPaused = false;
            UpdateCommands();

            StatusMessage = $"Capturing on {SelectedInterfaceName}";
            StatusColor = ThemeColorHelper.GetCaptureStatusColorHex("capturing");
        }
        catch (Exception ex)
        {
            ShowError($"Failed to start capture: {ex.Message}");
        }
    }

    /// <summary>
    /// Stops packet capture
    /// </summary>
    private async Task StopCaptureAsync()
    {
        try
        {
            _captureCts?.Cancel();
            await _captureService.StopCaptureAsync();

            IsCapturing = false;
            IsPaused = false;
            UpdateCommands();

            StatusMessage = $"Capture stopped. Captured {StatisticsViewModel.TotalPackets:N0} packets";
            StatusColor = ThemeColorHelper.GetCaptureStatusColorHex("stopped");
        }
        catch (Exception ex)
        {
            ShowError($"Error stopping capture: {ex.Message}");
        }
    }

    /// <summary>
    /// Pauses packet capture
    /// </summary>
    private async Task PauseCaptureAsync()
    {
        try
        {
            await _captureService.PauseCaptureAsync();

            IsPaused = true;
            UpdateCommands();

            StatusMessage = "Capture paused";
            StatusColor = ThemeColorHelper.GetCaptureStatusColorHex("paused");
        }
        catch (Exception ex)
        {
            ShowError($"Error pausing capture: {ex.Message}");
        }
    }

    /// <summary>
    /// Resumes packet capture
    /// </summary>
    private async Task ResumeCaptureAsync()
    {
        try
        {
            await _captureService.ResumeCaptureAsync();

            IsPaused = false;
            UpdateCommands();

            StatusMessage = $"Capturing on {SelectedInterfaceName}";
            StatusColor = ThemeColorHelper.GetCaptureStatusColorHex("capturing");
        }
        catch (Exception ex)
        {
            ShowError($"Error resuming capture: {ex.Message}");
        }
    }

    /// <summary>
    /// Clears all captured packets from display
    /// </summary>
    private void ClearPackets()
    {
        PacketListViewModel.Clear();
        StatisticsViewModel.Reset();
    }

    /// <summary>
    /// Exports current capture to file
    /// </summary>
    private async Task ExportCaptureAsync()
    {
        try
        {
            // In a real implementation, would show file save dialog
            var outputPath = Path.Combine(
                _currentConfiguration?.OutputDirectory ?? Path.GetTempPath(),
                $"export_{DateTime.Now:yyyyMMdd_HHmmss}.pcapng");

            // SECURITY FIX: Validate path before export
            if (!ValidateExportPath(outputPath))
            {
                ShowError("Invalid export path. Please choose a valid location.");
                return;
            }

            var exportedFile = await _captureService.ExportCaptureAsync(outputPath);
            StatusMessage = $"Capture exported to {Path.GetFileName(exportedFile)}";
        }
        catch (UnauthorizedAccessException)
        {
            ShowError("Access denied. Please choose a different location.");
        }
        catch (IOException ex)
        {
            ShowError($"Export failed: {ex.Message}");
        }
        catch (Exception ex)
        {
            ShowError($"Error exporting capture: {ex.Message}");
        }
    }

    /// <summary>
    /// Validates export file path for security and accessibility
    /// </summary>
    /// <param name="filePath">Path to validate</param>
    /// <returns>True if path is valid and safe</returns>
    private bool ValidateExportPath(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
            return false;

        try
        {
            // Normalize path to prevent traversal
            var fullPath = Path.GetFullPath(filePath);

            // Check file extension
            var extension = Path.GetExtension(fullPath).ToLowerInvariant();
            if (extension != ".pcap" && extension != ".pcapng")
                return false;

            // Ensure directory exists or can be created
            var directory = Path.GetDirectoryName(fullPath);
            if (string.IsNullOrEmpty(directory))
                return false;

            // Check for write permissions (attempt to get directory info)
            var dirInfo = new DirectoryInfo(directory);
            if (!dirInfo.Exists)
            {
                // Try to create if doesn't exist
                dirInfo.Create();
            }

            // Additional check: ensure path is not a system directory
            var systemDirs = new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
            };

            if (systemDirs.Any(sysDir =>
                !string.IsNullOrEmpty(sysDir) &&
                fullPath.StartsWith(sysDir, StringComparison.OrdinalIgnoreCase)))
            {
                return false;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Event handler for packet captured
    /// </summary>
    private void OnPacketCaptured(object? sender, LivePacketData packet)
    {
        if (_disposed || IsPaused) return;

        // Add to packet list (thread-safe with buffering)
        PacketListViewModel.AddPacket(packet);

        // Update statistics
        StatisticsViewModel.RecordPacket(packet.Protocol, packet.Length);
    }

    /// <summary>
    /// Event handler for statistics updated
    /// </summary>
    private void OnStatisticsUpdated(object? sender, CaptureSessionStats stats)
    {
        if (_disposed) return;

        // Update statistics ViewModel (already thread-safe)
        StatisticsViewModel.UpdateFromSessionStats(stats);
    }

    /// <summary>
    /// Event handler for status changed
    /// </summary>
    private void OnStatusChanged(object? sender, CaptureStatus status)
    {
        if (_disposed) return;

        RunOnUIThread(() =>
        {
            Status = status;

            switch (status)
            {
                case CaptureStatus.Initializing:
                    StatusMessage = "Initializing capture...";
                    StatusColor = ThemeColorHelper.GetCaptureStatusColorHex("initializing");
                    break;

                case CaptureStatus.Capturing:
                    StatusMessage = $"Capturing on {SelectedInterfaceName}";
                    StatusColor = ThemeColorHelper.GetCaptureStatusColorHex("capturing");
                    IsCapturing = true;
                    break;

                case CaptureStatus.Paused:
                    StatusMessage = "Capture paused";
                    StatusColor = ThemeColorHelper.GetCaptureStatusColorHex("paused");
                    IsPaused = true;
                    break;

                case CaptureStatus.Stopped:
                case CaptureStatus.Completed:
                    StatusMessage = "Capture stopped";
                    StatusColor = ThemeColorHelper.GetCaptureStatusColorHex("stopped");
                    IsCapturing = false;
                    IsPaused = false;
                    break;

                case CaptureStatus.Failed:
                    StatusMessage = "Capture failed";
                    StatusColor = ThemeColorHelper.GetCaptureStatusColorHex("failed");
                    IsCapturing = false;
                    IsPaused = false;
                    ShowError(_captureService.CurrentSession?.ErrorMessage ?? "Unknown error");
                    break;
            }

            UpdateCommands();
        });
    }

    /// <summary>
    /// Updates command CanExecute states
    /// </summary>
    private void UpdateCommands()
    {
        StartCaptureCommand.NotifyCanExecuteChanged();
        StopCaptureCommand.NotifyCanExecuteChanged();
        PauseCaptureCommand.NotifyCanExecuteChanged();
        ResumeCaptureCommand.NotifyCanExecuteChanged();
        ConfigureCaptureCommand.NotifyCanExecuteChanged();
        ExportCaptureCommand.NotifyCanExecuteChanged();
    }

    /// <summary>
    /// Shows an error message
    /// </summary>
    private void ShowError(string message)
    {
        ErrorMessage = message;
        HasError = true;
    }

    /// <summary>
    /// Clears error state
    /// </summary>
    private void ClearError()
    {
        ErrorMessage = string.Empty;
        HasError = false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // Unsubscribe from events
        _captureService.PacketCaptured -= OnPacketCaptured;
        _captureService.StatisticsUpdated -= OnStatisticsUpdated;
        _captureService.StatusChanged -= OnStatusChanged;

        // Stop capture if active
        if (IsCapturing)
        {
            _captureCts?.Cancel();
            _captureService.StopCaptureAsync().Wait(TimeSpan.FromSeconds(5));
        }

        // Dispose child ViewModels
        PacketListViewModel?.Dispose();
        StatisticsViewModel?.Dispose();

        _captureCts?.Dispose();

        GC.SuppressFinalize(this);
    }
}
