using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models.Capture;
using PCAPAnalyzer.Core.Services.Capture;

namespace PCAPAnalyzer.UI.ViewModels.Capture;

/// <summary>
/// ViewModel for capture configuration dialog
/// Manages interface selection, filters, and capture settings
/// </summary>
public partial class CaptureConfigurationViewModel : ViewModelBase, IDisposable
{
    private readonly INetworkInterfaceManager _interfaceManager;
    private CancellationTokenSource? _validationCts;
    private readonly SemaphoreSlim _validationLock = new(1, 1);
    private bool _disposed;

    /// <summary>
    /// Available network interfaces
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<CaptureInterface> _availableInterfaces = [];

    /// <summary>
    /// Selected network interface
    /// </summary>
    [ObservableProperty]
    private CaptureInterface? _selectedInterface;

    /// <summary>
    /// BPF capture filter
    /// </summary>
    [ObservableProperty]
    private string _captureFilter = string.Empty;

    /// <summary>
    /// Filter validation status
    /// </summary>
    [ObservableProperty]
    private string _filterValidationMessage = string.Empty;

    /// <summary>
    /// Whether filter is valid
    /// </summary>
    [ObservableProperty]
    private bool _isFilterValid = true;

    /// <summary>
    /// Enable promiscuous mode
    /// </summary>
    [ObservableProperty]
    private bool _promiscuousMode = true;

    /// <summary>
    /// Snapshot length (bytes per packet)
    /// </summary>
    [ObservableProperty]
    private int _snapshotLength = 65535;

    /// <summary>
    /// Buffer size in MB
    /// </summary>
    [ObservableProperty]
    private int _bufferSizeMB = 50;

    /// <summary>
    /// Maximum file size in MB (for rolling captures)
    /// </summary>
    [ObservableProperty]
    private int _maxFileSizeMB = 100;

    /// <summary>
    /// Auto-save interval in seconds
    /// </summary>
    [ObservableProperty]
    private int _autoSaveIntervalSeconds = 300;

    /// <summary>
    /// Maximum capture duration in seconds (0 = unlimited)
    /// </summary>
    [ObservableProperty]
    private int _maxDurationSeconds = 0;

    /// <summary>
    /// Maximum packets to capture (0 = unlimited)
    /// </summary>
    [ObservableProperty]
    private long _maxPackets = 0;

    /// <summary>
    /// Number of rolling files to keep
    /// </summary>
    [ObservableProperty]
    private int _maxRollingFiles = 10;

    /// <summary>
    /// Output directory for capture files
    /// </summary>
    [ObservableProperty]
    private string _outputDirectory = Path.Combine(Path.GetTempPath(), "pcap_captures");

    /// <summary>
    /// File name prefix
    /// </summary>
    [ObservableProperty]
    private string _fileNamePrefix = "capture";

    /// <summary>
    /// Whether to enable real-time analysis
    /// </summary>
    [ObservableProperty]
    private bool _enableRealtimeAnalysis = true;

    /// <summary>
    /// Common BPF filter templates
    /// </summary>
    public ObservableCollection<string> FilterTemplates { get; } = new()
    {
        "tcp port 80",
        "tcp port 443",
        "udp port 53",
        "icmp",
        "host 192.168.1.1",
        "net 192.168.0.0/16",
        "not port 22",
        "tcp and not port 22",
        "port 80 or port 443",
        "src host 192.168.1.1",
        "dst host 192.168.1.1"
    };

    /// <summary>
    /// Snapshot length presets
    /// </summary>
    public ObservableCollection<int> SnapshotLengthPresets { get; } = new()
    {
        65535, // Full packet
        1514,  // Ethernet MTU
        9000,  // Jumbo frames
        128,   // Headers only
        0      // System default
    };

    /// <summary>
    /// Whether configuration is loading
    /// </summary>
    [ObservableProperty]
    private bool _isLoading = true;

    /// <summary>
    /// Whether TShark is available
    /// </summary>
    [ObservableProperty]
    private bool _isTSharkAvailable;

    /// <summary>
    /// TShark version
    /// </summary>
    [ObservableProperty]
    private string _tsharkVersion = string.Empty;

    /// <summary>
    /// Error message
    /// </summary>
    [ObservableProperty]
    private string _errorMessage = string.Empty;

    public CaptureConfigurationViewModel(INetworkInterfaceManager interfaceManager)
    {
        _interfaceManager = interfaceManager;
    }

    /// <summary>
    /// Initializes the view model by loading interfaces
    /// </summary>
    public async Task InitializeAsync()
    {
        IsLoading = true;
        ErrorMessage = string.Empty;

        try
        {
            // Check TShark availability
            IsTSharkAvailable = await _interfaceManager.TestTSharkAvailabilityAsync();
            if (!IsTSharkAvailable)
            {
                ErrorMessage = "TShark is not installed or not in PATH. Please install Wireshark/TShark.";
                return;
            }

            TsharkVersion = await _interfaceManager.GetTSharkVersionAsync();

            // Load available interfaces
            var interfaces = await _interfaceManager.GetAvailableInterfacesAsync();
            AvailableInterfaces.Clear();
            foreach (var iface in interfaces.Where(i => i.IsUp))
            {
                AvailableInterfaces.Add(iface);
            }

            // Select first available interface
            if (AvailableInterfaces.Any())
            {
                SelectedInterface = AvailableInterfaces.First();
            }

            // Create output directory if it doesn't exist
            if (!Directory.Exists(OutputDirectory))
            {
                Directory.CreateDirectory(OutputDirectory);
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error initializing capture configuration: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    /// <summary>
    /// Validates the BPF filter syntax
    /// </summary>
    [RelayCommand]
    private async Task ValidateFilterAsync()
    {
        // Cancel previous validation
        _validationCts?.Cancel();
        _validationCts?.Dispose();
        _validationCts = new CancellationTokenSource();

        // Acquire lock to prevent concurrent validations
        await _validationLock.WaitAsync(_validationCts.Token);

        try
        {
            if (string.IsNullOrWhiteSpace(CaptureFilter))
            {
                IsFilterValid = true;
                FilterValidationMessage = "No filter applied (capture all packets)";
                return;
            }

            // Debounce: wait 300ms for user to finish typing
            await Task.Delay(300, _validationCts.Token);

            // Check if cancelled during delay
            if (_validationCts.Token.IsCancellationRequested)
                return;

            // Validate on background thread (interface manager should handle this)
            var (isValid, errorMessage) = await _interfaceManager.ValidateCaptureFilterAsync(
                CaptureFilter, _validationCts.Token);

            // Update UI (will be automatically marshaled by ReactiveUI/CommunityToolkit)
            IsFilterValid = isValid;
            FilterValidationMessage = isValid
                ? "✓ Filter syntax is valid"
                : $"✗ Invalid filter: {errorMessage}";
        }
        catch (OperationCanceledException)
        {
            // Expected when user types quickly, do nothing
        }
        catch (Exception ex)
        {
            IsFilterValid = false;
            FilterValidationMessage = $"✗ Error validating filter: {ex.Message}";
        }
        finally
        {
            _validationLock.Release();
        }
    }

    /// <summary>
    /// Applies a filter template
    /// </summary>
    [RelayCommand]
    private void ApplyFilterTemplate(string template)
    {
        CaptureFilter = template;
        _ = ValidateFilterAsync();
    }

    /// <summary>
    /// Browses for output directory
    /// </summary>
    [RelayCommand]
    private async Task BrowseOutputDirectoryAsync()
    {
        // In a real implementation, would use platform-specific folder picker
        // For now, use a predefined path
        await Task.CompletedTask;
    }

    /// <summary>
    /// Creates a CaptureConfiguration from the current settings
    /// </summary>
    public CaptureConfiguration BuildConfiguration()
    {
        if (SelectedInterface == null)
        {
            throw new InvalidOperationException("No network interface selected");
        }

        return new CaptureConfiguration
        {
            InterfaceId = SelectedInterface.Id,
            CaptureFilter = CaptureFilter,
            PromiscuousMode = PromiscuousMode,
            SnapshotLength = SnapshotLength,
            BufferSizeMB = BufferSizeMB,
            MaxFileSizeMB = MaxFileSizeMB,
            AutoSaveIntervalSeconds = AutoSaveIntervalSeconds,
            MaxDurationSeconds = MaxDurationSeconds,
            MaxPackets = MaxPackets,
            MaxRollingFiles = MaxRollingFiles,
            OutputDirectory = OutputDirectory,
            FileNamePrefix = FileNamePrefix,
            EnableRealtimeAnalysis = EnableRealtimeAnalysis
        };
    }

    /// <summary>
    /// Validates the entire configuration
    /// </summary>
    public (bool IsValid, string ErrorMessage) ValidateConfiguration()
    {
        if (SelectedInterface == null)
            return (false, "Please select a network interface");

        if (!IsTSharkAvailable)
            return (false, "TShark is not available");

        if (!IsFilterValid)
            return (false, "Capture filter is invalid");

        if (SnapshotLength < 0 || SnapshotLength > 65535)
            return (false, "Snapshot length must be between 0 and 65535");

        if (BufferSizeMB < 1)
            return (false, "Buffer size must be at least 1 MB");

        if (MaxFileSizeMB < 0)
            return (false, "Max file size cannot be negative");

        if (MaxRollingFiles < 0)
            return (false, "Max rolling files cannot be negative");

        if (string.IsNullOrWhiteSpace(OutputDirectory))
            return (false, "Output directory must be specified");

        if (string.IsNullOrWhiteSpace(FileNamePrefix))
            return (false, "File name prefix must be specified");

        return (true, string.Empty);
    }

    /// <summary>
    /// Auto-validates filter on changes (debounced)
    /// </summary>
    partial void OnCaptureFilterChanged(string value)
    {
        // Start new validation (old validation will be cancelled automatically)
        _ = ValidateFilterAsync();
    }

    /// <summary>
    /// Disposes resources
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _validationCts?.Cancel();
        _validationCts?.Dispose();
        _validationLock?.Dispose();

        GC.SuppressFinalize(this);
    }
}
