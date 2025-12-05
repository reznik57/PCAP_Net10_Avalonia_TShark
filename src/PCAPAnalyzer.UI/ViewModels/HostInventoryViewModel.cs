using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Data.Converters;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.OsFingerprinting;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// ViewModel for Host Inventory tab - displays OS fingerprinting results.
/// Shows detected hosts with their OS, MAC vendor, JA3 verification, and other metadata.
/// </summary>
public partial class HostInventoryViewModel : ObservableObject, ITabPopulationTarget
{
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    private readonly IOsFingerprintService? _fingerprintService;
    private IReadOnlyList<HostFingerprint>? _allHosts;

    // ==================== ITabPopulationTarget ====================

    public string TabName => "Host Inventory";

    // ==================== OBSERVABLE PROPERTIES ====================

    [ObservableProperty] private ObservableCollection<HostInventoryItem> _hosts = new();
    [ObservableProperty] private HostInventoryItem? _selectedHost;
    [ObservableProperty] private string _searchFilter = string.Empty;
    [ObservableProperty] private string _osFilter = "All";
    [ObservableProperty] private string _deviceTypeFilter = "All";
    [ObservableProperty] private bool _showVerifiedOnly;

    // Statistics
    [ObservableProperty] private int _totalHosts;
    [ObservableProperty] private int _windowsHosts;
    [ObservableProperty] private int _linuxHosts;
    [ObservableProperty] private int _macOsHosts;
    [ObservableProperty] private int _mobileHosts;
    [ObservableProperty] private int _iotHosts;
    [ObservableProperty] private int _unknownHosts;

    // Filter options
    public ObservableCollection<string> OsFilterOptions { get; } = new()
    {
        "All", "Windows", "Linux", "macOS", "iOS", "Android", "Network Equipment", "IoT", "Unknown"
    };

    public ObservableCollection<string> DeviceTypeFilterOptions { get; } = new()
    {
        "All", "Desktop", "Server", "Mobile", "IoT", "Network Equipment", "Printer", "Virtual", "Unknown"
    };

    // ==================== CONSTRUCTORS ====================

    public HostInventoryViewModel()
    {
    }

    public HostInventoryViewModel(IOsFingerprintService? fingerprintService)
    {
        _fingerprintService = fingerprintService;
    }

    // ==================== PUBLIC METHODS ====================

    /// <summary>
    /// Updates the host inventory from the fingerprint service.
    /// </summary>
    public async Task UpdateHostsAsync()
    {
        if (_fingerprintService == null)
            return;

        await Task.Run(() =>
        {
            _allHosts = _fingerprintService.GetHostFingerprints();
            DebugLogger.Log($"[HostInventoryViewModel] Retrieved {_allHosts.Count} hosts from fingerprint service");
        });

        await Dispatcher.InvokeAsync(() =>
        {
            RefreshHostList();
            UpdateStatistics();
        });
    }

    /// <summary>
    /// Sets hosts directly (for testing or alternative data sources).
    /// </summary>
    public void SetHosts(IReadOnlyList<HostFingerprint> hosts)
    {
        _allHosts = hosts;
        RefreshHostList();
        UpdateStatistics();
    }

    // ==================== FILTER HANDLERS ====================

    partial void OnSearchFilterChanged(string value) => RefreshHostList();
    partial void OnOsFilterChanged(string value) => RefreshHostList();
    partial void OnDeviceTypeFilterChanged(string value) => RefreshHostList();
    partial void OnShowVerifiedOnlyChanged(bool value) => RefreshHostList();

    // ==================== PRIVATE METHODS ====================

    private void RefreshHostList()
    {
        if (_allHosts == null)
            return;

        var filtered = _allHosts.AsEnumerable();

        // Apply search filter
        if (!string.IsNullOrWhiteSpace(SearchFilter))
        {
            var search = SearchFilter.Trim();
            filtered = filtered.Where(h =>
                h.IpAddress.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                (h.MacAddress?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (h.MacVendor?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (h.Hostname?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (h.OsDisplayName.Contains(search, StringComparison.OrdinalIgnoreCase)));
        }

        // Apply OS filter
        if (OsFilter != "All")
        {
            filtered = filtered.Where(h =>
                h.OsDetection?.OsFamily?.Contains(OsFilter, StringComparison.OrdinalIgnoreCase) ?? false);
        }

        // Apply device type filter
        if (DeviceTypeFilter != "All")
        {
            var targetType = DeviceTypeFilter switch
            {
                "Desktop" => DeviceType.Desktop,
                "Server" => DeviceType.Server,
                "Mobile" => DeviceType.Mobile,
                "IoT" => DeviceType.IoT,
                "Network Equipment" => DeviceType.NetworkEquipment,
                "Printer" => DeviceType.Printer,
                "Virtual" => DeviceType.Virtual,
                _ => DeviceType.Unknown
            };

            filtered = filtered.Where(h =>
                h.OsDetection?.DeviceType == targetType);
        }

        // Apply verified filter
        if (ShowVerifiedOnly)
        {
            filtered = filtered.Where(h => h.Ja3Verified);
        }

        // Convert to view items and update collection
        Hosts.Clear();
        foreach (var host in filtered.OrderByDescending(h => h.PacketCount))
        {
            Hosts.Add(CreateHostItem(host));
        }

        DebugLogger.Log($"[HostInventoryViewModel] Refreshed host list: {Hosts.Count} hosts displayed");
    }

    private static HostInventoryItem CreateHostItem(HostFingerprint host)
    {
        var item = new HostInventoryItem
        {
            IpAddress = host.IpAddress,
            MacAddress = host.MacAddress ?? "-",
            MacVendor = host.MacVendor ?? "Unknown",
            Hostname = host.Hostname ?? "-",
            RawHost = host
        };

        PopulateOsProperties(item, host);
        PopulateConfidenceProperties(item, host);
        PopulateFingerprintProperties(item, host);
        PopulateNetworkProperties(item, host);

        return item;
    }

    private static void PopulateOsProperties(HostInventoryItem item, HostFingerprint host)
    {
        item.OsFamily = host.OsDetection?.OsFamily ?? "Unknown";
        item.OsVersion = host.OsDetection?.OsVersion ?? "";
        item.OsDisplayName = host.OsDisplayName;
        item.DeviceType = host.OsDetection?.DeviceType ?? DeviceType.Unknown;
        item.DeviceTypeDisplay = GetDeviceTypeDisplay(host.OsDetection?.DeviceType ?? DeviceType.Unknown);
    }

    private static void PopulateConfidenceProperties(HostInventoryItem item, HostFingerprint host)
    {
        item.Confidence = host.OsDetection?.Confidence ?? OsConfidenceLevel.Unknown;
        item.ConfidenceDisplay = GetConfidenceDisplay(host.OsDetection?.Confidence ?? OsConfidenceLevel.Unknown);
        item.ConfidenceScore = host.OsDetection?.ConfidenceScore ?? 0;
        item.DetectionMethod = host.OsDetection?.Method ?? OsDetectionMethod.Unknown;
        item.DetectionMethodDisplay = GetMethodDisplay(host.OsDetection?.Method ?? OsDetectionMethod.Unknown);
    }

    private static void PopulateFingerprintProperties(HostInventoryItem item, HostFingerprint host)
    {
        item.Ja3Verified = host.Ja3Verified;
        item.Ja3Hash = host.Ja3Fingerprints.FirstOrDefault()?.Ja3Hash ?? "-";
        item.Ja3Application = host.Ja3Verification?.DetectedApplication ?? "-";
        item.TcpFingerprint = host.TcpFingerprints.FirstOrDefault()?.ToSignature() ?? "-";
    }

    private static void PopulateNetworkProperties(HostInventoryItem item, HostFingerprint host)
    {
        item.PacketCount = host.PacketCount;
        item.FirstSeen = host.FirstSeen;
        item.LastSeen = host.LastSeen;
        item.OpenPorts = string.Join(", ", host.OpenPorts.OrderBy(p => p).Take(10));
        item.ServerBanners = string.Join("; ", host.ServerBanners.Take(3).Select(b => $"{b.Protocol}: {b.ProductName ?? b.Banner}"));
    }

    private static string GetDeviceTypeDisplay(DeviceType type)
    {
        return type switch
        {
            DeviceType.Desktop => "Desktop",
            DeviceType.Server => "Server",
            DeviceType.Mobile => "Mobile",
            DeviceType.IoT => "IoT",
            DeviceType.NetworkEquipment => "Network",
            DeviceType.Printer => "Printer",
            DeviceType.Virtual => "Virtual",
            _ => "Unknown"
        };
    }

    private static string GetConfidenceDisplay(OsConfidenceLevel level)
    {
        return level switch
        {
            OsConfidenceLevel.VeryHigh => "Very High",
            OsConfidenceLevel.High => "High",
            OsConfidenceLevel.Medium => "Medium",
            OsConfidenceLevel.Low => "Low",
            _ => "Unknown"
        };
    }

    private static string GetMethodDisplay(OsDetectionMethod method)
    {
        return method switch
        {
            OsDetectionMethod.TcpSyn => "TCP SYN",
            OsDetectionMethod.Ja3 => "JA3",
            OsDetectionMethod.MacVendor => "MAC Vendor",
            OsDetectionMethod.Dhcp => "DHCP",
            OsDetectionMethod.ServerBanner => "Banner",
            OsDetectionMethod.Combined => "Combined",
            _ => "Unknown"
        };
    }

    private void UpdateStatistics()
    {
        if (_allHosts == null)
        {
            TotalHosts = 0;
            WindowsHosts = 0;
            LinuxHosts = 0;
            MacOsHosts = 0;
            MobileHosts = 0;
            IotHosts = 0;
            UnknownHosts = 0;
            return;
        }

        TotalHosts = _allHosts.Count;
        WindowsHosts = _allHosts.Count(h =>
            h.OsDetection?.OsFamily?.Contains("Windows", StringComparison.OrdinalIgnoreCase) ?? false);
        LinuxHosts = _allHosts.Count(h =>
            h.OsDetection?.OsFamily?.Contains("Linux", StringComparison.OrdinalIgnoreCase) ?? false);
        MacOsHosts = _allHosts.Count(h =>
            (h.OsDetection?.OsFamily?.Contains("macOS", StringComparison.OrdinalIgnoreCase) ?? false) ||
            (h.OsDetection?.OsFamily?.Contains("iOS", StringComparison.OrdinalIgnoreCase) ?? false));
        MobileHosts = _allHosts.Count(h =>
            h.OsDetection?.DeviceType == DeviceType.Mobile);
        IotHosts = _allHosts.Count(h =>
            h.OsDetection?.DeviceType == DeviceType.IoT ||
            h.OsDetection?.DeviceType == DeviceType.NetworkEquipment);
        UnknownHosts = _allHosts.Count(h =>
            h.OsDetection == null ||
            h.OsDetection.OsFamily == "Unknown" ||
            string.IsNullOrEmpty(h.OsDetection.OsFamily));
    }

    // ==================== COMMANDS ====================

    [RelayCommand]
    private void ClearFilters()
    {
        SearchFilter = string.Empty;
        OsFilter = "All";
        DeviceTypeFilter = "All";
        ShowVerifiedOnly = false;
    }

    [RelayCommand]
    private async Task ExportToCsv()
    {
        if (!Hosts.Any())
        {
            DebugLogger.Log("[HostInventoryViewModel] No hosts to export");
            return;
        }

        try
        {
            if (Avalonia.Application.Current?.ApplicationLifetime is not
                Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop ||
                desktop.MainWindow == null)
            {
                return;
            }

            var topLevel = desktop.MainWindow;
            var saveDialog = new Avalonia.Platform.Storage.FilePickerSaveOptions
            {
                Title = "Export Host Inventory to CSV",
                DefaultExtension = "csv",
                SuggestedFileName = $"HostInventory_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
                FileTypeChoices = new[]
                {
                    new Avalonia.Platform.Storage.FilePickerFileType("CSV Files") { Patterns = new[] { "*.csv" } }
                }
            };

            var file = await topLevel.StorageProvider.SaveFilePickerAsync(saveDialog);
            if (file == null) return;

            await using var stream = await file.OpenWriteAsync();
            await using var writer = new System.IO.StreamWriter(stream);

            // Write header
            await writer.WriteLineAsync("IP Address,MAC Address,MAC Vendor,Hostname,OS Family,OS Version,OS Display Name,Device Type,Confidence,Confidence Score,Detection Method,JA3 Verified,JA3 Hash,JA3 Application,TCP Fingerprint,Packet Count,First Seen,Last Seen,Open Ports,Server Banners");

            // Write data
            foreach (var item in Hosts)
            {
                var line = string.Join(",",
                    EscapeCsv(item.IpAddress),
                    EscapeCsv(item.MacAddress),
                    EscapeCsv(item.MacVendor),
                    EscapeCsv(item.Hostname),
                    EscapeCsv(item.OsFamily),
                    EscapeCsv(item.OsVersion),
                    EscapeCsv(item.OsDisplayName),
                    EscapeCsv(item.DeviceTypeDisplay),
                    EscapeCsv(item.ConfidenceDisplay),
                    item.ConfidenceScore.ToString("F2"),
                    EscapeCsv(item.DetectionMethodDisplay),
                    item.Ja3Verified.ToString(),
                    EscapeCsv(item.Ja3Hash),
                    EscapeCsv(item.Ja3Application),
                    EscapeCsv(item.TcpFingerprint),
                    item.PacketCount,
                    item.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    item.LastSeen.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    EscapeCsv(item.OpenPorts),
                    EscapeCsv(item.ServerBanners)
                );
                await writer.WriteLineAsync(line);
            }

            DebugLogger.Log($"[HostInventoryViewModel] Exported {Hosts.Count} hosts to CSV");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[HostInventoryViewModel] CSV export failed: {ex.Message}");
        }
    }

    private static string EscapeCsv(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        if (value.Contains(',', StringComparison.Ordinal) ||
            value.Contains('"', StringComparison.Ordinal) ||
            value.Contains('\n', StringComparison.Ordinal))
            return $"\"{value.Replace("\"", "\"\"", StringComparison.Ordinal)}\"";
        return value;
    }

    [RelayCommand]
    private async Task CopyToClipboard(HostInventoryItem? item)
    {
        if (item == null) return;

        var text = $"IP: {item.IpAddress}\n" +
                   $"MAC: {item.MacAddress}\n" +
                   $"Vendor: {item.MacVendor}\n" +
                   $"Hostname: {item.Hostname}\n" +
                   $"OS: {item.OsDisplayName}\n" +
                   $"Device Type: {item.DeviceTypeDisplay}\n" +
                   $"Confidence: {item.ConfidenceDisplay}\n" +
                   $"Detection: {item.DetectionMethodDisplay}\n" +
                   $"JA3 Verified: {item.Ja3Verified}\n" +
                   $"Packets: {item.PacketCount:N0}";

        // Copy to clipboard via Avalonia
        var clipboard = Avalonia.Application.Current?.ApplicationLifetime is
            Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
            ? desktop.MainWindow?.Clipboard
            : null;

        if (clipboard != null)
        {
            await clipboard.SetTextAsync(text);
            DebugLogger.Log($"[HostInventoryViewModel] Copied host info for {item.IpAddress} to clipboard");
        }
    }

    // ==================== ITabPopulationTarget ====================

    public async Task PopulateFromCacheAsync(AnalysisResult result)
    {
        DebugLogger.Log("[HostInventoryViewModel] PopulateFromCacheAsync called");
        await UpdateHostsAsync();
    }
}

/// <summary>
/// View item for host inventory display.
/// </summary>
public class HostInventoryItem : ObservableObject
{
    public string IpAddress { get; set; } = string.Empty;
    public string MacAddress { get; set; } = "-";
    public string MacVendor { get; set; } = "Unknown";
    public string Hostname { get; set; } = "-";
    public string OsFamily { get; set; } = "Unknown";
    public string OsVersion { get; set; } = string.Empty;
    public string OsDisplayName { get; set; } = "Unknown";
    public DeviceType DeviceType { get; set; }
    public string DeviceTypeDisplay { get; set; } = "Unknown";
    public OsConfidenceLevel Confidence { get; set; }
    public string ConfidenceDisplay { get; set; } = "Unknown";
    public double ConfidenceScore { get; set; }
    public OsDetectionMethod DetectionMethod { get; set; }
    public string DetectionMethodDisplay { get; set; } = "Unknown";
    public bool Ja3Verified { get; set; }
    public string Ja3Hash { get; set; } = "-";
    public string Ja3Application { get; set; } = "-";
    public string TcpFingerprint { get; set; } = "-";
    public int PacketCount { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public string OpenPorts { get; set; } = string.Empty;
    public string ServerBanners { get; set; } = string.Empty;
    public HostFingerprint? RawHost { get; set; }

    // Display helpers
    public string FirstSeenDisplay => FirstSeen.ToString("yyyy-MM-dd HH:mm:ss");
    public string LastSeenDisplay => LastSeen.ToString("yyyy-MM-dd HH:mm:ss");
    public string PacketCountDisplay => $"{PacketCount:N0}";
    public string ConfidencePercentage => $"{ConfidenceScore * 100:F0}%";

    // Icon helpers for UI
    public string OsIcon => OsFamily.ToLowerInvariant() switch
    {
        "windows" => "💻",
        "linux" => "🐧",
        "macos" => "🍎",
        "ios" => "📱",
        "android" => "🤖",
        _ => "❓"
    };

    public string VerifiedIcon => Ja3Verified ? "✅" : "";
}

/// <summary>
/// Converts OsConfidenceLevel to a brush color for display.
/// </summary>
public class ConfidenceToBrushConverter : IValueConverter
{
    public static readonly ConfidenceToBrushConverter Instance = new();

    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is OsConfidenceLevel level)
        {
            return level switch
            {
                OsConfidenceLevel.VeryHigh => new SolidColorBrush(ThemeColorHelper.GetColor("ColorSuccess", "#10B981")),
                OsConfidenceLevel.High => new SolidColorBrush(ThemeColorHelper.GetColor("ColorSuccessLight", "#22C55E")),
                OsConfidenceLevel.Medium => new SolidColorBrush(ThemeColorHelper.GetColor("ColorWarning", "#F59E0B")),
                OsConfidenceLevel.Low => new SolidColorBrush(ThemeColorHelper.GetColor("ColorDanger", "#EF4444")),
                _ => new SolidColorBrush(ThemeColorHelper.GetColor("TextMuted", "#6B7280"))
            };
        }
        return new SolidColorBrush(ThemeColorHelper.GetColor("TextMuted", "#6B7280"));
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
