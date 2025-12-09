using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// ViewModel for the dedicated Anomalies analysis tab.
/// Provides filtering, sorting, and detail view of detected anomalies.
/// </summary>
public partial class AnomalyViewModel : ObservableObject
{
    // ==================== DATA ====================

    private IReadOnlyList<NetworkAnomaly> _allAnomalies = [];

    // Fingerprint for early-exit optimization
    private string? _lastFilterFingerprint;

    [ObservableProperty]
    private ObservableCollection<AnomalyDisplayItem> _filteredAnomalies = [];

    [ObservableProperty]
    private AnomalyDisplayItem? _selectedAnomaly;

    // ==================== FILTER STATE ====================

    [ObservableProperty] private bool _showCritical = true;
    [ObservableProperty] private bool _showHigh = true;
    [ObservableProperty] private bool _showMedium = true;
    [ObservableProperty] private bool _showLow = false;

    [ObservableProperty] private bool _filterNetwork = true;
    [ObservableProperty] private bool _filterTcp = true;
    [ObservableProperty] private bool _filterApplication = true;
    [ObservableProperty] private bool _filterVoip = true;
    [ObservableProperty] private bool _filterIot = true;
    [ObservableProperty] private bool _filterSecurity = true;
    [ObservableProperty] private bool _filterMalformed = true;

    [ObservableProperty] private string _searchText = "";

    // ==================== STATISTICS ====================

    [ObservableProperty] private int _totalCount;
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumCount;
    [ObservableProperty] private int _lowCount;
    [ObservableProperty] private int _filteredCount;

    // ==================== NAVIGATION ====================

    private readonly Action<string, string>? _navigateWithFilter;

    public AnomalyViewModel(Action<string, string>? navigateWithFilter = null)
    {
        _navigateWithFilter = navigateWithFilter;
    }

    // ==================== PUBLIC METHODS ====================

    /// <summary>
    /// Update with new anomaly data from analysis.
    /// Uses single-pass counting (5 Count() → 1 foreach).
    /// </summary>
    public void UpdateAnomalies(IReadOnlyList<NetworkAnomaly>? anomalies)
    {
        _allAnomalies = anomalies ?? [];

        // Single-pass severity counting (was 5 separate .Count() calls)
        int critical = 0, high = 0, medium = 0, low = 0;
        foreach (var a in _allAnomalies)
        {
            switch (a.Severity)
            {
                case AnomalySeverity.Critical: critical++; break;
                case AnomalySeverity.High: high++; break;
                case AnomalySeverity.Medium: medium++; break;
                case AnomalySeverity.Low: low++; break;
            }
        }

        TotalCount = _allAnomalies.Count;
        CriticalCount = critical;
        HighCount = high;
        MediumCount = medium;
        LowCount = low;

        // Reset fingerprint to force filter rebuild with new data
        _lastFilterFingerprint = null;
        ApplyFilters();
        DebugLogger.Log($"[AnomalyViewModel] Updated with {TotalCount} anomalies");
    }

    /// <summary>
    /// Apply navigation filter (from Dashboard link).
    /// </summary>
    public void ApplyNavigationFilter(string? severity, string? category)
    {
        // Reset all filters first
        ShowCritical = ShowHigh = ShowMedium = ShowLow = true;
        FilterNetwork = FilterTcp = FilterApplication = FilterVoip = FilterIot = FilterSecurity = FilterMalformed = true;

        // Apply severity filter if specified
        if (!string.IsNullOrEmpty(severity))
        {
            ShowCritical = severity.Equals("Critical", StringComparison.OrdinalIgnoreCase);
            ShowHigh = severity.Equals("High", StringComparison.OrdinalIgnoreCase);
            ShowMedium = severity.Equals("Medium", StringComparison.OrdinalIgnoreCase);
            ShowLow = severity.Equals("Low", StringComparison.OrdinalIgnoreCase);

            // If a specific severity is selected, also show critical+ for context
            if (ShowHigh) ShowCritical = true;
            if (ShowMedium) { ShowCritical = true; ShowHigh = true; }
        }

        ApplyFilters();
    }

    /// <summary>
    /// Clear all data.
    /// </summary>
    public void Clear()
    {
        _allAnomalies = [];
        FilteredAnomalies.Clear();
        SelectedAnomaly = null;
        TotalCount = CriticalCount = HighCount = MediumCount = LowCount = FilteredCount = 0;
    }

    // ==================== FILTER LOGIC ====================

    partial void OnShowCriticalChanged(bool value) => ApplyFilters();
    partial void OnShowHighChanged(bool value) => ApplyFilters();
    partial void OnShowMediumChanged(bool value) => ApplyFilters();
    partial void OnShowLowChanged(bool value) => ApplyFilters();
    partial void OnFilterNetworkChanged(bool value) => ApplyFilters();
    partial void OnFilterTcpChanged(bool value) => ApplyFilters();
    partial void OnFilterApplicationChanged(bool value) => ApplyFilters();
    partial void OnFilterVoipChanged(bool value) => ApplyFilters();
    partial void OnFilterIotChanged(bool value) => ApplyFilters();
    partial void OnFilterSecurityChanged(bool value) => ApplyFilters();
    partial void OnFilterMalformedChanged(bool value) => ApplyFilters();
    partial void OnSearchTextChanged(string value) => ApplyFilters();

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive class coupling", Justification = "Filter method checks 4 severity + 7 category flags with search - complexity is inherent to multi-criteria filtering")]
    private void ApplyFilters()
    {
        // Fingerprint check for early-exit (includes all filter states)
        var fingerprint = $"{_allAnomalies.Count}|{ShowCritical}|{ShowHigh}|{ShowMedium}|{ShowLow}|{FilterNetwork}|{FilterTcp}|{FilterApplication}|{FilterVoip}|{FilterIot}|{FilterSecurity}|{FilterMalformed}|{SearchText}";
        if (fingerprint == _lastFilterFingerprint)
        {
            DebugLogger.Log("[AnomalyViewModel] SKIPPING ApplyFilters - unchanged");
            return;
        }
        _lastFilterFingerprint = fingerprint;

        var filtered = _allAnomalies.AsEnumerable();

        // Severity filter
        filtered = filtered.Where(a =>
            (ShowCritical && a.Severity == AnomalySeverity.Critical) ||
            (ShowHigh && a.Severity == AnomalySeverity.High) ||
            (ShowMedium && a.Severity == AnomalySeverity.Medium) ||
            (ShowLow && a.Severity == AnomalySeverity.Low));

        // Category filter
        filtered = filtered.Where(a =>
            (FilterNetwork && a.Category == AnomalyCategory.Network) ||
            (FilterTcp && a.Category == AnomalyCategory.TCP) ||
            (FilterApplication && a.Category == AnomalyCategory.Application) ||
            (FilterVoip && a.Category == AnomalyCategory.VoIP) ||
            (FilterIot && a.Category == AnomalyCategory.IoT) ||
            (FilterSecurity && a.Category == AnomalyCategory.Security) ||
            (FilterMalformed && a.Category == AnomalyCategory.Malformed));

        // Search filter
        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var search = SearchText.Trim();
            filtered = filtered.Where(a =>
                (a.Type?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (a.Description?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (a.SourceIP?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false) ||
                (a.DestinationIP?.Contains(search, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        // Convert to display items
        var items = filtered
            .OrderByDescending(a => a.Severity)
            .ThenByDescending(a => a.DetectedAt)
            .Select(a => new AnomalyDisplayItem(a))
            .ToList();

        FilteredAnomalies = new ObservableCollection<AnomalyDisplayItem>(items);
        FilteredCount = items.Count;
    }

    // ==================== COMMANDS ====================

    [RelayCommand]
    private void ViewPackets()
    {
        if (SelectedAnomaly is null) return;

        var filter = !string.IsNullOrEmpty(SelectedAnomaly.SourceIP)
            ? $"ip={SelectedAnomaly.SourceIP}"
            : "";

        _navigateWithFilter?.Invoke("PacketAnalysis", filter);
    }

    [RelayCommand]
    private void ClearFilters()
    {
        ShowCritical = ShowHigh = ShowMedium = true;
        ShowLow = false;
        FilterNetwork = FilterTcp = FilterApplication = FilterVoip = FilterIot = FilterSecurity = FilterMalformed = true;
        SearchText = "";
    }

    [RelayCommand]
    private async Task ExportToCsv()
    {
        if (!FilteredAnomalies.Any())
        {
            DebugLogger.Log("[AnomalyViewModel] No anomalies to export");
            return;
        }

        try
        {
            if (Avalonia.Application.Current?.ApplicationLifetime is not
                Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop ||
                desktop.MainWindow is null)
            {
                return;
            }

            var topLevel = desktop.MainWindow;
            var saveDialog = new Avalonia.Platform.Storage.FilePickerSaveOptions
            {
                Title = "Export Anomalies to CSV",
                DefaultExtension = "csv",
                SuggestedFileName = $"Anomalies_{DateTime.Now:yyyyMMdd_HHmmss}.csv",
                FileTypeChoices = new[]
                {
                    new Avalonia.Platform.Storage.FilePickerFileType("CSV Files") { Patterns = new[] { "*.csv" } }
                }
            };

            var file = await topLevel.StorageProvider.SaveFilePickerAsync(saveDialog);
            if (file is null) return;

            await using var stream = await file.OpenWriteAsync();
            await using var writer = new System.IO.StreamWriter(stream);

            // Write header
            await writer.WriteLineAsync("Type,Severity,Category,Source IP,Source Port,Destination IP,Destination Port,Detected At,Description");

            // Write data
            foreach (var item in FilteredAnomalies)
            {
                var line = string.Join(",",
                    EscapeCsv(item.Type),
                    item.Severity.ToString(),
                    item.Category.ToString(),
                    EscapeCsv(item.SourceIP),
                    item.SourcePort,
                    EscapeCsv(item.DestinationIP),
                    item.DestinationPort,
                    item.DetectedAt.ToString("yyyy-MM-dd HH:mm:ss.fff"),
                    EscapeCsv(item.Description)
                );
                await writer.WriteLineAsync(line);
            }

            DebugLogger.Log($"[AnomalyViewModel] Exported {FilteredAnomalies.Count} anomalies to CSV");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[AnomalyViewModel] CSV export failed: {ex.Message}");
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
}

/// <summary>
/// Display wrapper for NetworkAnomaly with UI-friendly properties.
/// </summary>
public class AnomalyDisplayItem
{
    private readonly NetworkAnomaly _anomaly;

    public AnomalyDisplayItem(NetworkAnomaly anomaly)
    {
        _anomaly = anomaly;
    }

    public string Type => _anomaly.Type ?? "Unknown";
    public string Description => _anomaly.Description ?? "";
    public AnomalySeverity Severity => _anomaly.Severity;
    public AnomalyCategory Category => _anomaly.Category;
    public string SourceIP => _anomaly.SourceIP ?? "";
    public string DestinationIP => _anomaly.DestinationIP ?? "";
    public DateTime DetectedAt => _anomaly.DetectedAt;
    public int SourcePort => _anomaly.SourcePort;
    public int DestinationPort => _anomaly.DestinationPort;

    public string SeverityIcon => Severity switch
    {
        AnomalySeverity.Critical => "\U0001F534", // Red circle
        AnomalySeverity.High => "\U0001F7E0",     // Orange circle
        AnomalySeverity.Medium => "\U0001F7E1",   // Yellow circle
        AnomalySeverity.Low => "\U0001F535",      // Blue circle
        _ => "\U000026AA"                          // White circle
    };

    public string SeverityColor => ThemeColorHelper.GetAnomalySeverityColorHex(Severity.ToString());

    public string CategoryIcon => Category switch
    {
        AnomalyCategory.Network => "\U0001F310",     // Globe
        AnomalyCategory.TCP => "\U0001F517",          // Link
        AnomalyCategory.Application => "\U0001F4F1", // Phone
        AnomalyCategory.VoIP => "\U0001F4DE",        // Phone receiver
        AnomalyCategory.IoT => "\U0001F50C",          // Plug
        AnomalyCategory.Security => "\U000026A0",    // Warning
        AnomalyCategory.Malformed => "\U00002753",   // Question
        _ => "\U00002754"                             // Question
    };

    public string TimeFormatted => DetectedAt.ToString("HH:mm:ss");
    public string ConnectionInfo => !string.IsNullOrEmpty(SourceIP)
        ? $"{SourceIP}:{SourcePort} \u2192 {DestinationIP}:{DestinationPort}"
        : "N/A";
}
