using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// ViewModel for the anomaly summary widget displayed on Dashboard.
/// Shows severity counts and top threats with navigation to Anomalies tab.
/// </summary>
public partial class AnomalySummaryViewModel : ObservableObject
{
    private readonly Action<string>? _navigateToTab;

    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumCount;
    [ObservableProperty] private int _lowCount;
    [ObservableProperty] private bool _isVisible = true;

    [ObservableProperty]
    private ObservableCollection<AnomalySummaryItem> _topThreats = [];

    public int TotalCount => CriticalCount + HighCount + MediumCount + LowCount;
    public bool HasAnomalies => TotalCount > 0;
    public bool HasCritical => CriticalCount > 0;

    public AnomalySummaryViewModel(Action<string>? navigateToTab = null)
    {
        _navigateToTab = navigateToTab;
    }

    /// <summary>
    /// Update summary from detected anomalies.
    /// </summary>
    public void UpdateFromAnomalies(IReadOnlyList<NetworkAnomaly>? anomalies)
    {
        if (anomalies == null || anomalies.Count == 0)
        {
            CriticalCount = HighCount = MediumCount = LowCount = 0;
            TopThreats.Clear();
            OnPropertyChanged(nameof(TotalCount));
            OnPropertyChanged(nameof(HasAnomalies));
            OnPropertyChanged(nameof(HasCritical));
            return;
        }

        CriticalCount = anomalies.Count(a => a.Severity == AnomalySeverity.Critical);
        HighCount = anomalies.Count(a => a.Severity == AnomalySeverity.High);
        MediumCount = anomalies.Count(a => a.Severity == AnomalySeverity.Medium);
        LowCount = anomalies.Count(a => a.Severity == AnomalySeverity.Low);

        // Get top 3 threats by severity
        var top3 = anomalies
            .OrderByDescending(a => a.Severity)
            .ThenByDescending(a => a.DetectedAt)
            .Take(3)
            .Select(a => new AnomalySummaryItem
            {
                Title = a.Type,
                Description = a.Description ?? $"Detected at {a.DetectedAt:HH:mm:ss}",
                Severity = a.Severity,
                SourceIP = a.SourceIP ?? "Unknown"
            })
            .ToList();

        TopThreats = new ObservableCollection<AnomalySummaryItem>(top3);

        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(HasAnomalies));
        OnPropertyChanged(nameof(HasCritical));
    }

    [RelayCommand]
    private void ViewAllAnomalies()
    {
        _navigateToTab?.Invoke("Anomalies");
    }

    [RelayCommand]
    private void ViewBySeverity(string severity)
    {
        // Navigate with filter parameter
        _navigateToTab?.Invoke($"Anomalies?severity={severity}");
    }

    /// <summary>
    /// Clear all data.
    /// </summary>
    public void Clear()
    {
        CriticalCount = HighCount = MediumCount = LowCount = 0;
        TopThreats.Clear();
        OnPropertyChanged(nameof(TotalCount));
        OnPropertyChanged(nameof(HasAnomalies));
        OnPropertyChanged(nameof(HasCritical));
    }
}

/// <summary>
/// Display item for anomaly summary list.
/// </summary>
public class AnomalySummaryItem
{
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public AnomalySeverity Severity { get; set; }
    public string SourceIP { get; set; } = "";

    public string SeverityIcon => Severity switch
    {
        AnomalySeverity.Critical => "!!",
        AnomalySeverity.High => "!",
        AnomalySeverity.Medium => "~",
        AnomalySeverity.Low => "-",
        _ => "?"
    };

    public string SeverityColor => Severity switch
    {
        AnomalySeverity.Critical => ThemeColorHelper.GetColorHex("ColorDanger", "#F85149"),
        AnomalySeverity.High => ThemeColorHelper.GetColorHex("ColorOrange", "#F0883E"),
        AnomalySeverity.Medium => ThemeColorHelper.GetColorHex("ColorWarning", "#D29922"),
        AnomalySeverity.Low => ThemeColorHelper.GetColorHex("AccentBlue", "#58A6FF"),
        _ => ThemeColorHelper.GetColorHex("TextMuted", "#8B949E")
    };
}
