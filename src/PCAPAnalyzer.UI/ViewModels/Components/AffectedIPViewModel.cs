using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// ViewModel for displaying affected IP statistics in side-by-side tables.
/// </summary>
public partial class AffectedIPViewModel : ObservableObject
{
    [ObservableProperty]
    private int _rank;

    [ObservableProperty]
    private string _address = string.Empty;

    [ObservableProperty]
    private string _country = "--";

    [ObservableProperty]
    private double _percentage;

    [ObservableProperty]
    private int _threatCount;

    /// <summary>
    /// Formatted display for threat count metric.
    /// </summary>
    public string ThreatCountFormatted => $"{ThreatCount:N0} threats";
}
