using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// ViewModel for displaying affected port statistics in side-by-side tables.
/// </summary>
public partial class AffectedPortViewModel : ObservableObject
{
    [ObservableProperty]
    private int _rank;

    [ObservableProperty]
    private int _port;

    [ObservableProperty]
    private string _protocol = "TCP";

    [ObservableProperty]
    private string _serviceName = "Unknown";

    [ObservableProperty]
    private double _percentage;

    [ObservableProperty]
    private int _threatCount;

    [ObservableProperty]
    private double _severityScore;

    /// <summary>
    /// Formatted display for threat count metric.
    /// </summary>
    public string ThreatCountFormatted => $"{ThreatCount:N0} threats";

    /// <summary>
    /// Formatted display for severity score metric.
    /// </summary>
    public string SeverityScoreFormatted => $"{SeverityScore:F1}";

    /// <summary>
    /// Combined port/protocol display (e.g., "443/TCP").
    /// </summary>
    public string PortDisplay => $"{Port}/{Protocol}";
}
