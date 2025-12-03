using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// KPI summary for the Anomalies tab header row.
/// </summary>
public class AnomalyKPIs
{
    public int TotalAnomalies { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int UniqueSourceIPs { get; set; }
    public int UniqueTargetIPs { get; set; }
    public TimeSpan TimeSpan { get; set; }
    public DateTime? FirstAnomalyTime { get; set; }
    public DateTime? LastAnomalyTime { get; set; }
}

/// <summary>
/// Display model for ranked anomaly source/target tables.
/// </summary>
public partial class AnomalyEndpointViewModel : ObservableObject
{
    [ObservableProperty] private string _ipAddress = string.Empty;
    [ObservableProperty] private int _anomalyCount;
    [ObservableProperty] private AnomalySeverity _highestSeverity;
    [ObservableProperty] private int _criticalCount;
    [ObservableProperty] private int _highCount;
    [ObservableProperty] private int _mediumCount;
    [ObservableProperty] private int _lowCount;
    [ObservableProperty] private double _percentage;
    [ObservableProperty] private int _rank;
    [ObservableProperty] private string _country = string.Empty;
    [ObservableProperty] private string _countryCode = string.Empty;
    [ObservableProperty] private List<AnomalyCategory> _categories = new();
    [ObservableProperty] private List<long> _affectedFrames = new();

    public string SeverityColor => HighestSeverity switch
    {
        AnomalySeverity.Critical => "#F85149",
        AnomalySeverity.High => "#F59E0B",
        AnomalySeverity.Medium => "#FCD34D",
        AnomalySeverity.Low => "#3B82F6",
        _ => "#8B949E"
    };

    public string CategoryBadges => Categories.Count switch
    {
        0 => "",
        1 => Categories[0].ToString(),
        2 => $"{Categories[0]}, {Categories[1]}",
        _ => $"{Categories[0]}, {Categories[1]}, +{Categories.Count - 2}"
    };
}

/// <summary>
/// Display model for anomalous ports bar chart.
/// </summary>
public class AnomalyPortViewModel
{
    public int Rank { get; set; }
    public int Port { get; set; }
    public string ServiceName { get; set; } = string.Empty;
    public int AnomalyCount { get; set; }
    public double Percentage { get; set; }
    public AnomalySeverity HighestSeverity { get; set; }
    public List<long> AffectedFrames { get; set; } = new();

    public string SeverityColor => HighestSeverity switch
    {
        AnomalySeverity.Critical => "#F85149",
        AnomalySeverity.High => "#F59E0B",
        AnomalySeverity.Medium => "#FCD34D",
        AnomalySeverity.Low => "#3B82F6",
        _ => "#8B949E"
    };
}

/// <summary>
/// Display model for category distribution donut chart.
/// </summary>
public class AnomalyCategoryViewModel
{
    public AnomalyCategory Category { get; set; }
    public int Count { get; set; }
    public double Percentage { get; set; }

    public string Color => Category switch
    {
        AnomalyCategory.Network => "#3B82F6",
        AnomalyCategory.TCP => "#10B981",
        AnomalyCategory.Application => "#F59E0B",
        AnomalyCategory.VoIP => "#8B5CF6",
        AnomalyCategory.IoT => "#06B6D4",
        AnomalyCategory.Security => "#F85149",
        AnomalyCategory.Malformed => "#EC4899",
        _ => "#8B949E"
    };
}

/// <summary>
/// Time-series data point for the anomaly timeline chart.
/// </summary>
public class AnomalyTimePoint
{
    public DateTime Timestamp { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public int TotalCount => CriticalCount + HighCount + MediumCount + LowCount;
}

/// <summary>
/// Drill-down summary for a specific time window.
/// </summary>
public class AnomalyTimeSliceSummary
{
    public DateTime WindowStart { get; set; }
    public DateTime WindowEnd { get; set; }
    public int TotalAnomalies { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public Dictionary<AnomalyCategory, int> CategoryBreakdown { get; set; } = new();
    public List<NetworkAnomaly> TopAnomalies { get; set; } = new();
}
