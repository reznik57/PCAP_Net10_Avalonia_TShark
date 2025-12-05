using System;
using System.Collections.Generic;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// ViewModel for displaying a security threat item in the threats list.
/// </summary>
public class SecurityThreatItemViewModel : ObservableObject
{
    private static readonly string DefaultSeverityColor = ThemeColorHelper.GetColorHex("TextMuted", "#6B7280");

    public string Id { get; set; } = "";
    public int Rank { get; set; }
    public string ThreatName { get; set; } = "";
    public string Category { get; set; } = "";
    public string Severity { get; set; } = "";
    public string SeverityColor { get; set; } = DefaultSeverityColor;
    public string Service { get; set; } = "";
    public int Port { get; set; }
    public double RiskScore { get; set; }
    public int OccurrenceCount { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public string Description { get; set; } = "";
    public List<string> Vulnerabilities { get; set; } = new();
    public List<string> Mitigations { get; set; } = new();
    public List<string> AffectedIPs { get; set; } = new();
    public string DetectedVersion { get; set; } = "";
    public bool IsEncryptedButInsecure { get; set; }
    public List<string> SourceIPs { get; set; } = new();
    public List<string> DestinationIPs { get; set; } = new();

    /// <summary>
    /// Percentage of total threats this item represents (for percentage bar display).
    /// </summary>
    public double Percentage { get; set; }

    public List<(string Source, string Destination)> Connections { get; set; } = new();
}
