using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Threats;

/// <summary>
/// Manages threat statistics, metrics display, table data aggregation, and sorting.
/// Extracted from ThreatsViewModel to isolate statistics calculations.
/// Uses fingerprinting for early-exit optimization.
/// </summary>
public partial class ThreatsStatisticsViewModel : ObservableObject
{
    // Fingerprints for early-exit optimization
    private string? _lastMetricsFingerprint;
    private string? _lastTableDataFingerprint;

    // ==================== SUMMARY METRICS ====================

    [ObservableProperty] private int _totalThreats;
    [ObservableProperty] private int _criticalThreats;
    [ObservableProperty] private int _highThreats;
    [ObservableProperty] private int _mediumThreats;
    [ObservableProperty] private int _lowThreats;
    [ObservableProperty] private double _overallRiskScore;
    [ObservableProperty] private string _riskLevel = "Unknown";
    [ObservableProperty] private string _riskLevelColor = ThemeColorHelper.GetColorHex("TextMuted", "#6B7280");

    // ==================== SORTING ====================

    [ObservableProperty] private string _selectedSortOption = "Severity ▼";
    public ObservableCollection<string> SortOptions { get; } = new()
    {
        "Severity ▼", "Severity ▲", "Time ▼", "Time ▲",
        "Occurrences ▼", "Occurrences ▲", "Source IP", "Dest IP"
    };

    /// <summary>
    /// Event fired when sort option changes
    /// </summary>
    public event Action? SortChanged;

    partial void OnSelectedSortOptionChanged(string value)
    {
        SortChanged?.Invoke();
    }

    // ==================== SIDE-BY-SIDE TABLE DATA ====================

    [ObservableProperty]
    private ObservableCollection<AffectedPortViewModel> _topAffectedPortsByCount = [];

    [ObservableProperty]
    private ObservableCollection<AffectedPortViewModel> _topAffectedPortsBySeverity = [];

    [ObservableProperty]
    private ObservableCollection<AffectedIPViewModel> _topSourceIPs = [];

    [ObservableProperty]
    private ObservableCollection<AffectedIPViewModel> _topDestinationIPs = [];

    /// <summary>
    /// Updates all statistics from SecurityMetrics with fingerprinting for early-exit.
    /// </summary>
    public void UpdateFromMetrics(SecurityMetrics? metrics)
    {
        if (metrics is null) return;

        // Fingerprint check for early-exit
        var fingerprint = $"{metrics.TotalThreats}|{metrics.CriticalThreats}|{metrics.HighThreats}|{metrics.MediumThreats}|{metrics.LowThreats}|{metrics.OverallRiskScore:F2}";
        if (fingerprint == _lastMetricsFingerprint)
            return;
        _lastMetricsFingerprint = fingerprint;

        TotalThreats = metrics.TotalThreats;
        CriticalThreats = metrics.CriticalThreats;
        HighThreats = metrics.HighThreats;
        MediumThreats = metrics.MediumThreats;
        LowThreats = metrics.LowThreats;
        OverallRiskScore = System.Math.Round(metrics.OverallRiskScore, 2);

        UpdateRiskLevel();
    }

    /// <summary>
    /// Updates risk level badge color based on score
    /// </summary>
    public void UpdateRiskLevel()
    {
        if (OverallRiskScore >= 8)
        {
            RiskLevel = "CRITICAL";
            RiskLevelColor = ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444");
        }
        else if (OverallRiskScore >= 6)
        {
            RiskLevel = "HIGH";
            RiskLevelColor = ThemeColorHelper.GetColorHex("ColorOrange", "#F97316");
        }
        else if (OverallRiskScore >= 4)
        {
            RiskLevel = "MEDIUM";
            RiskLevelColor = ThemeColorHelper.GetColorHex("ColorWarning", "#F59E0B");
        }
        else if (OverallRiskScore >= 2)
        {
            RiskLevel = "LOW";
            RiskLevelColor = ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6");
        }
        else
        {
            RiskLevel = "MINIMAL";
            RiskLevelColor = ThemeColorHelper.GetColorHex("ColorSuccess", "#10B981");
        }
    }

    /// <summary>
    /// Updates side-by-side table data from threats list with fingerprinting for early-exit.
    /// </summary>
    public void UpdateTableData(List<EnhancedSecurityThreat> threats)
    {
        if (!threats.Any())
        {
            if (_lastTableDataFingerprint == "empty")
                return;
            _lastTableDataFingerprint = "empty";
            TopAffectedPortsByCount.Clear();
            TopAffectedPortsBySeverity.Clear();
            TopSourceIPs.Clear();
            TopDestinationIPs.Clear();
            return;
        }

        // Generate fingerprint from threat count and top ports
        var fingerprint = $"{threats.Count}|{threats.Sum(t => t.Port)}|{threats.Count(t => t.Port > 0)}";
        if (fingerprint == _lastTableDataFingerprint)
        {
            DebugLogger.Log("[ThreatsStatisticsViewModel] SKIPPING UpdateTableData - data unchanged");
            return;
        }
        _lastTableDataFingerprint = fingerprint;

        // Pre-group ports once for both queries (avoid duplicate GroupBy)
        var portGroups = threats
            .Where(t => t.Port > 0)
            .GroupBy(t => new { t.Port, t.Protocol })
            .Select(g => new
            {
                g.Key.Port,
                g.Key.Protocol,
                ThreatCount = g.Count(),
                MaxSeverity = g.Max(t => (int)t.Severity),
                AvgSeverity = g.Average(t => (int)t.Severity)
            })
            .ToList();

        // Top Affected Ports by Count
        var portsByCount = portGroups
            .OrderByDescending(p => p.ThreatCount)
            .Take(10)
            .Select(p => new AffectedPortViewModel
            {
                Port = p.Port,
                Protocol = p.Protocol ?? "TCP",
                ServiceName = ThreatDisplayHelpers.GetServiceName(p.Port),
                ThreatCount = p.ThreatCount,
                SeverityScore = p.AvgSeverity
            })
            .ToList();

        var totalPortThreats = portsByCount.Sum(p => p.ThreatCount);
        for (int i = 0; i < portsByCount.Count; i++)
        {
            portsByCount[i].Rank = i + 1;
            portsByCount[i].Percentage = totalPortThreats > 0
                ? (portsByCount[i].ThreatCount / (double)totalPortThreats) * 100 : 0;
        }
        TopAffectedPortsByCount = new ObservableCollection<AffectedPortViewModel>(portsByCount);

        // Top Affected Ports by Severity (reuse pre-grouped data)
        var portsBySeverity = portGroups
            .OrderByDescending(p => p.MaxSeverity + p.AvgSeverity)
            .Take(10)
            .Select(p => new AffectedPortViewModel
            {
                Port = p.Port,
                Protocol = p.Protocol ?? "TCP",
                ServiceName = ThreatDisplayHelpers.GetServiceName(p.Port),
                ThreatCount = p.ThreatCount,
                SeverityScore = p.MaxSeverity + p.AvgSeverity
            })
            .ToList();

        var maxSeverityScore = portsBySeverity.Count > 0 ? portsBySeverity.Max(p => p.SeverityScore) : 1;
        for (int i = 0; i < portsBySeverity.Count; i++)
        {
            portsBySeverity[i].Rank = i + 1;
            portsBySeverity[i].Percentage = maxSeverityScore > 0
                ? (portsBySeverity[i].SeverityScore / maxSeverityScore) * 100 : 0;
        }
        TopAffectedPortsBySeverity = new ObservableCollection<AffectedPortViewModel>(portsBySeverity);

        // Top Source IPs
        var sourceIPs = threats
            .Where(t => t.AffectedIPs?.Any() == true)
            .SelectMany(t => t.AffectedIPs!.Take(1).Select(ip => new { IP = ip, Threat = t }))
            .GroupBy(x => x.IP)
            .Select(g => new AffectedIPViewModel
            {
                Address = g.Key,
                Country = "--",
                ThreatCount = g.Count()
            })
            .OrderByDescending(ip => ip.ThreatCount)
            .Take(10)
            .ToList();

        var totalSourceThreats = sourceIPs.Sum(ip => ip.ThreatCount);
        for (int i = 0; i < sourceIPs.Count; i++)
        {
            sourceIPs[i].Rank = i + 1;
            sourceIPs[i].Percentage = totalSourceThreats > 0
                ? (sourceIPs[i].ThreatCount / (double)totalSourceThreats) * 100 : 0;
        }
        TopSourceIPs = new ObservableCollection<AffectedIPViewModel>(sourceIPs);

        // Top Destination IPs
        var destIPs = threats
            .Where(t => t.AffectedIPs?.Count >= 2)
            .SelectMany(t => t.AffectedIPs!.Skip(1).Take(1).Select(ip => new { IP = ip, Threat = t }))
            .GroupBy(x => x.IP)
            .Select(g => new AffectedIPViewModel
            {
                Address = g.Key,
                Country = "--",
                ThreatCount = g.Count()
            })
            .OrderByDescending(ip => ip.ThreatCount)
            .Take(10)
            .ToList();

        var totalDestThreats = destIPs.Sum(ip => ip.ThreatCount);
        for (int i = 0; i < destIPs.Count; i++)
        {
            destIPs[i].Rank = i + 1;
            destIPs[i].Percentage = totalDestThreats > 0
                ? (destIPs[i].ThreatCount / (double)totalDestThreats) * 100 : 0;
        }
        TopDestinationIPs = new ObservableCollection<AffectedIPViewModel>(destIPs);
    }


    /// <summary>
    /// Applies the selected sort option to the threat list
    /// </summary>
    public List<EnhancedSecurityThreat> ApplySorting(List<EnhancedSecurityThreat> threats)
    {
        if (!threats.Any()) return threats;

        return SelectedSortOption switch
        {
            "Severity ▼" => threats.OrderByDescending(t => t.Severity).ThenByDescending(t => t.RiskScore).ToList(),
            "Severity ▲" => threats.OrderBy(t => t.Severity).ThenBy(t => t.RiskScore).ToList(),
            "Time ▼" => threats.OrderByDescending(t => t.LastSeen).ToList(),
            "Time ▲" => threats.OrderBy(t => t.FirstSeen).ToList(),
            "Occurrences ▼" => threats.OrderByDescending(t => t.OccurrenceCount).ToList(),
            "Occurrences ▲" => threats.OrderBy(t => t.OccurrenceCount).ToList(),
            "Source IP" => threats.OrderBy(t => t.AffectedIPs.FirstOrDefault() ?? "").ToList(),
            "Dest IP" => threats.OrderBy(t => t.AffectedIPs.Skip(1).FirstOrDefault() ?? "").ToList(),
            _ => threats.OrderByDescending(t => t.Severity).ThenByDescending(t => t.RiskScore).ToList()
        };
    }
}
