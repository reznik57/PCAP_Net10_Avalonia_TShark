using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels.Threats;

/// <summary>
/// Manages threat statistics, metrics display, table data aggregation, and sorting.
/// Extracted from ThreatsViewModel to isolate statistics calculations.
/// </summary>
public partial class ThreatsStatisticsViewModel : ObservableObject
{
    // ==================== SUMMARY METRICS ====================

    [ObservableProperty] private int _totalThreats;
    [ObservableProperty] private int _criticalThreats;
    [ObservableProperty] private int _highThreats;
    [ObservableProperty] private int _mediumThreats;
    [ObservableProperty] private int _lowThreats;
    [ObservableProperty] private double _overallRiskScore;
    [ObservableProperty] private string _riskLevel = "Unknown";
    [ObservableProperty] private string _riskLevelColor = "#6B7280";

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
    private ObservableCollection<AffectedPortViewModel> _topAffectedPortsByCount = new();

    [ObservableProperty]
    private ObservableCollection<AffectedPortViewModel> _topAffectedPortsBySeverity = new();

    [ObservableProperty]
    private ObservableCollection<AffectedIPViewModel> _topSourceIPs = new();

    [ObservableProperty]
    private ObservableCollection<AffectedIPViewModel> _topDestinationIPs = new();

    /// <summary>
    /// Updates all statistics from SecurityMetrics
    /// </summary>
    public void UpdateFromMetrics(SecurityMetrics? metrics)
    {
        if (metrics == null) return;

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
            RiskLevelColor = "#EF4444";
        }
        else if (OverallRiskScore >= 6)
        {
            RiskLevel = "HIGH";
            RiskLevelColor = "#F97316";
        }
        else if (OverallRiskScore >= 4)
        {
            RiskLevel = "MEDIUM";
            RiskLevelColor = "#F59E0B";
        }
        else if (OverallRiskScore >= 2)
        {
            RiskLevel = "LOW";
            RiskLevelColor = "#3B82F6";
        }
        else
        {
            RiskLevel = "MINIMAL";
            RiskLevelColor = "#10B981";
        }
    }

    /// <summary>
    /// Updates side-by-side table data from threats list
    /// </summary>
    public void UpdateTableData(List<EnhancedSecurityThreat> threats)
    {
        if (!threats.Any()) return;

        // Top Affected Ports by Count
        var portsByCount = threats
            .Where(t => t.Port > 0)
            .GroupBy(t => new { t.Port, t.Protocol })
            .Select(g => new AffectedPortViewModel
            {
                Port = g.Key.Port,
                Protocol = g.Key.Protocol ?? "TCP",
                ServiceName = GetServiceName(g.Key.Port),
                ThreatCount = g.Count(),
                SeverityScore = g.Average(t => (int)t.Severity)
            })
            .OrderByDescending(p => p.ThreatCount)
            .Take(10)
            .ToList();

        var totalPortThreats = portsByCount.Sum(p => p.ThreatCount);
        for (int i = 0; i < portsByCount.Count; i++)
        {
            portsByCount[i].Rank = i + 1;
            portsByCount[i].Percentage = totalPortThreats > 0
                ? (portsByCount[i].ThreatCount / (double)totalPortThreats) * 100 : 0;
        }
        TopAffectedPortsByCount = new ObservableCollection<AffectedPortViewModel>(portsByCount);

        // Top Affected Ports by Severity
        var portsBySeverity = threats
            .Where(t => t.Port > 0)
            .GroupBy(t => new { t.Port, t.Protocol })
            .Select(g => new AffectedPortViewModel
            {
                Port = g.Key.Port,
                Protocol = g.Key.Protocol ?? "TCP",
                ServiceName = GetServiceName(g.Key.Port),
                ThreatCount = g.Count(),
                SeverityScore = g.Max(t => (int)t.Severity) + g.Average(t => (int)t.Severity)
            })
            .OrderByDescending(p => p.SeverityScore)
            .Take(10)
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

    private static string GetServiceName(int port) => port switch
    {
        20 or 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        993 => "IMAPS",
        995 => "POP3S",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        8080 => "HTTP-Alt",
        _ => "Unknown"
    };

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
