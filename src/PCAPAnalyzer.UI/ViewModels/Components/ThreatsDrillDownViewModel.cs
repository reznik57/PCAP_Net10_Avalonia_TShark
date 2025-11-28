using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component ViewModel for the full investigation DrillDown view.
/// Provides packet correlation, related threats, timeline, IOCs, and mitigations.
/// </summary>
public partial class ThreatsDrillDownViewModel : ObservableObject
{
    // Visibility
    [ObservableProperty] private bool _isVisible;

    // Header information
    [ObservableProperty] private string _threatName = "";
    [ObservableProperty] private string _severity = "";
    [ObservableProperty] private string _severityColor = "#6B7280";
    [ObservableProperty] private string _category = "";
    [ObservableProperty] private int _port;
    [ObservableProperty] private string _protocol = "";
    [ObservableProperty] private double _riskScore;

    // Summary section
    [ObservableProperty] private string _description = "";
    [ObservableProperty] private DateTime _firstSeen;
    [ObservableProperty] private DateTime _lastSeen;
    [ObservableProperty] private int _occurrenceCount;
    [ObservableProperty] private int _affectedIPCount;

    // Active tab
    [ObservableProperty] private int _selectedTabIndex;

    // Tab 1: Timeline data
    [ObservableProperty] private string _timelineSvg = "";

    // Tab 2: Evidence packets
    [ObservableProperty] private ObservableCollection<EvidencePacketViewModel> _evidencePackets = new();
    [ObservableProperty] private int _totalEvidencePackets;
    [ObservableProperty] private int _displayedEvidencePackets;
    [ObservableProperty] private int _evidencePacketsPage = 1;
    [ObservableProperty] private int _evidencePacketsTotalPages = 1;
    private const int PacketsPerPage = 20;

    // Tab 3: Related threats
    [ObservableProperty] private ObservableCollection<RelatedThreatGroup> _relatedThreatGroups = new();
    [ObservableProperty] private int _totalRelatedThreats;

    // Tab 4: IOCs (Indicators of Compromise)
    [ObservableProperty] private ObservableCollection<IOCItem> _networkIOCs = new();
    [ObservableProperty] private string _iocExportText = "";

    // Tab 5: Mitigations
    [ObservableProperty] private ObservableCollection<string> _vulnerabilities = new();
    [ObservableProperty] private ObservableCollection<MitigationItem> _mitigations = new();

    // Internal state
    private EnhancedSecurityThreat? _currentThreat;
    private List<PacketInfo> _allPackets = new();
    private List<EnhancedSecurityThreat> _allThreats = new();
    private List<uint> _currentFrameNumbers = new();

    public ThreatsDrillDownViewModel()
    {
    }

    /// <summary>
    /// Shows the DrillDown for a specific threat with full investigation context
    /// </summary>
    public void ShowForThreat(
        EnhancedSecurityThreat threat,
        List<PacketInfo> allPackets,
        List<EnhancedSecurityThreat> allThreats)
    {
        _currentThreat = threat;
        _allPackets = allPackets;
        _allThreats = allThreats;
        _currentFrameNumbers = threat.FrameNumbers;

        // Set header
        ThreatName = threat.ThreatName;
        Severity = threat.Severity.ToString();
        SeverityColor = GetSeverityColor(threat.Severity);
        Category = threat.Category.ToString();
        Port = threat.Port;
        Protocol = threat.Protocol;
        RiskScore = threat.RiskScore;

        // Set summary
        Description = threat.Description;
        FirstSeen = threat.FirstSeen;
        LastSeen = threat.LastSeen;
        OccurrenceCount = threat.OccurrenceCount;
        AffectedIPCount = threat.AffectedIPs?.Count ?? 0;

        // Initialize tabs
        LoadTimelineTab(threat);
        LoadEvidencePacketsTab(threat, allPackets);
        LoadRelatedThreatsTab(threat, allThreats);
        LoadIOCsTab(threat);
        LoadMitigationsTab(threat);

        // Show the panel
        SelectedTabIndex = 0;
        IsVisible = true;
    }

    [RelayCommand]
    private void Close()
    {
        IsVisible = false;
        _currentThreat = null;
    }

    [RelayCommand]
    private void NextEvidencePage()
    {
        if (EvidencePacketsPage < EvidencePacketsTotalPages)
        {
            EvidencePacketsPage++;
            UpdateEvidencePacketsPage();
        }
    }

    [RelayCommand]
    private void PreviousEvidencePage()
    {
        if (EvidencePacketsPage > 1)
        {
            EvidencePacketsPage--;
            UpdateEvidencePacketsPage();
        }
    }

    [RelayCommand]
    private async Task CopyIOCsToClipboard()
    {
        try
        {
            if (string.IsNullOrEmpty(IocExportText)) return;

            var clipboard = Avalonia.Application.Current?.ApplicationLifetime is
                Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                ? desktop.MainWindow?.Clipboard
                : null;

            if (clipboard != null)
            {
                await clipboard.SetTextAsync(IocExportText);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ThreatsDrillDown] Clipboard error: {ex.Message}");
        }
    }

    /// <summary>
    /// Copies a formatted investigation report to clipboard
    /// </summary>
    [RelayCommand]
    private async Task CopyReport()
    {
        try
        {
            var report = GenerateInvestigationReport();

            var clipboard = Avalonia.Application.Current?.ApplicationLifetime is
                Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                ? desktop.MainWindow?.Clipboard
                : null;

            if (clipboard != null)
            {
                await clipboard.SetTextAsync(report);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[ThreatsDrillDown] Copy report error: {ex.Message}");
        }
    }

    /// <summary>
    /// Event raised when user wants to view threat in Packet Analysis tab
    /// </summary>
    public event EventHandler<ViewInPacketAnalysisEventArgs>? ViewInPacketAnalysisRequested;

    /// <summary>
    /// Navigates to Packet Analysis tab with threat-related packets filtered
    /// </summary>
    [RelayCommand]
    private void ViewInPacketAnalysis()
    {
        if (_currentThreat == null) return;

        // Raise event for parent to handle navigation
        ViewInPacketAnalysisRequested?.Invoke(this, new ViewInPacketAnalysisEventArgs
        {
            ThreatId = _currentThreat.Id,
            FrameNumbers = _currentFrameNumbers,
            AffectedIPs = _currentThreat.AffectedIPs,
            Port = _currentThreat.Port
        });

        // Close the DrillDown after navigation request
        IsVisible = false;
    }

    /// <summary>
    /// Generates a text-based investigation report for clipboard export
    /// </summary>
    private string GenerateInvestigationReport()
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine("               SECURITY THREAT INVESTIGATION REPORT            ");
        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine();
        sb.AppendLine($"Threat:        {ThreatName}");
        sb.AppendLine($"Severity:      {Severity}");
        sb.AppendLine($"Category:      {Category}");
        sb.AppendLine($"Risk Score:    {RiskScore:F1}/10");
        sb.AppendLine($"Port:          {Port}/{Protocol}");
        sb.AppendLine();
        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine("TIMELINE");
        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine($"First Seen:    {FirstSeen:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Last Seen:     {LastSeen:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Occurrences:   {OccurrenceCount:N0}");
        sb.AppendLine($"Affected IPs:  {AffectedIPCount:N0}");
        sb.AppendLine();
        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine("DESCRIPTION");
        sb.AppendLine("───────────────────────────────────────────────────────────────");
        sb.AppendLine(Description);
        sb.AppendLine();

        if (NetworkIOCs.Any())
        {
            sb.AppendLine("───────────────────────────────────────────────────────────────");
            sb.AppendLine("INDICATORS OF COMPROMISE (IOCs)");
            sb.AppendLine("───────────────────────────────────────────────────────────────");
            foreach (var ioc in NetworkIOCs)
            {
                sb.AppendLine($"  [{ioc.Type}] {ioc.Value} - {ioc.Context}");
            }
            sb.AppendLine();
        }

        if (Vulnerabilities.Any())
        {
            sb.AppendLine("───────────────────────────────────────────────────────────────");
            sb.AppendLine("VULNERABILITIES");
            sb.AppendLine("───────────────────────────────────────────────────────────────");
            foreach (var vuln in Vulnerabilities)
            {
                sb.AppendLine($"  • {vuln}");
            }
            sb.AppendLine();
        }

        if (Mitigations.Any())
        {
            sb.AppendLine("───────────────────────────────────────────────────────────────");
            sb.AppendLine("RECOMMENDED MITIGATIONS");
            sb.AppendLine("───────────────────────────────────────────────────────────────");
            foreach (var mit in Mitigations)
            {
                sb.AppendLine($"  [{mit.Priority}] {mit.Description}");
            }
            sb.AppendLine();
        }

        sb.AppendLine("═══════════════════════════════════════════════════════════════");
        sb.AppendLine($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine("═══════════════════════════════════════════════════════════════");

        return sb.ToString();
    }

    private void LoadTimelineTab(EnhancedSecurityThreat threat)
    {
        // Generate a simple SVG timeline showing threat occurrences
        var threatTimes = new List<DateTime> { threat.FirstSeen };
        if (threat.LastSeen != threat.FirstSeen)
        {
            threatTimes.Add(threat.LastSeen);
        }

        // If we have frame numbers, try to get actual timestamps
        if (_currentFrameNumbers.Any() && _allPackets.Any())
        {
            var frameSet = new HashSet<uint>(_currentFrameNumbers);
            threatTimes = _allPackets
                .Where(p => frameSet.Contains(p.FrameNumber))
                .Select(p => p.Timestamp)
                .OrderBy(t => t)
                .ToList();
        }

        TimelineSvg = GenerateMiniTimelineSvg(threatTimes, threat.Severity);
    }

    private void LoadEvidencePacketsTab(EnhancedSecurityThreat threat, List<PacketInfo> allPackets)
    {
        // Get packets by frame numbers if available
        List<PacketInfo> evidencePackets;

        if (threat.FrameNumbers.Any())
        {
            var frameSet = new HashSet<uint>(threat.FrameNumbers);
            evidencePackets = allPackets.Where(p => frameSet.Contains(p.FrameNumber)).ToList();
        }
        else if (threat.AffectedConnections.Any())
        {
            // Fall back to connection-based filtering
            evidencePackets = allPackets.Where(p =>
                threat.AffectedConnections.Any(c =>
                    (c.SourceIP == p.SourceIP && c.DestinationIP == p.DestinationIP &&
                     c.SourcePort == p.SourcePort && c.DestinationPort == p.DestinationPort) ||
                    (c.SourceIP == p.DestinationIP && c.DestinationIP == p.SourceIP &&
                     c.SourcePort == p.DestinationPort && c.DestinationPort == p.SourcePort)
                )).ToList();
        }
        else
        {
            // Last resort: filter by affected IPs
            evidencePackets = allPackets.Where(p =>
                threat.AffectedIPs.Contains(p.SourceIP) ||
                threat.AffectedIPs.Contains(p.DestinationIP)).ToList();
        }

        TotalEvidencePackets = evidencePackets.Count;
        EvidencePacketsTotalPages = Math.Max(1, (int)Math.Ceiling((double)evidencePackets.Count / PacketsPerPage));
        EvidencePacketsPage = 1;

        // Store for paging
        _currentFrameNumbers = evidencePackets.Select(p => p.FrameNumber).ToList();

        UpdateEvidencePacketsPage();
    }

    private void UpdateEvidencePacketsPage()
    {
        if (!_allPackets.Any() || !_currentFrameNumbers.Any())
        {
            EvidencePackets.Clear();
            DisplayedEvidencePackets = 0;
            return;
        }

        var frameSet = new HashSet<uint>(_currentFrameNumbers);
        var allEvidencePackets = _allPackets
            .Where(p => frameSet.Contains(p.FrameNumber))
            .OrderBy(p => p.Timestamp)
            .ToList();

        var pagePackets = allEvidencePackets
            .Skip((EvidencePacketsPage - 1) * PacketsPerPage)
            .Take(PacketsPerPage)
            .Select(p => new EvidencePacketViewModel
            {
                FrameNumber = p.FrameNumber,
                Timestamp = p.Timestamp,
                SourceIP = p.SourceIP,
                DestinationIP = p.DestinationIP,
                SourcePort = p.SourcePort,
                DestinationPort = p.DestinationPort,
                Protocol = p.Protocol.ToString(),
                Length = p.Length,
                Info = p.Info ?? string.Empty
            })
            .ToList();

        EvidencePackets = new ObservableCollection<EvidencePacketViewModel>(pagePackets);
        DisplayedEvidencePackets = pagePackets.Count;
    }

    private void LoadRelatedThreatsTab(EnhancedSecurityThreat threat, List<EnhancedSecurityThreat> allThreats)
    {
        var relatedGroups = new List<RelatedThreatGroup>();
        var otherThreats = allThreats.Where(t => t.Id != threat.Id).ToList();

        // By IP (same affected IPs)
        var byIP = otherThreats
            .Where(t => t.AffectedIPs.Intersect(threat.AffectedIPs).Any())
            .Take(10)
            .ToList();
        if (byIP.Any())
        {
            relatedGroups.Add(new RelatedThreatGroup
            {
                GroupName = "By Source IP",
                GroupIcon = "🔗",
                Threats = new ObservableCollection<RelatedThreatItem>(
                    byIP.Select(t => new RelatedThreatItem
                    {
                        ThreatName = t.ThreatName,
                        Severity = t.Severity.ToString(),
                        SeverityColor = GetSeverityColor(t.Severity),
                        Port = t.Port
                    }))
            });
        }

        // By Port (same port)
        if (threat.Port > 0)
        {
            var byPort = otherThreats
                .Where(t => t.Port == threat.Port && !byIP.Contains(t))
                .Take(10)
                .ToList();
            if (byPort.Any())
            {
                relatedGroups.Add(new RelatedThreatGroup
                {
                    GroupName = "By Target Port",
                    GroupIcon = "🔌",
                    Threats = new ObservableCollection<RelatedThreatItem>(
                        byPort.Select(t => new RelatedThreatItem
                        {
                            ThreatName = t.ThreatName,
                            Severity = t.Severity.ToString(),
                            SeverityColor = GetSeverityColor(t.Severity),
                            Port = t.Port
                        }))
                });
            }
        }

        // By Time (within 5 minutes)
        var timeWindow = TimeSpan.FromMinutes(5);
        var byTime = otherThreats
            .Where(t => Math.Abs((t.FirstSeen - threat.FirstSeen).TotalMinutes) <= 5)
            .Where(t => !byIP.Contains(t))
            .Take(10)
            .ToList();
        if (byTime.Any())
        {
            relatedGroups.Add(new RelatedThreatGroup
            {
                GroupName = "By Time Window (±5 min)",
                GroupIcon = "⏱️",
                Threats = new ObservableCollection<RelatedThreatItem>(
                    byTime.Select(t => new RelatedThreatItem
                    {
                        ThreatName = t.ThreatName,
                        Severity = t.Severity.ToString(),
                        SeverityColor = GetSeverityColor(t.Severity),
                        Port = t.Port
                    }))
            });
        }

        // By Category (same category)
        var byCategory = otherThreats
            .Where(t => t.Category == threat.Category)
            .Where(t => !byIP.Contains(t) && !byTime.Contains(t))
            .Take(10)
            .ToList();
        if (byCategory.Any())
        {
            relatedGroups.Add(new RelatedThreatGroup
            {
                GroupName = "By Category",
                GroupIcon = "📂",
                Threats = new ObservableCollection<RelatedThreatItem>(
                    byCategory.Select(t => new RelatedThreatItem
                    {
                        ThreatName = t.ThreatName,
                        Severity = t.Severity.ToString(),
                        SeverityColor = GetSeverityColor(t.Severity),
                        Port = t.Port
                    }))
            });
        }

        RelatedThreatGroups = new ObservableCollection<RelatedThreatGroup>(relatedGroups);
        TotalRelatedThreats = relatedGroups.Sum(g => g.Threats.Count);
    }

    private void LoadIOCsTab(EnhancedSecurityThreat threat)
    {
        var iocs = new List<IOCItem>();

        // Network IOCs - IPs
        foreach (var ip in threat.AffectedIPs.Distinct().Take(20))
        {
            iocs.Add(new IOCItem
            {
                Type = "IP Address",
                Value = ip,
                Context = $"Affected by {threat.ThreatName}",
                Severity = threat.Severity.ToString()
            });
        }

        // Network IOCs - Port
        if (threat.Port > 0)
        {
            iocs.Add(new IOCItem
            {
                Type = "Port",
                Value = $"{threat.Port}/{threat.Protocol}",
                Context = threat.Service,
                Severity = threat.Severity.ToString()
            });
        }

        // CVE if available
        if (!string.IsNullOrEmpty(threat.CVE))
        {
            iocs.Add(new IOCItem
            {
                Type = "CVE",
                Value = threat.CVE,
                Context = "Known vulnerability",
                Severity = "High"
            });
        }

        // Vulnerabilities as IOCs
        foreach (var vuln in threat.Vulnerabilities.Where(v => v.StartsWith("CVE-", StringComparison.Ordinal)))
        {
            iocs.Add(new IOCItem
            {
                Type = "CVE",
                Value = vuln,
                Context = "Associated vulnerability",
                Severity = "High"
            });
        }

        NetworkIOCs = new ObservableCollection<IOCItem>(iocs);

        // Generate export text (pipe-delimited for easy parsing)
        var exportLines = iocs.Select(i => $"{i.Type}|{i.Value}|{i.Severity}|{i.Context}");
        IocExportText = string.Join("\n", exportLines);
    }

    private void LoadMitigationsTab(EnhancedSecurityThreat threat)
    {
        Vulnerabilities = new ObservableCollection<string>(threat.Vulnerabilities ?? new List<string>());

        var mitigationItems = (threat.Mitigations ?? new List<string>())
            .Select((m, i) => new MitigationItem
            {
                Priority = i < 2 ? "High" : (i < 4 ? "Medium" : "Low"),
                PriorityColor = i < 2 ? "#EF4444" : (i < 4 ? "#F59E0B" : "#10B981"),
                Description = m
            })
            .ToList();

        Mitigations = new ObservableCollection<MitigationItem>(mitigationItems);
    }

    private static string GetSeverityColor(ThreatSeverity severity) => severity switch
    {
        ThreatSeverity.Critical => "#EF4444",
        ThreatSeverity.High => "#F97316",
        ThreatSeverity.Medium => "#F59E0B",
        ThreatSeverity.Low => "#3B82F6",
        ThreatSeverity.Info => "#6B7280",
        _ => "#6B7280"
    };

    private string GenerateMiniTimelineSvg(List<DateTime> times, ThreatSeverity severity)
    {
        if (!times.Any()) return "";

        var width = 500;
        var height = 80;
        var margin = 20;
        var chartWidth = width - margin * 2;

        var minTime = times.Min();
        var maxTime = times.Max();
        var timeRange = (maxTime - minTime).TotalSeconds;
        if (timeRange < 60) timeRange = 120;

        var color = GetSeverityColor(severity);

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"<svg width=\"{width}\" height=\"{height}\" xmlns=\"http://www.w3.org/2000/svg\">");
        sb.AppendLine($"  <rect width=\"{width}\" height=\"{height}\" fill=\"#161B22\" rx=\"4\" />");

        // X axis
        sb.AppendLine($"  <line x1=\"{margin}\" y1=\"{height - margin}\" x2=\"{width - margin}\" y2=\"{height - margin}\" stroke=\"#30363D\" stroke-width=\"1\" />");

        // Time labels
        sb.AppendLine($"  <text x=\"{margin}\" y=\"{height - 5}\" fill=\"#8B949E\" font-size=\"9\">{minTime:HH:mm:ss}</text>");
        sb.AppendLine($"  <text x=\"{width - margin - 40}\" y=\"{height - 5}\" fill=\"#8B949E\" font-size=\"9\">{maxTime:HH:mm:ss}</text>");

        // Plot points
        foreach (var time in times)
        {
            var x = margin + (chartWidth * (time - minTime).TotalSeconds / timeRange);
            var y = height - margin - 20;
            sb.AppendLine($"  <circle cx=\"{x:F1}\" cy=\"{y}\" r=\"4\" fill=\"{color}\" />");
        }

        // Activity bar
        var barY = height - margin - 40;
        var activityWidth = Math.Max(10, chartWidth * times.Count / 100);
        sb.AppendLine($"  <rect x=\"{margin}\" y=\"{barY}\" width=\"{activityWidth:F0}\" height=\"8\" fill=\"{color}\" opacity=\"0.5\" rx=\"2\" />");

        sb.AppendLine("</svg>");
        return sb.ToString();
    }
}

// Supporting ViewModels for DrillDown tabs

public class EvidencePacketViewModel
{
    public uint FrameNumber { get; set; }
    public DateTime Timestamp { get; set; }
    public string SourceIP { get; set; } = "";
    public string DestinationIP { get; set; } = "";
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public string Protocol { get; set; } = "";
    public int Length { get; set; }
    public string Info { get; set; } = "";

    // AXAML bindings - combined IP:Port format
    public string Source => $"{SourceIP}:{SourcePort}";
    public string Destination => $"{DestinationIP}:{DestinationPort}";
    public string TimestampFormatted => Timestamp.ToString("HH:mm:ss.fff");
    public string PortDisplay => $"{SourcePort} → {DestinationPort}";
}

public class RelatedThreatGroup
{
    public string GroupName { get; set; } = "";
    public string GroupIcon { get; set; } = "";
    public ObservableCollection<RelatedThreatItem> Threats { get; set; } = new();

    // AXAML bindings
    public string GroupType => GroupIcon;
    public string GroupValue => GroupName;
    public int ThreatCount => Threats.Count;
    public IEnumerable<string> ThreatNames => Threats.Select(t => $"• {t.ThreatName} ({t.Severity})");
}

public class RelatedThreatItem
{
    public string ThreatName { get; set; } = "";
    public string Severity { get; set; } = "";
    public string SeverityColor { get; set; } = "#6B7280";
    public int Port { get; set; }
}

public class IOCItem
{
    public string Type { get; set; } = "";
    public string Value { get; set; } = "";
    public string Context { get; set; } = "";
    public string Severity { get; set; } = "";
}

public class MitigationItem
{
    public string Priority { get; set; } = "";
    public string PriorityColor { get; set; } = "";
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
}

/// <summary>
/// Event args for navigating to Packet Analysis with threat context
/// </summary>
public class ViewInPacketAnalysisEventArgs : EventArgs
{
    public string ThreatId { get; set; } = "";
    public List<uint> FrameNumbers { get; set; } = new();
    public List<string> AffectedIPs { get; set; } = new();
    public int Port { get; set; }
}
