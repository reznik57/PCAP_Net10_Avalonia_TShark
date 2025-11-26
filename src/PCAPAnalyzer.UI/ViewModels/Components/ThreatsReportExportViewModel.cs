using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component ViewModel for exporting threat reports in CSV, JSON, and HTML formats.
/// Supports full investigation dossier generation for compliance and incident response.
/// </summary>
public partial class ThreatsReportExportViewModel : ObservableObject
{
    private readonly ThreatsChartsViewModel? _chartsViewModel;

    // Export state
    [ObservableProperty] private bool _isExporting;
    [ObservableProperty] private string _exportStatusMessage = "";
    [ObservableProperty] private string _exportStatusColor = "#10B981";
    [ObservableProperty] private double _exportProgress;
    [ObservableProperty] private bool _showExportStatus;

    // Data references (set by coordinator)
    private List<EnhancedSecurityThreat> _allThreats = new();
    private SecurityMetrics? _metrics;
    private string _sourceFileName = "";

    public ThreatsReportExportViewModel() : this(null)
    {
    }

    public ThreatsReportExportViewModel(ThreatsChartsViewModel? chartsViewModel)
    {
        _chartsViewModel = chartsViewModel;
    }

    /// <summary>
    /// Updates the data references for export
    /// </summary>
    public void SetExportData(
        List<EnhancedSecurityThreat> threats,
        SecurityMetrics? metrics,
        string sourceFileName)
    {
        _allThreats = threats;
        _metrics = metrics;
        _sourceFileName = sourceFileName;
    }

    [RelayCommand]
    private async Task ExportToCsv()
    {
        await ExportWithDialog("csv", "CSV Files|*.csv", ExportToCsvAsync);
    }

    [RelayCommand]
    private async Task ExportToJson()
    {
        await ExportWithDialog("json", "JSON Files|*.json", ExportToJsonAsync);
    }

    [RelayCommand]
    private async Task ExportToHtml()
    {
        await ExportWithDialog("html", "HTML Files|*.html", ExportToHtmlAsync);
    }

    [RelayCommand]
    private async Task ExportAll()
    {
        // Export all three formats to a directory
        if (Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var window = desktop.MainWindow;
            if (window == null) return;

            var folderOptions = new FolderPickerOpenOptions
            {
                Title = "Select Export Directory",
                AllowMultiple = false
            };

            var folders = await window.StorageProvider.OpenFolderPickerAsync(folderOptions);
            if (folders.Count == 0) return;

            var folder = folders[0];
            var baseName = Path.GetFileNameWithoutExtension(_sourceFileName);
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");

            IsExporting = true;
            ShowExportStatus = true;
            ExportStatusMessage = "Exporting reports...";
            ExportStatusColor = "#3B82F6";

            try
            {
                var basePath = folder.Path.LocalPath;

                // Export CSV
                ExportProgress = 0.1;
                ExportStatusMessage = "Exporting CSV...";
                await ExportToCsvAsync(Path.Combine(basePath, $"{baseName}_threats_{timestamp}.csv"));

                // Export JSON
                ExportProgress = 0.4;
                ExportStatusMessage = "Exporting JSON...";
                await ExportToJsonAsync(Path.Combine(basePath, $"{baseName}_threats_{timestamp}.json"));

                // Export HTML
                ExportProgress = 0.7;
                ExportStatusMessage = "Generating HTML report...";
                await ExportToHtmlAsync(Path.Combine(basePath, $"{baseName}_report_{timestamp}.html"));

                ExportProgress = 1.0;
                ExportStatusMessage = $"✓ Exported 3 files to {basePath}";
                ExportStatusColor = "#10B981";

                DebugLogger.Log($"[ThreatsExport] Exported all formats to {basePath}");
            }
            catch (Exception ex)
            {
                ExportStatusMessage = $"✗ Export failed: {ex.Message}";
                ExportStatusColor = "#EF4444";
                DebugLogger.Log($"[ThreatsExport] Export all failed: {ex.Message}");
            }
            finally
            {
                IsExporting = false;
                _ = AutoClearStatusAsync();
            }
        }
    }

    private async Task ExportWithDialog(string extension, string filter, Func<string, Task> exportFunc)
    {
        if (Avalonia.Application.Current?.ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var window = desktop.MainWindow;
            if (window == null) return;

            var saveOptions = new FilePickerSaveOptions
            {
                Title = $"Export Security Threats ({extension.ToUpper()})",
                DefaultExtension = extension,
                SuggestedFileName = $"threats_report_{DateTime.Now:yyyyMMdd_HHmmss}",
                FileTypeChoices = new List<FilePickerFileType>
                {
                    new(filter.Split('|')[0]) { Patterns = new[] { $"*.{extension}" } }
                }
            };

            var result = await window.StorageProvider.SaveFilePickerAsync(saveOptions);
            if (result == null) return;

            IsExporting = true;
            ShowExportStatus = true;
            ExportStatusMessage = $"Exporting {extension.ToUpper()}...";
            ExportStatusColor = "#3B82F6";

            try
            {
                await exportFunc(result.Path.LocalPath);
                ExportStatusMessage = $"✓ Exported to {Path.GetFileName(result.Path.LocalPath)}";
                ExportStatusColor = "#10B981";
            }
            catch (Exception ex)
            {
                ExportStatusMessage = $"✗ Export failed: {ex.Message}";
                ExportStatusColor = "#EF4444";
            }
            finally
            {
                IsExporting = false;
                _ = AutoClearStatusAsync();
            }
        }
    }

    private async Task AutoClearStatusAsync()
    {
        await Task.Delay(5000);
        ShowExportStatus = false;
    }

    private async Task ExportToCsvAsync(string filePath)
    {
        var csv = new StringBuilder();
        csv.AppendLine("Threat Name,Category,Severity,Service,Port,Protocol,Risk Score,Occurrences,First Seen,Last Seen,Affected IPs,CVE,Description");

        foreach (var threat in _allThreats.OrderByDescending(t => t.Severity).ThenByDescending(t => t.RiskScore))
        {
            var affectedIPs = string.Join(";", threat.AffectedIPs?.Take(10) ?? Array.Empty<string>());
            var description = EscapeCsv(threat.Description);
            var threatName = EscapeCsv(threat.ThreatName);

            csv.AppendLine($"\"{threatName}\",\"{threat.Category}\",\"{threat.Severity}\",\"{threat.Service}\",{threat.Port},\"{threat.Protocol}\",{threat.RiskScore:F1},{threat.OccurrenceCount},\"{threat.FirstSeen:yyyy-MM-dd HH:mm:ss}\",\"{threat.LastSeen:yyyy-MM-dd HH:mm:ss}\",\"{affectedIPs}\",\"{threat.CVE}\",\"{description}\"");
        }

        await File.WriteAllTextAsync(filePath, csv.ToString(), Encoding.UTF8);
    }

    private async Task ExportToJsonAsync(string filePath)
    {
        var exportData = new
        {
            ReportMetadata = new
            {
                GeneratedAt = DateTime.Now,
                SourceFile = _sourceFileName,
                TotalThreats = _allThreats.Count,
                RiskScore = _metrics?.OverallRiskScore ?? 0
            },
            Summary = new
            {
                Critical = _metrics?.CriticalThreats ?? 0,
                High = _metrics?.HighThreats ?? 0,
                Medium = _metrics?.MediumThreats ?? 0,
                Low = _metrics?.LowThreats ?? 0,
                ByCategory = _metrics?.ThreatsByCategory ?? new Dictionary<string, int>(),
                ByPort = _metrics?.ThreatsByPort ?? new Dictionary<int, int>()
            },
            Threats = _allThreats.Select(t => new
            {
                t.Id,
                t.ThreatName,
                Category = t.Category.ToString(),
                Severity = t.Severity.ToString(),
                t.Service,
                t.Port,
                t.Protocol,
                t.RiskScore,
                t.OccurrenceCount,
                t.FirstSeen,
                t.LastSeen,
                t.Description,
                t.CVE,
                t.Vulnerabilities,
                t.Mitigations,
                t.AffectedIPs,
                FrameCount = t.FrameNumbers?.Count ?? 0,
                ConnectionCount = t.AffectedConnections?.Count ?? 0
            }).OrderByDescending(t => t.Severity).ThenByDescending(t => t.RiskScore)
        };

        var json = JsonSerializer.Serialize(exportData, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });

        await File.WriteAllTextAsync(filePath, json, Encoding.UTF8);
    }

    private async Task ExportToHtmlAsync(string filePath)
    {
        var html = GenerateHtmlReport();
        await File.WriteAllTextAsync(filePath, html, Encoding.UTF8);
    }

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "HTML report generation inherently requires multiple conditional sections for executive summary, charts, threat tables, IOCs, and recommendations - this is a template method that assembles report sections")]
    private string GenerateHtmlReport()
    {
        var criticalCount = _metrics?.CriticalThreats ?? 0;
        var highCount = _metrics?.HighThreats ?? 0;
        var mediumCount = _metrics?.MediumThreats ?? 0;
        var lowCount = _metrics?.LowThreats ?? 0;
        var riskScore = _metrics?.OverallRiskScore ?? 0;

        var riskLevel = riskScore >= 8 ? "CRITICAL" : riskScore >= 6 ? "HIGH" : riskScore >= 4 ? "MEDIUM" : riskScore >= 2 ? "LOW" : "MINIMAL";
        var riskColor = riskScore >= 8 ? "#EF4444" : riskScore >= 6 ? "#F97316" : riskScore >= 4 ? "#F59E0B" : riskScore >= 2 ? "#3B82F6" : "#10B981";

        // Generate SVG charts
        var severityChartSvg = _chartsViewModel?.GenerateSeverityChartSvg(criticalCount, highCount, mediumCount, lowCount) ?? "";
        var timelineChartSvg = _chartsViewModel?.GenerateTimelineChartSvg(_allThreats) ?? "";

        var html = new StringBuilder();
        html.AppendLine("<!DOCTYPE html>");
        html.AppendLine("<html lang=\"en\">");
        html.AppendLine("<head>");
        html.AppendLine("  <meta charset=\"UTF-8\">");
        html.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
        html.AppendLine($"  <title>Security Threat Analysis Report - {DateTime.Now:yyyy-MM-dd}</title>");
        html.AppendLine("  <style>");
        html.AppendLine(GetEmbeddedCss());
        html.AppendLine("  </style>");
        html.AppendLine("</head>");
        html.AppendLine("<body>");

        // Header
        html.AppendLine("  <header class=\"report-header\">");
        html.AppendLine("    <h1>Security Threat Analysis Report</h1>");
        html.AppendLine($"    <div class=\"meta\">Source: {EscapeHtml(_sourceFileName)} | Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}</div>");
        html.AppendLine("  </header>");

        // Executive Summary
        html.AppendLine("  <section id=\"executive-summary\">");
        html.AppendLine("    <h2>Executive Summary</h2>");
        html.AppendLine("    <div class=\"summary-grid\">");
        html.AppendLine($"      <div class=\"risk-badge\" style=\"background-color: {riskColor};\">");
        html.AppendLine($"        <span class=\"risk-level\">{riskLevel}</span>");
        html.AppendLine($"        <span class=\"risk-score\">Risk Score: {riskScore:F1}/10</span>");
        html.AppendLine("      </div>");
        html.AppendLine("      <div class=\"severity-counts\">");
        html.AppendLine($"        <div class=\"severity critical\">Critical: <strong>{criticalCount}</strong></div>");
        html.AppendLine($"        <div class=\"severity high\">High: <strong>{highCount}</strong></div>");
        html.AppendLine($"        <div class=\"severity medium\">Medium: <strong>{mediumCount}</strong></div>");
        html.AppendLine($"        <div class=\"severity low\">Low: <strong>{lowCount}</strong></div>");
        html.AppendLine("      </div>");
        html.AppendLine("    </div>");

        // Charts
        if (!string.IsNullOrEmpty(severityChartSvg))
        {
            html.AppendLine("    <div class=\"chart-container\">");
            html.AppendLine("      <h3>Threat Distribution by Severity</h3>");
            html.AppendLine($"      {severityChartSvg}");
            html.AppendLine("    </div>");
        }
        html.AppendLine("  </section>");

        // Timeline
        html.AppendLine("  <section id=\"timeline\">");
        html.AppendLine("    <h2>Threat Activity Timeline</h2>");
        if (!string.IsNullOrEmpty(timelineChartSvg))
        {
            html.AppendLine($"    {timelineChartSvg}");
        }
        if (_allThreats.Any())
        {
            var minTime = _allThreats.Min(t => t.FirstSeen);
            var maxTime = _allThreats.Max(t => t.LastSeen);
            html.AppendLine($"    <p class=\"timeline-range\">Activity period: {minTime:HH:mm:ss} - {maxTime:HH:mm:ss}</p>");
        }
        html.AppendLine("  </section>");

        // Threat Details Table
        html.AppendLine("  <section id=\"threats\">");
        html.AppendLine("    <h2>Identified Threats</h2>");
        html.AppendLine("    <table class=\"threats-table\">");
        html.AppendLine("      <thead>");
        html.AppendLine("        <tr><th>Severity</th><th>Threat</th><th>Category</th><th>Port</th><th>Count</th><th>Risk</th></tr>");
        html.AppendLine("      </thead>");
        html.AppendLine("      <tbody>");

        foreach (var threat in _allThreats.OrderByDescending(t => t.Severity).ThenByDescending(t => t.RiskScore).Take(50))
        {
            var severityColor = GetSeverityColor(threat.Severity);
            html.AppendLine($"        <tr>");
            html.AppendLine($"          <td><span class=\"severity-badge\" style=\"background:{severityColor}\">{threat.Severity}</span></td>");
            html.AppendLine($"          <td><strong>{EscapeHtml(threat.ThreatName)}</strong><br/><small>{EscapeHtml(threat.Service)}</small></td>");
            html.AppendLine($"          <td>{threat.Category}</td>");
            html.AppendLine($"          <td>{threat.Port}/{threat.Protocol}</td>");
            html.AppendLine($"          <td>{threat.OccurrenceCount}</td>");
            html.AppendLine($"          <td>{threat.RiskScore:F1}</td>");
            html.AppendLine($"        </tr>");
        }

        html.AppendLine("      </tbody>");
        html.AppendLine("    </table>");
        if (_allThreats.Count > 50)
        {
            html.AppendLine($"    <p class=\"note\">Showing top 50 of {_allThreats.Count} threats. See CSV export for full list.</p>");
        }
        html.AppendLine("  </section>");

        // Affected Infrastructure
        html.AppendLine("  <section id=\"infrastructure\">");
        html.AppendLine("    <h2>Affected Infrastructure</h2>");

        var allIPs = _allThreats.SelectMany(t => t.AffectedIPs ?? new List<string>()).Distinct().Take(30).ToList();
        if (allIPs.Any())
        {
            html.AppendLine("    <h3>IP Addresses</h3>");
            html.AppendLine("    <ul class=\"ip-list\">");
            foreach (var ip in allIPs)
            {
                var threatCount = _allThreats.Count(t => t.AffectedIPs?.Contains(ip) ?? false);
                html.AppendLine($"      <li>{ip} <span class=\"count\">({threatCount} threats)</span></li>");
            }
            html.AppendLine("    </ul>");
        }

        var portStats = _metrics?.ThreatsByPort.OrderByDescending(p => p.Value).Take(10);
        if (portStats?.Any() == true)
        {
            html.AppendLine("    <h3>Ports &amp; Services</h3>");
            html.AppendLine("    <ul class=\"port-list\">");
            foreach (var port in portStats)
            {
                html.AppendLine($"      <li>Port {port.Key} <span class=\"count\">({port.Value} threats)</span></li>");
            }
            html.AppendLine("    </ul>");
        }
        html.AppendLine("  </section>");

        // IOCs
        html.AppendLine("  <section id=\"iocs\">");
        html.AppendLine("    <h2>Indicators of Compromise (IOCs)</h2>");
        html.AppendLine("    <h3>Network IOCs</h3>");
        html.AppendLine("    <pre class=\"ioc-list\">");

        foreach (var threat in _allThreats.Where(t => t.Severity >= ThreatSeverity.High).Take(20))
        {
            foreach (var ip in threat.AffectedIPs?.Take(3) ?? Array.Empty<string>())
            {
                html.AppendLine($"{ip}|{threat.Port}/{threat.Protocol}|{threat.Severity}|{threat.ThreatName}");
            }
        }

        html.AppendLine("    </pre>");
        html.AppendLine("  </section>");

        // Recommendations
        html.AppendLine("  <section id=\"recommendations\">");
        html.AppendLine("    <h2>Recommended Actions</h2>");

        if (criticalCount > 0)
        {
            html.AppendLine("    <div class=\"priority-section critical\">");
            html.AppendLine("      <h3>🔴 Immediate Action Required</h3>");
            html.AppendLine("      <ul>");
            foreach (var threat in _allThreats.Where(t => t.Severity == ThreatSeverity.Critical).Take(5))
            {
                foreach (var mitigation in threat.Mitigations?.Take(2) ?? Array.Empty<string>())
                {
                    html.AppendLine($"        <li>{EscapeHtml(mitigation)}</li>");
                }
            }
            html.AppendLine("      </ul>");
            html.AppendLine("    </div>");
        }

        if (highCount > 0)
        {
            html.AppendLine("    <div class=\"priority-section high\">");
            html.AppendLine("      <h3>🟠 High Priority</h3>");
            html.AppendLine("      <ul>");
            foreach (var threat in _allThreats.Where(t => t.Severity == ThreatSeverity.High).Take(5))
            {
                foreach (var mitigation in threat.Mitigations?.Take(1) ?? Array.Empty<string>())
                {
                    html.AppendLine($"        <li>{EscapeHtml(mitigation)}</li>");
                }
            }
            html.AppendLine("      </ul>");
            html.AppendLine("    </div>");
        }

        html.AppendLine("  </section>");

        // Footer
        html.AppendLine("  <footer>");
        html.AppendLine($"    <p>Generated by PCAP Analyzer | {DateTime.Now:yyyy-MM-dd HH:mm:ss}</p>");
        html.AppendLine("  </footer>");

        html.AppendLine("</body>");
        html.AppendLine("</html>");

        return html.ToString();
    }

    private static string GetEmbeddedCss() => @"
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0D1117; color: #C9D1D9; line-height: 1.6; padding: 20px; }
        .report-header { text-align: center; padding: 30px 0; border-bottom: 1px solid #30363D; margin-bottom: 30px; }
        .report-header h1 { color: #F0F6FC; font-size: 28px; }
        .report-header .meta { color: #8B949E; margin-top: 10px; }
        section { background: #161B22; border-radius: 8px; padding: 24px; margin-bottom: 24px; }
        h2 { color: #F0F6FC; font-size: 20px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #30363D; }
        h3 { color: #C9D1D9; font-size: 16px; margin: 16px 0 8px; }
        .summary-grid { display: flex; gap: 24px; flex-wrap: wrap; }
        .risk-badge { padding: 20px 30px; border-radius: 8px; text-align: center; color: white; }
        .risk-level { display: block; font-size: 24px; font-weight: bold; }
        .risk-score { display: block; font-size: 14px; opacity: 0.9; }
        .severity-counts { display: flex; gap: 16px; flex-wrap: wrap; }
        .severity { padding: 12px 20px; border-radius: 6px; background: #21262D; }
        .severity.critical { border-left: 4px solid #EF4444; }
        .severity.high { border-left: 4px solid #F97316; }
        .severity.medium { border-left: 4px solid #F59E0B; }
        .severity.low { border-left: 4px solid #3B82F6; }
        .chart-container { margin-top: 24px; text-align: center; }
        .timeline-range { color: #8B949E; font-size: 14px; margin-top: 8px; }
        .threats-table { width: 100%; border-collapse: collapse; }
        .threats-table th, .threats-table td { padding: 12px; text-align: left; border-bottom: 1px solid #30363D; }
        .threats-table th { background: #21262D; color: #F0F6FC; font-weight: 600; }
        .threats-table tr:hover { background: #1C2128; }
        .severity-badge { padding: 4px 8px; border-radius: 4px; color: white; font-size: 11px; font-weight: bold; }
        .ip-list, .port-list { list-style: none; display: flex; flex-wrap: wrap; gap: 8px; }
        .ip-list li, .port-list li { background: #21262D; padding: 6px 12px; border-radius: 4px; font-family: monospace; }
        .count { color: #8B949E; font-size: 12px; }
        .ioc-list { background: #21262D; padding: 16px; border-radius: 6px; font-family: monospace; font-size: 12px; overflow-x: auto; white-space: pre; }
        .priority-section { margin: 16px 0; padding: 16px; border-radius: 6px; }
        .priority-section.critical { background: rgba(239, 68, 68, 0.1); border-left: 4px solid #EF4444; }
        .priority-section.high { background: rgba(249, 115, 22, 0.1); border-left: 4px solid #F97316; }
        .priority-section ul { margin-left: 24px; }
        .priority-section li { margin: 8px 0; }
        .note { color: #8B949E; font-size: 13px; font-style: italic; margin-top: 12px; }
        footer { text-align: center; color: #6B7280; font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid #30363D; }
        @media print { body { background: white; color: black; } section { border: 1px solid #ddd; } }
    ";

    private static string GetSeverityColor(ThreatSeverity severity) => severity switch
    {
        ThreatSeverity.Critical => "#EF4444",
        ThreatSeverity.High => "#F97316",
        ThreatSeverity.Medium => "#F59E0B",
        ThreatSeverity.Low => "#3B82F6",
        _ => "#6B7280"
    };

    private static string EscapeCsv(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value
            .Replace("\"", "\"\"", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal)
            .Replace("\r", "", StringComparison.Ordinal);
    }

    private static string EscapeHtml(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        return value
            .Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal)
            .Replace("\"", "&quot;", StringComparison.Ordinal);
    }
}
