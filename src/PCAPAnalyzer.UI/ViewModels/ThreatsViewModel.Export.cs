using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Export functionality for ThreatsViewModel.
/// Contains CSV export methods for tables and report export delegation.
/// </summary>
public partial class ThreatsViewModel
{
    /// <summary>
    /// Exports Top Affected Ports (by Count) to CSV file.
    /// </summary>
    [RelayCommand]
    private async Task ExportPortsByCount()
    {
        await ExportTableToCsvAsync("threats_ports_by_count.csv",
            new[] { "Rank", "Port", "Protocol", "Service", "Percentage", "ThreatCount" },
            Statistics.TopAffectedPortsByCount.Select(p => new[] { p.Rank.ToString(), p.Port.ToString(), p.Protocol, p.ServiceName, $"{p.Percentage:F1}%", p.ThreatCount.ToString() }));
    }

    /// <summary>
    /// Exports Top Affected Ports (by Severity) to CSV file.
    /// </summary>
    [RelayCommand]
    private async Task ExportPortsBySeverity()
    {
        await ExportTableToCsvAsync("threats_ports_by_severity.csv",
            new[] { "Rank", "Port", "Protocol", "Service", "Percentage", "SeverityScore" },
            Statistics.TopAffectedPortsBySeverity.Select(p => new[] { p.Rank.ToString(), p.Port.ToString(), p.Protocol, p.ServiceName, $"{p.Percentage:F1}%", $"{p.SeverityScore:F1}" }));
    }

    /// <summary>
    /// Exports Top Source IPs to CSV file.
    /// </summary>
    [RelayCommand]
    private async Task ExportSourceIPs()
    {
        await ExportTableToCsvAsync("threats_source_ips.csv",
            new[] { "Rank", "Address", "Country", "Percentage", "ThreatCount" },
            Statistics.TopSourceIPs.Select(ip => new[] { ip.Rank.ToString(), ip.Address, ip.Country, $"{ip.Percentage:F1}%", ip.ThreatCount.ToString() }));
    }

    /// <summary>
    /// Exports Top Destination IPs to CSV file.
    /// </summary>
    [RelayCommand]
    private async Task ExportDestinationIPs()
    {
        await ExportTableToCsvAsync("threats_dest_ips.csv",
            new[] { "Rank", "Address", "Country", "Percentage", "ThreatCount" },
            Statistics.TopDestinationIPs.Select(ip => new[] { ip.Rank.ToString(), ip.Address, ip.Country, $"{ip.Percentage:F1}%", ip.ThreatCount.ToString() }));
    }

    /// <summary>
    /// Generic CSV export helper for table data.
    /// </summary>
    private async Task ExportTableToCsvAsync(string filename, string[] headers, IEnumerable<string[]> rows)
    {
        try
        {
            var saveFileDialog = new Avalonia.Platform.Storage.FilePickerSaveOptions
            {
                Title = "Export Table to CSV",
                SuggestedFileName = filename,
                FileTypeChoices = new[]
                {
                    new Avalonia.Platform.Storage.FilePickerFileType("CSV Files") { Patterns = new[] { "*.csv" } }
                }
            };

            var topLevel = Avalonia.Application.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                ? desktop.MainWindow
                : null;

            if (topLevel == null)
            {
                DebugLogger.Log("[ThreatsViewModel] Export failed - no main window found");
                return;
            }

            var storageProvider = topLevel.StorageProvider;
            var file = await storageProvider.SaveFilePickerAsync(saveFileDialog);

            if (file == null) return;

            await using var stream = await file.OpenWriteAsync();
            await using var writer = new System.IO.StreamWriter(stream);

            // Write header
            await writer.WriteLineAsync(string.Join(",", headers));

            // Write rows
            foreach (var row in rows)
            {
                var escapedRow = row.Select(v => v?.Contains(',', StringComparison.Ordinal) == true ? $"\"{v}\"" : v);
                await writer.WriteLineAsync(string.Join(",", escapedRow));
            }

            DebugLogger.Log($"[ThreatsViewModel] Exported {filename} successfully");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[ThreatsViewModel] Export error: {ex.Message}");
        }
    }

    /// <summary>
    /// Opens export dialog - delegates to ThreatsReportExportViewModel.
    /// Supports CSV, JSON, and full HTML Investigation Dossier.
    /// </summary>
    [RelayCommand]
    private async Task ExportThreats()
    {
        // Delegate to ReportExport component (Dashboard composition pattern)
        if (ReportExport.ExportAllCommand.CanExecute(null))
        {
            await ReportExport.ExportAllCommand.ExecuteAsync(null);
        }
        DebugLogger.Log("[ThreatsViewModel] Export completed via ReportExport component");
    }
}
