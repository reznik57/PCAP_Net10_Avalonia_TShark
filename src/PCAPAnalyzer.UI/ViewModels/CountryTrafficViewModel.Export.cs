using System;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Export functionality for CountryTrafficViewModel.
/// Contains CSV, JSON, and Markdown export methods.
/// </summary>
public partial class CountryTrafficViewModel
{
    /// <summary>
    /// Exports country traffic summary to file (CSV, JSON, or Markdown)
    /// </summary>
    [RelayCommand]
    private async Task ExportSummary()
    {
        try
        {
            if (_currentStatistics?.CountryStatistics == null || _currentStatistics.CountryStatistics.Count == 0)
            {
                DebugLogger.Log("[CountryTrafficViewModel] Export: No country data to export");
                return;
            }

            // Get the main window for dialog
            if (Avalonia.Application.Current?.ApplicationLifetime is not
                Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop ||
                desktop.MainWindow == null)
            {
                return;
            }

            var topLevel = desktop.MainWindow;
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");

            // Show save file dialog
            var saveDialog = new Avalonia.Platform.Storage.FilePickerSaveOptions
            {
                Title = "Export Country Traffic Summary",
                SuggestedFileName = $"CountryTraffic_{timestamp}",
                FileTypeChoices = new[]
                {
                    new Avalonia.Platform.Storage.FilePickerFileType("CSV Files") { Patterns = new[] { "*.csv" } },
                    new Avalonia.Platform.Storage.FilePickerFileType("JSON Files") { Patterns = new[] { "*.json" } },
                    new Avalonia.Platform.Storage.FilePickerFileType("Markdown Report") { Patterns = new[] { "*.md" } }
                }
            };

            var file = await topLevel.StorageProvider.SaveFilePickerAsync(saveDialog);
            if (file == null)
                return;

            var filePath = file.Path.LocalPath;
            var extension = System.IO.Path.GetExtension(filePath).ToLowerInvariant();

            // Export based on file type
            switch (extension)
            {
                case ".csv":
                    await ExportToCsvAsync(filePath);
                    break;
                case ".json":
                    await ExportToJsonAsync(filePath);
                    break;
                case ".md":
                    await ExportToMarkdownAsync(filePath);
                    break;
                default:
                    await ExportToCsvAsync(filePath);
                    break;
            }

            DebugLogger.Log($"[CountryTrafficViewModel] Exported country summary to {filePath}");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[CountryTrafficViewModel] Export failed: {ex.Message}");
        }
    }

    private async Task ExportToCsvAsync(string filePath)
    {
        var sb = new System.Text.StringBuilder();

        // Header
        sb.AppendLine("Type,Rank,Country Code,Country Name,Continent,Packets,Bytes,Packet %,Byte %,High Risk");

        // Source countries by packets
        foreach (var country in Tables.TopSourceCountriesByPackets.Take(50))
        {
            sb.AppendLine($"Source,{country.Rank},{country.CountryCode},\"{country.CountryName}\",{country.Continent},{country.TotalPackets},{country.TotalBytes},{country.PacketPercentage:F2},{country.BytePercentage:F2},{country.IsHighRisk}");
        }

        // Destination countries by packets
        foreach (var country in Tables.TopDestinationCountriesByPackets.Take(50))
        {
            sb.AppendLine($"Destination,{country.Rank},{country.CountryCode},\"{country.CountryName}\",{country.Continent},{country.TotalPackets},{country.TotalBytes},{country.PacketPercentage:F2},{country.BytePercentage:F2},{country.IsHighRisk}");
        }

        // Active flows
        sb.AppendLine();
        sb.AppendLine("Flow Type,Rank,Source,Destination,Protocol,Packets,Bytes,Packet %,Byte %,Bidirectional");
        foreach (var flow in Tables.ActiveFlowsByPackets.Take(50))
        {
            sb.AppendLine($"Flow,{flow.Rank},{flow.SourceCountryCode},{flow.DestinationCountryCode},{flow.Protocol},{flow.PacketCount},{flow.ByteCount},{flow.FlowIntensity:F2},{flow.ByteIntensity:F2},{flow.IsBidirectional}");
        }

        await System.IO.File.WriteAllTextAsync(filePath, sb.ToString());
    }

    private async Task ExportToJsonAsync(string filePath)
    {
        var exportData = new
        {
            ExportedAt = DateTime.UtcNow.ToString("O"),
            Summary = new
            {
                UniqueCountries = Statistics.UniqueCountries,
                TotalPackets = Statistics.TotalPackets,
                TotalBytes = Statistics.TotalBytes,
                ActiveFlows = Tables.ActiveFlowCount
            },
            SourceCountries = Tables.TopSourceCountriesByPackets.Take(50).Select(c => new
            {
                c.Rank,
                c.CountryCode,
                c.CountryName,
                c.Continent,
                c.TotalPackets,
                c.TotalBytes,
                PacketPercentage = Math.Round(c.PacketPercentage, 2),
                BytePercentage = Math.Round(c.BytePercentage, 2),
                c.IsHighRisk
            }),
            DestinationCountries = Tables.TopDestinationCountriesByPackets.Take(50).Select(c => new
            {
                c.Rank,
                c.CountryCode,
                c.CountryName,
                c.Continent,
                c.TotalPackets,
                c.TotalBytes,
                PacketPercentage = Math.Round(c.PacketPercentage, 2),
                BytePercentage = Math.Round(c.BytePercentage, 2),
                c.IsHighRisk
            }),
            Flows = Tables.ActiveFlowsByPackets.Take(50).Select(f => new
            {
                f.Rank,
                f.SourceCountryCode,
                f.DestinationCountryCode,
                f.Protocol,
                f.PacketCount,
                f.ByteCount,
                FlowIntensity = Math.Round(f.FlowIntensity, 2),
                ByteIntensity = Math.Round(f.ByteIntensity, 2),
                f.IsBidirectional
            })
        };

        var json = System.Text.Json.JsonSerializer.Serialize(exportData, new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true
        });

        await System.IO.File.WriteAllTextAsync(filePath, json);
    }

    private async Task ExportToMarkdownAsync(string filePath)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("# Country Traffic Summary Report");
        sb.AppendLine();
        sb.AppendLine($"**Generated:** {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();

        // Summary section
        sb.AppendLine("## Overview");
        sb.AppendLine();
        sb.AppendLine($"| Metric | Value |");
        sb.AppendLine($"|--------|-------|");
        sb.AppendLine($"| Unique Countries | {Statistics.UniqueCountries:N0} |");
        sb.AppendLine($"| Total Packets | {Statistics.TotalPackets:N0} |");
        sb.AppendLine($"| Total Bytes | {NumberFormatter.FormatBytes(Statistics.TotalBytes)} |");
        sb.AppendLine($"| Active Flows | {Tables.ActiveFlowCount:N0} |");
        sb.AppendLine();

        // Top Source Countries
        sb.AppendLine("## Top 10 Source Countries (by Packets)");
        sb.AppendLine();
        sb.AppendLine("| Rank | Country | Code | Packets | % | High Risk |");
        sb.AppendLine("|------|---------|------|---------|---|-----------|");
        foreach (var country in Tables.TopSourceCountriesByPackets.Take(10))
        {
            var risk = country.IsHighRisk ? "⚠️ Yes" : "No";
            sb.AppendLine($"| {country.Rank} | {country.CountryName} | {country.CountryCode} | {country.TotalPackets:N0} | {country.PacketPercentage:F1}% | {risk} |");
        }
        sb.AppendLine();

        // Top Destination Countries
        sb.AppendLine("## Top 10 Destination Countries (by Packets)");
        sb.AppendLine();
        sb.AppendLine("| Rank | Country | Code | Packets | % | High Risk |");
        sb.AppendLine("|------|---------|------|---------|---|-----------|");
        foreach (var country in Tables.TopDestinationCountriesByPackets.Take(10))
        {
            var risk = country.IsHighRisk ? "⚠️ Yes" : "No";
            sb.AppendLine($"| {country.Rank} | {country.CountryName} | {country.CountryCode} | {country.TotalPackets:N0} | {country.PacketPercentage:F1}% | {risk} |");
        }
        sb.AppendLine();

        // Top Flows
        sb.AppendLine("## Top 10 Traffic Flows");
        sb.AppendLine();
        sb.AppendLine("| Rank | Flow | Protocol | Packets | % | Direction |");
        sb.AppendLine("|------|------|----------|---------|---|-----------|");
        foreach (var flow in Tables.ActiveFlowsByPackets.Take(10))
        {
            var direction = flow.IsBidirectional ? "↔ Bidirectional" : "→ Unidirectional";
            sb.AppendLine($"| {flow.Rank} | {flow.SourceCountryCode} → {flow.DestinationCountryCode} | {flow.Protocol} | {flow.PacketCount:N0} | {flow.FlowIntensity:F1}% | {direction} |");
        }
        sb.AppendLine();

        sb.AppendLine("---");
        sb.AppendLine("*Report generated by PCAP Analyzer*");

        await System.IO.File.WriteAllTextAsync(filePath, sb.ToString());
    }
}
