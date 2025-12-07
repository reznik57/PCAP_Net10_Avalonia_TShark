using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Base ViewModel with CSV export capabilities
/// Provides reusable export functionality for all ViewModels with tabular data
/// </summary>
public abstract partial class ExportableViewModelBase : ObservableObject
{
    private readonly ICsvExportService? _csvExportService;
    private readonly IFileDialogService? _fileDialogService;

    [ObservableProperty] private bool _isExporting;
    [ObservableProperty] private string? _lastExportPath;
    [ObservableProperty] private string? _exportStatusMessage;

    protected ExportableViewModelBase(
        ICsvExportService? csvExportService = null,
        IFileDialogService? fileDialogService = null)
    {
        _csvExportService = csvExportService;
        _fileDialogService = fileDialogService;
    }

    /// <summary>
    /// Export data to CSV with file dialog
    /// </summary>
    [RelayCommand]
    protected async Task ExportToCsvAsync(string dataType)
    {
        if (_csvExportService is null || _fileDialogService is null)
        {
            ExportStatusMessage = "Export service not available";
            return;
        }

        try
        {
            IsExporting = true;
            ExportStatusMessage = "Preparing export...";

            // Get data to export
            var data = GetExportData(dataType);
            if (data is null || !data.Any())
            {
                ExportStatusMessage = "No data to export";
                return;
            }

            // Show save file dialog
            var suggestedFileName = _csvExportService.GetSuggestedFileName(dataType);
            var filePath = await _fileDialogService.SaveFileAsync(
                "Export to CSV",
                suggestedFileName,
                new FileDialogFilter("CSV Files", "*.csv"),
                new FileDialogFilter("All Files", "*.*"));

            if (string.IsNullOrWhiteSpace(filePath))
            {
                ExportStatusMessage = "Export cancelled";
                return;
            }

            // Validate path
            if (!await _csvExportService.ValidateAndPreparePathAsync(filePath))
            {
                ExportStatusMessage = "Cannot write to selected location";
                return;
            }

            ExportStatusMessage = $"Exporting {data.Count()} rows...";

            // Export based on data type
            await ExportDataAsync(dataType, data, filePath);

            LastExportPath = filePath;
            ExportStatusMessage = $"Exported {data.Count()} rows to {System.IO.Path.GetFileName(filePath)}";
        }
        catch (Exception ex)
        {
            ExportStatusMessage = $"Export failed: {ex.Message}";
        }
        finally
        {
            IsExporting = false;
        }
    }

    /// <summary>
    /// Quick export to last used path or default location
    /// </summary>
    [RelayCommand]
    protected async Task QuickExportAsync(string dataType)
    {
        if (_csvExportService is null)
        {
            ExportStatusMessage = "Export service not available";
            return;
        }

        try
        {
            IsExporting = true;
            ExportStatusMessage = "Preparing quick export...";

            var data = GetExportData(dataType);
            if (data is null || !data.Any())
            {
                ExportStatusMessage = "No data to export";
                return;
            }

            // Use last path or default to user's documents folder
            var filePath = LastExportPath ?? System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                _csvExportService.GetSuggestedFileName(dataType));

            await ExportDataAsync(dataType, data, filePath);

            LastExportPath = filePath;
            ExportStatusMessage = $"Quick export: {data.Count()} rows to {System.IO.Path.GetFileName(filePath)}";
        }
        catch (Exception ex)
        {
            ExportStatusMessage = $"Quick export failed: {ex.Message}";
        }
        finally
        {
            IsExporting = false;
        }
    }

    /// <summary>
    /// Override this method to provide data for export
    /// </summary>
    /// <param name="dataType">Type of data to export</param>
    /// <returns>Enumerable collection of data items</returns>
    protected abstract IEnumerable<dynamic>? GetExportData(string dataType);

    /// <summary>
    /// Perform the actual export operation
    /// </summary>
    private async Task ExportDataAsync(string dataType, IEnumerable<dynamic> data, string filePath)
    {
        if (_csvExportService is null)
            return;

        switch (dataType.ToLowerInvariant())
        {
            case "protocols":
            case "protocol-distribution":
                await _csvExportService.ExportProtocolDistributionAsync(data, filePath);
                break;

            case "toptalkers":
            case "top-talkers":
                await _csvExportService.ExportTopTalkersAsync(data, filePath);
                break;

            case "ports":
            case "port-analysis":
                await _csvExportService.ExportPortAnalysisAsync(data, filePath);
                break;

            case "countries":
            case "country-traffic":
                await _csvExportService.ExportCountryTrafficAsync(data, filePath);
                break;

            case "threats":
                await _csvExportService.ExportThreatsAsync(data, filePath);
                break;

            case "anomalies":
                await _csvExportService.ExportAnomaliesAsync(data, filePath);
                break;

            case "packets":
                await _csvExportService.ExportPacketsAsync(data, filePath);
                break;

            default:
                // Generic export with auto-detected columns
                var columnMappings = BuildColumnMappings(data.First());
                await _csvExportService.ExportToCsvAsync(data, filePath, columnMappings);
                break;
        }
    }

    /// <summary>
    /// Build column mappings from dynamic object properties
    /// </summary>
    private Dictionary<string, Func<dynamic, object?>> BuildColumnMappings(object sampleItem)
    {
        var mappings = new Dictionary<string, Func<dynamic, object?>>();
        var type = sampleItem.GetType();
        var properties = type.GetProperties();

        foreach (var prop in properties)
        {
            var propInfo = prop; // Capture for lambda
            mappings[propInfo.Name] = (dynamic item) =>
            {
                try
                {
                    return propInfo.GetValue(item);
                }
                catch
                {
                    return null;
                }
            };
        }

        return mappings;
    }

    /// <summary>
    /// Clear export status message after delay
    /// </summary>
    protected async Task ClearExportStatusAsync(int delayMs = 5000)
    {
        await Task.Delay(delayMs);
        ExportStatusMessage = null;
    }
}
