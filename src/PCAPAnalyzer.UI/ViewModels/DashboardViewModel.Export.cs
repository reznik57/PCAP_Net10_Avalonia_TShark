using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.ViewModels.Components;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// DashboardViewModel partial - CSV Export and Details Commands
/// Extracted to reduce main file complexity (~350 lines)
/// </summary>
public partial class DashboardViewModel
{
    // ==================== EXPORT STATE ====================
    // NOTE: These properties are defined in main DashboardViewModel.cs
    // This partial file only contains methods that use them

    // ==================== CSV EXPORT COMMANDS ====================

    [RelayCommand]
    private async Task ExportPortsByPacketsAsync()
    {
        await ExportPortsAsync(TopPortsByPacketsExtended, "PortsByPackets");
    }

    [RelayCommand]
    private async Task ExportPortsByBytesAsync()
    {
        await ExportPortsAsync(TopPortsByBytesExtended, "PortsByBytes");
    }

    [RelayCommand]
    private async Task ExportSourcesByPacketsAsync()
    {
        await ExportEndpointsAsync(TopSourcesExtended, "SourceIPsByPackets");
    }

    [RelayCommand]
    private async Task ExportSourcesByBytesAsync()
    {
        await ExportEndpointsAsync(TopSourcesByBytesExtended, "SourceIPsByBytes");
    }

    [RelayCommand]
    private async Task ExportDestinationsByPacketsAsync()
    {
        await ExportEndpointsAsync(TopDestinationsExtended, "DestinationIPsByPackets");
    }

    [RelayCommand]
    private async Task ExportDestinationsByBytesAsync()
    {
        await ExportEndpointsAsync(TopDestinationsByBytesExtended, "DestinationIPsByBytes");
    }

    [RelayCommand]
    private async Task ExportConnectionsByPacketsAsync()
    {
        await ExportConnectionsAsync(TopConnectionsExtended, "ConnectionsByPackets");
    }

    [RelayCommand]
    private async Task ExportConnectionsByBytesAsync()
    {
        await ExportConnectionsAsync(TopConnectionsByBytesExtended, "ConnectionsByBytes");
    }

    [RelayCommand]
    private async Task ExportTotalIPsByPacketsAsync()
    {
        await ExportEndpointsAsync(TopTotalIPsByPacketsExtended, "TotalIPsByPackets");
    }

    [RelayCommand]
    private async Task ExportTotalIPsByBytesAsync()
    {
        await ExportEndpointsAsync(TopTotalIPsByBytesExtended, "TotalIPsByBytes");
    }

    // ==================== DETAILS COMMANDS ====================

    [RelayCommand]
    private Task ShowPortDetails(object? parameter)
    {
        if (parameter is TopPortViewModelExtended port && CurrentPackets.Any())
        {
            DebugLogger.Log($"[DashboardViewModel] Show DrillDown for Port {port.Port}/{port.Protocol} ({port.ServiceName})");
            // Pass pre-calculated stats from Dashboard table to ensure consistency
            DrillDown.ShowForPort(port.Port, port.Protocol, CurrentPackets, port.PacketCount, port.ByteCount);
        }
        return Task.CompletedTask;
    }

    [RelayCommand]
    private Task ShowIPDetails(object? parameter)
    {
        if (parameter is EndpointViewModelExtended endpoint && CurrentPackets.Any())
        {
            DebugLogger.Log($"[DashboardViewModel] Show DrillDown for IP {endpoint.Address} ({endpoint.Country})");
            // Pass pre-calculated stats from Dashboard table to ensure consistency
            DrillDown.ShowForIP(endpoint.Address, CurrentPackets, endpoint.PacketCount, endpoint.ByteCount);
        }
        return Task.CompletedTask;
    }

    [RelayCommand]
    private Task ShowConnectionDetails(object? parameter)
    {
        if (parameter is ConnectionViewModelExtended connection && CurrentPackets.Any())
        {
            DebugLogger.Log($"[DashboardViewModel] Show DrillDown for connection {connection.SourceIP}:{connection.SourcePort} → {connection.DestinationIP}:{connection.DestinationPort}");
            DrillDown.ShowForConnection(connection.SourceIP, connection.SourcePort, connection.DestinationIP, connection.DestinationPort, CurrentPackets);
        }
        return Task.CompletedTask;
    }

    // ==================== EXPORT HELPER METHODS ====================

    private async Task ExportPortsAsync(ObservableCollection<TopPortViewModelExtended> ports, string dataTypeName)
    {
        // Guard against race condition from rapid clicks
        if (IsExporting) return;

        if (_csvExportService == null || _fileDialogService == null)
        {
            ShowExportStatus("Export services not available", isError: true);
            return;
        }

        if (ports == null || !ports.Any())
        {
            ShowExportStatus("No port data available to export", isError: true);
            return;
        }

        try
        {
            IsExporting = true;
            ShowExportStatus($"Preparing to export {ports.Count} ports...");

            var filePath = await _fileDialogService.SaveFileAsync(
                $"Export {dataTypeName}",
                _csvExportService.GetSuggestedFileName(dataTypeName),
                new Services.FileDialogFilter("CSV Files", "csv"));

            if (string.IsNullOrWhiteSpace(filePath))
            {
                ClearExportStatus();
                return;
            }

            ShowExportStatus($"Exporting {ports.Count} ports to CSV...");

            var exportData = ports.Select(p => new
            {
                Rank = p.Rank,
                Port = p.Port,
                Protocol = p.Protocol,
                Service = p.ServiceName,
                PacketCount = p.PacketCount,
                Bytes = p.ByteCount,
                Percentage = p.Percentage
            }).ToList();

            var columnMappings = new Dictionary<string, Func<dynamic, object?>>
            {
                ["Rank"] = d => d.Rank,
                ["Port"] = d => d.Port,
                ["Protocol"] = d => d.Protocol,
                ["Service"] = d => d.Service,
                ["Packet Count"] = d => d.PacketCount,
                ["Bytes"] = d => d.Bytes,
                ["Percentage"] = d => $"{d.Percentage:F2}%"
            };

            await _csvExportService.ExportToCsvAsync(exportData, filePath, columnMappings);

            ShowExportStatus($"Successfully exported to {System.IO.Path.GetFileName(filePath)}", isError: false);
            _ = AutoClearExportStatusAsync();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Export ports error: {ex.Message}");
            ShowExportStatus($"Export failed: {ex.Message}", isError: true);
        }
        finally
        {
            IsExporting = false;
        }
    }

    private async Task ExportEndpointsAsync(ObservableCollection<EndpointViewModelExtended> endpoints, string dataTypeName)
    {
        // Guard against race condition from rapid clicks
        if (IsExporting) return;

        if (_csvExportService == null || _fileDialogService == null)
        {
            ShowExportStatus("Export services not available", isError: true);
            return;
        }

        if (endpoints == null || !endpoints.Any())
        {
            ShowExportStatus("No endpoint data available to export", isError: true);
            return;
        }

        try
        {
            IsExporting = true;
            ShowExportStatus($"Preparing to export {endpoints.Count} endpoints...");

            var filePath = await _fileDialogService.SaveFileAsync(
                $"Export {dataTypeName}",
                _csvExportService.GetSuggestedFileName(dataTypeName),
                new Services.FileDialogFilter("CSV Files", "csv"));

            if (string.IsNullOrWhiteSpace(filePath))
            {
                ClearExportStatus();
                return;
            }

            ShowExportStatus($"Exporting {endpoints.Count} endpoints to CSV...");

            var exportData = endpoints.Select(e => new
            {
                Rank = e.Rank,
                IPAddress = e.Address,
                Country = e.Country,
                CountryCode = e.CountryCode,
                PacketCount = e.PacketCount,
                Bytes = e.ByteCount,
                BytesFormatted = e.BytesFormatted,
                Percentage = e.Percentage
            }).ToList();

            var columnMappings = new Dictionary<string, Func<dynamic, object?>>
            {
                ["Rank"] = d => d.Rank,
                ["IP Address"] = d => d.IPAddress,
                ["Country"] = d => d.Country,
                ["Country Code"] = d => d.CountryCode,
                ["Packet Count"] = d => d.PacketCount,
                ["Bytes"] = d => d.Bytes,
                ["Bytes Formatted"] = d => d.BytesFormatted,
                ["Percentage"] = d => $"{d.Percentage:F2}%"
            };

            await _csvExportService.ExportToCsvAsync(exportData, filePath, columnMappings);

            ShowExportStatus($"Successfully exported to {System.IO.Path.GetFileName(filePath)}", isError: false);
            _ = AutoClearExportStatusAsync();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Export endpoints error: {ex.Message}");
            ShowExportStatus($"Export failed: {ex.Message}", isError: true);
        }
        finally
        {
            IsExporting = false;
        }
    }

    private async Task ExportConnectionsAsync(ObservableCollection<ConnectionViewModelExtended> connections, string dataTypeName)
    {
        // Guard against race condition from rapid clicks
        if (IsExporting) return;

        if (_csvExportService == null || _fileDialogService == null)
        {
            ShowExportStatus("Export services not available", isError: true);
            return;
        }

        if (connections == null || !connections.Any())
        {
            ShowExportStatus("No connection data available to export", isError: true);
            return;
        }

        try
        {
            IsExporting = true;
            ShowExportStatus($"Preparing to export {connections.Count} connections...");

            var filePath = await _fileDialogService.SaveFileAsync(
                $"Export {dataTypeName}",
                _csvExportService.GetSuggestedFileName(dataTypeName),
                new Services.FileDialogFilter("CSV Files", "csv"));

            if (string.IsNullOrWhiteSpace(filePath))
            {
                ClearExportStatus();
                return;
            }

            ShowExportStatus($"Exporting {connections.Count} connections to CSV...");

            var exportData = connections.Select(c => new
            {
                Rank = c.Rank,
                SourceIP = c.SourceIP,
                SourcePort = c.SourcePort,
                DestinationIP = c.DestinationIP,
                DestinationPort = c.DestinationPort,
                Protocol = c.Protocol,
                PacketCount = c.PacketCount,
                Bytes = c.ByteCount
            }).ToList();

            var columnMappings = new Dictionary<string, Func<dynamic, object?>>
            {
                ["Rank"] = d => d.Rank,
                ["Source IP"] = d => d.SourceIP,
                ["Source Port"] = d => d.SourcePort,
                ["Destination IP"] = d => d.DestinationIP,
                ["Destination Port"] = d => d.DestinationPort,
                ["Protocol"] = d => d.Protocol,
                ["Packet Count"] = d => d.PacketCount,
                ["Bytes"] = d => d.Bytes
            };

            await _csvExportService.ExportToCsvAsync(exportData, filePath, columnMappings);

            ShowExportStatus($"Successfully exported to {System.IO.Path.GetFileName(filePath)}", isError: false);
            _ = AutoClearExportStatusAsync();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Export connections error: {ex.Message}");
            ShowExportStatus($"Export failed: {ex.Message}", isError: true);
        }
        finally
        {
            IsExporting = false;
        }
    }

    // ==================== EXPORT STATUS HELPERS ====================

    private void ShowExportStatus(string message, bool isError = false)
    {
        ExportStatusMessage = message;
        ExportStatusColor = isError ? ThemeColorHelper.GetColorHex("ColorDanger", "#DA3633") : ThemeColorHelper.GetColorHex("ColorSuccess", "#238636"); // GitHub red for errors, green for success
    }

    private void ClearExportStatus()
    {
        ExportStatusMessage = null;
        _exportStatusCts?.Cancel();
        _exportStatusCts = null;
    }

    private async Task AutoClearExportStatusAsync()
    {
        // Cancel any existing auto-clear
        _exportStatusCts?.Cancel();
        _exportStatusCts = new CancellationTokenSource();

        try
        {
            await Task.Delay(5000, _exportStatusCts.Token);
            ClearExportStatus();
        }
        catch (TaskCanceledException)
        {
            // Expected when cancelled
        }
    }
}
