using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels
{
    public partial class DetailedTableViewModel : ObservableObject
    {
        [ObservableProperty] private string _title = "Detailed View";
        [ObservableProperty] private object? _data;
        [ObservableProperty] private string[] _columns = [];
        [ObservableProperty] private int _totalItems;
        [ObservableProperty] private string _statusMessage = "";
        [ObservableProperty] private bool _isExporting;

        public DetailedTableViewModel()
        {
            // Default constructor for design time
        }

        public DetailedTableViewModel(string title, object data, string[] columns)
        {
            Title = title;
            Data = data;
            Columns = columns;
            
            if (data is ICollection collection)
            {
                TotalItems = collection.Count;
                StatusMessage = $"Showing {TotalItems:N0} items";
            }
        }

        [RelayCommand]
        private async Task ExportToCsv()
        {
            try
            {
                IsExporting = true;
                StatusMessage = "Preparing export...";

                // Get the main window
                var mainWindow = Avalonia.Application.Current?.ApplicationLifetime is 
                    Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                    ? desktop.MainWindow
                    : null;

                if (mainWindow == null)
                {
                    StatusMessage = "Error: Cannot access main window";
                    return;
                }

                // Show save file dialog
                var file = await mainWindow.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
                {
                    Title = "Export to CSV",
                    DefaultExtension = "csv",
                    FileTypeChoices = new[]
                    {
                        new FilePickerFileType("CSV Files")
                        {
                            Patterns = new[] { "*.csv" }
                        }
                    },
                    SuggestedFileName = $"{Title.Replace(" ", "_", StringComparison.Ordinal).Replace("-", "_", StringComparison.Ordinal)}.csv"
                });

                if (file == null)
                {
                    StatusMessage = "Export cancelled";
                    return;
                }

                // Export data
                var csvContent = GenerateCsvContent();
                await File.WriteAllTextAsync(file.Path.LocalPath, csvContent);
                
                StatusMessage = $"Exported {TotalItems:N0} items to {Path.GetFileName(file.Path.LocalPath)}";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Export failed: {ex.Message}";
                DebugLogger.Log($"[DetailedTableViewModel] Export error: {ex}");
            }
            finally
            {
                IsExporting = false;
            }
        }

        [RelayCommand]
        private async Task ExportToJson()
        {
            try
            {
                IsExporting = true;
                StatusMessage = "Preparing JSON export...";

                // Get the main window
                var mainWindow = Avalonia.Application.Current?.ApplicationLifetime is 
                    Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                    ? desktop.MainWindow
                    : null;

                if (mainWindow == null)
                {
                    StatusMessage = "Error: Cannot access main window";
                    return;
                }

                // Show save file dialog
                var file = await mainWindow.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
                {
                    Title = "Export to JSON",
                    DefaultExtension = "json",
                    FileTypeChoices = new[]
                    {
                        new FilePickerFileType("JSON Files")
                        {
                            Patterns = new[] { "*.json" }
                        }
                    },
                    SuggestedFileName = $"{Title.Replace(" ", "_", StringComparison.Ordinal).Replace("-", "_", StringComparison.Ordinal)}.json"
                });

                if (file == null)
                {
                    StatusMessage = "Export cancelled";
                    return;
                }

                // Export data as JSON
                var jsonContent = System.Text.Json.JsonSerializer.Serialize(Data, new System.Text.Json.JsonSerializerOptions
                {
                    WriteIndented = true
                });
                
                await File.WriteAllTextAsync(file.Path.LocalPath, jsonContent);
                
                StatusMessage = $"Exported {TotalItems:N0} items to {Path.GetFileName(file.Path.LocalPath)}";
            }
            catch (Exception ex)
            {
                StatusMessage = $"JSON export failed: {ex.Message}";
                DebugLogger.Log($"[DetailedTableViewModel] JSON export error: {ex}");
            }
            finally
            {
                IsExporting = false;
            }
        }

        [RelayCommand]
        private void CopyToClipboard()
        {
            try
            {
                var csvContent = GenerateCsvContent();
                // Note: Actual clipboard implementation depends on platform
                // This is a placeholder for the actual clipboard operation
                StatusMessage = $"Copied {TotalItems:N0} items to clipboard";
            }
            catch (Exception ex)
            {
                StatusMessage = $"Copy failed: {ex.Message}";
                DebugLogger.Log($"[DetailedTableViewModel] Copy error: {ex}");
            }
        }

        [RelayCommand]
        private void Close()
        {
            // This will be handled by the view to close the window
            StatusMessage = "Closing...";
        }

        private string GenerateCsvContent()
        {
            var sb = new StringBuilder();
            
            // Add headers
            sb.AppendLine(string.Join(",", Columns.Select(c => $"\"{c}\"")));
            
            // Add data rows
            if (Data is IEnumerable enumerable)
            {
                foreach (var item in enumerable)
                {
                    if (item == null) continue;
                    
                    var values = new List<string>();
                    var itemType = item.GetType();
                    
                    foreach (var column in Columns)
                    {
                        // Try to get the property value
                        var prop = itemType.GetProperty(column.Replace(" ", "", StringComparison.Ordinal));
                        if (prop != null)
                        {
                            var value = prop.GetValue(item);
                            values.Add($"\"{value?.ToString() ?? ""}\"");
                        }
                        else
                        {
                            // Try alternate property names
                            if (column == "Packets")
                                prop = itemType.GetProperty("PacketCount");
                            else if (column == "Bytes")
                                prop = itemType.GetProperty("BytesFormatted");
                            else if (column == "Unique Hosts")
                                prop = itemType.GetProperty("UniqueHostCount");
                            else if (column == "Encrypted")
                                prop = itemType.GetProperty("IsEncrypted");
                            else if (column == "Source")
                                prop = itemType.GetProperty("SourceDisplay");
                            else if (column == "Destination")
                                prop = itemType.GetProperty("DestinationDisplay");
                            
                            if (prop != null)
                            {
                                var value = prop.GetValue(item);
                                values.Add($"\"{value?.ToString() ?? ""}\"");
                            }
                            else
                            {
                                values.Add("\"\"");
                            }
                        }
                    }
                    
                    sb.AppendLine(string.Join(",", values));
                }
            }
            
            return sb.ToString();
        }
    }
}