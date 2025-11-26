using System;
using System.IO;
using System.Threading.Tasks;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Handles file selection, loading, and validation for the main window.
/// Manages file state and triggers auto-start analysis when configured.
/// </summary>
public partial class MainWindowFileViewModel : ObservableObject
{
    // Events
    public event EventHandler<string>? FileLoaded;
    public event EventHandler? FileClear;

    // State
    [ObservableProperty] private string? _currentFile;
    [ObservableProperty] private bool _hasFile;
    [ObservableProperty] private bool _canAnalyze;

    public MainWindowFileViewModel()
    {
    }

    partial void OnCurrentFileChanged(string? value)
    {
        HasFile = !string.IsNullOrWhiteSpace(value);
        CanAnalyze = HasFile && File.Exists(value);

        // ✅ DIAGNOSTIC: Log file selection and CanAnalyze status
        DebugLogger.Log($"[MainWindowFileViewModel] File changed: {value}");
        DebugLogger.Log($"[MainWindowFileViewModel] HasFile: {HasFile}, CanAnalyze: {CanAnalyze}, File.Exists: {(value != null && File.Exists(value))}");
    }

    partial void OnHasFileChanged(bool value)
    {
        if (!value)
        {
            CanAnalyze = false;
        }
    }

    /// <summary>
    /// Opens a file picker dialog for selecting PCAP files
    /// </summary>
    [RelayCommand]
    private async Task OpenFileAsync()
    {
        try
        {
            var topLevel = App.Current?.ApplicationLifetime is Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                ? desktop.MainWindow
                : null;

            if (topLevel == null)
            {
                DebugLogger.Log("[MainWindowFileViewModel] Error: Unable to get main window");
                return;
            }

            var files = await topLevel.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Select PCAP File",
                AllowMultiple = false,
                FileTypeFilter = new[]
                {
                    new FilePickerFileType("PCAP Files")
                    {
                        Patterns = new[] { "*.pcap", "*.pcapng", "*.cap" }
                    },
                    new FilePickerFileType("All Files")
                    {
                        Patterns = new[] { "*.*" }
                    }
                }
            });

            if (files.Count > 0)
            {
                var file = files[0];
                var filePath = file.Path.LocalPath;
                await LoadCaptureAsync(filePath);
            }
            else
            {
                await LoadCaptureAsync(null);
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowFileViewModel] Error opening file: {ex.Message}");
        }
    }

    /// <summary>
    /// Loads a capture file and validates it
    /// </summary>
    public Task LoadCaptureAsync(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            CurrentFile = null;
            CanAnalyze = false;
            DebugLogger.Log("[MainWindowFileViewModel] LoadCaptureAsync invoked with no file path");
            FileClear?.Invoke(this, EventArgs.Empty);
            return Task.CompletedTask;
        }

        if (!File.Exists(filePath))
        {
            CurrentFile = filePath;
            CanAnalyze = false;
            DebugLogger.Log($"[MainWindowFileViewModel] Invalid file selected: {filePath}");
            FileClear?.Invoke(this, EventArgs.Empty);
            return Task.CompletedTask;
        }

        CurrentFile = filePath;
        CanAnalyze = true;

        DebugLogger.Log($"[MainWindowFileViewModel] File loaded: {filePath}");
        FileLoaded?.Invoke(this, filePath);

        return Task.CompletedTask;
    }

    /// <summary>
    /// Clears the current file selection
    /// </summary>
    public void ClearFile()
    {
        CurrentFile = null;
        CanAnalyze = false;
        HasFile = false;
        FileClear?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Gets file information for display
    /// </summary>
    public (string fileName, long fileSize, long expectedDataSize) GetFileInfo()
    {
        if (string.IsNullOrEmpty(CurrentFile) || !File.Exists(CurrentFile))
        {
            return (string.Empty, 0, 0);
        }

        var fileInfo = new FileInfo(CurrentFile);
        var fileName = Path.GetFileName(CurrentFile);
        var fileSize = fileInfo.Length;
        var expectedDataSize = (long)(fileInfo.Length * 0.94); // Estimate ~94% is packet data

        return (fileName, fileSize, expectedDataSize);
    }

    /// <summary>
    /// Validates if the current file can be analyzed
    /// </summary>
    public bool CanStartAnalysis(bool isAnalyzing)
    {
        return CanAnalyze && !isAnalyzing && !string.IsNullOrEmpty(CurrentFile) && File.Exists(CurrentFile);
    }
}
