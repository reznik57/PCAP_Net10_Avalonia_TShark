using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// ViewModel for displaying and managing recent PCAP files
/// </summary>
public partial class RecentFilesViewModel : ObservableObject
{
    private readonly RecentFilesService _recentFilesService;

    public ObservableCollection<RecentFileInfo> RecentFiles => _recentFilesService.RecentFilesList;

    [ObservableProperty] private bool _hasRecentFiles;
    [ObservableProperty] private RecentFileInfo? _selectedRecentFile;

    public event EventHandler<RecentFileInfo>? FileSelected;

    public RecentFilesViewModel(RecentFilesService recentFilesService)
    {
        _recentFilesService = recentFilesService ?? throw new ArgumentNullException(nameof(recentFilesService));

        // Subscribe to service events
        _recentFilesService.RecentFileSelected += OnFileSelectedFromService;

        // Subscribe to collection changes
        _recentFilesService.RecentFilesList.CollectionChanged += (s, e) =>
        {
            HasRecentFiles = _recentFilesService.RecentFilesList.Count > 0;
        };

        HasRecentFiles = _recentFilesService.RecentFilesList.Count > 0;
    }

    /// <summary>
    /// Select and open a recent file
    /// </summary>
    [RelayCommand]
    private void SelectFile(RecentFileInfo file)
    {
        if (file is null) return;

        _recentFilesService.SelectRecentFile(file);
        SelectedRecentFile = file;
    }

    /// <summary>
    /// Toggle pin status of a file
    /// </summary>
    [RelayCommand]
    private async Task TogglePin(RecentFileInfo file)
    {
        if (file is null) return;

        await _recentFilesService.TogglePinAsync(file);
    }

    /// <summary>
    /// Remove a file from recent files list
    /// </summary>
    [RelayCommand]
    private async Task RemoveFile(RecentFileInfo file)
    {
        if (file is null) return;

        await _recentFilesService.RemoveRecentFileAsync(file);
    }

    /// <summary>
    /// Clear all recent files
    /// </summary>
    [RelayCommand]
    private async Task ClearAllFiles()
    {
        await _recentFilesService.ClearRecentFilesAsync();
    }

    private void OnFileSelectedFromService(object? sender, RecentFileInfo file)
    {
        // Forward the event to UI
        FileSelected?.Invoke(this, file);
    }
}
