using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// ViewModel for the About tab - displays application dependencies and version information.
/// Shows NuGet packages, external tools (TShark), data files, and their status.
/// </summary>
public partial class AboutViewModel : ObservableObject
{
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    private readonly IDependencyService? _dependencyService;
    private bool _isLoaded;

    // ==================== APPLICATION INFO ====================

    [ObservableProperty] private string _applicationName = "PCAP Security Analyzer";
    [ObservableProperty] private string _applicationVersion = "1.0.0";
    [ObservableProperty] private string _runtimeVersion = string.Empty;
    [ObservableProperty] private string _osDescription = string.Empty;
    [ObservableProperty] private string _collectedAt = string.Empty;

    // ==================== DEPENDENCY COLLECTIONS ====================

    [ObservableProperty] private ObservableCollection<DependencyInfo> _frameworkDependencies = [];
    [ObservableProperty] private ObservableCollection<DependencyInfo> _uiFrameworkDependencies = [];
    [ObservableProperty] private ObservableCollection<DependencyInfo> _coreLibraries = [];
    [ObservableProperty] private ObservableCollection<DependencyInfo> _externalTools = [];
    [ObservableProperty] private ObservableCollection<DependencyInfo> _dataFiles = [];

    // ==================== STATISTICS ====================

    [ObservableProperty] private int _totalDependencies;
    [ObservableProperty] private int _availableCount;
    [ObservableProperty] private int _notFoundCount;
    [ObservableProperty] private bool _isLoading;

    // ==================== SELECTED ITEM ====================

    [ObservableProperty] private DependencyInfo? _selectedDependency;

    public AboutViewModel()
    {
        _dependencyService = App.Services?.GetService<IDependencyService>();
    }

    /// <summary>
    /// Loads dependency information. Called when tab is first displayed.
    /// </summary>
    public async Task LoadDependenciesAsync()
    {
        if (_isLoaded || _dependencyService == null)
            return;

        IsLoading = true;

        try
        {
            var dependencies = await _dependencyService.CollectDependenciesAsync();

            await Dispatcher.InvokeAsync(() =>
            {
                ApplicationName = dependencies.ApplicationName;
                ApplicationVersion = dependencies.ApplicationVersion;
                RuntimeVersion = dependencies.RuntimeVersion;
                OsDescription = dependencies.OSDescription;
                CollectedAt = dependencies.CollectedAt.ToString("yyyy-MM-dd HH:mm:ss");

                // Group by category
                FrameworkDependencies = new ObservableCollection<DependencyInfo>(
                    dependencies.GetByCategory(DependencyCategory.Framework).OrderBy(d => d.Name));

                UiFrameworkDependencies = new ObservableCollection<DependencyInfo>(
                    dependencies.GetByCategory(DependencyCategory.UIFramework).OrderBy(d => d.Name));

                CoreLibraries = new ObservableCollection<DependencyInfo>(
                    dependencies.GetByCategory(DependencyCategory.CoreLibrary).OrderBy(d => d.Name));

                ExternalTools = new ObservableCollection<DependencyInfo>(
                    dependencies.GetByCategory(DependencyCategory.ExternalTool).OrderBy(d => d.Name));

                DataFiles = new ObservableCollection<DependencyInfo>(
                    dependencies.GetByCategory(DependencyCategory.DataFile).OrderBy(d => d.Name));

                // Statistics
                TotalDependencies = dependencies.Dependencies.Count;
                AvailableCount = dependencies.Dependencies.Count(d => d.Status == DependencyStatus.Available);
                NotFoundCount = dependencies.Dependencies.Count(d => d.Status == DependencyStatus.NotFound);

                _isLoaded = true;
            });

            DebugLogger.Log($"[AboutViewModel] Loaded {TotalDependencies} dependencies");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[AboutViewModel] Error loading dependencies: {ex.Message}");
        }
        finally
        {
            IsLoading = false;
        }
    }

    /// <summary>
    /// Refreshes dependency information
    /// </summary>
    [RelayCommand]
    private async Task RefreshAsync()
    {
        _isLoaded = false;
        await LoadDependenciesAsync();
    }

    /// <summary>
    /// Opens the project URL for a dependency in the default browser
    /// </summary>
    [RelayCommand]
    private void OpenProjectUrl(DependencyInfo? dependency)
    {
        if (dependency?.ProjectUrl == null)
            return;

        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = dependency.ProjectUrl,
                UseShellExecute = true
            };
            System.Diagnostics.Process.Start(psi);
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[AboutViewModel] Failed to open URL: {ex.Message}");
        }
    }

    /// <summary>
    /// Copies dependency information to clipboard
    /// </summary>
    [RelayCommand]
    private async Task CopyToClipboardAsync()
    {
        try
        {
            var clipboard = Avalonia.Application.Current?.ApplicationLifetime is
                Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop
                ? desktop.MainWindow?.Clipboard
                : null;

            if (clipboard == null)
                return;

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"# {ApplicationName} v{ApplicationVersion}");
            sb.AppendLine($"Runtime: {RuntimeVersion}");
            sb.AppendLine($"OS: {OsDescription}");
            sb.AppendLine();

            AppendCategory(sb, "## Framework", FrameworkDependencies);
            AppendCategory(sb, "## UI Framework", UiFrameworkDependencies);
            AppendCategory(sb, "## Core Libraries", CoreLibraries);
            AppendCategory(sb, "## External Tools", ExternalTools);
            AppendCategory(sb, "## Data Files", DataFiles);

            await clipboard.SetTextAsync(sb.ToString());
            DebugLogger.Log("[AboutViewModel] Dependencies copied to clipboard");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[AboutViewModel] Failed to copy to clipboard: {ex.Message}");
        }
    }

    private static void AppendCategory(System.Text.StringBuilder sb, string title, IEnumerable<DependencyInfo> dependencies)
    {
        sb.AppendLine(title);
        foreach (var dep in dependencies)
        {
            var status = dep.Status == DependencyStatus.Available ? "OK" : "MISSING";
            sb.AppendLine($"- {dep.Name} v{dep.Version} [{status}]");
            if (!string.IsNullOrEmpty(dep.Description))
                sb.AppendLine($"  {dep.Description}");
        }
        sb.AppendLine();
    }
}
