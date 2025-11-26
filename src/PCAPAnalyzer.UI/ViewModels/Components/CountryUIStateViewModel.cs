using System;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component responsible for managing UI state for country traffic view.
/// Handles map visualization toggles, continent navigation, and display preferences.
/// </summary>
public partial class CountryUIStateViewModel : ObservableObject
{
    // Map visualization properties
    [ObservableProperty] private bool _showParticles = true;
    [ObservableProperty] private bool _showGridLines = true;
    [ObservableProperty] private bool _showConnections = true;
    [ObservableProperty] private bool _enableAnimations = true;
    [ObservableProperty] private bool _showAnimations = true;
    [ObservableProperty] private bool _showTrafficFlows = true;
    [ObservableProperty] private bool _showCountryLabels = true;

    // Continent tab navigation
    [ObservableProperty] private int _selectedContinentTab = 0; // 0=World, 1=NA, 2=SA, 3=EU, 4=AF, 5=AS, 6=OC, 7=INT, 8=IPv6
    [ObservableProperty] private string _selectedContinent = "All";

    /// <summary>
    /// Event raised when continent selection changes
    /// </summary>
    public event EventHandler<string>? ContinentChanged;

    /// <summary>
    /// Event raised when visualization settings change
    /// </summary>
    public event EventHandler? VisualizationSettingsChanged;

    /// <summary>
    /// Zooms in on the map
    /// </summary>
    [RelayCommand]
    public void ZoomIn()
    {
        DebugLogger.Log("[CountryUIStateViewModel] ZoomIn requested");
        // Map control will handle this via binding
    }

    /// <summary>
    /// Zooms out on the map
    /// </summary>
    [RelayCommand]
    public void ZoomOut()
    {
        DebugLogger.Log("[CountryUIStateViewModel] ZoomOut requested");
        // Map control will handle this via binding
    }

    /// <summary>
    /// Resets the map view to defaults
    /// </summary>
    [RelayCommand]
    public void ResetView()
    {
        DebugLogger.Log("[CountryUIStateViewModel] ResetView requested");
        ShowAnimations = true;
        ShowTrafficFlows = true;
        ShowCountryLabels = false;
        SelectedContinentTab = 0;
        SelectedContinent = "All";
        VisualizationSettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Navigates to a specific continent
    /// </summary>
    [RelayCommand]
    public void NavigateToContinent(object? parameter)
    {
        if (parameter is string continentCode)
        {
            OnContinentClicked(continentCode);
        }
    }

    /// <summary>
    /// Handles continent click navigation
    /// </summary>
    public void OnContinentClicked(string continentCode)
    {
        DebugLogger.Log($"[CountryUIStateViewModel] Continent clicked: {continentCode}");

        // Map continent codes to tab indices
        SelectedContinentTab = continentCode switch
        {
            "NA" or "NorthAmerica" => 1,
            "SA" or "SouthAmerica" => 2,
            "EU" or "Europe" => 3,
            "AF" or "Africa" => 4,
            "AS" or "Asia" => 5,
            "OC" or "Oceania" => 6,
            "INT" or "Internal" => 7,
            "IP6" or "IPv6" => 8,
            _ => 0 // World
        };

        // Update selected continent
        SelectedContinent = continentCode switch
        {
            "NA" or "NorthAmerica" => "North America",
            "SA" or "SouthAmerica" => "South America",
            "EU" or "Europe" => "Europe",
            "AF" or "Africa" => "Africa",
            "AS" or "Asia" => "Asia",
            "OC" or "Oceania" => "Oceania",
            "INT" or "Internal" => "Internal",
            "IP6" or "IPv6" => "IPv6",
            _ => "All"
        };

        ContinentChanged?.Invoke(this, continentCode);
    }

    /// <summary>
    /// Property change handlers to notify visualization changes
    /// </summary>
    partial void OnShowParticlesChanged(bool value)
    {
        DebugLogger.Log($"[CountryUIStateViewModel] ShowParticles changed to: {value}");
        VisualizationSettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    partial void OnShowGridLinesChanged(bool value)
    {
        DebugLogger.Log($"[CountryUIStateViewModel] ShowGridLines changed to: {value}");
        VisualizationSettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    partial void OnShowConnectionsChanged(bool value)
    {
        DebugLogger.Log($"[CountryUIStateViewModel] ShowConnections changed to: {value}");
        VisualizationSettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    partial void OnEnableAnimationsChanged(bool value)
    {
        DebugLogger.Log($"[CountryUIStateViewModel] EnableAnimations changed to: {value}");
        VisualizationSettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    partial void OnShowAnimationsChanged(bool value)
    {
        DebugLogger.Log($"[CountryUIStateViewModel] ShowAnimations changed to: {value}");
        VisualizationSettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    partial void OnShowTrafficFlowsChanged(bool value)
    {
        DebugLogger.Log($"[CountryUIStateViewModel] ShowTrafficFlows changed to: {value}");
        VisualizationSettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    partial void OnShowCountryLabelsChanged(bool value)
    {
        DebugLogger.Log($"[CountryUIStateViewModel] ShowCountryLabels changed to: {value}");
        VisualizationSettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    partial void OnSelectedContinentTabChanged(int value)
    {
        DebugLogger.Log($"[CountryUIStateViewModel] SelectedContinentTab changed to: {value}");

        // Update selected continent name based on tab
        SelectedContinent = value switch
        {
            1 => "North America",
            2 => "South America",
            3 => "Europe",
            4 => "Africa",
            5 => "Asia",
            6 => "Oceania",
            7 => "Internal",
            8 => "IPv6",
            _ => "All"
        };

        // Convert tab index to continent code and raise event
        var continentCode = value switch
        {
            1 => "NA",
            2 => "SA",
            3 => "EU",
            4 => "AF",
            5 => "AS",
            6 => "OC",
            7 => "INT",
            8 => "IP6",
            _ => "All"
        };

        ContinentChanged?.Invoke(this, continentCode);
    }

    /// <summary>
    /// Gets current visualization settings as a summary string
    /// </summary>
    public string GetVisualizationSettingsSummary()
    {
        var settings = new System.Collections.Generic.List<string>();

        if (ShowParticles) settings.Add("Particles");
        if (ShowGridLines) settings.Add("Grid");
        if (ShowConnections) settings.Add("Connections");
        if (ShowAnimations) settings.Add("Animations");
        if (ShowTrafficFlows) settings.Add("Flows");
        if (ShowCountryLabels) settings.Add("Labels");

        return settings.Count > 0 ? string.Join(", ", settings) : "None";
    }

    /// <summary>
    /// Resets all visualization settings to defaults
    /// </summary>
    public void ResetVisualizationSettings()
    {
        ShowParticles = true;
        ShowGridLines = true;
        ShowConnections = true;
        EnableAnimations = true;
        ShowAnimations = true;
        ShowTrafficFlows = true;
        ShowCountryLabels = true;
        DebugLogger.Log("[CountryUIStateViewModel] Reset all visualization settings to defaults");
    }
}
