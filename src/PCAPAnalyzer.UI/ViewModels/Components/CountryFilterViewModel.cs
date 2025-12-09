using System;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component responsible for country filtering and sorting functionality.
/// Manages excluded countries, sort modes, and Top 10/50 toggles.
/// </summary>
public partial class CountryFilterViewModel : ObservableObject
{
    // Sort modes
    [ObservableProperty] private int _sortMode = 0; // 0=Traffic, 1=Risk, 2=Name

    // Country exclusion
    [ObservableProperty] private ObservableCollection<string> _excludedCountries = [];
    [ObservableProperty] private bool _hasExcludedCountries;
    [ObservableProperty] private string _excludedCountriesText = "";

    // Top 10/50 toggles
    [ObservableProperty] private bool _showTop50Countries = false; // false = Top 10, true = Top 50
    [ObservableProperty] private int _displayedCountryCount = 10;

    // Separate toggles for source and destination countries
    [ObservableProperty] private bool _showTop50SourceCountries = false;
    [ObservableProperty] private bool _showTop50DestinationCountries = false;

    // Flow display toggles
    [ObservableProperty] private bool _showAllFlows = false;
    [ObservableProperty] private int _displayedFlowCount = 10;

    // Hide internal/IPv6 traffic toggle (filters out Internal, IP6_LINK, IP6_LOOP, etc.)
    [ObservableProperty] private bool _hideInternalTraffic = false;

    /// <summary>
    /// Event raised when sort mode changes
    /// </summary>
    public event EventHandler? SortModeChanged;

    /// <summary>
    /// Event raised when excluded countries change
    /// </summary>
    public event EventHandler? ExcludedCountriesChanged;

    /// <summary>
    /// Event raised when display count changes
    /// </summary>
    public event EventHandler? DisplayCountChanged;

    /// <summary>
    /// Event raised when hide internal traffic toggle changes
    /// </summary>
    public event EventHandler? HideInternalTrafficChanged;

    public CountryFilterViewModel()
    {
        // Monitor exclusion changes
        ExcludedCountries.CollectionChanged += OnExcludedCountriesCollectionChanged;
    }

    /// <summary>
    /// Clears all country exclusions
    /// </summary>
    [RelayCommand]
    public void ClearExclusions()
    {
        ExcludedCountries.Clear();
        HasExcludedCountries = false;
        ExcludedCountriesText = "";
        DebugLogger.Log("[CountryFilterViewModel] Cleared all exclusions");
    }

    /// <summary>
    /// Adds a country to the exclusion list
    /// </summary>
    public void AddExclusion(string countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
            return;

        if (!ExcludedCountries.Contains(countryCode))
        {
            ExcludedCountries.Add(countryCode);
            DebugLogger.Log($"[CountryFilterViewModel] Added exclusion: {countryCode}");
        }
    }

    /// <summary>
    /// Removes a country from the exclusion list
    /// </summary>
    public void RemoveExclusion(string countryCode)
    {
        if (ExcludedCountries.Contains(countryCode))
        {
            ExcludedCountries.Remove(countryCode);
            DebugLogger.Log($"[CountryFilterViewModel] Removed exclusion: {countryCode}");
        }
    }

    /// <summary>
    /// Toggles a country's exclusion status
    /// </summary>
    public void ToggleExclusion(string countryCode)
    {
        if (ExcludedCountries.Contains(countryCode))
            RemoveExclusion(countryCode);
        else
            AddExclusion(countryCode);
    }

    /// <summary>
    /// Gets the current display limit for countries
    /// </summary>
    public int GetCountryDisplayLimit()
    {
        return ShowTop50Countries ? 50 : 10;
    }

    /// <summary>
    /// Gets the current display limit for source countries
    /// </summary>
    public int GetSourceCountryDisplayLimit()
    {
        return ShowTop50SourceCountries ? 50 : 10;
    }

    /// <summary>
    /// Gets the current display limit for destination countries
    /// </summary>
    public int GetDestinationCountryDisplayLimit()
    {
        return ShowTop50DestinationCountries ? 50 : 10;
    }

    /// <summary>
    /// Gets the current display limit for flows
    /// </summary>
    public int GetFlowDisplayLimit(int totalFlows)
    {
        return ShowAllFlows ? totalFlows : Math.Min(10, totalFlows);
    }

    /// <summary>
    /// Handles changes to the excluded countries collection
    /// </summary>
    private void OnExcludedCountriesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        UpdateExcludedCountriesText();
        ExcludedCountriesChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Updates the excluded countries text display
    /// </summary>
    private void UpdateExcludedCountriesText()
    {
        HasExcludedCountries = ExcludedCountries.Count > 0;
        if (HasExcludedCountries)
        {
            ExcludedCountriesText = $"({ExcludedCountries.Count} excluded)";
        }
        else
        {
            ExcludedCountriesText = "";
        }
    }

    /// <summary>
    /// Property change handler for sort mode
    /// </summary>
    partial void OnSortModeChanged(int value)
    {
        DebugLogger.Log($"[CountryFilterViewModel] Sort mode changed to: {value} ({GetSortModeName(value)})");
        SortModeChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Property change handler for Top 50 toggle
    /// </summary>
    partial void OnShowTop50CountriesChanged(bool value)
    {
        DisplayedCountryCount = value ? 50 : 10;
        DebugLogger.Log($"[CountryFilterViewModel] Display count changed to: {DisplayedCountryCount}");
        DisplayCountChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Property change handler for Top 50 Source toggle
    /// </summary>
    partial void OnShowTop50SourceCountriesChanged(bool value)
    {
        DebugLogger.Log($"[CountryFilterViewModel] Source display limit changed to: {(value ? 50 : 10)}");
        DisplayCountChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Property change handler for Top 50 Destination toggle
    /// </summary>
    partial void OnShowTop50DestinationCountriesChanged(bool value)
    {
        DebugLogger.Log($"[CountryFilterViewModel] Destination display limit changed to: {(value ? 50 : 10)}");
        DisplayCountChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Property change handler for Show All Flows toggle
    /// </summary>
    partial void OnShowAllFlowsChanged(bool value)
    {
        // DisplayedFlowCount will be set by the caller based on actual flow count
        DebugLogger.Log($"[CountryFilterViewModel] Show all flows: {value}");
        DisplayCountChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Property change handler for Hide Internal Traffic toggle
    /// </summary>
    partial void OnHideInternalTrafficChanged(bool value)
    {
        DebugLogger.Log($"[CountryFilterViewModel] Hide internal traffic: {value}");
        HideInternalTrafficChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Gets the friendly name for a sort mode
    /// </summary>
    private string GetSortModeName(int mode)
    {
        return mode switch
        {
            0 => "Traffic",
            1 => "Risk",
            2 => "Name",
            _ => "Unknown"
        };
    }

    /// <summary>
    /// Gets the sort mode description
    /// </summary>
    public string GetSortModeDescription()
    {
        return GetSortModeName(SortMode);
    }

    /// <summary>
    /// Checks if a country code represents internal/private/IPv6 local traffic.
    /// Used by HideInternalTraffic filter.
    /// </summary>
    public static bool IsInternalOrIPv6Local(string? countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
            return false;

        return countryCode.ToUpperInvariant() switch
        {
            // IPv4 internal/private
            "INTERNAL" or "INT" or "PRIV" or "PRV" or "PRIVATE" or "LOCAL" or "LAN" => true,
            // IPv6 local types
            "IP6" or "IP6_LINK" or "IP6_LOOP" or "IP6_MCAST" or "IP6_ULA" or "IP6_SITE" or "IP6_ANY" => true,
            // Public IPv6 should NOT be hidden
            "IP6_GLOBAL" => false,
            _ => false
        };
    }
}
