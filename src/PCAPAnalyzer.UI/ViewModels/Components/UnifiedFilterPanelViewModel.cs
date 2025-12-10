using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

public partial class UnifiedFilterPanelViewModel : ObservableObject
{
    private readonly GlobalFilterState _filterState;
    private FilterChipMode _currentMode = FilterChipMode.Include;

    public FilterSummaryViewModel Summary { get; }
    public GeneralFilterTabViewModel GeneralTab { get; }
    public ThreatsFilterTabViewModel ThreatsTab { get; }
    public AnomaliesFilterTabViewModel AnomaliesTab { get; }
    public VoiceQoSFilterTabViewModel VoiceQoSTab { get; }
    public CountryFilterTabViewModel CountryTab { get; }
    public HostInventoryFilterTabViewModel HostInventoryTab { get; }

    // Initialize to -1 so the first real value (even 0) triggers a property change notification
    [ObservableProperty] private int _selectedTabIndex = -1;

    // Global IP/Port inputs (moved from GeneralTab - apply to all tabs)
    [ObservableProperty] private string _sourceIPInput = "";
    [ObservableProperty] private string _destinationIPInput = "";
    [ObservableProperty] private string _portRangeInput = "";

    /// <summary>
    /// Indicates that filter application is in progress.
    /// Delegates to GlobalFilterState for cross-tab visibility.
    /// </summary>
    public bool IsApplyingFilter
    {
        get => _filterState.IsFilteringInProgress;
        set
        {
            if (_filterState.IsFilteringInProgress != value)
            {
                _filterState.IsFilteringInProgress = value;
                OnPropertyChanged();
            }
        }
    }

    /// <summary>
    /// Filter progress (0.0 to 1.0) during application.
    /// Delegates to GlobalFilterState for cross-tab visibility.
    /// </summary>
    public double FilterProgress
    {
        get => _filterState.FilterProgress;
        set
        {
            if (Math.Abs(_filterState.FilterProgress - value) > 0.001)
            {
                _filterState.FilterProgress = value;
                OnPropertyChanged();
            }
        }
    }

    /// <summary>
    /// Controls whether the filter panel is expanded or collapsed.
    /// Collapsed state shows only summary chips and Apply/Clear buttons.
    /// </summary>
    [ObservableProperty] private bool _isExpanded = true;

    /// <summary>
    /// Chevron icon for expand/collapse toggle.
    /// </summary>
    public string ExpandCollapseIcon => IsExpanded ? "▲" : "▼";

    public bool IsIncludeMode => _currentMode == FilterChipMode.Include;
    public bool IsExcludeMode => _currentMode == FilterChipMode.Exclude;

    /// <summary>
    /// Returns true if any filters are active (for showing indicator in collapsed state).
    /// </summary>
    public bool HasActiveFilters => Summary.HasIncludeFilters || Summary.HasExcludeFilters;

    /// <summary>
    /// Count of active filter chips for badge display.
    /// </summary>
    public int ActiveFilterCount => Summary.IncludeChips.Count + Summary.ExcludeChips.Count;

    // Slack-style colors (no mode-dependent tinting)
    public string PanelBackground => ThemeColorHelper.GetColorHex("BackgroundLevel1", "#222529");
    public string PanelBorder => ThemeColorHelper.GetColorHex("BorderSubtle", "#3F4248");

    // Tab filter indicators
    public bool GeneralHasIncludeFilters => _filterState.IncludeGroups.Any(g =>
        !string.IsNullOrEmpty(g.Protocol) || g.QuickFilters?.Count > 0 ||
        !string.IsNullOrEmpty(g.SourceIP) || !string.IsNullOrEmpty(g.DestinationIP) || !string.IsNullOrEmpty(g.PortRange));
    public bool GeneralHasExcludeFilters => _filterState.ExcludeGroups.Any(g =>
        !string.IsNullOrEmpty(g.Protocol) || g.QuickFilters?.Count > 0 ||
        !string.IsNullOrEmpty(g.SourceIP) || !string.IsNullOrEmpty(g.DestinationIP) || !string.IsNullOrEmpty(g.PortRange));
    public bool ThreatsHasIncludeFilters => _filterState.IncludeGroups.Any(g =>
        g.Severities?.Count > 0 || g.ThreatCategories?.Count > 0);
    public bool ThreatsHasExcludeFilters => _filterState.ExcludeGroups.Any(g =>
        g.Severities?.Count > 0 || g.ThreatCategories?.Count > 0);
    public bool AnomaliesHasIncludeFilters => _filterState.IncludeGroups.Any(g =>
        g.AnomalySeverities?.Count > 0 || g.AnomalyCategories?.Count > 0 || g.AnomalyDetectors?.Count > 0);
    public bool AnomaliesHasExcludeFilters => _filterState.ExcludeGroups.Any(g =>
        g.AnomalySeverities?.Count > 0 || g.AnomalyCategories?.Count > 0 || g.AnomalyDetectors?.Count > 0);
    public bool VoiceQoSHasIncludeFilters => _filterState.IncludeGroups.Any(g =>
        g.Codecs?.Count > 0 || g.QualityLevels?.Count > 0 || g.VoipIssues?.Count > 0);
    public bool VoiceQoSHasExcludeFilters => _filterState.ExcludeGroups.Any(g =>
        g.Codecs?.Count > 0 || g.QualityLevels?.Count > 0 || g.VoipIssues?.Count > 0);
    public bool CountryHasIncludeFilters => _filterState.IncludeGroups.Any(g =>
        g.Countries?.Count > 0 || g.Directions?.Count > 0 || g.Regions?.Count > 0);
    public bool CountryHasExcludeFilters => _filterState.ExcludeGroups.Any(g =>
        g.Countries?.Count > 0 || g.Directions?.Count > 0 || g.Regions?.Count > 0);
    public bool HostInventoryHasIncludeFilters => _filterState.IncludeGroups.Any(g =>
        g.OsTypes?.Count > 0 || g.DeviceTypes?.Count > 0 || g.HostRoles?.Count > 0);
    public bool HostInventoryHasExcludeFilters => _filterState.ExcludeGroups.Any(g =>
        g.OsTypes?.Count > 0 || g.DeviceTypes?.Count > 0 || g.HostRoles?.Count > 0);

    public event Action? ApplyFiltersRequested;

    public UnifiedFilterPanelViewModel(GlobalFilterState filterState, FilterSummaryViewModel summary)
    {
        _filterState = filterState;
        Summary = summary;

        // Create tab ViewModels WITHOUT GlobalFilterState
        GeneralTab = new();
        ThreatsTab = new();
        AnomaliesTab = new();
        VoiceQoSTab = new();
        CountryTab = new();
        HostInventoryTab = new();

        // Subscribe to GlobalFilterState changes for progress state forwarding
        _filterState.PropertyChanged += OnFilterStatePropertyChanged;
    }

    private void OnFilterStatePropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // Forward progress state changes to trigger UI updates
        if (e.PropertyName == nameof(GlobalFilterState.IsFilteringInProgress))
            OnPropertyChanged(nameof(IsApplyingFilter));
        else if (e.PropertyName == nameof(GlobalFilterState.FilterProgress))
            OnPropertyChanged(nameof(FilterProgress));
    }

    [RelayCommand]
    private void ToggleExpanded()
    {
        IsExpanded = !IsExpanded;
        OnPropertyChanged(nameof(ExpandCollapseIcon));
    }

    [RelayCommand]
    private void SetIncludeMode()
    {
        _currentMode = FilterChipMode.Include;
        GeneralTab.SetMode(_currentMode);
        ThreatsTab.SetMode(_currentMode);
        AnomaliesTab.SetMode(_currentMode);
        VoiceQoSTab.SetMode(_currentMode);
        CountryTab.SetMode(_currentMode);
        HostInventoryTab.SetMode(_currentMode);
        NotifyModeChanged();
    }

    [RelayCommand]
    private void SetExcludeMode()
    {
        _currentMode = FilterChipMode.Exclude;
        GeneralTab.SetMode(_currentMode);
        ThreatsTab.SetMode(_currentMode);
        AnomaliesTab.SetMode(_currentMode);
        VoiceQoSTab.SetMode(_currentMode);
        CountryTab.SetMode(_currentMode);
        HostInventoryTab.SetMode(_currentMode);
        NotifyModeChanged();
    }

    private void NotifyModeChanged()
    {
        OnPropertyChanged(nameof(IsIncludeMode));
        OnPropertyChanged(nameof(IsExcludeMode));
        // Panel colors are now static in Slack style, but keep for compatibility
        OnPropertyChanged(nameof(PanelBackground));
        OnPropertyChanged(nameof(PanelBorder));
    }

    private void NotifyTabIndicatorsChanged()
    {
        OnPropertyChanged(nameof(GeneralHasIncludeFilters));
        OnPropertyChanged(nameof(GeneralHasExcludeFilters));
        OnPropertyChanged(nameof(ThreatsHasIncludeFilters));
        OnPropertyChanged(nameof(ThreatsHasExcludeFilters));
        OnPropertyChanged(nameof(AnomaliesHasIncludeFilters));
        OnPropertyChanged(nameof(AnomaliesHasExcludeFilters));
        OnPropertyChanged(nameof(VoiceQoSHasIncludeFilters));
        OnPropertyChanged(nameof(VoiceQoSHasExcludeFilters));
        OnPropertyChanged(nameof(CountryHasIncludeFilters));
        OnPropertyChanged(nameof(CountryHasExcludeFilters));
        OnPropertyChanged(nameof(HostInventoryHasIncludeFilters));
        OnPropertyChanged(nameof(HostInventoryHasExcludeFilters));
    }

    [RelayCommand]
    private void ApplyFilters()
    {
        // NOTE: Progress bar is now controlled by GlobalFilterState via OnGlobalFilterStateChanged handlers.
        // This method just builds the filter group and fires the event.

        // Collect all pending filters from all tabs
        var general = GeneralTab.GetPendingFilters();
        var threats = ThreatsTab.GetPendingFilters();
        var anomalies = AnomaliesTab.GetPendingFilters();
        var voip = VoiceQoSTab.GetPendingFilters();
        var country = CountryTab.GetPendingFilters();
        var hostInventory = HostInventoryTab.GetPendingFilters();

        // Build a single FilterGroup with ALL criteria populated
        var group = new Models.FilterGroup
        {
            // Global IP/Port inputs (from this class, not GeneralTab)
            SourceIP = !string.IsNullOrEmpty(SourceIPInput) ? SourceIPInput.Trim() : null,
            DestinationIP = !string.IsNullOrEmpty(DestinationIPInput) ? DestinationIPInput.Trim() : null,
            PortRange = !string.IsNullOrEmpty(PortRangeInput) ? PortRangeInput.Trim() : null,

            // General tab (protocols/security only - IP/Port handled above)
            Protocol = general.Protocols.Count > 0 ? string.Join(",", general.Protocols) : null,
            QuickFilters = general.QuickFilters.Count > 0 ? general.QuickFilters : null,

            // Threats tab
            Severities = threats.Severities.Count > 0 ? threats.Severities : null,
            ThreatCategories = threats.Categories.Count > 0 ? threats.Categories : null,

            // Anomalies tab
            AnomalySeverities = anomalies.Severities.Count > 0 ? anomalies.Severities : null,
            AnomalyCategories = anomalies.Categories.Count > 0 ? anomalies.Categories : null,
            AnomalyDetectors = anomalies.Detectors.Count > 0 ? anomalies.Detectors : null,

            // VoiceQoS tab
            Codecs = voip.Codecs.Count > 0 ? voip.Codecs : null,
            QualityLevels = voip.Qualities.Count > 0 ? voip.Qualities : null,
            VoipIssues = voip.Issues.Count > 0 ? voip.Issues : null,

            // Country tab
            Countries = country.Countries.Count > 0 ? country.Countries : null,
            Directions = country.Directions.Count > 0 ? country.Directions : null,
            Regions = country.Regions.Count > 0 ? country.Regions : null,

            // Host Inventory tab
            OsTypes = hostInventory.OsTypes.Count > 0 ? hostInventory.OsTypes : null,
            DeviceTypes = hostInventory.DeviceTypes.Count > 0 ? hostInventory.DeviceTypes : null,
            HostRoles = hostInventory.HostRoles.Count > 0 ? hostInventory.HostRoles : null
        };

        // Only create group if there's something to filter
        if (group.HasCriteria())
        {
            // Build display label from all criteria
            group.BuildDisplayLabel();
            group.IsAndGroup = true;
            group.IsExcludeGroup = _currentMode == FilterChipMode.Exclude;

            // Add the group to GlobalFilterState (this triggers OnFilterChanged -> progress bar)
            if (_currentMode == FilterChipMode.Include)
                _filterState.AddIncludeGroup(group);
            else
                _filterState.AddExcludeGroup(group);

            // Clear all pending inputs after creating group
            SourceIPInput = "";
            DestinationIPInput = "";
            PortRangeInput = "";
            GeneralTab.Reset();
            ThreatsTab.Reset();
            AnomaliesTab.Reset();
            VoiceQoSTab.Reset();
            CountryTab.Reset();
            HostInventoryTab.Reset();
        }

        // Update tab indicators
        NotifyTabIndicatorsChanged();

        // Explicitly trigger filter application (this fires OnFiltersApplied)
        _filterState.ApplyFilters();

        // Fire event for any additional local handling
        ApplyFiltersRequested?.Invoke();
    }

    [RelayCommand]
    private void ClearFilters()
    {
        // Clear global IP/Port inputs
        SourceIPInput = "";
        DestinationIPInput = "";
        PortRangeInput = "";

        // Clear pending state in all tabs
        GeneralTab.Reset();
        ThreatsTab.Reset();
        AnomaliesTab.Reset();
        VoiceQoSTab.Reset();
        CountryTab.Reset();
        HostInventoryTab.Reset();

        // Clear GlobalFilterState AND trigger re-application (show all data)
        _filterState.ClearAndApply();

        // Update tab indicators
        NotifyTabIndicatorsChanged();

        // Fire event for any additional local handling
        ApplyFiltersRequested?.Invoke();
    }
}
