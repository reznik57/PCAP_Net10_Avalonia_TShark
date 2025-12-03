using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.UI.Models;

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

    [ObservableProperty] private int _selectedTabIndex;

    // Global IP/Port inputs (moved from GeneralTab - apply to all tabs)
    [ObservableProperty] private string _sourceIPInput = "";
    [ObservableProperty] private string _destinationIPInput = "";
    [ObservableProperty] private string _portRangeInput = "";

    /// <summary>
    /// Indicates that filter application is in progress.
    /// Set by the View when filter operation starts/completes.
    /// </summary>
    [ObservableProperty] private bool _isApplyingFilter;

    /// <summary>
    /// Filter progress (0.0 to 1.0) during application.
    /// </summary>
    [ObservableProperty] private double _filterProgress;

    public bool IsIncludeMode => _currentMode == FilterChipMode.Include;
    public bool IsExcludeMode => _currentMode == FilterChipMode.Exclude;

    // Mode-dependent colors for panel tinting
    public string PanelBackground => IsIncludeMode ? "#0A1A14" : "#1A0A0A";
    public string PanelBorder => IsIncludeMode ? "#2EA043" : "#F85149";

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

    public event Action? ApplyFiltersRequested;

    public UnifiedFilterPanelViewModel(GlobalFilterState filterState, FilterSummaryViewModel summary)
    {
        _filterState = filterState;
        Summary = summary;

        // Create tab ViewModels WITHOUT GlobalFilterState
        GeneralTab = new GeneralFilterTabViewModel();
        ThreatsTab = new ThreatsFilterTabViewModel();
        AnomaliesTab = new AnomaliesFilterTabViewModel();
        VoiceQoSTab = new VoiceQoSFilterTabViewModel();
        CountryTab = new CountryFilterTabViewModel();
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
        NotifyModeChanged();
    }

    private void NotifyModeChanged()
    {
        OnPropertyChanged(nameof(IsIncludeMode));
        OnPropertyChanged(nameof(IsExcludeMode));
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
    }

    [RelayCommand]
    private void ApplyFilters()
    {
        // NOTE: Do NOT clear GlobalFilterState - new groups are OR'd with existing groups
        // User can click Clear to remove all groups

        // Collect all pending filters from all tabs
        var general = GeneralTab.GetPendingFilters();
        var threats = ThreatsTab.GetPendingFilters();
        var anomalies = AnomaliesTab.GetPendingFilters();
        var voip = VoiceQoSTab.GetPendingFilters();
        var country = CountryTab.GetPendingFilters();

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
            Regions = country.Regions.Count > 0 ? country.Regions : null
        };

        // Only create group if there's something to filter
        if (group.HasCriteria())
        {
            // Build display label from all criteria
            group.BuildDisplayLabel();
            group.IsAndGroup = true;
            group.IsExcludeGroup = _currentMode == FilterChipMode.Exclude;

            // Add the group to GlobalFilterState
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
        }

        // Update tab indicators
        NotifyTabIndicatorsChanged();

        // Fire event to trigger filter execution
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

        // Clear GlobalFilterState
        _filterState.Clear();

        // Update tab indicators
        NotifyTabIndicatorsChanged();

        // Fire event to trigger filter execution (show all data)
        ApplyFiltersRequested?.Invoke();
    }
}
