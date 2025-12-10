using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Global filter state singleton. Stores Include/Exclude criteria.
/// Version increments on every change for lazy per-tab evaluation.
/// Supports both flat filters (OR mode) and grouped filters (AND mode).
/// </summary>
public partial class GlobalFilterState : ObservableObject
{
    [ObservableProperty] private FilterMode _currentMode = FilterMode.Include;
    [ObservableProperty] private int _version;
    private int _nextGroupId = 1;

    /// <summary>
    /// Whether filtering is currently in progress (across any tab).
    /// UI binds to this for progress bar visibility.
    /// </summary>
    [ObservableProperty] private bool _isFilteringInProgress;

    /// <summary>
    /// Current filter progress (0.0 to 1.0).
    /// </summary>
    [ObservableProperty] private double _filterProgress;

    public FilterCriteria IncludeFilters { get; } = new();
    public FilterCriteria ExcludeFilters { get; } = new();

    /// <summary>AND-grouped include filters (each group = all criteria AND'd together)</summary>
    public ObservableCollection<FilterGroup> IncludeGroups { get; } = [];

    /// <summary>AND-grouped exclude filters (each group = all criteria AND'd together, then NOT)</summary>
    public ObservableCollection<FilterGroup> ExcludeGroups { get; } = [];

    public bool HasActiveFilters => IncludeFilters.HasAny || ExcludeFilters.HasAny ||
                                     IncludeGroups.Count > 0 || ExcludeGroups.Count > 0;

    /// <summary>
    /// Fired when filter state changes (add/remove). Used by UI to refresh chip display.
    /// Does NOT trigger filter re-application. Use OnFiltersApplied for that.
    /// </summary>
    public event Action? OnFilterChanged;

    /// <summary>
    /// Fired when user explicitly requests filter application (Apply/Clear buttons).
    /// ViewModels should subscribe to this to re-apply filters, NOT OnFilterChanged.
    /// </summary>
    public event Action? OnFiltersApplied;

    public void AddIncludeProtocol(string protocol)
    {
        IncludeFilters.Protocols.Add(protocol);
        IncrementVersion();
    }

    public void AddExcludeProtocol(string protocol)
    {
        ExcludeFilters.Protocols.Add(protocol);
        IncrementVersion();
    }

    public void AddIncludeIP(string ip)
    {
        IncludeFilters.IPs.Add(ip);
        IncrementVersion();
    }

    public void AddExcludeIP(string ip)
    {
        ExcludeFilters.IPs.Add(ip);
        IncrementVersion();
    }

    public void AddIncludePort(string port)
    {
        IncludeFilters.Ports.Add(port);
        IncrementVersion();
    }

    public void AddExcludePort(string port)
    {
        ExcludeFilters.Ports.Add(port);
        IncrementVersion();
    }

    public void AddIncludeQuickFilter(string filter)
    {
        IncludeFilters.QuickFilters.Add(filter);
        IncrementVersion();
    }

    public void AddExcludeQuickFilter(string filter)
    {
        ExcludeFilters.QuickFilters.Add(filter);
        IncrementVersion();
    }

    public void AddIncludeSeverity(string severity)
    {
        IncludeFilters.Severities.Add(severity);
        IncrementVersion();
    }

    public void AddExcludeSeverity(string severity)
    {
        ExcludeFilters.Severities.Add(severity);
        IncrementVersion();
    }

    public void AddIncludeThreatCategory(string category)
    {
        IncludeFilters.ThreatCategories.Add(category);
        IncrementVersion();
    }

    public void AddExcludeThreatCategory(string category)
    {
        ExcludeFilters.ThreatCategories.Add(category);
        IncrementVersion();
    }

    public void AddIncludeCodec(string codec)
    {
        IncludeFilters.Codecs.Add(codec);
        IncrementVersion();
    }

    public void AddExcludeCodec(string codec)
    {
        ExcludeFilters.Codecs.Add(codec);
        IncrementVersion();
    }

    public void AddIncludeQualityLevel(string quality)
    {
        IncludeFilters.QualityLevels.Add(quality);
        IncrementVersion();
    }

    public void AddExcludeQualityLevel(string quality)
    {
        ExcludeFilters.QualityLevels.Add(quality);
        IncrementVersion();
    }

    public void AddIncludeVoipIssue(string issue)
    {
        IncludeFilters.VoipIssues.Add(issue);
        IncrementVersion();
    }

    public void AddExcludeVoipIssue(string issue)
    {
        ExcludeFilters.VoipIssues.Add(issue);
        IncrementVersion();
    }

    public void SetJitterThreshold(string threshold)
    {
        IncludeFilters.JitterThreshold = threshold;
        IncrementVersion();
    }

    public void SetLatencyThreshold(string threshold)
    {
        IncludeFilters.LatencyThreshold = threshold;
        IncrementVersion();
    }

    public void AddIncludeCountry(string country)
    {
        IncludeFilters.Countries.Add(country);
        IncrementVersion();
    }

    public void AddExcludeCountry(string country)
    {
        ExcludeFilters.Countries.Add(country);
        IncrementVersion();
    }

    public void AddIncludeDirection(string direction)
    {
        IncludeFilters.Directions.Add(direction);
        IncrementVersion();
    }

    public void AddExcludeDirection(string direction)
    {
        ExcludeFilters.Directions.Add(direction);
        IncrementVersion();
    }

    public void AddIncludeRegion(string region)
    {
        IncludeFilters.Regions.Add(region);
        IncrementVersion();
    }

    public void AddExcludeRegion(string region)
    {
        ExcludeFilters.Regions.Add(region);
        IncrementVersion();
    }

    public void RemoveIncludeFilter(string value, FilterCategory category)
    {
        var removed = category switch
        {
            FilterCategory.Protocol => IncludeFilters.Protocols.Remove(value),
            FilterCategory.IP => IncludeFilters.IPs.Remove(value),
            FilterCategory.Port => IncludeFilters.Ports.Remove(value),
            FilterCategory.QuickFilter => IncludeFilters.QuickFilters.Remove(value),
            FilterCategory.Severity => IncludeFilters.Severities.Remove(value),
            FilterCategory.ThreatCategory => IncludeFilters.ThreatCategories.Remove(value),
            FilterCategory.TlsVersion => IncludeFilters.TlsVersions.Remove(value),
            FilterCategory.Country => IncludeFilters.Countries.Remove(value),
            FilterCategory.Codec => IncludeFilters.Codecs.Remove(value),
            FilterCategory.QualityLevel => IncludeFilters.QualityLevels.Remove(value),
            FilterCategory.VoipIssue => IncludeFilters.VoipIssues.Remove(value),
            FilterCategory.Direction => IncludeFilters.Directions.Remove(value),
            FilterCategory.Region => IncludeFilters.Regions.Remove(value),
            _ => false
        };
        if (removed) IncrementVersion();
    }

    public void RemoveExcludeFilter(string value, FilterCategory category)
    {
        var removed = category switch
        {
            FilterCategory.Protocol => ExcludeFilters.Protocols.Remove(value),
            FilterCategory.IP => ExcludeFilters.IPs.Remove(value),
            FilterCategory.Port => ExcludeFilters.Ports.Remove(value),
            FilterCategory.QuickFilter => ExcludeFilters.QuickFilters.Remove(value),
            FilterCategory.Severity => ExcludeFilters.Severities.Remove(value),
            FilterCategory.ThreatCategory => ExcludeFilters.ThreatCategories.Remove(value),
            FilterCategory.TlsVersion => ExcludeFilters.TlsVersions.Remove(value),
            FilterCategory.Country => ExcludeFilters.Countries.Remove(value),
            FilterCategory.Codec => ExcludeFilters.Codecs.Remove(value),
            FilterCategory.QualityLevel => ExcludeFilters.QualityLevels.Remove(value),
            FilterCategory.VoipIssue => ExcludeFilters.VoipIssues.Remove(value),
            FilterCategory.Direction => ExcludeFilters.Directions.Remove(value),
            FilterCategory.Region => ExcludeFilters.Regions.Remove(value),
            _ => false
        };
        if (removed) IncrementVersion();
    }

    public void Clear()
    {
        IncludeFilters.Clear();
        ExcludeFilters.Clear();
        IncludeGroups.Clear();
        ExcludeGroups.Clear();
        IncrementVersion();
    }

    /// <summary>
    /// Adds a filter group (AND-combined criteria) to include filters.
    /// </summary>
    public void AddIncludeGroup(FilterGroup group)
    {
        group.GroupId = _nextGroupId++;
        group.IsExcludeGroup = false;
        group.IsAndGroup = true;
        group.BuildDisplayLabel();
        IncludeGroups.Add(group);
        IncrementVersion();
    }

    /// <summary>
    /// Adds a filter group (AND-combined criteria) to exclude filters (NOT group).
    /// </summary>
    public void AddExcludeGroup(FilterGroup group)
    {
        group.GroupId = _nextGroupId++;
        group.IsExcludeGroup = true;
        group.IsAndGroup = true;
        group.BuildDisplayLabel();
        ExcludeGroups.Add(group);
        IncrementVersion();
    }

    /// <summary>
    /// Removes a filter group by its ID.
    /// </summary>
    public void RemoveGroup(int groupId, bool isExclude)
    {
        var collection = isExclude ? ExcludeGroups : IncludeGroups;
        var group = collection.FirstOrDefault(g => g.GroupId == groupId);
        if (group is not null)
        {
            collection.Remove(group);
            IncrementVersion();
        }
    }

    private void IncrementVersion()
    {
        Version++;
        OnFilterChanged?.Invoke();
    }

    /// <summary>
    /// Explicitly requests filter application. Call this when user clicks Apply button.
    /// Fires OnFiltersApplied to trigger ViewModels to re-apply filters.
    /// </summary>
    public void ApplyFilters()
    {
        OnFiltersApplied?.Invoke();
    }

    /// <summary>
    /// Clears all filters AND triggers re-application.
    /// Use this when user clicks Clear button (to show all data).
    /// </summary>
    public void ClearAndApply()
    {
        IncludeFilters.Clear();
        ExcludeFilters.Clear();
        IncludeGroups.Clear();
        ExcludeGroups.Clear();
        IncrementVersion();
        OnFiltersApplied?.Invoke();
    }

    // Anomaly filters (global scope - affects all tabs)
    [ObservableProperty]
    private List<AnomalySeverity> _anomalySeverityFilter = [];

    [ObservableProperty]
    private List<AnomalyCategory> _anomalyCategoryFilter = [];

    [ObservableProperty]
    private List<string> _anomalyDetectorFilter = [];

    /// <summary>
    /// Check if any anomaly filters are active.
    /// </summary>
    public bool HasAnomalyFilters =>
        AnomalySeverityFilter.Count > 0 ||
        AnomalyCategoryFilter.Count > 0 ||
        AnomalyDetectorFilter.Count > 0;

    /// <summary>
    /// Clear all anomaly-specific filters.
    /// </summary>
    public void ClearAnomalyFilters()
    {
        AnomalySeverityFilter = new List<AnomalySeverity>();
        AnomalyCategoryFilter = new List<AnomalyCategory>();
        AnomalyDetectorFilter = new List<string>();
    }
}

public enum FilterMode { Include, Exclude }

public enum FilterCategory { Protocol, IP, Port, QuickFilter, Severity, ThreatCategory, TlsVersion, Country, Codec, QualityLevel, VoipIssue, Direction, Region }

public class FilterCriteria
{
    public ObservableCollection<string> Protocols { get; } = [];
    public ObservableCollection<string> IPs { get; } = [];
    public ObservableCollection<string> Ports { get; } = [];
    public ObservableCollection<string> QuickFilters { get; } = [];
    public ObservableCollection<string> Severities { get; } = [];
    public ObservableCollection<string> ThreatCategories { get; } = [];
    public ObservableCollection<string> TlsVersions { get; } = [];
    public ObservableCollection<string> Countries { get; } = [];
    public ObservableCollection<string> Codecs { get; } = [];
    public ObservableCollection<string> QualityLevels { get; } = [];
    public ObservableCollection<string> VoipIssues { get; } = [];
    public ObservableCollection<string> Directions { get; } = [];
    public ObservableCollection<string> Regions { get; } = [];

    public string JitterThreshold { get; set; } = "";
    public string LatencyThreshold { get; set; } = "";

    public bool HasAny => Protocols.Count > 0 || IPs.Count > 0 || Ports.Count > 0 ||
                          QuickFilters.Count > 0 || Severities.Count > 0 ||
                          ThreatCategories.Count > 0 || TlsVersions.Count > 0 ||
                          Countries.Count > 0 || Codecs.Count > 0 ||
                          QualityLevels.Count > 0 || VoipIssues.Count > 0 ||
                          Directions.Count > 0 || Regions.Count > 0 ||
                          !string.IsNullOrWhiteSpace(JitterThreshold) ||
                          !string.IsNullOrWhiteSpace(LatencyThreshold);

    public void Clear()
    {
        Protocols.Clear();
        IPs.Clear();
        Ports.Clear();
        QuickFilters.Clear();
        Severities.Clear();
        ThreatCategories.Clear();
        TlsVersions.Clear();
        Countries.Clear();
        Codecs.Clear();
        QualityLevels.Clear();
        VoipIssues.Clear();
        Directions.Clear();
        Regions.Clear();
        JitterThreshold = "";
        LatencyThreshold = "";
    }
}
