using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Represents a grouped filter with AND logic between all fields.
/// Used when user selects AND mode and clicks Apply - creates a single chip with all active fields.
/// Example: "Dest IP: 8.8.8.8 AND Port: 53"
/// </summary>
public partial class FilterGroup : ObservableObject
{
    /// <summary>Unique identifier for this filter group</summary>
    [ObservableProperty]
    private int _groupId;

    /// <summary>Display label shown in the chip (e.g., "Dest IP: 8.8.8.8 AND Port: 53")</summary>
    [ObservableProperty]
    private string _displayLabel = string.Empty;

    /// <summary>True if this is an AND group, false if individual OR chips</summary>
    [ObservableProperty]
    private bool _isAndGroup;

    /// <summary>True if this is a NOT/EXCLUDE group</summary>
    [ObservableProperty]
    private bool _isExcludeGroup;

    // ==================== GENERAL TAB CRITERIA ====================
    [ObservableProperty] private string? _sourceIP;
    [ObservableProperty] private string? _destinationIP;
    [ObservableProperty] private string? _portRange;
    [ObservableProperty] private string? _protocol;
    [ObservableProperty] private List<string>? _quickFilters;

    // ==================== THREATS TAB CRITERIA ====================
    [ObservableProperty] private List<string>? _severities;
    [ObservableProperty] private List<string>? _threatCategories;

    // ==================== ANOMALIES TAB CRITERIA ====================
    [ObservableProperty] private List<string>? _anomalySeverities;
    [ObservableProperty] private List<string>? _anomalyCategories;
    [ObservableProperty] private List<string>? _anomalyDetectors;

    // ==================== VOICEQOS TAB CRITERIA ====================
    [ObservableProperty] private List<string>? _codecs;
    [ObservableProperty] private List<string>? _qualityLevels;
    [ObservableProperty] private List<string>? _voipIssues;
    [ObservableProperty] private string? _jitterThreshold;
    [ObservableProperty] private string? _latencyThreshold;

    // ==================== COUNTRY TAB CRITERIA ====================
    [ObservableProperty] private List<string>? _countries;
    [ObservableProperty] private List<string>? _directions;
    [ObservableProperty] private List<string>? _regions;

    /// <summary>Command to remove this entire filter group</summary>
    public IRelayCommand? RemoveCommand { get; set; }

    public FilterGroup()
    {
    }

    public FilterGroup(int groupId, string displayLabel, bool isAndGroup, bool isExcludeGroup)
    {
        GroupId = groupId;
        DisplayLabel = displayLabel;
        IsAndGroup = isAndGroup;
        IsExcludeGroup = isExcludeGroup;
    }

    /// <summary>
    /// Checks if this filter group has any populated criteria
    /// </summary>
    public bool HasCriteria() =>
        HasGeneralCriteria() || HasThreatsCriteria() || HasAnomaliesCriteria() ||
        HasVoiceQoSCriteria() || HasCountryCriteria();

    private bool HasGeneralCriteria() =>
        !string.IsNullOrWhiteSpace(SourceIP) || !string.IsNullOrWhiteSpace(DestinationIP) ||
        !string.IsNullOrWhiteSpace(PortRange) || !string.IsNullOrWhiteSpace(Protocol) ||
        (QuickFilters?.Count > 0);

    private bool HasThreatsCriteria() =>
        (Severities?.Count > 0) || (ThreatCategories?.Count > 0);

    private bool HasAnomaliesCriteria() =>
        (AnomalySeverities?.Count > 0) || (AnomalyCategories?.Count > 0) || (AnomalyDetectors?.Count > 0);

    private bool HasVoiceQoSCriteria() =>
        (Codecs?.Count > 0) || (QualityLevels?.Count > 0) || (VoipIssues?.Count > 0) ||
        !string.IsNullOrWhiteSpace(JitterThreshold) || !string.IsNullOrWhiteSpace(LatencyThreshold);

    private bool HasCountryCriteria() =>
        (Countries?.Count > 0) || (Directions?.Count > 0) || (Regions?.Count > 0);

    /// <summary>
    /// Gets a list of all non-empty field descriptions for this group
    /// </summary>
    public List<string> GetFieldDescriptions()
    {
        var descriptions = new List<string>();
        AddGeneralDescriptions(descriptions);
        AddThreatsDescriptions(descriptions);
        AddAnomaliesDescriptions(descriptions);
        AddVoiceQoSDescriptions(descriptions);
        AddCountryDescriptions(descriptions);
        return descriptions;
    }

    private void AddGeneralDescriptions(List<string> descriptions)
    {
        if (!string.IsNullOrWhiteSpace(SourceIP)) descriptions.Add($"Src IP: {SourceIP}");
        if (!string.IsNullOrWhiteSpace(DestinationIP)) descriptions.Add($"Dest IP: {DestinationIP}");
        if (!string.IsNullOrWhiteSpace(PortRange)) descriptions.Add($"Port: {PortRange}");
        if (!string.IsNullOrWhiteSpace(Protocol)) descriptions.Add($"Protocol: {Protocol}");
        if (QuickFilters?.Count > 0) descriptions.AddRange(QuickFilters);
    }

    private void AddThreatsDescriptions(List<string> descriptions)
    {
        if (Severities?.Count > 0) descriptions.AddRange(Severities.Select(s => $"Severity: {s}"));
        if (ThreatCategories?.Count > 0) descriptions.AddRange(ThreatCategories.Select(c => $"Threat: {c}"));
    }

    private void AddAnomaliesDescriptions(List<string> descriptions)
    {
        if (AnomalySeverities?.Count > 0) descriptions.AddRange(AnomalySeverities.Select(s => $"Anomaly Sev: {s}"));
        if (AnomalyCategories?.Count > 0) descriptions.AddRange(AnomalyCategories.Select(c => $"Anomaly Cat: {c}"));
        if (AnomalyDetectors?.Count > 0) descriptions.AddRange(AnomalyDetectors.Select(d => $"Detector: {d}"));
    }

    private void AddVoiceQoSDescriptions(List<string> descriptions)
    {
        if (Codecs?.Count > 0) descriptions.AddRange(Codecs.Select(c => $"Codec: {c}"));
        if (QualityLevels?.Count > 0) descriptions.AddRange(QualityLevels.Select(q => $"Quality: {q}"));
        if (VoipIssues?.Count > 0) descriptions.AddRange(VoipIssues.Select(i => $"Issue: {i}"));
        if (!string.IsNullOrWhiteSpace(JitterThreshold)) descriptions.Add($"Jitter: >{JitterThreshold}ms");
        if (!string.IsNullOrWhiteSpace(LatencyThreshold)) descriptions.Add($"Latency: >{LatencyThreshold}ms");
    }

    private void AddCountryDescriptions(List<string> descriptions)
    {
        if (Countries?.Count > 0) descriptions.AddRange(Countries.Select(c => $"Country: {c}"));
        if (Directions?.Count > 0) descriptions.AddRange(Directions.Select(d => $"Direction: {d}"));
        if (Regions?.Count > 0) descriptions.AddRange(Regions.Select(r => $"Region: {r}"));
    }

    /// <summary>
    /// Builds and sets the DisplayLabel based on populated filter fields.
    /// Should be called after setting filter properties.
    /// </summary>
    public void BuildDisplayLabel()
    {
        var descriptions = GetFieldDescriptions();

        if (descriptions.Count == 0)
        {
            DisplayLabel = "(empty filter)";
            return;
        }

        // Join with " AND " for AND groups, ", " for OR mode
        var separator = IsAndGroup ? " AND " : ", ";
        DisplayLabel = string.Join(separator, descriptions);
    }

    // ==================== TAB-SPECIFIC CRITERIA EXTRACTION ====================

    /// <summary>
    /// Extracts threat-specific filter criteria from this group.
    /// Returns null if no threat criteria are set.
    /// </summary>
    public (List<string>? Severities, List<string>? Categories)? GetThreatCriteria()
    {
        if ((Severities?.Count ?? 0) == 0 && (ThreatCategories?.Count ?? 0) == 0)
            return null;
        return (Severities, ThreatCategories);
    }

    /// <summary>
    /// Extracts VoiceQoS-specific filter criteria from this group.
    /// Returns null if no VoiceQoS criteria are set.
    /// </summary>
    public (List<string>? Codecs, List<string>? Qualities, List<string>? Issues)? GetVoiceQoSCriteria()
    {
        if ((Codecs?.Count ?? 0) == 0 && (QualityLevels?.Count ?? 0) == 0 && (VoipIssues?.Count ?? 0) == 0)
            return null;
        return (Codecs, QualityLevels, VoipIssues);
    }

    /// <summary>
    /// Extracts country-specific filter criteria from this group.
    /// Returns null if no country criteria are set.
    /// </summary>
    public (List<string>? Countries, List<string>? Regions)? GetCountryCriteria()
    {
        if ((Countries?.Count ?? 0) == 0 && (Regions?.Count ?? 0) == 0)
            return null;
        return (Countries, Regions);
    }
}
