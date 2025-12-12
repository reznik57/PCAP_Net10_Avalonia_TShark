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
    [ObservableProperty] private string? _searchText;  // Global AND filter - matches any field
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

    // ==================== HOST INVENTORY TAB CRITERIA ====================
    [ObservableProperty] private List<string>? _osTypes;
    [ObservableProperty] private List<string>? _deviceTypes;
    [ObservableProperty] private List<string>? _hostRoles;

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
        HasVoiceQoSCriteria() || HasCountryCriteria() || HasHostInventoryCriteria();

    private bool HasGeneralCriteria() =>
        !string.IsNullOrWhiteSpace(SourceIP) || !string.IsNullOrWhiteSpace(DestinationIP) ||
        !string.IsNullOrWhiteSpace(PortRange) || !string.IsNullOrWhiteSpace(SearchText) ||
        !string.IsNullOrWhiteSpace(Protocol) || (QuickFilters?.Count > 0);

    private bool HasThreatsCriteria() =>
        (Severities?.Count > 0) || (ThreatCategories?.Count > 0);

    private bool HasAnomaliesCriteria() =>
        (AnomalySeverities?.Count > 0) || (AnomalyCategories?.Count > 0) || (AnomalyDetectors?.Count > 0);

    private bool HasVoiceQoSCriteria() =>
        (Codecs?.Count > 0) || (QualityLevels?.Count > 0) || (VoipIssues?.Count > 0) ||
        !string.IsNullOrWhiteSpace(JitterThreshold) || !string.IsNullOrWhiteSpace(LatencyThreshold);

    private bool HasCountryCriteria() =>
        (Countries?.Count > 0) || (Directions?.Count > 0) || (Regions?.Count > 0);

    private bool HasHostInventoryCriteria() =>
        (OsTypes?.Count > 0) || (DeviceTypes?.Count > 0) || (HostRoles?.Count > 0);

    /// <summary>
    /// Gets a list of all non-empty field descriptions for this group.
    /// Uses DOMAIN-BASED grouping: items in same domain use OR, different domains use AND.
    ///
    /// Domains:
    /// - IP Address: SourceIP, DestIP, Regions, Countries (all target IP addresses)
    /// - Direction: Inbound, Outbound, Internal (traffic flow)
    /// - Port: Port ranges
    /// - Protocol: L4/L7 protocols
    /// </summary>
    public List<string> GetFieldDescriptions()
    {
        var descriptions = new List<string>();

        // === IP ADDRESS DOMAIN: Group together SourceIP, DestIP, Regions, Countries ===
        var ipDomainParts = new List<string>();
        if (!string.IsNullOrWhiteSpace(SourceIP)) ipDomainParts.Add($"Src IP: {SourceIP}");
        if (!string.IsNullOrWhiteSpace(DestinationIP)) ipDomainParts.Add($"Dest IP: {DestinationIP}");
        if (Regions?.Count > 0) ipDomainParts.Add($"Region: {string.Join("/", Regions)}");
        if (Countries?.Count > 0) ipDomainParts.Add($"Country: {string.Join("/", Countries)}");

        if (ipDomainParts.Count > 0)
        {
            // If multiple IP-based filters, wrap in parentheses to show OR logic
            var ipDesc = ipDomainParts.Count > 1
                ? $"({string.Join(" OR ", ipDomainParts)})"
                : ipDomainParts[0];
            descriptions.Add(ipDesc);
        }

        // === DIRECTION DOMAIN ===
        if (Directions?.Count > 0)
            descriptions.Add($"Direction: {string.Join(" OR ", Directions)}");

        // === PORT DOMAIN ===
        if (!string.IsNullOrWhiteSpace(PortRange)) descriptions.Add($"Port: {PortRange}");

        // === SEARCH (Global AND filter) ===
        if (!string.IsNullOrWhiteSpace(SearchText)) descriptions.Add($"Search: \"{SearchText}\"");

        // === PROTOCOL DOMAIN ===
        if (!string.IsNullOrWhiteSpace(Protocol)) descriptions.Add($"Protocol: {Protocol}");

        // === QUICK FILTERS (shown separately, domain logic applied at filter time) ===
        if (QuickFilters?.Count > 0)
            descriptions.Add(string.Join(" OR ", QuickFilters));

        // === OTHER TAB-SPECIFIC CRITERIA ===
        AddThreatsDescriptions(descriptions);
        AddAnomaliesDescriptions(descriptions);
        AddVoiceQoSDescriptions(descriptions);
        AddHostInventoryDescriptions(descriptions);

        return descriptions;
    }

    private void AddThreatsDescriptions(List<string> descriptions)
    {
        // Each list field is OR'd within, then AND'd with other categories
        if (Severities?.Count > 0)
            descriptions.Add($"Severity: {string.Join(" OR ", Severities)}");
        if (ThreatCategories?.Count > 0)
            descriptions.Add($"Threat: {string.Join(" OR ", ThreatCategories)}");
    }

    private void AddAnomaliesDescriptions(List<string> descriptions)
    {
        if (AnomalySeverities?.Count > 0)
            descriptions.Add($"Anomaly Sev: {string.Join(" OR ", AnomalySeverities)}");
        if (AnomalyCategories?.Count > 0)
            descriptions.Add($"Anomaly Cat: {string.Join(" OR ", AnomalyCategories)}");
        if (AnomalyDetectors?.Count > 0)
            descriptions.Add($"Detector: {string.Join(" OR ", AnomalyDetectors)}");
    }

    private void AddVoiceQoSDescriptions(List<string> descriptions)
    {
        if (Codecs?.Count > 0)
            descriptions.Add($"Codec: {string.Join(" OR ", Codecs)}");
        if (QualityLevels?.Count > 0)
            descriptions.Add($"Quality: {string.Join(" OR ", QualityLevels)}");
        if (VoipIssues?.Count > 0)
            descriptions.Add($"Issue: {string.Join(" OR ", VoipIssues)}");

        // Single-value thresholds
        if (!string.IsNullOrWhiteSpace(JitterThreshold)) descriptions.Add($"Jitter: >{JitterThreshold}ms");
        if (!string.IsNullOrWhiteSpace(LatencyThreshold)) descriptions.Add($"Latency: >{LatencyThreshold}ms");
    }

    private void AddHostInventoryDescriptions(List<string> descriptions)
    {
        if (OsTypes?.Count > 0)
            descriptions.Add($"OS: {string.Join(" OR ", OsTypes)}");
        if (DeviceTypes?.Count > 0)
            descriptions.Add($"Device: {string.Join(" OR ", DeviceTypes)}");
        if (HostRoles?.Count > 0)
            descriptions.Add($"Role: {string.Join(" OR ", HostRoles)}");
    }

    /// <summary>
    /// Builds and sets the DisplayLabel based on populated filter fields.
    /// Uses DOMAIN-BASED grouping:
    /// - Items within the same domain use OR logic (e.g., "Src IP OR Country")
    /// - Different domains use AND logic (e.g., "(IP-domain) AND Port")
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

        // Domains are AND'd together (each domain internally uses OR)
        DisplayLabel = string.Join(" AND ", descriptions);
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
    public (List<string>? Countries, List<string>? Regions, List<string>? Directions)? GetCountryCriteria()
    {
        if ((Countries?.Count ?? 0) == 0 && (Regions?.Count ?? 0) == 0 && (Directions?.Count ?? 0) == 0)
            return null;
        return (Countries, Regions, Directions);
    }
}
