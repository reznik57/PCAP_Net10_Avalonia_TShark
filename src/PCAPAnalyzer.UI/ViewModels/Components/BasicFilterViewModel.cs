using System;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Component responsible for basic filtering functionality.
/// Handles IP/CIDR filtering, port range filtering, protocol filtering, and NOT toggles.
/// </summary>
public partial class BasicFilterViewModel : ObservableObject
{
    // IP filtering
    [ObservableProperty] private string _ipFilterText = "";
    [ObservableProperty] private string _sourceIpCidrFilter = "";
    [ObservableProperty] private string _destIpCidrFilter = "";
    [ObservableProperty] private bool _notSourceIp;
    [ObservableProperty] private bool _notDestIp;

    // Port filtering
    [ObservableProperty] private string _portFilterText = "";
    [ObservableProperty] private string _sourcePortRangeFilter = "";
    [ObservableProperty] private string _destPortRangeFilter = "";
    [ObservableProperty] private bool _notSourcePort;
    [ObservableProperty] private bool _notDestPort;

    // Protocol filtering
    [ObservableProperty] private string _protocolFilterText = "";
    [ObservableProperty] private bool _notProtocol;

    // Global NOT toggle
    [ObservableProperty] private bool _useNotFilter;
    [ObservableProperty] private bool _useNotForAllFilters;

    // Combination mode
    [ObservableProperty] private bool _useAndMode = true;
    [ObservableProperty] private bool _useOrMode;

    /// <summary>
    /// Event raised when any filter property changes
    /// </summary>
    public event EventHandler? FilterChanged;

    /// <summary>
    /// Gets whether any basic filter is active
    /// </summary>
    public bool HasActiveFilters =>
        !string.IsNullOrWhiteSpace(IpFilterText) ||
        !string.IsNullOrWhiteSpace(SourceIpCidrFilter) ||
        !string.IsNullOrWhiteSpace(DestIpCidrFilter) ||
        !string.IsNullOrWhiteSpace(PortFilterText) ||
        !string.IsNullOrWhiteSpace(SourcePortRangeFilter) ||
        !string.IsNullOrWhiteSpace(DestPortRangeFilter) ||
        !string.IsNullOrWhiteSpace(ProtocolFilterText);

    /// <summary>
    /// Clears all basic filter values
    /// </summary>
    public void ClearAll()
    {
        IpFilterText = "";
        SourceIpCidrFilter = "";
        DestIpCidrFilter = "";
        PortFilterText = "";
        SourcePortRangeFilter = "";
        DestPortRangeFilter = "";
        ProtocolFilterText = "";

        NotSourceIp = false;
        NotDestIp = false;
        NotSourcePort = false;
        NotDestPort = false;
        NotProtocol = false;
        UseNotFilter = false;
        UseNotForAllFilters = false;

        DebugLogger.Log("[BasicFilterViewModel] Cleared all basic filters");
        FilterChanged?.Invoke(this, EventArgs.Empty);
    }

    /// <summary>
    /// Gets a description of active basic filters
    /// </summary>
    public string GetFilterDescription()
    {
        var parts = new System.Collections.Generic.List<string>();

        if (!string.IsNullOrWhiteSpace(IpFilterText))
            parts.Add($"IP: {IpFilterText}");

        if (!string.IsNullOrWhiteSpace(SourceIpCidrFilter))
            parts.Add($"Source IP/CIDR: {SourceIpCidrFilter}");

        if (!string.IsNullOrWhiteSpace(DestIpCidrFilter))
            parts.Add($"Dest IP/CIDR: {DestIpCidrFilter}");

        if (!string.IsNullOrWhiteSpace(PortFilterText))
            parts.Add($"Port: {PortFilterText}");

        if (!string.IsNullOrWhiteSpace(SourcePortRangeFilter))
            parts.Add($"Source Port: {SourcePortRangeFilter}");

        if (!string.IsNullOrWhiteSpace(DestPortRangeFilter))
            parts.Add($"Dest Port: {DestPortRangeFilter}");

        if (!string.IsNullOrWhiteSpace(ProtocolFilterText))
            parts.Add($"Protocol: {ProtocolFilterText}");

        if (parts.Count == 0)
            return "";

        var mode = UseAndMode ? "AND" : "OR";
        return $"{string.Join($" {mode} ", parts)}";
    }

    // Property change handlers to raise FilterChanged event
    partial void OnIpFilterTextChanged(string value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnSourceIpCidrFilterChanged(string value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnDestIpCidrFilterChanged(string value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnPortFilterTextChanged(string value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnSourcePortRangeFilterChanged(string value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnDestPortRangeFilterChanged(string value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnProtocolFilterTextChanged(string value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnNotSourceIpChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnNotDestIpChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnNotSourcePortChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnNotDestPortChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnNotProtocolChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnUseNotFilterChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);
    partial void OnUseNotForAllFiltersChanged(bool value) => FilterChanged?.Invoke(this, EventArgs.Empty);

    partial void OnUseAndModeChanged(bool value)
    {
        if (value)
            UseOrMode = false;
        FilterChanged?.Invoke(this, EventArgs.Empty);
    }

    partial void OnUseOrModeChanged(bool value)
    {
        if (value)
            UseAndMode = false;
        FilterChanged?.Invoke(this, EventArgs.Empty);
    }
}
