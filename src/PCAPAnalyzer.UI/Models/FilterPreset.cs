using System;
using System.Diagnostics.CodeAnalysis;

namespace PCAPAnalyzer.UI.Models;

/// <summary>
/// Represents a saved filter preset for the Dashboard tab.
/// Stores all 38+ smart filter toggle states for quick recall.
/// </summary>
public record FilterPreset
{
    /// <summary>
    /// User-defined name for the preset (e.g., "Security Audit", "VPN Traffic")
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Description of what this preset filters for
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Whether this is a built-in preset (cannot be deleted or modified)
    /// </summary>
    public bool IsBuiltIn { get; init; }

    /// <summary>
    /// Timestamp when preset was created
    /// </summary>
    public DateTime CreatedAt { get; init; } = DateTime.Now;

    /// <summary>
    /// Timestamp when preset was last modified
    /// </summary>
    public DateTime LastModified { get; init; } = DateTime.Now;

    // ==================== FILTER LOGIC CONTROLS ====================
    public bool FilterUseAndMode { get; init; } = true;
    public bool FilterUseNotMode { get; init; }

    // ==================== NETWORK TYPE FILTERS ====================
    public bool FilterRfc1918Toggle { get; init; }
    public bool FilterPublicIpToggle { get; init; }
    public bool FilterApipaToggle { get; init; }
    public bool FilterIPv4Toggle { get; init; }
    public bool FilterIPv6Toggle { get; init; }

    // ==================== TRAFFIC TYPE FILTERS ====================
    public bool FilterMulticastToggle { get; init; }
    public bool FilterBroadcastToggle { get; init; }
    public bool FilterAnycastToggle { get; init; }

    // ==================== SECURITY FILTERS ====================
    public bool FilterInsecureToggle { get; init; }
    public bool FilterAnomaliesToggle { get; init; }

    // ==================== L7 PROTOCOL FILTERS ====================
    public bool FilterTlsV10Toggle { get; init; }
    public bool FilterTlsV11Toggle { get; init; }
    public bool FilterTlsV12Toggle { get; init; }
    public bool FilterTlsV13Toggle { get; init; }
    public bool FilterHttpToggle { get; init; }
    public bool FilterHttpsToggle { get; init; }
    public bool FilterDnsToggle { get; init; }
    public bool FilterSnmpToggle { get; init; }
    public bool FilterSshToggle { get; init; }
    public bool FilterFtpToggle { get; init; }
    public bool FilterSmtpToggle { get; init; }
    public bool FilterStunToggle { get; init; }
    public bool FilterDhcpServerToggle { get; init; }

    // ==================== VPN PROTOCOL FILTERS ====================
    public bool FilterWireGuardToggle { get; init; }
    public bool FilterOpenVpnToggle { get; init; }
    public bool FilterIkeV2Toggle { get; init; }
    public bool FilterIpsecToggle { get; init; }
    public bool FilterL2tpToggle { get; init; }
    public bool FilterPptpToggle { get; init; }

    // ==================== ADDITIONAL FILTERS ====================
    public bool FilterJumboFramesToggle { get; init; }
    public bool FilterPrivateToPublicToggle { get; init; }
    public bool FilterPublicToPrivateToggle { get; init; }
    public bool FilterLinkLocalToggle { get; init; }
    public bool FilterLoopbackToggle { get; init; }
    public bool FilterSuspiciousToggle { get; init; }
    public bool FilterTcpIssuesToggle { get; init; }
    public bool FilterDnsAnomaliesToggle { get; init; }
    public bool FilterPortScansToggle { get; init; }

    /// <summary>
    /// Check if any filters are active in this preset
    /// </summary>
    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity", Justification = "Filter aggregation requires checking all 38 filter flags - complexity is inherent to the domain")]
    public bool HasActiveFilters =>
        FilterRfc1918Toggle || FilterPublicIpToggle || FilterApipaToggle || FilterIPv4Toggle || FilterIPv6Toggle ||
        FilterMulticastToggle || FilterBroadcastToggle || FilterAnycastToggle ||
        FilterInsecureToggle || FilterAnomaliesToggle ||
        FilterTlsV10Toggle || FilterTlsV11Toggle || FilterTlsV12Toggle || FilterTlsV13Toggle ||
        FilterHttpToggle || FilterHttpsToggle || FilterDnsToggle || FilterSnmpToggle || FilterSshToggle ||
        FilterFtpToggle || FilterSmtpToggle || FilterStunToggle || FilterDhcpServerToggle ||
        FilterWireGuardToggle || FilterOpenVpnToggle || FilterIkeV2Toggle || FilterIpsecToggle ||
        FilterL2tpToggle || FilterPptpToggle ||
        FilterJumboFramesToggle || FilterPrivateToPublicToggle || FilterPublicToPrivateToggle ||
        FilterLinkLocalToggle || FilterLoopbackToggle || FilterSuspiciousToggle ||
        FilterTcpIssuesToggle || FilterDnsAnomaliesToggle || FilterPortScansToggle;

    /// <summary>
    /// Display text for preset (shows built-in indicator)
    /// </summary>
    public string DisplayName => IsBuiltIn ? $"{Name} (Built-in)" : Name;
}
