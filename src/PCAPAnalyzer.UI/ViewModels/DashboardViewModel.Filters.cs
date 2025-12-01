using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// DashboardViewModel partial - Smart Filter Helper Methods
/// Delegates to centralized NetworkFilterHelper for consistency.
/// </summary>
public partial class DashboardViewModel
{
    /// <summary>
    /// Applies filters from GlobalFilterState to Dashboard packets.
    /// Converts GlobalFilterState criteria to PacketFilter and triggers ApplySmartFilter.
    /// </summary>
    public void ApplyGlobalFilters()
    {
        if (_globalFilterState == null)
        {
            DebugLogger.Log("[DashboardViewModel] GlobalFilterState not available");
            return;
        }

        DebugLogger.Log("[DashboardViewModel] Applying global filters from UnifiedFilterPanel");

        // Build list of filters to combine
        var filters = new List<PacketFilter>();

        // Process Include filters
        var includeFilters = BuildFiltersFromCriteria(_globalFilterState.IncludeFilters, isExclude: false);
        if (includeFilters.Count > 0)
        {
            filters.Add(CombineFiltersWithOr(includeFilters));
        }

        // Process Exclude filters
        var excludeFilters = BuildFiltersFromCriteria(_globalFilterState.ExcludeFilters, isExclude: true);
        if (excludeFilters.Count > 0)
        {
            // Combine exclude filters with OR, then invert
            var excludeOr = CombineFiltersWithOr(excludeFilters);
            var invertedExclude = InvertFilter(excludeOr);
            filters.Add(invertedExclude);
        }

        // Combine include and exclude filters
        PacketFilter? finalFilter = null;
        if (filters.Count == 1)
        {
            finalFilter = filters[0];
        }
        else if (filters.Count == 2)
        {
            // AND combination: INCLUDE AND NOT(EXCLUDE)
            finalFilter = CombineFiltersWithAnd(filters);
        }
        else
        {
            finalFilter = new PacketFilter(); // Empty filter
        }

        // Apply the filter using existing infrastructure
        if (finalFilter != null)
        {
            ApplySmartFilter(finalFilter);
            DebugLogger.Log($"[DashboardViewModel] Global filters applied (IsEmpty={finalFilter.IsEmpty})");
        }
    }

    /// <summary>
    /// Builds list of PacketFilters from FilterCriteria
    /// </summary>
    private List<PacketFilter> BuildFiltersFromCriteria(Models.FilterCriteria criteria, bool isExclude)
    {
        var filters = new List<PacketFilter>();

        // Protocol filters
        foreach (var protocol in criteria.Protocols)
        {
            filters.Add(new PacketFilter
            {
                CustomPredicate = p => p.Protocol.ToString().Equals(protocol, System.StringComparison.OrdinalIgnoreCase) ||
                                      (p.L7Protocol?.Equals(protocol, System.StringComparison.OrdinalIgnoreCase) ?? false),
                Description = $"{(isExclude ? "Exclude" : "Include")} Protocol: {protocol}"
            });
        }

        // IP filters
        foreach (var ip in criteria.IPs)
        {
            filters.Add(new PacketFilter
            {
                CustomPredicate = p => p.SourceIP == ip || p.DestinationIP == ip,
                Description = $"{(isExclude ? "Exclude" : "Include")} IP: {ip}"
            });
        }

        // Port filters
        foreach (var port in criteria.Ports)
        {
            if (int.TryParse(port, out var portNum))
            {
                filters.Add(new PacketFilter
                {
                    CustomPredicate = p => p.SourcePort == portNum || p.DestinationPort == portNum,
                    Description = $"{(isExclude ? "Exclude" : "Include")} Port: {port}"
                });
            }
        }

        // QuickFilters (special filters like "TCP", "UDP", "Encrypted", etc.)
        foreach (var qf in criteria.QuickFilters)
        {
            var predicate = BuildQuickFilterPredicate(qf);
            if (predicate != null)
            {
                filters.Add(new PacketFilter
                {
                    CustomPredicate = predicate,
                    Description = $"{(isExclude ? "Exclude" : "Include")} {qf}"
                });
            }
        }

        // TODO: Country filters require GeoIP enrichment - implement after statistics enhancement
        // For now, country filtering is not supported in GlobalFilterState

        return filters;
    }

    /// <summary>
    /// Builds predicate for QuickFilter strings
    /// </summary>
    private System.Func<PacketInfo, bool>? BuildQuickFilterPredicate(string quickFilter)
    {
        return quickFilter.ToUpperInvariant() switch
        {
            "TCP" => p => p.Protocol == Protocol.TCP,
            "UDP" => p => p.Protocol == Protocol.UDP,
            "ICMP" => p => p.Protocol == Protocol.ICMP,
            "ENCRYPTED" => p => p.L7Protocol?.Contains("TLS", System.StringComparison.OrdinalIgnoreCase) ?? false,
            "PRIVATE" => p => IsPrivateIP(p.SourceIP) || IsPrivateIP(p.DestinationIP),
            "PUBLIC" => p => !IsPrivateIP(p.SourceIP) || !IsPrivateIP(p.DestinationIP),
            _ => null
        };
    }

    /// <summary>
    /// Combines filters with OR logic
    /// </summary>
    private PacketFilter CombineFiltersWithOr(List<PacketFilter> filters)
    {
        if (filters.Count == 0) return new PacketFilter();
        if (filters.Count == 1) return filters[0];

        return new PacketFilter
        {
            CombinedFilters = filters,
            CombineMode = FilterCombineMode.Or,
            Description = $"OR({string.Join(", ", filters.Select(f => f.Description))})"
        };
    }

    /// <summary>
    /// Combines filters with AND logic
    /// </summary>
    private PacketFilter CombineFiltersWithAnd(List<PacketFilter> filters)
    {
        if (filters.Count == 0) return new PacketFilter();
        if (filters.Count == 1) return filters[0];

        return new PacketFilter
        {
            CombinedFilters = filters,
            CombineMode = FilterCombineMode.And,
            Description = $"AND({string.Join(", ", filters.Select(f => f.Description))})"
        };
    }

    /// <summary>
    /// Inverts a filter (NOT operation)
    /// </summary>
    private PacketFilter InvertFilter(PacketFilter filter)
    {
        return new PacketFilter
        {
            CustomPredicate = p => !filter.MatchesPacket(p),
            Description = $"NOT({filter.Description})"
        };
    }
    // ==================== TAB-SPECIFIC QUICK FILTER OVERRIDES ====================

    /// <summary>
    /// Returns ONLY Dashboard-specific filter mappings for chip creation.
    /// These are L7 protocols, TLS versions, and VPN protocols that don't exist in NetworkQuickFilters.
    ///
    /// ARCHITECTURE NOTE:
    /// - Shared filters (Network, Security, Traffic, TCP Perf, etc.) are handled by the
    ///   base class GetActiveQuickFilterMappings() which reads from NetworkQuickFilters.
    /// - This method returns ONLY Dashboard-specific filters to avoid duplicate chips.
    /// </summary>
    protected override List<(string DisplayName, string CodeName)> GetTabSpecificQuickFilterMappings()
    {
        var result = new List<(string, string)>();

        // ==================== L7 PROTOCOL FILTERS (Dashboard-only) ====================
        if (FilterTlsV10Toggle) result.Add(("TLS 1.0", "TlsV10"));
        if (FilterTlsV11Toggle) result.Add(("TLS 1.1", "TlsV11"));
        if (FilterTlsV12Toggle) result.Add(("TLS 1.2", "TlsV12"));
        if (FilterTlsV13Toggle) result.Add(("TLS 1.3", "TlsV13"));
        if (FilterHttpToggle) result.Add(("HTTP", "HTTP"));
        if (FilterHttpsToggle) result.Add(("HTTPS", "HTTPS"));
        if (FilterDnsToggle) result.Add(("DNS", "DNS"));
        if (FilterSnmpToggle) result.Add(("SNMP", "SNMP"));
        if (FilterSshToggle) result.Add(("SSH", "SSH"));
        if (FilterFtpToggle) result.Add(("FTP", "FTP"));
        if (FilterSmtpToggle) result.Add(("SMTP", "SMTP"));
        if (FilterStunToggle) result.Add(("STUN", "STUN"));
        if (FilterDhcpServerToggle) result.Add(("DHCP", "DHCP"));

        // ==================== VPN PROTOCOL FILTERS (Dashboard-only) ====================
        if (FilterWireGuardToggle) result.Add(("WireGuard", "WireGuard"));
        if (FilterOpenVpnToggle) result.Add(("OpenVPN", "OpenVPN"));
        if (FilterIkeV2Toggle) result.Add(("IKEv2", "IKEv2"));
        if (FilterIpsecToggle) result.Add(("IPSec", "IPSec"));
        if (FilterL2tpToggle) result.Add(("L2TP", "L2TP"));
        if (FilterPptpToggle) result.Add(("PPTP", "PPTP"));

        return result;
    }

    /// <summary>
    /// Untoggles Dashboard-specific filters only.
    /// Returns true if the filter was handled, false to let base class handle it.
    /// </summary>
    protected override bool UnToggleTabSpecificFilter(string codeName)
    {
        switch (codeName)
        {
            // L7 Protocol Filters (Dashboard-only)
            case "TlsV10": FilterTlsV10Toggle = false; return true;
            case "TlsV11": FilterTlsV11Toggle = false; return true;
            case "TlsV12": FilterTlsV12Toggle = false; return true;
            case "TlsV13": FilterTlsV13Toggle = false; return true;
            case "HTTP": FilterHttpToggle = false; return true;
            case "HTTPS": FilterHttpsToggle = false; return true;
            case "DNS": FilterDnsToggle = false; return true;
            case "SNMP": FilterSnmpToggle = false; return true;
            case "SSH": FilterSshToggle = false; return true;
            case "FTP": FilterFtpToggle = false; return true;
            case "SMTP": FilterSmtpToggle = false; return true;
            case "STUN": FilterStunToggle = false; return true;
            case "DHCP": FilterDhcpServerToggle = false; return true;

            // VPN Protocol Filters (Dashboard-only)
            case "WireGuard": FilterWireGuardToggle = false; return true;
            case "OpenVPN": FilterOpenVpnToggle = false; return true;
            case "IKEv2": FilterIkeV2Toggle = false; return true;
            case "IPSec": FilterIpsecToggle = false; return true;
            case "L2TP": FilterL2tpToggle = false; return true;
            case "PPTP": FilterPptpToggle = false; return true;

            // Shared filters are handled by base class UnToggleQuickFilter()
            default: return false;
        }
    }

    // ==================== SMART FILTER HELPER METHODS ====================
    // All methods delegate to centralized NetworkFilterHelper for consistency

    private static bool IsRFC1918(string ip) => NetworkFilterHelper.IsRFC1918(ip);

    private static bool IsPrivateIP(string ip) =>
        NetworkFilterHelper.IsRFC1918(ip) ||
        NetworkFilterHelper.IsLoopback(ip) ||
        NetworkFilterHelper.IsLinkLocal(ip);

    private static bool IsAPIPA(string ip) => NetworkFilterHelper.IsLinkLocal(ip);

    private static bool IsIPv4(string ip) => NetworkFilterHelper.IsIPv4(ip);

    private static bool IsIPv6(string ip) => NetworkFilterHelper.IsIPv6(ip);

    private static bool IsMulticast(string ip) => NetworkFilterHelper.IsMulticast(ip);

    private static bool IsBroadcast(string ip) => NetworkFilterHelper.IsBroadcast(ip);

    private static bool IsAnycast(string ip) => NetworkFilterHelper.IsAnycast(ip);

    private static bool IsInsecureProtocol(PacketInfo p) =>
        NetworkFilterHelper.IsInsecureProtocol(p.L7Protocol ?? p.Protocol.ToString());
}
