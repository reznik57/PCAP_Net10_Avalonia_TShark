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
    ///
    /// Filter Logic:
    /// - FilterGroups: All fields within group are AND'd together
    /// - Flat filters: OR within category, AND between categories
    /// - Include vs Exclude: INCLUDE AND NOT(EXCLUDE)
    /// </summary>
    public void ApplyGlobalFilters()
    {
        if (_globalFilterState is null)
        {
            DebugLogger.Log("[DashboardViewModel] GlobalFilterState not available");
            return;
        }

        DebugLogger.Log("[DashboardViewModel] Applying global filters from UnifiedFilterPanel");

        var includeFilters = new List<PacketFilter>();
        var excludeFilters = new List<PacketFilter>();

        // Process FilterGroups (each group = all criteria AND'd together)
        foreach (var group in _globalFilterState.IncludeGroups)
        {
            var groupFilter = BuildFilterFromGroup(group);
            if (groupFilter is not null)
            {
                includeFilters.Add(groupFilter);
                DebugLogger.Log($"[DashboardViewModel] Include group filter: {groupFilter.Description}");
            }
        }

        foreach (var group in _globalFilterState.ExcludeGroups)
        {
            var groupFilter = BuildFilterFromGroup(group);
            if (groupFilter is not null)
            {
                excludeFilters.Add(groupFilter);
                DebugLogger.Log($"[DashboardViewModel] Exclude group filter: {groupFilter.Description}");
            }
        }

        // Process flat filters (legacy - OR within category, AND between categories)
        var flatIncludeFilter = BuildGroupedFilters(_globalFilterState.IncludeFilters, isExclude: false);
        if (flatIncludeFilter is not null)
        {
            includeFilters.Add(flatIncludeFilter);
            DebugLogger.Log($"[DashboardViewModel] Include flat filter: {flatIncludeFilter.Description}");
        }

        var flatExcludeFilter = BuildGroupedFilters(_globalFilterState.ExcludeFilters, isExclude: true);
        if (flatExcludeFilter is not null)
        {
            excludeFilters.Add(flatExcludeFilter);
        }

        // Combine all include filters with OR (any group can match)
        PacketFilter? includeFilter = includeFilters.Count switch
        {
            0 => null,
            1 => includeFilters[0],
            _ => CombineFiltersWithOr(includeFilters, "Include")
        };

        // Combine all exclude filters with OR (any group to exclude)
        PacketFilter? excludeFilter = excludeFilters.Count switch
        {
            0 => null,
            1 => excludeFilters[0],
            _ => CombineFiltersWithOr(excludeFilters, "Exclude")
        };

        // Combine: INCLUDE AND NOT(EXCLUDE)
        var filters = new List<PacketFilter>();
        if (includeFilter is not null)
        {
            filters.Add(includeFilter);
            DebugLogger.Log($"[DashboardViewModel] Include filter: {includeFilter.Description}");
        }

        if (excludeFilter is not null)
        {
            var invertedExclude = InvertFilter(excludeFilter);
            filters.Add(invertedExclude);
            DebugLogger.Log($"[DashboardViewModel] Exclude filter (inverted): {invertedExclude.Description}");
        }

        PacketFilter? finalFilter = null;
        if (filters.Count == 0)
        {
            finalFilter = new PacketFilter(); // Empty filter - show all
        }
        else if (filters.Count == 1)
        {
            finalFilter = filters[0];
        }
        else
        {
            finalFilter = CombineFiltersWithAnd(filters);
        }

        // Apply the filter using existing infrastructure
        ApplySmartFilter(finalFilter);
        DebugLogger.Log($"[DashboardViewModel] Global filters applied (IsEmpty={finalFilter.IsEmpty})");
    }

    /// <summary>
    /// Builds a PacketFilter from a FilterGroup (all criteria AND'd together).
    /// </summary>
    private PacketFilter? BuildFilterFromGroup(Models.FilterGroup group)
    {
        var groupFilters = new List<PacketFilter>();

        // ==================== GENERAL TAB ====================

        // Source IP
        if (!string.IsNullOrWhiteSpace(group.SourceIP))
        {
            var srcIp = group.SourceIP;
            groupFilters.Add(new PacketFilter
            {
                CustomPredicate = p => MatchesIpOrCidr(p.SourceIP, srcIp),
                Description = $"Src IP: {srcIp}"
            });
        }

        // Destination IP
        if (!string.IsNullOrWhiteSpace(group.DestinationIP))
        {
            var destIp = group.DestinationIP;
            groupFilters.Add(new PacketFilter
            {
                CustomPredicate = p => MatchesIpOrCidr(p.DestinationIP, destIp),
                Description = $"Dest IP: {destIp}"
            });
        }

        // Port Range
        if (!string.IsNullOrWhiteSpace(group.PortRange) && TryParsePortOrRange(group.PortRange, out var portPredicate))
        {
            groupFilters.Add(new PacketFilter
            {
                CustomPredicate = portPredicate,
                Description = $"Port: {group.PortRange}"
            });
        }

        // Protocol(s) - may be comma-separated
        if (!string.IsNullOrWhiteSpace(group.Protocol))
        {
            var protocols = group.Protocol.Split(',', StringSplitOptions.RemoveEmptyEntries);
            var protocolFilters = protocols.Select(proto =>
            {
                var p = proto.Trim();
                return new PacketFilter
                {
                    CustomPredicate = pkt => pkt.Protocol.ToString().Equals(p, StringComparison.OrdinalIgnoreCase) ||
                                             (pkt.L7Protocol?.Equals(p, StringComparison.OrdinalIgnoreCase) ?? false),
                    Description = p
                };
            }).ToList();

            if (protocolFilters.Count == 1)
                groupFilters.Add(protocolFilters[0]);
            else if (protocolFilters.Count > 1)
                groupFilters.Add(CombineFiltersWithOr(protocolFilters, "Protocol"));
        }

        // QuickFilters (Insecure, Anomalies, TCP Issues, etc.)
        if (group.QuickFilters?.Count > 0)
        {
            var quickFilterPredicates = group.QuickFilters
                .Select(qf => BuildQuickFilterPredicate(qf))
                .Where(p => p is not null)
                .ToList();

            if (quickFilterPredicates.Count > 0)
            {
                var quickFilters = quickFilterPredicates.Select((pred, i) => new PacketFilter
                {
                    CustomPredicate = pred!,
                    Description = group.QuickFilters[i]
                }).ToList();

                groupFilters.Add(CombineFiltersWithOr(quickFilters, "QuickFilter"));
            }
        }

        // ==================== COUNTRY TAB ====================

        // Countries - Note: Country info requires GeoIP lookup per-packet.
        // For now, country filtering is applied at the CountryTrafficViewModel level
        // where GeoIP-enriched statistics are available.
        // The filter chip will still display correctly.

        // Directions (Inbound, Outbound, Internal)
        if (group.Directions?.Count > 0)
        {
            var directions = group.Directions;
            groupFilters.Add(new PacketFilter
            {
                CustomPredicate = p =>
                {
                    var srcPrivate = IsPrivateIP(p.SourceIP);
                    var dstPrivate = IsPrivateIP(p.DestinationIP);

                    foreach (var dir in directions)
                    {
                        var match = dir.ToUpperInvariant() switch
                        {
                            "INBOUND" => !srcPrivate && dstPrivate,
                            "OUTBOUND" => srcPrivate && !dstPrivate,
                            "INTERNAL" => srcPrivate && dstPrivate,
                            _ => false
                        };
                        if (match) return true;
                    }
                    return false;
                },
                Description = $"Direction: {string.Join("|", directions)}"
            });
        }

        // ==================== TAB-SPECIFIC FILTERS (NOT PACKET-LEVEL) ====================
        //
        // The following filter criteria CANNOT be applied at packet level because the data
        // exists only in AnalysisResult, computed after packet parsing:
        //
        // - Codecs (G.729, G.711, etc.): Stored in VoiceQoSData.QoSTraffic[].QoSType
        //   L7Protocol only contains "RTP", not the codec name
        // - Severities (Critical, High, etc.): Stored in AnalysisResult.Threats[].Severity
        // - ThreatCategories: Stored in AnalysisResult.Threats[].Type
        // - QualityLevels: Computed from jitter/latency metrics in VoiceQoSData
        // - VoipIssues: Detected by VoIP anomaly analysis
        // - Countries/Regions: Requires GeoIP enrichment of IP addresses
        //
        // These filters are applied at the tab-specific level:
        // - VoiceQoSViewModel filters its QoS connections
        // - ThreatsViewModel filters its threat list
        // - CountryTrafficViewModel filters its country statistics
        //
        // The filter chip displays correctly, but packet-level filtering is limited
        // to General tab criteria (IP, Port, Protocol, Direction, QuickFilters).

        // Use group's display label
        if (groupFilters.Count == 0)
            return null;

        if (groupFilters.Count == 1)
        {
            groupFilters[0].Description = group.DisplayLabel ?? groupFilters[0].Description;
            return groupFilters[0];
        }

        return new PacketFilter
        {
            CombinedFilters = groupFilters,
            CombineMode = FilterCombineMode.And,
            Description = group.DisplayLabel ?? string.Join(" AND ", groupFilters.Select(f => f.Description))
        };
    }

    /// <summary>
    /// Builds grouped filters: OR within category, AND between categories.
    /// Example: (TLS OR HTTPS) AND (192.168.1.0/24) AND (Port:443 OR Port:8443)
    /// </summary>
    private PacketFilter? BuildGroupedFilters(Models.FilterCriteria criteria, bool isExclude)
    {
        var categoryFilters = new List<PacketFilter>();
        var prefix = isExclude ? "Exclude" : "Include";

        // Category 1: Protocols (OR within category)
        var protocolFilters = new List<PacketFilter>();
        foreach (var protocol in criteria.Protocols)
        {
            protocolFilters.Add(new PacketFilter
            {
                CustomPredicate = p => p.Protocol.ToString().Equals(protocol, StringComparison.OrdinalIgnoreCase) ||
                                      (p.L7Protocol?.Equals(protocol, StringComparison.OrdinalIgnoreCase) ?? false),
                Description = protocol
            });
        }
        if (protocolFilters.Count > 0)
        {
            categoryFilters.Add(CombineFiltersWithOr(protocolFilters, $"{prefix} Protocol"));
        }

        // Category 2: IPs (OR within category)
        var ipFilters = new List<PacketFilter>();
        foreach (var ip in criteria.IPs)
        {
            ipFilters.Add(new PacketFilter
            {
                CustomPredicate = p => MatchesIpOrCidr(p.SourceIP, ip) || MatchesIpOrCidr(p.DestinationIP, ip),
                Description = ip
            });
        }
        if (ipFilters.Count > 0)
        {
            categoryFilters.Add(CombineFiltersWithOr(ipFilters, $"{prefix} IP"));
        }

        // Category 3: Ports (OR within category)
        var portFilters = new List<PacketFilter>();
        foreach (var port in criteria.Ports)
        {
            if (TryParsePortOrRange(port, out var portPredicate))
            {
                portFilters.Add(new PacketFilter
                {
                    CustomPredicate = portPredicate,
                    Description = $"Port:{port}"
                });
            }
        }
        if (portFilters.Count > 0)
        {
            categoryFilters.Add(CombineFiltersWithOr(portFilters, $"{prefix} Port"));
        }

        // Category 4: QuickFilters (OR within category)
        var quickFilters = new List<PacketFilter>();
        foreach (var qf in criteria.QuickFilters)
        {
            var predicate = BuildQuickFilterPredicate(qf);
            if (predicate is not null)
            {
                quickFilters.Add(new PacketFilter
                {
                    CustomPredicate = predicate,
                    Description = qf
                });
            }
        }
        if (quickFilters.Count > 0)
        {
            categoryFilters.Add(CombineFiltersWithOr(quickFilters, $"{prefix} QuickFilter"));
        }

        // Combine all categories with AND
        if (categoryFilters.Count == 0)
            return null;
        if (categoryFilters.Count == 1)
            return categoryFilters[0];

        return CombineFiltersWithAnd(categoryFilters);
    }

    /// <summary>
    /// Matches IP against exact match or CIDR notation
    /// </summary>
    private static bool MatchesIpOrCidr(string packetIp, string filterIp)
    {
        if (string.IsNullOrEmpty(packetIp) || string.IsNullOrEmpty(filterIp))
            return false;

        // Use existing CIDR matcher from NetworkHelper
        return Core.Services.NetworkHelper.MatchesIpPattern(packetIp, filterIp);
    }

    /// <summary>
    /// Parses port string to predicate (supports single port, range like "80-443", or comma-separated)
    /// </summary>
    private static bool TryParsePortOrRange(string portString, out Func<PacketInfo, bool> predicate)
    {
        predicate = null!;

        if (string.IsNullOrWhiteSpace(portString))
            return false;

        // Single port
        if (int.TryParse(portString, out var singlePort))
        {
            predicate = p => p.SourcePort == singlePort || p.DestinationPort == singlePort;
            return true;
        }

        // Port range: "80-443"
        if (portString.Contains('-', StringComparison.Ordinal))
        {
            var parts = portString.Split('-');
            if (parts.Length == 2 && int.TryParse(parts[0], out var start) && int.TryParse(parts[1], out var end))
            {
                predicate = p => (p.SourcePort >= start && p.SourcePort <= end) ||
                                (p.DestinationPort >= start && p.DestinationPort <= end);
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Builds predicate for QuickFilter strings
    /// </summary>
    private Func<PacketInfo, bool>? BuildQuickFilterPredicate(string quickFilter)
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
    private PacketFilter CombineFiltersWithOr(List<PacketFilter> filters, string? categoryName = null)
    {
        if (filters.Count == 0) return new PacketFilter();
        if (filters.Count == 1)
        {
            // Preserve single filter with category name for debugging
            if (!string.IsNullOrEmpty(categoryName) && string.IsNullOrEmpty(filters[0].Description))
                filters[0].Description = categoryName;
            return filters[0];
        }

        var itemDescriptions = string.Join(" OR ", filters.Select(f => f.Description));
        var desc = string.IsNullOrEmpty(categoryName)
            ? $"({itemDescriptions})"
            : $"{categoryName}: ({itemDescriptions})";

        return new PacketFilter
        {
            CombinedFilters = filters,
            CombineMode = FilterCombineMode.Or,
            Description = desc
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
