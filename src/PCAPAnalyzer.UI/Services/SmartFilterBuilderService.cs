using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace PCAPAnalyzer.UI.Services
{
    /// <summary>
    /// Service for building sophisticated PacketFilter objects from UI filter inputs.
    /// Implements complex filter logic including INCLUDE/EXCLUDE groups, AND/OR combinations,
    /// port range patterns, and protocol matching.
    ///
    /// Extracted from MainWindowViewModel (250+ lines) to enable reuse across all analysis tabs:
    /// - Packet Analysis
    /// - Dashboard
    /// - Security Threats
    /// - Voice/QoS
    /// - Country Traffic
    ///
    /// Each tab can now have the same sophisticated filtering UI without code duplication.
    /// </summary>
    public class SmartFilterBuilderService : ISmartFilterBuilder
    {
        /// <summary>
        /// Builds a combined PacketFilter from filter groups and individual chips.
        ///
        /// Logic Flow:
        /// 1. Build PacketFilters from INCLUDE groups (each group is AND of its fields)
        /// 2. Build PacketFilters from INCLUDE individual chips
        /// 3. Build PacketFilters from EXCLUDE groups (each group is AND of its fields)
        /// 4. Build PacketFilters from EXCLUDE individual chips
        /// 5. Combine all INCLUDE filters with OR
        /// 6. Combine all EXCLUDE filters with OR, then invert with NOT
        /// 7. Final combination: (INCLUDE) AND NOT (EXCLUDE)
        /// </summary>
        public PacketFilter BuildCombinedPacketFilter(
            IEnumerable<FilterGroup> includeGroups,
            IEnumerable<FilterChipItem> includeChips,
            IEnumerable<FilterGroup> excludeGroups,
            IEnumerable<FilterChipItem> excludeChips)
        {
            // ✅ ROBUSTNESS FIX: Defensive validation prevents NullReferenceException
            ArgumentNullException.ThrowIfNull(includeGroups);
            ArgumentNullException.ThrowIfNull(includeChips);
            ArgumentNullException.ThrowIfNull(excludeGroups);
            ArgumentNullException.ThrowIfNull(excludeChips);

            var includeFilters = new List<PacketFilter>();
            var excludeFilters = new List<PacketFilter>();

            // Step 1: Build PacketFilters from INCLUDE groups (each group is AND of its fields)
            foreach (var group in includeGroups)
            {
                var groupFilters = BuildFilterFromGroup(group);
                if (groupFilters.Any())
                {
                    includeFilters.Add(CombineFiltersWithAnd(groupFilters));
                }
            }

            // Step 2: Build PacketFilters from INCLUDE individual chips
            foreach (var chip in includeChips)
            {
                includeFilters.Add(BuildFilterFromChip(chip));
            }

            // Step 3: Build PacketFilters from EXCLUDE groups (each group is AND of its fields)
            foreach (var group in excludeGroups)
            {
                var groupFilters = BuildFilterFromGroup(group);
                if (groupFilters.Any())
                {
                    excludeFilters.Add(CombineFiltersWithAnd(groupFilters));
                }
            }

            // Step 4: Build PacketFilters from EXCLUDE individual chips
            foreach (var chip in excludeChips)
            {
                excludeFilters.Add(BuildFilterFromChip(chip));
            }

            // Step 5: Combine all INCLUDE filters with OR
            PacketFilter? combinedInclude = null;
            if (includeFilters.Count > 0)
            {
                combinedInclude = CombineFiltersWithOr(includeFilters);
            }

            // Step 6: Combine all EXCLUDE filters with OR, then invert with NOT
            PacketFilter? combinedExclude = null;
            if (excludeFilters.Count > 0)
            {
                var excludeOr = CombineFiltersWithOr(excludeFilters);
                combinedExclude = InvertFilter(excludeOr);
            }

            // Step 7: Final combination: (INCLUDE) AND (NOT EXCLUDE)
            if (combinedInclude != null && combinedExclude != null)
            {
                return CombineFiltersWithAnd(new List<PacketFilter> { combinedInclude, combinedExclude });
            }
            else if (combinedInclude != null)
            {
                return combinedInclude;
            }
            else if (combinedExclude != null)
            {
                return combinedExclude;
            }
            else
            {
                return new PacketFilter(); // Empty filter (show all packets)
            }
        }

        /// <summary>
        /// Builds PacketFilters from a FilterGroup's fields.
        /// Each non-empty field (SourceIP, DestinationIP, PortRange, Protocol) creates a separate filter.
        /// These filters are later combined with AND logic to enforce group semantics.
        /// </summary>
        /// <param name="group">Filter group containing user-specified criteria</param>
        /// <returns>List of PacketFilters, one per populated field (0-4 filters)</returns>
        private List<PacketFilter> BuildFilterFromGroup(FilterGroup group)
        {
            var groupFilters = new List<PacketFilter>();

            if (!string.IsNullOrWhiteSpace(group.SourceIP))
            {
                groupFilters.Add(new PacketFilter
                {
                    SourceIpFilter = group.SourceIP,
                    Description = $"Src IP: {group.SourceIP}"
                });
            }

            if (!string.IsNullOrWhiteSpace(group.DestinationIP))
            {
                groupFilters.Add(new PacketFilter
                {
                    DestinationIpFilter = group.DestinationIP,
                    Description = $"Dest IP: {group.DestinationIP}"
                });
            }

            if (!string.IsNullOrWhiteSpace(group.PortRange))
            {
                // ✅ DEFENSIVE: Trim whitespace to protect against UI model changes
                var portTrimmed = group.PortRange.Trim();
                groupFilters.Add(new PacketFilter
                {
                    CustomPredicate = p => MatchesPortPattern(p.SourcePort, portTrimmed) ||
                                           MatchesPortPattern(p.DestinationPort, portTrimmed),
                    Description = $"Port: {portTrimmed}"
                });
            }

            if (!string.IsNullOrWhiteSpace(group.Protocol))
            {
                // ✅ DEFENSIVE: Trim whitespace to protect against UI model changes
                var protocolTrimmed = group.Protocol.Trim();
                groupFilters.Add(new PacketFilter
                {
                    CustomPredicate = p => MatchesProtocol(p, protocolTrimmed),
                    Description = $"Protocol: {protocolTrimmed}"
                });
            }

            return groupFilters;
        }

        /// <summary>
        /// Builds a PacketFilter from a single FilterChipItem.
        /// Supports field types: "Src IP", "Dest IP", "Port", "Protocol"
        /// Also handles Quick Filter chips (IPv4, IPv6, Retransmissions, etc.)
        /// </summary>
        public PacketFilter BuildFilterFromChip(FilterChipItem chip)
        {
            // ✅ Handle Quick Filter chips (those with QuickFilterCodeName set)
            if (!string.IsNullOrEmpty(chip.QuickFilterCodeName))
            {
                return BuildFilterFromQuickFilterChip(chip);
            }

            // ✅ SECURITY FIX: Use OrdinalIgnoreCase instead of culture-aware comparison
            // Prevents Turkish "I" problem and improves performance
            return chip.FieldName switch
            {
                var name when name.Equals("Src IP", StringComparison.OrdinalIgnoreCase) ||
                              name.Equals("NOT Src IP", StringComparison.OrdinalIgnoreCase)
                    => new PacketFilter
                    {
                        SourceIpFilter = chip.Value,
                        Description = chip.DisplayLabel
                    },

                var name when name.Equals("Dest IP", StringComparison.OrdinalIgnoreCase) ||
                              name.Equals("NOT Dest IP", StringComparison.OrdinalIgnoreCase)
                    => new PacketFilter
                    {
                        DestinationIpFilter = chip.Value,
                        Description = chip.DisplayLabel
                    },

                var name when name.Equals("Port", StringComparison.OrdinalIgnoreCase) ||
                              name.Equals("NOT Port", StringComparison.OrdinalIgnoreCase)
                    => new PacketFilter
                    {
                        CustomPredicate = p => MatchesPortPattern(p.SourcePort, chip.Value) ||
                                               MatchesPortPattern(p.DestinationPort, chip.Value),
                        Description = chip.DisplayLabel
                    },

                var name when name.Equals("Protocol", StringComparison.OrdinalIgnoreCase) ||
                              name.Equals("NOT Protocol", StringComparison.OrdinalIgnoreCase)
                    => new PacketFilter
                    {
                        CustomPredicate = p => MatchesProtocol(p, chip.Value),
                        Description = chip.DisplayLabel
                    },

                _ => new PacketFilter { Description = chip.DisplayLabel }
            };
        }

        /// <summary>
        /// Builds a PacketFilter from a Quick Filter chip (IPv4, IPv6, RFC1918, etc.)
        /// Uses NetworkFilterHelper for consistent IP classification.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
            Justification = "Switch expression for quick filter types is intentionally comprehensive")]
        private static PacketFilter BuildFilterFromQuickFilterChip(FilterChipItem chip)
        {
            Func<PacketInfo, bool> predicate = chip.QuickFilterCodeName switch
            {
                // ==================== NETWORK TYPE FILTERS ====================
                "IPv4" => p => Core.Services.NetworkFilterHelper.IsIPv4(p.SourceIP) ||
                               Core.Services.NetworkFilterHelper.IsIPv4(p.DestinationIP),
                "IPv6" => p => Core.Services.NetworkFilterHelper.IsIPv6(p.SourceIP) ||
                               Core.Services.NetworkFilterHelper.IsIPv6(p.DestinationIP),
                "RFC1918" => p => Core.Services.NetworkFilterHelper.IsRFC1918(p.SourceIP) ||
                                  Core.Services.NetworkFilterHelper.IsRFC1918(p.DestinationIP),
                "PublicIP" => p => !Core.Services.NetworkFilterHelper.IsRFC1918(p.SourceIP) &&
                                   !Core.Services.NetworkFilterHelper.IsLoopback(p.SourceIP) &&
                                   !Core.Services.NetworkFilterHelper.IsLinkLocal(p.SourceIP),
                "APIPA" => p => Core.Services.NetworkFilterHelper.IsLinkLocal(p.SourceIP) ||
                                Core.Services.NetworkFilterHelper.IsLinkLocal(p.DestinationIP),
                "Multicast" => p => Core.Services.NetworkFilterHelper.IsMulticast(p.SourceIP) ||
                                    Core.Services.NetworkFilterHelper.IsMulticast(p.DestinationIP),
                "Broadcast" => p => Core.Services.NetworkFilterHelper.IsBroadcast(p.SourceIP) ||
                                    Core.Services.NetworkFilterHelper.IsBroadcast(p.DestinationIP),
                "Anycast" => p => Core.Services.NetworkFilterHelper.IsAnycast(p.SourceIP) ||
                                  Core.Services.NetworkFilterHelper.IsAnycast(p.DestinationIP),
                "Loopback" => p => Core.Services.NetworkFilterHelper.IsLoopback(p.SourceIP) ||
                                   Core.Services.NetworkFilterHelper.IsLoopback(p.DestinationIP),
                "LinkLocal" => p => Core.Services.NetworkFilterHelper.IsLinkLocal(p.SourceIP) ||
                                    Core.Services.NetworkFilterHelper.IsLinkLocal(p.DestinationIP),

                // ==================== TRAFFIC DIRECTION FILTERS ====================
                "PrivateToPublic" => p => Core.Services.NetworkFilterHelper.IsRFC1918(p.SourceIP) &&
                                          !Core.Services.NetworkFilterHelper.IsRFC1918(p.DestinationIP) &&
                                          !Core.Services.NetworkFilterHelper.IsLoopback(p.DestinationIP),
                "PublicToPrivate" => p => !Core.Services.NetworkFilterHelper.IsRFC1918(p.SourceIP) &&
                                          Core.Services.NetworkFilterHelper.IsRFC1918(p.DestinationIP),

                // ==================== PROTOCOL FILTERS ====================
                "TCP" => p => p.Protocol == Protocol.TCP,
                "UDP" => p => p.Protocol == Protocol.UDP,
                "ICMP" => p => p.Protocol == Protocol.ICMP,
                "HTTP" => p => p.L7Protocol?.Contains("HTTP", StringComparison.OrdinalIgnoreCase) == true &&
                               p.L7Protocol?.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) != true,
                "HTTPS" => p => p.L7Protocol?.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("TLS", StringComparison.OrdinalIgnoreCase) == true,
                "DNS" => p => p.L7Protocol?.Contains("DNS", StringComparison.OrdinalIgnoreCase) == true ||
                              p.SourcePort == 53 || p.DestinationPort == 53,
                "SSH" => p => p.SourcePort == 22 || p.DestinationPort == 22,
                "FTP" => p => p.SourcePort == 21 || p.DestinationPort == 21 ||
                              p.SourcePort == 20 || p.DestinationPort == 20,
                "SMTP" => p => p.SourcePort == 25 || p.DestinationPort == 25 ||
                               p.SourcePort == 587 || p.DestinationPort == 587,
                "SNMP" => p => p.SourcePort == 161 || p.DestinationPort == 161 ||
                               p.SourcePort == 162 || p.DestinationPort == 162,
                "DHCP" => p => p.SourcePort == 67 || p.DestinationPort == 67 ||
                               p.SourcePort == 68 || p.DestinationPort == 68,
                "STUN" => p => p.SourcePort == 3478 || p.DestinationPort == 3478,

                // ==================== TLS VERSION FILTERS ====================
                "TlsV10" => p => p.L7Protocol?.Contains("TLS 1.0", StringComparison.OrdinalIgnoreCase) == true ||
                                 p.L7Protocol?.Contains("TLSv1.0", StringComparison.OrdinalIgnoreCase) == true,
                "TlsV11" => p => p.L7Protocol?.Contains("TLS 1.1", StringComparison.OrdinalIgnoreCase) == true ||
                                 p.L7Protocol?.Contains("TLSv1.1", StringComparison.OrdinalIgnoreCase) == true,
                "TlsV12" => p => p.L7Protocol?.Contains("TLS 1.2", StringComparison.OrdinalIgnoreCase) == true ||
                                 p.L7Protocol?.Contains("TLSv1.2", StringComparison.OrdinalIgnoreCase) == true,
                "TlsV13" => p => p.L7Protocol?.Contains("TLS 1.3", StringComparison.OrdinalIgnoreCase) == true ||
                                 p.L7Protocol?.Contains("TLSv1.3", StringComparison.OrdinalIgnoreCase) == true,

                // ==================== VPN PROTOCOL FILTERS ====================
                "WireGuard" => p => p.SourcePort == 51820 || p.DestinationPort == 51820,
                "OpenVPN" => p => p.SourcePort == 1194 || p.DestinationPort == 1194,
                "IKEv2" => p => p.SourcePort == 500 || p.DestinationPort == 500 ||
                                p.SourcePort == 4500 || p.DestinationPort == 4500,
                "IPSec" => p => p.Protocol.ToString().Contains("ESP", StringComparison.OrdinalIgnoreCase) ||
                                p.Protocol.ToString().Contains("AH", StringComparison.OrdinalIgnoreCase),
                "L2TP" => p => p.SourcePort == 1701 || p.DestinationPort == 1701,
                "PPTP" => p => p.SourcePort == 1723 || p.DestinationPort == 1723,

                // ==================== SECURITY FILTERS ====================
                "Insecure" => p => Core.Services.NetworkFilterHelper.IsInsecureProtocol(
                                       p.L7Protocol ?? p.Protocol.ToString()),

                // ==================== TCP PERFORMANCE FILTERS ====================
                "Retransmissions" => p => p.Info?.Contains("Retransmission", StringComparison.OrdinalIgnoreCase) == true,
                "ZeroWindow" => p => p.Info?.Contains("Zero window", StringComparison.OrdinalIgnoreCase) == true ||
                                     p.Info?.Contains("ZeroWindow", StringComparison.OrdinalIgnoreCase) == true,
                "KeepAlive" => p => p.Info?.Contains("Keep-Alive", StringComparison.OrdinalIgnoreCase) == true,
                "ConnectionRefused" => p => p.Info?.Contains("RST", StringComparison.OrdinalIgnoreCase) == true,
                "WindowFull" => p => p.Info?.Contains("Window full", StringComparison.OrdinalIgnoreCase) == true,

                // ==================== SECURITY AUDIT FILTERS ====================
                "CleartextAuth" => p => p.Info?.Contains("AUTH", StringComparison.OrdinalIgnoreCase) == true ||
                                        p.Info?.Contains("USER", StringComparison.OrdinalIgnoreCase) == true ||
                                        p.Info?.Contains("PASS", StringComparison.OrdinalIgnoreCase) == true,
                "ObsoleteCrypto" => p => p.L7Protocol?.Contains("SSL", StringComparison.OrdinalIgnoreCase) == true ||
                                         p.L7Protocol?.Contains("TLS 1.0", StringComparison.OrdinalIgnoreCase) == true ||
                                         p.L7Protocol?.Contains("TLS 1.1", StringComparison.OrdinalIgnoreCase) == true,
                "SmbV1" => p => p.L7Protocol?.Contains("SMBv1", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("SMB1", StringComparison.OrdinalIgnoreCase) == true,

                // ==================== SIZE FILTERS ====================
                "JumboFrames" => p => p.Length > 1500,

                // ==================== PROTOCOL ERROR FILTERS ====================
                "HTTPErrors" => p => p.Info?.Contains(" 4", StringComparison.OrdinalIgnoreCase) == true ||
                                     p.Info?.Contains(" 5", StringComparison.OrdinalIgnoreCase) == true,
                "DNSFailures" => p => p.Info?.Contains("NXDOMAIN", StringComparison.OrdinalIgnoreCase) == true ||
                                      p.Info?.Contains("SERVFAIL", StringComparison.OrdinalIgnoreCase) == true,
                "ICMPUnreachable" => p => p.Info?.Contains("unreachable", StringComparison.OrdinalIgnoreCase) == true,

                // Default: no filter (match all)
                _ => _ => true
            };

            return new PacketFilter
            {
                CustomPredicate = predicate,
                Description = chip.DisplayLabel
            };
        }

        /// <summary>
        /// Combines multiple filters with AND logic (all must match).
        /// </summary>
        public PacketFilter CombineFiltersWithAnd(IEnumerable<PacketFilter> filters)
        {
            var filterList = filters.ToList();

            if (filterList.Count == 0)
                return new PacketFilter();

            if (filterList.Count == 1)
                return filterList[0];

            var descriptions = filterList.Select(f => f.Description).Where(d => !string.IsNullOrWhiteSpace(d));
            var combinedDescription = string.Join(" AND ", descriptions);

            return new PacketFilter
            {
                CustomPredicate = p => filterList.All(f => f.MatchesPacket(p)),
                Description = $"({combinedDescription})"
            };
        }

        /// <summary>
        /// Combines multiple filters with OR logic (any can match).
        /// </summary>
        public PacketFilter CombineFiltersWithOr(IEnumerable<PacketFilter> filters)
        {
            var filterList = filters.ToList();

            if (filterList.Count == 0)
                return new PacketFilter();

            if (filterList.Count == 1)
                return filterList[0];

            var descriptions = filterList.Select(f => f.Description).Where(d => !string.IsNullOrWhiteSpace(d));
            var combinedDescription = string.Join(" OR ", descriptions);

            return new PacketFilter
            {
                CustomPredicate = p => filterList.Any(f => f.MatchesPacket(p)),
                Description = $"({combinedDescription})"
            };
        }

        /// <summary>
        /// Inverts a filter (NOT logic).
        /// </summary>
        public PacketFilter InvertFilter(PacketFilter filter)
        {
            if (filter.IsEmpty)
                return filter;

            return new PacketFilter
            {
                CustomPredicate = p => !filter.MatchesPacket(p),
                Description = $"NOT ({filter.Description})"
            };
        }

        /// <summary>
        /// Checks if a port matches a pattern.
        /// Supports:
        /// - Single ports: "80"
        /// - Comma-separated lists: "80,443,8080"
        /// - Ranges: "137-139"
        /// - Combined: "80,443,137-139"
        /// </summary>
        public bool MatchesPortPattern(int port, string pattern)
        {
            // ✅ ROBUSTNESS FIX: Validate input to prevent exceptions
            if (string.IsNullOrWhiteSpace(pattern))
                return false;

            var parts = pattern.Split(',', StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                var trimmed = part.Trim();

                // Check for range (e.g., "137-139")
                if (trimmed.Contains('-', StringComparison.Ordinal))
                {
                    var rangeParts = trimmed.Split('-');
                    if (rangeParts.Length == 2 &&
                        int.TryParse(rangeParts[0].Trim(), out var start) &&
                        int.TryParse(rangeParts[1].Trim(), out var end))
                    {
                        if (port >= start && port <= end)
                            return true;
                    }
                }
                // Check for exact match
                else if (int.TryParse(trimmed, out var singlePort))
                {
                    if (port == singlePort)
                        return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Checks if a packet's protocol matches a pattern.
        /// Supports:
        /// - L4 protocols: "TCP", "UDP", "ICMP"
        /// - L7 protocols: "HTTP", "DNS", "TLS"
        /// - Comma-separated: "TCP,HTTP"
        /// Case-insensitive matching.
        /// </summary>
        public bool MatchesProtocol(PacketInfo packet, string pattern)
        {
            // ✅ ROBUSTNESS FIX: Validate input to prevent exceptions
            if (string.IsNullOrWhiteSpace(pattern))
                return false;

            var parts = pattern.Split(',', StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                var trimmed = part.Trim();

                // Check L4 protocol
                if (Enum.TryParse<Protocol>(trimmed, true, out var l4Protocol))
                {
                    if (packet.Protocol == l4Protocol)
                        return true;
                }

                // Check L7 protocol
                if (!string.IsNullOrWhiteSpace(packet.L7Protocol))
                {
                    if (packet.L7Protocol.Equals(trimmed, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            return false;
        }
    }
}
