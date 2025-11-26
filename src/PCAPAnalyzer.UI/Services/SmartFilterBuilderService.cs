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
        /// </summary>
        public PacketFilter BuildFilterFromChip(FilterChipItem chip)
        {
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
