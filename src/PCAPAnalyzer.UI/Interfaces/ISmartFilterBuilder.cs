using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;
using System.Collections.Generic;

namespace PCAPAnalyzer.UI.Interfaces
{
    /// <summary>
    /// Service for building sophisticated PacketFilter objects from UI filter inputs.
    /// Supports INCLUDE/EXCLUDE groups, individual filter chips, AND/OR logic,
    /// port range patterns, and protocol matching.
    ///
    /// Enables consistent filtering across all analysis tabs (Packet Analysis, Dashboard,
    /// Threats, VoiceQoS, Country Traffic) without code duplication.
    /// </summary>
    public interface ISmartFilterBuilder
    {
        /// <summary>
        /// Builds a combined PacketFilter from filter groups and individual chips.
        /// Logic: (All INCLUDE filters OR'd together) AND NOT (All EXCLUDE filters OR'd together)
        /// </summary>
        /// <param name="includeGroups">INCLUDE filter groups (each group is AND of its fields)</param>
        /// <param name="includeChips">INCLUDE individual filter chips (OR'd together)</param>
        /// <param name="excludeGroups">EXCLUDE filter groups (each group is AND of its fields)</param>
        /// <param name="excludeChips">EXCLUDE individual filter chips (OR'd together)</param>
        /// <returns>Combined PacketFilter ready for packet filtering operations</returns>
        PacketFilter BuildCombinedPacketFilter(
            IEnumerable<FilterGroup> includeGroups,
            IEnumerable<FilterChipItem> includeChips,
            IEnumerable<FilterGroup> excludeGroups,
            IEnumerable<FilterChipItem> excludeChips);

        /// <summary>
        /// Builds a PacketFilter from a single FilterChipItem.
        /// Handles field types: "Src IP", "Dest IP", "Port", "Protocol"
        /// </summary>
        /// <param name="chip">Filter chip item with field name and value</param>
        /// <returns>PacketFilter for the specified field</returns>
        PacketFilter BuildFilterFromChip(FilterChipItem chip);

        /// <summary>
        /// Combines multiple filters with AND logic.
        /// All filters must match for a packet to pass.
        /// </summary>
        /// <param name="filters">Filters to combine</param>
        /// <returns>Combined filter with AND logic</returns>
        PacketFilter CombineFiltersWithAnd(IEnumerable<PacketFilter> filters);

        /// <summary>
        /// Combines multiple filters with OR logic.
        /// Any filter matching allows a packet to pass.
        /// </summary>
        /// <param name="filters">Filters to combine</param>
        /// <returns>Combined filter with OR logic</returns>
        PacketFilter CombineFiltersWithOr(IEnumerable<PacketFilter> filters);

        /// <summary>
        /// Inverts a filter (NOT logic).
        /// Packets that match the filter will be excluded.
        /// </summary>
        /// <param name="filter">Filter to invert</param>
        /// <returns>Inverted filter</returns>
        PacketFilter InvertFilter(PacketFilter filter);

        /// <summary>
        /// Checks if a port matches a pattern.
        /// Supports single ports (80), comma-separated lists (80,443), and ranges (137-139).
        /// </summary>
        /// <param name="port">Port number to check</param>
        /// <param name="pattern">Port pattern (e.g., "80,443,137-139")</param>
        /// <returns>True if port matches pattern</returns>
        bool MatchesPortPattern(int port, string pattern);

        /// <summary>
        /// Checks if a packet's protocol matches a pattern.
        /// Supports L4 protocols (TCP, UDP) and L7 protocols (HTTP, DNS).
        /// Pattern matching is case-insensitive and supports comma-separated lists.
        /// </summary>
        /// <param name="packet">Packet to check</param>
        /// <param name="pattern">Protocol pattern (e.g., "TCP,HTTP")</param>
        /// <returns>True if packet protocol matches pattern</returns>
        bool MatchesProtocol(PacketInfo packet, string pattern);
    }
}
