using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using PCAPAnalyzer.Core.Services;

namespace PCAPAnalyzer.Core.Models;

public enum FilterCombineMode
{
    And,  // All conditions must match
    Or    // Any condition must match
}

public class PacketFilter
{
    public string? SourceIpFilter { get; set; }
    public string? DestinationIpFilter { get; set; }
    public string? SourcePortFilter { get; set; }  // Changed to string to support ranges
    public string? DestinationPortFilter { get; set; }  // Changed to string to support ranges
    public Protocol? ProtocolFilter { get; set; }
    public int? MinLength { get; set; }
    public int? MaxLength { get; set; }
    public DateTime? StartTime { get; set; }
    public DateTime? EndTime { get; set; }
    public string? InfoSearchText { get; set; }

    // Collection-based filters (for UI binding)
    public HashSet<string>? SourceIPs { get; set; }
    public HashSet<string>? DestinationIPs { get; set; }
    public HashSet<string>? Protocols { get; set; }
    public HashSet<int>? Ports { get; set; }

    // IP type filters
    public bool? ShowOnlyRFC1918 { get; set; }
    public bool? ShowOnlyPublicIPs { get; set; }

    // Negation flags for NOT filters
    public bool NegateSourceIp { get; set; }
    public bool NegateDestinationIp { get; set; }
    public bool NegateProtocol { get; set; }
    public bool NegateSourcePort { get; set; }
    public bool NegateDestinationPort { get; set; }
    public bool NegateInfo { get; set; }

    // Filter combination support
    public FilterCombineMode CombineMode { get; set; } = FilterCombineMode.And;
    public List<PacketFilter>? CombinedFilters { get; set; }

    // Custom filter support
    public Func<PacketInfo, bool>? CustomPredicate { get; set; }
    public string? Description { get; set; }

    public bool IsEmpty =>
        string.IsNullOrWhiteSpace(SourceIpFilter) &&
        string.IsNullOrWhiteSpace(DestinationIpFilter) &&
        string.IsNullOrWhiteSpace(SourcePortFilter) &&
        string.IsNullOrWhiteSpace(DestinationPortFilter) &&
        !ProtocolFilter.HasValue &&
        !MinLength.HasValue &&
        !MaxLength.HasValue &&
        !StartTime.HasValue &&
        !EndTime.HasValue &&
        string.IsNullOrWhiteSpace(InfoSearchText) &&
        CustomPredicate == null &&
        (CombinedFilters == null || CombinedFilters.Count == 0);

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Packet filtering requires comprehensive checks across IP, port, protocol, time range, length, and content fields with proper negation support")]
    public bool MatchesPacket(PacketInfo packet)
    {
        // Custom predicate takes precedence
        if (CustomPredicate != null)
        {
            return CustomPredicate(packet);
        }
        
        // Handle combined filters
        if (CombinedFilters != null && CombinedFilters.Count > 0)
        {
            if (CombineMode == FilterCombineMode.And)
            {
                return CombinedFilters.All(f => f.MatchesPacket(packet));
            }
            else // OR mode
            {
                return CombinedFilters.Any(f => f.MatchesPacket(packet));
            }
        }
        
        // Source IP filter with negation and CIDR support
        if (!string.IsNullOrWhiteSpace(SourceIpFilter))
        {
            var matches = NetworkHelper.MatchesIpPattern(packet.SourceIP, SourceIpFilter);
            if (NegateSourceIp ? matches : !matches)
                return false;
        }

        // Destination IP filter with negation and CIDR support
        if (!string.IsNullOrWhiteSpace(DestinationIpFilter))
        {
            var matches = NetworkHelper.MatchesIpPattern(packet.DestinationIP, DestinationIpFilter);
            if (NegateDestinationIp ? matches : !matches)
                return false;
        }

        // Protocol filter with negation support
        if (ProtocolFilter.HasValue)
        {
            var matches = packet.Protocol == ProtocolFilter.Value;
            if (NegateProtocol ? matches : !matches)
                return false;
        }

        // Length filters
        if (MinLength.HasValue && packet.Length < MinLength.Value)
            return false;
        
        if (MaxLength.HasValue && packet.Length > MaxLength.Value)
            return false;

        // Time filters
        if (StartTime.HasValue && packet.Timestamp < StartTime.Value)
            return false;
        
        if (EndTime.HasValue && packet.Timestamp > EndTime.Value)
            return false;

        // Port filters with negation support and range/list support
        if (!string.IsNullOrWhiteSpace(SourcePortFilter))
        {
            var matches = NetworkHelper.MatchesPortPattern(packet.SourcePort, SourcePortFilter);
            if (NegateSourcePort ? matches : !matches)
                return false;
        }
        
        if (!string.IsNullOrWhiteSpace(DestinationPortFilter))
        {
            var matches = NetworkHelper.MatchesPortPattern(packet.DestinationPort, DestinationPortFilter);
            if (NegateDestinationPort ? matches : !matches)
                return false;
        }

        // Info text search with negation support
        if (!string.IsNullOrWhiteSpace(InfoSearchText))
        {
            var matches = packet.Info != null && packet.Info.Contains(InfoSearchText, StringComparison.OrdinalIgnoreCase);
            if (NegateInfo ? matches : !matches)
                return false;
        }

        return true;
    }

    public void Clear()
    {
        SourceIpFilter = null;
        DestinationIpFilter = null;
        ProtocolFilter = null;
        MinLength = null;
        MaxLength = null;
        StartTime = null;
        EndTime = null;
        SourcePortFilter = null;
        DestinationPortFilter = null;
        InfoSearchText = null;
    }
}