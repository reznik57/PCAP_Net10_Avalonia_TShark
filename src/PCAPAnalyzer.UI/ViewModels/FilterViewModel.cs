using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.ViewModels;

public partial class FilterViewModel : ObservableObject
{
    private readonly Action<PacketFilter> _onFilterApplied;
    
    [ObservableProperty] private string? _sourceIpFilter;
    [ObservableProperty] private string? _destinationIpFilter;
    [ObservableProperty] private string? _protocolFilterText;  // Changed from dropdown to text field
    [ObservableProperty] private string? _minLengthText;
    [ObservableProperty] private string? _maxLengthText;
    [ObservableProperty] private string? _sourcePortText;
    [ObservableProperty] private string? _destinationPortText;
    [ObservableProperty] private string? _infoSearchText;
    [ObservableProperty] private bool _isFilterActive;
    
    public FilterViewModel(Action<PacketFilter> onFilterApplied)
    {
        _onFilterApplied = onFilterApplied;
    }

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Filter application requires comprehensive validation and combination of IP filters, protocol filters, port filters, length filters, and info search with proper negation support")]
    [RelayCommand]
    private void ApplyFilter()
    {
        var filter = new PacketFilter();
        
        // Process Source IP filter with negation check
        if (!string.IsNullOrWhiteSpace(SourceIpFilter))
        {
            var trimmed = SourceIpFilter.Trim();
            if (trimmed.StartsWith("!", StringComparison.Ordinal))
            {
                filter.NegateSourceIp = true;
                filter.SourceIpFilter = trimmed.Substring(1).Trim();
            }
            else
            {
                filter.SourceIpFilter = trimmed;
            }
        }
        
        // Process Destination IP filter with negation check
        if (!string.IsNullOrWhiteSpace(DestinationIpFilter))
        {
            var trimmed = DestinationIpFilter.Trim();
            if (trimmed.StartsWith("!", StringComparison.Ordinal))
            {
                filter.NegateDestinationIp = true;
                filter.DestinationIpFilter = trimmed.Substring(1).Trim();
            }
            else
            {
                filter.DestinationIpFilter = trimmed;
            }
        }
        
        // Protocol filter using text field
        if (!string.IsNullOrWhiteSpace(ProtocolFilterText))
        {
            var protocolText = ProtocolFilterText.Trim();
            var isNegated = protocolText.StartsWith("!", StringComparison.Ordinal);
            if (isNegated) protocolText = protocolText.Substring(1).Trim();
            
            // Try to parse as enum protocol
            if (Enum.TryParse<Protocol>(protocolText, true, out var protocol))
            {
                filter.ProtocolFilter = protocol;
                filter.NegateProtocol = isNegated;
            }
            else
            {
                // For non-enum protocols, check Wireshark protocol field first
                filter.CustomPredicate = p => {
                    // Check exact Wireshark protocol match first
                    var matches = (p.WiresharkProtocol?.Equals(protocolText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                 p.Protocol.ToString().Equals(protocolText, StringComparison.OrdinalIgnoreCase) ||
                                 (p.Info?.Contains(protocolText, StringComparison.OrdinalIgnoreCase) ?? false);
                    return isNegated ? !matches : matches;
                };
                filter.Description = $"{(isNegated ? "NOT " : "")}Protocol: {protocolText}";
            }
        }
        
        // Process Info search text with negation check
        if (!string.IsNullOrWhiteSpace(InfoSearchText))
        {
            var trimmed = InfoSearchText.Trim();
            if (trimmed.StartsWith("!", StringComparison.Ordinal))
            {
                filter.NegateInfo = true;
                filter.InfoSearchText = trimmed.Substring(1).Trim();
            }
            else
            {
                filter.InfoSearchText = trimmed;
            }
        }
        
        // Parse numeric fields
        if (!string.IsNullOrWhiteSpace(MinLengthText) && int.TryParse(MinLengthText, out var minLen))
            filter.MinLength = minLen;
            
        if (!string.IsNullOrWhiteSpace(MaxLengthText) && int.TryParse(MaxLengthText, out var maxLen))
            filter.MaxLength = maxLen;
            
        // Process Source Port with negation check
        if (!string.IsNullOrWhiteSpace(SourcePortText))
        {
            var trimmed = SourcePortText.Trim();
            if (trimmed.StartsWith("!", StringComparison.Ordinal))
            {
                // When negating a port, we want to exclude packets where EITHER source OR destination matches
                filter.NegateSourcePort = true;
                if (ushort.TryParse(trimmed.Substring(1).Trim(), out var srcPort))
                {
                    var portStr = srcPort.ToString();
                    filter.SourcePortFilter = portStr;
                    // Also set destination port filter if not already set
                    if (string.IsNullOrWhiteSpace(DestinationPortText))
                    {
                        filter.DestinationPortFilter = portStr;
                        filter.NegateDestinationPort = true;
                    }
                }
            }
            else if (ushort.TryParse(trimmed, out var srcPort))
            {
                filter.SourcePortFilter = srcPort.ToString();
            }
        }
            
        // Process Destination Port with negation check
        if (!string.IsNullOrWhiteSpace(DestinationPortText))
        {
            var trimmed = DestinationPortText.Trim();
            if (trimmed.StartsWith("!", StringComparison.Ordinal))
            {
                // When negating a port, we want to exclude packets where EITHER source OR destination matches
                filter.NegateDestinationPort = true;
                if (ushort.TryParse(trimmed.Substring(1).Trim(), out var dstPort))
                {
                    var portStr = dstPort.ToString();
                    filter.DestinationPortFilter = portStr;
                    // Also set source port filter if not already set
                    if (string.IsNullOrWhiteSpace(SourcePortText))
                    {
                        filter.SourcePortFilter = portStr;
                        filter.NegateSourcePort = true;
                    }
                }
            }
            else if (ushort.TryParse(trimmed, out var dstPort))
            {
                filter.DestinationPortFilter = dstPort.ToString();
            }
        }
        
        IsFilterActive = !filter.IsEmpty;
        _onFilterApplied(filter);
    }
    
    [RelayCommand]
    private void ClearFilter()
    {
        SourceIpFilter = null;
        DestinationIpFilter = null;
        ProtocolFilterText = null;
        MinLengthText = null;
        MaxLengthText = null;
        SourcePortText = null;
        DestinationPortText = null;
        InfoSearchText = null;
        IsFilterActive = false;
        
        _onFilterApplied(new PacketFilter());
    }
    
    public string GetProtocolDisplayName(Protocol? protocol)
    {
        if (!protocol.HasValue)
            return "All";
            
        return protocol.Value switch
        {
            Protocol.TCP => "TCP",
            Protocol.UDP => "UDP",
            Protocol.ICMP => "ICMP",
            Protocol.HTTP => "HTTP",
            Protocol.HTTPS => "HTTPS",
            Protocol.DNS => "DNS",
            Protocol.ARP => "ARP",
            Protocol.DHCP => "DHCP",
            Protocol.LLMNR => "LLMNR",
            Protocol.NBNS => "NBNS",
            Protocol.Unknown => "Unknown",
            _ => "Unknown"
        };
    }
}