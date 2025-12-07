using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Handles navigation and filter operations for tab switching and packet navigation.
/// Extracted from MainWindowViewModel to reduce file size.
/// </summary>
public class MainWindowNavigationViewModel
{
    private readonly ITabFilterService _packetAnalysisFilterService;

    public MainWindowNavigationViewModel(ITabFilterService packetAnalysisFilterService)
    {
        ArgumentNullException.ThrowIfNull(packetAnalysisFilterService);
        _packetAnalysisFilterService = packetAnalysisFilterService;
    }

    /// <summary>
    /// Handles Dashboard navigation requests with tab name and optional filter.
    /// Format: "TabName?filter=value"
    /// </summary>
    public int? HandleDashboardNavigation(string navigationTarget, Action<string?>? applyFilter = null)
    {
        DebugLogger.Log($"[Navigation] HandleDashboardNavigation: {navigationTarget}");

        var parts = navigationTarget.Split('?', 2);
        var tabName = parts[0];
        var filter = parts.Length > 1 ? parts[1] : null;

        var tabIndex = tabName switch
        {
            "PacketAnalysis" => 1,
            "Dashboard" => 2,
            "Threats" => 3,
            "VoiceQoS" => 4,
            "CountryTraffic" => 5,
            "Map" => 6,
            "Report" => 7,
            "Anomalies" => 8,
            _ => -1
        };

        if (tabIndex >= 0)
        {
            DebugLogger.Log($"[Navigation] Navigating to tab {tabName} (index {tabIndex}), filter: {filter ?? "none"}");

            // Apply filter if provided (for PacketAnalysis tab)
            if (!string.IsNullOrEmpty(filter) && tabIndex == 1)
            {
                ApplyNavigationFilter(filter);
            }

            return tabIndex;
        }
        else
        {
            DebugLogger.Critical($"[Navigation] Unknown tab name: {tabName}");
            return null;
        }
    }

    /// <summary>
    /// Applies filter from navigation query string (e.g., "ip=192.168.1.1" or "port=443").
    /// </summary>
    private void ApplyNavigationFilter(string filter)
    {
        var filterParts = filter.Split('=', 2);
        if (filterParts.Length != 2) return;

        var filterType = filterParts[0];
        var filterValue = filterParts[1];
        DebugLogger.Log($"[Navigation] Applying filter: {filterType}={filterValue}");

        switch (filterType.ToLowerInvariant())
        {
            case "ip":
                _packetAnalysisFilterService.ApplyIPFilter(filterValue);
                break;
            case "port":
                if (int.TryParse(filterValue, out var port))
                    _packetAnalysisFilterService.ApplyPortFilter(port);
                break;
            case "conversation":
            case "connection":
                ApplyConversationFilter(filterValue);
                break;
            default:
                DebugLogger.Log($"[Navigation] Unknown filter type: {filterType}");
                break;
        }
    }

    /// <summary>
    /// Applies conversation filter from format "srcIP:srcPort-dstIP:dstPort".
    /// </summary>
    private void ApplyConversationFilter(string filterValue)
    {
        var convParts = filterValue.Split('-');
        if (convParts.Length != 2) return;

        var srcParts = convParts[0].Split(':');
        var dstParts = convParts[1].Split(':');

        if (srcParts.Length == 2 && dstParts.Length == 2 &&
            int.TryParse(srcParts[1], out var srcPort) &&
            int.TryParse(dstParts[1], out var dstPort))
        {
            var srcIP = srcParts[0];
            var dstIP = dstParts[0];
            _packetAnalysisFilterService.ApplyCustomFilter(
                p => (p.SourceIP == srcIP && p.SourcePort == srcPort && p.DestinationIP == dstIP && p.DestinationPort == dstPort) ||
                     (p.SourceIP == dstIP && p.SourcePort == dstPort && p.DestinationIP == srcIP && p.DestinationPort == srcPort),
                $"Connection: {srcIP}:{srcPort} ↔ {dstIP}:{dstPort}");
        }
    }

    /// <summary>
    /// Handles DrillDown navigation from Security Threats to Packet Analysis.
    /// Filters packets to show only threat-related frames.
    /// </summary>
    public void NavigateToPacketAnalysisFromThreat(List<uint> frameNumbers, string context)
    {
        try
        {
            if (frameNumbers is null || frameNumbers.Count == 0)
            {
                DebugLogger.Log("[Navigation] No frame numbers to filter - showing all packets");
                return;
            }

            var frameSet = new HashSet<uint>(frameNumbers);

            _packetAnalysisFilterService.ApplyCustomFilter(
                p => frameSet.Contains(p.FrameNumber),
                $"Threat Evidence: {context} ({frameNumbers.Count} packets)");

            DebugLogger.Log($"[Navigation] Filtered to {frameNumbers.Count} threat-related frames");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[Navigation] Error navigating to Packet Analysis: {ex.Message}");
        }
    }

    /// <summary>
    /// Handles "Go to Packet" request by frame number.
    /// </summary>
    public (int PageNumber, int PacketIndex) FindPacketPage(uint frameNumber, IReadOnlyList<Core.Models.PacketInfo> filteredPackets, int pageSize)
    {
        var packetIndex = -1;

        for (int i = 0; i < filteredPackets.Count; i++)
        {
            if (filteredPackets[i].FrameNumber == frameNumber)
            {
                packetIndex = i;
                break;
            }
        }

        if (packetIndex < 0)
            return (-1, -1);

        var pageNumber = (packetIndex / pageSize) + 1;
        return (pageNumber, packetIndex);
    }

    /// <summary>
    /// Handles stream filter request.
    /// </summary>
    public int ApplyStreamFilter(string searchPattern, MainWindowPacketViewModel packetManager)
    {
        if (string.IsNullOrWhiteSpace(searchPattern))
        {
            packetManager.ClearStreamFilter();
            return 0;
        }

        return packetManager.ApplyStreamFilter(searchPattern);
    }
}
