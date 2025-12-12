using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Filtering logic for DashboardViewModel.
/// Contains async filter methods and smart filter building.
/// </summary>
public partial class DashboardViewModel
{
    private async Task UpdateFilteredStatisticsAsync()
    {
        // Cancel any in-progress filter operation
        _filterCancellationTokenSource?.Cancel();
        _filterCancellationTokenSource = new System.Threading.CancellationTokenSource();
        var cancellationToken = _filterCancellationTokenSource.Token;

        try
        {
            if (_allPackets is null || _allPackets.Count == 0)
            {
                DebugLogger.Log("[DashboardViewModel] No packets available for filtering");
                return;
            }

            IsFilteringInProgress = true;
            FilterProgress = 0.0;

            var startTime = DateTime.Now;
            DebugLogger.Log($"[DashboardViewModel] Starting async filter on {_allPackets.Count:N0} packets");

            // Build smart filter state from current toggle values
            var smartFilters = BuildSmartFilterState();
            var hasSmartFilters = smartFilters.HasActiveFilters;

            // Check if any filters are active
            var hasCommonFilters = CommonFilters.HasActiveFilters ||
                                   TrafficTypeFilter != "All" ||
                                   !string.IsNullOrWhiteSpace(PortRangeFilter) ||
                                   !string.IsNullOrWhiteSpace(FilterText) ||
                                   FilterStartTime.HasValue ||
                                   FilterEndTime.HasValue ||
                                   FilterProtocol != "All";

            IsFilterActive = hasCommonFilters || hasSmartFilters;

            // Update filter descriptions for badge display
            await _dispatcher.InvokeAsync(() =>
            {
                ActiveFilterDescriptions.Clear();
                if (hasSmartFilters)
                {
                    var descriptions = _dashboardFilterService.GetActiveFilterDescriptions(smartFilters);
                    foreach (var desc in descriptions)
                    {
                        ActiveFilterDescriptions.Add(desc);
                    }
                }
            });

            if (!IsFilterActive)
            {
                _filteredPackets = null;
                await RestoreUnfilteredStateAsync("Legacy filter cleared");
                return;
            }

            // Phase 1: Apply common/legacy filters
            var preFilteredPackets = await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ApplyCommonFilters(_allPackets);
            }, cancellationToken);

            FilterProgress = 0.3;

            // Phase 2: Apply smart filters using the optimized service
            List<PacketInfo> filteredList;
            if (hasSmartFilters)
            {
                var progress = new Progress<double>(p => FilterProgress = 0.3 + (p * 0.5));
                var anomalyFrameSet = BuildAnomalyFrameSet();
                filteredList = await _dashboardFilterService.ApplySmartFiltersAsync(
                    preFilteredPackets,
                    smartFilters,
                    anomalyFrameSet,
                    FilterUseAndMode,
                    FilterUseNotMode,
                    progress,
                    cancellationToken);
            }
            else
            {
                filteredList = preFilteredPackets;
            }

            FilterProgress = 0.8;
            cancellationToken.ThrowIfCancellationRequested();

            // Phase 3: Calculate statistics on background thread
            var filteredStats = await Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();
                return _statisticsService.CalculateStatistics(filteredList);
            }, cancellationToken);

            FilterProgress = 0.95;
            cancellationToken.ThrowIfCancellationRequested();

            // Phase 4: Update UI
            await _dispatcher.InvokeAsync(() =>
            {
                _filteredPackets = filteredList;
                _filteredStatistics = filteredStats;
                _currentStatistics = filteredStats;
                Statistics.UpdateAllStatistics(filteredStats, isFiltered: true);
                Charts.UpdateAllCharts(filteredStats);
                UpdateExtendedCollections();
                UpdatePortActivityTimeline();
                UpdateNetworkStatsBar();
            });

            FilterProgress = 1.0;
            var elapsed = (DateTime.Now - startTime).TotalSeconds;
            DebugLogger.Log($"[DashboardViewModel] Async filter complete in {elapsed:F2}s: {filteredList.Count:N0}/{_allPackets.Count:N0} packets");
        }
        catch (OperationCanceledException)
        {
            DebugLogger.Log("[DashboardViewModel] Filter operation cancelled");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DashboardViewModel] Error in async filtering: {ex.Message}");
        }
        finally
        {
            IsFilteringInProgress = false;
        }
    }

    private async Task RestoreUnfilteredStateAsync(string logContext)
    {
        await _dispatcher.InvokeAsync(() =>
        {
            _currentStatistics = _unfilteredStatistics;
            _filteredStatistics = null; // Clear filtered stats
            Statistics.ClearFilteredStatistics();

            if (_unfilteredStatistics is not null)
            {
                Statistics.UpdateAllStatistics(_unfilteredStatistics, isFiltered: false);
                Charts.UpdateAllCharts(_unfilteredStatistics);
                DebugLogger.Log($"[DashboardViewModel] {logContext} - Charts restored to unfiltered data");
            }

            UpdateExtendedCollections();
            UpdatePortActivityTimeline();
            UpdateNetworkStatsBar();
        });
        DebugLogger.Log("[DashboardViewModel] No filters active, using unfiltered packets");
    }

    private List<PacketInfo> ApplyCommonFilters(IReadOnlyList<PacketInfo> packets)
    {
        var predicates = new List<Func<PacketInfo, bool>>();

        if (!string.IsNullOrWhiteSpace(CommonFilters.ProtocolFilter))
        {
            var filter = CommonFilters.ProtocolFilter;
            predicates.Add(p => p.Protocol.ToString().Contains(filter, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(CommonFilters.SourceIPFilter))
        {
            var filter = CommonFilters.SourceIPFilter;
            predicates.Add(p => p.SourceIP.Contains(filter, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(CommonFilters.DestinationIPFilter))
        {
            var filter = CommonFilters.DestinationIPFilter;
            predicates.Add(p => p.DestinationIP.Contains(filter, StringComparison.OrdinalIgnoreCase));
        }

        if (TrafficTypeFilter != "All")
        {
            var filter = TrafficTypeFilter;
            predicates.Add(p => p.Protocol.ToString().Equals(filter, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(PortRangeFilter))
        {
            var portPredicate = BuildPortRangePredicate(PortRangeFilter);
            if (portPredicate is not null)
                predicates.Add(portPredicate);
        }

        if (!string.IsNullOrWhiteSpace(FilterText))
        {
            var filter = FilterText;
            predicates.Add(p =>
                p.SourceIP.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                p.DestinationIP.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                (p.Info?.Contains(filter, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        if (FilterStartTime.HasValue)
        {
            var startTime = FilterStartTime.Value;
            predicates.Add(p => p.Timestamp >= startTime);
        }

        if (FilterEndTime.HasValue)
        {
            var endTime = FilterEndTime.Value;
            predicates.Add(p => p.Timestamp <= endTime);
        }

        if (FilterProtocol != "All")
        {
            var filter = FilterProtocol;
            predicates.Add(p => p.Protocol.ToString() == filter);
        }

        if (predicates.Count == 0)
            return packets as List<PacketInfo> ?? packets.ToList();

        var result = new List<PacketInfo>(packets.Count / 2);
        foreach (var packet in packets)
        {
            var passes = true;
            foreach (var pred in predicates)
            {
                if (!pred(packet))
                {
                    passes = false;
                    break;
                }
            }
            if (passes)
                result.Add(packet);
        }

        return result;
    }

    private static Func<PacketInfo, bool>? BuildPortRangePredicate(string portFilter)
    {
        var ports = new HashSet<ushort>();
        var ranges = new List<(ushort min, ushort max)>();

        foreach (var part in portFilter.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.Contains('-', StringComparison.Ordinal))
            {
                var rangeParts = part.Split('-');
                if (rangeParts.Length == 2 &&
                    ushort.TryParse(rangeParts[0].Trim(), out var minPort) &&
                    ushort.TryParse(rangeParts[1].Trim(), out var maxPort))
                {
                    ranges.Add((Math.Min(minPort, maxPort), Math.Max(minPort, maxPort)));
                }
            }
            else if (ushort.TryParse(part, out var singlePort))
            {
                ports.Add(singlePort);
            }
        }

        if (ports.Count == 0 && ranges.Count == 0)
            return null;

        return p =>
        {
            if (ports.Contains(p.SourcePort) || ports.Contains(p.DestinationPort))
                return true;

            foreach (var (min, max) in ranges)
            {
                if ((p.SourcePort >= min && p.SourcePort <= max) ||
                    (p.DestinationPort >= min && p.DestinationPort <= max))
                    return true;
            }

            return false;
        };
    }

    private AnomalyFrameSet BuildAnomalyFrameSet()
    {
        return new AnomalyFrameSet
        {
            AllFrames = new HashSet<long>(_anomalyFrameNumbers),
            HighSeverityFrames = new HashSet<long>(_highSeverityFrames),
            TcpAnomalyFrames = new HashSet<long>(_tcpAnomalyFrames),
            NetworkAnomalyFrames = new HashSet<long>(_networkAnomalyFrames)
        };
    }

    private DashboardSmartFilters BuildSmartFilterState()
    {
        return new DashboardSmartFilters
        {
            // Network Type Filters (from SmartFilterableTab)
            Rfc1918 = FilterRfc1918Toggle,
            PublicIP = FilterPublicIpToggle,
            Apipa = FilterApipaToggle,
            Ipv4 = FilterIPv4Toggle,
            Ipv6 = FilterIPv6Toggle,
            Multicast = FilterMulticastToggle,
            Broadcast = FilterBroadcastToggle,
            Anycast = FilterAnycastToggle,

            // Security Filters
            Insecure = FilterInsecureToggle,
            Anomalies = FilterAnomaliesToggle,
            Suspicious = FilterSuspiciousToggle,
            TcpIssues = FilterTcpIssuesToggle,
            DnsAnomalies = FilterDnsAnomaliesToggle,
            PortScans = FilterPortScansToggle,

            // Traffic Pattern Filters
            JumboFrames = FilterJumboFramesToggle,
            PrivateToPublic = FilterPrivateToPublicToggle,
            PublicToPrivate = FilterPublicToPrivateToggle,
            LinkLocal = FilterLinkLocalToggle,
            Loopback = FilterLoopbackToggle,

            // TCP Performance
            Retransmissions = FilterRetransmissionsToggle,
            ZeroWindow = FilterZeroWindowToggle,
            KeepAlive = FilterKeepAliveToggle,
            ConnectionRefused = FilterConnectionRefusedToggle,
            WindowFull = FilterWindowFullToggle,

            // Security Audit
            CleartextAuth = FilterCleartextAuthToggle,
            ObsoleteCrypto = FilterObsoleteCryptoToggle,
            DnsTunneling = FilterDnsTunnelingToggle,
            ScanTraffic = FilterScanTrafficToggle,
            NonStandardPorts = FilterNonStandardPortsToggle,
            SmbV1 = FilterSmbV1Toggle,

            // Clean View
            HideBroadcast = FilterHideBroadcastToggle,
            ApplicationDataOnly = FilterApplicationDataOnlyToggle,
            HideTunnelOverhead = FilterHideTunnelOverheadToggle,

            // Protocol Errors
            HttpErrors = FilterHttpErrorsToggle,
            DnsFailures = FilterDnsFailuresToggle,
            IcmpUnreachable = FilterIcmpUnreachableToggle,

            // L7 Protocol Filters (Dashboard-only)
            TlsV10 = FilterTlsV10Toggle,
            TlsV11 = FilterTlsV11Toggle,
            TlsV12 = FilterTlsV12Toggle,
            TlsV13 = FilterTlsV13Toggle,
            Http = FilterHttpToggle,
            Https = FilterHttpsToggle,
            Dns = FilterDnsToggle,
            Snmp = FilterSnmpToggle,
            Ssh = FilterSshToggle,
            Ftp = FilterFtpToggle,
            Smtp = FilterSmtpToggle,
            Stun = FilterStunToggle,
            Dhcp = FilterDhcpServerToggle,

            // VPN Protocol Filters
            WireGuard = FilterWireGuardToggle,
            OpenVPN = FilterOpenVpnToggle,
            IkeV2 = FilterIkeV2Toggle,
            Ipsec = FilterIpsecToggle,
            L2tp = FilterL2tpToggle,
            Pptp = FilterPptpToggle
        };
    }
}
