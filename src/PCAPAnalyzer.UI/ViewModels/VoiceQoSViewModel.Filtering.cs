using System;
using System.Collections.Generic;
using System.Linq;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Helpers;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// VoiceQoSViewModel partial class containing all filtering logic.
/// Handles QoS type, DSCP, IP, and GlobalFilterState filtering.
/// </summary>
public partial class VoiceQoSViewModel
{
    // ==================== FILTER CHANGE HANDLERS ====================

    partial void OnSearchFilterChanged(string value)
    {
        ApplyLocalFilters();
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    partial void OnSelectedQoSTypeChanged(string? value)
    {
        DebugLogger.Log($"[VoiceQoSViewModel] QoS Type filter changed to: {value}");
        ApplyLocalFilters();
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    partial void OnSelectedDscpMarkingChanged(string? value)
    {
        DebugLogger.Log($"[VoiceQoSViewModel] DSCP Marking filter changed to: {value}");
        ApplyLocalFilters();
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    partial void OnSourceIPFilterChanged(string value)
    {
        DebugLogger.Log($"[VoiceQoSViewModel] Source IP filter changed to: {value} (debounced)");
        _filterDebouncer.Debounce(() =>
        {
            ApplyLocalFilters();
            OnPropertyChanged(nameof(HasActiveFilters));
        });
    }

    partial void OnDestinationIPFilterChanged(string value)
    {
        DebugLogger.Log($"[VoiceQoSViewModel] Destination IP filter changed to: {value} (debounced)");
        _filterDebouncer.Debounce(() =>
        {
            ApplyLocalFilters();
            OnPropertyChanged(nameof(HasActiveFilters));
        });
    }

    partial void OnMinimumPacketThresholdChanged(int value)
    {
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    partial void OnLatencyThresholdChanged(double value)
    {
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    partial void OnJitterThresholdChanged(double value)
    {
        OnPropertyChanged(nameof(HasActiveFilters));
    }

    // ==================== LOCAL FILTER APPLICATION ====================

    /// <summary>
    /// Applies local QoS Type and DSCP Marking filters to the cached collections
    /// </summary>
    private void ApplyLocalFilters()
    {
        _dispatcher.InvokeAsync(() =>
        {
            // Snapshot collections first to avoid enumeration errors
            var qosSnapshot = _allQoSTraffic.ToList();
            var latencySnapshot = _allLatencyConnections.ToList();
            var jitterSnapshot = _allJitterConnections.ToList();

            // Apply filters using extracted helper methods
            var filteredQoS = ApplyQoSFilters(qosSnapshot);
            var filteredLatency = ApplyLatencyJitterFilters(latencySnapshot);
            var filteredJitter = ApplyLatencyJitterFilters(jitterSnapshot);

            // Apply GlobalFilterState quality/threshold filters to latency and jitter
            filteredLatency = ApplyGlobalLatencyFilters(filteredLatency);
            filteredJitter = ApplyGlobalJitterFilters(filteredJitter);

            // PAGINATION: Sort and apply pagination to filtered results
            var sortedQoS = filteredQoS.OrderByDescending(q => q.PacketCount).ToList();
            var sortedLatency = filteredLatency.OrderByDescending(l => l.AverageLatency).ToList();
            var sortedJitter = filteredJitter.OrderByDescending(j => j.AverageJitter).ToList();

            // Update pagination components with item counts
            QosTrafficPagination.UpdateFromItemCount(sortedQoS.Count);
            LatencyPagination.UpdateFromItemCount(sortedLatency.Count);
            JitterPagination.UpdateFromItemCount(sortedJitter.Count);

            // Apply pagination: Skip + Take with row numbering
            var pagedQoS = sortedQoS.Skip(QosTrafficPagination.Skip).Take(QosTrafficPagination.PageSize).ToList();
            var pagedLatency = sortedLatency.Skip(LatencyPagination.Skip).Take(LatencyPagination.PageSize).ToList();
            var pagedJitter = sortedJitter.Skip(JitterPagination.Skip).Take(JitterPagination.PageSize).ToList();

            // Calculate row numbers for each item
            for (int i = 0; i < pagedQoS.Count; i++)
            {
                pagedQoS[i].RowNumber = QosTrafficPagination.Skip + i + 1;
            }
            for (int i = 0; i < pagedLatency.Count; i++)
            {
                pagedLatency[i].RowNumber = LatencyPagination.Skip + i + 1;
            }
            for (int i = 0; i < pagedJitter.Count; i++)
            {
                pagedJitter[i].RowNumber = JitterPagination.Skip + i + 1;
            }

            lock (_collectionLock)
            {
                QosTraffic.Clear();
                foreach (var item in pagedQoS)
                {
                    QosTraffic.Add(item);
                }

                HighLatencyConnections.Clear();
                foreach (var item in pagedLatency)
                {
                    HighLatencyConnections.Add(item);
                }

                HighJitterConnections.Clear();
                foreach (var item in pagedJitter)
                {
                    HighJitterConnections.Add(item);
                }
            }

            // Recalculate filtered statistics AND top endpoints
            CalculateStatistics();
            CalculateTopEndpoints();

            // Update timeline chart with filtered data
            UpdateTimelineChart();

            DebugLogger.Log($"[VoiceQoSViewModel] Local filters applied - QoS: {QosTraffic.Count}, Latency: {HighLatencyConnections.Count}, Jitter: {HighJitterConnections.Count}");
        });
    }

    /// <summary>
    /// Apply QoS-specific filters (QoS Type, DSCP Marking, IP filters, GlobalFilterState codecs)
    /// </summary>
    private IEnumerable<QoSTrafficItem> ApplyQoSFilters(List<QoSTrafficItem> items)
    {
        var filtered = items.AsEnumerable();

        // Common protocol filter
        if (!string.IsNullOrWhiteSpace(CommonFilters.ProtocolFilter))
            filtered = filtered.Where(q => q.Protocol.Contains(CommonFilters.ProtocolFilter, StringComparison.OrdinalIgnoreCase));

        // QoS Type filter
        if (!string.IsNullOrEmpty(SelectedQoSType) && SelectedQoSType != "All")
            filtered = filtered.Where(q => q.QoSType.Contains(SelectedQoSType, StringComparison.OrdinalIgnoreCase));

        // DSCP Marking filter
        if (!string.IsNullOrEmpty(SelectedDscpMarking) && SelectedDscpMarking != "All")
            filtered = ApplyDscpFilter(filtered);

        // IP filters
        filtered = ApplyIPFilters(filtered, q => q.SourceIP, q => q.DestinationIP);

        // GlobalFilterState codec/quality filters (from UnifiedFilterPanel)
        filtered = ApplyGlobalFilterStateCriteria(filtered);

        return filtered;
    }

    /// <summary>
    /// Maps UI quality chip names to actual severity values used in data models.
    /// UI uses user-friendly terms; data uses severity-based terms.
    /// </summary>
    private static readonly Dictionary<string, string> QualityToSeverityMapping =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["Poor"] = "Critical",
            ["Fair"] = "High",
            ["Good"] = "Medium",
            ["Excellent"] = "Low"
        };

    /// <summary>
    /// Applies VoiceQoS-specific criteria from GlobalFilterState (codec, DSCP, quality filters from UnifiedFilterPanel).
    /// Supports common VoIP codecs: G.711, G.729, G.722, Opus, RTP, SIP, RTCP, H.323, MGCP, SCCP
    /// Supports DSCP classes: EF (voice), AF41-43 (video), CS3/CS5 (signaling)
    /// </summary>
    private IEnumerable<QoSTrafficItem> ApplyGlobalFilterStateCriteria(IEnumerable<QoSTrafficItem> items)
    {
        if (_globalFilterState is null || !_globalFilterState.HasActiveFilters)
            return items;

        var result = items;

        // Use helper to collect all criteria (6-tuple now includes VoipIssues)
        var (includeCodecs, _, _, excludeCodecs, _, _) =
            GlobalFilterStateHelper.CollectVoiceQoSCriteria(_globalFilterState);

        // Apply include codec/protocol filter - match against QoSType, Protocol, or DSCP marking
        if (includeCodecs.Count > 0)
        {
            result = result.Where(q => MatchesCodecOrDscp(q, includeCodecs));
        }

        // Apply exclude codec/protocol filter
        if (excludeCodecs.Count > 0)
        {
            result = result.Where(q => !MatchesCodecOrDscp(q, excludeCodecs));
        }

        return result;
    }

    /// <summary>
    /// Checks if a QoSTrafficItem matches any of the specified codecs/protocols/DSCP classes.
    /// </summary>
    private static bool MatchesCodecOrDscp(QoSTrafficItem q, HashSet<string> codecs)
    {
        // Match against QoSType (e.g., "Voice", "Video", "RTP")
        if (codecs.Any(c => q.QoSType?.Contains(c, StringComparison.OrdinalIgnoreCase) ?? false))
            return true;

        // Match against Protocol (e.g., "RTP", "SIP", "RTCP")
        if (codecs.Any(c => q.Protocol?.Contains(c, StringComparison.OrdinalIgnoreCase) ?? false))
            return true;

        // Match against DSCP marking (e.g., "EF", "AF41", "CS5")
        if (codecs.Any(c => q.DscpMarking?.Equals(c, StringComparison.OrdinalIgnoreCase) ?? false))
            return true;

        return false;
    }

    /// <summary>
    /// Applies GlobalFilterState quality, threshold, and VoipIssues criteria to latency connections.
    /// Maps UI quality values (Poor/Fair/Good/Excellent) to data severity values (Critical/High/Medium/Low).
    /// </summary>
    private IEnumerable<LatencyConnectionItem> ApplyGlobalLatencyFilters(IEnumerable<LatencyConnectionItem> items)
    {
        if (_globalFilterState is null || !_globalFilterState.HasActiveFilters)
            return items;

        var result = items;

        // Use helper to collect quality level and VoIP issues filters (6-tuple)
        var (_, includeQualities, includeIssues, _, excludeQualities, excludeIssues) =
            GlobalFilterStateHelper.CollectVoiceQoSCriteria(_globalFilterState);

        // Map UI quality values to data severity values
        var mappedIncludeQualities = MapQualitiesToSeverities(includeQualities);
        var mappedExcludeQualities = MapQualitiesToSeverities(excludeQualities);

        // Apply include quality filter
        if (mappedIncludeQualities.Count > 0)
        {
            result = result.Where(l => mappedIncludeQualities.Contains(l.LatencySeverity));
        }

        // Apply exclude quality filter
        if (mappedExcludeQualities.Count > 0)
        {
            result = result.Where(l => !mappedExcludeQualities.Contains(l.LatencySeverity));
        }

        // Apply VoIP issues filter - "High Latency" issue filters latency connections
        if (includeIssues.Count > 0 && includeIssues.Contains("High Latency"))
        {
            result = result.Where(l => l.AverageLatency >= LatencyThreshold);
        }

        // Apply latency threshold filter (show only connections above threshold)
        if (!string.IsNullOrEmpty(_globalFilterState.IncludeFilters.LatencyThreshold) &&
            double.TryParse(_globalFilterState.IncludeFilters.LatencyThreshold, out var latencyThreshold))
        {
            result = result.Where(l => l.AverageLatency >= latencyThreshold);
        }

        return result;
    }

    /// <summary>
    /// Maps UI quality chip values to data severity values.
    /// Example: "Poor" → "Critical", "Fair" → "High", "Good" → "Medium", "Excellent" → "Low"
    /// Also includes direct severity values for backwards compatibility.
    /// </summary>
    private static HashSet<string> MapQualitiesToSeverities(HashSet<string> qualities)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var q in qualities)
        {
            if (QualityToSeverityMapping.TryGetValue(q, out var severity))
                result.Add(severity);
            else
                result.Add(q); // Direct pass-through for already-severity values
        }
        return result;
    }

    /// <summary>
    /// Applies GlobalFilterState quality, threshold, and VoipIssues criteria to jitter connections.
    /// Maps UI quality values (Poor/Fair/Good/Excellent) to data severity values (Critical/High/Medium/Low).
    /// </summary>
    private IEnumerable<JitterConnectionItem> ApplyGlobalJitterFilters(IEnumerable<JitterConnectionItem> items)
    {
        if (_globalFilterState is null || !_globalFilterState.HasActiveFilters)
            return items;

        var result = items;

        // Use helper to collect quality level and VoIP issues filters (6-tuple)
        var (_, includeQualities, includeIssues, _, excludeQualities, _) =
            GlobalFilterStateHelper.CollectVoiceQoSCriteria(_globalFilterState);

        // Map UI quality values to data severity values
        var mappedIncludeQualities = MapQualitiesToSeverities(includeQualities);
        var mappedExcludeQualities = MapQualitiesToSeverities(excludeQualities);

        // Apply include quality filter
        if (mappedIncludeQualities.Count > 0)
        {
            result = result.Where(j => mappedIncludeQualities.Contains(j.JitterSeverity));
        }

        // Apply exclude quality filter
        if (mappedExcludeQualities.Count > 0)
        {
            result = result.Where(j => !mappedExcludeQualities.Contains(j.JitterSeverity));
        }

        // Apply VoIP issues filter - "High Jitter" issue filters jitter connections
        if (includeIssues.Count > 0 && includeIssues.Contains("High Jitter"))
        {
            result = result.Where(j => j.AverageJitter >= JitterThreshold);
        }

        // Apply jitter threshold filter (show only connections above threshold)
        if (!string.IsNullOrEmpty(_globalFilterState.IncludeFilters.JitterThreshold) &&
            double.TryParse(_globalFilterState.IncludeFilters.JitterThreshold, out var jitterThreshold))
        {
            result = result.Where(j => j.AverageJitter >= jitterThreshold);
        }

        return result;
    }

    /// <summary>
    /// Apply DSCP marking filter with name and value matching
    /// </summary>
    private IEnumerable<QoSTrafficItem> ApplyDscpFilter(IEnumerable<QoSTrafficItem> items)
    {
        var dscpName = SelectedDscpMarking!.Split('(')[0].Trim();
        var dscpValue = ExtractDscpValue(SelectedDscpMarking);

        return items.Where(q =>
            q.DscpMarking.Equals(dscpName, StringComparison.OrdinalIgnoreCase) ||
            q.DscpDisplay.Contains(SelectedDscpMarking, StringComparison.OrdinalIgnoreCase) ||
            (dscpValue >= 0 && q.DscpValue == dscpValue));
    }

    /// <summary>
    /// Extract DSCP numeric value from marking string "EF (46)" -> 46
    /// </summary>
    private static int ExtractDscpValue(string dscpMarking)
    {
        var startParen = dscpMarking.IndexOf('(', StringComparison.Ordinal);
        var endParen = dscpMarking.IndexOf(')', StringComparison.Ordinal);

        if (startParen > 0 && endParen > startParen)
        {
            var valueStr = dscpMarking.Substring(startParen + 1, endParen - startParen - 1).Trim();
            if (int.TryParse(valueStr, out var parsedValue))
                return parsedValue;
        }

        return -1;
    }

    /// <summary>
    /// Apply protocol and IP filters to latency/jitter connections
    /// </summary>
    private IEnumerable<T> ApplyLatencyJitterFilters<T>(List<T> items) where T : class
    {
        var filtered = items.AsEnumerable();

        // Common protocol filter
        if (!string.IsNullOrWhiteSpace(CommonFilters.ProtocolFilter))
            filtered = filtered.Where(item => GetProtocol(item).Contains(CommonFilters.ProtocolFilter, StringComparison.OrdinalIgnoreCase));

        // IP filters
        filtered = ApplyIPFilters(filtered, item => GetSourceIP(item), item => GetDestinationIP(item));

        return filtered;
    }

    /// <summary>
    /// Apply source and destination IP filters using generic selectors
    /// </summary>
    private IEnumerable<T> ApplyIPFilters<T>(IEnumerable<T> items, Func<T, string> sourceSelector, Func<T, string> destSelector)
    {
        var filtered = items;

        if (!string.IsNullOrWhiteSpace(SourceIPFilter))
            filtered = filtered.Where(item => sourceSelector(item).Contains(SourceIPFilter, StringComparison.OrdinalIgnoreCase));

        if (!string.IsNullOrWhiteSpace(DestinationIPFilter))
            filtered = filtered.Where(item => destSelector(item).Contains(DestinationIPFilter, StringComparison.OrdinalIgnoreCase));

        return filtered;
    }

    /// <summary>
    /// Get Protocol property from generic item (reflection-free)
    /// </summary>
    private static string GetProtocol<T>(T item) where T : class
    {
        return item switch
        {
            LatencyConnectionItem l => l.Protocol,
            JitterConnectionItem j => j.Protocol,
            _ => ""
        };
    }

    /// <summary>
    /// Get SourceIP property from generic item (reflection-free)
    /// </summary>
    private static string GetSourceIP<T>(T item) where T : class
    {
        return item switch
        {
            LatencyConnectionItem l => l.SourceIP,
            JitterConnectionItem j => j.SourceIP,
            _ => ""
        };
    }

    /// <summary>
    /// Get DestinationIP property from generic item (reflection-free)
    /// </summary>
    private static string GetDestinationIP<T>(T item) where T : class
    {
        return item switch
        {
            LatencyConnectionItem l => l.DestinationIP,
            JitterConnectionItem j => j.DestinationIP,
            _ => ""
        };
    }

    [RelayCommand]
    private void ClearLocalFilters()
    {
        // Clear common filters
        CommonFilters.Clear();

        // Clear tab-specific filters
        SearchFilter = "";
        LatencyThreshold = 100.0;
        JitterThreshold = 30.0;
        MinimumPacketThreshold = 10;
        SelectedQoSType = null;
        SelectedDscpMarking = null;
        SourceIPFilter = "";
        DestinationIPFilter = "";
        OnPropertyChanged(nameof(HasActiveFilters));
    }
}
