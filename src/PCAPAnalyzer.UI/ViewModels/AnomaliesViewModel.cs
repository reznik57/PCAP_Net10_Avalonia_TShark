using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// Main ViewModel for the Anomalies tab.
/// Orchestrates component ViewModels and manages anomaly data.
/// </summary>
public partial class AnomaliesViewModel : ObservableObject, ITabPopulationTarget, IDisposable
{
    private readonly IAnomalyFrameIndexService _frameIndexService;
    private readonly GlobalFilterState _globalFilterState;
    private readonly IGeoIPService _geoIPService;
    private readonly ILogger<AnomaliesViewModel> _logger;

    private List<NetworkAnomaly> _allAnomalies = new();
    private List<NetworkAnomaly> _filteredAnomalies = new();
    private CancellationTokenSource? _filterCts;
    private bool _disposed;

    // Component ViewModels
    public AnomaliesStatisticsViewModel Statistics { get; }
    public AnomaliesChartsViewModel Charts { get; }
    public AnomaliesDrillDownViewModel DrillDown { get; }
    public AnomaliesFilterViewModel Filters { get; }

    // Loading state
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private bool _hasData;
    [ObservableProperty] private string _loadingMessage = "Loading anomalies...";

    // Filter progress
    [ObservableProperty] private bool _isFiltering;
    [ObservableProperty] private double _filterProgress;

    // ITabPopulationTarget implementation
    public string TabName => "Anomalies";

    public AnomaliesViewModel(
        IAnomalyFrameIndexService frameIndexService,
        GlobalFilterState globalFilterState,
        IGeoIPService geoIPService,
        ILogger<AnomaliesViewModel> logger)
    {
        _frameIndexService = frameIndexService;
        _globalFilterState = globalFilterState;
        _geoIPService = geoIPService;
        _logger = logger;

        // Initialize component ViewModels
        Statistics = new AnomaliesStatisticsViewModel();
        Charts = new AnomaliesChartsViewModel();
        DrillDown = new AnomaliesDrillDownViewModel();
        Filters = new AnomaliesFilterViewModel(globalFilterState);

        // Subscribe to filter changes
        Filters.FiltersChanged += OnFiltersChanged;
        _globalFilterState.PropertyChanged += OnGlobalFilterStateChanged;
    }

    /// <summary>
    /// ITabPopulationTarget implementation - populate from cached analysis result.
    /// </summary>
    public async Task PopulateFromCacheAsync(AnalysisResult result)
    {
        _logger.LogInformation("PopulateFromCacheAsync called with {Count} anomalies", result.Anomalies?.Count ?? 0);

        if (result.Anomalies == null || result.Anomalies.Count == 0)
        {
            _logger.LogWarning("No anomalies in AnalysisResult");
            HasData = false;
            return;
        }

        await LoadFromAnalysisResultAsync(result.Anomalies);
    }

    public async Task LoadFromAnalysisResultAsync(List<NetworkAnomaly> anomalies)
    {
        if (anomalies == null)
        {
            _logger.LogWarning("LoadFromAnalysisResultAsync called with null anomalies");
            HasData = false;
            return;
        }

        IsLoading = true;
        LoadingMessage = "Loading anomalies...";

        try
        {
            _allAnomalies = anomalies.ToList();
            _filteredAnomalies = _allAnomalies;

            // Build frame index for cross-tab filtering
            _frameIndexService.BuildIndex(_allAnomalies);

            // Populate available detectors in filter panel
            Filters.SetAvailableDetectors(_frameIndexService.GetDetectorNames());

            await UpdateAllComponentsAsync();

            HasData = _allAnomalies.Count > 0;
            _logger.LogInformation("Loaded {Count} anomalies", _allAnomalies.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error loading anomalies");
            HasData = false;
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task UpdateAllComponentsAsync()
    {
        await Task.Run(() =>
        {
            var kpis = CalculateKPIs(_filteredAnomalies);
            var timePoints = BuildTimelineSeries(_filteredAnomalies);
            var sources = BuildRankedSources(_filteredAnomalies);
            var targets = BuildRankedTargets(_filteredAnomalies);
            var ports = BuildPortBreakdown(_filteredAnomalies);
            var categories = BuildCategoryBreakdown(_filteredAnomalies);

            Dispatcher.UIThread.Post(() =>
            {
                Statistics.UpdateKPIs(kpis);
                Statistics.UpdateTopSources(sources);
                Statistics.UpdateTopTargets(targets);
                Statistics.UpdateTopPorts(ports);
                Statistics.UpdateCategoryBreakdown(categories);
                Statistics.SetFilteredState(
                    _filteredAnomalies.Count != _allAnomalies.Count,
                    _filteredAnomalies.Count);

                Charts.UpdateTimeline(timePoints);
                Charts.UpdateCategoryDonut(categories);
                Charts.UpdatePortsBar(ports);
            });
        });
    }

    private AnomalyKPIs CalculateKPIs(List<NetworkAnomaly> anomalies)
    {
        if (anomalies.Count == 0)
            return new AnomalyKPIs();

        var timestamps = anomalies
            .Select(a => a.DetectedAt)
            .OrderBy(t => t)
            .ToList();

        return new AnomalyKPIs
        {
            TotalAnomalies = anomalies.Count,
            CriticalCount = anomalies.Count(a => a.Severity == AnomalySeverity.Critical),
            HighCount = anomalies.Count(a => a.Severity == AnomalySeverity.High),
            MediumCount = anomalies.Count(a => a.Severity == AnomalySeverity.Medium),
            LowCount = anomalies.Count(a => a.Severity == AnomalySeverity.Low),
            UniqueSourceIPs = anomalies.Select(a => a.SourceIP).Where(ip => !string.IsNullOrEmpty(ip)).Distinct().Count(),
            UniqueTargetIPs = anomalies.Select(a => a.DestinationIP).Where(ip => !string.IsNullOrEmpty(ip)).Distinct().Count(),
            FirstAnomalyTime = timestamps.FirstOrDefault(),
            LastAnomalyTime = timestamps.LastOrDefault(),
            TimeSpan = timestamps.Count > 1 ? timestamps.Last() - timestamps.First() : TimeSpan.Zero
        };
    }

    private List<AnomalyTimePoint> BuildTimelineSeries(List<NetworkAnomaly> anomalies)
    {
        if (anomalies.Count == 0)
            return new List<AnomalyTimePoint>();

        // Group by second for fine-grained timeline
        var grouped = anomalies
            .GroupBy(a => new DateTime(
                a.DetectedAt.Year, a.DetectedAt.Month, a.DetectedAt.Day,
                a.DetectedAt.Hour, a.DetectedAt.Minute, a.DetectedAt.Second))
            .OrderBy(g => g.Key);

        return grouped.Select(g => new AnomalyTimePoint
        {
            Timestamp = g.Key,
            CriticalCount = g.Count(a => a.Severity == AnomalySeverity.Critical),
            HighCount = g.Count(a => a.Severity == AnomalySeverity.High),
            MediumCount = g.Count(a => a.Severity == AnomalySeverity.Medium),
            LowCount = g.Count(a => a.Severity == AnomalySeverity.Low)
        }).ToList();
    }

    private List<AnomalyEndpointViewModel> BuildRankedSources(List<NetworkAnomaly> anomalies)
    {
        return anomalies
            .Where(a => !string.IsNullOrEmpty(a.SourceIP))
            .GroupBy(a => a.SourceIP)
            .Select(g => BuildEndpointViewModel(g.Key!, g.ToList()))
            .OrderByDescending(e => e.CriticalCount)
            .ThenByDescending(e => e.HighCount)
            .ThenByDescending(e => e.AnomalyCount)
            .Take(20)
            .Select((e, i) => { e.Rank = i + 1; return e; })
            .ToList();
    }

    private List<AnomalyEndpointViewModel> BuildRankedTargets(List<NetworkAnomaly> anomalies)
    {
        return anomalies
            .Where(a => !string.IsNullOrEmpty(a.DestinationIP))
            .GroupBy(a => a.DestinationIP)
            .Select(g => BuildEndpointViewModel(g.Key!, g.ToList()))
            .OrderByDescending(e => e.CriticalCount)
            .ThenByDescending(e => e.HighCount)
            .ThenByDescending(e => e.AnomalyCount)
            .Take(20)
            .Select((e, i) => { e.Rank = i + 1; return e; })
            .ToList();
    }

    private AnomalyEndpointViewModel BuildEndpointViewModel(string ip, List<NetworkAnomaly> anomalies)
    {
        var total = _filteredAnomalies.Count > 0 ? _filteredAnomalies.Count : 1;
        // GetLocationAsync is async, but we're in a sync method. For now, use sync wrapper or defaults.
        // TODO: Refactor to async if needed for GeoIP enrichment
        var geoInfo = Task.Run(() => _geoIPService.GetLocationAsync(ip)).GetAwaiter().GetResult();

        return new AnomalyEndpointViewModel
        {
            IpAddress = ip,
            AnomalyCount = anomalies.Count,
            CriticalCount = anomalies.Count(a => a.Severity == AnomalySeverity.Critical),
            HighCount = anomalies.Count(a => a.Severity == AnomalySeverity.High),
            MediumCount = anomalies.Count(a => a.Severity == AnomalySeverity.Medium),
            LowCount = anomalies.Count(a => a.Severity == AnomalySeverity.Low),
            HighestSeverity = anomalies.Max(a => a.Severity),
            Percentage = (double)anomalies.Count / total * 100,
            Country = geoInfo?.CountryName ?? "Unknown",
            CountryCode = geoInfo?.CountryCode ?? "",
            Categories = anomalies.Select(a => a.Category).Distinct().ToList(),
            AffectedFrames = anomalies.SelectMany(a => a.AffectedFrames ?? Enumerable.Empty<long>()).Distinct().ToList()
        };
    }

    private List<AnomalyPortViewModel> BuildPortBreakdown(List<NetworkAnomaly> anomalies)
    {
        var portAnomalies = anomalies
            .Where(a => a.DestinationPort > 0)
            .GroupBy(a => a.DestinationPort)
            .Select(g => new AnomalyPortViewModel
            {
                Port = g.Key,
                ServiceName = GetServiceName(g.Key),
                AnomalyCount = g.Count(),
                Percentage = (double)g.Count() / anomalies.Count * 100,
                HighestSeverity = g.Max(a => a.Severity),
                AffectedFrames = g.SelectMany(a => a.AffectedFrames ?? Enumerable.Empty<long>()).Distinct().ToList()
            })
            .OrderByDescending(p => p.AnomalyCount)
            .Take(15)
            .Select((p, i) => { p.Rank = i + 1; return p; })
            .ToList();

        return portAnomalies;
    }

    private List<AnomalyCategoryViewModel> BuildCategoryBreakdown(List<NetworkAnomaly> anomalies)
    {
        if (anomalies.Count == 0)
            return new List<AnomalyCategoryViewModel>();

        return anomalies
            .GroupBy(a => a.Category)
            .Select(g => new AnomalyCategoryViewModel
            {
                Category = g.Key,
                Count = g.Count(),
                Percentage = (double)g.Count() / anomalies.Count * 100
            })
            .OrderByDescending(c => c.Count)
            .ToList();
    }

    private static string GetServiceName(int port) => port switch
    {
        20 => "FTP-Data",
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        67 => "DHCP",
        68 => "DHCP",
        69 => "TFTP",
        80 => "HTTP",
        88 => "Kerberos",
        110 => "POP3",
        111 => "RPC",
        123 => "NTP",
        135 => "RPC-Loc",
        137 => "NetBIOS",
        138 => "NetBIOS",
        139 => "NetBIOS",
        143 => "IMAP",
        161 => "SNMP",
        162 => "SNMP-Trap",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        464 => "Kerberos",
        465 => "SMTPS",
        500 => "IKE",
        514 => "Syslog",
        515 => "LPR",
        520 => "RIP",
        587 => "SMTP",
        636 => "LDAPS",
        993 => "IMAPS",
        995 => "POP3S",
        1080 => "SOCKS",
        1194 => "OpenVPN",
        1433 => "MSSQL",
        1434 => "MSSQL-UDP",
        1521 => "Oracle",
        1723 => "PPTP",
        1883 => "MQTT",
        2049 => "NFS",
        2082 => "cPanel",
        2083 => "cPanel-SSL",
        2181 => "ZooKeeper",
        3306 => "MySQL",
        3389 => "RDP",
        4060 => "DT-Mgmt",
        5060 => "SIP",
        5061 => "SIP-TLS",
        5432 => "PostgreSQL",
        5672 => "AMQP",
        5683 => "CoAP",
        5900 => "VNC",
        5985 => "WinRM",
        5986 => "WinRM-SSL",
        6379 => "Redis",
        6443 => "K8s-API",
        7680 => "WUDO",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        8883 => "MQTT-SSL",
        9000 => "SonarQube",
        9092 => "Kafka",
        9200 => "Elastic",
        27017 => "MongoDB",
        _ => ""
    };

    private void OnFiltersChanged(object? sender, EventArgs e)
    {
        _ = ApplyFiltersAsync();
    }

    private void OnGlobalFilterStateChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        // React to anomaly filter changes
        if (e.PropertyName is "AnomalySeverityFilter" or "AnomalyCategoryFilter" or "AnomalyDetectorFilter")
        {
            _ = ApplyFiltersAsync();
        }
    }

    [RelayCommand]
    private async Task ApplyFiltersAsync()
    {
        _filterCts?.Cancel();
        _filterCts = new CancellationTokenSource();
        var token = _filterCts.Token;

        IsFiltering = true;
        FilterProgress = 0;

        try
        {
            _filteredAnomalies = await Task.Run(() =>
            {
                var result = _frameIndexService.GetFilteredAnomalies(
                    _globalFilterState.AnomalySeverityFilter.Count > 0 ? _globalFilterState.AnomalySeverityFilter : null,
                    _globalFilterState.AnomalyCategoryFilter.Count > 0 ? _globalFilterState.AnomalyCategoryFilter : null,
                    _globalFilterState.AnomalyDetectorFilter.Count > 0 ? _globalFilterState.AnomalyDetectorFilter : null);

                // Apply IP filters from IncludeFilters/ExcludeFilters if set
                var filtered = result.AsEnumerable();

                if (_globalFilterState.IncludeFilters.IPs.Count > 0)
                {
                    filtered = filtered.Where(a =>
                        _globalFilterState.IncludeFilters.IPs.Contains(a.SourceIP) ||
                        _globalFilterState.IncludeFilters.IPs.Contains(a.DestinationIP));
                }

                if (_globalFilterState.ExcludeFilters.IPs.Count > 0)
                {
                    filtered = filtered.Where(a =>
                        !_globalFilterState.ExcludeFilters.IPs.Contains(a.SourceIP) &&
                        !_globalFilterState.ExcludeFilters.IPs.Contains(a.DestinationIP));
                }

                return filtered.ToList();
            }, token);

            FilterProgress = 50;

            if (!token.IsCancellationRequested)
            {
                await UpdateAllComponentsAsync();
                FilterProgress = 100;
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Filter operation cancelled");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error applying filters");
        }
        finally
        {
            IsFiltering = false;
        }
    }

    [RelayCommand]
    private void ShowSourceDrillDown(AnomalyEndpointViewModel source)
    {
        var sourceAnomalies = _filteredAnomalies
            .Where(a => a.SourceIP == source.IpAddress)
            .ToList();

        DrillDown.ShowSourceDetail(source.IpAddress, sourceAnomalies);
    }

    [RelayCommand]
    private void ShowTargetDrillDown(AnomalyEndpointViewModel target)
    {
        var targetAnomalies = _filteredAnomalies
            .Where(a => a.DestinationIP == target.IpAddress)
            .ToList();

        DrillDown.ShowTargetDetail(target.IpAddress, targetAnomalies);
    }

    [RelayCommand]
    private void ShowPortDrillDown(AnomalyPortViewModel port)
    {
        var portAnomalies = _filteredAnomalies
            .Where(a => a.DestinationPort == port.Port)
            .ToList();

        var serviceName = string.IsNullOrEmpty(port.ServiceName) ? port.Port.ToString() : $"{port.Port} ({port.ServiceName})";
        DrillDown.ShowPortDetail(serviceName, portAnomalies);
    }

    [RelayCommand]
    private void ShowTimeSliceDrillDown(DateTime timestamp)
    {
        DrillDown.ShowTimeSliceDrillDown(timestamp, TimeSpan.FromMinutes(5), _filteredAnomalies);
    }

    public void Clear()
    {
        _allAnomalies.Clear();
        _filteredAnomalies.Clear();
        _frameIndexService.ClearIndex();
        Statistics.Clear();
        Charts.Clear();
        DrillDown.Clear();
        HasData = false;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        Filters.FiltersChanged -= OnFiltersChanged;
        _globalFilterState.PropertyChanged -= OnGlobalFilterStateChanged;
        _filterCts?.Cancel();
        _filterCts?.Dispose();
    }
}
