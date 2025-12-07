using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Constants;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// ViewModel for the Top Talkers report view.
/// Provides comprehensive analysis of most active network endpoints.
/// </summary>
public partial class TopTalkersViewModel : ObservableObject
{
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    private readonly ICsvExportService? _csvExportService;
    private readonly IFileDialogService? _fileDialogService;

    // ==================== DATA SOURCES ====================

    private NetworkStatistics? _currentStatistics;
    private List<PacketInfo>? _currentPackets;

    // ==================== VIEW MODE ====================

    [ObservableProperty] private string _selectedView = ViewModes.Combined;
    [ObservableProperty] private string _selectedMetric = MetricTypes.Packets;
    [ObservableProperty] private int _topN = 20;

    public ObservableCollection<string> ViewOptions { get; } = new()
    {
        "Combined",
        "Sources Only",
        "Destinations Only",
        "Conversations"
    };

    public ObservableCollection<string> MetricOptions { get; } = new()
    {
        "Packets",
        "Bytes",
        "Both"
    };

    public ObservableCollection<int> TopNOptions { get; } = new()
    {
        10, 20, 50, 100
    };

    // ==================== TOP TALKERS DATA ====================

    [ObservableProperty] private ObservableCollection<TopTalkerViewModel> _topTalkers = [];
    [ObservableProperty] private ObservableCollection<ConversationDetailViewModel> _topConversations = [];

    // ==================== SELECTED TALKER DETAILS ====================

    [ObservableProperty] private TopTalkerViewModel? _selectedTalker;
    [ObservableProperty] private ObservableCollection<ProtocolBreakdownViewModel> _protocolBreakdown = [];
    [ObservableProperty] private ObservableCollection<ConversationDetailViewModel> _talkerConversations = [];
    [ObservableProperty] private ObservableCollection<TimeSeriesPointViewModel> _talkerTimeline = [];

    // ==================== SUMMARY STATISTICS ====================

    [ObservableProperty] private long _totalPackets;
    [ObservableProperty] private string _totalBytesFormatted = "0 B";
    [ObservableProperty] private int _uniqueEndpoints;
    [ObservableProperty] private int _activeConversations;
    [ObservableProperty] private double _topTalkersPercentage;

    // ==================== EXPORT ====================

    [ObservableProperty] private bool _isExporting;

    // ==================== CONSTRUCTOR ====================

    public TopTalkersViewModel(
        ICsvExportService? csvExportService = null,
        IFileDialogService? fileDialogService = null)
    {
        _csvExportService = csvExportService;
        _fileDialogService = fileDialogService;
    }

    // ==================== UPDATE METHODS ====================

    /// <summary>
    /// Updates the Top Talkers view with new statistics.
    /// </summary>
    public async Task UpdateData(NetworkStatistics statistics, List<PacketInfo>? packets = null)
    {
        if (!Dispatcher.CheckAccess())
        {
            await Dispatcher.InvokeAsync(async () => await UpdateData(statistics, packets));
            return;
        }

        try
        {
            _currentStatistics = statistics;
            _currentPackets = packets;

            UpdateSummaryStatistics(statistics);
            await UpdateTopTalkersDisplay();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[TopTalkersViewModel] Error updating data: {ex.Message}");
        }
    }

    /// <summary>
    /// Updates summary statistics.
    /// </summary>
    private void UpdateSummaryStatistics(NetworkStatistics statistics)
    {
        TotalPackets = statistics.TotalPackets;
        TotalBytesFormatted = NumberFormatter.FormatBytes(statistics.TotalBytes);
        UniqueEndpoints = statistics.AllUniqueIPs?.Count ?? 0;
        ActiveConversations = statistics.TopConversations?.Count ?? 0;
    }

    /// <summary>
    /// Updates the top talkers display based on current view settings.
    /// </summary>
    private Task UpdateTopTalkersDisplay()
    {
        if (_currentStatistics is null) return Task.CompletedTask;

        var talkers = new List<TopTalkerViewModel>();

        switch (SelectedView)
        {
            case "Combined":
                talkers = BuildCombinedView(_currentStatistics);
                break;
            case "Sources Only":
                talkers = BuildSourcesView(_currentStatistics);
                break;
            case "Destinations Only":
                talkers = BuildDestinationsView(_currentStatistics);
                break;
            case "Conversations":
                UpdateConversationsView(_currentStatistics);
                return Task.CompletedTask;
        }

        // Apply Top N limit and sort
        talkers = SelectedMetric switch
        {
            "Packets" => talkers.OrderByDescending(t => t.PacketCount).Take(TopN).ToList(),
            "Bytes" => talkers.OrderByDescending(t => t.ByteCount).Take(TopN).ToList(),
            _ => talkers.OrderByDescending(t => t.TotalTraffic).Take(TopN).ToList()
        };

        // Calculate percentage of total
        var topTalkersTraffic = talkers.Sum(t => SelectedMetric == MetricTypes.Bytes ? t.ByteCount : t.PacketCount);
        var totalTraffic = SelectedMetric == MetricTypes.Bytes ? _currentStatistics.TotalBytes : _currentStatistics.TotalPackets;
        TopTalkersPercentage = totalTraffic > 0 ? (double)topTalkersTraffic / totalTraffic * 100 : 0;

        // Assign ranks
        for (int i = 0; i < talkers.Count; i++)
        {
            talkers[i].Rank = i + 1;
        }

        TopTalkers = new ObservableCollection<TopTalkerViewModel>(talkers);

        return Task.CompletedTask;
    }

    /// <summary>
    /// Builds combined view of sources and destinations.
    /// </summary>
    private List<TopTalkerViewModel> BuildCombinedView(NetworkStatistics statistics)
    {
        var talkers = new Dictionary<string, TopTalkerViewModel>();

        // Add sources
        if (statistics.TopSources is not null)
        {
            foreach (var source in statistics.TopSources)
            {
                if (!talkers.ContainsKey(source.Address))
                {
                    talkers[source.Address] = new TopTalkerViewModel
                    {
                        Address = source.Address,
                        Country = source.Country,
                        CountryCode = source.CountryCode,
                        IsInternal = source.IsInternal,
                        IsHighRisk = source.IsHighRisk
                    };
                }

                talkers[source.Address].SentPackets += source.PacketCount;
                talkers[source.Address].SentBytes += source.ByteCount;
            }
        }

        // Add destinations
        if (statistics.TopDestinations is not null)
        {
            foreach (var dest in statistics.TopDestinations)
            {
                if (!talkers.ContainsKey(dest.Address))
                {
                    talkers[dest.Address] = new TopTalkerViewModel
                    {
                        Address = dest.Address,
                        Country = dest.Country,
                        CountryCode = dest.CountryCode,
                        IsInternal = dest.IsInternal,
                        IsHighRisk = dest.IsHighRisk
                    };
                }

                talkers[dest.Address].ReceivedPackets += dest.PacketCount;
                talkers[dest.Address].ReceivedBytes += dest.ByteCount;
            }
        }

        return talkers.Values.ToList();
    }

    /// <summary>
    /// Builds sources-only view.
    /// </summary>
    private List<TopTalkerViewModel> BuildSourcesView(NetworkStatistics statistics)
    {
        if (statistics.TopSources is null) return new List<TopTalkerViewModel>();

        return statistics.TopSources.Select(s => new TopTalkerViewModel
        {
            Address = s.Address,
            SentPackets = s.PacketCount,
            SentBytes = s.ByteCount,
            Country = s.Country,
            CountryCode = s.CountryCode,
            IsInternal = s.IsInternal,
            IsHighRisk = s.IsHighRisk,
            Direction = ViewModes.Source
        }).ToList();
    }

    /// <summary>
    /// Builds destinations-only view.
    /// </summary>
    private List<TopTalkerViewModel> BuildDestinationsView(NetworkStatistics statistics)
    {
        if (statistics.TopDestinations is null) return new List<TopTalkerViewModel>();

        return statistics.TopDestinations.Select(d => new TopTalkerViewModel
        {
            Address = d.Address,
            ReceivedPackets = d.PacketCount,
            ReceivedBytes = d.ByteCount,
            Country = d.Country,
            CountryCode = d.CountryCode,
            IsInternal = d.IsInternal,
            IsHighRisk = d.IsHighRisk,
            Direction = ViewModes.Destination
        }).ToList();
    }

    /// <summary>
    /// Updates conversations view.
    /// </summary>
    private void UpdateConversationsView(NetworkStatistics statistics)
    {
        if (statistics.TopConversations is null)
        {
            TopConversations = new ObservableCollection<ConversationDetailViewModel>();
            return;
        }

        var conversations = statistics.TopConversations
            .OrderByDescending(c => SelectedMetric == MetricTypes.Bytes ? c.ByteCount : c.PacketCount)
            .Take(TopN)
            .Select((c, index) => new ConversationDetailViewModel
            {
                Rank = index + 1,
                SourceAddress = c.SourceAddress,
                DestinationAddress = c.DestinationAddress,
                SourcePort = c.SourcePort,
                DestinationPort = c.DestinationPort,
                Protocol = c.Protocol,
                PacketCount = c.PacketCount,
                ByteCount = c.ByteCount,
                BytesFormatted = NumberFormatter.FormatBytes(c.ByteCount),
                Duration = c.Duration,
                DurationFormatted = Helpers.TimeFormatter.FormatAsSeconds(c.Duration),
                PacketsPerSecond = c.PacketsPerSecond,
                State = c.State,
                SourceCountry = c.SourceCountry,
                DestinationCountry = c.DestinationCountry,
                IsCrossBorder = c.IsCrossBorder,
                IsHighRisk = c.IsHighRisk
            })
            .ToList();

        TopConversations = new ObservableCollection<ConversationDetailViewModel>(conversations);
    }

    // ==================== SELECTION HANDLING ====================

    /// <summary>
    /// Handles selection of a talker for detailed view.
    /// </summary>
    [RelayCommand]
    private async Task SelectTalker(TopTalkerViewModel talker)
    {
        if (talker is null || _currentStatistics is null) return;

        SelectedTalker = talker;

        // Find protocol breakdown for this talker
        var source = _currentStatistics.TopSources?.FirstOrDefault(s => s.Address == talker.Address);
        if (source?.ProtocolBreakdown is not null)
        {
            var breakdown = source.ProtocolBreakdown
                .Select(kvp => new ProtocolBreakdownViewModel
                {
                    Protocol = kvp.Key,
                    PacketCount = kvp.Value,
                    Percentage = source.PacketCount > 0 ? (double)kvp.Value / source.PacketCount * 100 : 0
                })
                .OrderByDescending(p => p.PacketCount)
                .ToList();

            ProtocolBreakdown = new ObservableCollection<ProtocolBreakdownViewModel>(breakdown);
        }

        // Find conversations involving this talker
        if (_currentStatistics.TopConversations is not null)
        {
            var conversations = _currentStatistics.TopConversations
                .Where(c => c.SourceAddress == talker.Address || c.DestinationAddress == talker.Address)
                .Select(c => new ConversationDetailViewModel
                {
                    SourceAddress = c.SourceAddress,
                    DestinationAddress = c.DestinationAddress,
                    SourcePort = c.SourcePort,
                    DestinationPort = c.DestinationPort,
                    Protocol = c.Protocol,
                    PacketCount = c.PacketCount,
                    ByteCount = c.ByteCount,
                    BytesFormatted = NumberFormatter.FormatBytes(c.ByteCount),
                    Duration = c.Duration,
                    DurationFormatted = Helpers.TimeFormatter.FormatAsSeconds(c.Duration),
                    State = c.State
                })
                .ToList();

            TalkerConversations = new ObservableCollection<ConversationDetailViewModel>(conversations);
        }

        await Task.CompletedTask;
    }

    // ==================== VIEW CHANGE HANDLERS ====================

    partial void OnSelectedViewChanged(string value)
    {
        _ = UpdateTopTalkersDisplay();
    }

    partial void OnSelectedMetricChanged(string value)
    {
        _ = UpdateTopTalkersDisplay();
    }

    partial void OnTopNChanged(int value)
    {
        _ = UpdateTopTalkersDisplay();
    }

    // ==================== EXPORT COMMANDS ====================

    [RelayCommand]
    private async Task ExportTopTalkers()
    {
        if (_csvExportService is null || _fileDialogService is null || TopTalkers.Count == 0)
        {
            DebugLogger.Log("[TopTalkersViewModel] Export services not available or no data");
            return;
        }

        try
        {
            IsExporting = true;

            var filePath = await _fileDialogService.SaveFileAsync(
                "Export Top Talkers",
                "top_talkers.csv",
                new FileDialogFilter("CSV Files", new[] { "csv" }));

            if (string.IsNullOrEmpty(filePath)) return;

            var columnMappings = new Dictionary<string, Func<TopTalkerViewModel, object?>>
            {
                { "Rank", t => t.Rank },
                { "Address", t => t.Address },
                { "Country", t => t.Country },
                { "Direction", t => t.Direction },
                { "Sent Packets", t => t.SentPackets },
                { "Received Packets", t => t.ReceivedPackets },
                { "Total Packets", t => t.PacketCount },
                { "Sent Bytes", t => t.SentBytes },
                { "Received Bytes", t => t.ReceivedBytes },
                { "Total Bytes", t => t.ByteCount },
                { "Type", t => t.IsInternal ? "Internal" : "External" },
                { "High Risk", t => t.IsHighRisk }
            };

            await _csvExportService.ExportToCsvAsync(TopTalkers, filePath, columnMappings);

            DebugLogger.Log($"[TopTalkersViewModel] Exported {TopTalkers.Count} top talkers to {filePath}");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[TopTalkersViewModel] Export failed: {ex.Message}");
        }
        finally
        {
            IsExporting = false;
        }
    }

    [RelayCommand]
    private async Task ExportConversations()
    {
        if (_csvExportService is null || _fileDialogService is null || TopConversations.Count == 0)
        {
            DebugLogger.Log("[TopTalkersViewModel] Export services not available or no data");
            return;
        }

        try
        {
            IsExporting = true;

            var filePath = await _fileDialogService.SaveFileAsync(
                "Export Conversations",
                "top_conversations.csv",
                new FileDialogFilter("CSV Files", new[] { "csv" }));

            if (string.IsNullOrEmpty(filePath)) return;

            var columnMappings = new Dictionary<string, Func<ConversationDetailViewModel, object?>>
            {
                { "Rank", c => c.Rank },
                { "Source Address", c => c.SourceAddress },
                { "Source Port", c => c.SourcePort },
                { "Destination Address", c => c.DestinationAddress },
                { "Destination Port", c => c.DestinationPort },
                { "Protocol", c => c.Protocol },
                { "Packet Count", c => c.PacketCount },
                { "Byte Count", c => c.ByteCount },
                { "Duration", c => c.DurationFormatted },
                { "Packets/sec", c => c.PacketsPerSecond },
                { "State", c => c.State },
                { "Cross Border", c => c.IsCrossBorder },
                { "High Risk", c => c.IsHighRisk }
            };

            await _csvExportService.ExportToCsvAsync(TopConversations, filePath, columnMappings);

            DebugLogger.Log($"[TopTalkersViewModel] Exported {TopConversations.Count} conversations to {filePath}");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[TopTalkersViewModel] Export failed: {ex.Message}");
        }
        finally
        {
            IsExporting = false;
        }
    }

}

// ==================== VIEW MODELS ====================

public partial class TopTalkerViewModel : ObservableObject
{
    [ObservableProperty] private int _rank;
    [ObservableProperty] private string _address = string.Empty;
    [ObservableProperty] private string _country = "Unknown";
    [ObservableProperty] private string _countryCode = "N/A";
    [ObservableProperty] private string _direction = "Both";
    [ObservableProperty] private bool _isInternal;
    [ObservableProperty] private bool _isHighRisk;

    [ObservableProperty] private long _sentPackets;
    [ObservableProperty] private long _receivedPackets;
    [ObservableProperty] private long _sentBytes;
    [ObservableProperty] private long _receivedBytes;

    public long PacketCount => SentPackets + ReceivedPackets;
    public long ByteCount => SentBytes + ReceivedBytes;
    public long TotalTraffic => PacketCount + ByteCount;

    public string PacketCountFormatted => $"{PacketCount:N0}";
    public string ByteCountFormatted => NumberFormatter.FormatBytes(ByteCount);
    public string TypeDisplay => IsInternal ? "Internal" : "External";
    public string RiskIndicator => IsHighRisk ? "⚠️" : "";
}

public partial class ConversationDetailViewModel : ObservableObject
{
    [ObservableProperty] private int _rank;
    [ObservableProperty] private string _sourceAddress = string.Empty;
    [ObservableProperty] private int _sourcePort;
    [ObservableProperty] private string _destinationAddress = string.Empty;
    [ObservableProperty] private int _destinationPort;
    [ObservableProperty] private string _protocol = string.Empty;
    [ObservableProperty] private long _packetCount;
    [ObservableProperty] private long _byteCount;
    [ObservableProperty] private string _bytesFormatted = "0 B";
    [ObservableProperty] private TimeSpan _duration;
    [ObservableProperty] private string _durationFormatted = "0s";
    [ObservableProperty] private double _packetsPerSecond;
    [ObservableProperty] private string _state = "Active";
    [ObservableProperty] private string _sourceCountry = "Unknown";
    [ObservableProperty] private string _destinationCountry = "Unknown";
    [ObservableProperty] private bool _isCrossBorder;
    [ObservableProperty] private bool _isHighRisk;

    public string ConversationLabel => $"{SourceAddress}:{SourcePort} → {DestinationAddress}:{DestinationPort}";
    public string RiskIndicator => IsHighRisk ? "⚠️" : "";
}

public partial class ProtocolBreakdownViewModel : ObservableObject
{
    [ObservableProperty] private string _protocol = string.Empty;
    [ObservableProperty] private long _packetCount;
    [ObservableProperty] private double _percentage;

    public string PercentageFormatted => $"{Percentage:F1}%";
}

public partial class TimeSeriesPointViewModel : ObservableObject
{
    [ObservableProperty] private DateTime _timestamp;
    [ObservableProperty] private double _value;
    [ObservableProperty] private string _label = string.Empty;
}
