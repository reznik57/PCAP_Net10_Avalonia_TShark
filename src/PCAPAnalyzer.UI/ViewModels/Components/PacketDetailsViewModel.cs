using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Performance;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// ViewModel for packet details panel with 2 tabs:
/// - Packet Analysis: Quick Summary (instant) + Cleartext Detection + Protocol Layers (on-demand TShark)
/// - Stream Context: Stream navigation, statistics, security analysis, traffic direction
/// </summary>
public partial class PacketDetailsViewModel : ObservableObject, IDisposable
{
    private bool _disposed;
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    private readonly ProtocolParser _protocolParser;
    private readonly StreamAnalyzer _streamAnalyzer;
    private readonly ProtocolDeepDiveService? _deepDiveService;
    private readonly StreamSecurityAnalyzer _streamSecurityAnalyzer = new();
    private string? _currentPcapPath;
    private IPacketStore? _packetStore;

    // Stream analysis cache: key = stream identifier, value = analysis result
    // LRU cache with max 50 streams to prevent memory leak when analyzing many streams
    private readonly ResultCache<string, StreamAnalysisResult> _streamCache = new(maxCapacity: 50);

    [ObservableProperty] private PacketInfo? _currentPacket;
    [ObservableProperty] private bool _hasPacket;
    [ObservableProperty] private string _emptyStateMessage = "Select a packet to view details";

    // Packet Analysis Tab - Protocol Layers section
    [ObservableProperty] private ObservableCollection<ProtocolTreeItemViewModel> _protocolTree = [];

    // Stream Context Tab
    [ObservableProperty] private string _flowStreamId = "--";
    [ObservableProperty] private string _flowConversation = "--";
    [ObservableProperty] private string _flowPacketCount = "--";
    [ObservableProperty] private string _flowPreviousPacket = "--";
    [ObservableProperty] private string _flowNextPacket = "--";
    [ObservableProperty] private string _flowStatistics = "--";
    [ObservableProperty] private bool _flowInfoAvailable;
    [ObservableProperty] private bool _canFilterByStream;

    // Security Indicators
    [ObservableProperty] private string _securityRiskLevel = "--";
    [ObservableProperty] private string _securityRiskColor = ThemeColorHelper.GetColorHex("TextMuted", "#6E7681");
    [ObservableProperty] private string _sourcePortSecurity = "--";
    [ObservableProperty] private string _destinationPortSecurity = "--";
    [ObservableProperty] private string _sourceGeoInfo = "--";
    [ObservableProperty] private string _destinationGeoInfo = "--";
    [ObservableProperty] private ObservableCollection<string> _securityWarnings = [];
    [ObservableProperty] private bool _hasSecurityWarnings;

    // Enhanced Security Analysis (StreamSecurityAnalyzer)
    [ObservableProperty] private int _streamRiskScore;
    [ObservableProperty] private string _streamRiskScoreDisplay = "0";
    [ObservableProperty] private string _encryptionStatus = "Unknown";
    [ObservableProperty] private string _encryptionStatusColor = ThemeColorHelper.GetColorHex("TextMuted", "#6E7681");
    [ObservableProperty] private string _encryptionProtocol = "";
    [ObservableProperty] private bool _beaconingDetected;
    [ObservableProperty] private string _beaconingInterval = "Not detected";
    [ObservableProperty] private string _beaconingConfidence = "";
    [ObservableProperty] private string _beaconingColor = ThemeColorHelper.GetColorHex("ColorSuccess", "#22C55E");
    [ObservableProperty] private string _uploadDownloadRatio = "--";
    [ObservableProperty] private bool _dataExfiltrationIndicator;
    [ObservableProperty] private string _exfiltrationColor = ThemeColorHelper.GetColorHex("ColorSuccess", "#22C55E");
    [ObservableProperty] private bool _hasEnhancedSecurityAnalysis;

    // Directional Metrics
    [ObservableProperty] private string _clientTraffic = "--";
    [ObservableProperty] private string _serverTraffic = "--";
    [ObservableProperty] private string _trafficDirection = "--";
    [ObservableProperty] private string _streamPosition = "--";
    [ObservableProperty] private string _connectionAge = "--";

    // Navigation
    [ObservableProperty] private uint? _previousPacketInStream;
    [ObservableProperty] private uint? _nextPacketInStream;
    [ObservableProperty] private bool _canNavigatePrevious;
    [ObservableProperty] private bool _canNavigateNext;

    // Packet Analysis Tab - Protocol Layers (TShark deep dissection)
    [ObservableProperty] private bool _deepDiveAvailable;
    [ObservableProperty] private bool _deepDiveLoading;
    [ObservableProperty] private string _deepDiveProtocol = "";
    [ObservableProperty] private string _deepDiveIcon = "📦";
    [ObservableProperty] private ObservableCollection<ProtocolSummaryItem> _deepDiveSummary = [];
    [ObservableProperty] private ObservableCollection<ProtocolLayerViewModel> _deepDiveLayers = [];

    // Packet Analysis Tab - Cleartext Detection section
    [ObservableProperty] private bool _hasCleartextCredentials;
    [ObservableProperty] private string _cleartextSeverityColor = ThemeColorHelper.GetColorHex("TextMuted", "#6E7681");
    [ObservableProperty] private string _cleartextSeverityText = "";
    [ObservableProperty] private ObservableCollection<CleartextContentViewModel> _cleartextContents = [];
    [ObservableProperty] private int _totalCredentialsCount;

    // Static color references for theme consistency
    private static readonly string ColorMuted = ThemeColorHelper.GetColorHex("TextMuted", "#6E7681");
    private static readonly string ColorDanger = ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444");
    private static readonly string ColorWarning = ThemeColorHelper.GetColorHex("ColorWarning", "#F59E0B");
    private static readonly string ColorOrange = ThemeColorHelper.GetColorHex("ColorOrange", "#F97316");
    private static readonly string ColorInfo = ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6");
    private static readonly string ColorSuccess = ThemeColorHelper.GetColorHex("ColorSuccess", "#22C55E");
    private static readonly string ColorSuccessLight = ThemeColorHelper.GetColorHex("ColorSuccessLight", "#8BC34A");
    private static readonly string ColorBeaconing = ThemeColorHelper.GetColorHex("ColorWarningLight", "#FFA726");
    private static readonly string ColorExfiltration = ThemeColorHelper.GetColorHex("ColorDangerLight", "#EF5350");

    // Event raised when user requests to filter by current stream
    public event EventHandler<PacketFilter>? FilterByStreamRequested;

    // Event raised when user requests to search for current stream (highlight without filtering)
    public event EventHandler<string>? SearchStreamRequested;

    // Event raised when user requests to navigate to a specific packet in stream
    public event EventHandler<uint>? NavigateToPacketRequested;

    public PacketDetailsViewModel(
        ProtocolParser protocolParser,
        StreamAnalyzer streamAnalyzer,
        ProtocolDeepDiveService? deepDiveService = null)
    {
        ArgumentNullException.ThrowIfNull(protocolParser);
        ArgumentNullException.ThrowIfNull(streamAnalyzer);
        _protocolParser = protocolParser;
        _streamAnalyzer = streamAnalyzer;
        _deepDiveService = deepDiveService; // Optional - deep dive disabled if null
    }

    /// <summary>
    /// Disposes the stream cache and releases resources.
    /// </summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _streamCache.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Sets the current PCAP file path for protocol deep dive.
    /// </summary>
    public void SetPcapPath(string pcapPath)
    {
        DebugLogger.Log($"[DETAILS] SetPcapPath: '{pcapPath}'");
        _currentPcapPath = pcapPath;
    }

    /// <summary>
    /// Sets the packet store for querying stream packets.
    /// Must be called after packet store initialization to enable flow analysis.
    /// </summary>
    public void SetPacketStore(IPacketStore packetStore)
    {
        _packetStore = packetStore;
    }

    /// <summary>
    /// Clears the stream analysis cache (call when loading a new PCAP file).
    /// </summary>
    public void ClearStreamCache()
    {
        _streamCache.Clear();
    }

    /// <summary>
    /// Command for loading protocol deep dive on-demand
    /// </summary>
    [RelayCommand]
    private async Task LoadDeepDive()
    {
        DeepDiveLoading = true;

        try
        {
            await LoadProtocolDeepDiveAsync();
        }
        finally
        {
            if (!DeepDiveAvailable)
                DeepDiveLoading = false;
        }
    }

    /// <summary>
    /// Loads detailed protocol dissection using TShark verbose output.
    /// </summary>
    public async Task LoadProtocolDeepDiveAsync()
    {
        if (CurrentPacket is null || _deepDiveService is null || string.IsNullOrWhiteSpace(_currentPcapPath))
        {
            DebugLogger.Log("[DeepDive] Cannot load - missing packet, service, or pcap path");
            return;
        }

        try
        {
            var frameNumber = CurrentPacket.Value.FrameNumber;
            DebugLogger.Log($"[DeepDive] Extracting details for frame {frameNumber}...");

            var result = await _deepDiveService.ExtractProtocolDetailsAsync(_currentPcapPath, frameNumber);

            if (result.Success)
            {
                // Extract summary
                var summary = ProtocolDeepDiveService.ExtractSummary(result);

                await Dispatcher.InvokeAsync(() =>
                {
                    DeepDiveProtocol = summary.Protocol;
                    DeepDiveIcon = summary.Icon;

                    // Update summary items
                    DeepDiveSummary.Clear();
                    foreach (var kv in summary.KeyValues)
                    {
                        DeepDiveSummary.Add(new ProtocolSummaryItem { Key = kv.Key, Value = kv.Value });
                    }

                    // Update layers
                    DeepDiveLayers.Clear();
                    foreach (var layer in result.Layers)
                    {
                        var layerVm = new ProtocolLayerViewModel
                        {
                            Name = layer.Name,
                            Fields = new ObservableCollection<ProtocolFieldViewModel>(
                                layer.Fields.Select(f => new ProtocolFieldViewModel
                                {
                                    Name = f.Name,
                                    Value = f.Value,
                                    IndentLevel = f.IndentLevel,
                                    IsHighlighted = f.IsHighlighted
                                }))
                        };
                        DeepDiveLayers.Add(layerVm);
                    }

                    // Update cleartext content and credentials
                    CleartextContents.Clear();
                    var totalCreds = 0;
                    foreach (var content in result.CleartextContent)
                    {
                        var contentVm = new CleartextContentViewModel
                        {
                            Protocol = content.Protocol,
                            ContentType = content.ContentType,
                            Description = content.Description,
                            RawContent = content.RawContent,
                            Severity = content.Severity,
                            Credentials = new ObservableCollection<CleartextCredentialViewModel>(
                                content.Credentials.Select(c => new CleartextCredentialViewModel
                                {
                                    Protocol = c.Protocol,
                                    CredentialType = c.CredentialType,
                                    FieldName = c.FieldName,
                                    Value = c.Value,
                                    IsPassword = c.IsPassword,
                                    SecurityWarning = c.SecurityWarning
                                }))
                        };
                        totalCreds += content.Credentials.Count;
                        CleartextContents.Add(contentVm);
                    }

                    HasCleartextCredentials = result.HasCleartextCredentials;
                    TotalCredentialsCount = totalCreds;
                    CleartextSeverityText = result.MaxSeverity switch
                    {
                        CleartextSeverity.Critical => "CRITICAL - Credentials Exposed",
                        CleartextSeverity.Warning => "WARNING - Sensitive Data",
                        _ => "INFO - Cleartext Content"
                    };
                    CleartextSeverityColor = result.MaxSeverity switch
                    {
                        CleartextSeverity.Critical => ColorDanger,
                        CleartextSeverity.Warning => ColorWarning,
                        _ => ColorInfo
                    };

                    DeepDiveAvailable = true;
                    DeepDiveLoading = false;
                });

                DebugLogger.Log($"[DeepDive] Loaded {result.Layers.Count} protocol layers, {result.CleartextContent.Sum(c => c.Credentials.Count)} credentials detected");
            }
            else
            {
                DebugLogger.Log($"[DeepDive] Failed: {result.Error}");
                DeepDiveLoading = false;
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DeepDive] Error: {ex.Message}");
            DeepDiveLoading = false;
        }
    }

    /// <summary>
    /// Command for filtering packets by the current stream (TCP/UDP conversation).
    /// Creates a bidirectional filter for all packets in this stream.
    /// </summary>
    [RelayCommand]
    private void FilterByStream()
    {
        if (CurrentPacket is null || !CanFilterByStream)
            return;

        var packet = CurrentPacket.Value;

        // Create bidirectional filter for the stream
        // This uses CombinedFilters with OR mode to match both directions
        var filter = new PacketFilter
        {
            CombineMode = FilterCombineMode.Or,
            CombinedFilters = new List<PacketFilter>
            {
                // Forward direction: src→dst
                new PacketFilter
                {
                    SourceIpFilter = packet.SourceIP,
                    DestinationIpFilter = packet.DestinationIP,
                    SourcePortFilter = packet.SourcePort > 0 ? packet.SourcePort.ToString() : null,
                    DestinationPortFilter = packet.DestinationPort > 0 ? packet.DestinationPort.ToString() : null,
                    ProtocolFilter = packet.Protocol
                },
                // Reverse direction: dst→src
                new PacketFilter
                {
                    SourceIpFilter = packet.DestinationIP,
                    DestinationIpFilter = packet.SourceIP,
                    SourcePortFilter = packet.DestinationPort > 0 ? packet.DestinationPort.ToString() : null,
                    DestinationPortFilter = packet.SourcePort > 0 ? packet.SourcePort.ToString() : null,
                    ProtocolFilter = packet.Protocol
                }
            }
        };

        // Raise event to apply filter
        FilterByStreamRequested?.Invoke(this, filter);
    }

    /// <summary>
    /// Command for searching packets by the current stream (TCP/UDP conversation).
    /// Highlights matching packets without filtering them out.
    /// </summary>
    [RelayCommand]
    private void SearchByStream()
    {
        if (CurrentPacket is null || !CanFilterByStream)
            return;

        var packet = CurrentPacket.Value;

        // Build search pattern: IP:Port-IP:Port format
        var searchPattern = $"{packet.SourceIP}:{packet.SourcePort}-{packet.DestinationIP}:{packet.DestinationPort}";

        // Raise event to perform search
        SearchStreamRequested?.Invoke(this, searchPattern);
    }

    /// <summary>
    /// Command for navigating to the previous packet in the same stream.
    /// </summary>
    [RelayCommand]
    private void NavigateToPreviousInStream()
    {
        if (PreviousPacketInStream.HasValue)
            NavigateToPacketRequested?.Invoke(this, PreviousPacketInStream.Value);
    }

    /// <summary>
    /// Command for navigating to the next packet in the same stream.
    /// </summary>
    [RelayCommand]
    private void NavigateToNextInStream()
    {
        if (NextPacketInStream.HasValue)
            NavigateToPacketRequested?.Invoke(this, NextPacketInStream.Value);
    }

    /// <summary>
    /// Loads packet details for the selected packet.
    /// Called when user selects a packet in the packet table.
    /// </summary>
    public async Task LoadPacketDetailsAsync(PacketInfo? packet)
    {
        DebugLogger.Log($"[DETAILS] LoadPacketDetailsAsync - packet: {packet?.FrameNumber}");

        if (packet is null)
        {
            ClearDetails();
            return;
        }

        // CRITICAL: Reset deep dive when selecting a NEW packet (user must click button again)
        var previousFrame = CurrentPacket?.FrameNumber;
        if (previousFrame != packet.Value.FrameNumber)
        {
            await Dispatcher.InvokeAsync(() =>
            {
                DeepDiveAvailable = false;
                DeepDiveLoading = false;
                DeepDiveProtocol = "";
                DeepDiveIcon = "📦";
                DeepDiveSummary.Clear();
                DeepDiveLayers.Clear();
                HasCleartextCredentials = false;
                TotalCredentialsCount = 0;
                CleartextSeverityText = "";
                CleartextSeverityColor = ColorMuted;
                CleartextContents.Clear();
            });
        }

        // CRITICAL: Update UI-bound properties on UI thread
        await Dispatcher.InvokeAsync(() =>
        {
            CurrentPacket = packet;
            HasPacket = true;
        });

        // Load details asynchronously to avoid UI blocking
        await Task.Run(() =>
        {
            LoadProtocolTree(packet.Value);
            LoadFlowInfo(packet.Value);
        });
    }

    /// <summary>
    /// Clears all packet details and resets to empty state
    /// </summary>
    private void ClearDetails()
    {
        CurrentPacket = null;
        HasPacket = false;

        Dispatcher.Post(() =>
        {
            ProtocolTree.Clear();
            SecurityWarnings.Clear();
        });

        FlowInfoAvailable = false;
        FlowStreamId = "--";
        FlowConversation = "--";
        FlowPacketCount = "--";
        FlowPreviousPacket = "--";
        FlowNextPacket = "--";
        FlowStatistics = "--";

        // Reset security indicators
        SecurityRiskLevel = "--";
        SecurityRiskColor = ColorMuted;
        SourcePortSecurity = "--";
        DestinationPortSecurity = "--";
        SourceGeoInfo = "--";
        DestinationGeoInfo = "--";
        HasSecurityWarnings = false;

        // Reset directional metrics
        ClientTraffic = "--";
        ServerTraffic = "--";
        TrafficDirection = "--";
        StreamPosition = "--";
        ConnectionAge = "--";

        // Reset navigation
        PreviousPacketInStream = null;
        NextPacketInStream = null;
        CanNavigatePrevious = false;
        CanNavigateNext = false;

        // Reset deep dive
        DeepDiveAvailable = false;
        DeepDiveLoading = false;
        DeepDiveProtocol = "";
        DeepDiveIcon = "📦";
        HasCleartextCredentials = false;
        TotalCredentialsCount = 0;
        CleartextSeverityText = "";
        CleartextSeverityColor = ColorMuted;
        Dispatcher.Post(() =>
        {
            DeepDiveSummary.Clear();
            DeepDiveLayers.Clear();
            CleartextContents.Clear();
        });
    }

    /// <summary>
    /// Parses packet into protocol layers and builds protocol tree
    /// </summary>
    private void LoadProtocolTree(PacketInfo packet)
    {
        var tree = _protocolParser.ParseProtocolTree(packet);

        Dispatcher.InvokeAsync(() =>
        {
            ProtocolTree.Clear();
            foreach (var item in tree)
            {
                ProtocolTree.Add(item);
            }
            // Force property change notification for bindings
            OnPropertyChanged(nameof(ProtocolTree));
            OnPropertyChanged(nameof(HasPacket));
        });
    }

    /// <summary>
    /// Loads TCP/UDP stream and flow context information with comprehensive analysis.
    /// Performs TCP state machine, bandwidth, timing, and protocol detection on background thread.
    /// </summary>
    private void LoadFlowInfo(PacketInfo packet)
    {
        // Build flow info from packet metadata
        var isStreamBased = packet.Protocol == Protocol.TCP || packet.Protocol == Protocol.UDP;

        if (isStreamBased)
        {
            // Generate stream key from conversation endpoints
            var streamKey = GenerateStreamKey(packet);
            var streamId = GenerateStreamId(packet);
            FlowStreamId = $"Stream {streamId}";

            // Format conversation
            FlowConversation = $"{packet.SourceIP}:{packet.SourcePort} ↔ {packet.DestinationIP}:{packet.DestinationPort}";

            // If packet store is available, perform comprehensive stream analysis
            if (_packetStore is not null)
            {
                // Run analysis on background thread to avoid blocking UI
                _ = Task.Run(async () => await PerformStreamAnalysisAsync(packet, streamKey));
            }
            else
            {
                // Fallback: basic info without stream analysis
                FlowPacketCount = "-- (packet store not available)";
                FlowPreviousPacket = "-- (packet store not available)";
                FlowNextPacket = "-- (packet store not available)";
                FlowStatistics = $"Protocol: {packet.Protocol}, Frame: {packet.FrameNumber}, Length: {packet.Length} bytes\n\nStream analysis unavailable - packet store not initialized.";
            }

            FlowInfoAvailable = true;
            CanFilterByStream = true;
        }
        else
        {
            FlowStreamId = "N/A (not a stream protocol)";
            FlowConversation = $"{packet.SourceIP} → {packet.DestinationIP}";
            FlowPacketCount = "--";
            FlowPreviousPacket = "--";
            FlowNextPacket = "--";
            FlowStatistics = $"Protocol: {packet.Protocol}, Frame: {packet.FrameNumber}, Length: {packet.Length} bytes";
            FlowInfoAvailable = false;
            CanFilterByStream = false;
        }
    }

    /// <summary>
    /// Performs comprehensive stream analysis on background thread and updates UI.
    /// </summary>
    private async Task PerformStreamAnalysisAsync(PacketInfo currentPacket, string streamKey)
    {
        try
        {
            // Query all packets in this stream
            var streamPackets = await QueryStreamPacketsAsync(currentPacket);

            // Check cache first
            if (_streamCache.TryGetValue(streamKey, out var cachedResult) && cachedResult is not null)
            {
                await UpdateFlowInfoFromAnalysisAsync(currentPacket, cachedResult, streamPackets);
                return;
            }

            if (streamPackets.Count == 0)
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    FlowStatistics = "No stream packets found";
                });
                return;
            }

            // Analyze stream
            var analysis = await _streamAnalyzer.AnalyzeStreamAsync(streamPackets, streamKey);

            // Cache result (LRU - evicts oldest when > 50 streams)
            _streamCache.AddOrUpdate(streamKey, analysis);

            // Update UI
            await UpdateFlowInfoFromAnalysisAsync(currentPacket, analysis, streamPackets);
        }
        catch (Exception ex)
        {
            await Dispatcher.InvokeAsync(() =>
            {
                FlowStatistics = $"Stream analysis error: {ex.Message}";
            });
        }
    }

    /// <summary>
    /// Queries all packets belonging to the same stream as the current packet.
    /// </summary>
    private async Task<List<PacketInfo>> QueryStreamPacketsAsync(PacketInfo packet)
    {
        if (_packetStore is null)
            return new List<PacketInfo>();

        // Create filter for this stream (bidirectional conversation)
        var filter = new PacketFilter
        {
            CombineMode = FilterCombineMode.Or,
            CombinedFilters = new List<PacketFilter>
            {
                // Forward direction: src->dst
                new PacketFilter
                {
                    SourceIpFilter = packet.SourceIP,
                    DestinationIpFilter = packet.DestinationIP,
                    SourcePortFilter = packet.SourcePort.ToString(),
                    DestinationPortFilter = packet.DestinationPort.ToString(),
                    ProtocolFilter = packet.Protocol
                },
                // Reverse direction: dst->src
                new PacketFilter
                {
                    SourceIpFilter = packet.DestinationIP,
                    DestinationIpFilter = packet.SourceIP,
                    SourcePortFilter = packet.DestinationPort.ToString(),
                    DestinationPortFilter = packet.SourcePort.ToString(),
                    ProtocolFilter = packet.Protocol
                }
            }
        };

        var query = new PacketQuery
        {
            Filter = filter,
            PageSize = 100000, // Large page size to get all stream packets
            SortDescending = false, // Chronological order
            IncludeSummary = false
        };

        var result = await _packetStore.QueryPacketsAsync(query, CancellationToken.None);
        return result.Packets.ToList();
    }

    /// <summary>
    /// Updates Flow Info UI from stream analysis results.
    /// </summary>
    private async Task UpdateFlowInfoFromAnalysisAsync(PacketInfo currentPacket, StreamAnalysisResult analysis, List<PacketInfo>? streamPackets)
    {
        // Find previous/next packets in stream
        uint? prevPacket = null, nextPacketFrame = null;
        if (streamPackets is not null && streamPackets.Count > 0)
        {
            var ordered = streamPackets.OrderBy(p => p.FrameNumber).ToList();
            var idx = ordered.FindIndex(p => p.FrameNumber == currentPacket.FrameNumber);
            if (idx > 0) prevPacket = ordered[idx - 1].FrameNumber;
            if (idx >= 0 && idx < ordered.Count - 1) nextPacketFrame = ordered[idx + 1].FrameNumber;
        }

        var previousPacketDisplay = prevPacket.HasValue ? $"#{prevPacket}" : "--";
        var nextPacketDisplay = nextPacketFrame.HasValue ? $"#{nextPacketFrame}" : "--";

        // Security indicators
        string riskLevel = "--";
        string riskColor = ColorMuted;
        string srcPortSec = "--";
        string dstPortSec = "--";
        string srcGeo = "--";
        string dstGeo = "--";
        var warnings = new List<string>();

        if (analysis.Security is not null)
        {
            riskLevel = analysis.Security.OverallRisk.ToString();
            riskColor = analysis.Security.OverallRisk switch
            {
                ThreatSeverity.Critical => ColorDanger,
                ThreatSeverity.High => ColorOrange,
                ThreatSeverity.Medium => ThemeColorHelper.GetColorHex("ColorYellow", "#EAB308"),
                ThreatSeverity.Low => ColorSuccess,
                _ => ColorMuted
            };
            warnings = analysis.Security.Warnings;

            // Format port security
            var srcPort = analysis.Security.SourcePortSecurity;
            srcPortSec = FormatPortSecurity(srcPort);

            var dstPort = analysis.Security.DestinationPortSecurity;
            dstPortSec = FormatPortSecurity(dstPort);

            // Format geo info
            srcGeo = FormatGeoInfo(analysis.Security.SourceGeoInfo);
            dstGeo = FormatGeoInfo(analysis.Security.DestinationGeoInfo);
        }

        // Enhanced Security Analysis (StreamSecurityAnalyzer)
        StreamSecurityResult? enhancedSecurity = null;
        if (streamPackets is not null && streamPackets.Count > 0)
        {
            enhancedSecurity = _streamSecurityAnalyzer.Analyze(
                streamPackets,
                currentPacket.SourceIP ?? "",
                currentPacket.SourcePort,
                currentPacket.DestinationIP ?? "",
                currentPacket.DestinationPort);
        }

        // Directional metrics
        string clientTraffic = "--", serverTraffic = "--", direction = "--", position = "--", age = "--";
        if (analysis.Directional is not null)
        {
            var d = analysis.Directional;
            clientTraffic = $"{d.Client.IP}:{d.Client.Port} -> {d.Client.BytesSentFormatted} ({d.Client.PacketsSent} pkts)";
            serverTraffic = $"{d.Server.IP}:{d.Server.Port} -> {d.Server.BytesSentFormatted} ({d.Server.PacketsSent} pkts)";
            direction = d.DominantDirection;
            position = $"Packet {d.StreamPositionCurrent} of {d.StreamPositionTotal}";
            age = FormatTimeSpan(d.ConnectionAge);
        }

        // Format comprehensive statistics
        var stats = FormatStreamStatistics(currentPacket, analysis);

        await Dispatcher.InvokeAsync(() =>
        {
            FlowPacketCount = $"{analysis.PacketCount} packets";
            FlowPreviousPacket = previousPacketDisplay;
            FlowNextPacket = nextPacketDisplay;
            FlowStatistics = stats;

            // Security indicators
            SecurityRiskLevel = riskLevel;
            SecurityRiskColor = riskColor;
            SourcePortSecurity = srcPortSec;
            DestinationPortSecurity = dstPortSec;
            SourceGeoInfo = srcGeo;
            DestinationGeoInfo = dstGeo;
            SecurityWarnings.Clear();
            foreach (var w in warnings) SecurityWarnings.Add(w);
            HasSecurityWarnings = warnings.Count > 0;

            // Enhanced Security Analysis
            if (enhancedSecurity is not null)
            {
                HasEnhancedSecurityAnalysis = true;
                StreamRiskScore = enhancedSecurity.RiskScore;
                StreamRiskScoreDisplay = enhancedSecurity.RiskScore.ToString();

                // Encryption status
                EncryptionStatus = GetEncryptionStatusText(enhancedSecurity.EncryptionStatus);
                EncryptionStatusColor = GetEncryptionStatusColor(enhancedSecurity.EncryptionStatus);
                EncryptionProtocol = enhancedSecurity.EncryptionProtocol ?? "";

                // Beaconing
                BeaconingDetected = enhancedSecurity.BeaconingDetected;
                BeaconingInterval = enhancedSecurity.BeaconingDetected
                    ? $"{enhancedSecurity.BeaconingInterval:F1}s"
                    : "Not detected";
                BeaconingConfidence = enhancedSecurity.BeaconingDetected
                    ? $"({enhancedSecurity.BeaconingConfidence:F0}%)"
                    : "";
                BeaconingColor = enhancedSecurity.BeaconingDetected ? ColorBeaconing : ColorSuccess;

                // Exfiltration
                UploadDownloadRatio = double.IsInfinity(enhancedSecurity.UploadDownloadRatio)
                    ? "∞:1 (upload only)"
                    : $"{enhancedSecurity.UploadDownloadRatio:F1}:1";
                DataExfiltrationIndicator = enhancedSecurity.DataExfiltrationIndicator;
                ExfiltrationColor = enhancedSecurity.DataExfiltrationIndicator ? ColorBeaconing : ColorSuccess;
            }
            else
            {
                HasEnhancedSecurityAnalysis = false;
            }

            // Directional metrics
            ClientTraffic = clientTraffic;
            ServerTraffic = serverTraffic;
            TrafficDirection = direction;
            StreamPosition = position;
            ConnectionAge = age;

            // Navigation
            PreviousPacketInStream = prevPacket;
            NextPacketInStream = nextPacketFrame;
            CanNavigatePrevious = prevPacket.HasValue;
            CanNavigateNext = nextPacketFrame.HasValue;
        });
    }

    /// <summary>
    /// Formats port security information for display.
    /// </summary>
    private static string FormatPortSecurity(PortSecurityInfo port)
    {
        if (port.IsKnownMalwarePort)
            return $"{port.Port} - MALWARE PORT";
        if (port.IsKnownInsecure)
            return $"{port.Port} ({port.ServiceName ?? "Unknown"}) - {port.RiskDescription ?? "Insecure"}";
        if (!string.IsNullOrEmpty(port.ServiceName))
            return $"{port.Port} ({port.ServiceName})";
        return $"{port.Port}";
    }

    /// <summary>
    /// Formats geographic security information for display.
    /// </summary>
    private static string FormatGeoInfo(GeoSecurityInfo? geo)
    {
        if (geo is null)
            return "--";
        if (geo.IsPrivateIP)
            return $"{geo.IP} (Private Network)";

        var location = geo.City is not null ? $"{geo.City}, {geo.CountryName}" : geo.CountryName ?? "Unknown";
        var risk = geo.IsHighRiskCountry ? " [HIGH RISK]" : "";
        return $"{geo.IP} - {location}{risk}";
    }

    /// <summary>
    /// Formats a TimeSpan for display.
    /// </summary>
    private static string FormatTimeSpan(TimeSpan ts)
    {
        if (ts.TotalSeconds < 1) return $"{ts.TotalMilliseconds:F0} ms";
        if (ts.TotalMinutes < 1) return $"{ts.TotalSeconds:F1} sec";
        if (ts.TotalHours < 1) return $"{ts.TotalMinutes:F1} min";
        return $"{ts.TotalHours:F1} hours";
    }

    /// <summary>
    /// Gets display text for encryption status.
    /// </summary>
    private static string GetEncryptionStatusText(EncryptionStatus status)
    {
        return status switch
        {
            Core.Services.EncryptionStatus.Encrypted => "Encrypted",
            Core.Services.EncryptionStatus.LikelyEncrypted => "Likely Encrypted",
            Core.Services.EncryptionStatus.LikelyUnencrypted => "Likely Unencrypted",
            Core.Services.EncryptionStatus.Unencrypted => "Unencrypted",
            _ => "Unknown"
        };
    }

    /// <summary>
    /// Gets color for encryption status.
    /// </summary>
    private static string GetEncryptionStatusColor(EncryptionStatus status)
    {
        return status switch
        {
            Core.Services.EncryptionStatus.Encrypted => ColorSuccess,
            Core.Services.EncryptionStatus.LikelyEncrypted => ColorSuccessLight,
            Core.Services.EncryptionStatus.LikelyUnencrypted => ColorBeaconing,
            Core.Services.EncryptionStatus.Unencrypted => ColorExfiltration,
            _ => ColorMuted
        };
    }

    // NOTE: FormatStreamStatistics moved to PacketDetailsViewModel.Formatting.cs

    /// <summary>
    /// Generates a stream key for caching (bidirectional conversation identifier).
    /// </summary>
    private static string GenerateStreamKey(PacketInfo packet)
    {
        // Sort endpoints to ensure same key for both directions
        var endpoints = new[]
        {
            $"{packet.SourceIP}:{packet.SourcePort}",
            $"{packet.DestinationIP}:{packet.DestinationPort}"
        };
        Array.Sort(endpoints);
        return $"{packet.Protocol}|{endpoints[0]}|{endpoints[1]}";
    }

    /// <summary>
    /// Generates a pseudo-stream ID from packet conversation endpoints.
    /// Real stream IDs would come from TShark's tcp.stream or udp.stream fields.
    /// </summary>
    private static int GenerateStreamId(PacketInfo packet)
    {
        // Simple hash-based stream ID (not accurate, just for display)
        var conversation = $"{packet.SourceIP}:{packet.SourcePort}-{packet.DestinationIP}:{packet.DestinationPort}";
        return Math.Abs(conversation.GetHashCode(StringComparison.Ordinal)) % 10000;
    }
}

/// <summary>
/// Summary item for protocol deep dive display (key-value pairs).
/// </summary>
public class ProtocolSummaryItem
{
    public string Key { get; set; } = "";
    public string Value { get; set; } = "";
}

/// <summary>
/// ViewModel for a protocol layer in deep dive display.
/// </summary>
public class ProtocolLayerViewModel
{
    public string Name { get; set; } = "";
    public ObservableCollection<ProtocolFieldViewModel> Fields { get; set; } = [];
    public bool HasFields => Fields.Count > 0;
}

/// <summary>
/// ViewModel for a protocol field in deep dive display.
/// </summary>
public class ProtocolFieldViewModel
{
    private static readonly string HighlightNameColor = ThemeColorHelper.GetColorHex("AccentBlue", "#58A6FF");
    private static readonly string NormalNameColor = ThemeColorHelper.GetColorHex("TextMuted", "#8B949E");
    private static readonly string HighlightValueColor = ThemeColorHelper.GetColorHex("TextPrimary", "#F0F6FC");
    private static readonly string NormalValueColor = ThemeColorHelper.GetColorHex("TextSecondary", "#C9D1D9");

    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public int IndentLevel { get; set; }
    public bool IsHighlighted { get; set; }
    public int IndentPixels => IndentLevel * 16;
    public string NameColor => IsHighlighted ? HighlightNameColor : NormalNameColor;
    public string ValueColor => IsHighlighted ? HighlightValueColor : NormalValueColor;
}

/// <summary>
/// ViewModel for cleartext content display in Protocol Deep Dive.
/// </summary>
public class CleartextContentViewModel
{
    private static readonly string CriticalColor = ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444");
    private static readonly string WarningColor = ThemeColorHelper.GetColorHex("ColorWarning", "#F59E0B");
    private static readonly string InfoColor = ThemeColorHelper.GetColorHex("AccentBlue", "#3B82F6");
    private static readonly string CriticalHeader = ThemeColorHelper.GetColorHex("ColorDangerDark", "#7F1D1D");
    private static readonly string WarningHeader = ThemeColorHelper.GetColorHex("ColorWarningDark", "#78350F");
    private static readonly string InfoHeader = ThemeColorHelper.GetColorHex("AccentBlueDark", "#1E3A5F");

    public string Protocol { get; set; } = "";
    public string ContentType { get; set; } = "";
    public string Description { get; set; } = "";
    public string RawContent { get; set; } = "";
    public CleartextSeverity Severity { get; set; }
    public ObservableCollection<CleartextCredentialViewModel> Credentials { get; set; } = [];

    public bool HasCredentials => Credentials.Count > 0;
    public string SeverityIcon => Severity switch
    {
        CleartextSeverity.Critical => "🔴",
        CleartextSeverity.Warning => "🟡",
        _ => "🔵"
    };
    public string SeverityColor => Severity switch
    {
        CleartextSeverity.Critical => CriticalColor,
        CleartextSeverity.Warning => WarningColor,
        _ => InfoColor
    };
    public string HeaderColor => Severity switch
    {
        CleartextSeverity.Critical => CriticalHeader,
        CleartextSeverity.Warning => WarningHeader,
        _ => InfoHeader
    };
}

/// <summary>
/// ViewModel for individual cleartext credential display.
/// </summary>
public class CleartextCredentialViewModel
{
    private static readonly string PasswordFieldColor = ThemeColorHelper.GetColorHex("ColorDanger", "#EF4444");
    private static readonly string NormalFieldColor = ThemeColorHelper.GetColorHex("TextPrimary", "#F0F6FC");
    private static readonly string PasswordValueColor = ThemeColorHelper.GetColorHex("ColorDangerLight", "#FCA5A5");
    private static readonly string NormalValueColor = ThemeColorHelper.GetColorHex("TextSecondary", "#C9D1D9");

    public string Protocol { get; set; } = "";
    public string CredentialType { get; set; } = "";
    public string FieldName { get; set; } = "";
    public string Value { get; set; } = "";
    public bool IsPassword { get; set; }
    public string SecurityWarning { get; set; } = "";

    public string FieldColor => IsPassword ? PasswordFieldColor : NormalFieldColor;
    public string ValueColor => IsPassword ? PasswordValueColor : NormalValueColor;
    public string Icon => IsPassword ? "🔑" : "👤";
}
