using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// ViewModel for packet details panel with 2 tabs:
/// - Packet Analysis: Quick Summary (instant) + Cleartext Detection + Protocol Layers (on-demand TShark)
/// - Stream Context: Stream navigation, statistics, security analysis, traffic direction
/// </summary>
public partial class PacketDetailsViewModel : ObservableObject
{
    private readonly ProtocolParser _protocolParser;
    private readonly HexFormatter _hexFormatter;
    private readonly PCAPAnalyzer.Core.Services.HexDataService? _hexDataService;
    private readonly StreamAnalyzer _streamAnalyzer;
    private readonly ProtocolDeepDiveService? _deepDiveService;
    private readonly StreamSecurityAnalyzer _streamSecurityAnalyzer = new();
    private string? _currentPcapPath;
    private IPacketStore? _packetStore;

    // Stream analysis cache: key = stream identifier, value = analysis result
    private readonly Dictionary<string, StreamAnalysisResult> _streamCache = new();

    // Pre-loaded hex data cache: key = frame number, value = raw bytes
    // Populated by batch extraction when page loads for instant hex dump display
    private readonly Dictionary<uint, byte[]> _hexDataCache = new();

    [ObservableProperty] private PacketInfo? _currentPacket;
    [ObservableProperty] private bool _hasPacket;
    [ObservableProperty] private string _emptyStateMessage = "Select a packet to view details";

    // Packet Analysis Tab - Protocol Layers section
    [ObservableProperty] private ObservableCollection<ProtocolTreeItemViewModel> _protocolTree = new();

    // Hex data for deep analysis (internal use, no dedicated tab)
    [ObservableProperty] private ObservableCollection<HexDumpLineViewModel> _hexDumpLines = new();
    [ObservableProperty] private bool _hexDumpAvailable;
    [ObservableProperty] private bool _hexDumpLoading;
    [ObservableProperty] private string _hexDumpPlaceholder = "Hex data available for protocol analysis.";

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
    [ObservableProperty] private string _securityRiskColor = "#6E7681";
    [ObservableProperty] private string _sourcePortSecurity = "--";
    [ObservableProperty] private string _destinationPortSecurity = "--";
    [ObservableProperty] private string _sourceGeoInfo = "--";
    [ObservableProperty] private string _destinationGeoInfo = "--";
    [ObservableProperty] private ObservableCollection<string> _securityWarnings = new();
    [ObservableProperty] private bool _hasSecurityWarnings;

    // Enhanced Security Analysis (StreamSecurityAnalyzer)
    [ObservableProperty] private int _streamRiskScore;
    [ObservableProperty] private string _streamRiskScoreDisplay = "0";
    [ObservableProperty] private string _encryptionStatus = "Unknown";
    [ObservableProperty] private string _encryptionStatusColor = "#6E7681";
    [ObservableProperty] private string _encryptionProtocol = "";
    [ObservableProperty] private bool _beaconingDetected;
    [ObservableProperty] private string _beaconingInterval = "Not detected";
    [ObservableProperty] private string _beaconingConfidence = "";
    [ObservableProperty] private string _beaconingColor = "#22C55E";
    [ObservableProperty] private string _uploadDownloadRatio = "--";
    [ObservableProperty] private bool _dataExfiltrationIndicator;
    [ObservableProperty] private string _exfiltrationColor = "#22C55E";
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
    [ObservableProperty] private ObservableCollection<ProtocolSummaryItem> _deepDiveSummary = new();
    [ObservableProperty] private ObservableCollection<ProtocolLayerViewModel> _deepDiveLayers = new();

    // Packet Analysis Tab - Cleartext Detection section
    [ObservableProperty] private bool _hasCleartextCredentials;
    [ObservableProperty] private string _cleartextSeverityColor = "#6E7681";
    [ObservableProperty] private string _cleartextSeverityText = "";
    [ObservableProperty] private ObservableCollection<CleartextContentViewModel> _cleartextContents = new();
    [ObservableProperty] private int _totalCredentialsCount;

    // Event raised when user requests to filter by current stream
    public event EventHandler<PacketFilter>? FilterByStreamRequested;

    // Event raised when user requests to search for current stream (highlight without filtering)
    public event EventHandler<string>? SearchStreamRequested;

    // Event raised when user requests to navigate to a specific packet in stream
    public event EventHandler<uint>? NavigateToPacketRequested;

    public PacketDetailsViewModel(
        ProtocolParser protocolParser,
        HexFormatter hexFormatter,
        StreamAnalyzer streamAnalyzer,
        PCAPAnalyzer.Core.Services.HexDataService? hexDataService = null,
        ProtocolDeepDiveService? deepDiveService = null)
    {
        _protocolParser = protocolParser ?? throw new ArgumentNullException(nameof(protocolParser));
        _hexFormatter = hexFormatter ?? throw new ArgumentNullException(nameof(hexFormatter));
        _streamAnalyzer = streamAnalyzer ?? throw new ArgumentNullException(nameof(streamAnalyzer));
        _hexDataService = hexDataService; // Optional - hex dump disabled if null
        _deepDiveService = deepDiveService; // Optional - deep dive disabled if null
    }

    /// <summary>
    /// Sets the current PCAP file path for hex data extraction.
    /// Must be called after file load to enable hex dump functionality.
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
        _hexDataCache.Clear();
    }

    /// <summary>
    /// Pre-loads hex data for multiple frames using batch extraction.
    /// Call this when a page of packets is displayed for instant hex dump access.
    /// </summary>
    public async Task PreloadHexDataForFramesAsync(IEnumerable<uint> frameNumbers, CancellationToken cancellationToken = default)
    {
        if (_hexDataService == null || string.IsNullOrWhiteSpace(_currentPcapPath))
            return;

        var framesToLoad = frameNumbers.Where(f => !_hexDataCache.ContainsKey(f)).ToList();
        if (framesToLoad.Count == 0)
            return;

        DebugLogger.Log($"[DETAILS] PreloadHexData - extracting {framesToLoad.Count} frames");
        try
        {
            var batchResult = await _hexDataService.ExtractHexDataBatchAsync(_currentPcapPath, framesToLoad, cancellationToken);
            foreach (var kvp in batchResult)
            {
                _hexDataCache[kvp.Key] = kvp.Value;
            }
            DebugLogger.Log($"[DETAILS] PreloadHexData - cached {batchResult.Count} frames");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[DETAILS] PreloadHexData error: {ex.Message}");
        }
    }

    /// <summary>
    /// Checks if hex data is pre-loaded for a frame.
    /// </summary>
    public bool HasPreloadedHexData(uint frameNumber) => _hexDataCache.ContainsKey(frameNumber);

    /// <summary>
    /// Command for loading hex dump on-demand
    /// </summary>
    [RelayCommand]
    private async Task LoadHexDump()
    {
        DebugLogger.Log("[PacketDetailsViewModel] LoadHexDump command triggered!");
        await LoadHexDumpAsync();
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
        if (CurrentPacket == null || _deepDiveService == null || string.IsNullOrWhiteSpace(_currentPcapPath))
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

                await Dispatcher.UIThread.InvokeAsync(() =>
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
                        CleartextSeverity.Critical => "#EF4444",
                        CleartextSeverity.Warning => "#F59E0B",
                        _ => "#3B82F6"
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
        if (CurrentPacket == null || !CanFilterByStream)
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
        if (CurrentPacket == null || !CanFilterByStream)
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

        if (packet == null)
        {
            ClearDetails();
            return;
        }

        // CRITICAL: Reset deep dive when selecting a NEW packet (user must click button again)
        var previousFrame = CurrentPacket?.FrameNumber;
        if (previousFrame != packet.Value.FrameNumber)
        {
            await Dispatcher.UIThread.InvokeAsync(() =>
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
                CleartextSeverityColor = "#6E7681";
                CleartextContents.Clear();
            });
        }

        // CRITICAL: Update UI-bound properties on UI thread
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            CurrentPacket = packet;
            HasPacket = true;
        });

        // Load details asynchronously to avoid UI blocking
        await Task.Run(() =>
        {
            LoadProtocolTree(packet.Value);
            LoadHexDump(packet.Value);
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

        Dispatcher.UIThread.Post(() =>
        {
            ProtocolTree.Clear();
            HexDumpLines.Clear();
            SecurityWarnings.Clear();
        });

        HexDumpAvailable = false;
        FlowInfoAvailable = false;
        FlowStreamId = "--";
        FlowConversation = "--";
        FlowPacketCount = "--";
        FlowPreviousPacket = "--";
        FlowNextPacket = "--";
        FlowStatistics = "--";

        // Reset security indicators
        SecurityRiskLevel = "--";
        SecurityRiskColor = "#6E7681";
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
        CleartextSeverityColor = "#6E7681";
        Dispatcher.UIThread.Post(() =>
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

        Dispatcher.UIThread.InvokeAsync(() =>
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
    /// Generates hex dump display from packet payload.
    /// If payload is already loaded, formats immediately.
    /// Otherwise, shows "Load Hex Dump" prompt for on-demand extraction.
    /// </summary>
    private void LoadHexDump(PacketInfo packet)
    {
        // Check if payload is already populated
        if (!packet.Payload.IsEmpty)
        {
            var lines = _hexFormatter.FormatHexDump(packet.Payload);
            Dispatcher.UIThread.Post(() =>
            {
                HexDumpLines.Clear();
                foreach (var line in lines)
                {
                    HexDumpLines.Add(line);
                }
                HexDumpAvailable = true;
                HexDumpLoading = false;
            });
        }
        else
        {
            // Hex dump not loaded yet - user must click "Load Hex Dump" button
            HexDumpAvailable = false;
            HexDumpLoading = false;

            Dispatcher.UIThread.Post(() =>
            {
                HexDumpLines.Clear();
            });
        }
    }

    /// <summary>
    /// Loads hex dump on-demand by extracting raw packet bytes from PCAP using TShark.
    /// Called when user clicks "Load Hex Dump" button in Hex Dump tab.
    /// </summary>
    public async Task LoadHexDumpAsync()
    {
        if (CurrentPacket == null || HexDumpLoading)
            return;

        try
        {
            HexDumpLoading = true;
            var frameNumber = CurrentPacket.Value.FrameNumber;

            // OPTIMIZATION: Check pre-loaded cache first (instant display)
            if (_hexDataCache.TryGetValue(frameNumber, out var cachedBytes))
            {
                DebugLogger.Log($"[HEX] ✓ Using cached hex data for frame {frameNumber} ({cachedBytes.Length} bytes)");
                await DisplayHexBytes(cachedBytes);
                return;
            }

            // Fallback: Extract from PCAP (slow for large files)
            if (_hexDataService == null || string.IsNullOrWhiteSpace(_currentPcapPath))
            {
                HexDumpPlaceholder = "Hex data service not available.\nEnsure TShark is installed.";
                HexDumpLoading = false;
                return;
            }

            DebugLogger.Log($"[HEX] Extracting from PCAP (not cached)...");
            var hexBytes = await _hexDataService.ExtractHexDataAsync(_currentPcapPath, frameNumber);

            if (hexBytes.Length == 0)
            {
                HexDumpPlaceholder = $"Failed to extract hex data for frame {frameNumber}.\nEnsure TShark is installed and accessible.";
                HexDumpLoading = false;
                return;
            }

            // Cache the result for future use
            _hexDataCache[frameNumber] = hexBytes;
            await DisplayHexBytes(hexBytes);
        }
        catch (Exception ex)
        {
            HexDumpPlaceholder = $"Error loading hex dump: {ex.Message}";
            HexDumpLoading = false;
        }
    }

    /// <summary>
    /// Formats and displays hex bytes in the UI.
    /// </summary>
    private async Task DisplayHexBytes(byte[] hexBytes)
    {
        var lines = _hexFormatter.FormatHexDump(hexBytes.AsSpan());

        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            HexDumpLines.Clear();
            foreach (var line in lines)
            {
                HexDumpLines.Add(line);
            }
            HexDumpAvailable = true;
            HexDumpLoading = false;
        });

        // Update PacketInfo with loaded payload (cache for future access)
        if (CurrentPacket.HasValue)
        {
            CurrentPacket = CurrentPacket.Value with { Payload = hexBytes };
        }
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
            if (_packetStore != null)
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
            if (_streamCache.TryGetValue(streamKey, out var cachedResult))
            {
                await UpdateFlowInfoFromAnalysisAsync(currentPacket, cachedResult, streamPackets);
                return;
            }

            if (streamPackets.Count == 0)
            {
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    FlowStatistics = "No stream packets found";
                });
                return;
            }

            // Analyze stream
            var analysis = await _streamAnalyzer.AnalyzeStreamAsync(streamPackets, streamKey);

            // Cache result
            _streamCache[streamKey] = analysis;

            // Update UI
            await UpdateFlowInfoFromAnalysisAsync(currentPacket, analysis, streamPackets);
        }
        catch (Exception ex)
        {
            await Dispatcher.UIThread.InvokeAsync(() =>
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
        if (_packetStore == null)
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
        if (streamPackets != null && streamPackets.Count > 0)
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
        string riskColor = "#6E7681";
        string srcPortSec = "--";
        string dstPortSec = "--";
        string srcGeo = "--";
        string dstGeo = "--";
        var warnings = new List<string>();

        if (analysis.Security != null)
        {
            riskLevel = analysis.Security.OverallRisk.ToString();
            riskColor = analysis.Security.OverallRisk switch
            {
                ThreatSeverity.Critical => "#EF4444",
                ThreatSeverity.High => "#F97316",
                ThreatSeverity.Medium => "#EAB308",
                ThreatSeverity.Low => "#22C55E",
                _ => "#6E7681"
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
        if (streamPackets != null && streamPackets.Count > 0)
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
        if (analysis.Directional != null)
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

        await Dispatcher.UIThread.InvokeAsync(() =>
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
            if (enhancedSecurity != null)
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
                BeaconingColor = enhancedSecurity.BeaconingDetected ? "#FFA726" : "#22C55E";

                // Exfiltration
                UploadDownloadRatio = double.IsInfinity(enhancedSecurity.UploadDownloadRatio)
                    ? "∞:1 (upload only)"
                    : $"{enhancedSecurity.UploadDownloadRatio:F1}:1";
                DataExfiltrationIndicator = enhancedSecurity.DataExfiltrationIndicator;
                ExfiltrationColor = enhancedSecurity.DataExfiltrationIndicator ? "#FFA726" : "#22C55E";
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
        if (geo == null)
            return "--";
        if (geo.IsPrivateIP)
            return $"{geo.IP} (Private Network)";

        var location = geo.City != null ? $"{geo.City}, {geo.CountryName}" : geo.CountryName ?? "Unknown";
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
            Core.Services.EncryptionStatus.Encrypted => "#22C55E",        // Green
            Core.Services.EncryptionStatus.LikelyEncrypted => "#8BC34A",  // Light Green
            Core.Services.EncryptionStatus.LikelyUnencrypted => "#FFA726",// Orange
            Core.Services.EncryptionStatus.Unencrypted => "#EF5350",      // Red
            _ => "#6E7681"                                                 // Gray
        };
    }

    /// <summary>
    /// Formats stream analysis results into rich display text.
    /// </summary>
    private static string FormatStreamStatistics(PacketInfo currentPacket, StreamAnalysisResult analysis)
    {
        var sb = new StringBuilder();

        // Current Packet Info
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine($"  CURRENT PACKET: #{currentPacket.FrameNumber}");
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine($"Length: {currentPacket.Length} bytes");
        sb.AppendLine($"Timestamp: {currentPacket.Timestamp:yyyy-MM-dd HH:mm:ss.fff}");
        sb.AppendLine();

        // TCP Connection State (if TCP)
        if (currentPacket.Protocol == Protocol.TCP)
        {
            sb.AppendLine("═══════════════════════════════════════════════════════");
            sb.AppendLine("  TCP CONNECTION STATE");
            sb.AppendLine("═══════════════════════════════════════════════════════");
            sb.AppendLine($"State: {analysis.TcpState.State}");

            if (analysis.TcpState.Handshake != null)
            {
                sb.AppendLine($"Handshake: {analysis.TcpState.Handshake.GetDisplayString()}");
                if (analysis.TcpState.Handshake.HandshakeDuration.HasValue)
                {
                    sb.AppendLine($"Handshake Duration: {analysis.TcpState.Handshake.HandshakeDuration.Value.TotalMilliseconds:F2} ms");
                }
            }

            sb.AppendLine($"Retransmissions: {analysis.TcpState.RetransmissionCount} packets");
            sb.AppendLine($"Window Scaling: {analysis.TcpState.WindowScaling.GetDisplayString()}");
            sb.AppendLine($"Flags: {analysis.TcpState.Flags.GetDisplayString()}");
            sb.AppendLine();
        }

        // Bandwidth Metrics
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine("  BANDWIDTH METRICS");
        sb.AppendLine("═══════════════════════════════════════════════════════");

        var totalMB = analysis.Bandwidth.TotalBytes / (1024.0 * 1024.0);
        var totalKB = analysis.Bandwidth.TotalBytes / 1024.0;

        if (totalMB >= 1.0)
            sb.AppendLine($"Total Data: {totalMB:F2} MB ({analysis.Bandwidth.TotalBytes:N0} bytes)");
        else if (totalKB >= 1.0)
            sb.AppendLine($"Total Data: {totalKB:F2} KB ({analysis.Bandwidth.TotalBytes:N0} bytes)");
        else
            sb.AppendLine($"Total Data: {analysis.Bandwidth.TotalBytes:N0} bytes");

        sb.AppendLine($"Duration: {analysis.Bandwidth.Duration.TotalSeconds:F2} seconds");
        sb.AppendLine($"Average Throughput: {analysis.Bandwidth.GetAverageThroughputDisplay()}");

        if (analysis.Bandwidth.Peak != null)
        {
            sb.AppendLine($"Peak Throughput: {analysis.Bandwidth.Peak.GetDisplayString()} at {analysis.Bandwidth.Peak.Timestamp:HH:mm:ss.fff}");
        }

        sb.AppendLine($"Average Packet Size: {analysis.Bandwidth.AveragePacketSize:F1} bytes");
        sb.AppendLine($"Packet Rate: {analysis.Bandwidth.AveragePacketsPerSecond:F1} packets/sec");
        sb.AppendLine();

        // Timing Analysis (if RTT data available)
        if (analysis.Timing.HasRttData)
        {
            sb.AppendLine("═══════════════════════════════════════════════════════");
            sb.AppendLine("  TIMING ANALYSIS");
            sb.AppendLine("═══════════════════════════════════════════════════════");
            sb.AppendLine($"Average RTT: {analysis.Timing.AverageRttMs:F2} ms");

            if (analysis.Timing.MinRttSample != null)
            {
                sb.AppendLine($"Min RTT: {analysis.Timing.MinRttMs:F2} ms (packet #{analysis.Timing.MinRttSample.RequestPacket} ↔ #{analysis.Timing.MinRttSample.ResponsePacket})");
            }

            if (analysis.Timing.MaxRttSample != null)
            {
                sb.AppendLine($"Max RTT: {analysis.Timing.MaxRttMs:F2} ms (packet #{analysis.Timing.MaxRttSample.RequestPacket} ↔ #{analysis.Timing.MaxRttSample.ResponsePacket})");
            }

            if (analysis.Timing.JitterMs.HasValue)
            {
                sb.AppendLine($"Jitter: {analysis.Timing.JitterMs.Value:F2} ms");
            }

            sb.AppendLine();
        }

        sb.AppendLine($"Inter-Packet Delay: {analysis.Timing.AverageInterPacketDelayMs:F2} ms (avg)");
        sb.AppendLine();

        // Application Protocol
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine("  APPLICATION LAYER");
        sb.AppendLine("═══════════════════════════════════════════════════════");
        sb.AppendLine($"Protocol: {analysis.Protocol.GetDisplayString()}");
        sb.AppendLine($"Description: {analysis.Protocol.Description}");

        if (analysis.Protocol.Details.Count > 0)
        {
            sb.AppendLine("Details:");
            foreach (var detail in analysis.Protocol.Details)
            {
                sb.AppendLine($"  {detail.Key}: {detail.Value}");
            }
        }

        return sb.ToString();
    }

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
    public ObservableCollection<ProtocolFieldViewModel> Fields { get; set; } = new();
    public bool HasFields => Fields.Count > 0;
}

/// <summary>
/// ViewModel for a protocol field in deep dive display.
/// </summary>
public class ProtocolFieldViewModel
{
    public string Name { get; set; } = "";
    public string Value { get; set; } = "";
    public int IndentLevel { get; set; }
    public bool IsHighlighted { get; set; }
    public int IndentPixels => IndentLevel * 16;
    public string NameColor => IsHighlighted ? "#58A6FF" : "#8B949E";
    public string ValueColor => IsHighlighted ? "#F0F6FC" : "#C9D1D9";
}

/// <summary>
/// ViewModel for cleartext content display in Protocol Deep Dive.
/// </summary>
public class CleartextContentViewModel
{
    public string Protocol { get; set; } = "";
    public string ContentType { get; set; } = "";
    public string Description { get; set; } = "";
    public string RawContent { get; set; } = "";
    public CleartextSeverity Severity { get; set; }
    public ObservableCollection<CleartextCredentialViewModel> Credentials { get; set; } = new();

    public bool HasCredentials => Credentials.Count > 0;
    public string SeverityIcon => Severity switch
    {
        CleartextSeverity.Critical => "🔴",
        CleartextSeverity.Warning => "🟡",
        _ => "🔵"
    };
    public string SeverityColor => Severity switch
    {
        CleartextSeverity.Critical => "#EF4444",
        CleartextSeverity.Warning => "#F59E0B",
        _ => "#3B82F6"
    };
    public string HeaderColor => Severity switch
    {
        CleartextSeverity.Critical => "#7F1D1D",
        CleartextSeverity.Warning => "#78350F",
        _ => "#1E3A5F"
    };
}

/// <summary>
/// ViewModel for individual cleartext credential display.
/// </summary>
public class CleartextCredentialViewModel
{
    public string Protocol { get; set; } = "";
    public string CredentialType { get; set; } = "";
    public string FieldName { get; set; } = "";
    public string Value { get; set; } = "";
    public bool IsPassword { get; set; }
    public string SecurityWarning { get; set; } = "";

    public string FieldColor => IsPassword ? "#EF4444" : "#F0F6FC";
    public string ValueColor => IsPassword ? "#FCA5A5" : "#C9D1D9";
    public string Icon => IsPassword ? "🔑" : "👤";
}
