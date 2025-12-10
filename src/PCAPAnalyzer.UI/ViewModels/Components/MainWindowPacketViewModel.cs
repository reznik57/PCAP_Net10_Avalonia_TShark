using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Collections;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.Collections;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages packet storage, filtering, and collection management.
/// Handles packet stores (DuckDB, Memory, Null) and maintains filtered/unfiltered packet lists.
/// </summary>
public partial class MainWindowPacketViewModel : ObservableObject, IAsyncDisposable
{
    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    // Packet stores
    private readonly IPacketStore _duckPacketStore = new DuckDbPacketStore();
    private readonly IPacketStore _memoryPacketStore = new InMemoryPacketStore();
    private readonly IPacketStore _nullPacketStore = new NullPacketStore();
    private IPacketStore _activePacketStore;
    private string _currentStorePath = string.Empty;
    private readonly bool _preferInMemoryStore;

    // Collections
    private readonly BatchObservableCollection<PacketInfo> _packets;
    private readonly CircularBuffer<PacketInfo> _recentPacketsBuffer;
    private List<PacketInfo> _allPackets = [];
    private List<PacketInfo> _filteredPackets = [];
    private List<PacketInfo>? _dashboardPacketCache;

    // ✅ CACHE FIX: Cache metadata for validation using file hash + session ID
    private CacheMetadata? _cacheMetadata;
    private string? _currentFileHash;
    private Guid _currentAnalysisSessionId = Guid.Empty;

    // Thread safety
    private readonly Lock _packetsLock = new();

    // Filter state
    private PacketFilter _currentFilter = new();
    private readonly ITabFilterService _filterService;

    // Stream filter state
    private string? _activeStreamFilter;
    private List<PacketInfo> _preStreamFilterPackets = []; // Stores packets before stream filter applied
    [ObservableProperty] private bool _hasStreamFilter;

    // Properties
    [ObservableProperty] private bool _hasPackets;
    [ObservableProperty] private long _filteredPacketCount;
    [ObservableProperty] private long _filteredBytes;
    [ObservableProperty] private string _filteredBytesFormatted = "0 B";
    [ObservableProperty] private int _filteredThreatsCount;
    [ObservableProperty] private int _totalFilteredPackets;
    [ObservableProperty] private string _filterStatus = "No filters applied";
    [ObservableProperty] private bool _isFilterActive;
    [ObservableProperty] private string _appliedFiltersText = "";
    [ObservableProperty] private string _capturedStatsTitle = "Captured Traffic Statistics";
    [ObservableProperty] private PacketInfo? _selectedPacket;
    [ObservableProperty] private string _selectedStreamKey = string.Empty;
    [ObservableProperty] private int _bookmarkedPacketsCount;

    /// <summary>
    /// Timestamp of the first packet in the filtered dataset (for Time Delta calculation).
    /// This is the reference point for all delta time calculations.
    /// </summary>
    [ObservableProperty] private DateTime? _firstPacketTimestamp;

    // Bookmarked packet frame numbers
    private readonly HashSet<uint> _bookmarkedFrames = [];
    public IReadOnlyCollection<uint> BookmarkedFrames => _bookmarkedFrames;

    // Packet Details ViewModel
    public PacketDetailsViewModel PacketDetails { get; }

    // Constants
    private const int RecentWindowCapacity = 200000;
    private const int DashboardQueryPageSize = 5000;

    // Events
    public event EventHandler<int>? FilteredPacketsChanged;
    public event EventHandler<uint>? NavigateToPacketRequested;

    public ObservableCollection<PacketInfo> Packets => _packets;
    public CircularBuffer<PacketInfo> RecentPacketsBuffer => _recentPacketsBuffer;
    public IPacketStore ActivePacketStore => _activePacketStore;

    /// <summary>
    /// Gets the cached dashboard packet collection, or null if not yet loaded.
    /// This avoids reloading packets from store, preventing memory duplication.
    /// </summary>
    public List<PacketInfo>? CachedDashboardPackets => _dashboardPacketCache;

    /// <summary>
    /// Cache metadata for validation
    /// </summary>
    private class CacheMetadata
    {
        public string FileHash { get; set; } = string.Empty;
        public Guid SessionId { get; set; }
        public int TotalPackets { get; set; }
        public DateTime CachedAt { get; set; }
    }

    public MainWindowPacketViewModel(ITabFilterService filterService, PacketDetailsViewModel packetDetailsViewModel)
    {
        ArgumentNullException.ThrowIfNull(filterService);
        ArgumentNullException.ThrowIfNull(packetDetailsViewModel);
        _filterService = filterService;
        PacketDetails = packetDetailsViewModel;

        // Subscribe to filter by stream event
        PacketDetails.FilterByStreamRequested += OnFilterByStreamRequested;
        PacketDetails.SearchStreamRequested += OnSearchByStreamRequested;
        PacketDetails.NavigateToPacketRequested += OnNavigateToPacketRequested;

        _packets = new BatchObservableCollection<PacketInfo>();
        _recentPacketsBuffer = new CircularBuffer<PacketInfo>(RecentWindowCapacity);
        _activePacketStore = _nullPacketStore;

        _preferInMemoryStore = !string.Equals(
            Environment.GetEnvironmentVariable("PCAP_ANALYZER_USE_DUCKDB"),
            "1",
            StringComparison.OrdinalIgnoreCase);

        // Subscribe to filter service
        _filterService.FilterChanged += OnFilterServiceChanged;
    }

    /// <summary>
    /// Initializes packet store for analysis
    /// </summary>
    public async Task InitializePacketStoreAsync(CancellationToken cancellationToken)
    {
        _activePacketStore = _nullPacketStore;
        _currentStorePath = string.Empty;

        if (_preferInMemoryStore)
        {
            try
            {
                await _memoryPacketStore.InitializeAsync(string.Empty, cancellationToken);
                _activePacketStore = _memoryPacketStore;
                DebugLogger.Log("[MainWindowPacketViewModel] Using high-performance in-memory packet store");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[WARN] In-memory packet store initialization failed: {ex.Message}");
                _activePacketStore = _nullPacketStore;
            }
        }

        if (_activePacketStore == _nullPacketStore)
        {
            _currentStorePath = System.IO.Path.Combine(Environment.CurrentDirectory, "analysis", "db", $"packets_{DateTime.Now:yyyyMMdd_HHmmss}.duckdb");
            try
            {
                await _duckPacketStore.InitializeAsync(_currentStorePath, cancellationToken);
                _activePacketStore = _duckPacketStore;
                DebugLogger.Log("[MainWindowPacketViewModel] Using DuckDB packet store");
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[WARN] Packet store initialization failed: {ex.Message}");
                _activePacketStore = _nullPacketStore;
                _currentStorePath = string.Empty;
            }
        }

        // Provide packet store to PacketDetails for stream analysis
        PacketDetails.SetPacketStore(_activePacketStore);
    }

    /// <summary>
    /// Applies a packet filter
    /// </summary>
    public void ApplyFilter(PacketFilter filter)
    {
        _currentFilter = filter;

        if (_filterService is not null && !filter.Equals(_filterService.CurrentFilter))
        {
            _filterService.ApplyFilter(filter);
            return;
        }

        FilterPackets();
        UpdateFilterStatus(filter, _filteredPackets.Count);
        FilteredPacketsChanged?.Invoke(this, _filteredPackets.Count);
    }

    /// <summary>
    /// Filters packets based on current filter and sorts by FrameNumber
    /// </summary>
    private void FilterPackets()
    {
        PacketInfo[] sourceSnapshot;
        if (_allPackets.Count > 0)
        {
            sourceSnapshot = _allPackets.ToArray();
            CapturedStatsTitle = "Captured Traffic Statistics";
        }
        else
        {
            sourceSnapshot = _recentPacketsBuffer.ToArray();
            CapturedStatsTitle = "Recent Traffic Statistics";
        }

        if (_currentFilter.IsEmpty)
        {
            // ✅ No filter - sort by FrameNumber ascending (packet capture order)
            _filteredPackets = sourceSnapshot.OrderBy(p => p.FrameNumber).ToList();
        }
        else
        {
            // ✅ Apply filter and sort by FrameNumber ascending
            _filteredPackets = sourceSnapshot
                .Where(_currentFilter.MatchesPacket)
                .OrderBy(p => p.FrameNumber)
                .ToList();
        }

        // Set first packet timestamp for Time Delta calculations
        FirstPacketTimestamp = _filteredPackets.Count > 0 ? _filteredPackets[0].Timestamp : null;

        TotalFilteredPackets = _filteredPackets.Count;
        UpdateFilteredStatistics();
    }

    /// <summary>
    /// Updates filtered statistics
    /// </summary>
    private void UpdateFilteredStatistics()
    {
        HasPackets = _filteredPackets.Count > 0;
        FilteredPacketCount = _filteredPackets.Count;
        FilteredBytes = _filteredPackets.Sum(p => (long)p.Length);
        FilteredBytesFormatted = NumberFormatter.FormatBytes(FilteredBytes);
        FilteredThreatsCount = _filteredPackets.Count(IsThreateningPacket);
    }

    /// <summary>
    /// Updates filter status message
    /// </summary>
    private void UpdateFilterStatus(PacketFilter filter, int filteredCount)
    {
        if (filter.IsEmpty)
        {
            FilterStatus = "No filters applied";
            IsFilterActive = false;
            AppliedFiltersText = string.Empty;
            return;
        }

        var scopeLabel = _allPackets.Count > 0 ? "capture" : "recent window";
        FilterStatus = $"Filter active: {filteredCount:N0} packets in {scopeLabel}";
        IsFilterActive = true;
        AppliedFiltersText = BuildFilterDescription(filter);
    }

    /// <summary>
    /// Builds a human-readable filter description
    /// </summary>
    private static string BuildFilterDescription(PacketFilter filter)
    {
        var parts = new List<string>();

        if (!string.IsNullOrEmpty(filter.SourceIpFilter))
            parts.Add($"Src: {filter.SourceIpFilter}");

        if (!string.IsNullOrEmpty(filter.DestinationIpFilter))
            parts.Add($"Dst: {filter.DestinationIpFilter}");

        if (!string.IsNullOrWhiteSpace(filter.SourcePortFilter))
            parts.Add($"Src Port: {filter.SourcePortFilter}");

        if (!string.IsNullOrWhiteSpace(filter.DestinationPortFilter))
            parts.Add($"Dst Port: {filter.DestinationPortFilter}");

        if (filter.ProtocolFilter.HasValue)
            parts.Add($"Protocol: {filter.ProtocolFilter}");

        if (filter.MinLength.HasValue)
            parts.Add($"Min Len: {filter.MinLength}");

        if (filter.MaxLength.HasValue)
            parts.Add($"Max Len: {filter.MaxLength}");

        if (!string.IsNullOrEmpty(filter.InfoSearchText))
            parts.Add($"Info: \"{filter.InfoSearchText}\"");

        return string.Join(" • ", parts);
    }

    /// <summary>
    /// Updates the page display with filtered packets
    /// </summary>
    public void UpdatePageDisplay(int currentPage, int pageSize)
    {
        List<uint> displayedFrameNumbers;

        lock (_packetsLock)
        {
            _packets.BeginBatchUpdate();
            try
            {
                Packets.Clear();

                var startIndex = (currentPage - 1) * pageSize;
                var endIndex = Math.Min(startIndex + pageSize, _filteredPackets.Count);

                for (int i = startIndex; i < endIndex; i++)
                {
                    Packets.Add(_filteredPackets[i]);
                }

                // ✅ DEFENSIVE: Check for duplicate frame numbers in displayed packets
                displayedFrameNumbers = Packets.Select(p => p.FrameNumber).ToList();
                var duplicates = displayedFrameNumbers.GroupBy(f => f).Where(g => g.Count() > 1).ToList();
                if (duplicates.Any())
                {
                    DebugLogger.Critical($"[UpdatePageDisplay] ⚠️  DUPLICATE FRAME NUMBERS DETECTED: {string.Join(", ", duplicates.Select(g => $"{g.Key} (x{g.Count()})"))}");
                }
            }
            finally
            {
                _packets.EndBatchUpdate();
            }
        }

    }

    /// <summary>
    /// Sets the current analysis session context for cache validation
    /// </summary>
    public void SetAnalysisSession(string fileHash, Guid sessionId)
    {
        _currentFileHash = fileHash;
        _currentAnalysisSessionId = sessionId;
        DebugLogger.Log($"[MainWindowPacketViewModel] Analysis session set: FileHash={fileHash.Substring(0, 8)}..., SessionId={sessionId}");
    }

    /// <summary>
    /// Loads all packets for dashboard with file hash + session ID cache validation
    /// </summary>
    public async Task<List<PacketInfo>> LoadAllPacketsForDashboardAsync(NetworkStatistics statistics, CancellationToken cancellationToken)
    {
        // ✅ CACHE FIX: Validate cache using file hash + session ID instead of packet count
        // This prevents false cache hits when:
        // 1. Different file is loaded (file hash changes)
        // 2. New analysis session starts (session ID changes)
        // 3. Incremental analysis updates (same file hash + session ID = valid cache)
        if (_dashboardPacketCache is not null && _cacheMetadata is not null)
        {
            bool isSameFile = _cacheMetadata.FileHash == _currentFileHash;
            bool isSameSession = _cacheMetadata.SessionId == _currentAnalysisSessionId;

            if (isSameFile && isSameSession)
            {
                var expectedTotal = statistics?.TotalPackets ?? 0;
                DebugLogger.Log($"[LoadAllPacketsForDashboard] ✓ Cache VALID: FileHash matches, SessionId matches, using {_dashboardPacketCache.Count:N0} packets (expected: {expectedTotal:N0})");
                return _dashboardPacketCache;
            }
            else
            {
                DebugLogger.Log($"[LoadAllPacketsForDashboard] ⚠️  Cache INVALID: FileHash match={isSameFile}, SessionId match={isSameSession} - invalidating");
                _dashboardPacketCache = null;
                _cacheMetadata = null;
            }
        }

        if (_activePacketStore == _nullPacketStore)
        {
            var recent = _recentPacketsBuffer.ToArray().ToList();
            DebugLogger.Log("[MainWindowPacketViewModel] WARNING: Packet store unavailable - using recent packet buffer for dashboard. Results may be incomplete.");

            // Cache with metadata
            _dashboardPacketCache = recent;
            _cacheMetadata = new CacheMetadata
            {
                FileHash = _currentFileHash ?? string.Empty,
                SessionId = _currentAnalysisSessionId,
                TotalPackets = recent.Count,
                CachedAt = DateTime.UtcNow
            };

            return recent;
        }

        var allPackets = new List<PacketInfo>();
        var pageNumber = 1;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var query = new PacketQuery
            {
                PageNumber = pageNumber,
                PageSize = DashboardQueryPageSize,
                SortDescending = false,
                IncludePackets = true,
                IncludeSummary = false
            };

            var result = await _activePacketStore.QueryPacketsAsync(query, cancellationToken).ConfigureAwait(false);
            if (result.Packets.Count == 0)
            {
                break;
            }

            allPackets.AddRange(result.Packets);

            if (result.Packets.Count < DashboardQueryPageSize)
            {
                break;
            }

            pageNumber++;
        }

        // ✅ DIAGNOSTIC: Run database diagnostics to verify frame numbers
        if (_activePacketStore is DuckDbPacketStore duckDbStore)
        {
            try
            {
                var (dbCount, minFrame, maxFrame) = duckDbStore.GetFrameNumberDiagnostics();
                DebugLogger.Log($"[LoadAllPacketsForDashboard] DB: {dbCount:N0} packets, Frames: {minFrame:N0}-{maxFrame:N0}");

                if (allPackets.Count > 0)
                {
                    var memMinFrame = allPackets.Min(p => p.FrameNumber);
                    var memMaxFrame = allPackets.Max(p => p.FrameNumber);

                    // Check for duplicates in loaded memory
                    var duplicateFrames = allPackets.GroupBy(p => p.FrameNumber).Where(g => g.Count() > 1).Take(10).ToList();
                    if (duplicateFrames.Any())
                    {
                        DebugLogger.Log($"[LoadAllPacketsForDashboard] DUPLICATES: {string.Join(", ", duplicateFrames.Select(g => $"{g.Key} (x{g.Count()})"))}");
                    }

                    if (memMinFrame != minFrame || memMaxFrame != maxFrame)
                    {
                        DebugLogger.Log($"[LoadAllPacketsForDashboard] FRAME MISMATCH! DB: {minFrame}-{maxFrame}, Memory: {memMinFrame}-{memMaxFrame}");
                    }
                }
            }
            catch (Exception ex)
            {
                DebugLogger.Log($"[LoadAllPacketsForDashboard] Diagnostics failed: {ex.Message}");
            }
        }

        // Cache with metadata
        _dashboardPacketCache = allPackets;
        _cacheMetadata = new CacheMetadata
        {
            FileHash = _currentFileHash ?? string.Empty,
            SessionId = _currentAnalysisSessionId,
            TotalPackets = allPackets.Count,
            CachedAt = DateTime.UtcNow
        };

        DebugLogger.Log($"[LoadAllPacketsForDashboard] Cached {allPackets.Count:N0} packets with metadata (FileHash={_currentFileHash?.Substring(0, 8)}..., SessionId={_currentAnalysisSessionId})");

        return allPackets;
    }

    /// <summary>
    /// Populates the full packet list from store
    /// </summary>
    public async Task PopulateFullPacketListAsync(NetworkStatistics? statistics)
    {
        try
        {
            List<PacketInfo> packetList;

            if (_activePacketStore != _nullPacketStore && statistics is not null)
            {
                var allPackets = await LoadAllPacketsForDashboardAsync(statistics, CancellationToken.None).ConfigureAwait(false);
                packetList = new List<PacketInfo>(allPackets);
            }
            else
            {
                packetList = _recentPacketsBuffer.ToArray().ToList();
            }

            await Dispatcher.InvokeAsync(() =>
            {
                _allPackets = packetList;
                FilterPackets();
            });
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowPacketViewModel] Failed to populate full packet list: {ex.Message}");
        }
    }

    /// <summary>
    /// Clears all packets and resets state
    /// </summary>
    public async Task ClearPacketsAsync()
    {
        lock (_packetsLock)
        {
            Packets.Clear();
            _filteredPackets.Clear();
            _recentPacketsBuffer.Clear();
        }

        _allPackets.Clear();
        _dashboardPacketCache = null;
        _cacheMetadata = null; // Reset cache metadata
        _currentFileHash = null;
        _currentAnalysisSessionId = Guid.Empty;

        await _activePacketStore.ClearAsync();

        // Clear stream analysis cache when loading new file
        PacketDetails.ClearStreamCache();

        HasPackets = false;
        FilteredPacketCount = 0;
        FilteredBytes = 0;
        FilteredBytesFormatted = "0 B";
        FilteredThreatsCount = 0;
        TotalFilteredPackets = 0;
        FilterStatus = "No filters applied";
        IsFilterActive = false;
        AppliedFiltersText = string.Empty;
        FirstPacketTimestamp = null;

        _currentFilter = new();
    }

    /// <summary>
    /// Gets the current filtered packets list
    /// </summary>
    public IReadOnlyList<PacketInfo> GetFilteredPackets() => _filteredPackets;

    /// <summary>
    /// Selects a packet and loads its details in the packet details panel
    /// </summary>
    public async Task SelectPacketAsync(PacketInfo packet)
    {
        DebugLogger.Log($"[MainWindowPacketViewModel] SelectPacketAsync called - packet: {packet.FrameNumber}");
        SelectedPacket = packet;

        // Set stream key for highlighting (normalized: smaller endpoint first)
        SelectedStreamKey = GetNormalizedStreamKey(packet);

        DebugLogger.Log($"[MainWindowPacketViewModel] SelectedPacket set, calling PacketDetails.LoadPacketDetailsAsync");
        await PacketDetails.LoadPacketDetailsAsync(packet);
        DebugLogger.Log($"[MainWindowPacketViewModel] PacketDetails.LoadPacketDetailsAsync completed");
    }

    /// <summary>
    /// Gets a normalized stream key for a packet (consistent regardless of direction)
    /// </summary>
    public static string GetNormalizedStreamKey(PacketInfo packet)
    {
        var endpoint1 = $"{packet.SourceIP}:{packet.SourcePort}";
        var endpoint2 = $"{packet.DestinationIP}:{packet.DestinationPort}";
        return string.Compare(endpoint1, endpoint2, StringComparison.Ordinal) < 0
            ? $"{endpoint1}-{endpoint2}"
            : $"{endpoint2}-{endpoint1}";
    }

    /// <summary>
    /// Toggles bookmark status for a packet
    /// </summary>
    public void ToggleBookmark(uint frameNumber)
    {
        if (_bookmarkedFrames.Contains(frameNumber))
            _bookmarkedFrames.Remove(frameNumber);
        else
            _bookmarkedFrames.Add(frameNumber);

        BookmarkedPacketsCount = _bookmarkedFrames.Count;
        DebugLogger.Log($"[Bookmarks] Toggled frame {frameNumber}, total bookmarks: {BookmarkedPacketsCount}");
    }

    /// <summary>
    /// Checks if a packet is bookmarked
    /// </summary>
    public bool IsBookmarked(uint frameNumber) => _bookmarkedFrames.Contains(frameNumber);

    /// <summary>
    /// Clears all bookmarks
    /// </summary>
    public void ClearBookmarks()
    {
        _bookmarkedFrames.Clear();
        BookmarkedPacketsCount = 0;
        DebugLogger.Log("[Bookmarks] All bookmarks cleared");
    }

    private void OnFilterServiceChanged(object? sender, FilterChangedEventArgs e)
    {
        ApplyFilter(e.Filter);
    }

    /// <summary>
    /// Handles request to filter by stream from PacketDetailsViewModel
    /// </summary>
    private void OnFilterByStreamRequested(object? sender, PacketFilter filter)
    {
        DebugLogger.Log($"[MainWindowPacketViewModel] FilterByStream requested");
        ApplyFilter(filter);
    }

    /// <summary>
    /// Handles request to search by stream from PacketDetailsViewModel
    /// </summary>
    private void OnSearchByStreamRequested(object? sender, string searchPattern)
    {
        DebugLogger.Log($"[MainWindowPacketViewModel] SearchByStream requested: {searchPattern}");
        // This will be handled by MainWindowViewModel which has access to UIState
        SearchByStreamRequested?.Invoke(this, searchPattern);
    }

    // Event to forward search request to MainWindowViewModel
    public event EventHandler<string>? SearchByStreamRequested;

    /// <summary>
    /// Handles request to navigate to a specific packet from PacketDetailsViewModel
    /// </summary>
    private void OnNavigateToPacketRequested(object? sender, uint frameNumber)
    {
        DebugLogger.Log($"[MainWindowPacketViewModel] NavigateToPacket requested: frame #{frameNumber}");
        NavigateToPacketRequested?.Invoke(this, frameNumber);
    }

    /// <summary>
    /// Applies a stream filter to show only packets matching the pattern.
    /// Returns the count of matching packets.
    /// </summary>
    public int ApplyStreamFilter(string searchPattern)
    {
        // Save current filtered packets if no stream filter active yet
        if (!HasStreamFilter)
        {
            _preStreamFilterPackets = [.._filteredPackets];
        }

        _activeStreamFilter = searchPattern;

        // Parse search pattern - supports formats:
        // "192.168.1.1" - matches any packet with this IP
        // "192.168.1.1:443" - matches packets with this IP:Port combination
        // "192.168.1.1:443-10.0.0.1:80" - matches specific conversation
        var (ip1, port1, ip2, port2) = ParseStreamPattern(searchPattern);

        // Filter packets based on stream pattern
        var matchingPackets = _preStreamFilterPackets
            .Where(packet => MatchesStreamPattern(packet, ip1, port1, ip2, port2))
            .OrderBy(p => p.FrameNumber)
            .ToList();

        _filteredPackets = matchingPackets;
        HasStreamFilter = true;
        TotalFilteredPackets = _filteredPackets.Count;
        UpdateFilteredStatistics();
        FilteredPacketsChanged?.Invoke(this, _filteredPackets.Count);

        return matchingPackets.Count;
    }

    /// <summary>
    /// Clears the stream filter and restores the previous filtered state.
    /// </summary>
    public void ClearStreamFilter()
    {
        if (!HasStreamFilter) return;

        _activeStreamFilter = null;
        HasStreamFilter = false;

        // Restore pre-stream-filter packets
        _filteredPackets = [.._preStreamFilterPackets];
        _preStreamFilterPackets.Clear();

        TotalFilteredPackets = _filteredPackets.Count;
        UpdateFilteredStatistics();
        FilteredPacketsChanged?.Invoke(this, _filteredPackets.Count);
    }

    /// <summary>
    /// Parses stream pattern into IP/port components.
    /// </summary>
    private static (string? ip1, int? port1, string? ip2, int? port2) ParseStreamPattern(string searchPattern)
    {
        var parts = searchPattern.Split(new[] { '-', '↔', ' ' }, StringSplitOptions.RemoveEmptyEntries);

        string? ip1 = null, ip2 = null;
        int? port1 = null, port2 = null;

        foreach (var part in parts)
        {
            var colonIdx = part.LastIndexOf(':');
            if (colonIdx > 0 && int.TryParse(part.AsSpan(colonIdx + 1), out var port))
            {
                var ip = part[..colonIdx];
                if (ip1 is null) { ip1 = ip; port1 = port; }
                else { ip2 = ip; port2 = port; }
            }
            else
            {
                if (ip1 is null) ip1 = part;
                else ip2 = part;
            }
        }

        return (ip1, port1, ip2, port2);
    }

    /// <summary>
    /// Checks if a packet matches the stream pattern.
    /// </summary>
    private static bool MatchesStreamPattern(PacketInfo packet, string? ip1, int? port1, string? ip2, int? port2)
    {
        if (ip2 is not null)
        {
            // Bidirectional conversation match
            var fwdMatch = MatchesEndpoint(packet.SourceIP, packet.SourcePort, ip1, port1) &&
                           MatchesEndpoint(packet.DestinationIP, packet.DestinationPort, ip2, port2);
            var revMatch = MatchesEndpoint(packet.SourceIP, packet.SourcePort, ip2, port2) &&
                           MatchesEndpoint(packet.DestinationIP, packet.DestinationPort, ip1, port1);
            return fwdMatch || revMatch;
        }
        else if (ip1 is not null)
        {
            // Single endpoint match
            return MatchesEndpoint(packet.SourceIP, packet.SourcePort, ip1, port1) ||
                   MatchesEndpoint(packet.DestinationIP, packet.DestinationPort, ip1, port1);
        }
        return false;
    }

    private static bool MatchesEndpoint(string ip, int port, string? searchIp, int? searchPort)
    {
        if (searchIp is null) return false;
        if (!ip.Equals(searchIp, StringComparison.OrdinalIgnoreCase)) return false;
        if (searchPort.HasValue && port != searchPort.Value) return false;
        return true;
    }

    private static bool IsThreateningPacket(PacketInfo packet)
    {
        return packet.Protocol == Protocol.ICMP ||
               packet.SourcePort == 445 || packet.DestinationPort == 445 ||
               packet.SourcePort == 139 || packet.DestinationPort == 139;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await _memoryPacketStore.DisposeAsync();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowPacketViewModel] Failed to dispose in-memory store: {ex.Message}");
        }

        try
        {
            await _duckPacketStore.DisposeAsync();
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[MainWindowPacketViewModel] Failed to dispose DuckDB store: {ex.Message}");
        }

        // Dispose stream cache in PacketDetails
        PacketDetails.Dispose();
    }
}
