using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.DependencyInjection;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Services;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// ViewModel for comparing two PCAP files.
/// Displays packets unique to each file and common packets with color-coded visualization.
/// </summary>
public partial class CompareViewModel : ObservableObject, IDisposable
{
    // ==================== DISPATCHER ====================

    private IDispatcherService Dispatcher => _dispatcher ??= App.Services?.GetService<IDispatcherService>()
        ?? throw new InvalidOperationException("IDispatcherService not registered");
    private IDispatcherService? _dispatcher;

    // ==================== SERVICES ====================

    private readonly IPacketComparer _packetComparer;
    private readonly IFileDialogService? _fileDialogService;

    // ==================== STATE ====================

    private CancellationTokenSource? _comparisonCts;
    private bool _isDisposed;

    // ==================== FILE SELECTION ====================

    [ObservableProperty] private string _fileAPath = "";
    [ObservableProperty] private string _fileAName = "No file selected";
    [ObservableProperty] private string _fileBPath = "";
    [ObservableProperty] private string _fileBName = "Select File B...";

    // ==================== COMPARISON STATE ====================

    [ObservableProperty] private bool _isComparing;
    [ObservableProperty] private int _comparisonProgress;
    [ObservableProperty] private string _statusMessage = "Select two PCAP files to compare";
    [ObservableProperty] private bool _hasResults;

    // ==================== STATISTICS ====================

    [ObservableProperty] private int _totalFileA;
    [ObservableProperty] private int _totalFileB;
    [ObservableProperty] private int _commonCount;
    [ObservableProperty] private int _uniqueToA;
    [ObservableProperty] private int _uniqueToB;
    [ObservableProperty] private string _matchPercentage = "0%";

    // Protocol breakdown for unique packets
    [ObservableProperty] private ObservableCollection<ProtocolDiffItem> _protocolDiffA = new();
    [ObservableProperty] private ObservableCollection<ProtocolDiffItem> _protocolDiffB = new();

    // ==================== FILTER STATE ====================

    [ObservableProperty] private PacketSourceFilter _currentFilter = PacketSourceFilter.All;
    [ObservableProperty] private string _searchText = "";

    // ==================== PACKET DATA ====================

    private List<ComparedPacketViewModel> _allPackets = new();

    [ObservableProperty] private ObservableCollection<ComparedPacketViewModel> _displayedPackets = new();

    // ==================== COLORS ====================

    public static IBrush FileAColor => ThemeColorHelper.CompareFileABrush;
    public static IBrush FileBColor => ThemeColorHelper.CompareFileBBrush;
    public static IBrush BothColor => ThemeColorHelper.CompareBothBrush;

    // ==================== CONSTRUCTOR ====================

    public CompareViewModel(IPacketComparer packetComparer, IFileDialogService? fileDialogService = null)
    {
        _packetComparer = packetComparer ?? throw new ArgumentNullException(nameof(packetComparer));
        _fileDialogService = fileDialogService;

        DebugLogger.Log("[CompareViewModel] Initialized");
    }

    // ==================== COMMANDS ====================

    /// <summary>
    /// Sets File A from the currently loaded PCAP in main analysis.
    /// Called when Compare tab is activated with a loaded file.
    /// </summary>
    public void SetFileA(string filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return;

        FileAPath = filePath;
        FileAName = System.IO.Path.GetFileName(filePath);
        UpdateCanCompare();

        DebugLogger.Log($"[CompareViewModel] File A set: {FileAName}");
    }

    [RelayCommand]
    private async Task BrowseFileBAsync()
    {
        if (_fileDialogService == null)
        {
            StatusMessage = "File dialog service not available";
            return;
        }

        var filePath = await _fileDialogService.OpenFileAsync(
            "Select PCAP File B",
            new FileDialogFilter("PCAP Files", "pcap", "pcapng", "cap"));

        if (!string.IsNullOrEmpty(filePath))
        {
            FileBPath = filePath;
            FileBName = System.IO.Path.GetFileName(filePath);
            UpdateCanCompare();

            DebugLogger.Log($"[CompareViewModel] File B selected: {FileBName}");
        }
    }

    [RelayCommand(CanExecute = nameof(CanCompare))]
    private async Task CompareAsync()
    {
        if (string.IsNullOrEmpty(FileAPath) || string.IsNullOrEmpty(FileBPath))
            return;

        IsComparing = true;
        ComparisonProgress = 0;
        StatusMessage = "Comparing files...";
        HasResults = false;

        _comparisonCts?.Cancel();
        _comparisonCts = new CancellationTokenSource();

        try
        {
            var progress = new Progress<int>(p =>
            {
                ComparisonProgress = p;
                StatusMessage = $"Comparing... {p}%";
            });

            var result = await _packetComparer.CompareAsync(
                FileAPath,
                FileBPath,
                progress,
                _comparisonCts.Token);

            await Dispatcher.InvokeAsync(() =>
            {
                UpdateFromResult(result);
                HasResults = true;
                StatusMessage = $"Comparison complete: {CommonCount:N0} common, {UniqueToA:N0} unique to A, {UniqueToB:N0} unique to B";
            });

            DebugLogger.Log($"[CompareViewModel] Comparison complete: {result.AllPackets.Count} total packets");
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Comparison cancelled";
            DebugLogger.Log("[CompareViewModel] Comparison cancelled");
        }
        catch (Exception ex)
        {
            StatusMessage = $"Error: {ex.Message}";
            DebugLogger.Log($"[CompareViewModel] Comparison error: {ex.Message}");
        }
        finally
        {
            IsComparing = false;
            ComparisonProgress = 100;
        }
    }

    [RelayCommand]
    private void CancelComparison()
    {
        _comparisonCts?.Cancel();
        StatusMessage = "Cancelling...";
    }

    [RelayCommand]
    private void ClearResults()
    {
        _allPackets.Clear();
        DisplayedPackets.Clear();
        ProtocolDiffA.Clear();
        ProtocolDiffB.Clear();

        TotalFileA = 0;
        TotalFileB = 0;
        CommonCount = 0;
        UniqueToA = 0;
        UniqueToB = 0;
        MatchPercentage = "0%";

        HasResults = false;
        CurrentFilter = PacketSourceFilter.All;
        SearchText = "";
        StatusMessage = "Results cleared";

        DebugLogger.Log("[CompareViewModel] Results cleared");
    }

    // ==================== FILTER COMMANDS ====================

    [RelayCommand]
    private void FilterAll() => ApplyFilter(PacketSourceFilter.All);

    [RelayCommand]
    private void FilterFileAOnly() => ApplyFilter(PacketSourceFilter.FileAOnly);

    [RelayCommand]
    private void FilterFileBOnly() => ApplyFilter(PacketSourceFilter.FileBOnly);

    [RelayCommand]
    private void FilterCommon() => ApplyFilter(PacketSourceFilter.Common);

    partial void OnSearchTextChanged(string value) => RefreshDisplayedPackets();

    // ==================== PRIVATE METHODS ====================

    private bool CanCompare() =>
        !string.IsNullOrEmpty(FileAPath) &&
        !string.IsNullOrEmpty(FileBPath) &&
        !IsComparing;

    private void UpdateCanCompare()
    {
        CompareCommand.NotifyCanExecuteChanged();
    }

    private void UpdateFromResult(ComparisonResult result)
    {
        var stats = result.Statistics;

        // Update statistics
        TotalFileA = stats.TotalFileA;
        TotalFileB = stats.TotalFileB;
        CommonCount = stats.CommonCount;
        UniqueToA = stats.UniqueToA;
        UniqueToB = stats.UniqueToB;
        MatchPercentage = $"{stats.MatchPercentage:F1}%";

        // Update protocol breakdowns
        ProtocolDiffA.Clear();
        foreach (var kvp in stats.ProtocolDiffA.OrderByDescending(x => x.Value).Take(10))
        {
            ProtocolDiffA.Add(new ProtocolDiffItem(kvp.Key, kvp.Value));
        }

        ProtocolDiffB.Clear();
        foreach (var kvp in stats.ProtocolDiffB.OrderByDescending(x => x.Value).Take(10))
        {
            ProtocolDiffB.Add(new ProtocolDiffItem(kvp.Key, kvp.Value));
        }

        // Convert packets to ViewModels
        _allPackets = result.AllPackets
            .Select(p => new ComparedPacketViewModel(p))
            .ToList();

        // Initial display
        CurrentFilter = PacketSourceFilter.All;
        RefreshDisplayedPackets();
    }

    private void ApplyFilter(PacketSourceFilter filter)
    {
        CurrentFilter = filter;
        RefreshDisplayedPackets();
        DebugLogger.Log($"[CompareViewModel] Filter applied: {filter}");
    }

    private void RefreshDisplayedPackets()
    {
        var filtered = _allPackets.AsEnumerable();

        // Apply source filter
        filtered = CurrentFilter switch
        {
            PacketSourceFilter.FileAOnly => filtered.Where(p => p.Source == PacketSource.FileA),
            PacketSourceFilter.FileBOnly => filtered.Where(p => p.Source == PacketSource.FileB),
            PacketSourceFilter.Common => filtered.Where(p => p.Source == PacketSource.Both),
            _ => filtered
        };

        // Apply search text
        if (!string.IsNullOrWhiteSpace(SearchText))
        {
            var search = SearchText.Trim();
            filtered = filtered.Where(p =>
                p.SourceIP.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                p.DestinationIP.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                p.Protocol.Contains(search, StringComparison.OrdinalIgnoreCase) ||
                p.Info.Contains(search, StringComparison.OrdinalIgnoreCase));
        }

        DisplayedPackets = new ObservableCollection<ComparedPacketViewModel>(filtered.Take(10000));
    }

    // ==================== DISPOSAL ====================

    public void Dispose()
    {
        if (_isDisposed) return;

        _comparisonCts?.Cancel();
        _comparisonCts?.Dispose();
        _isDisposed = true;

        DebugLogger.Log("[CompareViewModel] Disposed");
    }
}

/// <summary>
/// Filter options for packet source display
/// </summary>
public enum PacketSourceFilter
{
    All,
    FileAOnly,
    FileBOnly,
    Common
}

/// <summary>
/// ViewModel wrapper for ComparedPacket with display properties
/// </summary>
public class ComparedPacketViewModel
{
    private readonly ComparedPacket _packet;

    public ComparedPacketViewModel(ComparedPacket packet)
    {
        _packet = packet;
    }

    public uint FrameNumber => _packet.Packet.FrameNumber;
    public string Timestamp => _packet.Packet.Timestamp.ToString("HH:mm:ss.fff");
    public string SourceIP => _packet.Packet.SourceIP;
    public string DestinationIP => _packet.Packet.DestinationIP;
    public string Protocol => _packet.Packet.GetProtocolDisplay();
    public int Length => _packet.Packet.Length;
    public string Info => _packet.Packet.Info ?? "";
    public PacketSource Source => _packet.Source;
    public string SourceFile => _packet.SourceFile;

    /// <summary>
    /// Row background color based on packet source
    /// </summary>
    public IBrush RowBackground => Source switch
    {
        PacketSource.FileA => ThemeColorHelper.GetCompareFileTintBrush("FileA"),
        PacketSource.FileB => ThemeColorHelper.GetCompareFileTintBrush("FileB"),
        _ => new SolidColorBrush(Colors.Transparent)
    };

    /// <summary>
    /// Source indicator color
    /// </summary>
    public IBrush SourceColor => Source switch
    {
        PacketSource.FileA => CompareViewModel.FileAColor,
        PacketSource.FileB => CompareViewModel.FileBColor,
        _ => CompareViewModel.BothColor
    };

    /// <summary>
    /// Source indicator text
    /// </summary>
    public string SourceIndicator => Source switch
    {
        PacketSource.FileA => "A",
        PacketSource.FileB => "B",
        _ => "="
    };
}

/// <summary>
/// Protocol breakdown item for unique packets
/// </summary>
public record ProtocolDiffItem(string Protocol, int Count);
