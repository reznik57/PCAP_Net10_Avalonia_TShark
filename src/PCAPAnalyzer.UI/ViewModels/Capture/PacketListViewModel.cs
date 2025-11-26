using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using Avalonia.Collections;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using PCAPAnalyzer.Core.Models.Capture;

namespace PCAPAnalyzer.UI.ViewModels.Capture;

/// <summary>
/// ViewModel managing the packet list with optimized batching and virtualization
/// Implements high-performance UI update patterns for 50K+ packets/sec capture rates
/// </summary>
public partial class PacketListViewModel : ViewModelBase, IDisposable
{
    private const int MaxDisplayedPackets = 10000; // Limit displayed packets for performance
    private const int BatchSize = 50; // Flush when buffer reaches 50 packets
    private const int FlushIntervalMs = 100; // Flush every 100ms (whichever comes first)

    private readonly AvaloniaList<PacketViewModel> _packets = new();
    private readonly List<LivePacketData> _packetBuffer = new();
    private readonly SemaphoreSlim _bufferLock = new(1, 1);
    private readonly DispatcherTimer _flushTimer;
    private bool _disposed;

    /// <summary>
    /// Read-only packet collection for DataGrid binding (high-performance AvaloniaList)
    /// </summary>
    public IAvaloniaReadOnlyList<PacketViewModel> Packets => _packets;

    /// <summary>
    /// Total packet count captured (including those not displayed due to max limit)
    /// </summary>
    [ObservableProperty]
    private long _totalPacketCount;

    /// <summary>
    /// Number of packets currently displayed in the UI
    /// </summary>
    [ObservableProperty]
    private int _packetsDisplayed;

    /// <summary>
    /// Whether max packet limit has been reached (FIFO mode active)
    /// </summary>
    [ObservableProperty]
    private bool _maxPacketsReached;

    /// <summary>
    /// Selected packet in the grid
    /// </summary>
    [ObservableProperty]
    private PacketViewModel? _selectedPacket;

    /// <summary>
    /// Filter text for packet filtering
    /// </summary>
    [ObservableProperty]
    private string _filterText = string.Empty;

    /// <summary>
    /// Whether to auto-scroll to new packets
    /// </summary>
    [ObservableProperty]
    private bool _autoScroll = true;

    public PacketListViewModel()
    {
        // Timer to flush buffered packets to UI (every 100ms)
        _flushTimer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(FlushIntervalMs)
        };
        _flushTimer.Tick += OnFlushTimerTick;
        _flushTimer.Start();
    }

    /// <summary>
    /// Adds a packet to the buffer (called from background thread)
    /// Thread-safe with async/await pattern for minimal blocking
    /// </summary>
    public void AddPacket(LivePacketData packet)
    {
        if (_disposed) return;

        _bufferLock.Wait();
        try
        {
            _packetBuffer.Add(packet);
            TotalPacketCount++;

            // Flush if batch size reached (50 packets)
            if (_packetBuffer.Count >= BatchSize)
            {
                FlushBufferToUI();
            }
        }
        finally
        {
            _bufferLock.Release();
        }
    }

    /// <summary>
    /// Timer tick handler - flushes buffer every 100ms
    /// </summary>
    private void OnFlushTimerTick(object? sender, EventArgs e)
    {
        _bufferLock.Wait();
        try
        {
            if (_packetBuffer.Count > 0)
            {
                FlushBufferToUI();
            }
        }
        finally
        {
            _bufferLock.Release();
        }
    }

    /// <summary>
    /// Flushes buffered packets to UI (must be called with _bufferLock held)
    /// Single UI thread call per batch for optimal performance
    /// </summary>
    private void FlushBufferToUI()
    {
        if (_packetBuffer.Count == 0) return;

        // Take packets from buffer
        var packetsToAdd = _packetBuffer.ToList();
        _packetBuffer.Clear();

        // Update UI on UI thread (single call for entire batch)
        Dispatcher.UIThread.Post(() =>
        {
            foreach (var packet in packetsToAdd)
            {
                // Apply filter if set
                if (!string.IsNullOrWhiteSpace(FilterText))
                {
                    if (!MatchesFilter(packet))
                        continue;
                }

                // Check max packet limit (FIFO - remove oldest)
                if (_packets.Count >= MaxDisplayedPackets)
                {
                    MaxPacketsReached = true;
                    _packets.RemoveAt(0);
                }

                _packets.Add(PacketViewModel.FromLivePacketData(packet));
            }

            PacketsDisplayed = _packets.Count;
        });
    }

    /// <summary>
    /// Checks if packet matches filter criteria
    /// </summary>
    private bool MatchesFilter(LivePacketData packet)
    {
        var filterLower = FilterText.ToLowerInvariant();
        return (packet.SourceIp?.Contains(filterLower, StringComparison.OrdinalIgnoreCase) ?? false) ||
               (packet.DestinationIp?.Contains(filterLower, StringComparison.OrdinalIgnoreCase) ?? false) ||
               packet.Protocol.Contains(filterLower, StringComparison.OrdinalIgnoreCase) ||
               (packet.ProtocolInfo?.Contains(filterLower, StringComparison.OrdinalIgnoreCase) ?? false);
    }

    /// <summary>
    /// Clears all packets from the list
    /// </summary>
    public void Clear()
    {
        _bufferLock.Wait();
        try
        {
            _packetBuffer.Clear();

            Dispatcher.UIThread.Post(() =>
            {
                _packets.Clear();
                TotalPacketCount = 0;
                PacketsDisplayed = 0;
                MaxPacketsReached = false;
            });
        }
        finally
        {
            _bufferLock.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _flushTimer?.Stop();
        _bufferLock?.Dispose();

        GC.SuppressFinalize(this);
    }
}
