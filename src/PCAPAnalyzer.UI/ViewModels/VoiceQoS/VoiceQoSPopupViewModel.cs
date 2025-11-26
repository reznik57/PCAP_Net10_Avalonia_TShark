using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Models;

namespace PCAPAnalyzer.UI.ViewModels.VoiceQoS;

/// <summary>
/// Manages detail popup dialogs for VoiceQoS tab.
/// Handles display of packet details for QoS traffic, latency connections, jitter connections, and top endpoints.
/// </summary>
public partial class VoiceQoSPopupViewModel : ObservableObject
{
    private readonly object _collectionLock = new();

    // Dialog state
    [ObservableProperty] private ObservableCollection<PacketInfo> _detailPackets = new();
    [ObservableProperty] private string _detailTitle = "";
    [ObservableProperty] private bool _isDetailDialogOpen;

    /// <summary>
    /// Shows packet details for a selected QoS traffic entry
    /// </summary>
    [RelayCommand]
    public void ShowQoSDetails(QoSTrafficItem? item)
    {
        if (item == null) return;

        Dispatcher.UIThread.InvokeAsync(() =>
        {
            lock (_collectionLock)
            {
                DetailPackets.Clear();
                foreach (var packet in item.Packets.OrderBy(p => p.Timestamp))
                {
                    DetailPackets.Add(packet);
                }
            }
            DetailTitle = $"QoS Flow Details: {item.SourceIP} → {item.DestinationIP} | {item.QoSType} | {item.DscpDisplay} | Ports: {item.PortRange}";
            IsDetailDialogOpen = true;

            DebugLogger.Log($"[VoiceQoSPopupViewModel] Opened QoS details for {item.SourceIP} → {item.DestinationIP} ({item.Packets.Count} packets)");
        });
    }

    /// <summary>
    /// Shows packet details for a selected high latency connection
    /// </summary>
    [RelayCommand]
    public void ShowLatencyDetails(LatencyConnectionItem? item)
    {
        if (item == null) return;

        Dispatcher.UIThread.InvokeAsync(() =>
        {
            lock (_collectionLock)
            {
                DetailPackets.Clear();
                foreach (var packet in item.Packets.OrderBy(p => p.Timestamp))
                {
                    DetailPackets.Add(packet);
                }
            }
            DetailTitle = $"High Latency Connection: {item.SourceIP} ↔ {item.DestinationIP} | Avg: {item.AverageLatencyFormatted}, Max: {item.MaxLatencyFormatted} | Ports: {item.PortRange}";
            IsDetailDialogOpen = true;

            DebugLogger.Log($"[VoiceQoSPopupViewModel] Opened latency details for {item.SourceIP} ↔ {item.DestinationIP} ({item.Packets.Count} packets)");
        });
    }

    /// <summary>
    /// Shows packet details for a selected high jitter connection
    /// </summary>
    [RelayCommand]
    public void ShowJitterDetails(JitterConnectionItem? item)
    {
        if (item == null) return;

        Dispatcher.UIThread.InvokeAsync(() =>
        {
            lock (_collectionLock)
            {
                DetailPackets.Clear();
                foreach (var packet in item.Packets.OrderBy(p => p.Timestamp))
                {
                    DetailPackets.Add(packet);
                }
            }
            DetailTitle = $"High Jitter Connection: {item.SourceIP} ↔ {item.DestinationIP} | Avg: {item.AverageJitterFormatted}, Max: {item.MaxJitterFormatted} | Ports: {item.PortRange}";
            IsDetailDialogOpen = true;

            DebugLogger.Log($"[VoiceQoSPopupViewModel] Opened jitter details for {item.SourceIP} ↔ {item.DestinationIP} ({item.Packets.Count} packets)");
        });
    }

    /// <summary>
    /// Shows packet details for a selected Top Endpoint entry.
    /// Requires the caller to provide the related packets based on metric type.
    /// </summary>
    /// <param name="item">The top endpoint item</param>
    /// <param name="relatedPackets">Pre-filtered packets related to this endpoint</param>
    public void ShowTopEndpointDetails(TopEndpointItem? item, IEnumerable<PacketInfo>? relatedPackets)
    {
        if (item == null) return;

        Dispatcher.UIThread.InvokeAsync(() =>
        {
            lock (_collectionLock)
            {
                DetailPackets.Clear();

                if (relatedPackets != null)
                {
                    foreach (var packet in relatedPackets.OrderBy(p => p.Timestamp))
                    {
                        DetailPackets.Add(packet);
                    }
                }
            }

            DetailTitle = $"Top Endpoint Details: {item.IPAddress} | {item.MetricType} | {item.FlowCount} Flows, {item.PacketCount} Packets, {item.BytesFormatted}";
            IsDetailDialogOpen = true;

            DebugLogger.Log($"[VoiceQoSPopupViewModel] Opened top endpoint details for {item.IPAddress} ({DetailPackets.Count} packets)");
        });
    }

    /// <summary>
    /// Closes the packet details dialog
    /// </summary>
    [RelayCommand]
    public void CloseDetailDialog()
    {
        IsDetailDialogOpen = false;
        lock (_collectionLock)
        {
            DetailPackets.Clear();
        }
        DetailTitle = "";

        DebugLogger.Log("[VoiceQoSPopupViewModel] Detail dialog closed");
    }
}
