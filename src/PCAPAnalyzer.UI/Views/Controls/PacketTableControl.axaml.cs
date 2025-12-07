using System;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.ViewModels;

namespace PCAPAnalyzer.UI.Views.Controls;

public partial class PacketTableControl : UserControl
{
    public PacketTableControl()
    {
        InitializeComponent();
        // Use Console.WriteLine DIRECTLY to guarantee output (DebugLogger may not be initialized yet)
        Console.WriteLine("═══════════════════════════════════════════════════════════");
        Console.WriteLine("🚀 [PacketTableControl] CONSTRUCTOR CALLED - NEW CODE IS RUNNING!");
        Console.WriteLine("═══════════════════════════════════════════════════════════");
    }

    private void GoToPageTextBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && DataContext is MainWindowViewModel viewModel)
        {
            viewModel.UIState.GoToPageCommand.Execute(null);
            e.Handled = true;
        }
    }

    private void GoToPacketTextBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && DataContext is MainWindowViewModel viewModel)
        {
            viewModel.UIState.GoToPacketCommand.Execute(null);
            e.Handled = true;
        }
    }

    private void SearchStreamTextBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && DataContext is MainWindowViewModel viewModel)
        {
            viewModel.UIState.SearchStreamCommand.Execute(null);
            e.Handled = true;
        }
    }

    #region Keyboard Navigation

    private async void PacketList_KeyDown(object? sender, KeyEventArgs e)
    {
        if (DataContext is not MainWindowViewModel viewModel) return;

        var packets = viewModel.Packets;
        if (packets is null || packets.Count == 0) return;

        var currentPacket = viewModel.PacketManager.SelectedPacket;
        int currentIndex = -1;
        if (currentPacket is PacketInfo selected)
            currentIndex = packets.IndexOf(selected);

        switch (e.Key)
        {
            case Key.Up when currentIndex > 0:
                await viewModel.PacketManager.SelectPacketAsync(packets[currentIndex - 1]);
                e.Handled = true;
                break;

            case Key.Down when currentIndex < packets.Count - 1:
                await viewModel.PacketManager.SelectPacketAsync(packets[currentIndex + 1]);
                e.Handled = true;
                break;

            case Key.Down when currentIndex == -1 && packets.Count > 0:
                await viewModel.PacketManager.SelectPacketAsync(packets[0]);
                e.Handled = true;
                break;

            case Key.Enter when currentPacket is { } pktEnter:
                await viewModel.PacketManager.SelectPacketAsync(pktEnter);
                e.Handled = true;
                break;

            case Key.Home when packets.Count > 0:
                await viewModel.PacketManager.SelectPacketAsync(packets[0]);
                e.Handled = true;
                break;

            case Key.End when packets.Count > 0:
                await viewModel.PacketManager.SelectPacketAsync(packets[^1]);
                e.Handled = true;
                break;

            case Key.PageUp:
                viewModel.GoToPreviousPageCommand.Execute(null);
                e.Handled = true;
                break;

            case Key.PageDown:
                viewModel.GoToNextPageCommand.Execute(null);
                e.Handled = true;
                break;

            case Key.C when e.KeyModifiers.HasFlag(KeyModifiers.Control) && currentPacket is { } pkt:
                var summary = $"#{pkt.FrameNumber} {pkt.Timestamp:HH:mm:ss.fff} {pkt.SourceIP}:{pkt.SourcePort} → {pkt.DestinationIP}:{pkt.DestinationPort} {pkt.Protocol} {pkt.Length}B";
                await CopyToClipboard(summary);
                e.Handled = true;
                break;

            case Key.F when currentPacket is { } filterPkt:
                viewModel.UIState.SearchStreamText = $"{filterPkt.SourceIP}:{filterPkt.SourcePort}-{filterPkt.DestinationIP}:{filterPkt.DestinationPort}";
                viewModel.UIState.SearchStreamCommand.Execute(null);
                e.Handled = true;
                break;

            case Key.Escape:
                viewModel.UIState.ClearStreamSearchCommand.Execute(null);
                e.Handled = true;
                break;
        }
    }

    #endregion

    #region Context Menu Handlers

    private async void CopyRowSummary_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (GetPacketFromMenuItem(sender) is { } packet)
        {
            var summary = $"#{packet.FrameNumber} {packet.Timestamp:HH:mm:ss.fff} {packet.SourceIP}:{packet.SourcePort} → {packet.DestinationIP}:{packet.DestinationPort} {packet.Protocol} {packet.Length}B {packet.Info}";
            await CopyToClipboard(summary);
        }
    }

    private async void CopySourceIP_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (GetPacketFromMenuItem(sender) is { } packet)
            await CopyToClipboard(packet.SourceIP);
    }

    private async void CopyDestIP_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (GetPacketFromMenuItem(sender) is { } packet)
            await CopyToClipboard(packet.DestinationIP);
    }

    private async void CopyConversation_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (GetPacketFromMenuItem(sender) is { } packet)
        {
            var conversation = $"{packet.SourceIP}:{packet.SourcePort} ↔ {packet.DestinationIP}:{packet.DestinationPort}";
            await CopyToClipboard(conversation);
        }
    }

    private async void CopyFrameNumber_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (GetPacketFromMenuItem(sender) is { } packet)
            await CopyToClipboard(packet.FrameNumber.ToString());
    }

    private void FilterByStream_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (GetPacketFromMenuItem(sender) is { } packet &&
            DataContext is MainWindowViewModel viewModel)
        {
            var streamPattern = $"{packet.SourceIP}:{packet.SourcePort}-{packet.DestinationIP}:{packet.DestinationPort}";
            viewModel.UIState.SearchStreamText = streamPattern;
            viewModel.UIState.SearchStreamCommand.Execute(null);
        }
    }

    private void ToggleBookmark_Click(object? sender, Avalonia.Interactivity.RoutedEventArgs e)
    {
        if (GetPacketFromMenuItem(sender) is { } packet &&
            DataContext is MainWindowViewModel viewModel)
        {
            viewModel.PacketManager.ToggleBookmark(packet.FrameNumber);
            Console.WriteLine($"[BOOKMARK] Toggled bookmark for frame {packet.FrameNumber}");
        }
    }

    private PacketInfo? GetPacketFromMenuItem(object? sender)
    {
        // Navigate up from MenuItem → ContextMenu → Border (with DataContext)
        if (sender is MenuItem menuItem &&
            menuItem.Parent is ContextMenu contextMenu &&
            contextMenu.PlacementTarget is Border { DataContext: PacketInfo packet })
        {
            return packet;
        }
        return null;
    }

    private async Task CopyToClipboard(string text)
    {
        try
        {
            var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
            if (clipboard is not null)
            {
                await clipboard.SetTextAsync(text);
                Console.WriteLine($"[CLIPBOARD] Copied: {text}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[CLIPBOARD] Error: {ex.Message}");
        }
    }

    #endregion

    /// <summary>
    /// Handles packet row selection - loads packet details in bottom panel
    /// </summary>
    private async void PacketRow_PointerPressed(object? sender, PointerPressedEventArgs e)
    {
        // Use Console.WriteLine DIRECTLY to guarantee output
        Console.WriteLine($"[CLICK] PacketRow_PointerPressed - sender: {sender?.GetType().Name}");

        if (sender is Border { DataContext: PacketInfo packet } &&
            DataContext is MainWindowViewModel viewModel)
        {
            Console.WriteLine($"[CLICK] ✅ Valid packet click - Frame: {packet.FrameNumber}");
            await viewModel.PacketManager.SelectPacketAsync(packet);
            Console.WriteLine($"[CLICK] SelectPacketAsync completed");
            e.Handled = true;
        }
        else
        {
            Console.WriteLine($"[CLICK] ❌ Invalid - sender: {sender?.GetType().Name}, DataContext: {DataContext?.GetType().Name}");
        }
    }
}
