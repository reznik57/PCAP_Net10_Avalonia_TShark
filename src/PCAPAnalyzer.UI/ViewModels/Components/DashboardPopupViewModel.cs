using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Avalonia.Controls;
using Avalonia.Layout;
using LiveChartsCore;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.ViewModels;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Components;

/// <summary>
/// Manages popup windows and dialogs for the Dashboard.
/// Handles detailed views, chart popups, and packet details.
/// Extracted from DashboardViewModel to follow Single Responsibility Principle.
/// </summary>
public partial class DashboardPopupViewModel : ObservableObject
{
    // ==================== POPUP STATE ====================

    [ObservableProperty] private bool _isPopupVisible;
    [ObservableProperty] private string _popupTitle = "";
    [ObservableProperty] private string _popupSubtitle = "";
    [ObservableProperty] private object? _popupContent;
    [ObservableProperty] private bool _hasPopupActions;
    [ObservableProperty] private bool _canExportPopupData;
    [ObservableProperty] private bool _canRefreshPopupData;

    // ==================== DATA REFERENCES ====================

    private NetworkStatistics? _currentStatistics;
    private IReadOnlyList<PacketInfo>? _currentPackets;
    private readonly DashboardViewModel? _parentViewModel;

    // ==================== CONSTRUCTOR ====================

    public DashboardPopupViewModel(DashboardViewModel? parentViewModel = null)
    {
        _parentViewModel = parentViewModel;
    }

    // ==================== DATA CONTEXT UPDATES ====================

    /// <summary>
    /// Updates the current statistics and packets for popup operations.
    /// </summary>
    public void UpdateDataContext(NetworkStatistics? statistics, IReadOnlyList<PacketInfo>? packets)
    {
        _currentStatistics = statistics;
        _currentPackets = packets;
    }

    // ==================== POPUP COMMANDS - DATA TABLES ====================

    [RelayCommand]
    private void ViewAllSources()
    {
        try
        {
            PopupTitle = "Top 30 Source IP Addresses - Detailed View";
            PopupSubtitle = $"Showing top 30 source IPs from {_currentStatistics?.TotalPackets:N0} total packets";

            if (_currentStatistics?.TopSources == null || !_currentStatistics.TopSources.Any())
            {
                PopupContent = CreateErrorMessage("No source data available");
                HasPopupActions = false;
                CanExportPopupData = false;
                CanRefreshPopupData = false;
                IsPopupVisible = true;
                return;
            }

            var sources = new ObservableCollection<EndpointViewModel>(
                _currentStatistics.TopSources.Take(30).Select(s => new EndpointViewModel
                {
                    Address = s.Address,
                    PacketCount = s.PacketCount,
                    ByteCount = s.ByteCount,
                    BytesFormatted = NumberFormatter.FormatBytes(s.ByteCount),
                    Percentage = s.Percentage,
                    Type = PCAPAnalyzer.Core.Services.NetworkFilterHelper.IsIPv4(s.Address) ? "IPv4" :
                           PCAPAnalyzer.Core.Services.NetworkFilterHelper.IsIPv6(s.Address) ? "IPv6" : "Unknown",
                    Country = s.Country,
                    CountryCode = s.CountryCode
                })
            );

            var tableViewModel = new PopupTableViewModel("sources", sources);
            var tableView = new Controls.PopupTableView
            {
                DataContext = tableViewModel
            };
            PopupContent = tableView;

            HasPopupActions = true;
            CanExportPopupData = true;
            CanRefreshPopupData = true;
            IsPopupVisible = true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error showing sources popup: {ex.Message}");
            ShowError("Error loading source data. Please try again.");
        }
    }

    [RelayCommand]
    private void ViewAllDestinations()
    {
        try
        {
            PopupTitle = "Top 30 Destination IP Addresses - Detailed View";
            PopupSubtitle = $"Showing top 30 destination IPs from {_currentStatistics?.TotalPackets:N0} total packets";

            if (_currentStatistics?.TopDestinations == null || !_currentStatistics.TopDestinations.Any())
            {
                ShowError("No destination data available");
                return;
            }

            var destinations = new ObservableCollection<EndpointViewModel>(
                _currentStatistics.TopDestinations.Take(30).Select(d => new EndpointViewModel
                {
                    Address = d.Address,
                    PacketCount = d.PacketCount,
                    ByteCount = d.ByteCount,
                    BytesFormatted = NumberFormatter.FormatBytes(d.ByteCount),
                    Percentage = d.Percentage,
                    Type = PCAPAnalyzer.Core.Services.NetworkFilterHelper.IsIPv4(d.Address) ? "IPv4" :
                           PCAPAnalyzer.Core.Services.NetworkFilterHelper.IsIPv6(d.Address) ? "IPv6" : "Unknown",
                    Country = d.Country,
                    CountryCode = d.CountryCode
                })
            );

            var tableViewModel = new PopupTableViewModel("destinations", destinations);
            var tableView = new Controls.PopupTableView
            {
                DataContext = tableViewModel
            };
            PopupContent = tableView;

            HasPopupActions = true;
            CanExportPopupData = true;
            CanRefreshPopupData = true;
            IsPopupVisible = true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error showing destinations popup: {ex.Message}");
            ShowError("Error loading destination data.");
        }
    }

    [RelayCommand]
    private void ViewAllConversations()
    {
        try
        {
            PopupTitle = "Top 30 Network Conversations - Detailed View";
            PopupSubtitle = $"Showing top 30 conversations";

            if (_currentStatistics?.TopConversations == null || !_currentStatistics.TopConversations.Any())
            {
                ShowError("No conversation data available");
                return;
            }

            var conversations = new ObservableCollection<ConversationViewModel>(
                _currentStatistics.TopConversations.Take(30).Select(c => new ConversationViewModel
                {
                    SourceAddress = c.SourceAddress,
                    SourcePort = c.SourcePort,
                    DestinationAddress = c.DestinationAddress,
                    DestinationPort = c.DestinationPort,
                    SourceDisplay = $"{c.SourceAddress}:{c.SourcePort}",
                    DestinationDisplay = $"{c.DestinationAddress}:{c.DestinationPort}",
                    Protocol = c.Protocol,
                    PacketCount = c.PacketCount,
                    ByteCount = c.ByteCount,
                    Duration = c.Duration,
                    DurationFormatted = Helpers.TimeFormatter.FormatAsSeconds(c.Duration),
                    Percentage = _currentStatistics.TotalPackets > 0 ? (double)c.PacketCount / _currentStatistics.TotalPackets * 100 : 0,
                    BytesFormatted = NumberFormatter.FormatBytes(c.ByteCount)
                })
            );

            var tableViewModel = new PopupTableViewModel("conversations", conversations);
            var tableView = new Controls.PopupTableView
            {
                DataContext = tableViewModel
            };
            PopupContent = tableView;

            HasPopupActions = true;
            CanExportPopupData = true;
            CanRefreshPopupData = true;
            IsPopupVisible = true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error showing conversations popup: {ex.Message}");
            ShowError("Error loading conversation data.");
        }
    }

    [RelayCommand]
    private void ViewAllServices()
    {
        try
        {
            PopupTitle = "Top 30 Service Statistics - Detailed View";
            PopupSubtitle = $"Analyzing {_currentStatistics?.ProtocolStats.Count ?? 0} protocols";

            if (_currentStatistics?.ServiceStats == null || !_currentStatistics.ServiceStats.Any())
            {
                ShowError("No service data available");
                return;
            }

            var services = new ObservableCollection<ServiceViewModel>(
                _currentStatistics.ServiceStats.Values.Take(30).Select(s => new ServiceViewModel
                {
                    ServiceName = s.ServiceName,
                    Port = s.Port,
                    Protocol = s.Protocol,
                    PacketCount = s.PacketCount,
                    ByteCount = s.ByteCount,
                    UniqueHostCount = s.UniqueHosts?.Count ?? 0,
                    IsEncrypted = s.IsEncrypted
                })
            );

            var tableViewModel = new PopupTableViewModel("services", services);
            var tableView = new Controls.PopupTableView
            {
                DataContext = tableViewModel
            };
            PopupContent = tableView;

            HasPopupActions = true;
            CanExportPopupData = true;
            CanRefreshPopupData = true;
            IsPopupVisible = true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error showing services popup: {ex.Message}");
            ShowError("Error loading service data.");
        }
    }

    // ==================== POPUP COMMANDS - CHARTS ====================

    [RelayCommand]
    private void ShowChartPopup(string? chartType)
    {
        try
        {
            if (string.IsNullOrEmpty(chartType))
            {
                System.Diagnostics.Debug.WriteLine("ShowChartPopup called with null or empty chartType");
                return;
            }

            // Ensure we're on UI thread
            if (!Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
            {
                Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => ShowChartPopup(chartType));
                return;
            }

            // Chart popup logic would be implemented here
            // For now, show a placeholder
            PopupTitle = $"{chartType.ToUpper()} Chart - Interactive View";
            PopupSubtitle = "Chart visualization";

            PopupContent = CreateErrorMessage($"Chart popup for {chartType} would be displayed here");

            HasPopupActions = true;
            CanExportPopupData = true;
            CanRefreshPopupData = false;
            IsPopupVisible = true;
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Error showing chart popup: {ex.Message}");
            ShowError("Error loading chart.");
        }
    }

    // ==================== POPUP ACTIONS ====================

    [RelayCommand]
    private void ClosePopup()
    {
        IsPopupVisible = false;
        PopupContent = null;
    }

    [RelayCommand]
    private void ExportPopupData()
    {
        // Export functionality would be implemented here
        System.Diagnostics.Debug.WriteLine("Export popup data requested");
    }

    [RelayCommand]
    private void RefreshPopupData()
    {
        // Refresh functionality would be implemented here
        System.Diagnostics.Debug.WriteLine("Refresh popup data requested");
    }

    // ==================== DETAIL WINDOWS ====================

    /// <summary>
    /// Shows IP address details in a separate window.
    /// </summary>
    [RelayCommand]
    private async Task ShowIPDetails(object? parameter)
    {
        if (!Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
        {
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(async () => await ShowIPDetails(parameter));
            return;
        }

        if (parameter is EndpointViewModel endpoint && _currentPackets != null)
        {
            var viewModel = new IPDetailsViewModel(endpoint, _currentPackets, isSource: true);
            var window = new Views.IPDetailsWindow
            {
                DataContext = viewModel
            };

            if (Avalonia.Application.Current?.ApplicationLifetime is
                Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop &&
                desktop.MainWindow != null)
            {
                await window.ShowDialog(desktop.MainWindow);
            }
        }
    }

    /// <summary>
    /// Shows port details in a separate window.
    /// </summary>
    [RelayCommand]
    private async Task ShowPortDetails(object? parameter)
    {
        DebugLogger.Log($"[DashboardPopupViewModel] ShowPortDetails called with parameter: {parameter?.GetType().Name ?? "null"}");

        if (!Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
        {
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(async () => await ShowPortDetails(parameter));
            return;
        }

        if (parameter is PCAPAnalyzer.UI.ViewModels.TopPortViewModel portInfo && _currentPackets != null)
        {
            DebugLogger.Log($"[DashboardPopupViewModel] Opening PortDetailsWindow for port {portInfo.DisplayName}");
            var viewModel = new PortDetailsViewModel(portInfo, _currentPackets);
            var window = new Views.PortDetailsWindow
            {
                DataContext = viewModel
            };

            if (Avalonia.Application.Current?.ApplicationLifetime is
                Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop &&
                desktop.MainWindow != null)
            {
                await window.ShowDialog(desktop.MainWindow);
            }
        }
    }

    /// <summary>
    /// Shows connection/conversation details in a separate window.
    /// Populates Dashboard filters before opening the window.
    /// </summary>
    [RelayCommand]
    private async Task ShowConnectionDetails(object? parameter)
    {
        DebugLogger.Log($"[DashboardPopupViewModel] ShowConnectionDetails called");

        if (!Avalonia.Threading.Dispatcher.UIThread.CheckAccess())
        {
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(async () => await ShowConnectionDetails(parameter));
            return;
        }

        if (parameter is ConversationViewModel conversation && _currentPackets != null)
        {
            // Populate Dashboard filters before opening details window (Quick Win!)
            _parentViewModel?.FilterByConnectionCommand.Execute(conversation);

            var connectionPackets = _currentPackets.Where(p =>
                (p.SourceIP == conversation.SourceAddress && p.SourcePort == conversation.SourcePort &&
                 p.DestinationIP == conversation.DestinationAddress && p.DestinationPort == conversation.DestinationPort) ||
                (p.DestinationIP == conversation.SourceAddress && p.DestinationPort == conversation.SourcePort &&
                 p.SourceIP == conversation.DestinationAddress && p.SourcePort == conversation.DestinationPort)
            ).ToList();

            var viewModel = new PacketDetailViewModel(
                $"Connection: {conversation.SourceDisplay} → {conversation.DestinationDisplay}",
                connectionPackets,
                filterPredicate: _ => true,
                $"All packets for connection {conversation.Protocol}"
            );

            var window = new Views.PacketDetailWindow
            {
                DataContext = viewModel
            };

            if (Avalonia.Application.Current?.ApplicationLifetime is
                Avalonia.Controls.ApplicationLifetimes.IClassicDesktopStyleApplicationLifetime desktop &&
                desktop.MainWindow != null)
            {
                await window.ShowDialog(desktop.MainWindow);
            }
        }
    }

    // ==================== HELPER METHODS ====================

    private object CreateErrorMessage(string message)
    {
        var panel = new StackPanel
        {
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            Spacing = 10
        };

        var textBlock = new TextBlock
        {
            Text = message,
            HorizontalAlignment = HorizontalAlignment.Center,
            FontSize = 16,
            Foreground = new Avalonia.Media.SolidColorBrush(Avalonia.Media.Colors.Gray)
        };

        panel.Children.Add(textBlock);
        return panel;
    }

    private void ShowError(string message)
    {
        PopupContent = CreateErrorMessage(message);
        HasPopupActions = false;
        CanExportPopupData = false;
        CanRefreshPopupData = false;
        IsPopupVisible = true;
    }
}

/// <summary>
/// ViewModel for popup table views.
/// </summary>
public class PopupTableViewModel
{
    public string TableType { get; }
    public object Data { get; }

    public PopupTableViewModel(string tableType, object data)
    {
        TableType = tableType;
        Data = data;
    }
}
