using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reactive;
using System.Reactive.Disposables;
using System.Reactive.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using DynamicData;
using DynamicData.Binding;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;
using ReactiveUI;

namespace PCAPAnalyzer.UI.ViewModels
{
    public class PortDetailsViewModel : ReactiveObject, IDisposable
    {
        private readonly TopPortViewModel _portInfo;
        private readonly CompositeDisposable _disposables = new();
        private bool _disposed;
        private string _filterText = "";
        private string _selectedDirection = "All";
        private ObservableCollection<PortPacketDetail> _allPackets = [];
        private ObservableCollection<PortPacketDetail> _filteredPackets = [];

        // Cached direction counts (computed once in LoadPackets instead of per-access)
        private int _sourcePortPacketsCount;
        private int _destinationPortPacketsCount;
        
        public PortDetailsViewModel(TopPortViewModel portInfo, IEnumerable<PacketInfo> packets)
        {
            _portInfo = portInfo;
            
            // Initialize properties
            Port = portInfo.Port;
            Protocol = portInfo.Protocol;
            ServiceName = portInfo.ServiceName ?? $"Port {portInfo.Port}";
            TotalPackets = portInfo.PacketCount;
            TotalBytes = portInfo.ByteCount;
            FormattedBytes = NumberFormatter.FormatBytes(portInfo.ByteCount);
            WindowTitle = $"Port Details - {ServiceName} ({Port}/{Protocol})";
            
            // Load packet data
            LoadPackets(packets);
            
            // Initialize filter lists
            Directions = new ObservableCollection<string> { "All", "Source", "Destination" };
            
            // Set up filtering (subscribe and track for disposal)
            this.WhenAnyValue(x => x.FilterText, x => x.SelectedDirection)
                .Throttle(TimeSpan.FromMilliseconds(300))
                .Subscribe(_ => ApplyFilter())
                .DisposeWith(_disposables);
            
            // Initialize commands
            ExportCommand = ReactiveCommand.CreateFromTask(ExportData);
            
            // Apply initial filter
            ApplyFilter();
        }
        
        // Properties
        public string WindowTitle { get; }
        public int Port { get; }
        public string Protocol { get; }
        public string ServiceName { get; }
        public long TotalPackets { get; }
        public long TotalBytes { get; }
        public string FormattedBytes { get; }
        public int UniqueIPs => _allPackets.Select(p => p.SourceIP).Union(_allPackets.Select(p => p.DestinationIP)).Distinct().Count();
        
        public string FilterText
        {
            get => _filterText;
            set => this.RaiseAndSetIfChanged(ref _filterText, value);
        }
        
        public string SelectedDirection
        {
            get => _selectedDirection;
            set => this.RaiseAndSetIfChanged(ref _selectedDirection, value);
        }
        
        public ObservableCollection<string> Directions { get; } = [];
        
        public ObservableCollection<PortPacketDetail> FilteredPackets
        {
            get => _filteredPackets;
            set => this.RaiseAndSetIfChanged(ref _filteredPackets, value);
        }
        
        public int FilteredCount => FilteredPackets?.Count ?? 0;
        public int TotalCount => _allPackets?.Count ?? 0;
        // Use cached counts (calculated once in LoadPackets instead of per-access Count())
        public int SourcePortPackets => _sourcePortPacketsCount;
        public int DestinationPortPackets => _destinationPortPacketsCount;
        
        // Commands
        public ICommand ExportCommand { get; }
        
        // Methods
        private void LoadPackets(IEnumerable<PacketInfo> packets)
        {
            var packetDetails = new List<PortPacketDetail>();
            int sourceCount = 0, destCount = 0;

            foreach (var packet in packets)
            {
                // Check if packet uses this port
                bool isSourcePort = packet.SourcePort == Port;
                bool isDestPort = packet.DestinationPort == Port;

                if ((isSourcePort || isDestPort) && packet.GetProtocolDisplay().Contains(Protocol, StringComparison.OrdinalIgnoreCase))
                {
                    var direction = isSourcePort ? "Source" : "Destination";

                    // Count directions during load (instead of per-access Count())
                    if (isSourcePort) sourceCount++; else destCount++;

                    packetDetails.Add(new PortPacketDetail
                    {
                        PacketNumber = (int)packet.FrameNumber,
                        Timestamp = packet.Timestamp,
                        SourceIP = packet.SourceIP,
                        SourcePort = packet.SourcePort,
                        DestinationIP = packet.DestinationIP,
                        DestinationPort = packet.DestinationPort,
                        Direction = direction,
                        Length = packet.Length,
                        Info = packet.Info ?? $"{packet.GetProtocolDisplay()} packet"
                    });
                }
            }

            _allPackets = new ObservableCollection<PortPacketDetail>(
                packetDetails.OrderBy(p => p.PacketNumber)
            );
            _sourcePortPacketsCount = sourceCount;
            _destinationPortPacketsCount = destCount;
        }
        
        private void ApplyFilter()
        {
            var filtered = _allPackets.AsEnumerable();
            
            // Apply direction filter
            if (!string.IsNullOrEmpty(SelectedDirection) && SelectedDirection != "All")
            {
                filtered = filtered.Where(p => p.Direction == SelectedDirection);
            }
            
            // Apply text filter
            if (!string.IsNullOrWhiteSpace(FilterText))
            {
                var searchText = FilterText.ToLower();
                filtered = filtered.Where(p =>
                    p.SourceIP.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ||
                    p.DestinationIP.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ||
                    (p.Info?.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ?? false)
                );
            }
            
            FilteredPackets = new ObservableCollection<PortPacketDetail>(filtered);
            
            // Notify property changes for counts
            this.RaisePropertyChanged(nameof(FilteredCount));
        }
        
        private async Task ExportData()
        {
            // Export functionality
            await Task.Delay(100); // Placeholder
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            _disposables.Dispose();
        }
    }

    public class PortPacketDetail
    {
        public int PacketNumber { get; set; }
        public DateTime Timestamp { get; set; }
        public string SourceIP { get; set; } = "";
        public int SourcePort { get; set; }
        public string DestinationIP { get; set; } = "";
        public int DestinationPort { get; set; }
        public string Direction { get; set; } = "";
        public int Length { get; set; }
        public string? Info { get; set; }
    }
}