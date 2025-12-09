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
using PCAPAnalyzer.UI.ViewModels.Components;
using ReactiveUI;

namespace PCAPAnalyzer.UI.ViewModels
{
    public class IPDetailsViewModel : ReactiveObject, IDisposable
    {
        private readonly EndpointViewModel _endpoint;
        private readonly CompositeDisposable _disposables = new();
        private bool _disposed;
        private string _filterText = "";
        private string _selectedProtocol = "All";
        private string _selectedDirection = "All";
        private ObservableCollection<IPPacketDetail> _allPackets = [];
        private ObservableCollection<IPPacketDetail> _filteredPackets = [];

        // Cached direction counts (computed once in LoadPackets instead of per-access)
        private int _incomingPacketsCount;
        private int _outgoingPacketsCount;
        
        public IPDetailsViewModel(EndpointViewModel endpoint, IEnumerable<PacketInfo> packets, bool isSource)
        {
            _endpoint = endpoint;
            
            // Initialize properties
            IPAddress = endpoint.Address;
            IPType = isSource ? "Source" : "Destination";
            TotalPackets = endpoint.PacketCount;
            TotalBytes = endpoint.ByteCount;
            FormattedBytes = endpoint.BytesFormatted;
            WindowTitle = $"IP Details - {endpoint.Address} ({IPType})";
            
            // Load packet data
            LoadPackets(packets, isSource);
            
            // Initialize filter lists
            Protocols = new ObservableCollection<string> { "All" };
            var uniqueProtocols = _allPackets.Select(p => p.Protocol).Distinct().OrderBy(p => p);
            foreach (var protocol in uniqueProtocols)
            {
                Protocols.Add(protocol);
            }
            
            Directions = new ObservableCollection<string> { "All", "Incoming", "Outgoing" };
            
            // Set up filtering (subscribe and track for disposal)
            this.WhenAnyValue(x => x.FilterText, x => x.SelectedProtocol, x => x.SelectedDirection)
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
        public string IPAddress { get; }
        public string IPType { get; }
        public long TotalPackets { get; }
        public long TotalBytes { get; }
        public string FormattedBytes { get; }
        public int UniqueConnections => _allPackets.Select(p => p.RemoteIP).Distinct().Count();
        
        public string FilterText
        {
            get => _filterText;
            set => this.RaiseAndSetIfChanged(ref _filterText, value);
        }
        
        public string SelectedProtocol
        {
            get => _selectedProtocol;
            set => this.RaiseAndSetIfChanged(ref _selectedProtocol, value);
        }
        
        public string SelectedDirection
        {
            get => _selectedDirection;
            set => this.RaiseAndSetIfChanged(ref _selectedDirection, value);
        }
        
        public ObservableCollection<string> Protocols { get; } = [];
        public ObservableCollection<string> Directions { get; } = [];
        
        public ObservableCollection<IPPacketDetail> FilteredPackets
        {
            get => _filteredPackets;
            set => this.RaiseAndSetIfChanged(ref _filteredPackets, value);
        }
        
        public int FilteredCount => FilteredPackets?.Count ?? 0;
        public int TotalCount => _allPackets?.Count ?? 0;
        // Use cached counts (calculated once in LoadPackets instead of per-access Count())
        public int IncomingPackets => _incomingPacketsCount;
        public int OutgoingPackets => _outgoingPacketsCount;
        
        // Commands
        public ICommand ExportCommand { get; }
        
        // Methods
        private void LoadPackets(IEnumerable<PacketInfo> packets, bool isSource)
        {
            var packetDetails = new List<IPPacketDetail>();
            int incoming = 0, outgoing = 0;

            foreach (var packet in packets)
            {
                // Check if packet involves this IP
                bool isRelevant = isSource ?
                    packet.SourceIP == IPAddress :
                    packet.DestinationIP == IPAddress;

                if (isRelevant)
                {
                    var direction = packet.SourceIP == IPAddress ? "Outgoing" : "Incoming";
                    var remoteIP = packet.SourceIP == IPAddress ? packet.DestinationIP : packet.SourceIP;
                    var localPort = packet.SourceIP == IPAddress ? packet.SourcePort : packet.DestinationPort;
                    var remotePort = packet.SourceIP == IPAddress ? packet.DestinationPort : packet.SourcePort;

                    // Count directions during load (instead of per-access Count())
                    if (direction == "Incoming") incoming++; else outgoing++;

                    packetDetails.Add(new IPPacketDetail
                    {
                        PacketNumber = (int)packet.FrameNumber,
                        Timestamp = packet.Timestamp,
                        Direction = direction,
                        RemoteIP = remoteIP,
                        LocalPort = localPort,
                        RemotePort = remotePort,
                        Protocol = packet.GetProtocolDisplay(),
                        Length = packet.Length,
                        Info = packet.Info ?? $"{packet.GetProtocolDisplay()} packet"
                    });
                }
            }

            _allPackets = new ObservableCollection<IPPacketDetail>(
                packetDetails.OrderBy(p => p.PacketNumber)
            );
            _incomingPacketsCount = incoming;
            _outgoingPacketsCount = outgoing;
        }
        
        private void ApplyFilter()
        {
            var filtered = _allPackets.AsEnumerable();
            
            // Apply protocol filter
            if (!string.IsNullOrEmpty(SelectedProtocol) && SelectedProtocol != "All")
            {
                filtered = filtered.Where(p => p.Protocol == SelectedProtocol);
            }
            
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
                    p.RemoteIP.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ||
                    p.LocalPort.ToString().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ||
                    p.RemotePort.ToString().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ||
                    p.Protocol.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ||
                    (p.Info?.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ?? false)
                );
            }
            
            FilteredPackets = new ObservableCollection<IPPacketDetail>(filtered);
            
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

    public class IPPacketDetail
    {
        public int PacketNumber { get; set; }
        public DateTime Timestamp { get; set; }
        public string Direction { get; set; } = "";
        public string RemoteIP { get; set; } = "";
        public int LocalPort { get; set; }
        public int RemotePort { get; set; }
        public string Protocol { get; set; } = "";
        public int Length { get; set; }
        public string? Info { get; set; }
    }
}