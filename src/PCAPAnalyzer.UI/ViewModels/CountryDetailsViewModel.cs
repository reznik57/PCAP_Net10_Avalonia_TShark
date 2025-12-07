using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reactive;
using System.Reactive.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using DynamicData;
using DynamicData.Binding;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.Core.Utilities;
using ReactiveUI;

namespace PCAPAnalyzer.UI.ViewModels
{
    public class CountryDetailsViewModel : ReactiveObject
    {
        private readonly CountryTableItem _countryItem;
        private readonly CountryTableContext _context;
        private string _filterText = "";
        private string _selectedProtocol = "All";
        private bool _useNotFilter;
        private ObservableCollection<CountryPacketDetail> _allPackets = [];
        private ObservableCollection<CountryPacketDetail> _filteredPackets = [];
        private readonly string _countryCode;
        private long _actualIncomingPackets;
        private long _actualOutgoingPackets;
        private readonly string? _contextDetail;

        public CountryDetailsViewModel(CountryTableItem countryItem, IEnumerable<PacketInfo> packets,
            long incomingPackets = 0, long outgoingPackets = 0, string? contextDetail = null)
        {
            _countryItem = countryItem;
            _context = countryItem.Context;
            _countryCode = countryItem.CountryCode;
            _actualIncomingPackets = incomingPackets;
            _actualOutgoingPackets = outgoingPackets;
            _contextDetail = contextDetail;

            // Initialize properties
            CountryCode = countryItem.CountryCode;
            CountryName = countryItem.CountryName;
            // Use the actual total from statistics if provided, otherwise use the passed values
            TotalPackets = (incomingPackets + outgoingPackets) > 0 ? incomingPackets + outgoingPackets : countryItem.TotalPackets;
            TotalBytes = countryItem.TotalBytes;
            FormattedBytes = NumberFormatter.FormatBytes(countryItem.TotalBytes);
            ContextLabel = GetContextLabel(_context);
            DisplayCountryName = GetDisplayCountryName(countryItem.CountryName, _context, _contextDetail);
            WindowTitle = _context == CountryTableContext.CrossBorderFlow && !string.IsNullOrWhiteSpace(_contextDetail)
                ? $"{ContextLabel}: {_contextDetail}"
                : $"{ContextLabel}: {countryItem.CountryName} ({countryItem.CountryCode})";
            
            // Load packet data
            LoadPackets(packets);
            
            // Initialize protocol list
            Protocols = new ObservableCollection<string> { "All" };
            var uniqueProtocols = _allPackets.Select(p => p.Protocol).Distinct().OrderBy(p => p);
            foreach (var protocol in uniqueProtocols)
            {
                Protocols.Add(protocol);
            }
            
            // Set up filtering
            this.WhenAnyValue(x => x.FilterText, x => x.SelectedProtocol, x => x.UseNotFilter)
                .Throttle(TimeSpan.FromMilliseconds(300))
                .Subscribe(_ => ApplyFilter());
            
            // Initialize commands
            ExportCommand = ReactiveCommand.CreateFromTask(ExportData);
            
            // Apply initial filter
            ApplyFilter();
        }
        
        // Properties
        public string WindowTitle { get; }
        public string CountryCode { get; }
        public string CountryName { get; }
        public string DisplayCountryName { get; }
        public string ContextLabel { get; }
        public CountryTableContext Context => _context;
        public long TotalPackets { get; }
        public long TotalBytes { get; }
        public string FormattedBytes { get; }
        public int UniqueIPs => _allPackets.Select(p => p.SourceIP).Union(_allPackets.Select(p => p.DestinationIP)).Distinct().Count();
        
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
        
        public bool UseNotFilter
        {
            get => _useNotFilter;
            set => this.RaiseAndSetIfChanged(ref _useNotFilter, value);
        }
        
        public ObservableCollection<string> Protocols { get; } = [];
        
        public ObservableCollection<CountryPacketDetail> FilteredPackets
        {
            get => _filteredPackets;
            set => this.RaiseAndSetIfChanged(ref _filteredPackets, value);
        }
        
        public int FilteredCount => FilteredPackets?.Count ?? 0;
        public int TotalCount => _allPackets?.Count ?? 0;
        public long IncomingPackets => _actualIncomingPackets;
        public long OutgoingPackets => _actualOutgoingPackets;
        
        // Commands
        public ICommand ExportCommand { get; }
        
        // Methods
        private void LoadPackets(IEnumerable<PacketInfo> packets)
        {
            var packetDetails = new List<CountryPacketDetail>();
            
            // The packets passed in are already filtered for this country
            // by the CountryTrafficViewModel using cached indices
            foreach (var packet in packets)
            {
                packetDetails.Add(new CountryPacketDetail
                {
                    PacketNumber = (int)packet.FrameNumber,
                    Timestamp = packet.Timestamp,
                    SourceIP = packet.SourceIP,
                    SourcePort = packet.SourcePort,
                    DestinationIP = packet.DestinationIP,
                    DestinationPort = packet.DestinationPort,
                    Protocol = packet.GetProtocolDisplay(),
                    Length = packet.Length,
                    Info = packet.Info ?? $"{packet.GetProtocolDisplay()} packet"
                });
            }
            
            _allPackets = new ObservableCollection<CountryPacketDetail>(
                packetDetails.OrderBy(p => p.PacketNumber)
            );
            
            DebugLogger.Log($"[CountryDetailsViewModel] Loaded {_allPackets.Count} packets for {CountryName}");
        }
        
        // Removed IsPacketForCountry - packets are already filtered by CountryTrafficViewModel
        
        private bool IsIncoming(CountryPacketDetail packet)
        {
            // Check if destination is in this country
            // This is simplified - real implementation would check against GeoIP
            return packet.DestinationIP.StartsWith("192.168", StringComparison.Ordinal) || 
                   packet.DestinationIP.StartsWith("10.", StringComparison.Ordinal) ||
                   packet.DestinationIP.StartsWith("172.", StringComparison.Ordinal);
        }
        
        private void ApplyFilter()
        {
            var filtered = _allPackets.AsEnumerable();
            
            // Apply protocol filter
            if (!string.IsNullOrEmpty(SelectedProtocol) && SelectedProtocol != "All")
            {
                filtered = filtered.Where(p => p.Protocol == SelectedProtocol);
            }
            
            // Apply text filter
            if (!string.IsNullOrWhiteSpace(FilterText))
            {
                var searchText = FilterText.ToLower();
                
                if (UseNotFilter)
                {
                    // NOT filter - exclude matches
                    filtered = filtered.Where(p =>
                        !p.SourceIP.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) &&
                        !p.DestinationIP.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) &&
                        !p.SourcePort.ToString().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) &&
                        !p.DestinationPort.ToString().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) &&
                        !p.Protocol.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) &&
                        !(p.Info?.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ?? false)
                    );
                }
                else
                {
                    // Normal filter - include matches
                    filtered = filtered.Where(p =>
                        p.SourceIP.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ||
                        p.DestinationIP.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ||
                        p.SourcePort.ToString().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ||
                        p.DestinationPort.ToString().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ||
                        p.Protocol.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ||
                        (p.Info?.ToLower().Contains(searchText, StringComparison.CurrentCultureIgnoreCase) ?? false)
                    );
                }
            }
            
            FilteredPackets = new ObservableCollection<CountryPacketDetail>(filtered);
            
            // Notify property changes for counts
            this.RaisePropertyChanged(nameof(FilteredCount));
        }
        
        private async Task ExportData()
        {
            // Export functionality
            await Task.Delay(100); // Placeholder
        }

        private static string GetContextLabel(CountryTableContext context)
        {
            return context switch
            {
                CountryTableContext.SourcePackets => "Top Source Country (Packets)",
                CountryTableContext.SourceBytes => "Top Source Country (Bytes)",
                CountryTableContext.DestinationPackets => "Top Destination Country (Packets)",
                CountryTableContext.DestinationBytes => "Top Destination Country (Bytes)",
                CountryTableContext.CrossBorderFlow => "Cross-Border Flow",
                _ => "Country Traffic"
            };
        }

        private static string GetDisplayCountryName(string countryName, CountryTableContext context, string? contextDetail)
        {
            return context switch
            {
                CountryTableContext.SourcePackets or CountryTableContext.SourceBytes => $"Top Source – {countryName}",
                CountryTableContext.DestinationPackets or CountryTableContext.DestinationBytes => $"Top Destination – {countryName}",
                CountryTableContext.CrossBorderFlow => string.IsNullOrWhiteSpace(contextDetail)
                    ? $"Flow – {countryName}"
                    : $"Flow – {contextDetail}",
                _ => countryName
            };
        }
    }

    public class CountryPacketDetail
    {
        public int PacketNumber { get; set; }
        public DateTime Timestamp { get; set; }
        public string SourceIP { get; set; } = "";
        public int SourcePort { get; set; }
        public string DestinationIP { get; set; } = "";
        public int DestinationPort { get; set; }
        public string Protocol { get; set; } = "";
        public int Length { get; set; }
        public string? Info { get; set; }
    }
}