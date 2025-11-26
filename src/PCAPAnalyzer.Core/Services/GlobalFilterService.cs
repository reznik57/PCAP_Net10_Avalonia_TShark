using System;
using System.Collections.Generic;
using System.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services
{
    public interface IGlobalFilterService : INotifyPropertyChanged
    {
        PacketFilter CurrentFilter { get; }
        bool IsFilterActive { get; }
        string FilterDescription { get; }
        event EventHandler<FilterChangedEventArgs> FilterChanged;

        void ApplyFilter(PacketFilter filter);
        void ClearFilter();
        IEnumerable<PacketInfo> GetFilteredPackets(IEnumerable<PacketInfo> allPackets);
        FilterStatistics GetFilterStatistics(IEnumerable<PacketInfo> allPackets);

        // Quick filter methods
        void ApplyProtocolFilter(Protocol protocol);
        void ApplyPortFilter(int port);
        void ApplyIPFilter(string ipAddress);
        void ApplyAnomalyFilter();
        void ApplySecurityFilter(string filterType);

        // Predefined filter methods
        void ApplyRFC1918Filter();
        void ApplyPublicIPFilter();
        void ApplyMulticastFilter();
        void ApplyBroadcastFilter();
        void ApplyAnycastFilter();
        void ApplyInsecureProtocolsFilter();
        void ApplyIPv4Filter();
        void ApplyIPv6Filter();
        void ApplyCustomFilter(Func<PacketInfo, bool> predicate, string description);
        Dictionary<string, Action> GetPredefinedFilters();
    }

    /// <summary>
    /// Global filter service using composition with FilterServiceCore.
    /// Delegates all filter operations to the composed FilterServiceCore component.
    /// </summary>
    public class GlobalFilterService : IGlobalFilterService
    {
        private readonly IFilterServiceCore _filterLogic;

        public GlobalFilterService(IFilterServiceCore filterLogic)
        {
            _filterLogic = filterLogic ?? throw new ArgumentNullException(nameof(filterLogic));

            // Forward events from FilterLogic
            _filterLogic.FilterChanged += (s, e) => FilterChanged?.Invoke(this, e);
            _filterLogic.PropertyChanged += (s, e) => PropertyChanged?.Invoke(this, e);
        }

        // Delegate all properties to FilterLogic
        public PacketFilter CurrentFilter => _filterLogic.CurrentFilter;
        public bool IsFilterActive => _filterLogic.IsFilterActive;
        public string FilterDescription => _filterLogic.FilterDescription;

        public event EventHandler<FilterChangedEventArgs>? FilterChanged;
        public event PropertyChangedEventHandler? PropertyChanged;

        // Delegate all methods to FilterLogic
        public void ApplyFilter(PacketFilter filter) => _filterLogic.ApplyFilter(filter);
        public void ClearFilter() => _filterLogic.ClearFilter();
        public IEnumerable<PacketInfo> GetFilteredPackets(IEnumerable<PacketInfo> allPackets)
            => _filterLogic.GetFilteredPackets(allPackets);
        public FilterStatistics GetFilterStatistics(IEnumerable<PacketInfo> allPackets)
            => _filterLogic.GetFilterStatistics(allPackets);

        // Quick filter methods
        public void ApplyProtocolFilter(Protocol protocol) => _filterLogic.ApplyProtocolFilter(protocol);
        public void ApplyPortFilter(int port) => _filterLogic.ApplyPortFilter(port);
        public void ApplyIPFilter(string ipAddress) => _filterLogic.ApplyIPFilter(ipAddress);
        public void ApplyAnomalyFilter() => _filterLogic.ApplyAnomalyFilter();
        public void ApplySecurityFilter(string filterType) => _filterLogic.ApplySecurityFilter(filterType);

        // Predefined filter methods
        public void ApplyRFC1918Filter() => _filterLogic.ApplyRFC1918Filter();
        public void ApplyPublicIPFilter() => _filterLogic.ApplyPublicIPFilter();
        public void ApplyMulticastFilter() => _filterLogic.ApplyMulticastFilter();
        public void ApplyBroadcastFilter() => _filterLogic.ApplyBroadcastFilter();
        public void ApplyAnycastFilter() => _filterLogic.ApplyAnycastFilter();
        public void ApplyInsecureProtocolsFilter() => _filterLogic.ApplyInsecureProtocolsFilter();
        public void ApplyIPv4Filter() => _filterLogic.ApplyIPv4Filter();
        public void ApplyIPv6Filter() => _filterLogic.ApplyIPv6Filter();
        public void ApplyCustomFilter(Func<PacketInfo, bool> predicate, string description)
            => _filterLogic.ApplyCustomFilter(predicate, description);
        public Dictionary<string, Action> GetPredefinedFilters() => _filterLogic.GetPredefinedFilters();
    }

    public class FilterChangedEventArgs : EventArgs
    {
        public PacketFilter Filter { get; }
        public FilterAction Action { get; }
        public DateTime Timestamp { get; }

        public FilterChangedEventArgs(PacketFilter filter, FilterAction action)
        {
            Filter = filter;
            Action = action;
            Timestamp = DateTime.Now;
        }
    }

    public enum FilterAction
    {
        Applied,
        Cleared,
        Modified
    }

    public class FilterStatistics
    {
        public long TotalPackets { get; set; }
        public long FilteredPackets { get; set; }
        public long TotalBytes { get; set; }
        public long FilteredBytes { get; set; }
        public double FilterEfficiency { get; set; }
        public int TotalProtocols { get; set; }
        public int FilteredProtocols { get; set; }
        public int TotalUniqueIPs { get; set; }
        public int FilteredUniqueIPs { get; set; }

        public string TotalBytesFormatted => NumberFormatter.FormatBytes(TotalBytes);
        public string FilteredBytesFormatted => NumberFormatter.FormatBytes(FilteredBytes);
        public string EfficiencyPercentage => $"{FilterEfficiency * 100:F1}%";
    }
}
