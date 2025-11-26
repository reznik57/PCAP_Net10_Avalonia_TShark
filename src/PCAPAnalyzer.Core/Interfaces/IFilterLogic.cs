using System;
using System.Collections.Generic;
using System.ComponentModel;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Core filter service component that can be composed into filter services.
    /// Eliminates duplication between GlobalFilterService and TabFilterService.
    /// Named "FilterServiceCore" to avoid collision with PCAPAnalyzer.UI.Models.FilterLogic enum.
    /// </summary>
    public interface IFilterServiceCore : INotifyPropertyChanged
    {
        /// <summary>
        /// Current active filter
        /// </summary>
        PacketFilter CurrentFilter { get; }

        /// <summary>
        /// Whether a filter is currently active
        /// </summary>
        bool IsFilterActive { get; }

        /// <summary>
        /// Human-readable description of current filter
        /// </summary>
        string FilterDescription { get; }

        /// <summary>
        /// Available preset filters
        /// </summary>
        IReadOnlyDictionary<string, PacketFilter> PresetFilters { get; }

        /// <summary>
        /// Event fired when filter changes
        /// </summary>
        event EventHandler<FilterChangedEventArgs>? FilterChanged;

        /// <summary>
        /// Apply a filter
        /// </summary>
        void ApplyFilter(PacketFilter filter);

        /// <summary>
        /// Clear the current filter
        /// </summary>
        void ClearFilter();

        /// <summary>
        /// Get filtered packets based on current filter
        /// </summary>
        IEnumerable<PacketInfo> GetFilteredPackets(IEnumerable<PacketInfo> allPackets);

        /// <summary>
        /// Calculate filter statistics
        /// </summary>
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
}
