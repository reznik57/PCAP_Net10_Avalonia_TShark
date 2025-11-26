using System;
using System.Collections.Generic;
using System.ComponentModel;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Tab-specific filter service interface.
    /// Each tab gets its own instance - filters are isolated to individual tabs.
    /// </summary>
    public interface ITabFilterService : INotifyPropertyChanged
    {
        /// <summary>
        /// Name of the tab this filter service belongs to (for debugging/logging)
        /// </summary>
        string TabName { get; }

        /// <summary>
        /// Current active filter for this tab
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
        /// Event fired when filter changes (tab-local, not global)
        /// </summary>
        event EventHandler<FilterChangedEventArgs> FilterChanged;

        /// <summary>
        /// Apply a filter to this tab
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
        /// Calculate filter statistics for this tab
        /// </summary>
        FilterStatistics GetFilterStatistics(IEnumerable<PacketInfo> allPackets);

        /// <summary>
        /// Copy filter from another tab (replaces current filter)
        /// </summary>
        void CopyFilterFrom(ITabFilterService sourceTab);

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
