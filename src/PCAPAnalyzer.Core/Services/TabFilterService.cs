using System;
using System.Collections.Generic;
using System.ComponentModel;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Tab-specific filter service using composition with FilterServiceCore.
    /// Each tab instance maintains its own filter state independently via its own FilterServiceCore instance.
    /// </summary>
    public class TabFilterService : ITabFilterService
    {
        private readonly IFilterServiceCore _filterLogic;

        public string TabName { get; }

        public TabFilterService(string tabName, IFilterServiceCore filterLogic)
        {
            TabName = tabName ?? throw new ArgumentNullException(nameof(tabName));
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

        /// <summary>
        /// Copy filter from another tab (replaces current filter).
        /// Tab-specific method not in FilterLogic.
        /// </summary>
        public void CopyFilterFrom(ITabFilterService sourceTab)
        {
            if (sourceTab is null)
                throw new ArgumentNullException(nameof(sourceTab));

            DebugLogger.Log($"[{TabName}] Copying filter from [{sourceTab.TabName}]");
            ApplyFilter(sourceTab.CurrentFilter);
        }

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
}
