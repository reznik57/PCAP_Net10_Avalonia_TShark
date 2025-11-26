using CommunityToolkit.Mvvm.ComponentModel;

namespace PCAPAnalyzer.UI.ViewModels.Components
{
    /// <summary>
    /// Common filter properties shared across multiple analysis tabs.
    /// These filters can be copied between tabs using the FilterCopyService.
    /// </summary>
    public partial class CommonFilterViewModel : ObservableObject
    {
        /// <summary>
        /// Protocol filter (e.g., "TCP", "UDP", "HTTP", "DNS")
        /// Null or empty means no protocol filtering
        /// </summary>
        [ObservableProperty]
        private string? _protocolFilter;

        /// <summary>
        /// Source IP address filter (supports CIDR notation: "192.168.1.0/24")
        /// Null or empty means no source IP filtering
        /// </summary>
        [ObservableProperty]
        private string? _sourceIPFilter;

        /// <summary>
        /// Destination IP address filter (supports CIDR notation: "10.0.0.0/8")
        /// Null or empty means no destination IP filtering
        /// </summary>
        [ObservableProperty]
        private string? _destinationIPFilter;

        /// <summary>
        /// Check if any filter is currently active
        /// </summary>
        public bool HasActiveFilters =>
            !string.IsNullOrWhiteSpace(ProtocolFilter) ||
            !string.IsNullOrWhiteSpace(SourceIPFilter) ||
            !string.IsNullOrWhiteSpace(DestinationIPFilter);

        /// <summary>
        /// Create a deep copy of this filter configuration
        /// </summary>
        public CommonFilterViewModel Clone()
        {
            return new CommonFilterViewModel
            {
                ProtocolFilter = ProtocolFilter,
                SourceIPFilter = SourceIPFilter,
                DestinationIPFilter = DestinationIPFilter
            };
        }

        /// <summary>
        /// Copy filter values from another CommonFilterViewModel instance
        /// </summary>
        public void CopyFrom(CommonFilterViewModel source)
        {
            if (source == null)
                return;

            ProtocolFilter = source.ProtocolFilter;
            SourceIPFilter = source.SourceIPFilter;
            DestinationIPFilter = source.DestinationIPFilter;
        }

        /// <summary>
        /// Clear all filter values
        /// </summary>
        public void Clear()
        {
            ProtocolFilter = null;
            SourceIPFilter = null;
            DestinationIPFilter = null;
        }

        /// <summary>
        /// Check if filters are empty (no active filtering)
        /// </summary>
        public bool IsEmpty() => !HasActiveFilters;
    }
}
