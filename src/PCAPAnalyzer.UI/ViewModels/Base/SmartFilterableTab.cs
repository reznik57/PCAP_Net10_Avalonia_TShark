using System;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Utilities;
using PCAPAnalyzer.UI.ViewModels.Components;

// Alias to avoid conflict with legacy PCAPAnalyzer.UI.ViewModels.RelayCommand
using ToolkitRelayCommand = CommunityToolkit.Mvvm.Input.RelayCommand;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.ViewModels.Base
{
    /// <summary>
    /// Base class for tab ViewModels with sophisticated INCLUDE/EXCLUDE filtering.
    /// Provides all filter UI state, commands, and logic - eliminates 600 lines of duplication.
    ///
    /// Architecture:
    /// - Each tab instance gets its OWN filter collections (instance properties, not static/shared)
    /// - Filter changes affect ONLY that tab's data (via abstract ApplySmartFilter method)
    /// - Tabs can override GetSmartFilterPresets() to provide tab-specific quick filters
    ///
    /// Benefits:
    /// - Zero code duplication (150 lines × 4 tabs = 600 lines saved)
    /// - Single source of truth for filter UI logic
    /// - Independent per-tab filtering (each tab filters its own data)
    /// - Easy maintenance (fix once, works for all tabs)
    /// </summary>
    public abstract partial class SmartFilterableTab : ObservableObject, IFilterableTab
    {
        // ==================== SERVICES ====================

        /// <summary>
        /// Service for building sophisticated PacketFilters from filter groups/chips.
        /// Shared stateless service (Singleton) used by all tabs.
        /// </summary>
        protected ISmartFilterBuilder FilterBuilder { get; }

        /// <summary>
        /// Unique ID generator for filter chips (ensures unique Remove commands per chip).
        /// Each tab instance has its own counter.
        /// </summary>
        private int _nextFilterChipId = 1;

        // ==================== QUICK FILTER TOGGLES (COMPOSITION) ====================

        /// <summary>
        /// Network-level quick filter toggles - RFC1918, Public, Egress, Insecure, etc.
        /// Available on all tabs for consistent packet-level filtering.
        /// </summary>
        public QuickFilterViewModel NetworkQuickFilters { get; } = new();

        // ==================== WRAPPER PROPERTIES FOR XAML BINDING ====================
        // These delegate to NetworkQuickFilters (SINGLE SOURCE OF TRUTH).
        // FilterPanelControl binds to these names.

        // Network Type Filters
        public bool FilterRfc1918Toggle { get => NetworkQuickFilters.Rfc1918Toggle; set => NetworkQuickFilters.Rfc1918Toggle = value; }
        public bool FilterPublicIpToggle { get => NetworkQuickFilters.PublicIpToggle; set => NetworkQuickFilters.PublicIpToggle = value; }
        public bool FilterApipaToggle { get => NetworkQuickFilters.ApipaToggle; set => NetworkQuickFilters.ApipaToggle = value; }
        public bool FilterIPv4Toggle { get => NetworkQuickFilters.IPv4Toggle; set => NetworkQuickFilters.IPv4Toggle = value; }
        public bool FilterIPv6Toggle { get => NetworkQuickFilters.IPv6Toggle; set => NetworkQuickFilters.IPv6Toggle = value; }
        public bool FilterMulticastToggle { get => NetworkQuickFilters.MulticastToggle; set => NetworkQuickFilters.MulticastToggle = value; }
        public bool FilterBroadcastToggle { get => NetworkQuickFilters.BroadcastToggle; set => NetworkQuickFilters.BroadcastToggle = value; }
        public bool FilterAnycastToggle { get => NetworkQuickFilters.AnycastToggle; set => NetworkQuickFilters.AnycastToggle = value; }

        // Security Filters
        public bool FilterInsecureToggle { get => NetworkQuickFilters.InsecureToggle; set => NetworkQuickFilters.InsecureToggle = value; }
        public bool FilterAnomaliesToggle { get => NetworkQuickFilters.AnomaliesToggle; set => NetworkQuickFilters.AnomaliesToggle = value; }
        public bool FilterSuspiciousToggle { get => NetworkQuickFilters.SuspiciousToggle; set => NetworkQuickFilters.SuspiciousToggle = value; }
        public bool FilterTcpIssuesToggle { get => NetworkQuickFilters.TcpIssuesToggle; set => NetworkQuickFilters.TcpIssuesToggle = value; }
        public bool FilterPortScansToggle { get => NetworkQuickFilters.PortScansToggle; set => NetworkQuickFilters.PortScansToggle = value; }
        public bool FilterDnsAnomaliesToggle { get => NetworkQuickFilters.DnsAnomaliesToggle; set => NetworkQuickFilters.DnsAnomaliesToggle = value; }

        // Traffic Pattern Filters
        public bool FilterPrivateToPublicToggle { get => NetworkQuickFilters.PrivateToPublicToggle; set => NetworkQuickFilters.PrivateToPublicToggle = value; }
        public bool FilterPublicToPrivateToggle { get => NetworkQuickFilters.PublicToPrivateToggle; set => NetworkQuickFilters.PublicToPrivateToggle = value; }
        public bool FilterJumboFramesToggle { get => NetworkQuickFilters.JumboFramesToggle; set => NetworkQuickFilters.JumboFramesToggle = value; }
        public bool FilterLoopbackToggle { get => NetworkQuickFilters.LoopbackToggle; set => NetworkQuickFilters.LoopbackToggle = value; }
        public bool FilterLinkLocalToggle { get => NetworkQuickFilters.LinkLocalToggle; set => NetworkQuickFilters.LinkLocalToggle = value; }
        // Protocol filter placeholders - Dashboard overrides with [ObservableProperty]
        public bool FilterDnsToggle { get; set; }
        public bool FilterHttpToggle { get; set; }
        public bool FilterHttpsToggle { get; set; }
        public bool FilterSshToggle { get; set; }
        public bool FilterSmtpToggle { get; set; }
        public bool FilterFtpToggle { get; set; }
        public bool FilterSnmpToggle { get; set; }
        public bool FilterStunToggle { get; set; }
        public bool FilterDhcpServerToggle { get; set; }

        // TLS version filter placeholders - Dashboard overrides with [ObservableProperty]
        public bool FilterTlsV10Toggle { get; set; }
        public bool FilterTlsV11Toggle { get; set; }
        public bool FilterTlsV12Toggle { get; set; }
        public bool FilterTlsV13Toggle { get; set; }

        // VPN protocol filter placeholders - Dashboard overrides with [ObservableProperty]
        public bool FilterWireGuardToggle { get; set; }
        public bool FilterOpenVpnToggle { get; set; }
        public bool FilterIkeV2Toggle { get; set; }
        public bool FilterIpsecToggle { get; set; }
        public bool FilterL2tpToggle { get; set; }
        public bool FilterPptpToggle { get; set; }

        // TCP Performance wrappers
        public bool FilterRetransmissionsToggle { get => NetworkQuickFilters.RetransmissionsToggle; set => NetworkQuickFilters.RetransmissionsToggle = value; }
        public bool FilterZeroWindowToggle { get => NetworkQuickFilters.ZeroWindowToggle; set => NetworkQuickFilters.ZeroWindowToggle = value; }
        public bool FilterKeepAliveToggle { get => NetworkQuickFilters.KeepAliveToggle; set => NetworkQuickFilters.KeepAliveToggle = value; }
        public bool FilterConnectionRefusedToggle { get => NetworkQuickFilters.ConnectionRefusedToggle; set => NetworkQuickFilters.ConnectionRefusedToggle = value; }
        public bool FilterWindowFullToggle { get => NetworkQuickFilters.WindowFullToggle; set => NetworkQuickFilters.WindowFullToggle = value; }

        // Security Audit wrappers
        public bool FilterCleartextAuthToggle { get => NetworkQuickFilters.CleartextAuthToggle; set => NetworkQuickFilters.CleartextAuthToggle = value; }
        public bool FilterObsoleteCryptoToggle { get => NetworkQuickFilters.ObsoleteCryptoToggle; set => NetworkQuickFilters.ObsoleteCryptoToggle = value; }
        public bool FilterDnsTunnelingToggle { get => NetworkQuickFilters.DnsTunnelingToggle; set => NetworkQuickFilters.DnsTunnelingToggle = value; }
        public bool FilterScanTrafficToggle { get => NetworkQuickFilters.ScanTrafficToggle; set => NetworkQuickFilters.ScanTrafficToggle = value; }
        public bool FilterNonStandardPortsToggle { get => NetworkQuickFilters.NonStandardPortsToggle; set => NetworkQuickFilters.NonStandardPortsToggle = value; }
        public bool FilterSmbV1Toggle { get => NetworkQuickFilters.SmbV1Toggle; set => NetworkQuickFilters.SmbV1Toggle = value; }

        // Clean View wrappers
        public bool FilterHideBroadcastToggle { get => NetworkQuickFilters.HideBroadcastToggle; set => NetworkQuickFilters.HideBroadcastToggle = value; }
        public bool FilterApplicationDataOnlyToggle { get => NetworkQuickFilters.ApplicationDataOnlyToggle; set => NetworkQuickFilters.ApplicationDataOnlyToggle = value; }
        public bool FilterHideTunnelOverheadToggle { get => NetworkQuickFilters.HideTunnelOverheadToggle; set => NetworkQuickFilters.HideTunnelOverheadToggle = value; }

        // Protocol Error wrappers
        public bool FilterHttpErrorsToggle { get => NetworkQuickFilters.HttpErrorsToggle; set => NetworkQuickFilters.HttpErrorsToggle = value; }
        public bool FilterDnsFailuresToggle { get => NetworkQuickFilters.DnsFailuresToggle; set => NetworkQuickFilters.DnsFailuresToggle = value; }
        public bool FilterIcmpUnreachableToggle { get => NetworkQuickFilters.IcmpUnreachableToggle; set => NetworkQuickFilters.IcmpUnreachableToggle = value; }

        // Mode selector wrapper
        public bool QuickFilterIsIncludeMode { get => NetworkQuickFilters.IsIncludeMode; set => NetworkQuickFilters.IsIncludeMode = value; }

        // ==================== COMPUTED UI PROPERTIES FOR MODE COLORS ====================
        // These provide dynamic colors for the Quick Filters border based on include/exclude mode

        /// <summary>Border color: Green for INCLUDE, Red for EXCLUDE</summary>
        public string QuickFilterBorderColor => ThemeColorHelper.GetQuickFilterBorderColorHex(QuickFilterIsIncludeMode);

        /// <summary>Background color: Dark blue-green for INCLUDE, Dark red for EXCLUDE</summary>
        public string QuickFilterBackgroundColor => ThemeColorHelper.GetQuickFilterBackgroundColorHex(QuickFilterIsIncludeMode);

        /// <summary>Glow/shadow color: Green glow for INCLUDE, Red glow for EXCLUDE</summary>
        public string QuickFilterGlowColor => ThemeColorHelper.GetQuickFilterGlowColorHex(QuickFilterIsIncludeMode);

        /// <summary>Mode label text: "INCLUDE MODE" or "EXCLUDE MODE"</summary>
        public string QuickFilterModeLabel => QuickFilterIsIncludeMode ? "INCLUDE MODE" : "EXCLUDE MODE";

        /// <summary>Mode label text color: Green for INCLUDE, Red for EXCLUDE</summary>
        public string QuickFilterModeLabelColor => ThemeColorHelper.GetQuickFilterLabelTextColorHex(QuickFilterIsIncludeMode);

        /// <summary>Mode label background: Dark green for INCLUDE, Dark red for EXCLUDE</summary>
        public string QuickFilterModeLabelBackground => ThemeColorHelper.GetQuickFilterLabelBgColorHex(QuickFilterIsIncludeMode);

        /// <summary>Mode label border: Green for INCLUDE, Red for EXCLUDE</summary>
        public string QuickFilterModeLabelBorder => ThemeColorHelper.GetQuickFilterLabelBorderColorHex(QuickFilterIsIncludeMode);

        /// <summary>Mode icon: checkmark for INCLUDE, prohibited for EXCLUDE</summary>
        public string QuickFilterModeIcon => QuickFilterIsIncludeMode ? "\u2705" : "\U0001F6AB";

        /// <summary>Title color: Green for INCLUDE, Red for EXCLUDE</summary>
        public string QuickFilterTitleColor => ThemeColorHelper.GetQuickFilterBorderColorHex(QuickFilterIsIncludeMode);

        // ==================== FILTER INPUT PROPERTIES ====================

        /// <summary>INCLUDE: Source IP filter (supports comma-separated: "192.168.1.1,10.0.0.1")</summary>
        [ObservableProperty] private string? _sourceIPFilter;

        /// <summary>INCLUDE: Destination IP filter</summary>
        [ObservableProperty] private string? _destinationIPFilter;

        /// <summary>INCLUDE: Port range filter (supports ranges: "80,443,137-139")</summary>
        [ObservableProperty] private string? _portRangeFilter;

        /// <summary>INCLUDE: Protocol filter (L4: "TCP,UDP" or L7: "HTTP,DNS")</summary>
        [ObservableProperty] private string? _protocolFilter;

        /// <summary>EXCLUDE: NOT Source IP filter</summary>
        [ObservableProperty] private string? _notSourceIPFilter;

        /// <summary>EXCLUDE: NOT Destination IP filter</summary>
        [ObservableProperty] private string? _notDestinationIPFilter;

        /// <summary>EXCLUDE: NOT Port range filter</summary>
        [ObservableProperty] private string? _notPortRangeFilter;

        /// <summary>EXCLUDE: NOT Protocol filter</summary>
        [ObservableProperty] private string? _notProtocolFilter;

        // ==================== FILTER LOGIC MODE SWITCHES ====================

        /// <summary>INCLUDE filters use AND mode (all fields must match)</summary>
        [ObservableProperty] private bool _includeFilterUseAndMode = true;

        /// <summary>INCLUDE filters use OR mode (any field can match)</summary>
        [ObservableProperty] private bool _includeFilterUseOrMode = false;

        /// <summary>EXCLUDE filters use AND mode (all fields must match to exclude)</summary>
        [ObservableProperty] private bool _excludeFilterUseAndMode = true;

        /// <summary>EXCLUDE filters use OR mode (any field can match to exclude)</summary>
        [ObservableProperty] private bool _excludeFilterUseOrMode = false;

        // ==================== FILTER COLLECTIONS (INSTANCE - NOT SHARED) ====================

        /// <summary>
        /// INCLUDE filter groups (each group is AND of its fields, groups are OR'd together).
        /// IMPORTANT: Each tab instance gets its OWN collection (not shared across tabs).
        /// </summary>
        [ObservableProperty]
        private ObservableCollection<FilterGroup> _includeFilterGroups = [];

        /// <summary>
        /// INCLUDE individual filter chips (OR'd together).
        /// IMPORTANT: Each tab instance gets its OWN collection (not shared across tabs).
        /// </summary>
        [ObservableProperty]
        private ObservableCollection<FilterChipItem> _includeIndividualChips = [];

        /// <summary>
        /// EXCLUDE filter groups (each group is AND of its fields, groups are OR'd together, then NOT'd).
        /// IMPORTANT: Each tab instance gets its OWN collection (not shared across tabs).
        /// </summary>
        [ObservableProperty]
        private ObservableCollection<FilterGroup> _excludeFilterGroups = [];

        /// <summary>
        /// EXCLUDE individual filter chips (OR'd together, then NOT'd).
        /// IMPORTANT: Each tab instance gets its OWN collection (not shared across tabs).
        /// </summary>
        [ObservableProperty]
        private ObservableCollection<FilterChipItem> _excludeIndividualChips = [];

        // ==================== FILTER STATE ====================

        /// <summary>Indicates if any filters are currently applied</summary>
        [ObservableProperty] private bool _hasFiltersApplied = false;

        // ==================== CONSTRUCTOR ====================

        /// <summary>
        /// Initializes the base filter infrastructure with SmartFilterBuilder service.
        /// </summary>
        /// <param name="filterBuilder">Singleton service for building PacketFilters from groups/chips</param>
        protected SmartFilterableTab(ISmartFilterBuilder filterBuilder)
        {
            FilterBuilder = filterBuilder ?? throw new ArgumentNullException(nameof(filterBuilder));

            // Forward property change notifications from NetworkQuickFilters to UI
            // Critical for mode toggle UI updates (border color, mode label)
            NetworkQuickFilters.PropertyChanged += (sender, e) =>
            {
                if (e.PropertyName == nameof(QuickFilterViewModel.IsIncludeMode))
                {
                    // Notify for the wrapper property AND all computed color properties
                    OnPropertyChanged(nameof(QuickFilterIsIncludeMode));
                    OnPropertyChanged(nameof(QuickFilterBorderColor));
                    OnPropertyChanged(nameof(QuickFilterBackgroundColor));
                    OnPropertyChanged(nameof(QuickFilterGlowColor));
                    OnPropertyChanged(nameof(QuickFilterModeLabel));
                    OnPropertyChanged(nameof(QuickFilterModeLabelColor));
                    OnPropertyChanged(nameof(QuickFilterModeLabelBackground));
                    OnPropertyChanged(nameof(QuickFilterModeLabelBorder));
                    OnPropertyChanged(nameof(QuickFilterModeIcon));
                    OnPropertyChanged(nameof(QuickFilterTitleColor));
                }
            };
        }

        // ==================== ABSTRACT METHODS (TAB-SPECIFIC IMPLEMENTATION) ====================

        /// <summary>
        /// Applies the built PacketFilter to this tab's specific data.
        /// Each tab implements this to filter its own data (packets, threats, calls, countries, etc.).
        /// </summary>
        /// <param name="filter">The combined PacketFilter built from all groups/chips</param>
        protected abstract void ApplySmartFilter(PacketFilter filter);

        /// <summary>
        /// Tab name for IFilterableTab interface (used for filter copy operations).
        /// </summary>
        public abstract string TabName { get; }

        /// <summary>
        /// Override to provide tab-specific smart filter presets.
        /// Example: Threats tab returns "High-Risk Countries", "Suspicious Ports"
        /// Example: VoiceQoS tab returns "Poor MOS Score", "High Jitter"
        /// </summary>
        protected virtual ObservableCollection<SmartFilterPreset> GetSmartFilterPresets()
        {
            return new ObservableCollection<SmartFilterPreset>();
        }

        // ==================== IFILTERABLE TAB IMPLEMENTATION ====================

        /// <summary>
        /// Legacy CommonFilters support for backward compatibility with IFilterableTab.
        /// Maps sophisticated filters to simple 3-field model for filter copying between tabs.
        /// </summary>
        public CommonFilterViewModel CommonFilters => new CommonFilterViewModel
        {
            ProtocolFilter = ProtocolFilter,
            SourceIPFilter = SourceIPFilter,
            DestinationIPFilter = DestinationIPFilter
        };

        /// <summary>
        /// Applies current filter settings (IFilterableTab interface implementation).
        /// Delegates to ApplyFiltersCommand.
        /// </summary>
        public void ApplyFilters()
        {
            ExecuteApplyFiltersCommand.Execute(null);
        }

        /// <summary>
        /// Determines if filters can be applied (always true for now).
        /// </summary>
        private bool CanApplyFilters() => true;

        // ==================== FILTER COMMANDS ====================

        /// <summary>
        /// Command property alias for XAML binding compatibility.
        /// Points to auto-generated ExecuteApplyFiltersCommand.
        /// Required because toolkit generates "ExecuteApplyFiltersCommand" from "ExecuteApplyFilters()" method,
        /// but XAML binds to shorter name "ApplyFiltersCommand".
        /// Note: Other commands (ClearFilters, CopyFilters*) don't need aliases - they're generated correctly.
        /// </summary>
        public IRelayCommand ApplyFiltersCommand => ExecuteApplyFiltersCommand;

        /// <summary>
        /// Command to apply current filter settings to this tab's data.
        /// Builds PacketFilter from all groups/chips and calls ApplySmartFilter.
        /// </summary>
        [RelayCommand(CanExecute = nameof(CanApplyFilters))]
        private void ExecuteApplyFilters()
        {
            // Create INCLUDE groups if fields are filled (AND or OR mode)
            if (IncludeFilterUseAndMode)
            {
                // AND mode: Create single group with all filled fields
                var group = new FilterGroup
                {
                    SourceIP = SourceIPFilter,
                    DestinationIP = DestinationIPFilter,
                    PortRange = PortRangeFilter,
                    Protocol = ProtocolFilter,
                    IsAndGroup = true,
                    IsExcludeGroup = false
                };

                group.BuildDisplayLabel();
                group.RemoveCommand = new ToolkitRelayCommand(() => RemoveIncludeGroup(group));

                if (group.HasCriteria())
                {
                    IncludeFilterGroups.Add(group);
                }
            }
            else
            {
                // OR mode: Create individual chips for each field
                CreateIncludeIndividualChips();
            }

            // Create EXCLUDE groups if NOT fields are filled
            if (ExcludeFilterUseAndMode)
            {
                // AND mode: Create single NOT group with all filled fields
                var notGroup = new FilterGroup
                {
                    SourceIP = NotSourceIPFilter,
                    DestinationIP = NotDestinationIPFilter,
                    PortRange = NotPortRangeFilter,
                    Protocol = NotProtocolFilter,
                    IsAndGroup = true,
                    IsExcludeGroup = true
                };

                notGroup.BuildDisplayLabel();
                notGroup.RemoveCommand = new ToolkitRelayCommand(() => RemoveExcludeGroup(notGroup));

                if (notGroup.HasCriteria())
                {
                    ExcludeFilterGroups.Add(notGroup);
                }
            }
            else
            {
                // OR mode: Create individual NOT chips for each field
                CreateExcludeIndividualChips();
            }

            // Clear input fields after creating groups/chips
            ClearIncludeInputFields();
            ClearExcludeInputFields();

            // Create chips from active quick filter toggles
            CreateQuickFilterChips();

            // Build combined filter and apply to tab's data
            RebuildAndApplyFilter();
        }

        /// <summary>
        /// Command to clear all filters and reset to unfiltered state.
        /// </summary>
        [RelayCommand]
        private void ClearFilters()
        {
            // Clear input fields
            ClearIncludeInputFields();
            ClearExcludeInputFields();

            // Clear all groups and chips
            IncludeFilterGroups.Clear();
            IncludeIndividualChips.Clear();
            ExcludeFilterGroups.Clear();
            ExcludeIndividualChips.Clear();
            HasFiltersApplied = false;

            // Clear all quick filter toggles
            NetworkQuickFilters.ClearAll();

            // Apply empty filter (show all data)
            var emptyFilter = new PacketFilter();
            ApplySmartFilter(emptyFilter);

            DebugLogger.Log($"[{TabName}] All filters cleared - showing all data");
        }

        // ==================== FILTER COPY COMMANDS (TAB-SPECIFIC) ====================
        // Note: These commands copy filters FROM this tab TO other tabs.
        // Override in derived classes if cross-tab filter copying is needed.

        /// <summary>Copy filters to Dashboard tab (virtual - override in MainWindowViewModel if needed)</summary>
        [RelayCommand]
        protected virtual void CopyFiltersToDashboard()
        {
            DebugLogger.Log($"[{TabName}] Filter copy to Dashboard not implemented (override in derived class)");
        }

        /// <summary>Copy filters to Threats tab (virtual - override in MainWindowViewModel if needed)</summary>
        [RelayCommand]
        protected virtual void CopyFiltersToThreats()
        {
            DebugLogger.Log($"[{TabName}] Filter copy to Threats not implemented (override in derived class)");
        }

        /// <summary>Copy filters to VoiceQoS tab (virtual - override in MainWindowViewModel if needed)</summary>
        [RelayCommand]
        protected virtual void CopyFiltersToVoiceQoS()
        {
            DebugLogger.Log($"[{TabName}] Filter copy to VoiceQoS not implemented (override in derived class)");
        }

        /// <summary>Copy filters to Country Traffic tab (virtual - override in MainWindowViewModel if needed)</summary>
        [RelayCommand]
        protected virtual void CopyFiltersToCountryTraffic()
        {
            DebugLogger.Log($"[{TabName}] Filter copy to CountryTraffic not implemented (override in derived class)");
        }

        // ==================== FILTER BUILDING HELPERS ====================

        /// <summary>
        /// Creates individual INCLUDE filter chips from current input fields (OR mode).
        /// </summary>
        private void CreateIncludeIndividualChips()
        {
            if (!string.IsNullOrWhiteSpace(SourceIPFilter))
            {
                var chip = new FilterChipItem(
                    _nextFilterChipId++,
                    "Src IP",
                    SourceIPFilter.Trim(),
                    isExclude: false);
                chip.RemoveCommand = new ToolkitRelayCommand(() => RemoveIncludeChip(chip));
                IncludeIndividualChips.Add(chip);
            }

            if (!string.IsNullOrWhiteSpace(DestinationIPFilter))
            {
                var chip = new FilterChipItem(
                    _nextFilterChipId++,
                    "Dest IP",
                    DestinationIPFilter.Trim(),
                    isExclude: false);
                chip.RemoveCommand = new ToolkitRelayCommand(() => RemoveIncludeChip(chip));
                IncludeIndividualChips.Add(chip);
            }

            if (!string.IsNullOrWhiteSpace(PortRangeFilter))
            {
                var chip = new FilterChipItem(
                    _nextFilterChipId++,
                    "Port",
                    PortRangeFilter.Trim(),
                    isExclude: false);
                chip.RemoveCommand = new ToolkitRelayCommand(() => RemoveIncludeChip(chip));
                IncludeIndividualChips.Add(chip);
            }

            if (!string.IsNullOrWhiteSpace(ProtocolFilter))
            {
                var chip = new FilterChipItem(
                    _nextFilterChipId++,
                    "Protocol",
                    ProtocolFilter.Trim(),
                    isExclude: false);
                chip.RemoveCommand = new ToolkitRelayCommand(() => RemoveIncludeChip(chip));
                IncludeIndividualChips.Add(chip);
            }

            DebugLogger.Log($"[{TabName}] Created {IncludeIndividualChips.Count} INCLUDE individual chips (OR logic)");
        }

        /// <summary>
        /// Creates individual EXCLUDE filter chips from current NOT input fields (OR mode).
        /// </summary>
        private void CreateExcludeIndividualChips()
        {
            if (!string.IsNullOrWhiteSpace(NotSourceIPFilter))
            {
                var chip = new FilterChipItem(
                    _nextFilterChipId++,
                    "NOT Src IP",
                    NotSourceIPFilter.Trim(),
                    isExclude: true);
                chip.RemoveCommand = new ToolkitRelayCommand(() => RemoveExcludeChip(chip));
                ExcludeIndividualChips.Add(chip);
            }

            if (!string.IsNullOrWhiteSpace(NotDestinationIPFilter))
            {
                var chip = new FilterChipItem(
                    _nextFilterChipId++,
                    "NOT Dest IP",
                    NotDestinationIPFilter.Trim(),
                    isExclude: true);
                chip.RemoveCommand = new ToolkitRelayCommand(() => RemoveExcludeChip(chip));
                ExcludeIndividualChips.Add(chip);
            }

            if (!string.IsNullOrWhiteSpace(NotPortRangeFilter))
            {
                var chip = new FilterChipItem(
                    _nextFilterChipId++,
                    "NOT Port",
                    NotPortRangeFilter.Trim(),
                    isExclude: true);
                chip.RemoveCommand = new ToolkitRelayCommand(() => RemoveExcludeChip(chip));
                ExcludeIndividualChips.Add(chip);
            }

            if (!string.IsNullOrWhiteSpace(NotProtocolFilter))
            {
                var chip = new FilterChipItem(
                    _nextFilterChipId++,
                    "NOT Protocol",
                    NotProtocolFilter.Trim(),
                    isExclude: true);
                chip.RemoveCommand = new ToolkitRelayCommand(() => RemoveExcludeChip(chip));
                ExcludeIndividualChips.Add(chip);
            }

            DebugLogger.Log($"[{TabName}] Created {ExcludeIndividualChips.Count} EXCLUDE individual chips (OR logic)");
        }

        /// <summary>Clears all INCLUDE input fields</summary>
        private void ClearIncludeInputFields()
        {
            SourceIPFilter = null;
            DestinationIPFilter = null;
            PortRangeFilter = null;
            ProtocolFilter = null;
        }

        /// <summary>Clears all EXCLUDE input fields</summary>
        private void ClearExcludeInputFields()
        {
            NotSourceIPFilter = null;
            NotDestinationIPFilter = null;
            NotPortRangeFilter = null;
            NotProtocolFilter = null;
        }

        /// <summary>Removes an INCLUDE filter group and rebuilds the combined filter</summary>
        private void RemoveIncludeGroup(FilterGroup group)
        {
            IncludeFilterGroups.Remove(group);
            RebuildAndApplyFilter();
        }

        /// <summary>Removes an EXCLUDE filter group and rebuilds the combined filter</summary>
        private void RemoveExcludeGroup(FilterGroup group)
        {
            ExcludeFilterGroups.Remove(group);
            RebuildAndApplyFilter();
        }

        /// <summary>Removes an INCLUDE individual chip and rebuilds the combined filter</summary>
        private void RemoveIncludeChip(FilterChipItem chip)
        {
            IncludeIndividualChips.Remove(chip);
            RebuildAndApplyFilter();
        }

        /// <summary>Removes an EXCLUDE individual chip and rebuilds the combined filter</summary>
        private void RemoveExcludeChip(FilterChipItem chip)
        {
            ExcludeIndividualChips.Remove(chip);
            RebuildAndApplyFilter();
        }

        /// <summary>
        /// Rebuilds the PacketFilter from all active groups/chips and re-applies it to tab's data.
        /// </summary>
        private void RebuildAndApplyFilter()
        {
            var combinedFilter = BuildCombinedPacketFilter();

            // Apply to this tab's specific data (abstract method - each tab implements differently)
            ApplySmartFilter(combinedFilter);

            HasFiltersApplied = HasAnyActiveFilters();

            DebugLogger.Log($"[{TabName}] Filter rebuilt and applied");
        }

        /// <summary>
        /// Builds the complete PacketFilter from all filter groups and individual chips.
        /// Delegates to SmartFilterBuilderService for sophisticated AND/OR/NOT logic.
        /// </summary>
        private PacketFilter BuildCombinedPacketFilter()
        {
            return FilterBuilder.BuildCombinedPacketFilter(
                IncludeFilterGroups,
                IncludeIndividualChips,
                ExcludeFilterGroups,
                ExcludeIndividualChips);
        }

        /// <summary>
        /// Checks if any filters are currently active (groups or chips).
        /// </summary>
        private bool HasAnyActiveFilters()
        {
            return IncludeFilterGroups.Count > 0 ||
                   IncludeIndividualChips.Count > 0 ||
                   ExcludeFilterGroups.Count > 0 ||
                   ExcludeIndividualChips.Count > 0 ||
                   NetworkQuickFilters.HasActiveFilters;
        }

        // ==================== QUICK FILTER CHIP CREATION ====================

        /// <summary>
        /// Creates filter chips from active quick filter toggles.
        /// Called from ExecuteApplyFilters after text filter processing.
        /// </summary>
        private void CreateQuickFilterChips()
        {
            // Get all active quick filters (display name + code name pairs)
            var activeFilters = GetActiveQuickFilterMappings();

            // Add tab-specific quick filter mappings (override in derived classes)
            var tabSpecificFilters = GetTabSpecificQuickFilterMappings();
            activeFilters.AddRange(tabSpecificFilters);

            if (activeFilters.Count == 0)
                return;

            bool isExcludeMode = !NetworkQuickFilters.IsIncludeMode;
            var targetCollection = isExcludeMode ? ExcludeIndividualChips : IncludeIndividualChips;

            foreach (var (displayName, codeName) in activeFilters)
            {
                // Skip if chip already exists for this quick filter
                if (ChipExistsForQuickFilter(codeName))
                    continue;

                var chip = new FilterChipItem(
                    _nextFilterChipId++,
                    displayName,
                    codeName,
                    isExcludeMode,
                    isQuickFilter: true);

                chip.RemoveCommand = new ToolkitRelayCommand(() => RemoveQuickFilterChip(chip));
                targetCollection.Add(chip);
            }

            // Clear toggle states after chips are created
            // Chips become the persistent indicator; toggles are cleared for clean UX
            ClearQuickFilterToggles(activeFilters);

            DebugLogger.Log($"[{TabName}] Created {activeFilters.Count} quick filter chips ({(isExcludeMode ? "EXCLUDE" : "INCLUDE")} mode)");
        }

        /// <summary>
        /// Override in derived classes to provide tab-specific quick filter mappings.
        /// Example: Dashboard returns protocol filters (HTTP, FTP, DNS, etc.)
        /// </summary>
        protected virtual System.Collections.Generic.List<(string DisplayName, string CodeName)> GetTabSpecificQuickFilterMappings()
        {
            return new System.Collections.Generic.List<(string, string)>();
        }

        /// <summary>
        /// Clears quick filter toggles after chips are created for clean UX.
        /// </summary>
        private void ClearQuickFilterToggles(System.Collections.Generic.List<(string DisplayName, string CodeName)> activeFilters)
        {
            foreach (var (_, codeName) in activeFilters)
            {
                UnToggleQuickFilter(codeName);
            }
        }

        /// <summary>
        /// Checks if a chip already exists for the given quick filter code name.
        /// </summary>
        private bool ChipExistsForQuickFilter(string codeName)
        {
            return IncludeIndividualChips.Any(c => c.QuickFilterCodeName == codeName) ||
                   ExcludeIndividualChips.Any(c => c.QuickFilterCodeName == codeName);
        }

        /// <summary>
        /// Removes a quick filter chip and untoggles the source filter.
        /// </summary>
        private void RemoveQuickFilterChip(FilterChipItem chip)
        {
            // Untoggle the source quick filter
            if (!string.IsNullOrEmpty(chip.QuickFilterCodeName))
            {
                UnToggleQuickFilter(chip.QuickFilterCodeName);
            }

            // Remove from collection
            if (chip.IsExclude)
                ExcludeIndividualChips.Remove(chip);
            else
                IncludeIndividualChips.Remove(chip);

            RebuildAndApplyFilter();
        }

        /// <summary>
        /// Untoggles a quick filter by its code name.
        /// High cyclomatic complexity is acceptable for simple switch-case mapping.
        /// </summary>
#pragma warning disable CA1502 // Simple switch-case mapping, complexity is acceptable
        private void UnToggleQuickFilter(string codeName)
        {
            switch (codeName)
            {
                // IP type filters
                case "RFC1918": NetworkQuickFilters.Rfc1918Toggle = false; break;
                case "PublicIP": NetworkQuickFilters.PublicIpToggle = false; break;
                case "APIPA": NetworkQuickFilters.ApipaToggle = false; break;
                case "IPv4": NetworkQuickFilters.IPv4Toggle = false; break;
                case "IPv6": NetworkQuickFilters.IPv6Toggle = false; break;
                case "Loopback": NetworkQuickFilters.LoopbackToggle = false; break;
                case "LinkLocal": NetworkQuickFilters.LinkLocalToggle = false; break;

                // Network filters
                case "Multicast": NetworkQuickFilters.MulticastToggle = false; break;
                case "Broadcast": NetworkQuickFilters.BroadcastToggle = false; break;
                case "Anycast": NetworkQuickFilters.AnycastToggle = false; break;

                // Security filters
                case "Insecure": NetworkQuickFilters.InsecureToggle = false; break;
                case "Anomalies": NetworkQuickFilters.AnomaliesToggle = false; break;
                case "Suspicious": NetworkQuickFilters.SuspiciousToggle = false; break;
                case "TCPIssues": NetworkQuickFilters.TcpIssuesToggle = false; break;
                case "DNSAnomalies": NetworkQuickFilters.DnsAnomaliesToggle = false; break;
                case "PortScans": NetworkQuickFilters.PortScansToggle = false; break;

                // Traffic direction
                case "PrivateToPublic": NetworkQuickFilters.PrivateToPublicToggle = false; break;
                case "PublicToPrivate": NetworkQuickFilters.PublicToPrivateToggle = false; break;
                case "JumboFrames": NetworkQuickFilters.JumboFramesToggle = false; break;

                // TCP Performance
                case "Retransmissions": NetworkQuickFilters.RetransmissionsToggle = false; break;
                case "ZeroWindow": NetworkQuickFilters.ZeroWindowToggle = false; break;
                case "KeepAlive": NetworkQuickFilters.KeepAliveToggle = false; break;
                case "ConnectionRefused": NetworkQuickFilters.ConnectionRefusedToggle = false; break;
                case "WindowFull": NetworkQuickFilters.WindowFullToggle = false; break;

                // Security Audit
                case "CleartextAuth": NetworkQuickFilters.CleartextAuthToggle = false; break;
                case "ObsoleteCrypto": NetworkQuickFilters.ObsoleteCryptoToggle = false; break;
                case "DNSTunneling": NetworkQuickFilters.DnsTunnelingToggle = false; break;
                case "ScanTraffic": NetworkQuickFilters.ScanTrafficToggle = false; break;
                case "NonStandardPorts": NetworkQuickFilters.NonStandardPortsToggle = false; break;
                case "SMBv1": NetworkQuickFilters.SmbV1Toggle = false; break;

                // Clean View
                case "HideBroadcast": NetworkQuickFilters.HideBroadcastToggle = false; break;
                case "AppDataOnly": NetworkQuickFilters.ApplicationDataOnlyToggle = false; break;
                case "HideTunnels": NetworkQuickFilters.HideTunnelOverheadToggle = false; break;

                // Protocol Errors
                case "HTTPErrors": NetworkQuickFilters.HttpErrorsToggle = false; break;
                case "DNSFailures": NetworkQuickFilters.DnsFailuresToggle = false; break;
                case "ICMPUnreachable": NetworkQuickFilters.IcmpUnreachableToggle = false; break;

                // Protocol Filters (handled by derived classes via UnToggleTabSpecificFilter)
                default:
                    if (!UnToggleTabSpecificFilter(codeName))
                    {
                        DebugLogger.Log($"[{TabName}] Unknown quick filter code name: {codeName}");
                    }
                    break;
            }
        }
#pragma warning restore CA1502

        /// <summary>
        /// Override in derived classes to untoggle tab-specific filters.
        /// Returns true if the filter was handled, false otherwise.
        /// </summary>
        protected virtual bool UnToggleTabSpecificFilter(string codeName)
        {
            return false;
        }

        /// <summary>
        /// Gets active quick filter mappings (display name, code name) for chip creation.
        /// High cyclomatic complexity is acceptable for simple conditional list building.
        /// </summary>
#pragma warning disable CA1502 // Simple conditional mapping, complexity is acceptable
        private System.Collections.Generic.List<(string DisplayName, string CodeName)> GetActiveQuickFilterMappings()
        {
            var result = new System.Collections.Generic.List<(string, string)>();

            // IP type filters
            if (NetworkQuickFilters.Rfc1918Toggle) result.Add(("RFC1918", "RFC1918"));
            if (NetworkQuickFilters.PublicIpToggle) result.Add(("Public IP", "PublicIP"));
            if (NetworkQuickFilters.ApipaToggle) result.Add(("APIPA", "APIPA"));
            if (NetworkQuickFilters.IPv4Toggle) result.Add(("IPv4", "IPv4"));
            if (NetworkQuickFilters.IPv6Toggle) result.Add(("IPv6", "IPv6"));
            if (NetworkQuickFilters.LoopbackToggle) result.Add(("Loopback", "Loopback"));
            if (NetworkQuickFilters.LinkLocalToggle) result.Add(("Link-local", "LinkLocal"));

            // Network filters
            if (NetworkQuickFilters.MulticastToggle) result.Add(("Multicast", "Multicast"));
            if (NetworkQuickFilters.BroadcastToggle) result.Add(("Broadcast", "Broadcast"));
            if (NetworkQuickFilters.AnycastToggle) result.Add(("Anycast", "Anycast"));

            // Security filters
            if (NetworkQuickFilters.InsecureToggle) result.Add(("Insecure", "Insecure"));
            if (NetworkQuickFilters.AnomaliesToggle) result.Add(("Anomalies", "Anomalies"));
            if (NetworkQuickFilters.SuspiciousToggle) result.Add(("Suspicious", "Suspicious"));
            if (NetworkQuickFilters.TcpIssuesToggle) result.Add(("TCP Issues", "TCPIssues"));
            if (NetworkQuickFilters.DnsAnomaliesToggle) result.Add(("DNS Anomalies", "DNSAnomalies"));
            if (NetworkQuickFilters.PortScansToggle) result.Add(("Port Scans", "PortScans"));

            // Traffic direction
            if (NetworkQuickFilters.PrivateToPublicToggle) result.Add(("Private→Public", "PrivateToPublic"));
            if (NetworkQuickFilters.PublicToPrivateToggle) result.Add(("Public→Private", "PublicToPrivate"));
            if (NetworkQuickFilters.JumboFramesToggle) result.Add(("Jumbo Frames", "JumboFrames"));

            // TCP Performance
            if (NetworkQuickFilters.RetransmissionsToggle) result.Add(("Retransmissions", "Retransmissions"));
            if (NetworkQuickFilters.ZeroWindowToggle) result.Add(("Zero Window", "ZeroWindow"));
            if (NetworkQuickFilters.KeepAliveToggle) result.Add(("Keep-Alive", "KeepAlive"));
            if (NetworkQuickFilters.ConnectionRefusedToggle) result.Add(("Conn Refused", "ConnectionRefused"));
            if (NetworkQuickFilters.WindowFullToggle) result.Add(("Window Full", "WindowFull"));

            // Security Audit
            if (NetworkQuickFilters.CleartextAuthToggle) result.Add(("Cleartext Auth", "CleartextAuth"));
            if (NetworkQuickFilters.ObsoleteCryptoToggle) result.Add(("Obsolete Crypto", "ObsoleteCrypto"));
            if (NetworkQuickFilters.DnsTunnelingToggle) result.Add(("DNS Tunneling", "DNSTunneling"));
            if (NetworkQuickFilters.ScanTrafficToggle) result.Add(("Scan Traffic", "ScanTraffic"));
            if (NetworkQuickFilters.NonStandardPortsToggle) result.Add(("Non-Std Ports", "NonStandardPorts"));
            if (NetworkQuickFilters.SmbV1Toggle) result.Add(("SMBv1", "SMBv1"));

            // Clean View (these are exclusion filters by nature)
            if (NetworkQuickFilters.HideBroadcastToggle) result.Add(("Hide Broadcast", "HideBroadcast"));
            if (NetworkQuickFilters.ApplicationDataOnlyToggle) result.Add(("App Data Only", "AppDataOnly"));
            if (NetworkQuickFilters.HideTunnelOverheadToggle) result.Add(("Hide Tunnels", "HideTunnels"));

            // Protocol Errors
            if (NetworkQuickFilters.HttpErrorsToggle) result.Add(("HTTP Errors", "HTTPErrors"));
            if (NetworkQuickFilters.DnsFailuresToggle) result.Add(("DNS Failures", "DNSFailures"));
            if (NetworkQuickFilters.IcmpUnreachableToggle) result.Add(("ICMP Unreachable", "ICMPUnreachable"));

            return result;
        }
#pragma warning restore CA1502
    }

    // ==================== SMART FILTER PRESET MODEL ====================

    /// <summary>
    /// Represents a tab-specific quick filter preset.
    /// Example: Threats tab → "High-Risk Countries", "Suspicious Ports"
    /// Example: VoiceQoS tab → "Poor MOS Score", "High Jitter"
    /// </summary>
    public class SmartFilterPreset
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public Func<PacketInfo, bool> Predicate { get; set; } = _ => true;

        public SmartFilterPreset() { }

        public SmartFilterPreset(string name, Func<PacketInfo, bool> predicate)
        {
            Name = name;
            Predicate = predicate;
        }
    }
}
