using System;
using System.Collections.ObjectModel;
using System.Linq;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
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
        private ObservableCollection<FilterGroup> _includeFilterGroups = new();

        /// <summary>
        /// INCLUDE individual filter chips (OR'd together).
        /// IMPORTANT: Each tab instance gets its OWN collection (not shared across tabs).
        /// </summary>
        [ObservableProperty]
        private ObservableCollection<FilterChipItem> _includeIndividualChips = new();

        /// <summary>
        /// EXCLUDE filter groups (each group is AND of its fields, groups are OR'd together, then NOT'd).
        /// IMPORTANT: Each tab instance gets its OWN collection (not shared across tabs).
        /// </summary>
        [ObservableProperty]
        private ObservableCollection<FilterGroup> _excludeFilterGroups = new();

        /// <summary>
        /// EXCLUDE individual filter chips (OR'd together, then NOT'd).
        /// IMPORTANT: Each tab instance gets its OWN collection (not shared across tabs).
        /// </summary>
        [ObservableProperty]
        private ObservableCollection<FilterChipItem> _excludeIndividualChips = new();

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
                   ExcludeIndividualChips.Count > 0;
        }
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
