using PCAPAnalyzer.UI.ViewModels.Components;

namespace PCAPAnalyzer.UI.Interfaces
{
    /// <summary>
    /// Interface for tabs that support common filter functionality and filter copying.
    /// Tabs implementing this interface can register with FilterCopyService to enable
    /// cross-tab filter copying.
    /// </summary>
    public interface IFilterableTab
    {
        /// <summary>
        /// Common filters shared across tabs (Protocol, Source IP, Destination IP)
        /// These filters can be copied to other tabs
        /// </summary>
        CommonFilterViewModel CommonFilters { get; }

        /// <summary>
        /// Apply current filter settings to the tab's data.
        /// Called after filters are updated (either locally or via copy operation)
        /// </summary>
        void ApplyFilters();

        /// <summary>
        /// Get the unique name identifier for this tab (used for filter copy operations)
        /// </summary>
        string TabName { get; }
    }
}
