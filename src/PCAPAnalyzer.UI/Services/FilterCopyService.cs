using PCAPAnalyzer.UI.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.UI.Services
{
    /// <summary>
    /// Service for managing filter registration and copying between analysis tabs.
    /// Enables users to copy common filters (Protocol, Source IP, Destination IP)
    /// from one tab to another without tight coupling between ViewModels.
    /// </summary>
    public class FilterCopyService
    {
        private readonly Dictionary<string, IFilterableTab> _registeredTabs = [];
        private readonly Lock _lock = new();

        /// <summary>
        /// Register a tab to participate in filter copying operations
        /// </summary>
        /// <param name="tabName">Unique identifier for the tab</param>
        /// <param name="tab">Tab instance implementing IFilterableTab</param>
        public void RegisterTab(string tabName, IFilterableTab tab)
        {
            if (string.IsNullOrWhiteSpace(tabName))
                throw new ArgumentNullException(nameof(tabName));

            if (tab is null)
                throw new ArgumentNullException(nameof(tab));

            using (_lock.EnterScope())
            {
                _registeredTabs[tabName] = tab;
                DebugLogger.Log($"[FilterCopyService] Registered tab: {tabName}");
            }
        }

        /// <summary>
        /// Unregister a tab from filter copying operations
        /// </summary>
        /// <param name="tabName">Unique identifier for the tab</param>
        public void UnregisterTab(string tabName)
        {
            if (string.IsNullOrWhiteSpace(tabName))
                return;

            using (_lock.EnterScope())
            {
                if (_registeredTabs.Remove(tabName))
                {
                    DebugLogger.Log($"[FilterCopyService] Unregistered tab: {tabName}");
                }
            }
        }

        /// <summary>
        /// Copy common filters from source tab to destination tab
        /// </summary>
        /// <param name="sourceTabName">Name of the tab to copy filters from</param>
        /// <param name="destinationTabName">Name of the tab to copy filters to</param>
        /// <returns>True if copy was successful, false if tabs not found or copy failed</returns>
        public bool CopyFilters(string sourceTabName, string destinationTabName)
        {
            if (string.IsNullOrWhiteSpace(sourceTabName) || string.IsNullOrWhiteSpace(destinationTabName))
            {
                DebugLogger.Log($"[FilterCopyService] Invalid tab names provided");
                return false;
            }

            if (sourceTabName == destinationTabName)
            {
                DebugLogger.Log($"[FilterCopyService] Cannot copy filters to the same tab");
                return false;
            }

            using (_lock.EnterScope())
            {
                if (!_registeredTabs.TryGetValue(sourceTabName, out var sourceTab))
                {
                    DebugLogger.Log($"[FilterCopyService] Source tab '{sourceTabName}' not registered");
                    return false;
                }

                if (!_registeredTabs.TryGetValue(destinationTabName, out var destinationTab))
                {
                    DebugLogger.Log($"[FilterCopyService] Destination tab '{destinationTabName}' not registered");
                    return false;
                }

                try
                {
                    // Copy common filters
                    destinationTab.CommonFilters.CopyFrom(sourceTab.CommonFilters);

                    DebugLogger.Log($"[FilterCopyService] Copied filters from '{sourceTabName}' to '{destinationTabName}':");
                    DebugLogger.Log($"  - Protocol: {sourceTab.CommonFilters.ProtocolFilter ?? "(none)"}");
                    DebugLogger.Log($"  - Source IP: {sourceTab.CommonFilters.SourceIPFilter ?? "(none)"}");
                    DebugLogger.Log($"  - Dest IP: {sourceTab.CommonFilters.DestinationIPFilter ?? "(none)"}");

                    // Apply filters on destination tab
                    destinationTab.ApplyFilters();

                    return true;
                }
                catch (Exception ex)
                {
                    DebugLogger.Log($"[FilterCopyService] Error copying filters: {ex.Message}");
                    return false;
                }
            }
        }

        /// <summary>
        /// Get list of available target tabs for filter copying (excludes the current tab)
        /// </summary>
        /// <param name="currentTabName">Name of the current tab (will be excluded from results)</param>
        /// <returns>List of tab names that filters can be copied to</returns>
        public IEnumerable<string> GetAvailableTargetTabs(string currentTabName)
        {
            using (_lock.EnterScope())
            {
                return _registeredTabs.Keys
                    .Where(name => name != currentTabName)
                    .OrderBy(name => name)
                    .ToList();
            }
        }

        /// <summary>
        /// Check if a specific tab is registered
        /// </summary>
        public bool IsTabRegistered(string tabName)
        {
            using (_lock.EnterScope())
            {
                return _registeredTabs.ContainsKey(tabName);
            }
        }

        /// <summary>
        /// Get count of registered tabs
        /// </summary>
        public int RegisteredTabCount
        {
            get
            {
                using (_lock.EnterScope())
                {
                    return _registeredTabs.Count;
                }
            }
        }
    }
}
