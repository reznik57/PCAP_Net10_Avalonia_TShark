using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Utilities
{
    /// <summary>
    /// Maps internal analysis phase names to user-friendly tab names with icons.
    /// Provides a consistent mapping for progress visualization across the UI.
    ///
    /// Design Goal:
    /// Instead of showing technical phase names like "Analyzing Data" or "Loading Packets",
    /// show which TAB is being prepared: "📊 Dashboard" or "📦 Packet Analysis".
    /// This gives users immediate context about what functionality is being prepared.
    /// </summary>
    public static class PhaseToTabMapper
    {
        /// <summary>
        /// Maps technical phase names to tab display names with emoji icons
        /// </summary>
        private static readonly Dictionary<string, string> PhaseToTabName = new()
        {
            // Counting phase prepares File Manager tab (file info, selection)
            { "Counting Packets", "📂 File Manager" },

            // Loading phase prepares Packet Analysis tab (packet list display)
            { "Loading Packets", "📦 Packet Analysis" },

            // Statistics analysis prepares Dashboard tab (overview metrics, charts)
            { "Analyzing Data", "📊 Dashboard" },

            // GeoIP enrichment prepares Country Traffic tab (geographic analysis)
            { "GeoIP Enrichment", "🌍 Country Traffic" },

            // Traffic flow analysis also prepares Country Traffic tab
            { "Traffic Flow Analysis", "🌍 Country Traffic" },

            // Threat detection prepares Security Threats tab (anomalies, threats)
            { "Threat Detection", "🛡️ Security Threats" },

            // VoIP analysis prepares Voice/QoS tab (SIP, RTP analysis)
            { "VoiceQoS Analysis", "📞 Voice/QoS" },

            // Final caching/indexing phase
            { "Finalizing", "✅ Finalizing" },

            // Completion marker
            { "Complete", "✅ Complete" }
        };

        /// <summary>
        /// Maps technical phase name to user-friendly tab name with icon
        /// </summary>
        /// <param name="technicalPhaseName">Internal phase name (e.g., "Analyzing Data")</param>
        /// <returns>Tab display name with icon (e.g., "📊 Dashboard")</returns>
        public static string GetTabDisplayName(string technicalPhaseName)
        {
            return PhaseToTabName.TryGetValue(technicalPhaseName, out var tabName)
                ? tabName
                : technicalPhaseName; // Fallback to original if not mapped
        }

        /// <summary>
        /// Gets the tab icon for a given technical phase
        /// </summary>
        /// <param name="technicalPhaseName">Internal phase name</param>
        /// <returns>Icon emoji (e.g., "📊")</returns>
        public static string GetTabIcon(string technicalPhaseName)
        {
            var tabName = GetTabDisplayName(technicalPhaseName);

            // Extract first character (emoji icon)
            if (tabName.Length > 0 && char.IsHighSurrogate(tabName[0]) && tabName.Length > 1)
            {
                // Handle emoji (2-char surrogate pair)
                return tabName.Substring(0, 2);
            }
            else if (tabName.Length > 0)
            {
                // Handle single-char icon
                return tabName.Substring(0, 1);
            }

            return "";
        }

        /// <summary>
        /// Gets the tab name without the icon prefix
        /// </summary>
        /// <param name="technicalPhaseName">Internal phase name</param>
        /// <returns>Tab name without icon (e.g., "Dashboard")</returns>
        public static string GetTabNameOnly(string technicalPhaseName)
        {
            var tabName = GetTabDisplayName(technicalPhaseName);

            // Remove icon and space prefix
            var parts = tabName.Split(' ', 2);
            return parts.Length > 1 ? parts[1] : tabName;
        }

        /// <summary>
        /// Checks if a technical phase name is recognized
        /// </summary>
        public static bool IsKnownPhase(string technicalPhaseName)
        {
            return PhaseToTabName.ContainsKey(technicalPhaseName);
        }

        /// <summary>
        /// Gets all registered phase-to-tab mappings
        /// </summary>
        public static IReadOnlyDictionary<string, string> GetAllMappings()
        {
            return PhaseToTabName;
        }
    }
}
