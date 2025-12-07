using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Configuration.Options
{
    /// <summary>
    /// Configuration for protocol-related settings.
    /// Loaded from config/protocols.json via IOptions pattern.
    /// </summary>
    public class ProtocolConfiguration
    {
        /// <summary>
        /// Protocol to display color mappings (hex colors).
        /// </summary>
        public Dictionary<string, string> ProtocolColors { get; set; } = new()
        {
            { "TCP", "#3B82F6" },
            { "UDP", "#10B981" },
            { "ICMP", "#F59E0B" },
            { "HTTP", "#8B5CF6" },
            { "HTTPS", "#EC4899" },
            { "DNS", "#14B8A6" },
            { "SSH", "#F97316" },
            { "FTP", "#EF4444" },
            { "SMTP", "#6366F1" },
            { "Other", "#6B7280" }
        };

        /// <summary>
        /// Protocol security ratings (0-5, higher is more secure).
        /// </summary>
        public Dictionary<string, int> SecurityRatings { get; set; } = [];

        /// <summary>
        /// Protocols considered suspicious/insecure.
        /// </summary>
        public List<string> SuspiciousProtocols { get; set; } = new() { "TELNET", "FTP", "HTTP" };
    }
}
