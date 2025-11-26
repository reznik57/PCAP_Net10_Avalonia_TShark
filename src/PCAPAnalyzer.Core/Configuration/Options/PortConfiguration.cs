using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Configuration.Options
{
    /// <summary>
    /// Configuration for port-related settings.
    /// Loaded from config/ports.json via IOptions pattern.
    /// </summary>
    public class PortConfiguration
    {
        /// <summary>
        /// Well-known port to service name mappings.
        /// </summary>
        public Dictionary<int, string> WellKnownPorts { get; set; } = new();

        /// <summary>
        /// Ports that use encrypted protocols (TLS/SSL).
        /// </summary>
        public List<int> EncryptedPorts { get; set; } = new() { 443, 22, 8443 };

        /// <summary>
        /// Ports that are considered insecure (clear-text protocols).
        /// </summary>
        public List<int> InsecurePorts { get; set; } = new() { 21, 23, 69, 110, 143 };
    }
}
