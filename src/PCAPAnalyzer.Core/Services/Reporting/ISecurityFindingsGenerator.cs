using System.Collections.Generic;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Reporting
{
    /// <summary>
    /// Interface for security findings generation.
    /// Analyzes network statistics and threats to produce actionable security findings.
    /// </summary>
    public interface ISecurityFindingsGenerator
    {
        /// <summary>
        /// Generates comprehensive security findings from network statistics and threats.
        /// </summary>
        /// <param name="statistics">Network statistics containing packet analysis data.</param>
        /// <param name="threats">List of detected security threats.</param>
        /// <returns>List of security findings with severity, remediation, and affected systems.</returns>
        Task<List<SecurityFinding>> GenerateAsync(NetworkStatistics statistics, List<SecurityThreat> threats);

        /// <summary>
        /// Analyzes network usage for insecure services (FTP, Telnet, etc.).
        /// </summary>
        /// <param name="statistics">Network statistics containing port usage data.</param>
        /// <returns>Security findings for detected insecure services.</returns>
        Task<List<SecurityFinding>> AnalyzeInsecureServicesAsync(NetworkStatistics statistics);

        /// <summary>
        /// Analyzes network traffic for suspicious patterns (port scanning, data exfiltration).
        /// </summary>
        /// <param name="statistics">Network statistics containing conversation data.</param>
        /// <returns>Security findings for detected suspicious patterns.</returns>
        Task<List<SecurityFinding>> AnalyzeSuspiciousPatternsAsync(NetworkStatistics statistics);
    }
}
