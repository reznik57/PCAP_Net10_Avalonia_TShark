using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Caching
{
    /// <summary>
    /// Generates deterministic, collision-resistant cache keys for report generation operations.
    /// Uses SHA256 hashing to create unique keys based on input parameters.
    /// </summary>
    public class CacheKeyGenerator
    {
        private const string ServicePrefix = "ReportCache";
        private const string SecurityFindingsOperation = "SecurityFindings";
        private const string RemediationPlanOperation = "RemediationPlan";

        /// <summary>
        /// Generates a cache key for security findings generation.
        /// </summary>
        /// <param name="statistics">Network statistics used for generation.</param>
        /// <param name="threats">List of security threats.</param>
        /// <returns>A deterministic cache key unique to the input parameters.</returns>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
        public string GenerateForSecurityFindings(NetworkStatistics statistics, List<SecurityThreat> threats)
        {
            ArgumentNullException.ThrowIfNull(statistics);
            ArgumentNullException.ThrowIfNull(threats);

            var contentBuilder = new StringBuilder();

            // Include statistics key properties
            contentBuilder.Append($"TotalPackets:{statistics.TotalPackets}|");
            contentBuilder.Append($"TotalBytes:{statistics.TotalBytes}|");
            contentBuilder.Append($"FirstPacket:{statistics.FirstPacketTime:O}|");
            contentBuilder.Append($"LastPacket:{statistics.LastPacketTime:O}|");

            // Include protocol distribution
            if (statistics.ProtocolStats is not null && statistics.ProtocolStats.Any())
            {
                var protocolHash = string.Join(";", statistics.ProtocolStats
                    .OrderBy(p => p.Key)
                    .Select(p => $"{p.Key}:{p.Value.PacketCount}"));
                contentBuilder.Append($"Protocols:{protocolHash}|");
            }

            // Include top ports
            if (statistics.TopPorts is not null && statistics.TopPorts.Any())
            {
                var portsHash = string.Join(";", statistics.TopPorts
                    .OrderBy(p => p.Port)
                    .Select(p => $"{p.Port}:{p.PacketCount}"));
                contentBuilder.Append($"Ports:{portsHash}|");
            }

            // Include threats summary
            contentBuilder.Append($"ThreatCount:{threats.Count}|");
            if (threats.Any())
            {
                // Group by type and severity for consistent hashing
                var threatHash = string.Join(";", threats
                    .GroupBy(t => new { t.Type, t.Severity })
                    .OrderBy(g => g.Key.Type)
                    .ThenBy(g => g.Key.Severity)
                    .Select(g => $"{g.Key.Type}:{g.Key.Severity}:{g.Count()}"));
                contentBuilder.Append($"Threats:{threatHash}|");
            }

            var content = contentBuilder.ToString();
            var hash = ComputeHash(content);

            return $"{ServicePrefix}:{SecurityFindingsOperation}:{hash}";
        }

        /// <summary>
        /// Generates a cache key for remediation plan generation.
        /// </summary>
        /// <param name="findings">Security findings used for planning.</param>
        /// <param name="recommendations">Recommendations list.</param>
        /// <returns>A deterministic cache key unique to the input parameters.</returns>
        /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
        public string GenerateForRemediationPlan(List<SecurityFinding> findings, List<Recommendation> recommendations)
        {
            ArgumentNullException.ThrowIfNull(findings);
            ArgumentNullException.ThrowIfNull(recommendations);

            var contentBuilder = new StringBuilder();

            // Include findings summary
            contentBuilder.Append($"FindingCount:{findings.Count}|");
            if (findings.Any())
            {
                // Group by severity and category for consistent hashing
                var findingsHash = string.Join(";", findings
                    .GroupBy(f => new { f.Severity, f.Category })
                    .OrderBy(g => g.Key.Severity)
                    .ThenBy(g => g.Key.Category)
                    .Select(g => $"{g.Key.Severity}:{g.Key.Category}:{g.Count()}:{g.Sum(f => f.RiskScore):F2}"));
                contentBuilder.Append($"Findings:{findingsHash}|");

                // Include finding IDs for uniqueness
                var findingIds = string.Join(";", findings.Select(f => f.FindingId).OrderBy(id => id));
                contentBuilder.Append($"FindingIds:{findingIds}|");
            }

            // Include recommendations summary
            contentBuilder.Append($"RecommendationCount:{recommendations.Count}|");
            if (recommendations.Any())
            {
                var recommendationsHash = string.Join(";", recommendations
                    .GroupBy(r => new { r.Priority, r.Category })
                    .OrderBy(g => g.Key.Priority)
                    .ThenBy(g => g.Key.Category)
                    .Select(g => $"{g.Key.Priority}:{g.Key.Category}:{g.Count()}"));
                contentBuilder.Append($"Recommendations:{recommendationsHash}|");
            }

            var content = contentBuilder.ToString();
            var hash = ComputeHash(content);

            return $"{ServicePrefix}:{RemediationPlanOperation}:{hash}";
        }

        /// <summary>
        /// Generates a generic cache key for any operation.
        /// Useful for custom caching scenarios not covered by specific methods.
        /// </summary>
        /// <param name="serviceName">Name of the service generating the cache key.</param>
        /// <param name="operation">Operation being cached.</param>
        /// <param name="parameters">Parameters that affect the operation result.</param>
        /// <returns>A deterministic cache key unique to the input parameters.</returns>
        /// <exception cref="ArgumentException">Thrown when required parameters are null or whitespace.</exception>
        public string GenerateGeneric(string serviceName, string operation, params object[] parameters)
        {
            if (string.IsNullOrWhiteSpace(serviceName))
                throw new ArgumentException("Service name cannot be null or whitespace", nameof(serviceName));
            if (string.IsNullOrWhiteSpace(operation))
                throw new ArgumentException("Operation cannot be null or whitespace", nameof(operation));

            var contentBuilder = new StringBuilder();
            contentBuilder.Append($"Service:{serviceName}|Operation:{operation}|");

            if (parameters is not null && parameters.Length > 0)
            {
                for (int i = 0; i < parameters.Length; i++)
                {
                    var param = parameters[i];
                    if (param is not null)
                    {
                        contentBuilder.Append($"Param{i}:{param}|");
                    }
                }
            }

            var content = contentBuilder.ToString();
            var hash = ComputeHash(content);

            return $"{ServicePrefix}:{serviceName}:{operation}:{hash}";
        }

        /// <summary>
        /// Computes a SHA256 hash of the input content.
        /// Returns a hex string representation of the hash.
        /// </summary>
        /// <param name="content">Content to hash.</param>
        /// <returns>Hex string representation of the SHA256 hash.</returns>
        private static string ComputeHash(string content)
        {
            using var sha256 = SHA256.Create();
            var bytes = Encoding.UTF8.GetBytes(content);
            var hashBytes = sha256.ComputeHash(bytes);

            // Convert to hex string (compact representation)
            var sb = new StringBuilder(hashBytes.Length * 2);
            foreach (var b in hashBytes)
            {
                sb.Append(b.ToString("X2"));
            }

            // Return first 16 characters for readability (still very low collision probability)
            return sb.ToString().Substring(0, 16);
        }

        /// <summary>
        /// Validates that a cache key follows the expected format.
        /// Useful for debugging and testing.
        /// </summary>
        /// <param name="key">Cache key to validate.</param>
        /// <returns>True if the key format is valid; otherwise, false.</returns>
        public static bool ValidateKeyFormat(string key)
        {
            if (string.IsNullOrWhiteSpace(key))
                return false;

            var parts = key.Split(':');
            return parts.Length >= 3 && parts[0] == ServicePrefix;
        }

        /// <summary>
        /// Extracts the operation name from a cache key.
        /// Returns null if the key format is invalid.
        /// </summary>
        /// <param name="key">Cache key.</param>
        /// <returns>Operation name or null if invalid.</returns>
        public static string? ExtractOperation(string key)
        {
            if (!ValidateKeyFormat(key))
                return null;

            var parts = key.Split(':');
            return parts.Length >= 2 ? parts[1] : null;
        }
    }
}
