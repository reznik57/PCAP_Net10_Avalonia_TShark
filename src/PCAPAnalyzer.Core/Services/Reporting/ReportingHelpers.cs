using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.Reporting
{
    /// <summary>
    /// Shared helper methods and data for report generation services.
    /// Provides common utilities for formatting, IP analysis, port classification, and compliance mapping.
    /// </summary>
    public static class ReportingHelpers
    {
        #region Insecure Ports Database

        /// <summary>
        /// Database of insecure ports and their security implications.
        /// Used for identifying security risks in network traffic.
        /// </summary>
        public static readonly Dictionary<int, string> InsecurePortDatabase = new()
        {
            { 21, "FTP (Unencrypted file transfer)" },
            { 23, "Telnet (Unencrypted remote access)" },
            { 25, "SMTP (Unencrypted email transmission)" },
            { 69, "TFTP (Trivial File Transfer Protocol - very insecure)" },
            { 80, "HTTP (Unencrypted web traffic)" },
            { 110, "POP3 (Unencrypted email retrieval)" },
            { 139, "NetBIOS (Legacy, security risk)" },
            { 143, "IMAP (Unencrypted email access)" },
            { 161, "SNMP (Network management - often misconfigured)" },
            { 389, "LDAP (Unencrypted directory access)" },
            { 445, "SMB (File sharing - frequent attack vector)" },
            { 512, "rexec (Remote execution - very insecure)" },
            { 513, "rlogin (Remote login - very insecure)" },
            { 514, "rsh (Remote shell - very insecure)" },
            { 1433, "MSSQL (Database - should use encrypted connections)" },
            { 1521, "Oracle DB (Database - should use encrypted connections)" },
            { 3306, "MySQL (Database - should use encrypted connections)" },
            { 5432, "PostgreSQL (Database - should use encrypted connections)" },
            { 5900, "VNC (Remote desktop - often unencrypted)" },
            { 6379, "Redis (Database - often exposed without auth)" },
            { 8080, "HTTP Alternate (Unencrypted web traffic)" },
            { 9200, "Elasticsearch (Often exposed without auth)" },
            { 11211, "Memcached (Cache server - often exposed)" },
            { 27017, "MongoDB (Database - often exposed without auth)" },
            { 50000, "SAP (Enterprise software - security sensitive)" }
        };

        #endregion

        #region Compliance Standards

        /// <summary>
        /// Compliance standards and their descriptions.
        /// Used for mapping security findings to regulatory requirements.
        /// </summary>
        public static readonly Dictionary<string, string> ComplianceStandards = new()
        {
            { "PCI-DSS", "Payment Card Industry Data Security Standard - Required for handling credit card data" },
            { "HIPAA", "Health Insurance Portability and Accountability Act - Required for healthcare data" },
            { "GDPR", "General Data Protection Regulation - Required for EU personal data processing" },
            { "SOX", "Sarbanes-Oxley Act - Required for public company financial reporting" },
            { "NIST", "National Institute of Standards and Technology Cybersecurity Framework" }
        };

        #endregion

        #region Formatting Helpers

        /// <summary>
        /// Formats byte count into human-readable string (B, KB, MB, GB, TB).
        /// </summary>
        public static string FormatBytes(long bytes)
        {
            string[] suffixes = { "B", "KB", "MB", "GB", "TB" };
            int suffixIndex = 0;
            double value = bytes;

            while (value >= 1024 && suffixIndex < suffixes.Length - 1)
            {
                value /= 1024;
                suffixIndex++;
            }

            return string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0:N2} {1}", value, suffixes[suffixIndex]);
        }

        /// <summary>
        /// Formats packet count into human-readable string (K, M, B).
        /// </summary>
        public static string FormatPacketCount(long count)
        {
            if (count >= 1_000_000_000)
                return string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0:N2}B", count / 1_000_000_000.0);
            if (count >= 1_000_000)
                return string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0:N2}M", count / 1_000_000.0);
            if (count >= 1_000)
                return string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0:N2}K", count / 1_000.0);
            return count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        /// <summary>
        /// Formats duration into standardized seconds format (e.g., "14.1s").
        /// Consistent with application-wide time display standard.
        /// </summary>
        public static string FormatDuration(TimeSpan duration)
        {
            return string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0:F1}s", duration.TotalSeconds);
        }

        /// <summary>
        /// Formats percentage with appropriate decimal places.
        /// </summary>
        public static string FormatPercentage(double value)
        {
            if (value < 0.01)
                return string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0:F3}%", value * 100);
            if (value < 0.1)
                return string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0:F2}%", value * 100);
            return string.Format(System.Globalization.CultureInfo.InvariantCulture, "{0:F1}%", value * 100);
        }

        #endregion

        #region IP Analysis

        /// <summary>
        /// Determines if an IP address is private (RFC 1918).
        /// Delegates to PrivateNetworkHandler for comprehensive IPv4/IPv6 support.
        /// </summary>
        public static bool IsPrivateIP(string ip) => PrivateNetworkHandler.IsPrivateIP(ip);

        /// <summary>
        /// Classifies IP type (Public, Private, Loopback, Link-Local, Multicast).
        /// </summary>
        public static string GetIPType(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
                return "Unknown";

            var parts = ip.Split('.');
            if (parts.Length != 4)
                return "Invalid";

            // Validate all octets are valid integers in range 0-255
            for (int i = 0; i < 4; i++)
            {
                if (!int.TryParse(parts[i], out int octet) || octet < 0 || octet > 255)
                    return "Invalid";
            }

            // Now we can safely use the first octet (already validated)
            int firstOctet = int.Parse(parts[0]);

            if (firstOctet == 127)
                return "Loopback";
            if (firstOctet == 169)
                return "Link-Local";
            if (firstOctet >= 224 && firstOctet <= 239)
                return "Multicast";
            if (IsPrivateIP(ip))
                return "Private";

            return "Public";
        }

        #endregion

        #region Port Classification

        /// <summary>
        /// Gets service name for a port number.
        /// </summary>
        public static string GetServiceName(int port)
        {
            return port switch
            {
                20 => "FTP-DATA",
                21 => "FTP",
                22 => "SSH",
                23 => "Telnet",
                25 => "SMTP",
                53 => "DNS",
                67 => "DHCP",
                68 => "DHCP",
                69 => "TFTP",
                80 => "HTTP",
                110 => "POP3",
                123 => "NTP",
                137 => "NetBIOS",
                138 => "NetBIOS",
                139 => "NetBIOS",
                143 => "IMAP",
                161 => "SNMP",
                162 => "SNMP-Trap",
                389 => "LDAP",
                443 => "HTTPS",
                445 => "SMB",
                465 => "SMTPS",
                514 => "Syslog",
                587 => "SMTP-Submit",
                636 => "LDAPS",
                993 => "IMAPS",
                995 => "POP3S",
                1433 => "MSSQL",
                1521 => "Oracle",
                3306 => "MySQL",
                3389 => "RDP",
                5432 => "PostgreSQL",
                5900 => "VNC",
                6379 => "Redis",
                8080 => "HTTP-Alt",
                8443 => "HTTPS-Alt",
                9200 => "Elasticsearch",
                11211 => "Memcached",
                27017 => "MongoDB",
                _ => port < 1024 ? "System Port" : port < 49152 ? "Registered Port" : "Dynamic Port"
            };
        }

        /// <summary>
        /// Determines if a port is considered insecure.
        /// </summary>
        public static bool IsInsecurePort(int port)
        {
            return InsecurePortDatabase.ContainsKey(port);
        }

        /// <summary>
        /// Gets the security implication description for an insecure port.
        /// </summary>
        public static string GetInsecurePortDescription(int port)
        {
            return InsecurePortDatabase.TryGetValue(port, out var description)
                ? description
                : "Unknown security risk";
        }

        #endregion

        #region Severity Mapping

        /// <summary>
        /// Maps threat severity to numeric priority (1-5, lower is more severe).
        /// </summary>
        public static int GetSeverityPriority(string severity)
        {
            return severity?.ToUpperInvariant() switch
            {
                "CRITICAL" => 1,
                "HIGH" => 2,
                "MEDIUM" => 3,
                "LOW" => 4,
                "INFO" => 5,
                _ => 6
            };
        }

        /// <summary>
        /// Gets CSS class for severity badge styling.
        /// </summary>
        public static string GetSeverityCssClass(string severity)
        {
            return severity?.ToUpperInvariant() switch
            {
                "CRITICAL" => "badge-critical",
                "HIGH" => "badge-high",
                "MEDIUM" => "badge-medium",
                "LOW" => "badge-low",
                "INFO" => "badge-info",
                _ => "badge-unknown"
            };
        }

        /// <summary>
        /// Gets color code for severity visualization.
        /// </summary>
        public static string GetSeverityColor(string severity)
        {
            return severity?.ToUpperInvariant() switch
            {
                "CRITICAL" => "#dc3545",  // Red
                "HIGH" => "#fd7e14",      // Orange
                "MEDIUM" => "#ffc107",    // Yellow
                "LOW" => "#28a745",       // Green
                "INFO" => "#17a2b8",      // Blue
                _ => "#6c757d"            // Gray
            };
        }

        #endregion

        #region Anomaly Classification

        /// <summary>
        /// Classifies anomaly type based on description.
        /// </summary>
        public static string ClassifyAnomalyType(string description)
        {
            if (string.IsNullOrWhiteSpace(description))
                return "Unknown";

            var desc = description.ToLowerInvariant();

            if (desc.Contains("port scan", StringComparison.Ordinal) || desc.Contains("scanning", StringComparison.Ordinal))
                return "Port Scanning";
            if (desc.Contains("ddos", StringComparison.Ordinal) || desc.Contains("denial of service", StringComparison.Ordinal))
                return "DDoS Attack";
            if (desc.Contains("exfiltration", StringComparison.Ordinal) || desc.Contains("data leak", StringComparison.Ordinal))
                return "Data Exfiltration";
            if (desc.Contains("brute force", StringComparison.Ordinal) || desc.Contains("authentication", StringComparison.Ordinal))
                return "Brute Force";
            if (desc.Contains("malware", StringComparison.Ordinal) || desc.Contains("trojan", StringComparison.Ordinal))
                return "Malware";
            if (desc.Contains("crypto", StringComparison.Ordinal) || desc.Contains("mining", StringComparison.Ordinal))
                return "Crypto Mining";
            if (desc.Contains("iot", StringComparison.Ordinal) || desc.Contains("device", StringComparison.Ordinal))
                return "IoT Anomaly";
            if (desc.Contains("voip", StringComparison.Ordinal) || desc.Contains("sip", StringComparison.Ordinal))
                return "VoIP Anomaly";
            if (desc.Contains("unusual protocol", StringComparison.Ordinal))
                return "Protocol Anomaly";
            if (desc.Contains("large packet", StringComparison.Ordinal) || desc.Contains("oversized", StringComparison.Ordinal))
                return "Traffic Anomaly";

            return "General Anomaly";
        }

        #endregion

        #region Report Metadata

        /// <summary>
        /// Generates unique report ID based on timestamp.
        /// </summary>
        public static string GenerateReportId()
        {
            return $"RPT-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString()[..8].ToUpperInvariant()}";
        }

        /// <summary>
        /// Gets report classification based on findings severity.
        /// </summary>
        public static string GetReportClassification(IEnumerable<SecurityFinding> findings)
        {
            if (!findings.Any())
                return "INFORMATIONAL";

            var hasCritical = findings.Any(f => f.Severity.Equals(SeverityLevel.Critical));
            var hasHigh = findings.Any(f => f.Severity.Equals(SeverityLevel.High));

            if (hasCritical)
                return "CRITICAL - IMMEDIATE ACTION REQUIRED";
            if (hasHigh)
                return "HIGH - URGENT ATTENTION NEEDED";

            return "MODERATE - REVIEW RECOMMENDED";
        }

        #endregion
    }
}
