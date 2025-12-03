using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.UI.Helpers;

/// <summary>
/// Static helper methods for threat display, mapping, and service name resolution.
/// Extracted from ThreatsViewModel to reduce file size.
/// </summary>
public static class ThreatDisplayHelpers
{
    /// <summary>
    /// Gets severity color for UI display
    /// </summary>
    public static string GetSeverityColor(ThreatSeverity severity)
    {
        return severity switch
        {
            ThreatSeverity.Critical => "#EF4444",
            ThreatSeverity.High => "#F97316",
            ThreatSeverity.Medium => "#F59E0B",
            ThreatSeverity.Low => "#3B82F6",
            ThreatSeverity.Info => "#6B7280",
            _ => "#6B7280"
        };
    }

    /// <summary>
    /// Maps anomaly severity to threat severity
    /// </summary>
    public static ThreatSeverity MapAnomalySeverity(AnomalySeverity anomalySeverity)
    {
        return anomalySeverity switch
        {
            AnomalySeverity.Critical => ThreatSeverity.Critical,
            AnomalySeverity.High => ThreatSeverity.High,
            AnomalySeverity.Medium => ThreatSeverity.Medium,
            AnomalySeverity.Low => ThreatSeverity.Low,
            _ => ThreatSeverity.Info
        };
    }

    /// <summary>
    /// Maps anomaly category to threat category
    /// </summary>
    public static ThreatCategory MapAnomalyCategory(AnomalyCategory anomalyCategory)
    {
        return anomalyCategory switch
        {
            AnomalyCategory.Network => ThreatCategory.MaliciousActivity,
            AnomalyCategory.TCP => ThreatCategory.MaliciousActivity,
            AnomalyCategory.Application => ThreatCategory.MaliciousActivity,
            AnomalyCategory.Security => ThreatCategory.KnownVulnerability,
            AnomalyCategory.Malformed => ThreatCategory.MaliciousActivity,
            _ => ThreatCategory.MaliciousActivity
        };
    }

    /// <summary>
    /// Maps common ports to service names for credential threat display.
    /// </summary>
    public static string GetServiceName(ushort port) => port switch
    {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        161 => "SNMP",
        389 => "LDAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        587 => "SMTP",
        636 => "LDAPS",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        8080 => "HTTP-ALT",
        8443 => "HTTPS-ALT",
        _ => $"Port {port}"
    };
}
