using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Utilities;

namespace PCAPAnalyzer.UI.Helpers;

/// <summary>
/// Static helper methods for threat display, mapping, and service name resolution.
/// Extracted from ThreatsViewModel to reduce file size.
/// </summary>
public static class ThreatDisplayHelpers
{
    /// <summary>
    /// Gets severity color for ThreatSeverity (from theme resources)
    /// </summary>
    public static string GetSeverityColor(ThreatSeverity severity)
    {
        return ThemeColorHelper.GetThreatSeverityColorHex(severity.ToString());
    }

    /// <summary>
    /// Gets severity color for AnomalySeverity (from theme resources)
    /// </summary>
    public static string GetSeverityColor(AnomalySeverity severity)
    {
        return ThemeColorHelper.GetThreatSeverityColorHex(severity.ToString());
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
    /// Uses PortDatabase for comprehensive lookup, falls back to common ports.
    /// </summary>
    public static string GetServiceName(ushort port) =>
        Core.Security.PortDatabase.GetServiceName(port, true) ?? $"Port {port}";

    /// <summary>
    /// Maps common ports to service names (int overload for convenience).
    /// </summary>
    public static string GetServiceName(int port) =>
        port >= 0 && port <= 65535
            ? GetServiceName((ushort)port)
            : $"Port {port}";
}
