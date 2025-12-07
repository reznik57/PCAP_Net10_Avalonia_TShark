using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Security;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Service implementation of protocol security evaluator.
/// Delegates to static ProtocolSecurityEvaluator for backward compatibility during migration.
/// Future enhancement: Load vulnerability database from config or external source via DI.
/// </summary>
public sealed class ProtocolSecurityEvaluatorService : IProtocolSecurityEvaluator
{
    /// <summary>
    /// Evaluates the security level of a protocol based on its name and optional port.
    /// </summary>
    /// <param name="protocolName">Protocol name (e.g., "TLS", "HTTP", "SSLv3")</param>
    /// <param name="port">Optional port number for additional context</param>
    /// <returns>Security assessment with level, reason, vulnerabilities, and recommendations</returns>
    public ProtocolSecurityEvaluator.SecurityAssessment EvaluateProtocol(string? protocolName, ushort? port = null)
    {
        return ProtocolSecurityEvaluator.EvaluateProtocol(protocolName, port);
    }

    /// <summary>
    /// Gets a human-readable string representation of a security level.
    /// </summary>
    /// <param name="level">Security level to convert</param>
    /// <returns>String representation (e.g., "Secure", "Critical")</returns>
    public string GetSecurityLevelString(ProtocolSecurityEvaluator.SecurityLevel level)
    {
        return ProtocolSecurityEvaluator.GetSecurityLevelString(level);
    }

    /// <summary>
    /// Gets the color code for a security level (for UI display).
    /// </summary>
    /// <param name="level">Security level</param>
    /// <returns>Hex color code (e.g., "#4CAF50" for Secure)</returns>
    public string GetSecurityLevelColor(ProtocolSecurityEvaluator.SecurityLevel level)
    {
        return ProtocolSecurityEvaluator.GetSecurityLevelColor(level);
    }
}
