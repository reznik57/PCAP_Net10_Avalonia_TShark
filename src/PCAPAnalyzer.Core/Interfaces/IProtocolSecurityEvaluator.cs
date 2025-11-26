using PCAPAnalyzer.Core.Security;

namespace PCAPAnalyzer.Core.Interfaces;

/// <summary>
/// Interface for protocol security evaluation service.
/// Evaluates protocol security based on protocol name, version, and known vulnerabilities.
/// Replaces static ProtocolSecurityEvaluator class with dependency injection pattern.
/// </summary>
public interface IProtocolSecurityEvaluator
{
    /// <summary>
    /// Evaluates the security level of a protocol based on its name and optional port.
    /// </summary>
    /// <param name="protocolName">Protocol name (e.g., "TLS", "HTTP", "SSLv3")</param>
    /// <param name="port">Optional port number for additional context</param>
    /// <returns>Security assessment with level, reason, vulnerabilities, and recommendations</returns>
    ProtocolSecurityEvaluator.SecurityAssessment EvaluateProtocol(string? protocolName, ushort? port = null);

    /// <summary>
    /// Gets a human-readable string representation of a security level.
    /// </summary>
    /// <param name="level">Security level to convert</param>
    /// <returns>String representation (e.g., "Secure", "Critical")</returns>
    string GetSecurityLevelString(ProtocolSecurityEvaluator.SecurityLevel level);

    /// <summary>
    /// Gets the color code for a security level (for UI display).
    /// </summary>
    /// <param name="level">Security level</param>
    /// <returns>Hex color code (e.g., "#4CAF50" for Secure)</returns>
    string GetSecurityLevelColor(ProtocolSecurityEvaluator.SecurityLevel level);
}
