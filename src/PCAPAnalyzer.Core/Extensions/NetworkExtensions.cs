using PCAPAnalyzer.Core.Services;

namespace PCAPAnalyzer.Core.Extensions;

/// <summary>
/// C# 14-ready extension methods for IP address and port validation.
/// Provides fluent syntax for network-related checks.
/// </summary>
public static class NetworkExtensions
{
    #region IP Address Extensions

    /// <summary>
    /// Checks if IP address is within the specified CIDR range.
    /// Example: "192.168.1.100".IsInCidrRange("192.168.1.0/24") → true
    /// </summary>
    public static bool IsInCidrRange(this string ipAddress, string cidrNotation) =>
        NetworkHelper.IsInCidrRange(ipAddress, cidrNotation);

    /// <summary>
    /// Checks if IP matches pattern (supports single IP, CIDR, or partial match).
    /// Example: "192.168.1.100".MatchesPattern("192.168.") → true
    /// </summary>
    public static bool MatchesIpPattern(this string ipAddress, string pattern) =>
        NetworkHelper.MatchesIpPattern(ipAddress, pattern);

    #endregion

    #region Port Extensions

    /// <summary>
    /// Checks if port matches pattern (supports single port, range, or comma-separated list).
    /// Examples:
    ///   443.MatchesPattern("443") → true
    ///   8080.MatchesPattern("8000-9000") → true
    ///   80.MatchesPattern("22,80,443") → true
    /// </summary>
    public static bool MatchesPortPattern(this int port, string pattern) =>
        NetworkHelper.MatchesPortPattern(port, pattern);

    /// <summary>
    /// Checks if port is in the specified range (inclusive).
    /// </summary>
    public static bool IsInRange(this int port, int minPort, int maxPort) =>
        port >= minPort && port <= maxPort;

    /// <summary>
    /// Checks if port is a well-known port (0-1023).
    /// </summary>
    public static bool IsWellKnownPort(this int port) =>
        port >= 0 && port <= 1023;

    /// <summary>
    /// Checks if port is a registered port (1024-49151).
    /// </summary>
    public static bool IsRegisteredPort(this int port) =>
        port >= 1024 && port <= 49151;

    /// <summary>
    /// Checks if port is a dynamic/ephemeral port (49152-65535).
    /// </summary>
    public static bool IsEphemeralPort(this int port) =>
        port >= 49152 && port <= 65535;

    #endregion

    #region CIDR Validation

    /// <summary>
    /// Validates if string is a valid CIDR notation.
    /// </summary>
    public static bool IsValidCidr(this string cidr) =>
        NetworkHelper.IsValidCidr(cidr);

    #endregion
}
