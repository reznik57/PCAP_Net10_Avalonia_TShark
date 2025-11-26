namespace PCAPAnalyzer.Core.Interfaces;

/// <summary>
/// Service for network filtering and IP address classification.
/// Provides methods to identify IP address types, detect insecure protocols/ports,
/// and check for network anomalies.
/// </summary>
public interface INetworkFilterHelper
{
    // ==================== IP ADDRESS CLASSIFICATION ====================

    /// <summary>
    /// Checks if IP is in RFC1918 private address space (10.x, 172.16-31.x, 192.168.x).
    /// </summary>
    bool IsRFC1918(string ipAddress);

    /// <summary>
    /// Checks if IP is a multicast address (224.0.0.0/4 or IPv6 ff00::/8).
    /// </summary>
    bool IsMulticast(string ipAddress);

    /// <summary>
    /// Checks if IP is a broadcast address (255.255.255.255 or subnet broadcast).
    /// </summary>
    bool IsBroadcast(string ipAddress);

    /// <summary>
    /// Checks if IP is a known anycast address (common DNS servers).
    /// </summary>
    bool IsAnycast(string ipAddress);

    /// <summary>
    /// Checks if IP is link-local (169.254.x.x / APIPA).
    /// </summary>
    bool IsLinkLocal(string ipAddress);

    /// <summary>
    /// Checks if IP is loopback (127.x.x.x or ::1).
    /// </summary>
    bool IsLoopback(string ipAddress);

    /// <summary>
    /// Checks if IP is a public (routable) address.
    /// </summary>
    bool IsPublicIP(string ipAddress);

    /// <summary>
    /// Checks if IP is reserved (TEST-NET, documentation, shared address space).
    /// </summary>
    bool IsReserved(string ipAddress);

    // ==================== IPv4/IPv6 DETECTION ====================

    /// <summary>
    /// Checks if address is IPv4.
    /// </summary>
    bool IsIPv4(string ipAddress);

    /// <summary>
    /// Checks if address is IPv6.
    /// </summary>
    bool IsIPv6(string ipAddress);

    /// <summary>
    /// Checks if IPv6 address is link-local (fe80::/10).
    /// </summary>
    bool IsIPv6LinkLocal(string ipAddress);

    /// <summary>
    /// Checks if IPv6 address is unique local (fc00::/7).
    /// </summary>
    bool IsIPv6UniqueLocal(string ipAddress);

    // ==================== CIDR MATCHING ====================

    /// <summary>
    /// Checks if IP address is within a CIDR range.
    /// </summary>
    bool IsInCidr(string ipAddress, string cidr);

    // ==================== SECURITY CHECKS ====================

    /// <summary>
    /// Checks if port is associated with an insecure protocol.
    /// </summary>
    bool IsInsecurePort(int port);

    /// <summary>
    /// Checks if protocol name indicates an insecure protocol.
    /// </summary>
    bool IsInsecureProtocol(string protocol);

    /// <summary>
    /// Checks if packet info contains anomaly indicators.
    /// </summary>
    bool IsAnomaly(string info);

    /// <summary>
    /// Checks for suspicious traffic patterns (port scanning, external-to-internal).
    /// </summary>
    bool IsSuspiciousTraffic(string sourceIp, string destIp, int sourcePort, int destPort, string info);
}
