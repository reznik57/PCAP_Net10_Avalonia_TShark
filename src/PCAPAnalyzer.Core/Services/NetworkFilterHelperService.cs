using PCAPAnalyzer.Core.Interfaces;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// DI-injectable service for network filtering and IP address classification.
/// Delegates to static NetworkFilterHelper for backward compatibility.
/// </summary>
public sealed class NetworkFilterHelperService : INetworkFilterHelper
{
    /// <inheritdoc />
    public bool IsRFC1918(string ipAddress) => NetworkFilterHelper.IsRFC1918(ipAddress);

    /// <inheritdoc />
    public bool IsMulticast(string ipAddress) => NetworkFilterHelper.IsMulticast(ipAddress);

    /// <inheritdoc />
    public bool IsBroadcast(string ipAddress) => NetworkFilterHelper.IsBroadcast(ipAddress);

    /// <inheritdoc />
    public bool IsAnycast(string ipAddress) => NetworkFilterHelper.IsAnycast(ipAddress);

    /// <inheritdoc />
    public bool IsLinkLocal(string ipAddress) => NetworkFilterHelper.IsLinkLocal(ipAddress);

    /// <inheritdoc />
    public bool IsLoopback(string ipAddress) => NetworkFilterHelper.IsLoopback(ipAddress);

    /// <inheritdoc />
    public bool IsPublicIP(string ipAddress) => NetworkFilterHelper.IsPublicIP(ipAddress);

    /// <inheritdoc />
    public bool IsReserved(string ipAddress) => NetworkFilterHelper.IsReserved(ipAddress);

    /// <inheritdoc />
    public bool IsIPv4(string ipAddress) => NetworkFilterHelper.IsIPv4(ipAddress);

    /// <inheritdoc />
    public bool IsIPv6(string ipAddress) => NetworkFilterHelper.IsIPv6(ipAddress);

    /// <inheritdoc />
    public bool IsIPv6LinkLocal(string ipAddress) => NetworkFilterHelper.IsIPv6LinkLocal(ipAddress);

    /// <inheritdoc />
    public bool IsIPv6UniqueLocal(string ipAddress) => NetworkFilterHelper.IsIPv6UniqueLocal(ipAddress);

    /// <inheritdoc />
    public bool IsInCidr(string ipAddress, string cidr) => NetworkFilterHelper.IsInCidr(ipAddress, cidr);

    /// <inheritdoc />
    public bool IsInsecurePort(int port) => NetworkFilterHelper.IsInsecurePort(port);

    /// <inheritdoc />
    public bool IsInsecureProtocol(string protocol) => NetworkFilterHelper.IsInsecureProtocol(protocol);

    /// <inheritdoc />
    public bool IsAnomaly(string info) => NetworkFilterHelper.IsAnomaly(info);

    /// <inheritdoc />
    public bool IsSuspiciousTraffic(string sourceIp, string destIp, int sourcePort, int destPort, string info)
        => NetworkFilterHelper.IsSuspiciousTraffic(sourceIp, destIp, sourcePort, destPort, info);
}
