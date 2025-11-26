using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;

namespace PCAPAnalyzer.UI.ViewModels;

/// <summary>
/// DashboardViewModel partial - Smart Filter Helper Methods
/// Delegates to centralized NetworkFilterHelper for consistency.
/// </summary>
public partial class DashboardViewModel
{
    // ==================== SMART FILTER HELPER METHODS ====================
    // All methods delegate to centralized NetworkFilterHelper for consistency

    private static bool IsRFC1918(string ip) => NetworkFilterHelper.IsRFC1918(ip);

    private static bool IsPrivateIP(string ip) =>
        NetworkFilterHelper.IsRFC1918(ip) ||
        NetworkFilterHelper.IsLoopback(ip) ||
        NetworkFilterHelper.IsLinkLocal(ip);

    private static bool IsAPIPA(string ip) => NetworkFilterHelper.IsLinkLocal(ip);

    private static bool IsIPv4(string ip) => NetworkFilterHelper.IsIPv4(ip);

    private static bool IsIPv6(string ip) => NetworkFilterHelper.IsIPv6(ip);

    private static bool IsMulticast(string ip) => NetworkFilterHelper.IsMulticast(ip);

    private static bool IsBroadcast(string ip) => NetworkFilterHelper.IsBroadcast(ip);

    private static bool IsAnycast(string ip) => NetworkFilterHelper.IsAnycast(ip);

    private static bool IsInsecureProtocol(PacketInfo p) =>
        NetworkFilterHelper.IsInsecureProtocol(p.L7Protocol ?? p.Protocol.ToString());
}
