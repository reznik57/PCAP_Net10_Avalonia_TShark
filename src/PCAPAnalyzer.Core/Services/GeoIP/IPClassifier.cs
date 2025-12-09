using System.Net;
using System.Net.Sockets;

namespace PCAPAnalyzer.Core.Services.GeoIP;

/// <summary>
/// Classifies IP addresses by type (public, private, IPv6 variants).
/// Extracted from UnifiedGeoIPService to reduce complexity and enable reuse.
/// </summary>
public static class IPClassifier
{
    /// <summary>
    /// Determines if an IP address is public (routable on the internet).
    /// </summary>
    public static bool IsPublicIP(string? ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            return false;

        if (!IPAddress.TryParse(ipAddress, out var ip))
            return false;

        // IPv6 checks
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = ip.GetAddressBytes();

            // Link-local (fe80::/10)
            if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
                return false;

            // Unique local (fc00::/7)
            if ((bytes[0] & 0xfe) == 0xfc)
                return false;

            // Loopback (::1)
            if (ip.Equals(IPAddress.IPv6Loopback))
                return false;

            return true;
        }

        // IPv4 checks
        byte[] bytes4 = ip.GetAddressBytes();
        if (bytes4.Length != 4)
            return false;

        // Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if (bytes4[0] == 10) return false;
        if (bytes4[0] == 172 && bytes4[1] >= 16 && bytes4[1] <= 31) return false;
        if (bytes4[0] == 192 && bytes4[1] == 168) return false;

        // Loopback: 127.0.0.0/8
        if (bytes4[0] == 127) return false;

        // Link-local: 169.254.0.0/16
        if (bytes4[0] == 169 && bytes4[1] == 254) return false;

        // Multicast: 224.0.0.0/4
        if (bytes4[0] >= 224 && bytes4[0] <= 239) return false;

        return true;
    }

    /// <summary>
    /// Classifies non-public IPs with comprehensive IPv6 type detection.
    /// Returns pseudo-country codes: "Internal", "IP6_LINK", "IP6_LOOP", etc.
    /// Returns null for invalid IPs.
    /// </summary>
    public static string? ClassifyNonPublicIP(string? ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            return null;

        if (!IPAddress.TryParse(ipAddress, out var ip))
            return null;

        // IPv6 Classification
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return ClassifyIPv6(ip);
        }

        // IPv4 Classification
        return ClassifyIPv4(ip);
    }

    /// <summary>
    /// Classifies IPv6 addresses into specific types.
    /// </summary>
    public static string ClassifyIPv6(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();

        // 1. Loopback (::1)
        if (ip.Equals(IPAddress.IPv6Loopback))
            return "IP6_LOOP";

        // 2. Link-Local (fe80::/10)
        if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80)
            return "IP6_LINK";

        // 3. Multicast (ff00::/8)
        if (bytes[0] == 0xff)
            return "IP6_MCAST";

        // 4. Unique Local Address - ULA (fc00::/7, primarily fd00::/8 in practice)
        if ((bytes[0] & 0xfe) == 0xfc)
            return "IP6_ULA";

        // 5. Site-Local (fec0::/10 - deprecated per RFC 3879)
        if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0xc0)
            return "IP6_SITE";

        // 6. IPv4-mapped IPv6 (::ffff:0:0/96)
        if (bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 &&
            bytes[4] == 0 && bytes[5] == 0 && bytes[6] == 0 && bytes[7] == 0 &&
            bytes[8] == 0 && bytes[9] == 0 && bytes[10] == 0xff && bytes[11] == 0xff)
        {
            // Extract IPv4 part and reclassify
            var ipv4Address = new IPAddress(new byte[] { bytes[12], bytes[13], bytes[14], bytes[15] });
            return ClassifyIPv4(ipv4Address);
        }

        // 7. Global Unicast (2000::/3)
        if ((bytes[0] & 0xe0) == 0x20)
            return "IP6_GLOBAL";

        // 8. Other IPv6 (documentation, 6to4, Teredo, etc.)
        return "IP6";
    }

    /// <summary>
    /// Classifies IPv4 addresses as Internal or other type.
    /// </summary>
    public static string ClassifyIPv4(IPAddress ip)
    {
        byte[] bytes = ip.GetAddressBytes();
        if (bytes.Length != 4)
            return "Internal";

        // Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if (bytes[0] == 10)
            return "Internal";

        if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            return "Internal";

        if (bytes[0] == 192 && bytes[1] == 168)
            return "Internal";

        // Loopback: 127.0.0.0/8
        if (bytes[0] == 127)
            return "Internal";

        // Link-local: 169.254.0.0/16
        if (bytes[0] == 169 && bytes[1] == 254)
            return "Internal";

        // Multicast: 224.0.0.0/4
        if (bytes[0] >= 224 && bytes[0] <= 239)
            return "Internal";

        // Broadcast: 255.255.255.255
        if (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255)
            return "Internal";

        // Default: Internal (shouldn't reach here for public IPs)
        return "Internal";
    }
}
