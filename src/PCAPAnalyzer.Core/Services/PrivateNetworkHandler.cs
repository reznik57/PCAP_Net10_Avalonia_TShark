using System;
using System.Net;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services
{
    public static class PrivateNetworkHandler
    {
        // Private network ranges
        private static readonly List<(IPAddress start, IPAddress end)> PrivateRanges = new()
        {
            // 10.0.0.0/8
            (IPAddress.Parse("10.0.0.0"), IPAddress.Parse("10.255.255.255")),
            // 172.16.0.0/12
            (IPAddress.Parse("172.16.0.0"), IPAddress.Parse("172.31.255.255")),
            // 192.168.0.0/16
            (IPAddress.Parse("192.168.0.0"), IPAddress.Parse("192.168.255.255")),
            // 169.254.0.0/16 (Link-local)
            (IPAddress.Parse("169.254.0.0"), IPAddress.Parse("169.254.255.255")),
            // 127.0.0.0/8 (Loopback)
            (IPAddress.Parse("127.0.0.0"), IPAddress.Parse("127.255.255.255")),
            // fc00::/7 (IPv6 Unique local)
            // fe80::/10 (IPv6 Link-local)
        };

        public static bool IsPrivateIP(string? ip)
        {
            if (string.IsNullOrEmpty(ip)) return false;
            
            if (IPAddress.TryParse(ip, out var ipAddr))
            {
                // Check IPv4 private ranges
                if (ipAddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    var bytes = ipAddr.GetAddressBytes();
                    var ipNum = BitConverter.ToUInt32(bytes.Reverse().ToArray(), 0);
                    
                    foreach (var range in PrivateRanges)
                    {
                        var startBytes = range.start.GetAddressBytes();
                        var endBytes = range.end.GetAddressBytes();
                        var startNum = BitConverter.ToUInt32(startBytes.Reverse().ToArray(), 0);
                        var endNum = BitConverter.ToUInt32(endBytes.Reverse().ToArray(), 0);
                        
                        if (ipNum >= startNum && ipNum <= endNum)
                            return true;
                    }
                }
                // Check IPv6 private ranges
                else if (ipAddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    var ipString = ipAddr.ToString();
                    // Check for IPv6 private addresses
                    if (ipString.StartsWith("fc", StringComparison.Ordinal) || ipString.StartsWith("fd", StringComparison.Ordinal) || // Unique local
                        ipString.StartsWith("fe80", StringComparison.Ordinal) || // Link-local
                        ipString.StartsWith("::1", StringComparison.Ordinal) || // Loopback
                        ipString == "::") // Unspecified
                    {
                        return true;
                    }
                }
            }
            
            return false;
        }
        
        public static CountryTrafficStatistics CreatePrivateNetworkStatistics(long packets, long bytes)
        {
            return new CountryTrafficStatistics
            {
                CountryCode = "PRV",
                CountryName = "Private Networks",
                TotalPackets = packets,
                TotalBytes = bytes,
                UniqueIPs = new HashSet<string>(),
                IsHighRisk = false,
                Percentage = 0 // Will be calculated by the caller
            };
        }
    }
}