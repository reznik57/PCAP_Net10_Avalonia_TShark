using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;

namespace PCAPAnalyzer.Core.Services
{
    public static class NetworkHelper
    {
        /// <summary>
        /// Check if an IP address matches a CIDR notation (e.g., 192.168.1.0/24)
        /// </summary>
        public static bool IsInCidrRange(string ipAddress, string cidrNotation)
        {
            if (string.IsNullOrWhiteSpace(ipAddress) || string.IsNullOrWhiteSpace(cidrNotation))
                return false;

            try
            {
                // Split CIDR notation into IP and prefix length
                var parts = cidrNotation.Split('/');
                if (parts.Length != 2)
                    return false;

                var networkAddress = IPAddress.Parse(parts[0]);
                if (!int.TryParse(parts[1], out var prefixLength))
                    return false;

                var testAddress = IPAddress.Parse(ipAddress);

                // Ensure both are the same address family
                if (networkAddress.AddressFamily != testAddress.AddressFamily)
                    return false;

                // Convert to bytes for comparison
                var networkBytes = networkAddress.GetAddressBytes();
                var testBytes = testAddress.GetAddressBytes();

                // Calculate the number of full bytes and remaining bits
                var fullBytes = prefixLength / 8;
                var remainingBits = prefixLength % 8;

                // Check full bytes
                for (int i = 0; i < fullBytes; i++)
                {
                    if (networkBytes[i] != testBytes[i])
                        return false;
                }

                // Check remaining bits if any
                if (remainingBits > 0 && fullBytes < networkBytes.Length)
                {
                    var mask = (byte)(0xFF << (8 - remainingBits));
                    if ((networkBytes[fullBytes] & mask) != (testBytes[fullBytes] & mask))
                        return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Check if IP matches pattern (supports single IP, CIDR, or partial match)
        /// </summary>
        public static bool MatchesIpPattern(string ipAddress, string pattern)
        {
            if (string.IsNullOrWhiteSpace(ipAddress) || string.IsNullOrWhiteSpace(pattern))
                return false;

            // Check if pattern contains CIDR notation
            if (pattern.Contains('/', StringComparison.Ordinal))
            {
                return IsInCidrRange(ipAddress, pattern);
            }

            // Check for exact match
            if (ipAddress.Equals(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Check for partial match (e.g., "192.168" matches "192.168.1.1")
            if (ipAddress.StartsWith(pattern, StringComparison.OrdinalIgnoreCase))
            {
                // Ensure it's a valid partial match (ends at octet boundary)
                if (pattern.EndsWith(".", StringComparison.Ordinal) || ipAddress.Length == pattern.Length || ipAddress[pattern.Length] == '.')
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Check if port matches pattern (supports single port, range, or comma-separated list)
        /// </summary>
        public static bool MatchesPortPattern(int port, string pattern)
        {
            if (string.IsNullOrWhiteSpace(pattern))
                return false;

            try
            {
                // Handle comma-separated list
                if (pattern.Contains(',', StringComparison.Ordinal))
                {
                    var ports = pattern.Split(',');
                    return ports.Any(p => MatchesPortPattern(port, p.Trim()));
                }

                // Handle range (e.g., "8000-9000")
                if (pattern.Contains('-', StringComparison.Ordinal))
                {
                    var parts = pattern.Split('-');
                    if (parts.Length == 2 &&
                        int.TryParse(parts[0].Trim(), out var startPort) &&
                        int.TryParse(parts[1].Trim(), out var endPort))
                    {
                        return port >= startPort && port <= endPort;
                    }
                }

                // Handle single port
                if (int.TryParse(pattern.Trim(), out var singlePort))
                {
                    return port == singlePort;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validate if string is a valid CIDR notation
        /// </summary>
        public static bool IsValidCidr(string cidr)
        {
            if (string.IsNullOrWhiteSpace(cidr))
                return false;

            var parts = cidr.Split('/');
            if (parts.Length != 2)
                return false;

            // Validate IP address part
            if (!IPAddress.TryParse(parts[0], out var ip))
                return false;

            // Validate prefix length
            if (!int.TryParse(parts[1], out var prefixLength))
                return false;

            // Check prefix length bounds
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                return prefixLength >= 0 && prefixLength <= 32;
            }
            else if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                return prefixLength >= 0 && prefixLength <= 128;
            }

            return false;
        }

        /// <summary>
        /// Get example text for IP input field
        /// </summary>
        public static string GetIpExamples()
        {
            return "Examples: 192.168.1.1, 10.0.0.0/8, 192.168., 172.16";
        }

        /// <summary>
        /// Get example text for Port input field
        /// </summary>
        public static string GetPortExamples()
        {
            return "Examples: 80, 443, 8080-8090, 22,80,443";
        }
    }
}