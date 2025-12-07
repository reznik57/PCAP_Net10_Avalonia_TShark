using System;
using System.Net;
using System.Linq;

namespace PCAPAnalyzer.Core.Services
{
    public static class NetworkFilterHelper
    {
        // RFC1918 Private IP Ranges
        // 10.0.0.0/8
        // 172.16.0.0/12
        // 192.168.0.0/16
        public static bool IsRFC1918(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            try
            {
                var ip = IPAddress.Parse(ipAddress);
                var bytes = ip.GetAddressBytes();

                if (bytes.Length == 4) // IPv4
                {
                    // 10.0.0.0/8
                    if (bytes[0] == 10)
                        return true;

                    // 172.16.0.0/12
                    if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                        return true;

                    // 192.168.0.0/16
                    if (bytes[0] == 192 && bytes[1] == 168)
                        return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        // Multicast: 224.0.0.0/4 (224.0.0.0 to 239.255.255.255)
        public static bool IsMulticast(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            try
            {
                var ip = IPAddress.Parse(ipAddress);
                var bytes = ip.GetAddressBytes();

                if (bytes.Length == 4) // IPv4
                {
                    // Multicast addresses: 224.0.0.0 to 239.255.255.255
                    return bytes[0] >= 224 && bytes[0] <= 239;
                }
                else if (bytes.Length == 16) // IPv6
                {
                    // IPv6 multicast addresses start with FF
                    return bytes[0] == 0xFF;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        // Broadcast: 255.255.255.255 or network broadcast addresses
        public static bool IsBroadcast(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            try
            {
                var ip = IPAddress.Parse(ipAddress);
                var bytes = ip.GetAddressBytes();

                if (bytes.Length == 4) // IPv4
                {
                    // Full broadcast
                    if (bytes.All(b => b == 255))
                        return true;

                    // Limited broadcast (last octet is 255)
                    if (bytes[3] == 255)
                        return true;

                    // Network broadcast (ends with .0)
                    if (bytes[3] == 0 && bytes[2] != 0)
                        return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        // Anycast detection (common anycast addresses)
        public static bool IsAnycast(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            // Common anycast addresses
            string[] anycastAddresses = {
                "1.1.1.1",      // Cloudflare DNS
                "1.0.0.1",      // Cloudflare DNS
                "8.8.8.8",      // Google DNS
                "8.8.4.4",      // Google DNS
                "9.9.9.9",      // Quad9 DNS
                "149.112.112.112", // Quad9 DNS
                "208.67.222.222",  // OpenDNS
                "208.67.220.220",  // OpenDNS
                "76.76.19.19",     // Alternate DNS
                "76.223.122.150"   // Alternate DNS
            };

            return anycastAddresses.Contains(ipAddress);
        }

        // Link-local addresses: 169.254.0.0/16
        public static bool IsLinkLocal(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            try
            {
                var ip = IPAddress.Parse(ipAddress);
                var bytes = ip.GetAddressBytes();

                if (bytes.Length == 4) // IPv4
                {
                    return bytes[0] == 169 && bytes[1] == 254;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        // Loopback: 127.0.0.0/8
        public static bool IsLoopback(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            try
            {
                var ip = IPAddress.Parse(ipAddress);
                return IPAddress.IsLoopback(ip);
            }
            catch
            {
                return false;
            }
        }

        // Check if IP is a public IP address (not private, not loopback, not link-local, not multicast, not broadcast)
        public static bool IsPublicIP(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            try
            {
                // Check if it's NOT any of the special/private addresses
                return !IsRFC1918(ipAddress) &&
                       !IsLoopback(ipAddress) &&
                       !IsLinkLocal(ipAddress) &&
                       !IsMulticast(ipAddress) &&
                       !IsBroadcast(ipAddress) &&
                       !IsReserved(ipAddress) &&
                       !ipAddress.Equals("0.0.0.0", StringComparison.Ordinal) &&
                       !ipAddress.StartsWith("0.", StringComparison.Ordinal);
            }
            catch
            {
                return false;
            }
        }

        // Reserved/Documentation: TEST-NET addresses
        public static bool IsReserved(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;

            try
            {
                var ip = IPAddress.Parse(ipAddress);
                var bytes = ip.GetAddressBytes();

                if (bytes.Length == 4) // IPv4
                {
                    // TEST-NET-1: 192.0.2.0/24
                    if (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2)
                        return true;

                    // TEST-NET-2: 198.51.100.0/24
                    if (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100)
                        return true;

                    // TEST-NET-3: 203.0.113.0/24
                    if (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113)
                        return true;

                    // Documentation: 192.0.0.0/24
                    if (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 0)
                        return true;

                    // Shared Address Space: 100.64.0.0/10
                    if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
                        return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        // Check if port represents an insecure protocol
        public static bool IsInsecurePort(int port)
        {
            int[] insecurePorts = {
                21,    // FTP
                23,    // Telnet
                25,    // SMTP (unencrypted)
                80,    // HTTP
                110,   // POP3
                143,   // IMAP
                161,   // SNMP
                445,   // SMB
                512,   // rexec
                513,   // rlogin
                514,   // rsh
                1433,  // MSSQL
                1521,  // Oracle
                3306,  // MySQL
                5432,  // PostgreSQL
                5900,  // VNC
                6379,  // Redis
                8080,  // HTTP Alt
                8081,  // HTTP Alt
                8888,  // HTTP Alt
                11211  // Memcached
            };

            return insecurePorts.Contains(port);
        }

        // Check if protocol is considered insecure
        public static bool IsInsecureProtocol(string protocol)
        {
            if (string.IsNullOrWhiteSpace(protocol))
                return false;

            // Secure protocols that should NOT be flagged
            string[] secureProtocols = {
                "HTTPS",
                "SSH",
                "TLS",
                "FTPS",
                "SFTP",
                "IMAPS",
                "POP3S",
                "SMTPS",
                "SNMPv3",
                "LDAPS"
            };

            // Check if it's a secure protocol first
            if (secureProtocols.Any(p =>
                protocol.Equals(p, StringComparison.OrdinalIgnoreCase)))
                return false;

            string[] insecureProtocols = {
                "HTTP",
                "FTP",
                "TELNET",
                "POP",
                "IMAP",
                "SMTP",
                "SMB",
                "SMB2",
                "NFS",
                "TFTP",
                "SNMPv1",
                "SNMPv2c",
                "RDP" // When not using Network Level Authentication
            };

            return insecureProtocols.Any(p =>
                protocol.Contains(p, StringComparison.OrdinalIgnoreCase));
        }

        // Check if packet info suggests an anomaly
        public static bool IsAnomaly(string info)
        {
            if (string.IsNullOrWhiteSpace(info))
                return false;

            string[] anomalyKeywords = {
                "malformed",
                "retransmission",
                "duplicate",
                "dup ack",
                "out-of-order",
                "tcp spurious",
                "tcp fast retransmission",
                "tcp previous segment",
                "tcp port numbers reused",
                "checksum",
                "flood",
                "scan",
                "rst",
                "fragmented",
                "bad",
                "invalid",
                "error",
                "suspicious",
                "unknown",
                "tcp zero window",
                "icmp redirect",
                "icmp unreachable",
                "arp duplicate",
                "dns no such name",
                "dns query refused"
            };

            var lowerInfo = info.ToLower();
            return anomalyKeywords.Any(keyword => lowerInfo.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        }

        // Check for suspicious patterns
        public static bool IsSuspiciousTraffic(string sourceIp, string destIp, int sourcePort, int destPort, string info)
        {
            // Port scanning pattern (many SYN packets to different ports)
            if (info is not null && info.Contains("SYN", StringComparison.OrdinalIgnoreCase) && !info.Contains("ACK", StringComparison.OrdinalIgnoreCase))
            {
                // High source port + low dest port often indicates scanning
                if (sourcePort > 1024 && destPort < 1024)
                    return true;
            }

            // Suspicious port combinations
            if ((sourcePort == 0 || destPort == 0) && !info?.Contains("ICMP", StringComparison.OrdinalIgnoreCase) == true)
                return true;

            // External to internal on sensitive ports
            if (IsRFC1918(destIp) && !IsRFC1918(sourceIp) && IsInsecurePort(destPort))
                return true;

            return false;
        }
        
        // Check if an IP address is within a CIDR range (supports both IPv4 and IPv6)
        public static bool IsInCidr(string ipAddress, string cidr)
        {
            if (string.IsNullOrWhiteSpace(ipAddress) || string.IsNullOrWhiteSpace(cidr))
                return false;
            
            try
            {
                // Parse CIDR notation
                var parts = cidr.Split('/');
                if (parts.Length != 2)
                    return false;
                
                if (!IPAddress.TryParse(parts[0], out var network))
                    return false;
                
                if (!IPAddress.TryParse(ipAddress, out var ip))
                    return false;
                
                // Ensure both addresses are same type
                if (network.AddressFamily != ip.AddressFamily)
                    return false;
                
                if (!int.TryParse(parts[1], out var maskBits))
                    return false;
                
                // Handle IPv4
                if (network.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    if (maskBits < 0 || maskBits > 32)
                        return false;
                        
                    var networkBytes = network.GetAddressBytes();
                    var ipBytes = ip.GetAddressBytes();
                    
                    // Create mask
                    uint mask = maskBits == 0 ? 0 : uint.MaxValue << (32 - maskBits);
                    
                    // Convert to uint for comparison
                    uint networkInt = BitConverter.ToUInt32(networkBytes.Reverse().ToArray(), 0);
                    uint ipInt = BitConverter.ToUInt32(ipBytes.Reverse().ToArray(), 0);
                    
                    // Apply mask and compare
                    return (networkInt & mask) == (ipInt & mask);
                }
                // Handle IPv6
                else if (network.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    if (maskBits < 0 || maskBits > 128)
                        return false;
                        
                    var networkBytes = network.GetAddressBytes();
                    var ipBytes = ip.GetAddressBytes();
                    
                    // Compare bytes up to the mask
                    for (int i = 0; i < networkBytes.Length; i++)
                    {
                        int bitsToCheck = Math.Min(8, maskBits - (i * 8));
                        if (bitsToCheck <= 0)
                            break;
                            
                        byte mask = (byte)(0xFF << (8 - bitsToCheck));
                        if ((networkBytes[i] & mask) != (ipBytes[i] & mask))
                            return false;
                    }
                    return true;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        // Check if IP is IPv4
        public static bool IsIPv4(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;
                
            try
            {
                if (IPAddress.TryParse(ipAddress, out var ip))
                {
                    return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        // Check if IP is IPv6
        public static bool IsIPv6(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return false;
                
            try
            {
                if (IPAddress.TryParse(ipAddress, out var ip))
                {
                    return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
        
        // Check if IPv6 is link-local (fe80::/10)
        public static bool IsIPv6LinkLocal(string ipAddress)
        {
            if (!IsIPv6(ipAddress))
                return false;
                
            try
            {
                var ip = IPAddress.Parse(ipAddress);
                var bytes = ip.GetAddressBytes();
                // fe80::/10 - first byte is 0xfe, second byte high 2 bits are 10
                return bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80;
            }
            catch
            {
                return false;
            }
        }
        
        // Check if IPv6 is unique local (fc00::/7)
        public static bool IsIPv6UniqueLocal(string ipAddress)
        {
            if (!IsIPv6(ipAddress))
                return false;
                
            try
            {
                var ip = IPAddress.Parse(ipAddress);
                var bytes = ip.GetAddressBytes();
                // fc00::/7 - first byte high 7 bits are 1111110
                return (bytes[0] & 0xfe) == 0xfc;
            }
            catch
            {
                return false;
            }
        }
    }
}