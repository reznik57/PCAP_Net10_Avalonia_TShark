using FluentAssertions;
using PCAPAnalyzer.Core.Services;

namespace PCAPAnalyzer.Tests.Services;

public class NetworkFilterHelperTests
{
    #region RFC1918 Tests

    [Theory]
    [InlineData("10.0.0.1", true)]
    [InlineData("10.255.255.255", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.255", true)]
    [InlineData("192.168.0.1", true)]
    [InlineData("192.168.255.255", true)]
    [InlineData("8.8.8.8", false)]
    [InlineData("1.1.1.1", false)]
    [InlineData("172.15.0.1", false)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.167.0.1", false)]
    public void IsRFC1918_WithVariousIPs_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsRFC1918(ip);

        // Assert
        result.Should().Be(expected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("invalid")]
    [InlineData("999.999.999.999")]
    public void IsRFC1918_WithInvalidInput_ReturnsFalse(string? ip)
    {
        // Act
        var result = NetworkFilterHelper.IsRFC1918(ip!);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region Multicast Tests

    [Theory]
    [InlineData("224.0.0.1", true)]
    [InlineData("239.255.255.255", true)]
    [InlineData("230.1.2.3", true)]
    [InlineData("223.255.255.255", false)]
    [InlineData("240.0.0.0", false)]
    [InlineData("192.168.1.1", false)]
    public void IsMulticast_WithIPv4_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsMulticast(ip);

        // Assert
        result.Should().Be(expected);
    }

    [Fact]
    public void IsMulticast_WithIPv6Multicast_ReturnsTrue()
    {
        // Arrange - IPv6 multicast addresses start with FF
        var ip = "ff02::1";

        // Act
        var result = NetworkFilterHelper.IsMulticast(ip);

        // Assert
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid")]
    public void IsMulticast_WithInvalidInput_ReturnsFalse(string? ip)
    {
        // Act
        var result = NetworkFilterHelper.IsMulticast(ip!);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region Broadcast Tests

    // IMPORTANT: IsBroadcast() can ONLY detect the limited broadcast (255.255.255.255)
    // without subnet mask information. Subnet broadcasts (*.*.*.255) require knowing
    // the network mask, which isn't available at the IP layer.
    //
    // Common misconceptions:
    // - *.*.*.255 is NOT always broadcast (e.g., 10.0.0.255 is valid host in /8)
    // - *.*.*.0 is NEVER broadcast (it's the network address!)
    //
    // For comprehensive broadcast detection, use IsBroadcastPacket() which checks
    // L2 MAC address (ff:ff:ff:ff:ff:ff) and protocol hints (ARP, DHCP Discover).
    [Theory]
    [InlineData("255.255.255.255", true)]   // Limited broadcast - always broadcast
    [InlineData("192.168.1.255", false)]    // Subnet broadcast - requires mask context
    [InlineData("10.0.0.255", false)]       // Could be valid host in /8 network
    [InlineData("192.168.1.0", false)]      // Network address, NEVER broadcast
    [InlineData("192.168.1.1", false)]
    [InlineData("8.8.8.8", false)]
    public void IsBroadcast_WithVariousIPs_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsBroadcast(ip);

        // Assert
        result.Should().Be(expected);
    }

    #endregion

    #region Anycast Tests

    [Theory]
    [InlineData("1.1.1.1", true)]
    [InlineData("1.0.0.1", true)]
    [InlineData("8.8.8.8", true)]
    [InlineData("8.8.4.4", true)]
    [InlineData("9.9.9.9", true)]
    [InlineData("208.67.222.222", true)]
    [InlineData("192.168.1.1", false)]
    [InlineData("10.0.0.1", false)]
    public void IsAnycast_WithCommonDNSServers_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsAnycast(ip);

        // Assert
        result.Should().Be(expected);
    }

    #endregion

    #region Link-Local Tests

    [Theory]
    [InlineData("169.254.0.1", true)]
    [InlineData("169.254.255.255", true)]
    [InlineData("169.253.0.1", false)]
    [InlineData("169.255.0.1", false)]
    [InlineData("192.168.1.1", false)]
    public void IsLinkLocal_WithVariousIPs_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsLinkLocal(ip);

        // Assert
        result.Should().Be(expected);
    }

    #endregion

    #region Loopback Tests

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("127.0.0.2", true)]
    [InlineData("127.255.255.255", true)]
    [InlineData("::1", true)] // IPv6 loopback
    [InlineData("192.168.1.1", false)]
    [InlineData("8.8.8.8", false)]
    public void IsLoopback_WithVariousIPs_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsLoopback(ip);

        // Assert
        result.Should().Be(expected);
    }

    #endregion

    #region Public IP Tests

    [Theory]
    [InlineData("8.8.8.8", true)]
    [InlineData("1.1.1.1", true)]
    [InlineData("93.184.216.34", true)]
    [InlineData("10.0.0.1", false)] // RFC1918
    [InlineData("172.16.0.1", false)] // RFC1918
    [InlineData("192.168.1.1", false)] // RFC1918
    [InlineData("127.0.0.1", false)] // Loopback
    [InlineData("169.254.1.1", false)] // Link-local
    [InlineData("224.0.0.1", false)] // Multicast
    [InlineData("255.255.255.255", false)] // Broadcast
    [InlineData("0.0.0.0", false)] // Reserved
    [InlineData("192.0.2.1", false)] // TEST-NET-1
    public void IsPublicIP_WithVariousIPs_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsPublicIP(ip);

        // Assert
        result.Should().Be(expected);
    }

    #endregion

    #region Reserved Tests

    [Theory]
    [InlineData("192.0.2.1", true)] // TEST-NET-1
    [InlineData("198.51.100.1", true)] // TEST-NET-2
    [InlineData("203.0.113.1", true)] // TEST-NET-3
    [InlineData("192.0.0.1", true)] // Documentation
    [InlineData("100.64.0.1", true)] // Shared Address Space
    [InlineData("100.127.255.255", true)] // Shared Address Space
    [InlineData("8.8.8.8", false)]
    [InlineData("192.168.1.1", false)]
    public void IsReserved_WithVariousIPs_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsReserved(ip);

        // Assert
        result.Should().Be(expected);
    }

    #endregion

    #region Insecure Port Tests

    [Theory]
    [InlineData(21, true)] // FTP
    [InlineData(23, true)] // Telnet
    [InlineData(80, true)] // HTTP
    [InlineData(445, true)] // SMB
    [InlineData(3306, true)] // MySQL
    [InlineData(443, false)] // HTTPS
    [InlineData(22, false)] // SSH
    [InlineData(8443, false)]
    public void IsInsecurePort_WithVariousPorts_ReturnsCorrectResult(int port, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsInsecurePort(port);

        // Assert
        result.Should().Be(expected);
    }

    #endregion

    #region Insecure Protocol Tests

    [Theory]
    [InlineData("HTTP", true)]
    [InlineData("FTP", true)]
    [InlineData("TELNET", true)]
    [InlineData("SMTP", true)]
    [InlineData("HTTPS", false)]
    [InlineData("SSH", false)]
    [InlineData("TLS", false)]
    [InlineData("UNKNOWN", false)]
    public void IsInsecureProtocol_WithVariousProtocols_ReturnsCorrectResult(string protocol, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsInsecureProtocol(protocol);

        // Assert
        result.Should().Be(expected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsInsecureProtocol_WithInvalidInput_ReturnsFalse(string? protocol)
    {
        // Act
        var result = NetworkFilterHelper.IsInsecureProtocol(protocol!);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region Anomaly Tests

    [Theory]
    [InlineData("malformed packet", true)]
    [InlineData("TCP retransmission", true)]
    [InlineData("duplicate ACK", true)]
    [InlineData("out-of-order", true)]
    [InlineData("checksum error", true)]
    [InlineData("port scan detected", true)]
    [InlineData("TCP RST", true)]
    [InlineData("Normal traffic", false)]
    [InlineData("ACK", false)]
    public void IsAnomaly_WithVariousInfoStrings_ReturnsCorrectResult(string info, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsAnomaly(info);

        // Assert
        result.Should().Be(expected);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void IsAnomaly_WithInvalidInput_ReturnsFalse(string? info)
    {
        // Act
        var result = NetworkFilterHelper.IsAnomaly(info!);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region Suspicious Traffic Tests

    [Fact]
    public void IsSuspiciousTraffic_WithPortScanPattern_ReturnsTrue()
    {
        // Arrange - High source port to low dest port with SYN flag
        var sourceIp = "10.0.0.100";
        var destIp = "192.168.1.50";
        var sourcePort = 54321;
        var destPort = 22;
        var info = "SYN";

        // Act
        var result = NetworkFilterHelper.IsSuspiciousTraffic(sourceIp, destIp, sourcePort, destPort, info);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsSuspiciousTraffic_WithZeroPort_ReturnsTrue()
    {
        // Arrange
        var sourceIp = "192.168.1.1";
        var destIp = "192.168.1.2";
        var sourcePort = 0;
        var destPort = 80;
        var info = "TCP";

        // Act
        var result = NetworkFilterHelper.IsSuspiciousTraffic(sourceIp, destIp, sourcePort, destPort, info);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsSuspiciousTraffic_WithExternalToInternalInsecurePort_ReturnsTrue()
    {
        // Arrange - External IP to internal RFC1918 on insecure port
        var sourceIp = "8.8.8.8";
        var destIp = "192.168.1.50";
        var sourcePort = 54321;
        var destPort = 23; // Telnet
        var info = "TCP";

        // Act
        var result = NetworkFilterHelper.IsSuspiciousTraffic(sourceIp, destIp, sourcePort, destPort, info);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public void IsSuspiciousTraffic_WithNormalTraffic_ReturnsFalse()
    {
        // Arrange
        var sourceIp = "192.168.1.100";
        var destIp = "8.8.8.8";
        var sourcePort = 54321;
        var destPort = 443;
        var info = "ACK";

        // Act
        var result = NetworkFilterHelper.IsSuspiciousTraffic(sourceIp, destIp, sourcePort, destPort, info);

        // Assert
        result.Should().BeFalse();
    }

    #endregion

    #region CIDR Tests

    [Theory]
    [InlineData("192.168.1.100", "192.168.1.0/24", true)]
    [InlineData("192.168.1.255", "192.168.1.0/24", true)]
    [InlineData("192.168.2.1", "192.168.1.0/24", false)]
    [InlineData("10.0.0.5", "10.0.0.0/8", true)]
    [InlineData("11.0.0.5", "10.0.0.0/8", false)]
    [InlineData("172.16.0.1", "172.16.0.0/12", true)]
    [InlineData("172.31.255.255", "172.16.0.0/12", true)]
    [InlineData("172.32.0.1", "172.16.0.0/12", false)]
    public void IsInCidr_WithIPv4_ReturnsCorrectResult(string ip, string cidr, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsInCidr(ip, cidr);

        // Assert
        result.Should().Be(expected);
    }

    [Theory]
    [InlineData("", "192.168.1.0/24")]
    [InlineData("192.168.1.1", "")]
    [InlineData("192.168.1.1", "invalid")]
    [InlineData("invalid", "192.168.1.0/24")]
    [InlineData("192.168.1.1", "192.168.1.0")]
    public void IsInCidr_WithInvalidInput_ReturnsFalse(string ip, string cidr)
    {
        // Act
        var result = NetworkFilterHelper.IsInCidr(ip, cidr);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public void IsInCidr_WithIPv6_ReturnsCorrectResult()
    {
        // Arrange
        var ip = "2001:db8::1";
        var cidr = "2001:db8::/32";

        // Act
        var result = NetworkFilterHelper.IsInCidr(ip, cidr);

        // Assert
        result.Should().BeTrue();
    }

    #endregion

    #region IPv4/IPv6 Tests

    [Theory]
    [InlineData("192.168.1.1", true)]
    [InlineData("8.8.8.8", true)]
    [InlineData("2001:db8::1", false)]
    [InlineData("::1", false)]
    [InlineData("invalid", false)]
    [InlineData("", false)]
    public void IsIPv4_WithVariousIPs_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsIPv4(ip);

        // Assert
        result.Should().Be(expected);
    }

    [Theory]
    [InlineData("2001:db8::1", true)]
    [InlineData("::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("192.168.1.1", false)]
    [InlineData("invalid", false)]
    [InlineData("", false)]
    public void IsIPv6_WithVariousIPs_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsIPv6(ip);

        // Assert
        result.Should().Be(expected);
    }

    [Theory]
    [InlineData("fe80::1", true)]
    [InlineData("fe80::", true)]
    [InlineData("2001:db8::1", false)]
    [InlineData("192.168.1.1", false)]
    public void IsIPv6LinkLocal_WithVariousIPs_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsIPv6LinkLocal(ip);

        // Assert
        result.Should().Be(expected);
    }

    [Theory]
    [InlineData("fc00::1", true)]
    [InlineData("fd00::1", true)]
    [InlineData("fe80::1", false)]
    [InlineData("2001:db8::1", false)]
    [InlineData("192.168.1.1", false)]
    public void IsIPv6UniqueLocal_WithVariousIPs_ReturnsCorrectResult(string ip, bool expected)
    {
        // Act
        var result = NetworkFilterHelper.IsIPv6UniqueLocal(ip);

        // Assert
        result.Should().Be(expected);
    }

    #endregion
}
