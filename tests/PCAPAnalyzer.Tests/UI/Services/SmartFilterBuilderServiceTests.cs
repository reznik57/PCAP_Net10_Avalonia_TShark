using FluentAssertions;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services;

namespace PCAPAnalyzer.Tests.UI.Services;

/// <summary>
/// Tests for SmartFilterBuilderService.GetQuickFilterPredicate() - the single source of truth
/// for all 90+ quick filters in the PCAP Analyzer application.
///
/// Test Organization by Tab:
/// - General/Packet Analysis: Network types, TCP flags, L4 protocols
/// - Threats: Security filters (Insecure, ObsoleteCrypto, CleartextAuth)
/// - VoiceQoS: VoIP protocols (SIP, RTP, RTCP)
/// - Country Traffic: Direction filters (PrivateToPublic, PublicToPrivate)
/// - Anomalies: Performance filters (Retransmission, DuplicateAck)
/// - Host Inventory: IP type filters
/// </summary>
public class SmartFilterBuilderServiceTests
{
    #region Test Fixture Factory

    /// <summary>
    /// Fluent builder for creating PacketInfo test fixtures with specific characteristics.
    /// Uses C# 14 primary constructor pattern for concise initialization.
    /// </summary>
    private static PacketInfo CreatePacket(
        string sourceIP = "192.168.1.100",
        string destIP = "8.8.8.8",
        ushort sourcePort = 50000,
        ushort destPort = 443,
        Protocol protocol = Protocol.TCP,
        string? l7Protocol = null,
        string? info = null,
        ushort tcpFlags = 0,
        ushort length = 100)
    {
        return new PacketInfo
        {
            Timestamp = DateTime.UtcNow,
            FrameNumber = 1,
            Length = length,
            SourceIP = sourceIP,
            DestinationIP = destIP,
            SourcePort = sourcePort,
            DestinationPort = destPort,
            Protocol = protocol,
            L7Protocol = l7Protocol,
            Info = info,
            TcpFlags = tcpFlags
        };
    }

    /// <summary>
    /// Helper to get predicate and assert it's not null
    /// </summary>
    private static Func<PacketInfo, bool> GetPredicate(string filterName)
    {
        var predicate = SmartFilterBuilderService.GetQuickFilterPredicate(filterName);
        predicate.Should().NotBeNull($"Filter '{filterName}' should be recognized");
        return predicate!;
    }

    #endregion

    #region Network Type Filters (General Tab)

    [Theory]
    [InlineData("10.0.0.1", "8.8.8.8", true)]       // Source is RFC1918
    [InlineData("8.8.8.8", "192.168.1.1", true)]    // Dest is RFC1918
    [InlineData("172.16.0.1", "172.31.255.255", true)] // Both RFC1918
    [InlineData("8.8.8.8", "1.1.1.1", false)]       // Neither is RFC1918
    public void RFC1918_Filter_MatchesPrivateIPAddresses(string srcIP, string destIP, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(sourceIP: srcIP, destIP: destIP);
        var predicate = GetPredicate("RFC1918");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData("192.168.1.1", true)]   // IPv4 source
    [InlineData("10.0.0.1", true)]      // IPv4 source
    [InlineData("::1", false)]          // IPv6 loopback (source)
    [InlineData("2001:db8::1", false)]  // IPv6 source
    public void IPv4_Filter_MatchesIPv4Addresses(string srcIP, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(sourceIP: srcIP, destIP: shouldMatch ? "10.0.0.2" : "::2");
        var predicate = GetPredicate("IPv4");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData("255.255.255.255", true)]   // L3 broadcast - always detected
    [InlineData("192.168.1.100", false)]    // Unicast
    public void Broadcast_Filter_MatchesBroadcastAddresses(string destIP, bool shouldMatch)
    {
        // Arrange
        // Note: Subnet broadcasts (e.g., 192.168.1.255) require L2 MAC or protocol hints
        // to detect reliably. The filter uses IsBroadcastPacket which checks:
        // 1. L3 broadcast (255.255.255.255)
        // 2. L2 broadcast MAC (ff:ff:ff:ff:ff:ff)
        // 3. Protocol hints (DHCP, ARP patterns)
        var packet = CreatePacket(destIP: destIP);
        var predicate = GetPredicate("Broadcast");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Fact]
    public void Broadcast_Filter_MatchesDHCPBroadcast()
    {
        // Arrange - DHCP uses broadcast for discovery
        var packet = CreatePacket(
            destIP: "255.255.255.255",
            l7Protocol: "DHCP",
            sourcePort: 68,
            destPort: 67);
        var predicate = GetPredicate("Broadcast");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().BeTrue("DHCP broadcast should match");
    }

    [Theory]
    [InlineData("224.0.0.1", true)]         // Multicast
    [InlineData("239.255.255.255", true)]   // Multicast
    [InlineData("223.255.255.255", false)]  // Not multicast
    public void Multicast_Filter_MatchesMulticastAddresses(string destIP, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(destIP: destIP);
        var predicate = GetPredicate("Multicast");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    #endregion

    #region TCP Flag Filters (General Tab)

    [Theory]
    [InlineData(0x02, true)]        // SYN only
    [InlineData(0x12, false)]       // SYN + ACK (this is SYN-ACK, not pure SYN)
    [InlineData(0x10, false)]       // ACK only
    [InlineData(0x00, false)]       // No flags
    public void SYN_Filter_MatchesSYNWithoutACK(ushort tcpFlags, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(protocol: Protocol.TCP, tcpFlags: tcpFlags);
        var predicate = GetPredicate("SYN");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch, $"TCP flags 0x{tcpFlags:X2} should {(shouldMatch ? "" : "not ")}match SYN filter");
    }

    [Theory]
    [InlineData(0x12, true)]        // SYN + ACK
    [InlineData(0x02, false)]       // SYN only
    [InlineData(0x10, false)]       // ACK only
    public void SYN_ACK_Filter_MatchesSYNWithACK(ushort tcpFlags, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(protocol: Protocol.TCP, tcpFlags: tcpFlags);
        var predicate = GetPredicate("SYN-ACK");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData(0x04, true)]        // RST only
    [InlineData(0x14, true)]        // RST + ACK
    [InlineData(0x10, false)]       // ACK only
    public void RST_Filter_MatchesRSTFlag(ushort tcpFlags, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(protocol: Protocol.TCP, tcpFlags: tcpFlags);
        var predicate = GetPredicate("RST");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData(0x01, true)]        // FIN only
    [InlineData(0x11, true)]        // FIN + ACK
    [InlineData(0x10, false)]       // ACK only
    public void FIN_Filter_MatchesFINFlag(ushort tcpFlags, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(protocol: Protocol.TCP, tcpFlags: tcpFlags);
        var predicate = GetPredicate("FIN");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Fact]
    public void TcpSyn_Alias_MatchesSameas_SYN()
    {
        // Arrange - Test that aliases work identically
        var packet = CreatePacket(protocol: Protocol.TCP, tcpFlags: 0x02);
        var synPredicate = GetPredicate("SYN");
        var tcpSynPredicate = GetPredicate("TcpSyn");

        // Act
        var synResult = synPredicate(packet);
        var tcpSynResult = tcpSynPredicate(packet);

        // Assert
        synResult.Should().BeTrue();
        tcpSynResult.Should().BeTrue();
        synResult.Should().Be(tcpSynResult, "Aliases should behave identically");
    }

    #endregion

    #region Security Filters (Threats Tab)

    [Theory]
    [InlineData("TLS 1.0", true)]
    [InlineData("TLSv1.0", true)]
    [InlineData("TLS 1.1", true)]
    [InlineData("TLSv1.1", true)]
    [InlineData("SSLv3", true)]
    [InlineData("TLS 1.2", false)]
    [InlineData("TLSv1.2", false)]
    [InlineData("TLS 1.3", false)]
    public void ObsoleteCrypto_Filter_MatchesDeprecatedTLSVersions(string l7Protocol, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(l7Protocol: l7Protocol);
        var predicate = GetPredicate("ObsoleteCrypto");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch, $"L7Protocol '{l7Protocol}' should {(shouldMatch ? "" : "not ")}match ObsoleteCrypto");
    }

    [Theory]
    [InlineData("FTP", 21, "USER admin", true)]
    [InlineData("FTP", 21, "PASS secret123", true)]
    [InlineData("SMTP", 25, "AUTH LOGIN", true)]
    [InlineData("TELNET", 23, "LOGIN root", true)]
    [InlineData("HTTP", 80, "Authorization: Basic dXNlcjpwYXNz", true)]
    [InlineData("HTTP", 80, "GET /index.html HTTP/1.1", false)]  // Normal HTTP, no auth
    [InlineData("DNS", 53, "Standard query A example.com", false)]  // DNS, not auth
    public void CleartextAuth_Filter_MatchesCleartextCredentials(string l7Protocol, ushort destPort, string info, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(l7Protocol: l7Protocol, destPort: destPort, info: info);
        var predicate = GetPredicate("CleartextAuth");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch, $"'{info}' in {l7Protocol} should {(shouldMatch ? "" : "not ")}match CleartextAuth");
    }

    [Theory]
    [InlineData("HTTP", true)]
    [InlineData("FTP", true)]
    [InlineData("TELNET", true)]
    [InlineData("HTTPS", false)]
    [InlineData("SSH", false)]
    public void Insecure_Filter_MatchesInsecureProtocols(string l7Protocol, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(l7Protocol: l7Protocol);
        var predicate = GetPredicate("Insecure");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Fact]
    public void SYNFlood_Filter_MatchesSYNWithoutACK()
    {
        // Arrange - SYN flood detection is SYN without ACK (same as SYN filter)
        var synPacket = CreatePacket(protocol: Protocol.TCP, tcpFlags: 0x02);
        var synAckPacket = CreatePacket(protocol: Protocol.TCP, tcpFlags: 0x12);
        var predicate = GetPredicate("SYNFlood");

        // Act & Assert
        predicate(synPacket).Should().BeTrue("SYN without ACK should match SYNFlood");
        predicate(synAckPacket).Should().BeFalse("SYN-ACK should not match SYNFlood");
    }

    [Theory]
    [InlineData("Certificate error", true)]
    [InlineData("Certificate expired", true)]
    [InlineData("Certificate invalid", true)]
    [InlineData("self-signed certificate", true)]
    [InlineData("TLS Handshake", false)]
    [InlineData("Application Data", false)]
    public void TLSCertError_Filter_MatchesCertificateErrors(string info, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(info: info);
        var predicate = GetPredicate("TLSCertError");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    #endregion

    #region VoIP Protocol Filters (VoiceQoS Tab)

    [Theory]
    [InlineData("SIP", 5060, true)]
    [InlineData("SIP/SDP", 5060, true)]
    [InlineData(null, 5060, true)]      // Port-based detection
    [InlineData(null, 5061, true)]      // SIP over TLS
    [InlineData("HTTP", 80, false)]
    public void SIP_Filter_MatchesSIPTraffic(string? l7Protocol, ushort destPort, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(l7Protocol: l7Protocol, destPort: destPort);
        var predicate = GetPredicate("SIP");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Fact]
    public void RTP_Filter_MatchesRTPButNotRTCP()
    {
        // Arrange
        var rtpPacket = CreatePacket(l7Protocol: "RTP");
        var rtcpPacket = CreatePacket(l7Protocol: "RTCP");
        var predicate = GetPredicate("RTP");

        // Act & Assert
        predicate(rtpPacket).Should().BeTrue("RTP protocol should match");
        predicate(rtcpPacket).Should().BeFalse("RTCP should NOT match RTP filter");
    }

    [Fact]
    public void RTCP_Filter_MatchesRTCPOnly()
    {
        // Arrange
        var rtcpPacket = CreatePacket(l7Protocol: "RTCP");
        var rtpPacket = CreatePacket(l7Protocol: "RTP");
        var predicate = GetPredicate("RTCP");

        // Act & Assert
        predicate(rtcpPacket).Should().BeTrue("RTCP protocol should match");
        predicate(rtpPacket).Should().BeFalse("RTP should NOT match RTCP filter");
    }

    [Theory]
    [InlineData("H.323", 1720, true)]
    [InlineData("H323", 1720, true)]
    [InlineData(null, 1720, true)]      // Port-based detection
    [InlineData("HTTP", 80, false)]
    public void H323_Filter_MatchesH323Traffic(string? l7Protocol, ushort destPort, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(l7Protocol: l7Protocol, destPort: destPort);
        var predicate = GetPredicate("H323");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    #endregion

    #region Traffic Direction Filters (Country Traffic Tab)

    [Theory]
    [InlineData("192.168.1.100", "8.8.8.8", true)]      // Private to public
    [InlineData("10.0.0.1", "1.1.1.1", true)]           // Private to public
    [InlineData("8.8.8.8", "192.168.1.1", false)]       // Public to private (wrong direction)
    [InlineData("192.168.1.1", "192.168.1.2", false)]   // Private to private
    [InlineData("8.8.8.8", "1.1.1.1", false)]           // Public to public
    public void PrivateToPublic_Filter_MatchesOutboundTraffic(string srcIP, string destIP, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(sourceIP: srcIP, destIP: destIP);
        var predicate = GetPredicate("PrivateToPublic");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData("8.8.8.8", "192.168.1.100", true)]      // Public to private
    [InlineData("1.1.1.1", "10.0.0.1", true)]           // Public to private
    [InlineData("192.168.1.100", "8.8.8.8", false)]     // Private to public (wrong direction)
    [InlineData("192.168.1.1", "192.168.1.2", false)]   // Private to private
    public void PublicToPrivate_Filter_MatchesInboundTraffic(string srcIP, string destIP, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(sourceIP: srcIP, destIP: destIP);
        var predicate = GetPredicate("PublicToPrivate");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    #endregion

    #region Performance Filters (Anomalies Tab)

    [Theory]
    [InlineData("TCP Retransmission", true)]
    [InlineData("TCP Fast Retransmission", true)]
    [InlineData("[TCP Retransmission]", true)]
    [InlineData("Normal TCP segment", false)]
    public void Retransmissions_Filter_MatchesRetransmittedPackets(string info, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(info: info);
        var predicate = GetPredicate("Retransmissions");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData("Dup ACK #1", true)]
    [InlineData("DupACK", true)]
    [InlineData("Duplicate ACK", true)]
    [InlineData("TCP ACK", false)]
    public void DuplicateAck_Filter_MatchesDupAckVariants(string info, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(info: info);
        var predicate = GetPredicate("DuplicateAck");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch, $"'{info}' should {(shouldMatch ? "" : "not ")}match DuplicateAck filter");
    }

    [Theory]
    [InlineData("Zero window", true)]
    [InlineData("ZeroWindow", true)]
    [InlineData("TCP segment", false)]
    public void ZeroWindow_Filter_MatchesZeroWindowVariants(string info, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(info: info);
        var predicate = GetPredicate("ZeroWindow");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData("Window full", true)]
    [InlineData("TCP segment", false)]
    public void WindowFull_Filter_MatchesWindowFullPackets(string info, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(info: info);
        var predicate = GetPredicate("WindowFull");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    #endregion

    #region ICMP Filters (Host Inventory / Network Analysis)

    [Theory]
    [InlineData("Echo (ping) request", true)]
    [InlineData("Echo request", true)]
    [InlineData("Echo (ping) reply", false)]
    public void ICMPEchoRequest_Filter_MatchesPingRequests(string info, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(protocol: Protocol.ICMP, info: info);
        var predicate = GetPredicate("ICMPEchoRequest");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData("Echo (ping) reply", true)]
    [InlineData("Echo reply", true)]
    [InlineData("Echo (ping) request", false)]
    public void ICMPEchoReply_Filter_MatchesPingReplies(string info, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(protocol: Protocol.ICMP, info: info);
        var predicate = GetPredicate("ICMPEchoReply");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Fact]
    public void PingRequest_Alias_MatchesSameas_ICMPEchoRequest()
    {
        // Arrange
        var packet = CreatePacket(protocol: Protocol.ICMP, info: "Echo (ping) request");
        var icmpPredicate = GetPredicate("ICMPEchoRequest");
        var aliasPredicate = GetPredicate("PingRequest");

        // Act & Assert
        icmpPredicate(packet).Should().BeTrue();
        aliasPredicate(packet).Should().BeTrue();
    }

    #endregion

    #region DNS Filters (Network Analysis)

    [Theory]
    [InlineData("Standard query A example.com", true)]
    [InlineData("Standard query AAAA ipv6.example.com", true)]
    [InlineData("Standard query response A 93.184.216.34", false)]  // This is a response
    public void DNSQuery_Filter_MatchesDNSQueries(string info, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(l7Protocol: "DNS", destPort: 53, info: info);
        var predicate = GetPredicate("DNSQuery");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData("Standard query response A 93.184.216.34", true)]
    [InlineData("Standard query response AAAA ::1", true)]
    [InlineData("Standard query A example.com", false)]  // This is a query, not response
    public void DNSResponse_Filter_MatchesDNSResponses(string info, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(l7Protocol: "DNS", sourcePort: 53, info: info);
        var predicate = GetPredicate("DNSResponse");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData("NXDOMAIN", true)]
    [InlineData("SERVFAIL", true)]
    [InlineData("Standard query response", false)]
    public void DNSFailures_Filter_MatchesDNSErrors(string info, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(info: info);
        var predicate = GetPredicate("DNSFailures");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    #endregion

    #region Port Range Filters (Network Analysis)

    [Theory]
    [InlineData((ushort)22, (ushort)50000, true)]       // SSH (well-known) to ephemeral
    [InlineData((ushort)443, (ushort)50000, true)]      // HTTPS (well-known) to ephemeral
    [InlineData((ushort)1023, (ushort)50000, true)]     // Edge of well-known
    [InlineData((ushort)1024, (ushort)50000, false)]    // Just outside well-known
    [InlineData((ushort)50000, (ushort)50001, false)]   // Both ephemeral
    public void WellKnownPorts_Filter_MatchesPorts0To1023(ushort srcPort, ushort destPort, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(sourcePort: srcPort, destPort: destPort);
        var predicate = GetPredicate("WellKnownPorts");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData((ushort)50000, (ushort)49152, true)]    // Both ephemeral
    [InlineData((ushort)65535, (ushort)443, true)]      // Source ephemeral, dest well-known
    [InlineData((ushort)443, (ushort)49151, false)]     // Neither ephemeral
    [InlineData((ushort)1024, (ushort)2000, false)]     // Both registered
    public void EphemeralPorts_Filter_MatchesPorts49152To65535(ushort srcPort, ushort destPort, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(sourcePort: srcPort, destPort: destPort);
        var predicate = GetPredicate("EphemeralPorts");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Fact]
    public void HighPorts_Alias_MatchesSameas_EphemeralPorts()
    {
        // Arrange
        var packet = CreatePacket(sourcePort: 55000, destPort: 443);
        var ephemeralPredicate = GetPredicate("EphemeralPorts");
        var highPortsPredicate = GetPredicate("HighPorts");

        // Act & Assert
        ephemeralPredicate(packet).Should().BeTrue();
        highPortsPredicate(packet).Should().BeTrue();
    }

    #endregion

    #region HTTP Error Filters (Application Analysis)

    [Theory]
    [InlineData("HTTP/1.1 404 Not Found", true)]
    [InlineData("HTTP/1.1 500 Internal Server Error", true)]
    [InlineData("HTTP/1.1 503 Service Unavailable", true)]
    [InlineData("404 Not Found", true)]
    [InlineData("HTTP/1.1 200 OK", false)]
    [InlineData("HTTP/1.1 301 Moved Permanently", false)]
    public void HTTPErrors_Filter_MatchesHTTP4xxAnd5xx(string info, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(l7Protocol: "HTTP", info: info);
        var predicate = GetPredicate("HTTPErrors");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch, $"'{info}' should {(shouldMatch ? "" : "not ")}match HTTPErrors");
    }

    #endregion

    #region Edge Cases and Null Handling

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void GetQuickFilterPredicate_WithInvalidInput_ReturnsNull(string? filterName)
    {
        // Act
        var result = SmartFilterBuilderService.GetQuickFilterPredicate(filterName);

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void GetQuickFilterPredicate_WithUnknownFilter_ReturnsNull()
    {
        // Act
        var result = SmartFilterBuilderService.GetQuickFilterPredicate("NonExistentFilter");

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public void Filters_WithNullInfo_DoNotThrow()
    {
        // Arrange - Packet with null Info field
        var packet = CreatePacket(info: null);

        // These filters depend on Info field
        var infoFilters = new[] { "Retransmissions", "DuplicateAck", "ZeroWindow", "HTTPErrors" };

        // Act & Assert - Should not throw, just return false
        foreach (var filterName in infoFilters)
        {
            var predicate = GetPredicate(filterName);
            var act = () => predicate(packet);
            act.Should().NotThrow($"Filter '{filterName}' should handle null Info gracefully");
        }
    }

    [Fact]
    public void Filters_WithNullL7Protocol_DoNotThrow()
    {
        // Arrange - Packet with null L7Protocol field
        var packet = CreatePacket(l7Protocol: null);

        // These filters depend on L7Protocol field
        var protocolFilters = new[] { "HTTP", "HTTPS", "SIP", "RTP", "ObsoleteCrypto" };

        // Act & Assert - Should not throw, just return false (or true for port-based matches)
        foreach (var filterName in protocolFilters)
        {
            var predicate = GetPredicate(filterName);
            var act = () => predicate(packet);
            act.Should().NotThrow($"Filter '{filterName}' should handle null L7Protocol gracefully");
        }
    }

    #endregion

    #region L4 Protocol Filters

    [Theory]
    [InlineData(Protocol.TCP, true)]
    [InlineData(Protocol.UDP, false)]
    [InlineData(Protocol.ICMP, false)]
    public void TCP_Filter_MatchesTCPProtocol(Protocol protocol, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(protocol: protocol);
        var predicate = GetPredicate("TCP");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData(Protocol.UDP, true)]
    [InlineData(Protocol.TCP, false)]
    [InlineData(Protocol.ICMP, false)]
    public void UDP_Filter_MatchesUDPProtocol(Protocol protocol, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(protocol: protocol);
        var predicate = GetPredicate("UDP");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    #endregion

    #region TLS Version Filters

    [Theory]
    [InlineData("TLS 1.2", true)]
    [InlineData("TLSv1.2", true)]
    [InlineData("TLS 1.3", false)]
    [InlineData("TLS 1.0", false)]
    public void TlsV12_Filter_MatchesTLS12Only(string l7Protocol, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(l7Protocol: l7Protocol);
        var predicate = GetPredicate("TlsV12");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    [Theory]
    [InlineData("TLS 1.3", true)]
    [InlineData("TLSv1.3", true)]
    [InlineData("TLS 1.2", false)]
    public void TlsV13_Filter_MatchesTLS13Only(string l7Protocol, bool shouldMatch)
    {
        // Arrange
        var packet = CreatePacket(l7Protocol: l7Protocol);
        var predicate = GetPredicate("TlsV13");

        // Act
        var result = predicate(packet);

        // Assert
        result.Should().Be(shouldMatch);
    }

    #endregion

    // ===================================================================================
    // COMBINED FILTER TESTS
    // ===================================================================================
    // These tests verify the BuildCombinedPacketFilter logic:
    // - AND logic within groups (all fields in a group must match)
    // - OR logic between groups (any group can match)
    // - EXCLUDE logic (NOT applied to exclude groups/chips)
    // - Final combination: (INCLUDE) AND NOT (EXCLUDE)
    // ===================================================================================

    #region Combined Filter Tests - OR Between Groups

    [Fact]
    public void CombinedFilter_TwoIncludeGroups_MatchesEitherGroup()
    {
        // Arrange
        // Group 1: TCP traffic (Protocol = TCP)
        // Chip 1: RTP traffic via QuickFilterCodeName (this is the proper way to use quick filters)
        // Expected: Match if packet is TCP OR RTP
        //
        // Note: FilterGroup.QuickFilters is NOT processed by BuildFilterFromGroup() -
        // use FilterChipItem with QuickFilterCodeName for quick filter predicates

        var service = new SmartFilterBuilderService();

        var group1 = new FilterGroup { Protocol = "TCP" };
        var rtpChip = new FilterChipItem { QuickFilterCodeName = "RTP" };

        var tcpPacket = CreatePacket(protocol: Protocol.TCP, l7Protocol: "TCP");
        var rtpPacket = CreatePacket(protocol: Protocol.UDP, l7Protocol: "RTP");
        var httpPacket = CreatePacket(protocol: Protocol.TCP, l7Protocol: "HTTP");

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [group1],
            includeChips: [rtpChip],
            excludeGroups: [],
            excludeChips: []);

        // Assert
        // TCP packet matches Group1 (Protocol=TCP)
        filter.MatchesPacket(tcpPacket).Should().BeTrue("TCP packet should match Group1");
        // RTP packet matches RTP chip (QuickFilterCodeName=RTP)
        filter.MatchesPacket(rtpPacket).Should().BeTrue("RTP packet should match RTP chip");
        // HTTP packet matches Group1 (it's still TCP at L4)
        filter.MatchesPacket(httpPacket).Should().BeTrue("HTTP packet is TCP at L4, should match Group1");
    }

    [Fact]
    public void CombinedFilter_ThreeGroups_MatchesAnyOfThree()
    {
        // Arrange
        // Group 1: Port 443 (HTTPS)
        // Group 2: Port 22 (SSH)
        // Group 3: Port 53 (DNS)
        // Expected: Match if packet uses any of these ports

        var service = new SmartFilterBuilderService();

        var group1 = new FilterGroup { PortRange = "443" };
        var group2 = new FilterGroup { PortRange = "22" };
        var group3 = new FilterGroup { PortRange = "53" };

        var httpsPacket = CreatePacket(destPort: 443);
        var sshPacket = CreatePacket(destPort: 22);
        var dnsPacket = CreatePacket(destPort: 53);
        var httpPacket = CreatePacket(destPort: 80);

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [group1, group2, group3],
            includeChips: [],
            excludeGroups: [],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(httpsPacket).Should().BeTrue("Port 443 matches Group1");
        filter.MatchesPacket(sshPacket).Should().BeTrue("Port 22 matches Group2");
        filter.MatchesPacket(dnsPacket).Should().BeTrue("Port 53 matches Group3");
        filter.MatchesPacket(httpPacket).Should().BeFalse("Port 80 doesn't match any group");
    }

    #endregion

    #region Combined Filter Tests - AND Within Groups

    [Fact]
    public void CombinedFilter_GroupWithMultipleFields_AllFieldsMustMatch()
    {
        // Arrange
        // Single group: SourceIP=192.168.* AND DestPort=443
        // Expected: Must match BOTH criteria

        var service = new SmartFilterBuilderService();

        var group = new FilterGroup
        {
            SourceIP = "192.168.1.100",
            PortRange = "443"
        };

        var matchBoth = CreatePacket(sourceIP: "192.168.1.100", destPort: 443);
        var matchOnlyIP = CreatePacket(sourceIP: "192.168.1.100", destPort: 80);
        var matchOnlyPort = CreatePacket(sourceIP: "10.0.0.1", destPort: 443);
        var matchNeither = CreatePacket(sourceIP: "10.0.0.1", destPort: 80);

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [group],
            includeChips: [],
            excludeGroups: [],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(matchBoth).Should().BeTrue("Matches both IP and port");
        filter.MatchesPacket(matchOnlyIP).Should().BeFalse("Matches IP but not port");
        filter.MatchesPacket(matchOnlyPort).Should().BeFalse("Matches port but not IP");
        filter.MatchesPacket(matchNeither).Should().BeFalse("Matches neither");
    }

    [Fact]
    public void CombinedFilter_ProtocolAndIP_BothMustMatch()
    {
        // Arrange
        // Group: Protocol=TCP AND DestIP=8.8.8.8
        // This is typical for "show me all TCP traffic to Google DNS"

        var service = new SmartFilterBuilderService();

        var group = new FilterGroup
        {
            Protocol = "TCP",
            DestinationIP = "8.8.8.8"
        };

        var tcpToGoogle = CreatePacket(protocol: Protocol.TCP, destIP: "8.8.8.8");
        var udpToGoogle = CreatePacket(protocol: Protocol.UDP, destIP: "8.8.8.8");
        var tcpToCloudflare = CreatePacket(protocol: Protocol.TCP, destIP: "1.1.1.1");

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [group],
            includeChips: [],
            excludeGroups: [],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(tcpToGoogle).Should().BeTrue("TCP to 8.8.8.8 matches");
        filter.MatchesPacket(udpToGoogle).Should().BeFalse("UDP to 8.8.8.8 doesn't match (wrong protocol)");
        filter.MatchesPacket(tcpToCloudflare).Should().BeFalse("TCP to 1.1.1.1 doesn't match (wrong IP)");
    }

    #endregion

    #region Combined Filter Tests - EXCLUDE Logic

    [Fact]
    public void CombinedFilter_ExcludeGroup_RemovesMatchingPackets()
    {
        // Arrange
        // Include: All TCP traffic
        // Exclude: Port 443
        // Expected: TCP traffic EXCEPT port 443

        var service = new SmartFilterBuilderService();

        var includeGroup = new FilterGroup { Protocol = "TCP" };
        var excludeGroup = new FilterGroup { PortRange = "443" };

        var tcpToHttp = CreatePacket(protocol: Protocol.TCP, destPort: 80);
        var tcpToHttps = CreatePacket(protocol: Protocol.TCP, destPort: 443);
        var udpToDns = CreatePacket(protocol: Protocol.UDP, destPort: 53);

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [includeGroup],
            includeChips: [],
            excludeGroups: [excludeGroup],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(tcpToHttp).Should().BeTrue("TCP to port 80 matches include, not excluded");
        filter.MatchesPacket(tcpToHttps).Should().BeFalse("TCP to port 443 matches include BUT is excluded");
        filter.MatchesPacket(udpToDns).Should().BeFalse("UDP doesn't match include");
    }

    [Fact]
    public void CombinedFilter_ExcludeChip_RemovesMatchingPackets()
    {
        // Arrange
        // Include: All packets (no include groups = match all)
        // Exclude chip: DNS traffic
        // Expected: Everything EXCEPT DNS

        var service = new SmartFilterBuilderService();

        var excludeChip = new FilterChipItem(1, "DNS", "DNS", isExclude: true)
        {
            QuickFilterCodeName = "DNS"
        };

        var httpPacket = CreatePacket(l7Protocol: "HTTP", destPort: 80);
        var dnsPacket = CreatePacket(l7Protocol: "DNS", destPort: 53);
        var sshPacket = CreatePacket(destPort: 22);

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [],
            includeChips: [],
            excludeGroups: [],
            excludeChips: [excludeChip]);

        // Assert - With no include filter, everything is included EXCEPT the exclude
        filter.MatchesPacket(httpPacket).Should().BeTrue("HTTP not excluded");
        filter.MatchesPacket(dnsPacket).Should().BeFalse("DNS is excluded");
        filter.MatchesPacket(sshPacket).Should().BeTrue("SSH not excluded");
    }

    [Fact]
    public void CombinedFilter_MultipleExcludes_ORLogicForExcludes()
    {
        // Arrange
        // Exclude Group 1: Port 53 (DNS)
        // Exclude Group 2: Port 443 (HTTPS)
        // Expected: Exclude if matches EITHER exclude

        var service = new SmartFilterBuilderService();

        var excludeDns = new FilterGroup { PortRange = "53" };
        var excludeHttps = new FilterGroup { PortRange = "443" };

        var httpPacket = CreatePacket(destPort: 80);
        var dnsPacket = CreatePacket(destPort: 53);
        var httpsPacket = CreatePacket(destPort: 443);

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [],
            includeChips: [],
            excludeGroups: [excludeDns, excludeHttps],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(httpPacket).Should().BeTrue("HTTP (80) not excluded");
        filter.MatchesPacket(dnsPacket).Should().BeFalse("DNS (53) excluded by group1");
        filter.MatchesPacket(httpsPacket).Should().BeFalse("HTTPS (443) excluded by group2");
    }

    #endregion

    #region Combined Filter Tests - Mixed INCLUDE/EXCLUDE

    [Fact]
    public void CombinedFilter_ComplexScenario_IncludeGroupsWithExcludeGroups()
    {
        // Arrange
        // Include Group 1: TCP traffic (Protocol=TCP)
        // Include Group 2: UDP traffic (Protocol=UDP)
        // Exclude: Port 53 (DNS)
        // Expected: (TCP OR UDP) AND NOT (port 53)

        var service = new SmartFilterBuilderService();

        var includeTcp = new FilterGroup { Protocol = "TCP" };
        var includeUdp = new FilterGroup { Protocol = "UDP" };
        var excludeDns = new FilterGroup { PortRange = "53" };

        var tcpHttp = CreatePacket(protocol: Protocol.TCP, destPort: 80);
        var tcpDns = CreatePacket(protocol: Protocol.TCP, destPort: 53);    // TCP DNS (rare but valid)
        var udpNtp = CreatePacket(protocol: Protocol.UDP, destPort: 123);
        var udpDns = CreatePacket(protocol: Protocol.UDP, destPort: 53);
        var icmpPacket = CreatePacket(protocol: Protocol.ICMP, destPort: 0);

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [includeTcp, includeUdp],
            includeChips: [],
            excludeGroups: [excludeDns],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(tcpHttp).Should().BeTrue("TCP:80 matches TCP include, not excluded");
        filter.MatchesPacket(tcpDns).Should().BeFalse("TCP:53 matches TCP include BUT excluded by port 53");
        filter.MatchesPacket(udpNtp).Should().BeTrue("UDP:123 matches UDP include, not excluded");
        filter.MatchesPacket(udpDns).Should().BeFalse("UDP:53 matches UDP include BUT excluded by port 53");
        filter.MatchesPacket(icmpPacket).Should().BeFalse("ICMP doesn't match any include group");
    }

    [Fact]
    public void CombinedFilter_SecurityThreatHunting_RealWorldScenario()
    {
        // Arrange
        // Real-world scenario: "Show me suspicious traffic"
        // Include Group 1: Cleartext protocols (HTTP, FTP, Telnet via port detection)
        // Include Group 2: Insecure TLS (TLS 1.0/1.1)
        // Exclude: Internal RFC1918 to RFC1918 traffic (not interesting)

        var service = new SmartFilterBuilderService();

        // Cleartext web/FTP/Telnet
        var includeHttp = new FilterGroup { PortRange = "80" };
        var includeFtp = new FilterGroup { PortRange = "21" };
        var includeTelnet = new FilterGroup { PortRange = "23" };

        // Exclude internal-only traffic (using source IP filter)
        var excludeInternal = new FilterGroup { SourceIP = "192.168.1.100", DestinationIP = "192.168.1.1" };

        var httpToExternal = CreatePacket(sourceIP: "192.168.1.100", destIP: "93.184.216.34", destPort: 80);
        var httpInternal = CreatePacket(sourceIP: "192.168.1.100", destIP: "192.168.1.1", destPort: 80);
        var httpsToExternal = CreatePacket(sourceIP: "192.168.1.100", destIP: "93.184.216.34", destPort: 443);
        var telnetToExternal = CreatePacket(sourceIP: "192.168.1.100", destIP: "8.8.8.8", destPort: 23);

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [includeHttp, includeFtp, includeTelnet],
            includeChips: [],
            excludeGroups: [excludeInternal],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(httpToExternal).Should().BeTrue("HTTP to external is suspicious");
        filter.MatchesPacket(httpInternal).Should().BeFalse("HTTP internal is excluded (matches exclude group exactly)");
        filter.MatchesPacket(httpsToExternal).Should().BeFalse("HTTPS doesn't match include ports");
        filter.MatchesPacket(telnetToExternal).Should().BeTrue("Telnet to external is very suspicious!");
    }

    #endregion

    #region Combined Filter Tests - Chips (Individual OR Filters)

    [Fact]
    public void CombinedFilter_MultipleIncludeChips_ORLogic()
    {
        // Arrange
        // Chip 1: Port 22 (SSH)
        // Chip 2: Port 3389 (RDP)
        // Expected: Match SSH OR RDP

        var service = new SmartFilterBuilderService();

        var sshChip = new FilterChipItem(1, "Port", "22", isExclude: false);
        var rdpChip = new FilterChipItem(2, "Port", "3389", isExclude: false);

        var sshPacket = CreatePacket(destPort: 22);
        var rdpPacket = CreatePacket(destPort: 3389);
        var httpPacket = CreatePacket(destPort: 80);

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [],
            includeChips: [sshChip, rdpChip],
            excludeGroups: [],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(sshPacket).Should().BeTrue("SSH matches chip 1");
        filter.MatchesPacket(rdpPacket).Should().BeTrue("RDP matches chip 2");
        filter.MatchesPacket(httpPacket).Should().BeFalse("HTTP doesn't match any chip");
    }

    [Fact]
    public void CombinedFilter_QuickFilterChips_UsePredicates()
    {
        // Arrange
        // Quick filter chips for TCP flags
        // Chip 1: SYN packets
        // Chip 2: RST packets
        // Expected: Match SYN OR RST

        var service = new SmartFilterBuilderService();

        var synChip = new FilterChipItem(1, "SYN", "SYN", isExclude: false, isQuickFilter: true)
        {
            QuickFilterCodeName = "SYN"
        };
        var rstChip = new FilterChipItem(2, "RST", "RST", isExclude: false, isQuickFilter: true)
        {
            QuickFilterCodeName = "RST"
        };

        var synPacket = CreatePacket(protocol: Protocol.TCP, tcpFlags: 0x02);      // SYN
        var rstPacket = CreatePacket(protocol: Protocol.TCP, tcpFlags: 0x04);      // RST
        var synAckPacket = CreatePacket(protocol: Protocol.TCP, tcpFlags: 0x12);   // SYN-ACK
        var ackPacket = CreatePacket(protocol: Protocol.TCP, tcpFlags: 0x10);      // ACK only

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [],
            includeChips: [synChip, rstChip],
            excludeGroups: [],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(synPacket).Should().BeTrue("SYN flag matches synChip");
        filter.MatchesPacket(rstPacket).Should().BeTrue("RST flag matches rstChip");
        filter.MatchesPacket(synAckPacket).Should().BeFalse("SYN-ACK doesn't match pure SYN filter");
        filter.MatchesPacket(ackPacket).Should().BeFalse("ACK only doesn't match either chip");
    }

    #endregion

    #region Combined Filter Tests - Edge Cases

    [Fact]
    public void CombinedFilter_NoFilters_MatchesAllPackets()
    {
        // Arrange - Empty filter should match everything
        var service = new SmartFilterBuilderService();

        var anyPacket = CreatePacket();

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [],
            includeChips: [],
            excludeGroups: [],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(anyPacket).Should().BeTrue("Empty filter matches all");
    }

    [Fact]
    public void CombinedFilter_OnlyExcludeNoInclude_ExcludesFromAll()
    {
        // Arrange
        // No include = match all implicitly
        // Exclude: DNS
        // Expected: Everything except DNS

        var service = new SmartFilterBuilderService();

        var excludeDns = new FilterGroup { PortRange = "53" };

        var dnsPacket = CreatePacket(destPort: 53);
        var httpPacket = CreatePacket(destPort: 80);

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [],
            includeChips: [],
            excludeGroups: [excludeDns],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(dnsPacket).Should().BeFalse("DNS is excluded");
        filter.MatchesPacket(httpPacket).Should().BeTrue("HTTP is not excluded, matches by default");
    }

    [Fact]
    public void CombinedFilter_EmptyGroup_IsIgnored()
    {
        // Arrange
        // Empty groups (no fields set) should be ignored
        var service = new SmartFilterBuilderService();

        var emptyGroup = new FilterGroup(); // All fields null/empty
        var validGroup = new FilterGroup { PortRange = "443" };

        var httpsPacket = CreatePacket(destPort: 443);
        var httpPacket = CreatePacket(destPort: 80);

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [emptyGroup, validGroup],
            includeChips: [],
            excludeGroups: [],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(httpsPacket).Should().BeTrue("Port 443 matches valid group");
        filter.MatchesPacket(httpPacket).Should().BeFalse("Port 80 doesn't match (empty group ignored)");
    }

    [Fact]
    public void CombinedFilter_GroupsAndChips_BothContribute()
    {
        // Arrange
        // Group: Port 22 (SSH)
        // Chip: Port 3389 (RDP)
        // Expected: SSH OR RDP (groups and chips combined with OR)

        var service = new SmartFilterBuilderService();

        var sshGroup = new FilterGroup { PortRange = "22" };
        var rdpChip = new FilterChipItem(1, "Port", "3389", isExclude: false);

        var sshPacket = CreatePacket(destPort: 22);
        var rdpPacket = CreatePacket(destPort: 3389);
        var httpPacket = CreatePacket(destPort: 80);

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [sshGroup],
            includeChips: [rdpChip],
            excludeGroups: [],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(sshPacket).Should().BeTrue("SSH matches group");
        filter.MatchesPacket(rdpPacket).Should().BeTrue("RDP matches chip");
        filter.MatchesPacket(httpPacket).Should().BeFalse("HTTP doesn't match either");
    }

    [Fact]
    public void CombinedFilter_ExcludeOverridesInclude()
    {
        // Arrange
        // This tests that exclude takes precedence
        // Include: Port 443
        // Exclude: Port 443 (same port!)
        // Expected: Nothing matches (exclude wins)

        var service = new SmartFilterBuilderService();

        var includeHttps = new FilterGroup { PortRange = "443" };
        var excludeHttps = new FilterGroup { PortRange = "443" };

        var httpsPacket = CreatePacket(destPort: 443);

        // Act
        var filter = service.BuildCombinedPacketFilter(
            includeGroups: [includeHttps],
            includeChips: [],
            excludeGroups: [excludeHttps],
            excludeChips: []);

        // Assert
        filter.MatchesPacket(httpsPacket).Should().BeFalse("Exclude overrides include for same criteria");
    }

    #endregion
}
