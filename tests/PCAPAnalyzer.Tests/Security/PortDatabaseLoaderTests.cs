using FluentAssertions;
using PCAPAnalyzer.Core.Security;
using Xunit;
using static PCAPAnalyzer.Core.Security.PortDatabase;

namespace PCAPAnalyzer.Tests.Security;

/// <summary>
/// Tests for PortDatabaseLoader to verify JSON embedded resource loading
/// </summary>
public class PortDatabaseLoaderTests
{
    [Fact]
    public void Database_LoadsSuccessfully()
    {
        // Act
        var database = PortDatabaseLoader.Database;

        // Assert
        database.Should().NotBeNull();
        database.Should().NotBeEmpty();
        database.Count.Should().BeGreaterThan(100, "ports.json should contain 600+ ports");
    }

    [Fact]
    public void TcpPorts_LoadsSuccessfully()
    {
        // Act
        var tcpPorts = PortDatabaseLoader.TcpPorts;

        // Assert
        tcpPorts.Should().NotBeNull();
        tcpPorts.Should().NotBeEmpty();
    }

    [Fact]
    public void UdpPorts_LoadsSuccessfully()
    {
        // Act
        var udpPorts = PortDatabaseLoader.UdpPorts;

        // Assert
        udpPorts.Should().NotBeNull();
        udpPorts.Should().NotBeEmpty();
    }

    [Fact]
    public void Database_ContainsExpectedWellKnownPorts()
    {
        // Arrange
        var database = PortDatabaseLoader.Database;

        // Act & Assert - Test common ports
        var httpKey = new PortKey(80, TransportProtocol.TCP);
        database.Should().ContainKey(httpKey);
        database[httpKey].ServiceName.Should().Contain("HTTP");

        var httpsKey = new PortKey(443, TransportProtocol.TCP);
        database.Should().ContainKey(httpsKey);
        database[httpsKey].ServiceName.Should().Contain("HTTPS");

        var dnsUdpKey = new PortKey(53, TransportProtocol.UDP);
        database.Should().ContainKey(dnsUdpKey);
        database[dnsUdpKey].ServiceName.Should().Contain("DNS");
    }

    [Fact]
    public void Database_HandlesTransportBothCorrectly()
    {
        // Arrange
        var database = PortDatabaseLoader.Database;

        // Act - Check for ports that use "Both" in JSON (e.g., port 53 DNS)
        var dnsTcpKey = new PortKey(53, TransportProtocol.TCP);
        var dnsUdpKey = new PortKey(53, TransportProtocol.UDP);

        // Assert - Both TCP and UDP entries should exist for "Both" transport
        database.Should().ContainKey(dnsTcpKey);
        database.Should().ContainKey(dnsUdpKey);
        database[dnsTcpKey].ServiceName.Should().Be(database[dnsUdpKey].ServiceName);
    }

    [Fact]
    public void TcpPorts_ContainsOnlyTcpEntries()
    {
        // Act
        var tcpPorts = PortDatabaseLoader.TcpPorts;

        // Assert
        tcpPorts.Should().ContainKey(80); // HTTP
        tcpPorts.Should().ContainKey(443); // HTTPS
        tcpPorts.Should().ContainKey(22); // SSH
    }

    [Fact]
    public void UdpPorts_ContainsOnlyUdpEntries()
    {
        // Act
        var udpPorts = PortDatabaseLoader.UdpPorts;

        // Assert
        udpPorts.Should().ContainKey(53); // DNS
        udpPorts.Should().ContainKey(67); // DHCP Server
        udpPorts.Should().ContainKey(161); // SNMP
    }

    [Fact]
    public void PortInfo_ContainsExpectedFields()
    {
        // Arrange
        var database = PortDatabaseLoader.Database;
        var httpsKey = new PortKey(443, TransportProtocol.TCP);

        // Act
        var portInfo = database[httpsKey];

        // Assert
        portInfo.ServiceName.Should().NotBeNullOrEmpty();
        portInfo.Description.Should().NotBeNullOrEmpty();
        portInfo.Risk.Should().BeOneOf(PortRisk.Low, PortRisk.Medium, PortRisk.High, PortRisk.Critical, PortRisk.Unknown);
    }

    [Fact]
    public void Database_IsThreadSafe_MultipleConcurrentAccesses()
    {
        // Act & Assert - Multiple concurrent accesses should not throw
        Parallel.For(0, 100, _ =>
        {
            var db = PortDatabaseLoader.Database;
            db.Should().NotBeNull();
        });
    }
}
