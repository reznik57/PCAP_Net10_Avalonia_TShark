using PCAPAnalyzer.UI.Services.Filters;
using Xunit;
using static PCAPAnalyzer.UI.Services.Filters.FilterDomainClassifier;

namespace PCAPAnalyzer.Tests.Services.Filters;

/// <summary>
/// Tests for FilterDomainClassifier - classifies quick filters for AND/OR logic.
/// </summary>
public class FilterDomainClassifierTests
{
    #region IP Address Domain

    [Theory]
    [InlineData("IPv4", FilterDomain.IpAddress)]
    [InlineData("IPv6", FilterDomain.IpAddress)]
    [InlineData("RFC1918", FilterDomain.IpAddress)]
    [InlineData("PublicIP", FilterDomain.IpAddress)]
    [InlineData("Public", FilterDomain.IpAddress)]
    [InlineData("APIPA", FilterDomain.IpAddress)]
    [InlineData("Loopback", FilterDomain.IpAddress)]
    [InlineData("Multicast", FilterDomain.IpAddress)]
    [InlineData("Broadcast", FilterDomain.IpAddress)]
    public void GetDomain_IpAddressFilters_ReturnIpAddressDomain(string filter, FilterDomain expected)
    {
        Assert.Equal(expected, GetDomain(filter));
    }

    #endregion

    #region Direction Domain

    [Theory]
    [InlineData("PrivateToPublic", FilterDomain.Direction)]
    [InlineData("PublicToPrivate", FilterDomain.Direction)]
    [InlineData("Inbound", FilterDomain.Direction)]
    [InlineData("Outbound", FilterDomain.Direction)]
    [InlineData("Internal", FilterDomain.Direction)]
    public void GetDomain_DirectionFilters_ReturnDirectionDomain(string filter, FilterDomain expected)
    {
        Assert.Equal(expected, GetDomain(filter));
    }

    #endregion

    #region Transport Domain

    [Theory]
    [InlineData("TCP", FilterDomain.Transport)]
    [InlineData("UDP", FilterDomain.Transport)]
    [InlineData("ICMP", FilterDomain.Transport)]
    [InlineData("ARP", FilterDomain.Transport)]
    [InlineData("IGMP", FilterDomain.Transport)]
    [InlineData("GRE", FilterDomain.Transport)]
    public void GetDomain_TransportFilters_ReturnTransportDomain(string filter, FilterDomain expected)
    {
        Assert.Equal(expected, GetDomain(filter));
    }

    #endregion

    #region TCP Flags Domain

    [Theory]
    [InlineData("SYN", FilterDomain.TcpFlags)]
    [InlineData("TcpSyn", FilterDomain.TcpFlags)]
    [InlineData("SYN-ACK", FilterDomain.TcpFlags)]
    [InlineData("TcpSynAck", FilterDomain.TcpFlags)]
    [InlineData("RST", FilterDomain.TcpFlags)]
    [InlineData("TcpRst", FilterDomain.TcpFlags)]
    [InlineData("FIN", FilterDomain.TcpFlags)]
    [InlineData("PSH", FilterDomain.TcpFlags)]
    [InlineData("ACK-only", FilterDomain.TcpFlags)]
    [InlineData("URG", FilterDomain.TcpFlags)]
    public void GetDomain_TcpFlagFilters_ReturnTcpFlagsDomain(string filter, FilterDomain expected)
    {
        Assert.Equal(expected, GetDomain(filter));
    }

    #endregion

    #region Service Domain

    [Theory]
    [InlineData("HTTP", FilterDomain.Service)]
    [InlineData("HTTPS", FilterDomain.Service)]
    [InlineData("DNS", FilterDomain.Service)]
    [InlineData("SSH", FilterDomain.Service)]
    [InlineData("FTP", FilterDomain.Service)]
    [InlineData("SMTP", FilterDomain.Service)]
    [InlineData("SIP", FilterDomain.Service)]
    [InlineData("RTP", FilterDomain.Service)]
    [InlineData("RTCP", FilterDomain.Service)]
    [InlineData("WebRTC", FilterDomain.Service)]
    public void GetDomain_ServiceFilters_ReturnServiceDomain(string filter, FilterDomain expected)
    {
        Assert.Equal(expected, GetDomain(filter));
    }

    #endregion

    #region Security Domain

    [Theory]
    [InlineData("TlsV10", FilterDomain.Security)]
    [InlineData("TlsV11", FilterDomain.Security)]
    [InlineData("ObsoleteCrypto", FilterDomain.Security)]
    [InlineData("Insecure", FilterDomain.Security)]
    [InlineData("CleartextAuth", FilterDomain.Security)]
    [InlineData("Encrypted", FilterDomain.Security)]
    [InlineData("WireGuard", FilterDomain.Security)]
    [InlineData("OpenVPN", FilterDomain.Security)]
    [InlineData("IPSec", FilterDomain.Security)]
    public void GetDomain_SecurityFilters_ReturnSecurityDomain(string filter, FilterDomain expected)
    {
        Assert.Equal(expected, GetDomain(filter));
    }

    #endregion

    #region Frame Domain

    [Theory]
    [InlineData("SmallFrame", FilterDomain.Frame)]
    [InlineData("Fragmented", FilterDomain.Frame)]
    [InlineData("Retransmission", FilterDomain.Frame)]
    [InlineData("Retransmissions", FilterDomain.Frame)]
    [InlineData("OutOfOrder", FilterDomain.Frame)]
    [InlineData("DuplicateAck", FilterDomain.Frame)]
    [InlineData("ZeroWindow", FilterDomain.Frame)]
    [InlineData("WindowFull", FilterDomain.Frame)]
    public void GetDomain_FrameFilters_ReturnFrameDomain(string filter, FilterDomain expected)
    {
        Assert.Equal(expected, GetDomain(filter));
    }

    #endregion

    #region Unknown Filters

    [Theory]
    [InlineData("Unknown")]
    [InlineData("NotAFilter")]
    [InlineData("")]
    [InlineData(null)]
    public void GetDomain_UnknownFilters_ReturnOtherDomain(string? filter)
    {
        Assert.Equal(FilterDomain.Other, GetDomain(filter));
    }

    #endregion

    #region AreSameDomain

    [Theory]
    [InlineData("TCP", "UDP", true)]       // Both Transport
    [InlineData("SYN", "RST", true)]       // Both TcpFlags
    [InlineData("HTTP", "DNS", true)]      // Both Service
    [InlineData("TCP", "SYN", false)]      // Transport vs TcpFlags
    [InlineData("HTTP", "IPv4", false)]    // Service vs IpAddress
    public void AreSameDomain_ReturnsCorrectResult(string filter1, string filter2, bool expected)
    {
        Assert.Equal(expected, AreSameDomain(filter1, filter2));
    }

    #endregion

    #region GroupByDomain

    [Fact]
    public void GroupByDomain_GroupsFiltersCorrectly()
    {
        var filters = new[] { "TCP", "UDP", "SYN", "RST", "HTTP" };
        var groups = GroupByDomain(filters);

        Assert.Equal(3, groups.Count);
        Assert.Contains(FilterDomain.Transport, groups.Keys);
        Assert.Contains(FilterDomain.TcpFlags, groups.Keys);
        Assert.Contains(FilterDomain.Service, groups.Keys);

        Assert.Equal(2, groups[FilterDomain.Transport].Count); // TCP, UDP
        Assert.Equal(2, groups[FilterDomain.TcpFlags].Count);  // SYN, RST
        Assert.Single(groups[FilterDomain.Service]);           // HTTP
    }

    [Fact]
    public void GroupByDomain_EmptyInput_ReturnsEmptyDictionary()
    {
        var groups = GroupByDomain([]);
        Assert.Empty(groups);
    }

    #endregion
}
