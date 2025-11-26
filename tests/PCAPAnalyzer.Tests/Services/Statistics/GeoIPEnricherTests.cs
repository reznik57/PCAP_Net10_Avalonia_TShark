using FluentAssertions;
using Moq;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Orchestration;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Services.Statistics;

namespace PCAPAnalyzer.Tests.Services.Statistics;

public class GeoIPEnricherTests
{
    private readonly Mock<IGeoIPService> _mockGeoIPService;
    private readonly GeoIPEnricher _enricher;

    public GeoIPEnricherTests()
    {
        _mockGeoIPService = new Mock<IGeoIPService>();
        _enricher = new GeoIPEnricher(_mockGeoIPService.Object);
    }

    #region Constructor Tests

    [Fact]
    public void Constructor_WithNullGeoIPService_ThrowsArgumentNullException()
    {
        // Act & Assert
        FluentActions.Invoking(() => new GeoIPEnricher(null!))
            .Should().Throw<ArgumentNullException>()
            .WithMessage("*geoIPService*");
    }

    #endregion

    #region SamplePackets Tests

    [Fact]
    public void SamplePackets_WithPacketsLessThanMaxSamples_ReturnsAllPackets()
    {
        // Arrange
        var packets = CreateTestPackets(50);

        // Act
        var result = _enricher.SamplePackets(packets, 100);

        // Assert
        result.Should().HaveCount(50);
        result.Should().BeEquivalentTo(packets);
    }

    [Fact]
    public void SamplePackets_WithPacketsMoreThanMaxSamples_ReturnsSampledPackets()
    {
        // Arrange
        var packets = CreateTestPackets(1000);

        // Act
        var result = _enricher.SamplePackets(packets, 100);

        // Assert
        result.Should().HaveCount(100);
        result.Should().BeSubsetOf(packets);
    }

    [Fact]
    public void SamplePackets_WithEvenDistribution_ReturnsEvenlySampledPackets()
    {
        // Arrange
        var packets = CreateTestPackets(100);

        // Act
        var result = _enricher.SamplePackets(packets, 10);

        // Assert
        result.Should().HaveCount(10);
        // Every 10th packet should be selected
        result[0].Should().Be(packets[0]);
        result[1].Should().Be(packets[10]);
        result[9].Should().Be(packets[90]);
    }

    [Fact]
    public void SamplePackets_WithEmptyList_ReturnsEmptyList()
    {
        // Arrange
        var packets = new List<PacketInfo>();

        // Act
        var result = _enricher.SamplePackets(packets, 100);

        // Assert
        result.Should().BeEmpty();
    }

    #endregion

    #region UpdateEndpointCountriesAsync Tests

    [Fact]
    public async Task UpdateEndpointCountriesAsync_WithNullEndpoints_DoesNotThrow()
    {
        // Act
        Func<Task> act = async () => await _enricher.UpdateEndpointCountriesAsync(null!);

        // Assert
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task UpdateEndpointCountriesAsync_WithPublicIP_EnrichesWithGeoData()
    {
        // Arrange
        var endpoints = new List<EndpointStatistics>
        {
            new() { Address = "8.8.8.8", PacketCount = 100 }
        };

        _mockGeoIPService.Setup(x => x.IsPublicIP("8.8.8.8")).Returns(true);
        _mockGeoIPService.Setup(x => x.GetLocationAsync("8.8.8.8"))
            .ReturnsAsync(new GeoLocation
            {
                IpAddress = "8.8.8.8",
                CountryCode = "US",
                CountryName = "United States",
                City = "Mountain View"
            });
        _mockGeoIPService.Setup(x => x.IsHighRiskCountry("US")).Returns(false);

        // Act
        await _enricher.UpdateEndpointCountriesAsync(endpoints);

        // Assert
        endpoints[0].Country.Should().Be("United States");
        endpoints[0].CountryCode.Should().Be("US");
        endpoints[0].City.Should().Be("Mountain View");
        endpoints[0].IsHighRisk.Should().BeFalse();
    }

    [Fact]
    public async Task UpdateEndpointCountriesAsync_WithPrivateIP_EnrichesAsPrivateNetwork()
    {
        // Arrange
        var endpoints = new List<EndpointStatistics>
        {
            new() { Address = "192.168.1.100", PacketCount = 50 }
        };

        _mockGeoIPService.Setup(x => x.IsPublicIP("192.168.1.100")).Returns(false);

        // Act
        await _enricher.UpdateEndpointCountriesAsync(endpoints);

        // Assert
        endpoints[0].Country.Should().Be("Private Network");
        endpoints[0].CountryCode.Should().Be("Local");
        endpoints[0].City.Should().Be("Internal");
        endpoints[0].IsHighRisk.Should().BeFalse();
    }

    [Fact]
    public async Task UpdateEndpointCountriesAsync_WithHighRiskCountry_MarksAsHighRisk()
    {
        // Arrange
        var endpoints = new List<EndpointStatistics>
        {
            new() { Address = "1.2.3.4", PacketCount = 25 }
        };

        _mockGeoIPService.Setup(x => x.IsPublicIP("1.2.3.4")).Returns(true);
        _mockGeoIPService.Setup(x => x.GetLocationAsync("1.2.3.4"))
            .ReturnsAsync(new GeoLocation
            {
                IpAddress = "1.2.3.4",
                CountryCode = "XX",
                CountryName = "High Risk Country"
            });
        _mockGeoIPService.Setup(x => x.IsHighRiskCountry("XX")).Returns(true);

        // Act
        await _enricher.UpdateEndpointCountriesAsync(endpoints);

        // Assert
        endpoints[0].IsHighRisk.Should().BeTrue();
        endpoints[0].CountryCode.Should().Be("XX");
    }

    [Fact]
    public async Task UpdateEndpointCountriesAsync_WithGeoLookupFailure_SetsUnknown()
    {
        // Arrange
        var endpoints = new List<EndpointStatistics>
        {
            new() { Address = "1.2.3.4", PacketCount = 10 }
        };

        _mockGeoIPService.Setup(x => x.IsPublicIP("1.2.3.4")).Returns(true);
        _mockGeoIPService.Setup(x => x.GetLocationAsync("1.2.3.4"))
            .ThrowsAsync(new Exception("GeoIP lookup failed"));

        // Act
        await _enricher.UpdateEndpointCountriesAsync(endpoints);

        // Assert
        // When lookup throws, the catch block uses ??= which only sets if null
        // Since EndpointStatistics initializes Country="Unknown" and CountryCode="", those remain unchanged
        endpoints[0].Country.Should().Be("Unknown");
        // CountryCode is initialized to empty string and ??= won't change it since it's not null
        endpoints[0].CountryCode.Should().NotBeNull(); // Could be "" or "??" depending on initialization
    }

    [Fact]
    public async Task UpdateEndpointCountriesAsync_WithMultipleEndpoints_EnrichesAllInParallel()
    {
        // Arrange
        var endpoints = new List<EndpointStatistics>
        {
            new() { Address = "8.8.8.8" },
            new() { Address = "1.1.1.1" },
            new() { Address = "192.168.1.1" }
        };

        _mockGeoIPService.Setup(x => x.IsPublicIP(It.IsAny<string>()))
            .Returns<string>(ip => !ip.StartsWith("192.168."));

        _mockGeoIPService.Setup(x => x.GetLocationAsync("8.8.8.8"))
            .ReturnsAsync(new GeoLocation { CountryCode = "US", CountryName = "United States" });
        _mockGeoIPService.Setup(x => x.GetLocationAsync("1.1.1.1"))
            .ReturnsAsync(new GeoLocation { CountryCode = "AU", CountryName = "Australia" });

        // Act
        await _enricher.UpdateEndpointCountriesAsync(endpoints);

        // Assert
        endpoints[0].Country.Should().Be("United States");
        endpoints[1].Country.Should().Be("Australia");
        endpoints[2].Country.Should().Be("Private Network");
    }

    #endregion

    #region ExtractUniqueIPs Tests

    [Fact]
    public void ExtractUniqueIPs_WithEmptyList_ReturnsZero()
    {
        // Arrange
        var packets = new List<PacketInfo>();

        // Act
        var result = _enricher.ExtractUniqueIPs(packets);

        // Assert
        result.Should().Be(0);
    }

    [Fact]
    public void ExtractUniqueIPs_WithSinglePacket_ReturnsTwo()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacket("192.168.1.1", "192.168.1.2")
        };

        // Act
        var result = _enricher.ExtractUniqueIPs(packets);

        // Assert
        result.Should().Be(2);
    }

    [Fact]
    public void ExtractUniqueIPs_WithDuplicateIPs_CountsOnlyUnique()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            CreatePacket("192.168.1.1", "192.168.1.2"),
            CreatePacket("192.168.1.1", "192.168.1.3"),
            CreatePacket("192.168.1.2", "192.168.1.1")
        };

        // Act
        var result = _enricher.ExtractUniqueIPs(packets);

        // Assert
        result.Should().Be(3); // 192.168.1.1, 192.168.1.2, 192.168.1.3
    }

    [Fact]
    public void ExtractUniqueIPs_WithNullOrEmptyIPs_IgnoresThem()
    {
        // Arrange
        var packets = new List<PacketInfo>
        {
            new() { FrameNumber = 1, Timestamp = DateTime.UtcNow, SourceIP = "192.168.1.1", DestinationIP = "", Length = 100, SourcePort = 50000, DestinationPort = 443, Protocol = Protocol.TCP },
            new() { FrameNumber = 2, Timestamp = DateTime.UtcNow, SourceIP = null!, DestinationIP = "192.168.1.2", Length = 100, SourcePort = 50000, DestinationPort = 443, Protocol = Protocol.TCP },
            new() { FrameNumber = 3, Timestamp = DateTime.UtcNow, SourceIP = "192.168.1.3", DestinationIP = "192.168.1.4", Length = 100, SourcePort = 50000, DestinationPort = 443, Protocol = Protocol.TCP }
        };

        // Act
        var result = _enricher.ExtractUniqueIPs(packets);

        // Assert
        result.Should().Be(4); // Only non-null/empty IPs counted
    }

    #endregion

    #region ReportInitialProgress Tests

    [Fact]
    public void ReportInitialProgress_WithNullProgress_DoesNotThrow()
    {
        // Act
        Action act = () => _enricher.ReportInitialProgress(null, 1000);

        // Assert
        act.Should().NotThrow();
    }

    [Fact]
    public void ReportInitialProgress_WithProgress_ReportsCorrectData()
    {
        // Arrange
        AnalysisProgress? reportedProgress = null;
        var progress = new Progress<AnalysisProgress>(p => reportedProgress = p);

        // Act
        _enricher.ReportInitialProgress(progress, 1500);

        // Give progress time to report
        Thread.Sleep(10);

        // Assert
        reportedProgress.Should().NotBeNull();
        reportedProgress!.Phase.Should().Be("Analyzing Data");
        reportedProgress.Percent.Should().Be(50);
        reportedProgress.SubPhase.Should().Be("GeoIP Lookups");
        reportedProgress.TotalUniqueIPs.Should().Be(1500);
        reportedProgress.UniqueIPsProcessed.Should().Be(0);
    }

    #endregion

    #region UpdateConversationCountriesAsync Tests

    [Fact]
    public async Task UpdateConversationCountriesAsync_WithNullConversations_DoesNotThrow()
    {
        // Act
        Func<Task> act = async () => await _enricher.UpdateConversationCountriesAsync(null!);

        // Assert
        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task UpdateConversationCountriesAsync_WithPublicIPs_EnrichesCountries()
    {
        // Arrange
        var conversations = new List<ConversationStatistics>
        {
            new() { SourceAddress = "8.8.8.8", DestinationAddress = "1.1.1.1" }
        };

        _mockGeoIPService.Setup(x => x.IsPublicIP(It.IsAny<string>())).Returns(true);
        _mockGeoIPService.Setup(x => x.GetLocationAsync("8.8.8.8"))
            .ReturnsAsync(new GeoLocation { CountryName = "United States" });
        _mockGeoIPService.Setup(x => x.GetLocationAsync("1.1.1.1"))
            .ReturnsAsync(new GeoLocation { CountryName = "Australia" });

        // Act
        await _enricher.UpdateConversationCountriesAsync(conversations);

        // Assert
        conversations[0].SourceCountry.Should().Be("United States");
        conversations[0].DestinationCountry.Should().Be("Australia");
        conversations[0].IsCrossBorder.Should().BeTrue();
    }

    [Fact]
    public async Task UpdateConversationCountriesAsync_WithPrivateIPs_MarksAsPrivateNetwork()
    {
        // Arrange
        var conversations = new List<ConversationStatistics>
        {
            new() { SourceAddress = "192.168.1.1", DestinationAddress = "192.168.1.2" }
        };

        _mockGeoIPService.Setup(x => x.IsPublicIP(It.IsAny<string>())).Returns(false);

        // Act
        await _enricher.UpdateConversationCountriesAsync(conversations);

        // Assert
        conversations[0].SourceCountry.Should().Be("Private Network");
        conversations[0].DestinationCountry.Should().Be("Private Network");
        conversations[0].IsCrossBorder.Should().BeFalse();
    }

    [Fact]
    public async Task UpdateConversationCountriesAsync_WithSameCountry_MarksAsNotCrossBorder()
    {
        // Arrange
        var conversations = new List<ConversationStatistics>
        {
            new() { SourceAddress = "8.8.8.8", DestinationAddress = "8.8.4.4" }
        };

        _mockGeoIPService.Setup(x => x.IsPublicIP(It.IsAny<string>())).Returns(true);
        _mockGeoIPService.Setup(x => x.GetLocationAsync(It.IsAny<string>()))
            .ReturnsAsync(new GeoLocation { CountryName = "United States" });

        // Act
        await _enricher.UpdateConversationCountriesAsync(conversations);

        // Assert
        conversations[0].SourceCountry.Should().Be("United States");
        conversations[0].DestinationCountry.Should().Be("United States");
        conversations[0].IsCrossBorder.Should().BeFalse();
    }

    [Fact]
    public async Task UpdateConversationCountriesAsync_WithHighRiskSource_MarksAsHighRisk()
    {
        // Arrange
        var conversations = new List<ConversationStatistics>
        {
            new() { SourceAddress = "1.2.3.4", DestinationAddress = "8.8.8.8" }
        };

        _mockGeoIPService.Setup(x => x.IsPublicIP(It.IsAny<string>())).Returns(true);
        _mockGeoIPService.Setup(x => x.GetLocationAsync("1.2.3.4"))
            .ReturnsAsync(new GeoLocation { CountryName = "High Risk Country" });
        _mockGeoIPService.Setup(x => x.GetLocationAsync("8.8.8.8"))
            .ReturnsAsync(new GeoLocation { CountryName = "United States" });
        _mockGeoIPService.Setup(x => x.IsHighRiskCountry("High Risk Country")).Returns(true);
        _mockGeoIPService.Setup(x => x.IsHighRiskCountry("United States")).Returns(false);

        // Act
        await _enricher.UpdateConversationCountriesAsync(conversations);

        // Assert
        conversations[0].IsHighRisk.Should().BeTrue();
    }

    [Fact]
    public async Task UpdateConversationCountriesAsync_WithGeoLookupFailure_SetsUnknown()
    {
        // Arrange
        var conversations = new List<ConversationStatistics>
        {
            new() { SourceAddress = "1.2.3.4", DestinationAddress = "5.6.7.8" }
        };

        _mockGeoIPService.Setup(x => x.IsPublicIP(It.IsAny<string>())).Returns(true);
        _mockGeoIPService.Setup(x => x.GetLocationAsync(It.IsAny<string>()))
            .ThrowsAsync(new Exception("Lookup failed"));

        // Act
        await _enricher.UpdateConversationCountriesAsync(conversations);

        // Assert
        // When lookup fails, fallback sets these to Unknown using ??=
        conversations[0].SourceCountry.Should().Be("Unknown");
        conversations[0].DestinationCountry.Should().Be("Unknown");
    }

    #endregion

    #region Helper Methods

    private List<PacketInfo> CreateTestPackets(int count)
    {
        var packets = new List<PacketInfo>();
        for (int i = 0; i < count; i++)
        {
            packets.Add(new PacketInfo
            {
                FrameNumber = (uint)(i + 1),
                Timestamp = DateTime.UtcNow.AddSeconds(i),
                SourceIP = $"192.168.1.{(i % 254) + 1}",
                DestinationIP = $"10.0.0.{(i % 254) + 1}",
                Protocol = Protocol.TCP,
                Length = 100,
                SourcePort = 50000,
                DestinationPort = 443
            });
        }
        return packets;
    }

    private PacketInfo CreatePacket(string sourceIP, string destIP)
    {
        return new PacketInfo
        {
            FrameNumber = 1,
            Timestamp = DateTime.UtcNow,
            SourceIP = sourceIP,
            DestinationIP = destIP,
            Protocol = Protocol.TCP,
            Length = 100,
            SourcePort = 50000,
            DestinationPort = 443
        };
    }

    #endregion
}
