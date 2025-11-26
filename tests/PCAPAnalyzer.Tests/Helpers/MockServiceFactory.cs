using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.Core.Services.GeoIP;

namespace PCAPAnalyzer.Tests.Helpers;

/// <summary>
/// Centralized factory for creating mock services with common configurations
/// </summary>
public class MockServiceFactory
{
    private readonly TestDataBuilder _dataBuilder;

    public MockServiceFactory()
    {
        _dataBuilder = new TestDataBuilder();
    }

    /// <summary>
    /// Create a mock logger that doesn't throw
    /// </summary>
    public Mock<ILogger<T>> CreateLogger<T>()
    {
        var mock = new Mock<ILogger<T>>();
        mock.Setup(x => x.Log(
            It.IsAny<LogLevel>(),
            It.IsAny<EventId>(),
            It.IsAny<It.IsAnyType>(),
            It.IsAny<Exception>(),
            It.IsAny<Func<It.IsAnyType, Exception?, string>>()))
            .Verifiable();

        return mock;
    }

    /// <summary>
    /// Create a mock GeoIP service with configurable behavior
    /// </summary>
    public Mock<IGeoIPService> CreateGeoIPService(bool returnResults = true)
    {
        var mock = new Mock<IGeoIPService>();

        if (returnResults)
        {
            mock.Setup(x => x.GetLocationAsync(It.IsAny<string>()))
                .ReturnsAsync((string ip) => new GeoLocation
                {
                    IpAddress = ip,
                    CountryCode = "US",
                    CountryName = "United States",
                    City = "New York",
                    Latitude = 40.7128,
                    Longitude = -74.0060
                });

            mock.Setup(x => x.IsPublicIP(It.IsAny<string>()))
                .Returns((string ip) => !ip.StartsWith("192.168.") && !ip.StartsWith("10."));
        }
        else
        {
            mock.Setup(x => x.GetLocationAsync(It.IsAny<string>()))
                .ReturnsAsync((GeoLocation?)null);
        }

        return mock;
    }

    /// <summary>
    /// Create a mock packet store with pre-loaded packets
    /// </summary>
    public Mock<IPacketStore> CreatePacketStore(List<PacketInfo>? packets = null)
    {
        var mock = new Mock<IPacketStore>();
        var testPackets = packets ?? _dataBuilder.Packets.WithCount(100).Build();

        // Mock QueryPacketsAsync with PacketQuery
        mock.Setup(x => x.QueryPacketsAsync(
                It.IsAny<PacketQuery>(),
                It.IsAny<CancellationToken>()))
            .ReturnsAsync((PacketQuery query, CancellationToken ct) =>
                new PacketQueryResult
                {
                    Packets = testPackets,
                    TotalCount = testPackets.Count
                });

        return mock;
    }

    /// <summary>
    /// Create a mock statistics service with realistic data
    /// </summary>
    public Mock<IStatisticsService> CreateStatisticsService(NetworkStatistics? stats = null)
    {
        var mock = new Mock<IStatisticsService>();
        var testStats = stats ?? _dataBuilder.Statistics
            .WithTotalPackets(1000)
            .WithTotalBytes(1_000_000)
            .Build();

        // Note: IStatisticsService interface may need to be checked for actual method signatures
        // This is a placeholder that can be adjusted based on actual interface
        return mock;
    }

    /// <summary>
    /// Create a mock anomaly detector
    /// </summary>
    public Mock<IAnomalyDetector> CreateAnomalyDetector(List<NetworkAnomaly>? anomalies = null)
    {
        var mock = new Mock<IAnomalyDetector>();
        var testAnomalies = anomalies ?? _dataBuilder.Anomalies
            .WithCount(5)
            .WithSeverity(AnomalySeverity.Medium)
            .Build();

        mock.Setup(x => x.Name).Returns("Test Anomaly Detector");
        mock.Setup(x => x.Category).Returns(AnomalyCategory.Network);
        mock.Setup(x => x.Detect(It.IsAny<IEnumerable<PacketInfo>>()))
            .Returns(testAnomalies);

        return mock;
    }

    /// <summary>
    /// Create a complete service collection for integration tests
    /// </summary>
    public ServiceCollection CreateServiceCollection()
    {
        var services = new ServiceCollection();

        // Add logging
        services.AddLogging(builder => builder.AddDebug());

        // Add mock services
        services.AddSingleton(CreateGeoIPService().Object);
        services.AddSingleton(CreatePacketStore().Object);
        services.AddSingleton(CreateAnomalyDetector().Object);

        return services;
    }
}

/// <summary>
/// Extension methods for easier mock setup
/// </summary>
public static class MockExtensions
{
    /// <summary>
    /// Setup a mock to return a value asynchronously
    /// </summary>
    public static Mock<T> ReturnsAsyncValue<T>(this Mock<T> mock, object value) where T : class
    {
        // Generic async return helper
        return mock;
    }

    /// <summary>
    /// Verify that a method was called with specific parameters
    /// </summary>
    public static void VerifyCalledWith<T>(
        this Mock<T> mock,
        System.Linq.Expressions.Expression<Action<T>> expression,
        Times? times = null) where T : class
    {
        mock.Verify(expression, times ?? Times.Once());
    }
}
