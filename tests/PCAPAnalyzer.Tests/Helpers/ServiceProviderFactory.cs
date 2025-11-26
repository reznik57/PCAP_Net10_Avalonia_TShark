using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.UI;

namespace PCAPAnalyzer.Tests.Helpers;

/// <summary>
/// Factory for creating service providers in tests.
/// Provides both real implementations and mock-friendly configurations.
/// </summary>
public static class ServiceProviderFactory
{
    /// <summary>
    /// Creates a service provider with real implementations (for integration tests).
    /// </summary>
    public static IServiceProvider CreateRealServiceProvider(
        ILoggerFactory? loggerFactory = null)
    {
        var services = new ServiceCollection();

        // Add logging
        if (loggerFactory != null)
        {
            services.AddSingleton(loggerFactory);
        }
        else
        {
            services.AddLogging(builder => builder.AddDebug());
        }

        // Add real services (from ServiceConfiguration)
        services.AddPcapAnalyzerServices();

        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Creates a service provider with specific service overrides (for unit tests).
    /// </summary>
    public static IServiceProvider CreateMockServiceProvider(
        Action<IServiceCollection>? configureServices = null)
    {
        var services = new ServiceCollection();

        // Add logging
        services.AddLogging(builder => builder.AddDebug());

        // Add base services
        services.AddPcapAnalyzerServices();

        // Allow test-specific overrides
        configureServices?.Invoke(services);

        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Creates a minimal service provider with only specified services.
    /// </summary>
    public static IServiceProvider CreateMinimalServiceProvider(
        params (Type serviceType, object implementation)[] services)
    {
        var collection = new ServiceCollection();

        collection.AddLogging(builder => builder.AddDebug());

        foreach (var (serviceType, implementation) in services)
        {
            collection.AddSingleton(serviceType, implementation);
        }

        return collection.BuildServiceProvider();
    }
}
