using System.Reflection;
using System.Runtime.InteropServices;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Collects and reports application dependencies including NuGet packages,
/// external tools (TShark), and data files (GeoIP, MAC vendors).
/// </summary>
public sealed class DependencyService : IDependencyService
{
    private readonly Func<string, string?, (bool IsAvailable, string? Version)>? _toolDetector;

    public DependencyService()
    {
    }

    /// <summary>
    /// Constructor for testing with mock tool detector
    /// </summary>
    public DependencyService(Func<string, string?, (bool IsAvailable, string? Version)> toolDetector)
    {
        _toolDetector = toolDetector;
    }

    public Task<ApplicationDependencies> CollectDependenciesAsync(CancellationToken cancellationToken = default)
    {
        var dependencies = new List<DependencyInfo>();

        // 1. Framework dependencies
        dependencies.AddRange(CollectFrameworkDependencies());

        // 2. NuGet package dependencies (from loaded assemblies)
        dependencies.AddRange(CollectNuGetDependencies());

        // 3. External tools (TShark, editcap, capinfos)
        dependencies.AddRange(CollectExternalTools());

        // 4. Data files
        dependencies.AddRange(CollectDataFiles());

        var result = new ApplicationDependencies
        {
            ApplicationName = "PCAP Security Analyzer",
            ApplicationVersion = GetApplicationVersion(),
            RuntimeVersion = RuntimeInformation.FrameworkDescription,
            OSDescription = RuntimeInformation.OSDescription,
            Dependencies = dependencies
        };

        return Task.FromResult(result);
    }

    private static IEnumerable<DependencyInfo> CollectFrameworkDependencies()
    {
        yield return new DependencyInfo
        {
            Name = ".NET Runtime",
            Version = Environment.Version.ToString(),
            Category = DependencyCategory.Framework,
            Description = RuntimeInformation.FrameworkDescription,
            Status = DependencyStatus.Available
        };

        yield return new DependencyInfo
        {
            Name = "C# Language",
            Version = "14.0",
            Category = DependencyCategory.Framework,
            Description = "C# 14 with field keyword, extension members",
            Status = DependencyStatus.Available
        };
    }

    // Package family definitions for consolidation
    private static readonly (string Prefix, string DisplayName, string Description, string License, string ProjectUrl, DependencyCategory Category)[] PackageFamilies =
    [
        ("Avalonia", "Avalonia UI", "Cross-platform .NET UI framework", "MIT", "https://github.com/AvaloniaUI/Avalonia", DependencyCategory.UIFramework),
        ("LiveCharts", "LiveCharts2", "Modern charting library for .NET", "MIT", "https://github.com/beto-rodriguez/LiveCharts2", DependencyCategory.UIFramework),
        ("SkiaSharp", "SkiaSharp", "Cross-platform 2D graphics library", "MIT", "https://github.com/mono/SkiaSharp", DependencyCategory.UIFramework),
        ("MaxMind", "MaxMind GeoIP", "IP geolocation library", "Apache-2.0", "https://github.com/maxmind/GeoIP2-dotnet", DependencyCategory.CoreLibrary),
        ("NetTopologySuite", "NetTopologySuite", "GIS/geometry library for .NET", "BSD-3-Clause", "https://github.com/NetTopologySuite/NetTopologySuite", DependencyCategory.CoreLibrary),
        ("QuestPDF", "QuestPDF", "PDF document generation library", "MIT", "https://github.com/QuestPDF/QuestPDF", DependencyCategory.CoreLibrary),
        ("CommunityToolkit", "CommunityToolkit", "MVVM toolkit and high-performance utilities", "MIT", "https://github.com/CommunityToolkit/dotnet", DependencyCategory.CoreLibrary),
        ("Microsoft.Extensions", "Microsoft.Extensions", "Dependency injection, caching, logging", "MIT", "https://github.com/dotnet/runtime", DependencyCategory.CoreLibrary),
        ("Microsoft.Data.Sqlite", "Microsoft.Data.Sqlite", "SQLite database provider", "MIT", "https://github.com/dotnet/efcore", DependencyCategory.CoreLibrary),
    ];

    private static IEnumerable<DependencyInfo> CollectNuGetDependencies()
    {
        var loadedAssemblies = AppDomain.CurrentDomain.GetAssemblies()
            .Where(a => !a.IsDynamic && !string.IsNullOrEmpty(a.Location))
            .ToList();

        // Group assemblies by package family and track highest version
        var familyVersions = new Dictionary<string, Version>(StringComparer.OrdinalIgnoreCase);

        foreach (var assembly in loadedAssemblies)
        {
            var name = assembly.GetName();
            var assemblyName = name.Name ?? string.Empty;
            var version = name.Version;

            if (version == null)
                continue;

            // Find which family this assembly belongs to
            foreach (var (prefix, _, _, _, _, _) in PackageFamilies)
            {
                if (assemblyName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                {
                    if (!familyVersions.TryGetValue(prefix, out var existingVersion) || version > existingVersion)
                    {
                        familyVersions[prefix] = version;
                    }
                    break;
                }
            }
        }

        // Yield consolidated entries for each detected family
        foreach (var (prefix, displayName, description, license, projectUrl, category) in PackageFamilies)
        {
            if (familyVersions.TryGetValue(prefix, out var version))
            {
                yield return new DependencyInfo
                {
                    Name = displayName,
                    Version = version.ToString(3),
                    Category = category,
                    Description = description,
                    License = license,
                    ProjectUrl = projectUrl,
                    Status = DependencyStatus.Available
                };
            }
        }
    }

    private IEnumerable<DependencyInfo> CollectExternalTools()
    {
        // TShark
        var (tsharkAvailable, tsharkVersion) = DetectTool("tshark", "tshark.exe");
        yield return new DependencyInfo
        {
            Name = "TShark (Wireshark CLI)",
            Version = tsharkVersion ?? "Not Found",
            Category = DependencyCategory.ExternalTool,
            Description = "Network protocol analyzer - core packet parsing engine",
            Status = tsharkAvailable ? DependencyStatus.Available : DependencyStatus.NotFound,
            ProjectUrl = "https://www.wireshark.org/"
        };

        // editcap
        var (editcapAvailable, editcapVersion) = DetectTool("editcap", "editcap.exe");
        yield return new DependencyInfo
        {
            Name = "editcap",
            Version = editcapVersion ?? "Not Found",
            Category = DependencyCategory.ExternalTool,
            Description = "PCAP file splitter for parallel processing",
            Status = editcapAvailable ? DependencyStatus.Available : DependencyStatus.NotFound,
            ProjectUrl = "https://www.wireshark.org/"
        };

        // capinfos
        var (capinfosAvailable, capinfosVersion) = DetectTool("capinfos", "capinfos.exe");
        yield return new DependencyInfo
        {
            Name = "capinfos",
            Version = capinfosVersion ?? "Not Found",
            Category = DependencyCategory.ExternalTool,
            Description = "Fast packet count from PCAP headers",
            Status = capinfosAvailable ? DependencyStatus.Available : DependencyStatus.NotFound,
            ProjectUrl = "https://www.wireshark.org/"
        };
    }

    private (bool IsAvailable, string? Version) DetectTool(string toolName, string windowsExeName)
    {
        if (_toolDetector != null)
            return _toolDetector(toolName, windowsExeName);

        try
        {
            // Use WiresharkToolDetector from TShark assembly via reflection to avoid circular dependency
            var tsharkAssembly = AppDomain.CurrentDomain.GetAssemblies()
                .FirstOrDefault(a => a.GetName().Name == "PCAPAnalyzer.TShark");

            if (tsharkAssembly == null)
                return (false, null);

            var detectorType = tsharkAssembly.GetType("PCAPAnalyzer.TShark.WiresharkToolDetector");
            if (detectorType == null)
                return (false, null);

            var detectMethod = detectorType.GetMethod($"Detect{char.ToUpperInvariant(toolName[0])}{toolName[1..]}",
                BindingFlags.Public | BindingFlags.Static);

            // Fall back to DetectTShark for tshark
            if (detectMethod == null && toolName == "tshark")
                detectMethod = detectorType.GetMethod("DetectTShark", BindingFlags.Public | BindingFlags.Static);
            if (detectMethod == null && toolName == "editcap")
                detectMethod = detectorType.GetMethod("DetectEditcap", BindingFlags.Public | BindingFlags.Static);
            if (detectMethod == null && toolName == "capinfos")
                detectMethod = detectorType.GetMethod("DetectCapinfos", BindingFlags.Public | BindingFlags.Static);

            if (detectMethod == null)
                return (false, null);

            var toolInfo = detectMethod.Invoke(null, null);
            if (toolInfo == null)
                return (false, null);

            var isAvailableProp = toolInfo.GetType().GetProperty("IsAvailable");
            var descriptionProp = toolInfo.GetType().GetProperty("Description");

            var isAvailable = (bool)(isAvailableProp?.GetValue(toolInfo) ?? false);
            var description = descriptionProp?.GetValue(toolInfo)?.ToString();

            if (!isAvailable)
                return (false, null);

            // Try to get version via TestTool
            var testMethod = detectorType.GetMethod("TestTool", BindingFlags.Public | BindingFlags.Static);
            if (testMethod != null)
            {
                var parameters = new object?[] { toolInfo, null };
                var result = (bool)(testMethod.Invoke(null, parameters) ?? false);
                if (result && parameters[1] is string version)
                    return (true, version);
            }

            return (true, description);
        }
        catch
        {
            return (false, null);
        }
    }

    private static IEnumerable<DependencyInfo> CollectDataFiles()
    {
        var baseDir = AppDomain.CurrentDomain.BaseDirectory;
        var workingDir = Environment.CurrentDirectory;

        // GeoIP Database
        var geoIpPaths = new[]
        {
            Path.Combine(workingDir, "GeoLite2-Country.mmdb"),
            Path.Combine(baseDir, "GeoLite2-Country.mmdb")
        };
        var geoIpPath = geoIpPaths.FirstOrDefault(File.Exists);

        yield return new DependencyInfo
        {
            Name = "MaxMind GeoLite2 Country",
            Version = geoIpPath != null ? GetFileDate(geoIpPath) : "Not Found",
            Category = DependencyCategory.DataFile,
            Description = "IP geolocation database for country detection",
            Path = geoIpPath,
            Status = geoIpPath != null ? DependencyStatus.Available : DependencyStatus.NotFound,
            License = "CC BY-SA 4.0",
            ProjectUrl = "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
        };

        // MAC Vendor Database (embedded resource, check if service is available)
        yield return new DependencyInfo
        {
            Name = "IEEE OUI MAC Vendor Database",
            Version = "1.0.0",
            Category = DependencyCategory.DataFile,
            Description = "MAC address vendor lookup (OUI prefixes)",
            Status = DependencyStatus.Available,
            License = "Public Domain"
        };

        // Natural Earth Shapefile
        var shapefilePaths = new[]
        {
            Path.Combine(baseDir, "Assets", "maps", "ne_110m_admin_0_countries.shp"),
            Path.Combine(workingDir, "Assets", "maps", "ne_110m_admin_0_countries.shp")
        };
        var shapefilePath = shapefilePaths.FirstOrDefault(File.Exists);

        yield return new DependencyInfo
        {
            Name = "Natural Earth Admin 0 Countries",
            Version = shapefilePath != null ? "110m resolution" : "Not Found",
            Category = DependencyCategory.DataFile,
            Description = "World map shapefile for geographic visualization",
            Path = shapefilePath,
            Status = shapefilePath != null ? DependencyStatus.Available : DependencyStatus.NotFound,
            License = "Public Domain",
            ProjectUrl = "https://www.naturalearthdata.com/"
        };

        // Port definitions (embedded)
        yield return new DependencyInfo
        {
            Name = "Port Definitions Database",
            Version = "1.0.0",
            Category = DependencyCategory.DataFile,
            Description = "Well-known port descriptions and categories",
            Status = DependencyStatus.Available
        };

        // Protocol definitions
        yield return new DependencyInfo
        {
            Name = "Protocol Definitions",
            Version = "1.0.0",
            Category = DependencyCategory.DataFile,
            Description = "Network protocol metadata and descriptions",
            Status = DependencyStatus.Available
        };
    }

    private static string GetFileDate(string path)
    {
        try
        {
            var lastWrite = File.GetLastWriteTime(path);
            return lastWrite.ToString("yyyy-MM-dd");
        }
        catch
        {
            return "Unknown";
        }
    }

    private static string GetApplicationVersion()
    {
        var assembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
        var version = assembly.GetName().Version;
        return version?.ToString(3) ?? "1.0.0";
    }
}
