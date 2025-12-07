using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Capture.Models;

namespace PCAPAnalyzer.Core.Capture
{
    /// <summary>
    /// Discovers available network interfaces using TShark
    /// Provides cross-platform interface detection and metadata retrieval
    /// </summary>
    public sealed partial class NetworkInterfaceDiscovery : IDisposable
    {
        private bool _disposed;
        private readonly string _tsharkPath;
        private List<NetworkInterface>? _cachedInterfaces;
        private DateTime _cacheExpiration = DateTime.MinValue;
        private readonly TimeSpan _cacheLifetime = TimeSpan.FromMinutes(5);
        private readonly SemaphoreSlim _cacheLock = new(1, 1);

        /// <summary>
        /// Gets or sets the TShark executable path
        /// </summary>
        public string TSharkPath => _tsharkPath;

        /// <summary>
        /// Initializes a new network interface discovery service
        /// </summary>
        /// <param name="tsharkPath">Path to TShark executable (null for system default)</param>
        public NetworkInterfaceDiscovery(string? tsharkPath = null)
        {
            _tsharkPath = tsharkPath ?? FindTSharkPath();
        }

        /// <summary>
        /// Discovers all available network interfaces
        /// </summary>
        /// <param name="forceRefresh">Forces cache refresh</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>List of discovered network interfaces</returns>
        public async Task<List<NetworkInterface>> DiscoverInterfacesAsync(
            bool forceRefresh = false,
            CancellationToken cancellationToken = default)
        {
            await _cacheLock.WaitAsync(cancellationToken);
            try
            {
                // Check cache
                if (!forceRefresh && _cachedInterfaces is not null && DateTime.UtcNow < _cacheExpiration)
                {
                    return _cachedInterfaces.ToList();
                }

                // Discover interfaces
                var interfaces = new List<NetworkInterface>();

                // Use tshark -D to list interfaces
                var interfaceList = await RunTSharkCommandAsync("-D", cancellationToken);
                if (!string.IsNullOrEmpty(interfaceList))
                {
                    interfaces.AddRange(ParseInterfaceList(interfaceList));
                }

                // Enrich with additional information
                await EnrichInterfaceInformationAsync(interfaces, cancellationToken);

                // Update cache
                _cachedInterfaces = interfaces;
                _cacheExpiration = DateTime.UtcNow.Add(_cacheLifetime);

                return interfaces.ToList();
            }
            finally
            {
                _cacheLock.Release();
            }
        }

        /// <summary>
        /// Gets a specific interface by ID
        /// </summary>
        /// <param name="interfaceId">Interface identifier</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Network interface or null if not found</returns>
        public async Task<NetworkInterface?> GetInterfaceByIdAsync(
            string interfaceId,
            CancellationToken cancellationToken = default)
        {
            var interfaces = await DiscoverInterfacesAsync(false, cancellationToken);
            return interfaces.FirstOrDefault(i =>
                i.Id.Equals(interfaceId, StringComparison.OrdinalIgnoreCase) ||
                i.Name.Equals(interfaceId, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Tests if an interface is available for capture
        /// </summary>
        /// <param name="interfaceId">Interface identifier</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>True if interface is available</returns>
        public async Task<bool> IsInterfaceAvailableAsync(
            string interfaceId,
            CancellationToken cancellationToken = default)
        {
            try
            {
                var iface = await GetInterfaceByIdAsync(interfaceId, cancellationToken);
                return iface is not null && iface.IsUp && iface.Status == InterfaceStatus.Up;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validates TShark installation
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Validation result with version information</returns>
        public async Task<TSharkValidationResult> ValidateTSharkInstallationAsync(
            CancellationToken cancellationToken = default)
        {
            try
            {
                var versionOutput = await RunTSharkCommandAsync("--version", cancellationToken);

                if (string.IsNullOrEmpty(versionOutput))
                {
                    return new TSharkValidationResult
                    {
                        IsValid = false,
                        ErrorMessage = "TShark not found or not executable"
                    };
                }

                // Parse version
                var versionMatch = VersionRegex().Match(versionOutput);
                string version = versionMatch.Success ? versionMatch.Groups[1].Value : "Unknown";

                return new TSharkValidationResult
                {
                    IsValid = true,
                    Version = version,
                    ExecutablePath = _tsharkPath
                };
            }
            catch (Exception ex)
            {
                return new TSharkValidationResult
                {
                    IsValid = false,
                    ErrorMessage = $"TShark validation failed: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Parses TShark interface list output
        /// </summary>
        private List<NetworkInterface> ParseInterfaceList(string output)
        {
            var interfaces = new List<NetworkInterface>();
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                // TShark format: "1. eth0 (Ethernet)"
                var match = InterfaceLineRegex().Match(line);
                if (!match.Success) continue;

                var index = match.Groups[1].Value;
                var name = match.Groups[2].Value;
                var description = match.Groups[3].Success ? match.Groups[3].Value : name;

                interfaces.Add(new NetworkInterface
                {
                    Id = name,
                    Name = name,
                    Description = description,
                    Status = InterfaceStatus.Unknown,
                    IsUp = true,
                    Type = DetermineInterfaceType(name, description),
                    SupportsPromiscuousMode = true
                });
            }

            return interfaces;
        }

        /// <summary>
        /// Enriches interface information with additional details
        /// </summary>
        private async Task EnrichInterfaceInformationAsync(
            List<NetworkInterface> interfaces,
            CancellationToken cancellationToken)
        {
            // Use platform-specific commands to get more details
            if (OperatingSystem.IsWindows())
            {
                await EnrichWindowsInterfacesAsync(interfaces, cancellationToken);
            }
            else if (OperatingSystem.IsLinux())
            {
                await EnrichLinuxInterfacesAsync(interfaces, cancellationToken);
            }
            else if (OperatingSystem.IsMacOS())
            {
                await EnrichMacOSInterfacesAsync(interfaces, cancellationToken);
            }
        }

        /// <summary>
        /// Enriches interface information on Windows
        /// </summary>
        private async Task EnrichWindowsInterfacesAsync(
            List<NetworkInterface> interfaces,
            CancellationToken cancellationToken)
        {
            try
            {
                var ipConfigOutput = await RunCommandAsync("ipconfig", "/all", cancellationToken);
                // Parse ipconfig output to enrich interface data
                // This is a simplified version - production code would parse more thoroughly
            }
            catch
            {
                // Enrichment is optional, continue without it
            }
        }

        /// <summary>
        /// Enriches interface information on Linux
        /// </summary>
        private async Task EnrichLinuxInterfacesAsync(
            List<NetworkInterface> interfaces,
            CancellationToken cancellationToken)
        {
            try
            {
                // Use 'ip' command to get interface details
                var ipOutput = await RunCommandAsync("ip", "-j addr show", cancellationToken);
                if (!string.IsNullOrEmpty(ipOutput))
                {
                    try
                    {
                        var ipData = JsonSerializer.Deserialize<JsonElement[]>(ipOutput);
                        if (ipData is not null)
                        {
                            foreach (var iface in interfaces)
                            {
                                var ipInfo = ipData.FirstOrDefault(x =>
                                    x.TryGetProperty("ifname", out var name) &&
                                    name.GetString() == iface.Name);

                                if (ipInfo.ValueKind != JsonValueKind.Undefined)
                                {
                                    EnrichFromIpJson(iface, ipInfo);
                                }
                            }
                        }
                    }
                    catch
                    {
                        // JSON parsing failed, continue without enrichment
                    }
                }
            }
            catch
            {
                // Enrichment is optional, continue without it
            }
        }

        /// <summary>
        /// Enriches interface information on macOS
        /// </summary>
        private async Task EnrichMacOSInterfacesAsync(
            List<NetworkInterface> interfaces,
            CancellationToken cancellationToken)
        {
            try
            {
                var ifconfigOutput = await RunCommandAsync("ifconfig", "-a", cancellationToken);
                // Parse ifconfig output to enrich interface data
            }
            catch
            {
                // Enrichment is optional, continue without it
            }
        }

        /// <summary>
        /// Enriches interface from ip command JSON output
        /// </summary>
        private void EnrichFromIpJson(NetworkInterface iface, JsonElement ipInfo)
        {
            // Extract flags
            if (ipInfo.TryGetProperty("flags", out var flags))
            {
                var flagArray = flags.EnumerateArray().Select(f => f.GetString()).ToList();
                // NetworkInterface is not a record, so we can't use 'with'
                // Instead, just update the properties if they're mutable
                // For now, we'll skip this enrichment
            }

            // Extract MTU
            if (ipInfo.TryGetProperty("mtu", out var mtu))
            {
                // Update if property is settable
            }

            // Extract IP addresses
            if (ipInfo.TryGetProperty("addr_info", out var addrInfo))
            {
                var addresses = new List<string>();
                foreach (var addr in addrInfo.EnumerateArray())
                {
                    if (addr.TryGetProperty("local", out var local))
                    {
                        addresses.Add(local.GetString() ?? "");
                    }
                }
                iface.IpAddresses.AddRange(addresses.Where(a => !string.IsNullOrEmpty(a)));
            }
        }

        /// <summary>
        /// Determines interface type from name and description
        /// </summary>
        private InterfaceType DetermineInterfaceType(string name, string description)
        {
            var combined = $"{name} {description}".ToLowerInvariant();

            if (combined.Contains("loopback", StringComparison.OrdinalIgnoreCase) || combined.Contains("lo", StringComparison.OrdinalIgnoreCase))
                return InterfaceType.Loopback;
            if (combined.Contains("wireless", StringComparison.OrdinalIgnoreCase) || combined.Contains("wi-fi", StringComparison.OrdinalIgnoreCase) || combined.Contains("wlan", StringComparison.OrdinalIgnoreCase))
                return InterfaceType.Wireless;
            if (combined.Contains("ethernet", StringComparison.OrdinalIgnoreCase) || combined.Contains("eth", StringComparison.OrdinalIgnoreCase))
                return InterfaceType.Ethernet;
            if (combined.Contains("tunnel", StringComparison.OrdinalIgnoreCase) || combined.Contains("tun", StringComparison.OrdinalIgnoreCase))
                return InterfaceType.Tunnel;
            if (combined.Contains("ppp", StringComparison.OrdinalIgnoreCase))
                return InterfaceType.Ppp;

            return InterfaceType.Unknown;
        }

        /// <summary>
        /// Runs a TShark command and returns output
        /// </summary>
        private async Task<string> RunTSharkCommandAsync(
            string arguments,
            CancellationToken cancellationToken)
        {
            return await RunCommandAsync(_tsharkPath, arguments, cancellationToken);
        }

        /// <summary>
        /// Runs a command and returns output
        /// </summary>
        private async Task<string> RunCommandAsync(
            string command,
            string arguments,
            CancellationToken cancellationToken)
        {
            var psi = new ProcessStartInfo
            {
                FileName = command,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = psi };
            process.Start();

            var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            return await outputTask;
        }

        /// <summary>
        /// Finds TShark executable path
        /// </summary>
        private static string FindTSharkPath()
        {
            // Try common locations
            var candidates = new List<string>
            {
                "tshark", // System PATH
                "/usr/bin/tshark",
                "/usr/local/bin/tshark",
                "C:\\Program Files\\Wireshark\\tshark.exe",
                "C:\\Program Files (x86)\\Wireshark\\tshark.exe"
            };

            foreach (var candidate in candidates)
            {
                try
                {
                    var psi = new ProcessStartInfo
                    {
                        FileName = candidate,
                        Arguments = "--version",
                        RedirectStandardOutput = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(psi);
                    if (process is not null)
                    {
                        process.WaitForExit(1000);
                        if (process.ExitCode == 0)
                        {
                            return candidate;
                        }
                    }
                }
                catch
                {
                    continue;
                }
            }

            return "tshark"; // Fallback to system PATH
        }

        [GeneratedRegex(@"^(\d+)\.\s+([^\s(]+)(?:\s+\(([^)]+)\))?", RegexOptions.Multiline)]
        private static partial Regex InterfaceLineRegex();

        [GeneratedRegex(@"TShark.*?(\d+\.\d+\.\d+)", RegexOptions.IgnoreCase)]
        private static partial Regex VersionRegex();

        /// <summary>
        /// Disposes resources
        /// </summary>
        public void Dispose()
        {
            if (_disposed) return;

            _cacheLock?.Dispose();
            _disposed = true;
        }
    }

    /// <summary>
    /// TShark validation result
    /// </summary>
    public sealed class TSharkValidationResult
    {
        public bool IsValid { get; init; }
        public string Version { get; init; } = string.Empty;
        public string ExecutablePath { get; init; } = string.Empty;
        public string? ErrorMessage { get; init; }

        public override string ToString()
        {
            return IsValid
                ? $"TShark {Version} at {ExecutablePath}"
                : $"Invalid: {ErrorMessage}";
        }
    }
}
