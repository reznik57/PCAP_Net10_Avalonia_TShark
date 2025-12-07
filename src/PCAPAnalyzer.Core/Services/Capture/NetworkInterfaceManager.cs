using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models.Capture;

namespace PCAPAnalyzer.Core.Services.Capture;

/// <summary>
/// Manages network interfaces for packet capture using TShark
/// </summary>
public class NetworkInterfaceManager : INetworkInterfaceManager
{
    private readonly ILogger<NetworkInterfaceManager> _logger;
    private readonly string _tsharkPath;
    private List<CaptureInterface>? _cachedInterfaces;
    private DateTime _lastCacheUpdate = DateTime.MinValue;
    private readonly TimeSpan _cacheExpiry = TimeSpan.FromMinutes(5);

    public NetworkInterfaceManager(ILogger<NetworkInterfaceManager> logger, string? tsharkPath = null)
    {
        _logger = logger;
        _tsharkPath = tsharkPath ?? FindTSharkPath();
    }

    /// <inheritdoc/>
    public async Task<List<CaptureInterface>> GetAvailableInterfacesAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            // Return cached interfaces if still valid
            if (_cachedInterfaces is not null && DateTime.UtcNow - _lastCacheUpdate < _cacheExpiry)
            {
                return _cachedInterfaces;
            }

            var interfaces = new List<CaptureInterface>();

            // Get interfaces from TShark
            var tsharkInterfaces = await GetTSharkInterfacesAsync(cancellationToken);

            // Get .NET NetworkInterface information for additional details
            var netInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (var tsharkIface in tsharkInterfaces)
            {
                var netIface = netInterfaces.FirstOrDefault(ni =>
                    ni.Name.Equals(tsharkIface.Name, StringComparison.OrdinalIgnoreCase) ||
                    ni.Description.Equals(tsharkIface.Description, StringComparison.OrdinalIgnoreCase));

                var captureInterface = new CaptureInterface
                {
                    Id = tsharkIface.Id,
                    Name = tsharkIface.Name,
                    Description = tsharkIface.Description,
                    InterfaceType = netIface?.NetworkInterfaceType.ToString() ?? "Unknown",
                    IsUp = netIface?.OperationalStatus == OperationalStatus.Up,
                    SupportsPromiscuousMode = !tsharkIface.IsLoopback,
                    IsLoopback = tsharkIface.IsLoopback,
                    IsWireless = netIface?.NetworkInterfaceType == NetworkInterfaceType.Wireless80211
                };

                // Get IP addresses
                if (netIface is not null)
                {
                    var ipProps = netIface.GetIPProperties();
                    captureInterface.Addresses = ipProps.UnicastAddresses
                        .Select(addr => addr.Address.ToString())
                        .ToList();

                    captureInterface.MacAddress = string.Join(":",
                        netIface.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2")));

                    try
                    {
                        captureInterface.LinkSpeed = netIface.Speed / 1_000_000; // Convert to Mbps
                    }
                    catch (PlatformNotSupportedException)
                    {
                        // Link speed not available on some platforms (Linux/WSL)
                        captureInterface.LinkSpeed = 0;
                    }

                    // Get statistics (with platform-specific handling)
                    try
                    {
                        var stats = netIface.GetIPv4Statistics();
                        captureInterface.Stats = new CaptureInterfaceStats
                        {
                            BytesReceived = stats.BytesReceived,
                            BytesSent = stats.BytesSent,
                            PacketsReceived = stats.UnicastPacketsReceived,
                            PacketsSent = stats.UnicastPacketsSent,
                            // OutgoingPacketsDiscarded is unsupported on macOS
                            PacketsDropped = stats.IncomingPacketsDiscarded +
                                (OperatingSystem.IsMacOS() ? 0 : stats.OutgoingPacketsDiscarded),
                            Errors = stats.IncomingPacketsWithErrors + stats.OutgoingPacketsWithErrors,
                            LastUpdate = DateTime.UtcNow
                        };
                    }
                    catch (PlatformNotSupportedException ex)
                    {
                        // Some statistics not available on Linux/WSL - use default values
                        _logger.LogDebug("Interface statistics not available on this platform: {Message}", ex.Message);
                        captureInterface.Stats = new CaptureInterfaceStats
                        {
                            BytesReceived = 0,
                            BytesSent = 0,
                            PacketsReceived = 0,
                            PacketsSent = 0,
                            PacketsDropped = 0,
                            Errors = 0,
                            LastUpdate = DateTime.UtcNow
                        };
                    }
                }

                interfaces.Add(captureInterface);
            }

            _cachedInterfaces = interfaces;
            _lastCacheUpdate = DateTime.UtcNow;

            _logger.LogInformation("Found {Count} network interfaces", interfaces.Count);
            return interfaces;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get available interfaces");
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task<CaptureInterface?> GetInterfaceByIdAsync(string interfaceId, CancellationToken cancellationToken = default)
    {
        var interfaces = await GetAvailableInterfacesAsync(cancellationToken);
        return interfaces.FirstOrDefault(i => i.Id == interfaceId);
    }

    /// <inheritdoc/>
    public async Task<Dictionary<string, CaptureInterfaceStats>> GetInterfaceStatisticsAsync(CancellationToken cancellationToken = default)
    {
        var stats = new Dictionary<string, CaptureInterfaceStats>();
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();

        foreach (var iface in interfaces)
        {
            try
            {
                var ipv4Stats = iface.GetIPv4Statistics();
                stats[iface.Name] = new CaptureInterfaceStats
                {
                    BytesReceived = ipv4Stats.BytesReceived,
                    BytesSent = ipv4Stats.BytesSent,
                    PacketsReceived = ipv4Stats.UnicastPacketsReceived + ipv4Stats.NonUnicastPacketsReceived,
                    PacketsSent = ipv4Stats.UnicastPacketsSent + ipv4Stats.NonUnicastPacketsSent,
                    // OutgoingPacketsDiscarded is unsupported on macOS
                    PacketsDropped = ipv4Stats.IncomingPacketsDiscarded +
                        (OperatingSystem.IsMacOS() ? 0 : ipv4Stats.OutgoingPacketsDiscarded),
                    Errors = ipv4Stats.IncomingPacketsWithErrors + ipv4Stats.OutgoingPacketsWithErrors,
                    LastUpdate = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get statistics for interface {Interface}", iface.Name);
            }
        }

        return await Task.FromResult(stats);
    }

    /// <inheritdoc/>
    public async Task<bool> TestTSharkAvailabilityAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var version = await GetTSharkVersionAsync(cancellationToken);
            return !string.IsNullOrEmpty(version);
        }
        catch
        {
            return false;
        }
    }

    /// <inheritdoc/>
    public async Task<string> GetTSharkVersionAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = _tsharkPath,
                Arguments = "--version",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process is null)
                throw new InvalidOperationException("Failed to start TShark process");

            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            var match = Regex.Match(output, @"TShark[^\d]*([\d.]+)");
            return match.Success ? match.Groups[1].Value : string.Empty;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get TShark version");
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task<(bool IsValid, string? ErrorMessage)> ValidateCaptureFilterAsync(string filter, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(filter))
            return (true, null);

        try
        {
            // Use TShark to validate the filter
            var startInfo = new ProcessStartInfo
            {
                FileName = _tsharkPath,
                Arguments = $"-f \"{filter}\" -c 0 -i 1",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process is null)
                return (false, "Failed to start TShark process");

            var error = await process.StandardError.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            if (process.ExitCode != 0 && !string.IsNullOrEmpty(error))
            {
                return (false, error);
            }

            return (true, null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to validate capture filter");
            return (false, ex.Message);
        }
    }

    private async Task<List<(string Id, string Name, string Description, bool IsLoopback)>> GetTSharkInterfacesAsync(CancellationToken cancellationToken)
    {
        var interfaces = new List<(string, string, string, bool)>();

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = _tsharkPath,
                Arguments = "-D",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process is null)
                throw new InvalidOperationException("Failed to start TShark process");

            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            // Parse TShark interface list
            // Format: "1. eth0 (Ethernet)"
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                var match = Regex.Match(line, @"^(\d+)\.\s+([^\s(]+)\s*\(([^)]+)\)");
                if (match.Success)
                {
                    var id = match.Groups[1].Value;
                    var name = match.Groups[2].Value;
                    var description = match.Groups[3].Value;
                    var isLoopback = name.Contains("loopback", StringComparison.OrdinalIgnoreCase) ||
                                   description.Contains("loopback", StringComparison.OrdinalIgnoreCase);

                    interfaces.Add((id, name, description, isLoopback));
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get TShark interfaces");
            throw;
        }

        return interfaces;
    }

    private static string FindTSharkPath()
    {
        // Try common TShark locations
        var possiblePaths = new List<string>();

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            possiblePaths.AddRange(new[]
            {
                @"C:\Program Files\Wireshark\tshark.exe",
                @"C:\Program Files (x86)\Wireshark\tshark.exe",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Wireshark", "tshark.exe")
            });
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            possiblePaths.AddRange(new[]
            {
                "/usr/bin/tshark",
                "/usr/local/bin/tshark",
                "/usr/sbin/tshark"
            });
        }
        else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            possiblePaths.AddRange(new[]
            {
                "/usr/local/bin/tshark",
                "/usr/bin/tshark",
                "/Applications/Wireshark.app/Contents/MacOS/tshark"
            });
        }

        foreach (var path in possiblePaths)
        {
            if (File.Exists(path))
                return path;
        }

        // Try PATH environment variable
        return "tshark";
    }
}
