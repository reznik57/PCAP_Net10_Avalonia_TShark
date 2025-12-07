using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Utilities;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.ViewModels;

namespace PCAPAnalyzer.UI.Services;

/// <summary>
/// Service for managing Dashboard filter presets.
/// Stores user presets in JSON, provides immutable built-in presets.
/// </summary>
public class FilterPresetService : IFilterPresetService
{
    private const string SettingsFileName = "filter-presets.json";
    private readonly string _settingsPath;
    private readonly List<FilterPreset> _builtInPresets;
    private List<FilterPreset> _userPresets;

    public FilterPresetService()
    {
        // Store settings in user's AppData folder
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var appFolder = Path.Combine(appDataPath, "PCAPAnalyzer");
        Directory.CreateDirectory(appFolder);
        _settingsPath = Path.Combine(appFolder, SettingsFileName);

        _builtInPresets = CreateBuiltInPresets();
        _userPresets = new List<FilterPreset>();

        // Load user presets asynchronously
        _ = LoadUserPresetsAsync();
    }

    /// <inheritdoc />
    public IReadOnlyList<FilterPreset> GetBuiltInPresets() => _builtInPresets.AsReadOnly();

    /// <inheritdoc />
    public async Task<IReadOnlyList<FilterPreset>> GetAllPresetsAsync()
    {
        // Ensure user presets are loaded
        await LoadUserPresetsAsync();

        // Combine built-in and user presets (built-ins first)
        var allPresets = new List<FilterPreset>(_builtInPresets);
        allPresets.AddRange(_userPresets);
        return allPresets.AsReadOnly();
    }

    /// <inheritdoc />
    public async Task<FilterPreset?> GetPresetAsync(string name)
    {
        var allPresets = await GetAllPresetsAsync();
        return allPresets.FirstOrDefault(p =>
            string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    /// <inheritdoc />
    public async Task<bool> SavePresetAsync(FilterPreset preset)
    {
        try
        {
            if (preset is null)
            {
                DebugLogger.Log("[FilterPresetService] Cannot save null preset");
                return false;
            }

            // Prevent overwriting built-in presets
            if (_builtInPresets.Any(p => string.Equals(p.Name, preset.Name, StringComparison.OrdinalIgnoreCase)))
            {
                DebugLogger.Log($"[FilterPresetService] Cannot overwrite built-in preset: {preset.Name}");
                return false;
            }

            // Ensure user presets are loaded
            await LoadUserPresetsAsync();

            // Remove existing preset with same name (case-insensitive)
            _userPresets.RemoveAll(p =>
                string.Equals(p.Name, preset.Name, StringComparison.OrdinalIgnoreCase));

            // Add new/updated preset
            var updatedPreset = preset with
            {
                IsBuiltIn = false,
                LastModified = DateTime.Now
            };
            _userPresets.Add(updatedPreset);

            // Save to disk
            await SaveUserPresetsAsync();

            DebugLogger.Log($"[FilterPresetService] Saved preset: {preset.Name}");
            return true;
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[FilterPresetService] Error saving preset: {ex.Message}");
            return false;
        }
    }

    /// <inheritdoc />
    public async Task<bool> DeletePresetAsync(string name)
    {
        try
        {
            // Cannot delete built-in presets
            if (_builtInPresets.Any(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)))
            {
                DebugLogger.Log($"[FilterPresetService] Cannot delete built-in preset: {name}");
                return false;
            }

            // Ensure user presets are loaded
            await LoadUserPresetsAsync();

            // Remove preset (case-insensitive)
            var removed = _userPresets.RemoveAll(p =>
                string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase));

            if (removed > 0)
            {
                await SaveUserPresetsAsync();
                DebugLogger.Log($"[FilterPresetService] Deleted preset: {name}");
                return true;
            }

            DebugLogger.Log($"[FilterPresetService] Preset not found: {name}");
            return false;
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[FilterPresetService] Error deleting preset: {ex.Message}");
            return false;
        }
    }

    /// <inheritdoc />
    public void ApplyPreset(FilterPreset preset, DashboardViewModel viewModel)
    {
        if (preset is null || viewModel is null)
        {
            DebugLogger.Log("[FilterPresetService] Cannot apply preset: null parameter");
            return;
        }

        try
        {
            // Apply filter logic controls
            viewModel.FilterUseAndMode = preset.FilterUseAndMode;
            viewModel.FilterUseNotMode = preset.FilterUseNotMode;

            // Apply network type filters
            viewModel.FilterRfc1918Toggle = preset.FilterRfc1918Toggle;
            viewModel.FilterPublicIpToggle = preset.FilterPublicIpToggle;
            viewModel.FilterApipaToggle = preset.FilterApipaToggle;
            viewModel.FilterIPv4Toggle = preset.FilterIPv4Toggle;
            viewModel.FilterIPv6Toggle = preset.FilterIPv6Toggle;

            // Apply traffic type filters
            viewModel.FilterMulticastToggle = preset.FilterMulticastToggle;
            viewModel.FilterBroadcastToggle = preset.FilterBroadcastToggle;
            viewModel.FilterAnycastToggle = preset.FilterAnycastToggle;

            // Apply security filters
            viewModel.FilterInsecureToggle = preset.FilterInsecureToggle;
            viewModel.FilterAnomaliesToggle = preset.FilterAnomaliesToggle;

            // Apply L7 protocol filters
            viewModel.FilterTlsV10Toggle = preset.FilterTlsV10Toggle;
            viewModel.FilterTlsV11Toggle = preset.FilterTlsV11Toggle;
            viewModel.FilterTlsV12Toggle = preset.FilterTlsV12Toggle;
            viewModel.FilterTlsV13Toggle = preset.FilterTlsV13Toggle;
            viewModel.FilterHttpToggle = preset.FilterHttpToggle;
            viewModel.FilterHttpsToggle = preset.FilterHttpsToggle;
            viewModel.FilterDnsToggle = preset.FilterDnsToggle;
            viewModel.FilterSnmpToggle = preset.FilterSnmpToggle;
            viewModel.FilterSshToggle = preset.FilterSshToggle;
            viewModel.FilterFtpToggle = preset.FilterFtpToggle;
            viewModel.FilterSmtpToggle = preset.FilterSmtpToggle;
            viewModel.FilterStunToggle = preset.FilterStunToggle;
            viewModel.FilterDhcpServerToggle = preset.FilterDhcpServerToggle;

            // Apply VPN protocol filters
            viewModel.FilterWireGuardToggle = preset.FilterWireGuardToggle;
            viewModel.FilterOpenVpnToggle = preset.FilterOpenVpnToggle;
            viewModel.FilterIkeV2Toggle = preset.FilterIkeV2Toggle;
            viewModel.FilterIpsecToggle = preset.FilterIpsecToggle;
            viewModel.FilterL2tpToggle = preset.FilterL2tpToggle;
            viewModel.FilterPptpToggle = preset.FilterPptpToggle;

            // Apply additional filters
            viewModel.FilterJumboFramesToggle = preset.FilterJumboFramesToggle;
            viewModel.FilterPrivateToPublicToggle = preset.FilterPrivateToPublicToggle;
            viewModel.FilterPublicToPrivateToggle = preset.FilterPublicToPrivateToggle;
            viewModel.FilterLinkLocalToggle = preset.FilterLinkLocalToggle;
            viewModel.FilterLoopbackToggle = preset.FilterLoopbackToggle;
            viewModel.FilterSuspiciousToggle = preset.FilterSuspiciousToggle;
            viewModel.FilterTcpIssuesToggle = preset.FilterTcpIssuesToggle;
            viewModel.FilterDnsAnomaliesToggle = preset.FilterDnsAnomaliesToggle;
            viewModel.FilterPortScansToggle = preset.FilterPortScansToggle;

            DebugLogger.Log($"[FilterPresetService] Applied preset: {preset.Name}");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[FilterPresetService] Error applying preset: {ex.Message}");
        }
    }

    /// <inheritdoc />
    public FilterPreset CreateFromViewModel(string name, string description, DashboardViewModel viewModel)
    {
        ArgumentNullException.ThrowIfNull(viewModel);

        return new FilterPreset
        {
            Name = name,
            Description = description,
            IsBuiltIn = false,
            CreatedAt = DateTime.Now,
            LastModified = DateTime.Now,

            // Capture filter logic controls
            FilterUseAndMode = viewModel.FilterUseAndMode,
            FilterUseNotMode = viewModel.FilterUseNotMode,

            // Capture network type filters
            FilterRfc1918Toggle = viewModel.FilterRfc1918Toggle,
            FilterPublicIpToggle = viewModel.FilterPublicIpToggle,
            FilterApipaToggle = viewModel.FilterApipaToggle,
            FilterIPv4Toggle = viewModel.FilterIPv4Toggle,
            FilterIPv6Toggle = viewModel.FilterIPv6Toggle,

            // Capture traffic type filters
            FilterMulticastToggle = viewModel.FilterMulticastToggle,
            FilterBroadcastToggle = viewModel.FilterBroadcastToggle,
            FilterAnycastToggle = viewModel.FilterAnycastToggle,

            // Capture security filters
            FilterInsecureToggle = viewModel.FilterInsecureToggle,
            FilterAnomaliesToggle = viewModel.FilterAnomaliesToggle,

            // Capture L7 protocol filters
            FilterTlsV10Toggle = viewModel.FilterTlsV10Toggle,
            FilterTlsV11Toggle = viewModel.FilterTlsV11Toggle,
            FilterTlsV12Toggle = viewModel.FilterTlsV12Toggle,
            FilterTlsV13Toggle = viewModel.FilterTlsV13Toggle,
            FilterHttpToggle = viewModel.FilterHttpToggle,
            FilterHttpsToggle = viewModel.FilterHttpsToggle,
            FilterDnsToggle = viewModel.FilterDnsToggle,
            FilterSnmpToggle = viewModel.FilterSnmpToggle,
            FilterSshToggle = viewModel.FilterSshToggle,
            FilterFtpToggle = viewModel.FilterFtpToggle,
            FilterSmtpToggle = viewModel.FilterSmtpToggle,
            FilterStunToggle = viewModel.FilterStunToggle,
            FilterDhcpServerToggle = viewModel.FilterDhcpServerToggle,

            // Capture VPN protocol filters
            FilterWireGuardToggle = viewModel.FilterWireGuardToggle,
            FilterOpenVpnToggle = viewModel.FilterOpenVpnToggle,
            FilterIkeV2Toggle = viewModel.FilterIkeV2Toggle,
            FilterIpsecToggle = viewModel.FilterIpsecToggle,
            FilterL2tpToggle = viewModel.FilterL2tpToggle,
            FilterPptpToggle = viewModel.FilterPptpToggle,

            // Capture additional filters
            FilterJumboFramesToggle = viewModel.FilterJumboFramesToggle,
            FilterPrivateToPublicToggle = viewModel.FilterPrivateToPublicToggle,
            FilterPublicToPrivateToggle = viewModel.FilterPublicToPrivateToggle,
            FilterLinkLocalToggle = viewModel.FilterLinkLocalToggle,
            FilterLoopbackToggle = viewModel.FilterLoopbackToggle,
            FilterSuspiciousToggle = viewModel.FilterSuspiciousToggle,
            FilterTcpIssuesToggle = viewModel.FilterTcpIssuesToggle,
            FilterDnsAnomaliesToggle = viewModel.FilterDnsAnomaliesToggle,
            FilterPortScansToggle = viewModel.FilterPortScansToggle
        };
    }

    /// <summary>
    /// Load user presets from disk
    /// </summary>
    private async Task LoadUserPresetsAsync()
    {
        try
        {
            if (!File.Exists(_settingsPath))
            {
                DebugLogger.Log("[FilterPresetService] No user presets found");
                _userPresets = new List<FilterPreset>();
                return;
            }

            var json = await File.ReadAllTextAsync(_settingsPath);
            var presets = JsonSerializer.Deserialize<List<FilterPreset>>(json);

            if (presets is not null)
            {
                // Filter out any that conflict with built-in names (defensive)
                _userPresets = presets
                    .Where(p => !_builtInPresets.Any(b =>
                        string.Equals(b.Name, p.Name, StringComparison.OrdinalIgnoreCase)))
                    .ToList();

                DebugLogger.Log($"[FilterPresetService] Loaded {_userPresets.Count} user presets");
            }
            else
            {
                _userPresets = new List<FilterPreset>();
            }
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[FilterPresetService] Error loading user presets: {ex.Message}");
            _userPresets = new List<FilterPreset>();
        }
    }

    /// <summary>
    /// Save user presets to disk
    /// </summary>
    private async Task SaveUserPresetsAsync()
    {
        try
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };

            var json = JsonSerializer.Serialize(_userPresets, options);
            await File.WriteAllTextAsync(_settingsPath, json);
            DebugLogger.Log($"[FilterPresetService] Saved {_userPresets.Count} user presets");
        }
        catch (Exception ex)
        {
            DebugLogger.Log($"[FilterPresetService] Error saving user presets: {ex.Message}");
        }
    }

    /// <summary>
    /// Create immutable built-in presets
    /// </summary>
    private static List<FilterPreset> CreateBuiltInPresets()
    {
        var now = DateTime.Now;

        return new List<FilterPreset>
        {
            // Security Audit: Focus on insecure protocols and anomalies
            new FilterPreset
            {
                Name = "Security Audit",
                Description = "Shows insecure protocols (TLS 1.0/1.1, HTTP, FTP, Telnet) and all anomalies",
                IsBuiltIn = true,
                CreatedAt = now,
                LastModified = now,
                FilterUseAndMode = false, // OR mode - show ANY match
                FilterInsecureToggle = true,
                FilterAnomaliesToggle = true,
                FilterTlsV10Toggle = true,
                FilterTlsV11Toggle = true,
                FilterHttpToggle = true,
                FilterFtpToggle = true,
                FilterSuspiciousToggle = true
            },

            // HTTP/HTTPS Traffic: Web traffic analysis
            new FilterPreset
            {
                Name = "HTTP/HTTPS Traffic",
                Description = "Shows all web traffic (HTTP and HTTPS)",
                IsBuiltIn = true,
                CreatedAt = now,
                LastModified = now,
                FilterUseAndMode = false, // OR mode
                FilterHttpToggle = true,
                FilterHttpsToggle = true,
                FilterTlsV12Toggle = true,
                FilterTlsV13Toggle = true
            },

            // VPN Protocols: All VPN traffic
            new FilterPreset
            {
                Name = "VPN Protocols",
                Description = "Shows all VPN protocol traffic (WireGuard, OpenVPN, IKEv2, IPsec, L2TP, PPTP)",
                IsBuiltIn = true,
                CreatedAt = now,
                LastModified = now,
                FilterUseAndMode = false, // OR mode
                FilterWireGuardToggle = true,
                FilterOpenVpnToggle = true,
                FilterIkeV2Toggle = true,
                FilterIpsecToggle = true,
                FilterL2tpToggle = true,
                FilterPptpToggle = true
            },

            // Network Issues: TCP problems, DNS anomalies, port scans
            new FilterPreset
            {
                Name = "Network Issues",
                Description = "Shows TCP retransmissions, DNS anomalies, and port scanning activity",
                IsBuiltIn = true,
                CreatedAt = now,
                LastModified = now,
                FilterUseAndMode = false, // OR mode
                FilterTcpIssuesToggle = true,
                FilterDnsAnomaliesToggle = true,
                FilterPortScansToggle = true,
                FilterAnomaliesToggle = true
            },

            // Internal RFC1918 Traffic: Private network analysis
            new FilterPreset
            {
                Name = "Internal Traffic",
                Description = "Shows only RFC1918 private network traffic (10.x.x.x, 172.16-31.x.x, 192.168.x.x)",
                IsBuiltIn = true,
                CreatedAt = now,
                LastModified = now,
                FilterUseAndMode = true, // AND mode
                FilterRfc1918Toggle = true
            },

            // External Traffic: Public IP communication
            new FilterPreset
            {
                Name = "External Traffic",
                Description = "Shows only public IP traffic (internet-bound)",
                IsBuiltIn = true,
                CreatedAt = now,
                LastModified = now,
                FilterUseAndMode = true, // AND mode
                FilterPublicIpToggle = true
            },

            // DNS Traffic: DNS analysis
            new FilterPreset
            {
                Name = "DNS Traffic",
                Description = "Shows all DNS queries and responses",
                IsBuiltIn = true,
                CreatedAt = now,
                LastModified = now,
                FilterUseAndMode = true,
                FilterDnsToggle = true
            },

            // Encrypted Traffic: All TLS versions
            new FilterPreset
            {
                Name = "Encrypted Traffic",
                Description = "Shows all TLS/encrypted traffic (all TLS versions + SSH)",
                IsBuiltIn = true,
                CreatedAt = now,
                LastModified = now,
                FilterUseAndMode = false, // OR mode
                FilterTlsV10Toggle = true,
                FilterTlsV11Toggle = true,
                FilterTlsV12Toggle = true,
                FilterTlsV13Toggle = true,
                FilterSshToggle = true,
                FilterHttpsToggle = true
            }
        };
    }
}
