using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models.Capture;

namespace PCAPAnalyzer.Core.Services.Capture;

/// <summary>
/// Interface for managing network interfaces available for capture
/// </summary>
public interface INetworkInterfaceManager
{
    /// <summary>
    /// Gets all available network interfaces
    /// </summary>
    Task<List<CaptureInterface>> GetAvailableInterfacesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a specific interface by ID
    /// </summary>
    Task<CaptureInterface?> GetInterfaceByIdAsync(string interfaceId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates statistics for all interfaces
    /// </summary>
    Task<Dictionary<string, CaptureInterfaceStats>> GetInterfaceStatisticsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Tests if TShark is available and properly configured
    /// </summary>
    Task<bool> TestTSharkAvailabilityAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the TShark version
    /// </summary>
    Task<string> GetTSharkVersionAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a BPF capture filter
    /// </summary>
    Task<(bool IsValid, string? ErrorMessage)> ValidateCaptureFilterAsync(string filter, CancellationToken cancellationToken = default);
}
