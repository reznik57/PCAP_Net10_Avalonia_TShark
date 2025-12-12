// MAC Vendor lookup service interface
// Provides OUI-based vendor identification with IEEE database support

namespace PCAPAnalyzer.Core.Services.MacVendor;

/// <summary>
/// Service for looking up MAC address vendor information using IEEE OUI database.
/// Supports automatic detection of randomized and locally administered MACs.
/// </summary>
public interface IMacVendorService
{
    /// <summary>
    /// Lookup vendor information by MAC address.
    /// Handles special MAC types (randomized, locally administered) before OUI lookup.
    /// </summary>
    /// <param name="macAddress">MAC address in any common format (XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, etc.)</param>
    /// <returns>Lookup result with vendor info and address classification</returns>
    MacLookupResult LookupVendor(string? macAddress);

    /// <summary>
    /// Download and update OUI database from IEEE registries.
    /// Downloads MA-L (OUI), MA-M, and MA-S registries.
    /// </summary>
    /// <param name="progress">Optional progress reporter (0-100)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Update result with statistics</returns>
    Task<MacDatabaseUpdateResult> UpdateDatabaseAsync(
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Get current database statistics.
    /// </summary>
    MacDatabaseStats GetDatabaseStats();

    /// <summary>
    /// Check if a database update is available (compares local vs remote version).
    /// </summary>
    Task<bool> IsUpdateAvailableAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of a MAC address vendor lookup.
/// </summary>
/// <param name="Vendor">Vendor name if found, null otherwise</param>
/// <param name="AddressType">Classification of the MAC address</param>
/// <param name="DeviceTypeHint">Optional device type hint (Desktop, Mobile, IoT, etc.)</param>
/// <param name="OsHint">Optional OS hint from curated database</param>
public readonly record struct MacLookupResult(
    string? Vendor,
    MacAddressType AddressType,
    string? DeviceTypeHint = null,
    string? OsHint = null)
{
    /// <summary>
    /// Display-friendly vendor string that handles special MAC types.
    /// </summary>
    public string DisplayVendor => AddressType switch
    {
        MacAddressType.Randomized => "Randomized (Private)",
        MacAddressType.LocallyAdministered => "Locally Administered",
        MacAddressType.Multicast => "Multicast",
        MacAddressType.Broadcast => "Broadcast",
        _ => Vendor ?? "Unknown"
    };

    /// <summary>
    /// Whether this is a special MAC type (not globally unique).
    /// </summary>
    public bool IsSpecialAddress => AddressType != MacAddressType.Global;
}

/// <summary>
/// Classification of MAC address types based on IEEE standards.
/// </summary>
public enum MacAddressType
{
    /// <summary>Globally unique address with valid OUI (standard manufacturer assignment)</summary>
    Global,

    /// <summary>Locally administered address (bit 1 of first octet = 1, unicast)</summary>
    LocallyAdministered,

    /// <summary>Randomized private address (iOS 14+, Android 10+ privacy feature)</summary>
    Randomized,

    /// <summary>Multicast address (bit 0 of first octet = 1)</summary>
    Multicast,

    /// <summary>Broadcast address (FF:FF:FF:FF:FF:FF)</summary>
    Broadcast,

    /// <summary>Invalid or unparseable MAC address</summary>
    Invalid
}

/// <summary>
/// Result of a database update operation.
/// </summary>
public readonly record struct MacDatabaseUpdateResult(
    bool Success,
    int TotalEntries,
    int NewEntries,
    int UpdatedEntries,
    TimeSpan Duration,
    string? ErrorMessage = null);

/// <summary>
/// Statistics about the current MAC vendor database.
/// </summary>
public readonly record struct MacDatabaseStats(
    int TotalEntries,
    int CuratedEntries,
    int IeeeEntries,
    DateTime? LastUpdated,
    string? DatabaseVersion);
