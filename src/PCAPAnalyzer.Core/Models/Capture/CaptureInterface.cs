using System;

namespace PCAPAnalyzer.Core.Models.Capture;

/// <summary>
/// Represents a network interface available for packet capture
/// </summary>
public class CaptureInterface
{
    /// <summary>
    /// Unique identifier for the interface
    /// </summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>
    /// Friendly name of the interface
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Description of the interface
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Type of interface (Ethernet, WiFi, Loopback, etc.)
    /// </summary>
    public string InterfaceType { get; set; } = string.Empty;

    /// <summary>
    /// List of IP addresses assigned to the interface
    /// </summary>
    public List<string> Addresses { get; set; } = [];

    /// <summary>
    /// MAC address of the interface
    /// </summary>
    public string MacAddress { get; set; } = string.Empty;

    /// <summary>
    /// Whether the interface is currently up/active
    /// </summary>
    public bool IsUp { get; set; }

    /// <summary>
    /// Whether the interface supports promiscuous mode
    /// </summary>
    public bool SupportsPromiscuousMode { get; set; }

    /// <summary>
    /// Current link speed in Mbps (0 if unknown)
    /// </summary>
    public long LinkSpeed { get; set; }

    /// <summary>
    /// Whether the interface is wireless
    /// </summary>
    public bool IsWireless { get; set; }

    /// <summary>
    /// Whether the interface is a loopback interface
    /// </summary>
    public bool IsLoopback { get; set; }

    /// <summary>
    /// Statistics for the interface
    /// </summary>
    public CaptureInterfaceStats Stats { get; set; } = new();
}

/// <summary>
/// Statistics for a capture interface
/// </summary>
public class CaptureInterfaceStats
{
    /// <summary>
    /// Total bytes received on the interface
    /// </summary>
    public long BytesReceived { get; set; }

    /// <summary>
    /// Total bytes sent on the interface
    /// </summary>
    public long BytesSent { get; set; }

    /// <summary>
    /// Total packets received
    /// </summary>
    public long PacketsReceived { get; set; }

    /// <summary>
    /// Total packets sent
    /// </summary>
    public long PacketsSent { get; set; }

    /// <summary>
    /// Number of packets dropped
    /// </summary>
    public long PacketsDropped { get; set; }

    /// <summary>
    /// Number of errors
    /// </summary>
    public long Errors { get; set; }

    /// <summary>
    /// Timestamp of last statistics update
    /// </summary>
    public DateTime LastUpdate { get; set; } = DateTime.UtcNow;
}
