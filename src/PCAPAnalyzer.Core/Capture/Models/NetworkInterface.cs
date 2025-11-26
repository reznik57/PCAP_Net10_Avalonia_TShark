using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Capture.Models
{
    /// <summary>
    /// Represents a network interface available for packet capture
    /// </summary>
    public sealed class NetworkInterface
    {
        /// <summary>
        /// Gets or sets the interface identifier (e.g., "eth0", "\\Device\\NPF_{GUID}")
        /// </summary>
        public string Id { get; init; } = string.Empty;

        /// <summary>
        /// Gets or sets the interface name (e.g., "Ethernet", "Wi-Fi")
        /// </summary>
        public string Name { get; init; } = string.Empty;

        /// <summary>
        /// Gets or sets the interface description
        /// </summary>
        public string Description { get; init; } = string.Empty;

        /// <summary>
        /// Gets or sets the interface type (Ethernet, Wireless, Loopback, etc.)
        /// </summary>
        public InterfaceType Type { get; init; }

        /// <summary>
        /// Gets or sets the interface status
        /// </summary>
        public InterfaceStatus Status { get; init; }

        /// <summary>
        /// Gets or sets whether the interface is up
        /// </summary>
        public bool IsUp { get; init; }

        /// <summary>
        /// Gets or sets whether the interface is a loopback interface
        /// </summary>
        public bool IsLoopback { get; init; }

        /// <summary>
        /// Gets or sets the list of IP addresses assigned to this interface
        /// </summary>
        public List<string> IpAddresses { get; init; } = new();

        /// <summary>
        /// Gets or sets the MAC address of the interface
        /// </summary>
        public string? MacAddress { get; init; }

        /// <summary>
        /// Gets or sets the maximum transmission unit (MTU)
        /// </summary>
        public int Mtu { get; init; }

        /// <summary>
        /// Gets or sets the link speed in Mbps (0 if unknown)
        /// </summary>
        public long SpeedMbps { get; init; }

        /// <summary>
        /// Gets or sets whether promiscuous mode is supported
        /// </summary>
        public bool SupportsPromiscuousMode { get; init; }

        /// <summary>
        /// Gets or sets additional metadata about the interface
        /// </summary>
        public Dictionary<string, object> Metadata { get; init; } = new();

        public override string ToString()
        {
            return $"{Name} ({Id}) - {Status} - {string.Join(", ", IpAddresses)}";
        }
    }

    /// <summary>
    /// Network interface type
    /// </summary>
    public enum InterfaceType
    {
        Unknown = 0,
        Ethernet = 1,
        Wireless = 2,
        Loopback = 3,
        Tunnel = 4,
        Ppp = 5,
        Other = 99
    }

    /// <summary>
    /// Network interface status
    /// </summary>
    public enum InterfaceStatus
    {
        Unknown = 0,
        Up = 1,
        Down = 2,
        NotPresent = 3,
        LowerLayerDown = 4
    }
}
