using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Interfaces;

/// <summary>
/// Abstraction for loading packets from PCAP files.
/// Allows PacketComparer to remain in Core without depending on TShark.
/// </summary>
public interface IPacketLoader
{
    /// <summary>
    /// Loads all packets from a PCAP file.
    /// </summary>
    /// <param name="filePath">Path to the PCAP file</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of packets loaded from the file</returns>
    Task<List<PacketInfo>> LoadPacketsAsync(string filePath, CancellationToken cancellationToken = default);
}
