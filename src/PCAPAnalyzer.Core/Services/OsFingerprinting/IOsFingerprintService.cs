using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.OsFingerprinting;

/// <summary>
/// Service for passive OS fingerprinting using TCP SYN, JA3, MAC vendor, and DHCP signals.
/// Inspired by NetworkMiner's multi-signal approach.
/// </summary>
public interface IOsFingerprintService
{
    /// <summary>
    /// Processes fingerprinting fields from a parsed TShark packet.
    /// Called per-packet during parsing. Must be fast and thread-safe.
    /// </summary>
    /// <param name="fields">OS fingerprinting fields from TShark output</param>
    /// <param name="frameNumber">Packet frame number</param>
    /// <param name="timestamp">Packet timestamp</param>
    /// <param name="sourceIP">Source IP address</param>
    /// <param name="destIP">Destination IP address</param>
    /// <param name="sourcePort">Source port</param>
    /// <param name="destPort">Destination port</param>
    /// <param name="tcpFlags">TCP flags (for SYN detection)</param>
    void ProcessPacket(
        OsFingerprintRawFields fields,
        uint frameNumber,
        DateTime timestamp,
        string sourceIP,
        string destIP,
        ushort sourcePort,
        ushort destPort,
        ushort tcpFlags);

    /// <summary>
    /// Finalizes fingerprint analysis after all packets processed.
    /// Runs signature matching and confidence scoring.
    /// </summary>
    Task FinalizeAnalysisAsync();

    /// <summary>
    /// Returns all detected host fingerprints.
    /// </summary>
    IReadOnlyList<HostFingerprint> GetHostFingerprints();

    /// <summary>
    /// Gets a host fingerprint by IP address.
    /// </summary>
    HostFingerprint? GetHost(string ipAddress);

    /// <summary>
    /// Gets count of detected hosts.
    /// </summary>
    int HostCount { get; }

    /// <summary>
    /// Clears all collected fingerprints. Called when starting new analysis.
    /// </summary>
    void Clear();
}

/// <summary>
/// Contains raw OS fingerprinting field strings extracted from TShark output.
/// Fields 39-59 in the TShark command.
/// </summary>
public readonly record struct OsFingerprintRawFields
{
    // IP Layer (fields 39-40)
    /// <summary>IP TTL value (field 39: ip.ttl)</summary>
    public string? IpTtl { get; init; }

    /// <summary>Don't Fragment flag (field 40: ip.flags.df)</summary>
    public string? IpDfFlag { get; init; }

    // Ethernet (fields 40-41)
    /// <summary>Source MAC address (field 40: eth.src)</summary>
    public string? EthSrc { get; init; }

    /// <summary>Destination MAC address (field 41: eth.dst) - used for L2 broadcast detection (ff:ff:ff:ff:ff:ff)</summary>
    public string? EthDst { get; init; }

    // TCP Options (fields 42-44)
    /// <summary>Raw TCP options (field 42: tcp.options)</summary>
    public string? TcpOptions { get; init; }

    /// <summary>MSS value (field 43: tcp.options.mss_val)</summary>
    public string? TcpMss { get; init; }

    /// <summary>Window scale (field 44: tcp.options.wscale)</summary>
    public string? TcpWindowScale { get; init; }

    /// <summary>SACK permitted (field 45: tcp.options.sack_perm)</summary>
    public string? TcpSackPerm { get; init; }

    /// <summary>Timestamp value (field 46: tcp.options.timestamp.tsval)</summary>
    public string? TcpTimestamp { get; init; }

    /// <summary>Initial window size (field 47: tcp.window_size_value)</summary>
    public string? TcpWindowSize { get; init; }

    // TLS/JA3 (fields 48-53)
    /// <summary>TLS handshake type (field 48: tls.handshake.type)</summary>
    public string? TlsHandshakeType { get; init; }

    /// <summary>TLS version (field 49: tls.handshake.version)</summary>
    public string? TlsVersion { get; init; }

    /// <summary>Cipher suites (field 50: tls.handshake.ciphersuite)</summary>
    public string? TlsCipherSuites { get; init; }

    /// <summary>Extensions (field 51: tls.handshake.extension.type)</summary>
    public string? TlsExtensions { get; init; }

    /// <summary>Elliptic curves (field 52: tls.handshake.extensions_elliptic_curves)</summary>
    public string? TlsEllipticCurves { get; init; }

    /// <summary>EC point formats (field 53: tls.handshake.extensions_ec_point_formats)</summary>
    public string? TlsEcPointFormats { get; init; }

    // DHCP (fields 54-57)
    /// <summary>DHCP message type (field 54: dhcp.option.dhcp)</summary>
    public string? DhcpMessageType { get; init; }

    /// <summary>Option 55 request list (field 55: dhcp.option.request_list)</summary>
    public string? DhcpOption55 { get; init; }

    /// <summary>Vendor class ID (field 56: dhcp.option.vendor_class_id)</summary>
    public string? DhcpVendorClassId { get; init; }

    /// <summary>Hostname (field 57: dhcp.option.hostname)</summary>
    public string? DhcpHostname { get; init; }

    // Application Banners (fields 58-59)
    /// <summary>SSH protocol string (field 58: ssh.protocol)</summary>
    public string? SshProtocol { get; init; }

    /// <summary>HTTP Server header (field 59: http.server)</summary>
    public string? HttpServer { get; init; }

    /// <summary>
    /// Returns true if this packet has TCP SYN fingerprinting data.
    /// </summary>
    public readonly bool HasTcpFingerprintData =>
        !string.IsNullOrEmpty(IpTtl) ||
        !string.IsNullOrEmpty(TcpOptions) ||
        !string.IsNullOrEmpty(TcpWindowSize);

    /// <summary>
    /// Returns true if this packet has JA3 TLS fingerprinting data.
    /// </summary>
    public readonly bool HasJa3Data =>
        !string.IsNullOrEmpty(TlsHandshakeType) &&
        !string.IsNullOrEmpty(TlsCipherSuites);

    /// <summary>
    /// Returns true if this packet has DHCP fingerprinting data.
    /// </summary>
    public readonly bool HasDhcpData =>
        !string.IsNullOrEmpty(DhcpOption55) ||
        !string.IsNullOrEmpty(DhcpVendorClassId);

    /// <summary>
    /// Returns true if this packet has any fingerprinting data.
    /// </summary>
    public readonly bool HasAnyFingerprintData =>
        HasTcpFingerprintData || HasJa3Data || HasDhcpData ||
        !string.IsNullOrEmpty(EthSrc) ||
        !string.IsNullOrEmpty(SshProtocol) ||
        !string.IsNullOrEmpty(HttpServer);
}
