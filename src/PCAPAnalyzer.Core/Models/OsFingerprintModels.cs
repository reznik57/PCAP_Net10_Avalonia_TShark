using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Services.MacVendor;

namespace PCAPAnalyzer.Core.Models;

/// <summary>
/// Represents a detected network host with aggregated fingerprinting signals.
/// Inspired by NetworkMiner's host inventory approach.
/// </summary>
public class HostFingerprint
{
    /// <summary>
    /// Primary IP address of the host.
    /// </summary>
    public required string IpAddress { get; init; }

    /// <summary>
    /// MAC address (if available from Ethernet frames).
    /// </summary>
    public string? MacAddress { get; set; }

    /// <summary>
    /// MAC vendor name (OUI lookup).
    /// </summary>
    public string? MacVendor { get; set; }

    /// <summary>
    /// MAC address type classification (Global, Randomized, LocallyAdministered, etc.).
    /// </summary>
    public MacAddressType MacAddressType { get; set; } = MacAddressType.Global;

    /// <summary>
    /// Primary OS detection result.
    /// </summary>
    public OsDetectionResult? OsDetection { get; set; }

    /// <summary>
    /// JA3 verification result (if TLS ClientHello seen).
    /// </summary>
    public Ja3DetectionResult? Ja3Verification { get; set; }

    /// <summary>
    /// All TCP fingerprint samples collected for this host.
    /// </summary>
    public List<TcpFingerprintData> TcpFingerprints { get; set; } = [];

    /// <summary>
    /// All JA3 hashes seen from this host (for JA3 variety analysis).
    /// </summary>
    public List<Ja3FingerprintData> Ja3Fingerprints { get; set; } = [];

    /// <summary>
    /// DHCP fingerprint data (if Option 55 seen).
    /// </summary>
    public DhcpFingerprintData? DhcpFingerprint { get; set; }

    /// <summary>
    /// Server banners detected (SSH, HTTP, FTP, etc.).
    /// </summary>
    public List<ServerBanner> ServerBanners { get; set; } = [];

    /// <summary>
    /// Hostname from DHCP, DNS, NetBIOS, or other sources.
    /// </summary>
    public string? Hostname { get; set; }

    /// <summary>
    /// Total packets seen from this host.
    /// </summary>
    public int PacketCount { get; set; }

    /// <summary>
    /// First packet timestamp from this host.
    /// </summary>
    public DateTime FirstSeen { get; set; }

    /// <summary>
    /// Last packet timestamp from this host.
    /// </summary>
    public DateTime LastSeen { get; set; }

    /// <summary>
    /// Open ports detected (services responding).
    /// </summary>
    public HashSet<ushort> OpenPorts { get; set; } = [];

    /// <summary>
    /// Gets a display-friendly OS name with confidence indicator.
    /// </summary>
    public string OsDisplayName => OsDetection?.DisplayName ?? "Unknown";

    /// <summary>
    /// Gets whether JA3 verification confirms or conflicts with TCP detection.
    /// </summary>
    public bool Ja3Verified => Ja3Verification?.ConfirmsTcpDetection ?? false;
}

/// <summary>
/// Primary OS detection result combining multiple signals.
/// </summary>
public record OsDetectionResult
{
    /// <summary>
    /// Operating system family (Windows, Linux, macOS, iOS, Android, etc.).
    /// </summary>
    public required string OsFamily { get; init; }

    /// <summary>
    /// Specific OS version if detectable (e.g., "Windows 10/11", "Ubuntu 22.04").
    /// </summary>
    public string? OsVersion { get; set; }

    /// <summary>
    /// Device type hint (Desktop, Server, Mobile, IoT, Network Equipment, etc.).
    /// </summary>
    public DeviceType DeviceType { get; set; } = DeviceType.Unknown;

    /// <summary>
    /// Confidence level of the detection.
    /// </summary>
    public OsConfidenceLevel Confidence { get; set; }

    /// <summary>
    /// Confidence score (0.0-1.0).
    /// </summary>
    public double ConfidenceScore { get; set; }

    /// <summary>
    /// Detection method that produced this result.
    /// </summary>
    public OsDetectionMethod Method { get; set; }

    /// <summary>
    /// Signature ID that matched (for database lookups).
    /// </summary>
    public string? SignatureId { get; set; }

    /// <summary>
    /// Gets a display-friendly name with version.
    /// </summary>
    public string DisplayName => string.IsNullOrEmpty(OsVersion)
        ? OsFamily
        : $"{OsFamily} {OsVersion}";
}

/// <summary>
/// JA3 verification result.
/// </summary>
public class Ja3DetectionResult
{
    /// <summary>
    /// The JA3 hash.
    /// </summary>
    public required string Ja3Hash { get; init; }

    /// <summary>
    /// Detected application/OS from JA3 database.
    /// </summary>
    public string? DetectedApplication { get; set; }

    /// <summary>
    /// OS hint from JA3 (if available).
    /// </summary>
    public string? OsHint { get; set; }

    /// <summary>
    /// Whether JA3 detection confirms TCP-based detection.
    /// </summary>
    public bool ConfirmsTcpDetection { get; set; }

    /// <summary>
    /// Conflict description if JA3 disagrees with TCP detection.
    /// </summary>
    public string? ConflictReason { get; set; }
}

/// <summary>
/// TCP SYN fingerprint data (p0f-style).
/// </summary>
public class TcpFingerprintData
{
    /// <summary>
    /// Frame number where this fingerprint was captured.
    /// </summary>
    public uint FrameNumber { get; set; }

    /// <summary>
    /// IP Time-To-Live value.
    /// </summary>
    public byte Ttl { get; set; }

    /// <summary>
    /// Don't Fragment flag set.
    /// </summary>
    public bool DfFlag { get; set; }

    /// <summary>
    /// Initial TCP window size.
    /// </summary>
    public ushort WindowSize { get; set; }

    /// <summary>
    /// Maximum Segment Size (MSS) option value.
    /// </summary>
    public ushort? Mss { get; set; }

    /// <summary>
    /// Window Scale option value.
    /// </summary>
    public byte? WindowScale { get; set; }

    /// <summary>
    /// SACK Permitted option present.
    /// </summary>
    public bool SackPermitted { get; set; }

    /// <summary>
    /// TCP Timestamp option present.
    /// </summary>
    public bool TimestampPresent { get; set; }

    /// <summary>
    /// TCP Timestamp value (for uptime estimation).
    /// </summary>
    public uint? TimestampValue { get; set; }

    /// <summary>
    /// Raw TCP options string from TShark.
    /// </summary>
    public string? RawOptions { get; set; }

    /// <summary>
    /// TCP options order as a signature string (e.g., "MSS,NOP,WS,NOP,NOP,TS,SACK").
    /// </summary>
    public string? OptionsOrder { get; set; }

    /// <summary>
    /// Generates a p0f-style fingerprint signature.
    /// Format: TTL:DF:WS:MSS:WSCALE:OPTS
    /// </summary>
    public string ToSignature()
    {
        var df = DfFlag ? "D" : ".";
        var mss = Mss?.ToString() ?? "*";
        var ws = WindowScale?.ToString() ?? "*";
        var opts = OptionsOrder ?? "*";
        return $"{Ttl}:{df}:{WindowSize}:{mss}:{ws}:{opts}";
    }
}

/// <summary>
/// JA3 TLS fingerprint data.
/// </summary>
public class Ja3FingerprintData
{
    /// <summary>
    /// Frame number where this fingerprint was captured.
    /// </summary>
    public uint FrameNumber { get; set; }

    /// <summary>
    /// TLS handshake version (e.g., 0x0303 for TLS 1.2).
    /// </summary>
    public ushort TlsVersion { get; set; }

    /// <summary>
    /// Cipher suites offered (comma-separated).
    /// </summary>
    public string? CipherSuites { get; set; }

    /// <summary>
    /// TLS extensions (comma-separated).
    /// </summary>
    public string? Extensions { get; set; }

    /// <summary>
    /// Elliptic curves (comma-separated).
    /// </summary>
    public string? EllipticCurves { get; set; }

    /// <summary>
    /// EC point formats (comma-separated).
    /// </summary>
    public string? EcPointFormats { get; set; }

    /// <summary>
    /// Computed JA3 hash (MD5 of JA3 string).
    /// </summary>
    public string? Ja3Hash { get; set; }

    /// <summary>
    /// Raw JA3 string before hashing.
    /// </summary>
    public string? Ja3String { get; set; }

    /// <summary>
    /// Generates the JA3 string (before MD5 hashing).
    /// Format: TLSVersion,CipherSuites,Extensions,EllipticCurves,EcPointFormats
    /// </summary>
    public string ToJa3String()
    {
        return $"{TlsVersion},{CipherSuites ?? ""},{Extensions ?? ""},{EllipticCurves ?? ""},{EcPointFormats ?? ""}";
    }
}

/// <summary>
/// DHCP fingerprint data (Option 55 based).
/// </summary>
public class DhcpFingerprintData
{
    /// <summary>
    /// Frame number where this fingerprint was captured.
    /// </summary>
    public uint FrameNumber { get; set; }

    /// <summary>
    /// DHCP Option 55 (Parameter Request List) as comma-separated values.
    /// </summary>
    public string? Option55 { get; set; }

    /// <summary>
    /// DHCP Vendor Class Identifier (Option 60).
    /// </summary>
    public string? VendorClassId { get; set; }

    /// <summary>
    /// DHCP Hostname (Option 12).
    /// </summary>
    public string? Hostname { get; set; }

    /// <summary>
    /// DHCP message type (Discover, Request, etc.).
    /// </summary>
    public byte? MessageType { get; set; }
}

/// <summary>
/// Server banner information.
/// </summary>
public class ServerBanner
{
    /// <summary>
    /// Protocol/service (SSH, HTTP, FTP, etc.).
    /// </summary>
    public required string Protocol { get; init; }

    /// <summary>
    /// Port number.
    /// </summary>
    public ushort Port { get; set; }

    /// <summary>
    /// Raw banner text.
    /// </summary>
    public required string Banner { get; init; }

    /// <summary>
    /// Parsed product name from banner.
    /// </summary>
    public string? ProductName { get; set; }

    /// <summary>
    /// Parsed version from banner.
    /// </summary>
    public string? Version { get; set; }

    /// <summary>
    /// OS hint extracted from banner (e.g., "Ubuntu" from SSH banner).
    /// </summary>
    public string? OsHint { get; set; }
}

/// <summary>
/// Confidence level for OS detection.
/// </summary>
public enum OsConfidenceLevel
{
    /// <summary>No usable fingerprint data.</summary>
    Unknown = 0,

    /// <summary>Weak signal (single field match, common TTL, etc.).</summary>
    Low = 1,

    /// <summary>Moderate signal (multiple fields match, but ambiguous).</summary>
    Medium = 2,

    /// <summary>Strong signal (TCP + JA3 agree, or unique signature match).</summary>
    High = 3,

    /// <summary>Very strong signal (multiple independent sources confirm).</summary>
    VeryHigh = 4
}

/// <summary>
/// Detection method used for OS identification.
/// </summary>
public enum OsDetectionMethod
{
    /// <summary>Unknown or undetected.</summary>
    Unknown = 0,

    /// <summary>TCP SYN fingerprinting (p0f-style).</summary>
    TcpSyn = 1,

    /// <summary>JA3 TLS fingerprinting.</summary>
    Ja3 = 2,

    /// <summary>MAC vendor OUI lookup.</summary>
    MacVendor = 3,

    /// <summary>DHCP Option 55 fingerprinting.</summary>
    Dhcp = 4,

    /// <summary>Server banner parsing (SSH, HTTP, etc.).</summary>
    ServerBanner = 5,

    /// <summary>Combined/hybrid detection using multiple methods.</summary>
    Combined = 6
}

/// <summary>
/// Device type classification.
/// </summary>
public enum DeviceType
{
    /// <summary>Unknown device type.</summary>
    Unknown = 0,

    /// <summary>Desktop or laptop computer.</summary>
    Desktop = 1,

    /// <summary>Server.</summary>
    Server = 2,

    /// <summary>Mobile device (phone, tablet).</summary>
    Mobile = 3,

    /// <summary>IoT device (camera, sensor, smart device).</summary>
    IoT = 4,

    /// <summary>Network equipment (router, switch, firewall).</summary>
    NetworkEquipment = 5,

    /// <summary>Printer or MFP.</summary>
    Printer = 6,

    /// <summary>Virtual machine or container.</summary>
    Virtual = 7
}

/// <summary>
/// OS signature for database matching.
/// </summary>
public class OsSignature
{
    /// <summary>
    /// Unique signature identifier.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// Operating system family.
    /// </summary>
    public required string OsFamily { get; init; }

    /// <summary>
    /// OS version or version range.
    /// </summary>
    public string? OsVersion { get; set; }

    /// <summary>
    /// Device type this signature represents.
    /// </summary>
    public DeviceType DeviceType { get; set; }

    /// <summary>
    /// TCP fingerprint pattern (regex or exact match).
    /// Format: TTL:DF:WS:MSS:WSCALE:OPTS (with wildcards)
    /// </summary>
    public string? TcpPattern { get; set; }

    /// <summary>
    /// Expected TTL value (before hop reduction).
    /// </summary>
    public byte? InitialTtl { get; set; }

    /// <summary>
    /// Don't Fragment flag expected value.
    /// </summary>
    public bool? DfFlag { get; set; }

    /// <summary>
    /// Window size pattern (exact or range).
    /// </summary>
    public string? WindowSizePattern { get; set; }

    /// <summary>
    /// MSS value pattern.
    /// </summary>
    public string? MssPattern { get; set; }

    /// <summary>
    /// TCP options order pattern.
    /// </summary>
    public string? OptionsPattern { get; set; }

    /// <summary>
    /// JA3 hashes known for this OS (if any).
    /// </summary>
    public List<string>? Ja3Hashes { get; set; }

    /// <summary>
    /// DHCP Option 55 patterns for this OS.
    /// </summary>
    public List<string>? DhcpPatterns { get; set; }

    /// <summary>
    /// Priority for signature matching (higher = checked first).
    /// </summary>
    public int Priority { get; set; }

    /// <summary>
    /// Source of signature (p0f, satori, custom, etc.).
    /// </summary>
    public string? Source { get; set; }
}

/// <summary>
/// MAC vendor OUI database entry.
/// </summary>
public class MacVendorEntry
{
    /// <summary>
    /// OUI prefix (first 3 bytes as hex, e.g., "00:50:56").
    /// </summary>
    public required string OuiPrefix { get; init; }

    /// <summary>
    /// Vendor/manufacturer name.
    /// </summary>
    public required string Vendor { get; init; }

    /// <summary>
    /// Device type hint (if known for this vendor).
    /// </summary>
    public DeviceType? DeviceTypeHint { get; set; }

    /// <summary>
    /// OS hint (e.g., "Apple" vendor → likely macOS/iOS).
    /// </summary>
    public string? OsHint { get; set; }
}
