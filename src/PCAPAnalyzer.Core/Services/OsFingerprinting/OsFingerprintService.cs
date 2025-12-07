using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.OsFingerprinting;

/// <summary>
/// Passive OS fingerprinting service using TCP SYN, JA3, MAC vendor, and DHCP signals.
/// Thread-safe for concurrent packet processing.
/// </summary>
public sealed class OsFingerprintService : IOsFingerprintService
{
    private readonly ILogger<OsFingerprintService> _logger;
    private readonly ConcurrentDictionary<string, HostFingerprint> _hosts = [];

    // Signature databases (loaded once at startup)
    private List<TcpSignatureEntry>? _tcpSignatures;
    private Dictionary<string, Ja3SignatureEntry>? _ja3Signatures;
    private Dictionary<string, MacVendorEntry>? _macVendors;

    // TCP SYN flag (0x02)
    private const ushort TCP_SYN_FLAG = 0x0002;

    public OsFingerprintService(ILogger<OsFingerprintService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        LoadSignatureDatabases();
    }

    public int HostCount => _hosts.Count;

    public void ProcessPacket(
        OsFingerprintRawFields fields,
        uint frameNumber,
        DateTime timestamp,
        string sourceIP,
        string destIP,
        ushort sourcePort,
        ushort destPort,
        ushort tcpFlags)
    {
        if (string.IsNullOrEmpty(sourceIP) && string.IsNullOrEmpty(destIP))
            return;

        // Get or create host entry for source IP
        if (!string.IsNullOrEmpty(sourceIP))
        {
            var host = _hosts.GetOrAdd(sourceIP, ip => new HostFingerprint
            {
                IpAddress = ip,
                FirstSeen = timestamp,
                LastSeen = timestamp
            });

            ProcessPacketForHost(host, fields, frameNumber, timestamp, sourcePort, destPort, tcpFlags, isSource: true);
        }

        // Also track destination for server banners
        if (!string.IsNullOrEmpty(destIP) && !string.IsNullOrEmpty(fields.HttpServer))
        {
            var destHost = _hosts.GetOrAdd(destIP, ip => new HostFingerprint
            {
                IpAddress = ip,
                FirstSeen = timestamp,
                LastSeen = timestamp
            });

            ProcessServerBanner(destHost, fields, frameNumber, destPort);
        }
    }

    private void ProcessPacketForHost(
        HostFingerprint host,
        OsFingerprintRawFields fields,
        uint frameNumber,
        DateTime timestamp,
        ushort sourcePort,
        ushort destPort,
        ushort tcpFlags,
        bool isSource)
    {
        lock (host)
        {
            host.PacketCount++;
            host.LastSeen = timestamp;

            // Extract MAC address (first time only)
            if (string.IsNullOrEmpty(host.MacAddress) && !string.IsNullOrEmpty(fields.EthSrc) && isSource)
            {
                host.MacAddress = NormalizeMacAddress(fields.EthSrc);
                host.MacVendor = LookupMacVendor(host.MacAddress);
            }

            // Process TCP SYN for fingerprinting (SYN without ACK = client SYN)
            if (isSource && IsTcpSyn(tcpFlags) && fields.HasTcpFingerprintData)
            {
                var tcpFingerprint = ExtractTcpFingerprint(fields, frameNumber);
                if (tcpFingerprint != null)
                {
                    host.TcpFingerprints.Add(tcpFingerprint);
                }
            }

            // Process TLS ClientHello for JA3 (handshake type 1 = ClientHello)
            if (isSource && fields.HasJa3Data && fields.TlsHandshakeType == "1")
            {
                var ja3Fingerprint = ExtractJa3Fingerprint(fields, frameNumber);
                if (ja3Fingerprint != null)
                {
                    host.Ja3Fingerprints.Add(ja3Fingerprint);
                }
            }

            // Process DHCP fingerprinting
            if (fields.HasDhcpData)
            {
                var dhcpFingerprint = ExtractDhcpFingerprint(fields, frameNumber);
                if (dhcpFingerprint != null)
                {
                    host.DhcpFingerprint = dhcpFingerprint;
                    if (!string.IsNullOrEmpty(dhcpFingerprint.Hostname))
                    {
                        host.Hostname = dhcpFingerprint.Hostname;
                    }
                }
            }

            // Extract server banners (SSH, HTTP)
            if (!string.IsNullOrEmpty(fields.SshProtocol))
            {
                ProcessSshBanner(host, fields.SshProtocol, frameNumber, sourcePort);
            }

            // Track open ports (for servers responding)
            if (!isSource && sourcePort > 0)
            {
                host.OpenPorts.Add(sourcePort);
            }
        }
    }

    private void ProcessServerBanner(HostFingerprint host, OsFingerprintRawFields fields, uint frameNumber, ushort port)
    {
        lock (host)
        {
            if (!string.IsNullOrEmpty(fields.HttpServer))
            {
                var existing = host.ServerBanners.FirstOrDefault(b => b.Protocol == "HTTP" && b.Port == port);
                if (existing == null)
                {
                    var (productName, version, osHint) = ParseHttpServerBanner(fields.HttpServer);
                    host.ServerBanners.Add(new ServerBanner
                    {
                        Protocol = "HTTP",
                        Port = port,
                        Banner = fields.HttpServer,
                        ProductName = productName,
                        Version = version,
                        OsHint = osHint
                    });
                }
            }
        }
    }

    private void ProcessSshBanner(HostFingerprint host, string sshProtocol, uint frameNumber, ushort port)
    {
        var existing = host.ServerBanners.FirstOrDefault(b => b.Protocol == "SSH" && b.Port == port);
        if (existing == null)
        {
            var (productName, version, osHint) = ParseSshBanner(sshProtocol);
            host.ServerBanners.Add(new ServerBanner
            {
                Protocol = "SSH",
                Port = port,
                Banner = sshProtocol,
                ProductName = productName,
                Version = version,
                OsHint = osHint
            });
        }
    }

    public async Task FinalizeAnalysisAsync()
    {
        await Task.Run(() =>
        {
            foreach (var host in _hosts.Values)
            {
                lock (host)
                {
                    // Perform OS detection using all collected signals
                    PerformOsDetection(host);

                    // Perform JA3 verification
                    PerformJa3Verification(host);
                }
            }
        });

        _logger.LogInformation("OS fingerprinting complete: {HostCount} hosts detected", _hosts.Count);
    }

    public IReadOnlyList<HostFingerprint> GetHostFingerprints()
    {
        return _hosts.Values.OrderByDescending(h => h.PacketCount).ToList();
    }

    public HostFingerprint? GetHost(string ipAddress)
    {
        return _hosts.TryGetValue(ipAddress, out var host) ? host : null;
    }

    public void Clear()
    {
        _hosts.Clear();
    }

    #region TCP Fingerprint Extraction

    private static bool IsTcpSyn(ushort flags)
    {
        // SYN set, ACK not set (client SYN)
        return (flags & TCP_SYN_FLAG) != 0 && (flags & 0x0010) == 0;
    }

    private TcpFingerprintData? ExtractTcpFingerprint(OsFingerprintRawFields fields, uint frameNumber)
    {
        var fingerprint = new TcpFingerprintData { FrameNumber = frameNumber };

        // Parse TTL
        if (byte.TryParse(fields.IpTtl, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ttl))
        {
            fingerprint.Ttl = ttl;
        }

        // Parse DF flag (TShark outputs "1" or "0" or empty)
        fingerprint.DfFlag = fields.IpDfFlag == "1";

        // Parse window size
        if (ushort.TryParse(fields.TcpWindowSize, NumberStyles.Integer, CultureInfo.InvariantCulture, out var winSize))
        {
            fingerprint.WindowSize = winSize;
        }

        // Parse MSS
        if (ushort.TryParse(fields.TcpMss, NumberStyles.Integer, CultureInfo.InvariantCulture, out var mss))
        {
            fingerprint.Mss = mss;
        }

        // Parse Window Scale
        if (byte.TryParse(fields.TcpWindowScale, NumberStyles.Integer, CultureInfo.InvariantCulture, out var wscale))
        {
            fingerprint.WindowScale = wscale;
        }

        // Parse SACK permitted (TShark outputs "1" or empty)
        fingerprint.SackPermitted = fields.TcpSackPerm == "1";

        // Parse timestamp
        if (uint.TryParse(fields.TcpTimestamp, NumberStyles.Integer, CultureInfo.InvariantCulture, out var ts))
        {
            fingerprint.TimestampPresent = true;
            fingerprint.TimestampValue = ts;
        }

        fingerprint.RawOptions = fields.TcpOptions;
        fingerprint.OptionsOrder = ParseTcpOptionsOrder(fields.TcpOptions);

        return fingerprint;
    }

    private static string? ParseTcpOptionsOrder(string? rawOptions)
    {
        if (string.IsNullOrEmpty(rawOptions))
            return null;

        // TShark outputs TCP options as hex bytes or descriptive text
        // We extract the option types in order
        var options = new List<string>();

        // Common option patterns in TShark output
        if (rawOptions.Contains("mss", StringComparison.OrdinalIgnoreCase))
            options.Add("MSS");
        if (rawOptions.Contains("sack_perm", StringComparison.OrdinalIgnoreCase) ||
            rawOptions.Contains("sack permitted", StringComparison.OrdinalIgnoreCase))
            options.Add("SACK");
        if (rawOptions.Contains("timestamp", StringComparison.OrdinalIgnoreCase) ||
            rawOptions.Contains("timestamps", StringComparison.OrdinalIgnoreCase))
            options.Add("TS");
        if (rawOptions.Contains("nop", StringComparison.OrdinalIgnoreCase))
            options.Add("NOP");
        if (rawOptions.Contains("wscale", StringComparison.OrdinalIgnoreCase) ||
            rawOptions.Contains("window scale", StringComparison.OrdinalIgnoreCase))
            options.Add("WS");

        return options.Count > 0 ? string.Join(",", options) : null;
    }

    #endregion

    #region JA3 Fingerprint Extraction

    private Ja3FingerprintData? ExtractJa3Fingerprint(OsFingerprintRawFields fields, uint frameNumber)
    {
        var fingerprint = new Ja3FingerprintData { FrameNumber = frameNumber };

        // Parse TLS version (hex string like "0x0303")
        if (!string.IsNullOrEmpty(fields.TlsVersion))
        {
            var versionStr = fields.TlsVersion.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                ? fields.TlsVersion[2..]
                : fields.TlsVersion;
            if (ushort.TryParse(versionStr, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var version))
            {
                fingerprint.TlsVersion = version;
            }
        }

        // Store cipher suites, extensions, etc.
        fingerprint.CipherSuites = NormalizeJa3List(fields.TlsCipherSuites);
        fingerprint.Extensions = NormalizeJa3List(fields.TlsExtensions);
        fingerprint.EllipticCurves = NormalizeJa3List(fields.TlsEllipticCurves);
        fingerprint.EcPointFormats = NormalizeJa3List(fields.TlsEcPointFormats);

        // Generate JA3 string and hash
        fingerprint.Ja3String = fingerprint.ToJa3String();
        fingerprint.Ja3Hash = ComputeMd5Hash(fingerprint.Ja3String);

        return fingerprint;
    }

    private static string? NormalizeJa3List(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return null;

        // TShark may output comma-separated or space-separated values
        // Normalize to comma-separated
        return value.Replace(" ", ",", StringComparison.Ordinal)
                   .Replace(",,", ",", StringComparison.Ordinal)
                   .Trim(',');
    }

    /// <summary>
    /// Computes MD5 hash for JA3 fingerprinting.
    /// Note: MD5 is required by JA3 specification (not used for security).
    /// </summary>
#pragma warning disable CA5351 // MD5 is required by JA3 specification
    private static string ComputeMd5Hash(string input)
    {
        var inputBytes = Encoding.UTF8.GetBytes(input);
        var hashBytes = MD5.HashData(inputBytes);
        return Convert.ToHexStringLower(hashBytes);
    }
#pragma warning restore CA5351

    #endregion

    #region DHCP Fingerprint Extraction

    private DhcpFingerprintData? ExtractDhcpFingerprint(OsFingerprintRawFields fields, uint frameNumber)
    {
        return new DhcpFingerprintData
        {
            FrameNumber = frameNumber,
            Option55 = fields.DhcpOption55,
            VendorClassId = fields.DhcpVendorClassId,
            Hostname = fields.DhcpHostname,
            MessageType = byte.TryParse(fields.DhcpMessageType, out var mt) ? mt : null
        };
    }

    #endregion

    #region MAC Vendor Lookup

    private static string NormalizeMacAddress(string mac)
    {
        // Normalize to XX:XX:XX:XX:XX:XX format
        return mac.ToUpperInvariant()
                  .Replace("-", ":", StringComparison.Ordinal)
                  .Replace(".", ":", StringComparison.Ordinal);
    }

    private string? LookupMacVendor(string macAddress)
    {
        if (_macVendors == null || string.IsNullOrEmpty(macAddress))
            return null;

        // Extract OUI prefix (first 3 octets)
        var parts = macAddress.Split(':');
        if (parts.Length < 3)
            return null;

        var oui = $"{parts[0]}:{parts[1]}:{parts[2]}".ToUpperInvariant();

        return _macVendors.TryGetValue(oui, out var entry) ? entry.Vendor : null;
    }

    #endregion

    #region Banner Parsing

    private static (string? ProductName, string? Version, string? OsHint) ParseHttpServerBanner(string banner)
    {
        // Examples: "Apache/2.4.41 (Ubuntu)", "nginx/1.18.0", "Microsoft-IIS/10.0"
        string? productName = null;
        string? version = null;
        string? osHint = null;

        var slashIndex = banner.IndexOf('/', StringComparison.Ordinal);
        if (slashIndex > 0)
        {
            productName = banner[..slashIndex].Trim();
            var rest = banner[(slashIndex + 1)..];
            var spaceIndex = rest.IndexOf(' ', StringComparison.Ordinal);
            version = spaceIndex > 0 ? rest[..spaceIndex] : rest;
        }
        else
        {
            productName = banner;
        }

        // Extract OS hints from banner
        if (banner.Contains("Ubuntu", StringComparison.OrdinalIgnoreCase))
            osHint = "Ubuntu";
        else if (banner.Contains("Debian", StringComparison.OrdinalIgnoreCase))
            osHint = "Debian";
        else if (banner.Contains("CentOS", StringComparison.OrdinalIgnoreCase))
            osHint = "CentOS";
        else if (banner.Contains("Red Hat", StringComparison.OrdinalIgnoreCase))
            osHint = "Red Hat";
        else if (banner.Contains("Win64", StringComparison.OrdinalIgnoreCase) ||
                 banner.Contains("Win32", StringComparison.OrdinalIgnoreCase) ||
                 banner.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
            osHint = "Windows";

        return (productName, version, osHint);
    }

    private static (string? ProductName, string? Version, string? OsHint) ParseSshBanner(string banner)
    {
        // Examples: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1", "SSH-2.0-OpenSSH_for_Windows_8.1"
        string? productName = null;
        string? version = null;
        string? osHint = null;

        // Skip "SSH-2.0-" prefix
        var dashIndex = banner.LastIndexOf('-');
        var relevantPart = dashIndex >= 0 && dashIndex < banner.Length - 1
            ? banner[(dashIndex + 1)..]
            : banner;

        // Parse OpenSSH version
        if (relevantPart.StartsWith("OpenSSH", StringComparison.OrdinalIgnoreCase))
        {
            productName = "OpenSSH";
            var underscoreIdx = relevantPart.IndexOf('_', StringComparison.Ordinal);
            if (underscoreIdx > 0)
            {
                var spaceIdx = relevantPart.IndexOf(' ', underscoreIdx);
                version = spaceIdx > underscoreIdx
                    ? relevantPart[(underscoreIdx + 1)..spaceIdx]
                    : relevantPart[(underscoreIdx + 1)..];
            }
        }

        // Extract OS hints
        if (banner.Contains("Ubuntu", StringComparison.OrdinalIgnoreCase))
            osHint = "Ubuntu";
        else if (banner.Contains("Debian", StringComparison.OrdinalIgnoreCase))
            osHint = "Debian";
        else if (banner.Contains("for_Windows", StringComparison.OrdinalIgnoreCase) ||
                 banner.Contains("Windows", StringComparison.OrdinalIgnoreCase))
            osHint = "Windows";
        else if (banner.Contains("FreeBSD", StringComparison.OrdinalIgnoreCase))
            osHint = "FreeBSD";

        return (productName, version, osHint);
    }

    #endregion

    #region OS Detection

    private void PerformOsDetection(HostFingerprint host)
    {
        var candidates = new List<(OsDetectionResult Result, double Score)>();

        // 1. TCP fingerprint matching
        if (host.TcpFingerprints.Count > 0)
        {
            var tcpResult = MatchTcpFingerprint(host.TcpFingerprints[0]);
            if (tcpResult != null)
            {
                candidates.Add((tcpResult, tcpResult.ConfidenceScore));
            }
        }

        // 2. JA3 matching
        if (host.Ja3Fingerprints.Count > 0)
        {
            var ja3Result = MatchJa3Fingerprint(host.Ja3Fingerprints[0]);
            if (ja3Result != null)
            {
                candidates.Add((ja3Result, ja3Result.ConfidenceScore));
            }
        }

        // 3. MAC vendor hints
        if (!string.IsNullOrEmpty(host.MacAddress) && _macVendors != null)
        {
            var macResult = GetMacVendorOsHint(host.MacAddress);
            if (macResult != null)
            {
                candidates.Add((macResult, macResult.ConfidenceScore));
            }
        }

        // 4. Server banner hints
        foreach (var banner in host.ServerBanners)
        {
            if (!string.IsNullOrEmpty(banner.OsHint))
            {
                candidates.Add((new OsDetectionResult
                {
                    OsFamily = banner.OsHint,
                    DeviceType = DeviceType.Server,
                    Confidence = OsConfidenceLevel.Medium,
                    ConfidenceScore = 0.5,
                    Method = OsDetectionMethod.ServerBanner
                }, 0.5));
            }
        }

        // Select best result
        if (candidates.Count > 0)
        {
            var best = candidates.OrderByDescending(c => c.Score).First();
            host.OsDetection = best.Result;

            // If multiple methods agree, boost confidence
            var agreeing = candidates.Count(c =>
                c.Result.OsFamily.Equals(best.Result.OsFamily, StringComparison.OrdinalIgnoreCase));

            if (agreeing > 1)
            {
                host.OsDetection = host.OsDetection with
                {
                    Confidence = OsConfidenceLevel.High,
                    ConfidenceScore = Math.Min(1.0, best.Score + 0.2),
                    Method = OsDetectionMethod.Combined
                };
            }
        }
    }

    private OsDetectionResult? MatchTcpFingerprint(TcpFingerprintData tcpFp)
    {
        if (_tcpSignatures == null)
            return null;

        OsDetectionResult? bestMatch = null;
        double bestScore = 0;

        foreach (var sig in _tcpSignatures.OrderByDescending(s => s.Priority))
        {
            double score = 0;
            int matchedFields = 0;
            int totalFields = 0;

            // Match TTL (allow for hop reduction - check initial TTL)
            if (sig.InitialTtl.HasValue)
            {
                totalFields++;
                var inferredInitialTtl = InferInitialTtl(tcpFp.Ttl);
                if (inferredInitialTtl == sig.InitialTtl.Value)
                {
                    score += 0.3;
                    matchedFields++;
                }
            }

            // Match DF flag
            if (sig.DfFlag.HasValue)
            {
                totalFields++;
                if (tcpFp.DfFlag == sig.DfFlag.Value)
                {
                    score += 0.1;
                    matchedFields++;
                }
            }

            // Match window size pattern
            if (!string.IsNullOrEmpty(sig.WindowSizePattern))
            {
                totalFields++;
                var patterns = sig.WindowSizePattern.Split('|');
                if (patterns.Any(p => p == tcpFp.WindowSize.ToString(CultureInfo.InvariantCulture)))
                {
                    score += 0.2;
                    matchedFields++;
                }
            }

            // Match MSS pattern
            if (!string.IsNullOrEmpty(sig.MssPattern) && tcpFp.Mss.HasValue)
            {
                totalFields++;
                var patterns = sig.MssPattern.Split('|');
                if (patterns.Any(p => p == tcpFp.Mss.Value.ToString(CultureInfo.InvariantCulture)))
                {
                    score += 0.15;
                    matchedFields++;
                }
            }

            // Match window scale
            if (!string.IsNullOrEmpty(sig.WindowScalePattern) && tcpFp.WindowScale.HasValue)
            {
                totalFields++;
                var patterns = sig.WindowScalePattern.Split('|');
                if (patterns.Any(p => p == tcpFp.WindowScale.Value.ToString(CultureInfo.InvariantCulture)))
                {
                    score += 0.15;
                    matchedFields++;
                }
            }

            // Calculate confidence based on matched fields
            if (matchedFields >= 3 && score > bestScore)
            {
                bestScore = score;
                bestMatch = new OsDetectionResult
                {
                    OsFamily = sig.OsFamily,
                    OsVersion = sig.OsVersion,
                    DeviceType = sig.DeviceType,
                    Confidence = score >= 0.7 ? OsConfidenceLevel.High :
                                score >= 0.5 ? OsConfidenceLevel.Medium : OsConfidenceLevel.Low,
                    ConfidenceScore = score,
                    Method = OsDetectionMethod.TcpSyn,
                    SignatureId = sig.Id
                };
            }
        }

        return bestMatch;
    }

    private static byte InferInitialTtl(byte observedTtl)
    {
        // Common initial TTL values and their typical ranges after hops
        return observedTtl switch
        {
            >= 1 and <= 64 => 64,      // Linux, macOS, FreeBSD, etc.
            >= 65 and <= 128 => 128,   // Windows
            >= 129 and <= 255 => 255,  // Cisco, some routers
            _ => observedTtl
        };
    }

    private OsDetectionResult? MatchJa3Fingerprint(Ja3FingerprintData ja3Fp)
    {
        if (_ja3Signatures == null || string.IsNullOrEmpty(ja3Fp.Ja3Hash))
            return null;

        if (_ja3Signatures.TryGetValue(ja3Fp.Ja3Hash, out var sig))
        {
            return new OsDetectionResult
            {
                OsFamily = sig.OsHint ?? "Unknown",
                OsVersion = sig.Application,
                DeviceType = sig.DeviceType,
                Confidence = OsConfidenceLevel.Medium,
                ConfidenceScore = 0.6,
                Method = OsDetectionMethod.Ja3,
                SignatureId = ja3Fp.Ja3Hash
            };
        }

        return null;
    }

    private OsDetectionResult? GetMacVendorOsHint(string macAddress)
    {
        if (_macVendors == null)
            return null;

        var parts = macAddress.Split(':');
        if (parts.Length < 3)
            return null;

        var oui = $"{parts[0]}:{parts[1]}:{parts[2]}".ToUpperInvariant();

        if (_macVendors.TryGetValue(oui, out var entry) && !string.IsNullOrEmpty(entry.OsHint))
        {
            return new OsDetectionResult
            {
                OsFamily = entry.OsHint,
                DeviceType = entry.DeviceTypeHint ?? DeviceType.Unknown,
                Confidence = OsConfidenceLevel.Low,
                ConfidenceScore = 0.3,
                Method = OsDetectionMethod.MacVendor
            };
        }

        return null;
    }

    private void PerformJa3Verification(HostFingerprint host)
    {
        if (host.OsDetection == null || host.Ja3Fingerprints.Count == 0)
            return;

        var ja3Hash = host.Ja3Fingerprints[0].Ja3Hash;
        if (string.IsNullOrEmpty(ja3Hash) || _ja3Signatures == null)
            return;

        if (_ja3Signatures.TryGetValue(ja3Hash, out var sig))
        {
            var confirms = !string.IsNullOrEmpty(sig.OsHint) &&
                          host.OsDetection.OsFamily.Contains(sig.OsHint, StringComparison.OrdinalIgnoreCase);

            host.Ja3Verification = new Ja3DetectionResult
            {
                Ja3Hash = ja3Hash,
                DetectedApplication = sig.Application,
                OsHint = sig.OsHint,
                ConfirmsTcpDetection = confirms,
                ConflictReason = confirms ? null :
                    $"JA3 suggests {sig.OsHint ?? sig.Application}, TCP suggests {host.OsDetection.OsFamily}"
            };
        }
    }

    #endregion

    #region Signature Database Loading

    private void LoadSignatureDatabases()
    {
        try
        {
            LoadTcpSignatures();
            LoadJa3Signatures();
            LoadMacVendors();

            _logger.LogInformation(
                "Loaded OS fingerprint databases: {TcpCount} TCP, {Ja3Count} JA3, {MacCount} MAC vendors",
                _tcpSignatures?.Count ?? 0,
                _ja3Signatures?.Count ?? 0,
                _macVendors?.Count ?? 0);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load OS fingerprint databases, using defaults");
            LoadDefaultSignatures();
        }
    }

    private void LoadTcpSignatures()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourcePath = "PCAPAnalyzer.Core.Data.OsFingerprinting.TcpSignatures.json";

        using var stream = assembly.GetManifestResourceStream(resourcePath);
        if (stream != null)
        {
            using var reader = new StreamReader(stream);
            var json = reader.ReadToEnd();
            var data = JsonSerializer.Deserialize<TcpSignatureDatabase>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            _tcpSignatures = data?.Signatures ?? new List<TcpSignatureEntry>();
        }
        else
        {
            // Try loading from file path (development)
            var filePath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "OsFingerprinting", "TcpSignatures.json");

            if (File.Exists(filePath))
            {
                var json = File.ReadAllText(filePath);
                var data = JsonSerializer.Deserialize<TcpSignatureDatabase>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                _tcpSignatures = data?.Signatures ?? new List<TcpSignatureEntry>();
            }
            else
            {
                _tcpSignatures = new List<TcpSignatureEntry>();
            }
        }
    }

    private void LoadJa3Signatures()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourcePath = "PCAPAnalyzer.Core.Data.OsFingerprinting.Ja3Signatures.json";

        using var stream = assembly.GetManifestResourceStream(resourcePath);
        if (stream != null)
        {
            using var reader = new StreamReader(stream);
            var json = reader.ReadToEnd();
            var data = JsonSerializer.Deserialize<Ja3SignatureDatabase>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            _ja3Signatures = data?.Signatures?.ToDictionary(s => s.Ja3Hash, s => s)
                            ?? new Dictionary<string, Ja3SignatureEntry>();
        }
        else
        {
            var filePath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "OsFingerprinting", "Ja3Signatures.json");

            if (File.Exists(filePath))
            {
                var json = File.ReadAllText(filePath);
                var data = JsonSerializer.Deserialize<Ja3SignatureDatabase>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                _ja3Signatures = data?.Signatures?.ToDictionary(s => s.Ja3Hash, s => s)
                                ?? new Dictionary<string, Ja3SignatureEntry>();
            }
            else
            {
                _ja3Signatures = new Dictionary<string, Ja3SignatureEntry>();
            }
        }
    }

    private void LoadMacVendors()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var resourcePath = "PCAPAnalyzer.Core.Data.OsFingerprinting.MacVendors.json";

        using var stream = assembly.GetManifestResourceStream(resourcePath);
        if (stream != null)
        {
            using var reader = new StreamReader(stream);
            var json = reader.ReadToEnd();
            var data = JsonSerializer.Deserialize<MacVendorDatabase>(json, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });
            _macVendors = data?.Vendors?.ToDictionary(
                v => v.Oui.ToUpperInvariant(),
                v => v)
                ?? new Dictionary<string, MacVendorEntry>();
        }
        else
        {
            var filePath = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Data", "OsFingerprinting", "MacVendors.json");

            if (File.Exists(filePath))
            {
                var json = File.ReadAllText(filePath);
                var data = JsonSerializer.Deserialize<MacVendorDatabase>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                _macVendors = data?.Vendors?.ToDictionary(
                    v => v.Oui.ToUpperInvariant(),
                    v => v)
                    ?? new Dictionary<string, MacVendorEntry>();
            }
            else
            {
                _macVendors = new Dictionary<string, MacVendorEntry>();
            }
        }
    }

    private void LoadDefaultSignatures()
    {
        // Minimal default signatures for when database loading fails
        _tcpSignatures = new List<TcpSignatureEntry>
        {
            new() { Id = "win-default", OsFamily = "Windows", InitialTtl = 128, DfFlag = true, Priority = 100 },
            new() { Id = "linux-default", OsFamily = "Linux", InitialTtl = 64, DfFlag = true, Priority = 100 },
            new() { Id = "macos-default", OsFamily = "macOS", InitialTtl = 64, DfFlag = true, Priority = 90 }
        };

        _ja3Signatures = new Dictionary<string, Ja3SignatureEntry>();
        _macVendors = new Dictionary<string, MacVendorEntry>();
    }

    #endregion

    #region Database DTOs

    private class TcpSignatureDatabase
    {
        public List<TcpSignatureEntry>? Signatures { get; set; }
    }

    private class Ja3SignatureDatabase
    {
        public List<Ja3SignatureEntry>? Signatures { get; set; }
    }

    private class MacVendorDatabase
    {
        public List<MacVendorEntry>? Vendors { get; set; }
    }

    private class TcpSignatureEntry
    {
        public string Id { get; set; } = string.Empty;
        public string OsFamily { get; set; } = string.Empty;
        public string? OsVersion { get; set; }
        public DeviceType DeviceType { get; set; }
        public byte? InitialTtl { get; set; }
        public bool? DfFlag { get; set; }
        public string? WindowSizePattern { get; set; }
        public string? MssPattern { get; set; }
        public string? WindowScalePattern { get; set; }
        public string? OptionsPattern { get; set; }
        public int Priority { get; set; }
    }

    private class Ja3SignatureEntry
    {
        public string Ja3Hash { get; set; } = string.Empty;
        public string? Application { get; set; }
        public string? OsHint { get; set; }
        public DeviceType DeviceType { get; set; }
        public bool IsMalware { get; set; }
    }

    private class MacVendorEntry
    {
        public string Oui { get; set; } = string.Empty;
        public string Vendor { get; set; } = string.Empty;
        public DeviceType? DeviceTypeHint { get; set; }
        public string? OsHint { get; set; }
    }

    #endregion
}
