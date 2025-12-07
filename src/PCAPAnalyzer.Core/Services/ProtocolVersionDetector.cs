using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.RegularExpressions;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services
{
    public interface IProtocolVersionDetector
    {
        VersionDetectionResult DetectVersion(PacketInfo packet);
        List<VersionDetectionResult> DetectVersions(IEnumerable<PacketInfo> packets);
        ProtocolVersionProfile? GetVersionProfile(int port, string protocol);
        Dictionary<string, List<VersionDetectionResult>> GroupVersionsByService(List<VersionDetectionResult> results);
    }

    public sealed class ProtocolVersionDetector : IProtocolVersionDetector
    {
        private readonly Dictionary<int, ProtocolVersionProfile> _versionProfiles;

        public ProtocolVersionDetector()
        {
            _versionProfiles = InitializeVersionProfiles();
        }

        private Dictionary<int, ProtocolVersionProfile> InitializeVersionProfiles()
        {
            return new Dictionary<int, ProtocolVersionProfile>
            {
                [443] = new ProtocolVersionProfile
                {
                    Port = 443,
                    Protocol = "TCP",
                    ServiceName = "HTTPS",
                    RequiresVersionCheck = true,
                    MinimumSecureVersion = "TLS 1.2",
                    SupportedVersions = ProtocolVersionDatabase.Protocols["SSL/TLS"]
                },
                [8443] = new ProtocolVersionProfile
                {
                    Port = 8443,
                    Protocol = "TCP",
                    ServiceName = "HTTPS-ALT",
                    RequiresVersionCheck = true,
                    MinimumSecureVersion = "TLS 1.2",
                    SupportedVersions = ProtocolVersionDatabase.Protocols["SSL/TLS"]
                },
                [22] = new ProtocolVersionProfile
                {
                    Port = 22,
                    Protocol = "TCP",
                    ServiceName = "SSH",
                    RequiresVersionCheck = true,
                    MinimumSecureVersion = "SSH-2.0",
                    SupportedVersions = ProtocolVersionDatabase.Protocols["SSH"]
                },
                [445] = new ProtocolVersionProfile
                {
                    Port = 445,
                    Protocol = "TCP",
                    ServiceName = "SMB",
                    RequiresVersionCheck = true,
                    MinimumSecureVersion = "SMB3.0",
                    SupportedVersions = ProtocolVersionDatabase.Protocols["SMB"]
                },
                [139] = new ProtocolVersionProfile
                {
                    Port = 139,
                    Protocol = "TCP",
                    ServiceName = "NetBIOS-SSN",
                    RequiresVersionCheck = true,
                    MinimumSecureVersion = "SMB3.0",
                    SupportedVersions = ProtocolVersionDatabase.Protocols["SMB"]
                },
                [3389] = new ProtocolVersionProfile
                {
                    Port = 3389,
                    Protocol = "TCP",
                    ServiceName = "RDP",
                    RequiresVersionCheck = true,
                    MinimumSecureVersion = "RDP 10.x",
                    SupportedVersions = ProtocolVersionDatabase.Protocols["RDP"]
                },
                [80] = new ProtocolVersionProfile
                {
                    Port = 80,
                    Protocol = "TCP",
                    ServiceName = "HTTP",
                    RequiresVersionCheck = true,
                    MinimumSecureVersion = "HTTP/2",
                    SupportedVersions = ProtocolVersionDatabase.Protocols["HTTP"]
                },
                [8080] = new ProtocolVersionProfile
                {
                    Port = 8080,
                    Protocol = "TCP",
                    ServiceName = "HTTP-PROXY",
                    RequiresVersionCheck = true,
                    MinimumSecureVersion = "HTTP/2",
                    SupportedVersions = ProtocolVersionDatabase.Protocols["HTTP"]
                },
                [636] = new ProtocolVersionProfile
                {
                    Port = 636,
                    Protocol = "TCP",
                    ServiceName = "LDAPS",
                    RequiresVersionCheck = true,
                    MinimumSecureVersion = "TLS 1.2",
                    SupportedVersions = ProtocolVersionDatabase.Protocols["SSL/TLS"]
                },
                [990] = new ProtocolVersionProfile
                {
                    Port = 990,
                    Protocol = "TCP",
                    ServiceName = "FTPS",
                    RequiresVersionCheck = true,
                    MinimumSecureVersion = "TLS 1.2",
                    SupportedVersions = ProtocolVersionDatabase.Protocols["SSL/TLS"]
                },
                [993] = new ProtocolVersionProfile
                {
                    Port = 993,
                    Protocol = "TCP",
                    ServiceName = "IMAPS",
                    RequiresVersionCheck = true,
                    MinimumSecureVersion = "TLS 1.2",
                    SupportedVersions = ProtocolVersionDatabase.Protocols["SSL/TLS"]
                },
                [995] = new ProtocolVersionProfile
                {
                    Port = 995,
                    Protocol = "TCP",
                    ServiceName = "POP3S",
                    RequiresVersionCheck = true,
                    MinimumSecureVersion = "TLS 1.2",
                    SupportedVersions = ProtocolVersionDatabase.Protocols["SSL/TLS"]
                }
            };
        }

        public VersionDetectionResult DetectVersion(PacketInfo packet)
        {
            var result = new VersionDetectionResult
            {
                Protocol = packet.Protocol.ToString(),
                VersionIdentified = false,
                SecurityRisk = ThreatSeverity.Info
            };

            // Check if this port requires version checking
            if (!_versionProfiles.ContainsKey(packet.DestinationPort))
            {
                return result;
            }

            var profile = _versionProfiles[packet.DestinationPort];
            var detectedVersion = ExtractVersionFromPacket(packet, profile);

            if (!string.IsNullOrEmpty(detectedVersion))
            {
                result.DetectedVersion = detectedVersion;
                result.VersionIdentified = true;
                result.Protocol = profile.ServiceName;

                // Evaluate security based on version
                EvaluateVersionSecurity(result, profile, detectedVersion);
            }
            else if (profile.RequiresVersionCheck)
            {
                // If version check is required but version not detected, flag as potential risk
                result.SecurityRisk = ThreatSeverity.Medium;
                result.SecurityAssessment = $"Unable to determine {profile.ServiceName} version. Version verification required.";
                result.Recommendation = $"Verify {profile.ServiceName} is using {profile.MinimumSecureVersion} or higher.";
            }

            return result;
        }

        [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
            Justification = "Version extraction requires comprehensive parsing of TLS handshakes, SSH banners, SMB negotiate protocol, HTTP version headers, and RDP security protocols across multiple protocol types")]
        private string ExtractVersionFromPacket(PacketInfo packet, ProtocolVersionProfile profile)
        {
            if (string.IsNullOrEmpty(packet.Info))
                return string.Empty;

            var info = packet.Info.ToUpper();
            
            // SSL/TLS version detection
            if (profile.ServiceName.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) || profile.ServiceName.Contains("TLS", StringComparison.OrdinalIgnoreCase) ||
                profile.ServiceName.EndsWith("S", StringComparison.OrdinalIgnoreCase)) // Services ending with S typically use TLS
            {
                if (info.Contains("SSLV2", StringComparison.OrdinalIgnoreCase) || info.Contains("SSL 2.0", StringComparison.OrdinalIgnoreCase))
                    return "SSL 2.0";
                if (info.Contains("SSLV3", StringComparison.OrdinalIgnoreCase) || info.Contains("SSL 3.0", StringComparison.OrdinalIgnoreCase))
                    return "SSL 3.0";
                if (info.Contains("TLS 1.0", StringComparison.OrdinalIgnoreCase) || info.Contains("TLSV1.0", StringComparison.OrdinalIgnoreCase))
                    return "TLS 1.0";
                if (info.Contains("TLS 1.1", StringComparison.OrdinalIgnoreCase) || info.Contains("TLSV1.1", StringComparison.OrdinalIgnoreCase))
                    return "TLS 1.1";
                if (info.Contains("TLS 1.2", StringComparison.OrdinalIgnoreCase) || info.Contains("TLSV1.2", StringComparison.OrdinalIgnoreCase))
                    return "TLS 1.2";
                if (info.Contains("TLS 1.3", StringComparison.OrdinalIgnoreCase) || info.Contains("TLSV1.3", StringComparison.OrdinalIgnoreCase))
                    return "TLS 1.3";

                // Check for TLS handshake
                if (info.Contains("CLIENT HELLO", StringComparison.OrdinalIgnoreCase) || info.Contains("SERVER HELLO", StringComparison.OrdinalIgnoreCase))
                {
                    // Try to extract version from handshake
                    var versionMatch = Regex.Match(packet.Info, @"Version:\s*([^\s,]+)", RegexOptions.IgnoreCase);
                    if (versionMatch.Success)
                        return NormalizeVersion(versionMatch.Groups[1].Value);
                }
            }

            // SSH version detection
            if (profile.ServiceName == "SSH")
            {
                if (info.Contains("SSH-1.0", StringComparison.OrdinalIgnoreCase))
                    return "SSH-1.0";
                if (info.Contains("SSH-1.5", StringComparison.OrdinalIgnoreCase))
                    return "SSH-1.5";
                if (info.Contains("SSH-2.0", StringComparison.OrdinalIgnoreCase))
                    return "SSH-2.0";
                
                // Look for SSH banner
                var sshMatch = Regex.Match(packet.Info, @"SSH-(\d+\.\d+)", RegexOptions.IgnoreCase);
                if (sshMatch.Success)
                    return $"SSH-{sshMatch.Groups[1].Value}";
            }

            // SMB version detection
            if (profile.ServiceName == "SMB" || profile.ServiceName == "NetBIOS-SSN")
            {
                if (info.Contains("SMB2", StringComparison.OrdinalIgnoreCase))
                {
                    if (info.Contains("SMB2.1", StringComparison.OrdinalIgnoreCase))
                        return "SMB2.1";
                    return "SMB2";
                }
                if (info.Contains("SMB3", StringComparison.OrdinalIgnoreCase))
                {
                    if (info.Contains("SMB3.1.1", StringComparison.OrdinalIgnoreCase))
                        return "SMB3.1.1";
                    if (info.Contains("SMB3.0", StringComparison.OrdinalIgnoreCase))
                        return "SMB3.0";
                    return "SMB3.0";
                }
                if (info.Contains("SMB", StringComparison.OrdinalIgnoreCase) && !info.Contains("SMB2", StringComparison.OrdinalIgnoreCase) && !info.Contains("SMB3", StringComparison.OrdinalIgnoreCase))
                    return "SMB1";

                // Check for SMB negotiate protocol
                if (info.Contains("NEGOTIATE PROTOCOL", StringComparison.OrdinalIgnoreCase))
                {
                    // Extract dialect from negotiate
                    var dialectMatch = Regex.Match(packet.Info, @"Dialect:\s*([^\s,]+)", RegexOptions.IgnoreCase);
                    if (dialectMatch.Success)
                        return MapSMBDialect(dialectMatch.Groups[1].Value);
                }
            }

            // HTTP version detection
            if (profile.ServiceName.StartsWith("HTTP", StringComparison.OrdinalIgnoreCase))
            {
                if (info.Contains("HTTP/1.0", StringComparison.OrdinalIgnoreCase))
                    return "HTTP/1.0";
                if (info.Contains("HTTP/1.1", StringComparison.OrdinalIgnoreCase))
                    return "HTTP/1.1";
                if (info.Contains("HTTP/2", StringComparison.OrdinalIgnoreCase))
                    return "HTTP/2";
                if (info.Contains("HTTP/3", StringComparison.OrdinalIgnoreCase) || info.Contains("QUIC", StringComparison.OrdinalIgnoreCase))
                    return "HTTP/3";
            }

            // RDP version detection (more complex, often requires session analysis)
            if (profile.ServiceName == "RDP")
            {
                if (info.Contains("RDP 4", StringComparison.OrdinalIgnoreCase))
                    return "RDP 4.0";
                if (info.Contains("RDP 5", StringComparison.OrdinalIgnoreCase))
                    return "RDP 5.x";
                if (info.Contains("RDP 6", StringComparison.OrdinalIgnoreCase))
                    return "RDP 6.x";
                if (info.Contains("RDP 10", StringComparison.OrdinalIgnoreCase) || info.Contains("RDP10", StringComparison.OrdinalIgnoreCase))
                    return "RDP 10.x";

                // Check for specific RDP security protocols
                if (info.Contains("CREDSSP", StringComparison.OrdinalIgnoreCase))
                    return "RDP 6.x"; // CredSSP introduced in RDP 6.0+
                if (info.Contains("NLA", StringComparison.OrdinalIgnoreCase))
                    return "RDP 6.x"; // NLA support indicates RDP 6.0+
            }

            return string.Empty;
        }

        private string NormalizeVersion(string version)
        {
            version = version.ToUpper();

            if (version.Contains("SSL2", StringComparison.OrdinalIgnoreCase) || version.Contains("SSLV2", StringComparison.OrdinalIgnoreCase))
                return "SSL 2.0";
            if (version.Contains("SSL3", StringComparison.OrdinalIgnoreCase) || version.Contains("SSLV3", StringComparison.OrdinalIgnoreCase))
                return "SSL 3.0";
            if (version.Contains("TLS10", StringComparison.OrdinalIgnoreCase) || version.Contains("TLS1.0", StringComparison.OrdinalIgnoreCase))
                return "TLS 1.0";
            if (version.Contains("TLS11", StringComparison.OrdinalIgnoreCase) || version.Contains("TLS1.1", StringComparison.OrdinalIgnoreCase))
                return "TLS 1.1";
            if (version.Contains("TLS12", StringComparison.OrdinalIgnoreCase) || version.Contains("TLS1.2", StringComparison.OrdinalIgnoreCase))
                return "TLS 1.2";
            if (version.Contains("TLS13", StringComparison.OrdinalIgnoreCase) || version.Contains("TLS1.3", StringComparison.OrdinalIgnoreCase))
                return "TLS 1.3";

            return version;
        }

        private string MapSMBDialect(string dialect)
        {
            if (dialect.Contains("NT LM", StringComparison.OrdinalIgnoreCase) || dialect.Contains("LANMAN", StringComparison.OrdinalIgnoreCase))
                return "SMB1";
            if (dialect.Contains("2.002", StringComparison.OrdinalIgnoreCase) || dialect.Contains("2.0", StringComparison.OrdinalIgnoreCase))
                return "SMB2";
            if (dialect.Contains("2.1", StringComparison.OrdinalIgnoreCase))
                return "SMB2.1";
            if (dialect.Contains("3.0", StringComparison.OrdinalIgnoreCase))
                return "SMB3.0";
            if (dialect.Contains("3.02", StringComparison.OrdinalIgnoreCase))
                return "SMB3.0.2";
            if (dialect.Contains("3.1.1", StringComparison.OrdinalIgnoreCase))
                return "SMB3.1.1";

            return "SMB1"; // Default to SMB1 for unknown
        }

        private void EvaluateVersionSecurity(VersionDetectionResult result, ProtocolVersionProfile profile, string detectedVersion)
        {
            // Find the version in the profile
            var versionInfo = profile.SupportedVersions.Values
                .FirstOrDefault(v => v.Version == detectedVersion || 
                                    $"{v.Protocol} {v.Version}" == detectedVersion ||
                                    $"{v.Protocol}-{v.Version}" == detectedVersion);

            if (versionInfo is not null)
            {
                result.SecurityRisk = versionInfo.RiskLevel;
                result.SecurityAssessment = versionInfo.SecurityNotes;
                result.Vulnerabilities = versionInfo.KnownVulnerabilities.ToList();
                result.Recommendation = $"Upgrade to {versionInfo.RecommendedVersion}";
                
                // Special handling for encrypted but insecure protocols
                if (versionInfo.IsEncrypted && !versionInfo.IsSecure)
                {
                    result.SecurityAssessment = $"WARNING: {detectedVersion} is encrypted but has known security vulnerabilities. " + 
                                               versionInfo.SecurityNotes;
                }
            }
            else
            {
                // Unknown version, flag for review
                result.SecurityRisk = ThreatSeverity.Medium;
                result.SecurityAssessment = $"Unknown version '{detectedVersion}' detected for {profile.ServiceName}";
                result.Recommendation = $"Verify this version meets security requirements. Minimum recommended: {profile.MinimumSecureVersion}";
            }
        }

        public List<VersionDetectionResult> DetectVersions(IEnumerable<PacketInfo> packets)
        {
            var results = new List<VersionDetectionResult>();
            var processedStreams = new HashSet<string>();

            foreach (var packet in packets)
            {
                // Create a unique stream identifier
                var streamId = $"{packet.SourceIP}:{packet.SourcePort}-{packet.DestinationIP}:{packet.DestinationPort}";
                
                // Skip if we've already processed this stream
                if (processedStreams.Contains(streamId))
                    continue;

                var result = DetectVersion(packet);
                if (result.VersionIdentified || result.SecurityRisk > ThreatSeverity.Info)
                {
                    results.Add(result);
                    processedStreams.Add(streamId);
                }
            }

            return results;
        }

        public ProtocolVersionProfile? GetVersionProfile(int port, string protocol)
        {
            return _versionProfiles.ContainsKey(port) ? _versionProfiles[port] : null;
        }

        public Dictionary<string, List<VersionDetectionResult>> GroupVersionsByService(List<VersionDetectionResult> results)
        {
            return results
                .GroupBy(r => r.Protocol)
                .ToDictionary(g => g.Key, g => g.ToList());
        }
    }
}