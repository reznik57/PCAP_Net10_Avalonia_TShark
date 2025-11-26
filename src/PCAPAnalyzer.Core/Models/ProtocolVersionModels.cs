using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Models
{
    public class ProtocolVersion
    {
        public string Protocol { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public bool IsEncrypted { get; set; }
        public bool IsSecure { get; set; }
        public ThreatSeverity RiskLevel { get; set; }
        public DateTime? DeprecatedDate { get; set; }
        public string[] KnownVulnerabilities { get; set; } = Array.Empty<string>();
        public string RecommendedVersion { get; set; } = string.Empty;
        public string SecurityNotes { get; set; } = string.Empty;
    }

    public class ProtocolVersionProfile
    {
        public int Port { get; set; }
        public string Protocol { get; set; } = string.Empty;
        public string ServiceName { get; set; } = string.Empty;
        public Dictionary<string, ProtocolVersion> SupportedVersions { get; set; } = new();
        public string MinimumSecureVersion { get; set; } = string.Empty;
        public bool RequiresVersionCheck { get; set; }
    }

    public class VersionDetectionResult
    {
        public string Protocol { get; set; } = string.Empty;
        public string DetectedVersion { get; set; } = string.Empty;
        public bool VersionIdentified { get; set; }
        public ThreatSeverity SecurityRisk { get; set; }
        public string SecurityAssessment { get; set; } = string.Empty;
        public List<string> Vulnerabilities { get; set; } = new();
        public string Recommendation { get; set; } = string.Empty;
    }

    public static class ProtocolVersionDatabase
    {
        public static readonly Dictionary<string, Dictionary<string, ProtocolVersion>> Protocols = new()
        {
            ["SSL/TLS"] = new Dictionary<string, ProtocolVersion>
            {
                ["SSL 2.0"] = new ProtocolVersion
                {
                    Protocol = "SSL",
                    Version = "2.0",
                    IsEncrypted = true,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.Critical,
                    DeprecatedDate = new DateTime(2011, 3, 1),
                    KnownVulnerabilities = new[] 
                    { 
                        "CVE-2016-0703 (DROWN attack)",
                        "CVE-2014-3566 (POODLE)",
                        "Weak 40-bit and 56-bit encryption",
                        "No protection against man-in-the-middle attacks",
                        "Vulnerable to cipher downgrade attacks"
                    },
                    RecommendedVersion = "TLS 1.3",
                    SecurityNotes = "SSL 2.0 has been deprecated since 2011. CRITICAL: Contains fundamental security flaws."
                },
                ["SSL 3.0"] = new ProtocolVersion
                {
                    Protocol = "SSL",
                    Version = "3.0",
                    IsEncrypted = true,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.Critical,
                    DeprecatedDate = new DateTime(2015, 6, 1),
                    KnownVulnerabilities = new[] 
                    { 
                        "CVE-2014-3566 (POODLE attack)",
                        "CVE-2014-8730 (Padding oracle)",
                        "Vulnerable to BEAST attack",
                        "Weak CBC mode ciphers"
                    },
                    RecommendedVersion = "TLS 1.3",
                    SecurityNotes = "SSL 3.0 deprecated by RFC 7568. Contains multiple critical vulnerabilities."
                },
                ["TLS 1.0"] = new ProtocolVersion
                {
                    Protocol = "TLS",
                    Version = "1.0",
                    IsEncrypted = true,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.High,
                    DeprecatedDate = new DateTime(2020, 3, 1),
                    KnownVulnerabilities = new[] 
                    { 
                        "CVE-2011-3389 (BEAST attack)",
                        "CVE-2014-3566 (POODLE variant)",
                        "Vulnerable to Lucky 13 attack",
                        "Weak cipher support",
                        "No support for modern cryptography"
                    },
                    RecommendedVersion = "TLS 1.3",
                    SecurityNotes = "TLS 1.0 deprecated by PCI DSS. Major browsers stopped support in 2020."
                },
                ["TLS 1.1"] = new ProtocolVersion
                {
                    Protocol = "TLS",
                    Version = "1.1",
                    IsEncrypted = true,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.High,
                    DeprecatedDate = new DateTime(2020, 3, 1),
                    KnownVulnerabilities = new[] 
                    { 
                        "CVE-2016-2107 (Padding oracle)",
                        "Vulnerable to Lucky 13 attack",
                        "Limited cipher suite options",
                        "No support for AEAD ciphers"
                    },
                    RecommendedVersion = "TLS 1.3",
                    SecurityNotes = "TLS 1.1 deprecated alongside TLS 1.0. Lacks modern security features."
                },
                ["TLS 1.2"] = new ProtocolVersion
                {
                    Protocol = "TLS",
                    Version = "1.2",
                    IsEncrypted = true,
                    IsSecure = true,
                    RiskLevel = ThreatSeverity.Info,
                    KnownVulnerabilities = new[] 
                    { 
                        "Secure when properly configured",
                        "Requires careful cipher suite selection",
                        "Should disable weak ciphers"
                    },
                    RecommendedVersion = "TLS 1.3",
                    SecurityNotes = "TLS 1.2 is acceptable but TLS 1.3 is preferred. Ensure strong cipher suites."
                },
                ["TLS 1.3"] = new ProtocolVersion
                {
                    Protocol = "TLS",
                    Version = "1.3",
                    IsEncrypted = true,
                    IsSecure = true,
                    RiskLevel = ThreatSeverity.Info,
                    KnownVulnerabilities = Array.Empty<string>(),
                    RecommendedVersion = "TLS 1.3",
                    SecurityNotes = "Current recommended version. Removes legacy insecure features."
                }
            },
            ["SSH"] = new Dictionary<string, ProtocolVersion>
            {
                ["SSH-1.0"] = new ProtocolVersion
                {
                    Protocol = "SSH",
                    Version = "1.0",
                    IsEncrypted = true,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.Critical,
                    DeprecatedDate = new DateTime(2001, 1, 1),
                    KnownVulnerabilities = new[] 
                    { 
                        "CVE-2001-0144 (Integer overflow)",
                        "CVE-2001-0572 (Authentication bypass)",
                        "Weak encryption algorithms",
                        "Vulnerable to insertion attacks",
                        "No integrity checking"
                    },
                    RecommendedVersion = "SSH-2.0",
                    SecurityNotes = "SSH-1 has fundamental security flaws and must not be used."
                },
                ["SSH-1.5"] = new ProtocolVersion
                {
                    Protocol = "SSH",
                    Version = "1.5",
                    IsEncrypted = true,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.Critical,
                    DeprecatedDate = new DateTime(2001, 1, 1),
                    KnownVulnerabilities = new[] 
                    { 
                        "Same vulnerabilities as SSH-1.0",
                        "CRC-32 compensation attack",
                        "Weak session key exchange"
                    },
                    RecommendedVersion = "SSH-2.0",
                    SecurityNotes = "SSH-1.5 inherits all SSH-1 vulnerabilities. Migrate to SSH-2 immediately."
                },
                ["SSH-2.0"] = new ProtocolVersion
                {
                    Protocol = "SSH",
                    Version = "2.0",
                    IsEncrypted = true,
                    IsSecure = true,
                    RiskLevel = ThreatSeverity.Info,
                    KnownVulnerabilities = new[] 
                    { 
                        "Secure when properly configured",
                        "Disable weak ciphers and key exchange algorithms",
                        "Use strong key sizes (RSA 2048+ or Ed25519)"
                    },
                    RecommendedVersion = "SSH-2.0",
                    SecurityNotes = "SSH-2 is secure. Ensure strong cipher configuration and key management."
                }
            },
            ["SMB"] = new Dictionary<string, ProtocolVersion>
            {
                ["SMB1"] = new ProtocolVersion
                {
                    Protocol = "SMB",
                    Version = "1.0",
                    IsEncrypted = false,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.Critical,
                    DeprecatedDate = new DateTime(2017, 1, 1),
                    KnownVulnerabilities = new[] 
                    { 
                        "CVE-2017-0144 (EternalBlue/WannaCry)",
                        "CVE-2017-0145 (Remote code execution)",
                        "No encryption support",
                        "Vulnerable to relay attacks",
                        "No message signing by default"
                    },
                    RecommendedVersion = "SMB3.1.1",
                    SecurityNotes = "SMBv1 is extremely dangerous. Disabled by default in Windows 10. MUST be disabled."
                },
                ["SMB2"] = new ProtocolVersion
                {
                    Protocol = "SMB",
                    Version = "2.0",
                    IsEncrypted = false,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.Medium,
                    KnownVulnerabilities = new[] 
                    { 
                        "No encryption in SMB 2.0",
                        "Vulnerable to downgrade attacks",
                        "Limited security features"
                    },
                    RecommendedVersion = "SMB3.1.1",
                    SecurityNotes = "SMB 2.0 lacks encryption. Upgrade to SMB 3.0+ for security features."
                },
                ["SMB2.1"] = new ProtocolVersion
                {
                    Protocol = "SMB",
                    Version = "2.1",
                    IsEncrypted = false,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.Medium,
                    KnownVulnerabilities = new[] 
                    { 
                        "No encryption support",
                        "Improved over SMB2.0 but still lacks security features"
                    },
                    RecommendedVersion = "SMB3.1.1",
                    SecurityNotes = "SMB 2.1 improved performance but still lacks encryption."
                },
                ["SMB3.0"] = new ProtocolVersion
                {
                    Protocol = "SMB",
                    Version = "3.0",
                    IsEncrypted = true,
                    IsSecure = true,
                    RiskLevel = ThreatSeverity.Low,
                    KnownVulnerabilities = new[] 
                    { 
                        "Encryption optional (must be enabled)",
                        "CVE-2020-0796 (SMBGhost) - patched"
                    },
                    RecommendedVersion = "SMB3.1.1",
                    SecurityNotes = "SMB 3.0 supports encryption but must be enabled. Good security when configured."
                },
                ["SMB3.1.1"] = new ProtocolVersion
                {
                    Protocol = "SMB",
                    Version = "3.1.1",
                    IsEncrypted = true,
                    IsSecure = true,
                    RiskLevel = ThreatSeverity.Info,
                    KnownVulnerabilities = Array.Empty<string>(),
                    RecommendedVersion = "SMB3.1.1",
                    SecurityNotes = "Latest SMB version with pre-authentication integrity and AES-128-GCM encryption."
                }
            },
            ["HTTP"] = new Dictionary<string, ProtocolVersion>
            {
                ["HTTP/1.0"] = new ProtocolVersion
                {
                    Protocol = "HTTP",
                    Version = "1.0",
                    IsEncrypted = false,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.High,
                    KnownVulnerabilities = new[] 
                    { 
                        "No encryption",
                        "No persistent connections",
                        "Limited security headers"
                    },
                    RecommendedVersion = "HTTPS with HTTP/2",
                    SecurityNotes = "HTTP/1.0 is obsolete and insecure. Use HTTPS immediately."
                },
                ["HTTP/1.1"] = new ProtocolVersion
                {
                    Protocol = "HTTP",
                    Version = "1.1",
                    IsEncrypted = false,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.Medium,
                    KnownVulnerabilities = new[] 
                    { 
                        "No encryption",
                        "Vulnerable to session hijacking",
                        "No integrity protection"
                    },
                    RecommendedVersion = "HTTPS with HTTP/2",
                    SecurityNotes = "HTTP/1.1 without TLS is insecure. Must use HTTPS for any sensitive data."
                },
                ["HTTP/2"] = new ProtocolVersion
                {
                    Protocol = "HTTP",
                    Version = "2.0",
                    IsEncrypted = false,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.Medium,
                    KnownVulnerabilities = new[] 
                    { 
                        "Requires TLS for security",
                        "Most browsers require HTTPS for HTTP/2"
                    },
                    RecommendedVersion = "HTTPS with HTTP/2",
                    SecurityNotes = "HTTP/2 typically requires TLS. Ensure HTTPS is used."
                },
                ["HTTP/3"] = new ProtocolVersion
                {
                    Protocol = "HTTP",
                    Version = "3.0",
                    IsEncrypted = true,
                    IsSecure = true,
                    RiskLevel = ThreatSeverity.Info,
                    KnownVulnerabilities = Array.Empty<string>(),
                    RecommendedVersion = "HTTP/3",
                    SecurityNotes = "HTTP/3 uses QUIC with mandatory TLS 1.3. Secure by design."
                }
            },
            ["RDP"] = new Dictionary<string, ProtocolVersion>
            {
                ["RDP 4.0"] = new ProtocolVersion
                {
                    Protocol = "RDP",
                    Version = "4.0",
                    IsEncrypted = false,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.Critical,
                    KnownVulnerabilities = new[] 
                    { 
                        "No encryption",
                        "No network level authentication"
                    },
                    RecommendedVersion = "RDP 10.0+",
                    SecurityNotes = "Ancient RDP version with no security features."
                },
                ["RDP 5.x"] = new ProtocolVersion
                {
                    Protocol = "RDP",
                    Version = "5.x",
                    IsEncrypted = true,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.High,
                    KnownVulnerabilities = new[] 
                    { 
                        "Weak encryption (RC4)",
                        "No NLA support"
                    },
                    RecommendedVersion = "RDP 10.0+",
                    SecurityNotes = "RDP 5.x has weak encryption. Upgrade required."
                },
                ["RDP 6.x"] = new ProtocolVersion
                {
                    Protocol = "RDP",
                    Version = "6.x",
                    IsEncrypted = true,
                    IsSecure = false,
                    RiskLevel = ThreatSeverity.High,
                    KnownVulnerabilities = new[] 
                    { 
                        "CVE-2019-0708 (BlueKeep)",
                        "Requires NLA to be secure"
                    },
                    RecommendedVersion = "RDP 10.0+",
                    SecurityNotes = "Vulnerable to BlueKeep. Must enable NLA and patch."
                },
                ["RDP 10.x"] = new ProtocolVersion
                {
                    Protocol = "RDP",
                    Version = "10.x",
                    IsEncrypted = true,
                    IsSecure = true,
                    RiskLevel = ThreatSeverity.Low,
                    KnownVulnerabilities = new[] 
                    { 
                        "Secure with NLA enabled",
                        "Use strong passwords and MFA"
                    },
                    RecommendedVersion = "RDP 10.x",
                    SecurityNotes = "Latest RDP with proper configuration is secure."
                }
            }
        };
    }
}