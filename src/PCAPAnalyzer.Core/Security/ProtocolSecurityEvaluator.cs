using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace PCAPAnalyzer.Core.Security;

/// <summary>
/// Evaluates protocol security based on protocol name, version, and known vulnerabilities
/// </summary>
public static partial class ProtocolSecurityEvaluator
{
    public enum SecurityLevel
    {
        Secure,      // Green - Modern secure protocols
        Low,         // Light Yellow - Minor concerns
        Medium,      // Orange - Notable security issues
        High,        // Red - Serious security issues
        Critical,    // Dark Red - Critical vulnerabilities
        Unknown      // Gray - Cannot determine
    }

    [SuppressMessage("Design", "CA1034:Nested types should not be visible",
        Justification = "SecurityAssessment is a public data structure returned by ProtocolSecurityEvaluator methods")]
    public class SecurityAssessment
    {
        public SecurityLevel Level { get; set; }
        public string Reason { get; set; } = "";
        public List<string> Vulnerabilities { get; set; } = [];
        public string Recommendation { get; set; } = "";
    }

    public static SecurityAssessment EvaluateProtocol(string? protocolName, ushort? port = null)
    {
        if (string.IsNullOrWhiteSpace(protocolName))
            return new SecurityAssessment { Level = SecurityLevel.Unknown, Reason = "No protocol information" };

        var protocol = protocolName.ToUpperInvariant();
        
        // Check for secure protocols first
        var secureAssessment = CheckSecureProtocols(protocol, port);
        if (secureAssessment is not null) return secureAssessment;

        // Check for critically insecure protocols
        var criticalAssessment = CheckCriticalProtocols(protocol, port);
        if (criticalAssessment is not null) return criticalAssessment;

        // Check for high-risk protocols
        var highRiskAssessment = CheckHighRiskProtocols(protocol, port);
        if (highRiskAssessment is not null) return highRiskAssessment;

        // Check for medium-risk protocols
        var mediumRiskAssessment = CheckMediumRiskProtocols(protocol, port);
        if (mediumRiskAssessment is not null) return mediumRiskAssessment;

        // Check for low-risk protocols
        var lowRiskAssessment = CheckLowRiskProtocols(protocol, port);
        if (lowRiskAssessment is not null) return lowRiskAssessment;

        // Default assessment based on common patterns
        return GetDefaultAssessment(protocol, port);
    }

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Secure protocol detection requires comprehensive checking of TLS versions, SSH versions, VPN protocols, secure email protocols, and encrypted database connections")]
    private static SecurityAssessment? CheckSecureProtocols(string protocol, ushort? port)
    {
        // Match exact Wireshark protocol names
        // TLS 1.2 and 1.3
        if (protocol == "TLSV1.2" || protocol.Contains("TLSV1.2", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "TLS 1.2 with modern cipher suites",
                Recommendation = "Continue using TLS 1.2 or upgrade to TLS 1.3"
            };
        }

        if (protocol == "TLSV1.3" || protocol.Contains("TLSV1.3", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "TLS 1.3 - Latest secure protocol",
                Recommendation = "Best practice - continue using TLS 1.3"
            };
        }

        // Note: "SSL" without version in Wireshark could be any SSL version
        // We'll classify it as Medium risk since we don't know the exact version
        if (protocol == "SSL")
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "SSL - Version unknown, may be insecure",
                Recommendation = "Verify SSL version, upgrade to TLS 1.2+ if possible"
            };
        }

        // SSH versions
        if (protocol.Contains("SSHV2", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SSH2", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SSH-2", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "SSH v2 - Secure remote access",
                Recommendation = "Ensure strong key exchange algorithms are used"
            };
        }

        // Modern VPN protocols
        if (protocol.Contains("WIREGUARD", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "WireGuard - Modern secure VPN",
                Recommendation = "Excellent choice for VPN"
            };
        }

        if (protocol.Contains("IKEV2", StringComparison.OrdinalIgnoreCase) || protocol.Contains("IPSEC-IKEV2", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "IKEv2/IPSec - Secure VPN protocol",
                Recommendation = "Good VPN choice with proper configuration"
            };
        }

        if (protocol.Contains("OPENVPN", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "OpenVPN - Secure when properly configured",
                Recommendation = "Ensure AES-256 encryption is used"
            };
        }

        // Secure email protocols
        if (protocol.Contains("IMAPS", StringComparison.OrdinalIgnoreCase) || (protocol.Contains("IMAP", StringComparison.OrdinalIgnoreCase) && port == 993))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "IMAP over TLS - Secure email access",
                Recommendation = "Good practice for email security"
            };
        }

        if (protocol.Contains("POP3S", StringComparison.OrdinalIgnoreCase) || (protocol.Contains("POP3", StringComparison.OrdinalIgnoreCase) && port == 995))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "POP3 over TLS - Secure email retrieval",
                Recommendation = "Consider IMAPS for better functionality"
            };
        }

        if (protocol.Contains("SMTPS", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SUBMISSION", StringComparison.OrdinalIgnoreCase) || port == 587 || port == 465)
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "SMTP with TLS - Secure email transmission",
                Recommendation = "Ensure STARTTLS or implicit TLS is used"
            };
        }

        // Secure file transfer
        if (protocol.Contains("SFTP", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SSH-FTP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "SFTP - Secure file transfer over SSH",
                Recommendation = "Best practice for file transfer"
            };
        }

        if (protocol.Contains("FTPS", StringComparison.OrdinalIgnoreCase) || protocol.Contains("FTP-TLS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "FTP over TLS - Encrypted file transfer",
                Recommendation = "Consider SFTP for better security"
            };
        }

        // Secure web protocols
        if (protocol.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) || protocol.Contains("HTTP/2", StringComparison.OrdinalIgnoreCase) || protocol.Contains("HTTP2", StringComparison.OrdinalIgnoreCase) ||
            protocol.Contains("HTTP/3", StringComparison.OrdinalIgnoreCase) || protocol.Contains("HTTP3", StringComparison.OrdinalIgnoreCase) || protocol.Contains("QUIC", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "HTTPS/HTTP2/HTTP3 - Encrypted web traffic",
                Recommendation = "Ensure strong TLS configuration"
            };
        }

        // Secure authentication
        if (protocol.Contains("LDAPS", StringComparison.OrdinalIgnoreCase) || (protocol.Contains("LDAP", StringComparison.OrdinalIgnoreCase) && port == 636))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "LDAP over TLS - Secure directory access",
                Recommendation = "Good practice for LDAP security"
            };
        }

        if (protocol.Contains("KERBEROS", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("V4", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "Kerberos v5 - Secure authentication",
                Recommendation = "Ensure proper ticket lifetime configuration"
            };
        }

        // Secure database protocols
        if (protocol.Contains("MYSQL", StringComparison.OrdinalIgnoreCase) && protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "MySQL with TLS encryption",
                Recommendation = "Good practice for database security"
            };
        }

        if (protocol.Contains("POSTGRESQL", StringComparison.OrdinalIgnoreCase) && protocol.Contains("SSL", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "PostgreSQL with SSL/TLS",
                Recommendation = "Ensure certificate validation is enabled"
            };
        }

        // Secure VoIP
        if (protocol.Contains("SIPS", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SIP-TLS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "SIP over TLS - Secure VoIP signaling",
                Recommendation = "Also use SRTP for media encryption"
            };
        }

        if (protocol.Contains("SRTP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "SRTP - Encrypted VoIP media",
                Recommendation = "Good practice for VoIP security"
            };
        }

        // Modern secure protocols
        if (protocol.Contains("DTLS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "DTLS - Datagram TLS for UDP traffic",
                Recommendation = "Good for securing UDP-based protocols"
            };
        }

        if (protocol.Contains("SNMPV3", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SNMP3", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "SNMPv3 with authentication and encryption",
                Recommendation = "Ensure authPriv security level is used"
            };
        }

        return null;
    }

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Critical protocol assessment requires checking multiple legacy and broken protocols including SSL v2/v3, Telnet, SMBv1, PPTP, SSHv1, WEP, Kerberos v4, and LM/NTLMv1")]
    private static SecurityAssessment? CheckCriticalProtocols(string protocol, ushort? port)
    {
        // SSL v2 and v3 - Completely broken
        if (protocol.Contains("SSLV2", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SSL2", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SSL_2", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Critical,
                Reason = "SSLv2 - Critically insecure, deprecated since 2011",
                Vulnerabilities = new List<string> { "DROWN attack", "Weak ciphers", "No protection against MITM" },
                Recommendation = "IMMEDIATELY upgrade to TLS 1.2 or higher"
            };
        }

        if (protocol.Contains("SSLV3", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SSL3", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SSL_3", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Critical,
                Reason = "SSLv3 - Critically insecure, deprecated since 2015",
                Vulnerabilities = new List<string> { "POODLE attack", "BEAST attack", "Weak ciphers" },
                Recommendation = "IMMEDIATELY upgrade to TLS 1.2 or higher"
            };
        }

        // Telnet - No encryption
        if (protocol.Contains("TELNET", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Critical,
                Reason = "Telnet - Transmits everything in plaintext including passwords",
                Vulnerabilities = new List<string> { "No encryption", "Credential theft", "Session hijacking" },
                Recommendation = "Replace with SSH immediately"
            };
        }

        // rlogin/rsh/rexec - Ancient insecure protocols
        if (protocol.Contains("RLOGIN", StringComparison.OrdinalIgnoreCase) || protocol.Contains("RSH", StringComparison.OrdinalIgnoreCase) || protocol.Contains("REXEC", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Critical,
                Reason = "R-commands - Ancient protocols with no security",
                Vulnerabilities = new List<string> { "No encryption", "IP-based authentication", "Spoofing attacks" },
                Recommendation = "Replace with SSH immediately"
            };
        }

        // SMBv1 - EternalBlue and other critical vulnerabilities
        if (protocol.Contains("SMBV1", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SMB1", StringComparison.OrdinalIgnoreCase) || protocol.Contains("CIFS", StringComparison.OrdinalIgnoreCase) ||
            (protocol == "SMB" && !protocol.Contains("SMB2", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("SMB3", StringComparison.OrdinalIgnoreCase)))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Critical,
                Reason = "SMBv1 - Multiple critical vulnerabilities",
                Vulnerabilities = new List<string> { "EternalBlue (MS17-010)", "WannaCry ransomware vector", "No encryption" },
                Recommendation = "Disable SMBv1 immediately, use SMBv3"
            };
        }

        // PPTP - Broken encryption
        if (protocol.Contains("PPTP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Critical,
                Reason = "PPTP - Broken encryption, easily crackable",
                Vulnerabilities = new List<string> { "MS-CHAPv2 is broken", "Can be cracked in hours", "No forward secrecy" },
                Recommendation = "Replace with OpenVPN, WireGuard, or IKEv2"
            };
        }

        // SSHv1 - Deprecated and insecure
        if (protocol.Contains("SSHV1", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SSH1", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SSH-1", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Critical,
                Reason = "SSH v1 - Deprecated protocol with known vulnerabilities",
                Vulnerabilities = new List<string> { "CRC-32 vulnerability", "Session key recovery", "MITM attacks" },
                Recommendation = "Upgrade to SSH v2 immediately"
            };
        }

        // WEP - Broken WiFi encryption
        if (protocol.Contains("WEP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Critical,
                Reason = "WEP - Broken WiFi encryption",
                Vulnerabilities = new List<string> { "Can be cracked in minutes", "IV collision attacks", "No integrity protection" },
                Recommendation = "Use WPA3 or at least WPA2"
            };
        }

        // Kerberos v4 - Obsolete
        if (protocol.Contains("KERBEROSV4", StringComparison.OrdinalIgnoreCase) || protocol.Contains("KERBEROS4", StringComparison.OrdinalIgnoreCase) || protocol.Contains("KRB4", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Critical,
                Reason = "Kerberos v4 - Obsolete with critical flaws",
                Vulnerabilities = new List<string> { "DES encryption only", "Replay attacks", "No mutual authentication" },
                Recommendation = "Upgrade to Kerberos v5"
            };
        }

        // LM/NTLM v1 - Broken Windows authentication
        if (protocol.Contains("LMHASH", StringComparison.OrdinalIgnoreCase) || protocol.Contains("NTLMV1", StringComparison.OrdinalIgnoreCase) || protocol.Contains("LANMAN", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Critical,
                Reason = "LM/NTLMv1 - Broken authentication protocols",
                Vulnerabilities = new List<string> { "Rainbow table attacks", "Pass-the-hash", "No salt" },
                Recommendation = "Use Kerberos or NTLMv2 minimum"
            };
        }

        return null;
    }

    // NOTE: CheckHighRiskProtocols moved to ProtocolSecurityEvaluator.HighRisk.cs

    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "Medium-risk protocol assessment requires checking TLS 1.1, SMBv2, NFS v2/v3, RDP without NLA, IKEv1, unencrypted SIP/RTP, DNS, DHCP, NetBIOS, LLMNR, mDNS, SSDP/UPnP, RADIUS, NTLMv2, X11, and Syslog")]
    private static SecurityAssessment? CheckMediumRiskProtocols(string protocol, ushort? port)
    {
        // TLS 1.1 - Deprecated but not critically broken
        if (protocol.Contains("TLSV1.1", StringComparison.OrdinalIgnoreCase) || protocol.Contains("TLS1.1", StringComparison.OrdinalIgnoreCase) || protocol.Contains("TLS_1.1", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "TLS 1.1 - Deprecated, should be upgraded",
                Vulnerabilities = new List<string> { "Weak ciphers", "CBC vulnerabilities" },
                Recommendation = "Upgrade to TLS 1.2 or 1.3"
            };
        }

        // SMBv2 - Better than v1 but not ideal
        if (protocol.Contains("SMBV2", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SMB2", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "SMBv2 - Lacks encryption by default",
                Vulnerabilities = new List<string> { "No encryption by default", "Downgrade attacks" },
                Recommendation = "Upgrade to SMBv3 with encryption"
            };
        }

        // NFS v2/v3
        if (protocol.Contains("NFSV2", StringComparison.OrdinalIgnoreCase) || protocol.Contains("NFSV3", StringComparison.OrdinalIgnoreCase) || protocol.Contains("NFS2", StringComparison.OrdinalIgnoreCase) || protocol.Contains("NFS3", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "NFS v2/v3 - Weak authentication",
                Vulnerabilities = new List<string> { "AUTH_SYS is weak", "No encryption", "UID spoofing" },
                Recommendation = "Upgrade to NFSv4 with Kerberos"
            };
        }

        // RDP without NLA
        if (protocol.Contains("RDP", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("RDPS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "RDP - Check Network Level Authentication",
                Vulnerabilities = new List<string> { "BlueKeep (if old)", "Credential exposure", "Brute force" },
                Recommendation = "Enable NLA and use RD Gateway"
            };
        }

        // IKEv1
        if (protocol.Contains("IKEV1", StringComparison.OrdinalIgnoreCase) || protocol.Contains("ISAKMP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "IKEv1 - Older VPN protocol",
                Vulnerabilities = new List<string> { "Aggressive mode issues", "Weaker than IKEv2" },
                Recommendation = "Upgrade to IKEv2"
            };
        }

        // SIP without encryption
        if (protocol == "SIP" || (protocol.Contains("SIP", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("SIPS", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase)))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "SIP - Unencrypted VoIP signaling",
                Vulnerabilities = new List<string> { "Call interception", "Caller ID spoofing", "Registration hijacking" },
                Recommendation = "Use SIP over TLS (SIPS)"
            };
        }

        // RTP without SRTP
        if (protocol == "RTP" || (protocol.Contains("RTP", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("SRTP", StringComparison.OrdinalIgnoreCase)))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "RTP - Unencrypted media streams",
                Vulnerabilities = new List<string> { "Eavesdropping", "Media injection" },
                Recommendation = "Use SRTP for media encryption"
            };
        }

        // DNS - Can be used for attacks
        if (protocol == "DNS" || protocol.Contains("DNS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "DNS - Unencrypted queries",
                Vulnerabilities = new List<string> { "DNS spoofing", "Cache poisoning", "Privacy concerns" },
                Recommendation = "Use DoT (DNS over TLS) or DoH (DNS over HTTPS)"
            };
        }

        // DHCP - Can be spoofed
        if (protocol.Contains("DHCP", StringComparison.OrdinalIgnoreCase) || protocol.Contains("BOOTP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "DHCP - No authentication",
                Vulnerabilities = new List<string> { "Rogue DHCP server", "IP exhaustion", "DNS hijacking" },
                Recommendation = "Use DHCP snooping and port security"
            };
        }

        // NetBIOS
        if (protocol.Contains("NETBIOS", StringComparison.OrdinalIgnoreCase) || protocol.Contains("NBT", StringComparison.OrdinalIgnoreCase) || protocol.Contains("NBNS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "NetBIOS - Legacy protocol",
                Vulnerabilities = new List<string> { "Information disclosure", "Name spoofing", "Session hijacking" },
                Recommendation = "Disable NetBIOS over TCP/IP if not needed"
            };
        }

        // LLMNR - Subject to spoofing
        if (protocol.Contains("LLMNR", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "LLMNR - Subject to spoofing attacks",
                Vulnerabilities = new List<string> { "Responder attacks", "Credential harvesting" },
                Recommendation = "Disable LLMNR if not required"
            };
        }

        // mDNS
        if (protocol.Contains("MDNS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "mDNS - Multicast DNS without authentication",
                Vulnerabilities = new List<string> { "Spoofing", "Information disclosure" },
                Recommendation = "Limit to trusted networks only"
            };
        }

        // SSDP/UPnP
        if (protocol.Contains("SSDP", StringComparison.OrdinalIgnoreCase) || protocol.Contains("UPNP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "SSDP/UPnP - Security risks",
                Vulnerabilities = new List<string> { "Port forwarding risks", "DDoS amplification", "Information disclosure" },
                Recommendation = "Disable UPnP on internet-facing devices"
            };
        }

        // RADIUS without TLS
        if (protocol.Contains("RADIUS", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("DTLS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "RADIUS - Weak encryption",
                Vulnerabilities = new List<string> { "MD5 hashing", "Dictionary attacks", "Shared secret issues" },
                Recommendation = "Use RADIUS over TLS (RadSec)"
            };
        }

        // NTLMv2
        if (protocol.Contains("NTLMV2", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "NTLMv2 - Better than v1 but still has issues",
                Vulnerabilities = new List<string> { "Pass-the-hash", "Relay attacks" },
                Recommendation = "Use Kerberos when possible"
            };
        }

        // X11 forwarding
        if (protocol.Contains("X11", StringComparison.OrdinalIgnoreCase) || protocol.Contains("XDMCP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "X11 - Unencrypted display protocol",
                Vulnerabilities = new List<string> { "Keystroke logging", "Screen capture", "No encryption" },
                Recommendation = "Use X11 over SSH tunnel"
            };
        }

        // Syslog
        if (protocol.Contains("SYSLOG", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Medium,
                Reason = "Syslog - Usually unencrypted",
                Vulnerabilities = new List<string> { "Log tampering", "Information disclosure", "No integrity" },
                Recommendation = "Use Syslog over TLS"
            };
        }

        return null;
    }

    private static SecurityAssessment? CheckLowRiskProtocols(string protocol, ushort? port)
    {
        // ICMP - Information gathering but not directly exploitable
        if (protocol.Contains("ICMP", StringComparison.OrdinalIgnoreCase) || protocol.Contains("ICMPV6", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Low,
                Reason = "ICMP - Can be used for reconnaissance",
                Vulnerabilities = new List<string> { "Network mapping", "Smurf attacks (historical)" },
                Recommendation = "Filter ICMP at network edge"
            };
        }

        // ARP - Local network only
        if (protocol.Contains("ARP", StringComparison.OrdinalIgnoreCase) || protocol.Contains("RARP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Low,
                Reason = "ARP - Local network protocol",
                Vulnerabilities = new List<string> { "ARP spoofing", "MITM on local network" },
                Recommendation = "Use static ARP entries for critical systems"
            };
        }

        // CDP/LLDP - Information disclosure
        if (protocol.Contains("CDP", StringComparison.OrdinalIgnoreCase) || protocol.Contains("LLDP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Low,
                Reason = "CDP/LLDP - Device discovery protocols",
                Vulnerabilities = new List<string> { "Information disclosure", "Network mapping" },
                Recommendation = "Disable on untrusted interfaces"
            };
        }

        // VRRP/HSRP - Redundancy protocols
        if (protocol.Contains("VRRP", StringComparison.OrdinalIgnoreCase) || protocol.Contains("HSRP", StringComparison.OrdinalIgnoreCase) || protocol.Contains("GLBP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Low,
                Reason = "VRRP/HSRP - Redundancy protocols",
                Vulnerabilities = new List<string> { "Authentication weakness", "Priority manipulation" },
                Recommendation = "Use MD5 authentication"
            };
        }

        // STP - Spanning Tree
        if (protocol.Contains("STP", StringComparison.OrdinalIgnoreCase) || protocol.Contains("RSTP", StringComparison.OrdinalIgnoreCase) || protocol.Contains("MSTP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Low,
                Reason = "STP - Layer 2 loop prevention",
                Vulnerabilities = new List<string> { "Root bridge attacks", "BPDU spoofing" },
                Recommendation = "Enable BPDU guard and root guard"
            };
        }

        // NTP without authentication
        if (protocol.Contains("NTP", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("SNTP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Low,
                Reason = "NTP - Time synchronization",
                Vulnerabilities = new List<string> { "DDoS amplification", "Time manipulation" },
                Recommendation = "Use NTP authentication (symmetric key or Autokey)"
            };
        }

        return null;
    }

    private static SecurityAssessment GetDefaultAssessment(string protocol, ushort? port)
    {
        // Handle exact Wireshark protocol names
        // TCP and UDP are transport protocols - try port-based lookup
        if (protocol == "TCP" || protocol == "UDP")
        {
            // Try to identify by port number using PortDatabase
            if (port.HasValue && port.Value > 0)
            {
                var isTcp = protocol == "TCP";
                var portInfo = PortDatabase.GetPortInfo(port.Value, isTcp);
                if (portInfo.HasValue)
                {
                    return new SecurityAssessment
                    {
                        Level = PortDatabase.ToSecurityLevel(portInfo.Value.Risk),
                        Reason = $"{portInfo.Value.ServiceName} - {portInfo.Value.Description}",
                        Recommendation = portInfo.Value.Recommendation ?? "Check service configuration"
                    };
                }
            }

            return new SecurityAssessment
            {
                Level = SecurityLevel.Unknown,
                Reason = "Transport protocol - security depends on application layer",
                Recommendation = "Check application protocol for security assessment"
            };
        }

        // ESP (IPSec) is secure
        if (protocol == "ESP")
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Secure,
                Reason = "IPSec ESP - Encrypted payload",
                Recommendation = "Good security practice"
            };
        }

        // SNMP without version info - assume v1/v2c (insecure)
        if (protocol == "SNMP")
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "SNMP - Likely v1/v2c with plaintext community strings",
                Vulnerabilities = new List<string> { "Community strings in plaintext", "No authentication" },
                Recommendation = "Upgrade to SNMPv3 with authPriv"
            };
        }

        // Check for encrypted indicators in protocol name
        if (protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase) || protocol.Contains("ENCRYPTED", StringComparison.OrdinalIgnoreCase) ||
            protocol.Contains("SECURE", StringComparison.OrdinalIgnoreCase) || protocol.Contains("CRYPTO", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.Low,
                Reason = "Appears to use encryption",
                Recommendation = "Verify encryption strength and configuration"
            };
        }

        // We do NOT infer security from ports alone
        // Wireshark identifies the actual protocol, not what we assume from ports
        // A TCP packet on port 443 is just TCP until TLS handshake is detected

        // Final fallback: try port-based lookup for any protocol
        if (port.HasValue && port.Value > 0)
        {
            // Default to TCP for most cases
            var portInfo = PortDatabase.GetPortInfo(port.Value, true);
            if (portInfo.HasValue)
            {
                return new SecurityAssessment
                {
                    Level = PortDatabase.ToSecurityLevel(portInfo.Value.Risk),
                    Reason = $"{portInfo.Value.ServiceName} (port {port.Value}) - {portInfo.Value.Description}",
                    Recommendation = portInfo.Value.Recommendation ?? "Check service configuration"
                };
            }
        }

        // Unknown protocol
        return new SecurityAssessment
        {
            Level = SecurityLevel.Unknown,
            Reason = "Unknown protocol security status",
            Recommendation = "Research protocol security characteristics"
        };
    }

    public static string GetSecurityLevelString(SecurityLevel level)
    {
        return level switch
        {
            SecurityLevel.Secure => "Secure",
            SecurityLevel.Low => "Low",
            SecurityLevel.Medium => "Medium",
            SecurityLevel.High => "High",
            SecurityLevel.Critical => "Critical",
            _ => "Unknown"
        };
    }

    public static string GetSecurityLevelColor(SecurityLevel level)
    {
        return level switch
        {
            SecurityLevel.Secure => "#4CAF50",   // Green
            SecurityLevel.Low => "#8BC34A",      // Light Green
            SecurityLevel.Medium => "#FFA726",   // Orange
            SecurityLevel.High => "#EF5350",     // Red
            SecurityLevel.Critical => "#B71C1C", // Dark Red
            _ => "#9E9E9E"                       // Gray
        };
    }
}