using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace PCAPAnalyzer.Core.Security;

/// <summary>
/// High-risk protocol detection for ProtocolSecurityEvaluator.
/// </summary>
public static partial class ProtocolSecurityEvaluator
{
    [SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
        Justification = "High-risk protocol detection requires comprehensive checking of deprecated TLS, unencrypted protocols (HTTP, FTP, TFTP, email), SNMP v1/v2c, plain LDAP, VNC, unencrypted databases, and industrial IoT protocols")]
    private static SecurityAssessment? CheckHighRiskProtocols(string protocol, ushort? port)
    {
        // TLS 1.0 - Deprecated
        if (protocol.Contains("TLSV1.0", StringComparison.OrdinalIgnoreCase) || protocol.Contains("TLS1.0", StringComparison.OrdinalIgnoreCase) || protocol.Contains("TLS_1.0", StringComparison.OrdinalIgnoreCase) || protocol == "TLSV1")
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "TLS 1.0 - Deprecated, multiple vulnerabilities",
                Vulnerabilities = new List<string> { "BEAST attack", "POODLE", "Weak ciphers" },
                Recommendation = "Upgrade to TLS 1.2 or 1.3"
            };
        }

        // Plain HTTP
        if ((protocol == "HTTP" || protocol.Contains("HTTP/1", StringComparison.OrdinalIgnoreCase)) && !protocol.Contains("HTTPS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "HTTP - Unencrypted web traffic",
                Vulnerabilities = new List<string> { "No encryption", "Session hijacking", "Data interception" },
                Recommendation = "Use HTTPS with TLS 1.2+"
            };
        }

        // Plain FTP
        if (protocol == "FTP" || (protocol.Contains("FTP", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("FTPS", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("SFTP", StringComparison.OrdinalIgnoreCase)))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "FTP - Transmits credentials in plaintext",
                Vulnerabilities = new List<string> { "No encryption", "Password sniffing", "Data tampering" },
                Recommendation = "Use SFTP or FTPS"
            };
        }

        // TFTP - No security at all
        if (protocol.Contains("TFTP", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "TFTP - No authentication or encryption",
                Vulnerabilities = new List<string> { "No authentication", "No encryption", "UDP-based attacks" },
                Recommendation = "Use SFTP or SCP instead"
            };
        }

        // Plain email protocols
        if (protocol == "POP3" || (protocol.Contains("POP3", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("POP3S", StringComparison.OrdinalIgnoreCase) && port != 995))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "POP3 - Unencrypted email retrieval",
                Vulnerabilities = new List<string> { "Password in plaintext", "Email interception" },
                Recommendation = "Use POP3S (port 995) or IMAPS"
            };
        }

        if (protocol == "IMAP" || (protocol.Contains("IMAP", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("IMAPS", StringComparison.OrdinalIgnoreCase) && port != 993))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "IMAP - Unencrypted email access",
                Vulnerabilities = new List<string> { "Password in plaintext", "Email interception" },
                Recommendation = "Use IMAPS (port 993)"
            };
        }

        if (protocol == "SMTP" || (protocol.Contains("SMTP", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("SMTPS", StringComparison.OrdinalIgnoreCase) && port == 25))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "SMTP - Unencrypted email transmission",
                Vulnerabilities = new List<string> { "No encryption", "Email spoofing", "Open relay risks" },
                Recommendation = "Use SMTP with STARTTLS (587) or SMTPS (465)"
            };
        }

        // SNMPv1 and v2c - Community strings in plaintext
        if (protocol.Contains("SNMPV1", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SNMP1", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "SNMPv1 - No security features",
                Vulnerabilities = new List<string> { "Community strings in plaintext", "No authentication", "Information disclosure" },
                Recommendation = "Upgrade to SNMPv3 with authPriv"
            };
        }

        if (protocol.Contains("SNMPV2C", StringComparison.OrdinalIgnoreCase) || protocol.Contains("SNMPV2", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "SNMPv2c - Community strings in plaintext",
                Vulnerabilities = new List<string> { "No encryption", "Weak authentication", "Information disclosure" },
                Recommendation = "Upgrade to SNMPv3 with authPriv"
            };
        }

        // Plain LDAP
        if (protocol == "LDAP" || (protocol.Contains("LDAP", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("LDAPS", StringComparison.OrdinalIgnoreCase) && port == 389))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "LDAP - Unencrypted directory access",
                Vulnerabilities = new List<string> { "Password in plaintext", "Information disclosure", "LDAP injection" },
                Recommendation = "Use LDAPS (port 636) or LDAP with StartTLS"
            };
        }

        // VNC - Often unencrypted
        if (protocol.Contains("VNC", StringComparison.OrdinalIgnoreCase) || protocol.Contains("RFB", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "VNC - Often uses weak or no encryption",
                Vulnerabilities = new List<string> { "Weak authentication", "Screen capture risks", "Keylogger potential" },
                Recommendation = "Use VNC over SSH tunnel or RDP"
            };
        }

        // Plain database protocols
        if ((protocol.Contains("MYSQL", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase) && port == 3306) ||
            (protocol.Contains("MARIADB", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase)))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "MySQL/MariaDB - Unencrypted database connection",
                Vulnerabilities = new List<string> { "SQL injection", "Credential theft", "Data exposure" },
                Recommendation = "Enable SSL/TLS for MySQL connections"
            };
        }

        if ((protocol.Contains("POSTGRESQL", StringComparison.OrdinalIgnoreCase) || protocol.Contains("POSTGRES", StringComparison.OrdinalIgnoreCase)) && !protocol.Contains("SSL", StringComparison.OrdinalIgnoreCase) && port == 5432)
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "PostgreSQL - Unencrypted database connection",
                Vulnerabilities = new List<string> { "Credential theft", "SQL injection", "Data exposure" },
                Recommendation = "Enable SSL for PostgreSQL"
            };
        }

        if (protocol.Contains("MONGODB", StringComparison.OrdinalIgnoreCase) && port == 27017)
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "MongoDB - Often deployed without authentication",
                Vulnerabilities = new List<string> { "No authentication by default", "Data exposure", "Ransomware target" },
                Recommendation = "Enable authentication and use TLS"
            };
        }

        if (protocol.Contains("REDIS", StringComparison.OrdinalIgnoreCase) && port == 6379)
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "Redis - No authentication by default",
                Vulnerabilities = new List<string> { "No authentication", "Command injection", "Data exposure" },
                Recommendation = "Enable AUTH and bind to localhost only"
            };
        }

        if (protocol.Contains("MEMCACHED", StringComparison.OrdinalIgnoreCase) || protocol.Contains("MEMCACHE", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "Memcached - No authentication",
                Vulnerabilities = new List<string> { "No authentication", "DDoS amplification", "Data exposure" },
                Recommendation = "Use SASL authentication and firewall rules"
            };
        }

        // Industrial protocols - generally insecure
        if (protocol.Contains("MODBUS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "Modbus - No security features",
                Vulnerabilities = new List<string> { "No authentication", "No encryption", "Command injection" },
                Recommendation = "Use Modbus Security or isolate network"
            };
        }

        if (protocol.Contains("DNP3", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("SECURE", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "DNP3 - Limited security in base protocol",
                Vulnerabilities = new List<string> { "Weak authentication", "No encryption", "Replay attacks" },
                Recommendation = "Use DNP3 Secure Authentication"
            };
        }

        if (protocol.Contains("BACNET", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "BACnet - Minimal security features",
                Vulnerabilities = new List<string> { "Limited authentication", "No encryption", "Device spoofing" },
                Recommendation = "Use BACnet/SC (Secure Connect)"
            };
        }

        // IoT protocols
        if (protocol.Contains("MQTT", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("TLS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "MQTT - Often deployed without security",
                Vulnerabilities = new List<string> { "Optional authentication", "No encryption", "Topic injection" },
                Recommendation = "Use MQTT over TLS with authentication"
            };
        }

        if (protocol.Contains("COAP", StringComparison.OrdinalIgnoreCase) && !protocol.Contains("DTLS", StringComparison.OrdinalIgnoreCase))
        {
            return new SecurityAssessment
            {
                Level = SecurityLevel.High,
                Reason = "CoAP - No built-in security",
                Vulnerabilities = new List<string> { "No encryption", "Amplification attacks", "Spoofing" },
                Recommendation = "Use CoAP with DTLS"
            };
        }

        return null;
    }
}
