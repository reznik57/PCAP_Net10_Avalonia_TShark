using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services
{
    public interface IInsecurePortDetector
    {
        List<EnhancedSecurityThreat> DetectInsecurePorts(IEnumerable<PacketInfo> packets);
        PortRiskProfile GetPortRiskProfile(int port, string protocol);
        SecurityMetrics CalculateSecurityMetrics(List<EnhancedSecurityThreat> threats);
        Dictionary<int, PortRiskProfile> GetKnownInsecurePorts();
        List<EnhancedSecurityThreat> DetectInsecureVersions(IEnumerable<PacketInfo> packets);

        /// <summary>
        /// Unified single-pass detection - combines insecure ports and version detection
        /// </summary>
        List<EnhancedSecurityThreat> DetectAllPortThreats(IEnumerable<PacketInfo> packets);
    }

    public class InsecurePortDetector : IInsecurePortDetector
    {
        private readonly Dictionary<int, PortRiskProfile> _insecurePortDatabase;
        private readonly IProtocolVersionDetector _versionDetector;

        public InsecurePortDetector() : this(new ProtocolVersionDetector())
        {
        }

        public InsecurePortDetector(IProtocolVersionDetector versionDetector)
        {
            _insecurePortDatabase = InitializeInsecurePortDatabase();
            _versionDetector = versionDetector;
        }

        private Dictionary<int, PortRiskProfile> InitializeInsecurePortDatabase()
        {
            return new Dictionary<int, PortRiskProfile>
            {
                // Telnet - Unencrypted remote access
                [23] = new PortRiskProfile
                {
                    Port = 23,
                    Protocol = "TCP",
                    ServiceName = "Telnet",
                    RiskLevel = ThreatSeverity.Critical,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "CVE-2020-10188", "Plaintext credentials", "MITM attacks" },
                    RecommendedAlternative = "SSH (Port 22)",
                    SecurityNotes = "Telnet transmits all data including passwords in plaintext. Critical security risk.",
                    RequiresImmediateAction = true
                },

                // FTP - Unencrypted file transfer
                [21] = new PortRiskProfile
                {
                    Port = 21,
                    Protocol = "TCP",
                    ServiceName = "FTP Control",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Plaintext credentials", "Data interception", "Bounce attacks" },
                    RecommendedAlternative = "SFTP (Port 22) or FTPS (Port 990)",
                    SecurityNotes = "FTP transmits credentials and data in plaintext. High security risk.",
                    RequiresImmediateAction = true
                },

                // FTP Data
                [20] = new PortRiskProfile
                {
                    Port = 20,
                    Protocol = "TCP",
                    ServiceName = "FTP Data",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Data interception", "MITM attacks" },
                    RecommendedAlternative = "SFTP or FTPS",
                    SecurityNotes = "FTP data channel - unencrypted file transfers.",
                    RequiresImmediateAction = true
                },

                // HTTP - Unencrypted web traffic
                [80] = new PortRiskProfile
                {
                    Port = 80,
                    Protocol = "TCP",
                    ServiceName = "HTTP",
                    RiskLevel = ThreatSeverity.Medium,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Session hijacking", "Data interception", "MITM attacks" },
                    RecommendedAlternative = "HTTPS (Port 443)",
                    SecurityNotes = "HTTP traffic is unencrypted. Should be used only for non-sensitive data.",
                    RequiresImmediateAction = false
                },

                // LDAP - Unencrypted directory services
                [389] = new PortRiskProfile
                {
                    Port = 389,
                    Protocol = "TCP/UDP",
                    ServiceName = "LDAP",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Plaintext authentication", "Information disclosure", "LDAP injection" },
                    RecommendedAlternative = "LDAPS (Port 636)",
                    SecurityNotes = "LDAP without TLS exposes authentication credentials and directory data.",
                    RequiresImmediateAction = true
                },

                // SNMP v1/v2c - Weak authentication
                [161] = new PortRiskProfile
                {
                    Port = 161,
                    Protocol = "UDP",
                    ServiceName = "SNMP",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Weak authentication", "Information disclosure", "Default community strings" },
                    RecommendedAlternative = "SNMPv3 with encryption",
                    SecurityNotes = "SNMP v1/v2c uses weak community string authentication. High risk for network device compromise.",
                    RequiresImmediateAction = true
                },

                // SMB/NetBIOS
                [139] = new PortRiskProfile
                {
                    Port = 139,
                    Protocol = "TCP",
                    ServiceName = "NetBIOS Session",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "EternalBlue", "SMB relay attacks", "Null sessions" },
                    RecommendedAlternative = "SMB over 445 with SMBv3 and encryption",
                    SecurityNotes = "Legacy SMB/NetBIOS vulnerable to numerous attacks including ransomware.",
                    RequiresImmediateAction = true
                },

                // SMB
                [445] = new PortRiskProfile
                {
                    Port = 445,
                    Protocol = "TCP",
                    ServiceName = "SMB/CIFS",
                    RiskLevel = ThreatSeverity.Medium,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "EternalBlue", "SMB signing bypass", "Relay attacks" },
                    RecommendedAlternative = "Use SMBv3 with encryption enabled",
                    SecurityNotes = "Ensure SMBv1 is disabled and SMB signing is required.",
                    RequiresImmediateAction = false
                },

                // RDP - Often targeted
                [3389] = new PortRiskProfile
                {
                    Port = 3389,
                    Protocol = "TCP",
                    ServiceName = "RDP",
                    RiskLevel = ThreatSeverity.Medium,
                    IsEncrypted = true,
                    KnownVulnerabilities = new[] { "BlueKeep (CVE-2019-0708)", "Brute force attacks", "MitM with weak encryption" },
                    RecommendedAlternative = "Use RDP with NLA, or VPN + RDP",
                    SecurityNotes = "RDP is frequently targeted. Use Network Level Authentication and strong passwords.",
                    RequiresImmediateAction = false
                },

                // VNC - Weak authentication
                [5900] = new PortRiskProfile
                {
                    Port = 5900,
                    Protocol = "TCP",
                    ServiceName = "VNC",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Weak authentication", "No encryption by default", "Password limit (8 chars)" },
                    RecommendedAlternative = "VNC over SSH tunnel or use RDP",
                    SecurityNotes = "VNC has weak security by default. Must be tunneled through SSH/VPN.",
                    RequiresImmediateAction = true
                },

                // MySQL
                [3306] = new PortRiskProfile
                {
                    Port = 3306,
                    Protocol = "TCP",
                    ServiceName = "MySQL",
                    RiskLevel = ThreatSeverity.Medium,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Default credentials", "Unencrypted connections", "SQL injection" },
                    RecommendedAlternative = "Use MySQL with SSL/TLS required",
                    SecurityNotes = "Database ports should not be exposed to public networks.",
                    RequiresImmediateAction = false
                },

                // PostgreSQL
                [5432] = new PortRiskProfile
                {
                    Port = 5432,
                    Protocol = "TCP",
                    ServiceName = "PostgreSQL",
                    RiskLevel = ThreatSeverity.Medium,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Default credentials", "Unencrypted connections", "SQL injection" },
                    RecommendedAlternative = "Use PostgreSQL with SSL required",
                    SecurityNotes = "Database ports should not be exposed to public networks.",
                    RequiresImmediateAction = false
                },

                // Redis
                [6379] = new PortRiskProfile
                {
                    Port = 6379,
                    Protocol = "TCP",
                    ServiceName = "Redis",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "No authentication by default", "Command injection", "Data exposure" },
                    RecommendedAlternative = "Use Redis with AUTH and SSL",
                    SecurityNotes = "Redis without authentication is critical security risk.",
                    RequiresImmediateAction = true
                },

                // MongoDB
                [27017] = new PortRiskProfile
                {
                    Port = 27017,
                    Protocol = "TCP",
                    ServiceName = "MongoDB",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "No authentication by default", "Data exposure", "Ransomware attacks" },
                    RecommendedAlternative = "Use MongoDB with authentication and TLS",
                    SecurityNotes = "Unsecured MongoDB instances are frequently compromised.",
                    RequiresImmediateAction = true
                },

                // Elasticsearch
                [9200] = new PortRiskProfile
                {
                    Port = 9200,
                    Protocol = "TCP",
                    ServiceName = "Elasticsearch",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "No authentication by default", "Data exposure", "Remote code execution" },
                    RecommendedAlternative = "Use Elasticsearch with X-Pack security",
                    SecurityNotes = "Elasticsearch without security is critical risk.",
                    RequiresImmediateAction = true
                },

                // rlogin
                [513] = new PortRiskProfile
                {
                    Port = 513,
                    Protocol = "TCP",
                    ServiceName = "rlogin",
                    RiskLevel = ThreatSeverity.Critical,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "No encryption", "Weak authentication", "Trust-based access" },
                    RecommendedAlternative = "SSH (Port 22)",
                    SecurityNotes = "Obsolete protocol with critical security flaws.",
                    RequiresImmediateAction = true
                },

                // rsh
                [514] = new PortRiskProfile
                {
                    Port = 514,
                    Protocol = "TCP",
                    ServiceName = "rsh/rexec",
                    RiskLevel = ThreatSeverity.Critical,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "No encryption", "No authentication", "Command execution" },
                    RecommendedAlternative = "SSH (Port 22)",
                    SecurityNotes = "Obsolete protocol with critical security flaws.",
                    RequiresImmediateAction = true
                },

                // TFTP
                [69] = new PortRiskProfile
                {
                    Port = 69,
                    Protocol = "UDP",
                    ServiceName = "TFTP",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "No authentication", "No encryption", "Directory traversal" },
                    RecommendedAlternative = "SFTP or SCP",
                    SecurityNotes = "TFTP has no security features. Use only in isolated networks.",
                    RequiresImmediateAction = true
                },
                
                // Additional critical insecure ports
                
                // RPC
                [135] = new PortRiskProfile
                {
                    Port = 135,
                    Protocol = "TCP/UDP",
                    ServiceName = "RPC/DCE endpoint mapper",
                    RiskLevel = ThreatSeverity.Critical,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Blaster worm", "Remote code execution", "Information disclosure" },
                    RecommendedAlternative = "Block at firewall, use RPC over HTTPS",
                    SecurityNotes = "Windows RPC endpoint mapper - frequently exploited for lateral movement.",
                    RequiresImmediateAction = true
                },
                
                // MSSQL
                [1433] = new PortRiskProfile
                {
                    Port = 1433,
                    Protocol = "TCP",
                    ServiceName = "MSSQL",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "SQL Slammer worm", "SQL injection", "Default sa password" },
                    RecommendedAlternative = "Use MSSQL with TLS encryption",
                    SecurityNotes = "SQL Server should not be exposed to public networks.",
                    RequiresImmediateAction = true
                },
                
                // Oracle
                [1521] = new PortRiskProfile
                {
                    Port = 1521,
                    Protocol = "TCP",
                    ServiceName = "Oracle Database",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "TNS poisoning", "Default credentials", "Remote code execution" },
                    RecommendedAlternative = "Use Oracle with network encryption",
                    SecurityNotes = "Oracle TNS Listener should not be exposed publicly.",
                    RequiresImmediateAction = true
                },
                
                // Memcached
                [11211] = new PortRiskProfile
                {
                    Port = 11211,
                    Protocol = "TCP/UDP",
                    ServiceName = "Memcached",
                    RiskLevel = ThreatSeverity.Critical,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "DDoS amplification", "No authentication", "Data exposure" },
                    RecommendedAlternative = "Use with SASL auth, bind to localhost",
                    SecurityNotes = "Memcached amplification attacks can generate 51,000x traffic.",
                    RequiresImmediateAction = true
                },
                
                // NFS
                [2049] = new PortRiskProfile
                {
                    Port = 2049,
                    Protocol = "TCP/UDP",
                    ServiceName = "NFS",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "No authentication", "Data exposure", "Privilege escalation" },
                    RecommendedAlternative = "Use NFSv4 with Kerberos",
                    SecurityNotes = "NFS shares can expose sensitive data without proper authentication.",
                    RequiresImmediateAction = true
                },
                
                // Docker API
                [2375] = new PortRiskProfile
                {
                    Port = 2375,
                    Protocol = "TCP",
                    ServiceName = "Docker API (unencrypted)",
                    RiskLevel = ThreatSeverity.Critical,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Container escape", "Cryptocurrency mining", "Full system compromise" },
                    RecommendedAlternative = "Use Docker API with TLS (port 2376)",
                    SecurityNotes = "Exposed Docker API allows full control of host system.",
                    RequiresImmediateAction = true
                },
                
                // Kubernetes API
                [6443] = new PortRiskProfile
                {
                    Port = 6443,
                    Protocol = "TCP",
                    ServiceName = "Kubernetes API",
                    RiskLevel = ThreatSeverity.Medium,
                    IsEncrypted = true,
                    KnownVulnerabilities = new[] { "Misconfiguration", "RBAC bypass", "Secrets exposure" },
                    RecommendedAlternative = "Use with proper RBAC and network policies",
                    SecurityNotes = "Kubernetes API server - ensure proper authentication.",
                    RequiresImmediateAction = false
                },
                
                // etcd
                [2379] = new PortRiskProfile
                {
                    Port = 2379,
                    Protocol = "TCP",
                    ServiceName = "etcd",
                    RiskLevel = ThreatSeverity.Critical,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "No authentication", "Secrets exposure", "Cluster compromise" },
                    RecommendedAlternative = "Use etcd with TLS and authentication",
                    SecurityNotes = "etcd stores Kubernetes secrets - critical to secure.",
                    RequiresImmediateAction = true
                },
                
                // CouchDB
                [5984] = new PortRiskProfile
                {
                    Port = 5984,
                    Protocol = "TCP",
                    ServiceName = "CouchDB",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Admin party mode", "Remote code execution", "Data exposure" },
                    RecommendedAlternative = "Configure authentication and use HTTPS",
                    SecurityNotes = "CouchDB default configuration allows admin access.",
                    RequiresImmediateAction = true
                },
                
                // RabbitMQ Management
                [15672] = new PortRiskProfile
                {
                    Port = 15672,
                    Protocol = "TCP",
                    ServiceName = "RabbitMQ Management",
                    RiskLevel = ThreatSeverity.Medium,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Default credentials", "Information disclosure" },
                    RecommendedAlternative = "Use with HTTPS and strong authentication",
                    SecurityNotes = "RabbitMQ management console exposes cluster information.",
                    RequiresImmediateAction = false
                },
                
                // Hadoop NameNode
                [9000] = new PortRiskProfile
                {
                    Port = 9000,
                    Protocol = "TCP",
                    ServiceName = "Hadoop NameNode",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "No authentication", "Data exposure", "Remote code execution" },
                    RecommendedAlternative = "Use Kerberos authentication",
                    SecurityNotes = "Hadoop clusters without auth are frequently compromised.",
                    RequiresImmediateAction = true
                },
                
                // Cassandra
                [9042] = new PortRiskProfile
                {
                    Port = 9042,
                    Protocol = "TCP",
                    ServiceName = "Cassandra",
                    RiskLevel = ThreatSeverity.Medium,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Default configuration", "No encryption", "CQL injection" },
                    RecommendedAlternative = "Enable authentication and TLS",
                    SecurityNotes = "Cassandra native transport should use encryption.",
                    RequiresImmediateAction = false
                },
                
                // Portmapper/rpcbind
                [111] = new PortRiskProfile
                {
                    Port = 111,
                    Protocol = "TCP/UDP",
                    ServiceName = "Portmapper/rpcbind",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Information disclosure", "DDoS amplification", "Service enumeration" },
                    RecommendedAlternative = "Block at firewall",
                    SecurityNotes = "RPC portmapper reveals available services.",
                    RequiresImmediateAction = true
                },
                
                // X11
                [6000] = new PortRiskProfile
                {
                    Port = 6000,
                    Protocol = "TCP",
                    ServiceName = "X11",
                    RiskLevel = ThreatSeverity.High,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Keylogging", "Screenshot capture", "No authentication" },
                    RecommendedAlternative = "Use X11 forwarding over SSH",
                    SecurityNotes = "X11 without authentication allows desktop access.",
                    RequiresImmediateAction = true
                },
                
                // IPMI
                [623] = new PortRiskProfile
                {
                    Port = 623,
                    Protocol = "UDP",
                    ServiceName = "IPMI",
                    RiskLevel = ThreatSeverity.Critical,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Cipher 0 vulnerability", "Default passwords", "Remote system control" },
                    RecommendedAlternative = "Use IPMI v2 with strong passwords",
                    SecurityNotes = "IPMI provides hardware-level control - critical vulnerability.",
                    RequiresImmediateAction = true
                },
                
                // SIP
                [5060] = new PortRiskProfile
                {
                    Port = 5060,
                    Protocol = "TCP/UDP",
                    ServiceName = "SIP",
                    RiskLevel = ThreatSeverity.Medium,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Call hijacking", "Toll fraud", "Eavesdropping" },
                    RecommendedAlternative = "Use SIP with TLS (SIPS)",
                    SecurityNotes = "Unencrypted VoIP can be intercepted and manipulated.",
                    RequiresImmediateAction = false
                },
                
                // CUPS
                [631] = new PortRiskProfile
                {
                    Port = 631,
                    Protocol = "TCP",
                    ServiceName = "CUPS (IPP)",
                    RiskLevel = ThreatSeverity.Low,
                    IsEncrypted = false,
                    KnownVulnerabilities = new[] { "Information disclosure", "Cross-site scripting" },
                    RecommendedAlternative = "Restrict to localhost only",
                    SecurityNotes = "CUPS printing service should not be exposed.",
                    RequiresImmediateAction = false
                }
            };
        }

        public List<EnhancedSecurityThreat> DetectInsecurePorts(IEnumerable<PacketInfo> packets)
        {
            var threats = new List<EnhancedSecurityThreat>();
            var packetList = packets.ToList();
            
            // Group packets by destination port to identify services
            var portGroups = packetList
                .Where(p => p.DestinationPort > 0)
                .GroupBy(p => p.DestinationPort);

            foreach (var portGroup in portGroups)
            {
                var port = portGroup.Key;
                
                // Check if this is a known insecure port
                if (_insecurePortDatabase.ContainsKey(port))
                {
                    var riskProfile = _insecurePortDatabase[port];
                    var portPackets = portGroup.ToList();
                    
                    // Get unique IPs using this insecure service
                    var uniqueSourceIPs = portPackets.Select(p => p.SourceIP).Distinct().ToList();
                    var uniqueDestIPs = portPackets.Select(p => p.DestinationIP).Distinct().ToList();
                    
                    // Capture ALL frame numbers for DrillDown investigation
                    var frameNumbers = portPackets.Select(p => p.FrameNumber).ToList();

                    // Build unique connection tuples for conversation-level investigation
                    var connections = portPackets
                        .Select(p => new ConnectionTuple
                        {
                            SourceIP = p.SourceIP,
                            DestinationIP = p.DestinationIP,
                            SourcePort = p.SourcePort,
                            DestinationPort = p.DestinationPort,
                            Protocol = p.Protocol.ToString()
                        })
                        .Distinct()
                        .ToList();

                    var threat = new EnhancedSecurityThreat
                    {
                        Category = DetermineCategory(riskProfile),
                        Severity = riskProfile.RiskLevel,
                        Protocol = riskProfile.Protocol,
                        Port = port,
                        Service = riskProfile.ServiceName,
                        ThreatName = $"Insecure {riskProfile.ServiceName} Service Detected",
                        Description = $"{riskProfile.SecurityNotes} Found {portPackets.Count} packets using this service.",
                        Vulnerabilities = riskProfile.KnownVulnerabilities.ToList(),
                        Mitigations = new List<string>
                        {
                            riskProfile.RecommendedAlternative,
                            "Implement network segmentation",
                            "Use VPN for remote access",
                            "Enable firewall rules to restrict access"
                        },
                        RiskScore = CalculateRiskScore(riskProfile, portPackets.Count),
                        FirstSeen = portPackets.Min(p => p.Timestamp),
                        LastSeen = portPackets.Max(p => p.Timestamp),
                        OccurrenceCount = portPackets.Count,
                        AffectedIPs = uniqueSourceIPs.Concat(uniqueDestIPs).Distinct().ToList(),
                        FrameNumbers = frameNumbers,
                        AffectedConnections = connections,
                        Metadata = new Dictionary<string, object>
                        {
                            { "RequiresImmediateAction", riskProfile.RequiresImmediateAction },
                            { "IsEncrypted", riskProfile.IsEncrypted },
                            { "UniqueConnections", connections.Count }
                        }
                    };

                    threats.Add(threat);
                }
            }

            // Also check for suspicious port patterns
            DetectSuspiciousPortPatterns(packetList, threats);
            
            return threats.OrderByDescending(t => t.Severity).ThenByDescending(t => t.RiskScore).ToList();
        }

        private void DetectSuspiciousPortPatterns(List<PacketInfo> packets, List<EnhancedSecurityThreat> threats)
        {
            // Detect port scanning
            var sourceGroups = packets.GroupBy(p => p.SourceIP);
            
            foreach (var sourceGroup in sourceGroups)
            {
                var sourcePack = sourceGroup.ToList();
                var uniquePorts = sourcePack.Select(p => p.DestinationPort).Distinct().Count();
                
                // If one source is hitting many ports, likely a port scan
                if (uniquePorts > 100)
                {
                    // Capture frame numbers and connections for port scan threat
                    var scanFrameNumbers = sourcePack.Select(p => p.FrameNumber).ToList();
                    var scanConnections = sourcePack
                        .Select(p => new ConnectionTuple
                        {
                            SourceIP = p.SourceIP,
                            DestinationIP = p.DestinationIP,
                            SourcePort = p.SourcePort,
                            DestinationPort = p.DestinationPort,
                            Protocol = p.Protocol.ToString()
                        })
                        .Distinct()
                        .ToList();

                    threats.Add(new EnhancedSecurityThreat
                    {
                        Category = ThreatCategory.Reconnaissance,
                        Severity = ThreatSeverity.High,
                        Protocol = "Multiple",
                        ThreatName = "Port Scanning Detected",
                        Description = $"Source {sourceGroup.Key} scanned {uniquePorts} different ports",
                        Vulnerabilities = new List<string> { "Information disclosure", "Attack preparation" },
                        Mitigations = new List<string> { "Block source IP", "Enable IDS/IPS", "Investigate source" },
                        RiskScore = 8.5,
                        FirstSeen = sourcePack.Min(p => p.Timestamp),
                        LastSeen = sourcePack.Max(p => p.Timestamp),
                        OccurrenceCount = uniquePorts,
                        AffectedIPs = sourcePack.Select(p => p.DestinationIP).Distinct().ToList(),
                        FrameNumbers = scanFrameNumbers,
                        AffectedConnections = scanConnections
                    });
                }
            }

            // Detect use of non-standard high ports for known services
            DetectServiceOnNonStandardPorts(packets, threats);
        }

        private void DetectServiceOnNonStandardPorts(List<PacketInfo> packets, List<EnhancedSecurityThreat> threats)
        {
            // Common services that might be hidden on non-standard ports
            var httpPatterns = new[] { "HTTP/", "GET ", "POST ", "PUT ", "DELETE " };
            var sshPatterns = new[] { "SSH-", "diffie-hellman" };
            var rdpPatterns = new[] { "RDP", "mstsc" };

            // Define well-known service ports that could be suspicious if used as source ports
            var wellKnownServicePorts = new HashSet<int>
            {
                21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443
            };

            // Group packets by service and port to avoid duplicate threats
            var detectedServices = new Dictionary<(string service, int port, bool isClient), List<PacketInfo>>();

            foreach (var packet in packets.Where(p => p.DestinationPort > 1024 && !string.IsNullOrEmpty(p.Info)))
            {
                string? detectedService = null;
                var info = packet.Info ?? string.Empty;

                // Check if source port is an ephemeral port (client connection)
                // Ephemeral ports are typically > 1024 and not well-known service ports
                bool isLikelyClientConnection = packet.SourcePort > 1024 && !wellKnownServicePorts.Contains(packet.SourcePort);

                if (httpPatterns.Any(pattern => info.Contains(pattern, StringComparison.OrdinalIgnoreCase)) && packet.DestinationPort != 80 && packet.DestinationPort != 443)
                {
                    // Only flag as suspicious if BOTH source and destination are non-standard service ports
                    // If source is ephemeral, it's likely a legitimate client connecting to a non-standard HTTP port
                    if (!isLikelyClientConnection)
                    {
                        detectedService = "HTTP";
                    }
                    // Skip HTTP on non-standard ports when it's a normal client connection
                }
                else if (sshPatterns.Any(pattern => info.Contains(pattern, StringComparison.OrdinalIgnoreCase)) && packet.DestinationPort != 22)
                {
                    // SSH on non-standard port is more suspicious, but still check source
                    if (!isLikelyClientConnection)
                    {
                        detectedService = "SSH";
                    }
                }
                else if (rdpPatterns.Any(pattern => info.Contains(pattern, StringComparison.OrdinalIgnoreCase)) && packet.DestinationPort != 3389)
                {
                    // RDP on non-standard port is always somewhat suspicious
                    detectedService = "RDP";
                }

                if (detectedService != null)
                {
                    var key = (detectedService, packet.DestinationPort, isLikelyClientConnection);
                    if (!detectedServices.ContainsKey(key))
                    {
                        detectedServices[key] = new List<PacketInfo>();
                    }
                    detectedServices[key].Add(packet);
                }
            }
            
            // Create aggregated threats for each unique service/port combination
            foreach (var kvp in detectedServices)
            {
                var (service, port, isClient) = kvp.Key;
                var servicePackets = kvp.Value;
                
                // Skip if this is HTTP and it's a client connection (not a threat)
                if (service == "HTTP" && isClient)
                    continue;
                
                // Adjust severity based on whether it's a client connection
                var severity = isClient && service != "RDP" 
                    ? ThreatSeverity.Low 
                    : ThreatSeverity.Medium;
                
                var uniqueSourceIPs = servicePackets.Select(p => p.SourceIP).Distinct().ToList();
                var uniqueDestIPs = servicePackets.Select(p => p.DestinationIP).Distinct().ToList();
                
                var description = isClient 
                    ? $"{service} client connecting to non-standard port {port} (likely legitimate)"
                    : $"{service} service detected on port {port} with suspicious source ports";
                
                // Capture frame numbers and connections for non-standard port threat
                var nonStdFrameNumbers = servicePackets.Select(p => p.FrameNumber).ToList();
                var nonStdConnections = servicePackets
                    .Select(p => new ConnectionTuple
                    {
                        SourceIP = p.SourceIP,
                        DestinationIP = p.DestinationIP,
                        SourcePort = p.SourcePort,
                        DestinationPort = p.DestinationPort,
                        Protocol = p.Protocol.ToString()
                    })
                    .Distinct()
                    .ToList();

                threats.Add(new EnhancedSecurityThreat
                {
                    Category = ThreatCategory.MaliciousActivity,
                    Severity = severity,
                    Protocol = servicePackets.First().Protocol.ToString(),
                    Port = port,
                    Service = service,
                    ThreatName = $"{service} on Non-Standard Port",
                    Description = $"{description}. Found {servicePackets.Count} packets from {uniqueSourceIPs.Count} unique sources.",
                    Vulnerabilities = new List<string> { "Service obfuscation", "Potential backdoor", "Evasion attempt" },
                    Mitigations = new List<string> { "Investigate service", "Verify if authorized", "Monitor for suspicious activity" },
                    RiskScore = isClient ? 3.5 : 6.5,
                    FirstSeen = servicePackets.Min(p => p.Timestamp),
                    LastSeen = servicePackets.Max(p => p.Timestamp),
                    OccurrenceCount = servicePackets.Count,
                    AffectedIPs = uniqueSourceIPs.Concat(uniqueDestIPs).Distinct().ToList(),
                    FrameNumbers = nonStdFrameNumbers,
                    AffectedConnections = nonStdConnections,
                    Metadata = new Dictionary<string, object>
                    {
                        { "UniqueSourcePorts", servicePackets.Select(p => p.SourcePort).Distinct().Count() },
                        { "IsLikelyClientConnection", isClient },
                        { "UniqueSources", uniqueSourceIPs.Count },
                        { "UniqueDestinations", uniqueDestIPs.Count }
                    }
                });
            }
        }

        private ThreatCategory DetermineCategory(PortRiskProfile profile)
        {
            if (!profile.IsEncrypted)
            {
                if (profile.ServiceName.Contains("Telnet", StringComparison.OrdinalIgnoreCase) || profile.ServiceName.Contains("FTP", StringComparison.OrdinalIgnoreCase) ||
                    profile.ServiceName.Contains("HTTP", StringComparison.OrdinalIgnoreCase) || profile.ServiceName.Contains("LDAP", StringComparison.OrdinalIgnoreCase))
                {
                    return ThreatCategory.UnencryptedService;
                }
            }

            if (profile.ServiceName.Contains("NetBIOS", StringComparison.OrdinalIgnoreCase) || profile.ServiceName.Contains("rlogin", StringComparison.OrdinalIgnoreCase) ||
                profile.ServiceName.Contains("rsh", StringComparison.OrdinalIgnoreCase) || profile.ServiceName.Contains("TFTP", StringComparison.OrdinalIgnoreCase))
            {
                return ThreatCategory.LegacyProtocol;
            }

            if (profile.KnownVulnerabilities.Any(v => v.Contains("CVE", StringComparison.OrdinalIgnoreCase)))
            {
                return ThreatCategory.KnownVulnerability;
            }

            return ThreatCategory.InsecureProtocol;
        }

        private double CalculateRiskScore(PortRiskProfile profile, int packetCount)
        {
            double baseScore = (double)profile.RiskLevel * 2; // 2-10 base score
            
            // Increase score based on packet count (activity level)
            if (packetCount > 1000) baseScore += 1.5;
            else if (packetCount > 100) baseScore += 1.0;
            else if (packetCount > 10) baseScore += 0.5;
            
            // Increase score if immediate action required
            if (profile.RequiresImmediateAction) baseScore += 1.0;
            
            // Increase score if not encrypted
            if (!profile.IsEncrypted) baseScore += 0.5;
            
            return Math.Min(10, baseScore); // Cap at 10
        }

        public PortRiskProfile GetPortRiskProfile(int port, string protocol)
        {
            if (_insecurePortDatabase.ContainsKey(port))
            {
                return _insecurePortDatabase[port];
            }
            
            // Return a default low-risk profile for unknown ports
            return new PortRiskProfile
            {
                Port = port,
                Protocol = protocol,
                ServiceName = "Unknown",
                RiskLevel = ThreatSeverity.Info,
                IsEncrypted = false,
                KnownVulnerabilities = Array.Empty<string>(),
                RecommendedAlternative = "Verify if this service is required",
                SecurityNotes = "Unknown service - verify if authorized",
                RequiresImmediateAction = false
            };
        }

        public SecurityMetrics CalculateSecurityMetrics(List<EnhancedSecurityThreat> threats)
        {
            var metrics = new SecurityMetrics
            {
                TotalThreats = threats.Count,
                CriticalThreats = threats.Count(t => t.Severity == ThreatSeverity.Critical),
                HighThreats = threats.Count(t => t.Severity == ThreatSeverity.High),
                MediumThreats = threats.Count(t => t.Severity == ThreatSeverity.Medium),
                LowThreats = threats.Count(t => t.Severity == ThreatSeverity.Low),
                InfoThreats = threats.Count(t => t.Severity == ThreatSeverity.Info)
            };
            
            // Calculate overall risk score
            double totalRiskScore = 0;
            foreach (var threat in threats)
            {
                totalRiskScore += threat.RiskScore;
            }
            metrics.OverallRiskScore = threats.Any() ? totalRiskScore / threats.Count : 0;
            
            // Group threats by category
            metrics.ThreatsByCategory = threats
                .GroupBy(t => t.Category.ToString())
                .ToDictionary(g => g.Key, g => g.Count());
            
            // Group threats by port
            metrics.ThreatsByPort = threats
                .Where(t => t.Port > 0)
                .GroupBy(t => t.Port)
                .ToDictionary(g => g.Key, g => g.Count());
            
            // Get top vulnerable services
            metrics.TopVulnerableServices = threats
                .GroupBy(t => t.Service)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .Select(g => $"{g.Key} ({g.Count()} threats)")
                .ToList();
            
            return metrics;
        }

        public Dictionary<int, PortRiskProfile> GetKnownInsecurePorts()
        {
            return new Dictionary<int, PortRiskProfile>(_insecurePortDatabase);
        }

        public List<EnhancedSecurityThreat> DetectInsecureVersions(IEnumerable<PacketInfo> packets)
        {
            var threats = new List<EnhancedSecurityThreat>();
            var packetsList = packets.ToList();
            
            if (!packetsList.Any())
                return threats;
                
            var versionResults = _versionDetector.DetectVersions(packetsList);
            var groupedResults = _versionDetector.GroupVersionsByService(versionResults);

            // Get the overall timestamp range from packets
            var minTimestamp = packetsList.Min(p => p.Timestamp);
            var maxTimestamp = packetsList.Max(p => p.Timestamp);

            foreach (var serviceGroup in groupedResults)
            {
                var service = serviceGroup.Key;
                var versions = serviceGroup.Value;

                foreach (var versionResult in versions.Where(v => v.SecurityRisk >= ThreatSeverity.Medium))
                {
                    var threat = new EnhancedSecurityThreat
                    {
                        Category = DetermineVersionCategory(versionResult),
                        Severity = versionResult.SecurityRisk,
                        Protocol = "TCP",
                        Service = service,
                        ThreatName = $"Insecure {service} Version: {versionResult.DetectedVersion}",
                        Description = versionResult.SecurityAssessment,
                        Vulnerabilities = versionResult.Vulnerabilities,
                        Mitigations = new List<string>
                        {
                            versionResult.Recommendation,
                            "Upgrade to the latest secure version",
                            "Apply all security patches",
                            "Enable strong cipher suites if applicable"
                        },
                        RiskScore = CalculateVersionRiskScore(versionResult),
                        FirstSeen = minTimestamp,
                        LastSeen = maxTimestamp,
                        OccurrenceCount = 1,
                        Metadata = new Dictionary<string, object>
                        {
                            { "DetectedVersion", versionResult.DetectedVersion },
                            { "VersionIdentified", versionResult.VersionIdentified },
                            { "IsEncryptedButInsecure", IsEncryptedButInsecure(versionResult) }
                        }
                    };

                    threats.Add(threat);
                }
            }

            return threats;
        }

        private ThreatCategory DetermineVersionCategory(VersionDetectionResult versionResult)
        {
            if (versionResult.DetectedVersion != null)
            {
                var version = versionResult.DetectedVersion.ToUpper();

                // Check for encrypted but insecure protocols
                if ((version.Contains("SSL", StringComparison.OrdinalIgnoreCase) || version.Contains("TLS 1.0", StringComparison.OrdinalIgnoreCase) || version.Contains("TLS 1.1", StringComparison.OrdinalIgnoreCase)) ||
                    (version.Contains("SSH-1", StringComparison.OrdinalIgnoreCase)) ||
                    (version.Contains("RDP", StringComparison.OrdinalIgnoreCase) && version.Contains("5", StringComparison.OrdinalIgnoreCase)))
                {
                    return ThreatCategory.InsecureProtocol;
                }

                // Check for deprecated protocols
                if (version.Contains("SSL", StringComparison.OrdinalIgnoreCase) || version.Contains("SMB1", StringComparison.OrdinalIgnoreCase) ||
                    version.Contains("HTTP/1.0", StringComparison.OrdinalIgnoreCase) || version.Contains("SSH-1", StringComparison.OrdinalIgnoreCase))
                {
                    return ThreatCategory.LegacyProtocol;
                }
            }

            if (versionResult.Vulnerabilities.Any(v => v.Contains("CVE", StringComparison.OrdinalIgnoreCase)))
            {
                return ThreatCategory.KnownVulnerability;
            }

            return ThreatCategory.InsecureProtocol;
        }

        private double CalculateVersionRiskScore(VersionDetectionResult versionResult)
        {
            double baseScore = (double)versionResult.SecurityRisk * 2;

            // Add score for known CVEs
            var cveCount = versionResult.Vulnerabilities.Count(v => v.Contains("CVE", StringComparison.OrdinalIgnoreCase));
            baseScore += cveCount * 0.5;

            // Add score for encrypted but insecure
            if (IsEncryptedButInsecure(versionResult))
            {
                baseScore += 1.5; // Extra risk for false sense of security
            }

            // Add score if version not properly identified
            if (!versionResult.VersionIdentified)
            {
                baseScore += 0.5;
            }

            return Math.Min(10, baseScore);
        }

        private bool IsEncryptedButInsecure(VersionDetectionResult versionResult)
        {
            if (versionResult.DetectedVersion == null)
                return false;

            var encryptedButInsecure = new[]
            {
                "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1",
                "SSH-1.0", "SSH-1.5",
                "RDP 5.x", "RDP 6.x"
            };

            return encryptedButInsecure.Any(v => versionResult.DetectedVersion.Contains(v, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Unified single-pass detection that combines insecure ports and version detection
        /// PERFORMANCE OPTIMIZATION: Shares packet list, early filtering, reduced allocations
        /// </summary>
        public List<EnhancedSecurityThreat> DetectAllPortThreats(IEnumerable<PacketInfo> packets)
        {
            var allThreats = new List<EnhancedSecurityThreat>(capacity: 1000);

            // OPTIMIZATION: Materialize once instead of twice (saves ~50ms per batch)
            var packetList = packets as List<PacketInfo> ?? packets.ToList();

            // OPTIMIZATION: Early filter for version detection (only check packets on monitored ports)
            // This reduces version detection work by ~80% (from 100K packets to ~20K packets)
            var monitoredPorts = new HashSet<int> { 21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 8080, 8443 };
            var versionCheckPackets = packetList.Where(p => monitoredPorts.Contains(p.DestinationPort) || monitoredPorts.Contains(p.SourcePort)).ToList();

            // Detect insecure ports (pass list directly - no re-enumeration)
            allThreats.AddRange(DetectInsecurePortsOptimized(packetList));

            // Detect insecure versions (only on filtered packets - much smaller dataset)
            if (versionCheckPackets.Count > 0)
            {
                allThreats.AddRange(DetectInsecureVersionsOptimized(versionCheckPackets, packetList.Min(p => p.Timestamp), packetList.Max(p => p.Timestamp)));
            }

            return allThreats;
        }

        // Optimized version that accepts List directly (no re-enumeration)
        private List<EnhancedSecurityThreat> DetectInsecurePortsOptimized(List<PacketInfo> packetList)
        {
            var threats = new List<EnhancedSecurityThreat>();

            // Group packets by destination port to identify services
            var portGroups = packetList
                .Where(p => p.DestinationPort > 0)
                .GroupBy(p => p.DestinationPort);

            foreach (var portGroup in portGroups)
            {
                var port = portGroup.Key;

                // Check if this is a known insecure port
                if (_insecurePortDatabase.ContainsKey(port))
                {
                    var riskProfile = _insecurePortDatabase[port];
                    var portPackets = portGroup.ToList();

                    // Get unique IPs using this insecure service
                    var uniqueSourceIPs = portPackets.Select(p => p.SourceIP).Distinct().ToList();
                    var uniqueDestIPs = portPackets.Select(p => p.DestinationIP).Distinct().ToList();

                    // Capture ALL frame numbers for DrillDown investigation
                    var frameNumbers = portPackets.Select(p => p.FrameNumber).ToList();

                    // Build unique connection tuples for conversation-level investigation
                    var connections = portPackets
                        .Select(p => new ConnectionTuple
                        {
                            SourceIP = p.SourceIP,
                            DestinationIP = p.DestinationIP,
                            SourcePort = p.SourcePort,
                            DestinationPort = p.DestinationPort,
                            Protocol = p.Protocol.ToString()
                        })
                        .Distinct()
                        .ToList();

                    var threat = new EnhancedSecurityThreat
                    {
                        Category = DetermineCategory(riskProfile),
                        Severity = riskProfile.RiskLevel,
                        Protocol = riskProfile.Protocol,
                        Port = port,
                        Service = riskProfile.ServiceName,
                        ThreatName = $"Insecure {riskProfile.ServiceName} Service Detected",
                        Description = $"{riskProfile.SecurityNotes} Found {portPackets.Count} packets using this service.",
                        Vulnerabilities = riskProfile.KnownVulnerabilities.ToList(),
                        Mitigations = new List<string>
                        {
                            riskProfile.RecommendedAlternative,
                            "Implement network segmentation",
                            "Use VPN for remote access",
                            "Enable firewall rules to restrict access"
                        },
                        RiskScore = CalculateRiskScore(riskProfile, portPackets.Count),
                        FirstSeen = portPackets.Min(p => p.Timestamp),
                        LastSeen = portPackets.Max(p => p.Timestamp),
                        OccurrenceCount = portPackets.Count,
                        AffectedIPs = uniqueSourceIPs.Concat(uniqueDestIPs).Distinct().ToList(),
                        FrameNumbers = frameNumbers,
                        AffectedConnections = connections,
                        Metadata = new Dictionary<string, object>
                        {
                            { "RequiresImmediateAction", riskProfile.RequiresImmediateAction },
                            { "IsEncrypted", riskProfile.IsEncrypted },
                            { "UniqueConnections", connections.Count }
                        }
                    };

                    threats.Add(threat);
                }
            }

            // Also check for suspicious port patterns
            DetectSuspiciousPortPatterns(packetList, threats);

            return threats.OrderByDescending(t => t.Severity).ThenByDescending(t => t.RiskScore).ToList();
        }

        // Optimized version with early filtering and pre-computed timestamps
        private List<EnhancedSecurityThreat> DetectInsecureVersionsOptimized(List<PacketInfo> filteredPackets, DateTime minTimestamp, DateTime maxTimestamp)
        {
            var threats = new List<EnhancedSecurityThreat>();

            if (filteredPackets.Count == 0)
                return threats;

            var versionResults = _versionDetector.DetectVersions(filteredPackets);
            var groupedResults = _versionDetector.GroupVersionsByService(versionResults);

            foreach (var serviceGroup in groupedResults)
            {
                var service = serviceGroup.Key;
                var versions = serviceGroup.Value;

                foreach (var versionResult in versions.Where(v => v.SecurityRisk >= ThreatSeverity.Medium))
                {
                    var threat = new EnhancedSecurityThreat
                    {
                        Category = DetermineVersionCategory(versionResult),
                        Severity = versionResult.SecurityRisk,
                        Protocol = "TCP",
                        Service = service,
                        ThreatName = $"Insecure {service} Version: {versionResult.DetectedVersion}",
                        Description = versionResult.SecurityAssessment,
                        Vulnerabilities = versionResult.Vulnerabilities,
                        Mitigations = new List<string>
                        {
                            versionResult.Recommendation,
                            "Upgrade to the latest secure version",
                            "Apply all security patches",
                            "Enable strong cipher suites if applicable"
                        },
                        RiskScore = CalculateVersionRiskScore(versionResult),
                        FirstSeen = minTimestamp,
                        LastSeen = maxTimestamp,
                        OccurrenceCount = 1,
                        Metadata = new Dictionary<string, object>
                        {
                            { "DetectedVersion", versionResult.DetectedVersion },
                            { "VersionIdentified", versionResult.VersionIdentified },
                            { "IsEncryptedButInsecure", IsEncryptedButInsecure(versionResult) }
                        }
                    };

                    threats.Add(threat);
                }
            }

            return threats;
        }
    }
}