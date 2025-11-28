using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace PCAPAnalyzer.Core.Security;

/// <summary>
/// Comprehensive enterprise port database with ~600 port mappings.
/// Provides service identification and security risk assessment when L7 protocol detection unavailable.
/// </summary>
[SuppressMessage("Performance", "CA1810:Initialize reference type static fields inline",
    Justification = "Static constructor is required to build the port database from categorized AddPort calls")]
[SuppressMessage("Maintainability", "CA1505:Avoid unmaintainable code",
    Justification = "Large port database (~800 entries) is intentional for comprehensive service identification")]
public static class PortDatabase
{
    /// <summary>
    /// Risk level for a port/service
    /// </summary>
    public enum PortRisk
    {
        /// <summary>Encrypted, modern, secure protocols</summary>
        Low,
        /// <summary>Minor security concerns, may need authentication</summary>
        Medium,
        /// <summary>Plaintext credentials or notable vulnerabilities</summary>
        High,
        /// <summary>Critical vulnerabilities, deprecated protocols</summary>
        Critical,
        /// <summary>Unknown or variable risk</summary>
        Unknown
    }

    /// <summary>
    /// Port service information
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible",
        Justification = "PortInfo is a public data structure tightly coupled to PortDatabase API")]
    public readonly record struct PortInfo
    {
        public required string ServiceName { get; init; }
        public required string Description { get; init; }
        public required PortRisk Risk { get; init; }
        public string? Recommendation { get; init; }
        public string? Category { get; init; }
    }

    /// <summary>
    /// Lookup key combining port and transport protocol
    /// </summary>
    [SuppressMessage("Design", "CA1034:Nested types should not be visible",
        Justification = "PortKey is a public data structure tightly coupled to PortDatabase API")]
    public readonly record struct PortKey(ushort Port, TransportProtocol Transport);

    public enum TransportProtocol { TCP, UDP, Both }

    // Frozen dictionaries for maximum lookup performance
    private static readonly FrozenDictionary<PortKey, PortInfo> _portDatabase;
    private static readonly FrozenDictionary<ushort, PortInfo> _tcpPorts;
    private static readonly FrozenDictionary<ushort, PortInfo> _udpPorts;

    static PortDatabase()
    {
        var ports = new Dictionary<PortKey, PortInfo>();

        // ===========================================
        // ACTIVE DIRECTORY & AUTHENTICATION
        // ===========================================
        AddPort(ports, 88, TransportProtocol.Both, "Kerberos", "Kerberos authentication", PortRisk.Low, "AD", "Secure when properly configured");
        AddPort(ports, 464, TransportProtocol.Both, "Kerberos-Change", "Kerberos password change", PortRisk.Low, "AD");
        AddPort(ports, 389, TransportProtocol.Both, "LDAP", "Lightweight Directory Access Protocol", PortRisk.High, "AD", "Use LDAPS (636) instead");
        AddPort(ports, 636, TransportProtocol.Both, "LDAPS", "LDAP over SSL/TLS", PortRisk.Low, "AD", "Secure directory access");
        AddPort(ports, 3268, TransportProtocol.TCP, "LDAP-GC", "LDAP Global Catalog", PortRisk.High, "AD", "Use LDAPS-GC (3269)");
        AddPort(ports, 3269, TransportProtocol.TCP, "LDAPS-GC", "LDAP Global Catalog over SSL", PortRisk.Low, "AD");
        AddPort(ports, 445, TransportProtocol.TCP, "SMB", "Server Message Block", PortRisk.Medium, "AD", "Ensure SMBv3 with encryption");
        AddPort(ports, 139, TransportProtocol.TCP, "NetBIOS-SSN", "NetBIOS Session Service", PortRisk.High, "AD", "Legacy - use SMB direct (445)");
        AddPort(ports, 137, TransportProtocol.UDP, "NetBIOS-NS", "NetBIOS Name Service", PortRisk.Medium, "AD", "Disable if not needed");
        AddPort(ports, 138, TransportProtocol.UDP, "NetBIOS-DGM", "NetBIOS Datagram", PortRisk.Medium, "AD", "Disable if not needed");
        AddPort(ports, 135, TransportProtocol.TCP, "MS-RPC", "Microsoft RPC Endpoint Mapper", PortRisk.Medium, "AD", "Required for AD, firewall carefully");
        AddPort(ports, 593, TransportProtocol.TCP, "RPC-HTTP", "RPC over HTTP", PortRisk.Medium, "AD");
        AddPort(ports, 49152, TransportProtocol.TCP, "RPC-Dynamic", "RPC Dynamic Ports Start", PortRisk.Medium, "AD", "Configure fixed RPC port range");
        AddPort(ports, 65535, TransportProtocol.TCP, "RPC-Dynamic-End", "RPC Dynamic Ports End", PortRisk.Medium, "AD");

        // ===========================================
        // WEB SERVERS & PROXIES
        // ===========================================
        AddPort(ports, 80, TransportProtocol.TCP, "HTTP", "Hypertext Transfer Protocol", PortRisk.High, "Web", "Use HTTPS instead");
        AddPort(ports, 443, TransportProtocol.TCP, "HTTPS", "HTTP over TLS", PortRisk.Low, "Web", "Ensure TLS 1.2+");
        AddPort(ports, 8080, TransportProtocol.TCP, "HTTP-Alt", "HTTP Alternate/Proxy", PortRisk.High, "Web", "Common proxy port");
        AddPort(ports, 8443, TransportProtocol.TCP, "HTTPS-Alt", "HTTPS Alternate", PortRisk.Low, "Web");
        AddPort(ports, 8000, TransportProtocol.TCP, "HTTP-Alt-2", "HTTP Alternate (dev)", PortRisk.High, "Web");
        AddPort(ports, 8888, TransportProtocol.TCP, "HTTP-Proxy", "HTTP Proxy/Alt", PortRisk.High, "Web");
        AddPort(ports, 3128, TransportProtocol.TCP, "Squid", "Squid proxy", PortRisk.Medium, "Web");
        AddPort(ports, 8081, TransportProtocol.TCP, "HTTP-Proxy-Alt", "HTTP Proxy Alternate", PortRisk.High, "Web");
        AddPort(ports, 9443, TransportProtocol.TCP, "HTTPS-Alt-2", "HTTPS Alternate 2", PortRisk.Low, "Web");
        AddPort(ports, 81, TransportProtocol.TCP, "HTTP-Alt-3", "HTTP Alternate 3", PortRisk.High, "Web");
        AddPort(ports, 82, TransportProtocol.TCP, "HTTP-Alt-4", "HTTP Alternate 4", PortRisk.High, "Web");
        AddPort(ports, 8008, TransportProtocol.TCP, "HTTP-Alt-5", "HTTP Alternate 5", PortRisk.High, "Web");
        AddPort(ports, 8090, TransportProtocol.TCP, "HTTP-Alt-6", "HTTP Alternate 6", PortRisk.High, "Web");
        AddPort(ports, 9080, TransportProtocol.TCP, "HTTP-WebSphere", "WebSphere HTTP", PortRisk.High, "Web");
        AddPort(ports, 9443, TransportProtocol.TCP, "HTTPS-WebSphere", "WebSphere HTTPS", PortRisk.Low, "Web");

        // ===========================================
        // EMAIL PROTOCOLS
        // ===========================================
        AddPort(ports, 25, TransportProtocol.TCP, "SMTP", "Simple Mail Transfer Protocol", PortRisk.High, "Email", "Use STARTTLS or port 587");
        AddPort(ports, 465, TransportProtocol.TCP, "SMTPS", "SMTP over SSL (deprecated)", PortRisk.Low, "Email", "Implicit TLS");
        AddPort(ports, 587, TransportProtocol.TCP, "Submission", "Mail Submission (STARTTLS)", PortRisk.Low, "Email", "Recommended for client submission");
        AddPort(ports, 2525, TransportProtocol.TCP, "SMTP-Alt", "SMTP Alternate", PortRisk.High, "Email");
        AddPort(ports, 110, TransportProtocol.TCP, "POP3", "Post Office Protocol v3", PortRisk.High, "Email", "Use POP3S (995)");
        AddPort(ports, 995, TransportProtocol.TCP, "POP3S", "POP3 over SSL/TLS", PortRisk.Low, "Email");
        AddPort(ports, 143, TransportProtocol.TCP, "IMAP", "Internet Message Access Protocol", PortRisk.High, "Email", "Use IMAPS (993)");
        AddPort(ports, 993, TransportProtocol.TCP, "IMAPS", "IMAP over SSL/TLS", PortRisk.Low, "Email");
        AddPort(ports, 2095, TransportProtocol.TCP, "Webmail", "cPanel Webmail", PortRisk.High, "Email");
        AddPort(ports, 2096, TransportProtocol.TCP, "Webmail-SSL", "cPanel Webmail SSL", PortRisk.Low, "Email");

        // ===========================================
        // DNS & NAME RESOLUTION
        // ===========================================
        AddPort(ports, 53, TransportProtocol.Both, "DNS", "Domain Name System", PortRisk.Medium, "DNS", "Use DoT/DoH for privacy");
        AddPort(ports, 853, TransportProtocol.TCP, "DNS-over-TLS", "DNS over TLS (DoT)", PortRisk.Low, "DNS", "Encrypted DNS");
        AddPort(ports, 5353, TransportProtocol.UDP, "mDNS", "Multicast DNS", PortRisk.Medium, "DNS", "Local network only");
        AddPort(ports, 5355, TransportProtocol.UDP, "LLMNR", "Link-Local Multicast Name Resolution", PortRisk.Medium, "DNS", "Disable - Responder attacks");
        AddPort(ports, 137, TransportProtocol.UDP, "NBNS", "NetBIOS Name Service", PortRisk.Medium, "DNS", "Legacy name resolution");

        // ===========================================
        // FILE TRANSFER
        // ===========================================
        AddPort(ports, 20, TransportProtocol.TCP, "FTP-Data", "FTP Data Transfer", PortRisk.High, "FileTransfer", "Plaintext - use SFTP");
        AddPort(ports, 21, TransportProtocol.TCP, "FTP", "File Transfer Protocol", PortRisk.High, "FileTransfer", "Use SFTP/FTPS instead");
        AddPort(ports, 22, TransportProtocol.TCP, "SSH/SFTP", "Secure Shell / SFTP", PortRisk.Low, "FileTransfer", "Preferred file transfer");
        AddPort(ports, 69, TransportProtocol.UDP, "TFTP", "Trivial File Transfer Protocol", PortRisk.High, "FileTransfer", "No auth - internal use only");
        AddPort(ports, 989, TransportProtocol.TCP, "FTPS-Data", "FTP Data over TLS", PortRisk.Low, "FileTransfer");
        AddPort(ports, 990, TransportProtocol.TCP, "FTPS", "FTP Control over TLS", PortRisk.Low, "FileTransfer");
        AddPort(ports, 115, TransportProtocol.TCP, "SFTP-Legacy", "Simple File Transfer Protocol", PortRisk.High, "FileTransfer", "Legacy - not SSH SFTP");
        AddPort(ports, 2049, TransportProtocol.Both, "NFS", "Network File System", PortRisk.Medium, "FileTransfer", "Use NFSv4 with Kerberos");
        AddPort(ports, 111, TransportProtocol.Both, "RPCBind", "RPC Port Mapper", PortRisk.Medium, "FileTransfer", "Required for NFS");
        AddPort(ports, 548, TransportProtocol.TCP, "AFP", "Apple Filing Protocol", PortRisk.Medium, "FileTransfer", "Use SMB instead");
        AddPort(ports, 873, TransportProtocol.TCP, "Rsync", "Remote Sync", PortRisk.Medium, "FileTransfer", "Use SSH tunnel");

        // ===========================================
        // REMOTE ACCESS
        // ===========================================
        AddPort(ports, 22, TransportProtocol.TCP, "SSH", "Secure Shell", PortRisk.Low, "RemoteAccess", "Use key authentication");
        AddPort(ports, 23, TransportProtocol.TCP, "Telnet", "Telnet", PortRisk.Critical, "RemoteAccess", "NEVER use - replace with SSH");
        AddPort(ports, 3389, TransportProtocol.TCP, "RDP", "Remote Desktop Protocol", PortRisk.Medium, "RemoteAccess", "Enable NLA, use RD Gateway");
        AddPort(ports, 5900, TransportProtocol.TCP, "VNC", "Virtual Network Computing", PortRisk.High, "RemoteAccess", "Tunnel over SSH");
        AddPort(ports, 5901, TransportProtocol.TCP, "VNC-1", "VNC Display :1", PortRisk.High, "RemoteAccess");
        AddPort(ports, 5902, TransportProtocol.TCP, "VNC-2", "VNC Display :2", PortRisk.High, "RemoteAccess");
        AddPort(ports, 5903, TransportProtocol.TCP, "VNC-3", "VNC Display :3", PortRisk.High, "RemoteAccess");
        AddPort(ports, 5904, TransportProtocol.TCP, "VNC-4", "VNC Display :4", PortRisk.High, "RemoteAccess");
        AddPort(ports, 5800, TransportProtocol.TCP, "VNC-HTTP", "VNC over HTTP", PortRisk.High, "RemoteAccess");
        AddPort(ports, 513, TransportProtocol.TCP, "rlogin", "Remote Login", PortRisk.Critical, "RemoteAccess", "NEVER use - replace with SSH");
        AddPort(ports, 514, TransportProtocol.TCP, "rsh", "Remote Shell (TCP)", PortRisk.Critical, "RemoteAccess", "NEVER use - replace with SSH");
        AddPort(ports, 512, TransportProtocol.TCP, "rexec", "Remote Execution", PortRisk.Critical, "RemoteAccess", "NEVER use");
        AddPort(ports, 2222, TransportProtocol.TCP, "SSH-Alt", "SSH Alternate", PortRisk.Low, "RemoteAccess");
        AddPort(ports, 4000, TransportProtocol.TCP, "Remote-Anything", "Remote Anything", PortRisk.Medium, "RemoteAccess");
        AddPort(ports, 5631, TransportProtocol.TCP, "pcAnywhere-Data", "pcAnywhere Data", PortRisk.High, "RemoteAccess", "Deprecated");
        AddPort(ports, 5632, TransportProtocol.UDP, "pcAnywhere-Status", "pcAnywhere Status", PortRisk.High, "RemoteAccess");

        // ===========================================
        // DATABASES
        // ===========================================
        AddPort(ports, 1433, TransportProtocol.TCP, "MSSQL", "Microsoft SQL Server", PortRisk.Medium, "Database", "Use TLS encryption");
        AddPort(ports, 1434, TransportProtocol.UDP, "MSSQL-Browser", "SQL Server Browser", PortRisk.Medium, "Database", "Instance discovery");
        AddPort(ports, 3306, TransportProtocol.TCP, "MySQL", "MySQL/MariaDB", PortRisk.Medium, "Database", "Enable SSL/TLS");
        AddPort(ports, 5432, TransportProtocol.TCP, "PostgreSQL", "PostgreSQL", PortRisk.Medium, "Database", "Enable SSL");
        AddPort(ports, 1521, TransportProtocol.TCP, "Oracle", "Oracle Database", PortRisk.Medium, "Database", "Use TLS");
        AddPort(ports, 1526, TransportProtocol.TCP, "Oracle-Alt", "Oracle Alternate", PortRisk.Medium, "Database");
        AddPort(ports, 1527, TransportProtocol.TCP, "Derby", "Apache Derby", PortRisk.Medium, "Database");
        AddPort(ports, 27017, TransportProtocol.TCP, "MongoDB", "MongoDB", PortRisk.High, "Database", "Enable auth and TLS");
        AddPort(ports, 27018, TransportProtocol.TCP, "MongoDB-Shard", "MongoDB Shard Server", PortRisk.High, "Database");
        AddPort(ports, 27019, TransportProtocol.TCP, "MongoDB-Config", "MongoDB Config Server", PortRisk.High, "Database");
        AddPort(ports, 6379, TransportProtocol.TCP, "Redis", "Redis", PortRisk.High, "Database", "Enable AUTH, bind localhost");
        AddPort(ports, 6380, TransportProtocol.TCP, "Redis-TLS", "Redis with TLS", PortRisk.Low, "Database");
        AddPort(ports, 11211, TransportProtocol.Both, "Memcached", "Memcached", PortRisk.High, "Database", "Bind localhost only");
        AddPort(ports, 9042, TransportProtocol.TCP, "Cassandra", "Apache Cassandra CQL", PortRisk.Medium, "Database", "Use client-to-node encryption");
        AddPort(ports, 7000, TransportProtocol.TCP, "Cassandra-Cluster", "Cassandra Inter-node", PortRisk.Medium, "Database");
        AddPort(ports, 7199, TransportProtocol.TCP, "Cassandra-JMX", "Cassandra JMX", PortRisk.Medium, "Database");
        AddPort(ports, 9200, TransportProtocol.TCP, "Elasticsearch", "Elasticsearch HTTP", PortRisk.High, "Database", "Enable X-Pack security");
        AddPort(ports, 9300, TransportProtocol.TCP, "Elasticsearch-Transport", "Elasticsearch Transport", PortRisk.High, "Database");
        AddPort(ports, 5984, TransportProtocol.TCP, "CouchDB", "Apache CouchDB", PortRisk.Medium, "Database");
        AddPort(ports, 8529, TransportProtocol.TCP, "ArangoDB", "ArangoDB", PortRisk.Medium, "Database");
        AddPort(ports, 7474, TransportProtocol.TCP, "Neo4j-HTTP", "Neo4j HTTP", PortRisk.Medium, "Database");
        AddPort(ports, 7687, TransportProtocol.TCP, "Neo4j-Bolt", "Neo4j Bolt", PortRisk.Medium, "Database");
        AddPort(ports, 26257, TransportProtocol.TCP, "CockroachDB", "CockroachDB", PortRisk.Medium, "Database");
        AddPort(ports, 4369, TransportProtocol.TCP, "EPMD", "Erlang Port Mapper", PortRisk.Medium, "Database");
        AddPort(ports, 50000, TransportProtocol.TCP, "DB2", "IBM DB2", PortRisk.Medium, "Database");
        AddPort(ports, 50001, TransportProtocol.TCP, "DB2-Admin", "IBM DB2 Admin", PortRisk.Medium, "Database");
        AddPort(ports, 1526, TransportProtocol.TCP, "Informix", "IBM Informix", PortRisk.Medium, "Database");

        // ===========================================
        // MONITORING & MANAGEMENT
        // ===========================================
        AddPort(ports, 161, TransportProtocol.UDP, "SNMP", "Simple Network Management Protocol", PortRisk.High, "Management", "Use SNMPv3");
        AddPort(ports, 162, TransportProtocol.UDP, "SNMP-Trap", "SNMP Trap", PortRisk.High, "Management", "Use SNMPv3");
        AddPort(ports, 514, TransportProtocol.UDP, "Syslog", "Syslog", PortRisk.Medium, "Management", "Use Syslog over TLS");
        AddPort(ports, 6514, TransportProtocol.TCP, "Syslog-TLS", "Syslog over TLS", PortRisk.Low, "Management");
        AddPort(ports, 2055, TransportProtocol.UDP, "NetFlow", "Cisco NetFlow", PortRisk.Low, "Management");
        AddPort(ports, 4739, TransportProtocol.UDP, "IPFIX", "IP Flow Information Export", PortRisk.Low, "Management");
        AddPort(ports, 2056, TransportProtocol.UDP, "NetFlow-Alt", "NetFlow Alternate", PortRisk.Low, "Management");
        AddPort(ports, 9996, TransportProtocol.UDP, "sFlow", "sFlow", PortRisk.Low, "Management");
        AddPort(ports, 10050, TransportProtocol.TCP, "Zabbix-Agent", "Zabbix Agent", PortRisk.Medium, "Management");
        AddPort(ports, 10051, TransportProtocol.TCP, "Zabbix-Server", "Zabbix Server", PortRisk.Medium, "Management");
        AddPort(ports, 5666, TransportProtocol.TCP, "NRPE", "Nagios Remote Plugin", PortRisk.Medium, "Management", "Use NRPE with SSL");
        AddPort(ports, 12489, TransportProtocol.TCP, "NSClient++", "NSClient++", PortRisk.Medium, "Management");
        AddPort(ports, 8086, TransportProtocol.TCP, "InfluxDB", "InfluxDB HTTP", PortRisk.Medium, "Management");
        AddPort(ports, 3000, TransportProtocol.TCP, "Grafana", "Grafana", PortRisk.Medium, "Management");
        AddPort(ports, 9090, TransportProtocol.TCP, "Prometheus", "Prometheus", PortRisk.Medium, "Management");
        AddPort(ports, 9093, TransportProtocol.TCP, "Alertmanager", "Prometheus Alertmanager", PortRisk.Medium, "Management");
        AddPort(ports, 9100, TransportProtocol.TCP, "Node-Exporter", "Prometheus Node Exporter", PortRisk.Medium, "Management");
        AddPort(ports, 8500, TransportProtocol.TCP, "Consul", "HashiCorp Consul", PortRisk.Medium, "Management");
        AddPort(ports, 8300, TransportProtocol.TCP, "Consul-Server", "Consul Server RPC", PortRisk.Medium, "Management");
        AddPort(ports, 8301, TransportProtocol.Both, "Consul-LAN", "Consul LAN Gossip", PortRisk.Medium, "Management");
        AddPort(ports, 8302, TransportProtocol.Both, "Consul-WAN", "Consul WAN Gossip", PortRisk.Medium, "Management");

        // ===========================================
        // VOIP & UNIFIED COMMUNICATIONS
        // ===========================================
        AddPort(ports, 5060, TransportProtocol.Both, "SIP", "Session Initiation Protocol", PortRisk.Medium, "VoIP", "Use SIPS (5061)");
        AddPort(ports, 5061, TransportProtocol.Both, "SIPS", "SIP over TLS", PortRisk.Low, "VoIP");
        AddPort(ports, 5062, TransportProtocol.Both, "SIP-Alt", "SIP Alternate", PortRisk.Medium, "VoIP");
        AddPort(ports, 1719, TransportProtocol.UDP, "H.323-GK-RAS", "H.323 Gatekeeper RAS", PortRisk.Medium, "VoIP");
        AddPort(ports, 1720, TransportProtocol.TCP, "H.323", "H.323 Call Setup", PortRisk.Medium, "VoIP");
        AddPort(ports, 2000, TransportProtocol.TCP, "Cisco-SCCP", "Cisco Skinny", PortRisk.Medium, "VoIP");
        AddPort(ports, 2443, TransportProtocol.TCP, "Cisco-SCCP-TLS", "Cisco Skinny over TLS", PortRisk.Low, "VoIP");
        AddPort(ports, 4569, TransportProtocol.UDP, "IAX2", "Inter-Asterisk eXchange", PortRisk.Medium, "VoIP");
        AddPort(ports, 5004, TransportProtocol.UDP, "RTP", "Real-time Transport Protocol", PortRisk.Medium, "VoIP", "Use SRTP");
        AddPort(ports, 5005, TransportProtocol.UDP, "RTCP", "RTP Control Protocol", PortRisk.Medium, "VoIP");
        // RTP dynamic range (16384-32767 commonly used)
        AddPort(ports, 16384, TransportProtocol.UDP, "RTP-Low", "RTP Dynamic Range Start", PortRisk.Medium, "VoIP");
        AddPort(ports, 32767, TransportProtocol.UDP, "RTP-High", "RTP Dynamic Range End", PortRisk.Medium, "VoIP");
        AddPort(ports, 1935, TransportProtocol.TCP, "RTMP", "Real-Time Messaging Protocol", PortRisk.Medium, "VoIP");
        AddPort(ports, 554, TransportProtocol.TCP, "RTSP", "Real Time Streaming Protocol", PortRisk.Medium, "VoIP");
        AddPort(ports, 8554, TransportProtocol.TCP, "RTSP-Alt", "RTSP Alternate", PortRisk.Medium, "VoIP");

        // ===========================================
        // VPN & TUNNELING
        // ===========================================
        AddPort(ports, 500, TransportProtocol.UDP, "IKE", "Internet Key Exchange (IPSec)", PortRisk.Low, "VPN");
        AddPort(ports, 4500, TransportProtocol.UDP, "IPSec-NAT-T", "IPSec NAT Traversal", PortRisk.Low, "VPN");
        AddPort(ports, 1701, TransportProtocol.UDP, "L2TP", "Layer 2 Tunneling Protocol", PortRisk.Medium, "VPN", "Use with IPSec");
        AddPort(ports, 1723, TransportProtocol.TCP, "PPTP", "Point-to-Point Tunneling", PortRisk.Critical, "VPN", "NEVER use - broken encryption");
        AddPort(ports, 1194, TransportProtocol.Both, "OpenVPN", "OpenVPN", PortRisk.Low, "VPN");
        AddPort(ports, 51820, TransportProtocol.UDP, "WireGuard", "WireGuard VPN", PortRisk.Low, "VPN", "Modern secure VPN");
        AddPort(ports, 443, TransportProtocol.TCP, "SSTP", "Secure Socket Tunneling", PortRisk.Low, "VPN");
        AddPort(ports, 4443, TransportProtocol.TCP, "Cisco-AnyConnect", "Cisco AnyConnect SSL", PortRisk.Low, "VPN");
        AddPort(ports, 10443, TransportProtocol.TCP, "GlobalProtect", "Palo Alto GlobalProtect", PortRisk.Low, "VPN");

        // ===========================================
        // AUTHENTICATION & RADIUS
        // ===========================================
        AddPort(ports, 1812, TransportProtocol.UDP, "RADIUS-Auth", "RADIUS Authentication", PortRisk.Medium, "Auth", "Use RadSec");
        AddPort(ports, 1813, TransportProtocol.UDP, "RADIUS-Acct", "RADIUS Accounting", PortRisk.Medium, "Auth");
        AddPort(ports, 2083, TransportProtocol.TCP, "RadSec", "RADIUS over TLS", PortRisk.Low, "Auth");
        AddPort(ports, 49, TransportProtocol.TCP, "TACACS+", "TACACS+", PortRisk.Medium, "Auth", "Encrypts payload");
        AddPort(ports, 1645, TransportProtocol.UDP, "RADIUS-Old-Auth", "RADIUS Auth (old)", PortRisk.Medium, "Auth");
        AddPort(ports, 1646, TransportProtocol.UDP, "RADIUS-Old-Acct", "RADIUS Acct (old)", PortRisk.Medium, "Auth");

        // ===========================================
        // TIME SERVICES
        // ===========================================
        AddPort(ports, 123, TransportProtocol.UDP, "NTP", "Network Time Protocol", PortRisk.Low, "Time", "Use NTP authentication");
        AddPort(ports, 37, TransportProtocol.Both, "Time", "Time Protocol (legacy)", PortRisk.Medium, "Time", "Use NTP instead");
        AddPort(ports, 4460, TransportProtocol.TCP, "NTS-KE", "NTS Key Establishment", PortRisk.Low, "Time", "NTP with TLS");

        // ===========================================
        // DHCP & NETWORK SERVICES
        // ===========================================
        AddPort(ports, 67, TransportProtocol.UDP, "DHCP-Server", "DHCP Server", PortRisk.Medium, "Network", "Enable DHCP snooping");
        AddPort(ports, 68, TransportProtocol.UDP, "DHCP-Client", "DHCP Client", PortRisk.Medium, "Network");
        AddPort(ports, 546, TransportProtocol.UDP, "DHCPv6-Client", "DHCPv6 Client", PortRisk.Medium, "Network");
        AddPort(ports, 547, TransportProtocol.UDP, "DHCPv6-Server", "DHCPv6 Server", PortRisk.Medium, "Network");

        // ===========================================
        // MESSAGING & QUEUES
        // ===========================================
        AddPort(ports, 5672, TransportProtocol.TCP, "AMQP", "Advanced Message Queue Protocol", PortRisk.Medium, "Messaging", "Use TLS");
        AddPort(ports, 5671, TransportProtocol.TCP, "AMQPS", "AMQP over TLS", PortRisk.Low, "Messaging");
        AddPort(ports, 61613, TransportProtocol.TCP, "STOMP", "Streaming Text Oriented Messaging", PortRisk.Medium, "Messaging");
        AddPort(ports, 61614, TransportProtocol.TCP, "STOMP-TLS", "STOMP over TLS", PortRisk.Low, "Messaging");
        AddPort(ports, 1883, TransportProtocol.TCP, "MQTT", "Message Queuing Telemetry Transport", PortRisk.High, "Messaging", "Use port 8883 with TLS");
        AddPort(ports, 8883, TransportProtocol.TCP, "MQTTS", "MQTT over TLS", PortRisk.Low, "Messaging");
        AddPort(ports, 9092, TransportProtocol.TCP, "Kafka", "Apache Kafka", PortRisk.Medium, "Messaging", "Enable SASL and TLS");
        AddPort(ports, 9093, TransportProtocol.TCP, "Kafka-TLS", "Kafka with TLS", PortRisk.Low, "Messaging");
        AddPort(ports, 2181, TransportProtocol.TCP, "ZooKeeper", "Apache ZooKeeper", PortRisk.Medium, "Messaging", "Use SASL auth");
        AddPort(ports, 2888, TransportProtocol.TCP, "ZooKeeper-Peer", "ZooKeeper Peer", PortRisk.Medium, "Messaging");
        AddPort(ports, 3888, TransportProtocol.TCP, "ZooKeeper-Election", "ZooKeeper Election", PortRisk.Medium, "Messaging");
        AddPort(ports, 15672, TransportProtocol.TCP, "RabbitMQ-Mgmt", "RabbitMQ Management", PortRisk.Medium, "Messaging");
        AddPort(ports, 6650, TransportProtocol.TCP, "Pulsar", "Apache Pulsar", PortRisk.Medium, "Messaging");
        AddPort(ports, 6651, TransportProtocol.TCP, "Pulsar-TLS", "Apache Pulsar TLS", PortRisk.Low, "Messaging");

        // ===========================================
        // CONTAINERS & ORCHESTRATION
        // ===========================================
        AddPort(ports, 2375, TransportProtocol.TCP, "Docker", "Docker API (unencrypted)", PortRisk.Critical, "Container", "NEVER expose - use 2376");
        AddPort(ports, 2376, TransportProtocol.TCP, "Docker-TLS", "Docker API with TLS", PortRisk.Low, "Container");
        AddPort(ports, 2377, TransportProtocol.TCP, "Docker-Swarm", "Docker Swarm Management", PortRisk.Medium, "Container");
        AddPort(ports, 4789, TransportProtocol.UDP, "VXLAN", "Docker Overlay VXLAN", PortRisk.Medium, "Container");
        AddPort(ports, 7946, TransportProtocol.Both, "Docker-Gossip", "Docker Swarm Gossip", PortRisk.Medium, "Container");
        AddPort(ports, 6443, TransportProtocol.TCP, "Kubernetes-API", "Kubernetes API Server", PortRisk.Medium, "Container", "Use RBAC");
        AddPort(ports, 10250, TransportProtocol.TCP, "Kubelet", "Kubernetes Kubelet", PortRisk.Medium, "Container");
        AddPort(ports, 10251, TransportProtocol.TCP, "Kube-Scheduler", "Kubernetes Scheduler", PortRisk.Medium, "Container");
        AddPort(ports, 10252, TransportProtocol.TCP, "Kube-Controller", "Kubernetes Controller Manager", PortRisk.Medium, "Container");
        AddPort(ports, 10255, TransportProtocol.TCP, "Kubelet-RO", "Kubelet Read-Only", PortRisk.High, "Container", "Disable in production");
        AddPort(ports, 30000, TransportProtocol.TCP, "K8s-NodePort-Start", "Kubernetes NodePort Range Start", PortRisk.Medium, "Container");
        AddPort(ports, 32767, TransportProtocol.TCP, "K8s-NodePort-End", "Kubernetes NodePort Range End", PortRisk.Medium, "Container");
        AddPort(ports, 2379, TransportProtocol.TCP, "etcd-Client", "etcd Client", PortRisk.High, "Container", "Enable auth and TLS");
        AddPort(ports, 2380, TransportProtocol.TCP, "etcd-Peer", "etcd Peer", PortRisk.High, "Container");
        AddPort(ports, 5000, TransportProtocol.TCP, "Registry", "Container Registry", PortRisk.Medium, "Container");
        AddPort(ports, 8472, TransportProtocol.UDP, "Flannel-VXLAN", "Flannel VXLAN", PortRisk.Medium, "Container");

        // ===========================================
        // CI/CD & DEVOPS
        // ===========================================
        AddPort(ports, 8080, TransportProtocol.TCP, "Jenkins", "Jenkins CI", PortRisk.Medium, "DevOps", "Use reverse proxy with TLS");
        AddPort(ports, 50000, TransportProtocol.TCP, "Jenkins-Agent", "Jenkins Agent", PortRisk.Medium, "DevOps");
        AddPort(ports, 9418, TransportProtocol.TCP, "Git", "Git Protocol", PortRisk.Medium, "DevOps", "Use SSH or HTTPS");
        AddPort(ports, 7990, TransportProtocol.TCP, "Bitbucket", "Atlassian Bitbucket", PortRisk.Medium, "DevOps");
        AddPort(ports, 80, TransportProtocol.TCP, "GitLab-HTTP", "GitLab HTTP", PortRisk.High, "DevOps");
        AddPort(ports, 8929, TransportProtocol.TCP, "GitLab-Mattermost", "GitLab Mattermost", PortRisk.Medium, "DevOps");
        AddPort(ports, 4040, TransportProtocol.TCP, "Puppet", "Puppet Agent", PortRisk.Medium, "DevOps");
        AddPort(ports, 8140, TransportProtocol.TCP, "Puppet-Master", "Puppet Master", PortRisk.Medium, "DevOps");
        AddPort(ports, 4505, TransportProtocol.TCP, "SaltStack-Pub", "SaltStack Publisher", PortRisk.Medium, "DevOps");
        AddPort(ports, 4506, TransportProtocol.TCP, "SaltStack-Ret", "SaltStack Return", PortRisk.Medium, "DevOps");
        AddPort(ports, 8200, TransportProtocol.TCP, "Vault", "HashiCorp Vault", PortRisk.Low, "DevOps", "Secrets management");
        AddPort(ports, 4646, TransportProtocol.TCP, "Nomad", "HashiCorp Nomad", PortRisk.Medium, "DevOps");
        AddPort(ports, 4647, TransportProtocol.TCP, "Nomad-RPC", "Nomad RPC", PortRisk.Medium, "DevOps");
        AddPort(ports, 4648, TransportProtocol.Both, "Nomad-Serf", "Nomad Serf", PortRisk.Medium, "DevOps");

        // ===========================================
        // PRINTING
        // ===========================================
        AddPort(ports, 515, TransportProtocol.TCP, "LPD", "Line Printer Daemon", PortRisk.Medium, "Printing");
        AddPort(ports, 631, TransportProtocol.Both, "IPP", "Internet Printing Protocol", PortRisk.Medium, "Printing");
        AddPort(ports, 9100, TransportProtocol.TCP, "JetDirect", "HP JetDirect", PortRisk.Medium, "Printing");
        AddPort(ports, 9101, TransportProtocol.TCP, "JetDirect-1", "HP JetDirect Alt", PortRisk.Medium, "Printing");
        AddPort(ports, 9102, TransportProtocol.TCP, "JetDirect-2", "HP JetDirect Alt 2", PortRisk.Medium, "Printing");

        // ===========================================
        // INDUSTRIAL / SCADA / ICS
        // ===========================================
        AddPort(ports, 502, TransportProtocol.TCP, "Modbus", "Modbus TCP", PortRisk.High, "Industrial", "Isolate from IT network");
        AddPort(ports, 102, TransportProtocol.TCP, "S7comm", "Siemens S7 Communication", PortRisk.High, "Industrial");
        AddPort(ports, 44818, TransportProtocol.TCP, "EtherNet/IP", "EtherNet/IP (CIP)", PortRisk.High, "Industrial");
        AddPort(ports, 2222, TransportProtocol.UDP, "EtherNet/IP-IO", "EtherNet/IP I/O", PortRisk.High, "Industrial");
        AddPort(ports, 20000, TransportProtocol.TCP, "DNP3", "Distributed Network Protocol 3", PortRisk.High, "Industrial");
        AddPort(ports, 47808, TransportProtocol.UDP, "BACnet", "Building Automation and Control", PortRisk.High, "Industrial");
        AddPort(ports, 1911, TransportProtocol.TCP, "Niagara-Fox", "Niagara Fox Protocol", PortRisk.High, "Industrial");
        AddPort(ports, 4911, TransportProtocol.TCP, "Niagara-Fox-TLS", "Niagara Fox TLS", PortRisk.Medium, "Industrial");
        AddPort(ports, 18245, TransportProtocol.TCP, "GE-SRTP", "GE SRTP", PortRisk.High, "Industrial");
        AddPort(ports, 2404, TransportProtocol.TCP, "IEC-60870-5-104", "IEC 60870-5-104", PortRisk.High, "Industrial");
        AddPort(ports, 4840, TransportProtocol.TCP, "OPC-UA", "OPC Unified Architecture", PortRisk.Medium, "Industrial");
        AddPort(ports, 4843, TransportProtocol.TCP, "OPC-UA-TLS", "OPC UA with TLS", PortRisk.Low, "Industrial");

        // ===========================================
        // GAMING & STREAMING (Enterprise may see these)
        // ===========================================
        AddPort(ports, 3478, TransportProtocol.Both, "STUN/TURN", "STUN/TURN (WebRTC)", PortRisk.Low, "Media");
        AddPort(ports, 3479, TransportProtocol.Both, "STUN-Alt", "STUN Alternate", PortRisk.Low, "Media");
        AddPort(ports, 5349, TransportProtocol.Both, "STUN-TLS", "STUN over TLS", PortRisk.Low, "Media");
        AddPort(ports, 19302, TransportProtocol.UDP, "Google-STUN", "Google STUN Server", PortRisk.Low, "Media");

        // ===========================================
        // MICROSOFT SERVICES
        // ===========================================
        AddPort(ports, 1688, TransportProtocol.TCP, "KMS", "Windows Key Management Service", PortRisk.Low, "Microsoft");
        AddPort(ports, 3343, TransportProtocol.UDP, "MS-Cluster", "Microsoft Cluster Service", PortRisk.Medium, "Microsoft");
        AddPort(ports, 5985, TransportProtocol.TCP, "WinRM-HTTP", "Windows Remote Management", PortRisk.Medium, "Microsoft", "Use port 5986");
        AddPort(ports, 5986, TransportProtocol.TCP, "WinRM-HTTPS", "Windows Remote Management HTTPS", PortRisk.Low, "Microsoft");
        AddPort(ports, 5723, TransportProtocol.TCP, "SCOM", "System Center Operations Manager", PortRisk.Medium, "Microsoft");
        AddPort(ports, 8530, TransportProtocol.TCP, "WSUS-HTTP", "Windows Server Update Services", PortRisk.Medium, "Microsoft");
        AddPort(ports, 8531, TransportProtocol.TCP, "WSUS-HTTPS", "WSUS HTTPS", PortRisk.Low, "Microsoft");
        AddPort(ports, 25443, TransportProtocol.TCP, "SharePoint-HTTPS", "SharePoint HTTPS", PortRisk.Low, "Microsoft");

        // ===========================================
        // MICROSOFT EXCHANGE
        // ===========================================
        AddPort(ports, 135, TransportProtocol.TCP, "Exchange-RPC", "Exchange RPC", PortRisk.Medium, "Exchange");
        AddPort(ports, 443, TransportProtocol.TCP, "Exchange-HTTPS", "Exchange HTTPS/OWA", PortRisk.Low, "Exchange");
        AddPort(ports, 25, TransportProtocol.TCP, "Exchange-SMTP", "Exchange SMTP", PortRisk.High, "Exchange");
        AddPort(ports, 587, TransportProtocol.TCP, "Exchange-Submit", "Exchange Submission", PortRisk.Low, "Exchange");

        // ===========================================
        // LDAP/DIRECTORY SERVICES (expanded)
        // ===========================================
        AddPort(ports, 1636, TransportProtocol.TCP, "eDir-LDAPS", "Novell eDirectory LDAPS", PortRisk.Low, "Directory");
        AddPort(ports, 524, TransportProtocol.TCP, "NCP", "NetWare Core Protocol", PortRisk.Medium, "Directory");

        // ===========================================
        // SECURITY TOOLS & SCANNERS
        // ===========================================
        AddPort(ports, 9390, TransportProtocol.TCP, "OpenVAS-Manager", "OpenVAS Manager", PortRisk.Medium, "Security");
        AddPort(ports, 9391, TransportProtocol.TCP, "OpenVAS-Scanner", "OpenVAS Scanner", PortRisk.Medium, "Security");
        AddPort(ports, 9392, TransportProtocol.TCP, "OpenVAS-GSA", "OpenVAS Greenbone", PortRisk.Medium, "Security");
        AddPort(ports, 8834, TransportProtocol.TCP, "Nessus", "Nessus Scanner", PortRisk.Medium, "Security");
        AddPort(ports, 5000, TransportProtocol.TCP, "Splunk-Management", "Splunk Management", PortRisk.Medium, "Security");
        AddPort(ports, 8000, TransportProtocol.TCP, "Splunk-Web", "Splunk Web Interface", PortRisk.Medium, "Security");
        AddPort(ports, 8089, TransportProtocol.TCP, "Splunk-API", "Splunk REST API", PortRisk.Medium, "Security");
        AddPort(ports, 9997, TransportProtocol.TCP, "Splunk-Forward", "Splunk Forwarder", PortRisk.Medium, "Security");
        AddPort(ports, 514, TransportProtocol.TCP, "Splunk-Syslog", "Splunk Syslog", PortRisk.Medium, "Security");
        AddPort(ports, 5601, TransportProtocol.TCP, "Kibana", "Kibana", PortRisk.Medium, "Security");
        AddPort(ports, 1514, TransportProtocol.TCP, "Wazuh-Agent", "Wazuh Agent", PortRisk.Medium, "Security");
        AddPort(ports, 1515, TransportProtocol.TCP, "Wazuh-Register", "Wazuh Registration", PortRisk.Medium, "Security");
        AddPort(ports, 55000, TransportProtocol.TCP, "Wazuh-API", "Wazuh API", PortRisk.Medium, "Security");

        // ===========================================
        // BACKUP & STORAGE
        // ===========================================
        AddPort(ports, 3260, TransportProtocol.TCP, "iSCSI", "Internet SCSI", PortRisk.Medium, "Storage", "Use CHAP auth and IPSec");
        AddPort(ports, 3205, TransportProtocol.TCP, "iSCSI-Target", "iSCSI Target", PortRisk.Medium, "Storage");
        AddPort(ports, 9000, TransportProtocol.TCP, "MinIO", "MinIO Object Storage", PortRisk.Medium, "Storage");
        AddPort(ports, 9001, TransportProtocol.TCP, "MinIO-Console", "MinIO Console", PortRisk.Medium, "Storage");
        AddPort(ports, 6660, TransportProtocol.TCP, "Bacula-Dir", "Bacula Director", PortRisk.Medium, "Backup");
        AddPort(ports, 6661, TransportProtocol.TCP, "Bacula-FD", "Bacula File Daemon", PortRisk.Medium, "Backup");
        AddPort(ports, 6662, TransportProtocol.TCP, "Bacula-SD", "Bacula Storage Daemon", PortRisk.Medium, "Backup");
        AddPort(ports, 10000, TransportProtocol.TCP, "Veritas-Netbackup", "Veritas NetBackup", PortRisk.Medium, "Backup");
        AddPort(ports, 13720, TransportProtocol.TCP, "Veritas-BP-VNETD", "NetBackup VNETD", PortRisk.Medium, "Backup");
        AddPort(ports, 13782, TransportProtocol.TCP, "Veritas-BP-BPCD", "NetBackup BPCD", PortRisk.Medium, "Backup");
        AddPort(ports, 8192, TransportProtocol.TCP, "Veeam-VBR", "Veeam Backup & Replication", PortRisk.Medium, "Backup");
        AddPort(ports, 9392, TransportProtocol.TCP, "Veeam-Agent", "Veeam Agent", PortRisk.Medium, "Backup");

        // ===========================================
        // CLOUD PROVIDER SERVICES
        // ===========================================
        AddPort(ports, 443, TransportProtocol.TCP, "AWS-API", "AWS API Endpoints", PortRisk.Low, "Cloud");
        AddPort(ports, 443, TransportProtocol.TCP, "Azure-API", "Azure API Endpoints", PortRisk.Low, "Cloud");
        AddPort(ports, 443, TransportProtocol.TCP, "GCP-API", "Google Cloud API", PortRisk.Low, "Cloud");

        // ===========================================
        // PROXY & LOAD BALANCING
        // ===========================================
        AddPort(ports, 1080, TransportProtocol.TCP, "SOCKS", "SOCKS Proxy", PortRisk.Medium, "Proxy");
        AddPort(ports, 8118, TransportProtocol.TCP, "Privoxy", "Privoxy HTTP Proxy", PortRisk.Medium, "Proxy");
        AddPort(ports, 9050, TransportProtocol.TCP, "Tor-SOCKS", "Tor SOCKS Proxy", PortRisk.Medium, "Proxy");
        AddPort(ports, 9051, TransportProtocol.TCP, "Tor-Control", "Tor Control Port", PortRisk.Medium, "Proxy");
        AddPort(ports, 8001, TransportProtocol.TCP, "HTTP-Proxy-Cache", "HTTP Proxy Cache", PortRisk.Medium, "Proxy");
        AddPort(ports, 3130, TransportProtocol.TCP, "Squid-ICP", "Squid ICP", PortRisk.Medium, "Proxy");

        // ===========================================
        // LEGACY & DEPRECATED (commonly seen in enterprise)
        // ===========================================
        AddPort(ports, 79, TransportProtocol.TCP, "Finger", "Finger Protocol", PortRisk.High, "Legacy", "Disable - information disclosure");
        AddPort(ports, 70, TransportProtocol.TCP, "Gopher", "Gopher Protocol", PortRisk.High, "Legacy", "Obsolete");
        AddPort(ports, 7, TransportProtocol.Both, "Echo", "Echo Protocol", PortRisk.Medium, "Legacy");
        AddPort(ports, 9, TransportProtocol.Both, "Discard", "Discard Protocol", PortRisk.Medium, "Legacy");
        AddPort(ports, 13, TransportProtocol.Both, "Daytime", "Daytime Protocol", PortRisk.Medium, "Legacy", "Use NTP");
        AddPort(ports, 17, TransportProtocol.Both, "QOTD", "Quote of the Day", PortRisk.Low, "Legacy");
        AddPort(ports, 19, TransportProtocol.Both, "Chargen", "Character Generator", PortRisk.High, "Legacy", "DoS amplification");

        // ===========================================
        // X11 & DISPLAY PROTOCOLS
        // ===========================================
        AddPort(ports, 6000, TransportProtocol.TCP, "X11", "X Window System", PortRisk.Medium, "Display", "Tunnel over SSH");
        AddPort(ports, 6001, TransportProtocol.TCP, "X11-1", "X11 Display :1", PortRisk.Medium, "Display");
        AddPort(ports, 6002, TransportProtocol.TCP, "X11-2", "X11 Display :2", PortRisk.Medium, "Display");
        AddPort(ports, 6003, TransportProtocol.TCP, "X11-3", "X11 Display :3", PortRisk.Medium, "Display");
        AddPort(ports, 177, TransportProtocol.UDP, "XDMCP", "X Display Manager Control", PortRisk.High, "Display", "Disable");

        // ===========================================
        // ADDITIONAL COMMON ENTERPRISE PORTS
        // ===========================================
        AddPort(ports, 113, TransportProtocol.TCP, "Ident", "Identification Protocol", PortRisk.Medium, "Network");
        AddPort(ports, 179, TransportProtocol.TCP, "BGP", "Border Gateway Protocol", PortRisk.Medium, "Network", "Internal routing only");
        AddPort(ports, 427, TransportProtocol.Both, "SLP", "Service Location Protocol", PortRisk.Medium, "Network");
        AddPort(ports, 500, TransportProtocol.UDP, "ISAKMP", "IKE/ISAKMP", PortRisk.Low, "Network");
        AddPort(ports, 520, TransportProtocol.UDP, "RIP", "Routing Information Protocol", PortRisk.Medium, "Network");
        AddPort(ports, 521, TransportProtocol.UDP, "RIPng", "RIP Next Generation (IPv6)", PortRisk.Medium, "Network");
        AddPort(ports, 646, TransportProtocol.Both, "LDP", "Label Distribution Protocol", PortRisk.Medium, "Network");
        AddPort(ports, 830, TransportProtocol.TCP, "NETCONF", "Network Configuration Protocol", PortRisk.Medium, "Network");
        AddPort(ports, 1812, TransportProtocol.UDP, "RADIUS", "RADIUS Authentication", PortRisk.Medium, "Network");
        AddPort(ports, 1900, TransportProtocol.UDP, "SSDP", "Simple Service Discovery", PortRisk.Medium, "Network", "Disable on internet-facing");
        AddPort(ports, 2049, TransportProtocol.Both, "NFS", "Network File System", PortRisk.Medium, "Network");
        AddPort(ports, 3535, TransportProtocol.TCP, "SMTP-Alt", "SMTP Alternate", PortRisk.High, "Network");
        AddPort(ports, 4443, TransportProtocol.TCP, "HTTPS-Alt", "HTTPS Alternate", PortRisk.Low, "Network");
        AddPort(ports, 5353, TransportProtocol.UDP, "mDNS", "Multicast DNS", PortRisk.Medium, "Network");
        AddPort(ports, 5432, TransportProtocol.TCP, "PostgreSQL", "PostgreSQL Database", PortRisk.Medium, "Network");
        AddPort(ports, 6633, TransportProtocol.TCP, "OpenFlow", "OpenFlow SDN", PortRisk.Medium, "Network");
        AddPort(ports, 6653, TransportProtocol.TCP, "OpenFlow-IANA", "OpenFlow (IANA)", PortRisk.Medium, "Network");
        AddPort(ports, 8000, TransportProtocol.TCP, "HTTP-Alt", "HTTP Alternate", PortRisk.High, "Network");
        AddPort(ports, 8443, TransportProtocol.TCP, "HTTPS-Alt", "HTTPS Alternate", PortRisk.Low, "Network");

        // ===========================================
        // CITRIX
        // ===========================================
        AddPort(ports, 1494, TransportProtocol.Both, "Citrix-ICA", "Citrix ICA Protocol", PortRisk.Medium, "Citrix", "Use SSL/TLS with NetScaler");
        AddPort(ports, 2598, TransportProtocol.Both, "Citrix-CGP", "Citrix CGP (Session Reliability)", PortRisk.Medium, "Citrix", "Session reliability/reconnect");
        AddPort(ports, 2512, TransportProtocol.TCP, "Citrix-Admin", "Citrix Management Console", PortRisk.Medium, "Citrix");
        AddPort(ports, 2513, TransportProtocol.TCP, "Citrix-SMA", "Citrix SMA Service", PortRisk.Medium, "Citrix");
        AddPort(ports, 2071, TransportProtocol.TCP, "Citrix-ADF", "Citrix ADF Service", PortRisk.Medium, "Citrix");
        AddPort(ports, 80, TransportProtocol.TCP, "Citrix-StoreFront", "Citrix StoreFront HTTP", PortRisk.High, "Citrix");
        AddPort(ports, 443, TransportProtocol.TCP, "Citrix-NetScaler", "Citrix NetScaler Gateway", PortRisk.Low, "Citrix");
        AddPort(ports, 8008, TransportProtocol.TCP, "Citrix-XenApp", "Citrix XenApp Services", PortRisk.Medium, "Citrix");
        AddPort(ports, 27000, TransportProtocol.TCP, "Citrix-License", "Citrix License Server", PortRisk.Medium, "Citrix");
        AddPort(ports, 7279, TransportProtocol.TCP, "Citrix-License-Vendor", "Citrix License Vendor Daemon", PortRisk.Medium, "Citrix");
        AddPort(ports, 8082, TransportProtocol.TCP, "Citrix-License-Web", "Citrix License Web Interface", PortRisk.Medium, "Citrix");
        AddPort(ports, 8083, TransportProtocol.TCP, "Citrix-License-WS", "Citrix License Web Service", PortRisk.Medium, "Citrix");
        AddPort(ports, 9028, TransportProtocol.TCP, "Citrix-WEM", "Citrix WEM Infrastructure", PortRisk.Medium, "Citrix");

        // ===========================================
        // MICROSOFT TEAMS / SKYPE FOR BUSINESS
        // ===========================================
        AddPort(ports, 3478, TransportProtocol.UDP, "Teams-STUN", "MS Teams STUN/TURN", PortRisk.Low, "Teams");
        AddPort(ports, 3479, TransportProtocol.UDP, "Teams-Audio", "MS Teams Audio", PortRisk.Low, "Teams");
        AddPort(ports, 3480, TransportProtocol.UDP, "Teams-Video", "MS Teams Video", PortRisk.Low, "Teams");
        AddPort(ports, 3481, TransportProtocol.UDP, "Teams-Sharing", "MS Teams Screen Sharing", PortRisk.Low, "Teams");
        // Teams UDP media range
        AddPort(ports, 50000, TransportProtocol.UDP, "Teams-Media-Low", "MS Teams Media Range Start", PortRisk.Low, "Teams");
        AddPort(ports, 50019, TransportProtocol.UDP, "Teams-Media-High", "MS Teams Media Range End", PortRisk.Low, "Teams");
        AddPort(ports, 443, TransportProtocol.TCP, "Teams-Signaling", "MS Teams Signaling", PortRisk.Low, "Teams");
        AddPort(ports, 5061, TransportProtocol.TCP, "Skype-SIP-TLS", "Skype for Business SIP TLS", PortRisk.Low, "Teams");
        AddPort(ports, 444, TransportProtocol.TCP, "Skype-Certs", "Skype for Business Certificates", PortRisk.Low, "Teams");
        AddPort(ports, 5063, TransportProtocol.TCP, "Skype-SIP-MTLS", "Skype for Business SIP MTLS", PortRisk.Low, "Teams");
        AddPort(ports, 5064, TransportProtocol.TCP, "Skype-Internal", "Skype for Business Internal", PortRisk.Medium, "Teams");
        AddPort(ports, 5065, TransportProtocol.TCP, "Skype-External", "Skype for Business External", PortRisk.Medium, "Teams");
        AddPort(ports, 5066, TransportProtocol.TCP, "Skype-Focus", "Skype for Business Focus", PortRisk.Medium, "Teams");
        AddPort(ports, 5067, TransportProtocol.TCP, "Skype-SRTP", "Skype for Business SRTP", PortRisk.Low, "Teams");
        AddPort(ports, 5068, TransportProtocol.TCP, "Skype-SRTP-Video", "Skype for Business Video SRTP", PortRisk.Low, "Teams");
        AddPort(ports, 5070, TransportProtocol.TCP, "Skype-CAA", "Skype for Business CAA", PortRisk.Medium, "Teams");
        AddPort(ports, 5071, TransportProtocol.TCP, "Skype-Autodiscover", "Skype for Business Autodiscover", PortRisk.Medium, "Teams");
        AddPort(ports, 57501, TransportProtocol.TCP, "Skype-Apps-Share", "Skype for Business App Sharing", PortRisk.Medium, "Teams");

        // ===========================================
        // ZOOM VIDEO CONFERENCING
        // ===========================================
        AddPort(ports, 8801, TransportProtocol.UDP, "Zoom-Media-1", "Zoom Media UDP", PortRisk.Low, "Zoom");
        AddPort(ports, 8802, TransportProtocol.UDP, "Zoom-Media-2", "Zoom Media UDP Alt", PortRisk.Low, "Zoom");
        AddPort(ports, 8803, TransportProtocol.TCP, "Zoom-Media-TCP", "Zoom Media TCP Fallback", PortRisk.Low, "Zoom");
        AddPort(ports, 9000, TransportProtocol.UDP, "Zoom-QoS", "Zoom QoS/Media", PortRisk.Low, "Zoom");
        AddPort(ports, 443, TransportProtocol.TCP, "Zoom-HTTPS", "Zoom HTTPS Signaling", PortRisk.Low, "Zoom");
        AddPort(ports, 5090, TransportProtocol.TCP, "Zoom-H323", "Zoom H.323 ALT", PortRisk.Medium, "Zoom");
        AddPort(ports, 5091, TransportProtocol.TCP, "Zoom-H323-TLS", "Zoom H.323 TLS", PortRisk.Low, "Zoom");

        // ===========================================
        // CISCO WEBEX
        // ===========================================
        AddPort(ports, 9000, TransportProtocol.UDP, "Webex-Media", "Cisco Webex Media", PortRisk.Low, "Webex");
        AddPort(ports, 5004, TransportProtocol.UDP, "Webex-RTP", "Webex RTP Media", PortRisk.Medium, "Webex");
        AddPort(ports, 443, TransportProtocol.TCP, "Webex-HTTPS", "Webex HTTPS", PortRisk.Low, "Webex");
        AddPort(ports, 5060, TransportProtocol.TCP, "Webex-SIP", "Webex SIP Signaling", PortRisk.Medium, "Webex");
        AddPort(ports, 5061, TransportProtocol.TCP, "Webex-SIP-TLS", "Webex SIP TLS", PortRisk.Low, "Webex");

        // ===========================================
        // TEAMVIEWER & REMOTE SUPPORT TOOLS
        // ===========================================
        AddPort(ports, 5938, TransportProtocol.TCP, "TeamViewer", "TeamViewer Connection", PortRisk.Medium, "RemoteSupport", "Monitor for unauthorized use");
        AddPort(ports, 443, TransportProtocol.TCP, "TeamViewer-HTTPS", "TeamViewer HTTPS Fallback", PortRisk.Medium, "RemoteSupport");
        AddPort(ports, 80, TransportProtocol.TCP, "TeamViewer-HTTP", "TeamViewer HTTP Fallback", PortRisk.High, "RemoteSupport");
        AddPort(ports, 7070, TransportProtocol.Both, "AnyDesk", "AnyDesk Connection", PortRisk.Medium, "RemoteSupport", "Monitor for unauthorized use");
        AddPort(ports, 6568, TransportProtocol.TCP, "AnyDesk-Direct", "AnyDesk Direct Connection", PortRisk.Medium, "RemoteSupport");
        AddPort(ports, 4100, TransportProtocol.TCP, "Splashtop", "Splashtop Remote", PortRisk.Medium, "RemoteSupport");
        AddPort(ports, 4101, TransportProtocol.TCP, "Splashtop-Gateway", "Splashtop Gateway", PortRisk.Medium, "RemoteSupport");
        AddPort(ports, 4102, TransportProtocol.TCP, "Splashtop-SOS", "Splashtop SOS", PortRisk.Medium, "RemoteSupport");
        AddPort(ports, 5500, TransportProtocol.TCP, "VNC-Reverse", "VNC Reverse Connection", PortRisk.High, "RemoteSupport");
        AddPort(ports, 3283, TransportProtocol.TCP, "Apple-Remote", "Apple Remote Desktop", PortRisk.Medium, "RemoteSupport");
        AddPort(ports, 5988, TransportProtocol.TCP, "WBEM-HTTP", "WBEM CIM/HTTP", PortRisk.Medium, "RemoteSupport");
        AddPort(ports, 5989, TransportProtocol.TCP, "WBEM-HTTPS", "WBEM CIM/HTTPS", PortRisk.Low, "RemoteSupport");
        AddPort(ports, 4899, TransportProtocol.TCP, "Radmin", "Radmin Remote Admin", PortRisk.Medium, "RemoteSupport");
        AddPort(ports, 4070, TransportProtocol.TCP, "LogMeIn", "LogMeIn Hamachi", PortRisk.Medium, "RemoteSupport");
        AddPort(ports, 8200, TransportProtocol.TCP, "GoToMyPC", "GoToMyPC", PortRisk.Medium, "RemoteSupport");
        AddPort(ports, 1585, TransportProtocol.TCP, "Bomgar", "BeyondTrust Remote Support", PortRisk.Medium, "RemoteSupport");
        AddPort(ports, 1586, TransportProtocol.TCP, "Bomgar-HTTPS", "BeyondTrust HTTPS", PortRisk.Low, "RemoteSupport");

        // ===========================================
        // VMWARE VSPHERE / ESXI
        // ===========================================
        AddPort(ports, 902, TransportProtocol.Both, "VMware-Auth", "VMware ESXi Auth/Console", PortRisk.Medium, "VMware");
        AddPort(ports, 903, TransportProtocol.TCP, "VMware-Console", "VMware Remote Console", PortRisk.Medium, "VMware");
        AddPort(ports, 443, TransportProtocol.TCP, "VMware-vCenter", "VMware vCenter HTTPS", PortRisk.Low, "VMware");
        AddPort(ports, 5480, TransportProtocol.TCP, "VMware-VAMI", "VMware VAMI", PortRisk.Medium, "VMware");
        AddPort(ports, 9443, TransportProtocol.TCP, "VMware-vSphere", "VMware vSphere Web Client", PortRisk.Low, "VMware");
        AddPort(ports, 8000, TransportProtocol.TCP, "VMware-vMotion", "VMware vMotion", PortRisk.Medium, "VMware");
        AddPort(ports, 8100, TransportProtocol.TCP, "VMware-Fault-Tolerance", "VMware FT Traffic", PortRisk.Medium, "VMware");
        AddPort(ports, 8200, TransportProtocol.TCP, "VMware-FT-Logging", "VMware FT Logging", PortRisk.Medium, "VMware");
        AddPort(ports, 8300, TransportProtocol.TCP, "VMware-vSAN", "VMware vSAN Cluster", PortRisk.Medium, "VMware");
        AddPort(ports, 12345, TransportProtocol.UDP, "VMware-vSAN-UDP", "VMware vSAN UDP", PortRisk.Medium, "VMware");
        AddPort(ports, 23451, TransportProtocol.UDP, "VMware-vSAN-Transport", "VMware vSAN Transport", PortRisk.Medium, "VMware");
        AddPort(ports, 5989, TransportProtocol.TCP, "VMware-CIM", "VMware CIM Server", PortRisk.Medium, "VMware");
        AddPort(ports, 427, TransportProtocol.Both, "VMware-SLP", "VMware SLP Discovery", PortRisk.Medium, "VMware");
        AddPort(ports, 514, TransportProtocol.UDP, "VMware-Syslog", "VMware Syslog", PortRisk.Medium, "VMware");
        AddPort(ports, 2012, TransportProtocol.TCP, "VMware-VCHA", "VMware vCenter HA", PortRisk.Medium, "VMware");
        AddPort(ports, 2014, TransportProtocol.TCP, "VMware-VCHA-Witness", "VMware vCenter HA Witness", PortRisk.Medium, "VMware");
        AddPort(ports, 2020, TransportProtocol.TCP, "VMware-VCHA-DB", "VMware vCenter HA DB", PortRisk.Medium, "VMware");

        // ===========================================
        // SAP / ERP SYSTEMS
        // ===========================================
        AddPort(ports, 3200, TransportProtocol.TCP, "SAP-Dispatcher", "SAP Dispatcher (00)", PortRisk.Medium, "SAP");
        AddPort(ports, 3201, TransportProtocol.TCP, "SAP-Dispatcher-01", "SAP Dispatcher (01)", PortRisk.Medium, "SAP");
        AddPort(ports, 3202, TransportProtocol.TCP, "SAP-Dispatcher-02", "SAP Dispatcher (02)", PortRisk.Medium, "SAP");
        AddPort(ports, 3300, TransportProtocol.TCP, "SAP-Gateway", "SAP Gateway (00)", PortRisk.Medium, "SAP");
        AddPort(ports, 3301, TransportProtocol.TCP, "SAP-Gateway-01", "SAP Gateway (01)", PortRisk.Medium, "SAP");
        AddPort(ports, 3600, TransportProtocol.TCP, "SAP-Message-Server", "SAP Message Server", PortRisk.Medium, "SAP");
        AddPort(ports, 3601, TransportProtocol.TCP, "SAP-Message-Server-01", "SAP Message Server Int", PortRisk.Medium, "SAP");
        AddPort(ports, 8000, TransportProtocol.TCP, "SAP-ICM-HTTP", "SAP ICM HTTP", PortRisk.High, "SAP");
        AddPort(ports, 8001, TransportProtocol.TCP, "SAP-ICM-HTTP-01", "SAP ICM HTTP Alt", PortRisk.High, "SAP");
        AddPort(ports, 44300, TransportProtocol.TCP, "SAP-ICM-HTTPS", "SAP ICM HTTPS (00)", PortRisk.Low, "SAP");
        AddPort(ports, 44301, TransportProtocol.TCP, "SAP-ICM-HTTPS-01", "SAP ICM HTTPS (01)", PortRisk.Low, "SAP");
        AddPort(ports, 8100, TransportProtocol.TCP, "SAP-Router", "SAProuter Admin", PortRisk.Medium, "SAP");
        AddPort(ports, 3299, TransportProtocol.TCP, "SAProuter", "SAProuter Connection", PortRisk.Medium, "SAP");
        AddPort(ports, 3298, TransportProtocol.TCP, "SAProuter-NI", "SAProuter NI", PortRisk.Medium, "SAP");
        AddPort(ports, 3203, TransportProtocol.TCP, "SAP-Dispatcher-03", "SAP Dispatcher (03)", PortRisk.Medium, "SAP");
        AddPort(ports, 50000, TransportProtocol.TCP, "SAP-Startup", "SAP J2EE HTTP", PortRisk.High, "SAP");
        AddPort(ports, 50001, TransportProtocol.TCP, "SAP-Startup-HTTPS", "SAP J2EE HTTPS", PortRisk.Low, "SAP");
        AddPort(ports, 50013, TransportProtocol.TCP, "SAP-StartService", "SAP Start Service HTTP", PortRisk.Medium, "SAP");
        AddPort(ports, 50014, TransportProtocol.TCP, "SAP-StartService-HTTPS", "SAP Start Service HTTPS", PortRisk.Low, "SAP");
        AddPort(ports, 4700, TransportProtocol.TCP, "SAP-HANA", "SAP HANA Index Server", PortRisk.Medium, "SAP");
        AddPort(ports, 30015, TransportProtocol.TCP, "SAP-HANA-SQL", "SAP HANA SQL/MDX", PortRisk.Medium, "SAP");
        AddPort(ports, 30013, TransportProtocol.TCP, "SAP-HANA-SQL-System", "SAP HANA System DB SQL", PortRisk.Medium, "SAP");
        AddPort(ports, 30017, TransportProtocol.TCP, "SAP-HANA-HTTP", "SAP HANA HTTP (XS)", PortRisk.High, "SAP");
        AddPort(ports, 30041, TransportProtocol.TCP, "SAP-HANA-Cockpit", "SAP HANA Cockpit", PortRisk.Medium, "SAP");

        // ===========================================
        // SERVER MANAGEMENT (iLO, iDRAC, IPMI)
        // ===========================================
        AddPort(ports, 17988, TransportProtocol.TCP, "iLO-Virtual-Media", "HPE iLO Virtual Media", PortRisk.Medium, "Management");
        AddPort(ports, 17990, TransportProtocol.TCP, "iLO-Remote-Console", "HPE iLO Remote Console", PortRisk.Medium, "Management");
        AddPort(ports, 443, TransportProtocol.TCP, "iLO-HTTPS", "HPE iLO Web HTTPS", PortRisk.Low, "Management");
        AddPort(ports, 22, TransportProtocol.TCP, "iLO-SSH", "HPE iLO SSH", PortRisk.Low, "Management");
        AddPort(ports, 80, TransportProtocol.TCP, "iLO-HTTP", "HPE iLO Web HTTP", PortRisk.High, "Management", "Use HTTPS");
        AddPort(ports, 443, TransportProtocol.TCP, "iDRAC-HTTPS", "Dell iDRAC HTTPS", PortRisk.Low, "Management");
        AddPort(ports, 5900, TransportProtocol.TCP, "iDRAC-VNC", "Dell iDRAC Virtual Console", PortRisk.Medium, "Management");
        AddPort(ports, 5901, TransportProtocol.TCP, "iDRAC-VNC-SSL", "Dell iDRAC Virtual Console SSL", PortRisk.Low, "Management");
        AddPort(ports, 623, TransportProtocol.UDP, "IPMI-RMCP", "IPMI Remote Management", PortRisk.High, "Management", "Vulnerable - isolate");
        AddPort(ports, 664, TransportProtocol.TCP, "IPMI-Serial", "IPMI Serial Over LAN", PortRisk.High, "Management");
        AddPort(ports, 443, TransportProtocol.TCP, "IMM-HTTPS", "Lenovo IMM HTTPS", PortRisk.Low, "Management");
        AddPort(ports, 7578, TransportProtocol.TCP, "IMM-Remote", "Lenovo IMM Remote Presence", PortRisk.Medium, "Management");
        AddPort(ports, 5120, TransportProtocol.TCP, "IMM-Virtual-Media", "Lenovo IMM Virtual Media", PortRisk.Medium, "Management");
        AddPort(ports, 8889, TransportProtocol.TCP, "Supermicro-IPMI", "Supermicro IPMI", PortRisk.High, "Management");

        // ===========================================
        // ADDITIONAL VPN VENDORS
        // ===========================================
        AddPort(ports, 541, TransportProtocol.TCP, "FortiGate-Admin", "FortiGate Management", PortRisk.Medium, "VPN");
        AddPort(ports, 10443, TransportProtocol.TCP, "FortiGate-SSL-VPN", "FortiGate SSL VPN", PortRisk.Low, "VPN");
        AddPort(ports, 8443, TransportProtocol.TCP, "PaloAlto-HTTPS", "Palo Alto Management", PortRisk.Low, "VPN");
        AddPort(ports, 443, TransportProtocol.TCP, "PaloAlto-GP", "Palo Alto GlobalProtect", PortRisk.Low, "VPN");
        AddPort(ports, 4443, TransportProtocol.TCP, "F5-SSL-VPN", "F5 BIG-IP SSL VPN", PortRisk.Low, "VPN");
        AddPort(ports, 943, TransportProtocol.TCP, "OpenVPN-AS-Admin", "OpenVPN Access Server Admin", PortRisk.Medium, "VPN");
        AddPort(ports, 1195, TransportProtocol.UDP, "OpenVPN-Alt", "OpenVPN Alternate", PortRisk.Low, "VPN");
        AddPort(ports, 500, TransportProtocol.UDP, "Check-Point-IKE", "Check Point IKE", PortRisk.Low, "VPN");
        AddPort(ports, 264, TransportProtocol.TCP, "Check-Point-FWA", "Check Point FWA", PortRisk.Medium, "VPN");
        AddPort(ports, 18181, TransportProtocol.TCP, "Check-Point-CPMI", "Check Point Management", PortRisk.Medium, "VPN");
        AddPort(ports, 18182, TransportProtocol.TCP, "Check-Point-CPMI-ALT", "Check Point Mgmt Alt", PortRisk.Medium, "VPN");
        AddPort(ports, 18183, TransportProtocol.TCP, "Check-Point-Log", "Check Point Log Server", PortRisk.Medium, "VPN");
        AddPort(ports, 18184, TransportProtocol.TCP, "Check-Point-CPCA", "Check Point CA", PortRisk.Medium, "VPN");
        AddPort(ports, 18191, TransportProtocol.TCP, "Check-Point-CPD", "Check Point CPD", PortRisk.Medium, "VPN");
        AddPort(ports, 18192, TransportProtocol.TCP, "Check-Point-CPRID", "Check Point CPRID", PortRisk.Medium, "VPN");
        AddPort(ports, 19009, TransportProtocol.TCP, "Check-Point-SIC", "Check Point SIC", PortRisk.Medium, "VPN");
        AddPort(ports, 444, TransportProtocol.TCP, "SonicWall-HTTPS", "SonicWall Management", PortRisk.Low, "VPN");
        AddPort(ports, 60443, TransportProtocol.TCP, "SonicWall-SSLVPN", "SonicWall SSL VPN", PortRisk.Low, "VPN");

        // ===========================================
        // ADDITIONAL MICROSOFT SERVICES
        // ===========================================
        AddPort(ports, 8530, TransportProtocol.TCP, "SCCM-HTTP", "SCCM/MECM HTTP", PortRisk.Medium, "Microsoft");
        AddPort(ports, 8531, TransportProtocol.TCP, "SCCM-HTTPS", "SCCM/MECM HTTPS", PortRisk.Low, "Microsoft");
        AddPort(ports, 10123, TransportProtocol.TCP, "SCCM-CMG", "SCCM Cloud Management Gateway", PortRisk.Low, "Microsoft");
        AddPort(ports, 10124, TransportProtocol.TCP, "SCCM-CMG-CDP", "SCCM CMG CDP", PortRisk.Low, "Microsoft");
        AddPort(ports, 4022, TransportProtocol.TCP, "SQL-Service-Broker", "SQL Server Service Broker", PortRisk.Medium, "Microsoft");
        AddPort(ports, 1431, TransportProtocol.TCP, "SQL-DAC", "SQL Server DAC", PortRisk.Medium, "Microsoft");
        AddPort(ports, 135, TransportProtocol.TCP, "DCOM-RPC", "DCOM/RPC Endpoint", PortRisk.Medium, "Microsoft");
        AddPort(ports, 464, TransportProtocol.Both, "Kpasswd", "Kerberos Password Change", PortRisk.Low, "Microsoft");
        AddPort(ports, 3268, TransportProtocol.TCP, "AD-GC", "Active Directory GC", PortRisk.Medium, "Microsoft");
        AddPort(ports, 3269, TransportProtocol.TCP, "AD-GC-SSL", "Active Directory GC SSL", PortRisk.Low, "Microsoft");
        AddPort(ports, 9389, TransportProtocol.TCP, "ADWS", "AD Web Services", PortRisk.Medium, "Microsoft");
        AddPort(ports, 5722, TransportProtocol.TCP, "DFS-R", "DFS Replication", PortRisk.Medium, "Microsoft");
        AddPort(ports, 1801, TransportProtocol.TCP, "MSMQ", "Microsoft Message Queue", PortRisk.Medium, "Microsoft");
        AddPort(ports, 2103, TransportProtocol.TCP, "MSMQ-RPC", "MSMQ RPC", PortRisk.Medium, "Microsoft");
        AddPort(ports, 2105, TransportProtocol.TCP, "MSMQ-Remote", "MSMQ Remote Read", PortRisk.Medium, "Microsoft");
        AddPort(ports, 2107, TransportProtocol.TCP, "MSMQ-Mgmt", "MSMQ Management", PortRisk.Medium, "Microsoft");

        // ===========================================
        // IOT & SMART DEVICES
        // ===========================================
        AddPort(ports, 5683, TransportProtocol.UDP, "CoAP", "Constrained Application Protocol", PortRisk.Medium, "IoT");
        AddPort(ports, 5684, TransportProtocol.UDP, "CoAPs", "CoAP over DTLS", PortRisk.Low, "IoT");
        AddPort(ports, 6668, TransportProtocol.TCP, "IoT-Gateway", "Generic IoT Gateway", PortRisk.Medium, "IoT");
        AddPort(ports, 8266, TransportProtocol.TCP, "ESP8266", "ESP8266 OTA Update", PortRisk.High, "IoT");
        AddPort(ports, 4840, TransportProtocol.TCP, "OPC-UA-IoT", "OPC UA for IoT", PortRisk.Medium, "IoT");
        AddPort(ports, 1400, TransportProtocol.TCP, "Sonos", "Sonos Speaker Control", PortRisk.Medium, "IoT");
        AddPort(ports, 8008, TransportProtocol.TCP, "Chromecast", "Google Chromecast", PortRisk.Medium, "IoT");
        AddPort(ports, 8009, TransportProtocol.TCP, "Chromecast-Cast", "Google Cast Protocol", PortRisk.Medium, "IoT");
        AddPort(ports, 8443, TransportProtocol.TCP, "UniFi-Controller", "Ubiquiti UniFi Controller", PortRisk.Low, "IoT");
        AddPort(ports, 8080, TransportProtocol.TCP, "UniFi-HTTP", "UniFi Controller HTTP", PortRisk.High, "IoT");
        AddPort(ports, 6789, TransportProtocol.TCP, "UniFi-Mobile", "UniFi Mobile Speed Test", PortRisk.Medium, "IoT");
        AddPort(ports, 10001, TransportProtocol.UDP, "UniFi-Discovery", "UniFi Device Discovery", PortRisk.Medium, "IoT");
        AddPort(ports, 3702, TransportProtocol.UDP, "WS-Discovery", "Web Services Discovery", PortRisk.Medium, "IoT");
        AddPort(ports, 21027, TransportProtocol.UDP, "Syncthing", "Syncthing Discovery", PortRisk.Medium, "IoT");
        AddPort(ports, 22000, TransportProtocol.TCP, "Syncthing-Transfer", "Syncthing File Transfer", PortRisk.Medium, "IoT");

        // ===========================================
        // GAME SERVERS (for detecting gaming traffic)
        // ===========================================
        AddPort(ports, 27015, TransportProtocol.UDP, "Steam-Game", "Steam Game Server", PortRisk.Low, "Gaming");
        AddPort(ports, 27016, TransportProtocol.UDP, "Steam-Game-Alt", "Steam Game Server Alt", PortRisk.Low, "Gaming");
        AddPort(ports, 27017, TransportProtocol.UDP, "Steam-Master", "Steam Master Server", PortRisk.Low, "Gaming");
        AddPort(ports, 3074, TransportProtocol.Both, "Xbox-Live", "Xbox Live", PortRisk.Low, "Gaming");
        AddPort(ports, 3478, TransportProtocol.UDP, "PlayStation-PSN", "PlayStation Network", PortRisk.Low, "Gaming");
        AddPort(ports, 3479, TransportProtocol.UDP, "PlayStation-PSN-Alt", "PlayStation Network Alt", PortRisk.Low, "Gaming");
        AddPort(ports, 3480, TransportProtocol.UDP, "PlayStation-PSN-2", "PlayStation Network 2", PortRisk.Low, "Gaming");
        AddPort(ports, 25565, TransportProtocol.TCP, "Minecraft", "Minecraft Server", PortRisk.Low, "Gaming");
        AddPort(ports, 19132, TransportProtocol.UDP, "Minecraft-Bedrock", "Minecraft Bedrock", PortRisk.Low, "Gaming");

        // ===========================================
        // MISCELLANEOUS ENTERPRISE
        // ===========================================
        AddPort(ports, 1270, TransportProtocol.TCP, "SCOM-Agent", "SCOM Agent", PortRisk.Medium, "Enterprise");
        AddPort(ports, 1433, TransportProtocol.TCP, "SQL-Browser", "SQL Server Browser", PortRisk.Medium, "Enterprise");
        AddPort(ports, 2701, TransportProtocol.TCP, "SMS-Remote", "SMS Remote Control", PortRisk.Medium, "Enterprise");
        AddPort(ports, 5985, TransportProtocol.TCP, "WS-Mgmt", "WS-Management HTTP", PortRisk.Medium, "Enterprise");
        AddPort(ports, 5986, TransportProtocol.TCP, "WS-Mgmt-HTTPS", "WS-Management HTTPS", PortRisk.Low, "Enterprise");
        AddPort(ports, 9998, TransportProtocol.TCP, "Splunk-Collect", "Splunk Data Collection", PortRisk.Medium, "Enterprise");
        AddPort(ports, 8880, TransportProtocol.TCP, "WebSphere-SOAP", "WebSphere SOAP Connector", PortRisk.Medium, "Enterprise");
        AddPort(ports, 9060, TransportProtocol.TCP, "WebSphere-Admin", "WebSphere Admin Console", PortRisk.Medium, "Enterprise");
        AddPort(ports, 9043, TransportProtocol.TCP, "WebSphere-Admin-SSL", "WebSphere Admin SSL", PortRisk.Low, "Enterprise");
        AddPort(ports, 7001, TransportProtocol.TCP, "WebLogic", "Oracle WebLogic", PortRisk.Medium, "Enterprise");
        AddPort(ports, 7002, TransportProtocol.TCP, "WebLogic-SSL", "Oracle WebLogic SSL", PortRisk.Low, "Enterprise");
        AddPort(ports, 4848, TransportProtocol.TCP, "GlassFish", "GlassFish Admin", PortRisk.Medium, "Enterprise");
        AddPort(ports, 8161, TransportProtocol.TCP, "ActiveMQ-Web", "Apache ActiveMQ Web", PortRisk.Medium, "Enterprise");
        AddPort(ports, 61616, TransportProtocol.TCP, "ActiveMQ-OpenWire", "Apache ActiveMQ OpenWire", PortRisk.Medium, "Enterprise");

        // Build frozen dictionaries for fast lookup
        _portDatabase = ports.ToFrozenDictionary();

        // Build TCP-only and UDP-only lookup tables for convenience
        var tcpPorts = new Dictionary<ushort, PortInfo>();
        var udpPorts = new Dictionary<ushort, PortInfo>();

        foreach (var kvp in ports)
        {
            if (kvp.Key.Transport == TransportProtocol.TCP || kvp.Key.Transport == TransportProtocol.Both)
            {
                tcpPorts.TryAdd(kvp.Key.Port, kvp.Value);
            }
            if (kvp.Key.Transport == TransportProtocol.UDP || kvp.Key.Transport == TransportProtocol.Both)
            {
                udpPorts.TryAdd(kvp.Key.Port, kvp.Value);
            }
        }

        _tcpPorts = tcpPorts.ToFrozenDictionary();
        _udpPorts = udpPorts.ToFrozenDictionary();
    }

    private static void AddPort(Dictionary<PortKey, PortInfo> ports, ushort port, TransportProtocol transport,
        string serviceName, string description, PortRisk risk, string category, string? recommendation = null)
    {
        var key = new PortKey(port, transport);
        // Only add if not already present (first entry wins for duplicates)
        if (!ports.ContainsKey(key))
        {
            ports[key] = new PortInfo
            {
                ServiceName = serviceName,
                Description = description,
                Risk = risk,
                Category = category,
                Recommendation = recommendation
            };
        }
    }

    /// <summary>
    /// Look up port information by port number and transport protocol.
    /// </summary>
    public static PortInfo? GetPortInfo(ushort port, bool isTcp = true)
    {
        // Try specific protocol first
        var key = new PortKey(port, isTcp ? TransportProtocol.TCP : TransportProtocol.UDP);
        if (_portDatabase.TryGetValue(key, out var info))
            return info;

        // Try "Both" protocol
        key = new PortKey(port, TransportProtocol.Both);
        if (_portDatabase.TryGetValue(key, out info))
            return info;

        // Try simple lookup tables
        if (isTcp && _tcpPorts.TryGetValue(port, out info))
            return info;
        if (!isTcp && _udpPorts.TryGetValue(port, out info))
            return info;

        return null;
    }

    /// <summary>
    /// Look up TCP port information.
    /// </summary>
    public static PortInfo? GetTcpPortInfo(ushort port) => GetPortInfo(port, true);

    /// <summary>
    /// Look up UDP port information.
    /// </summary>
    public static PortInfo? GetUdpPortInfo(ushort port) => GetPortInfo(port, false);

    /// <summary>
    /// Get the service name for a port, or null if unknown.
    /// </summary>
    public static string? GetServiceName(ushort port, bool isTcp = true)
    {
        return GetPortInfo(port, isTcp)?.ServiceName;
    }

    /// <summary>
    /// Get the risk level for a port.
    /// </summary>
    public static PortRisk GetRisk(ushort port, bool isTcp = true)
    {
        return GetPortInfo(port, isTcp)?.Risk ?? PortRisk.Unknown;
    }

    /// <summary>
    /// Check if a port is considered high-risk or critical.
    /// </summary>
    public static bool IsHighRiskPort(ushort port, bool isTcp = true)
    {
        var risk = GetRisk(port, isTcp);
        return risk == PortRisk.High || risk == PortRisk.Critical;
    }

    /// <summary>
    /// Get all ports in a specific category.
    /// </summary>
    public static IEnumerable<(ushort Port, TransportProtocol Transport, PortInfo Info)> GetPortsByCategory(string category)
    {
        foreach (var kvp in _portDatabase)
        {
            if (string.Equals(kvp.Value.Category, category, StringComparison.OrdinalIgnoreCase))
            {
                yield return (kvp.Key.Port, kvp.Key.Transport, kvp.Value);
            }
        }
    }

    /// <summary>
    /// Get all ports with a specific risk level.
    /// </summary>
    public static IEnumerable<(ushort Port, TransportProtocol Transport, PortInfo Info)> GetPortsByRisk(PortRisk risk)
    {
        foreach (var kvp in _portDatabase)
        {
            if (kvp.Value.Risk == risk)
            {
                yield return (kvp.Key.Port, kvp.Key.Transport, kvp.Value);
            }
        }
    }

    /// <summary>
    /// Get the total number of ports in the database.
    /// </summary>
    public static int Count => _portDatabase.Count;

    /// <summary>
    /// Get all available categories.
    /// </summary>
    public static IEnumerable<string> GetCategories()
    {
        var categories = new HashSet<string>();
        foreach (var kvp in _portDatabase)
        {
            if (kvp.Value.Category != null)
                categories.Add(kvp.Value.Category);
        }
        return categories;
    }

    /// <summary>
    /// Maps PortRisk to ProtocolSecurityEvaluator.SecurityLevel for integration.
    /// </summary>
    public static ProtocolSecurityEvaluator.SecurityLevel ToSecurityLevel(PortRisk risk)
    {
        return risk switch
        {
            PortRisk.Low => ProtocolSecurityEvaluator.SecurityLevel.Low,
            PortRisk.Medium => ProtocolSecurityEvaluator.SecurityLevel.Medium,
            PortRisk.High => ProtocolSecurityEvaluator.SecurityLevel.High,
            PortRisk.Critical => ProtocolSecurityEvaluator.SecurityLevel.Critical,
            _ => ProtocolSecurityEvaluator.SecurityLevel.Unknown
        };
    }

    /// <summary>
    /// Get color for risk level (UI display).
    /// </summary>
    public static string GetRiskColor(PortRisk risk)
    {
        return risk switch
        {
            PortRisk.Low => "#4CAF50",      // Green
            PortRisk.Medium => "#FFA726",   // Orange
            PortRisk.High => "#EF5350",     // Red
            PortRisk.Critical => "#B71C1C", // Dark Red
            _ => "#9E9E9E"                  // Gray
        };
    }
}
