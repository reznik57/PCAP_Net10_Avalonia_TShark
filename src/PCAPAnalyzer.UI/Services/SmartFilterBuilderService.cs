using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using System;
using System.Collections.Generic;
using System.Linq;

namespace PCAPAnalyzer.UI.Services
{
    /// <summary>
    /// Service for building sophisticated PacketFilter objects from UI filter inputs.
    /// Implements complex filter logic including INCLUDE/EXCLUDE groups, AND/OR combinations,
    /// port range patterns, and protocol matching.
    ///
    /// Extracted from MainWindowViewModel (250+ lines) to enable reuse across all analysis tabs:
    /// - Packet Analysis
    /// - Dashboard
    /// - Security Threats
    /// - Voice/QoS
    /// - Country Traffic
    ///
    /// Each tab can now have the same sophisticated filtering UI without code duplication.
    /// </summary>
    public sealed class SmartFilterBuilderService : ISmartFilterBuilder
    {
        /// <summary>
        /// Builds a combined PacketFilter from filter groups and individual chips.
        ///
        /// Logic Flow:
        /// 1. Build PacketFilters from INCLUDE groups (each group is AND of its fields)
        /// 2. Build PacketFilters from INCLUDE individual chips
        /// 3. Build PacketFilters from EXCLUDE groups (each group is AND of its fields)
        /// 4. Build PacketFilters from EXCLUDE individual chips
        /// 5. Combine all INCLUDE filters with OR
        /// 6. Combine all EXCLUDE filters with OR, then invert with NOT
        /// 7. Final combination: (INCLUDE) AND NOT (EXCLUDE)
        /// </summary>
        public PacketFilter BuildCombinedPacketFilter(
            IEnumerable<FilterGroup> includeGroups,
            IEnumerable<FilterChipItem> includeChips,
            IEnumerable<FilterGroup> excludeGroups,
            IEnumerable<FilterChipItem> excludeChips)
        {
            // ✅ ROBUSTNESS FIX: Defensive validation prevents NullReferenceException
            ArgumentNullException.ThrowIfNull(includeGroups);
            ArgumentNullException.ThrowIfNull(includeChips);
            ArgumentNullException.ThrowIfNull(excludeGroups);
            ArgumentNullException.ThrowIfNull(excludeChips);

            var includeFilters = new List<PacketFilter>();
            var excludeFilters = new List<PacketFilter>();

            // Step 1: Build PacketFilters from INCLUDE groups (each group is AND of its fields)
            foreach (var group in includeGroups)
            {
                var groupFilters = BuildFilterFromGroup(group);
                if (groupFilters.Any())
                {
                    includeFilters.Add(CombineFiltersWithAnd(groupFilters));
                }
            }

            // Step 2: Build PacketFilters from INCLUDE individual chips
            foreach (var chip in includeChips)
            {
                includeFilters.Add(BuildFilterFromChip(chip));
            }

            // Step 3: Build PacketFilters from EXCLUDE groups (each group is AND of its fields)
            foreach (var group in excludeGroups)
            {
                var groupFilters = BuildFilterFromGroup(group);
                if (groupFilters.Any())
                {
                    excludeFilters.Add(CombineFiltersWithAnd(groupFilters));
                }
            }

            // Step 4: Build PacketFilters from EXCLUDE individual chips
            foreach (var chip in excludeChips)
            {
                excludeFilters.Add(BuildFilterFromChip(chip));
            }

            // Step 5: Combine all INCLUDE filters with OR
            PacketFilter? combinedInclude = null;
            if (includeFilters.Count > 0)
            {
                combinedInclude = CombineFiltersWithOr(includeFilters);
            }

            // Step 6: Combine all EXCLUDE filters with OR, then invert with NOT
            PacketFilter? combinedExclude = null;
            if (excludeFilters.Count > 0)
            {
                var excludeOr = CombineFiltersWithOr(excludeFilters);
                combinedExclude = InvertFilter(excludeOr);
            }

            // Step 7: Final combination: (INCLUDE) AND (NOT EXCLUDE)
            if (combinedInclude is not null && combinedExclude is not null)
            {
                return CombineFiltersWithAnd(new List<PacketFilter> { combinedInclude, combinedExclude });
            }
            else if (combinedInclude is not null)
            {
                return combinedInclude;
            }
            else if (combinedExclude is not null)
            {
                return combinedExclude;
            }
            else
            {
                return new PacketFilter(); // Empty filter (show all packets)
            }
        }

        /// <summary>
        /// Builds PacketFilters from a FilterGroup's fields.
        /// Each non-empty field (SourceIP, DestinationIP, PortRange, Protocol) creates a separate filter.
        /// These filters are later combined with AND logic to enforce group semantics.
        /// </summary>
        /// <param name="group">Filter group containing user-specified criteria</param>
        /// <returns>List of PacketFilters, one per populated field (0-4 filters)</returns>
        private List<PacketFilter> BuildFilterFromGroup(FilterGroup group)
        {
            var groupFilters = new List<PacketFilter>();

            if (!string.IsNullOrWhiteSpace(group.SourceIP))
            {
                groupFilters.Add(new PacketFilter
                {
                    SourceIpFilter = group.SourceIP,
                    Description = $"Src IP: {group.SourceIP}"
                });
            }

            if (!string.IsNullOrWhiteSpace(group.DestinationIP))
            {
                groupFilters.Add(new PacketFilter
                {
                    DestinationIpFilter = group.DestinationIP,
                    Description = $"Dest IP: {group.DestinationIP}"
                });
            }

            if (!string.IsNullOrWhiteSpace(group.PortRange))
            {
                // ✅ DEFENSIVE: Trim whitespace to protect against UI model changes
                var portTrimmed = group.PortRange.Trim();
                groupFilters.Add(new PacketFilter
                {
                    CustomPredicate = p => MatchesPortPattern(p.SourcePort, portTrimmed) ||
                                           MatchesPortPattern(p.DestinationPort, portTrimmed),
                    Description = $"Port: {portTrimmed}"
                });
            }

            if (!string.IsNullOrWhiteSpace(group.Protocol))
            {
                // ✅ DEFENSIVE: Trim whitespace to protect against UI model changes
                var protocolTrimmed = group.Protocol.Trim();
                groupFilters.Add(new PacketFilter
                {
                    CustomPredicate = p => MatchesProtocol(p, protocolTrimmed),
                    Description = $"Protocol: {protocolTrimmed}"
                });
            }

            return groupFilters;
        }

        /// <summary>
        /// Builds a PacketFilter from a single FilterChipItem.
        /// Supports field types: "Src IP", "Dest IP", "Port", "Protocol"
        /// Also handles Quick Filter chips (IPv4, IPv6, Retransmissions, etc.)
        /// </summary>
        public PacketFilter BuildFilterFromChip(FilterChipItem chip)
        {
            // ✅ Handle Quick Filter chips (those with QuickFilterCodeName set)
            if (!string.IsNullOrEmpty(chip.QuickFilterCodeName))
            {
                return BuildFilterFromQuickFilterChip(chip);
            }

            // ✅ SECURITY FIX: Use OrdinalIgnoreCase instead of culture-aware comparison
            // Prevents Turkish "I" problem and improves performance
            return chip.FieldName switch
            {
                var name when name.Equals("Src IP", StringComparison.OrdinalIgnoreCase) ||
                              name.Equals("NOT Src IP", StringComparison.OrdinalIgnoreCase)
                    => new PacketFilter
                    {
                        SourceIpFilter = chip.Value,
                        Description = chip.DisplayLabel
                    },

                var name when name.Equals("Dest IP", StringComparison.OrdinalIgnoreCase) ||
                              name.Equals("NOT Dest IP", StringComparison.OrdinalIgnoreCase)
                    => new PacketFilter
                    {
                        DestinationIpFilter = chip.Value,
                        Description = chip.DisplayLabel
                    },

                var name when name.Equals("Port", StringComparison.OrdinalIgnoreCase) ||
                              name.Equals("NOT Port", StringComparison.OrdinalIgnoreCase)
                    => new PacketFilter
                    {
                        CustomPredicate = p => MatchesPortPattern(p.SourcePort, chip.Value) ||
                                               MatchesPortPattern(p.DestinationPort, chip.Value),
                        Description = chip.DisplayLabel
                    },

                var name when name.Equals("Protocol", StringComparison.OrdinalIgnoreCase) ||
                              name.Equals("NOT Protocol", StringComparison.OrdinalIgnoreCase)
                    => new PacketFilter
                    {
                        CustomPredicate = p => MatchesProtocol(p, chip.Value),
                        Description = chip.DisplayLabel
                    },

                _ => new PacketFilter { Description = chip.DisplayLabel }
            };
        }

        /// <summary>
        /// Gets a predicate for a quick filter by code name.
        /// This is the SINGLE SOURCE OF TRUTH for all quick filter predicates.
        /// Both ViewModels and the chip-based filter path use this method.
        /// </summary>
        /// <param name="quickFilterCodeName">The code name of the quick filter (e.g., "SYN", "TCP", "IPv4")</param>
        /// <returns>A predicate function, or null if the filter name is not recognized</returns>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1502:Avoid excessive complexity",
            Justification = "Switch expression for quick filter types is intentionally comprehensive")]
        public static Func<PacketInfo, bool>? GetQuickFilterPredicate(string? quickFilterCodeName)
        {
            if (string.IsNullOrWhiteSpace(quickFilterCodeName))
                return null;

            return quickFilterCodeName switch
            {
                // ╔══════════════════════════════════════════════════════════════════╗
                // ║                    IP ADDRESS CLASSIFICATION                      ║
                // ╠══════════════════════════════════════════════════════════════════╣
                // ║  Logical grouping for network analysts:                          ║
                // ║  • Version: IPv4, IPv6                                           ║
                // ║  • Scope: RFC1918 (private), PublicIP, APIPA (link-local)        ║
                // ║  • Special: Loopback, LinkLocal, Anycast                         ║
                // ║  • Delivery: Unicast, Multicast, Broadcast                       ║
                // ╚══════════════════════════════════════════════════════════════════╝

                // --- IP Version ---
                "IPv4" => p => Core.Services.NetworkFilterHelper.IsIPv4(p.SourceIP) ||
                               Core.Services.NetworkFilterHelper.IsIPv4(p.DestinationIP),
                "IPv6" => p => Core.Services.NetworkFilterHelper.IsIPv6(p.SourceIP) ||
                               Core.Services.NetworkFilterHelper.IsIPv6(p.DestinationIP),

                // --- Address Scope ---
                "RFC1918" => p => Core.Services.NetworkFilterHelper.IsRFC1918(p.SourceIP) ||
                                  Core.Services.NetworkFilterHelper.IsRFC1918(p.DestinationIP),
                "PublicIP" or "Public" => p => !Core.Services.NetworkFilterHelper.IsRFC1918(p.SourceIP) &&
                                               !Core.Services.NetworkFilterHelper.IsLoopback(p.SourceIP) &&
                                               !Core.Services.NetworkFilterHelper.IsLinkLocal(p.SourceIP),
                "APIPA" => p => Core.Services.NetworkFilterHelper.IsLinkLocal(p.SourceIP) ||
                                Core.Services.NetworkFilterHelper.IsLinkLocal(p.DestinationIP),

                // --- Special Addresses ---
                "Loopback" => p => Core.Services.NetworkFilterHelper.IsLoopback(p.SourceIP) ||
                                   Core.Services.NetworkFilterHelper.IsLoopback(p.DestinationIP),
                "LinkLocal" => p => Core.Services.NetworkFilterHelper.IsLinkLocal(p.SourceIP) ||
                                    Core.Services.NetworkFilterHelper.IsLinkLocal(p.DestinationIP),
                "Anycast" => p => Core.Services.NetworkFilterHelper.IsAnycast(p.SourceIP) ||
                                  Core.Services.NetworkFilterHelper.IsAnycast(p.DestinationIP),

                // --- Delivery Method ---
                "Unicast" => p => !Core.Services.NetworkFilterHelper.IsBroadcastPacket(
                                      p.DestinationIP, p.L7Protocol, p.Info, p.DestinationMAC) &&
                                  !Core.Services.NetworkFilterHelper.IsMulticast(p.DestinationIP),
                "Multicast" => p => Core.Services.NetworkFilterHelper.IsMulticast(p.SourceIP) ||
                                    Core.Services.NetworkFilterHelper.IsMulticast(p.DestinationIP),
                // Broadcast: Uses L2 MAC + IP + protocol-level indicators (DHCP, ARP)
                "Broadcast" => p => Core.Services.NetworkFilterHelper.IsBroadcastPacket(
                                        p.DestinationIP, p.L7Protocol, p.Info, p.DestinationMAC),

                // ==================== TRAFFIC DIRECTION ====================
                // PrivateToPublic: RFC1918 source → non-RFC1918 destination
                "PrivateToPublic" => p => Core.Services.NetworkFilterHelper.IsRFC1918(p.SourceIP) &&
                                          !Core.Services.NetworkFilterHelper.IsRFC1918(p.DestinationIP) &&
                                          !Core.Services.NetworkFilterHelper.IsLoopback(p.DestinationIP) &&
                                          !Core.Services.NetworkFilterHelper.IsMulticast(p.DestinationIP) &&
                                          !Core.Services.NetworkFilterHelper.IsBroadcastPacket(
                                              p.DestinationIP, p.L7Protocol, p.Info, p.DestinationMAC),
                // PublicToPrivate: Non-RFC1918 source → RFC1918 destination
                "PublicToPrivate" => p => !Core.Services.NetworkFilterHelper.IsRFC1918(p.SourceIP) &&
                                          !Core.Services.NetworkFilterHelper.IsLoopback(p.SourceIP) &&
                                          Core.Services.NetworkFilterHelper.IsRFC1918(p.DestinationIP),

                // ==================== L4 TRANSPORT PROTOCOLS ====================
                "TCP" => p => p.Protocol == Protocol.TCP,
                "UDP" => p => p.Protocol == Protocol.UDP,
                "ICMP" => p => p.Protocol == Protocol.ICMP,
                "ARP" => p => p.L7Protocol?.Equals("ARP", StringComparison.OrdinalIgnoreCase) == true,
                "IGMP" => p => p.L7Protocol?.Contains("IGMP", StringComparison.OrdinalIgnoreCase) == true ||
                               p.Protocol.ToString().Contains("IGMP", StringComparison.OrdinalIgnoreCase),
                "GRE" => p => p.L7Protocol?.Contains("GRE", StringComparison.OrdinalIgnoreCase) == true ||
                              p.Protocol.ToString().Contains("GRE", StringComparison.OrdinalIgnoreCase),

                // ==================== TCP FLAGS FILTERS ====================
                // TCP flag bits: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
                // Canonical names with aliases for backwards compatibility
                "SYN" or "TcpSyn" => p => p.Protocol == Protocol.TCP &&
                                          (p.TcpFlags & 0x02) != 0 && (p.TcpFlags & 0x10) == 0,  // SYN without ACK
                // SYN-ACK: Connection response (server accepting connection)
                "SYN-ACK" or "TcpSynAck" => p => p.Protocol == Protocol.TCP &&
                                                 (p.TcpFlags & 0x12) == 0x12,  // Both SYN (0x02) and ACK (0x10) set
                "RST" or "TcpRst" => p => p.Protocol == Protocol.TCP && (p.TcpFlags & 0x04) != 0,
                "FIN" or "TcpFin" => p => p.Protocol == Protocol.TCP && (p.TcpFlags & 0x01) != 0,
                // PSH: Push flag - data packets requesting immediate delivery to application
                "PSH" or "TcpPsh" => p => p.Protocol == Protocol.TCP && (p.TcpFlags & 0x08) != 0,
                // ACK-only: Has ACK, but no SYN, FIN, or RST (pure ACK packets)
                "ACK-only" or "TcpAckOnly" => p => p.Protocol == Protocol.TCP &&
                                                   (p.TcpFlags & 0x10) != 0 &&  // Has ACK
                                                   (p.TcpFlags & 0x07) == 0,     // No SYN, FIN, RST
                // URG: Urgent pointer flag (rarely used in modern traffic)
                "URG" or "TcpUrg" => p => p.Protocol == Protocol.TCP && (p.TcpFlags & 0x20) != 0,

                // ==================== FRAME SIZE FILTERS ====================
                // SmallFrame: < 60 bytes (Ethernet minimum is 64, but frame.len excludes 4-byte CRC)
                "SmallFrame" => p => p.Length < 60,
                "Fragmented" => p => MatchesAnyInfoPattern(p.Info, ["fragment", "frag offset"]),

                // ==================== L7 APPLICATION PROTOCOL FILTERS ====================
                // HTTP: Plaintext HTTP including HTTP/2 (h2c), excluding HTTPS/TLS
                "HTTP" => p => (p.L7Protocol?.Contains("HTTP", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Equals("HTTP2", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Equals("h2c", StringComparison.OrdinalIgnoreCase) == true) &&
                               p.L7Protocol?.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) != true &&
                               p.L7Protocol?.Contains("TLS", StringComparison.OrdinalIgnoreCase) != true,
                "HTTPS" => p => p.L7Protocol?.Contains("HTTPS", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("TLS", StringComparison.OrdinalIgnoreCase) == true,
                "DNS" => p => p.L7Protocol?.Contains("DNS", StringComparison.OrdinalIgnoreCase) == true ||
                              p.SourcePort == 53 || p.DestinationPort == 53,
                "SSH" => p => p.SourcePort == 22 || p.DestinationPort == 22,
                "FTP" => p => p.SourcePort == 21 || p.DestinationPort == 21 ||
                              p.SourcePort == 20 || p.DestinationPort == 20,
                "SMTP" => p => p.SourcePort == 25 || p.DestinationPort == 25 ||
                               p.SourcePort == 587 || p.DestinationPort == 587,
                "SNMP" => p => p.SourcePort == 161 || p.DestinationPort == 161 ||
                               p.SourcePort == 162 || p.DestinationPort == 162,
                "DHCP" => p => p.SourcePort == 67 || p.DestinationPort == 67 ||
                               p.SourcePort == 68 || p.DestinationPort == 68,
                // STUN: Standard port 3478, STUN over TLS uses 5349
                "STUN" => p => p.SourcePort == 3478 || p.DestinationPort == 3478 ||
                               p.SourcePort == 5349 || p.DestinationPort == 5349,

                // ==================== VOIP PROTOCOL FILTERS ====================
                // SIP: Session Initiation Protocol (signaling for VoIP calls)
                "SIP" => p => p.L7Protocol?.Contains("SIP", StringComparison.OrdinalIgnoreCase) == true ||
                              p.SourcePort == 5060 || p.DestinationPort == 5060 ||
                              p.SourcePort == 5061 || p.DestinationPort == 5061,  // SIP over TLS
                // RTP: Real-time Transport Protocol (actual audio/video payload)
                "RTP" => p => p.L7Protocol?.Contains("RTP", StringComparison.OrdinalIgnoreCase) == true &&
                              p.L7Protocol?.Contains("RTCP", StringComparison.OrdinalIgnoreCase) != true,
                // RTCP: RTP Control Protocol (QoS feedback for RTP streams)
                "RTCP" => p => p.L7Protocol?.Contains("RTCP", StringComparison.OrdinalIgnoreCase) == true,
                // H.323: Legacy VoIP signaling protocol (enterprise PBX systems)
                "H323" or "H.323" => p => p.L7Protocol?.Contains("H.323", StringComparison.OrdinalIgnoreCase) == true ||
                                          p.L7Protocol?.Contains("H323", StringComparison.OrdinalIgnoreCase) == true ||
                                          p.SourcePort == 1720 || p.DestinationPort == 1720,
                // MGCP: Media Gateway Control Protocol (telecom infrastructure)
                "MGCP" => p => p.L7Protocol?.Contains("MGCP", StringComparison.OrdinalIgnoreCase) == true ||
                               p.SourcePort == 2427 || p.DestinationPort == 2427 ||
                               p.SourcePort == 2727 || p.DestinationPort == 2727,
                // SCCP: Skinny Client Control Protocol (Cisco VoIP)
                "SCCP" or "Skinny" => p => p.L7Protocol?.Contains("SCCP", StringComparison.OrdinalIgnoreCase) == true ||
                                           p.L7Protocol?.Contains("Skinny", StringComparison.OrdinalIgnoreCase) == true ||
                                           p.SourcePort == 2000 || p.DestinationPort == 2000,
                // WebRTC ICE candidates: Uses STUN/TURN for NAT traversal
                "WebRTC" => p => p.L7Protocol?.Contains("WebRTC", StringComparison.OrdinalIgnoreCase) == true ||
                                 p.L7Protocol?.Contains("DTLS", StringComparison.OrdinalIgnoreCase) == true ||
                                 p.Info?.Contains("ICE", StringComparison.OrdinalIgnoreCase) == true,

                // ╔══════════════════════════════════════════════════════════════════╗
                // ║                  SECURITY & COMPLIANCE                            ║
                // ╠══════════════════════════════════════════════════════════════════╣
                // ║  Consolidated security filters:                                   ║
                // ║  • Deprecated crypto: TLSv1.0, TLSv1.1, SSLv3, SSHv1, SmbV1       ║
                // ║  • Authentication: CleartextAuth, HTTP Basic                      ║
                // ║  • Attack indicators: SYNFlood, PortScan, InvalidTTL              ║
                // ║  • Certificate issues: TLSCertError                               ║
                // ╚══════════════════════════════════════════════════════════════════╝

                // --- Deprecated Crypto (⚠️ Security Risk) ---
                // TLSv1.0 and TLSv1.1 are deprecated per RFC 8996 (March 2021)
                "TlsV10" => p => p.L7Protocol?.Contains("TLS 1.0", StringComparison.OrdinalIgnoreCase) == true ||
                                 p.L7Protocol?.Contains("TLSv1.0", StringComparison.OrdinalIgnoreCase) == true,
                "TlsV11" => p => p.L7Protocol?.Contains("TLS 1.1", StringComparison.OrdinalIgnoreCase) == true ||
                                 p.L7Protocol?.Contains("TLSv1.1", StringComparison.OrdinalIgnoreCase) == true,
                // ObsoleteCrypto: Combined SSL + deprecated TLS versions
                "ObsoleteCrypto" => p => p.L7Protocol?.Contains("SSL", StringComparison.OrdinalIgnoreCase) == true ||
                                         p.L7Protocol?.Contains("TLS 1.0", StringComparison.OrdinalIgnoreCase) == true ||
                                         p.L7Protocol?.Contains("TLSv1.0", StringComparison.OrdinalIgnoreCase) == true ||
                                         p.L7Protocol?.Contains("TLS 1.1", StringComparison.OrdinalIgnoreCase) == true ||
                                         p.L7Protocol?.Contains("TLSv1.1", StringComparison.OrdinalIgnoreCase) == true,
                // SSHv1: Deprecated SSH version 1 (insecure, should not be used)
                "SSHv1" => p => p.L7Protocol?.Contains("SSH-1", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("SSHv1", StringComparison.OrdinalIgnoreCase) == true ||
                                p.Info?.Contains("SSH-1.", StringComparison.OrdinalIgnoreCase) == true,
                // SMBv1: Vulnerable to EternalBlue (WannaCry, NotPetya)
                "SmbV1" => p => p.L7Protocol?.Contains("SMBv1", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("SMB1", StringComparison.OrdinalIgnoreCase) == true,

                // --- Cleartext Authentication (⚠️ Credential Exposure) ---
                "Insecure" or "INSECURE" => p => Core.Services.NetworkFilterHelper.IsInsecureProtocol(
                                                     p.L7Protocol ?? p.Protocol.ToString()),
                // CleartextAuth: Matches USER/PASS commands in FTP, SMTP, POP3, IMAP, Telnet, HTTP Basic
                "CleartextAuth" => p =>
                    // FTP/SMTP/POP3/IMAP/Telnet - check for USER/PASS commands
                    ((p.L7Protocol?.Contains("FTP", StringComparison.OrdinalIgnoreCase) == true ||
                      p.L7Protocol?.Contains("SMTP", StringComparison.OrdinalIgnoreCase) == true ||
                      p.L7Protocol?.Contains("POP", StringComparison.OrdinalIgnoreCase) == true ||
                      p.L7Protocol?.Contains("IMAP", StringComparison.OrdinalIgnoreCase) == true ||
                      p.L7Protocol?.Contains("TELNET", StringComparison.OrdinalIgnoreCase) == true ||
                      p.DestinationPort == 21 || p.DestinationPort == 23 || p.DestinationPort == 25 ||
                      p.DestinationPort == 110 || p.DestinationPort == 143 || p.DestinationPort == 587) &&
                     (p.Info?.Contains("USER ", StringComparison.Ordinal) == true ||
                      p.Info?.Contains("PASS ", StringComparison.Ordinal) == true ||
                      p.Info?.Contains("AUTH ", StringComparison.Ordinal) == true ||
                      p.Info?.Contains("LOGIN ", StringComparison.Ordinal) == true)) ||
                    // HTTP Basic Auth header
                    (p.L7Protocol?.Contains("HTTP", StringComparison.OrdinalIgnoreCase) == true &&
                     p.Info?.Contains("Authorization: Basic", StringComparison.OrdinalIgnoreCase) == true),

                // --- Attack Indicators ---
                // SYNFlood: SYN packets without ACK (potential scan/flood)
                "SYNFlood" or "SynFlood" => p => p.Protocol == Protocol.TCP &&
                                                 (p.TcpFlags & 0x02) != 0 &&  // SYN flag set
                                                 (p.TcpFlags & 0x10) == 0,     // ACK flag NOT set
                // PortScan: Connect to many ports in sequence (targeting well-known ports)
                "PortScan" => p => p.Protocol == Protocol.TCP &&
                                   (p.TcpFlags & 0x02) != 0 &&  // SYN flag set
                                   (p.TcpFlags & 0x10) == 0 &&  // ACK flag NOT set
                                   p.DestinationPort < 1024,    // Targeting well-known ports
                // InvalidTTL: TTL=0 or TTL=1 (routing issues, traceroute, or TTL-based attacks)
                "InvalidTTL" or "LowTTL" => p => p.Info?.Contains("TTL=1 ", StringComparison.Ordinal) == true ||
                                                 p.Info?.Contains("TTL=0 ", StringComparison.Ordinal) == true ||
                                                 p.Info?.Contains("ttl=1 ", StringComparison.OrdinalIgnoreCase) == true ||
                                                 p.Info?.Contains("ttl=0 ", StringComparison.OrdinalIgnoreCase) == true,

                // --- Certificate Issues ---
                "TLSCertError" or "CertError" => p => p.Info?.Contains("Certificate", StringComparison.OrdinalIgnoreCase) == true &&
                                                      (p.Info?.Contains("error", StringComparison.OrdinalIgnoreCase) == true ||
                                                       p.Info?.Contains("expired", StringComparison.OrdinalIgnoreCase) == true ||
                                                       p.Info?.Contains("invalid", StringComparison.OrdinalIgnoreCase) == true ||
                                                       p.Info?.Contains("untrusted", StringComparison.OrdinalIgnoreCase) == true ||
                                                       p.Info?.Contains("self-signed", StringComparison.OrdinalIgnoreCase) == true),

                // ==================== MODERN ENCRYPTION ====================
                // TLSv1.2 and TLSv1.3 are current secure standards
                "TlsV12" => p => p.L7Protocol?.Contains("TLS 1.2", StringComparison.OrdinalIgnoreCase) == true ||
                                 p.L7Protocol?.Contains("TLSv1.2", StringComparison.OrdinalIgnoreCase) == true,
                "TlsV13" => p => p.L7Protocol?.Contains("TLS 1.3", StringComparison.OrdinalIgnoreCase) == true ||
                                 p.L7Protocol?.Contains("TLSv1.3", StringComparison.OrdinalIgnoreCase) == true,

                // ==================== VPN PROTOCOLS ====================
                "WireGuard" => p => p.SourcePort == 51820 || p.DestinationPort == 51820,
                "OpenVPN" => p => p.SourcePort == 1194 || p.DestinationPort == 1194,
                "IKEv2" => p => p.SourcePort == 500 || p.DestinationPort == 500 ||
                                p.SourcePort == 4500 || p.DestinationPort == 4500,
                "IPSec" => p => p.L7Protocol?.Contains("ESP", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("AH", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("ISAKMP", StringComparison.OrdinalIgnoreCase) == true ||
                                p.L7Protocol?.Contains("IKE", StringComparison.OrdinalIgnoreCase) == true,
                "L2TP" => p => p.SourcePort == 1701 || p.DestinationPort == 1701,
                "PPTP" => p => p.SourcePort == 1723 || p.DestinationPort == 1723,

                // ==================== TCP PERFORMANCE ====================
                "Retransmissions" or "Retransmission" => p => p.Info?.Contains("Retransmission", StringComparison.OrdinalIgnoreCase) == true,
                "DuplicateAck" or "DupAck" => p => MatchesAnyInfoPattern(p.Info,
                    ["Dup ACK", "DupACK", "Duplicate ACK"]),
                "ZeroWindow" => p => MatchesAnyInfoPattern(p.Info, ["Zero window", "ZeroWindow"]),
                "KeepAlive" => p => p.Info?.Contains("Keep-Alive", StringComparison.OrdinalIgnoreCase) == true,
                "ConnectionRefused" => p =>
                    (p.Protocol == Protocol.TCP && (p.TcpFlags & 0x04) != 0 && (p.TcpFlags & 0x10) == 0) ||  // RST without ACK
                    MatchesAnyInfoPattern(p.Info, ["refused", "Connection reset"]),
                "WindowFull" => p => p.Info?.Contains("Window full", StringComparison.OrdinalIgnoreCase) == true,

                // ==================== FRAME SIZE ====================
                "JumboFrames" => p => p.Length > 1514,  // > standard Ethernet MTU

                // ==================== PROTOCOL ERROR FILTERS ====================
                // HTTPErrors: Match HTTP 4xx/5xx responses - supports multiple TShark output formats
                // TShark may output "HTTP/1.1 404 Not Found" or "404 Not Found" or just response codes
                "HTTPErrors" => p => p.L7Protocol?.Contains("HTTP", StringComparison.OrdinalIgnoreCase) == true &&
                                     MatchesHttpErrorCode(p.Info),
                "DNSFailures" => p => p.Info?.Contains("NXDOMAIN", StringComparison.OrdinalIgnoreCase) == true ||
                                      p.Info?.Contains("SERVFAIL", StringComparison.OrdinalIgnoreCase) == true,
                "ICMPUnreachable" => p => p.Info?.Contains("unreachable", StringComparison.OrdinalIgnoreCase) == true,

                // ==================== ICMP TYPE FILTERS ====================
                // ICMP Echo Request (ping): Type 8 - TShark shows "Echo (ping) request"
                "ICMPEchoRequest" or "PingRequest" => p => p.Protocol == Protocol.ICMP &&
                                                           MatchesAnyInfoPattern(p.Info, ["Echo (ping) request", "Echo request"]),
                // ICMP Echo Reply (pong): Type 0 - TShark shows "Echo (ping) reply"
                "ICMPEchoReply" or "PingReply" => p => p.Protocol == Protocol.ICMP &&
                                                       MatchesAnyInfoPattern(p.Info, ["Echo (ping) reply", "Echo reply"]),
                // ICMP Time Exceeded: Type 11 - indicates TTL expired (traceroute)
                "ICMPTimeExceeded" => p => p.Protocol == Protocol.ICMP &&
                                           p.Info?.Contains("Time-to-live exceeded", StringComparison.OrdinalIgnoreCase) == true,
                // ICMP Redirect: Type 5 - potential routing issue or MITM
                "ICMPRedirect" => p => p.Protocol == Protocol.ICMP &&
                                       p.Info?.Contains("Redirect", StringComparison.OrdinalIgnoreCase) == true,

                // ==================== DNS TYPE FILTERS ====================
                // DNS Query: TShark shows "Standard query" for requests (but NOT "Standard query response")
                "DNSQuery" => p => (p.L7Protocol?.Contains("DNS", StringComparison.OrdinalIgnoreCase) == true ||
                                    p.SourcePort == 53 || p.DestinationPort == 53) &&
                                   p.Info?.Contains("Standard query", StringComparison.OrdinalIgnoreCase) == true &&
                                   p.Info?.Contains("response", StringComparison.OrdinalIgnoreCase) != true,
                // DNS Response: TShark shows "Standard query response" for answers
                "DNSResponse" => p => (p.L7Protocol?.Contains("DNS", StringComparison.OrdinalIgnoreCase) == true ||
                                       p.SourcePort == 53 || p.DestinationPort == 53) &&
                                      p.Info?.Contains("Standard query response", StringComparison.OrdinalIgnoreCase) == true,

                // ==================== PORT RANGE FILTERS ====================
                // Well-known ports: 0-1023 (privileged, require root on Unix)
                "WellKnownPorts" => p => (p.SourcePort >= 0 && p.SourcePort <= 1023) ||
                                         (p.DestinationPort >= 0 && p.DestinationPort <= 1023),
                // Registered ports: 1024-49151 (assigned by IANA for specific services)
                "RegisteredPorts" => p => (p.SourcePort >= 1024 && p.SourcePort <= 49151) ||
                                          (p.DestinationPort >= 1024 && p.DestinationPort <= 49151),
                // Dynamic/Ephemeral ports: 49152-65535 (client-side, OS-assigned)
                "EphemeralPorts" or "HighPorts" => p => (p.SourcePort >= 49152 && p.SourcePort <= 65535) ||
                                                        (p.DestinationPort >= 49152 && p.DestinationPort <= 65535),

                // Default: not recognized
                _ => null
            };
        }

        /// <summary>
        /// Matches HTTP 4xx/5xx error status codes in packet info.
        /// Handles multiple TShark output formats:
        /// - "HTTP/1.1 404 Not Found"
        /// - "404 Not Found"
        /// - Response codes at various positions
        /// </summary>
        private static bool MatchesHttpErrorCode(string? info)
        {
            if (string.IsNullOrEmpty(info))
                return false;

            // Common HTTP error status codes (4xx client errors, 5xx server errors)
            ReadOnlySpan<string> errorCodes =
            [
                "400", "401", "402", "403", "404", "405", "406", "407", "408", "409",
                "410", "411", "412", "413", "414", "415", "416", "417", "418", "421",
                "422", "423", "424", "425", "426", "428", "429", "431", "451",
                "500", "501", "502", "503", "504", "505", "506", "507", "508", "510", "511"
            ];

            foreach (var code in errorCodes)
            {
                // Match with space before (most common): " 404 " or " 404\n" or " 404" at end
                if (info.Contains($" {code} ", StringComparison.Ordinal) ||
                    info.Contains($" {code}\r", StringComparison.Ordinal) ||
                    info.Contains($" {code}\n", StringComparison.Ordinal) ||
                    info.EndsWith($" {code}", StringComparison.Ordinal))
                    return true;

                // Match at start of info (rare but possible): "404 Not Found"
                if (info.StartsWith($"{code} ", StringComparison.Ordinal))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Matches if the Info field contains any of the specified patterns.
        /// Useful for TShark output variations (e.g., "Dup ACK", "DupACK", "Duplicate ACK").
        /// </summary>
        /// <param name="info">The packet Info field to search</param>
        /// <param name="patterns">Alternative patterns to match (any match returns true)</param>
        /// <param name="comparisonType">String comparison type (default: OrdinalIgnoreCase)</param>
        /// <returns>True if any pattern matches</returns>
        private static bool MatchesAnyInfoPattern(string? info, ReadOnlySpan<string> patterns,
            StringComparison comparisonType = StringComparison.OrdinalIgnoreCase)
        {
            if (string.IsNullOrEmpty(info))
                return false;

            foreach (var pattern in patterns)
            {
                if (info.Contains(pattern, comparisonType))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Builds a PacketFilter from a Quick Filter chip (IPv4, IPv6, RFC1918, etc.)
        /// Uses NetworkFilterHelper for consistent IP classification.
        /// Delegates to GetQuickFilterPredicate for the actual predicate logic.
        /// </summary>
        private static PacketFilter BuildFilterFromQuickFilterChip(FilterChipItem chip)
        {
            var predicate = GetQuickFilterPredicate(chip.QuickFilterCodeName);

            // Fallback: if predicate is null, use match-all
            predicate ??= _ => true;

            return new PacketFilter
            {
                CustomPredicate = predicate,
                Description = chip.DisplayLabel
            };
        }

        /// <summary>
        /// Combines multiple filters with AND logic (all must match).
        /// </summary>
        public PacketFilter CombineFiltersWithAnd(IEnumerable<PacketFilter> filters)
        {
            var filterList = filters.ToList();

            if (filterList.Count == 0)
                return new PacketFilter();

            if (filterList.Count == 1)
                return filterList[0];

            var descriptions = filterList.Select(f => f.Description).Where(d => !string.IsNullOrWhiteSpace(d));
            var combinedDescription = string.Join(" AND ", descriptions);

            return new PacketFilter
            {
                CustomPredicate = p => filterList.All(f => f.MatchesPacket(p)),
                Description = $"({combinedDescription})"
            };
        }

        /// <summary>
        /// Combines multiple filters with OR logic (any can match).
        /// </summary>
        public PacketFilter CombineFiltersWithOr(IEnumerable<PacketFilter> filters)
        {
            var filterList = filters.ToList();

            if (filterList.Count == 0)
                return new PacketFilter();

            if (filterList.Count == 1)
                return filterList[0];

            var descriptions = filterList.Select(f => f.Description).Where(d => !string.IsNullOrWhiteSpace(d));
            var combinedDescription = string.Join(" OR ", descriptions);

            return new PacketFilter
            {
                CustomPredicate = p => filterList.Any(f => f.MatchesPacket(p)),
                Description = $"({combinedDescription})"
            };
        }

        /// <summary>
        /// Inverts a filter (NOT logic).
        /// </summary>
        public PacketFilter InvertFilter(PacketFilter filter)
        {
            if (filter.IsEmpty)
                return filter;

            return new PacketFilter
            {
                CustomPredicate = p => !filter.MatchesPacket(p),
                Description = $"NOT ({filter.Description})"
            };
        }

        /// <summary>
        /// Checks if a port matches a pattern.
        /// Supports:
        /// - Single ports: "80"
        /// - Comma-separated lists: "80,443,8080"
        /// - Ranges: "137-139"
        /// - Combined: "80,443,137-139"
        /// </summary>
        public bool MatchesPortPattern(int port, string pattern)
        {
            // ✅ ROBUSTNESS FIX: Validate input to prevent exceptions
            if (string.IsNullOrWhiteSpace(pattern))
                return false;

            var parts = pattern.Split(',', StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                var trimmed = part.Trim();

                // Check for range (e.g., "137-139")
                if (trimmed.Contains('-', StringComparison.Ordinal))
                {
                    var rangeParts = trimmed.Split('-');
                    if (rangeParts.Length == 2 &&
                        int.TryParse(rangeParts[0].Trim(), out var start) &&
                        int.TryParse(rangeParts[1].Trim(), out var end))
                    {
                        if (port >= start && port <= end)
                            return true;
                    }
                }
                // Check for exact match
                else if (int.TryParse(trimmed, out var singlePort))
                {
                    if (port == singlePort)
                        return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Checks if a packet's protocol matches a pattern.
        /// Supports:
        /// - L4 protocols: "TCP", "UDP", "ICMP"
        /// - L7 protocols: "HTTP", "DNS", "TLS"
        /// - Comma-separated: "TCP,HTTP"
        /// Case-insensitive matching.
        /// </summary>
        public bool MatchesProtocol(PacketInfo packet, string pattern)
        {
            // ✅ ROBUSTNESS FIX: Validate input to prevent exceptions
            if (string.IsNullOrWhiteSpace(pattern))
                return false;

            var parts = pattern.Split(',', StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                var trimmed = part.Trim();

                // Check L4 protocol
                if (Enum.TryParse<Protocol>(trimmed, true, out var l4Protocol))
                {
                    if (packet.Protocol == l4Protocol)
                        return true;
                }

                // Check L7 protocol
                if (!string.IsNullOrWhiteSpace(packet.L7Protocol))
                {
                    if (packet.L7Protocol.Equals(trimmed, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }

            return false;
        }
    }
}
