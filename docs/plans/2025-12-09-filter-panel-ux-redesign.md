# Filter Panel UX Redesign

**Date:** 2025-12-09
**Status:** Approved
**Author:** Claude (Principal Engineer)

## Problem Statement

The current `FilterPanelControl` displays **Security-related quick filters** (Insecure, Anomalies, Suspicious, TCP Issues, Port Scans) on the **General/Packet Analysis tab**. This is confusing because:

1. Security filters depend on anomaly detection results that may not be available on General tab
2. General tab users want network-layer filters (L2/L3/L4), not threat-hunting filters
3. Missing essential network analysis filters: Broadcast, ICMP, ARP, IGMP, TCP flags

## Solution Overview

1. **Hide Security/Audit rows** on General tab via `IsVisible` bindings
2. **Add new network analysis filters** for General tab
3. **Reorganize filter rows** for better UX

## New Filters to Add

| Filter | Code Name | Predicate Logic | Row |
|--------|-----------|-----------------|-----|
| Broadcast | `Broadcast` | Already in VM, add to UI | Network |
| Unicast | `Unicast` | `!IsBroadcast(dst) && !IsMulticast(dst)` | Network |
| ICMP | `Icmp` | `p.Protocol == Protocol.ICMP` | L4 Proto |
| ARP | `Arp` | `p.L7Protocol == "ARP"` | L4 Proto |
| IGMP | `Igmp` | `p.L7Protocol?.Contains("IGMP")` | L4 Proto |
| GRE | `Gre` | `p.L7Protocol?.Contains("GRE")` | L4 Proto |
| SYN | `TcpSyn` | `(TcpFlags & 0x02) != 0 && (TcpFlags & 0x10) == 0` | TCP Flags |
| RST | `TcpRst` | `(TcpFlags & 0x04) != 0` | TCP Flags |
| FIN | `TcpFin` | `(TcpFlags & 0x01) != 0` | TCP Flags |
| ACK-Only | `TcpAckOnly` | `(TcpFlags & 0x10) != 0 && (TcpFlags & ~0x10) == 0` | TCP Flags |
| Fragmented | `Fragmented` | `ip.frag_offset > 0` (need to verify field) | Frame |
| Small Frame | `SmallFrame` | `p.Length < 64` | Frame |

## UI Layout (General Tab)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ QUICK FILTERS                                           Switch Mode: [INCLUDE] │
├─────────────────────────────────────────────────────────────────────────────┤
│ Network:   [RFC1918] [Public] [IPv4] [IPv6] [Multicast] [Broadcast] [Unicast]  │
│ L4 Proto:  [TCP] [UDP] [ICMP] [ARP] [IGMP] [GRE]                               │
│ TCP Flags: [SYN] [RST] [FIN] [ACK Only]                                        │
│ Protocol:  [DNS] [HTTP] [HTTPS] [SSH] [SMTP] [FTP] [SNMP] [STUN] [DHCP]        │
│ TLS Ver:   [TLS 1.0] [TLS 1.1] [TLS 1.2] [TLS 1.3]                             │
│ VPN:       [WireGuard] [OpenVPN] [IKEv2] [IPSec] [L2TP] [PPTP]                 │
│ Traffic:   [Egress] [Ingress] [Large Pkts] [Loopback] [Link-Local]            │
│ Frame:     [Fragmented] [Small (<64B)] [Jumbo (>1500B)]                        │
│ TCP Perf:  [Retrans] [Zero Win] [Keep-Alive] [Conn Refused] [Win Full]        │
│ Clean:     [Hide Bcast] [App Data] [Hide Tunnels]                              │
│ Errors:    [HTTP Err] [DNS Fail] [ICMP Unreach]                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ HIDDEN on General tab (visible on Threats tab):                               │
│ Security: [Insecure] [Anomalies] [Suspicious] [TCP Issues] [Port Scans]       │
│ Audit:    [Clear Auth] [Old Crypto] [DNS Tunnel] [Scan] [Non-Std Port]        │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Phase 1: ViewModel Changes
- Add new toggle properties to `QuickFilterViewModel.cs`
- Add wrapper properties to `SmartFilterableTab.cs`
- Add `ShowSecurityFilters` virtual property

### Phase 2: Filter Predicate Logic
- Add predicates for new filters in filter builder
- Use existing `NetworkFilterHelper` methods where possible

### Phase 3: XAML Changes
- Update `FilterPanelControl.axaml` with new rows
- Bind `IsVisible` on Security/Audit rows to `ShowSecurityFilters`
- Add Broadcast/Unicast to Network row

### Phase 4: Testing
- Build and verify no regressions
- Test each new filter

## Files to Modify

1. `src/PCAPAnalyzer.UI/ViewModels/Components/QuickFilterViewModel.cs`
2. `src/PCAPAnalyzer.UI/ViewModels/Base/SmartFilterableTab.cs`
3. `src/PCAPAnalyzer.UI/Views/Controls/FilterPanelControl.axaml`
4. `src/PCAPAnalyzer.Core/Services/NetworkFilterHelper.cs` (if needed for new predicates)

## TCP Flags Reference

| Flag | Hex Value | Bit Position |
|------|-----------|--------------|
| FIN  | 0x01      | Bit 0        |
| SYN  | 0x02      | Bit 1        |
| RST  | 0x04      | Bit 2        |
| PSH  | 0x08      | Bit 3        |
| ACK  | 0x10      | Bit 4        |
| URG  | 0x20      | Bit 5        |

## Decision Log

| Decision | Rationale |
|----------|-----------|
| Use visibility bindings (not separate controls) | Less code duplication, minimal changes |
| Hide Security row completely (not collapse) | Reduces cognitive load on General tab |
| Add TCP flags row | Essential for connection analysis |
| Add L4 Proto row | Separates transport layer from application protocols |
