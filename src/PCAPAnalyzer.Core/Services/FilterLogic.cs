using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Utilities;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Core filter service implementation that can be composed into filter services.
    /// Eliminates duplication between GlobalFilterService and TabFilterService.
    /// Named "FilterServiceCore" to avoid collision with PCAPAnalyzer.UI.Models.FilterLogic enum.
    /// </summary>
    public class FilterServiceCore : IFilterServiceCore
    {
        private PacketFilter _currentFilter = new PacketFilter();
        private readonly List<PacketFilter> _filterHistory = [];
        private readonly Dictionary<string, PacketFilter> _presetFilters = [];

        public PacketFilter CurrentFilter
        {
            get => _currentFilter;
            private set
            {
                if (_currentFilter != value)
                {
                    _currentFilter = value;
                    OnPropertyChanged();
                    OnPropertyChanged(nameof(IsFilterActive));
                    OnPropertyChanged(nameof(FilterDescription));
                }
            }
        }

        public bool IsFilterActive => !_currentFilter.IsEmpty;

        public string FilterDescription
        {
            get
            {
                if (_currentFilter.IsEmpty)
                    return "No filter applied";

                // If custom description is provided, use it
                if (!string.IsNullOrEmpty(_currentFilter.Description))
                    return _currentFilter.Description;

                var parts = new List<string>();

                if (!string.IsNullOrEmpty(_currentFilter.SourceIpFilter))
                    parts.Add($"{(_currentFilter.NegateSourceIp ? "NOT " : "")}Src: {_currentFilter.SourceIpFilter}");

                if (!string.IsNullOrEmpty(_currentFilter.DestinationIpFilter))
                    parts.Add($"{(_currentFilter.NegateDestinationIp ? "NOT " : "")}Dst: {_currentFilter.DestinationIpFilter}");

                if (!string.IsNullOrWhiteSpace(_currentFilter.SourcePortFilter))
                    parts.Add($"{(_currentFilter.NegateSourcePort ? "NOT " : "")}SrcPort: {_currentFilter.SourcePortFilter}");

                if (!string.IsNullOrWhiteSpace(_currentFilter.DestinationPortFilter))
                    parts.Add($"{(_currentFilter.NegateDestinationPort ? "NOT " : "")}DstPort: {_currentFilter.DestinationPortFilter}");

                if (_currentFilter.ProtocolFilter.HasValue)
                    parts.Add($"{(_currentFilter.NegateProtocol ? "NOT " : "")}Protocol: {_currentFilter.ProtocolFilter}");

                if (_currentFilter.MinLength.HasValue)
                    parts.Add($"MinLen: {_currentFilter.MinLength}");

                if (_currentFilter.MaxLength.HasValue)
                    parts.Add($"MaxLen: {_currentFilter.MaxLength}");

                if (!string.IsNullOrEmpty(_currentFilter.InfoSearchText))
                    parts.Add($"{(_currentFilter.NegateInfo ? "NOT " : "")}Info: \"{_currentFilter.InfoSearchText}\"");

                return string.Join(" • ", parts);
            }
        }

        public IReadOnlyDictionary<string, PacketFilter> PresetFilters => _presetFilters;

        public event EventHandler<FilterChangedEventArgs>? FilterChanged;
        public event PropertyChangedEventHandler? PropertyChanged;

        public FilterServiceCore()
        {
            InitializePresetFilters();
        }

        private void InitializePresetFilters()
        {
            // Security-focused preset filters
            _presetFilters["anomalies"] = new PacketFilter
            {
                InfoSearchText = "malformed|retransmission|duplicate|dup ack|out-of-order|spurious|checksum|flood|scan|rst|fragmented|bad|invalid|error|suspicious|unknown|zero window|redirect|unreachable"
            };

            _presetFilters["tcp_issues"] = new PacketFilter
            {
                ProtocolFilter = Protocol.TCP,
                InfoSearchText = "RST|retransmission|dup|out-of-order|spurious|previous segment|port numbers reused|zero window"
            };

            _presetFilters["dns_anomalies"] = new PacketFilter
            {
                ProtocolFilter = Protocol.DNS,
                InfoSearchText = "no such name|refused|NXDOMAIN|SERVFAIL"
            };

            _presetFilters["unencrypted"] = new PacketFilter
            {
                ProtocolFilter = Protocol.HTTP
            };

            _presetFilters["port_scan"] = new PacketFilter
            {
                InfoSearchText = "SYN",
                ProtocolFilter = Protocol.TCP
            };

            _presetFilters["large_packets"] = new PacketFilter
            {
                MinLength = 1515
            };

            _presetFilters["icmp"] = new PacketFilter
            {
                ProtocolFilter = Protocol.ICMP
            };

            _presetFilters["smb"] = new PacketFilter
            {
                DestinationPortFilter = "445"
            };

            _presetFilters["ssh"] = new PacketFilter
            {
                DestinationPortFilter = "22"
            };

            _presetFilters["web"] = new PacketFilter
            {
                ProtocolFilter = Protocol.HTTP
            };

            _presetFilters["secure_web"] = new PacketFilter
            {
                ProtocolFilter = Protocol.HTTPS
            };

            // Insecure protocols filter
            _presetFilters["insecure_protocols"] = new PacketFilter
            {
                InfoSearchText = "HTTP|FTP|TELNET|POP|IMAP|SMTP|SMB|NFS|TFTP|SNMPv1|SNMPv2c"
            };

            // IPv4 filter
            _presetFilters["ipv4"] = new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsIPv4(p.SourceIP) || NetworkFilterHelper.IsIPv4(p.DestinationIP),
                Description = "IPv4 Traffic Only"
            };

            // IPv6 filter
            _presetFilters["ipv6"] = new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsIPv6(p.SourceIP) || NetworkFilterHelper.IsIPv6(p.DestinationIP),
                Description = "IPv6 Traffic Only"
            };
        }

        public void ApplyFilter(PacketFilter filter)
        {
            if (filter == null)
                throw new ArgumentNullException(nameof(filter));

            // Save to history
            if (!_currentFilter.IsEmpty)
            {
                _filterHistory.Add(_currentFilter);
                if (_filterHistory.Count > 10)
                    _filterHistory.RemoveAt(0);
            }

            CurrentFilter = filter;
            FilterChanged?.Invoke(this, new FilterChangedEventArgs(filter, FilterAction.Applied));
        }

        public void ClearFilter()
        {
            CurrentFilter = new PacketFilter();
            FilterChanged?.Invoke(this, new FilterChangedEventArgs(_currentFilter, FilterAction.Cleared));
        }

        public IEnumerable<PacketInfo> GetFilteredPackets(IEnumerable<PacketInfo> allPackets)
        {
            if (allPackets == null)
                return Enumerable.Empty<PacketInfo>();

            if (_currentFilter.IsEmpty)
                return allPackets;

            return allPackets.Where(_currentFilter.MatchesPacket);
        }

        public FilterStatistics GetFilterStatistics(IEnumerable<PacketInfo> allPackets)
        {
            if (allPackets == null)
                return new FilterStatistics();

            var allPacketsList = allPackets.ToList();
            var filteredPackets = GetFilteredPackets(allPacketsList).ToList();

            return new FilterStatistics
            {
                TotalPackets = allPacketsList.Count,
                FilteredPackets = filteredPackets.Count,
                TotalBytes = allPacketsList.Sum(p => p.Length),
                FilteredBytes = filteredPackets.Sum(p => p.Length),
                FilterEfficiency = allPacketsList.Count > 0
                    ? (double)filteredPackets.Count / allPacketsList.Count
                    : 0,
                TotalProtocols = allPacketsList.GroupBy(p => p.Protocol).Count(),
                FilteredProtocols = filteredPackets.GroupBy(p => p.Protocol).Count(),
                TotalUniqueIPs = allPacketsList.SelectMany(p => new[] { p.SourceIP, p.DestinationIP })
                    .Where(ip => !string.IsNullOrEmpty(ip))
                    .Distinct()
                    .Count(),
                FilteredUniqueIPs = filteredPackets.SelectMany(p => new[] { p.SourceIP, p.DestinationIP })
                    .Where(ip => !string.IsNullOrEmpty(ip))
                    .Distinct()
                    .Count()
            };
        }

        // Quick filter methods
        public void ApplyProtocolFilter(Protocol protocol)
        {
            var filter = new PacketFilter { ProtocolFilter = protocol };
            ApplyFilter(filter);
        }

        public void ApplyPortFilter(int port)
        {
            // Use OR logic: match if port appears in EITHER source OR destination
            var filter = new PacketFilter
            {
                CombineMode = FilterCombineMode.Or,
                CombinedFilters = new List<PacketFilter>
                {
                    new PacketFilter { SourcePortFilter = port.ToString() },
                    new PacketFilter { DestinationPortFilter = port.ToString() }
                },
                Description = $"Port: {port}"
            };
            ApplyFilter(filter);
        }

        public void ApplyIPFilter(string ipAddress)
        {
            // Use OR logic: match if IP appears in EITHER source OR destination
            var filter = new PacketFilter
            {
                CombineMode = FilterCombineMode.Or,
                CombinedFilters = new List<PacketFilter>
                {
                    new PacketFilter { SourceIpFilter = ipAddress },
                    new PacketFilter { DestinationIpFilter = ipAddress }
                },
                Description = $"IP: {ipAddress}"
            };
            ApplyFilter(filter);
        }

        public void ApplyAnomalyFilter()
        {
            if (_presetFilters.TryGetValue("anomalies", out var filter))
            {
                ApplyFilter(filter);
            }
        }

        public void ApplySecurityFilter(string filterType)
        {
            if (_presetFilters.TryGetValue(filterType.ToLower(), out var filter))
            {
                ApplyFilter(filter);
            }
        }

        // Predefined filter methods
        public void ApplyRFC1918Filter()
        {
            var filter = new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsRFC1918(p.SourceIP) && NetworkFilterHelper.IsRFC1918(p.DestinationIP),
                Description = "RFC1918 Private-to-Private Only"
            };
            ApplyFilter(filter);
        }

        public void ApplyPublicIPFilter()
        {
            var filter = new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsPublicIP(p.SourceIP) || NetworkFilterHelper.IsPublicIP(p.DestinationIP),
                Description = "Public IP Traffic"
            };
            ApplyFilter(filter);
        }

        public void ApplyMulticastFilter()
        {
            var filter = new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsMulticast(p.DestinationIP),
                Description = "Multicast Traffic"
            };
            ApplyFilter(filter);
        }

        public void ApplyBroadcastFilter()
        {
            var filter = new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsBroadcast(p.DestinationIP),
                Description = "Broadcast Traffic"
            };
            ApplyFilter(filter);
        }

        public void ApplyAnycastFilter()
        {
            var filter = new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsAnycast(p.SourceIP) || NetworkFilterHelper.IsAnycast(p.DestinationIP),
                Description = "Anycast Addresses"
            };
            ApplyFilter(filter);
        }

        public void ApplyInsecureProtocolsFilter()
        {
            var filter = new PacketFilter
            {
                CustomPredicate = p => NetworkFilterHelper.IsInsecurePort(p.SourcePort) ||
                                      NetworkFilterHelper.IsInsecurePort(p.DestinationPort) ||
                                      NetworkFilterHelper.IsInsecureProtocol(p.Protocol.ToString()),
                Description = "Insecure Protocols"
            };
            ApplyFilter(filter);
        }

        public void ApplyCustomFilter(Func<PacketInfo, bool> predicate, string description)
        {
            var filter = new PacketFilter
            {
                CustomPredicate = predicate,
                Description = description
            };
            ApplyFilter(filter);
        }

        public void ApplyIPv4Filter()
        {
            if (_presetFilters.TryGetValue("ipv4", out var filter))
            {
                ApplyFilter(filter);
            }
        }

        public void ApplyIPv6Filter()
        {
            if (_presetFilters.TryGetValue("ipv6", out var filter))
            {
                ApplyFilter(filter);
            }
        }

        public Dictionary<string, Action> GetPredefinedFilters()
        {
            return new Dictionary<string, Action>
            {
                { "IPv4 Only", ApplyIPv4Filter },
                { "IPv6 Only", ApplyIPv6Filter },
                { "RFC1918 (Private-to-Private)", ApplyRFC1918Filter },
                { "Public IP Traffic", ApplyPublicIPFilter },
                { "Multicast", ApplyMulticastFilter },
                { "Broadcast", ApplyBroadcastFilter },
                { "Anycast", ApplyAnycastFilter },
                { "Insecure Protocols", ApplyInsecureProtocolsFilter },
                { "Anomalies", ApplyAnomalyFilter },
                { "Clear Filter", ClearFilter }
            };
        }

        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
