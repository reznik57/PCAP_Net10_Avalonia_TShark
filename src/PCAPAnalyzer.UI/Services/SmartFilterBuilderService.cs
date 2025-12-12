using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.UI.Interfaces;
using PCAPAnalyzer.UI.Models;
using PCAPAnalyzer.UI.Services.Filters;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

// Type alias for extracted FilterDomain enum
using FilterDomain = PCAPAnalyzer.UI.Services.Filters.FilterDomainClassifier.FilterDomain;

namespace PCAPAnalyzer.UI.Services
{
    /// <summary>
    /// Service for building sophisticated PacketFilter objects from UI filter inputs.
    /// Implements complex filter logic including INCLUDE/EXCLUDE groups, AND/OR combinations,
    /// port range patterns, and protocol matching.
    ///
    /// Refactored to delegate to extracted components:
    /// - QuickFilterPredicateRegistry: 100+ quick filter predicates
    /// - GeoDataConstants: Continent/country geographic data
    /// - FilterDomainClassifier: Domain classification for OR/AND logic
    ///
    /// Used by all analysis tabs:
    /// - Packet Analysis, Dashboard, Security Threats, Voice/QoS, Country Traffic
    /// </summary>
    public sealed class SmartFilterBuilderService : ISmartFilterBuilder
    {
        private readonly IGeoIPService? _geoIPService;

        // Thread-safe cache for IP -> country code lookups
        private readonly ConcurrentDictionary<string, string> _ipCountryCache = new();

        // Use extracted type alias for cleaner code
        private static FilterDomainClassifier.FilterDomain GetQuickFilterDomain(string quickFilterCodeName)
            => FilterDomainClassifier.GetDomain(quickFilterCodeName);

        /// <summary>
        /// Creates a new SmartFilterBuilderService with optional GeoIP service for region filtering.
        /// </summary>
        public SmartFilterBuilderService(IGeoIPService? geoIPService = null)
        {
            _geoIPService = geoIPService;
        }
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
        /// Builds PacketFilters from a FilterGroup's fields using domain-based grouping.
        ///
        /// DOMAIN-BASED LOGIC:
        /// - Filters within the SAME domain use OR logic (e.g., SourceIP OR Country OR Region)
        /// - Filters across DIFFERENT domains use AND logic (e.g., IP-domain AND Port-domain)
        ///
        /// This allows intuitive filter combinations like:
        /// - "From Germany OR From USA" (both in IP domain → OR)
        /// - "From Germany AND Port 443" (IP domain AND Port domain → AND)
        /// - "Source IP: 8.8.8.8 OR Country: DE" (both target IPs → OR)
        /// </summary>
        /// <param name="group">Filter group containing user-specified criteria</param>
        /// <returns>List of PacketFilters, one per domain (0-N filters, each domain OR'd internally)</returns>
        private List<PacketFilter> BuildFilterFromGroup(FilterGroup group)
        {
            // Collect all filters with their domain classification
            var domainFilters = new Dictionary<FilterDomain, List<(PacketFilter Filter, string Description)>>();

            void AddToDomain(FilterDomain domain, PacketFilter filter, string description)
            {
                if (!domainFilters.ContainsKey(domain))
                    domainFilters[domain] = [];
                domainFilters[domain].Add((filter, description));
            }

            // === SPECIFIC IP FILTERS: SourceIP and DestIP in separate domains (AND logic) ===
            // When user specifies BOTH Source and Dest IP, they want a specific traffic path
            // (Src=X AND Dest=Y), not any traffic involving either IP (Src=X OR Dest=Y).
            if (!string.IsNullOrWhiteSpace(group.SourceIP))
            {
                AddToDomain(FilterDomain.SourceIpSpecific, new PacketFilter
                {
                    SourceIpFilter = group.SourceIP,
                    Description = $"Src IP: {group.SourceIP}"
                }, $"Src IP: {group.SourceIP}");
            }

            if (!string.IsNullOrWhiteSpace(group.DestinationIP))
            {
                AddToDomain(FilterDomain.DestIpSpecific, new PacketFilter
                {
                    DestinationIpFilter = group.DestinationIP,
                    Description = $"Dest IP: {group.DestinationIP}"
                }, $"Dest IP: {group.DestinationIP}");
            }

            // === GENERAL IP ADDRESS DOMAIN: Regions, Countries (check either endpoint, OR logic) ===

            if (group.Regions?.Count > 0)
            {
                var regionFilter = BuildRegionFilter(group.Regions);
                if (regionFilter is not null)
                {
                    AddToDomain(FilterDomain.IpAddress, regionFilter, regionFilter.Description ?? "Region");
                }
            }

            if (group.Countries?.Count > 0)
            {
                var countryFilter = BuildCountryFilter(group.Countries);
                if (countryFilter is not null)
                {
                    AddToDomain(FilterDomain.IpAddress, countryFilter, countryFilter.Description ?? "Country");
                }
            }

            // === PORT DOMAIN ===
            if (!string.IsNullOrWhiteSpace(group.PortRange))
            {
                var portTrimmed = group.PortRange.Trim();
                AddToDomain(FilterDomain.Port, new PacketFilter
                {
                    CustomPredicate = p => MatchesPortPattern(p.SourcePort, portTrimmed) ||
                                           MatchesPortPattern(p.DestinationPort, portTrimmed),
                    Description = $"Port: {portTrimmed}"
                }, $"Port: {portTrimmed}");
            }

            // === PROTOCOL DOMAIN ===
            if (!string.IsNullOrWhiteSpace(group.Protocol))
            {
                var protocolTrimmed = group.Protocol.Trim();
                AddToDomain(FilterDomain.Transport, new PacketFilter
                {
                    CustomPredicate = p => MatchesProtocol(p, protocolTrimmed),
                    Description = $"Protocol: {protocolTrimmed}"
                }, $"Protocol: {protocolTrimmed}");
            }

            // === DIRECTION DOMAIN ===
            if (group.Directions?.Count > 0)
            {
                var directionFilter = BuildDirectionFilter(group.Directions);
                if (directionFilter is not null)
                {
                    AddToDomain(FilterDomain.Direction, directionFilter, directionFilter.Description ?? "Direction");
                }
            }

            // === QUICK FILTERS: Classify each by its domain ===
            if (group.QuickFilters?.Count > 0)
            {
                // Group quick filters by their domain
                var quickFiltersByDomain = group.QuickFilters
                    .Select(qf => (Name: qf, Domain: GetQuickFilterDomain(qf), Predicate: GetQuickFilterPredicate(qf)))
                    .Where(x => x.Predicate is not null)
                    .GroupBy(x => x.Domain);

                foreach (var domainGroup in quickFiltersByDomain)
                {
                    var predicates = domainGroup.Select(x => x.Predicate!).ToList();
                    var names = domainGroup.Select(x => x.Name).ToList();

                    // Create OR filter for all quick filters in this domain
                    var filter = new PacketFilter
                    {
                        CustomPredicate = p => predicates.Any(pred => pred(p)),
                        Description = string.Join(" OR ", names)
                    };
                    AddToDomain(domainGroup.Key, filter, string.Join(" OR ", names));
                }
            }

            // === COMBINE: OR within domain, result in list for AND across domains ===
            var result = new List<PacketFilter>();

            foreach (var kvp in domainFilters)
            {
                var filtersInDomain = kvp.Value;
                if (filtersInDomain.Count == 0) continue;

                if (filtersInDomain.Count == 1)
                {
                    // Single filter in domain - use directly
                    result.Add(filtersInDomain[0].Filter);
                }
                else
                {
                    // Multiple filters in same domain - OR them together
                    var domainDescription = string.Join(" OR ", filtersInDomain.Select(f => f.Description));
                    var domainPredicates = filtersInDomain.Select(f => f.Filter).ToList();

                    result.Add(new PacketFilter
                    {
                        CombinedFilters = domainPredicates,
                        CombineMode = FilterCombineMode.Or,
                        Description = $"({domainDescription})"
                    });
                }
            }

            return result;
        }

        /// <summary>
        /// Builds a filter for multiple regions with OR logic between them.
        /// Example: "Europe OR Asia" matches packets from either region.
        /// Delegates to GeoDataConstants for geographic lookups.
        /// </summary>
        private PacketFilter? BuildRegionFilter(List<string> regions)
        {
            if (regions.Count == 0) return null;

            // Delegate to GeoDataConstants for country code lookup
            var regionCountryCodes = GeoDataConstants.GetCountriesForRegions(regions);

            if (regionCountryCodes.Count == 0) return null;

            return new PacketFilter
            {
                CustomPredicate = p => PacketMatchesCountryCodes(p, regionCountryCodes),
                Description = $"Region: {string.Join(" OR ", regions)}"
            };
        }

        /// <summary>
        /// Builds a filter for multiple countries with OR logic between them.
        /// Example: "DE OR US" matches packets from Germany or USA.
        /// </summary>
        private PacketFilter? BuildCountryFilter(List<string> countries)
        {
            if (countries.Count == 0) return null;

            var countryCodes = new HashSet<string>(countries, StringComparer.OrdinalIgnoreCase);

            return new PacketFilter
            {
                CustomPredicate = p => PacketMatchesCountryCodes(p, countryCodes),
                Description = $"Country: {string.Join(" OR ", countries)}"
            };
        }

        /// <summary>
        /// Builds a filter for traffic directions with OR logic between them.
        /// Directions: Inbound (external->internal), Outbound (internal->external), Internal (internal<->internal)
        /// </summary>
        private static PacketFilter? BuildDirectionFilter(List<string> directions)
        {
            if (directions.Count == 0) return null;

            var directionPredicates = new List<Func<PacketInfo, bool>>();

            foreach (var direction in directions)
            {
                var pred = direction.ToUpperInvariant() switch
                {
                    "INBOUND" or "INCOMING" => (Func<PacketInfo, bool>)(p =>
                        !Core.Services.NetworkFilterHelper.IsRFC1918(p.SourceIP) &&
                        Core.Services.NetworkFilterHelper.IsRFC1918(p.DestinationIP)),
                    "OUTBOUND" or "OUTGOING" => (Func<PacketInfo, bool>)(p =>
                        Core.Services.NetworkFilterHelper.IsRFC1918(p.SourceIP) &&
                        !Core.Services.NetworkFilterHelper.IsRFC1918(p.DestinationIP)),
                    "INTERNAL" or "LOCAL" => (Func<PacketInfo, bool>)(p =>
                        Core.Services.NetworkFilterHelper.IsRFC1918(p.SourceIP) &&
                        Core.Services.NetworkFilterHelper.IsRFC1918(p.DestinationIP)),
                    _ => null
                };

                if (pred is not null)
                    directionPredicates.Add(pred);
            }

            if (directionPredicates.Count == 0) return null;

            return new PacketFilter
            {
                CustomPredicate = p => directionPredicates.Any(pred => pred(p)),
                Description = $"Direction: {string.Join(" OR ", directions)}"
            };
        }

        /// <summary>
        /// Checks if a packet's source or destination IP belongs to any of the specified country codes.
        /// Uses GeoIP service with caching for efficient lookups.
        /// </summary>
        private bool PacketMatchesCountryCodes(PacketInfo packet, HashSet<string> countryCodes)
        {
            var srcCountry = GetCountryCodeForIP(packet.SourceIP);
            var dstCountry = GetCountryCodeForIP(packet.DestinationIP);

            return (srcCountry is not null && countryCodes.Contains(srcCountry)) ||
                   (dstCountry is not null && countryCodes.Contains(dstCountry));
        }

        /// <summary>
        /// Gets the country code for an IP address using cached GeoIP lookups.
        /// Returns null for private/internal IPs or lookup failures.
        /// </summary>
        private string? GetCountryCodeForIP(string? ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return null;

            // Check cache first
            if (_ipCountryCache.TryGetValue(ip, out var cached))
                return string.IsNullOrEmpty(cached) ? null : cached;

            // Skip private IPs
            if (Core.Services.NetworkFilterHelper.IsRFC1918(ip) ||
                Core.Services.NetworkFilterHelper.IsLoopback(ip) ||
                Core.Services.NetworkFilterHelper.IsLinkLocal(ip))
            {
                _ipCountryCache[ip] = "";
                return null;
            }

            // Use GeoIP service if available
            if (_geoIPService is not null)
            {
                try
                {
                    // Use synchronous lookup from cache (GeoIP service caches results)
                    var location = _geoIPService.GetLocationAsync(ip).GetAwaiter().GetResult();
                    var countryCode = location?.CountryCode?.ToUpperInvariant() ?? "";
                    _ipCountryCache[ip] = countryCode;
                    return string.IsNullOrEmpty(countryCode) ? null : countryCode;
                }
                catch
                {
                    _ipCountryCache[ip] = "";
                    return null;
                }
            }

            _ipCountryCache[ip] = "";
            return null;
        }

        /// <summary>
        /// Pre-warms the IP→Country cache for all unique IPs in the packet collection.
        /// Runs GeoIP lookups in parallel batches to avoid blocking the UI thread.
        /// MUST be called before applying region/country filters to avoid UI freeze.
        /// </summary>
        /// <param name="packets">Packets to extract unique IPs from</param>
        /// <param name="progressCallback">Optional callback for progress updates (0.0 to 1.0)</param>
        /// <returns>Number of IPs cached</returns>
        public async Task<int> PreWarmCountryCacheAsync(
            IEnumerable<PacketInfo> packets,
            Action<double, int, int>? progressCallback = null)
        {
            if (_geoIPService is null)
                return 0;

            // Extract unique public IPs that aren't already cached
            var uniqueIps = new HashSet<string>();
            foreach (var packet in packets)
            {
                AddIfPublicAndNotCached(packet.SourceIP, uniqueIps);
                AddIfPublicAndNotCached(packet.DestinationIP, uniqueIps);
            }

            if (uniqueIps.Count == 0)
                return 0;

            // Smaller batches (100) for smoother progress updates - trades raw speed for UX
            // Each batch completes with await, naturally yielding to UI thread
            const int batchSize = 100;
            var ipList = uniqueIps.ToList();
            var totalIps = ipList.Count;
            var cachedCount = 0;

            for (var i = 0; i < ipList.Count; i += batchSize)
            {
                var batch = ipList.Skip(i).Take(batchSize).ToList();
                var tasks = batch.Select(async ip =>
                {
                    try
                    {
                        var location = await _geoIPService.GetLocationAsync(ip).ConfigureAwait(false);
                        var countryCode = location?.CountryCode?.ToUpperInvariant() ?? "";
                        _ipCountryCache[ip] = countryCode;
                    }
                    catch
                    {
                        _ipCountryCache[ip] = "";
                    }
                });

                await Task.WhenAll(tasks).ConfigureAwait(false);
                cachedCount += batch.Count;

                // Report progress after each batch for smooth UX
                // Progress is 0.0 to 1.0 representing cache-warming phase
                var progress = (double)cachedCount / totalIps;
                progressCallback?.Invoke(progress, cachedCount, totalIps);
            }

            return cachedCount;
        }

        /// <summary>
        /// Adds an IP to the set if it's public (not private/loopback/link-local) and not already cached.
        /// </summary>
        private void AddIfPublicAndNotCached(string? ip, HashSet<string> targetSet)
        {
            if (string.IsNullOrWhiteSpace(ip))
                return;

            // Skip if already cached
            if (_ipCountryCache.ContainsKey(ip))
                return;

            // Skip private/special IPs
            if (Core.Services.NetworkFilterHelper.IsRFC1918(ip) ||
                Core.Services.NetworkFilterHelper.IsLoopback(ip) ||
                Core.Services.NetworkFilterHelper.IsLinkLocal(ip))
            {
                _ipCountryCache[ip] = ""; // Cache empty result for private IPs
                return;
            }

            targetSet.Add(ip);
        }

        /// <summary>
        /// Checks if a filter group contains region or country criteria that require GeoIP lookups.
        /// Used to determine if cache pre-warming is needed before applying filters.
        /// </summary>
        public bool HasGeoIPCriteria(FilterGroup group)
        {
            return (group.Regions?.Count > 0) || (group.Countries?.Count > 0);
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
        /// Delegates to QuickFilterPredicateRegistry for consistent behavior across all tabs.
        ///
        /// This is the SINGLE SOURCE OF TRUTH for all quick filter predicates.
        /// Both ViewModels and the chip-based filter path use this method.
        /// </summary>
        /// <param name="quickFilterCodeName">The code name of the quick filter (e.g., "SYN", "TCP", "IPv4")</param>
        /// <returns>A predicate function, or null if the filter name is not recognized</returns>
        public static Func<PacketInfo, bool>? GetQuickFilterPredicate(string? quickFilterCodeName)
            => QuickFilterPredicateRegistry.GetPredicate(quickFilterCodeName);

        // NOTE: MatchesHttpErrorCode and MatchesAnyInfoPattern moved to QuickFilterPredicateRegistry

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
