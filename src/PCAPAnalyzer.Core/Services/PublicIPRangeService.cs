using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services
{
    /// <summary>
    /// Service for IP geolocation using public IP range databases
    /// Uses data from Regional Internet Registries (RIRs) and public sources
    /// </summary>
    public interface IPublicIPRangeService : IDisposable
    {
        Task InitializeAsync();
        Task<string?> GetCountryCodeAsync(string ipAddress);
        Task<GeoLocation?> GetLocationAsync(string ipAddress);
        Task UpdateDatabaseAsync();
        Task<int> GetTotalRangesCount();
        bool IsInitialized { get; }
    }

    public class PublicIPRangeService : IPublicIPRangeService
    {
        private readonly ILogger<PublicIPRangeService>? _logger;
        private readonly HttpClient _httpClient;
        private readonly string _dataDirectory;
        private readonly SemaphoreSlim _initLock = new(1, 1);
        private bool _isInitialized;
        
        // Efficient lookup structure using sorted ranges
        private List<IPRange> _ipv4Ranges = [];
        
        // Known Cloudflare IP ranges
        private readonly List<(uint start, uint end)> _cloudflareRanges =
        [
            // 104.16.0.0/12
            (1745879040, 1746927615),
            // 141.101.64.0/18  
            (2372665344, 2372681727),
            // 172.64.0.0/13
            (2886729728, 2886991871),
            // 172.67.0.0/16 (includes 172.67.164.214)
            (2886926336, 2886991871),
            // 173.245.48.0/20
            (2915123200, 2915139583),
            // 103.21.244.0/22
            (1729978368, 1729979391),
            // 103.22.200.0/22
            (1730043904, 1730044927),
            // 103.31.4.0/22
            (1730609152, 1730610175),
            // 104.18.0.0/16 (includes 104.18.20.226)
            (1746010112, 1746075647),
            // 141.101.90.0/24 (includes 141.101.90.107)
            (2372686336, 2372686591),
        ];
        private readonly Dictionary<string, string> _countryCodeToName = [];
        private readonly Dictionary<string, GeoLocation> _cache = [];

        public bool IsInitialized => _isInitialized;

        public PublicIPRangeService(ILogger<PublicIPRangeService>? logger = null)
        {
            _logger = logger;
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(30);
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "PCAPAnalyzer/1.0");
            
            _dataDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PCAPAnalyzer", "IPRanges");
            
            InitializeCountryNames();
        }

        public async Task InitializeAsync()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(PublicIPRangeService));

            if (_isInitialized) return;

            await _initLock.WaitAsync();
            try
            {
                if (_isInitialized) return;

                // Create data directory if it doesn't exist
                Directory.CreateDirectory(_dataDirectory);

                // Load existing data or download new
                var dataFile = Path.Combine(_dataDirectory, "ip_ranges.json");
                if (File.Exists(dataFile))
                {
                    var lastModified = File.GetLastWriteTimeUtc(dataFile);
                    if ((DateTime.UtcNow - lastModified).TotalDays < 7)
                    {
                        await LoadFromFileAsync(dataFile);
                    }
                    else
                    {
                        await UpdateDatabaseAsync();
                    }
                }
                else
                {
                    await UpdateDatabaseAsync();
                }

                _isInitialized = true;
                _logger?.LogInformation("Public IP range service initialized with {Count} ranges", _ipv4Ranges.Count);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to initialize public IP range service");
                // Load embedded fallback data
                LoadEmbeddedData();
                _isInitialized = true;
            }
            finally
            {
                _initLock.Release();
            }
        }

        public async Task UpdateDatabaseAsync()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(PublicIPRangeService));

            _logger?.LogInformation("Updating IP range database from public sources");
            
            var ranges = new List<IPRange>();
            
            try
            {
                // Download from multiple public sources
                var sources = new[]
                {
                    // IP2Location Lite (free version)
                    "https://raw.githubusercontent.com/sapics/ip-location-db/main/iptoasn-country/iptoasn-country-ipv4.csv",
                    
                    // Alternative: Webnet77 IP to Country
                    "https://software77.net/geo-ip/?DL=1",
                    
                    // Alternative: IPDeny country blocks
                    "https://www.ipdeny.com/ipblocks/data/aggregated/{cc}-aggregated.zone"
                };

                // For this implementation, we'll use a simplified approach
                // In production, you would parse data from RIRs (ARIN, RIPE, APNIC, LACNIC, AFRINIC)
                
                // Load IP2Location Lite CSV format
                var response = await _httpClient.GetStringAsync(sources[0]);
                ranges.AddRange(ParseIP2LocationCSV(response));
                
                // Sort ranges for binary search
                ranges.Sort((a, b) => a.StartNumeric.CompareTo(b.StartNumeric));
                _ipv4Ranges = ranges;
                
                // Save to file
                await SaveToFileAsync(Path.Combine(_dataDirectory, "ip_ranges.json"));
                
                _logger?.LogInformation("Successfully updated IP range database with {Count} ranges", ranges.Count);
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to update IP range database");
                LoadEmbeddedData();
            }
        }

        private List<IPRange> ParseIP2LocationCSV(string csvData)
        {
            var ranges = new List<IPRange>();
            var lines = csvData.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            
            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith("#", StringComparison.Ordinal))
                    continue;
                
                var parts = line.Split(',');
                if (parts.Length >= 3)
                {
                    try
                    {
                        var startIP = parts[0].Trim();
                        var endIP = parts[1].Trim();
                        var countryCode = parts[2].Trim().ToUpperInvariant();
                        
                        // Skip invalid or reserved ranges
                        if (countryCode == "-" || countryCode == "ZZ" || string.IsNullOrEmpty(countryCode))
                            continue;
                        
                        ranges.Add(new IPRange
                        {
                            StartIP = startIP,
                            EndIP = endIP,
                            StartNumeric = IPToLong(startIP),
                            EndNumeric = IPToLong(endIP),
                            CountryCode = countryCode
                        });
                    }
                    catch
                    {
                        // Skip invalid entries
                    }
                }
            }
            
            return ranges;
        }

        public async Task<string?> GetCountryCodeAsync(string ipAddress)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(PublicIPRangeService));

            if (!_isInitialized)
                await InitializeAsync();
            
            if (!IsValidIP(ipAddress))
                return null;
            
            var ipNumeric = IPToLong(ipAddress);
            
            // Binary search for the IP range
            var index = BinarySearchRange(ipNumeric);
            if (index >= 0)
            {
                return _ipv4Ranges[index].CountryCode;
            }
            
            return null;
        }

        public async Task<GeoLocation?> GetLocationAsync(string ipAddress)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(PublicIPRangeService));

            if (!_isInitialized)
                await InitializeAsync();
            
            // Check cache first
            if (_cache.TryGetValue(ipAddress, out var cached))
                return cached;
            
            // Check if it's a Cloudflare IP
            if (IPAddress.TryParse(ipAddress, out var ip))
            {
                var bytes = ip.GetAddressBytes();
                if (bytes.Length == 4)
                {
                    uint ipNum = (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
                    if (IsCloudflareIP(ipNum))
                    {
                        var cloudflareLocation = new GeoLocation
                        {
                            IpAddress = ipAddress,
                            CountryCode = "US",
                            CountryName = "United States (Cloudflare CDN)",
                            ContinentCode = "NA",
                            ContinentName = "North America",
                            ConfidenceScore = 1.0,
                            Source = "Cloudflare",
                            Organization = "Cloudflare CDN - actual origin server location may differ"
                        };
                        _cache[ipAddress] = cloudflareLocation;
                        return cloudflareLocation;
                    }
                }
            }
            
            var countryCode = await GetCountryCodeAsync(ipAddress);
            if (countryCode is null)
                return null;
            
            var location = new GeoLocation
            {
                IpAddress = ipAddress,
                CountryCode = countryCode,
                CountryName = GetCountryName(countryCode),
                ContinentCode = GetContinentCode(countryCode),
                ContinentName = GetContinentName(GetContinentCode(countryCode)),
                ConfidenceScore = 0.95, // High confidence for public databases
                Source = "PublicIPRanges"
            };
            
            // Cache the result
            _cache[ipAddress] = location;
            
            return location;
        }

        private int BinarySearchRange(long ipNumeric)
        {
            int left = 0;
            int right = _ipv4Ranges.Count - 1;
            
            while (left <= right)
            {
                int mid = left + (right - left) / 2;
                var range = _ipv4Ranges[mid];
                
                if (ipNumeric >= range.StartNumeric && ipNumeric <= range.EndNumeric)
                {
                    return mid;
                }
                else if (ipNumeric < range.StartNumeric)
                {
                    right = mid - 1;
                }
                else
                {
                    left = mid + 1;
                }
            }
            
            return -1;
        }

        private async Task SaveToFileAsync(string filePath)
        {
            var data = new
            {
                Version = "1.0",
                UpdatedAt = DateTime.UtcNow,
                Ranges = _ipv4Ranges
            };
            
            var json = JsonSerializer.Serialize(data, new JsonSerializerOptions
            {
                WriteIndented = true
            });
            
            await File.WriteAllTextAsync(filePath, json);
        }

        private async Task LoadFromFileAsync(string filePath)
        {
            try
            {
                var json = await File.ReadAllTextAsync(filePath);
                var data = JsonSerializer.Deserialize<IPRangeData>(json);
                
                if (data?.Ranges is not null)
                {
                    _ipv4Ranges = data.Ranges.OrderBy(r => r.StartNumeric).ToList();
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Failed to load IP ranges from file");
                LoadEmbeddedData();
            }
        }

        private void LoadEmbeddedData()
        {
            // Load a minimal set of common IP ranges as fallback
            _ipv4Ranges = GetCommonIPRanges();
            _logger?.LogInformation("Loaded {Count} embedded IP ranges", _ipv4Ranges.Count);
        }

        private List<IPRange> GetCommonIPRanges()
        {
            // Common IP ranges for major countries (simplified)
            return new List<IPRange>
            {
                // United States
                new IPRange { StartIP = "3.0.0.0", EndIP = "3.255.255.255", StartNumeric = IPToLong("3.0.0.0"), EndNumeric = IPToLong("3.255.255.255"), CountryCode = "US" },
                new IPRange { StartIP = "4.0.0.0", EndIP = "4.255.255.255", StartNumeric = IPToLong("4.0.0.0"), EndNumeric = IPToLong("4.255.255.255"), CountryCode = "US" },
                new IPRange { StartIP = "8.0.0.0", EndIP = "8.255.255.255", StartNumeric = IPToLong("8.0.0.0"), EndNumeric = IPToLong("8.255.255.255"), CountryCode = "US" },
                
                // China
                new IPRange { StartIP = "1.0.0.0", EndIP = "1.255.255.255", StartNumeric = IPToLong("1.0.0.0"), EndNumeric = IPToLong("1.255.255.255"), CountryCode = "CN" },
                new IPRange { StartIP = "14.0.0.0", EndIP = "14.255.255.255", StartNumeric = IPToLong("14.0.0.0"), EndNumeric = IPToLong("14.255.255.255"), CountryCode = "CN" },
                
                // Europe (various)
                new IPRange { StartIP = "2.0.0.0", EndIP = "2.255.255.255", StartNumeric = IPToLong("2.0.0.0"), EndNumeric = IPToLong("2.255.255.255"), CountryCode = "FR" },
                new IPRange { StartIP = "5.0.0.0", EndIP = "5.255.255.255", StartNumeric = IPToLong("5.0.0.0"), EndNumeric = IPToLong("5.255.255.255"), CountryCode = "DE" },
                
                // Add more ranges as needed...
            };
        }

        public Task<int> GetTotalRangesCount()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(PublicIPRangeService));

            return Task.FromResult(_ipv4Ranges.Count);
        }

        private bool IsCloudflareIP(uint ipNum)
        {
            return _cloudflareRanges.Any(r => ipNum >= r.start && ipNum <= r.end);
        }
        
        private bool IsValidIP(string ipAddress)
        {
            return IPAddress.TryParse(ipAddress, out _);
        }

        private long IPToLong(string ipAddress)
        {
            try
            {
                if (IPAddress.TryParse(ipAddress, out var ip))
                {
                    var bytes = ip.GetAddressBytes();
                    if (bytes.Length == 4) // IPv4
                    {
                        return ((long)bytes[0] << 24) | ((long)bytes[1] << 16) | 
                               ((long)bytes[2] << 8) | bytes[3];
                    }
                }
            }
            catch { /* Return 0 for invalid IP - safe fallback */ }
            
            return 0;
        }

        private void InitializeCountryNames()
        {
            // ISO 3166-1 alpha-2 country codes
            _countryCodeToName["US"] = "United States";
            _countryCodeToName["CN"] = "China";
            _countryCodeToName["JP"] = "Japan";
            _countryCodeToName["DE"] = "Germany";
            _countryCodeToName["GB"] = "United Kingdom";
            _countryCodeToName["FR"] = "France";
            _countryCodeToName["IN"] = "India";
            _countryCodeToName["CA"] = "Canada";
            _countryCodeToName["IT"] = "Italy";
            _countryCodeToName["KR"] = "South Korea";
            _countryCodeToName["ES"] = "Spain";
            _countryCodeToName["AU"] = "Australia";
            _countryCodeToName["RU"] = "Russia";
            _countryCodeToName["BR"] = "Brazil";
            _countryCodeToName["NL"] = "Netherlands";
            _countryCodeToName["PL"] = "Poland";
            _countryCodeToName["MX"] = "Mexico";
            _countryCodeToName["SE"] = "Sweden";
            _countryCodeToName["CH"] = "Switzerland";
            _countryCodeToName["BE"] = "Belgium";
            _countryCodeToName["AR"] = "Argentina";
            _countryCodeToName["NO"] = "Norway";
            _countryCodeToName["AT"] = "Austria";
            _countryCodeToName["DK"] = "Denmark";
            _countryCodeToName["SG"] = "Singapore";
            _countryCodeToName["FI"] = "Finland";
            _countryCodeToName["IE"] = "Ireland";
            _countryCodeToName["NZ"] = "New Zealand";
            _countryCodeToName["PT"] = "Portugal";
            _countryCodeToName["CZ"] = "Czech Republic";
            _countryCodeToName["HK"] = "Hong Kong";
            _countryCodeToName["IL"] = "Israel";
            _countryCodeToName["TH"] = "Thailand";
            _countryCodeToName["MY"] = "Malaysia";
            _countryCodeToName["ZA"] = "South Africa";
            _countryCodeToName["PH"] = "Philippines";
            _countryCodeToName["ID"] = "Indonesia";
            _countryCodeToName["EG"] = "Egypt";
            _countryCodeToName["VN"] = "Vietnam";
            _countryCodeToName["TR"] = "Turkey";
            _countryCodeToName["SA"] = "Saudi Arabia";
            _countryCodeToName["AE"] = "United Arab Emirates";
            _countryCodeToName["CL"] = "Chile";
            _countryCodeToName["GR"] = "Greece";
            _countryCodeToName["HU"] = "Hungary";
            _countryCodeToName["RO"] = "Romania";
            _countryCodeToName["UA"] = "Ukraine";
            _countryCodeToName["PK"] = "Pakistan";
            _countryCodeToName["BD"] = "Bangladesh";
            _countryCodeToName["NG"] = "Nigeria";
            _countryCodeToName["KE"] = "Kenya";
            // Additional country codes
            _countryCodeToName["AZ"] = "Azerbaijan";
            _countryCodeToName["AF"] = "Afghanistan";
            _countryCodeToName["AL"] = "Albania";
            _countryCodeToName["DZ"] = "Algeria";
            _countryCodeToName["AD"] = "Andorra";
            _countryCodeToName["AO"] = "Angola";
            _countryCodeToName["AG"] = "Antigua and Barbuda";
            _countryCodeToName["AM"] = "Armenia";
            _countryCodeToName["BS"] = "Bahamas";
            _countryCodeToName["BH"] = "Bahrain";
            _countryCodeToName["BB"] = "Barbados";
            _countryCodeToName["BY"] = "Belarus";
            _countryCodeToName["BZ"] = "Belize";
            _countryCodeToName["BJ"] = "Benin";
            _countryCodeToName["BT"] = "Bhutan";
            _countryCodeToName["BO"] = "Bolivia";
            _countryCodeToName["BA"] = "Bosnia and Herzegovina";
            _countryCodeToName["BW"] = "Botswana";
            _countryCodeToName["BN"] = "Brunei";
            _countryCodeToName["BG"] = "Bulgaria";
            _countryCodeToName["BF"] = "Burkina Faso";
            _countryCodeToName["BI"] = "Burundi";
            _countryCodeToName["KH"] = "Cambodia";
            _countryCodeToName["CM"] = "Cameroon";
            _countryCodeToName["CV"] = "Cape Verde";
            _countryCodeToName["CF"] = "Central African Republic";
            _countryCodeToName["TD"] = "Chad";
            _countryCodeToName["CO"] = "Colombia";
            _countryCodeToName["KM"] = "Comoros";
            _countryCodeToName["CG"] = "Congo";
            _countryCodeToName["CR"] = "Costa Rica";
            _countryCodeToName["CI"] = "Côte d'Ivoire";
            _countryCodeToName["HR"] = "Croatia";
            _countryCodeToName["CU"] = "Cuba";
            _countryCodeToName["CY"] = "Cyprus";
            _countryCodeToName["DJ"] = "Djibouti";
            _countryCodeToName["DM"] = "Dominica";
            _countryCodeToName["DO"] = "Dominican Republic";
            _countryCodeToName["EC"] = "Ecuador";
            _countryCodeToName["SV"] = "El Salvador";
            _countryCodeToName["GQ"] = "Equatorial Guinea";
            _countryCodeToName["ER"] = "Eritrea";
            _countryCodeToName["EE"] = "Estonia";
            _countryCodeToName["ET"] = "Ethiopia";
            _countryCodeToName["FJ"] = "Fiji";
            _countryCodeToName["GA"] = "Gabon";
            _countryCodeToName["GM"] = "Gambia";
            _countryCodeToName["GE"] = "Georgia";
            _countryCodeToName["GH"] = "Ghana";
            _countryCodeToName["GD"] = "Grenada";
            _countryCodeToName["GT"] = "Guatemala";
            _countryCodeToName["GN"] = "Guinea";
            _countryCodeToName["GW"] = "Guinea-Bissau";
            _countryCodeToName["GY"] = "Guyana";
            _countryCodeToName["HT"] = "Haiti";
            _countryCodeToName["HN"] = "Honduras";
            _countryCodeToName["IS"] = "Iceland";
            _countryCodeToName["IQ"] = "Iraq";
            _countryCodeToName["JM"] = "Jamaica";
            _countryCodeToName["JO"] = "Jordan";
            _countryCodeToName["KZ"] = "Kazakhstan";
            _countryCodeToName["KW"] = "Kuwait";
            _countryCodeToName["KG"] = "Kyrgyzstan";
            _countryCodeToName["LA"] = "Laos";
            _countryCodeToName["LV"] = "Latvia";
            _countryCodeToName["LB"] = "Lebanon";
            _countryCodeToName["LS"] = "Lesotho";
            _countryCodeToName["LR"] = "Liberia";
            _countryCodeToName["LY"] = "Libya";
            _countryCodeToName["LI"] = "Liechtenstein";
            _countryCodeToName["LT"] = "Lithuania";
            _countryCodeToName["LU"] = "Luxembourg";
            _countryCodeToName["MK"] = "North Macedonia";
            _countryCodeToName["MG"] = "Madagascar";
            _countryCodeToName["MW"] = "Malawi";
            _countryCodeToName["MV"] = "Maldives";
            _countryCodeToName["ML"] = "Mali";
            _countryCodeToName["MT"] = "Malta";
            _countryCodeToName["MH"] = "Marshall Islands";
            _countryCodeToName["MR"] = "Mauritania";
            _countryCodeToName["MU"] = "Mauritius";
            _countryCodeToName["FM"] = "Micronesia";
            _countryCodeToName["MD"] = "Moldova";
            _countryCodeToName["MC"] = "Monaco";
            _countryCodeToName["MN"] = "Mongolia";
            _countryCodeToName["ME"] = "Montenegro";
            _countryCodeToName["MA"] = "Morocco";
            _countryCodeToName["MZ"] = "Mozambique";
            _countryCodeToName["MM"] = "Myanmar";
            _countryCodeToName["NA"] = "Namibia";
            _countryCodeToName["NR"] = "Nauru";
            _countryCodeToName["NP"] = "Nepal";
            _countryCodeToName["NI"] = "Nicaragua";
            _countryCodeToName["NE"] = "Niger";
            _countryCodeToName["KP"] = "North Korea";
            _countryCodeToName["OM"] = "Oman";
            _countryCodeToName["PW"] = "Palau";
            _countryCodeToName["PS"] = "Palestine";
            _countryCodeToName["PA"] = "Panama";
            _countryCodeToName["PG"] = "Papua New Guinea";
            _countryCodeToName["PY"] = "Paraguay";
            _countryCodeToName["PE"] = "Peru";
            _countryCodeToName["QA"] = "Qatar";
            _countryCodeToName["RW"] = "Rwanda";
            _countryCodeToName["KN"] = "Saint Kitts and Nevis";
            _countryCodeToName["LC"] = "Saint Lucia";
            _countryCodeToName["VC"] = "Saint Vincent and the Grenadines";
            _countryCodeToName["WS"] = "Samoa";
            _countryCodeToName["SM"] = "San Marino";
            _countryCodeToName["ST"] = "São Tomé and Príncipe";
            _countryCodeToName["SN"] = "Senegal";
            _countryCodeToName["RS"] = "Serbia";
            _countryCodeToName["SC"] = "Seychelles";
            _countryCodeToName["SL"] = "Sierra Leone";
            _countryCodeToName["SK"] = "Slovakia";
            _countryCodeToName["SI"] = "Slovenia";
            _countryCodeToName["SB"] = "Solomon Islands";
            _countryCodeToName["SO"] = "Somalia";
            _countryCodeToName["SS"] = "South Sudan";
            _countryCodeToName["LK"] = "Sri Lanka";
            _countryCodeToName["SD"] = "Sudan";
            _countryCodeToName["SR"] = "Suriname";
            _countryCodeToName["SZ"] = "Eswatini";
            _countryCodeToName["TJ"] = "Tajikistan";
            _countryCodeToName["TZ"] = "Tanzania";
            _countryCodeToName["TL"] = "Timor-Leste";
            _countryCodeToName["TG"] = "Togo";
            _countryCodeToName["TO"] = "Tonga";
            _countryCodeToName["TT"] = "Trinidad and Tobago";
            _countryCodeToName["TN"] = "Tunisia";
            _countryCodeToName["TM"] = "Turkmenistan";
            _countryCodeToName["TV"] = "Tuvalu";
            _countryCodeToName["UG"] = "Uganda";
            _countryCodeToName["UY"] = "Uruguay";
            _countryCodeToName["UZ"] = "Uzbekistan";
            _countryCodeToName["VU"] = "Vanuatu";
            _countryCodeToName["VA"] = "Vatican City";
            _countryCodeToName["VE"] = "Venezuela";
            _countryCodeToName["YE"] = "Yemen";
            _countryCodeToName["ZM"] = "Zambia";
            _countryCodeToName["ZW"] = "Zimbabwe";
            // Special codes for CDN/Cloud providers
            _countryCodeToName["CF"] = "Cloudflare";
            _countryCodeToName["EU"] = "Europe (Generic)";
            _countryCodeToName["AP"] = "Asia Pacific (Generic)";
            // Add more as needed
        }

        private string GetCountryName(string countryCode)
        {
            return _countryCodeToName.TryGetValue(countryCode, out var name) ? name : countryCode;
        }

        private string GetContinentCode(string countryCode)
        {
            return countryCode switch
            {
                "US" or "CA" or "MX" => "NA",
                "BR" or "AR" or "CL" or "CO" or "PE" => "SA",
                "GB" or "DE" or "FR" or "IT" or "ES" or "NL" or "BE" or "CH" or "AT" or "SE" or 
                "NO" or "DK" or "FI" or "PL" or "RU" or "PT" or "GR" or "CZ" or "HU" or "RO" or 
                "UA" or "IE" => "EU",
                "CN" or "JP" or "IN" or "KR" or "SG" or "HK" or "TH" or "MY" or "ID" or "PH" or 
                "VN" or "TR" or "SA" or "AE" or "IL" or "PK" or "BD" => "AS",
                "AU" or "NZ" => "OC",
                "ZA" or "EG" or "NG" or "KE" => "AF",
                _ => "UN"
            };
        }

        private string GetContinentName(string continentCode)
        {
            return continentCode switch
            {
                "NA" => "North America",
                "SA" => "South America",
                "EU" => "Europe",
                "AS" => "Asia",
                "AF" => "Africa",
                "OC" => "Oceania",
                "AN" => "Antarctica",
                _ => "Unknown"
            };
        }

        private class IPRange
        {
            public string StartIP { get; set; } = "";
            public string EndIP { get; set; } = "";
            public long StartNumeric { get; set; }
            public long EndNumeric { get; set; }
            public string CountryCode { get; set; } = "";
        }

        private class IPRangeData
        {
            public string Version { get; set; } = "";
            public DateTime UpdatedAt { get; set; }
            public List<IPRange> Ranges { get; set; } = [];
        }

        // IDisposable implementation
        private bool _disposed;

        /// <summary>
        /// Releases all resources used by the PublicIPRangeService.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Releases the unmanaged resources used by the PublicIPRangeService and optionally releases the managed resources.
        /// </summary>
        /// <param name="disposing">true to release both managed and unmanaged resources; false to release only unmanaged resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // Dispose managed resources
                _httpClient?.Dispose();
                _initLock?.Dispose();
            }

            _disposed = true;
        }
    }
}