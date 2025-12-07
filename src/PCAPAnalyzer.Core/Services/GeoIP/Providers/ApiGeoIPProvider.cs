using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services.GeoIP.Configuration;

namespace PCAPAnalyzer.Core.Services.GeoIP.Providers
{
    /// <summary>
    /// GeoIP provider using online API services as fallback.
    /// Extracted from EnhancedGeoIPService with rate limiting and error handling.
    /// Supports multiple API providers: ip-api.com, ipinfo.io, ipgeolocation.io
    /// </summary>
    public sealed class ApiGeoIPProvider : IGeoIPProvider, IDisposable
    {
        private readonly ILogger? _logger;
        private readonly HttpClient _httpClient;
        private readonly SemaphoreSlim _rateLimiter;
        private readonly string _apiProvider = string.Empty;
        private readonly string _baseUrl = string.Empty;
        private readonly string? _apiKey;
        private readonly int _rateLimitPerSecond;
        private bool _isReady;
        private bool _disposed;

        public string ProviderName => $"API ({_apiProvider})";

        public bool IsReady => _isReady;

        /// <summary>
        /// Creates a new API provider with specified configuration
        /// </summary>
        public ApiGeoIPProvider(ProviderConfiguration config, ILogger? logger = null)
        {
            _logger = logger;
            _apiProvider = config.GetSetting("ApiProvider") ?? "ip-api";
            _baseUrl = config.GetSetting("BaseUrl") ?? GetDefaultBaseUrl(_apiProvider);
            _apiKey = config.GetSetting("ApiKey");
            _rateLimitPerSecond = config.GetSettingAsInt("RateLimitPerSecond", 45);

            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(10)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "PCAPAnalyzer/1.0");

            _rateLimiter = new SemaphoreSlim(_rateLimitPerSecond, _rateLimitPerSecond);
        }

        /// <summary>
        /// Creates a new API provider with direct parameters
        /// </summary>
        public ApiGeoIPProvider(
            string apiProvider = "ip-api",
            string? baseUrl = null,
            string? apiKey = null,
            int rateLimitPerSecond = 45,
            ILogger? logger = null)
        {
            _logger = logger;
            _apiProvider = apiProvider;
            _baseUrl = baseUrl ?? GetDefaultBaseUrl(apiProvider);
            _apiKey = apiKey;
            _rateLimitPerSecond = rateLimitPerSecond;

            _httpClient = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(10)
            };
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "PCAPAnalyzer/1.0");

            _rateLimiter = new SemaphoreSlim(rateLimitPerSecond, rateLimitPerSecond);
        }

        public async Task<bool> InitializeAsync()
        {
            if (_isReady) return true;

            try
            {
                _logger?.LogInformation("[{Provider}] Starting initialization...", ProviderName);

                // Test the API with a known IP
                var testResult = await LookupAsync("8.8.8.8");
                _isReady = testResult is not null;

                if (_isReady)
                {
                    _logger?.LogInformation("[{Provider}] Successfully initialized", ProviderName);
                }
                else
                {
                    _logger?.LogWarning("[{Provider}] API test failed, lookups may not work", ProviderName);
                }

                return _isReady;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[{Provider}] Initialization failed", ProviderName);
                return false;
            }
        }

        public async Task<GeoLocation?> LookupAsync(string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return null;

            await _rateLimiter.WaitAsync();
            try
            {
                var url = BuildUrl(ipAddress);
                var response = await _httpClient.GetAsync(url);

                if (!response.IsSuccessStatusCode)
                {
                    _logger?.LogWarning("[{Provider}] API request failed: {StatusCode}", ProviderName, response.StatusCode);
                    return null;
                }

                var json = await response.Content.ReadAsStringAsync();
                var data = JsonDocument.Parse(json);

                return _apiProvider.ToLowerInvariant() switch
                {
                    "ip-api" => ParseIPAPIResponse(ipAddress, data),
                    "ipinfo" => ParseIPInfoResponse(ipAddress, data),
                    "ipgeolocation" => ParseIPGeolocationResponse(ipAddress, data),
                    _ => null
                };
            }
            catch (HttpRequestException ex)
            {
                _logger?.LogWarning(ex, "[{Provider}] Network error for IP: {IpAddress}", ProviderName, ipAddress);
                return null;
            }
            catch (TaskCanceledException ex)
            {
                _logger?.LogWarning(ex, "[{Provider}] Timeout for IP: {IpAddress}", ProviderName, ipAddress);
                return null;
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[{Provider}] Lookup error for IP: {IpAddress}", ProviderName, ipAddress);
                return null;
            }
            finally
            {
                // Release rate limiter after a delay to maintain rate limit
                _ = Task.Delay(1000 / _rateLimitPerSecond).ContinueWith(_ => _rateLimiter.Release());
            }
        }

        public async Task<GeoIPDatabaseStats?> GetStatsAsync()
        {
            return await Task.FromResult(new GeoIPDatabaseStats
            {
                Provider = ProviderName,
                IsLoaded = _isReady,
                TotalRecords = -1, // API doesn't have fixed records
                LastUpdate = DateTime.UtcNow,
                DatabaseSizeBytes = 0
            });
        }

        public async Task DisposeAsync()
        {
            await Task.Run(() =>
            {
                _httpClient?.Dispose();
                _rateLimiter?.Dispose();
                _isReady = false;
                _logger?.LogInformation("[{Provider}] Disposed", ProviderName);
            });
        }

        private string BuildUrl(string ipAddress)
        {
            var url = _baseUrl + ipAddress;

            // Add API key if required
            if (!string.IsNullOrEmpty(_apiKey))
            {
                var separator = url.Contains("?", StringComparison.Ordinal) ? "&" : "?";
                url += $"{separator}apiKey={_apiKey}";
            }

            return url;
        }

        private GeoLocation? ParseIPAPIResponse(string ipAddress, JsonDocument data)
        {
            try
            {
                var root = data.RootElement;

                if (root.TryGetProperty("status", out var status) && status.GetString() != "success")
                {
                    if (root.TryGetProperty("message", out var message))
                    {
                        _logger?.LogWarning("[{Provider}] API returned error: {Message}", ProviderName, message.GetString());
                    }
                    return null;
                }

                return new GeoLocation
                {
                    IpAddress = ipAddress,
                    CountryCode = root.TryGetProperty("countryCode", out var cc) ? cc.GetString() ?? "Unknown" : "Unknown",
                    CountryName = root.TryGetProperty("country", out var cn) ? cn.GetString() ?? "Unknown" : "Unknown",
                    City = root.TryGetProperty("city", out var city) ? city.GetString() : null,
                    Region = root.TryGetProperty("regionName", out var region) ? region.GetString() : null,
                    ISP = root.TryGetProperty("isp", out var isp) ? isp.GetString() : null,
                    Organization = root.TryGetProperty("org", out var org) ? org.GetString() : null,
                    ASN = root.TryGetProperty("as", out var asn) ? asn.GetString() : null,
                    Latitude = root.TryGetProperty("lat", out var lat) ? lat.GetDouble() : null,
                    Longitude = root.TryGetProperty("lon", out var lon) ? lon.GetDouble() : null,
                    TimeZone = root.TryGetProperty("timezone", out var tz) ? tz.GetString() : null,
                    ConfidenceScore = 0.85,
                    Source = ProviderName,
                    IsPublicIP = true,
                    LastUpdated = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[{Provider}] Error parsing ip-api response", ProviderName);
                return null;
            }
        }

        private GeoLocation? ParseIPInfoResponse(string ipAddress, JsonDocument data)
        {
            try
            {
                var root = data.RootElement;

                // Check for error
                if (root.TryGetProperty("error", out var error))
                {
                    _logger?.LogWarning("[{Provider}] API returned error: {Error}", ProviderName, error.GetString());
                    return null;
                }

                return new GeoLocation
                {
                    IpAddress = ipAddress,
                    CountryCode = root.TryGetProperty("country", out var country) ? country.GetString() ?? "Unknown" : "Unknown",
                    CountryName = root.TryGetProperty("country", out var cn) ? GetCountryName(cn.GetString() ?? "") : "Unknown",
                    City = root.TryGetProperty("city", out var city) ? city.GetString() : null,
                    Region = root.TryGetProperty("region", out var region) ? region.GetString() : null,
                    Organization = root.TryGetProperty("org", out var org) ? org.GetString() : null,
                    TimeZone = root.TryGetProperty("timezone", out var tz) ? tz.GetString() : null,
                    ConfidenceScore = 0.90,
                    Source = ProviderName,
                    IsPublicIP = true,
                    LastUpdated = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[{Provider}] Error parsing ipinfo response", ProviderName);
                return null;
            }
        }

        private GeoLocation? ParseIPGeolocationResponse(string ipAddress, JsonDocument data)
        {
            try
            {
                var root = data.RootElement;

                // Check for error
                if (root.TryGetProperty("message", out var message) && !string.IsNullOrEmpty(message.GetString()))
                {
                    _logger?.LogWarning("[{Provider}] API returned error: {Message}", ProviderName, message.GetString());
                    return null;
                }

                return new GeoLocation
                {
                    IpAddress = ipAddress,
                    CountryCode = root.TryGetProperty("country_code2", out var code) ? code.GetString() ?? "Unknown" : "Unknown",
                    CountryName = root.TryGetProperty("country_name", out var name) ? name.GetString() ?? "Unknown" : "Unknown",
                    City = root.TryGetProperty("city", out var city) ? city.GetString() : null,
                    Region = root.TryGetProperty("state_prov", out var region) ? region.GetString() : null,
                    ISP = root.TryGetProperty("isp", out var isp) ? isp.GetString() : null,
                    Organization = root.TryGetProperty("organization", out var org) ? org.GetString() : null,
                    Latitude = root.TryGetProperty("latitude", out var lat) && !string.IsNullOrEmpty(lat.GetString())
                        ? double.Parse(lat.GetString()!) : null,
                    Longitude = root.TryGetProperty("longitude", out var lon) && !string.IsNullOrEmpty(lon.GetString())
                        ? double.Parse(lon.GetString()!) : null,
                    TimeZone = root.TryGetProperty("time_zone", out var tz) ? tz.GetString() : null,
                    ConfidenceScore = 0.88,
                    Source = ProviderName,
                    IsPublicIP = true,
                    LastUpdated = DateTime.UtcNow
                };
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "[{Provider}] Error parsing ipgeolocation response", ProviderName);
                return null;
            }
        }

        private static string GetDefaultBaseUrl(string provider)
        {
            return provider.ToLowerInvariant() switch
            {
                "ip-api" => "http://ip-api.com/json/",
                "ipinfo" => "https://ipinfo.io/",
                "ipgeolocation" => "https://api.ipgeolocation.io/ipgeo?ip=",
                _ => "http://ip-api.com/json/"
            };
        }

        private static string GetCountryName(string countryCode)
        {
            // Simple mapping for common codes
            var mapping = new Dictionary<string, string>
            {
                ["US"] = "United States",
                ["GB"] = "United Kingdom",
                ["CA"] = "Canada",
                ["AU"] = "Australia",
                ["DE"] = "Germany",
                ["FR"] = "France",
                ["JP"] = "Japan",
                ["CN"] = "China",
                ["IN"] = "India",
                ["BR"] = "Brazil"
            };

            return mapping.TryGetValue(countryCode, out var name) ? name : countryCode;
        }

        private void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // Dispose managed resources
                _httpClient?.Dispose();
                _rateLimiter?.Dispose();
                _isReady = false;
            }
            // Dispose unmanaged resources (if any) here

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
