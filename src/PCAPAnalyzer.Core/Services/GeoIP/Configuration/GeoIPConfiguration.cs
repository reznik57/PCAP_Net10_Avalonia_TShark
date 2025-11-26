using System;
using System.Collections.Generic;

namespace PCAPAnalyzer.Core.Services.GeoIP.Configuration
{
    /// <summary>
    /// Configuration for GeoIP service and providers.
    /// Supports multiple provider configurations with priority and fallback settings.
    /// </summary>
    public class GeoIPConfiguration
    {
        /// <summary>
        /// Enable caching of lookup results
        /// </summary>
        public bool EnableCache { get; set; } = true;

        /// <summary>
        /// Cache expiration time (default: 24 hours)
        /// </summary>
        public TimeSpan CacheExpiration { get; set; } = TimeSpan.FromHours(24);

        /// <summary>
        /// Maximum number of entries to cache in memory
        /// </summary>
        public int MaxCacheSize { get; set; } = 10000;

        /// <summary>
        /// Provider configurations in priority order (lower number = higher priority)
        /// </summary>
        public List<ProviderConfiguration> Providers { get; set; } = new();

        /// <summary>
        /// Enable automatic fallback to next provider on failure
        /// </summary>
        public bool EnableProviderFallback { get; set; } = true;

        /// <summary>
        /// Timeout for provider initialization (default: 30 seconds)
        /// </summary>
        public TimeSpan ProviderInitializationTimeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Timeout for individual IP lookups (default: 5 seconds)
        /// </summary>
        public TimeSpan LookupTimeout { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>
        /// Enable parallel batch lookups
        /// </summary>
        public bool EnableParallelBatchLookups { get; set; } = true;

        /// <summary>
        /// Maximum degree of parallelism for batch lookups
        /// </summary>
        public int MaxDegreeOfParallelism { get; set; } = 4;

        /// <summary>
        /// Enable detailed logging
        /// </summary>
        public bool EnableDetailedLogging { get; set; }

        /// <summary>
        /// Creates default configuration with MMDB provider
        /// </summary>
        public static GeoIPConfiguration CreateDefault()
        {
            return new GeoIPConfiguration
            {
                Providers = new List<ProviderConfiguration>
                {
                    new ProviderConfiguration
                    {
                        ProviderType = ProviderType.Mmdb,
                        Priority = 1,
                        IsEnabled = true,
                        Settings = new Dictionary<string, string>
                        {
                            ["DatabasePath"] = "GeoLite2-Country.mmdb"
                        }
                    }
                }
            };
        }

        /// <summary>
        /// Creates configuration with MMDB and SQLite providers
        /// </summary>
        public static GeoIPConfiguration CreateWithSqliteBackup()
        {
            return new GeoIPConfiguration
            {
                Providers = new List<ProviderConfiguration>
                {
                    new ProviderConfiguration
                    {
                        ProviderType = ProviderType.Mmdb,
                        Priority = 1,
                        IsEnabled = true,
                        Settings = new Dictionary<string, string>
                        {
                            ["DatabasePath"] = "GeoLite2-Country.mmdb"
                        }
                    },
                    new ProviderConfiguration
                    {
                        ProviderType = ProviderType.Sqlite,
                        Priority = 2,
                        IsEnabled = true,
                        Settings = new Dictionary<string, string>
                        {
                            ["DatabasePath"] = "geoip.db"
                        }
                    }
                }
            };
        }

        /// <summary>
        /// Creates configuration with all providers including API fallback
        /// </summary>
        public static GeoIPConfiguration CreateWithApiFullback()
        {
            return new GeoIPConfiguration
            {
                Providers = new List<ProviderConfiguration>
                {
                    new ProviderConfiguration
                    {
                        ProviderType = ProviderType.Mmdb,
                        Priority = 1,
                        IsEnabled = true,
                        Settings = new Dictionary<string, string>
                        {
                            ["DatabasePath"] = "GeoLite2-Country.mmdb"
                        }
                    },
                    new ProviderConfiguration
                    {
                        ProviderType = ProviderType.Sqlite,
                        Priority = 2,
                        IsEnabled = true,
                        Settings = new Dictionary<string, string>
                        {
                            ["DatabasePath"] = "geoip.db"
                        }
                    },
                    new ProviderConfiguration
                    {
                        ProviderType = ProviderType.Api,
                        Priority = 3,
                        IsEnabled = true,
                        Settings = new Dictionary<string, string>
                        {
                            ["ApiProvider"] = "ip-api",
                            ["RateLimitPerSecond"] = "45",
                            ["BaseUrl"] = "http://ip-api.com/json/"
                        }
                    }
                }
            };
        }

        /// <summary>
        /// Validates the configuration
        /// </summary>
        public bool Validate(out List<string> errors)
        {
            errors = new List<string>();

            if (CacheExpiration <= TimeSpan.Zero)
            {
                errors.Add("CacheExpiration must be greater than zero");
            }

            if (MaxCacheSize <= 0)
            {
                errors.Add("MaxCacheSize must be greater than zero");
            }

            if (ProviderInitializationTimeout <= TimeSpan.Zero)
            {
                errors.Add("ProviderInitializationTimeout must be greater than zero");
            }

            if (LookupTimeout <= TimeSpan.Zero)
            {
                errors.Add("LookupTimeout must be greater than zero");
            }

            if (MaxDegreeOfParallelism <= 0)
            {
                errors.Add("MaxDegreeOfParallelism must be greater than zero");
            }

            if (Providers == null || Providers.Count == 0)
            {
                errors.Add("At least one provider must be configured");
            }
            else
            {
                var enabledProviders = Providers.FindAll(p => p.IsEnabled);
                if (enabledProviders.Count == 0)
                {
                    errors.Add("At least one provider must be enabled");
                }

                // Check for duplicate priorities
                var priorities = new HashSet<int>();
                foreach (var provider in enabledProviders)
                {
                    if (!priorities.Add(provider.Priority))
                    {
                        errors.Add($"Duplicate priority {provider.Priority} found in provider configuration");
                    }

                    // Validate each provider
                    if (!provider.Validate(out var providerErrors))
                    {
                        errors.AddRange(providerErrors);
                    }
                }
            }

            return errors.Count == 0;
        }
    }

    /// <summary>
    /// Configuration for a specific GeoIP provider
    /// </summary>
    public class ProviderConfiguration
    {
        /// <summary>
        /// Type of provider
        /// </summary>
        public ProviderType ProviderType { get; set; }

        /// <summary>
        /// Priority (lower number = higher priority, tried first)
        /// </summary>
        public int Priority { get; set; }

        /// <summary>
        /// Whether this provider is enabled
        /// </summary>
        public bool IsEnabled { get; set; } = true;

        /// <summary>
        /// Provider-specific settings
        /// </summary>
        public Dictionary<string, string> Settings { get; set; } = new();

        /// <summary>
        /// Retry attempts on failure
        /// </summary>
        public int MaxRetries { get; set; } = 3;

        /// <summary>
        /// Delay between retries
        /// </summary>
        public TimeSpan RetryDelay { get; set; } = TimeSpan.FromMilliseconds(500);

        /// <summary>
        /// Timeout for this specific provider
        /// </summary>
        public TimeSpan? Timeout { get; set; }

        /// <summary>
        /// Validates the provider configuration
        /// </summary>
        public bool Validate(out List<string> errors)
        {
            errors = new List<string>();

            if (Priority < 0)
            {
                errors.Add($"Priority must be non-negative for provider {ProviderType}");
            }

            if (MaxRetries < 0)
            {
                errors.Add($"MaxRetries must be non-negative for provider {ProviderType}");
            }

            if (RetryDelay < TimeSpan.Zero)
            {
                errors.Add($"RetryDelay must be non-negative for provider {ProviderType}");
            }

            if (Timeout.HasValue && Timeout.Value <= TimeSpan.Zero)
            {
                errors.Add($"Timeout must be greater than zero for provider {ProviderType}");
            }

            // Provider-specific validation
            switch (ProviderType)
            {
                case ProviderType.Mmdb:
                    if (!Settings.ContainsKey("DatabasePath"))
                    {
                        errors.Add("MMDB provider requires 'DatabasePath' setting");
                    }
                    break;

                case ProviderType.Sqlite:
                    if (!Settings.ContainsKey("DatabasePath"))
                    {
                        errors.Add("SQLite provider requires 'DatabasePath' setting");
                    }
                    break;

                case ProviderType.Api:
                    if (!Settings.ContainsKey("BaseUrl"))
                    {
                        errors.Add("API provider requires 'BaseUrl' setting");
                    }
                    if (!Settings.ContainsKey("ApiProvider"))
                    {
                        errors.Add("API provider requires 'ApiProvider' setting");
                    }
                    break;

                case ProviderType.Csv:
                    if (!Settings.ContainsKey("BlocksPath") || !Settings.ContainsKey("LocationsPath"))
                    {
                        errors.Add("CSV provider requires 'BlocksPath' and 'LocationsPath' settings");
                    }
                    break;
            }

            return errors.Count == 0;
        }

        /// <summary>
        /// Gets a setting value
        /// </summary>
        public string? GetSetting(string key, string? defaultValue = null)
        {
            return Settings.TryGetValue(key, out var value) ? value : defaultValue;
        }

        /// <summary>
        /// Gets a setting value as integer
        /// </summary>
        public int GetSettingAsInt(string key, int defaultValue = 0)
        {
            if (Settings.TryGetValue(key, out var value) && int.TryParse(value, out var result))
            {
                return result;
            }
            return defaultValue;
        }

        /// <summary>
        /// Gets a setting value as boolean
        /// </summary>
        public bool GetSettingAsBool(string key, bool defaultValue = false)
        {
            if (Settings.TryGetValue(key, out var value) && bool.TryParse(value, out var result))
            {
                return result;
            }
            return defaultValue;
        }
    }

    /// <summary>
    /// Type of GeoIP provider
    /// </summary>
    public enum ProviderType
    {
        /// <summary>
        /// MaxMind MMDB (binary database) - Fast, local
        /// </summary>
        Mmdb,

        /// <summary>
        /// SQLite database - Persistent storage with additional metadata
        /// </summary>
        Sqlite,

        /// <summary>
        /// API-based (online) - Fallback for missing data
        /// </summary>
        Api,

        /// <summary>
        /// CSV-based (GeoLite2 CSV format) - For custom imports
        /// </summary>
        Csv
    }
}
