namespace PCAPAnalyzer.API.Configuration;

/// <summary>
/// JWT authentication settings
/// </summary>
public class JwtSettings
{
    public const string SectionName = "JwtSettings";

    public required string SecretKey { get; set; }
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public int ExpirationMinutes { get; set; } = 60;
    public int RefreshTokenExpirationDays { get; set; } = 7;
}

/// <summary>
/// Rate limiting settings
/// </summary>
public class RateLimitSettings
{
    public const string SectionName = "RateLimitSettings";

    public bool Enabled { get; set; } = true;
    public int PermitLimit { get; set; } = 100;
    public int WindowSeconds { get; set; } = 60;
    public int QueueLimit { get; set; } = 10;
}

/// <summary>
/// CORS settings
/// </summary>
public class CorsSettings
{
    public const string SectionName = "CorsSettings";

    public required string[] AllowedOrigins { get; set; }
    public bool AllowCredentials { get; set; } = true;
    public string[] AllowedMethods { get; set; } = new[] { "GET", "POST", "PUT", "DELETE", "OPTIONS" };
    public string[] AllowedHeaders { get; set; } = new[] { "Content-Type", "Authorization" };
}
