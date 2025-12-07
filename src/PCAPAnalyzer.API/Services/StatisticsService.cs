using PCAPAnalyzer.API.DTOs;

namespace PCAPAnalyzer.API.Services;

public sealed class StatisticsService : IStatisticsService
{
    private readonly ILogger<StatisticsService> _logger;

    public StatisticsService(ILogger<StatisticsService> logger)
    {
        _logger = logger;
    }

    public Task<StatisticsSummaryDto> GetSummaryAsync(string pcapId, CancellationToken cancellationToken = default)
    {
        // Mock implementation
        var summary = new StatisticsSummaryDto
        {
            PcapId = pcapId,
            TotalPackets = 15234,
            TotalBytes = 12456789,
            FirstPacketTime = DateTime.UtcNow.AddHours(-2),
            LastPacketTime = DateTime.UtcNow,
            Duration = TimeSpan.FromHours(2),
            AveragePacketSize = 817.5,
            PacketsPerSecond = 2.12,
            UniqueSourceIPs = 45,
            UniqueDestinationIPs = 128,
            ProtocolDistribution = new Dictionary<string, long>
            {
                { "TCP", 8234 },
                { "UDP", 5123 },
                { "ICMP", 1234 },
                { "ARP", 643 }
            }
        };

        return Task.FromResult(summary);
    }

    public Task<IEnumerable<ProtocolStatisticsDto>> GetProtocolsAsync(string pcapId, CancellationToken cancellationToken = default)
    {
        var protocols = new List<ProtocolStatisticsDto>
        {
            new() { Protocol = "TCP", PacketCount = 8234, ByteCount = 6789012, Percentage = 54.1, AveragePacketSize = 824.5 },
            new() { Protocol = "UDP", PacketCount = 5123, ByteCount = 4123456, Percentage = 33.6, AveragePacketSize = 804.8 },
            new() { Protocol = "ICMP", PacketCount = 1234, ByteCount = 987654, Percentage = 8.1, AveragePacketSize = 800.0 },
            new() { Protocol = "ARP", PacketCount = 643, ByteCount = 556667, Percentage = 4.2, AveragePacketSize = 866.0 }
        };

        return Task.FromResult<IEnumerable<ProtocolStatisticsDto>>(protocols);
    }

    public Task<PaginatedResult<ConversationDto>> GetConversationsAsync(string pcapId, int page, int pageSize, CancellationToken cancellationToken = default)
    {
        var allConversations = GenerateMockConversations();
        var totalCount = allConversations.Count;
        var totalPages = (int)Math.Ceiling(totalCount / (double)pageSize);

        var pagedConversations = allConversations
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToList();

        var result = new PaginatedResult<ConversationDto>
        {
            Items = pagedConversations,
            Page = page,
            PageSize = pageSize,
            TotalPages = totalPages,
            TotalCount = totalCount,
            Links = new Dictionary<string, string>
            {
                { "self", $"/api/v1/stats/{pcapId}/conversations?page={page}&pageSize={pageSize}" },
                { "first", $"/api/v1/stats/{pcapId}/conversations?page=1&pageSize={pageSize}" },
                { "last", $"/api/v1/stats/{pcapId}/conversations?page={totalPages}&pageSize={pageSize}" }
            }
        };

        if (page > 1)
            result.Links["previous"] = $"/api/v1/stats/{pcapId}/conversations?page={page - 1}&pageSize={pageSize}";

        if (page < totalPages)
            result.Links["next"] = $"/api/v1/stats/{pcapId}/conversations?page={page + 1}&pageSize={pageSize}";

        return Task.FromResult(result);
    }

    public Task<IEnumerable<GeographicStatisticsDto>> GetGeographicAsync(string pcapId, CancellationToken cancellationToken = default)
    {
        var geoStats = new List<GeographicStatisticsDto>
        {
            new() { Country = "United States", CountryCode = "US", PacketCount = 5234, ByteCount = 4123456, IpAddresses = new List<string> { "8.8.8.8", "1.1.1.1" } },
            new() { Country = "Germany", CountryCode = "DE", PacketCount = 3123, ByteCount = 2456789, IpAddresses = new List<string> { "185.12.64.1" } },
            new() { Country = "United Kingdom", CountryCode = "GB", PacketCount = 2234, ByteCount = 1789012, IpAddresses = new List<string> { "151.101.1.140" } },
            new() { Country = "Japan", CountryCode = "JP", PacketCount = 1543, ByteCount = 1234567, IpAddresses = new List<string> { "210.152.12.1" } }
        };

        return Task.FromResult<IEnumerable<GeographicStatisticsDto>>(geoStats);
    }

    private static List<ConversationDto> GenerateMockConversations()
    {
        return new List<ConversationDto>
        {
            new() { SourceIP = "192.168.1.100", DestinationIP = "8.8.8.8", SourcePort = 54321, DestinationPort = 443, Protocol = "TCP", PacketCount = 1234, ByteCount = 987654, FirstSeen = DateTime.UtcNow.AddHours(-1), LastSeen = DateTime.UtcNow },
            new() { SourceIP = "192.168.1.100", DestinationIP = "1.1.1.1", SourcePort = 54322, DestinationPort = 53, Protocol = "UDP", PacketCount = 567, ByteCount = 456789, FirstSeen = DateTime.UtcNow.AddHours(-1), LastSeen = DateTime.UtcNow },
            new() { SourceIP = "192.168.1.101", DestinationIP = "93.184.216.34", SourcePort = 54323, DestinationPort = 80, Protocol = "TCP", PacketCount = 890, ByteCount = 765432, FirstSeen = DateTime.UtcNow.AddMinutes(-30), LastSeen = DateTime.UtcNow },
        };
    }
}
