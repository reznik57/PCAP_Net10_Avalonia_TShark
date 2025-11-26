using Microsoft.AspNetCore.Mvc;
using PCAPAnalyzer.API.DTOs;
using PCAPAnalyzer.API.Models;
using PCAPAnalyzer.API.Services;

namespace PCAPAnalyzer.API.Controllers;

/// <summary>
/// Statistics and metrics endpoints
/// </summary>
[ApiController]
[Route("api/v1/stats")]
[Produces("application/json")]
public class StatisticsController : ControllerBase
{
    private readonly IStatisticsService _statisticsService;
    private readonly ILogger<StatisticsController> _logger;

    public StatisticsController(IStatisticsService statisticsService, ILogger<StatisticsController> logger)
    {
        _statisticsService = statisticsService;
        _logger = logger;
    }

    /// <summary>
    /// Get overall statistics summary
    /// </summary>
    [HttpGet("{id}/summary")]
    [ProducesResponseType(typeof(ApiResponse<StatisticsSummaryDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<StatisticsSummaryDto>>> GetSummary(
        string id,
        CancellationToken cancellationToken)
    {
        var summary = await _statisticsService.GetSummaryAsync(id, cancellationToken);
        return Ok(ApiResponse<StatisticsSummaryDto>.SuccessResult(summary));
    }

    /// <summary>
    /// Get protocol distribution statistics
    /// </summary>
    [HttpGet("{id}/protocols")]
    [ProducesResponseType(typeof(ApiResponse<IEnumerable<ProtocolStatisticsDto>>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<IEnumerable<ProtocolStatisticsDto>>>> GetProtocols(
        string id,
        CancellationToken cancellationToken)
    {
        var protocols = await _statisticsService.GetProtocolsAsync(id, cancellationToken);
        return Ok(ApiResponse<IEnumerable<ProtocolStatisticsDto>>.SuccessResult(protocols));
    }

    /// <summary>
    /// Get top conversations with pagination
    /// </summary>
    [HttpGet("{id}/conversations")]
    [ProducesResponseType(typeof(ApiResponse<PaginatedResult<ConversationDto>>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<PaginatedResult<ConversationDto>>>> GetConversations(
        string id,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        CancellationToken cancellationToken = default)
    {
        var conversations = await _statisticsService.GetConversationsAsync(id, page, pageSize, cancellationToken);
        return Ok(ApiResponse<PaginatedResult<ConversationDto>>.SuccessResult(conversations));
    }

    /// <summary>
    /// Get geographic distribution of traffic
    /// </summary>
    [HttpGet("{id}/geographic")]
    [ProducesResponseType(typeof(ApiResponse<IEnumerable<GeographicStatisticsDto>>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<IEnumerable<GeographicStatisticsDto>>>> GetGeographic(
        string id,
        CancellationToken cancellationToken)
    {
        var geoStats = await _statisticsService.GetGeographicAsync(id, cancellationToken);
        return Ok(ApiResponse<IEnumerable<GeographicStatisticsDto>>.SuccessResult(geoStats));
    }
}
