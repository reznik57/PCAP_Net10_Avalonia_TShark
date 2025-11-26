using Microsoft.AspNetCore.Mvc;
using PCAPAnalyzer.API.DTOs;
using PCAPAnalyzer.API.Models;
using PCAPAnalyzer.API.Services;

namespace PCAPAnalyzer.API.Controllers;

/// <summary>
/// Real-time packet capture endpoints
/// </summary>
[ApiController]
[Route("api/v1/capture")]
[Produces("application/json")]
public class CaptureController : ControllerBase
{
    private readonly ICaptureService _captureService;
    private readonly ILogger<CaptureController> _logger;

    public CaptureController(ICaptureService captureService, ILogger<CaptureController> logger)
    {
        _captureService = captureService;
        _logger = logger;
    }

    /// <summary>
    /// Get list of available network interfaces
    /// </summary>
    [HttpGet("interfaces")]
    [ProducesResponseType(typeof(ApiResponse<IEnumerable<NetworkInterfaceDto>>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<IEnumerable<NetworkInterfaceDto>>>> GetInterfaces(
        CancellationToken cancellationToken)
    {
        var interfaces = await _captureService.GetInterfacesAsync(cancellationToken);
        return Ok(ApiResponse<IEnumerable<NetworkInterfaceDto>>.SuccessResult(interfaces));
    }

    /// <summary>
    /// Start a new packet capture session
    /// </summary>
    [HttpPost("start")]
    [ProducesResponseType(typeof(ApiResponse<CaptureSessionDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<CaptureSessionDto>>> StartCapture(
        [FromBody] StartCaptureRequest request,
        CancellationToken cancellationToken)
    {
        var session = await _captureService.StartCaptureAsync(request, cancellationToken);
        return Ok(ApiResponse<CaptureSessionDto>.SuccessResult(session, "Capture started"));
    }

    /// <summary>
    /// Stop an active capture session
    /// </summary>
    [HttpPost("{sessionId}/stop")]
    [ProducesResponseType(typeof(ApiResponse<CaptureSessionDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<CaptureSessionDto>>> StopCapture(
        string sessionId,
        CancellationToken cancellationToken)
    {
        var session = await _captureService.StopCaptureAsync(sessionId, cancellationToken);
        return Ok(ApiResponse<CaptureSessionDto>.SuccessResult(session, "Capture stopped"));
    }

    /// <summary>
    /// Get status of a capture session
    /// </summary>
    [HttpGet("{sessionId}/status")]
    [ProducesResponseType(typeof(ApiResponse<CaptureSessionDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<ApiResponse<CaptureSessionDto>>> GetCaptureStatus(
        string sessionId,
        CancellationToken cancellationToken)
    {
        var session = await _captureService.GetCaptureStatusAsync(sessionId, cancellationToken);
        return Ok(ApiResponse<CaptureSessionDto>.SuccessResult(session));
    }
}
