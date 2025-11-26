namespace PCAPAnalyzer.API.DTOs;

/// <summary>
/// Network interface DTO
/// </summary>
public class NetworkInterfaceDto
{
    public required string Id { get; set; }
    public required string Name { get; set; }
    public required string Description { get; set; }
    public bool IsUp { get; set; }
    public List<string>? IpAddresses { get; set; }
    public string? MacAddress { get; set; }
}

/// <summary>
/// Start capture request
/// </summary>
public class StartCaptureRequest
{
    public required string InterfaceId { get; set; }
    public string? Filter { get; set; } // BPF filter
    public int? MaxPackets { get; set; }
    public int? MaxDurationSeconds { get; set; }
    public int? SnapshotLength { get; set; }
    public bool Promiscuous { get; set; } = true;
}

/// <summary>
/// Capture session DTO
/// </summary>
public class CaptureSessionDto
{
    public required string SessionId { get; set; }
    public required string InterfaceId { get; set; }
    public required string Status { get; set; } // running, stopped, error
    public DateTime StartedAt { get; set; }
    public DateTime? StoppedAt { get; set; }
    public long PacketsCaptured { get; set; }
    public long BytesCaptured { get; set; }
    public string? Filter { get; set; }
}

/// <summary>
/// Live packet stream event
/// </summary>
public class LivePacketEvent
{
    public required string SessionId { get; set; }
    public long PacketNumber { get; set; }
    public DateTime Timestamp { get; set; }
    public required string SourceIP { get; set; }
    public required string DestinationIP { get; set; }
    public int SourcePort { get; set; }
    public int DestinationPort { get; set; }
    public required string Protocol { get; set; }
    public int Length { get; set; }
    public string? Info { get; set; }
}
