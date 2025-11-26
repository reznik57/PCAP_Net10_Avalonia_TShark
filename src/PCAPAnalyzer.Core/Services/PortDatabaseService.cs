using System.Collections.Generic;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Security;

namespace PCAPAnalyzer.Core.Services;

/// <summary>
/// Service implementation of port database using IOptions pattern.
/// Delegates to static PortDatabase for backward compatibility during migration.
/// Future enhancement: Load from config/ports.json via IOptions&lt;PortConfiguration&gt;.
/// </summary>
public class PortDatabaseService : IPortDatabase
{
    /// <summary>
    /// Look up port information by port number and transport protocol.
    /// </summary>
    public PortDatabase.PortInfo? GetPortInfo(ushort port, bool isTcp = true)
    {
        return PortDatabase.GetPortInfo(port, isTcp);
    }

    /// <summary>
    /// Look up TCP port information.
    /// </summary>
    public PortDatabase.PortInfo? GetTcpPortInfo(ushort port)
    {
        return PortDatabase.GetTcpPortInfo(port);
    }

    /// <summary>
    /// Look up UDP port information.
    /// </summary>
    public PortDatabase.PortInfo? GetUdpPortInfo(ushort port)
    {
        return PortDatabase.GetUdpPortInfo(port);
    }

    /// <summary>
    /// Get the service name for a port, or null if unknown.
    /// </summary>
    public string? GetServiceName(ushort port, bool isTcp = true)
    {
        return PortDatabase.GetServiceName(port, isTcp);
    }

    /// <summary>
    /// Get the risk level for a port.
    /// </summary>
    public PortDatabase.PortRisk GetRisk(ushort port, bool isTcp = true)
    {
        return PortDatabase.GetRisk(port, isTcp);
    }

    /// <summary>
    /// Check if a port is considered high-risk or critical.
    /// </summary>
    public bool IsHighRiskPort(ushort port, bool isTcp = true)
    {
        return PortDatabase.IsHighRiskPort(port, isTcp);
    }

    /// <summary>
    /// Get all ports in a specific category.
    /// </summary>
    public IEnumerable<(ushort Port, PortDatabase.TransportProtocol Transport, PortDatabase.PortInfo Info)> GetPortsByCategory(string category)
    {
        return PortDatabase.GetPortsByCategory(category);
    }

    /// <summary>
    /// Get all ports with a specific risk level.
    /// </summary>
    public IEnumerable<(ushort Port, PortDatabase.TransportProtocol Transport, PortDatabase.PortInfo Info)> GetPortsByRisk(PortDatabase.PortRisk risk)
    {
        return PortDatabase.GetPortsByRisk(risk);
    }

    /// <summary>
    /// Get the total number of ports in the database.
    /// </summary>
    public int Count => PortDatabase.Count;

    /// <summary>
    /// Get all available categories.
    /// </summary>
    public IEnumerable<string> GetCategories()
    {
        return PortDatabase.GetCategories();
    }

    /// <summary>
    /// Maps PortRisk to ProtocolSecurityEvaluator.SecurityLevel for integration.
    /// </summary>
    public ProtocolSecurityEvaluator.SecurityLevel ToSecurityLevel(PortDatabase.PortRisk risk)
    {
        return PortDatabase.ToSecurityLevel(risk);
    }

    /// <summary>
    /// Get color for risk level (UI display).
    /// </summary>
    public string GetRiskColor(PortDatabase.PortRisk risk)
    {
        return PortDatabase.GetRiskColor(risk);
    }
}
