using System.Collections.Generic;
using PCAPAnalyzer.Core.Security;

namespace PCAPAnalyzer.Core.Interfaces;

/// <summary>
/// Interface for port database service providing port information and risk assessment.
/// Replaces static PortDatabase class with dependency injection pattern.
/// </summary>
public interface IPortDatabase
{
    /// <summary>
    /// Look up port information by port number and transport protocol.
    /// </summary>
    PortDatabase.PortInfo? GetPortInfo(ushort port, bool isTcp = true);

    /// <summary>
    /// Look up TCP port information.
    /// </summary>
    PortDatabase.PortInfo? GetTcpPortInfo(ushort port);

    /// <summary>
    /// Look up UDP port information.
    /// </summary>
    PortDatabase.PortInfo? GetUdpPortInfo(ushort port);

    /// <summary>
    /// Get the service name for a port, or null if unknown.
    /// </summary>
    string? GetServiceName(ushort port, bool isTcp = true);

    /// <summary>
    /// Get the risk level for a port.
    /// </summary>
    PortDatabase.PortRisk GetRisk(ushort port, bool isTcp = true);

    /// <summary>
    /// Check if a port is considered high-risk or critical.
    /// </summary>
    bool IsHighRiskPort(ushort port, bool isTcp = true);

    /// <summary>
    /// Get all ports in a specific category.
    /// </summary>
    IEnumerable<(ushort Port, PortDatabase.TransportProtocol Transport, PortDatabase.PortInfo Info)> GetPortsByCategory(string category);

    /// <summary>
    /// Get all ports with a specific risk level.
    /// </summary>
    IEnumerable<(ushort Port, PortDatabase.TransportProtocol Transport, PortDatabase.PortInfo Info)> GetPortsByRisk(PortDatabase.PortRisk risk);

    /// <summary>
    /// Get the total number of ports in the database.
    /// </summary>
    int Count { get; }

    /// <summary>
    /// Get all available categories.
    /// </summary>
    IEnumerable<string> GetCategories();

    /// <summary>
    /// Maps PortRisk to ProtocolSecurityEvaluator.SecurityLevel for integration.
    /// </summary>
    ProtocolSecurityEvaluator.SecurityLevel ToSecurityLevel(PortDatabase.PortRisk risk);

    /// <summary>
    /// Get color for risk level (UI display).
    /// </summary>
    string GetRiskColor(PortDatabase.PortRisk risk);
}
