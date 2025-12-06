using System;
using System.Collections.Generic;
using System.Linq;
using PCAPAnalyzer.Core.Extensions;
using PCAPAnalyzer.Core.Interfaces;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Core.Services.AnomalyDetectors;

/// <summary>
/// Detects IoT-specific anomalies: MQTT flooding, CoAP amplification, unauthorized access, multiple brokers
/// </summary>
public class IoTAnomalyDetector : ISpecializedDetector
{
    private const int MQTT_PORT = 1883;
    private const int MQTT_SECURE_PORT = 8883;
    private const int COAP_PORT = 5683;
    private const int MQTT_MESSAGE_THRESHOLD = 100; // Messages per second
    private const double COAP_AMPLIFICATION_RATIO = 10; // Response/Request size ratio

    public string Name => "IoT Anomaly Detector";
    public AnomalyCategory Category => AnomalyCategory.IoT;
    public int Priority => 4;

    public bool CanDetect(IEnumerable<PacketInfo> packets) =>
        packets.Any(p => p.IsIoTTraffic());

    public List<NetworkAnomaly> Detect(IEnumerable<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var packetList = packets.ToList();

        if (!packetList.Any())
            return anomalies;

        anomalies.AddRange(DetectMQTTFlooding(packetList));
        anomalies.AddRange(DetectMultipleBrokers(packetList));
        anomalies.AddRange(DetectCoAPAmplification(packetList));
        anomalies.AddRange(DetectUnauthorizedAccess(packetList));

        return anomalies;
    }

    private List<NetworkAnomaly> DetectMQTTFlooding(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var mqttPackets = packets.Where(p => p.IsMqttTraffic()).ToList();

        if (!mqttPackets.Any())
            return anomalies;

        // Group by broker (destination IP for client->broker traffic)
        var brokerGroups = mqttPackets
            .Where(p => p.DestinationPort == MQTT_PORT || p.DestinationPort == MQTT_SECURE_PORT)
            .GroupBy(p => p.DestinationIP);

        foreach (var broker in brokerGroups)
        {
            var brokerPackets = broker.ToList();
            var timeWindow = brokerPackets.Max(p => p.Timestamp) - brokerPackets.Min(p => p.Timestamp);

            if (timeWindow.TotalSeconds > 0)
            {
                var messagesPerSecond = brokerPackets.Count / timeWindow.TotalSeconds;

                if (messagesPerSecond >= MQTT_MESSAGE_THRESHOLD)
                {
                    var publishCount = brokerPackets.Count(p => p.IsMqttPublish());
                    var subscribeCount = brokerPackets.Count(p => p.IsMqttSubscribe());
                    var connectCount = brokerPackets.Count(p => p.IsMqttConnect());

                    // Get the most active source (attacker)
                    var topSource = brokerPackets
                        .GroupBy(p => p.SourceIP)
                        .OrderByDescending(g => g.Count())
                        .First();

                    anomalies.Add(new NetworkAnomaly
                    {
                        Category = AnomalyCategory.IoT,
                        Type = "IoT MQTT Flooding",
                        Severity = messagesPerSecond > 200 ? AnomalySeverity.Critical : AnomalySeverity.High,
                        Description = $"MQTT flooding detected: {messagesPerSecond:F1} messages/second to broker {broker.Key}",
                        DetectedAt = brokerPackets.First().Timestamp,
                        DetectorName = Name,
                        SourceIP = topSource.Key ?? "",
                        DestinationIP = broker.Key ?? "",
                        DestinationPort = MQTT_PORT,
                        Protocol = "MQTT",
                        AffectedFrames = brokerPackets.Select(p => (long)p.FrameNumber).Take(100).ToList(),
                        Metrics = new Dictionary<string, object>
                        {
                            { "MessagesPerSecond", messagesPerSecond },
                            { "TotalMessages", brokerPackets.Count },
                            { "PublishCount", publishCount },
                            { "SubscribeCount", subscribeCount },
                            { "ConnectCount", connectCount },
                            { "UniqueSources", brokerPackets.Select(p => p.SourceIP).Distinct().Count() },
                            { "TopSourceIP", topSource.Key ?? "" }
                        },
                        Recommendation = "MQTT flooding may indicate DoS attack on IoT infrastructure. Implement rate limiting, message throttling, and authenticate MQTT clients."
                    });
                }
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectMultipleBrokers(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var mqttPackets = packets.Where(p =>
            p.IsMqttTraffic() && p.ToAnyPort(MQTT_PORT, MQTT_SECURE_PORT)).ToList();

        if (!mqttPackets.Any())
            return anomalies;

        // Group by source to find devices connecting to multiple brokers
        var deviceGroups = mqttPackets.GroupBy(p => p.SourceIP);

        foreach (var device in deviceGroups)
        {
            var uniqueBrokers = device.Select(p => p.DestinationIP).Distinct().ToList();

            if (uniqueBrokers.Count >= 3) // Device connecting to 3+ different brokers
            {
                var devicePackets = device.ToList();
                // Get the most common broker destination
                var topBroker = devicePackets
                    .GroupBy(p => p.DestinationIP)
                    .OrderByDescending(g => g.Count())
                    .FirstOrDefault()?.Key ?? "";

                anomalies.Add(new NetworkAnomaly
                {
                    Category = AnomalyCategory.IoT,
                    Type = "IoT Multiple Brokers",
                    Severity = uniqueBrokers.Count >= 5 ? AnomalySeverity.High : AnomalySeverity.Medium,
                    Description = $"IoT device {device.Key} connected to {uniqueBrokers.Count} different MQTT brokers",
                    DetectedAt = devicePackets.First().Timestamp,
                    DetectorName = Name,
                    SourceIP = device.Key ?? "",
                    DestinationIP = topBroker,
                    DestinationPort = MQTT_PORT,
                    Protocol = "MQTT",
                    AffectedFrames = devicePackets.Select(p => (long)p.FrameNumber).ToList(),
                    Metrics = new Dictionary<string, object>
                    {
                        { "BrokerCount", uniqueBrokers.Count },
                        { "Brokers", uniqueBrokers },
                        { "ConnectionAttempts", devicePackets.Count },
                        { "TopBrokerIP", topBroker }
                    },
                    Recommendation = "IoT device connecting to multiple brokers may indicate compromise or misconfiguration. Investigate device behavior and ensure proper network segmentation."
                });
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectCoAPAmplification(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();
        var coapPackets = packets.Where(p => p.IsCoapTraffic()).ToList();

        if (coapPackets.Count < 10)
            return anomalies;

        // Look for CoAP request/response pairs with significant amplification
        var requests = coapPackets.Where(p => p.DestinationPort == COAP_PORT).ToList();
        var responses = coapPackets.Where(p => p.SourcePort == COAP_PORT).ToList();

        if (!requests.Any() || !responses.Any())
            return anomalies;

        // Group by source IP (potential attacker) to find amplification patterns
        var sourceGroups = requests.GroupBy(p => p.SourceIP);

        foreach (var source in sourceGroups)
        {
            var sourceRequests = source.ToList();
            var relatedResponses = responses.Where(r =>
                sourceRequests.Any(req =>
                    req.SourceIP == r.DestinationIP &&
                    Math.Abs((r.Timestamp - req.Timestamp).TotalSeconds) < 1)).ToList();

            if (relatedResponses.Any())
            {
                var totalRequestSize = sourceRequests.Sum(p => (long)p.Length);
                var totalResponseSize = relatedResponses.Sum(p => (long)p.Length);

                if (totalRequestSize > 0)
                {
                    var amplificationRatio = (double)totalResponseSize / totalRequestSize;

                    if (amplificationRatio >= COAP_AMPLIFICATION_RATIO)
                    {
                        // Get the most common CoAP server destination
                        var topDestination = sourceRequests
                            .GroupBy(p => p.DestinationIP)
                            .OrderByDescending(g => g.Count())
                            .FirstOrDefault()?.Key ?? "";

                        anomalies.Add(new NetworkAnomaly
                        {
                            Category = AnomalyCategory.IoT,
                            Type = "IoT CoAP Amplification",
                            Severity = amplificationRatio > 50 ? AnomalySeverity.Critical : AnomalySeverity.High,
                            Description = $"CoAP amplification attack: {amplificationRatio:F1}x amplification ratio",
                            DetectedAt = sourceRequests.First().Timestamp,
                            DetectorName = Name,
                            SourceIP = source.Key ?? "",
                            DestinationIP = topDestination,
                            DestinationPort = COAP_PORT,
                            Protocol = "CoAP",
                            AffectedFrames = sourceRequests.Concat(relatedResponses).Select(p => (long)p.FrameNumber).Take(100).ToList(),
                            Metrics = new Dictionary<string, object>
                            {
                                { "AmplificationRatio", amplificationRatio },
                                { "RequestCount", sourceRequests.Count },
                                { "ResponseCount", relatedResponses.Count },
                                { "TotalRequestBytes", totalRequestSize },
                                { "TotalResponseBytes", totalResponseSize },
                                { "TopCoAPServer", topDestination }
                            },
                            Recommendation = "CoAP amplification attack detected. Block source IP and implement CoAP request rate limiting. Consider disabling CoAP on public interfaces."
                        });
                    }
                }
            }
        }

        return anomalies;
    }

    private List<NetworkAnomaly> DetectUnauthorizedAccess(List<PacketInfo> packets)
    {
        var anomalies = new List<NetworkAnomaly>();

        // Look for failed authentication or connection attempts
        var iotPackets = packets.Where(p => p.IsIoTTraffic()).ToList();

        if (!iotPackets.Any())
            return anomalies;

        // Look for multiple connection attempts from the same source
        var connectionAttempts = iotPackets.Where(p =>
            p.InfoContainsAny("Connect", "CON")).ToList();

        var sourceGroups = connectionAttempts.GroupBy(p => p.SourceIP);

        foreach (var source in sourceGroups)
        {
            var attempts = source.ToList();
            var timeWindow = attempts.Max(p => p.Timestamp) - attempts.Min(p => p.Timestamp);

            // Multiple rapid connection attempts may indicate scanning or brute force
            if (attempts.Count >= 10 && timeWindow.TotalMinutes < 5)
            {
                var attemptsPerMinute = attempts.Count / Math.Max(timeWindow.TotalMinutes, 1);

                // Get the most targeted broker/server
                var topTarget = attempts
                    .GroupBy(p => p.DestinationIP)
                    .OrderByDescending(g => g.Count())
                    .FirstOrDefault()?.Key ?? "";

                anomalies.Add(new NetworkAnomaly
                {
                    Category = AnomalyCategory.IoT,
                    Type = "IoT Unauthorized Access",
                    Severity = attemptsPerMinute > 10 ? AnomalySeverity.High : AnomalySeverity.Medium,
                    Description = $"Potential unauthorized access attempts: {attempts.Count} connection attempts from {source.Key}",
                    DetectedAt = attempts.First().Timestamp,
                    DetectorName = Name,
                    SourceIP = source.Key ?? "",
                    DestinationIP = topTarget,
                    DestinationPort = attempts.First().DestinationPort,
                    Protocol = attempts.First().DestinationPort == MQTT_PORT ? "MQTT" : "CoAP",
                    AffectedFrames = attempts.Select(p => (long)p.FrameNumber).ToList(),
                    Metrics = new Dictionary<string, object>
                    {
                        { "ConnectionAttempts", attempts.Count },
                        { "AttemptsPerMinute", attemptsPerMinute },
                        { "TimeWindowMinutes", timeWindow.TotalMinutes },
                        { "TargetedBrokers", attempts.Select(p => p.DestinationIP).Distinct().Count() },
                        { "TopTargetIP", topTarget }
                    },
                    Recommendation = "Multiple connection attempts may indicate scanning or brute force attack. Enable authentication, implement rate limiting, and consider blocking the source."
                });
            }
        }

        return anomalies;
    }
}
