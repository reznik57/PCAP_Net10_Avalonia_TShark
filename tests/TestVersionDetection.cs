using System;
using System.Collections.Generic;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;

namespace PCAPAnalyzer.Tests
{
    public class TestVersionDetection
    {
        public static void TestProtocolVersionDetection()
        {
            var detector = new ProtocolVersionDetector();
            var insecurePortDetector = new InsecurePortDetector(detector);
            
            // Create test packets with version information
            var testPackets = new List<PacketInfo>
            {
                // HTTPS with TLS 1.0 (insecure)
                new PacketInfo
                {
                    FrameNumber = 1,
                    Timestamp = DateTime.Now,
                    SourceIP = "192.168.1.100",
                    DestinationIP = "10.0.0.1",
                    SourcePort = 54321,
                    DestinationPort = 443,
                    Protocol = Protocol.TCP,
                    Length = 100,
                    Info = "TLS 1.0 Client Hello"
                },
                
                // HTTPS with SSL 3.0 (critical)
                new PacketInfo
                {
                    FrameNumber = 2,
                    Timestamp = DateTime.Now,
                    SourceIP = "192.168.1.101",
                    DestinationIP = "10.0.0.2",
                    SourcePort = 54322,
                    DestinationPort = 443,
                    Protocol = Protocol.TCP,
                    Length = 100,
                    Info = "SSL 3.0 Handshake"
                },
                
                // SSH-1.5 (critical)
                new PacketInfo
                {
                    FrameNumber = 3,
                    Timestamp = DateTime.Now,
                    SourceIP = "192.168.1.102",
                    DestinationIP = "10.0.0.3",
                    SourcePort = 54323,
                    DestinationPort = 22,
                    Protocol = Protocol.TCP,
                    Length = 100,
                    Info = "SSH-1.5-OpenSSH_4.3"
                },
                
                // SMBv1 (critical)
                new PacketInfo
                {
                    FrameNumber = 4,
                    Timestamp = DateTime.Now,
                    SourceIP = "192.168.1.103",
                    DestinationIP = "10.0.0.4",
                    SourcePort = 54324,
                    DestinationPort = 445,
                    Protocol = Protocol.TCP,
                    Length = 100,
                    Info = "SMB Negotiate Protocol Request"
                },
                
                // HTTP/1.0 (insecure)
                new PacketInfo
                {
                    FrameNumber = 5,
                    Timestamp = DateTime.Now,
                    SourceIP = "192.168.1.104",
                    DestinationIP = "10.0.0.5",
                    SourcePort = 54325,
                    DestinationPort = 80,
                    Protocol = Protocol.TCP,
                    Length = 100,
                    Info = "HTTP/1.0 GET /index.html"
                },
                
                // TLS 1.3 (secure)
                new PacketInfo
                {
                    FrameNumber = 6,
                    Timestamp = DateTime.Now,
                    SourceIP = "192.168.1.105",
                    DestinationIP = "10.0.0.6",
                    SourcePort = 54326,
                    DestinationPort = 443,
                    Protocol = Protocol.TCP,
                    Length = 100,
                    Info = "TLSv1.3 Client Hello"
                }
            };
            
            Console.WriteLine("Testing Protocol Version Detection:");
            Console.WriteLine("====================================");
            
            // Test version detection
            var versionThreats = insecurePortDetector.DetectInsecureVersions(testPackets);
            
            Console.WriteLine($"\nDetected {versionThreats.Count} version-based threats:");
            foreach (var threat in versionThreats)
            {
                Console.WriteLine($"\n- {threat.ThreatName}");
                Console.WriteLine($"  Severity: {threat.Severity}");
                Console.WriteLine($"  Risk Score: {threat.RiskScore:F1}");
                Console.WriteLine($"  Description: {threat.Description}");
                
                if (threat.Metadata.ContainsKey("DetectedVersion"))
                    Console.WriteLine($"  Detected Version: {threat.Metadata["DetectedVersion"]}");
                
                if (threat.Metadata.ContainsKey("IsEncryptedButInsecure"))
                    Console.WriteLine($"  Encrypted but Insecure: {threat.Metadata["IsEncryptedButInsecure"]}");
                
                if (threat.Vulnerabilities.Count > 0)
                {
                    Console.WriteLine($"  Vulnerabilities:");
                    foreach (var vuln in threat.Vulnerabilities)
                    {
                        Console.WriteLine($"    - {vuln}");
                    }
                }
            }
            
            // Test individual version detection
            Console.WriteLine("\n\nTesting Individual Packet Version Detection:");
            Console.WriteLine("============================================");
            
            foreach (var packet in testPackets)
            {
                var result = detector.DetectVersion(packet);
                Console.WriteLine($"\nPacket {packet.FrameNumber} (Port {packet.DestinationPort}):");
                Console.WriteLine($"  Info: {packet.Info}");
                Console.WriteLine($"  Version Identified: {result.VersionIdentified}");
                Console.WriteLine($"  Detected Version: {result.DetectedVersion ?? "None"}");
                Console.WriteLine($"  Security Risk: {result.SecurityRisk}");
                Console.WriteLine($"  Assessment: {result.SecurityAssessment}");
            }
            
            // Test port-based threats (original functionality)
            Console.WriteLine("\n\nTesting Port-Based Threat Detection:");
            Console.WriteLine("=====================================");
            
            var portThreats = insecurePortDetector.DetectInsecurePorts(testPackets);
            Console.WriteLine($"\nDetected {portThreats.Count} port-based threats");
            
            foreach (var threat in portThreats)
            {
                Console.WriteLine($"- {threat.ThreatName} (Port {threat.Port}, Severity: {threat.Severity})");
            }
        }
        
        public static void Main(string[] args)
        {
            try
            {
                TestProtocolVersionDetection();
                Console.WriteLine("\n\nTest completed successfully!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n\nTest failed: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
            }
        }
    }
}