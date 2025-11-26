using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.TShark;

namespace PCAPAnalyzer.Tests
{
    public class FilterVerification
    {
        private readonly ITSharkService _tsharkService;

        public FilterVerification()
        {
            _tsharkService = new TSharkService();
        }
        
        public async Task RunFilterTests(string pcapFilePath)
        {
            Console.WriteLine($"=== Filter Verification Test ===");
            Console.WriteLine($"PCAP File: {pcapFilePath}");
            Console.WriteLine($"File Size: {new FileInfo(pcapFilePath).Length / 1024.0 / 1024.0:F2} MB");
            Console.WriteLine();
            
            // Load all packets
            Console.WriteLine("Loading packets from PCAP file...");
            var allPackets = await _tsharkService.ReadPcapFileAsync(pcapFilePath, CancellationToken.None);
            Console.WriteLine($"Total packets loaded: {allPackets.Count}");
            Console.WriteLine();
            
            // Test 1: No filter (baseline)
            Console.WriteLine("TEST 1: No Filter (Baseline)");
            Console.WriteLine("─────────────────────────────");
            AnalyzePackets(allPackets, allPackets, "No filter");
            Console.WriteLine();
            
            // Test 2: Port 2598 filter
            Console.WriteLine("TEST 2: Port 2598 Filter");
            Console.WriteLine("─────────────────────────────");
            var port2598Filter = new PacketFilter
            {
                SourcePortFilter = "2598"
            };
            var port2598Packets = ApplyFilter(allPackets, port2598Filter);
            AnalyzePackets(allPackets, port2598Packets, "Port 2598");
            Console.WriteLine();
            
            // Test 3: NOT Port 2598 filter
            Console.WriteLine("TEST 3: NOT Port 2598 Filter");
            Console.WriteLine("─────────────────────────────");
            var notPort2598Filter = new PacketFilter
            {
                SourcePortFilter = "2598",
                NegateSourcePort = true,
                DestinationPortFilter = "2598",
                NegateDestinationPort = true
            };
            var notPort2598Packets = ApplyFilter(allPackets, notPort2598Filter);
            AnalyzePackets(allPackets, notPort2598Packets, "NOT Port 2598");
            
            // Verify the NOT filter is working correctly
            Console.WriteLine("\nVerification:");
            var port2598Count = port2598Packets.Count;
            var notPort2598Count = notPort2598Packets.Count;
            var totalCount = allPackets.Count;
            
            // Count packets that have port 2598 in either source or destination
            var actualPort2598Packets = allPackets.Where(p => 
                p.SourcePort == 2598 || p.DestinationPort == 2598).ToList();
            var actualNotPort2598Packets = allPackets.Where(p => 
                p.SourcePort != 2598 && p.DestinationPort != 2598).ToList();
            
            Console.WriteLine($"✓ Packets with port 2598 (source OR dest): {actualPort2598Packets.Count}");
            Console.WriteLine($"✓ Packets without port 2598 (neither source nor dest): {actualNotPort2598Packets.Count}");
            Console.WriteLine($"✓ Total should equal original: {actualPort2598Packets.Count + actualNotPort2598Packets.Count} = {totalCount}");
            
            if (actualNotPort2598Packets.Count == notPort2598Count)
            {
                Console.WriteLine("✅ NOT Port filter is working correctly!");
            }
            else
            {
                Console.WriteLine($"❌ NOT Port filter issue: Expected {actualNotPort2598Packets.Count}, got {notPort2598Count}");
            }
            Console.WriteLine();
            
            // Test 4: Port statistics
            Console.WriteLine("TEST 4: Port Statistics");
            Console.WriteLine("─────────────────────────────");
            var portStats = CalculatePortStatistics(allPackets);
            Console.WriteLine("Top 10 Ports by Packet Count:");
            foreach (var (port, count) in portStats.Take(10))
            {
                var percentage = (count * 100.0 / allPackets.Count);
                Console.WriteLine($"  Port {port}: {count} packets ({percentage:F2}%)");
            }
            Console.WriteLine();
            
            // Test 5: IP statistics
            Console.WriteLine("TEST 5: IP Address Statistics");
            Console.WriteLine("─────────────────────────────");
            var sourceIpStats = allPackets.GroupBy(p => p.SourceIP)
                .Select(g => new { IP = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .Take(5);
            
            Console.WriteLine("Top 5 Source IPs:");
            foreach (var stat in sourceIpStats)
            {
                Console.WriteLine($"  {stat.IP}: {stat.Count} packets");
            }
            Console.WriteLine();
            
            var destIpStats = allPackets.GroupBy(p => p.DestinationIP)
                .Select(g => new { IP = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .Take(5);
            
            Console.WriteLine("Top 5 Destination IPs:");
            foreach (var stat in destIpStats)
            {
                Console.WriteLine($"  {stat.IP}: {stat.Count} packets");
            }
        }
        
        private List<PacketInfo> ApplyFilter(List<PacketInfo> packets, PacketFilter filter)
        {
            return packets.Where(p => filter.Matches(p)).ToList();
        }
        
        private void AnalyzePackets(List<PacketInfo> allPackets, List<PacketInfo> filteredPackets, string filterName)
        {
            Console.WriteLine($"Filter: {filterName}");
            Console.WriteLine($"Matched packets: {filteredPackets.Count} / {allPackets.Count} ({filteredPackets.Count * 100.0 / allPackets.Count:F2}%)");
            
            if (filteredPackets.Any())
            {
                var protocols = filteredPackets.GroupBy(p => p.Protocol)
                    .Select(g => $"{g.Key}:{g.Count()}")
                    .Take(5);
                Console.WriteLine($"Top protocols: {string.Join(", ", protocols)}");
                
                var ports = filteredPackets
                    .SelectMany(p => new[] { p.SourcePort, p.DestinationPort })
                    .Where(port => port > 0)
                    .GroupBy(port => port)
                    .OrderByDescending(g => g.Count())
                    .Take(5)
                    .Select(g => $"{g.Key}:{g.Count()}");
                Console.WriteLine($"Top ports: {string.Join(", ", ports)}");
            }
        }
        
        private Dictionary<int, int> CalculatePortStatistics(List<PacketInfo> packets)
        {
            var portCounts = new Dictionary<int, int>();
            
            foreach (var packet in packets)
            {
                if (packet.SourcePort > 0)
                {
                    if (!portCounts.ContainsKey(packet.SourcePort))
                        portCounts[packet.SourcePort] = 0;
                    portCounts[packet.SourcePort]++;
                }
                
                if (packet.DestinationPort > 0)
                {
                    if (!portCounts.ContainsKey(packet.DestinationPort))
                        portCounts[packet.DestinationPort] = 0;
                    portCounts[packet.DestinationPort]++;
                }
            }
            
            return portCounts.OrderByDescending(kvp => kvp.Value)
                .ToDictionary(kvp => kvp.Key, kvp => kvp.Value);
        }
        
        public static async Task Main(string[] args)
        {
            var pcapFile = args.Length > 0 ? args[0] : "/mnt/c/Claude Code/PCAP_Net9_Avalonia_TShark/04.07.2025_10k.pcap";
            
            if (!File.Exists(pcapFile))
            {
                Console.WriteLine($"Error: PCAP file not found: {pcapFile}");
                return;
            }
            
            var verifier = new FilterVerification();
            await verifier.RunFilterTests(pcapFile);
        }
    }
}