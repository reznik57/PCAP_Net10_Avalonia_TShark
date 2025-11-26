using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PCAPAnalyzer.Core.Models;
using PCAPAnalyzer.Core.Services;
using PCAPAnalyzer.TShark;

class DiagnosticTest
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("=== PCAP Packet Count Diagnostic Test ===\n");
        
        // Find the PCAP file
        string pcapPath = "";
        var searchPaths = new[]
        {
            "/mnt/c/Claude Code/04.07.2025.pcap",
            "/mnt/c/Claude Code/04.07.2025_10k.pcap",
            "/mnt/c/Claude Code/PCAP_Net9_Avalonia_TShark/../04.07.2025.pcap",
            "/mnt/c/Claude Code/PCAP_Net9_Avalonia_TShark/../04.07.2025_10k.pcap"
        };
        
        foreach (var path in searchPaths)
        {
            if (File.Exists(path))
            {
                pcapPath = path;
                break;
            }
        }
        
        if (string.IsNullOrEmpty(pcapPath))
        {
            Console.WriteLine("ERROR: Could not find PCAP file");
            return;
        }
        
        Console.WriteLine($"Using PCAP file: {pcapPath}");
        Console.WriteLine($"File size: {new FileInfo(pcapPath).Length / (1024 * 1024):F2} MB\n");
        
        // Create logger
        var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(LogLevel.Information);
            builder.AddConsole();
        });
        var logger = loggerFactory.CreateLogger<TSharkService>();
        
        // Create TShark service
        var tsharkService = new TSharkService(logger);
        
        // Start analysis
        Console.WriteLine("Starting TShark analysis...");
        var cts = new CancellationTokenSource();
        var startSuccess = await tsharkService.StartAnalysisAsync(pcapPath, cts.Token);
        
        if (!startSuccess)
        {
            Console.WriteLine("ERROR: Failed to start TShark analysis");
            return;
        }
        
        // Collect packets
        var packets = new List<PacketInfo>();
        var targetIP = "91.249.175.101";
        var targetPacketCount = 0;
        var publicIPPackets = 0;
        var privateIPPackets = 0;
        var ipCounts = new Dictionary<string, int>();
        
        // Create GeoIP service
        var geoIPService = new GeoIPService();
        await geoIPService.InitializeAsync();
        
        Console.WriteLine("\nProcessing packets...");
        
        // Read packets from channel
        var reader = tsharkService.PacketReader;
        var maxPackets = 100000; // Limit for testing
        
        while (await reader.WaitToReadAsync(cts.Token) && packets.Count < maxPackets)
        {
            while (reader.TryRead(out var packet) && packets.Count < maxPackets)
            {
                packets.Add(packet);
                
                // Count packets for target IP
                if (packet.SourceIP == targetIP || packet.DestinationIP == targetIP)
                {
                    targetPacketCount++;
                }
                
                // Count public vs private IPs
                bool srcPublic = geoIPService.IsPublicIP(packet.SourceIP);
                bool dstPublic = geoIPService.IsPublicIP(packet.DestinationIP);
                
                if (srcPublic || dstPublic)
                {
                    publicIPPackets++;
                }
                else
                {
                    privateIPPackets++;
                }
                
                // Track IP counts
                if (!string.IsNullOrEmpty(packet.SourceIP))
                {
                    if (!ipCounts.ContainsKey(packet.SourceIP))
                        ipCounts[packet.SourceIP] = 0;
                    ipCounts[packet.SourceIP]++;
                }
                
                if (packets.Count % 10000 == 0)
                {
                    Console.WriteLine($"  Processed {packets.Count:N0} packets...");
                    Console.WriteLine($"    Target IP packets so far: {targetPacketCount:N0}");
                    Console.WriteLine($"    Public IP packets: {publicIPPackets:N0}");
                }
            }
        }
        
        // Cancel if we hit the limit
        if (packets.Count >= maxPackets)
        {
            Console.WriteLine($"\nReached {maxPackets:N0} packet limit, stopping analysis...");
            cts.Cancel();
        }
        
        Console.WriteLine($"\n=== Analysis Complete ===");
        Console.WriteLine($"Total packets read: {packets.Count:N0}");
        Console.WriteLine($"Packets with public IPs: {publicIPPackets:N0} ({publicIPPackets * 100.0 / packets.Count:F1}%)");
        Console.WriteLine($"Packets with only private IPs: {privateIPPackets:N0} ({privateIPPackets * 100.0 / packets.Count:F1}%)");
        Console.WriteLine($"\nPackets for IP {targetIP}: {targetPacketCount:N0}");
        Console.WriteLine($"  As percentage of total: {targetPacketCount * 100.0 / packets.Count:F1}%");
        Console.WriteLine($"  As percentage of public IP packets: {targetPacketCount * 100.0 / publicIPPackets:F1}%");
        
        // Show top 10 IPs by packet count
        Console.WriteLine($"\n=== Top 10 IPs by Packet Count ===");
        var topIPs = ipCounts.OrderByDescending(kvp => kvp.Value).Take(10);
        foreach (var ip in topIPs)
        {
            var isPublic = geoIPService.IsPublicIP(ip.Key);
            var location = isPublic ? await geoIPService.GetLocationAsync(ip.Key) : null;
            Console.WriteLine($"  {ip.Key,-20} {ip.Value,7:N0} packets  {(isPublic ? "PUBLIC" : "PRIVATE")}  {location?.CountryName ?? ""}");
        }
        
        // Calculate country statistics
        Console.WriteLine($"\n=== Country Statistics ===");
        Console.WriteLine("Calculating country statistics for public IP packets...");
        
        var publicPackets = packets.Where(p => 
            geoIPService.IsPublicIP(p.SourceIP) || geoIPService.IsPublicIP(p.DestinationIP)
        ).ToList();
        
        var countryStats = await geoIPService.AnalyzeCountryTrafficAsync(publicPackets);
        
        Console.WriteLine($"Countries detected: {countryStats.Count}");
        Console.WriteLine($"\nTop 10 Countries by Packet Count:");
        
        var topCountries = countryStats.OrderByDescending(c => c.Value.TotalPackets).Take(10);
        long totalCountedPackets = 0;
        foreach (var country in topCountries)
        {
            Console.WriteLine($"  {country.Value.CountryName,-20} ({country.Value.CountryCode})  {country.Value.TotalPackets,7:N0} packets  {country.Value.Percentage,5:F1}%");
            totalCountedPackets += country.Value.TotalPackets;
        }
        
        Console.WriteLine($"\nTotal packets in country statistics: {countryStats.Sum(c => c.Value.TotalPackets):N0}");
        Console.WriteLine($"Expected (public IP packets): {publicIPPackets:N0}");
        
        if (Math.Abs(countryStats.Sum(c => c.Value.TotalPackets) - publicIPPackets) > publicIPPackets * 0.1)
        {
            Console.WriteLine("\n⚠️ WARNING: Country statistics packet count doesn't match expected public IP packets!");
            Console.WriteLine("   This could indicate an issue with GeoIP lookups or double-counting.");
        }
        
        // Stop the service
        await tsharkService.StopAnalysisAsync();
        tsharkService.Dispose();
        
        Console.WriteLine("\n=== Test Complete ===");
    }
}