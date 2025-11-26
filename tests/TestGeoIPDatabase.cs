using System;
using System.Threading.Tasks;
using PCAPAnalyzer.Core.Services;

class TestGeoIPDatabase
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("Testing GeoIP Database...\n");
        
        var database = new GeoIPDatabase();
        
        // Load the database
        var ipv4Path = "GeoLite2-Country-Blocks-IPv4.csv";
        var ipv6Path = "GeoLite2-Country-Blocks-IPv6.csv";
        var locationsPath = "GeoLite2-Country-Locations-en.csv";
        
        Console.WriteLine("Loading database from CSV files...");
        var loaded = await database.LoadFromCsvFilesAsync(ipv4Path, ipv6Path, locationsPath);
        
        if (!loaded)
        {
            Console.WriteLine("Failed to load database!");
            return;
        }
        
        Console.WriteLine($"Database loaded successfully!");
        Console.WriteLine($"  Countries: {database.CountryCount}");
        Console.WriteLine($"  IPv4 ranges: {database.IPv4RangeCount}");
        Console.WriteLine($"  IPv6 ranges: {database.IPv6RangeCount}");
        Console.WriteLine();
        
        // Test some IPs
        var testIPs = new[]
        {
            "8.8.8.8",        // Google DNS (US)
            "1.1.1.1",        // Cloudflare DNS
            "223.5.5.5",      // Alibaba DNS (China)
            "77.88.8.8",      // Yandex DNS (Russia)
            "156.154.70.1",   // Neustar DNS
            "208.67.222.222", // OpenDNS
            "94.140.14.14",   // AdGuard DNS
            "185.228.168.9",  // CleanBrowsing
            "2001:4860:4860::8888", // Google IPv6
            "2606:4700:4700::1111"  // Cloudflare IPv6
        };
        
        Console.WriteLine("Testing IP lookups:\n");
        foreach (var ip in testIPs)
        {
            var country = database.LookupIP(ip);
            if (country != null)
            {
                Console.WriteLine($"{ip,-25} -> {country.CountryName} ({country.CountryCode}) - {country.ContinentName}");
            }
            else
            {
                Console.WriteLine($"{ip,-25} -> Not found");
            }
        }
        
        // Save to binary for faster loading
        Console.WriteLine("\nSaving to binary format...");
        await database.SaveToBinaryAsync("geoip.db");
        Console.WriteLine("Binary database saved to geoip.db");
        
        // Test loading from binary
        Console.WriteLine("\nTesting binary load...");
        var database2 = new GeoIPDatabase();
        if (await database2.LoadFromBinaryAsync("geoip.db"))
        {
            Console.WriteLine("Binary database loaded successfully!");
            var testIP = "8.8.8.8";
            var country = database2.LookupIP(testIP);
            Console.WriteLine($"Test lookup {testIP}: {country?.CountryName ?? "Not found"}");
        }
    }
}