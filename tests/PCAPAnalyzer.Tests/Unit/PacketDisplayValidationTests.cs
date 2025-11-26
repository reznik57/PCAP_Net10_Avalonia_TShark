using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using Avalonia;
using PCAPAnalyzer.Core.Models;

namespace PCAPAnalyzer.Tests.Unit
{
    /// <summary>
    /// Simplified packet display validation tests
    /// Tests core functionality without complex UI dependencies
    /// </summary>
    public class PacketDisplayValidationTests
    {
        #region Coordinate Calculation Tests

        [Theory]
        [InlineData(-90, -180, 800, 400)] // South Pole, Date Line
        [InlineData(90, 180, 800, 400)]   // North Pole, Date Line
        [InlineData(0, 0, 800, 400)]      // Equator, Prime Meridian
        [InlineData(40.7128, -74.0060, 800, 400)] // New York
        [InlineData(51.5074, -0.1278, 800, 400)]  // London
        public void GeographicToScreen_WithValidCoordinates_ShouldReturnValidScreenPosition(
            double lat, double lon, double width, double height)
        {
            // Arrange
            var bounds = new Rect(0, 0, width, height);
            
            // Act
            var screenPos = GeographicToScreen(lat, lon, bounds);
            
            // Assert
            Assert.True(screenPos.X >= 0 && screenPos.X <= width, 
                $"X coordinate {screenPos.X} should be between 0 and {width}");
            Assert.True(screenPos.Y >= 0 && screenPos.Y <= height, 
                $"Y coordinate {screenPos.Y} should be between 0 and {height}");
        }

        [Theory]
        [InlineData(100, 50, 800, 400)]    // Point in screen
        [InlineData(400, 200, 800, 400)]   // Center point
        [InlineData(0, 0, 800, 400)]       // Top-left corner
        [InlineData(800, 400, 800, 400)]   // Bottom-right corner
        public void ScreenToGeographic_WithValidScreenPosition_ShouldReturnValidCoordinates(
            double x, double y, double width, double height)
        {
            // Arrange
            var bounds = new Rect(0, 0, width, height);
            var screenPos = new Point(x, y);
            
            // Act
            var (lat, lon) = ScreenToGeographic(screenPos, bounds);
            
            // Assert
            Assert.True(lat >= -90 && lat <= 90, 
                $"Latitude {lat} should be between -90 and 90");
            Assert.True(lon >= -180 && lon <= 180, 
                $"Longitude {lon} should be between -180 and 180");
        }

        [Fact]
        public void CoordinateConversion_RoundTrip_ShouldPreserveAccuracy()
        {
            // Arrange
            var originalLat = 40.7128; // New York
            var originalLon = -74.0060;
            var bounds = new Rect(0, 0, 800, 400);
            
            // Act
            var screenPos = GeographicToScreen(originalLat, originalLon, bounds);
            var (convertedLat, convertedLon) = ScreenToGeographic(screenPos, bounds);
            
            // Assert - Allow small precision loss due to floating point operations
            Assert.Equal(originalLat, convertedLat, 1);
            Assert.Equal(originalLon, convertedLon, 1);
        }

        #endregion

        #region Packet Processing Tests

        [Fact]
        public void CreateMapPoint_WithValidPacket_ShouldCreateCorrectMapPoint()
        {
            // Arrange
            var packet = new PacketInfo
            {
                Timestamp = DateTime.UtcNow,
                FrameNumber = 1,
                Length = 64,
                SourceIP = "192.168.1.1",
                DestinationIP = "10.0.0.1",
                SourcePort = 80,
                DestinationPort = 8080,
                Protocol = Protocol.HTTP
            };

            // Act
            var mapPoint = CreateMapPointFromPacket(packet);

            // Assert
            Assert.NotNull(mapPoint);
            Assert.Equal(packet.SourceIP, mapPoint.SourceIP);
            Assert.Equal(packet.DestinationIP, mapPoint.DestinationIP);
            Assert.Equal(packet.Protocol.ToString(), mapPoint.Protocol);
            Assert.Equal(packet.Length, mapPoint.PacketSize);
            Assert.Equal(packet.Timestamp, mapPoint.Timestamp);
        }

        [Fact]
        public void CreateMapPoint_WithInvalidIP_ShouldUseDefaultCoordinates()
        {
            // Arrange
            var packet = new PacketInfo
            {
                Timestamp = DateTime.UtcNow,
                FrameNumber = 1,
                Length = 64,
                SourceIP = "invalid.ip.address",
                DestinationIP = "192.168.1.1",
                SourcePort = 80,
                DestinationPort = 8080,
                Protocol = Protocol.TCP
            };

            // Act
            var mapPoint = CreateMapPointFromPacket(packet);

            // Assert
            Assert.NotNull(mapPoint);
            Assert.Equal(0.0, mapPoint.Latitude);
            Assert.Equal(0.0, mapPoint.Longitude);
        }

        [Theory]
        [InlineData("192.168.1.1", "10.0.0.1")]
        [InlineData("8.8.8.8", "1.1.1.1")]
        [InlineData("172.16.0.1", "172.16.0.100")]
        public void CreateMapPoint_WithVariousIPs_ShouldCalculateValidCoordinates(string sourceIP, string destIP)
        {
            // Arrange
            var packet = new PacketInfo
            {
                Timestamp = DateTime.UtcNow,
                FrameNumber = 1,
                Length = 64,
                SourceIP = sourceIP,
                DestinationIP = destIP,
                SourcePort = 80,
                DestinationPort = 8080,
                Protocol = Protocol.TCP
            };

            // Act
            var mapPoint = CreateMapPointFromPacket(packet);

            // Assert
            Assert.NotNull(mapPoint);
            Assert.True(mapPoint.Latitude >= -90 && mapPoint.Latitude <= 90,
                $"Source latitude {mapPoint.Latitude} should be valid");
            Assert.True(mapPoint.Longitude >= -180 && mapPoint.Longitude <= 180,
                $"Source longitude {mapPoint.Longitude} should be valid");
            Assert.True(mapPoint.DestLatitude >= -90 && mapPoint.DestLatitude <= 90,
                $"Destination latitude {mapPoint.DestLatitude} should be valid");
            Assert.True(mapPoint.DestLongitude >= -180 && mapPoint.DestLongitude <= 180,
                $"Destination longitude {mapPoint.DestLongitude} should be valid");
        }

        #endregion

        #region Performance Tests

        [Fact]
        public void ProcessLargePacketSet_ShouldCompleteWithinTimeLimit()
        {
            // Arrange
            var packets = CreateLargePacketSet(5000);
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            // Act
            var mapPoints = new List<TestMapPoint>();
            foreach (var packet in packets)
            {
                var mapPoint = CreateMapPointFromPacket(packet);
                if (mapPoint != null)
                {
                    mapPoints.Add(mapPoint);
                }
            }
            stopwatch.Stop();

            // Assert
            Assert.Equal(packets.Count, mapPoints.Count);
            Assert.True(stopwatch.ElapsedMilliseconds < 5000, 
                $"Processing {packets.Count} packets took {stopwatch.ElapsedMilliseconds}ms, should be < 5000ms");
        }

        [Fact]
        public void FilteredPackets_ShouldProcessCorrectly()
        {
            // Arrange
            var allPackets = CreateTestPackets();
            var httpPackets = allPackets.Where(p => p.Protocol == Protocol.HTTP).ToList();

            // Act
            var allMapPoints = allPackets.Select(CreateMapPointFromPacket).Where(mp => mp != null).ToList();
            var filteredMapPoints = httpPackets.Select(CreateMapPointFromPacket).Where(mp => mp != null).ToList();

            // Assert
            Assert.True(allMapPoints.Count > filteredMapPoints.Count);
            Assert.All(filteredMapPoints, mp => Assert.Equal("HTTP", mp?.Protocol));
        }

        #endregion

        #region Edge Cases and Error Handling

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("invalid")]
        [InlineData("999.999.999.999")]
        [InlineData("not.an.ip.address")]
        public void CreateMapPoint_WithInvalidSourceIP_ShouldHandleGracefully(string invalidIP)
        {
            // Arrange
            var packet = new PacketInfo
            {
                Timestamp = DateTime.UtcNow,
                FrameNumber = 1,
                Length = 64,
                SourceIP = invalidIP,
                DestinationIP = "192.168.1.1",
                SourcePort = 80,
                DestinationPort = 8080,
                Protocol = Protocol.TCP
            };

            // Act
            var mapPoint = CreateMapPointFromPacket(packet);

            // Assert
            Assert.NotNull(mapPoint);
            Assert.Equal(0.0, mapPoint.Latitude);
            Assert.Equal(0.0, mapPoint.Longitude);
        }

        [Fact]
        public void CreateMapPoint_WithZeroLengthPacket_ShouldStillProcess()
        {
            // Arrange
            var packet = new PacketInfo
            {
                Timestamp = DateTime.UtcNow,
                FrameNumber = 1,
                Length = 0,
                SourceIP = "192.168.1.1",
                DestinationIP = "192.168.1.2",
                SourcePort = 80,
                DestinationPort = 8080,
                Protocol = Protocol.TCP
            };

            // Act
            var mapPoint = CreateMapPointFromPacket(packet);

            // Assert
            Assert.NotNull(mapPoint);
            Assert.Equal(0, mapPoint.PacketSize);
        }

        #endregion

        #region Helper Methods

        private Point GeographicToScreen(double lat, double lon, Rect bounds)
        {
            // Convert geographic coordinates to screen coordinates
            // Using simple equirectangular projection
            var x = (lon + 180) / 360 * bounds.Width;
            var y = (90 - lat) / 180 * bounds.Height;
            return new Point(x, y);
        }

        private (double lat, double lon) ScreenToGeographic(Point screenPos, Rect bounds)
        {
            // Convert screen coordinates to geographic coordinates
            var lon = (screenPos.X / bounds.Width * 360) - 180;
            var lat = 90 - (screenPos.Y / bounds.Height * 180);
            return (lat, lon);
        }

        private TestMapPoint? CreateMapPointFromPacket(PacketInfo packet)
        {
            if (packet.SourceIP == null || packet.DestinationIP == null) 
                return null;

            var sourceCoords = GetCoordinatesForIP(packet.SourceIP);
            var destCoords = GetCoordinatesForIP(packet.DestinationIP);

            return new TestMapPoint
            {
                SourceIP = packet.SourceIP,
                DestinationIP = packet.DestinationIP,
                Latitude = sourceCoords.Latitude,
                Longitude = sourceCoords.Longitude,
                DestLatitude = destCoords.Latitude,
                DestLongitude = destCoords.Longitude,
                Protocol = packet.Protocol.ToString(),
                PacketSize = packet.Length,
                Timestamp = packet.Timestamp
            };
        }

        private (double Latitude, double Longitude) GetCoordinatesForIP(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip) || !IsValidIP(ip))
                return (0.0, 0.0);

            // Mock GeoIP lookup for testing
            return ip switch
            {
                "192.168.1.1" => (40.7128, -74.0060),   // New York
                "8.8.8.8" => (37.4419, -122.1419),      // Mountain View
                "1.1.1.1" => (-33.8688, 151.2093),      // Sydney
                "10.0.0.1" => (51.5074, -0.1278),       // London
                "172.16.0.1" => (48.8566, 2.3522),      // Paris
                "172.16.0.100" => (52.5200, 13.4050),   // Berlin
                _ => (0.0, 0.0)                          // Default
            };
        }

        private bool IsValidIP(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip)) return false;
            
            var parts = ip.Split('.');
            if (parts.Length != 4) return false;

            return parts.All(part => 
                int.TryParse(part, out var num) && num >= 0 && num <= 255);
        }

        private List<PacketInfo> CreateTestPackets()
        {
            return new List<PacketInfo>
            {
                new PacketInfo
                {
                    Timestamp = DateTime.UtcNow.AddSeconds(-10),
                    FrameNumber = 1,
                    Length = 64,
                    SourceIP = "192.168.1.1",
                    DestinationIP = "10.0.0.1",
                    SourcePort = 80,
                    DestinationPort = 8080,
                    Protocol = Protocol.HTTP
                },
                new PacketInfo
                {
                    Timestamp = DateTime.UtcNow.AddSeconds(-9),
                    FrameNumber = 2,
                    Length = 128,
                    SourceIP = "8.8.8.8",
                    DestinationIP = "192.168.1.1",
                    SourcePort = 53,
                    DestinationPort = 12345,
                    Protocol = Protocol.DNS
                },
                new PacketInfo
                {
                    Timestamp = DateTime.UtcNow.AddSeconds(-8),
                    FrameNumber = 3,
                    Length = 256,
                    SourceIP = "1.1.1.1",
                    DestinationIP = "192.168.1.100",
                    SourcePort = 443,
                    DestinationPort = 54321,
                    Protocol = Protocol.HTTPS
                },
                new PacketInfo
                {
                    Timestamp = DateTime.UtcNow.AddSeconds(-7),
                    FrameNumber = 4,
                    Length = 512,
                    SourceIP = "10.0.0.1",
                    DestinationIP = "172.16.0.1",
                    SourcePort = 22,
                    DestinationPort = 2222,
                    Protocol = Protocol.TCP
                },
                new PacketInfo
                {
                    Timestamp = DateTime.UtcNow.AddSeconds(-6),
                    FrameNumber = 5,
                    Length = 32,
                    SourceIP = "172.16.0.1",
                    DestinationIP = "172.16.0.100",
                    SourcePort = 67,
                    DestinationPort = 68,
                    Protocol = Protocol.DHCP
                }
            };
        }

        private List<PacketInfo> CreateLargePacketSet(int count)
        {
            var packets = new List<PacketInfo>();
            var random = new Random(42); // Fixed seed for reproducibility
            var sourceIPs = new[] { "192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8", "1.1.1.1" };
            var destIPs = new[] { "93.184.216.34", "151.101.193.140", "172.217.12.174", "13.107.42.14" };
            var protocols = new[] { Protocol.HTTP, Protocol.HTTPS, Protocol.TCP, Protocol.UDP, Protocol.DNS };
            
            for (int i = 0; i < count; i++)
            {
                packets.Add(new PacketInfo
                {
                    Timestamp = DateTime.UtcNow.AddSeconds(-random.Next(3600)),
                    FrameNumber = (uint)i + 1,
                    Length = (ushort)(64 + random.Next(1400)),
                    SourceIP = sourceIPs[random.Next(sourceIPs.Length)],
                    DestinationIP = destIPs[random.Next(destIPs.Length)],
                    SourcePort = (ushort)random.Next(1, 65535),
                    DestinationPort = (ushort)random.Next(1, 65535),
                    Protocol = protocols[random.Next(protocols.Length)]
                });
            }
            
            return packets;
        }

        #endregion
    }

    /// <summary>
    /// Simple test map point class
    /// </summary>
    public class TestMapPoint
    {
        public string SourceIP { get; set; } = "";
        public string DestinationIP { get; set; } = "";
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public double DestLatitude { get; set; }
        public double DestLongitude { get; set; }
        public string Protocol { get; set; } = "";
        public int PacketSize { get; set; }
        public DateTime Timestamp { get; set; }
    }
}